package softether

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	packInt uint32 = iota
	packData
	packString
	packUnicodeString
	packInt64
)

const (
	maxPackElements = 4096
	maxPackValues   = 4096
	maxPackValue    = 16 * 1024 * 1024
)

type packValue struct {
	integer   uint32
	integer64 uint64
	data      []byte
	text      string
}

type packElement struct {
	name   string
	kind   uint32
	values []packValue
}

type pack struct {
	elements []packElement
}

func (p *pack) addInt(name string, value uint32) {
	p.addElement(packElement{name: name, kind: packInt, values: []packValue{{integer: value}}})
}

func (p *pack) addBool(name string, value bool) {
	if value {
		p.addInt(name, 1)
		return
	}
	p.addInt(name, 0)
}

func (p *pack) addString(name, value string) {
	p.addElement(packElement{name: name, kind: packString, values: []packValue{{text: value}}})
}

func (p *pack) addStrings(name string, values []string) {
	items := make([]packValue, len(values))
	for index, value := range values {
		items[index].text = value
	}
	p.addElement(packElement{name: name, kind: packString, values: items})
}

func (p *pack) addData(name string, value []byte) {
	p.addElement(packElement{name: name, kind: packData, values: []packValue{{data: append([]byte(nil), value...)}}})
}

func (p *pack) addElement(value packElement) {
	for _, existing := range p.elements {
		if strings.EqualFold(existing.name, value.name) {
			return
		}
	}
	p.elements = append(p.elements, value)
}

func (p *pack) element(name string, kind uint32) *packElement {
	for index := range p.elements {
		value := &p.elements[index]
		if value.kind == kind && strings.EqualFold(value.name, name) {
			return value
		}
	}
	return nil
}

func (p *pack) getInt(name string) uint32 {
	value := p.element(name, packInt)
	if value == nil || len(value.values) == 0 {
		return 0
	}
	return value.values[0].integer
}

func (p *pack) getBool(name string) bool {
	return p.getInt(name) != 0
}

func (p *pack) getString(name string) string {
	return p.getStringAt(name, 0)
}

func (p *pack) getStringAt(name string, index int) string {
	value := p.element(name, packString)
	if value == nil || index < 0 || index >= len(value.values) {
		return ""
	}
	return value.values[index].text
}

func (p *pack) stringCount(name string) int {
	value := p.element(name, packString)
	if value == nil {
		return 0
	}
	return len(value.values)
}

func (p *pack) getData(name string) []byte {
	value := p.element(name, packData)
	if value == nil || len(value.values) == 0 {
		return nil
	}
	return append([]byte(nil), value.values[0].data...)
}

func (p *pack) marshal() ([]byte, error) {
	if len(p.elements) > maxPackElements {
		return nil, errors.New("SoftEther PACK 元素过多")
	}
	var output bytes.Buffer
	if err := binary.Write(&output, binary.BigEndian, uint32(len(p.elements))); err != nil {
		return nil, err
	}
	for _, element := range p.elements {
		if element.name == "" || len(element.name) > 63 || len(element.values) == 0 || len(element.values) > maxPackValues {
			return nil, errors.New("SoftEther PACK 元素无效")
		}
		if err := writePackString(&output, element.name); err != nil {
			return nil, err
		}
		if err := binary.Write(&output, binary.BigEndian, element.kind); err != nil {
			return nil, err
		}
		if err := binary.Write(&output, binary.BigEndian, uint32(len(element.values))); err != nil {
			return nil, err
		}
		for _, value := range element.values {
			if err := writePackValue(&output, element.kind, value); err != nil {
				return nil, err
			}
		}
	}
	return output.Bytes(), nil
}

func unmarshalPack(data []byte) (*pack, error) {
	reader := bytes.NewReader(data)
	var count uint32
	if err := binary.Read(reader, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count > maxPackElements {
		return nil, errors.New("SoftEther PACK 元素数量超限")
	}
	result := &pack{elements: make([]packElement, 0, count)}
	for index := uint32(0); index < count; index++ {
		name, err := readPackString(reader)
		if err != nil {
			return nil, err
		}
		var kind, valueCount uint32
		if err := binary.Read(reader, binary.BigEndian, &kind); err != nil {
			return nil, err
		}
		if err := binary.Read(reader, binary.BigEndian, &valueCount); err != nil {
			return nil, err
		}
		if valueCount == 0 || valueCount > maxPackValues {
			return nil, errors.New("SoftEther PACK 值数量无效")
		}
		element := packElement{name: name, kind: kind, values: make([]packValue, 0, valueCount)}
		for valueIndex := uint32(0); valueIndex < valueCount; valueIndex++ {
			value, err := readPackValue(reader, kind)
			if err != nil {
				return nil, err
			}
			element.values = append(element.values, value)
		}
		result.elements = append(result.elements, element)
	}
	if reader.Len() != 0 {
		return nil, errors.New("SoftEther PACK 存在尾随数据")
	}
	return result, nil
}

func writePackString(writer io.Writer, value string) error {
	if err := binary.Write(writer, binary.BigEndian, uint32(len(value)+1)); err != nil {
		return err
	}
	_, err := io.WriteString(writer, value)
	return err
}

func readPackString(reader io.Reader) (string, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return "", err
	}
	if size == 0 || size > 64 {
		return "", errors.New("SoftEther PACK 名称长度无效")
	}
	value := make([]byte, size-1)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", err
	}
	return string(value), nil
}

func writePackValue(writer io.Writer, kind uint32, value packValue) error {
	switch kind {
	case packInt:
		return binary.Write(writer, binary.BigEndian, value.integer)
	case packInt64:
		return binary.Write(writer, binary.BigEndian, value.integer64)
	case packData:
		if len(value.data) > maxPackValue {
			return errors.New("SoftEther PACK 数据过大")
		}
		if err := binary.Write(writer, binary.BigEndian, uint32(len(value.data))); err != nil {
			return err
		}
		_, err := writer.Write(value.data)
		return err
	case packString, packUnicodeString:
		data := []byte(value.text)
		if kind == packUnicodeString {
			data = append(data, 0)
		}
		if len(data) > maxPackValue {
			return errors.New("SoftEther PACK 字符串过长")
		}
		if err := binary.Write(writer, binary.BigEndian, uint32(len(data))); err != nil {
			return err
		}
		_, err := writer.Write(data)
		return err
	default:
		return fmt.Errorf("不支持的 SoftEther PACK 类型: %d", kind)
	}
}

func readPackValue(reader io.Reader, kind uint32) (packValue, error) {
	var value packValue
	switch kind {
	case packInt:
		return value, binary.Read(reader, binary.BigEndian, &value.integer)
	case packInt64:
		return value, binary.Read(reader, binary.BigEndian, &value.integer64)
	case packData, packString, packUnicodeString:
		var size uint32
		if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
			return value, err
		}
		if size > maxPackValue {
			return value, errors.New("SoftEther PACK 值长度超限")
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(reader, data); err != nil {
			return value, err
		}
		if kind == packData {
			value.data = data
		} else {
			value.text = strings.TrimSuffix(string(data), "\x00")
		}
		return value, nil
	default:
		return value, fmt.Errorf("不支持的 SoftEther PACK 类型: %d", kind)
	}
}
