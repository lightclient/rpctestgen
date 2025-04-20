package main

import (
	"encoding/json"

	openrpc "github.com/open-rpc/meta-schema"
)

// ErrorObject represents a single error in an error group
type ErrorObject struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ErrorGroup represents a group of errors
type ErrorGroup []ErrorObject

// ErrorGroups is an array of error groups
type ErrorGroups []ErrorGroup

// Add support for error group extensions in method objects
type ExtendedMethodObject struct {
	*openrpc.MethodObject
	XErrorGroup ErrorGroups `json:"x-error-group,omitempty"`
}

// Wrap the standard MethodOrReference with extensions
type ExtendedMethodOrReference struct {
	MethodObject    *ExtendedMethodObject    `json:"-"`
	ReferenceObject *openrpc.ReferenceObject `json:"-"`
	Raw             map[string]interface{}   `json:"-"`
}

// Wraps the standard OpenrpcDocument with methods that support extensions
type ExtendedOpenrpcDocument struct {
	openrpc.OpenrpcDocument
	Methods *[]ExtendedMethodOrReference `json:"methods"`
}

// UnmarshalJSON custom unmarshaller to capture both standard and extended fields
func (e *ExtendedMethodOrReference) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	e.Raw = raw

	// Check if it's a $ref object, should never be true
	if _, ok := raw["$ref"]; ok {
		refObj := &openrpc.ReferenceObject{}
		if err := json.Unmarshal(data, refObj); err != nil {
			return err
		}
		e.ReferenceObject = refObj
		return nil
	}

	methodObj := &ExtendedMethodObject{
		MethodObject: &openrpc.MethodObject{},
	}
	if err := json.Unmarshal(data, methodObj); err != nil {
		return err
	}
	e.MethodObject = methodObj
	return nil
}
