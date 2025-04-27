package main

import (
	"encoding/json"
	"fmt"

	openrpc "github.com/open-rpc/meta-schema"
)

type ErrorGroupOrReference struct {
	ErrorObjects    []openrpc.ErrorOrReference `json:"-"`
	ReferenceObject *openrpc.ReferenceObject   `json:"-"`
}

func (e *ErrorGroupOrReference) UnmarshalJSON(data []byte) error {
	var refObj openrpc.ReferenceObject
	// If ErrorGroup has a reference
	if err := json.Unmarshal(data, &refObj); err == nil && refObj.Ref != nil {
		return fmt.Errorf("references not supported in error groups: %v", *refObj.Ref)
	}

	var errors []openrpc.ErrorOrReference
	if err := json.Unmarshal(data, &errors); err == nil {
		// If the ErrorObject has a reference TODO: validate if this case is needed
		for _, errObj := range errors {
			if errObj.ReferenceObject != nil {
				if err := json.Unmarshal(data, errObj.ErrorObject); err == nil {
					return fmt.Errorf("references not supported in error Objects: %v", *refObj.Ref)
				}
			}
		}
		e.ErrorObjects = errors
		return nil
	}

	return fmt.Errorf("failed to unmarshal error group")
}

// ErrorGroups is an array of error groups or reference
type ErrorGroups []ErrorGroupOrReference

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
