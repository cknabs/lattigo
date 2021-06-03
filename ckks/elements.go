package ckks

import (
	"github.com/ldsec/lattigo/v2/rlwe"
)

// Element is a generic type for ciphertext and plaintexts
type Element struct {
	rlwe.Element
	scale float64
}

func newElement(params Parameters, degree, level int, scale float64) *Element {
	return &Element{*rlwe.NewElementAtLevel(params.Parameters, degree, level), scale}
}

// El returns itself.
func (el *Element) El() *Element {
	return el
}

// Scale returns the scale of the target element.
func (el *Element) Scale() float64 {
	return el.scale
}

// IsNTT returns true if the underlying rlwe.Element is in the NTT domain.
func (el *Element) IsNTT() bool {
	return el.Element.IsNTT
}

// SetScale sets the scale of the the target element to the input scale.
func (el *Element) SetScale(scale float64) {
	el.scale = scale
}

// MulScale multiplies the scale of the target element with the input scale.
func (el *Element) MulScale(scale float64) {
	el.scale *= scale
}

// DivScale divides the scale of the target element by the input scale.
func (el *Element) DivScale(scale float64) {
	el.scale /= scale
}

// Resize resizes the degree of the target element.
func (el *Element) Resize(params Parameters, degree int) {
	el.Element.Resize(params.Parameters, degree)
}

// Copy copies the `other` into the reciever Element.
func (el *Element) Copy(other *Element) {
	el.Element.Copy(&other.Element)
	el.scale = other.scale
}

// CopyNew creates a deep copy of the receiver Element and returns it.
func (el *Element) CopyNew() *Element {
	return &Element{*el.Element.CopyNew(), el.scale}
}
