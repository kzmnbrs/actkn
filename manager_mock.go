// Code generated by MockGen. DO NOT EDIT.
// Source: manager.go

// Package actkn is a generated GoMock package.
package actkn

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockManagerInterface is a mock of ManagerInterface interface.
type MockManagerInterface struct {
	ctrl     *gomock.Controller
	recorder *MockManagerInterfaceMockRecorder
}

// MockManagerInterfaceMockRecorder is the mock recorder for MockManagerInterface.
type MockManagerInterfaceMockRecorder struct {
	mock *MockManagerInterface
}

// NewMockManagerInterface creates a new mock instance.
func NewMockManagerInterface(ctrl *gomock.Controller) *MockManagerInterface {
	mock := &MockManagerInterface{ctrl: ctrl}
	mock.recorder = &MockManagerInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManagerInterface) EXPECT() *MockManagerInterfaceMockRecorder {
	return m.recorder
}

// Decode mocks base method.
func (m *MockManagerInterface) Decode(src []byte, c *Ctx) []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Decode", src, c)
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Decode indicates an expected call of Decode.
func (mr *MockManagerInterfaceMockRecorder) Decode(src, c interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decode", reflect.TypeOf((*MockManagerInterface)(nil).Decode), src, c)
}

// Encode mocks base method.
func (m *MockManagerInterface) Encode(dst, src []byte, c *Ctx) []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Encode", dst, src, c)
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Encode indicates an expected call of Encode.
func (mr *MockManagerInterfaceMockRecorder) Encode(dst, src, c interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Encode", reflect.TypeOf((*MockManagerInterface)(nil).Encode), dst, src, c)
}