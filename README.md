# Scudo

An authentication library for Go applications with JWT and refresh token support.

# TODO

## Features

- Delete a user
- Soft delete for users
- Authentication middleware for easy integration
- Email update
- Password update/reset
- Metrics

## Configuration

- Cookie names should be configurable
- Configurable password policies

## General improvements

- Implement proper refresh token storage - Use hash for O(1) lookup
- Email verification or some interface for verification confirmation

## Testing gaps

- Concurrent access testing
- Performance/load testing
