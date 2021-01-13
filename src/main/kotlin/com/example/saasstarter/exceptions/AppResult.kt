package com.example.saasstarter.exceptions

sealed class Result<T> {
    data class Success<T>(val data: T) : Result<T>()
    data class Failure(val error: Throwable): Result<Nothing>()
}