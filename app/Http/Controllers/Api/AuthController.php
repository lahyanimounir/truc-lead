<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $registeredData = $request->validate([
                'name' => 'required|max:55',
                'email' => 'email|required|unique:users',
                'password' => 'required'
            ]);

            $user = User::create($registeredData);
            $accessToken = $user->createToken('authToken')->accessToken;

            return response(['user' => $user, 'access_token' => $accessToken], 201);
        } catch (ValidationException $e) {
            return response()->json($e->errors(), 422);
        }
    }

    public function login(Request $request)
    {
        $loginData = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if (!auth()->attempt($loginData)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $user = auth()->user();
        $accessToken = $user->createToken('authToken')->accessToken;

        return response()->json([
            'user' => $user,
            'access_token' => $accessToken,
        ]);
    }

    public function getAuthenticatedUser(Request $request)
    {
        dd(111);
        $user = Auth::user();

        if ($user) {
            return response()->json([
                'user' => $user,
            ], 200);
        }

        return response()->json([
            'message' => 'Unauthenticated',
        ], 401); // Unauthorized
    }
}
