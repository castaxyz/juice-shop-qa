/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/**
 * Suite de pruebas automatizadas – Persona 2 (Santiago Castaño Torres)
 * Caso Práctico Final – Aseguramiento de la Calidad de Software
 *
 * Casos cubiertos:
 *   CP-A-01  RF06  Partición de Equivalencia  Búsqueda de productos
 *   CP-A-02  RF07  Valores Límite             Registro de tarjeta de crédito
 *   CP-A-03  RF08  Valores Límite             Recarga de billetera digital
 *   CP-A-04  RF01  Tabla de Decisión          Validación de registro (password ≠ confirm)
 *   CP-A-05  RF02  Autenticación E2E/API      Inicio de sesión y JWT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

/* ─────────────────────────────────────────────────────────────────────────────
 * CP-A-01  RF06 – Búsqueda de productos (Partición de Equivalencia)
 *   Clase válida   : término con coincidencias ("apple")  → HTTP 200, data.length > 0
 *   Clase inválida : término sin coincidencias ("xyz999") → HTTP 200, data.length === 0
 * ───────────────────────────────────────────────────────────────────────────── */
void describe('CP-A-01 | RF06 | Búsqueda de productos (Partición de Equivalencia)', () => {
  void it('GET /rest/products/search?q=apple  →  200 con al menos un resultado', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=apple')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data), 'El cuerpo debe contener un arreglo en data')
    assert.ok(res.body.data.length > 0, 'Se esperan resultados para "apple"')
  })

  void it('GET /rest/products/search?q=xyz999  →  200 con cero resultados', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=xyz999')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0, 'No deben haber resultados para "xyz999"')
  })
})

/* ─────────────────────────────────────────────────────────────────────────────
 * CP-A-02  RF07 – Registro de tarjeta de crédito (Valores Límite)
 *   Valor válido   : 16 dígitos (1000000000000000, límite inferior del modelo)
 *   Valor inválido : 15 dígitos (999999999999999 < min)  → Sequelize validation error
 *
 * El modelo CardModel define cardNum con validate: { min: 1000000000000000 }
 * ───────────────────────────────────────────────────────────────────────────── */
void describe('CP-A-02 | RF07 – Registro de tarjeta (Valores Límite)', () => {
  let authHeader: { Authorization: string, 'content-type': string }

  before(async () => {
    const email = `card-tester-${Date.now()}@juice-sh.op`
    await request(app)
      .post('/api/Users')
      .set('content-type', 'application/json')
      .send({ email, password: 'Testpass1!', passwordRepeat: 'Testpass1!', securityQuestion: null, securityAnswer: null })
    const { token } = await login(app, { email, password: 'Testpass1!' })
    authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
  })

  void it('POST /api/Cards con 16 dígitos (límite inferior válido)  →  201', async () => {
    const res = await request(app)
      .post('/api/Cards')
      .set(authHeader)
      .send({
        fullName: 'Santiago Castaño',
        cardNum: 1000000000000000,
        expMonth: 12,
        expYear: 2080
      })
    assert.equal(res.status, 201,
      `Se esperaba 201 para 16 dígitos, se obtuvo ${res.status}: ${JSON.stringify(res.body)}`)
    assert.ok(res.body.data?.id > 0, 'La respuesta debe incluir el id creado')
  })

  void it('POST /api/Cards con 15 dígitos (límite inferior inválido)  →  400 esperado', async () => {
    const res = await request(app)
      .post('/api/Cards')
      .set(authHeader)
      .send({
        fullName: 'Santiago Castaño',
        cardNum: 999999999999999,
        expMonth: 12,
        expYear: 2080
      })
    // RF07: una tarjeta de 15 dígitos se debe rechazar con 400 (error del cliente).
    assert.equal(res.status, 400,
      `Se esperaba 400 para 15 dígitos y se obtuvo ${res.status}`)
  })
})

/* ─────────────────────────────────────────────────────────────────────────────
 * CP-A-03  RF08 – Recarga de billetera (Valores Límite)
 *   Valor dentro del rango  : $10 (límite inferior válido según RF08)  → 200
 *   Valor fuera del rango   : $9  (inferior al mínimo)                 → 400
 *
 * NOTA: el backend actual en routes/wallet.ts no impone validación de monto
 * mínimo ($10) a nivel de API; sólo verifica que exista la tarjeta. La regla
 * $10 es un criterio de aceptación documentado en el informe (RF08). Se
 * documenta el comportamiento real del sistema: $9 resulta en HTTP 200 (ausencia
 * de la validación), lo que se registra como DEF-P2-01.
 * ───────────────────────────────────────────────────────────────────────────── */
void describe('CP-A-03 | RF08 – Recarga de billetera (Valores Límite)', () => {
  let authHeader: { Authorization: string, 'content-type': string }
  let cardId: number

  before(async () => {
    const email = `wallet-tester-${Date.now()}@juice-sh.op`
    await request(app)
      .post('/api/Users')
      .set('content-type', 'application/json')
      .send({ email, password: 'Testpass1!', passwordRepeat: 'Testpass1!', securityQuestion: null, securityAnswer: null })
    const { token } = await login(app, { email, password: 'Testpass1!' })
    authHeader = { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }

    const cardRes = await request(app)
      .post('/api/Cards')
      .set(authHeader)
      .send({ fullName: 'Santiago Castaño', cardNum: 1000000000000000, expMonth: 12, expYear: 2080 })
    cardId = cardRes.body.data?.id
  })

  void it('PUT /rest/wallet/balance con $10 (límite inferior válido)  →  200', async () => {
    const res = await request(app)
      .put('/rest/wallet/balance')
      .set(authHeader)
      .send({ balance: 10, paymentId: cardId })
    assert.equal(res.status, 200,
      `Se esperaba 200 para balance=10, se obtuvo ${res.status}`)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })

  void it('PUT /rest/wallet/balance con $9 (inferior al mínimo)  →  400 esperado', { todo: 'DEF-P2-01 abierto: el backend acepta montos menores a $10' }, async () => {
    const res = await request(app)
      .put('/rest/wallet/balance')
      .set(authHeader)
      .send({ balance: 9, paymentId: cardId })
    // RF08: una recarga menor a $10 se debe rechazar con 400.
    // Mientras DEF-P2-01 siga abierto, este test falla y node:test lo muestra como TODO,
    // así se ve el defecto sin dejar la suite (ni el pipeline) en rojo.
    // Cuando se corrija el backend, quitar la opción todo.
    assert.equal(res.status, 400,
      `[DEF-P2-01] Se esperaba 400 para balance=9 y se obtuvo ${res.status}`)
  })
})

/* ─────────────────────────────────────────────────────────────────────────────
 * CP-A-04  RF01 – Formulario de registro (Tabla de Decisión)
 *   Regla 1: email válido + password coincide    → 201 Created
 *   Regla 2: email válido + password NO coincide → 400 / mensaje de error
 *
 * La tabla de decisión tiene 2 condiciones (email válido, passwords coinciden)
 * y cubre las reglas relevantes del formulario de registro.
 * ───────────────────────────────────────────────────────────────────────────── */
void describe('CP-A-04 | RF01 – Registro de usuario (Tabla de Decisión)', () => {
  void it('POST /api/Users con passwords iguales  →  201 Created', async () => {
    const email = `reg-match-${Date.now()}@juice-sh.op`
    const res = await request(app)
      .post('/api/Users')
      .set('content-type', 'application/json')
      .send({
        email,
        password: 'ValidPass1!',
        passwordRepeat: 'ValidPass1!',
        securityQuestion: null,
        securityAnswer: null
      })
    assert.equal(res.status, 201,
      `Se esperaba 201, se obtuvo ${res.status}: ${JSON.stringify(res.body)}`)
    assert.equal(res.body.data.email, email)
  })

  void it('POST /api/Users con passwords distintos  →  400 esperado', { todo: 'DEF-P2-02 abierto: la API no compara password y passwordRepeat' }, async () => {
    const email = `reg-mismatch-${Date.now()}@juice-sh.op`
    const res = await request(app)
      .post('/api/Users')
      .set('content-type', 'application/json')
      .send({
        email,
        password: 'ValidPass1!',
        passwordRepeat: 'DifferentPass2!',
        securityQuestion: null,
        securityAnswer: null
      })
    // RF01: si las contraseñas no coinciden, el registro se debe rechazar.
    // Mientras DEF-P2-02 siga abierto, este test falla y se muestra como TODO.
    // Cuando se corrija el backend, quitar la opción todo.
    assert.equal(res.status, 400,
      `[DEF-P2-02] Se esperaba 400 con passwords distintos y se obtuvo ${res.status}`)
  })
})

/* ─────────────────────────────────────────────────────────────────────────────
 * CP-A-05  RF02 – Autenticación e inspección de JWT (E2E/API)
 *   Escenario 1: credenciales correctas → 200, token JWT presente, payload válido
 *   Escenario 2: credenciales incorrectas → 401 Unauthorized
 * ───────────────────────────────────────────────────────────────────────────── */
void describe('CP-A-05 | RF02 – Inicio de sesión y validación de JWT', () => {
  const testEmail = `jwt-test-${Date.now()}@juice-sh.op`
  const testPass = 'JwtTest1!'

  before(async () => {
    await request(app)
      .post('/api/Users')
      .set('content-type', 'application/json')
      .send({
        email: testEmail,
        password: testPass,
        passwordRepeat: testPass,
        securityQuestion: null,
        securityAnswer: null
      })
  })

  void it('POST /rest/user/login con credenciales válidas  →  200 + token JWT con payload válido', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email: testEmail, password: testPass })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))

    const auth = res.body.authentication
    assert.ok(auth, 'El cuerpo debe contener authentication')
    assert.equal(typeof auth.token, 'string', 'El token debe ser un string')
    assert.ok(auth.token.length > 0, 'El token no debe estar vacío')
    assert.equal(typeof auth.bid, 'number', 'bid debe ser un número (basket id)')
    assert.equal(typeof auth.umail, 'string', 'umail debe ser un string')

    // Validar estructura del JWT (header.payload.signature)
    const parts = auth.token.split('.')
    assert.equal(parts.length, 3, 'El JWT debe tener 3 partes separadas por punto')

    // Decodificar payload y verificar campos clave
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    assert.ok(payload.data?.email, 'El payload debe contener data.email')
    assert.equal(payload.data.email, testEmail, 'El email en el payload debe coincidir')
    assert.ok(typeof payload.iat === 'number', 'El payload debe contener iat (issued at)')

    // NOTA: Juice Shop emite JWT sin claim 'exp' (sin expiración).
    // Esto es una vulnerabilidad de seguridad documentada (token no caduca).
    if (typeof payload.exp === 'undefined') {
      console.warn('[HALLAZGO-SEC-01] El JWT emitido por /rest/user/login no contiene claim "exp". El token no tiene expiración.')
    }
    // La ausencia de exp no impide el uso del token; el sistema sigue funcionando con él.
    assert.ok(typeof payload.iat === 'number', 'El payload debe contener iat')
  })

  void it('POST /rest/user/login con contraseña incorrecta  →  401 Unauthorized', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email: testEmail, password: 'WrongPassword!' })
    assert.equal(res.status, 401,
      `Se esperaba 401, se obtuvo ${res.status}`)
  })

  void it('POST /rest/user/login con credenciales vacías  →  401 Unauthorized', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email: '', password: '' })
    assert.equal(res.status, 401,
      `Se esperaba 401, se obtuvo ${res.status}`)
  })
})
