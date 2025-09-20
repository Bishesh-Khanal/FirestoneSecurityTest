const { initializeTestEnvironment } = require('@firebase/rules-unit-testing');
const fs = require('fs');

const projectId = 'firestonesecuritytest';
let testEnv;

beforeAll(async () => {
  testEnv = await initializeTestEnvironment({
    projectId,
    firestore: {
      host: 'localhost',
      port: 8080,
      rules: fs.readFileSync('firestore.rules', 'utf8'),
    },
  });
});

afterAll(async () => {
  await testEnv.cleanup();
});

describe('Firestore Security Rules -', () => {

  it('User can read/write their own document', async () => {
    const alice = testEnv.authenticatedContext('alice');
    const db = alice.firestore();
    const docRef = db.collection('users').doc('alice');

    await expect(docRef.set({ name: 'Alice' })).resolves.toBeUndefined();
    await expect(docRef.get()).resolves.toHaveProperty('exists', true);
  });

  it('User cannot read another user\'s document', async () => {
    const bob = testEnv.authenticatedContext('bob');
    const db = bob.firestore();
    const docRef = db.collection('users').doc('alice');

    await expect(docRef.get()).rejects.toThrow(/false for 'get'/);
  });

  it('Unauthenticated user cannot write', async () => {
    const anon = testEnv.unauthenticatedContext();
    const db = anon.firestore();
    const docRef = db.collection('users').doc('anon');

    await expect(docRef.set({ name: 'Anon' })).rejects.toThrow(/false for 'create'/);
  });

  it('Authenticated user can read posts but only update own post', async () => {
    const alice = testEnv.authenticatedContext('alice');
    const bob = testEnv.authenticatedContext('bob');

    const postRefAlice = alice.firestore().collection('posts').doc('post1');
    const postRefBob = bob.firestore().collection('posts').doc('post1');

    await expect(postRefAlice.set({ title: 'Hello', authorId: 'alice' })).resolves.toBeUndefined();

    await expect(postRefBob.update({ title: 'Hack' })).rejects.toThrow(/false for 'update'/);

    await expect(postRefAlice.get()).resolves.toHaveProperty('exists', true);
    await expect(postRefAlice.get()).resolves.toHaveProperty('data');
  });

  it('Automated XSS-style input scan', async () => {
    const alice = testEnv.authenticatedContext('alice');
    const db = alice.firestore();
    const docRef = db.collection('users').doc('alice');

    const xssPayloads = [
      '<script>alert("XSS1")</script>',
      '" onerror="alert(\'XSS2\')"',
      "<img src=x onerror=alert('XSS3')>",
      "';alert('XSS4');//",
      "<svg onload=alert('XSS5')>"
    ];

    for (const payload of xssPayloads) {
      await expect(docRef.set({ bio: payload })).resolves.toBeUndefined();
      const snapshot = await docRef.get();
      expect(snapshot.data().bio).toBe(payload);
    }
  });

});