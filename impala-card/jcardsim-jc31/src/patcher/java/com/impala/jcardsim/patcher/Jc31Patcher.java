package com.impala.jcardsim.patcher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Unpacks a jcardsim jar (JavaCard 3.0.5 API) and makes the changes the
 * simulated platform in this module needs. Two kinds:
 *
 * <p><b>API that jcardsim does not have</b> (JavaCard 3.1 and 3.2 EdDSA):</p>
 * <ul>
 *   <li>{@code javacard.security.KeyBuilder} gains {@code TYPE_XEC},
 *       {@code ATTR_PUBLIC}, {@code ATTR_PRIVATE} and {@code buildXECKey},
 *       which calls {@code Jc31.buildXecKey};</li>
 *   <li>{@code javacard.security.Signature} gains the JavaCard 3.1 constants
 *       {@code SIG_CIPHER_EDDSA} and {@code SIG_CIPHER_EDDSAPH} and the
 *       JavaCard 3.2 ones ({@code SIG_CIPHER_EDDSA_ED25519},
 *       {@code SIG_CIPHER_EDDSA_ED448}, {@code SIG_CIPHER_EDDSAPH_ED25519},
 *       {@code SIG_CIPHER_EDDSAPH_ED448});</li>
 *   <li>{@code javacard.security.KeyPair} is left out: this module supplies it
 *       as source (it also accepts XEC keys).</li>
 * </ul>
 *
 * <p><b>Factory methods a card's platform must be asked about</b>
 * ({@code CardPlatform}: not every card has every algorithm, or the memory).
 * Each is kept under the name {@code jcardsim<Name>} and replaced by one that
 * calls the hook in {@code Jc31}, which refuses or falls through to the
 * original:</p>
 * <ul>
 *   <li>{@code Signature.getInstance(byte, byte, byte, boolean)};</li>
 *   <li>{@code KeyAgreement.getInstance(byte, boolean)};</li>
 *   <li>{@code MessageDigest.getInstance(byte, boolean)};</li>
 *   <li>{@code KeyBuilder.buildKey(byte, short, boolean)};</li>
 *   <li>{@code JCSystem.makeTransientByteArray}, {@code ShortArray},
 *       {@code BooleanArray} and {@code ObjectArray}.</li>
 * </ul>
 *
 * Everything else is copied byte for byte. The patcher fails, rather than
 * guess, when a class does not look the way it expects.
 *
 * <p>Usage: {@code Jc31Patcher <jcardsim.jar> <output directory>}</p>
 */
public final class Jc31Patcher {
    private static final String KEY_BUILDER = "javacard/security/KeyBuilder.class";
    private static final String SIGNATURE = "javacard/security/Signature.class";
    private static final String KEY_AGREEMENT = "javacard/security/KeyAgreement.class";
    private static final String MESSAGE_DIGEST = "javacard/security/MessageDigest.class";
    private static final String JC_SYSTEM = "javacard/framework/JCSystem.class";
    private static final String KEY_PAIR = "javacard/security/KeyPair.class";
    private static final String HOOKS = "com/impala/jcardsim/jc31/Jc31";

    private static final String BUILD_XEC_DESC =
            "(Ljavacard/security/NamedParameterSpec;SZ)Ljavacard/security/Key;";
    private static final String GET_INSTANCE_DESC = "(BBBZ)Ljavacard/security/Signature;";
    private static final String[] CRYPTO_EXCEPTION = {"javacard/security/CryptoException"};
    private static final int CONSTANT = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL;

    /** A static factory to route through a hook: the class file, the method, its descriptor and the hook's name. */
    private static final class Hook {
        final String method;
        final String descriptor;
        final String hook;

        Hook(String method, String descriptor, String hook) {
            this.method = method;
            this.descriptor = descriptor;
            this.hook = hook;
        }

        /** {@code getInstance} is kept as {@code jcardsimGetInstance}. */
        String kept() {
            return "jcardsim" + Character.toUpperCase(method.charAt(0)) + method.substring(1);
        }
    }

    private Jc31Patcher() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: Jc31Patcher <jcardsim.jar> <output directory>");
        }
        Path out = Paths.get(args[1]);
        boolean keyBuilder = false;
        boolean signature = false;
        boolean keyAgreement = false;
        boolean messageDigest = false;
        boolean jcSystem = false;
        boolean keyPair = false;
        try (ZipFile jar = new ZipFile(args[0])) {
            Enumeration<? extends ZipEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() || skipped(name)) {
                    continue;
                }
                if (name.equals(KEY_PAIR)) {
                    keyPair = true;
                    continue;
                }
                byte[] bytes = read(jar, entry);
                if (name.equals(KEY_BUILDER)) {
                    bytes = patchKeyBuilder(bytes);
                    keyBuilder = true;
                } else if (name.equals(SIGNATURE)) {
                    bytes = patchSignature(bytes);
                    signature = true;
                } else if (name.equals(KEY_AGREEMENT)) {
                    bytes = route(bytes, new Hook("getInstance", "(BZ)Ljavacard/security/KeyAgreement;", "keyAgreement"));
                    keyAgreement = true;
                } else if (name.equals(MESSAGE_DIGEST)) {
                    bytes = route(bytes, new Hook("getInstance", "(BZ)Ljavacard/security/MessageDigest;", "messageDigest"));
                    messageDigest = true;
                } else if (name.equals(JC_SYSTEM)) {
                    bytes = route(bytes,
                            new Hook("makeTransientByteArray", "(SB)[B", "transientByteArray"),
                            new Hook("makeTransientShortArray", "(SB)[S", "transientShortArray"),
                            new Hook("makeTransientBooleanArray", "(SB)[Z", "transientBooleanArray"),
                            new Hook("makeTransientObjectArray", "(SB)[Ljava/lang/Object;", "transientObjectArray"));
                    jcSystem = true;
                }
                Path target = out.resolve(name).normalize();
                if (!target.startsWith(out)) {
                    throw new IOException("entry escapes the output directory: " + name);
                }
                Files.createDirectories(target.getParent());
                Files.write(target, bytes);
            }
        }
        if (!keyBuilder || !signature || !keyAgreement || !messageDigest || !jcSystem || !keyPair) {
            throw new IllegalStateException("not the jcardsim jar this patcher knows: KeyBuilder="
                    + keyBuilder + " Signature=" + signature + " KeyAgreement=" + keyAgreement
                    + " MessageDigest=" + messageDigest + " JCSystem=" + jcSystem + " KeyPair=" + keyPair);
        }
    }

    /**
     * Routes static factory methods of one class through their hooks: each
     * original is renamed to {@link Hook#kept()} and a method of the original
     * name, signature and access is added that passes its arguments to the
     * hook and returns what the hook returns. Fails if a method is missing.
     */
    static byte[] route(byte[] original, Hook... hooks) {
        ClassReader reader = new ClassReader(original);
        ClassWriter writer = new ClassWriter(reader, 0);
        final int[] access = new int[hooks.length];
        final String[][] thrown = new String[hooks.length][];
        final boolean[] found = new boolean[hooks.length];
        reader.accept(new ClassVisitor(Opcodes.ASM7, writer) {
            @Override
            public MethodVisitor visitMethod(int methodAccess, String name, String descriptor,
                    String signature, String[] exceptions) {
                for (int i = 0; i < hooks.length; i++) {
                    if (name.equals(hooks[i].kept())) {
                        throw new IllegalStateException("already routed: " + name);
                    }
                    if (name.equals(hooks[i].method) && descriptor.equals(hooks[i].descriptor)) {
                        if ((methodAccess & Opcodes.ACC_STATIC) == 0) {
                            throw new IllegalStateException(name + descriptor + " is not static");
                        }
                        found[i] = true;
                        access[i] = methodAccess;
                        thrown[i] = exceptions;
                        return super.visitMethod(methodAccess, hooks[i].kept(), descriptor, signature, exceptions);
                    }
                }
                return super.visitMethod(methodAccess, name, descriptor, signature, exceptions);
            }

            @Override
            public void visitEnd() {
                for (int i = 0; i < hooks.length; i++) {
                    if (!found[i]) {
                        throw new IllegalStateException("no static " + hooks[i].method + hooks[i].descriptor);
                    }
                    MethodVisitor mv = super.visitMethod(access[i], hooks[i].method, hooks[i].descriptor,
                            null, thrown[i]);
                    mv.visitCode();
                    int slots = loadArguments(mv, hooks[i].descriptor);
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, hooks[i].hook, hooks[i].descriptor, false);
                    mv.visitInsn(Opcodes.ARETURN);
                    mv.visitMaxs(Math.max(slots, 1), slots);
                    mv.visitEnd();
                }
                super.visitEnd();
            }
        }, 0);
        return writer.toByteArray();
    }

    /** Pushes the arguments of a static method whose parameters are all byte, short or boolean; returns their count. */
    private static int loadArguments(MethodVisitor mv, String descriptor) {
        String parameters = descriptor.substring(1, descriptor.indexOf(')'));
        for (int i = 0; i < parameters.length(); i++) {
            char type = parameters.charAt(i);
            if (type != 'B' && type != 'S' && type != 'Z') {
                throw new IllegalStateException("unexpected parameter type in " + descriptor);
            }
            mv.visitVarInsn(Opcodes.ILOAD, i);
        }
        return parameters.length();
    }

    /** The manifest and the Maven descriptors describe the original jar, not this copy. */
    private static boolean skipped(String name) {
        return name.equals("META-INF/MANIFEST.MF") || name.startsWith("META-INF/maven/");
    }

    private static byte[] read(ZipFile jar, ZipEntry entry) throws IOException {
        try (InputStream in = jar.getInputStream(entry)) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            for (int n = in.read(chunk); n >= 0; n = in.read(chunk)) {
                buffer.write(chunk, 0, n);
            }
            return buffer.toByteArray();
        }
    }

    static byte[] patchKeyBuilder(byte[] original) {
        original = route(original, new Hook("buildKey", "(BSZ)Ljavacard/security/Key;", "buildKey"));
        ClassReader reader = new ClassReader(original);
        ClassWriter writer = new ClassWriter(reader, 0);
        reader.accept(new ClassVisitor(Opcodes.ASM7, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                    String signature, String[] exceptions) {
                if (name.equals("buildXECKey")) {
                    throw new IllegalStateException("KeyBuilder already has buildXECKey");
                }
                return super.visitMethod(access, name, descriptor, signature, exceptions);
            }

            @Override
            public void visitEnd() {
                constant("TYPE_XEC", "B", -1);
                constant("ATTR_PUBLIC", "S", 0);
                constant("ATTR_PRIVATE", "S", -32768);
                MethodVisitor mv = super.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                        "buildXECKey", BUILD_XEC_DESC, null, CRYPTO_EXCEPTION);
                mv.visitCode();
                mv.visitVarInsn(Opcodes.ALOAD, 0);
                mv.visitVarInsn(Opcodes.ILOAD, 1);
                mv.visitVarInsn(Opcodes.ILOAD, 2);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "buildXecKey", BUILD_XEC_DESC, false);
                mv.visitInsn(Opcodes.ARETURN);
                mv.visitMaxs(3, 3);
                mv.visitEnd();
                super.visitEnd();
            }

            private void constant(String name, String descriptor, int value) {
                super.visitField(CONSTANT, name, descriptor, null, Integer.valueOf(value)).visitEnd();
            }
        }, 0);
        return writer.toByteArray();
    }

    static byte[] patchSignature(byte[] original) {
        ClassReader reader = new ClassReader(original);
        ClassWriter writer = new ClassWriter(reader, 0);
        final boolean[] renamed = {false};
        reader.accept(new ClassVisitor(Opcodes.ASM7, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                    String signature, String[] exceptions) {
                if (name.equals("getInstance") && descriptor.equals(GET_INSTANCE_DESC)) {
                    renamed[0] = true;
                    return super.visitMethod(access, "jcardsimGetInstance", descriptor, signature, exceptions);
                }
                return super.visitMethod(access, name, descriptor, signature, exceptions);
            }

            @Override
            public void visitEnd() {
                if (!renamed[0]) {
                    throw new IllegalStateException("Signature has no getInstance(byte, byte, byte, boolean)");
                }
                super.visitField(CONSTANT, "SIG_CIPHER_EDDSA", "B", null, Integer.valueOf(13)).visitEnd();
                super.visitField(CONSTANT, "SIG_CIPHER_EDDSAPH", "B", null, Integer.valueOf(14)).visitEnd();
                // JavaCard 3.2: the per-curve ciphers.
                super.visitField(CONSTANT, "SIG_CIPHER_EDDSA_ED25519", "B", null, Integer.valueOf(15)).visitEnd();
                super.visitField(CONSTANT, "SIG_CIPHER_EDDSA_ED448", "B", null, Integer.valueOf(16)).visitEnd();
                super.visitField(CONSTANT, "SIG_CIPHER_EDDSAPH_ED25519", "B", null, Integer.valueOf(17)).visitEnd();
                super.visitField(CONSTANT, "SIG_CIPHER_EDDSAPH_ED448", "B", null, Integer.valueOf(18)).visitEnd();
                MethodVisitor mv = super.visitMethod(CONSTANT, "getInstance", GET_INSTANCE_DESC,
                        null, CRYPTO_EXCEPTION);
                mv.visitCode();
                mv.visitVarInsn(Opcodes.ILOAD, 0);
                mv.visitVarInsn(Opcodes.ILOAD, 1);
                mv.visitVarInsn(Opcodes.ILOAD, 2);
                mv.visitVarInsn(Opcodes.ILOAD, 3);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "signature", GET_INSTANCE_DESC, false);
                mv.visitInsn(Opcodes.ARETURN);
                mv.visitMaxs(4, 4);
                mv.visitEnd();
                super.visitEnd();
            }
        }, 0);
        return writer.toByteArray();
    }
}
