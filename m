Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX4RRHUAKGQE23WMSQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id CF3A643625
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 15:00:16 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id v4sf16501964qkj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 06:00:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560430816; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q3nQjRoTaEHyo6lKavgGyKwnGVWtBimELii+rgm0UrI/l0QX0VQSqsJS9X7mJeLbe2
         7wGa2nTFUPAcnZgCy8g8FZFDk2LdXv500kxwGeyvKmlYlWBawlOD5Pmxg7NVTUeUN0as
         1jkHCq40dvW5Av4zTz02dgrT1O1PemxC5tRydLXQHyz5JNDCQjpGN9oGfwAszC3SpeIg
         +B0l6NCTYkM643hkhg6TWB6WgPHNeYKD4WQvTj/ASruJ1vcEUsqtlE5Bi8AlssqXDVgd
         QFhgu+9ZgfzN4f23cUpj11vXQvfnBm4r0hGh2tazs3cQ/mlKuQ6KowBQmqT/5xpewjHx
         UHLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=PViPpblKvDSwtSARb4lLkpfIH8F0ah77TO72OtJWy9g=;
        b=onky/8UpqNL1o5KDpNz/nzKwpHv0SYSLX5nv11heOjsEOMcBP52Ysqzf+kjKqex+R3
         j38xw9W7WDxl2nHBKEcnNYW9UzZf2OZOnVnT6D4xAAYG70Hf0VeTHtetqnww1JrWmRdw
         4MuWOu8Qph1FqYi+T+/1mJWr4Gwzeowy3oL7KirDIpBKmi80e9Mhq5Gij2wq5gsijOul
         gXM4eLxn6BUOFchPp8IzQ3TEaVRncJJ64eOrUUJPLbIENjY98OpC1JD7tqefzf4cmEV1
         RShikoj8nPNuoL3Gl0A8z61Z7ckPoxkMuNQbD/TXjs0vXmqBdDhfBlM5/BLt+l4xPDgN
         Rd2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lRHdh83F;
       spf=pass (google.com: domain of 330gcxqukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=330gCXQUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PViPpblKvDSwtSARb4lLkpfIH8F0ah77TO72OtJWy9g=;
        b=npCzWQ45/Y8vYzv0gj3kFFBTxWwNwsmF49RL3GeVLF7i8fpkTxEOBnUKqxq5QNglIl
         bAH1oov5xK/pPNFIDNfk+yA43s2IZhdMelpZR8YGqbkjpeYXwq19lcrj1gj63mQT3msf
         qGQtOGeMWDCgdi2NmSEBdJ5jTJa6u1cPnbZmeFaBxjnasOjfF/lfbPZI1h/Ws4GLBTns
         dHa73Fj8QPulQCUX/znL/BztXlqdyI3M3D9C3AKhfn4GDvTY4GRci9LSJhsTOzkdt8gZ
         KB4jzKk80qKto4m2DEZFl6T9F6wLqdvK2UQWypVZ3iM+zd2rI4PEN0QLRtKUc5SPdXVG
         CShA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PViPpblKvDSwtSARb4lLkpfIH8F0ah77TO72OtJWy9g=;
        b=a4ftSM/ZIdB0BLeLBQqDV0Yd1S3Sjq4uksEHTkJID9sJjskF2N//F5JJ0AwiIjeb97
         E/LoBzb5OnxCTmWwr/PpZLZrx79MUyGGWKdvnjqRGKNK2RNZ45NmuodtKaGGAFDQtUrI
         WUbJjHVoFxcF6P5tJ2VopCRpeg+QbtWwCC/qQVKlk3rrKuvqIqzn/vZnSasWgqPgrTPI
         93Re+K9zvRmCLdJDcXC1eqgNmUIl8UMAnlqZtKPpz7+FQ8gdbPa8d7auiVdyXW2E+EfX
         v48da2C9rqoAArTh7HW5cC478kpEub4StVtJkFqDSUfbCiQgc1pftPmkblPdPyftvlA1
         KJBw==
X-Gm-Message-State: APjAAAWNyjE1HgndTbLECfXd9MFk8bWbpKpKsIBkRJ1XjKQSG0ZW0lL8
	5281+67ebZ1Hb2bSYtDq7wc=
X-Google-Smtp-Source: APXvYqzUhKWIaSXPtRfaprtPzcMocBCWgQeicfgzRhj7K78U9wQZuQ40BeRwxvLDuD1SZ414lgZ7qA==
X-Received: by 2002:ac8:2e6a:: with SMTP id s39mr72971937qta.201.1560430815909;
        Thu, 13 Jun 2019 06:00:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:34a8:: with SMTP id w37ls1459881qtb.13.gmail; Thu, 13
 Jun 2019 06:00:15 -0700 (PDT)
X-Received: by 2002:ac8:3637:: with SMTP id m52mr61597317qtb.238.1560430815525;
        Thu, 13 Jun 2019 06:00:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560430815; cv=none;
        d=google.com; s=arc-20160816;
        b=BP1ZogFNzQjHaAyy0iwFLM4YHmP+PEIKWF4AwdvFPOgbyy7D9+etlFHMUr/5e9JctA
         9VBlcQOdpKk+Dd1IvPsAfS6BXB6Ck2Tw+AJKj5gcncJ6uKXGZ9UFKAcIzRvoeZ8zaF4M
         6Ts2+/fefYdZDfDriAC1t5C53++li+4ahtECbaopgyEcl7dAQj/D51lSfQKThxuWVozL
         Y4rPE2X1+qabwETDrjpfI05k1/8VHQE2gcX0Cg0CJAtAugFYh3y02Sxc/VtBiBPkkr+C
         RmrbqzVCxir8ZBrPwNnrkK1AxtGzIrCsxticMlPD+fWDFbMJMN+Amrp/JH5uv9hhG+4k
         zjwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nTyT6z08CUm2wRhb0PBuVFW+TkegThF+CqD5j6KVtL0=;
        b=NDNIdFPfjn5lLeLJfuqFVXpq9cHbZZeRAXohrZ12g/WGUKSBrK54Q18/X1N5qdUO2+
         cuOFhrp2RtYu2fi+yc07gjBN/tBOEfKKRjgdgfU7559rQ3LcV+t/Ibso9VaWugHaiNUK
         QI4AUm3nspWgPkITQ0q2VNPIaVgePEKBaXQ2xMdXjn80b+CN90FjIog4sVieNbPzMuDG
         m/CSaqzrYHmtR6HytDyoZTBc9A0VOB8fhq/eJ8TaO66SrsjsZALDf0EWZkRgOUY30hTP
         rylkBG1rXbs/7GVqrFxMAMZFwnXqJ8QsNlruo2urOFWnPZ6Rkt/Z7btZcPNoTDY0Tg/H
         v6FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lRHdh83F;
       spf=pass (google.com: domain of 330gcxqukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=330gCXQUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa49.google.com (mail-vk1-xa49.google.com. [2607:f8b0:4864:20::a49])
        by gmr-mx.google.com with ESMTPS id 34si156082qtz.2.2019.06.13.06.00.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 06:00:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 330gcxqukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) client-ip=2607:f8b0:4864:20::a49;
Received: by mail-vk1-xa49.google.com with SMTP id x198so6307499vke.21
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 06:00:15 -0700 (PDT)
X-Received: by 2002:a1f:3141:: with SMTP id x62mr7521248vkx.12.1560430815021;
 Thu, 13 Jun 2019 06:00:15 -0700 (PDT)
Date: Thu, 13 Jun 2019 14:59:50 +0200
In-Reply-To: <20190613125950.197667-1-elver@google.com>
Message-Id: <20190613125950.197667-4-elver@google.com>
Mime-Version: 1.0
References: <20190613125950.197667-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc2.383.gf4fbbf30c2-goog
Subject: [PATCH v5 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lRHdh83F;       spf=pass
 (google.com: domain of 330gcxqukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=330gCXQUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

This adds a new header to asm-generic to allow optionally instrumenting
architecture-specific asm implementations of bitops.

This change includes the required change for x86 as reference and
changes the kernel API doc to point to bitops-instrumented.h instead.
Rationale: the functions in x86's bitops.h are no longer the kernel API
functions, but instead the arch_ prefixed functions, which are then
instrumented via bitops-instrumented.h.

Other architectures can similarly add support for asm implementations of
bitops.

The documentation text was derived from x86 and existing bitops
asm-generic versions: 1) references to x86 have been removed; 2) as a
result, some of the text had to be reworded for clarity and consistency.

Tested: using lib/test_kasan with bitops tests (pre-requisite patch).

Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
---
Changes in v3:
* Remove references to 'x86' in API documentation; as a result, had to
  reword doc text for clarify and consistency.
* Remove #ifdef, since it is assumed that if asm-generic bitops
  implementations are used, bitops-instrumented.h is not needed.

Changes in v2:
* Instrument word-sized accesses, as specified by the interface.
---
 Documentation/core-api/kernel-api.rst     |   2 +-
 arch/x86/include/asm/bitops.h             | 189 ++++------------
 include/asm-generic/bitops-instrumented.h | 263 ++++++++++++++++++++++
 3 files changed, 302 insertions(+), 152 deletions(-)
 create mode 100644 include/asm-generic/bitops-instrumented.h

diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
index a29c99d13331..65266fa1b706 100644
--- a/Documentation/core-api/kernel-api.rst
+++ b/Documentation/core-api/kernel-api.rst
@@ -51,7 +51,7 @@ The Linux kernel provides more basic utility functions.
 Bit Operations
 --------------
 
-.. kernel-doc:: arch/x86/include/asm/bitops.h
+.. kernel-doc:: include/asm-generic/bitops-instrumented.h
    :internal:
 
 Bitmap Operations
diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
index 8e790ec219a5..ba15d53c1ca7 100644
--- a/arch/x86/include/asm/bitops.h
+++ b/arch/x86/include/asm/bitops.h
@@ -49,23 +49,8 @@
 #define CONST_MASK_ADDR(nr, addr)	WBYTE_ADDR((void *)(addr) + ((nr)>>3))
 #define CONST_MASK(nr)			(1 << ((nr) & 7))
 
-/**
- * set_bit - Atomically set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * This function is atomic and may not be reordered.  See __set_bit()
- * if you do not require the atomic guarantees.
- *
- * Note: there are no guarantees that this function will not be reordered
- * on non x86 architectures, so if you are writing portable code,
- * make sure not to rely on its reordering guarantees.
- *
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
 static __always_inline void
-set_bit(long nr, volatile unsigned long *addr)
+arch_set_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "orb %1,%0"
@@ -78,32 +63,14 @@ set_bit(long nr, volatile unsigned long *addr)
 	}
 }
 
-/**
- * __set_bit - Set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * Unlike set_bit(), this function is non-atomic and may be reordered.
- * If it's called on the same region of memory simultaneously, the effect
- * may be that only one operation succeeds.
- */
-static __always_inline void __set_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___set_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(bts) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
 
-/**
- * clear_bit - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * clear_bit() is atomic and may not be reordered.  However, it does
- * not contain a memory barrier, so if it is used for locking purposes,
- * you should call smp_mb__before_atomic() and/or smp_mb__after_atomic()
- * in order to ensure changes are visible on other processors.
- */
 static __always_inline void
-clear_bit(long nr, volatile unsigned long *addr)
+arch_clear_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "andb %1,%0"
@@ -115,26 +82,21 @@ clear_bit(long nr, volatile unsigned long *addr)
 	}
 }
 
-/*
- * clear_bit_unlock - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * clear_bit() is atomic and implies release semantics before the memory
- * operation. It can be used for an unlock.
- */
-static __always_inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch_clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	barrier();
-	clear_bit(nr, addr);
+	arch_clear_bit(nr, addr);
 }
 
-static __always_inline void __clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___clear_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(btr) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
 
-static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
 	bool negative;
 	asm volatile(LOCK_PREFIX "andb %2,%1"
@@ -143,48 +105,23 @@ static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile
 		: "ir" ((char) ~(1 << nr)) : "memory");
 	return negative;
 }
+#define arch_clear_bit_unlock_is_negative_byte                                 \
+	arch_clear_bit_unlock_is_negative_byte
 
-// Let everybody know we have it
-#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
-
-/*
- * __clear_bit_unlock - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * __clear_bit() is non-atomic and implies release semantics before the memory
- * operation. It can be used for an unlock if no other CPUs can concurrently
- * modify other bits in the word.
- */
-static __always_inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
-	__clear_bit(nr, addr);
+	arch___clear_bit(nr, addr);
 }
 
-/**
- * __change_bit - Toggle a bit in memory
- * @nr: the bit to change
- * @addr: the address to start counting from
- *
- * Unlike change_bit(), this function is non-atomic and may be reordered.
- * If it's called on the same region of memory simultaneously, the effect
- * may be that only one operation succeeds.
- */
-static __always_inline void __change_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___change_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(btc) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
 
-/**
- * change_bit - Toggle a bit in memory
- * @nr: Bit to change
- * @addr: Address to start counting from
- *
- * change_bit() is atomic and may not be reordered.
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
-static __always_inline void change_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch_change_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "xorb %1,%0"
@@ -196,42 +133,20 @@ static __always_inline void change_bit(long nr, volatile unsigned long *addr)
 	}
 }
 
-/**
- * test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(bts), *addr, c, "Ir", nr);
 }
 
-/**
- * test_and_set_bit_lock - Set a bit and return its old value for lock
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This is the same as test_and_set_bit on x86.
- */
 static __always_inline bool
-test_and_set_bit_lock(long nr, volatile unsigned long *addr)
+arch_test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
-	return test_and_set_bit(nr, addr);
+	return arch_test_and_set_bit(nr, addr);
 }
 
-/**
- * __test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is non-atomic and can be reordered.
- * If two examples of this operation race, one can appear to succeed
- * but actually fail.  You must protect multiple accesses with a lock.
- */
-static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -242,28 +157,13 @@ static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *
 	return oldbit;
 }
 
-/**
- * test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btr), *addr, c, "Ir", nr);
 }
 
-/**
- * __test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is non-atomic and can be reordered.
- * If two examples of this operation race, one can appear to succeed
- * but actually fail.  You must protect multiple accesses with a lock.
- *
+/*
  * Note: the operation is performed atomically with respect to
  * the local CPU, but not other CPUs. Portable code should not
  * rely on this behaviour.
@@ -271,7 +171,8 @@ static __always_inline bool test_and_clear_bit(long nr, volatile unsigned long *
  * accessed from a hypervisor on the same CPU if running in a VM: don't change
  * this without also updating arch/x86/kernel/kvm.c
  */
-static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -282,8 +183,8 @@ static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long
 	return oldbit;
 }
 
-/* WARNING: non atomic and it can be reordered! */
-static __always_inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -295,15 +196,8 @@ static __always_inline bool __test_and_change_bit(long nr, volatile unsigned lon
 	return oldbit;
 }
 
-/**
- * test_and_change_bit - Change a bit and return its old value
- * @nr: Bit to change
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
 }
@@ -326,16 +220,7 @@ static __always_inline bool variable_test_bit(long nr, volatile const unsigned l
 	return oldbit;
 }
 
-#if 0 /* Fool kernel-doc since it doesn't do macros yet */
-/**
- * test_bit - Determine whether a bit is set
- * @nr: bit number to test
- * @addr: Address to start counting from
- */
-static bool test_bit(int nr, const volatile unsigned long *addr);
-#endif
-
-#define test_bit(nr, addr)			\
+#define arch_test_bit(nr, addr)			\
 	(__builtin_constant_p((nr))		\
 	 ? constant_test_bit((nr), (addr))	\
 	 : variable_test_bit((nr), (addr)))
@@ -504,6 +389,8 @@ static __always_inline int fls64(__u64 x)
 
 #include <asm-generic/bitops/const_hweight.h>
 
+#include <asm-generic/bitops-instrumented.h>
+
 #include <asm-generic/bitops/le.h>
 
 #include <asm-generic/bitops/ext2-atomic-setbit.h>
diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
new file mode 100644
index 000000000000..ddd1c6d9d8db
--- /dev/null
+++ b/include/asm-generic/bitops-instrumented.h
@@ -0,0 +1,263 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for bit
+ * operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.).
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
+
+#include <linux/kasan-checks.h>
+
+/**
+ * set_bit - Atomically set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ *
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_set_bit(nr, addr);
+}
+
+/**
+ * __set_bit - Set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * Unlike set_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___set_bit(nr, addr);
+}
+
+/**
+ * clear_bit - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ */
+static inline void clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_clear_bit(nr, addr);
+}
+
+/**
+ * __clear_bit - Clears a bit in memory
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * Unlike clear_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit(nr, addr);
+}
+
+/**
+ * clear_bit_unlock - Clear a bit in memory, for unlock
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * This operation is atomic and provides release barrier semantics.
+ */
+static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_clear_bit_unlock(nr, addr);
+}
+
+/**
+ * __clear_bit_unlock - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * This is a non-atomic operation but implies a release barrier before the
+ * memory operation. It can be used for an unlock if no other CPUs can
+ * concurrently modify other bits in the word.
+ */
+static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit_unlock(nr, addr);
+}
+
+/**
+ * change_bit - Toggle a bit in memory
+ * @nr: Bit to change
+ * @addr: Address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ *
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_change_bit(nr, addr);
+}
+
+/**
+ * __change_bit - Toggle a bit in memory
+ * @nr: the bit to change
+ * @addr: the address to start counting from
+ *
+ * Unlike change_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___change_bit(nr, addr);
+}
+
+/**
+ * test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_set_bit(nr, addr);
+}
+
+/**
+ * __test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_set_bit(nr, addr);
+}
+
+/**
+ * test_and_set_bit_lock - Set a bit and return its old value, for lock
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is atomic and provides acquire barrier semantics if
+ * the returned value is 0.
+ * It can be used to implement bit locks.
+ */
+static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_set_bit_lock(nr, addr);
+}
+
+/**
+ * test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_clear_bit(nr, addr);
+}
+
+/**
+ * __test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_clear_bit(nr, addr);
+}
+
+/**
+ * test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_change_bit(nr, addr);
+}
+
+/**
+ * __test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_change_bit(nr, addr);
+}
+
+/**
+ * test_bit - Determine whether a bit is set
+ * @nr: bit number to test
+ * @addr: Address to start counting from
+ */
+static inline bool test_bit(long nr, const volatile unsigned long *addr)
+{
+	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_bit(nr, addr);
+}
+
+#if defined(arch_clear_bit_unlock_is_negative_byte)
+/**
+ * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
+ *                                     byte is negative, for unlock.
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * This operation is atomic and provides release barrier semantics.
+ *
+ * This is a bit of a one-trick-pony for the filemap code, which clears
+ * PG_locked and tests PG_waiters,
+ */
+static inline bool
+clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
+}
+/* Let everybody know we have it. */
+#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
+#endif
+
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
-- 
2.22.0.rc2.383.gf4fbbf30c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613125950.197667-4-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
