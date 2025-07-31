Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYFRVXCAMGQEGMLDTKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 693D4B170A1
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:52:02 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-3322b98b1a6sf1762771fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:52:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962722; cv=pass;
        d=google.com; s=arc-20240605;
        b=ajC2spY3kEZ63TSy4/hAS5ZAJet0bFfeRbNZd+lSPe/9wbKBDkPxViZpN9P4wuVcCp
         anZRkmEtRGuLJN6obXGNoy0jznuyAsQzouHUBlmR4SJuFbVAi+3NjGTbr4EqoggiLkQ5
         sVlzkNaW2X2lnu5RidFZyRfqCbaBSKUupCMvdN1Js7q9CkHyYfT0WXssyvPhxF4dk+uG
         QIuj7hqLvhTU0uaX9cm0gw/M+ax1je0z+8rkxB6v/5bEr9GjW47En4RymsbV1uaKlng5
         T5y8vUEG157mb5yqOOixm+XzifxLvl1qlf9r9nFKeUsvL/ALKk/dB6VZMFG+1N9ymg9g
         /P1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=DsEc5TdbUsHhj7amckY6ofRzy19CaCYhFNE1CJIyJjo=;
        fh=k71mhawUP6wrg6tHhnbfG6eYoy9vHbEp+E6Bk5LBm0U=;
        b=NP36QskbcdRguQx6zguS926Bltllq8a+U5SPEZsIsANch2SU7a4VyZbsGf7l88lVFF
         EcBsY2Cod7Z8zLYWO6wpXiuYgi//W2wx/QLhczS2lsc+Dx2QonYbQ8ekO5tRia1Aje6h
         IkduM7SO+rL7ZplWldaWTa4Nc5pBdsldeVW62LqfbaomYt+eZAKsjRYYrGTtcIRsPxg0
         ZlLVvJm9N61BrKzJWj+tFq9I0CRYqXqcYRQNf1437p5EUc8o99Q4qilY9n4KOfHE/B62
         1d7kEycfGgKP6dlKYDpfFRAeE+zN5QYXzI5GlcDLGA6C1vO6GA+1ZqmOvdmipKCs2cLx
         y3eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0IzCJN3q;
       spf=pass (google.com: domain of 33vilaaykcqgotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33ViLaAYKCQgotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962722; x=1754567522; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DsEc5TdbUsHhj7amckY6ofRzy19CaCYhFNE1CJIyJjo=;
        b=AOCKCQtUCWCUS+1Aub03kSbOIQaM7Z1x34+SK593r6BhGsvzFy+SpYFvy98w4U11yT
         Vewhl+k5iYK3bLfXZ67VS0KboQTMtBXPGysaEAWCi0ghNQnnEgC1kNhq39Ksbo28cq5V
         XAD/7NkrL6Y1gDYhBy2mjPmaI/ZyYs/BhqvQ8R1/zEIbQfdPB7vsavxX3gFBhVoWWUgh
         J76va4bwdoHmst15S65dJ8dk+sbKsJBT3mUH91Qdk0TPZuKCrn4iPMbqC42AGc3HMTgo
         fgADfopWwUkZ0ZJltWRK0HDCG37ui2C4cEivmpTbM0I09d0XFEXs1F114u4tGYT4bgRq
         75nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962722; x=1754567522;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DsEc5TdbUsHhj7amckY6ofRzy19CaCYhFNE1CJIyJjo=;
        b=l++Az0eLr/x03Rcp9Tfm4lLnD6hyDMumw1O3g0LanbIxnfEQk80vq/V8Sz9+B+JxxN
         f1XVWcRKBSLQa9ECkZkMr+oBlUK9mBr9hNmkenkUwF2S95zvk6EEic32RcdUHfdyNmuX
         Z9Fgvdh8BLixqXqRFyV96kbMSOuAjDXbndCS8k/Zv9WkxzR8Is31ZHODPtEve1LVqh8S
         pBOAok9iW5oxWOh+kY6GD/Ds+rsadltJRtHhjV/qcbWYVz8BejP+srNcZEVN1Mhg+TEj
         HmkDalHofxKUwjIEkt4NgJchNqHopdt6nt0E2LFloFYVwj2nPyKPr3s0f0nysHRNl+mt
         Kz6g==
X-Forwarded-Encrypted: i=2; AJvYcCXBMjryoJgneUg6KMD23N2shUOyDUIAodLd7zCjl5/CCRbENNHoX4jwmeeukHgXPy+mdXkq6g==@lfdr.de
X-Gm-Message-State: AOJu0YxLIDznXYNtaePLm6Trh0RqQcvQ77fUwfH7oJtVZMqsT6XamkmS
	n09H82vlQb0+RRI3Lt9/67VS117Fd7OwcAXJlnpI58mbIGiFsoLMH03E
X-Google-Smtp-Source: AGHT+IFilqm9EWmgFJBKk7KNReM1apXhNekzcfc2iGI8U+i6dCPfumAdBZ1zmLKLLbv24Gc91LEtzQ==
X-Received: by 2002:a05:651c:4187:b0:32a:7951:554 with SMTP id 38308e7fff4ca-33224a9b771mr22000201fa.11.1753962721590;
        Thu, 31 Jul 2025 04:52:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeSqj0nJVOrxK7plcBdMeOT4glb35wFc5RhYHIMXWWR/Q==
Received: by 2002:a2e:602:0:b0:331:e5a8:6292 with SMTP id 38308e7fff4ca-332381f7a4bls1024201fa.0.-pod-prod-04-eu;
 Thu, 31 Jul 2025 04:51:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVa6JJKZjTo8RqfsfzT8L2v1VQRYka9Ssw2lIKuZUvNxW79e4DW1ASLzq8rMdm2Nqav2nBsrPQak0c=@googlegroups.com
X-Received: by 2002:a2e:bc07:0:b0:32b:3cf5:7358 with SMTP id 38308e7fff4ca-33224bd34f9mr26943961fa.28.1753962718580;
        Thu, 31 Jul 2025 04:51:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962718; cv=none;
        d=google.com; s=arc-20240605;
        b=BnO03ilFEY4Z/yMSGcrpD8mekmYxebyhAVDyx/PKum2JwwU6Cj5CLBCCJLEgP/KyMG
         mPU/WVKVTVD+eWbLjccxsQJX1q4XsepPrR+XfwYyKBXKV+EGGmAxHcAo2ZvlEwZ+iNt3
         XmHHHictAnN6YUFH1rpDP0AGXD8K5UTtzqbMh3nbFJGxAtJ+EHh7bYUIkXNHOIz7yrym
         8MV6QxKI8tP9TyU2uB2QU9Buw9CRXeyXVt+W2Idtnq2p20sNIQzLkxmZqLwgH0SA9cTn
         t2rYbpw9l0fZUdGnBKdAqSqQ0c8+PbydS6ettr4alW83UmStXtk5jBM5aelugHZA0EFn
         sKBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fr3wdyxx9nf1qL2KhZS1xwKvuRnArjYIvI1lmTgg9P0=;
        fh=PFip/dFR5O5/s+C+VcMjtdNJd5T5OvkzZCNzlF7Th6U=;
        b=Rjrxm7ABTSy0jIggKkW+dDCV6hxFsVRE03R5TtvpCcMxVUVzWcUCAPQKxmSgtWq5Y2
         E5ygNfBdd+ugDmnC96gUL4hrDo5BVOzIUw+bLCw1AqGSDXs9rxjeCpwVZxMBgmhI2917
         L/MiLgiNRn05QnShItKrWIRPXGXwr0B3xb41OpZ7/HPGNjDwD7yEaWsHqoDG82JI2wbm
         5yCqlhoRGxbNucdqjaGO2x858qWsB/hKSyemId56MMcVS6KJv8f9bJNYGLWc56EDQOlT
         M/wcBHF6OlqYz6Ist9Y/X22KQnjLcw9r2zjwFFKvD/3RQsPzL5UvQ+lV2cYOXFQghM1n
         lr+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0IzCJN3q;
       spf=pass (google.com: domain of 33vilaaykcqgotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33ViLaAYKCQgotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-33237fffb5fsi409451fa.4.2025.07.31.04.51.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:51:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33vilaaykcqgotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ae0a3511145so73126666b.3
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:51:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOEwNFxMbFuUrz+bgjS07UoE5g684vvOsje1rD+lDpxhxkp+YCwzlmD0S8J0LG7XHxb4dNXype8Cs=@googlegroups.com
X-Received: from edj19.prod.google.com ([2002:a05:6402:3253:b0:615:979:8d80])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:2689:b0:ae3:6cc8:e431
 with SMTP id a640c23a62f3a-af8fda6fb17mr960236966b.57.1753962717188; Thu, 31
 Jul 2025 04:51:57 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:34 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-6-glider@google.com>
Subject: [PATCH v4 05/10] kcov: x86: introduce CONFIG_KCOV_UNIQUE
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=0IzCJN3q;       spf=pass
 (google.com: domain of 33vilaaykcqgotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33ViLaAYKCQgotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

The new config switches coverage instrumentation to using
  __sanitizer_cov_trace_pc_guard(u32 *guard)
instead of
  __sanitizer_cov_trace_pc(void)

This relies on Clang's -fsanitize-coverage=trace-pc-guard flag [1].

Each callback receives a unique 32-bit guard variable residing in .bss.
Those guards can be used by kcov to deduplicate the coverage on the fly.

As a first step, we make the new instrumentation mode 1:1 compatible
with the old one.

[1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards

Cc: x86@kernel.org
Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v4:
 - add Reviewed-by: Dmitry Vyukov

v3:
 - per Dmitry Vyukov's request, add better comments in
   scripts/module.lds.S and lib/Kconfig.debug
 - add -sanitizer-coverage-drop-ctors to scripts/Makefile.kcov
   to drop the unwanted constructors emitting unsupported relocations
 - merge the __sancov_guards section into .bss

v2:
 - Address comments by Dmitry Vyukov
   - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
   - update commit description and config description
 - Address comments by Marco Elver
   - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
   - make config depend on X86_64 (via ARCH_HAS_KCOV_UNIQUE)
   - swap #ifdef branches
   - tweak config description
   - remove redundant check for CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD

Change-Id: Iacb1e71fd061a82c2acadf2347bba4863b9aec39
---
 arch/x86/Kconfig                  |  1 +
 arch/x86/kernel/vmlinux.lds.S     |  1 +
 include/asm-generic/vmlinux.lds.h | 13 ++++++-
 include/linux/kcov.h              |  2 +
 kernel/kcov.c                     | 61 +++++++++++++++++++++----------
 lib/Kconfig.debug                 | 26 +++++++++++++
 scripts/Makefile.kcov             |  7 ++++
 scripts/module.lds.S              | 35 ++++++++++++++++++
 tools/objtool/check.c             |  1 +
 9 files changed, 126 insertions(+), 21 deletions(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 8bed9030ad473..0533070d24fe7 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -94,6 +94,7 @@ config X86
 	select ARCH_HAS_FORTIFY_SOURCE
 	select ARCH_HAS_GCOV_PROFILE_ALL
 	select ARCH_HAS_KCOV			if X86_64
+	select ARCH_HAS_KCOV_UNIQUE		if X86_64
 	select ARCH_HAS_KERNEL_FPU_SUPPORT
 	select ARCH_HAS_MEM_ENCRYPT
 	select ARCH_HAS_MEMBARRIER_SYNC_CORE
diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index 4fa0be732af10..52fe6539b9c91 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -372,6 +372,7 @@ SECTIONS
 		. = ALIGN(PAGE_SIZE);
 		*(BSS_MAIN)
 		BSS_DECRYPTED
+		BSS_SANCOV_GUARDS
 		. = ALIGN(PAGE_SIZE);
 		__bss_stop = .;
 	}
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index fa5f19b8d53a0..ee78328eecade 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -102,7 +102,8 @@
  * sections to be brought in with rodata.
  */
 #if defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || defined(CONFIG_LTO_CLANG) || \
-defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
+	defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG) || \
+	defined(CONFIG_KCOV_UNIQUE)
 #define TEXT_MAIN .text .text.[0-9a-zA-Z_]*
 #else
 #define TEXT_MAIN .text
@@ -121,6 +122,16 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 #define SBSS_MAIN .sbss
 #endif
 
+#if defined(CONFIG_KCOV_UNIQUE)
+/* BSS_SANCOV_GUARDS must be part of the .bss section so that it is zero-initialized. */
+#define BSS_SANCOV_GUARDS			\
+	__start___sancov_guards = .;		\
+	*(__sancov_guards);			\
+	__stop___sancov_guards = .;
+#else
+#define BSS_SANCOV_GUARDS
+#endif
+
 /*
  * GCC 4.5 and later have a 32 bytes section alignment for structures.
  * Except GCC 4.9, that feels the need to align on 64 bytes.
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 2b3655c0f2278..2acccfa5ae9af 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -107,6 +107,8 @@ typedef unsigned long long kcov_u64;
 #endif
 
 void __sanitizer_cov_trace_pc(void);
+void __sanitizer_cov_trace_pc_guard(u32 *guard);
+void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
 void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
 void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
 void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 5170f367c8a1b..8154ac1c1622e 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -194,27 +194,15 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
 	return ip;
 }
 
-/*
- * Entry point from instrumented code.
- * This is called once per basic-block/edge.
- */
-void notrace __sanitizer_cov_trace_pc(void)
+static notrace void kcov_append_to_buffer(unsigned long *area, int size,
+					  unsigned long ip)
 {
-	struct task_struct *t;
-	unsigned long *area;
-	unsigned long ip = canonicalize_ip(_RET_IP_);
-	unsigned long pos;
-
-	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
-		return;
-
-	area = t->kcov_state.area;
 	/* The first 64-bit word is the number of subsequent PCs. */
-	pos = READ_ONCE(area[0]) + 1;
-	if (likely(pos < t->kcov_state.size)) {
-		/* Previously we write pc before updating pos. However, some
-		 * early interrupt code could bypass check_kcov_mode() check
+	unsigned long pos = READ_ONCE(area[0]) + 1;
+
+	if (likely(pos < size)) {
+		/*
+		 * Some early interrupt code could bypass check_kcov_mode() check
 		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
 		 * raised between writing pc and updating pos, the pc could be
 		 * overitten by the recursive __sanitizer_cov_trace_pc().
@@ -225,7 +213,40 @@ void notrace __sanitizer_cov_trace_pc(void)
 		area[pos] = ip;
 	}
 }
+
+/*
+ * Entry point from instrumented code.
+ * This is called once per basic-block/edge.
+ */
+#ifdef CONFIG_KCOV_UNIQUE
+void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
+{
+	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
+		return;
+
+	kcov_append_to_buffer(current->kcov_state.area,
+			      current->kcov_state.size,
+			      canonicalize_ip(_RET_IP_));
+}
+EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
+
+void notrace __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
+						 uint32_t *stop)
+{
+}
+EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
+#else /* !CONFIG_KCOV_UNIQUE */
+void notrace __sanitizer_cov_trace_pc(void)
+{
+	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
+		return;
+
+	kcov_append_to_buffer(current->kcov_state.area,
+			      current->kcov_state.size,
+			      canonicalize_ip(_RET_IP_));
+}
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
+#endif
 
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
 static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
@@ -253,7 +274,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	start_index = 1 + count * KCOV_WORDS_PER_CMP;
 	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
 	if (likely(end_pos <= max_pos)) {
-		/* See comment in __sanitizer_cov_trace_pc(). */
+		/* See comment in kcov_append_to_buffer(). */
 		WRITE_ONCE(area[0], count + 1);
 		barrier();
 		area[start_index] = type;
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index ebe33181b6e6e..a7441f89465f3 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2153,6 +2153,12 @@ config ARCH_HAS_KCOV
 	  build and run with CONFIG_KCOV. This typically requires
 	  disabling instrumentation for some early boot code.
 
+config CC_HAS_SANCOV_TRACE_PC
+	def_bool $(cc-option,-fsanitize-coverage=trace-pc)
+
+config CC_HAS_SANCOV_TRACE_PC_GUARD
+	def_bool $(cc-option,-fsanitize-coverage=trace-pc-guard)
+
 config KCOV
 	bool "Code coverage for fuzzing"
 	depends on ARCH_HAS_KCOV
@@ -2166,6 +2172,26 @@ config KCOV
 
 	  For more details, see Documentation/dev-tools/kcov.rst.
 
+config ARCH_HAS_KCOV_UNIQUE
+	bool
+	help
+	  An architecture should select this when it can successfully
+	  build and run with CONFIG_KCOV_UNIQUE.
+
+config KCOV_UNIQUE
+	depends on KCOV
+	depends on CC_HAS_SANCOV_TRACE_PC_GUARD && ARCH_HAS_KCOV_UNIQUE
+	bool "Enable unique program counter collection mode for KCOV"
+	help
+	  This option enables KCOV's unique program counter (PC) collection mode,
+	  which deduplicates PCs on the fly when the KCOV_UNIQUE_ENABLE ioctl is
+	  used.
+
+	  This significantly reduces the memory footprint for coverage data
+	  collection compared to trace mode, as it prevents the kernel from
+	  storing the same PC multiple times.
+	  Enabling this mode incurs a slight increase in kernel binary size.
+
 config KCOV_ENABLE_COMPARISONS
 	bool "Enable comparison operands collection by KCOV"
 	depends on KCOV
diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 78305a84ba9d2..c3ad5504f5600 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -1,5 +1,12 @@
 # SPDX-License-Identifier: GPL-2.0-only
+ifeq ($(CONFIG_KCOV_UNIQUE),y)
+kcov-flags-y					+= -fsanitize-coverage=trace-pc-guard
+# Drop per-file constructors that -fsanitize-coverage=trace-pc-guard inserts by default.
+# Kernel does not need them, and they may produce unknown relocations.
+kcov-flags-y					+= -mllvm -sanitizer-coverage-drop-ctors
+else
 kcov-flags-y					+= -fsanitize-coverage=trace-pc
+endif
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
 
 kcov-rflags-y					+= -Cpasses=sancov-module
diff --git a/scripts/module.lds.S b/scripts/module.lds.S
index 450f1088d5fd3..17f36d5112c5d 100644
--- a/scripts/module.lds.S
+++ b/scripts/module.lds.S
@@ -47,6 +47,7 @@ SECTIONS {
 	.bss : {
 		*(.bss .bss.[0-9a-zA-Z_]*)
 		*(.bss..L*)
+		*(__sancov_guards)
 	}
 
 	.data : {
@@ -64,6 +65,40 @@ SECTIONS {
 		MOD_CODETAG_SECTIONS()
 	}
 #endif
+
+#ifdef CONFIG_KCOV_UNIQUE
+	/*
+	 * CONFIG_KCOV_UNIQUE creates COMDAT groups for instrumented functions,
+	 * which has the following consequences in the presence of
+	 * -ffunction-sections:
+	 *  - Separate .init.text and .exit.text sections in the modules are not
+	 *    merged together, which results in errors trying to create
+	 *    duplicate entries in /sys/module/MODNAME/sections/ at module load
+	 *    time.
+	 *  - Each function is placed in a separate .text.funcname section, so
+	 *    there is no .text section anymore. Collecting them together here
+	 *    has mostly aesthetic purpose, although some tools may be expecting
+	 *    it to be present.
+	 */
+	.text : {
+		*(.text .text.[0-9a-zA-Z_]*)
+		*(.text..L*)
+	}
+	.init.text : {
+		*(.init.text .init.text.[0-9a-zA-Z_]*)
+		*(.init.text..L*)
+	}
+	.exit.text : {
+		*(.exit.text .exit.text.[0-9a-zA-Z_]*)
+		*(.exit.text..L*)
+	}
+	.bss : {
+		*(.bss .bss.[0-9a-zA-Z_]*)
+		*(.bss..L*)
+		*(__sancov_guards)
+	}
+#endif
+
 	MOD_SEPARATE_CODETAG_SECTIONS()
 }
 
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 67d76f3a1dce5..60eb5faa27d28 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1156,6 +1156,7 @@ static const char *uaccess_safe_builtin[] = {
 	"write_comp_data",
 	"check_kcov_mode",
 	"__sanitizer_cov_trace_pc",
+	"__sanitizer_cov_trace_pc_guard",
 	"__sanitizer_cov_trace_const_cmp1",
 	"__sanitizer_cov_trace_const_cmp2",
 	"__sanitizer_cov_trace_const_cmp4",
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-6-glider%40google.com.
