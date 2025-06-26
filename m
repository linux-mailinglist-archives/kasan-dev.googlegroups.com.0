Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPM46XBAMGQECTEUFOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id F11AEAE9F30
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:24 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4532ff43376sf7623935e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945342; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZsroHLxdTzcxM1XzOjNYcmYzYX868Uu5m1cYyRR65gwSs+b5bjeUurkWbTPSslzTyv
         edaHoGLglHkN1Yv8/YY96Z2x73KRt+OpP04cy/W7xtVtNJhFR3ksR5teue/FgMF9ZBpT
         +w6eSDiA0TAflo5n+LTBjoHm9VbIs0ZuFxu+/lv6T1O1G4F/jJTbLZTRTA92XBDeOt8U
         iQeu60zvpayhtsl+RBsGYHoQ2AwifW3yePZ1DDhyZ/STK2wzrmofHZW3JcShEGfdxzXD
         Sy4gGNSDS9giKzFv9W+EXFmqQ91Y861v1ydEyGQja+Wnb/P78ak+QsRQg3P08ywsJUQk
         Pbaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Fhg9idfcVKKZ/imbvOE3f0wjhr+B1+42Ehpj7ShlzQ4=;
        fh=x3gd7dtlB0109+/ugbXqoB1a9ae9ns7SAIA+Tl7tH+I=;
        b=Ieowx2bBP/u7TBQbi8hRcFltKIvIHwoF1jZkwtuhSszSX3ujiZiW3Pv4cfuWQ27TDb
         GrOmvaQLNWZMYZuh/2rwu83dn9x8jY+OggLMwh9t0ZSbB0PNms2iyxg+49G1pgGoVF8M
         erSygu3qnRd5KKJ59i4iZof+pCPNpPFu2eosvEi/vurjmv9VxDg5J0b4ktELg9CIGI4L
         AXagaf53xc4TI3rwzb2LgT3GZHpwGouaHp4uUh4DxLdeXhK4dVn26D8acCnMcD9lPukX
         B0eBNQqsT9ZlNjnqceb3FpCpCgAYRwIoNeMY28OKbPJEuUPFLPKYoiWJP0hTgk4Bws3v
         FX+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AD0FrbX1;
       spf=pass (google.com: domain of 3o05daaykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3O05daAYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945342; x=1751550142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Fhg9idfcVKKZ/imbvOE3f0wjhr+B1+42Ehpj7ShlzQ4=;
        b=m0WrZdqxQSYE0mMT04q6Zm3X4Alt9X4wDCaZM8xMjccvq5JAZVwcwL7xsZA9bUQ42y
         0tnwYD9RdL7NQIrGIIruLb6k+1EBLHxIE5HaUzqcyS8TJ08qtt2znofXxcqrg90Ddhp5
         taAWwli9zObXzT1ZVHCM2OF3MoasX5F0ZBh8Jb6y/SGkFepmfxZs+QYc6/oXFCq8YOeD
         gtn+iedvmG/InWpD3+nAUPGL1cuLQmR9Ecxc+Jb1Ie6tO4UTAygH5sOjjtCUJMjwTIW5
         Mrpt3jSdZFAt8AARHDExcOcfNGXLbdlhZ1/gyrmmTYnU4INrBJr4xruApFPvoRa/2f9F
         0SpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945342; x=1751550142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Fhg9idfcVKKZ/imbvOE3f0wjhr+B1+42Ehpj7ShlzQ4=;
        b=XGsoIiqPto09svBwGvNFUneLAN0m3MVpDsRjX+uZnk6i6uQkNsH5jTyGxO9GHw9jSH
         TxNXLsdtVYTZonmkVz7QlE7wu8PUf2UTxItsYW8vehgpapUSiKF9Dz7dTTp9NYPKjXfp
         wkomSso4WRcG6HxPMyN3tvSlCRI+gIfTwy9vv9y4Gb1cjE0deRy0mfnxMe2PZf5FY4at
         Q2aLaI1MRreYsbfYG5U48TmEe+C845e/R0QvYr04ZxAPMmuslAOfMT6vcZrH+yT694k8
         9B2VJNET5erlhKeHk6pCcPYkP1lXuNYQBXeAbfTNpNHcL3LPXSw+Mlbu2gR+TMte0Rmn
         tJtQ==
X-Forwarded-Encrypted: i=2; AJvYcCXwDKY/yh18SEKEmwuGjmB0rRskolrNqZ0PKlr4XmRgSdtTRmV1tM536vfXPXQZ/awC8BN00w==@lfdr.de
X-Gm-Message-State: AOJu0Yylm1hiBkeS5XzIJbsJngSBJ2ovkFNtJbMvdLKAlmbDgKVFFAQv
	Ly2bW7UbSxidXYxwzbSS2U9Mbrx6Zvgfg/UonbV3lqsu3F96SUjj8GPx
X-Google-Smtp-Source: AGHT+IEhI3ViKhzLMKVwrD0CQTGC80bpHQ+APrm/9fhMwJOpP/fgR8eCDL3OkHcEqjQd0sEnVjp4MA==
X-Received: by 2002:a05:600c:37ca:b0:450:cf42:7565 with SMTP id 5b1f17b1804b1-45381ae5157mr62782425e9.23.1750945342298;
        Thu, 26 Jun 2025 06:42:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc2U2mJXXr0ZBSaKKMJO/X/c8bPv7+3cai4SE9pKiZpjg==
Received: by 2002:a05:600c:6087:b0:43c:eb7b:1403 with SMTP id
 5b1f17b1804b1-45388a8786als6694145e9.1.-pod-prod-09-eu; Thu, 26 Jun 2025
 06:42:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUO1ZFVhwrYLQF+cBQpqiwTNB0FbWzuK5QW79sEP75ZA58EquNo/5LVX2YHyPwpiY7TyiYL/rVGy+Q=@googlegroups.com
X-Received: by 2002:a05:6000:3111:b0:3a4:e629:6504 with SMTP id ffacd0b85a97d-3a6ed6508a1mr5724389f8f.49.1750945340041;
        Thu, 26 Jun 2025 06:42:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945340; cv=none;
        d=google.com; s=arc-20240605;
        b=G7qnA9ea2pkaDU03L/fL5Taw2zZAwrx3YLSUb9MKT+6ON+qr83ldr28wGVzQ+hyg0Y
         rjj2EbPjxPF9hcljcBmLgA3KA6SMbzk/RerRtvHIxUhowZxepppUv51Wp3YRafwQNSSd
         Uksy2XiABSpToP+nYxAM6KFJrdmWVX07bER9H3ITYmlVQCCT+taqfxqjyfOvUsKheVmF
         kFpJIL9veXm56aKiw0A94Jh0FMErVrA3/k4EEZkSyrLzywl9rNq1ylkk8Z/MAxmYB2LN
         ARQA94A990g1+FQmsZ8Llg/oohk7RHe0lLk7QywMUXAvoALFbyzbMcb5Pj2JR1LPBKIw
         ZSQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=yNvNdo60faam5nFnHvZbzCMJ04X3V7FkkVfM1Z/F4Ac=;
        fh=RBZhsEr0jb6P8/v3l3l6fNr6o+G7e5e3oHZJJTgTrSI=;
        b=AbPw9ON3YlRWJKonZerG2CaM+csveM2CMOKXD4zJtdDo643NAOAiRHcaI3NW6RQEhx
         w71k/0YXmlVWSnAyLxPIBhistAd7UgZDa/CjEDHvZMTuszmsGhYjbRn33E672ZGOA3Ej
         sJo42sUV8m/u3qvbyKJr1rmqlOYb5TwcdZnRP+JOYUDtOdiZBlLo33JBQ1VSYFfh8GRL
         GKu4aRevZEJJq+vYrmg1cvNG1VII3DtjXIMw/Oyxgq8IfdfSoI64Jy6er8lmMEIrZmPl
         hLkTsSmx5/eB8frD5PFqRikVoROrEFFCyjAB8HdP1fITf+51ZUF3zbBzEhUzUxn5Do/s
         Oq+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AD0FrbX1;
       spf=pass (google.com: domain of 3o05daaykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3O05daAYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a6e80e41d5si136466f8f.8.2025.06.26.06.42.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3o05daaykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3a6d90929d6so431651f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWt2YR6Wlh5j08gckV3xMdTvqgJfZRZlgTfJstMqVx4Wyj72bJxEvCOWmLol6nLE0ZAGudvO0/qBms=@googlegroups.com
X-Received: from wmbfs5.prod.google.com ([2002:a05:600c:3f85:b0:450:41ed:d20e])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2011:b0:3a4:e54c:adf2
 with SMTP id ffacd0b85a97d-3a6ed61a12cmr5925433f8f.5.1750945339545; Thu, 26
 Jun 2025 06:42:19 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:53 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-7-glider@google.com>
Subject: [PATCH v2 06/11] kcov: x86: introduce CONFIG_KCOV_UNIQUE
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AD0FrbX1;       spf=pass
 (google.com: domain of 3o05daaykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3O05daAYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
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

Each callback receives a unique 32-bit guard variable residing in the
__sancov_guards section. Those guards can be used by kcov to deduplicate
the coverage on the fly.

As a first step, we make the new instrumentation mode 1:1 compatible
with the old one.

[1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards

Cc: x86@kernel.org
Signed-off-by: Alexander Potapenko <glider@google.com>

---
Change-Id: Iacb1e71fd061a82c2acadf2347bba4863b9aec39

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
---
 arch/x86/Kconfig                  |  1 +
 arch/x86/kernel/vmlinux.lds.S     |  1 +
 include/asm-generic/vmlinux.lds.h | 14 ++++++-
 include/linux/kcov.h              |  2 +
 kernel/kcov.c                     | 61 +++++++++++++++++++++----------
 lib/Kconfig.debug                 | 24 ++++++++++++
 scripts/Makefile.kcov             |  4 ++
 scripts/module.lds.S              | 23 ++++++++++++
 tools/objtool/check.c             |  1 +
 9 files changed, 110 insertions(+), 21 deletions(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index e21cca404943e..d104c5a193bdf 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -93,6 +93,7 @@ config X86
 	select ARCH_HAS_FORTIFY_SOURCE
 	select ARCH_HAS_GCOV_PROFILE_ALL
 	select ARCH_HAS_KCOV			if X86_64
+	select ARCH_HAS_KCOV_UNIQUE		if X86_64
 	select ARCH_HAS_KERNEL_FPU_SUPPORT
 	select ARCH_HAS_MEM_ENCRYPT
 	select ARCH_HAS_MEMBARRIER_SYNC_CORE
diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index cda5f8362e9da..8076e8953fddc 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -372,6 +372,7 @@ SECTIONS
 		. = ALIGN(PAGE_SIZE);
 		__bss_stop = .;
 	}
+	SANCOV_GUARDS_BSS
 
 	/*
 	 * The memory occupied from _text to here, __end_of_kernel_reserve, is
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 58a635a6d5bdf..875c4deb66208 100644
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
@@ -121,6 +122,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 #define SBSS_MAIN .sbss
 #endif
 
+#if defined(CONFIG_KCOV_UNIQUE)
+#define SANCOV_GUARDS_BSS			\
+	__sancov_guards(NOLOAD) : {		\
+		__start___sancov_guards = .;	\
+		*(__sancov_guards);		\
+		__stop___sancov_guards = .;	\
+	}
+#else
+#define SANCOV_GUARDS_BSS
+#endif
+
 /*
  * GCC 4.5 and later have a 32 bytes section alignment for structures.
  * Except GCC 4.9, that feels the need to align on 64 bytes.
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 0e425c3524b86..dd8bbee6fe274 100644
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
index ff7f118644f49..8e98ca8d52743 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -195,27 +195,15 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
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
@@ -226,7 +214,40 @@ void notrace __sanitizer_cov_trace_pc(void)
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
@@ -254,7 +275,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	start_index = 1 + count * KCOV_WORDS_PER_CMP;
 	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
 	if (likely(end_pos <= max_pos)) {
-		/* See comment in __sanitizer_cov_trace_pc(). */
+		/* See comment in kcov_append_to_buffer(). */
 		WRITE_ONCE(area[0], count + 1);
 		barrier();
 		area[start_index] = type;
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index f9051ab610d54..24dcb721dbb0b 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2156,6 +2156,8 @@ config ARCH_HAS_KCOV
 config CC_HAS_SANCOV_TRACE_PC
 	def_bool $(cc-option,-fsanitize-coverage=trace-pc)
 
+config CC_HAS_SANCOV_TRACE_PC_GUARD
+	def_bool $(cc-option,-fsanitize-coverage=trace-pc-guard)
 
 config KCOV
 	bool "Code coverage for fuzzing"
@@ -2172,6 +2174,28 @@ config KCOV
 
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
+	bool "Use coverage guards for KCOV"
+	help
+	  Use coverage guards instrumentation for KCOV, passing
+	  -fsanitize-coverage=trace-pc-guard to the compiler.
+
+	  Every coverage callback is associated with a global variable that
+	  allows to efficiently deduplicate coverage at collection time.
+	  This drastically reduces the buffer size required for coverage
+	  collection.
+
+	  This config comes at a cost of increased binary size (4 bytes of .bss
+	  plus 1-2 instructions to pass an extra parameter, per basic block).
+
 config KCOV_ENABLE_COMPARISONS
 	bool "Enable comparison operands collection by KCOV"
 	depends on KCOV
diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 67e8cfe3474b7..0b17533ef35f6 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -1,5 +1,9 @@
 # SPDX-License-Identifier: GPL-2.0-only
+ifeq ($(CONFIG_KCOV_UNIQUE),y)
+kcov-flags-y					+= -fsanitize-coverage=trace-pc-guard
+else
 kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
+endif
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
 kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)		+= -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
 
diff --git a/scripts/module.lds.S b/scripts/module.lds.S
index 450f1088d5fd3..314b56680ea1a 100644
--- a/scripts/module.lds.S
+++ b/scripts/module.lds.S
@@ -64,6 +64,29 @@ SECTIONS {
 		MOD_CODETAG_SECTIONS()
 	}
 #endif
+
+#ifdef CONFIG_KCOV_UNIQUE
+	__sancov_guards(NOLOAD) : {
+		__start___sancov_guards = .;
+		*(__sancov_guards);
+		__stop___sancov_guards = .;
+	}
+
+	.text : {
+		*(.text .text.[0-9a-zA-Z_]*)
+		*(.text..L*)
+	}
+
+	.init.text : {
+		*(.init.text .init.text.[0-9a-zA-Z_]*)
+		*(.init.text..L*)
+	}
+	.exit.text : {
+		*(.exit.text .exit.text.[0-9a-zA-Z_]*)
+		*(.exit.text..L*)
+	}
+#endif
+
 	MOD_SEPARATE_CODETAG_SECTIONS()
 }
 
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index b21b12ec88d96..62fbe9b2aa077 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1154,6 +1154,7 @@ static const char *uaccess_safe_builtin[] = {
 	"write_comp_data",
 	"check_kcov_mode",
 	"__sanitizer_cov_trace_pc",
+	"__sanitizer_cov_trace_pc_guard",
 	"__sanitizer_cov_trace_const_cmp1",
 	"__sanitizer_cov_trace_const_cmp2",
 	"__sanitizer_cov_trace_const_cmp4",
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-7-glider%40google.com.
