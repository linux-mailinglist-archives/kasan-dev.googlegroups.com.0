Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFNNT3CAMGQEW4V6WUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B4F79B13E3A
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:14 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-555024588e2sf2760723e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716374; cv=pass;
        d=google.com; s=arc-20240605;
        b=IvdBHxG8PcMnScmISkOu8YmciHiEDJfQkfguPorpYr7qH11BcJel66SltHEjL54INf
         7ay3vzzmAeq7oQlq+yBg23IDxrmWhK6PoAGy8uGKEtafFV4hZ4NYjYBsn0z4b9Y7+AGw
         U/EtbmbDl0tKXrhiTnCUpGFV8tOoW8szRrkHUtwNmW104Pl1gn30obfN5BCrRUgfHUWY
         nn0WnyGUl48JEL096DNTl2PJY77TDIYr0hTuj9Y5h7p3lvJAkpbxjmdBDzZ+M3K4i1bd
         mRXirCiFE7HXu6TWoqzLAhRtlU+eY6pmZhekgPJ3DZmDtXNFexX5kSd1/zzvPSmOGuHT
         rzsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=iZ9ibZDNPD2NoGhAm1UU/WEs2VIcPaRJkTlljKDRQbs=;
        fh=n7IKf12w449JF6JHT/g5C2iqCAQAfqboF6d2vkjPncA=;
        b=NY6h8/lqG79L8bFCm2/HWoRv2s6jzjVgzb3xCsxsEzZNRWfROEi3VtnzB6A3Gs6ho3
         3aiPnNyqGa5UNiKSfvzAbtcHFDxUxJ6VhVfflx8fkX3Oa7YYhSUtyiaSq4ddPNglGYtf
         Iws6MwQbXWg0FtnHH53oxKtnB586E9G1RCbWK1zKXJ3mQmrJSJ3gW2Qjq1KgPsGlU69+
         MMAX1HnYMV1SbML3x6concjhiqrowoqGaSdrY1QHJ93xA1bz081YJnbsvqtXDdywPDRH
         r/EgKAGk1oPI9N2FFmD5mHUaGWSU8wGsFK721nrOqD6Rj+UU43nrJtwZiXvLWtT9YPFm
         34oQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3uXZmbCU;
       spf=pass (google.com: domain of 3kpahaaykcsklqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3kpaHaAYKCSkLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716374; x=1754321174; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=iZ9ibZDNPD2NoGhAm1UU/WEs2VIcPaRJkTlljKDRQbs=;
        b=tBuzJD5KQwkou8BtYFxyrJWn/1ZnQur+HMfPrz2XH0OzB1ZTsTmilF7OEXw9bHlKsv
         HSF79bmngjWde4cdnvf2QRy5bFnYQGPB4Yv7vCKk5r3YqYWAg3JFiSEf4ZqKIN8ZiwqG
         3OiVScuZmbjfKV3mD5ACpzESnFVymJr3CfF37kW2OgkLnB/z1ZFpZCbanWWRFQcIIB3w
         H3CbrWGkvlTjBMgrxywE2gnps6A0i7RTDrTFujLrEYSP3YvRbBOuZpjtcot3ksj7OqSC
         8xK1O+J44Hen5IvhFK9lCA7hYSABVCWIA/KihK5KGM8vyaXZg+93HrDxxEYfpYEk2z6d
         l1tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716374; x=1754321174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iZ9ibZDNPD2NoGhAm1UU/WEs2VIcPaRJkTlljKDRQbs=;
        b=HyMuOw2EKzM8UVn92PeBKrmHxoU2aAUmh+CrmX26Rjxt+bj+MAqtco5q0CywNnhGGH
         PVVw+rEaCMYQyM2MO2zNX5e9Zpdp8ZYt74kPrK16OTU0IRvVK99H9td1tw2e7EKN1zVb
         NaYwJBTeT6I/dhGBO7OTpqMf9Ihew1nf7howHcqZ6Ns0lKIy+r80prgPY1FjAjAEmUgw
         KsgXTNGMAfOZ2PFyeKPHl3pe/iBU22Sy9ol4aKsRAPLNe9SMPj4qaWyc25LTHyAV9szd
         BDEAKU2IIB63wsQ1MEa8ntQy7qGu/ZTV21ed2ftWBDS1a9QZBfuLre4zG21k6MB0Asvw
         tZFg==
X-Forwarded-Encrypted: i=2; AJvYcCXpCPuXatf9iOPUW1IomZPmlOK4cBJ33HH48linfUFQXyRKyu/8TFhjb29HExgBVw+I4tr05A==@lfdr.de
X-Gm-Message-State: AOJu0YzoIunV+wD0vP9+sKSyqqrKKXDP4zGJbcLYXvDiey5k4koqlZEF
	vhNA6sCdn1mRuQK9gc5Tf+KdYK7Q9m8DLWWW4tnUFUJ2O3QGfvh79UrV
X-Google-Smtp-Source: AGHT+IHctYC9nFvtRF/+1nGkH4Zdgyld0mI+RREszUFHqbhFKg5m4bkvoEJC6PwGYziwd5Ij7wMaHA==
X-Received: by 2002:a05:6512:61a2:b0:55b:5912:3f8f with SMTP id 2adb3069b0e04-55b5f480ac3mr2987100e87.26.1753716373860;
        Mon, 28 Jul 2025 08:26:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZerQFpTeEYzmRU4MFyG4UMTsYdo/p26kEIoETJCB/xZEA==
Received: by 2002:a05:6512:438a:b0:553:34d7:c3a3 with SMTP id
 2adb3069b0e04-55b51f322c6ls1336823e87.1.-pod-prod-02-eu; Mon, 28 Jul 2025
 08:26:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnGlNbdPrOyXitxnsHJtxkovlpN+eOg7OXoO+anxbgxeh8DCL+esIaUrXFtH+TV99Mk3fk8Zzhtjs=@googlegroups.com
X-Received: by 2002:a05:6512:3996:b0:553:5429:bb87 with SMTP id 2adb3069b0e04-55b5f48fbdemr2875797e87.36.1753716370814;
        Mon, 28 Jul 2025 08:26:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716370; cv=none;
        d=google.com; s=arc-20240605;
        b=TMvmo+hRI7qlFi+iCSRdy+JQjwX1vRleYm2EkwjbFkp9Ke/yyzm5PA52uFEgvBeeZN
         FgQ8vtGSPBjJzT10BZpO3jGvHuKvsEU8I+vEkEAkzWm4KXcPaJ8BaWYlLSLUTzwJiaC3
         kE+trw1Ykc3H3iDFHmjWKTnWhn7HoFD6VPIlz6bop1Vok0vfst7CO12EzSm98DywL1/n
         osughT7BxuufepxBjpzpgXYCdgtXwtHmtSnHUchGLrAzXhdy/XWsb/vzslG+wcLVx7Vo
         beZ0AaaJtXJChxWDDOUvlUxSnBMwy75qE1q3ndsVeFM0oI9GheGHmrAanzqIC1drzVLV
         dpaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OKqMQFpHzUCDFRnRabqvw1Gefpd/rsbhAybeGDXo5FM=;
        fh=b0tmhImTq+sBmFhMvTn2SPZ9tKRERMSu26RuIBb2u/A=;
        b=WIyjM0qjEb6dGmWb9FyLOvyMOEqAKJe7PPUWbXpuVUdv1Cv/SGn96vTzCUG1QsHdhR
         rmrJZejQt8IEn7n9Qz+srmSp9PTE8mr25VFqE6WrE17fcXqeAIaJInpU3SB0CoTAW8/K
         7IMJygUd2EWzJUAUKALvr/ViJNVm43BrmmoPZIygtE81L/qqCvBGIH8Cz91h0FVzsbn5
         lGTCpeEXgh8Ja6OjQdeOgWDO7cBDeXk8rXD8TQi7Y+TG3tYUoKmOPpYuekio6K7Bqg79
         s6xZuENJHITmNAtlaXO1zEyJqzf2O1tVi0cKlHPQvX9fdLLrKBZDyViZtwBlcwBDhdpa
         sR8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3uXZmbCU;
       spf=pass (google.com: domain of 3kpahaaykcsklqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3kpaHaAYKCSkLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b633329c1si55575e87.8.2025.07.28.08.26.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kpahaaykcsklqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4561dfd07bcso23301265e9.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWD/+TpGRAgBFHxS4mjXBa4GHH2gBkV1hZk+9DK1J4aisUUtUau21Py9Cdyu16oyMZKKzOmGUXnRFQ=@googlegroups.com
X-Received: from wmbei27.prod.google.com ([2002:a05:600c:3f1b:b0:456:1b6f:c878])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:6592:b0:456:76c:84f2
 with SMTP id 5b1f17b1804b1-45876e70183mr119044925e9.30.1753716370100; Mon, 28
 Jul 2025 08:26:10 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:43 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-6-glider@google.com>
Subject: [PATCH v3 05/10] kcov: x86: introduce CONFIG_KCOV_UNIQUE
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
 header.i=@google.com header.s=20230601 header.b=3uXZmbCU;       spf=pass
 (google.com: domain of 3kpahaaykcsklqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3kpaHaAYKCSkLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
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

---
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
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-6-glider%40google.com.
