Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMFOW3XAKGQECAUV4MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id AF171FCC9A
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:04:32 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id e3sf4883009wrs.17
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:04:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754672; cv=pass;
        d=google.com; s=arc-20160816;
        b=W3LXqfWYk13EDSuE9LYWQ7YC0thBbdc4rvPo9r0TacEWrk5yDG4ON5h/+5QXS/y0BW
         Ojh1K1VkomuKfs2Ai+nQUnYcqYkb1FoN+c+h16dYBTItWP73nUfb1bryRd3r8EeeGpS/
         IEn69eVLe58BzRUXYUau+ZJdiELwgUcedBjLT2mPJU3b9QgbNpKCbgsE0P+ith0b0C2p
         SOZ68ow8n/9+I0ZCkngZfu/XfOFNE+8F2Kpwv/uRSQZIEmoOEz0XZ+cRHdJsQBjZpVYV
         meUfGcNZKjLlJUWobw7m04weP123yM+Zt9ohSRvn+mf9v6vWN8zffTyWmO6C6vCuLXoG
         atQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=IqFmIrtD4x8diy5Zajgd13J+Jyw+zvhHTv/KIsFwA9A=;
        b=00shIK0ui/Vsl9uXjME1xRYffk79gAERBVRxFX5CF29ihD5+xBmoc/BnFkxzePn4Tp
         v1+vvBGOrCktscenH/f92tC4lHpecKrocD3mM5hpT3+9cMt1TFCjpOU26fozfsz/qxsF
         I+gxAZHNmgmeZhUC+3n3si6FV0UnY9WPrURvEBInYgKHleIUzlgh/nKQz5P5vukT6uWp
         Z80T0SBAScQomTnkj0IHrXkftvBJNkmAkvMz8pNOSmpDwdVXSbkAlQL2LccRTZmZrhbi
         D3Cvkd0uQ2vXeS6AVvVZSDWrRh5Tnd7FwKnZfe5aoADxxx/W6EgYai+i4CdhGGFu3n8Q
         islw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SnVWFOxr;
       spf=pass (google.com: domain of 3lpfnxqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LpfNXQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IqFmIrtD4x8diy5Zajgd13J+Jyw+zvhHTv/KIsFwA9A=;
        b=LmxvfMHlAgbbvGzyWAfl4mrFDmkzJh8VcLqHHitajKa2lD6nYBSQKTFFgMrmY3rC1L
         ejiO376+8nf2AlsL0dfajbxCsqpRtxGWWU5UHjOIcylKuKlkdZSGW/TA0A3wHNILUe8U
         aYT6UqpHqE2FOkKcZszle4lWB1uv1FLbub5qFaONke5fL9hgmJRrfEgZJMbCG1fwDlA3
         LIwk6rqLx/s4SnCF4r70inEVkflH4Yx6CqHyHsXby0qMrqNbozVeq8CJUbDyF046YgDc
         O8ByU1SGsiuXLrSjdvkWf3XtjU5XD1tL4w1cgYeXt+7ZFh8m57ctFsmp/DuouHYRkep2
         MY4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IqFmIrtD4x8diy5Zajgd13J+Jyw+zvhHTv/KIsFwA9A=;
        b=Z8qrqxMKx5+6a9vk1NtfuimOubnbrVIK/PHpJLIX2i5xxoPi1ZT1sMYl/5LOK4u5eZ
         zPOLZLdSJH965CTWQ1qhkVACrmJ5VP3xwnL3LDXQCo7bxVu++kmBOB0tHGrxCiaZlt5r
         o5wWEk5JtBh70bBaMFjx3nDvcft1luIcDpz+7r/5SZ4CI60mX9PckizhuoxudsYRfOiD
         duBlg/Nv3kLHUoeAF8hSQSbn7xRNdmCHcFF/vKEFh7jE4cYRa7Uh8Ea10xJkn8raploR
         zpJdkpvN/TBShWbvpRg+0G38+wneY9hPI+BQppvtIK6zDhVWdcJPtTzsKZZ/uVG5FvGv
         dc/g==
X-Gm-Message-State: APjAAAVeQmiORMssbpmtJAYQGht7LdllkTDtuTYmWbhkQAdg/IT9IflO
	nqNsq8Djfa3ks3lQrAUZCJg=
X-Google-Smtp-Source: APXvYqw4f95MiNVcGVkY9QSjOLv4bLs+dpjBf3iaTDzNrCkrb1TYU+3zU/2GwroREcDGPXMi1zLWSA==
X-Received: by 2002:adf:fa0b:: with SMTP id m11mr10217453wrr.279.1573754672393;
        Thu, 14 Nov 2019 10:04:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:82:: with SMTP id 124ls10011367wma.1.gmail; Thu, 14 Nov
 2019 10:04:31 -0800 (PST)
X-Received: by 2002:a1c:7209:: with SMTP id n9mr9207895wmc.9.1573754671698;
        Thu, 14 Nov 2019 10:04:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754671; cv=none;
        d=google.com; s=arc-20160816;
        b=Mi0o5FNnLoVIkDIN+ApX0BdNSsvl0CN0fE458tMThQ9zzaj+A6zNvDP5Q3ITcdF0/C
         YyFX1l4WUFIOVdb907BTdAk/tD0tnIuzfoSVaXOtiUeOh1zWNZAqU12AJYQhFXv2Y17v
         YZB6nsmqqnEi7GGcLUv0onuvOOmGi9EXOQItO2ia3IfKyeQc0HekZUQr6PoHtSWkI1NP
         mVyUYErh9kOHhCdcKYOeKjrfPjwE7eM3s6KuRzeft9i31b4uC2z9CW7a6J87m+ls+2ou
         NTnorNf62BqD80AIwdZCy7JiCuvfvjJsWQlxaAWzMfKBSDtu68i+sc6hYEKOWlFhPVoS
         uTxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=V48+CW8SP21nJTw3n511EV0NzIrdGUkA/Mo6H0aYbCQ=;
        b=hol2Xkk3CPAvTR6rkzfqq36W2k2TeUJTTqByDbnGwo0I366ZhySBv+9JARBCU4Qrsu
         cn5HOwf2V3o0EETzcRdgL1GtD3lifTeHb8HeFmGnYP82xaKA6nbKnSaATLegJsxs3zNU
         luK+MRAxQPe/SUVjDrmOTkJq1lJAPO6KKMcyUnxE2mdOFIOk1u2TKWoAkLAQVOwpLpI3
         fGh4nqVXQ8d3HuePrW+tkXpni5+PVx/N3vo6ecq2B210MGiqvzIQ+m2v+NlKxEd2rXdl
         rqnMFnJ47I/upt3XJticBSpMYlN199354te+3CAM5+BWD77i/nwXIP6UX1GwUUAsI/qi
         lyQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SnVWFOxr;
       spf=pass (google.com: domain of 3lpfnxqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LpfNXQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v57si630246edc.3.2019.11.14.10.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:04:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lpfnxqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id t203so3747264wmt.7
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:04:31 -0800 (PST)
X-Received: by 2002:adf:e50e:: with SMTP id j14mr8629262wrm.179.1573754670805;
 Thu, 14 Nov 2019 10:04:30 -0800 (PST)
Date: Thu, 14 Nov 2019 19:03:03 +0100
In-Reply-To: <20191114180303.66955-1-elver@google.com>
Message-Id: <20191114180303.66955-11-elver@google.com>
Mime-Version: 1.0
References: <20191114180303.66955-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 10/10] x86, kcsan: Enable KCSAN for x86
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, edumazet@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SnVWFOxr;       spf=pass
 (google.com: domain of 3lpfnxqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LpfNXQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
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

This patch enables KCSAN for x86, with updates to build rules to not use
KCSAN for several incompatible compilation units.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Paul E. McKenney <paulmck@kernel.org>
---
v4:
* Fix code generation with clang (KCSAN_SANITIZE := n for affected
  compilation units).

v3:
* Moved EFI stub build exception hunk to generic build exception patch,
  since it's not x86-specific.

v2:
* Document build exceptions where no previous above comment explained
  why we cannot instrument.
---
 arch/x86/Kconfig                  | 1 +
 arch/x86/boot/Makefile            | 2 ++
 arch/x86/boot/compressed/Makefile | 2 ++
 arch/x86/entry/vdso/Makefile      | 3 +++
 arch/x86/include/asm/bitops.h     | 6 +++++-
 arch/x86/kernel/Makefile          | 4 ++++
 arch/x86/kernel/cpu/Makefile      | 3 +++
 arch/x86/lib/Makefile             | 4 ++++
 arch/x86/mm/Makefile              | 4 ++++
 arch/x86/purgatory/Makefile       | 2 ++
 arch/x86/realmode/Makefile        | 3 +++
 arch/x86/realmode/rm/Makefile     | 3 +++
 12 files changed, 36 insertions(+), 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 8ef85139553f..9933ca8ffe16 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -226,6 +226,7 @@ config X86
 	select VIRT_TO_BUS
 	select X86_FEATURE_NAMES		if PROC_FS
 	select PROC_PID_ARCH_STATUS		if PROC_FS
+	select HAVE_ARCH_KCSAN if X86_64
 
 config INSTRUCTION_DECODER
 	def_bool y
diff --git a/arch/x86/boot/Makefile b/arch/x86/boot/Makefile
index e2839b5c246c..9c7942794164 100644
--- a/arch/x86/boot/Makefile
+++ b/arch/x86/boot/Makefile
@@ -9,7 +9,9 @@
 # Changed by many, many contributors over the years.
 #
 
+# Sanitizer runtimes are unavailable and cannot be linked for early boot code.
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Kernel does not boot with kcov instrumentation here.
diff --git a/arch/x86/boot/compressed/Makefile b/arch/x86/boot/compressed/Makefile
index 6b84afdd7538..a1c248b8439f 100644
--- a/arch/x86/boot/compressed/Makefile
+++ b/arch/x86/boot/compressed/Makefile
@@ -17,7 +17,9 @@
 #	(see scripts/Makefile.lib size_append)
 #	compressed vmlinux.bin.all + u32 size of vmlinux.bin.all
 
+# Sanitizer runtimes are unavailable and cannot be linked for early boot code.
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
diff --git a/arch/x86/entry/vdso/Makefile b/arch/x86/entry/vdso/Makefile
index 0f2154106d01..a23debaad5b9 100644
--- a/arch/x86/entry/vdso/Makefile
+++ b/arch/x86/entry/vdso/Makefile
@@ -10,8 +10,11 @@ ARCH_REL_TYPE_ABS += R_386_GLOB_DAT|R_386_JMP_SLOT|R_386_RELATIVE
 include $(srctree)/lib/vdso/Makefile
 
 KBUILD_CFLAGS += $(DISABLE_LTO)
+
+# Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
index 7d1f6a49bfae..542b63ddc8aa 100644
--- a/arch/x86/include/asm/bitops.h
+++ b/arch/x86/include/asm/bitops.h
@@ -201,8 +201,12 @@ arch_test_and_change_bit(long nr, volatile unsigned long *addr)
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
 }
 
-static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
+static __no_kcsan_or_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
 {
+	/*
+	 * Because this is a plain access, we need to disable KCSAN here to
+	 * avoid double instrumentation via instrumented bitops.
+	 */
 	return ((1UL << (nr & (BITS_PER_LONG-1))) &
 		(addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
 }
diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 3578ad248bc9..a9a1cab437bc 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -28,6 +28,10 @@ KASAN_SANITIZE_dumpstack_$(BITS).o			:= n
 KASAN_SANITIZE_stacktrace.o				:= n
 KASAN_SANITIZE_paravirt.o				:= n
 
+# With some compiler versions the generated code results in boot hangs, caused
+# by several compilation units. To be safe, disable all instrumentation.
+KCSAN_SANITIZE := n
+
 OBJECT_FILES_NON_STANDARD_relocate_kernel_$(BITS).o	:= y
 OBJECT_FILES_NON_STANDARD_test_nx.o			:= y
 OBJECT_FILES_NON_STANDARD_paravirt_patch.o		:= y
diff --git a/arch/x86/kernel/cpu/Makefile b/arch/x86/kernel/cpu/Makefile
index 890f60083eca..a704fb9ee98e 100644
--- a/arch/x86/kernel/cpu/Makefile
+++ b/arch/x86/kernel/cpu/Makefile
@@ -13,6 +13,9 @@ endif
 KCOV_INSTRUMENT_common.o := n
 KCOV_INSTRUMENT_perf_event.o := n
 
+# As above, instrumenting secondary CPU boot code causes boot hangs.
+KCSAN_SANITIZE_common.o := n
+
 # Make sure load_percpu_segment has no stackprotector
 nostackp := $(call cc-option, -fno-stack-protector)
 CFLAGS_common.o		:= $(nostackp)
diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
index 5246db42de45..432a07705677 100644
--- a/arch/x86/lib/Makefile
+++ b/arch/x86/lib/Makefile
@@ -6,10 +6,14 @@
 # Produces uninteresting flaky coverage.
 KCOV_INSTRUMENT_delay.o	:= n
 
+# KCSAN uses udelay for introducing watchpoint delay; avoid recursion.
+KCSAN_SANITIZE_delay.o := n
+
 # Early boot use of cmdline; don't instrument it
 ifdef CONFIG_AMD_MEM_ENCRYPT
 KCOV_INSTRUMENT_cmdline.o := n
 KASAN_SANITIZE_cmdline.o  := n
+KCSAN_SANITIZE_cmdline.o  := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_cmdline.o = -pg
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index 84373dc9b341..3559f4297ee1 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -7,6 +7,10 @@ KCOV_INSTRUMENT_mem_encrypt_identity.o	:= n
 KASAN_SANITIZE_mem_encrypt.o		:= n
 KASAN_SANITIZE_mem_encrypt_identity.o	:= n
 
+# Disable KCSAN entirely, because otherwise we get warnings that some functions
+# reference __initdata sections.
+KCSAN_SANITIZE := n
+
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_mem_encrypt.o		= -pg
 CFLAGS_REMOVE_mem_encrypt_identity.o	= -pg
diff --git a/arch/x86/purgatory/Makefile b/arch/x86/purgatory/Makefile
index fb4ee5444379..69379bce9574 100644
--- a/arch/x86/purgatory/Makefile
+++ b/arch/x86/purgatory/Makefile
@@ -17,7 +17,9 @@ CFLAGS_sha256.o := -D__DISABLE_EXPORTS
 LDFLAGS_purgatory.ro := -e purgatory_start -r --no-undefined -nostdlib -z nodefaultlib
 targets += purgatory.ro
 
+# Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE	:= n
+KCSAN_SANITIZE	:= n
 KCOV_INSTRUMENT := n
 
 # These are adjustments to the compiler flags used for objects that
diff --git a/arch/x86/realmode/Makefile b/arch/x86/realmode/Makefile
index 682c895753d9..6b1f3a4eeb44 100644
--- a/arch/x86/realmode/Makefile
+++ b/arch/x86/realmode/Makefile
@@ -6,7 +6,10 @@
 # for more details.
 #
 #
+
+# Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 subdir- := rm
diff --git a/arch/x86/realmode/rm/Makefile b/arch/x86/realmode/rm/Makefile
index f60501a384f9..fdbbb945c216 100644
--- a/arch/x86/realmode/rm/Makefile
+++ b/arch/x86/realmode/rm/Makefile
@@ -6,7 +6,10 @@
 # for more details.
 #
 #
+
+# Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-11-elver%40google.com.
