Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIHOUHWQKGQE5QR3SVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BFAFDAF6D
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 16:13:53 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id i10sf1022425wrb.20
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 07:13:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571321632; cv=pass;
        d=google.com; s=arc-20160816;
        b=NKWl21CQydYpehu0GjT7c+k4ppFvsYYWP+HFOKtbfQWsqXduDxkJiBKMYFtW4evo/9
         EAjwnqQlIb9jDdhPod6/4S0wsOMO7Ly0LYgl3V7gxAamOUndg7vMZEAcYloPYYxnYFwd
         vOnj+nyz8trAlsT6PhlgF/k2qsqkoWbDuspZ+Py3cOIG99wtoEOEPgks5JrOi1/Q0RD8
         bmSj0KgGHNYTCyf8U/7HdOUwg0gHRRSyaZoozrWX90huc5vude1w+tw1WJLIF229X8cE
         qmkPjIVVIQasFqjp8iUH/7TRHpHSobBsAQ+v6E6uhq7ksj4ykti7zXapd5FF9UaA5pZA
         Q8/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZRZgesGPJmB43mkrLv+po8xx76pdAL8d0MOKhtZxcVI=;
        b=zIoUMwk1SUBwbUClRi533EnHANnJWGQlDSsgs3ZbjC7El+3WsRRR7yPj2Gk1BXHZ2j
         By9PaQ3i7S7CiwlcqjnGFhats+oVu6fO4GcyGQVGFQDZRqKTKsX0Yj8Ga/ZKYdyhX02+
         FzbXCVJm9zczZPeOd9lPHXthmxn8sKDajAuLGc6so761iA3/p1ZI75PzwqgW0Uy4UvsO
         VWodJXoAdMBeDs18U175VJSxNadwUjZ9VN/TCemG/4qzpVJDPuiTGy2jPJAw9greaalB
         HPW0Tm2X7d7ySy71pMgsP2kIOHqT55IRpLwR5AMog5Du4UuJOHQzLwzUv4yH/HqprS7L
         meNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mYDkEQ8s;
       spf=pass (google.com: domain of 3h3eoxqukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3H3eoXQUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZRZgesGPJmB43mkrLv+po8xx76pdAL8d0MOKhtZxcVI=;
        b=SQw2s+fPOpL3dMC84S9gc/lrl221RXmRgqTReRicTxAOZO+M7RNMXwco0EJjy37PMP
         Wws62Zj+RGlXFWKUolnNPvjksMDRJ6kqPJlSfSnjgX8nGunkzWJfDxguRjHC+ow7+rk7
         p9y+Us/+pQtum2wqg1JJR9GcPrkAzooagxdXeaKyY4cBHFUhRsaprP54VyzjryFJw46B
         Vz5fmPeUgztE/06/35ejmvvaHNiK//vqXlWcr+wGaaQtHKJ6Mz7hPlRueehr92QzR7M7
         jhDYGvohmOLX+dGvo++pLs13fiYQCC7vjvQFuP59gJcgO+VMgPieZQd5kdamh8r7Lkcp
         hzYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZRZgesGPJmB43mkrLv+po8xx76pdAL8d0MOKhtZxcVI=;
        b=R7LM7ekJUEBJruP58+B2+pDyh8biALc5ahcPOJV32rkJhS0C7jUmt3+dMrbtOjc5Ab
         Sw83IcyoCSey0dv6eciKyVfUfKZxx+QFGWI9NUGDF649YoI7LJ7dYBDAOjsgzGRNxmjD
         AL3shoLqf2pztX0KO58TfJW+mrfTEUGmenmhPmOv3X/kITiJRl0AfOa0SAq+ZPi9UBzr
         i2YzsnEN3DixiwwnCXup1fnLNGx2O3xZ2f863sCmgUbnc+bdOlZabiXxO3VivH9sneqn
         /CS7TyzaBRrmeXp8Zi4X97ACeQOQ1yHfpjq20jMI9wnBhMnJny84Y4nwmj6JMhsz4ksl
         4jrw==
X-Gm-Message-State: APjAAAXVggE/pJtagmzxZDBI7+YbNAHNBK5ap/R/6DkYYO2sqOXq3Jad
	6Vedw26/My9YZZSEOn51c/c=
X-Google-Smtp-Source: APXvYqyaVrxrAfsINZjoXJ/la02QwM0ccitI3AGIUV0uLIICgI51ckEfPt+gnoZ6e3/lU+yZJvRa8A==
X-Received: by 2002:a5d:630f:: with SMTP id i15mr3337165wru.226.1571321632682;
        Thu, 17 Oct 2019 07:13:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe43:: with SMTP id m3ls1090240wrs.4.gmail; Thu, 17 Oct
 2019 07:13:52 -0700 (PDT)
X-Received: by 2002:a5d:4302:: with SMTP id h2mr3407563wrq.35.1571321632093;
        Thu, 17 Oct 2019 07:13:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571321632; cv=none;
        d=google.com; s=arc-20160816;
        b=OgXS/qJM+nr/9n9mqha4eXpCk7gubuoL+WyGYqxlfm8AWxp2oSTMmxA3krqT/KXAe0
         X+yB1vSLqzNJ0hDQtwGnRMCXBAGiyPWO/2K1+ABtNffOWVkvhmM4onmHI9O4rnjyovrd
         lEl7nlYFrYAdhnUgVNCp2he8ssFpr3rss5lpb5adu3qrN3Wd4t70/W+up1jy68e4hy48
         dTdPr0xmR/CLOSo9xIPbm2HdciX5yiC3WTS/kz82ThtlFf/2wpNSuJDwKHvZdCVWKA+n
         +GxlPNexFolDpHNh8DriNba7LcO98II70nJ8cCuatc7fPM7M1x5hzs6+fqdIQr+jVhzH
         O7bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=C4dnsunAWNHT00RdRPhWuKYLNPc5AUOyg3b62948kqU=;
        b=ay2/7HpAQ9/WFV6ruIoxnFZrTWFVTjxjLhAsYXVjvtaH4ynxS9Bmm3SozlhyHlAL84
         zzqo05uZifbswcgh7vYPwNgPk49CQ44iRKd20ZaDa1TUeF40y4e3b7V8PaK9Z+epEkme
         uKgUeEjCVuYIjRuMeOmR/eUt7JUzgb10sY93tRog69ae4ImrP3f6EU4gB/k0z71Sxa8X
         7qAHQzTxAS1hrCUOY3bdVKmdqB5qvF9cTUELi6YpYPvXLkPssMRVxX1oGEmw+7HhPLIm
         VVJQzpKKdC847yxkPsnkYm2pN5Yzqrs4hHJgRrtW9ukwroqx2/pYUwqAoVfXJDqIRBs5
         h/gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mYDkEQ8s;
       spf=pass (google.com: domain of 3h3eoxqukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3H3eoXQUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5si601965wmf.1.2019.10.17.07.13.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 07:13:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h3eoxqukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id j125so1227504wmj.6
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 07:13:52 -0700 (PDT)
X-Received: by 2002:a5d:674e:: with SMTP id l14mr3127939wrw.45.1571321631237;
 Thu, 17 Oct 2019 07:13:51 -0700 (PDT)
Date: Thu, 17 Oct 2019 16:13:05 +0200
In-Reply-To: <20191017141305.146193-1-elver@google.com>
Message-Id: <20191017141305.146193-9-elver@google.com>
Mime-Version: 1.0
References: <20191017141305.146193-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.866.gb869b98d4c-goog
Subject: [PATCH v2 8/8] x86, kcsan: Enable KCSAN for x86
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mYDkEQ8s;       spf=pass
 (google.com: domain of 3h3eoxqukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3H3eoXQUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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
---
v2:
* Document build exceptions where no previous above comment explained
  why we cannot instrument.
---
 arch/x86/Kconfig                      | 1 +
 arch/x86/boot/Makefile                | 2 ++
 arch/x86/boot/compressed/Makefile     | 2 ++
 arch/x86/entry/vdso/Makefile          | 3 +++
 arch/x86/include/asm/bitops.h         | 6 +++++-
 arch/x86/kernel/Makefile              | 7 +++++++
 arch/x86/kernel/cpu/Makefile          | 3 +++
 arch/x86/lib/Makefile                 | 4 ++++
 arch/x86/mm/Makefile                  | 3 +++
 arch/x86/purgatory/Makefile           | 2 ++
 arch/x86/realmode/Makefile            | 3 +++
 arch/x86/realmode/rm/Makefile         | 3 +++
 drivers/firmware/efi/libstub/Makefile | 2 ++
 13 files changed, 40 insertions(+), 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index d6e1faa28c58..81859be4a005 100644
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
index 7d1f6a49bfae..ee08917d3d92 100644
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
+	 * avoid double instrumentation via bitops-instrumented.h.
+	 */
 	return ((1UL << (nr & (BITS_PER_LONG-1))) &
 		(addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
 }
diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 3578ad248bc9..2aa122d94956 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -28,6 +28,13 @@ KASAN_SANITIZE_dumpstack_$(BITS).o			:= n
 KASAN_SANITIZE_stacktrace.o				:= n
 KASAN_SANITIZE_paravirt.o				:= n
 
+# Do not instrument early boot code.
+KCSAN_SANITIZE_head$(BITS).o				:= n
+# Do not instrument debug code to avoid corrupting bug reporting.
+KCSAN_SANITIZE_dumpstack.o				:= n
+KCSAN_SANITIZE_dumpstack_$(BITS).o			:= n
+KCSAN_SANITIZE_stacktrace.o				:= n
+
 OBJECT_FILES_NON_STANDARD_relocate_kernel_$(BITS).o	:= y
 OBJECT_FILES_NON_STANDARD_test_nx.o			:= y
 OBJECT_FILES_NON_STANDARD_paravirt_patch.o		:= y
diff --git a/arch/x86/kernel/cpu/Makefile b/arch/x86/kernel/cpu/Makefile
index d7a1e5a9331c..1f1b0edc0187 100644
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
index 84373dc9b341..ee871602f96a 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -7,6 +7,9 @@ KCOV_INSTRUMENT_mem_encrypt_identity.o	:= n
 KASAN_SANITIZE_mem_encrypt.o		:= n
 KASAN_SANITIZE_mem_encrypt_identity.o	:= n
 
+KCSAN_SANITIZE_mem_encrypt.o		:= n
+KCSAN_SANITIZE_mem_encrypt_identity.o	:= n
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
diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index 0460c7581220..693d0a94b118 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -31,7 +31,9 @@ KBUILD_CFLAGS			:= $(cflags-y) -DDISABLE_BRANCH_PROFILING \
 				   -D__DISABLE_EXPORTS
 
 GCOV_PROFILE			:= n
+# Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
-- 
2.23.0.866.gb869b98d4c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017141305.146193-9-elver%40google.com.
