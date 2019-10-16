Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP5PTPWQKGQEVSHFIOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id DAA05D8B61
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 10:41:35 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id q22sf671816wmc.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 01:41:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571215295; cv=pass;
        d=google.com; s=arc-20160816;
        b=mShjGYZXwQ4QOMdbLNNjwiitpzsrGkNvhhOo+2YnIvP7jnIeBBsvkQnzFKdmNOsa+v
         /3hn64OwiSx9UMc+Z3HPviNyz0T1ZLq+tlELDY/rBTX0pRQGiNboG6o2q1DvfbNAUs8p
         /ew3reCS9AMwsSee19f/14V32x2Z1AHwGweYp1V69qtOomyCU1ohlsiYkE632gIkIahf
         uanDC1U9p2jmFob6XvdUhfxs/VQjGaqzrCHsog/fOcVhbDqbz7JUsPVzD3Ql4zwGx+2V
         Lu9itQ7TscnBJGLhl/uJtS7r1D9SB6+jjodK23OTDncIa0o8fi2MXhazXq57DAHdVXSh
         +miA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4qfduTA0VD6ZaxfWYfrJ0JhST8FX5G8IOwwgjvVHjcs=;
        b=su7PhDu/wvGibIgFqXmisDFjlZMIuhPIF0okOtksmf8HSPu4v3NCtxaZlskfjXS0E3
         RtvDyGa3z+u0LlqgTKTBAAuRAUUPVATbXdx41/FLjI9fu9TTLD2REtNucST7zyCUJpfo
         i56db1JLALLLt+RTmBb6la6apzTu7u892Phn8te9aJV54aZY3z1Mr5+vS+fQn+pCXcDJ
         mQc8OAHD2MMJ7UX84ACMtenDomRvTPzZ5X9/CHkD4hTx+BlkXZHnXJRnBQAXA92cvY+l
         eooU2hL/yCtrHhMIsRkOiXlXsdnuSxsfZ+PZWHPAt7MA8UfNde3178pMr5rOC3H+uvOI
         j/mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NSrpYdVj;
       spf=pass (google.com: domain of 3vtemxqukcfshoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vtemXQUKCfshoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4qfduTA0VD6ZaxfWYfrJ0JhST8FX5G8IOwwgjvVHjcs=;
        b=dwtr52QQRnhMhQfcxqGld9oWPU7ju3Fq/O6vo9aIbo/PAAaS42R+YkA/R+hIGUgNV2
         azE6Q5xmDLxwNWLKBjmUqzqG3P08CB8z3W8BExZe8y6LMpKIJIXzhlv1Q/soyECDDoHn
         KSHYoDTwkSKW59MRp1HdcGv44E3+2bCdrIJnGh1Z/nHoWbQmZ/fWP8RIQnwhDZcpCui9
         kxTw45I4NyWEFV8hOXmmOzkN6ej5SbLvGtqHq3rdmJgjTyCWCQcCLaJRtSy/Kp3g31dK
         ViQ6AbTU22XIZSCDjqstronaHDXbTrroN6cosRcQeeiz6tWMuJPwtYkwViGKxswgaa+t
         XqfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4qfduTA0VD6ZaxfWYfrJ0JhST8FX5G8IOwwgjvVHjcs=;
        b=iHcS0BdIqfOIrAshX+EI7CeVHAL04CIeM9MEnut5WuLH5bAeP3exWBoBbgx7IvAHdR
         cTw3UMCCBAUSuKrPiVm6eyGNRsB7IeKO55Hfz9TxW/9JXEN6tqi2CiiSVzA24NGnKiJk
         4hA0FR2ZJCJJz5EKNy+JgRTI8oP/Q7TmhBxtRVJLASJvQ8wJElBbpUHYlhcbjqKXGgTk
         SAYE10pTZlPt4P5EVwHy2LOz9idu71sM6l2FsSnUvMvhlg1h2sny7znflEPXIa6r1TiT
         VQnE3O3RVudqaHQGbyzr69dG7QI8e2Ud0Hkp/iqLtVduTB6kykWzdtyOV7FLn/lSCplj
         QYEQ==
X-Gm-Message-State: APjAAAUbrTmzEym0fUukhJWssasHgZ7i1naTR3Qd3s7wgmpS+dtAqO4Z
	uPE2iXi4bL76XipeneqDVFs=
X-Google-Smtp-Source: APXvYqwPjV//R+zil6dF2q345SJjpl4jaM8MnwWHZe4WUVZewlqmLUsfYYFNxAM17J76YHmyoP7GQw==
X-Received: by 2002:a7b:c206:: with SMTP id x6mr2398964wmi.147.1571215295551;
        Wed, 16 Oct 2019 01:41:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:54cc:: with SMTP id x12ls7924263wrv.0.gmail; Wed, 16 Oct
 2019 01:41:34 -0700 (PDT)
X-Received: by 2002:a5d:5743:: with SMTP id q3mr1641447wrw.394.1571215294969;
        Wed, 16 Oct 2019 01:41:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571215294; cv=none;
        d=google.com; s=arc-20160816;
        b=uV3wEzn5LOobaOuLjlc4kKBXuPpjbjulfxafwO44JhbJNQdjiN126ET2dMO7pRR3/v
         PaF/MdEDjFkLidSCer482ewS+ITa+V4jFJrytggVbIrnRwiClnRTh76TvzfTRtERsJtr
         obgGB/HXvw/PaxapNLJkuJp4p0dgzSvS1aSBkTU7wq5zAEUr5q1J3q/Xyix/fRPsh9V+
         uCeN8gy3iANWQK4oQohlTEROjx6b10eHcp1NPn7cC2l6a7XXVkz5qA+gpDmhtnWnG7Gn
         Xk3b0u03eZqTquh0ns4oXzYXBkaWK9Qek3MBY4Xh8xM+A7x4Px940IWJAjp41cq5cVS+
         fLAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7ROjjIT0dSiqK7weicBG4sWceIh3b0q1ZAIHDJ8V6Dk=;
        b=fGalGkiTTBSzhmY+oa1HCabdJKwwAwppkCQA1ylz8zB9IL6/CbdPpjnSQPBgHmPoyg
         xEHMdCHVkcvnLY4qd2OyHsXJ78sviXr5Wn9G0qowJm5v0TsHbGqez1qEKWIOpy21jXtW
         udQwRnjGnj4nMzUcdCbvp/B6uxNOz2VmULaBe9NL8jD7SniKwj4g01K7M+dBQuu9D7jE
         uRwBIre8zCk4HZaS/z8qHZ83xySjYe3VKTm1y2/SNm38XWaVFHJ8q5pYUCattEwZd3LW
         f5OAyxJx9VkA3QgqDEXQK+AuQpTDL/Rx+Xg/PNmWDM7RoUqlzFkkUjgs1+FZF2s+Mzh7
         EvHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NSrpYdVj;
       spf=pass (google.com: domain of 3vtemxqukcfshoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vtemXQUKCfshoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a133si319977wma.4.2019.10.16.01.41.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 01:41:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vtemxqukcfshoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j7so11426328wrx.14
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 01:41:34 -0700 (PDT)
X-Received: by 2002:adf:e983:: with SMTP id h3mr1520622wrm.95.1571215294184;
 Wed, 16 Oct 2019 01:41:34 -0700 (PDT)
Date: Wed, 16 Oct 2019 10:39:59 +0200
In-Reply-To: <20191016083959.186860-1-elver@google.com>
Message-Id: <20191016083959.186860-9-elver@google.com>
Mime-Version: 1.0
References: <20191016083959.186860-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.700.g56cf767bdb-goog
Subject: [PATCH 8/8] x86, kcsan: Enable KCSAN for x86
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
 header.i=@google.com header.s=20161025 header.b=NSrpYdVj;       spf=pass
 (google.com: domain of 3vtemxqukcfshoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vtemXQUKCfshoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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
 arch/x86/Kconfig                      | 1 +
 arch/x86/boot/Makefile                | 1 +
 arch/x86/boot/compressed/Makefile     | 1 +
 arch/x86/entry/vdso/Makefile          | 1 +
 arch/x86/include/asm/bitops.h         | 2 +-
 arch/x86/kernel/Makefile              | 6 ++++++
 arch/x86/kernel/cpu/Makefile          | 3 +++
 arch/x86/lib/Makefile                 | 2 ++
 arch/x86/mm/Makefile                  | 3 +++
 arch/x86/purgatory/Makefile           | 1 +
 arch/x86/realmode/Makefile            | 1 +
 arch/x86/realmode/rm/Makefile         | 1 +
 drivers/firmware/efi/libstub/Makefile | 1 +
 13 files changed, 23 insertions(+), 1 deletion(-)

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
index e2839b5c246c..2f9e928acae6 100644
--- a/arch/x86/boot/Makefile
+++ b/arch/x86/boot/Makefile
@@ -10,6 +10,7 @@
 #
 
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Kernel does not boot with kcov instrumentation here.
diff --git a/arch/x86/boot/compressed/Makefile b/arch/x86/boot/compressed/Makefile
index 6b84afdd7538..0921689f7c70 100644
--- a/arch/x86/boot/compressed/Makefile
+++ b/arch/x86/boot/compressed/Makefile
@@ -18,6 +18,7 @@
 #	compressed vmlinux.bin.all + u32 size of vmlinux.bin.all
 
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
diff --git a/arch/x86/entry/vdso/Makefile b/arch/x86/entry/vdso/Makefile
index 0f2154106d01..d2cd34d2ac4e 100644
--- a/arch/x86/entry/vdso/Makefile
+++ b/arch/x86/entry/vdso/Makefile
@@ -12,6 +12,7 @@ include $(srctree)/lib/vdso/Makefile
 KBUILD_CFLAGS += $(DISABLE_LTO)
 KASAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
index 7d1f6a49bfae..a36d900960e4 100644
--- a/arch/x86/include/asm/bitops.h
+++ b/arch/x86/include/asm/bitops.h
@@ -201,7 +201,7 @@ arch_test_and_change_bit(long nr, volatile unsigned long *addr)
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
 }
 
-static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
+static __no_kcsan_or_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
 {
 	return ((1UL << (nr & (BITS_PER_LONG-1))) &
 		(addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 3578ad248bc9..adccbbfa47e4 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -28,6 +28,12 @@ KASAN_SANITIZE_dumpstack_$(BITS).o			:= n
 KASAN_SANITIZE_stacktrace.o				:= n
 KASAN_SANITIZE_paravirt.o				:= n
 
+KCSAN_SANITIZE_head$(BITS).o				:= n
+KCSAN_SANITIZE_dumpstack.o				:= n
+KCSAN_SANITIZE_dumpstack_$(BITS).o			:= n
+KCSAN_SANITIZE_stacktrace.o				:= n
+KCSAN_SANITIZE_paravirt.o				:= n
+
 OBJECT_FILES_NON_STANDARD_relocate_kernel_$(BITS).o	:= y
 OBJECT_FILES_NON_STANDARD_test_nx.o			:= y
 OBJECT_FILES_NON_STANDARD_paravirt_patch.o		:= y
diff --git a/arch/x86/kernel/cpu/Makefile b/arch/x86/kernel/cpu/Makefile
index d7a1e5a9331c..7651c4f37e5e 100644
--- a/arch/x86/kernel/cpu/Makefile
+++ b/arch/x86/kernel/cpu/Makefile
@@ -3,6 +3,9 @@
 # Makefile for x86-compatible CPU details, features and quirks
 #
 
+KCSAN_SANITIZE_common.o = n
+KCSAN_SANITIZE_perf_event.o = n
+
 # Don't trace early stages of a secondary CPU boot
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_common.o = -pg
diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
index 5246db42de45..4e4b74f525f2 100644
--- a/arch/x86/lib/Makefile
+++ b/arch/x86/lib/Makefile
@@ -5,11 +5,13 @@
 
 # Produces uninteresting flaky coverage.
 KCOV_INSTRUMENT_delay.o	:= n
+KCSAN_SANITIZE_delay.o := n
 
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
index fb4ee5444379..72060744f34f 100644
--- a/arch/x86/purgatory/Makefile
+++ b/arch/x86/purgatory/Makefile
@@ -18,6 +18,7 @@ LDFLAGS_purgatory.ro := -e purgatory_start -r --no-undefined -nostdlib -z nodefa
 targets += purgatory.ro
 
 KASAN_SANITIZE	:= n
+KCSAN_SANITIZE	:= n
 KCOV_INSTRUMENT := n
 
 # These are adjustments to the compiler flags used for objects that
diff --git a/arch/x86/realmode/Makefile b/arch/x86/realmode/Makefile
index 682c895753d9..4fc7ce2534dd 100644
--- a/arch/x86/realmode/Makefile
+++ b/arch/x86/realmode/Makefile
@@ -7,6 +7,7 @@
 #
 #
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 subdir- := rm
diff --git a/arch/x86/realmode/rm/Makefile b/arch/x86/realmode/rm/Makefile
index f60501a384f9..6f7fbe9dfda6 100644
--- a/arch/x86/realmode/rm/Makefile
+++ b/arch/x86/realmode/rm/Makefile
@@ -7,6 +7,7 @@
 #
 #
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index 0460c7581220..a56981286623 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -32,6 +32,7 @@ KBUILD_CFLAGS			:= $(cflags-y) -DDISABLE_BRANCH_PROFILING \
 
 GCOV_PROFILE			:= n
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
-- 
2.23.0.700.g56cf767bdb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016083959.186860-9-elver%40google.com.
