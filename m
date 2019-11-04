Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP7LQDXAKGQEHMPZDZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 39698EE26B
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 15:29:20 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id d140sf6062227wmd.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 06:29:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572877760; cv=pass;
        d=google.com; s=arc-20160816;
        b=u3I2jrcVcR7Mxc3JrAhF/vEXzp32h9qk1Yh0EiC+rdeLp6AvzlUMuXqoSSN0oX43vZ
         oCLB3KOiumC7m/XZ4ito+e6MnRbz+3X38jYQP9hceiA+jqJKb29OYs5Fsp8IU4ToutVs
         0wOckzTVX7F0ZNTW7mnpKX3fF/pJX5ruJ9elxqCVzzg0td8xkZ8/l47JkcmY/UOOVRAq
         xkmv7k5r4qhKoFXzwuLliBSKkagR9Ci73rdy6ysQQit9R/Gel3lx55xHAyMpnjYHVn+f
         u5kvFoBOPEuMPDlwoDmQIJj5blMrKQ9iZxtrrLivKlp0hwy+ZZLtvhuISJ803rx7VDXJ
         g+gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=WLIWhS4UbE3qi1YAE8sPCfIDQN7IE4zWOy+uBPzoolM=;
        b=beJ72MR2XTU0W7uvWD6NkKMBFcvlOwSdUJyZi7TLjX4l3gODOmfinYd0ULZAA1YvBr
         EKOuuHR+oqrQeeGUHjcI8ORS4DrGA8RXxqkdA6Em1dVhfn1Xgy1Q+7D9G8Ju19vA36Az
         hJUjYu9yoUKSJWAv2HeLG1GDqiFz3UMc+GNmXTw+yO35DsAfUw+BK2civJ8AGiy2tvRI
         n4CrcSsD1YUt8wbLibdTQtG1lKx+Oqq6kM+f4bNwQqXYLBwwEc0hMtRYnRDUP4kxl64w
         D9USW9MMOt16RUM1BdUIw8lStvRu1P+k4mXu/dTjGSIkqqpjk6/V0v1UFGl2ydHhN5iT
         duQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RwMp4ufZ;
       spf=pass (google.com: domain of 3vjxaxqukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vjXAXQUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WLIWhS4UbE3qi1YAE8sPCfIDQN7IE4zWOy+uBPzoolM=;
        b=kykW8TfjBxz1JupjX61r8ROgz76H5UGqad4IqyWWcCBMqz6xeyWdZyXgt7uD++p1de
         sTQQ7Il5HW9M/WHxDD+ppYxikxyGXY7btv6WVfZcl5hTr6dMygztR5D9NvPjp5kBi4S5
         G6VSOJbHYrUso7zMBosY6gMJUNjlEOiLfBulefJPxCXY16seFnM7eUd1UFF2eOU2guUD
         LgFSprfgvANllJ6HbN9OnDvJOGHnmlcclnpyberSdejlD48AuDJMjEcgUyfLquDyF9v/
         vn60yd1i+ytGGByLkudkSPymYoXRTRDTkMjX7+ndmm8prc074Nus2n/ZNgr6cV7Q0CM8
         B0nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WLIWhS4UbE3qi1YAE8sPCfIDQN7IE4zWOy+uBPzoolM=;
        b=tJO6LHVDLNTqZiJaCOJWfrqg6H/abNUT/DNCTvTYWPhjkvyybgtzixrlgw8S0rLHqe
         Th9UhwrAz/sYCSPWNivwxExwi4r45DPx7zIpOfbI8tKOZjgca0cBFYv4ecW0ukU9no0g
         Fenxx6Q8VKUKhOW9GusSdu5MVE4XtQsYU7IfbqB5HnyDe2kg69Mw5J3tnr86bfrnawH0
         0z5y7e57O8adBfIIqK41bUTI40qT252gBKoQVnNZY6S6W3Sx7LTwICET6t5GxRT15rly
         Avh50W8KTBipoSb9cOcWudW0CenPpys7fQ+AVgWHNuw06/2BlTV67Rc1PuE7TVavQ4Hz
         s1uw==
X-Gm-Message-State: APjAAAWqG4Bk0WsxByXPmyXovXO82lcLRdp5aWTMuAN7CHlQAKqACIMj
	xqxLxfLOmqtZ73cd5F8sILk=
X-Google-Smtp-Source: APXvYqwnvDbvAaK5Z4OCl9xALT8ea1aVP4itIzraekpf7OZAUkQmHymqYmbFyVHsMxJrD6I6PwJUGQ==
X-Received: by 2002:a5d:674d:: with SMTP id l13mr13448551wrw.170.1572877759961;
        Mon, 04 Nov 2019 06:29:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f61a:: with SMTP id w26ls17110860wmc.5.canary-gmail;
 Mon, 04 Nov 2019 06:29:19 -0800 (PST)
X-Received: by 2002:a1c:560b:: with SMTP id k11mr25132414wmb.153.1572877759361;
        Mon, 04 Nov 2019 06:29:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572877759; cv=none;
        d=google.com; s=arc-20160816;
        b=DlW+Mv68r3en0H/8FdtHNhQF0ufD1VheLCo8Eg6RLF91PwBGtMo+K0LyjGQPVQnPir
         r4tNY/qOYLjohnVZwEmSkv2wEyCwEMum8NkY8Pg1vbBz7rSSqPpEaFOghxHDx94Ssr/X
         IFtoIkvMVdriAlVppVektHBY0tmsX502a7TR3taADckavXfv/pcdjwSz0Lo9ixtPJrbN
         HaVsHkHg7UfHJ47pEViFA7lJZyLkyrurO4rcBQzD97fYzhBenTDqtbuWwyTLxDiYOuM4
         raisA6A1xwZrTE5gXN6OP8Yt6S6PlPjONEuFk4JHPOzfu6QoudIZN0r1nUg3n9Y0Y+ih
         l99Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=v/fBCawgbNr9z8sHoDyBwn+JenP5278dLuCFcze5nO4=;
        b=UvTMG/pJivFsJWqqHQ1J+J4cQfVpJVuuEoBM51fKmjPN7jAcL7IArS+IIjx+BemzaL
         G/IA8q2yzcWw5kE2P0Z7kPc+Z+pl7BlOcpyeEKmg4H04t0MAgneaY9ICW/FxNy3osTiR
         YZoh9we+fMOZzN4p2HoFzIEZms6EPS0Ab00rID8WOgZECtO2AvEi6Hu08jGGnKXwQM1t
         IhRh0aDWQZ6p+WsGiH6SqVSd8hi53El45arEKl/NO3KydxyMIaG6SJ2YBXoSwHk0QI9l
         o2y71+9ieQCXJ0AauvuglCon/FXOvB5R1ZOUAg9BZB3PFtdkjJiW4kAYUUYa99dixyms
         PKOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RwMp4ufZ;
       spf=pass (google.com: domain of 3vjxaxqukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vjXAXQUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id t18si957718wrw.0.2019.11.04.06.29.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2019 06:29:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vjxaxqukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id s9so10436998wrw.23
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 06:29:19 -0800 (PST)
X-Received: by 2002:a5d:4808:: with SMTP id l8mr23085087wrq.118.1572877758478;
 Mon, 04 Nov 2019 06:29:18 -0800 (PST)
Date: Mon,  4 Nov 2019 15:27:45 +0100
In-Reply-To: <20191104142745.14722-1-elver@google.com>
Message-Id: <20191104142745.14722-10-elver@google.com>
Mime-Version: 1.0
References: <20191104142745.14722-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v3 9/9] x86, kcsan: Enable KCSAN for x86
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
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RwMp4ufZ;       spf=pass
 (google.com: domain of 3vjxaxqukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vjXAXQUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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
 arch/x86/kernel/Makefile          | 7 +++++++
 arch/x86/kernel/cpu/Makefile      | 3 +++
 arch/x86/lib/Makefile             | 4 ++++
 arch/x86/mm/Makefile              | 3 +++
 arch/x86/purgatory/Makefile       | 2 ++
 arch/x86/realmode/Makefile        | 3 +++
 arch/x86/realmode/rm/Makefile     | 3 +++
 12 files changed, 38 insertions(+), 1 deletion(-)

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
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104142745.14722-10-elver%40google.com.
