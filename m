Return-Path: <kasan-dev+bncBDZIZ2OL6IIRBLVC5KZAMGQEKULSGRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7ACCE8D6DA0
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Jun 2024 05:10:40 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2c1e6a08555sf905527a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 20:10:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717211438; cv=pass;
        d=google.com; s=arc-20160816;
        b=itv0loxvBmFnJ3+Y2W3Sw28JorfNPqTlBFEig0A/i2GWKbe4zRqRtCol7CS3BWejCP
         AyY2ZrEuV4Z32C2Ld6RTGywSVG5C4Woy4y43V07bGqcIWgS5ZwLOhUM5vdH0latHSdD3
         iN1i3i+aAtTbUiFoZjnsMuGW8kwxLMKAcq37i+plqF+bjTA+JNeLnpgTCEwAM6Pf/+Iz
         QPQVzKMCvw/rAX1a1sWVGt7F/ymQvcFA79sepCazYdJss6n+7QmeByjSGWPPrFaVpIOn
         zpmeNGbDqwA7VrNpeMUBZ/Jmf8mX34QWjv+yMSq/cu0iL3ad7O+tEvUQd4BSAjcsSZBV
         3W1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature:dkim-signature;
        bh=oF/x1U9cir6uSTLCroJbAoYTxhKIzuTk5lCaJ0LXP7M=;
        fh=qcDefxvF2HCz/eAI+SC1lFJ/xzqV/rYXQlVrN+zz+wc=;
        b=iLgnZX/66X8arDt4V3T1PMBtanBr9kHydVACEGCwA+P4Lx0WCzh+bmohvNDMR7nuLN
         KAFfjcB9JmogI7KpUODxRDSxsj6otbMI65qk8hdsuGBAcBGtr7EYH5TGdC+oZ4d2DAhY
         I0EPua7x85Q5E9ObV0E2hxv8gsFE4ZeMOrDp0y88VsLkjN5oxHYKuBhzLheUHEJkY6m8
         LxiGCHaFR/n5IZzvtsyUKUlcEvJLJaDd2NnkbIQwClAmumlrYmy59c1T8xWUQWC+XyQg
         XYPt8SAohr0KkNwtbuF4pe3ga6bliMImIVHQ/9RSCTJebdqD+45ej0Atdfd8o53dpm9c
         Ktwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Hn+b7zTL;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717211438; x=1717816238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oF/x1U9cir6uSTLCroJbAoYTxhKIzuTk5lCaJ0LXP7M=;
        b=k+Epo2vPaawYMBgvq1ZnuYl38mafP5HPIe4uBg6PrtJmQsPOKRQ4wzitm0zyGq2YaV
         38uCMe1QCYxKApMnDZiECogM3LW1RycNbKlK/pldCRHHz/8i8ofNzW3bvo5KzudYReyf
         P/qmG6C9MjgF4nXoGBkMjrU7fwSCtlH1BBzWw0R7Sd9t2cK/5NTp3DYE7nROj5UwZZon
         DytuRT/fBYqWpix6K7WCAHpVYyBgUo0Ljh14EPM/fjkCWObZOdVaQsBryFmFLSHj/lYp
         UX36e4/SdOqRdfTRT3D9f7lmbbmYI2HryTSziOymuc0L1WSzwjOxrDZz+VbHOdMUsC3S
         qTPw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1717211438; x=1717816238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=oF/x1U9cir6uSTLCroJbAoYTxhKIzuTk5lCaJ0LXP7M=;
        b=FhRwphCRec6EQDUJ7qPp4ewZfxvos+wyfeFoDGhgJt2qMDV/tC3hpk0QTo9yAaVuXf
         Ijz0VscfBzJNuwyCSMjWQMBQmW7BG/v3X5nyCIoDd2PLtg0jTph75oXORJog03wTX9bt
         1jc2TeA0W1ccAGehP41YE7swXDlZ8HVxQtRup9pJzjmn+m6Q8mDY8N9uqWj5VSlBcqKN
         7j38aBqRRPZSfEZtT3UWSubkqlh5i6csdX5FwAD+yf1puiLaVA1+OR2BsgiNk4FX0fmz
         IsVeEibtF+/NJrPc2uutJ9ABnLmbVCJ+/Ez/n3cWEbRguBi47qrm8XlXx9rGr3QMebDH
         2ECA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717211438; x=1717816238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oF/x1U9cir6uSTLCroJbAoYTxhKIzuTk5lCaJ0LXP7M=;
        b=EIMBwQBhNj7/CWhnc10fK/z0S0PK/ceVCwTcoCf7poBEMHlNU0W1bXhFZ/wJNy16/P
         GAwe3irRvOPdSQZyETDgi0N2i1vNaAO22VdN3yB1BGKzY/yvierL1XPXQv8EkKQL7g08
         taoX4iyFe4cR4YKBPk1J970odBWcF9si16boYrlOS1RkJkfmV4oFFfox/aTU23UQkxuz
         qIik451ifBNzPbYQRX6wF6V39Uqq8vNsZE4UDK5rz3ATqL9FMA+VKuBgYqt0A8y1HIrh
         0WwGPALXfcM4HAJSXR5S6xxHk1ocJtKu1xVUVeffv6eMulomJalLIIw5ueCvEh2WLx2Y
         Omtw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbSZGR4FmoneoXLdhJD8bGSMJcIR4Q1eE0ii6EfhKeaF6MHdg79ZwydEYwo9+jpUETJL1DEtQMKwrNSTFM+4TaYjy/RT6yDg==
X-Gm-Message-State: AOJu0YxfHGAwS/hmsfiwkqlHi/LRLaU55yrlG07UjE2XRk7HcYH/4QRz
	gjLc5ocD+ceRTX3tf5+hKxo/gOOgjI5IdDYIAt08sJ8hg4/6FydW
X-Google-Smtp-Source: AGHT+IG7ptXYAXn1/qX6pNfmgmv9FKpuOrn3LbVfgJxewRG8McpgtXxg6QxBMNmry4BY6+xNbe86EQ==
X-Received: by 2002:a17:90a:f198:b0:2c1:a546:350d with SMTP id 98e67ed59e1d1-2c1c43df043mr5679718a91.4.1717211438400;
        Fri, 31 May 2024 20:10:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f00a:b0:2bd:9255:91ed with SMTP id
 98e67ed59e1d1-2c1a512ff8bls212633a91.1.-pod-prod-00-us-canary; Fri, 31 May
 2024 20:10:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnN5K76LnEO/S/A6LQI4+HhJkugTZESvz9+fVLvG/8Gc72732Dxl4dSg69iABuWHSlcYGYTa8zhkyOftsBu+h4WHFlPc4q0SFy4g==
X-Received: by 2002:a17:90a:4885:b0:2bf:7dd0:1713 with SMTP id 98e67ed59e1d1-2c1acc91486mr9182508a91.16.1717211436839;
        Fri, 31 May 2024 20:10:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717211436; cv=none;
        d=google.com; s=arc-20160816;
        b=oYjRKYGrraQGKR33sxbHRTS2sPlMbRLFb9AWyr2zu2FH4dkeuwvw706eY7ceriX3KP
         iPxHYvFcWuP5Da7tV+IxtQFKTPQ5Msa4Uknvix2H5c1YDdtllgcFlUgFEZ9Jz0YImKo2
         BiWhAvkW3GWwXu2Os44obzmHrkeF52JSVPDOzk7BEfd8LOBxaY8R8kQ/tXMEbyNoHh1V
         dVIxd0gSgbFy0wRgQrbeGjy0VShPHN43zClNenC7BR8JnK23T0tnTrj0uCfU45LiPaiO
         3MpVhfPKm5iwhhwvoUYsn0QZQ5SEW3g5UH4ArSexOA2XVxEBntyyiGeU2Jr+ncKkBOxt
         RhzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=SZapLPythn+7OkdKcS6JWdxzNsHsHOH/K7Ra5EurPq0=;
        fh=Q0mosOaehBPd1KUUXk6lG/TRWA4oUt58KayIpTk9UHI=;
        b=d/nkqhz1kPv4bu0Yzn7Y1mWb/GMHRwZHhJbdWd/8ORBWrc7KNLFCksFbaYE45/aobm
         fUwQ9snhbWPS0JNf/L92KrsahnHaSa0RUks2FpAzIjoJMcOc6YIhz5RNidk8ZM9brY93
         OFz+JE5CAjKfPd9uUcACXAtl1FnHDlefrPNiyHZBzbIEPJjvB2jQrkigbHzEpejGMqcD
         Vy9TYbEdb70iLb6jrQ/3EZKa5ODK2n5TQBIGdXa2JSRhW+9933xURQynzDrrf2leUSe4
         Y4LgykfUaIzQsEu/pZy0Pj1F/Cii8EM8uOAdNwByWmggWGkpYX/x3S4fiL2iGzTO0FbM
         IdnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Hn+b7zTL;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6c36a53c06dsi176295a12.0.2024.05.31.20.10.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 May 2024 20:10:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-1f48e9414e9so21920005ad.0
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2024 20:10:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV0a7K/ErQ3nXCVhiqEtkFCx5kOW960kbtLvX3N/Se1w7Fn5q5IVdoyoEzxAuc/EroT96+/WEb751jniPLkbQih/HswvbFJC+SEKw==
X-Received: by 2002:a17:902:780c:b0:1f1:8fd9:b99d with SMTP id d9443c01a7336-1f61bfa6dc5mr71550035ad.23.1717211436189;
        Fri, 31 May 2024 20:10:36 -0700 (PDT)
Received: from localhost.localdomain ([2604:a880:4:1d0::427:6000])
        by smtp.googlemail.com with ESMTPSA id d9443c01a7336-1f6323ddac9sm24097325ad.173.2024.05.31.20.10.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 31 May 2024 20:10:35 -0700 (PDT)
From: Gatlin Newhouse <gatlin.newhouse@gmail.com>
To: Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Gatlin Newhouse <gatlin.newhouse@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Baoquan He <bhe@redhat.com>,
	Changbin Du <changbin.du@huawei.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Tina Zhang <tina.zhang@intel.com>,
	Uros Bizjak <ubizjak@gmail.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2] x86/traps: Enable UBSAN traps on x86
Date: Sat,  1 Jun 2024 03:10:05 +0000
Message-Id: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Hn+b7zTL;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

Bring x86 to parity with arm64, similar to commit 25b84002afb9
("arm64: Support Clang UBSAN trap codes for better reporting").
Enable the output of UBSAN type information on x86 architectures
compiled with clang when CONFIG_UBSAN_TRAP=y. Currently ARM
architectures output which specific sanitizer caused the trap,
via the encoded data in the trap instruction. Clang on x86
currently encodes the same data in ud1 instructions but the x86
handle_bug() and is_valid_bugaddr() functions currently only look
at ud2s.

Signed-off-by: Gatlin Newhouse <gatlin.newhouse@gmail.com>
---
Changes in v2:
  - Name the new constants 'LEN_ASOP' and 'INSN_ASOP' instead of
    'LEN_REX' and 'INSN_REX'
  - Change handle_ubsan_failure() from enum bug_trap_type to void
    function

v1: https://lore.kernel.org/linux-hardening/20240529022043.3661757-1-gatlin.newhouse@gmail.com/
---
 MAINTAINERS                  |  2 ++
 arch/x86/include/asm/bug.h   |  8 ++++++++
 arch/x86/include/asm/ubsan.h | 18 ++++++++++++++++++
 arch/x86/kernel/Makefile     |  1 +
 arch/x86/kernel/traps.c      | 29 +++++++++++++++++++++++------
 arch/x86/kernel/ubsan.c      | 30 ++++++++++++++++++++++++++++++
 6 files changed, 82 insertions(+), 6 deletions(-)
 create mode 100644 arch/x86/include/asm/ubsan.h
 create mode 100644 arch/x86/kernel/ubsan.c

diff --git a/MAINTAINERS b/MAINTAINERS
index 28e20975c26f..b8512887ffb1 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -22635,6 +22635,8 @@ L:	kasan-dev@googlegroups.com
 L:	linux-hardening@vger.kernel.org
 S:	Supported
 T:	git git://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-next/hardening
+F:	arch/x86/include/asm/ubsan.h
+F:	arch/x86/kernel/ubsan.c
 F:	Documentation/dev-tools/ubsan.rst
 F:	include/linux/ubsan.h
 F:	lib/Kconfig.ubsan
diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
index a3ec87d198ac..1023c149f93d 100644
--- a/arch/x86/include/asm/bug.h
+++ b/arch/x86/include/asm/bug.h
@@ -13,6 +13,14 @@
 #define INSN_UD2	0x0b0f
 #define LEN_UD2		2
 
+/*
+ * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
+ */
+#define INSN_UD1	0xb90f
+#define LEN_UD1		2
+#define INSN_ASOP	0x67
+#define LEN_ASOP	1
+
 #ifdef CONFIG_GENERIC_BUG
 
 #ifdef CONFIG_X86_32
diff --git a/arch/x86/include/asm/ubsan.h b/arch/x86/include/asm/ubsan.h
new file mode 100644
index 000000000000..896ad7bf587f
--- /dev/null
+++ b/arch/x86/include/asm/ubsan.h
@@ -0,0 +1,18 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _ASM_X86_UBSAN_H
+#define _ASM_X86_UBSAN_H
+
+/*
+ * Clang Undefined Behavior Sanitizer trap mode support.
+ */
+#include <linux/bug.h>
+#include <linux/ubsan.h>
+#include <asm/ptrace.h>
+
+#ifdef CONFIG_UBSAN_TRAP
+void handle_ubsan_failure(struct pt_regs *regs, int insn);
+#else
+static inline void handle_ubsan_failure(struct pt_regs *regs, int insn) { return; }
+#endif /* CONFIG_UBSAN_TRAP */
+
+#endif /* _ASM_X86_UBSAN_H */
diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 74077694da7d..fe1d9db27500 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -145,6 +145,7 @@ obj-$(CONFIG_UNWINDER_GUESS)		+= unwind_guess.o
 obj-$(CONFIG_AMD_MEM_ENCRYPT)		+= sev.o
 
 obj-$(CONFIG_CFI_CLANG)			+= cfi.o
+obj-$(CONFIG_UBSAN_TRAP)		+= ubsan.o
 
 obj-$(CONFIG_CALL_THUNKS)		+= callthunks.o
 
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 4fa0b17e5043..ee77c868090a 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -67,6 +67,7 @@
 #include <asm/vdso.h>
 #include <asm/tdx.h>
 #include <asm/cfi.h>
+#include <asm/ubsan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/x86_init.h>
@@ -79,6 +80,9 @@
 
 DECLARE_BITMAP(system_vectors, NR_VECTORS);
 
+/*
+ * Check for UD1, UD2, with or without Address Size Override Prefixes instructions.
+ */
 __always_inline int is_valid_bugaddr(unsigned long addr)
 {
 	if (addr < TASK_SIZE_MAX)
@@ -88,7 +92,13 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
 	 * We got #UD, if the text isn't readable we'd have gotten
 	 * a different exception.
 	 */
-	return *(unsigned short *)addr == INSN_UD2;
+	if (*(u16 *)addr == INSN_UD2)
+		return INSN_UD2;
+	if (*(u16 *)addr == INSN_UD1)
+		return INSN_UD1;
+	if (*(u8 *)addr == INSN_ASOP && *(u16 *)(addr + 1) == INSN_UD1)
+		return INSN_ASOP;
+	return 0;
 }
 
 static nokprobe_inline int
@@ -216,6 +226,7 @@ static inline void handle_invalid_op(struct pt_regs *regs)
 static noinstr bool handle_bug(struct pt_regs *regs)
 {
 	bool handled = false;
+	int insn;
 
 	/*
 	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
@@ -223,7 +234,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 * irqentry_enter().
 	 */
 	kmsan_unpoison_entry_regs(regs);
-	if (!is_valid_bugaddr(regs->ip))
+	insn = is_valid_bugaddr(regs->ip);
+	if (insn == 0)
 		return handled;
 
 	/*
@@ -236,10 +248,15 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 */
 	if (regs->flags & X86_EFLAGS_IF)
 		raw_local_irq_enable();
-	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
-	    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
-		regs->ip += LEN_UD2;
-		handled = true;
+
+	if (insn == INSN_UD2) {
+		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
+		handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
+			regs->ip += LEN_UD2;
+			handled = true;
+		}
+	} else {
+		handle_ubsan_failure(regs, insn);
 	}
 	if (regs->flags & X86_EFLAGS_IF)
 		raw_local_irq_disable();
diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
new file mode 100644
index 000000000000..35b2039a3b8f
--- /dev/null
+++ b/arch/x86/kernel/ubsan.c
@@ -0,0 +1,30 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Clang Undefined Behavior Sanitizer trap mode support.
+ */
+#include <linux/bug.h>
+#include <linux/string.h>
+#include <linux/printk.h>
+#include <linux/ubsan.h>
+#include <asm/ptrace.h>
+#include <asm/ubsan.h>
+
+/*
+ * Checks for the information embedded in the UD1 trap instruction
+ * for the UB Sanitizer in order to pass along debugging output.
+ */
+void handle_ubsan_failure(struct pt_regs *regs, int insn)
+{
+	u32 type = 0;
+
+	if (insn == INSN_ASOP) {
+		type = (*(u16 *)(regs->ip + LEN_ASOP + LEN_UD1));
+		if ((type & 0xFF) == 0x40)
+			type = (type >> 8) & 0xFF;
+	} else {
+		type = (*(u16 *)(regs->ip + LEN_UD1));
+		if ((type & 0xFF) == 0x40)
+			type = (type >> 8) & 0xFF;
+	}
+	pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
+}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240601031019.3708758-1-gatlin.newhouse%40gmail.com.
