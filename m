Return-Path: <kasan-dev+bncBDZIZ2OL6IIRB7G7XO2AMGQEKNANIPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id C227692DA27
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jul 2024 22:33:02 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-78296514ec8sf824358a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jul 2024 13:33:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1720643581; cv=pass;
        d=google.com; s=arc-20160816;
        b=d0zOSCVZD2ob5oGE4b9FBFhaSIfFd8ikskHPfxHBoEuxzFqOS0YKoeW7wiR5dkKaDF
         X+uhDrxvv4ChJoP+VfSuZWyVLVNA+McG8NeBqVpe6SI8OcTeb4h/sNyE0Mu1ryAMDnL9
         0yrb0R2MV99zq52uO216snQzlmpsq69Qh5mOsYEQ8IvTNJCHUTsfUa7aWEpDsPAhJUb8
         TZg3P0aKrkzuONjvfl3uTd3MziXWDd2zaMbFuzDvRkWKOjSHnv6Qv+UwM97W3E98v0iW
         vxZp4jpGCIJ4ZW4KJI6J/mGrHMRNI5aamN5ubWLzUcBjRl/EPhJIZBi0I44zF2mwW/AN
         H6qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature:dkim-signature;
        bh=9+KvjS2hkDZF6cBM21sXmi3DU3OAvfiUByEikhOCnjM=;
        fh=+eS6NiTg/R/23tHVHt3TLin0Tk/NQg7duHXDg/BiTVw=;
        b=VBqGmfRqu4D+JEc0uogHCV15YWWiVtxa+MjJBqNUes7D3hcCMP7j5jktS76BD+qpNs
         D8v6FNo5DpeYRlYRd5XbZTikpnexL9omc8iW0gCzvDqtuiLFy3fwxV9Jdk2MJG9AUBB8
         iY7hUwvit0yzppKNZoByxrue62/46C8WU996wvs0cqQzbXvG/iDPLWGl5MyRbrzDA8bc
         2Ok1l8PB5Wjw6RYrMwvxU1fQKkGDgbHl8hiFL0JSmrxPOxvwLBzFVL6Jkza/SDiihPpU
         4Qb/sJId08ADQDX1X7MMy+MIlxHl2yIZkEl260+SvIFQNfTdK8ddyWndpmVvPQR5u2Mc
         3Gng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FXZj8YsI;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1720643581; x=1721248381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9+KvjS2hkDZF6cBM21sXmi3DU3OAvfiUByEikhOCnjM=;
        b=IhqEgMnyuT/olsJH90Cbjw6+daxzkwEOYTEJ668KVJzVeydQqOEP8GP5VNIngQ2uuM
         6RFiNPjSSfhwRhWfY8vzMRSvCJJAhxitZPTaTftTp1pw+ZVpNhYicE/HyfHXcRu7NOXO
         i1iclsyMy3gx2U9fVLAszyW9WznFUx8TZ2S890H948iPOB8ksKRA/2t6d8k2ZYA5ur+v
         +lM5IokA3CscDLxUSLDDMV/wWWiArRyKtvLaZpjjED0gaeYx+aU3WMT0qM4GZfGXFcmI
         i0rg/Ghkg2WYbaen1YXIx9rikNIMGfoMb1ToRQdm+RdwbZGj0DPrFcvQg8QK8lpVxKma
         T3KQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1720643581; x=1721248381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=9+KvjS2hkDZF6cBM21sXmi3DU3OAvfiUByEikhOCnjM=;
        b=bFMSBYIs1cKp6JNnMane9q8QEVCBtlursWnYLwFY8Y/GdIqLkfRLnX5XgERBVOFq1i
         UC9CtM+jDjfUdzwtH+p4FbdoH9RCXWvBAKnMeTIMjsoRuJKAjODE/CNByelJFmRn7I4A
         /muT+r30Un24obrWeOJ68BI+sHscSTqBXUFySI+b4fLfHBtbLn1vp81j+8pKkgCsp5yZ
         2WGeZLbJjJdHrpeHB1RYU7F42rFjauB9+WdF9KWQf6QbbHI25jH1J3doaSDhozO48hbS
         J3yd3lwlUC7RySVHENjEjzMid3HEav2nXy+lC2Zml6FL3zZq9CnjoQTxkAE+eiLd1dVY
         N9ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1720643581; x=1721248381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9+KvjS2hkDZF6cBM21sXmi3DU3OAvfiUByEikhOCnjM=;
        b=Bq1PxErErzpxDLSbTceHv6DlR3mCileUhtOlvbWeb3c+nRL2Vz7q6XtYHS8QgQr106
         rpirAsNV9g0uNKNeWqHxXuWznJPf5K5icUBws9Io/Mwanp2dhFJq+2gkECYDhN1KdDzf
         G5tFIZNXEe6/zweFN8S21OEP6jwpxL2BREXTeM6s32j5j7o4ZBkUyYC5CUqizrGHccqj
         uDl9Cp+N5eMXIXDMRoyfCplA9POUyewNUM2ou+q54mYIV7dh4Z39LggN8GYQxdKroa6V
         s6jBZA0a4pQ1Rg3bTCCTnOB3wFW3accRxKrm3Lx0IIxSesAO2wFULeLETJ/e7hk+TsCC
         /tGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXIn9k+9fC/tfo5zfV2H3H4FHgOF6f22qXSgFKc/WiKXKGMG3czlkj+ndI7gkp16rS68bWkUX4lAIdJtzAMAF8o7390SIICRg==
X-Gm-Message-State: AOJu0Yx+7YXWwcLOCPGjFZrfZpxYYQgXRo9JtSFyaJhT9jWedhI7GdZz
	uW4nDe6KiV2zRJD4ajBkywd5kE+s0gHLw1AP1SHr/DuGOLN0trs8
X-Google-Smtp-Source: AGHT+IH7FjVbKn9Y/GtNDr4bMmo4PcEBTg0uPE016Se+TR1pStLLbmnuXAzNsEl1OCYe7a00H9Syjg==
X-Received: by 2002:a17:90a:d149:b0:2c9:7343:71f1 with SMTP id 98e67ed59e1d1-2ca9dbc058emr986022a91.14.1720643580439;
        Wed, 10 Jul 2024 13:33:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2e41:b0:2c9:6419:243d with SMTP id
 98e67ed59e1d1-2ca75948ac7ls862075a91.0.-pod-prod-00-us-canary; Wed, 10 Jul
 2024 13:32:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXrDrABPh2dM9X/Ux0AY642xFCU5bsx0fMRat7vgdAdbqx5p9E10+6s1CUwiDfGo+2EoXceE0SnoMLi7RHP35jfiBVT0PDHKsqb8w==
X-Received: by 2002:a17:90b:8c:b0:2c9:63fb:d3ab with SMTP id 98e67ed59e1d1-2ca9dff47b0mr975517a91.22.1720643579103;
        Wed, 10 Jul 2024 13:32:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1720643579; cv=none;
        d=google.com; s=arc-20160816;
        b=LWOUDOFf/VbdzN03VccS2ogv2lsQqWbN5jSlOYoNf+GOpXmPp7OGkNMCaW4ZYzmG8s
         dJ82n8y27WVz9iluN9FJXQ/4FKZUUoX1xiDi0bBUvOX/mSiLoiFukgKqMhCkPiKRvAoY
         7mHmUKBYjPkJPjecliJlLodbVfzE51nEOB51m6/mKsVMHAvIQADpyVg+Cgi4ZmxxqU1W
         w4ABr9+3loMYpuYanf2mpYUTo4aDHawMO0TLzl7reqd9LkjXmSxLmlMNuemL6ZLrC3+M
         m8o/WZbekJvA32ImCDbhLVo7/91giXG5A0KgU/7eGqrI2QOq2Kf3xiUMb4ZPhWh2yQXe
         EJaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=Eq3JIg1oATa3NdJjOk623LvywPQZdgGRBXTXdShRg5I=;
        fh=vtQ1pYut/TqpiK1zr1Uwt++e2Yab3sO4XbQzJ5Ku+DI=;
        b=FwL84FheAMsH+ytCZ9AYWd3rAYc7gpRUwv0l6mIkokpuDQBZwSyW3/qthuDMzmThnq
         /bbs3P6xRlQwbUAne3SnbtVEq9zB8P+neWnYYzvHeDF7jUYa+EvuE84MFvPa7u4T9E3U
         N1q8Kd7xxMGvwjV1dG/DdGz3OUN5qcwLn2Ol5dakFiI6EqiuYCHLgq4Hseu5Adz8EvS3
         UBzaJABjDKkqtZ6k1FkcLA2nmZgzdDiO5el1j10XESj44UL1Sud+TeSUlmdXymTLAIk3
         IwuXoMhKyrIt1wkhPVuMrzCRuBb1feeFcCyONZGTUMdlWrD18J2nY32yrmkeFigRfYax
         MHdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FXZj8YsI;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c99aa70359si482770a91.3.2024.07.10.13.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Jul 2024 13:32:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-70b04cb28acso188844b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 10 Jul 2024 13:32:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW4H/JI4CPYovwXXiFUGGcVwPoSbyHWCrZzRfmoIbVz8vMVciUraKSZ+bg5sX4/2ZwqIstBZ11HByQkUBwrVnBqJ7Mz8LPUivC11g==
X-Received: by 2002:a05:6a00:986:b0:706:5c4c:1390 with SMTP id d2e1a72fcca58-70b5de18917mr903207b3a.7.1720643578437;
        Wed, 10 Jul 2024 13:32:58 -0700 (PDT)
Received: from localhost.localdomain ([2604:a880:4:1d0::427:6000])
        by smtp.googlemail.com with ESMTPSA id d2e1a72fcca58-70b439b5676sm4222180b3a.184.2024.07.10.13.32.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Jul 2024 13:32:57 -0700 (PDT)
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
	Baoquan He <bhe@redhat.com>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Changbin Du <changbin.du@huawei.com>,
	Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Arnd Bergmann <arnd@arndb.de>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v4] x86/traps: Enable UBSAN traps on x86
Date: Wed, 10 Jul 2024 20:32:38 +0000
Message-Id: <20240710203250.238782-1-gatlin.newhouse@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FXZj8YsI;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
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

Currently ARM architectures extract which specific sanitizer
has caused a trap via encoded data in the trap instruction.
Clang on x86 currently encodes the same data in ud1 instructions
but the x86 handle_bug() and is_valid_bugaddr() functions
currently only look at ud2s.

Bring x86 to parity with arm64, similar to commit 25b84002afb9
("arm64: Support Clang UBSAN trap codes for better reporting").
Enable the reporting of UBSAN sanitizer detail on x86 architectures
compiled with clang when CONFIG_UBSAN_TRAP=y.

Signed-off-by: Gatlin Newhouse <gatlin.newhouse@gmail.com>
---
Changes in v4:
  - Implement Peter's suggestions for decode_bug(), and fix
    inconsistent capitalization in hex values.

Changes in v3:
  - Address Thomas's remarks about: change log structure,
    get_ud_type() instead of is_valid_bugaddr(), handle_bug()
    changes, and handle_ubsan_failure().

Changes in v2:
  - Name the new constants 'LEN_ASOP' and 'INSN_ASOP' instead of
    'LEN_REX' and 'INSN_REX'
  - Change handle_ubsan_failure() from enum bug_trap_type to void
    function

v1: https://lore.kernel.org/linux-hardening/20240529022043.3661757-1-gatlin.newhouse@gmail.com/
v2: https://lore.kernel.org/linux-hardening/20240601031019.3708758-1-gatlin.newhouse@gmail.com/
v3: https://lore.kernel.org/linux-hardening/20240625032509.4155839-1-gatlin.newhouse@gmail.com/
---
 MAINTAINERS                  |  2 ++
 arch/x86/include/asm/bug.h   | 11 +++++++
 arch/x86/include/asm/ubsan.h | 23 +++++++++++++++
 arch/x86/kernel/Makefile     |  1 +
 arch/x86/kernel/traps.c      | 57 ++++++++++++++++++++++++++++++++----
 arch/x86/kernel/ubsan.c      | 21 +++++++++++++
 6 files changed, 110 insertions(+), 5 deletions(-)
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
index a3ec87d198ac..ccd573d58edb 100644
--- a/arch/x86/include/asm/bug.h
+++ b/arch/x86/include/asm/bug.h
@@ -13,6 +13,17 @@
 #define INSN_UD2	0x0b0f
 #define LEN_UD2		2
 
+/*
+ * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
+ */
+#define INSN_ASOP	0x67
+#define OPCODE_PREFIX	0x0f
+#define OPCODE_UD1	0xb9
+#define OPCODE_UD2	0x0b
+#define BUG_NONE	0xffff
+#define BUG_UD1		0xfffe
+#define BUG_UD2		0xfffd
+
 #ifdef CONFIG_GENERIC_BUG
 
 #ifdef CONFIG_X86_32
diff --git a/arch/x86/include/asm/ubsan.h b/arch/x86/include/asm/ubsan.h
new file mode 100644
index 000000000000..ac2080984e83
--- /dev/null
+++ b/arch/x86/include/asm/ubsan.h
@@ -0,0 +1,23 @@
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
+/*
+ * UBSAN uses the EAX register to encode its type in the ModRM byte.
+ */
+#define UBSAN_REG	0x40
+
+#ifdef CONFIG_UBSAN_TRAP
+void handle_ubsan_failure(struct pt_regs *regs, u16 insn);
+#else
+static inline void handle_ubsan_failure(struct pt_regs *regs, u16 insn) { return; }
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
index 4fa0b17e5043..b6664016622a 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -67,6 +67,7 @@
 #include <asm/vdso.h>
 #include <asm/tdx.h>
 #include <asm/cfi.h>
+#include <asm/ubsan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/x86_init.h>
@@ -91,6 +92,45 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
 	return *(unsigned short *)addr == INSN_UD2;
 }
 
+/*
+ * Check for UD1 or UD2, accounting for Address Size Override Prefixes.
+ * If it's a UD1, get the ModRM byte to pass along to UBSan.
+ */
+__always_inline int decode_bug(unsigned long addr, u32 *imm)
+{
+	u8 v;
+
+	if (addr < TASK_SIZE_MAX)
+		return BUG_NONE;
+
+	v = *(u8 *)(addr++);
+	if (v == INSN_ASOP)
+		v = *(u8 *)(addr++);
+	if (v != OPCODE_PREFIX)
+		return BUG_NONE;
+
+	v = *(u8 *)(addr++);
+	if (v == OPCODE_UD2)
+		return BUG_UD2;
+	if (v != OPCODE_UD1)
+		return BUG_NONE;
+
+	v = *(u8 *)(addr++);
+	if (X86_MODRM_RM(v) == 4)
+		addr++;
+
+	*imm = 0;
+	if (X86_MODRM_MOD(v) == 1)
+		*imm = *(u8 *)addr;
+	else if (X86_MODRM_MOD(v) == 2)
+		*imm = *(u32 *)addr;
+	else
+		WARN_ONCE(1, "Unexpected MODRM_MOD: %u\n", X86_MODRM_MOD(v));
+
+	return BUG_UD1;
+}
+
+
 static nokprobe_inline int
 do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
 		  struct pt_regs *regs,	long error_code)
@@ -216,6 +256,8 @@ static inline void handle_invalid_op(struct pt_regs *regs)
 static noinstr bool handle_bug(struct pt_regs *regs)
 {
 	bool handled = false;
+	int ud_type;
+	u32 imm;
 
 	/*
 	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
@@ -223,7 +265,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 * irqentry_enter().
 	 */
 	kmsan_unpoison_entry_regs(regs);
-	if (!is_valid_bugaddr(regs->ip))
+	ud_type = decode_bug(regs->ip, &imm);
+	if (ud_type == BUG_NONE)
 		return handled;
 
 	/*
@@ -236,10 +279,14 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 */
 	if (regs->flags & X86_EFLAGS_IF)
 		raw_local_irq_enable();
-	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
-	    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
-		regs->ip += LEN_UD2;
-		handled = true;
+	if (ud_type == BUG_UD2) {
+		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
+		    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
+			regs->ip += LEN_UD2;
+			handled = true;
+		}
+	} else {
+		handle_ubsan_failure(regs, imm);
 	}
 	if (regs->flags & X86_EFLAGS_IF)
 		raw_local_irq_disable();
diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
new file mode 100644
index 000000000000..c90e337a1b6a
--- /dev/null
+++ b/arch/x86/kernel/ubsan.c
@@ -0,0 +1,21 @@
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
+void handle_ubsan_failure(struct pt_regs *regs, u16 type)
+{
+	if ((type & 0xFF) == UBSAN_REG)
+		type >>= 8;
+	pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
+}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240710203250.238782-1-gatlin.newhouse%40gmail.com.
