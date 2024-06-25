Return-Path: <kasan-dev+bncBDZIZ2OL6IIRBOPR5CZQMGQES4OHBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 82C9E915D52
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 05:25:46 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4404a08e4d0sf115765631cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 20:25:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719285945; cv=pass;
        d=google.com; s=arc-20160816;
        b=MWRBD3nLwoqSxsDAgHrmHqcSRuMbv4I+z/WjWkVMO8u+CzbABawnL5c7aQXGmBRV9C
         YZdG4xigFwUm2BHaJx9uHNymYQL17gzlKdoUZI38qDpjry6O7VcXeN5tgmGZFfPUXZ5p
         afu3Z/CP7rzEkupdO8GlLdrbvh4HqZJmEu8apS6foJfdzlTcovBvDmY2AGBr9rfoJ+NM
         4o4fgwCesiVGvyX0yO5H0q5Dqyn/zMAXswFn8VbYsh8LRAXvdWfsaAiqhacmpr80eQnp
         5BsANO3RWPp1eKzjVh/gRDApbiaDZNPS7JMAPYhl3Ar3IV4dXhd+HZtWCYmnWLRFhO1r
         sO9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature:dkim-signature;
        bh=Nxf1fiJT4teYUjXJAemaXitH5weAy66zIJWO9X/f3JA=;
        fh=0CR7XSVCvy4qlwHPKYfEPs96hR3xyDGwkoolErvAgck=;
        b=ipN/j6QkzhNhLnqqpxT2yh91c5U+dSx6L+zxDelVP3kapqI1bV349WWQ0TI85QbYVC
         z7o3v++Y8XNT7V8aoVJkrkCKz8VB/Vgr+papZaDp8oNdGwpDFDNBbmnNs0cf990MHMPN
         PKCEq0F8/NsD/AhBbnBo9+IoVgVPVMF5i4DqBazpOpylLtkTChRzQxv3iXXWSnWHoah5
         AViuhGrV/vYiv7jUzBW251Vi9LwVQtSZbW9FiTVO7CovbzO/rQV3ONAOScC5v0bkEHI5
         dHQiolHibnzVBXGox3SU4+Q0xnyj+cz02LTe2vsHo7vw9vjGyXlBfY8z9vGGiZOPU1O9
         gmCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EWMpGRid;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719285945; x=1719890745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Nxf1fiJT4teYUjXJAemaXitH5weAy66zIJWO9X/f3JA=;
        b=C/ytdd77PpXILHGgRAIE28wB+Wnr4aZQPefVSxnr65bF56jpZkHYB5WXVGa4OnOGIk
         8bV4/Z7eqsUzC+wIjEHT6lmMxcFF/wpPzGuYVzNt7zC8o31wDkfOcXxfAcQgXpT+Ppx+
         x39tSvxEIbZEwQ7ZjHi5TU0nhffjYikRvA2I7sBb30bmFII7nsfFo81nxkccjSWQyQch
         Ntfs26MIBUlIU17xg/jqsGM4HF50amvkw5UotZ7qTqRXFGKLmjpvsXYusWTJil8uNb6n
         n0TI8AKK/OlL3hkPSEoxYLh0t3FxE+CVUfbN8O0PjGZuvG4yeunplazUlL5EBNfmEpEZ
         gFRQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1719285945; x=1719890745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Nxf1fiJT4teYUjXJAemaXitH5weAy66zIJWO9X/f3JA=;
        b=CztmlBB6cqvjNcX8wfJK8mpT6PgQRTTqQhZVPJD8MJ5kAhSZ+3SJHDvTw6vLXjN9gS
         gEUxNyxh2q36fOTN7zjVYqUZmR6l2ROQNK17+YbwixEBf0G6XjO8a7xl/Kqzt27+WKRN
         mjKXqOb+Z/4vcmLVYYCN+hOruWgh1DNwevZxSYT0TSrXXPVJUz/UgTvZaC2iHHomCL2L
         STt+1NZnZvwlC6gIJnsNG93qy9zIFuC9LVKb1Z/2RFLCx33dkKDr4aYTgK9QK4oVzquS
         oXmzeZMRPinTnzZ59Zr8rw+zSMIPfQ3rFMKhjjpfwlxe5n08JTyLILLxPKWyNdY+RYAo
         aCUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719285945; x=1719890745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Nxf1fiJT4teYUjXJAemaXitH5weAy66zIJWO9X/f3JA=;
        b=LRvfZM00RUA7mtGFYTt1XhSdgbV8Ac/zyF7tnAHZ9xgwfByVgRQsx37IGUVaSQh6Ol
         nj4Sdk95I9vR+Je32ZoHCVTOoa3QhFItmQxkzutfo99rRKsp/vvB9Z7tMGsAdTKkbk03
         eSqlr1Ic1+KY1cibt1unl74OiLDsjJ6oTvUd6+NVrdPm/M/5jAA0CXvAtmqNIaCH10TL
         5oXAr8VJ56mhzbaBQ4KFawesfSTK7AnY9LDejE5XuO24lVveaP5Gj6IMuoVmmBPxZtct
         LBk18LgOx+FpjCKgfWSfwgEG59Xd+M7g5IqTsKdKFJS35K21ojtzpNzjtxhLHa2w9A6T
         xuRQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUvJIp5qPJRYBYsgM6bBLBLGx7RojGaCE8IT6Qz3F0gCNCHAU5OYYKJLS676esj+7bpZqdSn4VpIyYnAnAWlw4kz34ZcOMkQ==
X-Gm-Message-State: AOJu0YymXUWkKSLwHjUwyR1sRbb3nMQEM/yqgiBSInPQIW1z7zcrk1G/
	Is5ki4kYDTllQQi6lz4f1ncBArE+8tSjAHwDHlyZ+ngFCuVNcJrG
X-Google-Smtp-Source: AGHT+IG5MctZQePVcDD8D5irhiC34xcjll5bynK8/eH2TO7d0sCtWEY5TJEGC3Xv5b77swEZRsrh7g==
X-Received: by 2002:a05:622a:60f:b0:444:faf2:1a48 with SMTP id d75a77b69052e-444faf21ea3mr791021cf.31.1719285945239;
        Mon, 24 Jun 2024 20:25:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5783:0:b0:444:f49b:2483 with SMTP id d75a77b69052e-444f49b5a6fls4393751cf.1.-pod-prod-00-us;
 Mon, 24 Jun 2024 20:25:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQEhtfscso4SPY3QcX74cRilc7Ucgcr5LXV7/6gzJKZV7Y1WwOTd6z+pI3KskIw8eGaL5xkSHeWBZsRzRSaenwckN0JSCSC1BNBw==
X-Received: by 2002:a05:620a:19a9:b0:795:484a:7f05 with SMTP id af79cd13be357-79bfd6236e4mr373809185a.1.1719285944357;
        Mon, 24 Jun 2024 20:25:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719285944; cv=none;
        d=google.com; s=arc-20160816;
        b=ALDJ2bXUUN/3DhreyK4mC0HBYbvRUT19WCovtSXT2uXHyAfcMsbesl7xg6Mu/clj/F
         QoBwxkjQyKfJsI0fxFpHRdCpAGLpViZdMHVDTJF9rYvkJcvBPwLCMzxdF/zAIeWKRSbi
         uFvB1ITateVxcCW9C/cjSQubVF2xsL8UVdCsZ1gbPmt1ZnjcHpHKI8lZKSNddiTcinPi
         Cv0NAQ0forRF9aIsCNAvTrsHhl8XrwjZ/hTdUQUsXeV0Jym4Q8Vm+gjcrDpMuz6Kn1Yr
         0Y4uIeUNn4W1CBp8RHiDhuMsJGjUGcfhRhJTWqicW0CUSfnTrA4GznDZiGCSMpa82Y5t
         B0mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=GgG88c9JE6XnPF8CRgN3glLQvH9X2RESdGb7e77LJso=;
        fh=JXYaMMYTGZkyiGyEvxXtDVQZmRBjgZWRCs+gcLGhxGM=;
        b=mptczi6l7adY87gJVqUltcICJVG0dBEMlfaN4MnI7H1Goeh9wmqGJ5hzlC0NJK7OAS
         4ft0/0sShp2zDCJ9bLHi5IhcAkH41dVMPaoDzD08b2NMLEgu7Mxf5NeMmUXWpkZt+H6T
         1nzCU2bkINv6hw9cVQqTRhsrsoKqqPwgJmZ4ZJKCu6Xc50JjUQUiBYgrCPDLyWThUVG4
         0nv0WXJS0437gmmIwATz6K2PI2kaPp6mhRBGrSNlgRv27Ty9zUy58ezdovplzlor5auD
         RFIRCMgmajurme3tV35mgTrd8EE5oFBVFmsTqpMbCheubgPieHYWZwR0zRKmWSySi9hH
         O/ng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EWMpGRid;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bce918a7asi34193485a.6.2024.06.24.20.25.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jun 2024 20:25:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-70665289275so1461645b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2024 20:25:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWCSKRavq4qAXfU8dkMooaZew45xyxu1DCYjY09QoaqANxS5SiZ8jn8VV/3gNqbVE6NdVZHb0Re+JWarw9rQCbNJ1Ff7t+4+rmnjg==
X-Received: by 2002:a05:6a21:6da4:b0:1b5:d07a:57b2 with SMTP id adf61e73a8af0-1bd13bb76camr3898830637.12.1719285942871;
        Mon, 24 Jun 2024 20:25:42 -0700 (PDT)
Received: from localhost.localdomain ([2604:a880:4:1d0::427:6000])
        by smtp.googlemail.com with ESMTPSA id d2e1a72fcca58-706512e1f6esm6952010b3a.180.2024.06.24.20.25.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Jun 2024 20:25:42 -0700 (PDT)
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
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Baoquan He <bhe@redhat.com>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Changbin Du <changbin.du@huawei.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Uros Bizjak <ubizjak@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3] x86/traps: Enable UBSAN traps on x86
Date: Tue, 25 Jun 2024 03:24:55 +0000
Message-Id: <20240625032509.4155839-1-gatlin.newhouse@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EWMpGRid;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
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

Currently ARM architectures output which specific sanitizer caused
the trap, via the encoded data in the trap instruction. Clang on
x86 currently encodes the same data in ud1 instructions but the x86
handle_bug() and is_valid_bugaddr() functions currently only look
at ud2s.

Bring x86 to parity with arm64, similar to commit 25b84002afb9
("arm64: Support Clang UBSAN trap codes for better reporting").
Enable the output of UBSAN type information on x86 architectures
compiled with clang when CONFIG_UBSAN_TRAP=y.

Signed-off-by: Gatlin Newhouse <gatlin.newhouse@gmail.com>
---
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
---
 MAINTAINERS                  |  2 ++
 arch/x86/include/asm/bug.h   | 11 ++++++++++
 arch/x86/include/asm/ubsan.h | 23 +++++++++++++++++++++
 arch/x86/kernel/Makefile     |  1 +
 arch/x86/kernel/traps.c      | 40 +++++++++++++++++++++++++++++++-----
 arch/x86/kernel/ubsan.c      | 21 +++++++++++++++++++
 6 files changed, 93 insertions(+), 5 deletions(-)
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
index a3ec87d198ac..a363d13c263b 100644
--- a/arch/x86/include/asm/bug.h
+++ b/arch/x86/include/asm/bug.h
@@ -13,6 +13,17 @@
 #define INSN_UD2	0x0b0f
 #define LEN_UD2		2
 
+/*
+ * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
+ */
+#define INSN_UD1	0xb90f
+#define INSN_UD_MASK	0xFFFF
+#define LEN_UD1		2
+#define INSN_ASOP	0x67
+#define INSN_ASOP_MASK	0x00FF
+#define BUG_UD_NONE	0xFFFF
+#define BUG_UD2		0xFFFE
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
index 4fa0b17e5043..aef21287e7ed 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -67,6 +67,7 @@
 #include <asm/vdso.h>
 #include <asm/tdx.h>
 #include <asm/cfi.h>
+#include <asm/ubsan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/x86_init.h>
@@ -91,6 +92,29 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
 	return *(unsigned short *)addr == INSN_UD2;
 }
 
+/*
+ * Check for UD1, UD2, with or without Address Size Override Prefixes instructions.
+ */
+__always_inline u16 get_ud_type(unsigned long addr)
+{
+	u16 insn;
+
+	if (addr < TASK_SIZE_MAX)
+		return BUG_UD_NONE;
+	insn = *(u16 *)addr;
+	if ((insn & INSN_UD_MASK) == INSN_UD2)
+		return BUG_UD2;
+	if ((insn & INSN_ASOP_MASK) == INSN_ASOP)
+		insn = *(u16 *)(++addr);
+
+	// UBSAN encode the failure type in the two bytes after UD1
+	if ((insn & INSN_UD_MASK) == INSN_UD1)
+		return *(u16 *)(addr + LEN_UD1);
+
+	return BUG_UD_NONE;
+}
+
+
 static nokprobe_inline int
 do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
 		  struct pt_regs *regs,	long error_code)
@@ -216,6 +240,7 @@ static inline void handle_invalid_op(struct pt_regs *regs)
 static noinstr bool handle_bug(struct pt_regs *regs)
 {
 	bool handled = false;
+	int ud_type;
 
 	/*
 	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
@@ -223,7 +248,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 * irqentry_enter().
 	 */
 	kmsan_unpoison_entry_regs(regs);
-	if (!is_valid_bugaddr(regs->ip))
+	ud_type = get_ud_type(regs->ip);
+	if (ud_type == BUG_UD_NONE)
 		return handled;
 
 	/*
@@ -236,10 +262,14 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 */
 	if (regs->flags & X86_EFLAGS_IF)
 		raw_local_irq_enable();
-	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
-	    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
-		regs->ip += LEN_UD2;
-		handled = true;
+	if (ud_type == INSN_UD2) {
+		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
+		    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
+			regs->ip += LEN_UD2;
+			handled = true;
+		}
+	} else {
+		handle_ubsan_failure(regs, ud_type);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625032509.4155839-1-gatlin.newhouse%40gmail.com.
