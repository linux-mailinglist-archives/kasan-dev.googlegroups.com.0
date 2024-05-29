Return-Path: <kasan-dev+bncBDZIZ2OL6IIRBAFC3KZAMGQE6ED264A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3643D8D2ABB
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 04:20:50 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-df771b5e942sf2179386276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 19:20:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716949248; cv=pass;
        d=google.com; s=arc-20160816;
        b=vzpXuB7/4MVjnwe3QLUiq+gZ3eg0dk8mXUiL0v08AcGlPexETmJslc8P1PRTZWgjaT
         lRK3wM9DH0/P48J05bhGDl9zAE2WI/5zcUUL9YGxGHQSOQYgJgC73xOJF0kyqXB7w1CA
         YFHkUPSkeGUog13c4GrYzZPSF3huDQs0x6mBZdKT08whqjB9EQhXiY3r+6OOKp94F9Bm
         ewg3xW4sFFP0nKRSgh9qnEapW+n7BOTtofqvRnJjiXsYDVeEDgFq0Do93pVJK/S6LfK2
         EfupD6teu8L3cYnraZ5GYZrnZM8Un1eLqQnA5rbZmwMzMOeRz+waA5S0Wd5bMdiak/NX
         ecMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature:dkim-signature;
        bh=G8rW5mVOtqOlpuxe2odXb8/RBlEzVmZ8woPVGq/LKng=;
        fh=qcLGgd1jOs1bCi+dsqtYmPlnA0gdQnSRwSgaWr6aduE=;
        b=NSCuKwa3Ltq0oKi5qspRJpszFwZiDd/07cIysUrnix7aRqHNr2Pnls3kZ5HOafwLlT
         wQ8EjqS35sLbjmfXeRXECWt0VFOXKcolynqHgnJvjx+MDq9HWDTwJOIbvOZi0vld4jKq
         4EBdySuI3k+mQCgWImTdzGFdXbiizJK/8wwn3v2RjTZixCMY1n1iHu5xRL0OapOJ8+RD
         1RFfExzLXW51/iXKXvqmnjmg/9k13jM4XFfg0HtZLMlZ2RL7oY6+i/+osqn4JBO217hE
         yO4aIDfnitXgdSCrM9gE2m/UaUl60pyJD7z4GOFr3IDQP0Qzr/gg64eA4UspFDe5EeWW
         lKNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OsJammXa;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716949248; x=1717554048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=G8rW5mVOtqOlpuxe2odXb8/RBlEzVmZ8woPVGq/LKng=;
        b=rNx/pv1ClqX/ZBgwx1wD4ZnZt3UPwToulAikpnjHFjli/SvJTCIiKgAqt9nmeb/4Uc
         OQya2Hr3iIfLMAsa5GorsZm0WwYx9gBCOZ+Dd1UC7DUjL3aTH65Ti0e+uisVJiv/d2ve
         BomsWepNFhYxxHztpD3zNSdOgo9yRO10DNpkbWvJt9DkmWALBZn2hvIo5gFtsCGMQ5Kj
         j6e0RvdlLpqISe61jmFeeqUUrpU9M1OO11n6LMaoYTH5RxmG9ZS6F+WqOWVfnHswB1gu
         kXZvDlJD2NgsR/pMnmvmA7ttF2GNpzwt2T6mAdWQgjkmeFy5UjjplsAO+atLfiubCGEt
         DeMg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1716949248; x=1717554048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=G8rW5mVOtqOlpuxe2odXb8/RBlEzVmZ8woPVGq/LKng=;
        b=HU37h/QT5Z/eUmlB6xYQgi09mDqfBtMvzAwarT0WomxXJRjC1DSIY6LoscypibglAI
         pKMAbYCUgfDcoJnzzA5JhDslYu1z2KHH4Qxt6UkZcFLHjHu1sepm7B2dYiqHr8FiHSfu
         MEqX3XMBnFHF5NDmGHHmJ/GPAOmr0+7BWvrWsb2tg6ZnSlw/Y7Wv2I5M0VEpjzSoTdy8
         1vY36GM/B8pjdNwbw9D+4HhHo+MMj76g2BOHumRBSt1Xm5CZ/pNlijZutDT4LMx+oXHX
         q74fjn6ACPQe7LwzgEG8RKQpXAqShlxgP70+CKdtpb48909IYqs2MoJF0VFOTf1UyaGT
         PNow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716949248; x=1717554048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=G8rW5mVOtqOlpuxe2odXb8/RBlEzVmZ8woPVGq/LKng=;
        b=V/JbNgfjw8YwUje6Rmu5a+77C6RMwC90JiQ95pfDex5KzfouoBFeSEwz8R2/CZK5TE
         sqHsmgwYhTl2UIoY0A6mNo7ye0VO51UhtSSsYhGR08BPo21rEohZYy0Rmt4keZ0Rdcsz
         mPmwXshw/Hx48gaB1sC92Vnj4lBhSmdmrH7fHQlU/s7YwOlSsuSaaiQFsUrXAgLCLRLk
         ElGWw9/c5aCVHPuTqJbfojNgPQeKBQVh4k6ItgN7nWzt01p5JjZ0l8ENpvhyzcDTzuuv
         tAwXvmSZT4CCKtac0fi6B27xxIsXIkn6DcOfi19fVSYZwxr3EQ4fNl++knVhPTfYqq8W
         9Mfw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlPlugB/mP9VS2A/8HTmD5HKSUYL9tLd5koyUjPKmuAr77oSUriC7aHc4fkRzdeMQd0S5xnwSpjLS/1RgXD8ScN0Zq1+2WXg==
X-Gm-Message-State: AOJu0YwzhalxH/gA40yQhrEJPRLZg3CK5fFBxqa4vjyJ2wOomwMkeYBG
	E/R94sk8ur36kWbRh/YZ7q07HyZr0icpoZjbZL7jx1zDdRjmj++H
X-Google-Smtp-Source: AGHT+IH1AI1LwL4oPREg9Z8iN8O2GyCajXflKo+kVWpVRIPMMqfExc34CvksbLNO48sNAE+4bTrH6A==
X-Received: by 2002:a25:ae1e:0:b0:df4:eed1:da0e with SMTP id 3f1490d57ef6-df772223621mr14468844276.49.1716949248150;
        Tue, 28 May 2024 19:20:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5fcb:0:b0:6ab:7910:c571 with SMTP id 6a1803df08f44-6acadb60006ls4250206d6.2.-pod-prod-02-us;
 Tue, 28 May 2024 19:20:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWz+uMv1DFkPyfwWIVuzqkaLPa5yccU3x766Z1SNhzEIFOL9chz0thA7Ug9GKGA+nk9uWcEeGTOPv5Kz8fkt7SEY4oCnxUN3PeSg==
X-Received: by 2002:a67:f7d5:0:b0:48b:9f36:14 with SMTP id ada2fe7eead31-48b9f360048mr596198137.10.1716949247210;
        Tue, 28 May 2024 19:20:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716949247; cv=none;
        d=google.com; s=arc-20160816;
        b=j5X0kJbtOosY+QM7kE1F6Lw1PC/pM+JmBNdlynTW8jDZ/LC+GG4+EwWMEK+l7BUDbf
         PHSW7gnJs7ljgroWdii1QfDktOJDmrK8cVJ134SLMg8HyAzikFB6LxocJrFwTtiZ10cL
         U+DjPGGYmEG1eKBTzOwd3kGIsF3sYUjNQJRz4ljzER5H+oYO3BMegScki2zWfwjwWXdO
         PxR3ftDs40myMH0yheRyvc4GMq/YvgF0JYMyuIUSYDtAfS8LbeoP9Ke0pQBXsdm6zcwX
         KZyBfn8H8unC2Jcj+bavByi/z+8HkmQyWB8dp/WCJZbFgkNz8Rk6u2KXyQcfV9kOJelc
         iINA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=347Tv+L36ItrUa9DcwFsT5YsIM2weBtvDOWbMcJm1vI=;
        fh=upEb7gwYT+L7sGEL2ly8dbWAljTU1hgFsdXsPpHIQ90=;
        b=y8ITsAV8gAk4XDa+6yF0UwWD0YinJ6e9nnZs3R14eoyQW1tEdawneSSjkM/SNKTUm5
         8qC+1a73+xDTEcBI51aT863KU9cAWCuxSV7GSOKVIyEcnmARZbtKP++ZtRNXISnSC4l6
         SjgVkEcFLbW2O/iRLrNWhmjQv3SdckWm/7fjupii+uQw4FLvqjiybN9BEqeWbvy7lHOU
         +FOVOvWittJB18yYtJpo3eyFA53iE9LHai1eWsBkRmnvBvcuUM7reActqr7bB160KfXY
         4Fv/kXoEl0MftDgFReFhNbJ8pUMI8TKIeJbW9OuylCYocAePPg0PVZWWLEJqg/tKgglX
         /ZqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OsJammXa;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-804cbd3cccasi653053241.0.2024.05.28.19.20.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 May 2024 19:20:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-6818811ef2dso997072a12.0
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 19:20:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2RQ5KWPr8yKna9VQcf9UeKttlvg1gzvsNK0ZLgy82oDBzy/9naqH+lyLzbLDnsYaTB5b6FjdxHTKPRurCSO5xjobADzoo19bSzw==
X-Received: by 2002:a05:6a20:da8f:b0:1af:aec3:2841 with SMTP id adf61e73a8af0-1b212e5bddbmr15754764637.56.1716949245970;
        Tue, 28 May 2024 19:20:45 -0700 (PDT)
Received: from localhost.localdomain ([2604:a880:4:1d0::427:6000])
        by smtp.googlemail.com with ESMTPSA id 98e67ed59e1d1-2bf5f6155b6sm9410812a91.29.2024.05.28.19.20.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 May 2024 19:20:45 -0700 (PDT)
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
	Changbin Du <changbin.du@huawei.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH] x86/traps: Enable UBSAN traps on x86
Date: Wed, 29 May 2024 02:20:30 +0000
Message-Id: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OsJammXa;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
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
 MAINTAINERS                  |  2 ++
 arch/x86/include/asm/bug.h   |  8 ++++++++
 arch/x86/include/asm/ubsan.h | 21 +++++++++++++++++++++
 arch/x86/kernel/Makefile     |  1 +
 arch/x86/kernel/traps.c      | 34 ++++++++++++++++++++++++++++------
 arch/x86/kernel/ubsan.c      | 32 ++++++++++++++++++++++++++++++++
 6 files changed, 92 insertions(+), 6 deletions(-)
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
index a3ec87d198ac..e3fbed9073f8 100644
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
+#define INSN_REX	0x67
+#define LEN_REX		1
+
 #ifdef CONFIG_GENERIC_BUG
 
 #ifdef CONFIG_X86_32
diff --git a/arch/x86/include/asm/ubsan.h b/arch/x86/include/asm/ubsan.h
new file mode 100644
index 000000000000..5235822eb4ae
--- /dev/null
+++ b/arch/x86/include/asm/ubsan.h
@@ -0,0 +1,21 @@
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
+enum bug_trap_type handle_ubsan_failure(struct pt_regs *regs, int insn);
+#else
+static inline enum bug_trap_type handle_ubsan_failure(struct pt_regs *regs, int insn)
+{
+	return BUG_TRAP_TYPE_NONE;
+}
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
index 4fa0b17e5043..7876449e97a0 100644
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
+ * Check for UD1, UD2, with or without REX instructions.
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
+	if (*(u8 *)addr == INSN_REX && *(u16 *)(addr + 1) == INSN_UD1)
+		return INSN_REX;
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
@@ -236,10 +248,20 @@ static noinstr bool handle_bug(struct pt_regs *regs)
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
+		if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {
+			if (insn == INSN_REX)
+				regs->ip += LEN_REX;
+			regs->ip += LEN_UD1;
+			handled = true;
+		}
 	}
 	if (regs->flags & X86_EFLAGS_IF)
 		raw_local_irq_disable();
diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
new file mode 100644
index 000000000000..6cae11f4fe23
--- /dev/null
+++ b/arch/x86/kernel/ubsan.c
@@ -0,0 +1,32 @@
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
+enum bug_trap_type handle_ubsan_failure(struct pt_regs *regs, int insn)
+{
+	u32 type = 0;
+
+	if (insn == INSN_REX) {
+		type = (*(u16 *)(regs->ip + LEN_REX + LEN_UD1));
+		if ((type & 0xFF) == 0x40)
+			type = (type >> 8) & 0xFF;
+	} else {
+		type = (*(u16 *)(regs->ip + LEN_UD1));
+		if ((type & 0xFF) == 0x40)
+			type = (type >> 8) & 0xFF;
+	}
+	pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
+
+	return BUG_TRAP_TYPE_NONE;
+}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240529022043.3661757-1-gatlin.newhouse%40gmail.com.
