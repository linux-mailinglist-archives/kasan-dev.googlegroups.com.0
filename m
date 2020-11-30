Return-Path: <kasan-dev+bncBAABBXPPSL7AKGQEQ3FTPVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BB5D2C80B1
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 10:14:07 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id q10sf9570403ile.1
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 01:14:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606727646; cv=pass;
        d=google.com; s=arc-20160816;
        b=qmep557yzhsdAUJymzx6P3FjwrvwsrlQ5ZrJsceq8/xURnxKHiJKpLkzdd29ow2Bho
         2sfJ5qaPiyg5xAdch71B2r3jJ8a8plmKBiX+NL9I9E79t5ypAqyTmu6x+2KgE9cRY2kn
         g0D2jj0gHDlpn5NXwkurdAKWE54qa8xpp7Y6ArCM6Wq4fBxJbgb+lNpMxaIrkYde+UE8
         06b9m5gdHRvqx/M9uQ1BfcUvGHrX6zXO9AR6CVifpo+d7f4SWv4XybVlhNJ3PN1XJanK
         su01bWMcpnJ7gqxZBBAUOdIlyV9aPEDeVNoJWLHSidJ042SauhJOutKBRyZAf7COkeIH
         k5gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=W66vLiSjmM8uvd/hezfpGQHvP7nWvEQD6ZtFh9L0D0g=;
        b=smu/HIqz3zPnseH+82qyqU8y9pADu+jKMi0QE1fK28Yof+s8K8Kt+X7r4/6X/V4/iG
         F5jBc5glAJ10ZNAQRqsxfz+syXrEA/UCkj2ZfzpZGO2Qa10LvVPDZ7tgG1W8D5y9fa2l
         twaOkqiMNJDKhOio0qmsgVXh0Xi2qWu+GYLNDMKr6jhR7ebSqjzm3pIufvY6tKjjWXDv
         Ierb1eD+9oDO/cv8E7kR7XlEdoNpV3/x23ER4TAdLOY9NzFK7xeraV4cKkgvDWVgRxAD
         CVnOAd+iGTOReN/x5OiggsPLVwm9xhskI/vcNeq8qznY4gzmEO0GF6FnbcxD9Zp7eLwm
         pKPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W66vLiSjmM8uvd/hezfpGQHvP7nWvEQD6ZtFh9L0D0g=;
        b=eIOt3Vlk/LtpMaXoYPnloWI7O7AwAYa+IYxnolWHT/QbA01ldMrBQ3/txMfXMWfwc7
         sKpsW+K80iKu8AlZaEzm1jtTLDKgqb/ReQQOyR30J7UhK3y/tPuKm+mjQ5xxmy7KNdDK
         jWXSsI8eUowinx0/CYO59VWqCs3mkgypeXEcyyzRGmG64PMkKSGyOMCaq1I7qY5uijR3
         AOB5T/vBhWaZPayB0G6kBbW9S6g3Tqv/T7yexg2hTveuDo46F+wEMzgZVgZk2AIkULpW
         GgoIJKGl2W939Hgq9qU3E5aWeIn3HE+VhyRbK2PkTW6CezV4pqO8ARFfLuIw5uY86BIb
         Jdew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W66vLiSjmM8uvd/hezfpGQHvP7nWvEQD6ZtFh9L0D0g=;
        b=ZP/VNO62z/ZLTv5KKdMv3wKqleJtq8b7NGi70kvVV5eAFdy3RWeb1l9dzR5YHWpZk/
         6RcM24FyPHbAR6e/QrSpgr7PddgucHN0X+RWFkspLyJrIQCLBrBWwEZ7h1p0Yxpf4p6G
         bWy+DJzMlEqI2ecQIXtCn6eBse4ZhECN8CI3g7qThRQiCQR9tQ6fF/xSryus1D47cPvA
         0HEULPpBXdR9VChf6x5SGj2oOEznNg0MNxPPQ/hjL+bKVL5jy6rdYdIOjJPMKjG9p3b+
         ko1CS/CpIBJrPt4yNW9iGfncX5g66qWU9AMWY/Hkf1DlN2/VyvosvDGmImyPWZX3JL4t
         4iIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532g7oY6teq2UeqpnFrhKDn79vvl4ahvXpPDs0zFSmPVfCFanb61
	MejpsN5/Zw2bNgAP84uGn6Y=
X-Google-Smtp-Source: ABdhPJxpGLz+X2LKQmYB0UfhHDNutlf8KQdyzrtHq9xfMCrkFUzqWH3eKbVW1gZEYhzo1L34rDVGWg==
X-Received: by 2002:a02:2e52:: with SMTP id u18mr17753442jae.29.1606727646094;
        Mon, 30 Nov 2020 01:14:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:9e46:: with SMTP id j6ls1796637ioq.8.gmail; Mon, 30 Nov
 2020 01:14:05 -0800 (PST)
X-Received: by 2002:a5d:9a0e:: with SMTP id s14mr15493111iol.108.1606727645617;
        Mon, 30 Nov 2020 01:14:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606727645; cv=none;
        d=google.com; s=arc-20160816;
        b=EpYH5j2D5tnhUfdRcI22nx28QUWukXBmNCDcvH7F6GCcQqFYn38+JfC9ZY9wkQAjiU
         hzgH6D4wKOCA1h+cgL9mgU75Ht6YOfii3AKi9xlw+Lz/0HiOPnM5fAoQDmWzQ+V+jGna
         t/RRqcMF4I7TTWRyXDT7DlnD2yfx8/Uvb1xRo4r38IAreEbJJNcjrmX+xs5kKCvqj+Np
         coRkajb0xnSKtLM5APWyzbI4cb6hLe+Y2fceStJ4eocQifVmgOl9/C5sBPllTdcdrq2U
         QEqobqahXHeho59S6gLCRomvPYJ5marub4PowimZJIEG3PBpQtDvMhRrU7RWyeBtb94Q
         IQNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=ZzVFv8GO+ibRzrrczPRI5CT9abHIP4Fk3+wB9oWnuIA=;
        b=Nb07xN/YWVEzOFp30GlxH+g0bsuDjbb15GaCvNN9/33BQ1yzJh5SgMRK+UlomX111J
         KwAzN75rC589lNwU3/mS0rBhPOiO91enNLKvNmqX1ccwTXSAQ+d6uMN59zJYn5orMdyt
         apOuDumqH+ONUVe4GysaPPoNqbj6NVJRIo/Mc5QzJsErTTcFFtLXgzHo8AbS1LWm56ib
         xK+Qf3cRRP+VSP6mbTZ0PwPqveDhDztpozIe2Bv1lJjUH5b7AJdaoQRVp8lwj85jbiyx
         8ZposNN/dNtwsvGEszqVXorbZPdWqcqVLtf0gUEmO8DQcu9aGOVJcdlSbNS1yLA/tbhb
         IeUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (exmail.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id a2si943403ild.4.2020.11.30.01.14.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Nov 2020 01:14:05 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 0AU9E2sr078789;
	Mon, 30 Nov 2020 17:14:02 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.487.0; Mon, 30 Nov 2020
 17:13:36 +0800
From: Nylon Chen <nylon7@andestech.com>
To: <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
        <kasan-dev@googlegroups.com>, <akpm@linux-foundation.org>,
        <paul.walmsley@sifive.com>, <palmer@dabbelt.com>,
        <aou@eecs.berkeley.edu>, <nickhu@andestech.com>,
        <nylon7@andestech.com>, <luc.vanoostenryck@gmail.com>,
        <greentime.hu@sifive.com>, <linux-riscv@lists.infradead.org>
CC: <nylon7717@gmail.com>, <alankao@andestech.com>,
        Nick Hu
	<nick650823@gmail.com>
Subject: [PATCH 1/1] riscv: provide memmove implementation
Date: Mon, 30 Nov 2020 17:13:19 +0800
Message-ID: <1606727599-8598-2-git-send-email-nylon7@andestech.com>
X-Mailer: git-send-email 2.7.4
In-Reply-To: <1606727599-8598-1-git-send-email-nylon7@andestech.com>
References: <1606727599-8598-1-git-send-email-nylon7@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 0AU9E2sr078789
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

The memmove used by the kernel feature like KASAN.

Signed-off-by: Nick Hu <nickhu@andestech.com>
Signed-off-by: Nick Hu <nick650823@gmail.com>
Signed-off-by: Nylon Chen <nylon7@andestech.com>
---
 arch/riscv/include/asm/string.h |  8 ++---
 arch/riscv/kernel/riscv_ksyms.c |  2 ++
 arch/riscv/lib/Makefile         |  1 +
 arch/riscv/lib/memmove.S        | 64 +++++++++++++++++++++++++++++++++
 4 files changed, 71 insertions(+), 4 deletions(-)
 create mode 100644 arch/riscv/lib/memmove.S

diff --git a/arch/riscv/include/asm/string.h b/arch/riscv/include/asm/string.h
index 924af13f8555..5477e7ecb6e1 100644
--- a/arch/riscv/include/asm/string.h
+++ b/arch/riscv/include/asm/string.h
@@ -12,16 +12,16 @@
 #define __HAVE_ARCH_MEMSET
 extern asmlinkage void *memset(void *, int, size_t);
 extern asmlinkage void *__memset(void *, int, size_t);
-
 #define __HAVE_ARCH_MEMCPY
 extern asmlinkage void *memcpy(void *, const void *, size_t);
 extern asmlinkage void *__memcpy(void *, const void *, size_t);
-
+#define __HAVE_ARCH_MEMMOVE
+extern asmlinkage void *memmove(void *, const void *, size_t);
+extern asmlinkage void *__memmove(void *, const void *, size_t);
 /* For those files which don't want to check by kasan. */
 #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
-
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
-
+#define memmove(dst, src, len) __memmove(dst, src, len)
 #endif
 #endif /* _ASM_RISCV_STRING_H */
diff --git a/arch/riscv/kernel/riscv_ksyms.c b/arch/riscv/kernel/riscv_ksyms.c
index 450492e1cb4e..5ab1c7e1a6ed 100644
--- a/arch/riscv/kernel/riscv_ksyms.c
+++ b/arch/riscv/kernel/riscv_ksyms.c
@@ -11,5 +11,7 @@
  */
 EXPORT_SYMBOL(memset);
 EXPORT_SYMBOL(memcpy);
+EXPORT_SYMBOL(memmove);
 EXPORT_SYMBOL(__memset);
 EXPORT_SYMBOL(__memcpy);
+EXPORT_SYMBOL(__memmove);
diff --git a/arch/riscv/lib/Makefile b/arch/riscv/lib/Makefile
index 47e7a8204460..ac6171e9c19e 100644
--- a/arch/riscv/lib/Makefile
+++ b/arch/riscv/lib/Makefile
@@ -2,5 +2,6 @@
 lib-y			+= delay.o
 lib-y			+= memcpy.o
 lib-y			+= memset.o
+lib-y			+= memmove.o
 lib-$(CONFIG_MMU)	+= uaccess.o
 lib-$(CONFIG_64BIT)	+= tishift.o
diff --git a/arch/riscv/lib/memmove.S b/arch/riscv/lib/memmove.S
new file mode 100644
index 000000000000..07d1d2152ba5
--- /dev/null
+++ b/arch/riscv/lib/memmove.S
@@ -0,0 +1,64 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#include <linux/linkage.h>
+#include <asm/asm.h>
+
+ENTRY(__memmove)
+WEAK(memmove)
+        move    t0, a0
+        move    t1, a1
+
+        beq     a0, a1, exit_memcpy
+        beqz    a2, exit_memcpy
+        srli    t2, a2, 0x2
+
+        slt     t3, a0, a1
+        beqz    t3, do_reverse
+
+        andi    a2, a2, 0x3
+        li      t4, 1
+        beqz    t2, byte_copy
+
+word_copy:
+        lw      t3, 0(a1)
+        addi    t2, t2, -1
+        addi    a1, a1, 4
+        sw      t3, 0(a0)
+        addi    a0, a0, 4
+        bnez    t2, word_copy
+        beqz    a2, exit_memcpy
+        j       byte_copy
+
+do_reverse:
+        add     a0, a0, a2
+        add     a1, a1, a2
+        andi    a2, a2, 0x3
+        li      t4, -1
+        beqz    t2, reverse_byte_copy
+
+reverse_word_copy:
+        addi    a1, a1, -4
+        addi    t2, t2, -1
+        lw      t3, 0(a1)
+        addi    a0, a0, -4
+        sw      t3, 0(a0)
+        bnez    t2, reverse_word_copy
+        beqz    a2, exit_memcpy
+
+reverse_byte_copy:
+        addi    a0, a0, -1
+        addi    a1, a1, -1
+
+byte_copy:
+        lb      t3, 0(a1)
+        addi    a2, a2, -1
+        sb      t3, 0(a0)
+        add     a1, a1, t4
+        add     a0, a0, t4
+        bnez    a2, byte_copy
+
+exit_memcpy:
+        move a0, t0
+        move a1, t1
+        ret
+END(__memmove)
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1606727599-8598-2-git-send-email-nylon7%40andestech.com.
