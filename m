Return-Path: <kasan-dev+bncBCH67JWTV4DBBTVAUDUAKGQEEMOJUAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 80114494DD
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 00:12:31 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id z124sf12148523ybz.15
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 15:12:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560809550; cv=pass;
        d=google.com; s=arc-20160816;
        b=HWOqRBpdZW9GNiH0V+XcJsV3LMEBhMcl61gLG+aO8yiycAE3pigoIVHj7Z5LP1tpMu
         ywxRoeC5GC4b+g7cyxSAlh4YWVY2BJdy/h/xFG8tYJIhc55mBD1KKsZePkwWu7iji5YK
         1RCXHrSevDEJRJTUXErrfcSxxcsxRs4ZVdzHNQZLDwGEn2Ls+7y5GmkunSjxkYuR76nX
         gYMvyfCVCm9YikCgePm/Qs5b7EupIdg5mQup11b3ZgCeskchjfRgePQQT0FAADTPSsqH
         m7OA82CwZ5uCG7tU9Hm+/68/JatKYmpH7+fw59LNSt5Qwgd3cplIao3OsYLRC1Ruqryv
         A4pQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=JvW5r1gT1umO+L5WZGZWJpAHAll2Nw7FruVQs0jEo2w=;
        b=i392ty8hMtNV6chpoIc3lwtTV/5Sb8rgYGhvESnzyIYROhN2q3yw9ZVxhlReamohdk
         y1gA21Lv0rOP3bVT52jLTMomP9jIqt9qQQcclylFbqzBP0gNRR8uGmIm1j/4rAuGP3Pi
         +HeuqbRON8Y60APf7owymxzYdQ0+aN0u743wInlzB2LPb+8uZEaOS9k2XGnFhcd3tjJO
         29DvNmLKhNkYpIQJXs3YJannY+oF4GYJup1PEyhd3NhZFsW++xVk+sb9CD9neOC62nJL
         ZwkZsjwEGCuVz9HFuqDJ2saYdGS5r4UoVdCZ87TbNzqafGyp3oDX5+fsIGizFYcjNpS6
         Jp1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XyDwQXzN;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JvW5r1gT1umO+L5WZGZWJpAHAll2Nw7FruVQs0jEo2w=;
        b=sDS5GLCWxbyp4I8vrXisrcV2yj4T3kTfCdcVilkiA2UW+mJzWe2VKgnBIATDmoGUuM
         QPc07C0oGHHdAgpetRBJLMKqI6NA+7LgNNr15MlEyXH3d3x39QURVxaSAL20/OCNnrqE
         CADY2nPyXZxiYHFzdjAR8LgTmPUsgWXqAxU3s2fbNI/cF9/G/uoNPIDyHFZVLgmO91EP
         +AXcV8WwRnZ+HW/uP0bgdfU1oxR8I/PfEC1jEuve+TBVtEtu+Ev9G4R43XjajHXukyMX
         ce94U7ZbAofYVix657Rzfb6V4bv8XBkcWvP86wZ4reyuobCOFImV342DvduOCsYNKNrL
         R8Vw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JvW5r1gT1umO+L5WZGZWJpAHAll2Nw7FruVQs0jEo2w=;
        b=dI8zCXAmf1mlcMrl0+N+797dOUWk8Qy3FHbMfXxanmxk4f5KAPEkPbGYJfnYMxoRZ7
         ENVZ1T3oYRV2OmtHNJuLTVzP6jAr5ZxDs4WCq1UglnB8AbH9dlSbBN0LNuTZEQL1nx4M
         EkNcz20nVh2qcHCdwDgJUkuKGW78J6lvXE1v2icMmMPPRcvI0csii8P9B2t/bj5O45bP
         wJM9MkF9f909D+g04Dr3s1A6DtIUDjuVtZfwtK5wMTCca1fCVC2EL2MKY/PNv0CXpjhc
         xdyKTjZ5or5QuGW1u7HNofEq/i0AH/Shol8emlsBdFy1QOiTaq5Jn5e6bWA77R2PeyCL
         suXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JvW5r1gT1umO+L5WZGZWJpAHAll2Nw7FruVQs0jEo2w=;
        b=ejJZgNftPyODT/Bh4VXTIDFr3IerFEQv0FgY4k6v98XYSQqJorY4kKlkpd8RxAodRR
         iohKZzRMn0JEpSSybtjbDcs1dvTYlEB8mymJYdsji4Ai5zGN6KxZZ/uyQSBtUH8u0oM2
         5YNDSwPXwpbkCYzchpTGzc/C7i1RfiFgOfsdykEUH7xfKvVycEovuqs8Ci5vaGHy141D
         6rbEUcrNfVNWvf2E96jIdSogIkg7NJ5siBkIqWnLvJT91fzg6M5CRaRg+YJuNnSZ9MYj
         iVcsOIsL5JDC1hWRxOnIeFZQkn6UtIEMnrd6lEioft+aJbGSOiBeDFougnkaz99ome3w
         WEaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUZS/+JbnDkz0ppoJ5q8Sj6A5G8UqbibMInT/iQimZ6UtpRLnq7
	ivb5Ixx0GjlkfKAahMrcYZ0=
X-Google-Smtp-Source: APXvYqwqk7wa3C8z+JQwyYlOCalybsUlIPB3sHkLjz1vtzFm9I5xy6ZpCE8S+furckOgt3wkRN6Tmg==
X-Received: by 2002:a81:4cd:: with SMTP id 196mr61310641ywe.101.1560809550525;
        Mon, 17 Jun 2019 15:12:30 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6ac3:: with SMTP id f186ls2193451ybc.11.gmail; Mon, 17
 Jun 2019 15:12:30 -0700 (PDT)
X-Received: by 2002:a25:cfca:: with SMTP id f193mr60770392ybg.478.1560809550195;
        Mon, 17 Jun 2019 15:12:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560809550; cv=none;
        d=google.com; s=arc-20160816;
        b=QMi7WQvWU2Q3UJX9noVgA+CrDbv4BOOIrE1O3WM+MwsAL+7ScURVePEFwzxaC2jvHj
         uuf8fD6cdFaN0YzAyrv/J5MxXhrdtGkZqqKllugURTbQj3Ox2go0oeCCusF0siGvuvBJ
         xeu1/3mzq6as4TuD7/sOIv7MgkQh82C0u73gj3zc1SPK38xcvXqnlxyIvloj0ZhsDRkP
         +BUVd3lpOZj1nsmd3VOqA63eajjJtzwaXBc2NpOO4mwDyTusy1mipJcynOxvO/5ic5Gi
         Gq22d5rpNM8bfV8TCN2rrR5nmjVwqaMUg5n8/j7g2j4EnIECzkYKv0du0RrxtvN8JwE4
         9MBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=7DrG5+RQG0FCVM4nQANaF2hEes9VxzWs9d/hV5PsNqg=;
        b=DvN+78UmuA+URikNUj61keHQnaRLHSLpefdbelRPvEhMErW3tfW3mJQvRfyXt/y4pX
         tUlFefam2mpw081xt7rk2W/vLv3tp9g+EtKe5XsA4QbT21WqkCvelYuEArbl6e++5SWo
         uqUfMrrojycXqDRIoBysehKc/B0xcdXhUQrMNGgkGW0fiIBmQm8xkdsljiwGNxMtxLVh
         J926yO+jh4WN308NL7mqY4uW0KBwPMX1wbmWS28ejhPeHiQ2O9tyo3QCg5ugwqLuGNZ6
         xqbQHZw66OWY8iAy+ls9XoFU7h3fNelq/Cj/qtefpKGxugGshnTMzoywcyZOwnePTGty
         gtYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XyDwQXzN;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id 189si872621ybc.1.2019.06.17.15.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 15:12:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id s21so6500500pga.12
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 15:12:30 -0700 (PDT)
X-Received: by 2002:a62:1d11:: with SMTP id d17mr24476871pfd.249.1560809510618;
        Mon, 17 Jun 2019 15:11:50 -0700 (PDT)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id s129sm12551020pfb.186.2019.06.17.15.11.48
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 17 Jun 2019 15:11:49 -0700 (PDT)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: bcm-kernel-feedback-list@broadcom.com,
	Abbott Liu <liuwenliang@huawei.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	glider@google.com,
	dvyukov@google.com,
	corbet@lwn.net,
	linux@armlinux.org.uk,
	christoffer.dall@arm.com,
	marc.zyngier@arm.com,
	arnd@arndb.de,
	nico@fluxnic.net,
	vladimir.murzin@arm.com,
	keescook@chromium.org,
	jinb.park7@gmail.com,
	alexandre.belloni@bootlin.com,
	ard.biesheuvel@linaro.org,
	daniel.lezcano@linaro.org,
	pombredanne@nexb.com,
	rob@landley.net,
	gregkh@linuxfoundation.org,
	akpm@linux-foundation.org,
	mark.rutland@arm.com,
	catalin.marinas@arm.com,
	yamada.masahiro@socionext.com,
	tglx@linutronix.de,
	thgarnie@google.com,
	dhowells@redhat.com,
	geert@linux-m68k.org,
	andre.przywara@arm.com,
	julien.thierry@arm.com,
	drjones@redhat.com,
	philip@cog.systems,
	mhocko@suse.com,
	kirill.shutemov@linux.intel.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.cs.columbia.edu,
	ryabinin.a.a@gmail.com
Subject: [PATCH v6 4/6] ARM: Define the virtual space of KASan's shadow region
Date: Mon, 17 Jun 2019 15:11:32 -0700
Message-Id: <20190617221134.9930-5-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20190617221134.9930-1-f.fainelli@gmail.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=XyDwQXzN;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Abbott Liu <liuwenliang@huawei.com>

Define KASAN_SHADOW_OFFSET,KASAN_SHADOW_START and KASAN_SHADOW_END for arm
kernel address sanitizer.

     +----+ 0xffffffff
     |    |
     |    |
     |    |
     +----+ CONFIG_PAGE_OFFSET
     |    |     |    | |->  module virtual address space area.
     |    |/
     +----+ MODULE_VADDR = KASAN_SHADOW_END
     |    |     |    | |-> the shadow area of kernel virtual address.
     |    |/
     +----+ TASK_SIZE(start of kernel space) = KASAN_SHADOW_START  the
     |    |\  shadow address of MODULE_VADDR
     |    | ---------------------+
     |    |                      |
     +    + KASAN_SHADOW_OFFSET  |-> the user space area. Kernel address
     |    |                      |    sanitizer do not use this space.
     |    | ---------------------+
     |    |/
     ------ 0

1)KASAN_SHADOW_OFFSET:
  This value is used to map an address to the corresponding shadow
address by the following formula:
shadow_addr = (address >> 3) + KASAN_SHADOW_OFFSET;

2)KASAN_SHADOW_START
  This value is the MODULE_VADDR's shadow address. It is the start
of kernel virtual space.

3)KASAN_SHADOW_END
  This value is the 0x100000000's shadow address. It is the end of
kernel addresssanitizer's shadow area. It is also the start of the
module area.

When enable kasan, the definition of TASK_SIZE is not an an 8-bit
rotated constant, so we need to modify the TASK_SIZE access code
in the *.s file.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Reported-by: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/include/asm/kasan_def.h | 64 ++++++++++++++++++++++++++++++++
 arch/arm/include/asm/memory.h    |  5 +++
 arch/arm/kernel/entry-armv.S     |  5 ++-
 arch/arm/kernel/entry-common.S   |  9 +++--
 arch/arm/mm/mmu.c                |  7 +++-
 5 files changed, 84 insertions(+), 6 deletions(-)
 create mode 100644 arch/arm/include/asm/kasan_def.h

diff --git a/arch/arm/include/asm/kasan_def.h b/arch/arm/include/asm/kasan_def.h
new file mode 100644
index 000000000000..7b7f42435146
--- /dev/null
+++ b/arch/arm/include/asm/kasan_def.h
@@ -0,0 +1,64 @@
+/*
+ *  arch/arm/include/asm/kasan_def.h
+ *
+ *  Copyright (c) 2018 Huawei Technologies Co., Ltd.
+ *
+ *  Author: Abbott Liu <liuwenliang@huawei.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ */
+
+#ifndef __ASM_KASAN_DEF_H
+#define __ASM_KASAN_DEF_H
+
+#ifdef CONFIG_KASAN
+
+/*
+ *    +----+ 0xffffffff
+ *    |    |
+ *    |    |
+ *    |    |
+ *    +----+ CONFIG_PAGE_OFFSET
+ *    |    |\
+ *    |    | |->  module virtual address space area.
+ *    |    |/
+ *    +----+ MODULE_VADDR = KASAN_SHADOW_END
+ *    |    |\
+ *    |    | |-> the shadow area of kernel virtual address.
+ *    |    |/
+ *    +----+ TASK_SIZE(start of kernel space) = KASAN_SHADOW_START  the
+ *    |    |\  shadow address of MODULE_VADDR
+ *    |    | ---------------------+
+ *    |    |                      |
+ *    +    + KASAN_SHADOW_OFFSET  |-> the user space area. Kernel address
+ *    |    |                      |    sanitizer do not use this space.
+ *    |    | ---------------------+
+ *    |    |/
+ *    ------ 0
+ *
+ *1)KASAN_SHADOW_OFFSET:
+ *    This value is used to map an address to the corresponding shadow
+ * address by the following formula:
+ * shadow_addr = (address >> 3) + KASAN_SHADOW_OFFSET;
+ *
+ * 2)KASAN_SHADOW_START
+ *     This value is the MODULE_VADDR's shadow address. It is the start
+ * of kernel virtual space.
+ *
+ * 3) KASAN_SHADOW_END
+ *   This value is the 0x100000000's shadow address. It is the end of
+ * kernel addresssanitizer's shadow area. It is also the start of the
+ * module area.
+ *
+ */
+
+#define KASAN_SHADOW_OFFSET     (KASAN_SHADOW_END - (1<<29))
+
+#define KASAN_SHADOW_START      ((KASAN_SHADOW_END >> 3) + KASAN_SHADOW_OFFSET)
+
+#define KASAN_SHADOW_END        (UL(CONFIG_PAGE_OFFSET) - UL(SZ_16M))
+
+#endif
+#endif
diff --git a/arch/arm/include/asm/memory.h b/arch/arm/include/asm/memory.h
index ed8fd0d19a3e..6e099a5458db 100644
--- a/arch/arm/include/asm/memory.h
+++ b/arch/arm/include/asm/memory.h
@@ -21,6 +21,7 @@
 #ifdef CONFIG_NEED_MACH_MEMORY_H
 #include <mach/memory.h>
 #endif
+#include <asm/kasan_def.h>
 
 /* PAGE_OFFSET - the virtual address of the start of the kernel image */
 #define PAGE_OFFSET		UL(CONFIG_PAGE_OFFSET)
@@ -31,7 +32,11 @@
  * TASK_SIZE - the maximum size of a user space task.
  * TASK_UNMAPPED_BASE - the lower boundary of the mmap VM area
  */
+#ifndef CONFIG_KASAN
 #define TASK_SIZE		(UL(CONFIG_PAGE_OFFSET) - UL(SZ_16M))
+#else
+#define TASK_SIZE		(KASAN_SHADOW_START)
+#endif
 #define TASK_UNMAPPED_BASE	ALIGN(TASK_SIZE / 3, SZ_16M)
 
 /*
diff --git a/arch/arm/kernel/entry-armv.S b/arch/arm/kernel/entry-armv.S
index ce4aea57130a..c3ca3b96f22a 100644
--- a/arch/arm/kernel/entry-armv.S
+++ b/arch/arm/kernel/entry-armv.S
@@ -183,7 +183,7 @@ ENDPROC(__und_invalid)
 
 	get_thread_info tsk
 	ldr	r0, [tsk, #TI_ADDR_LIMIT]
-	mov	r1, #TASK_SIZE
+	ldr	r1, =TASK_SIZE
 	str	r1, [tsk, #TI_ADDR_LIMIT]
 	str	r0, [sp, #SVC_ADDR_LIMIT]
 
@@ -437,7 +437,8 @@ ENDPROC(__fiq_abt)
 	@ if it was interrupted in a critical region.  Here we
 	@ perform a quick test inline since it should be false
 	@ 99.9999% of the time.  The rest is done out of line.
-	cmp	r4, #TASK_SIZE
+	ldr	r0, =TASK_SIZE
+	cmp	r4, r0
 	blhs	kuser_cmpxchg64_fixup
 #endif
 #endif
diff --git a/arch/arm/kernel/entry-common.S b/arch/arm/kernel/entry-common.S
index f7649adef505..0dfa3153d633 100644
--- a/arch/arm/kernel/entry-common.S
+++ b/arch/arm/kernel/entry-common.S
@@ -53,7 +53,8 @@ __ret_fast_syscall:
  UNWIND(.cantunwind	)
 	disable_irq_notrace			@ disable interrupts
 	ldr	r2, [tsk, #TI_ADDR_LIMIT]
-	cmp	r2, #TASK_SIZE
+	ldr	r1, =TASK_SIZE
+	cmp	r2, r1
 	blne	addr_limit_check_failed
 	ldr	r1, [tsk, #TI_FLAGS]		@ re-check for syscall tracing
 	tst	r1, #_TIF_SYSCALL_WORK | _TIF_WORK_MASK
@@ -90,7 +91,8 @@ __ret_fast_syscall:
 #endif
 	disable_irq_notrace			@ disable interrupts
 	ldr	r2, [tsk, #TI_ADDR_LIMIT]
-	cmp	r2, #TASK_SIZE
+	ldr     r1, =TASK_SIZE
+	cmp     r2, r1
 	blne	addr_limit_check_failed
 	ldr	r1, [tsk, #TI_FLAGS]		@ re-check for syscall tracing
 	tst	r1, #_TIF_SYSCALL_WORK | _TIF_WORK_MASK
@@ -131,7 +133,8 @@ ret_slow_syscall:
 	disable_irq_notrace			@ disable interrupts
 ENTRY(ret_to_user_from_irq)
 	ldr	r2, [tsk, #TI_ADDR_LIMIT]
-	cmp	r2, #TASK_SIZE
+	ldr     r1, =TASK_SIZE
+	cmp	r2, r1
 	blne	addr_limit_check_failed
 	ldr	r1, [tsk, #TI_FLAGS]
 	tst	r1, #_TIF_WORK_MASK
diff --git a/arch/arm/mm/mmu.c b/arch/arm/mm/mmu.c
index f3ce34113f89..3ae33c2dc1ad 100644
--- a/arch/arm/mm/mmu.c
+++ b/arch/arm/mm/mmu.c
@@ -1256,9 +1256,14 @@ static inline void prepare_page_table(void)
 	/*
 	 * Clear out all the mappings below the kernel image.
 	 */
-	for (addr = 0; addr < MODULES_VADDR; addr += PMD_SIZE)
+	for (addr = 0; addr < TASK_SIZE; addr += PMD_SIZE)
 		pmd_clear(pmd_off_k(addr));
 
+#ifdef CONFIG_KASAN
+	/*TASK_SIZE ~ MODULES_VADDR is the KASAN's shadow area -- skip over it*/
+	addr = MODULES_VADDR;
+#endif
+
 #ifdef CONFIG_XIP_KERNEL
 	/* The XIP kernel is mapped in the module area -- skip over it */
 	addr = ((unsigned long)_exiprom + PMD_SIZE - 1) & PMD_MASK;
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617221134.9930-5-f.fainelli%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
