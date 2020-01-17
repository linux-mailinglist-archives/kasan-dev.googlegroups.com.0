Return-Path: <kasan-dev+bncBCH67JWTV4DBBGPVRDYQKGQEW6OKUJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 87C28141466
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:52:09 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id t8sf4812756lfc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:52:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301529; cv=pass;
        d=google.com; s=arc-20160816;
        b=EJ3iUxDDQhrF9/qxJ3cT/XKSWpuvrTnAzlkGHcSaPgZaqVLaOlf/I2lk3xJ2TXSR9U
         o86BfmFF96GP8/FCU4gea0f3QrbxZ9n2UqIG86AOKWI+vdf5agC9K7Ub1yZM2idox3Uu
         doc08ykNo09NagB6y8P2LNy7fobi+bvmEN4zcDIALn6SJGX5eeJh5lp+uLuuAC8a7PRy
         HYCw3+SpHB6UZzwLzp5Vbbm75NyS4RT0d7b/pr9jorDFqTgGJ5PLSsbE8vjnmwROscdg
         R5Bwbj60zlloY4rufdqH/nc6HGzaB9XfsEUReKiToUA/jcijYcv7vcDsYm2hFeoRCN9G
         aNag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=0pxw4BewIQPNtljWIzUnGTfITvhpJBE0oFgfrJItasw=;
        b=v2wkNAYj9ZxpUuGhZjCDcxluGDhNqfN0NYl/8DFXo7yIiyTBzi9Gh7Fuxi9DKLgqUi
         NhMQ8HyWX1+uvaND5dGVyGjuEuMYm8GVwXLYYrkustu7g409UpnU1LNtNqzBbaZDj90X
         GyLAtQit//yxbIpdxLweyQXzqKfdfZt43OokWlMFPJVPhth9go0/fxK2JyaMG/+yrKJp
         8yPm5k4gbAmbxagTlitiZ0RVfvxDdGi2gLTOuLwDyonFUw772a3CKjlD1t0IoHVCPf0q
         +WkOQh6V9UhORmNj9JfxzlXaIONcLX9M/gwjtm3lzgMX1CG1rxc2u/QhgxKQuLJo0XYS
         rhAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=IqFZchOc;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0pxw4BewIQPNtljWIzUnGTfITvhpJBE0oFgfrJItasw=;
        b=Z9MTdmfT3Jkv+3t695U6JqiVcA0HKiLNF9MQ/2s6ntZ2XMHwy2HweFL9ZJNFylCVvK
         nIaFL4v1fZpf5z4cZK+55TGgeavGy1aUdAgxfTLBm1OqKrj8AxGUeLr8f/Y79wBB8UgS
         kGUSJjOO+U6RrpnMriBE0kR0q29bZ6jzl9XViLUBVAT3eDJbcB8pHuax0NAlLB4zanHr
         TFYFl9JMa86ym+xQrei4GPBF9iDUY4IJiXmcPpgLf7TdPmWN3qiuRa6TzRj9NA+RrnDL
         2QFe3ORFYPO62a4w8PFUpEvsnxSMq2wbOT7JCxOvR5nIti4YJZMF8i7GlEqmV6gNh7cC
         /QfQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0pxw4BewIQPNtljWIzUnGTfITvhpJBE0oFgfrJItasw=;
        b=Kr4QeVkw8aFZUs8NnuODZ+i9Qd30eG9ogMQizBrrh/24DvIhT5ogTOlaIPrx9ob5He
         /7jhZ1qSviSWHH2NOZatQvq1cfl3jByi/5USJbQ+8MAtcrLtWNDZGChBo4f8L/Ru8sEe
         MrVZcCcVWRUs1o8zxUfQyKzugU2x7ev6wdzDJAdrXL6M3kwAy13+Qj37gkKr/t+5T3zV
         txwOwq24GeTcQa0n0DmKBynU7Cv9yiCgYcIWSlb7ezwkTzEcJR8jf1kemx8QfQj9rGhx
         xh/XgmvYEBzIGNmGDFFggPB8SR3UCj/R3qrDRETILk9uH4z2KCNnm/n1ub6z/KA9T4nG
         h1KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0pxw4BewIQPNtljWIzUnGTfITvhpJBE0oFgfrJItasw=;
        b=Hr0fNjhBcSqQKD61escBjtde+uyD8uuIIjA5sOC/b0ha3Olp3w42qYdjUpBlVoUttt
         75gOLi20wI8L6DyR+tZ900GitTc6v0KK8xBunkSHloVSFsmf+uwPRT48aQSLdCorPfWK
         agX3r49uFVqHtb+L/dapdVnYYM6h5nehE6sp2Wo47byH++G1at80wiETTvNybykASEvQ
         Z4iX9XRyO+zqGY6gEizUYyNAvt9zSmZ4/jBpxHWTnngk0rvxsE9IAvERAfepi15RufKE
         1jO/UwNPamuz+5pNQNvEIIAeQ4BwdOkHHDZaBsAIjXuTeGbMvAtLKNC8GdBimcWObF/O
         orRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX09Hr5thwhtfLpsyCAAFnWOi13NdJrFDMH3q8yoiBvwA10j9X+
	X83UqhinZyQhLOtazfCIoSQ=
X-Google-Smtp-Source: APXvYqw10kOyNZNDRc+2kO+n0evSGES9yF9dZTp8rsPryUh1VWstIzHJl7NoMYsVDo/KHtaq8P/k2w==
X-Received: by 2002:a2e:9b05:: with SMTP id u5mr6923264lji.59.1579301529115;
        Fri, 17 Jan 2020 14:52:09 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8790:: with SMTP id n16ls3721522lji.7.gmail; Fri, 17 Jan
 2020 14:52:08 -0800 (PST)
X-Received: by 2002:a2e:b4e7:: with SMTP id s7mr7042712ljm.58.1579301528404;
        Fri, 17 Jan 2020 14:52:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301528; cv=none;
        d=google.com; s=arc-20160816;
        b=Fmt7nBOx/0sOlSyADqe6ryNUxJiM+p5y7p+oHnVctdy+b/zYwZ59w4g06es657by4Y
         UFWF41kjWDyLaWRPViU+z9u1P9uDR81ice1slZ47OgTzwz1okhJHiXGYaxFBOXC5cWX9
         aJbNO9SOtUNvBQZ0G0NnhJeTe1AhSLfsyx4lIrSfW6icsDM8kzvO1w6nkFIDGHMjqEgb
         qvN7Zf+QYLTJxgUlF2B3kyBC6EKHC/vMXcGNN+gGL74qJJs/bgM0RD08xiAaxFORiT9p
         5Hyatunns+lB3YjiKs+kitMSsL1OoeQCnj430hP4HcUBTA8gODRQVxxXWFgLRibJbKzq
         ysDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=N4HjiapVisuR4SSv5+7J8w7zPzYkQ0Yvx9VG/gpvcq0=;
        b=Y3ZQrCqmIc8THblrE4w5Xg4n5jDhdW3AewDPjHJoexuR0mGnCbRXxOoSqQGsbdRCt3
         snvJLfrIHgqbrnTdMyIwzvWfPu2O1cFMw6YMZ06+egFUH1dpPrtfGGSvD0dGdFUyDXTI
         iJsi2xr2Z+zk47aDPTlZRNqoIMXjL6f+8n0QgfK4TBC1Wq1NkdXw+UP17QRHSdIGHy/H
         J3ZN3cyTj1qB9jP4aisZj600PNvvbMLdileP1Um5/UAKAiQe0InjogS4jF0issXtXv2v
         4hH7NSZhOynl/vaEaLQoP3VEwzPjLlR+ayuGg2X4zwp+2O0JthIt28C7ElcZnv+uTZ2D
         6hAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=IqFZchOc;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id z16si996946ljk.0.2020.01.17.14.52.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:52:08 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id d16so24202052wre.10
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:52:08 -0800 (PST)
X-Received: by 2002:adf:8041:: with SMTP id 59mr5364700wrk.257.1579301527683;
        Fri, 17 Jan 2020 14:52:07 -0800 (PST)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id l3sm32829387wrt.29.2020.01.17.14.52.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jan 2020 14:52:07 -0800 (PST)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Abbott Liu <liuwenliang@huawei.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	bcm-kernel-feedback-list@broadcom.com,
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
Subject: [PATCH v7 5/7] ARM: Define the virtual space of KASan's shadow region
Date: Fri, 17 Jan 2020 14:48:37 -0800
Message-Id: <20200117224839.23531-6-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117224839.23531-1-f.fainelli@gmail.com>
References: <20200117224839.23531-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=IqFZchOc;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::442
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
  kernel address sanitizer shadow area. It is also the start of the
  module area.

When kasan is enabled, the definition of TASK_SIZE is not an 8-bit
rotated constant, so we need to modify the TASK_SIZE access code in the
*.s file.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Reported-by: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/include/asm/kasan_def.h | 63 ++++++++++++++++++++++++++++++++
 arch/arm/include/asm/memory.h    |  5 +++
 arch/arm/kernel/entry-armv.S     |  5 ++-
 arch/arm/kernel/entry-common.S   |  9 +++--
 arch/arm/mm/mmu.c                |  7 +++-
 5 files changed, 83 insertions(+), 6 deletions(-)
 create mode 100644 arch/arm/include/asm/kasan_def.h

diff --git a/arch/arm/include/asm/kasan_def.h b/arch/arm/include/asm/kasan_def.h
new file mode 100644
index 000000000000..4f0aa9869f54
--- /dev/null
+++ b/arch/arm/include/asm/kasan_def.h
@@ -0,0 +1,63 @@
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
+ *1) KASAN_SHADOW_OFFSET:
+ * This value is used to map an address to the corresponding shadow address by
+ * the following formula: shadow_addr = (address >> KASAN_SHADOW_SCALE_SHIFT) +
+ * KASAN_SHADOW_OFFSET;
+ *
+ * 2) KASAN_SHADOW_START:
+ * This value is the MODULE_VADDR's shadow address. It is the start of kernel
+ * virtual space.
+ *
+ * 3) KASAN_SHADOW_END
+ * This value is the 0x100000000's shadow address. It is the end of kernel
+ * addresssanitizer's shadow area. It is also the start of the module area.
+ *
+ */
+
+#define KASAN_SHADOW_SCALE_SHIFT	3
+#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+#define KASAN_SHADOW_END	((UL(1) << (32 - KASAN_SHADOW_SCALE_SHIFT)) \
+				 + KASAN_SHADOW_OFFSET)
+#define KASAN_SHADOW_START      ((KASAN_SHADOW_END >> 3) + KASAN_SHADOW_OFFSET)
+
+#endif
+#endif
diff --git a/arch/arm/include/asm/memory.h b/arch/arm/include/asm/memory.h
index 99035b5891ef..5cfa9e5dc733 100644
--- a/arch/arm/include/asm/memory.h
+++ b/arch/arm/include/asm/memory.h
@@ -18,6 +18,7 @@
 #ifdef CONFIG_NEED_MACH_MEMORY_H
 #include <mach/memory.h>
 #endif
+#include <asm/kasan_def.h>
 
 /* PAGE_OFFSET - the virtual address of the start of the kernel image */
 #define PAGE_OFFSET		UL(CONFIG_PAGE_OFFSET)
@@ -28,7 +29,11 @@
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
index 858d4e541532..8cf1cc30fa7f 100644
--- a/arch/arm/kernel/entry-armv.S
+++ b/arch/arm/kernel/entry-armv.S
@@ -180,7 +180,7 @@ ENDPROC(__und_invalid)
 
 	get_thread_info tsk
 	ldr	r0, [tsk, #TI_ADDR_LIMIT]
-	mov	r1, #TASK_SIZE
+	ldr	r1, =TASK_SIZE
 	str	r1, [tsk, #TI_ADDR_LIMIT]
 	str	r0, [sp, #SVC_ADDR_LIMIT]
 
@@ -434,7 +434,8 @@ ENDPROC(__fiq_abt)
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
index 271cb8a1eba1..fee279e28a72 100644
--- a/arch/arm/kernel/entry-common.S
+++ b/arch/arm/kernel/entry-common.S
@@ -50,7 +50,8 @@ __ret_fast_syscall:
  UNWIND(.cantunwind	)
 	disable_irq_notrace			@ disable interrupts
 	ldr	r2, [tsk, #TI_ADDR_LIMIT]
-	cmp	r2, #TASK_SIZE
+	ldr	r1, =TASK_SIZE
+	cmp	r2, r1
 	blne	addr_limit_check_failed
 	ldr	r1, [tsk, #TI_FLAGS]		@ re-check for syscall tracing
 	tst	r1, #_TIF_SYSCALL_WORK | _TIF_WORK_MASK
@@ -87,7 +88,8 @@ __ret_fast_syscall:
 #endif
 	disable_irq_notrace			@ disable interrupts
 	ldr	r2, [tsk, #TI_ADDR_LIMIT]
-	cmp	r2, #TASK_SIZE
+	ldr     r1, =TASK_SIZE
+	cmp     r2, r1
 	blne	addr_limit_check_failed
 	ldr	r1, [tsk, #TI_FLAGS]		@ re-check for syscall tracing
 	tst	r1, #_TIF_SYSCALL_WORK | _TIF_WORK_MASK
@@ -128,7 +130,8 @@ ret_slow_syscall:
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
index 5d0d0f86e790..d05493ec7d7f 100644
--- a/arch/arm/mm/mmu.c
+++ b/arch/arm/mm/mmu.c
@@ -1272,9 +1272,14 @@ static inline void prepare_page_table(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117224839.23531-6-f.fainelli%40gmail.com.
