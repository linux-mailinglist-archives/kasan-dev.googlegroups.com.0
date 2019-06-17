Return-Path: <kasan-dev+bncBCH67JWTV4DBBKVAUDUAKGQE5WPUWKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id D2D0D494D8
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 00:11:55 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id s3sf5303218vkb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 15:11:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560809514; cv=pass;
        d=google.com; s=arc-20160816;
        b=tW/pd4nL2oYxteCA5/hcer2wAxrw2MSFLMTkPlfxgjXY/43L0cDr80eToOUZDIC353
         eDd3u2HBkGY/Z6BJ4CkuNJ9uxwpTd30nbfCyJsG8mK2WnezTm63TYQftjdRPep1Ki8KU
         X2MH+wSigtLhmYJ0Uy+hzdBADpQveFR7XyZocSi6pYHJgR8YXNzCXl+EG4kkewbKSxMM
         NN274yhhIBczmtUIzckjzdRmaolC8j0aNDhkki2zR7skm0YbqTaq9Sq0NoE1MvLZCXOt
         OMa2DJVuV1mYHGZ6zjsERKWln4EQgDc4XTEyl8oYJxlxMyj1Cn/+GjNkBfeWgEA+GS/O
         iiaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=EqG4KSLPNPOw2hV5v2oOzX7OuL62r0VBMHhp4uGyNb8=;
        b=nsiImKw57k1rofhykaOak8PrXZjqrmXo3a7HsmMBWxq0GR17HFFWYx3BcgTw9di+cn
         KqvRm6X1fw4dQW7LzlFzGN0aeLGAvRs+B/lTrJ5W1KKMCWV1udJ+ksNEuCTRC6KRtqQr
         sYd/mgtC6rEDQ0fku2J9LiJLOTfDfGkrRo2rzWlZOAT6tCIjjLjO3QY9hvNjYciwJW5x
         XjFhYihiQ5J23BDbaNY/WjChkP54Jak34gdKGfeoVJv24SmC9Mk4lajwIanOaNj7URGg
         Xav8w43IAmC6Qx2rEHNFLZccPn5Ub1Yj2ukF++qRt42nVZoKYLhseMsHfSNOmzIRMvCC
         yPwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lM9V28lH;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EqG4KSLPNPOw2hV5v2oOzX7OuL62r0VBMHhp4uGyNb8=;
        b=gMYnw9dijNLfthkWy87QHD3/YacNG83sUNx01EqIbb3e+nHYZTtDqiqt7EqukUj44K
         Xn/PhoHzvQwh6zdIXgqB1oJ33ZK5KHMRJV9oX7jH4Sd9r7kQfutCnwkT+p17tQW4MTvS
         xsfO0buoHXAOmb1H13K+KMYZPtphB0ap+T6ZgVluw7js4vyo7a/7mp9pIyWyi7mQdXYh
         AxlTBbBEqC+I+RQmdYKVEOxTj8naCliYJQ/jhCeHQobqaV6uq8J775OcXv+2uqhyVigf
         eEDVPHzGb1J2oiKWXCZQ7lxYSxx7cLd0rEAk63pvoUACwZ8QHWCuxch52YlfzUPDvSFt
         nQhw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EqG4KSLPNPOw2hV5v2oOzX7OuL62r0VBMHhp4uGyNb8=;
        b=R44UDntxvdO1r40VQTMzartjl52otAhg6wdZReqFaOnxuFy9nvLPCrOdtBHttad9oS
         nUZvraHfYC9iMSj2PBdN0+tAhT9IaSZSgcSe247JixD/tiicpJVcHXC384QX6Z18b5v3
         kim3gDU8B8CGqBFwFNv/Ru0T7Y6gesUSqhvZc9Tphhx5FXldih9fMtbZDVmBUpKFhim+
         sZzpyhO8tLv4YGNyQTyCJbd2qWeL7vcUEg7F3Dg0weCVn5bbQvpHKcVD//sWzNRJtQA+
         t3XZiGQD3awWLN1Dd1WishJbePzQDEDFrFZap8Gu/t3J8nJWvyLahq84i0luPHJKx1NV
         R69g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EqG4KSLPNPOw2hV5v2oOzX7OuL62r0VBMHhp4uGyNb8=;
        b=muRpQQZxVmHqaQeWi32i1OGmUIKClLf+vJZ0Cy57jmLGcwTvvPbQXp6qZQDPbXtW0S
         3tyv+e4Pec62Ets4XFG7jDndESK0+EkGKqdpItNeQitCQ2Y98esyDEpkCeZGPAGNHQGO
         SPDe7kkfKBvDu5ZMq8ZAnWKS6YI2Mu8U0VKAcykKzIZIhm3ab7g6mbRzmIk8g+5L3h4e
         wphkX9EkalKLcKZHGBi6OPDZBcEZ/zA+AuFomTsw3teW3kkiXikKIjndJIWb0t3YocXB
         itd4B4laMK8lU0gtyEZSgPEjrmz+bgyS8XUoqXrBY2G4QGbxe5NbDhe/kAVh4dDsgeE8
         UZnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW4nRYmnZIsbNZkN3Fkwv1UX95S5j7+Ay5beqUSAw9NyOLFtQZk
	5zsjUYinArBrqPzlNMQbsQQ=
X-Google-Smtp-Source: APXvYqw3FTbYEJ9wZwW/eev++nccIiyK3OWwO5iF0ol65HphSe2n7AX2GZ5xK2ESwDsgc8FQ1XGj2w==
X-Received: by 2002:a1f:cf46:: with SMTP id f67mr12369037vkg.13.1560809514716;
        Mon, 17 Jun 2019 15:11:54 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ecd7:: with SMTP id i23ls2104244vsp.8.gmail; Mon, 17 Jun
 2019 15:11:54 -0700 (PDT)
X-Received: by 2002:a67:ff0a:: with SMTP id v10mr4903180vsp.1.1560809514135;
        Mon, 17 Jun 2019 15:11:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560809514; cv=none;
        d=google.com; s=arc-20160816;
        b=gwadddVYhsI4fmW3lhxQU/oy5TsyBStEsqw8KEtQ2VAg3zd21cl+xTSvzVOCnETLar
         dFyawiI8itKWBb8XMcLJI5L36i75yx7JP909hIPCSV4Uu3IiNUl+Ijgze2LVGdlSYTWm
         lBV8aCaP7MxxQTXZKoVVpS4lXCaw4XHjbapw6cuYXSOz1B0LUe6Pt0hxv9HXWqagjkJj
         BAd5UoU/kfCJ6cq4gWPbe0a7PZIIJZuvpMzSVGFM5p1WWSKOrM736yG7EbvmNbR6N6xV
         yy0t0cz9B7+brrniUhwHcuF5QcA0gKmrbt8F5yFigrlqRKeHICjy/b7Xe+cPaIjHdyIp
         UxvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=p6XDrWIXPxwiC0WkVplyBA2eip53/d0wLoTT+kG56h8=;
        b=Y5jOLIU6IKPzmus3hEE7mN4SAoUIt9um96qofdK9oDmDap8eE4iVYwGiHOlTDqEGsj
         487fkRVwUgvaFPLWaS/fBcwZ+Ca6eohobFDRtuVfgCPt0kp1lvZ0ISvKhaWlsDN//Z1X
         jpKGRd4rYFg9S/S3QSxVJri+HT/Zl6s02UO3Gycv7+P3GGxNQrENIRE+/nx/t1rSGwst
         oIRRSGkKWw9EJ+aN3NWlUOjJuG0SSNpcMv7eKzNL15xilwO++ttMB/x08OLz54oEIHME
         UfVEwqlmh76jtCxDfyuNzDvXtP9HbscQ6k3OG41RdciB5keUA5wAn2s8/Mx7gwRW8rwU
         iRJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lM9V28lH;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id d8si587901uam.0.2019.06.17.15.11.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 15:11:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id 196so6526173pgc.6
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 15:11:54 -0700 (PDT)
X-Received: by 2002:a62:764d:: with SMTP id r74mr95168317pfc.110.1560809513044;
        Mon, 17 Jun 2019 15:11:53 -0700 (PDT)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id s129sm12551020pfb.186.2019.06.17.15.11.50
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 17 Jun 2019 15:11:52 -0700 (PDT)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: bcm-kernel-feedback-list@broadcom.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Abbott Liu <liuwenliang@huawei.com>,
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
Subject: [PATCH v6 5/6] ARM: Initialize the mapping of KASan shadow memory
Date: Mon, 17 Jun 2019 15:11:33 -0700
Message-Id: <20190617221134.9930-6-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20190617221134.9930-1-f.fainelli@gmail.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=lM9V28lH;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::542
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

This patch initializes KASan shadow region's page table and memory.
There are two stage for KASan initializing:
1. At early boot stage the whole shadow region is mapped to just
   one physical page (kasan_zero_page). It's finished by the function
   kasan_early_init which is called by __mmap_switched(arch/arm/kernel/
   head-common.S)
             ---Andrey Ryabinin <aryabinin@virtuozzo.com>

2. After the calling of paging_init, we use kasan_zero_page as zero
   shadow for some memory that KASan don't need to track, and we alloc
   new shadow space for the other memory that KASan need to track. These
   issues are finished by the function kasan_init which is call by
   setup_arch.
            ---Andrey Ryabinin <aryabinin@virtuozzo.com>

3. Add support arm LPAE
   If LPAE is enabled, KASan shadow region's mapping table need be copyed
   in pgd_alloc function.
            ---Abbott Liu <liuwenliang@huawei.com>

4. Change kasan_pte_populate,kasan_pmd_populate,kasan_pud_populate,
   kasan_pgd_populate from .meminit.text section to .init.text section.
           ---Reported by: Florian Fainelli <f.fainelli@gmail.com>
           ---Signed off by: Abbott Liu <liuwenliang@huawei.com>

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Co-Developed-by: Abbott Liu <liuwenliang@huawei.com>
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/include/asm/kasan.h       |  35 ++++
 arch/arm/include/asm/pgalloc.h     |   7 +-
 arch/arm/include/asm/thread_info.h |   4 +
 arch/arm/kernel/head-common.S      |   3 +
 arch/arm/kernel/setup.c            |   2 +
 arch/arm/mm/Makefile               |   3 +
 arch/arm/mm/kasan_init.c           | 301 +++++++++++++++++++++++++++++
 arch/arm/mm/pgd.c                  |  14 ++
 8 files changed, 367 insertions(+), 2 deletions(-)
 create mode 100644 arch/arm/include/asm/kasan.h
 create mode 100644 arch/arm/mm/kasan_init.c

diff --git a/arch/arm/include/asm/kasan.h b/arch/arm/include/asm/kasan.h
new file mode 100644
index 000000000000..1801f4d30993
--- /dev/null
+++ b/arch/arm/include/asm/kasan.h
@@ -0,0 +1,35 @@
+/*
+ * arch/arm/include/asm/kasan.h
+ *
+ * Copyright (c) 2015 Samsung Electronics Co., Ltd.
+ * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ *
+ */
+
+#ifndef __ASM_KASAN_H
+#define __ASM_KASAN_H
+
+#ifdef CONFIG_KASAN
+
+#include <asm/kasan_def.h>
+
+#define KASAN_SHADOW_SCALE_SHIFT 3
+
+/*
+ * Compiler uses shadow offset assuming that addresses start
+ * from 0. Kernel addresses don't start from 0, so shadow
+ * for kernel really starts from 'compiler's shadow offset' +
+ * ('kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT)
+ */
+
+extern void kasan_init(void);
+
+#else
+static inline void kasan_init(void) { }
+#endif
+
+#endif
diff --git a/arch/arm/include/asm/pgalloc.h b/arch/arm/include/asm/pgalloc.h
index 17ab72f0cc4e..6cf45c249136 100644
--- a/arch/arm/include/asm/pgalloc.h
+++ b/arch/arm/include/asm/pgalloc.h
@@ -50,8 +50,11 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
  */
 #define pmd_alloc_one(mm,addr)		({ BUG(); ((pmd_t *)2); })
 #define pmd_free(mm, pmd)		do { } while (0)
-#define pud_populate(mm,pmd,pte)	BUG()
-
+#ifndef CONFIG_KASAN
+#define pud_populate(mm, pmd, pte)	BUG()
+#else
+#define pud_populate(mm, pmd, pte)	do { } while (0)
+#endif
 #endif	/* CONFIG_ARM_LPAE */
 
 extern pgd_t *pgd_alloc(struct mm_struct *mm);
diff --git a/arch/arm/include/asm/thread_info.h b/arch/arm/include/asm/thread_info.h
index 286eb61c632b..fae2fa993e86 100644
--- a/arch/arm/include/asm/thread_info.h
+++ b/arch/arm/include/asm/thread_info.h
@@ -16,7 +16,11 @@
 #include <asm/fpstate.h>
 #include <asm/page.h>
 
+#ifdef CONFIG_KASAN
+#define THREAD_SIZE_ORDER	2
+#else
 #define THREAD_SIZE_ORDER	1
+#endif
 #define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)
 #define THREAD_START_SP		(THREAD_SIZE - 8)
 
diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
index 6e3b9179806b..5db2a094a44c 100644
--- a/arch/arm/kernel/head-common.S
+++ b/arch/arm/kernel/head-common.S
@@ -115,6 +115,9 @@ __mmap_switched:
 	str	r8, [r2]			@ Save atags pointer
 	cmp	r3, #0
 	strne	r10, [r3]			@ Save control register values
+#ifdef CONFIG_KASAN
+	bl	kasan_early_init
+#endif
 	mov	lr, #0
 	b	start_kernel
 ENDPROC(__mmap_switched)
diff --git a/arch/arm/kernel/setup.c b/arch/arm/kernel/setup.c
index 5d78b6ac0429..71c27f3c3ed4 100644
--- a/arch/arm/kernel/setup.c
+++ b/arch/arm/kernel/setup.c
@@ -61,6 +61,7 @@
 #include <asm/unwind.h>
 #include <asm/memblock.h>
 #include <asm/virt.h>
+#include <asm/kasan.h>
 
 #include "atags.h"
 
@@ -1133,6 +1134,7 @@ void __init setup_arch(char **cmdline_p)
 	early_ioremap_reset();
 
 	paging_init(mdesc);
+	kasan_init();
 	request_standard_resources(mdesc);
 
 	if (mdesc->restart)
diff --git a/arch/arm/mm/Makefile b/arch/arm/mm/Makefile
index 432302911d6e..1c937135c9c4 100644
--- a/arch/arm/mm/Makefile
+++ b/arch/arm/mm/Makefile
@@ -112,3 +112,6 @@ obj-$(CONFIG_CACHE_L2X0_PMU)	+= cache-l2x0-pmu.o
 obj-$(CONFIG_CACHE_XSC3L2)	+= cache-xsc3l2.o
 obj-$(CONFIG_CACHE_TAUROS2)	+= cache-tauros2.o
 obj-$(CONFIG_CACHE_UNIPHIER)	+= cache-uniphier.o
+
+KASAN_SANITIZE_kasan_init.o    := n
+obj-$(CONFIG_KASAN)            += kasan_init.o
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
new file mode 100644
index 000000000000..a7122b28fffa
--- /dev/null
+++ b/arch/arm/mm/kasan_init.c
@@ -0,0 +1,301 @@
+/*
+ * This file contains kasan initialization code for ARM.
+ *
+ * Copyright (c) 2018 Samsung Electronics Co., Ltd.
+ * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ *
+ */
+
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memblock.h>
+#include <linux/start_kernel.h>
+#include <asm/cputype.h>
+#include <asm/highmem.h>
+#include <asm/mach/map.h>
+#include <asm/memory.h>
+#include <asm/page.h>
+#include <asm/pgalloc.h>
+#include <asm/pgtable.h>
+#include <asm/procinfo.h>
+#include <asm/proc-fns.h>
+#include <asm/tlbflush.h>
+#include <asm/cp15.h>
+#include <linux/sched/task.h>
+
+#include "mm.h"
+
+static pgd_t tmp_pgd_table[PTRS_PER_PGD] __initdata __aligned(1ULL << 14);
+
+pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
+
+static __init void *kasan_alloc_block(size_t size, int node)
+{
+	return memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
+				      MEMBLOCK_ALLOC_KASAN, node);
+}
+
+static void __init kasan_early_pmd_populate(unsigned long start,
+					unsigned long end, pud_t *pud)
+{
+	unsigned long addr;
+	unsigned long next;
+	pmd_t *pmd;
+
+	pmd = pmd_offset(pud, start);
+	for (addr = start; addr < end;) {
+		pmd_populate_kernel(&init_mm, pmd, kasan_early_shadow_pte);
+		next = pmd_addr_end(addr, end);
+		addr = next;
+		flush_pmd_entry(pmd);
+		pmd++;
+	}
+}
+
+static void __init kasan_early_pud_populate(unsigned long start,
+				unsigned long end, pgd_t *pgd)
+{
+	unsigned long addr;
+	unsigned long next;
+	pud_t *pud;
+
+	pud = pud_offset(pgd, start);
+	for (addr = start; addr < end;) {
+		next = pud_addr_end(addr, end);
+		kasan_early_pmd_populate(addr, next, pud);
+		addr = next;
+		pud++;
+	}
+}
+
+void __init kasan_map_early_shadow(pgd_t *pgdp)
+{
+	int i;
+	unsigned long start = KASAN_SHADOW_START;
+	unsigned long end = KASAN_SHADOW_END;
+	unsigned long addr;
+	unsigned long next;
+	pgd_t *pgd;
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte_at(&init_mm, KASAN_SHADOW_START + i*PAGE_SIZE,
+			&kasan_early_shadow_pte[i], pfn_pte(
+				virt_to_pfn(kasan_early_shadow_page),
+				__pgprot(_L_PTE_DEFAULT | L_PTE_DIRTY
+					| L_PTE_XN)));
+
+	pgd = pgd_offset_k(start);
+	for (addr = start; addr < end;) {
+		next = pgd_addr_end(addr, end);
+		kasan_early_pud_populate(addr, next, pgd);
+		addr = next;
+		pgd++;
+	}
+}
+
+extern struct proc_info_list *lookup_processor_type(unsigned int);
+
+void __init kasan_early_init(void)
+{
+	struct proc_info_list *list;
+
+	/*
+	 * locate processor in the list of supported processor
+	 * types.  The linker builds this table for us from the
+	 * entries in arch/arm/mm/proc-*.S
+	 */
+	list = lookup_processor_type(read_cpuid_id());
+	if (list) {
+#ifdef MULTI_CPU
+		processor = *list->proc;
+#endif
+	}
+
+	BUILD_BUG_ON((KASAN_SHADOW_END - (1UL << 29)) != KASAN_SHADOW_OFFSET);
+	kasan_map_early_shadow(swapper_pg_dir);
+}
+
+static void __init clear_pgds(unsigned long start,
+			unsigned long end)
+{
+	for (; start && start < end; start += PMD_SIZE)
+		pmd_clear(pmd_off_k(start));
+}
+
+pte_t * __init kasan_pte_populate(pmd_t *pmd, unsigned long addr, int node)
+{
+	pte_t *pte = pte_offset_kernel(pmd, addr);
+
+	if (pte_none(*pte)) {
+		pte_t entry;
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p)
+			return NULL;
+		entry = pfn_pte(virt_to_pfn(p),
+			__pgprot(pgprot_val(PAGE_KERNEL)));
+		set_pte_at(&init_mm, addr, pte, entry);
+	}
+	return pte;
+}
+
+pmd_t * __init kasan_pmd_populate(pud_t *pud, unsigned long addr, int node)
+{
+	pmd_t *pmd = pmd_offset(pud, addr);
+
+	if (pmd_none(*pmd)) {
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p)
+			return NULL;
+		pmd_populate_kernel(&init_mm, pmd, p);
+	}
+	return pmd;
+}
+
+pud_t * __init kasan_pud_populate(pgd_t *pgd, unsigned long addr, int node)
+{
+	pud_t *pud = pud_offset(pgd, addr);
+
+	if (pud_none(*pud)) {
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p)
+			return NULL;
+		pr_err("populating pud addr %lx\n", addr);
+		pud_populate(&init_mm, pud, p);
+	}
+	return pud;
+}
+
+pgd_t * __init kasan_pgd_populate(unsigned long addr, int node)
+{
+	pgd_t *pgd = pgd_offset_k(addr);
+
+	if (pgd_none(*pgd)) {
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p)
+			return NULL;
+		pgd_populate(&init_mm, pgd, p);
+	}
+	return pgd;
+}
+
+static int __init create_mapping(unsigned long start, unsigned long end,
+				int node)
+{
+	unsigned long addr = start;
+	pgd_t *pgd;
+	pud_t *pud;
+	pmd_t *pmd;
+	pte_t *pte;
+
+	pr_info("populating shadow for %lx, %lx\n", start, end);
+
+	for (; addr < end; addr += PAGE_SIZE) {
+		pgd = kasan_pgd_populate(addr, node);
+		if (!pgd)
+			return -ENOMEM;
+
+		pud = kasan_pud_populate(pgd, addr, node);
+		if (!pud)
+			return -ENOMEM;
+
+		pmd = kasan_pmd_populate(pud, addr, node);
+		if (!pmd)
+			return -ENOMEM;
+
+		pte = kasan_pte_populate(pmd, addr, node);
+		if (!pte)
+			return -ENOMEM;
+	}
+	return 0;
+}
+
+
+void __init kasan_init(void)
+{
+	struct memblock_region *reg;
+	u64 orig_ttbr0;
+	int i;
+
+	/*
+	 * We are going to perform proper setup of shadow memory.
+	 * At first we should unmap early shadow (clear_pgds() call bellow).
+	 * However, instrumented code couldn't execute without shadow memory.
+	 * tmp_pgd_table and tmp_pmd_table used to keep early shadow mapped
+	 * until full shadow setup will be finished.
+	 */
+	orig_ttbr0 = get_ttbr0();
+
+#ifdef CONFIG_ARM_LPAE
+	memcpy(tmp_pmd_table,
+		pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
+		sizeof(tmp_pmd_table));
+	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
+	set_pgd(&tmp_pgd_table[pgd_index(KASAN_SHADOW_START)],
+		__pgd(__pa(tmp_pmd_table) | PMD_TYPE_TABLE | L_PGD_SWAPPER));
+	set_ttbr0(__pa(tmp_pgd_table));
+#else
+	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
+	set_ttbr0((u64)__pa(tmp_pgd_table));
+#endif
+	flush_cache_all();
+	local_flush_bp_all();
+	local_flush_tlb_all();
+
+	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
+
+	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+				    kasan_mem_to_shadow((void *)-1UL) + 1);
+
+	for_each_memblock(memory, reg) {
+		void *start = __va(reg->base);
+		void *end = __va(reg->base + reg->size);
+
+		if (reg->base + reg->size > arm_lowmem_limit)
+			end = __va(arm_lowmem_limit);
+		if (start >= end)
+			break;
+
+		create_mapping((unsigned long)kasan_mem_to_shadow(start),
+			(unsigned long)kasan_mem_to_shadow(end),
+			NUMA_NO_NODE);
+	}
+
+	/*1.the module's global variable is in MODULES_VADDR ~ MODULES_END,
+	 *  so we need mapping.
+	 *2.PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
+	 *  ~ MODULES_END's shadow is in the same PMD_SIZE, so we cant
+	 *  use kasan_populate_zero_shadow.
+	 */
+	create_mapping(
+		(unsigned long)kasan_mem_to_shadow((void *)MODULES_VADDR),
+
+		(unsigned long)kasan_mem_to_shadow((void *)(PKMAP_BASE +
+							PMD_SIZE)),
+		NUMA_NO_NODE);
+
+	/*
+	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
+	 * we should make sure that it maps the zero page read-only.
+	 */
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte_at(&init_mm, KASAN_SHADOW_START + i*PAGE_SIZE,
+			&kasan_early_shadow_pte[i],
+			pfn_pte(virt_to_pfn(kasan_early_shadow_page),
+				__pgprot(pgprot_val(PAGE_KERNEL)
+					| L_PTE_RDONLY)));
+	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	set_ttbr0(orig_ttbr0);
+	flush_cache_all();
+	local_flush_bp_all();
+	local_flush_tlb_all();
+	pr_info("Kernel address sanitizer initialized\n");
+	init_task.kasan_depth = 0;
+}
diff --git a/arch/arm/mm/pgd.c b/arch/arm/mm/pgd.c
index a1606d950251..30c70f4ef1b9 100644
--- a/arch/arm/mm/pgd.c
+++ b/arch/arm/mm/pgd.c
@@ -64,6 +64,20 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
 	new_pmd = pmd_alloc(mm, new_pud, 0);
 	if (!new_pmd)
 		goto no_pmd;
+#ifdef CONFIG_KASAN
+	/*
+	 *Copy PMD table for KASAN shadow mappings.
+	 */
+	init_pgd = pgd_offset_k(TASK_SIZE);
+	init_pud = pud_offset(init_pgd, TASK_SIZE);
+	init_pmd = pmd_offset(init_pud, TASK_SIZE);
+	new_pmd = pmd_offset(new_pud, TASK_SIZE);
+	memcpy(new_pmd, init_pmd,
+		(pmd_index(MODULES_VADDR)-pmd_index(TASK_SIZE))
+		* sizeof(pmd_t));
+	clean_dcache_area(new_pmd, PTRS_PER_PMD*sizeof(pmd_t));
+#endif
+
 #endif
 
 	if (!vectors_high()) {
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617221134.9930-6-f.fainelli%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
