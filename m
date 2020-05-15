Return-Path: <kasan-dev+bncBDE6RCFOWIARBPP77H2QKGQERU2CSEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B8C311D4CC9
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 13:40:45 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id c4sf775606lfj.16
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 04:40:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589542845; cv=pass;
        d=google.com; s=arc-20160816;
        b=MTn44Y/i16R/n+LlosgOVaFGvou46DX+R/VdEgB4JQ4MbdW8M/hsKM7Jw5O1C0PwVZ
         55S2vgcV4gALhY/vhKfgBOk5B+5gfAs3B30KAXQJdadYDAoWhCnb/PiAFqCrlh3yQFPm
         SlTf0/1rVePWiWGJ8VM3brF1+xNV9MjwFYEwrOHOEUCggUbdGWmHON6N0WW3mKGbxZoG
         UrJZx/Y/SswDL6HuUPahwokWypsi5Z4o5nGDo6HFHUPsHBCM8C8FEuEM87zC7YavUa1C
         o2Kx/COAbR8Tf+iHCTcFwdhPP+VHB6yfodI1eeCKdg2IJj0Ath7J3AdOxydfigQozy4A
         xTOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TBqkD9J6tVPz4ps5FQ0v3BvNkMNjvV4FEBPPHtO68rI=;
        b=F0PQS6JQ0X1klRZckkoI/WrNkvZQN/C5XWTGiewQVsfN7Sj4UyWRRfDSTfEySuzSCy
         br1Q7qJ+KOD6LLqLugHepj98iYnaojW+3t7kaYd/P15MMKlyWDooJh/Tz0xOelZ/UG8r
         3L4cHov4jyIoJtvvDxXSO9UTmSdHYJxGTakkJUJZuGAWG3QLQ1YhUz3csqfZ963dVH2k
         r0BmLt8k87SLVYGw/tNcSAP15h0Yx9G1SLhLJxNLJrOy9Ros91AtD/nki+DjdFUY60vo
         8VCbEBG34wTpeZqRUegogJwP7K+H8E/vbuRcsccHPXxZaVvhvtL7eaPOCTEa0tnuaZLq
         MOmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EJFsHD5d;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TBqkD9J6tVPz4ps5FQ0v3BvNkMNjvV4FEBPPHtO68rI=;
        b=cH7xHQs9sPGOBYLecG8z7a0HzWPthM4SicEFfLw7OaSuPyQLm3f1LeQbI4xJ0fj7NG
         AaR3S0H9Iiz74uXQ+oj/DC2qF37fw+mbsIojdkrOaDK8gOYB7fPQ03l9Lzkm5dvwt3Ij
         5A+OSfONFBUUacx5yURgsncvg29q1gIsBYijaq01VLvAbD/HSR01u5X0BZjUhbYWjE5g
         SFlLVVEgxWtMhikRaGFcxDjohqPt7DDC9vWYJednX0/p+G6y1Az/2CcLDUle2pcL/Vew
         NBe+MOilrdTY0HLpMyQrcT+1RkpOTtvsFV/UIKZYwuwawrlR6FVNALbRW/VJMVKd+oNU
         IZQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TBqkD9J6tVPz4ps5FQ0v3BvNkMNjvV4FEBPPHtO68rI=;
        b=RVWw7bMuT/91egN/9kw+p5jsnxnt26lNwoEzjnQefM9yMIeSmydgpQld7seBvlifOL
         1zptvln5EcPA1vU6cGsZFVe0m80lf/SWk5Kaso4GkMMIpn3RN3WXotTO2mo+lxgHcuGX
         e2XI1cYAEyxehmuMHGuaSUbM5tb/qdDZXCK54foNi0GQBPeXckV6Qsd3TJI9OQx9FHTV
         7MDliL6jUJxfePHxy1DNCU29hNJpyXrHyr+tnOOqFiYcWRRhK5Bi192b7DsO0Bkb7+cn
         Gl3//1yR22YIsUooPjmFEGxcIT6djYk7Eu8NPIH5RTQdONcUOK9RapmfG/cEtnnYegoo
         Jibg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HkBTU8Bl5fZtplOtgepij7lveT9J8kGyMypTZYhU3T7Rlp6VD
	WEMyevHqzehHK8YVnZPv5EA=
X-Google-Smtp-Source: ABdhPJwJAleunIZ3qWUvWKDTj6azknXTvM69xH9RSLe4pWdZrKodCeaTwoLqH8U14uSL3/c4lx1RTw==
X-Received: by 2002:ac2:4257:: with SMTP id m23mr2125352lfl.141.1589542845230;
        Fri, 15 May 2020 04:40:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4566:: with SMTP id k6ls269907lfm.6.gmail; Fri, 15 May
 2020 04:40:44 -0700 (PDT)
X-Received: by 2002:a05:6512:3ea:: with SMTP id n10mr2180137lfq.127.1589542844599;
        Fri, 15 May 2020 04:40:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589542844; cv=none;
        d=google.com; s=arc-20160816;
        b=NkFIY8hxSxFHIQStsoV2B4dgfhUEhfRDzBXKBCss6YybwzOh4CJIewC9DtDgCIoHe4
         PUgOhm3hHYqoXgvPzOb1EfOH/NB0avh0uwIMxbYttaYZeIvHVznuWYLpAyrvpEp9N5md
         BAZgRsP6v2xTETtFmRR5u0biBZLvT0yp/11yLbZapqnZGCwsSpKGLbPdcE7c5h8umN50
         uc9Yy4JlSnyPvkjZeZ4ZAu9XHp48+gYCu4q8Mvuuiny+EpXPJUbP7GaIs/ZXzYN99KAf
         UkXq5vQpT2jF7cw0grQeJ4HaWGiDNnebfm9bvB+9Sns8sbGlXIEnChgJRmnKbn4+dV+m
         1QkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=g6gTqv4UmGAZbCp5TjzzAy5mfc7aqGMQAl6xsZbz28M=;
        b=ecfLvcTeiXU+x6i8jVSiXAfmC4eNwAWkVTg9eNq89bhO22M2ojZfJGnCvg6QQwEjnI
         AUWnLo3b2C78I6p5LpCcZ4Aa/U67W0NoN+h6i6BCvCTzobTml+LHaTm4hMrgWKF/8SSJ
         UrkXj8Q0PvLHdWtE8kcnXCXpU1HgyvNyv9vE9nLUt4M4AelMMRptS7wCJIS2+pTDJeoS
         fMglpMUj+QWZH53/OuKs6j4QdizMR7bY5JaLGzF/mp/e0UNk0pddn26/C7EUBA+oswvP
         5uoByV0O8b7YViaAauGM3RjsDXi72tLaeeoUCSqB/q8Gu16FaRwa9wME7G3yjx/Zh62Y
         k4SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EJFsHD5d;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id c24si160216lff.2.2020.05.15.04.40.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 04:40:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id w10so1907944ljo.0
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 04:40:44 -0700 (PDT)
X-Received: by 2002:a05:651c:14d:: with SMTP id c13mr1850742ljd.94.1589542844329;
        Fri, 15 May 2020 04:40:44 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id 130sm1218445lfl.37.2020.05.15.04.40.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 May 2020 04:40:43 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Marc Zyngier <marc.zyngier@arm.com>,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 1/5 v9] ARM: Disable KASan instrumentation for some code
Date: Fri, 15 May 2020 13:40:24 +0200
Message-Id: <20200515114028.135674-2-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200515114028.135674-1-linus.walleij@linaro.org>
References: <20200515114028.135674-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=EJFsHD5d;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Disable instrumentation for arch/arm/boot/compressed/*
since that code is executed before the kernel has even
set up its mappings and definately out of scope for
KASan.

Disable instrumentation of arch/arm/vdso/* because that code
is not linked with the kernel image, so the KASan management
code would fail to link.

Disable instrumentation of arch/arm/mm/physaddr.c. See commit
ec6d06efb0ba ("arm64: Add support for CONFIG_DEBUG_VIRTUAL")
for more details.

Disable kasan check in the function unwind_pop_register because
it does not matter that kasan checks failed when unwind_pop_register()
reads the stack memory of a task.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Reported-by: Marc Zyngier <marc.zyngier@arm.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v8->v9:
- Collect Ard's tags.
ChangeLog v7->v8:
- Do not sanitize arch/arm/mm/mmu.c.
  Apart from being intuitively correct, it turns out that KASan
  will insert a __asan_load4() into the set_pte_at() function
  in mmu.c and this is something that KASan calls in the early
  initialization, to set up the shadow memory. Naturally,
  __asan_load4() cannot be called before the shadow memory is
  set up so we need to exclude mmu.c from sanitization.
ChangeLog v6->v7:
- Removed the KVM instrumentaton disablement since KVM
  on ARM32 is gone.
---
 arch/arm/boot/compressed/Makefile | 1 +
 arch/arm/kernel/unwind.c          | 6 +++++-
 arch/arm/mm/Makefile              | 2 ++
 arch/arm/vdso/Makefile            | 2 ++
 4 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index 9c11e7490292..abd6f3d5c2ba 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -24,6 +24,7 @@ OBJS		+= hyp-stub.o
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT		:= n
diff --git a/arch/arm/kernel/unwind.c b/arch/arm/kernel/unwind.c
index 11a964fd66f4..739a77f39a8f 100644
--- a/arch/arm/kernel/unwind.c
+++ b/arch/arm/kernel/unwind.c
@@ -236,7 +236,11 @@ static int unwind_pop_register(struct unwind_ctrl_block *ctrl,
 		if (*vsp >= (unsigned long *)ctrl->sp_high)
 			return -URC_FAILURE;
 
-	ctrl->vrs[reg] = *(*vsp)++;
+	/* Use READ_ONCE_NOCHECK here to avoid this memory access
+	 * from being tracked by KASAN.
+	 */
+	ctrl->vrs[reg] = READ_ONCE_NOCHECK(*(*vsp));
+	(*vsp)++;
 	return URC_OK;
 }
 
diff --git a/arch/arm/mm/Makefile b/arch/arm/mm/Makefile
index 7cb1699fbfc4..99699c32d8a5 100644
--- a/arch/arm/mm/Makefile
+++ b/arch/arm/mm/Makefile
@@ -7,6 +7,7 @@ obj-y				:= extable.o fault.o init.o iomap.o
 obj-y				+= dma-mapping$(MMUEXT).o
 obj-$(CONFIG_MMU)		+= fault-armv.o flush.o idmap.o ioremap.o \
 				   mmap.o pgd.o mmu.o pageattr.o
+KASAN_SANITIZE_mmu.o		:= n
 
 ifneq ($(CONFIG_MMU),y)
 obj-y				+= nommu.o
@@ -16,6 +17,7 @@ endif
 obj-$(CONFIG_ARM_PTDUMP_CORE)	+= dump.o
 obj-$(CONFIG_ARM_PTDUMP_DEBUGFS)	+= ptdump_debugfs.o
 obj-$(CONFIG_MODULES)		+= proc-syms.o
+KASAN_SANITIZE_physaddr.o	:= n
 obj-$(CONFIG_DEBUG_VIRTUAL)	+= physaddr.o
 
 obj-$(CONFIG_ALIGNMENT_TRAP)	+= alignment.o
diff --git a/arch/arm/vdso/Makefile b/arch/arm/vdso/Makefile
index d3c9f03e7e79..71d18d59bd35 100644
--- a/arch/arm/vdso/Makefile
+++ b/arch/arm/vdso/Makefile
@@ -42,6 +42,8 @@ GCOV_PROFILE := n
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT := n
 
+KASAN_SANITIZE := n
+
 # Force dependency
 $(obj)/vdso.o : $(obj)/vdso.so
 
-- 
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515114028.135674-2-linus.walleij%40linaro.org.
