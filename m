Return-Path: <kasan-dev+bncBDE6RCFOWIARBSOM7X5AKGQEGCQEHSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 72A31268B5E
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 14:47:07 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id i9sf5574991ljc.12
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 05:47:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600087627; cv=pass;
        d=google.com; s=arc-20160816;
        b=B+3kM4UckPm5SXJLGCNDX1aIwznv+4/FYd57N9rx7OxsSyELJ5EfESzQi6b383tvdO
         8v0PSfPWEcY2oeIK6IaEgtXOtYJi8GxaLQz8ueWk/Dbgm53RXWM3+Qd1YGNBy6jco1zt
         Vhc98hE2K2yALGaX1V7CmMb+NpIwQ0oxNFXmdzL7+lLLk7BQ3t3gPEdn+N8ZtqRRNP1T
         W+nPrGDxRVFdFKk50UvLJi3fl+NAgjdlZsOBlNuNMJGjukl67gOqW7AllbUgX5AVEh+G
         XEqTQ7SkOyk6D4V2lo0JWPwpnrWEpEKCzGGN6cao6atcVUXXOnGIySLbfLtW/abhdnfm
         YD8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IKnJNiKsqXe/yzK95Jo8gKG/zm+sRReh9lc0kDhl5uc=;
        b=vA3maUY3Rn+a/Uy1tx0gYTxsFPLzSIcBRVvrKX4dZqoO+FwdgZ98kRigqrKUmlZlFE
         7r3+4ZCXSUF0PXiXXbQEb8jVHHTZ5MgGK1nhHN5NDKwOZfyvepVEiwp1EBWc4OJ/q29t
         I6iGeoyaP7NTivV8LU1dtkSmpNfu1sne8I8WBY2c+Ios9FyEi2B4Gy078QIlyZmkqD24
         Ee4d0//9Cxp6bSdhS4q60iZEHqHfJH+Gb4Wv04y9JFMMO/dHPBT37NoeWWDCsEX2oreC
         7wKrtpret0uszSnDeM62jvxEilISZRX2M1ydFPiBzrCPESKEIoLOajjGy7AH2lqmmPLh
         EHxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=UlTFGgqS;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IKnJNiKsqXe/yzK95Jo8gKG/zm+sRReh9lc0kDhl5uc=;
        b=lIu0yYSXRLioDqTtDbbe1KJBF+QE7iecYp+xAWdTJQActYkeQSt4n6vJ++NBbBnfzb
         5kTGU29KeSRsKUY0ctMtI/0oVsCDMclKX/zImZMnQ9RRu7SEUo3kiikm5DHcsOm2aVFz
         YAy88Mbid0xgIYdarntNcTOofxaeZfrQnkgEulcUceOJmRNdiF8zQP5X/1joSmwnGyQK
         1W5wMDCKqPILzdKoCbPU5gy0qBx4rAFE4TQiLSxpywqlVJ/Vhie/Eb/Mhw0kt5MYMhkC
         g3quoMYXI+0pUzkoLCqKXfEvvZbR5Zlo+JSuC0ph0gmNp9BgmxsiHeuQyrTjEwleGA+B
         3mYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IKnJNiKsqXe/yzK95Jo8gKG/zm+sRReh9lc0kDhl5uc=;
        b=J6nFX8k2QTvafVQsyzBVB4THtqmRpww4K8SkN3Qo6TpQ0kDt1jMcEPetCHo9KuI7G6
         XMB5aefdN9W2NtYCiYEnnP3DYN7f6G9Vb//fDYuMcpQNG1CJYFIxfOl4JY/BAbaUdXpr
         fAHS7rx83q7zeduIkaykOE4+hixq0BNwulaQJGXJYBGVjFifkCRkCQukHKq4USQJXstT
         Nz9XAHtpz9kl+6RmSazJPou4Yne7a0EfxNdyefw71Oy8YUumLwvD1Ho9Dj7tWjSPhjhQ
         Zy3pjq7WssyWS5ep5Hz5HXDR1diIDWl5DizH41SFPiKd/IBIqTXnYUKjt0GoFTQwm6T3
         u5qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533egFtzwWCydp/Nz4mcXtc+c3CBvWERAhB/ySaJ0alr6w7yOPzm
	+YitDGwKxHwTDb1tvxg8X5c=
X-Google-Smtp-Source: ABdhPJxkF6ClBW3c+pMzsOAJhBPyN2wN7daO+o2Qa4mpWRt9l56F8Ou3EBCRLWeI7IqdyWFWz5Plcw==
X-Received: by 2002:a2e:81d7:: with SMTP id s23mr5377900ljg.69.1600087625404;
        Mon, 14 Sep 2020 05:47:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls3283757lfn.2.gmail; Mon, 14 Sep
 2020 05:47:02 -0700 (PDT)
X-Received: by 2002:a05:6512:682:: with SMTP id t2mr5263673lfe.201.1600087622832;
        Mon, 14 Sep 2020 05:47:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600087622; cv=none;
        d=google.com; s=arc-20160816;
        b=e1naQHmUa5SFMaQNz8sk1PlqmXRvMWGJrQKil3O8y1WDshqCj+Xid1he2gBX3TGFaP
         Rd0MeVD5aPH3yssyF1a/rAVo8VebL+liXJ7mbP3+L2OB0O4JqxESmtdKdosptGwS0pbH
         0twHTWdutjozNVr8DLX9Fo+EYjQZYX9qfDxIx4ek036FnAFRjF46HJIVVgcN4q9Hzmrm
         73xFlH9XGowzHN8VsOoUwF8ppckxAQ9DcfNlK+ovlY6B9LUnsAwX+RXzuol9ooCgIPgR
         FvXsLLs5/aKv/3G8sqh3SKazxhdoUj9AcZNALHUnOY7SXuXhYIPA2S+QFj4AlygayH1O
         BxGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NUh1eftA/+0eZX5iLCrDayhmFXLud2BeUHLHENQdVQk=;
        b=dz+yET0GDNohCg9ASZKo457+n2QAxdALQUgGocltsOwk97APlPdjB9oUWMj/IKPfu6
         8KOsTibShTWOv0jUOdx9loXigm1+hXSpYyhKKTigtvWrrCsRyHUI3Nc+YFykC+fmDcR7
         m32hSycQr5VbyMYrR/c/PyxV1HZ+fYwFLRyHXyl6ZHADXUWoEcMCV7cMfvVsGsft/+eT
         KR1zJ1yaTYIFSlUwfaxs2KzvkKn/c9ity7zI3oThvQt5PZ+HLaOQpiMq1V7zCCeHY8e7
         YWdLvhSwxff7IULi/MpA59NnOMQMbDTXeK9SpCxwfdabi7FcvVrNzmidyV1tUxT0qMWE
         kq1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=UlTFGgqS;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x142.google.com (mail-lf1-x142.google.com. [2a00:1450:4864:20::142])
        by gmr-mx.google.com with ESMTPS id y17si326327lfg.2.2020.09.14.05.47.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 05:47:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) client-ip=2a00:1450:4864:20::142;
Received: by mail-lf1-x142.google.com with SMTP id y11so13281339lfl.5
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 05:47:02 -0700 (PDT)
X-Received: by 2002:a05:6512:3191:: with SMTP id i17mr4105880lfe.460.1600087622332;
        Mon, 14 Sep 2020 05:47:02 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id e17sm4050173ljn.18.2020.09.14.05.47.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Sep 2020 05:47:01 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Marc Zyngier <marc.zyngier@arm.com>,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 1/5 v13] ARM: Disable KASan instrumentation for some code
Date: Mon, 14 Sep 2020 14:43:20 +0200
Message-Id: <20200914124324.107114-2-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200914124324.107114-1-linus.walleij@linaro.org>
References: <20200914124324.107114-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=UlTFGgqS;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
ChangeLog v12->v13:
- Rebase on kernel v5.9-rc1
ChangeLog v11->v12:
- Resend with the other changes.
ChangeLog v10->v11:
- Resend with the other changes.
ChangeLog v9->v10:
- Rebase on v5.8-rc1
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
index b1147b7f2c8d..362e17e37398 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -24,6 +24,7 @@ OBJS		+= hyp-stub.o
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT		:= n
diff --git a/arch/arm/kernel/unwind.c b/arch/arm/kernel/unwind.c
index d2bd0df2318d..f35eb584a18a 100644
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
index a54f70731d9f..171c3dcb5242 100644
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
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200914124324.107114-2-linus.walleij%40linaro.org.
