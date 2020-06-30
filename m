Return-Path: <kasan-dev+bncBDE6RCFOWIARBJMB5X3QKGQEV3JMNYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 40F0C20F5E3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 15:39:50 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id a21sf17186373edy.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 06:39:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593524390; cv=pass;
        d=google.com; s=arc-20160816;
        b=i6hXkIgaJLfGJzlyyX4yRKfyeEdT5zSTypJE6p6hQMRd6DO3bN4WMT4pzM/QuLrRXu
         7uRyj1NZpmX0J7tGR88mmwKMoEU75B+UJuqD6NvfZ5awjU3q8oUlhBJ2gWQJOCaU6M1V
         moiccen6RfWzxdw6eqm4IWRH9rnhxjs/hmaNnSrtvPwDfYD+QY9gx1wsR/hKjWOYRsNm
         z0OiBR6QWPysUcsCrFU7ezMuq9PtA4RwzTmIHXgyS1OFgGFL9MisTkTOKAqo5tRq9JYR
         A7U9XJeV2gEHA5tyls4TZcDY3Zs0FEthQ29wya6S7Xp+9Dv1z2ivulkIk9yqWZqhlFbV
         tgSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8p4gKuZ9F2dD7ldSPjTmdnFVMOfIpMkYBnXPyQw7WI8=;
        b=ELyGIb1CNPCmcVzATGsk9nk/cKlqNqGuRdIeyGVtk6YRR0xRX6f1ucOqbkuQXhDD2I
         P7WlFQF3ll8e/cfNrz7SrJSxWYwdyGaI/93cpovZGJ/GkC7aASE032vZKuavONO+r2ip
         K8rn0FNhNwX9hz9OGLcyHUk9irZfLd7ylCjmsI58811yT9l2hqOwlkQ9bCqGAAi4kx1x
         3fsD2KWXNJnGksc6iQpcwFWXYNgsrFzvtOo6eIIKo4gm7CmnxJzSDqn69apqcy4giNk/
         1Y1B3YRn7ofciM3WK/grJNn8QyS3ppobU//aZqELLS5UoPHX4fgDvLmzcoDbG1gcnWYx
         4UWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Ee2GSg+i;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8p4gKuZ9F2dD7ldSPjTmdnFVMOfIpMkYBnXPyQw7WI8=;
        b=kFUBfNTmxJM0xvrrAJL9IWa0UbQHwieOKKICRgkqgCb7/GWZftNSkoJQNFvfl9Pn6J
         tCqipw6JT1GxrgKRWmyq7CQgDmvIaTX/YgeBAHgu9r7T8UVVeeTN7iLPV0I6+b6+Zos8
         ExLUp/nfPvYpT4nCIfNk9ldYmGGoSqD/6CjpQcpJD73YN0cBwUGwicz1lQ+npyT+fAB2
         1hJqkSo5AbMuEVozKa1ZDREmSfqXkUn9A8sx/kr9Ck6ilzHbrYOVvbYmgPIMBOp66Aiu
         HxI6ulyz05069ff0jh+flUGM6KLbvMx1uXsvXgJBy4Viq+XOflttHv0QMbBWdtqwDTXM
         jzow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8p4gKuZ9F2dD7ldSPjTmdnFVMOfIpMkYBnXPyQw7WI8=;
        b=M62lRHhr1pg6kpc8Opw1vnWV0iKlKX92Gjl/3P41eFFBvFBkb/u1l7u2aTWycgP1Ze
         A4BCanzmdiBrW5JjHZNAhq1eocTBxP5fwI42CnyDEgXdcrfzp+tfxlzy6lUIfkwJOryN
         s0OnhxqBBw/dxs5OZPQGzorf8V1ZkaEilih71CLN5N8FM04Uj64esur8hU2uHprh3g2b
         1JIXI9g9kQUUcdMs789q7uNNnvM2uDK3NIsV9/5QH4QRBfCOqqdrplgbiPYaQgGOEN4B
         5N9pP+l8tXNEeDWJizMjjAUwAefXMCjHwz/t7PQbghQx2ek+isB4FRMmTdml2tbmQ0z6
         IxUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5307QYUBiurELA/iDJ9quwaeW9SDP2U4B8KOixXl1tRPfWeW/WW+
	krfuDm9UUFMH8Vl8kmvv4tM=
X-Google-Smtp-Source: ABdhPJxQ4Gfr3Vlq0XMRhhW9hpm7iW5SihdDiN4oo5UQaeXLzJDOTKT1gpt7ttj076KMvFniOfnc+w==
X-Received: by 2002:aa7:d88e:: with SMTP id u14mr6537550edq.11.1593524389987;
        Tue, 30 Jun 2020 06:39:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3e02:: with SMTP id k2ls6417382eji.4.gmail; Tue, 30
 Jun 2020 06:39:49 -0700 (PDT)
X-Received: by 2002:a17:906:3152:: with SMTP id e18mr18942139eje.137.1593524389444;
        Tue, 30 Jun 2020 06:39:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593524389; cv=none;
        d=google.com; s=arc-20160816;
        b=z+O9DCZLW93RtrAx6z6BtPN8iK7IiGpmjKxiJu9qiO3UchXEgr2gdKSooE83aMY0wW
         oedmnckOmc3pUhWJEbKPzag+FlTnzCkjY/imgtU8kwiAEn6Cn3RhFFDPYzB2Tr6VptvG
         P6Zbp0Dso8QBRomMKeDKL2/lsyv8jG0HItS2mOw1U+AL5nTtmMTKgtCG+q2UGdZG5uQh
         kZFO4nMyMFK13dokSAkY5oSZ3lo2fwhicVIgFc2RB5BjtEjn6fv5ehdg9rM9Is5f2LQn
         RsR3RG6VZ7AkOBELXi1FQA0AyWfo7jriHJnkqAm5ZOqY6yFLzwv4AM/SRLbXjdPTiGso
         NYhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=roJTbpjwW3lAD+B443RLkzAL1uCepXXd7h+hSPpVXWs=;
        b=CTzLFaxXoLAQpPw1BpDz2Ps+RzScNim4VJmdPeJYsMI467NRyFZNMVG7IJurPJ5idV
         quOxMHynb1skwdIoBQkLfe1mWT5YJ5y4dB8YYA1ISDHWfgxKW185Q5Pnf4axKNfYwuXB
         F4c9YaHsD27/39EA+C/yu37PuABIhN6/AyC7pef4zVV8EdOZjOga9T0LeuNEYu52F9AN
         UNPWzbvXHAl7x9rHzHSN26BCUyPmM+PiDdYypIDPJI7mmjuLuIwemnR33YDa0F9ONfiq
         EP0YPJ24ZaUNowsEzEtxpMgRPHi0Pg7nDnO5qpxeN6Zl5b9I/aG/v7gumieaVxs4xBvp
         H+Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Ee2GSg+i;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id k4si155540edl.4.2020.06.30.06.39.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jun 2020 06:39:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id d17so7892614ljl.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Jun 2020 06:39:49 -0700 (PDT)
X-Received: by 2002:a2e:9d10:: with SMTP id t16mr10621981lji.46.1593524389126;
        Tue, 30 Jun 2020 06:39:49 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id a15sm737819ljn.105.2020.06.30.06.39.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jun 2020 06:39:47 -0700 (PDT)
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
Subject: [PATCH 1/5 v11] ARM: Disable KASan instrumentation for some code
Date: Tue, 30 Jun 2020 15:37:32 +0200
Message-Id: <20200630133736.231220-2-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200630133736.231220-1-linus.walleij@linaro.org>
References: <20200630133736.231220-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=Ee2GSg+i;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
index 00602a6fba04..bb8d193d13de 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200630133736.231220-2-linus.walleij%40linaro.org.
