Return-Path: <kasan-dev+bncBDE6RCFOWIARBUNCWX6AKGQETWN6CEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B4A412923CD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 10:41:53 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id t1sf4366392ejb.21
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 01:41:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603096913; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ppb2+foC+vMW8lfE69GkmiEm83rLMe5rHPoviVMYSep2Wv6RER71sRMH4Bz/bk9Rce
         CUpcvK0jhbxm8QotF3MKA5ry1k/m7Bt7k/5Eri+1QQT9MqsvmJ4QyC3C8qjBoZ7hjc2s
         4KisicL3MH/SkZKqaMjFJ2IWpjlFm+BAe2+WSit2FZGvSkXimJ48l4uVtXoCJVScj2F/
         ycErBPtx5FuGDEQQUG+y4+oPseXeA6fNp7M4mRVZPPXkCR3xMvN666HFOcPZqhKy8bGs
         7cMr9doTGHxe3odWxuV+lUl0KY1G+7gPMtpuLnCi8b/xuEsaThp2E88yrFmvugI6iULo
         u7SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ajGDu4RYfZeRwHAhjddknZwPYx99HkeXKl1xf3K7K8Q=;
        b=Uj4U2qdifmG/Lrk+qS7Dg07EkPuDKGGVvpvRkNFTdEE/5vD+wA8L155d2RKROMJdvP
         lICHfV1WIZSFkJPnN/ng/G1qrDq0tKMnM1ZIMXCxy9MCbrxTGVriYpP4ecGOh+6C7W45
         ZbJApYBTeGDMRoS4V5cHobQIsykW91gxwmCP99X2gwW232mSxy7VtXcEBxrNnf44egq0
         sudX8/mlkJB3HU3Ke/SqJURH8ZdHH3RC451KEQFSq0uVtbFYx5CBTqugzZ6h+UFBXIKS
         KUAL8pW4PY3edxfB4bqZOYLjwxDRTT2x0CK2gW5IAJGDd/4CCkaWqz8MmPC9W1SBuI1t
         qnAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=vOykgeZE;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ajGDu4RYfZeRwHAhjddknZwPYx99HkeXKl1xf3K7K8Q=;
        b=EVWuelSfPc3oong7kqSBNo/xsNKkmTIR23q36IOjMLt8maJb8+uf0OCGKyBO6Tti61
         bzAXbUH6QAyjCQXpzUusCshA+yxnEwdRuUq3nNzWbIcUoiVLPQ+VFxwRZLUHA1r2MdKq
         +65D25am0FbRxdV/djjMQea1g98VeM5eLG5tAuVXa/YVCewPIyA/EdUYc/INj29nLaxd
         GxIXuwvYqSfiP9oBbesFFjqH3ejoo1eLJ1cg7e7c2lvWkNPirgnTVkH0UfPpviA5rFEb
         MSLtTGBzpOd+f+XP2STs66ZqxnajTR3BTnxt37MAgD6GHX/jqaz7hJ+pHH/nVejVTtG9
         XMpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ajGDu4RYfZeRwHAhjddknZwPYx99HkeXKl1xf3K7K8Q=;
        b=ZBCjENzkncjQdx7yoHd3Y9l0IDOfT4bAo5NLXwQwx+MxBVSNXBaRDcYlYkIr0A3Gs4
         lSxrkYgX1e6p/acXTWai3u3k4RFOh1S7QHDaEl2IpfycC5FkO4e/GMoWjYpuiyla6wKj
         4OMoM8hyygSqdQ5GiUWB9OupmUrrjdz5MoXjRzReYz8udvg5OH0ZiRyKkRoA5N60gdop
         D0ybVRQlIV8X2/behT6P70X5bioeSIY41rviIr9CqrZNYkLL9axbfylrAlzG9lh3OVgx
         aMsrlTkV+/WqXJsplMYaRkhHNvCOH45NyKFgLAaEl97/ba+B3kHdSnr7sL//EEgKdpWp
         jnRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GbCSvTmVH7Be136+g5Ge8k8wAQgiXlCksE2ZOcc9WbR18F5x/
	mAtO30p+O1E0BVecdr4X26c=
X-Google-Smtp-Source: ABdhPJxozyC6wUOORpSzdHXDKF/B98Lssc07KAq+/up0sEsnG4ihEHZrgzLyHwP0eN5rsg2fU5Cc7Q==
X-Received: by 2002:a17:907:20e7:: with SMTP id rh7mr16915035ejb.515.1603096913416;
        Mon, 19 Oct 2020 01:41:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:160e:: with SMTP id f14ls7270976edv.2.gmail; Mon,
 19 Oct 2020 01:41:52 -0700 (PDT)
X-Received: by 2002:a05:6402:1615:: with SMTP id f21mr17707719edv.257.1603096912554;
        Mon, 19 Oct 2020 01:41:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603096912; cv=none;
        d=google.com; s=arc-20160816;
        b=us/QqKJnB/7TJkPTWj4sJ+5SAjlVEdZ2D7LaskVj0H6/TcToz6S0nB4AzCNrlHlOjW
         6mkqv7YGXF2ILPIBUSrDhjgmK+m/qiS8zC2+XgiIsfUWjNNeSeYRIgFQOK8zMx1bXadi
         b5gQ1OAt5Vc/O2/63CfPK+TWdhwxbOBSJqXDWYVNV9Xe6zk9ZWt4rLkk7FFI137nuX6R
         pb/BMVNX+UDCs3g3nt4pN6SW8RjEyV5vzIKEi6e6oHtEYPb+cUNbT5T2YbUeMNweMVAv
         GiBZLGblDLRSFVcndFF3DIShoD5HZ6mL4htgrZiaV0zMXxrMcuzZ8S+CE88mZZjYHcpC
         eHJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z5rl+dr93qvAjAtOmOIYI3mLkiuQrNK/hBohXcBcUbI=;
        b=OdARjTKgE0Pd8NBf8m+XwM8vWP7tYPu+1bSXbD/+eYUFFBg9IiE8eJlrz46XMx/hG4
         qL9YQDTmz5TAY/vcVxNgwDakBTPnEr1jc4sxT/Nv63BXI4tnTen7wTh2n29SHgwiI5aS
         VjetlkUh7V8j5qIoRMoDW5Xh8v2lv/uXIh4Bh/HJOSTitCZhce2/Bzp5roYfilovW9fg
         ejERluwGih7/piHOfBNmbzwxd+5fpwVkX3L/T0ImXx5bh8EoDFKTLyGX2qDQf2ZKD7LF
         nutAXrUepzOx4MWXdzlrf3Q8mk3aAoHNgCO+FrlFKcvd9pDKeN+JOFAafsgvhIlF63cw
         S0hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=vOykgeZE;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id g25si240542eds.3.2020.10.19.01.41.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 01:41:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id a5so10972427ljj.11
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 01:41:52 -0700 (PDT)
X-Received: by 2002:a2e:b5c1:: with SMTP id g1mr5747865ljn.305.1603096912051;
        Mon, 19 Oct 2020 01:41:52 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id b18sm3174795lfp.89.2020.10.19.01.41.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Oct 2020 01:41:51 -0700 (PDT)
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
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Marc Zyngier <marc.zyngier@arm.com>,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 1/5 v16] ARM: Disable KASan instrumentation for some code
Date: Mon, 19 Oct 2020 10:41:36 +0200
Message-Id: <20201019084140.4532-2-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201019084140.4532-1-linus.walleij@linaro.org>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=vOykgeZE;       spf=pass
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
Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Reported-by: Marc Zyngier <marc.zyngier@arm.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v15->v16:
- Collect Florian's Tested-by
- Resend with the other patches
ChangeLog v14->v15:
- Resend with the other patches
ChangeLog v13->v14:
- Resend with the other patches
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201019084140.4532-2-linus.walleij%40linaro.org.
