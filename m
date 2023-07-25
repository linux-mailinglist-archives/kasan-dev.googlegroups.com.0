Return-Path: <kasan-dev+bncBAABBHF376SQMGQEWKGMRVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E710A761BD6
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 16:35:09 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-3fd2e59bc53sf15139015e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 07:35:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690295709; cv=pass;
        d=google.com; s=arc-20160816;
        b=bz8WTmN+/KjjxwANHCy/HFFJ7FEeywVKf6M/H54nHeJ2ii1Wa0iTurum5Ea0HOwph0
         lyVTsftPgTZdxsKett9+dTIGV4i6hpQLSZNP1nXPlHnXFcBVeJSM1aUPd2hTkNKJPshC
         84xze+keEwheku35lf7VpGBibjeTnAcGh4Q/1v2mXHxxctti105KsKxnwyC6QXB35q/u
         Me44t5dGXc8SMh9gGdY9tkHhLy3AK3Z886ll1XmwfZpP0cE9aYWShie5/9m2cLrgDmx3
         kXQgD4oJH0jnSaY/PkY9xk6xXUjUQGH3ZaGPI8CKGwEatfRNgcvG0AWH7T7lPVMi5BGm
         q6Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:mime-version:date
         :message-id:sender:dkim-signature;
        bh=FhzF8wHgXlYDYJiNbPgI89R15gUUeY/4AyQWuluCgjc=;
        fh=R2jtCj4VU/jni9//3DfiNFTisYCOJcS+3KNWqTAUWzk=;
        b=W28857dSJjwXuFm/Mjrh0XVrqjL95yl1VjFa0UyJehrTDFIoGis6dpI137rjHRhsRI
         2cL5o30Jx8QNhyZzA5lD/xPgthtZ3hWC3s6B3zoN7Cwp6RpxaqTrpGLwj00ERqm0p7fH
         1k5tyFynn6xxQYFATaUNfPGpNrFEezfleMWA3JRoXk3pfuQsC0WckO9KW2/Dxvksil8K
         YZQRPUQozD8W4Zr6xR70VHd1ybjaBsBs6MaGoMC0xvt1UPe9GY/kE+q0a9AxLKKdxsDd
         d6keC3/t0eIJ0vhkvKQC8MacPyn22ZNc35nSQd90assORfGuTSYh270eqDqd4hf4hxyL
         4NHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tX0LnmXr;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 95.215.58.1 as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690295709; x=1690900509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=FhzF8wHgXlYDYJiNbPgI89R15gUUeY/4AyQWuluCgjc=;
        b=aunEDbTvM3IJEyavY7tM2SVYda+dkWYnI53tSkq3vVChRRXIBpP5mG3Vcv5Ms9jzR4
         SbUXyv99RMJP6rDIOp39Ezz28XR4EkJhf1BknqZfhZiqJr0MB8c7/+RIejcSxc4AoKPS
         qA4Xkg7dvFeVPWSV9Gkd2LttaQ9KxP+akVK6sv7qXtjVd2uqRPDA4jGH/lMQCkyaPE82
         AwLQ9mbnYT5XIxeRFHdGDpVP7LWS1R7mBtNxXkNAvhtO4l5k6rQ9VzXbORprlgvVWMcn
         yBcZvQNNsfJNqckNZ7QNZoOg8LejLn7+AI0vl3+1T6Bn4RT9CYeo7OvpqulS62O5htNJ
         N+Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690295709; x=1690900509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FhzF8wHgXlYDYJiNbPgI89R15gUUeY/4AyQWuluCgjc=;
        b=gFXapjD+ckAnmgKgPP12AFB01ZGbjBn6YPg4MpsEJtYb1Qg44OwX0f2bz2Yd7hSYOP
         mkiWmtymwzjuwVZ/SXeOJXP5mbH2I/hzOdjsA2trZDzeo8Nf83fJBn1iE5ueeOY6L2QM
         QSmFvtrhTo+FK5mLVZgEGZHi2IXwF7MBC3jTD5ENZVt2etg00X09L9+JyeTW+OsWRKgF
         2c6GV8Ptl+ZJV2/aQ/mzfZrl6aTVojEa2MXbqupr6me1NKTETdDYLlXtY/Angr40Ge1c
         G06tVBfW50A71+FzoVsQ+a2qn5fHXOQpqhFOolodcRlK0NL1y+89viIq7sAdD29Au1+q
         ZL1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYsVeuyLjc8qZxfAk28DFbkbj2v/zWL5tA0UsrBnBdAeAzwj/w1
	sNrz7/3NtrZL6lPM7354PWg=
X-Google-Smtp-Source: APBJJlGEoxcEuYO+NY3MBBsuWnFZWKcW8/qjNgMTdio0wTrw5w6sW1nd4FiubNbdA1zxgN7qt1UF7w==
X-Received: by 2002:a05:600c:2343:b0:3fd:2f8e:2c69 with SMTP id 3-20020a05600c234300b003fd2f8e2c69mr6574281wmq.32.1690295708979;
        Tue, 25 Jul 2023 07:35:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:850d:b0:3fb:ad1f:1fd0 with SMTP id
 gw13-20020a05600c850d00b003fbad1f1fd0ls2055828wmb.0.-pod-prod-03-eu; Tue, 25
 Jul 2023 07:35:07 -0700 (PDT)
X-Received: by 2002:a7b:ce99:0:b0:3fa:991c:2af9 with SMTP id q25-20020a7bce99000000b003fa991c2af9mr8206269wmj.16.1690295707651;
        Tue, 25 Jul 2023 07:35:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690295707; cv=none;
        d=google.com; s=arc-20160816;
        b=rDTuoxe1HOJ6eePiqnHNN0GQEHP2dW/OxUTIRu5Uk5BTEX8ZjpMVj7Oq9Cp+D4kAYA
         Y4NA531k7MSYf7sa6E4ZdY+krr+LK34PhtHlWugrk3TpzIOjysH464kwJo02jDLuEu/F
         z/8QFPqBjhYRyK0PlgIwudPPMgzlJkgUuIm21jquIrmh2xvG3Arf9iIwiF0v+GRTdlaN
         30Hps/DF8FKISpKsJYexp5bS0Du5JK9aCjAXNCv3NyG192desPx0oFFl5S0BkVDKJQoF
         +HRJvBA2IgeEwqKNRZdEx2qJYKZ21TG+/sJJYx2BhNmyRfWUcB4Q+XJlXsBsAD+RDARP
         1YxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :mime-version:date:dkim-signature:message-id;
        bh=kKHakHn9VkLzs6aBbGqhzrbFWR3GMi6GzUkvu6NHQbY=;
        fh=R2jtCj4VU/jni9//3DfiNFTisYCOJcS+3KNWqTAUWzk=;
        b=YXZYUIfGwstB2lw59ekvu4TsIZarak2ecxaOdTw0R33cTVekReictK5ALkJBub8+CJ
         riQYpuCHzQKmVfLkECEcN4xR+6QRuGtct/IsVEJRVjpmEClo+Izyknl/jSZpvlC4yFXh
         1aYNbx+HtSJLzWbtVvZ+XESWK+eoC6IPeXkTvBlU4ffJNFVL/J/F6u8SiUZ4SSwLVdTG
         3j8Dkol3lI1uEzs1MgY7BxM/eLMcOWWtRNiCKO0Hh0CyCThUTDYpNVK6oHLaToyo6iAI
         tmf1knZrK7XsLvOkNXUDX81OPEAl+rsVdQhMZ9f7G5w8yvQkIAeBrk630c8D7X86fcYi
         9PWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tX0LnmXr;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 95.215.58.1 as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-1.mta1.migadu.com (out-1.mta1.migadu.com. [95.215.58.1])
        by gmr-mx.google.com with ESMTPS id az19-20020a05600c601300b003fb415dd573si881037wmb.2.2023.07.25.07.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jul 2023 07:35:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu.yun@linux.dev designates 95.215.58.1 as permitted sender) client-ip=95.215.58.1;
Message-ID: <fa3dcc1b-03b2-567c-b143-8e3a100af9f6@linux.dev>
Date: Tue, 25 Jul 2023 22:34:50 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 4/4 v2] LoongArch: Add KFENCE support
To: Enze Li <lienze@kylinos.cn>, chenhuacai@kernel.org, kernel@xen0n.name,
 loongarch@lists.linux.dev, glider@google.com, elver@google.com,
 akpm@linux-foundation.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Cc: zhangqing@loongson.cn, yangtiezhu@loongson.cn, dvyukov@google.com
References: <20230725061451.1231480-1-lienze@kylinos.cn>
 <20230725061451.1231480-5-lienze@kylinos.cn>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Jackie Liu <liu.yun@linux.dev>
In-Reply-To: <20230725061451.1231480-5-lienze@kylinos.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: liu.yun@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tX0LnmXr;       spf=pass
 (google.com: domain of liu.yun@linux.dev designates 95.215.58.1 as permitted
 sender) smtp.mailfrom=liu.yun@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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



=E5=9C=A8 2023/7/25 14:14, Enze Li =E5=86=99=E9=81=93:
> The LoongArch architecture is quite different from other architectures.
> When the allocating of KFENCE itself is done, it is mapped to the direct
> mapping configuration window [1] by default on LoongArch.  It means that
> it is not possible to use the page table mapped mode which required by
> the KFENCE system and therefore it should be remapped to the appropriate
> region.
>
> This patch adds architecture specific implementation details for KFENCE.
> In particular, this implements the required interface in <asm/kfence.h>.
>
> Tested this patch by running the testcases and all passed.
>
> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.=
html#virtual-address-space-and-address-translation-mode
>
> Signed-off-by: Enze Li <lienze@kylinos.cn>
> ---
>   arch/loongarch/Kconfig               |  1 +
>   arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
>   arch/loongarch/include/asm/pgtable.h | 14 ++++++-
>   arch/loongarch/mm/fault.c            | 22 ++++++----
>   4 files changed, 90 insertions(+), 9 deletions(-)
>   create mode 100644 arch/loongarch/include/asm/kfence.h
>
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index 70635ea3d1e4..5b63b16be49e 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -91,6 +91,7 @@ config LOONGARCH
>   	select HAVE_ARCH_AUDITSYSCALL
>   	select HAVE_ARCH_JUMP_LABEL
>   	select HAVE_ARCH_JUMP_LABEL_RELATIVE
> +	select HAVE_ARCH_KFENCE
>   	select HAVE_ARCH_MMAP_RND_BITS if MMU
>   	select HAVE_ARCH_SECCOMP_FILTER
>   	select HAVE_ARCH_TRACEHOOK
> diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/include=
/asm/kfence.h
> new file mode 100644
> index 000000000000..fb39076fe4d7
> --- /dev/null
> +++ b/arch/loongarch/include/asm/kfence.h
> @@ -0,0 +1,62 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * KFENCE support for LoongArch.
> + *
> + * Author: Enze Li <lienze@kylinos.cn>
> + * Copyright (C) 2022-2023 KylinSoft Corporation.
> + */
> +
> +#ifndef _ASM_LOONGARCH_KFENCE_H
> +#define _ASM_LOONGARCH_KFENCE_H
> +
> +#include <linux/kfence.h>
> +#include <asm/pgtable.h>
> +#include <asm/tlb.h>
> +
> +static inline bool arch_kfence_init_pool(void)
> +{
> +	char *kfence_pool =3D __kfence_pool;
> +	struct vm_struct *area;
> +	int err;
> +
> +	area =3D __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
> +				    KFENCE_AREA_START, KFENCE_AREA_END,
> +				    __builtin_return_address(0));
> +	if (!area)
> +		return false;
> +
> +	__kfence_pool =3D (char *)area->addr;

I think there should be something wrong here.

> +	err =3D ioremap_page_range((unsigned long)__kfence_pool,
> +				 (unsigned long)__kfence_pool + KFENCE_POOL_SIZE,
> +				 virt_to_phys((void *)kfence_pool),
> +				 PAGE_KERNEL);
> +	if (err) {
> +		free_vm_area(area);

If err > 0, return area->addr here, It's not correct.

--=20
Jackie Liu

> +		return false;
> +	}
> +
> +	return true;
> +}
> +
> +/* Protect the given page and flush TLB. */
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
> +	pte_t *pte =3D virt_to_kpte(addr);
> +
> +	if (WARN_ON(!pte) || pte_none(*pte))
> +		return false;
> +
> +	if (protect)
> +		set_pte(pte, __pte(pte_val(*pte) & ~(_PAGE_VALID | _PAGE_PRESENT)));
> +	else
> +		set_pte(pte, __pte(pte_val(*pte) | (_PAGE_VALID | _PAGE_PRESENT)));
> +
> +	/* Flush this CPU's TLB. */
> +	preempt_disable();
> +	local_flush_tlb_one(addr);
> +	preempt_enable();
> +
> +	return true;
> +}
> +
> +#endif /* _ASM_LOONGARCH_KFENCE_H */
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index 98a0c98de9d1..2702a6ba7122 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -77,6 +77,13 @@ extern unsigned long zero_page_mask;
>   	(virt_to_page((void *)(empty_zero_page + (((unsigned long)(vaddr)) & z=
ero_page_mask))))
>   #define __HAVE_COLOR_ZERO_PAGE
>  =20
> +#ifdef CONFIG_KFENCE
> +#define KFENCE_AREA_SIZE \
> +	(((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
> +#else
> +#define KFENCE_AREA_SIZE	0
> +#endif
> +
>   /*
>    * TLB refill handlers may also map the vmalloc area into xkvrange.
>    * Avoid the first couple of pages so NULL pointer dereferences will
> @@ -88,11 +95,16 @@ extern unsigned long zero_page_mask;
>   #define VMALLOC_START	MODULES_END
>   #define VMALLOC_END	\
>   	(vm_map_base +	\
> -	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_S=
IZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
> +	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_S=
IZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE - KFENCE_AREA_SIZE)
>  =20
>   #define vmemmap		((struct page *)((VMALLOC_END + PMD_SIZE) & PMD_MASK))
>   #define VMEMMAP_END	((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
>  =20
> +#ifdef CONFIG_KFENCE
> +#define KFENCE_AREA_START	VMEMMAP_END
> +#define KFENCE_AREA_END		(KFENCE_AREA_START + KFENCE_AREA_SIZE)
> +#endif
> +
>   #define pte_ERROR(e) \
>   	pr_err("%s:%d: bad pte %016lx.\n", __FILE__, __LINE__, pte_val(e))
>   #ifndef __PAGETABLE_PMD_FOLDED
> diff --git a/arch/loongarch/mm/fault.c b/arch/loongarch/mm/fault.c
> index da5b6d518cdb..c0319128b221 100644
> --- a/arch/loongarch/mm/fault.c
> +++ b/arch/loongarch/mm/fault.c
> @@ -23,6 +23,7 @@
>   #include <linux/kprobes.h>
>   #include <linux/perf_event.h>
>   #include <linux/uaccess.h>
> +#include <linux/kfence.h>
>  =20
>   #include <asm/branch.h>
>   #include <asm/mmu_context.h>
> @@ -30,7 +31,8 @@
>  =20
>   int show_unhandled_signals =3D 1;
>  =20
> -static void __kprobes no_context(struct pt_regs *regs, unsigned long add=
ress)
> +static void __kprobes no_context(struct pt_regs *regs, unsigned long add=
ress,
> +				 unsigned long write)
>   {
>   	const int field =3D sizeof(unsigned long) * 2;
>  =20
> @@ -38,6 +40,9 @@ static void __kprobes no_context(struct pt_regs *regs, =
unsigned long address)
>   	if (fixup_exception(regs))
>   		return;
>  =20
> +	if (kfence_handle_page_fault(address, write, regs))
> +		return;
> +
>   	/*
>   	 * Oops. The kernel tried to access some bad page. We'll have to
>   	 * terminate things with extreme prejudice.
> @@ -51,14 +56,15 @@ static void __kprobes no_context(struct pt_regs *regs=
, unsigned long address)
>   	die("Oops", regs);
>   }
>  =20
> -static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned lo=
ng address)
> +static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned lo=
ng address,
> +				       unsigned long write)
>   {
>   	/*
>   	 * We ran out of memory, call the OOM killer, and return the userspace
>   	 * (which will retry the fault, or kill us if we got oom-killed).
>   	 */
>   	if (!user_mode(regs)) {
> -		no_context(regs, address);
> +		no_context(regs, address, write);
>   		return;
>   	}
>   	pagefault_out_of_memory();
> @@ -69,7 +75,7 @@ static void __kprobes do_sigbus(struct pt_regs *regs,
>   {
>   	/* Kernel mode? Handle exceptions or die */
>   	if (!user_mode(regs)) {
> -		no_context(regs, address);
> +		no_context(regs, address, write);
>   		return;
>   	}
>  =20
> @@ -90,7 +96,7 @@ static void __kprobes do_sigsegv(struct pt_regs *regs,
>  =20
>   	/* Kernel mode? Handle exceptions or die */
>   	if (!user_mode(regs)) {
> -		no_context(regs, address);
> +		no_context(regs, address, write);
>   		return;
>   	}
>  =20
> @@ -149,7 +155,7 @@ static void __kprobes __do_page_fault(struct pt_regs =
*regs,
>   	 */
>   	if (address & __UA_LIMIT) {
>   		if (!user_mode(regs))
> -			no_context(regs, address);
> +			no_context(regs, address, write);
>   		else
>   			do_sigsegv(regs, write, address, si_code);
>   		return;
> @@ -211,7 +217,7 @@ static void __kprobes __do_page_fault(struct pt_regs =
*regs,
>  =20
>   	if (fault_signal_pending(fault, regs)) {
>   		if (!user_mode(regs))
> -			no_context(regs, address);
> +			no_context(regs, address, write);
>   		return;
>   	}
>  =20
> @@ -232,7 +238,7 @@ static void __kprobes __do_page_fault(struct pt_regs =
*regs,
>   	if (unlikely(fault & VM_FAULT_ERROR)) {
>   		mmap_read_unlock(mm);
>   		if (fault & VM_FAULT_OOM) {
> -			do_out_of_memory(regs, address);
> +			do_out_of_memory(regs, address, write);
>   			return;
>   		} else if (fault & VM_FAULT_SIGSEGV) {
>   			do_sigsegv(regs, write, address, si_code);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fa3dcc1b-03b2-567c-b143-8e3a100af9f6%40linux.dev.
