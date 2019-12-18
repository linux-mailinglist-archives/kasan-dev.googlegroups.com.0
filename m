Return-Path: <kasan-dev+bncBAABBW7A47XQKGQEQM2MR6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C64B51242F2
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 10:24:43 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id b26sf143162lfq.16
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 01:24:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576661083; cv=pass;
        d=google.com; s=arc-20160816;
        b=aUm6p8E7sKQEan4QSwgfl8VP3aU80FGQP3Lef2VtzLosycFmZJIWV3r6AReQsjFbTb
         quG6wkWycSsgBtbUlgXPM4ym7gvtKM+cWRtDHKobfADbQ3wn0fyjbFQRsmzfPFDX6ql/
         IzleYYzsDrTGv9oqw07TnVGNAVF4sjwi7gC181hgcokG/mvB8aHEY+bbv98ktiauNer8
         KjkiyB1yY3gCYiD+PwBhCEpDLH/DG3P9hh4a9wyuTz8Ls+THc63J6HQbg5eSU8wVZATz
         P0yf8wCj9C3PQcWR5BLkfCY22jYztHXCvU3Ju1Xx/g8h53WfcC/B0Za44fzy5/r2H/HG
         qYOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=nnlNhEGytzr+GCm5iiWEdc/ypbYL2hqqGAoaurk2d54=;
        b=jN8uBAJixxH1IeZ4/qSk34MHJkKQxiW5ywmLYfVguibPNmBa6eqFdYWnMvGqfG7GJL
         DFn5/TKc8+zunmFWoVtoCFyY7QTifV3vdMw26GLBjnvqJMLyfHmTak36jd4PKgNKzL1G
         v1Ae4apkgh2rt9KvNb/CevlmkV3Q12YC7ynWeOgKBqIrxZjnDdrmLlu1rW1Zc4DBcajw
         O8RbskqgzutdUmh4pMCKoEhnw9Jp+CKu+nkQM0g6RJIDsOGVakfMR1jtcMe6ngGevEnj
         R4wHah6cCgvvZBikWROiawhyRomnJvco9J3P/8YBaG73KCsxs7h8Az8ROZ78KRXeVLoO
         /CLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nnlNhEGytzr+GCm5iiWEdc/ypbYL2hqqGAoaurk2d54=;
        b=fpZPLbOv0B2+V5JcVD+RN5Cne0CS4TR8l2S619Op5qYA+s9VEEQn0TPkyyxH6wEYgy
         5kWTNLj45+dmXRHG+SoyGzlL0IugJkfNOcPvNUijDtVkBx1sVPeruueSx4S3mb0RsGST
         JASLj28qwwsaBdNkVHe9BR5tjiCJuQygHr47Vb5SqeJBKkac7jncOD2mqxetH/VjgfPv
         VQ1qP4OkYK+Q0L40exKu8Cj0XG1Y3yqoPQC0srUmsU8YqV8vvxi7aSm5lOWr/wdzeorW
         kfVSMRpIomYqQtBC9BBrZzNgPq0hLgSGqE1ujZ1qO+gNQVFjCI/pC8Z/MEoFLNcQjyLA
         663A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nnlNhEGytzr+GCm5iiWEdc/ypbYL2hqqGAoaurk2d54=;
        b=OsUBWFBdxPHqDcm5tXW4P6Q/Klvbf0jPy0RRpxGh1mhU8PaG+pk8pzeyMn0tNz/s9t
         rJRVxn2JgYrP+c98W0r+alD2VP3o2X89zFZuuJlQeMiob7iitGvOEjM7+4vATVMLt3/H
         dP+TMbawbni3n5Ymn7dQoG7xqXyUQlXbt9dNI87pGSV6+P/XMQOySaG68cBMzPYpxCyu
         7G8T/8KvYAZR8iEoCxsKc2ru4QmYuhIm1+PKkNDqsGNjPBAsCLalR9NUAWwVPlkNlEnj
         DUHGcLvacmaZGTZhjoXYtOSz+mcohxPR6CZGjurw/evgEyX98YSBYsCmOrC+2+FOLpb7
         wM/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVc/EAJOg4mFai5XeOC7vrEEZzNunnqHS2gMy9lS+bE9OHI0j3i
	BZAQXetqwdW5PzTKwT8gHkI=
X-Google-Smtp-Source: APXvYqx5BgTfjFt3SpFbOE4dUHAGhE1HVz/8bc4mzWJ2xLeY+oDjwPlMKJUnZhPKd9EXMZ3sX9JlLQ==
X-Received: by 2002:a2e:9157:: with SMTP id q23mr1027116ljg.196.1576661083343;
        Wed, 18 Dec 2019 01:24:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3a07:: with SMTP id h7ls204504lja.3.gmail; Wed, 18 Dec
 2019 01:24:42 -0800 (PST)
X-Received: by 2002:a2e:81c3:: with SMTP id s3mr1023332ljg.168.1576661082872;
        Wed, 18 Dec 2019 01:24:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576661082; cv=none;
        d=google.com; s=arc-20160816;
        b=tmatquZoHvJoAtkqcXtJ04+U76zdAwvBMUIwpdl9GRl7tY06JNOqUSLVo5wgzpcpFk
         RUPJ/wUJDE9lrcz5PLZQgPwdJ/XiVlFdKhPIJ8dLMr48B6opSZGnqDdf+o3vFhF22Ohl
         aczjo+GOR3Pd+qMgFe9I79anF7xB1vYX0EWo1FVScUSpHThQDF4VMVsVYszCadZiGrSg
         fTp60LfE/cgXeXbExx/8kmicdrv0pp9nvGfjDG8JlvmsU4zfvyLIatDNiCUg1AvDaVg+
         cZHwDmp+vlSRNSadYzYREBBc2u3vJsHtUZOa2O0FeSgIQTX8y127eSrM9z9arpXyk6Th
         iXzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=UIFpxTW4P5MeDnUuPm4BnwWHGD1JSFxkki5UmrGbTsw=;
        b=zTxlms4A4MuDvTTWJyoxuik9bWVCOvnWxKvzYbT2OzRgsABMKkwbspJCtO8OBlLp9l
         erpHq9skhzOv6aHewtcPFUWAbW2M4OsU5y3uLY7jDLYN0+I+Waq9OKWnsRsFRxcK5YgP
         BWtgPGZteOJ9rGa9YhaUe4AG5/C+xevtbxsjuMUglKvaJfbiQo9teITn5F5Iy59ralQh
         kiq9yoQGH46V3fU6O1kfPUAPNnFbJomFmUhrkE305JanDBmWU1/HM8v+a5G4ALR39WZv
         iVUPZnDuAW054yooitiTq4Him6u6uUthtfDj6vgiE1BPMb7c6iQAUQ7nmNRJCZy741mN
         iYKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id j30si80298lfp.5.2019.12.18.01.24.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Dec 2019 01:24:42 -0800 (PST)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 93C0CAB71;
	Wed, 18 Dec 2019 09:24:41 +0000 (UTC)
Subject: Re: [RFC PATCH 1/3] x86/xen: add basic KASAN support for PV kernel
To: Sergey Dyasli <sergey.dyasli@citrix.com>, xen-devel@lists.xen.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Boris Ostrovsky <boris.ostrovsky@oracle.com>,
 Stefano Stabellini <sstabellini@kernel.org>,
 George Dunlap <george.dunlap@citrix.com>,
 Ross Lagerwall <ross.lagerwall@citrix.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
 <20191217140804.27364-2-sergey.dyasli@citrix.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <934a2950-9079-138d-5476-5eabd84dfec5@suse.com>
Date: Wed, 18 Dec 2019 10:24:38 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.1
MIME-Version: 1.0
In-Reply-To: <20191217140804.27364-2-sergey.dyasli@citrix.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=jgross@suse.com
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

On 17.12.19 15:08, Sergey Dyasli wrote:
> This enables to use Outline instrumentation for Xen PV kernels.
> 
> KASAN_INLINE and KASAN_VMALLOC options currently lead to boot crashes
> and hence disabled.
> 
> Rough edges in the patch are marked with XXX.
> 
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
> ---
>   arch/x86/mm/init.c          | 14 ++++++++++++++
>   arch/x86/mm/kasan_init_64.c | 28 ++++++++++++++++++++++++++++
>   arch/x86/xen/Makefile       |  7 +++++++
>   arch/x86/xen/enlighten_pv.c |  3 +++
>   arch/x86/xen/mmu_pv.c       | 13 +++++++++++--
>   arch/x86/xen/multicalls.c   | 10 ++++++++++
>   drivers/xen/Makefile        |  2 ++
>   kernel/Makefile             |  2 ++
>   lib/Kconfig.kasan           |  3 ++-
>   9 files changed, 79 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/x86/mm/init.c b/arch/x86/mm/init.c
> index e7bb483557c9..0c98a45eec6c 100644
> --- a/arch/x86/mm/init.c
> +++ b/arch/x86/mm/init.c
> @@ -8,6 +8,8 @@
>   #include <linux/kmemleak.h>
>   #include <linux/sched/task.h>
>   
> +#include <xen/xen.h>
> +
>   #include <asm/set_memory.h>
>   #include <asm/e820/api.h>
>   #include <asm/init.h>
> @@ -835,6 +837,18 @@ void free_kernel_image_pages(const char *what, void *begin, void *end)
>   	unsigned long end_ul = (unsigned long)end;
>   	unsigned long len_pages = (end_ul - begin_ul) >> PAGE_SHIFT;
>   
> +	/*
> +	 * XXX: skip this for now. Otherwise it leads to:
> +	 *
> +	 * (XEN) mm.c:2713:d157v0 Bad type (saw 8c00000000000001 != exp e000000000000000) for mfn 36f40 (pfn 02f40)
> +	 * (XEN) mm.c:1043:d157v0 Could not get page type PGT_writable_page
> +	 * (XEN) mm.c:1096:d157v0 Error getting mfn 36f40 (pfn 02f40) from L1 entry 8010000036f40067 for l1e_owner d157, pg_owner d157
> +	 *
> +	 * and further #PF error: [PROT] [WRITE] in the kernel.
> +	 */
> +	if (xen_pv_domain() && IS_ENABLED(CONFIG_KASAN))
> +		return;
> +

I guess this is related to freeing some kasan page tables without
unpinning them?

>   	free_init_pages(what, begin_ul, end_ul);
>   
>   	/*
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index cf5bc37c90ac..caee2022f8b0 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -13,6 +13,8 @@
>   #include <linux/sched/task.h>
>   #include <linux/vmalloc.h>
>   
> +#include <xen/xen.h>
> +
>   #include <asm/e820/types.h>
>   #include <asm/pgalloc.h>
>   #include <asm/tlbflush.h>
> @@ -20,6 +22,9 @@
>   #include <asm/pgtable.h>
>   #include <asm/cpu_entry_area.h>
>   
> +#include <xen/interface/xen.h>
> +#include <asm/xen/hypervisor.h>
> +
>   extern struct range pfn_mapped[E820_MAX_ENTRIES];
>   
>   static p4d_t tmp_p4d_table[MAX_PTRS_PER_P4D] __initdata __aligned(PAGE_SIZE);
> @@ -305,6 +310,12 @@ static struct notifier_block kasan_die_notifier = {
>   };
>   #endif
>   
> +#ifdef CONFIG_XEN
> +/* XXX: this should go to some header */
> +void __init set_page_prot(void *addr, pgprot_t prot);
> +void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn);
> +#endif
> +

Instead of exporting those, why don't you ...

>   void __init kasan_early_init(void)
>   {
>   	int i;
> @@ -332,6 +343,16 @@ void __init kasan_early_init(void)
>   	for (i = 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
>   		kasan_early_shadow_p4d[i] = __p4d(p4d_val);
>   
> +	if (xen_pv_domain()) {
> +		/* PV page tables must have PAGE_KERNEL_RO */
> +		set_page_prot(kasan_early_shadow_pud, PAGE_KERNEL_RO);
> +		set_page_prot(kasan_early_shadow_pmd, PAGE_KERNEL_RO);
> +		set_page_prot(kasan_early_shadow_pte, PAGE_KERNEL_RO);

add a function doing that to mmu_pv.c (e.g. xen_pv_kasan_early_init())?

> +
> +		/* Add mappings to the initial PV page tables */
> +		kasan_map_early_shadow((pgd_t *)xen_start_info->pt_base);
> +	}
> +
>   	kasan_map_early_shadow(early_top_pgt);
>   	kasan_map_early_shadow(init_top_pgt);
>   }
> @@ -369,6 +390,13 @@ void __init kasan_init(void)
>   				__pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
>   	}
>   
> +	if (xen_pv_domain()) {
> +		/* PV page tables must be pinned */
> +		set_page_prot(early_top_pgt, PAGE_KERNEL_RO);
> +		pin_pagetable_pfn(MMUEXT_PIN_L4_TABLE,
> +				  PFN_DOWN(__pa_symbol(early_top_pgt)));

and another one like xen_pv_kasan_init() here.

> +	}
> +
>   	load_cr3(early_top_pgt);
>   	__flush_tlb_all();
>   
> diff --git a/arch/x86/xen/Makefile b/arch/x86/xen/Makefile
> index 084de77a109e..102fad0b0bca 100644
> --- a/arch/x86/xen/Makefile
> +++ b/arch/x86/xen/Makefile
> @@ -1,3 +1,10 @@
> +KASAN_SANITIZE_enlighten_pv.o := n
> +KASAN_SANITIZE_enlighten.o := n
> +KASAN_SANITIZE_irq.o := n
> +KASAN_SANITIZE_mmu_pv.o := n
> +KASAN_SANITIZE_p2m.o := n
> +KASAN_SANITIZE_multicalls.o := n
> +
>   # SPDX-License-Identifier: GPL-2.0
>   OBJECT_FILES_NON_STANDARD_xen-asm_$(BITS).o := y
>   
> diff --git a/arch/x86/xen/enlighten_pv.c b/arch/x86/xen/enlighten_pv.c
> index ae4a41ca19f6..27de55699f24 100644
> --- a/arch/x86/xen/enlighten_pv.c
> +++ b/arch/x86/xen/enlighten_pv.c
> @@ -72,6 +72,7 @@
>   #include <asm/mwait.h>
>   #include <asm/pci_x86.h>
>   #include <asm/cpu.h>
> +#include <asm/kasan.h>
>   
>   #ifdef CONFIG_ACPI
>   #include <linux/acpi.h>
> @@ -1231,6 +1232,8 @@ asmlinkage __visible void __init xen_start_kernel(void)
>   	/* Get mfn list */
>   	xen_build_dynamic_phys_to_machine();
>   
> +	kasan_early_init();
> +
>   	/*
>   	 * Set up kernel GDT and segment registers, mainly so that
>   	 * -fstack-protector code can be executed.
> diff --git a/arch/x86/xen/mmu_pv.c b/arch/x86/xen/mmu_pv.c
> index c8dbee62ec2a..eaf63f1f26af 100644
> --- a/arch/x86/xen/mmu_pv.c
> +++ b/arch/x86/xen/mmu_pv.c
> @@ -1079,7 +1079,7 @@ static void xen_exit_mmap(struct mm_struct *mm)
>   
>   static void xen_post_allocator_init(void);
>   
> -static void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn)
> +void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn)
>   {
>   	struct mmuext_op op;
>   
> @@ -1767,7 +1767,7 @@ static void __init set_page_prot_flags(void *addr, pgprot_t prot,
>   	if (HYPERVISOR_update_va_mapping((unsigned long)addr, pte, flags))
>   		BUG();
>   }
> -static void __init set_page_prot(void *addr, pgprot_t prot)
> +void __init set_page_prot(void *addr, pgprot_t prot)
>   {
>   	return set_page_prot_flags(addr, prot, UVMF_NONE);
>   }
> @@ -1943,6 +1943,15 @@ void __init xen_setup_kernel_pagetable(pgd_t *pgd, unsigned long max_pfn)
>   	if (i && i < pgd_index(__START_KERNEL_map))
>   		init_top_pgt[i] = ((pgd_t *)xen_start_info->pt_base)[i];
>   
> +#ifdef CONFIG_KASAN
> +	/*
> +	 * Copy KASAN mappings
> +	 * ffffec0000000000 - fffffbffffffffff (=44 bits) kasan shadow memory (16TB)
> +	 */
> +	for (i = 0xec0 >> 3; i < 0xfc0 >> 3; i++)
> +		init_top_pgt[i] = ((pgd_t *)xen_start_info->pt_base)[i];
> +#endif
> +
>   	/* Make pagetable pieces RO */
>   	set_page_prot(init_top_pgt, PAGE_KERNEL_RO);
>   	set_page_prot(level3_ident_pgt, PAGE_KERNEL_RO);
> diff --git a/arch/x86/xen/multicalls.c b/arch/x86/xen/multicalls.c
> index 07054572297f..5e4729efbbe2 100644
> --- a/arch/x86/xen/multicalls.c
> +++ b/arch/x86/xen/multicalls.c
> @@ -99,6 +99,15 @@ void xen_mc_flush(void)
>   				ret++;
>   	}
>   
> +	/*
> +	 * XXX: Kasan produces quite a lot (~2000) of warnings in a form of:
> +	 *
> +	 *     (XEN) mm.c:3222:d155v0 mfn 3704b already pinned
> +	 *
> +	 * during kasan_init(). They are benign, but silence them for now.
> +	 * Otherwise, booting takes too long due to printk() spam.
> +	 */
> +#ifndef CONFIG_KASAN

It might be interesting to identify the problematic page tables.

I guess this would require some hacking to avoid the multicalls in order
to identify which page table should not be pinned again.


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/934a2950-9079-138d-5476-5eabd84dfec5%40suse.com.
