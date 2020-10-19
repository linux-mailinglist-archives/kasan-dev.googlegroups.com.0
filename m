Return-Path: <kasan-dev+bncBAABB3N4WX6AKGQEPOXVVFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id C24AB2924BB
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 11:37:50 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id w16sf6048264ioa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 02:37:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603100269; cv=pass;
        d=google.com; s=arc-20160816;
        b=H37GxFfVxuXY/AomNLupLOHIx+ZlQkDlP8NUloB8LnTca00fbPGPl6GmBqKA2JTh1u
         it/lqbixuLIbz5O7mbXtNV1RNIOOphO7ZEb8JX+WRBGW6q4T+lvH3c2iJmOkpYiK5V8p
         U6elB4yPnmk5Gwz8Uw1GS8erJGVuk+zdfwp1OrR1bxWAYS56sphuIirOO3efOh6bOvvg
         lRn3q1qFou7DMI4Owx1RV4izQBqz+udZVANXf9VMUBnZTlVRafbyxJp83qX0jf1TihRh
         bvzO8sU9lc2KUZho1xwRk1kaxZB55BvQtjKjHkWB7HzE4u4+YSwYBZKVf/vNXh1grtYf
         gpJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8nC2oKrwhxmlaPin/xeCoiwy1Eif9Q1mMfcsEQT3GuY=;
        b=cycAqIL+y9314HrPTSFYSEqx9xu1n8cH/nrlNBor0grEgd8n2rxrYAwzXe+dNySZp8
         kHjVfxpl9jWtiKY58WCT3bfhqrgQ+F1JVHw0/n/RjaGIWe/yd1jCqiSE1UykkGXz2mCK
         tLWFDQ8qTzxzaMZEZrCmefoWEpLI4uQH+VN6G9NUML2Wm9OsSfxrpWvwjR53KqFb3r23
         CnQiamoSi1kyn+fhv+p/Wiy3a5MNBlsfc202giMrOkxqTpv2AzuNVcfotA0+qKQbYWQP
         0LqHbZ9CYCKXNXz5KCs79q5WuVQtqMkZ//VKp1E0O3fdMfD4BYGIJ42iVw1qgRwP+Dhz
         d3Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SWYzc7Vg;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8nC2oKrwhxmlaPin/xeCoiwy1Eif9Q1mMfcsEQT3GuY=;
        b=UJNKZZl/0eIhVcPyW7DDDN7qXtJEFduqkat6ka/MOQ9Nwchva9kLe7adqwWeEXFiS0
         zerZcbAaAUkQMm24mtUa1cB5Xq5BK7RxbWby+tx/crI9bhPQcgFBz0/ffYAsxUTbGjz9
         52L961hG1h2/XLcZ+Wl9romoh7jakfSNPDix5yS/5Q2yp3iy2JEDcOVOL5ljp2HZfuvH
         nuVbkeEcic/O2iC2qJ69qbdwBT8hJYeYGN5VC/l1fa4Fijj7/20WpRauDXPpSEZ6Dcz5
         gxQuVPHxHH7O2o4e+1WnmmC5//O5cc2/SGeR4IKvnJ/D1DjTyy7ERUMdxIc6MhjPvYkJ
         jgGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8nC2oKrwhxmlaPin/xeCoiwy1Eif9Q1mMfcsEQT3GuY=;
        b=jEKUTMics92RWYYI4MDo+EkrO1XFQaLVwnz72jQwbTkPk4bwpcGnVp4xF4JwEtFzEN
         bxkmNPvRmKro/inKXxEX0CLaWUv4xQw0KCGOsqGsg0GiP4fisytxcZL2lMeg4YyoLgvV
         PEf6IZFgK7sAenDNOdH+KOo06GVV5FoX3N9r0MYhx1V+WGdoBolv81et4gJs6Tf0Bhct
         WS3eXTqf4Vfh6SEDQM4Z89etmBS3Glkk8BuTXi/vPL6hCstonca8YRSs/GaIMZZsQbDd
         9wLGkJE8S7EWrZeEm+UZwUYvYd9Uvd/MC7mxUU6c+9ws3jtos8AQHMAjTf0I9rZVL08b
         igDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532n4lr0bQ7VxinU2PI4sAmggNKhtx+rJ/AYvHsWBDLZgdk1IFol
	aPP01APCCceRL+/vDgThKTo=
X-Google-Smtp-Source: ABdhPJzBWRjrGzuet2iVvSwhj4tRcd3Nphv6EJR/5xYSPxXIE52dEpnbb0bh7tiYbzBe1NOrhRFXtw==
X-Received: by 2002:a02:1c8a:: with SMTP id c132mr6321839jac.126.1603100269417;
        Mon, 19 Oct 2020 02:37:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c9c9:: with SMTP id c9ls996443jap.11.gmail; Mon, 19 Oct
 2020 02:37:49 -0700 (PDT)
X-Received: by 2002:a05:6638:1502:: with SMTP id b2mr11100170jat.142.1603100269080;
        Mon, 19 Oct 2020 02:37:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603100269; cv=none;
        d=google.com; s=arc-20160816;
        b=mrXf22S3Ji3gGh8ehAz9g3Ymxtw7QlJ+lROZE8x3I7X8VAAlQ+AX1KFqROFDJ1D07I
         3P4rswLFlCl4i3cBryoFNnViY4XnPyztyNcrrKxncChsaAKGt+A+7GOScvEABKd9bGSW
         QSoR6VErtGKGHzKfazv8Ifv94k19dwyyQw1248PqiDWSZgHYjgPDFnRZexkdAIIPCfoP
         OZ1zox7+OFZdldgj5SE3y2RfCH+b9vzEY5/hxQ6GSaTksoiTipxH5Nd5vijGufpYtmtT
         JoFO8kzGd5GP+W7FURB5e5PnJp3HacRa78xIHHaAh4sYyUw3rlkmwNqDgIYv5U7nubnu
         0G2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DGqDx0QDLVB5nhiA0UEyllENc9qqMSGZv+rHdnkHovM=;
        b=JhlbrDeyMzidzuu+T5+EYlxnxj+imuYV+8PrDJlSpwBb9RdWqsbRxRbIjc0p3YxgLd
         6YaoTAfF/CRd3hpfIN2kRbHyUWMQMGjDiqB0JaFD2YeAsfWJup8/+RkA1CgWqsygNgcZ
         67KcVRT+vJkz88Ko5MSqhMLxLH8nNDLcbzGECIz3w7z4CCAvzhLFwjelq+Cs7bJPE3q9
         Xe3wR6K/AeATctCwD3JJuF3/gIvZ7zBdi+KYc95RaXgE8TTxexl5RvVHIvqujttD0ocg
         RB9E9an+aNVo/TbjWGEWbg4drpByOZbQ+hH47XD55HXljDunSXht59d9sHZniHK6++TO
         nlSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SWYzc7Vg;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id j68si528642ilg.3.2020.10.19.02.37.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Oct 2020 02:37:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098396.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 09J9bXZO180636;
	Mon, 19 Oct 2020 05:37:40 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3498010kny-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 19 Oct 2020 05:37:39 -0400
Received: from m0098396.ppops.net (m0098396.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 09J9bXav180693;
	Mon, 19 Oct 2020 05:37:39 -0400
Received: from ppma02fra.de.ibm.com (47.49.7a9f.ip4.static.sl-reverse.com [159.122.73.71])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3498010kgh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 19 Oct 2020 05:37:39 -0400
Received: from pps.filterd (ppma02fra.de.ibm.com [127.0.0.1])
	by ppma02fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 09J9TbOf006391;
	Mon, 19 Oct 2020 09:34:28 GMT
Received: from b06cxnps3075.portsmouth.uk.ibm.com (d06relay10.portsmouth.uk.ibm.com [9.149.109.195])
	by ppma02fra.de.ibm.com with ESMTP id 347r880yvm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 19 Oct 2020 09:34:27 +0000
Received: from d06av25.portsmouth.uk.ibm.com (d06av25.portsmouth.uk.ibm.com [9.149.105.61])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 09J9YPOI25428418
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Oct 2020 09:34:25 GMT
Received: from d06av25.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 836EF11C052;
	Mon, 19 Oct 2020 09:34:25 +0000 (GMT)
Received: from d06av25.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1210811C04A;
	Mon, 19 Oct 2020 09:34:24 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.52.221])
	by d06av25.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Mon, 19 Oct 2020 09:34:23 +0000 (GMT)
Date: Mon, 19 Oct 2020 12:34:21 +0300
From: Mike Rapoport <rppt@linux.ibm.com>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>,
        Abbott Liu <liuwenliang@huawei.com>,
        Russell King <linux@armlinux.org.uk>, Ard Biesheuvel <ardb@kernel.org>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        linux-arm-kernel@lists.infradead.org, Arnd Bergmann <arnd@arndb.de>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
        Ahmad Fatoum <a.fatoum@pengutronix.de>
Subject: Re: [PATCH 4/5 v16] ARM: Initialize the mapping of KASan shadow
 memory
Message-ID: <20201019093421.GA455883@linux.ibm.com>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-5-linus.walleij@linaro.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201019084140.4532-5-linus.walleij@linaro.org>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.235,18.0.687
 definitions=2020-10-19_02:2020-10-16,2020-10-19 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=1
 impostorscore=0 bulkscore=0 clxscore=1011 adultscore=0 mlxscore=0
 phishscore=0 spamscore=0 mlxlogscore=999 priorityscore=1501 malwarescore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2010190072
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=SWYzc7Vg;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Oct 19, 2020 at 10:41:39AM +0200, Linus Walleij wrote:
> This patch initializes KASan shadow region's page table and memory.
> There are two stage for KASan initializing:
> 
> 1. At early boot stage the whole shadow region is mapped to just
>    one physical page (kasan_zero_page). It is finished by the function
>    kasan_early_init which is called by __mmap_switched(arch/arm/kernel/
>    head-common.S)
> 
> 2. After the calling of paging_init, we use kasan_zero_page as zero
>    shadow for some memory that KASan does not need to track, and we
>    allocate a new shadow space for the other memory that KASan need to
>    track. These issues are finished by the function kasan_init which is
>    call by setup_arch.
> 
> When using KASan we also need to increase the THREAD_SIZE_ORDER
> from 1 to 2 as the extra calls for shadow memory uses quite a bit
> of stack.
> 
> As we need to make a temporary copy of the PGD when setting up
> shadow memory we create a helpful PGD_SIZE definition for both
> LPAE and non-LPAE setups.
> 
> The KASan core code unconditionally calls pud_populate() so this
> needs to be changed from BUG() to do {} while (0) when building
> with KASan enabled.
> 
> After the initial development by Andre Ryabinin several modifications
> have been made to this code:
> 
> Abbott Liu <liuwenliang@huawei.com>
> - Add support ARM LPAE: If LPAE is enabled, KASan shadow region's
>   mapping table need be copied in the pgd_alloc() function.
> - Change kasan_pte_populate,kasan_pmd_populate,kasan_pud_populate,
>   kasan_pgd_populate from .meminit.text section to .init.text section.
>   Reported by Florian Fainelli <f.fainelli@gmail.com>
> 
> Linus Walleij <linus.walleij@linaro.org>:
> - Drop the custom mainpulation of TTBR0 and just use
>   cpu_switch_mm() to switch the pgd table.
> - Adopt to handle 4th level page tabel folding.
> - Rewrite the entire page directory and page entry initialization
>   sequence to be recursive based on ARM64:s kasan_init.c.
> 
> Ard Biesheuvel <ardb@kernel.org>:
> - Necessary underlying fixes.
> - Crucial bug fixes to the memory set-up code.
> 
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Cc: Mike Rapoport <rppt@linux.ibm.com>
> Co-developed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Co-developed-by: Abbott Liu <liuwenliang@huawei.com>
> Co-developed-by: Ard Biesheuvel <ardb@kernel.org>
> Acked-by: Mike Rapoport <rppt@linux.ibm.com>
> Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
> Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
> Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
> Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
> Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
> Reported-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Ard Biesheuvel <ardb@kernel.org>
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
> ---

...

> +	cpu_switch_mm(tmp_pgd_table, &init_mm);
> +	local_flush_tlb_all();
> +
> +	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> +
> +	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> +				    kasan_mem_to_shadow((void *)-1UL) + 1);
> +
> +	for_each_memblock(memory, reg) {
> +		void *start = __va(reg->base);
> +		void *end = __va(reg->base + reg->size);
> +

I've killed for_each_memblock() recently and we have now 

	for_each_mem_range(idx, &pa_start, &pa_end)

instead.

> +		/* Do not attempt to shadow highmem */
> +		if (reg->base >= arm_lowmem_limit) {
> +			pr_info("Skip highmem block %pap-%pap\n",
> +				&reg->base, &reg->base + reg->size);
> +			continue;
> +		}
> +		if (reg->base + reg->size > arm_lowmem_limit) {
> +			pr_info("Truncating shadow for %pap-%pap to lowmem region\n",
> +				&reg->base, &reg->base + reg->size);
> +			end = __va(arm_lowmem_limit);
> +		}
> +		if (start >= end) {
> +			pr_info("Skipping invalid memory block %px-%px\n",
> +				start, end);
> +			continue;
> +		}
> +
> +		create_mapping(start, end);
> +	}
> +
> +	/*
> +	 * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
> +	 *    so we need to map this area.
> +	 * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
> +	 *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
> +	 *    use kasan_populate_zero_shadow.
> +	 */
> +	create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
> +
> +	/*
> +	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
> +	 * we should make sure that it maps the zero page read-only.
> +	 */
> +	for (i = 0; i < PTRS_PER_PTE; i++)
> +		set_pte_at(&init_mm, KASAN_SHADOW_START + i*PAGE_SIZE,
> +			   &kasan_early_shadow_pte[i],
> +			   pfn_pte(virt_to_pfn(kasan_early_shadow_page),
> +				__pgprot(pgprot_val(PAGE_KERNEL)
> +					 | L_PTE_RDONLY)));
> +
> +	cpu_switch_mm(swapper_pg_dir, &init_mm);
> +	local_flush_tlb_all();
> +
> +	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +	pr_info("Kernel address sanitizer initialized\n");
> +	init_task.kasan_depth = 0;
> +}
> diff --git a/arch/arm/mm/pgd.c b/arch/arm/mm/pgd.c
> index c5e1b27046a8..f8e9bc58a84f 100644
> --- a/arch/arm/mm/pgd.c
> +++ b/arch/arm/mm/pgd.c
> @@ -66,7 +66,21 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>  	new_pmd = pmd_alloc(mm, new_pud, 0);
>  	if (!new_pmd)
>  		goto no_pmd;
> -#endif
> +#ifdef CONFIG_KASAN
> +	/*
> +	 * Copy PMD table for KASAN shadow mappings.
> +	 */
> +	init_pgd = pgd_offset_k(TASK_SIZE);
> +	init_p4d = p4d_offset(init_pgd, TASK_SIZE);
> +	init_pud = pud_offset(init_p4d, TASK_SIZE);
> +	init_pmd = pmd_offset(init_pud, TASK_SIZE);
> +	new_pmd = pmd_offset(new_pud, TASK_SIZE);
> +	memcpy(new_pmd, init_pmd,
> +	       (pmd_index(MODULES_VADDR) - pmd_index(TASK_SIZE))
> +	       * sizeof(pmd_t));
> +	clean_dcache_area(new_pmd, PTRS_PER_PMD * sizeof(pmd_t));
> +#endif /* CONFIG_KASAN */
> +#endif /* CONFIG_LPAE */
>  
>  	if (!vectors_high()) {
>  		/*
> -- 
> 2.26.2
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201019093421.GA455883%40linux.ibm.com.
