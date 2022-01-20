Return-Path: <kasan-dev+bncBAABBIX4UOHQMGQEPU7GNDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 79B71494737
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jan 2022 07:16:03 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 4-20020a250304000000b006137f4a9920sf9166390ybd.6
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jan 2022 22:16:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642659362; cv=pass;
        d=google.com; s=arc-20160816;
        b=IRYBi6xIgXoBzNdn0ysYICgHJJj9ukJeXB1ndfHyxUUysZJcYEoj6J8P+OSd02jVUy
         SfxaZw0LKAnlU6jHvIJo//NysV05lcjuwOV0vGwOVtElvcl6yTmlMq203SDmJVELJykb
         GCJDaQtwmBYKB8X1+oQk2TYQZfgyHmfYJfH1IoQ+l4twJJ7VohwToXg+DT1e+73VI5Va
         29tuFERAQpKWcQsyI2+nKvWSOSy21Q2NnAwdSZVsk+8QgnR//oF1gePviFVa+wjgFFUY
         ladq4htCzTrX6s8Cm1sIPv1V4WcCLyMkcDYDQ9Jn0emptHYvA6qYFRtC86lT3blzxbqe
         2+gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :references:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xepA5CdiPQokktFSXbDX6WhomilR7mgvABTHcZlKRoQ=;
        b=Tqu+fYP6jiwHQElktHkkQmvvL3v7sUOSZrHxb4DTp3BW8i3w4PpARR1kLsyQ1d0QpF
         dFos26BDCKaqkPYyIVf/Gamx1xtpMCQe5/+ViPXg4fY/CtHe10EGcu8P82z5521ElGKH
         w9WP6goW0OaH/N1Z+D3Y0QKhzqnmRqBHly8NIZHi6mWtEvwtdN41xkqRhRwojAdzUn6n
         Bjtp+7pBn0RMihWfbK4GB8mJOEVqP/Ja8vzrUuJ4SPWvM9X6YzmKQg6YHwywgWJxil0p
         IM5KP1X08PZREbOoKgHDtfxNBPPHNUE594Jj4hmPvNnDd+RnvKAsh/wQI5x90ZU+N3ju
         h6pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:references:in-reply-to
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xepA5CdiPQokktFSXbDX6WhomilR7mgvABTHcZlKRoQ=;
        b=maAUsofIWPzrl5/RKHbo80sfgVggF1tuZkyREdKWGCB/SXiSOoNz/wR+OA/OxrJAl6
         eTKVJaFZ9JeLmiPAh4v53famq9OJbrzp/Ijm264Yrmp29kdtURoLJaJB4fOK0IcAUfN0
         LhDlJgvYEr7lF5hZolm7QcL5md8hTMmPA2ePyzc7iirSuINPpXkbJRnBWHppP8aRsnUc
         uD8MQjp57qdinNIDsvtvR40BKbLeiNFZL0CdRSUqbz5+xAjggGWGx9BOXrHAcrFXXLn/
         B1kTssK/G/PdATSFNL5c8F8Ek9+5bYBDFQVFCpDlqDkUlTqL6MNeUZAZPqyeswFQkN5u
         s87Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:references
         :in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xepA5CdiPQokktFSXbDX6WhomilR7mgvABTHcZlKRoQ=;
        b=aAvDG2ifCWgsFlK6zDs0IPvOF7S8PUNRwV/5UNAcqEsDi7pNWAqD/pbOLxup/DHp58
         zN+VqJYBjasF/8G9dpCoPzuUFR9zjQ4InSd2G16sogrwqchaiwQa2BTN5QK7chF8Ebv1
         X4VDIo6c9GmsZaN2gybWGhW8JNI23w0uY8ndG6HVguWMtiAz4cUOA4+8E6gOnH/B67kX
         ra5sxLyA2bwWkdSETDkAHupnPd9PyKv8o8w4rq7Z00K1Luo0zwPmaX9TXdWdVOZZ3Iak
         lpW6HV+WVTaJNMy31nICgYhCzmH43IM1Nty0SdMmcXqYt6w+cQAmwDuMb9p1uNRGgW5J
         0X7w==
X-Gm-Message-State: AOAM531aSxw19qCtrTBepxwCiqq68XCmshO3hN1bPXPk2RB1fD/ZzWGS
	2YpP8l1fXxjEvzyxMf/0sD8=
X-Google-Smtp-Source: ABdhPJznef8qgnj6PFeRty0hIzfXLtWX2XOQiopCP70T8rLoWDiuSBD7F5FYVIBhEIVGZy3PFJilXQ==
X-Received: by 2002:a05:6902:150a:: with SMTP id q10mr48411660ybu.386.1642659362408;
        Wed, 19 Jan 2022 22:16:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:1254:: with SMTP id 81ls4254934ybs.6.gmail; Wed, 19 Jan
 2022 22:16:02 -0800 (PST)
X-Received: by 2002:a05:6902:100b:: with SMTP id w11mr19628803ybt.350.1642659361978;
        Wed, 19 Jan 2022 22:16:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642659361; cv=none;
        d=google.com; s=arc-20160816;
        b=Ug2muOkbtfCaEPOtUdi6ppFPtJVI5XyN2oA2olOSG3rUwODkd3dhA3QWqU1Z6R6gs7
         PheGkuYRWvdOs7bQagH0nbheCLWJhe1aK2ZaOYti/bYoEJJrg4wQiSRBCo78pqHkFa11
         5KJCx2yNhm6jjXYRZ99Lp1GpQmOMsGLjX06qOtfEg+EUI0v+erx6RUYQ4V+JG1rQeTo9
         cwfVYNqrH86XZmmfCu09+YmfSDlqG/9OEAJqfI5VUEJjKhkq2og7QDD0Je9JQ+BqV0rO
         IeINiQIiqigG6TCeWtVP0V6uRsp2ipl7PHU3/VH0Zl4yC4tMhqZSqM+vKchTAJMBldaC
         UD2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:references:message-id:date:subject:cc:to
         :from;
        bh=lHD+5SXI2yI24yhOmDiWf4vfaQPv+3Wx488yioswqbE=;
        b=yT7oFAtYM9I+joViyFJrR/Tv+q1XeGyAnKK15jW4b0evPc9zVHTqXQfpdBOH5RtBWX
         EME3elUwRyhmln/VnlROmkv4UDPhNklQjiRGgVCtt+I9wN40xxiO/qZDF6g2BWv3JNhU
         +AP0sKVNEumYGOKoNxdTWksI6P7AjEcZqP4yfzz6mEKzWAAu9zlvJi1gPusroWlxc6Hu
         4mhjF9I8M2mxO/9ug7I9/dkAeSCMFRP14L/XkuNlDHIrQyecpHI7Dq9BuDinPNHmMkqC
         pxosG/yO/6X7/XhkA77ezDwMg3+X8FyEfMIb2qUNPDq8bLtNlPHy7qM+5ay1oEIjjCO/
         VWMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id e65si247787ybf.5.2022.01.19.22.16.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jan 2022 22:16:01 -0800 (PST)
Received-SPF: pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpeml500021.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4JfXL94MJKzccch;
	Thu, 20 Jan 2022 14:15:13 +0800 (CST)
Received: from dggpeml500017.china.huawei.com (7.185.36.243) by
 dggpeml500021.china.huawei.com (7.185.36.21) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Thu, 20 Jan 2022 14:15:58 +0800
Received: from linux-suspe12sp5.huawei.com (10.67.133.83) by
 dggpeml500017.china.huawei.com (7.185.36.243) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Thu, 20 Jan 2022 14:15:58 +0800
From: "'ChenJingwen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <chenjingwen6@huawei.com>
CC: <benh@kernel.crashing.org>, <christophe.leroy@c-s.fr>,
	<kasan-dev@googlegroups.com>, <linuxppc-dev@lists.ozlabs.org>,
	<mpe@ellerman.id.au>, <paulus@samba.org>
Subject: Re: [PATCH] powerpc/kasan: Fix early region not updated correctly
Date: Thu, 20 Jan 2022 14:15:58 +0800
Message-ID: <20220120061558.60526-1-chenjingwen6@huawei.com>
X-Mailer: git-send-email 2.12.3
References: <20211229035226.59159-1-chenjingwen6@huawei.com>
In-Reply-To: 20211229035226.59159-1-chenjingwen6@huawei.com
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.133.83]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 dggpeml500017.china.huawei.com (7.185.36.243)
X-CFilter-Loop: Reflected
X-Original-Sender: chenjingwen6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: ChenJingwen <chenjingwen6@huawei.com>
Reply-To: ChenJingwen <chenjingwen6@huawei.com>
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

From: Chen Jingwen <chenjingwen6@huawei.com>

> The shadow's page table is not updated when PTE_RPN_SHIFT is 24
> and PAGE_SHIFT is 12. It not only causes false positives but
> also false negative as shown the following text.
> 
> Fix it by bringing the logic of kasan_early_shadow_page_entry here.
> 
> 1. False Positive:
> ==================================================================
> BUG: KASAN: vmalloc-out-of-bounds in pcpu_alloc+0x508/0xa50
> Write of size 16 at addr f57f3be0 by task swapper/0/1
> 
> CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.15.0-12267-gdebe436e77c7 #1
> Call Trace:
> [c80d1c20] [c07fe7b8] dump_stack_lvl+0x4c/0x6c (unreliable)
> [c80d1c40] [c02ff668] print_address_description.constprop.0+0x88/0x300
> [c80d1c70] [c02ff45c] kasan_report+0x1ec/0x200
> [c80d1cb0] [c0300b20] kasan_check_range+0x160/0x2f0
> [c80d1cc0] [c03018a4] memset+0x34/0x90
> [c80d1ce0] [c0280108] pcpu_alloc+0x508/0xa50
> [c80d1d40] [c02fd7bc] __kmem_cache_create+0xfc/0x570
> [c80d1d70] [c0283d64] kmem_cache_create_usercopy+0x274/0x3e0
> [c80d1db0] [c2036580] init_sd+0xc4/0x1d0
> [c80d1de0] [c00044a0] do_one_initcall+0xc0/0x33c
> [c80d1eb0] [c2001624] kernel_init_freeable+0x2c8/0x384
> [c80d1ef0] [c0004b14] kernel_init+0x24/0x170
> [c80d1f10] [c001b26c] ret_from_kernel_thread+0x5c/0x64
> 
> Memory state around the buggy address:
>  f57f3a80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>  f57f3b00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
> >f57f3b80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>                                                ^
>  f57f3c00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>  f57f3c80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
> ==================================================================
> 
> 2. False Negative (with KASAN tests):
> ==================================================================
> Before fix:
>     ok 45 - kmalloc_double_kzfree
>     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:1039
>     KASAN failure expected in "((volatile char *)area)[3100]", but none occurred
>     not ok 46 - vmalloc_oob
>     not ok 1 - kasan
> 
> ==================================================================
> After fix:
>     ok 1 - kasan
> 
> Fixes: cbd18991e24fe ("powerpc/mm: Fix an Oops in kasan_mmu_init()")
> Cc: stable@vger.kernel.org # 5.4.x
> Signed-off-by: Chen Jingwen <chenjingwen6@huawei.com>
> ---
>  arch/powerpc/mm/kasan/kasan_init_32.c | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
> 
> diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/kasan_init_32.c
> index cf8770b1a692e..f3e4d069e0ba7 100644
> --- a/arch/powerpc/mm/kasan/kasan_init_32.c
> +++ b/arch/powerpc/mm/kasan/kasan_init_32.c
> @@ -83,13 +83,12 @@ void __init
>  kasan_update_early_region(unsigned long k_start, unsigned long k_end, pte_t pte)
>  {
>  	unsigned long k_cur;
> -	phys_addr_t pa = __pa(kasan_early_shadow_page);
>  
>  	for (k_cur = k_start; k_cur != k_end; k_cur += PAGE_SIZE) {
>  		pmd_t *pmd = pmd_off_k(k_cur);
>  		pte_t *ptep = pte_offset_kernel(pmd, k_cur);
>  
> -		if ((pte_val(*ptep) & PTE_RPN_MASK) != pa)
> +		if (pte_page(*ptep) != virt_to_page(lm_alias(kasan_early_shadow_page)))
>  			continue;
>  
>  		__set_pte_at(&init_mm, k_cur, ptep, pte, 0);
> -- 
> 2.19.1

Hi, It can be reproduced with the following kernel configs.
make corenet32_smp_defconfig

CONFIG_PPC_QEMU_E500=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=y
CONFIG_KASAN_VMALLOC=y

And boot the kernel with the rootfs created by buildroot-2021.08.1.
qemu-system-ppc -M ppce500 -cpu e500mc -m 256 -kernel /code/linux/vmlinux \
-drive file=output/images/rootfs.ext2,if=virtio,format=raw \
-append "console=ttyS0 rootwait root=/dev/vda" -serial mon:stdio -nographic

Could you help review this patch?
I will add the necessary info if any is needed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220120061558.60526-1-chenjingwen6%40huawei.com.
