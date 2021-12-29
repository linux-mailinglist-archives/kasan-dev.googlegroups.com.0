Return-Path: <kasan-dev+bncBAABBAVXV6HAMGQEQ3NCJDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id CB8AE480F70
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Dec 2021 04:52:36 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id w7-20020a628207000000b004ba79b50064sf10971151pfd.21
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Dec 2021 19:52:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640749955; cv=pass;
        d=google.com; s=arc-20160816;
        b=I639bPr0tz6ZJktrG1TaI4l0XkAwYG5ISByKt/JdNQlU/LYbfhHTmXN7Q0gxcpG284
         yZNLIaRPY1yWRcFTd//Ywk08gdGf8SLNj9nWBeENa6WCgMhuyxHHS3sKVOoR6LjEvS4x
         HMzDGeoKXjSKe70CgWSalVcO4Y8Y0J/vSI8RyE+z2tHOSEJwWk3e0SFUGzg5jL7GBECf
         BeD40U24vsXd1ze0vCG62QfCf4ZHx5bnyFynj2bgRZ7ECMW97N3IgaXU4Zy03A2WO5tY
         Lc0ndGoq3Niwg9VZmulFI3/esltl74n0e56LAvQKO3DDAQ6oMJFa+FjK+UYI7jk+6ioL
         XEtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:to:from:dkim-signature;
        bh=n2qYN9ku5DaQSbZ4/AuY0DopDMAbhOGCJ3e02UcGsIE=;
        b=K5bS5dJz4cQCkqcsc5yWG7igjqVnpW15BhCwiicKGI0HQ2j6sBK7lzCscaUbaxPSDQ
         3TgAyYs/cXdW7Y+jRKnaATaUYzXD3n0FcIB+yAKA8XNhlyNjSyA8kzbFZAro5p0jPDle
         2zAksKH/D66Oy6+PwV8u83Hck9nKMO/H7k/3HyHr20GnNsSz24A6D7FPAv3A4zEOxThg
         ubiBBwUaBb5ae77TdUSAurJifmXkr0Lq51GS2nRfJaFCXLx03Gcwju8zchW9ffMO43J6
         qDFLXGHvif0x4N+f/zaxGpq6ws0OSXE1udW2CCr8/hG8bquoajfiEEMsFOmijbaMu8lE
         jDhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=n2qYN9ku5DaQSbZ4/AuY0DopDMAbhOGCJ3e02UcGsIE=;
        b=tWcqcyPIZfr4/fjyQQYoCAY2afbB+p8yXTznvXo+3lZyoWMXCJxwXRk3TW7j2F+5c6
         aLpvEpMVlM3wdxCJ9pzLnrjyMoUhap6JOwXYEb/aK3kVPypeAJG+MtjmlewVH9pcIFqZ
         DQACj5g6GYa4jj5Sd/mWLX1vhuqz/p+a/m5CUnbj9FnujoAnbtKHZ1TbeDHVM3qjJ0vL
         0uWH4FJrPFYtDr0/4T0UPTEwTG0AlwlY8CRsNYaVqA3N7GmCx2wUFqYpGyinV/Fmlf3+
         JGlynXYAfSBrUHue+EnR9S46jV9CjCZ/KaoNiZZyvc77iaNgN7UolFBL+nSGOn3FRp9C
         5WYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=n2qYN9ku5DaQSbZ4/AuY0DopDMAbhOGCJ3e02UcGsIE=;
        b=GgiS8ovnRBXc444JSFi4GhUbdiNWd13ZMFXkMaqvkZD654jfDBrlCbss+njsURk60r
         zorWlcOTk/tQFjKSsSiA5JL+352VV/c9Xa5XohYvfU8yh45Jxvpdxi/3k2rmGWshtC1T
         39/GIUku2WnEE+E0q9KJ/E9ywPRMwYY4pghHGxoLBKCEnwwXoAt5YjBIBof9108Msaj2
         jFP1fXpubLFidN1iM08cTDgQylrYriLj3ycOm53AR85/ey7akXKoLPV9Cuoh/GwTdCum
         ezQBG9bhxlw2vS1nqBM02TYR3ZUfZATlJton3AP0wqvun2x2G8ApGmTmEissuPCM8Yky
         6opQ==
X-Gm-Message-State: AOAM530oR9DfqunxKrDJ4RS4KYt8pmvZedJ7zFFtw2f1edsZ0UVBDJYv
	hunHrzU1aPA/jn6Jf0+lBeQ=
X-Google-Smtp-Source: ABdhPJwH66tBptiNVOf3RqQANBs7mRn2u4SjmzsJKV9lxuZlxbaZ44oXrC2sIKSilPadXsdJvy3OIQ==
X-Received: by 2002:a17:90a:7001:: with SMTP id f1mr30100615pjk.70.1640749955014;
        Tue, 28 Dec 2021 19:52:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3442:: with SMTP id lj2ls6453669pjb.1.gmail; Tue, 28
 Dec 2021 19:52:34 -0800 (PST)
X-Received: by 2002:a17:90b:4b0e:: with SMTP id lx14mr18899219pjb.66.1640749954531;
        Tue, 28 Dec 2021 19:52:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640749954; cv=none;
        d=google.com; s=arc-20160816;
        b=jWCKjtRe7SMAx2kYFiIZvCCviYZdEKAgZCdJLGIseYER/kiNe9hjMckP27YYM/ShlR
         m6aUMb+JE+wUaPHVgw104e69VretuZ3f5W84Jg6OOjIHCe6zMnSLi2GaL0Q9hQT3x8Ac
         /DOHabU91NCTcFcWrE9B0i8BxgndulvxlAzNWdAV+5PMDblFZkHuEZVjYUKWUAuR+/IP
         PHLbKcPKQnZ7wkLP6QKXmJ5hR9KEHlYjmjGtA79+eN7yB53qG0n3QoOL4F9qPYjwVy67
         FKL6+cpNTW3Kryp/J/BPeWTHNfai6lRkPrI9u4YT0VD2zbaLY2VPHB648ReXThtb5vEY
         51RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:to:from;
        bh=1LfmY5ciHzcrn0niPAo96geCOzQorEXEzjBIMDkmyO8=;
        b=DyKeIQQx3hmk6DHnO7LYaUoKlv8vbq+Z4TvDEdjyly7AcKXUakl4gt0V0u37pwYRVQ
         qjjWgfic1t3xrB1Jv0jBI4pPrMDjEaYWj2MzSBSd/JbPslJQFEmzQSmm2mqf8thFQdg3
         kyMG/m4K6+0Zj4wPAKA/AsOOv92tZttor9Kml4NTZGHXc+sLL9g1F79au+Z08Dm6ONCg
         oaN8AJU4U1LSKUDr1ntmjBUtRqpVbBn7XiZOYpr7m8cTdrFo+UHtrfbUmg6C0VGi404k
         umyE2RNprexjlJMy+hYBeyXPxnDMZcc/zpAT4NmlOvGaV09cXUZfhKbhHZEWXqO4Oc/P
         S99g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id k14si1750077pji.1.2021.12.28.19.52.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Dec 2021 19:52:34 -0800 (PST)
Received-SPF: pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpeml500025.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4JNyC764gtzccBh;
	Wed, 29 Dec 2021 11:52:03 +0800 (CST)
Received: from dggpeml500017.china.huawei.com (7.185.36.243) by
 dggpeml500025.china.huawei.com (7.185.36.35) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Wed, 29 Dec 2021 11:52:32 +0800
Received: from linux-suspe12sp5.huawei.com (10.67.133.83) by
 dggpeml500017.china.huawei.com (7.185.36.243) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Wed, 29 Dec 2021 11:52:31 +0800
From: "'Chen Jingwen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Chen Jingwen <chenjingwen6@huawei.com>, Michael Ellerman
	<mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	"Paul Mackerras" <paulus@samba.org>, Christophe Leroy
	<christophe.leroy@c-s.fr>, <linuxppc-dev@lists.ozlabs.org>,
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: [PATCH] powerpc/kasan: Fix early region not updated correctly
Date: Wed, 29 Dec 2021 11:52:26 +0800
Message-ID: <20211229035226.59159-1-chenjingwen6@huawei.com>
X-Mailer: git-send-email 2.12.3
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.133.83]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpeml500017.china.huawei.com (7.185.36.243)
X-CFilter-Loop: Reflected
X-Original-Sender: chenjingwen6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Chen Jingwen <chenjingwen6@huawei.com>
Reply-To: Chen Jingwen <chenjingwen6@huawei.com>
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

The shadow's page table is not updated when PTE_RPN_SHIFT is 24
and PAGE_SHIFT is 12. It not only causes false positives but
also false negative as shown the following text.

Fix it by bringing the logic of kasan_early_shadow_page_entry here.

1. False Positive:
==================================================================
BUG: KASAN: vmalloc-out-of-bounds in pcpu_alloc+0x508/0xa50
Write of size 16 at addr f57f3be0 by task swapper/0/1

CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.15.0-12267-gdebe436e77c7 #1
Call Trace:
[c80d1c20] [c07fe7b8] dump_stack_lvl+0x4c/0x6c (unreliable)
[c80d1c40] [c02ff668] print_address_description.constprop.0+0x88/0x300
[c80d1c70] [c02ff45c] kasan_report+0x1ec/0x200
[c80d1cb0] [c0300b20] kasan_check_range+0x160/0x2f0
[c80d1cc0] [c03018a4] memset+0x34/0x90
[c80d1ce0] [c0280108] pcpu_alloc+0x508/0xa50
[c80d1d40] [c02fd7bc] __kmem_cache_create+0xfc/0x570
[c80d1d70] [c0283d64] kmem_cache_create_usercopy+0x274/0x3e0
[c80d1db0] [c2036580] init_sd+0xc4/0x1d0
[c80d1de0] [c00044a0] do_one_initcall+0xc0/0x33c
[c80d1eb0] [c2001624] kernel_init_freeable+0x2c8/0x384
[c80d1ef0] [c0004b14] kernel_init+0x24/0x170
[c80d1f10] [c001b26c] ret_from_kernel_thread+0x5c/0x64

Memory state around the buggy address:
 f57f3a80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
 f57f3b00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>f57f3b80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
                                               ^
 f57f3c00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
 f57f3c80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
==================================================================

2. False Negative (with KASAN tests):
==================================================================
Before fix:
    ok 45 - kmalloc_double_kzfree
    # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:1039
    KASAN failure expected in "((volatile char *)area)[3100]", but none occurred
    not ok 46 - vmalloc_oob
    not ok 1 - kasan

==================================================================
After fix:
    ok 1 - kasan

Fixes: cbd18991e24fe ("powerpc/mm: Fix an Oops in kasan_mmu_init()")
Cc: stable@vger.kernel.org # 5.4.x
Signed-off-by: Chen Jingwen <chenjingwen6@huawei.com>
---
 arch/powerpc/mm/kasan/kasan_init_32.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/kasan_init_32.c
index cf8770b1a692e..f3e4d069e0ba7 100644
--- a/arch/powerpc/mm/kasan/kasan_init_32.c
+++ b/arch/powerpc/mm/kasan/kasan_init_32.c
@@ -83,13 +83,12 @@ void __init
 kasan_update_early_region(unsigned long k_start, unsigned long k_end, pte_t pte)
 {
 	unsigned long k_cur;
-	phys_addr_t pa = __pa(kasan_early_shadow_page);
 
 	for (k_cur = k_start; k_cur != k_end; k_cur += PAGE_SIZE) {
 		pmd_t *pmd = pmd_off_k(k_cur);
 		pte_t *ptep = pte_offset_kernel(pmd, k_cur);
 
-		if ((pte_val(*ptep) & PTE_RPN_MASK) != pa)
+		if (pte_page(*ptep) != virt_to_page(lm_alias(kasan_early_shadow_page)))
 			continue;
 
 		__set_pte_at(&init_mm, k_cur, ptep, pte, 0);
-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211229035226.59159-1-chenjingwen6%40huawei.com.
