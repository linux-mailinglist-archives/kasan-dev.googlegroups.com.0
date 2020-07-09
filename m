Return-Path: <kasan-dev+bncBAABBANNTX4AKGQEXCWCPNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 78AC121A5FE
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jul 2020 19:40:18 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id r17sf3631030ybj.22
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jul 2020 10:40:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594316417; cv=pass;
        d=google.com; s=arc-20160816;
        b=mdPwcSEUQjp7Ow+cs1j5HvdErpnsd1bJR8YBhpcpsAEoJFntHBJQaC7Z5tie/giz36
         zCtUBNomOA4js19qw26+WDADvA6tOLPH28W5zsOwz3G5zfWk/pd4UxsUwz2PvLTXNbz8
         ovmNLzjGTk5+tX0ZnDukZWeGag6mhH9RaKNwkokEi45CJ/UPDMtiTX3Ns05e+a800Ltm
         cWTXnyvYxDA/0TGuFYHNVw3IUat6FOhqGGX7htk9zcBfTfp0fzL1r5dtsBD7aw2ZXiDX
         1TJ+EXTJD9O5PPKch70RUcZA4Ndqms7SsDLv0GCZAYuZUOkx2Xl68JxhWmbwxRSrpwrJ
         dAag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=p5YQDXynxyXu6bV5qdFp01pHOzqesCOO813gqMYXjug=;
        b=RWA6AOSOLZNrqqCon0wxP/TblDyFu8YwiVCu2tM5YTOzsHqzhjyvrodmZbrH295FPm
         nsDvEluhhbRy4VmfzAG+0Fz/oDXEVSZetlYlt1bungBeei8WFaOJQ5BZgbveCX043RTb
         sDqnHcgUN9o4bOqYTJGMJ5OF/U5XZakIhvLUeYYQlk2ZbYIOlWkNrP2tjwh0xA0vnEC5
         xxZFRhElAZUJV700B7sozLuSx511Yc6XfWVHraBQhpZzOQyKp14XCpViiISkmENCAns/
         Ujd9XBSPJR+8SRYALVvnwA19GHjgz+RGB4IyazT0dImqZNZ/JRvczEbUle9kw1TWOWu/
         UvHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p5YQDXynxyXu6bV5qdFp01pHOzqesCOO813gqMYXjug=;
        b=E8AiTTmLrm4fCCQpzfqoIXT7RJCJuNbsedE6So7kOEd00t4i1w3e6xF1lQqtpvxdYy
         FPtYRehGCUay/n7mPYPOe0wI4IG5z99PUMJ8E4z2o7Es8TqQUzvGmj0bw0uqzo4r/iDI
         vcZ6+4f8fEKSSKuunEYNFX8JWLvaisvc6a+zb8pZ7RJXqgSYmU4YQwsSmjyc8UV9bOYQ
         WKFCC3T5SgFhiUSDXKIBqJDFJyMM2iZfkOc4vZU1XbkDoJL1sKbK3mDGB4N7ZEcwfnAm
         AOje8e0ZCiNC0KMyYIyjlNPAk9MaU4FC7PjasRiQQLBFYk8k2YbPkJNxez3ENKsTz2t1
         3PGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=p5YQDXynxyXu6bV5qdFp01pHOzqesCOO813gqMYXjug=;
        b=Hf0hmYxb/MDcfq58zELseavpTtFn2PyDYTX8j53OVHEK2dN2l4XWQE8Lq/CGluuI8O
         DtM7oNk1v2Xqbel7ILw+0wQgd5Nw9COCpD7VgiwM4T75YayZD7Np+7Vl7zmJujGodJ3q
         RNDGu2LCyRBCiwWBAmnzSib5oOJya1hjkSMwuzyUZyMpsXdlVKFkuBmz2NxICc2FmOvK
         MHcHXWK2OJpZVWXdrkLk9O0w3UGJ4C5zjQjOW1DuWCq9gMwYvNVPpQZ+TDrSsDouBg5c
         comAUiUKH2ENJZ2XORJM/SN7fKbvt+FceZJoFOyvvDZoH/pkJLvacDikuk4ZeV5z9pd4
         cUog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531U2yE/2I2AYaEXhP+C8CfP6DDKj7xFBmsz6SbFGGfB+ZP+Aw5q
	IOBi9JpPBO+5keZ5DlHgAOc=
X-Google-Smtp-Source: ABdhPJzbzbk3iBSQLIXCSEOD4nejDSgaKjzrs3CKeNp4EV5iE0JvBL4QHcNcM2xybbi6buyaau9f0A==
X-Received: by 2002:a25:cc12:: with SMTP id l18mr37166455ybf.480.1594316417225;
        Thu, 09 Jul 2020 10:40:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ec5:: with SMTP id 188ls2357306ybo.11.gmail; Thu, 09 Jul
 2020 10:40:16 -0700 (PDT)
X-Received: by 2002:a25:2557:: with SMTP id l84mr28847746ybl.404.1594316416823;
        Thu, 09 Jul 2020 10:40:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594316416; cv=none;
        d=google.com; s=arc-20160816;
        b=KmLm2kXI+wPjo/eHSU/+z4bZNEb9rtfgRNOpy1TJ8M2qLzgzXLaCzmD2AXXzmCYLIh
         Ta1sWfFL57FJN7UfiqS2LCyAwKSddZycvx44gbLn+jTb3DFY4g1eJuVwvBTeGNfsKUwn
         dL3L5orXUHTxDVBYl1rjnR64u2CAzyFCeAZarWxI/AXM3332w2FzvQOY+jN2GGuNGH0H
         k9yZrsKdkRRvSBYRn8nKYsbrZi14vz0qpeBp3+FCqaNw6yhztH5NMe83YXRcDziYfTwv
         BXf7ZgpNaZkx/XkHkczKpHaPFew8LbLT53ZcvEyuyy8lXehz+rEpQpCAJJnuA4j1Mb11
         VvjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=gIzdhFR2WGXDghDXtsLmX2PigqbKOJszRapcgXOUEqM=;
        b=vtogXyStk7gla+3dNMReXDC//yEV6U7HqBBVE5EFnRnt5+ak46T/FZSADGCYCv4oqI
         8uCLLgcL4yygWZDow0McuDmvQA920uPM+4M+5K4u7N7iBukU8AsQ32ikugJcIaueYWkD
         t9zIrN65UEhL5ZtjCIZny5T/4AMyR8FjIqfcJG+Ah3Eua5TXnp9P58qx6MAGJjKaMOnB
         378hdQOIlhIfRBosGxAxz09MRFtAOHWEIpE/HrcKUylpaByr4sTTzxFJc/0xRRXW6UK7
         G0Ix2r7LusNIySsc+1isJvamFt0Gzv6TI4GZfelEhGyRyEAwmxiif6vhs09VlCNrJYy3
         oe9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id v16si247186ybe.2.2020.07.09.10.40.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jul 2020 10:40:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098396.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 069HXM46191377;
	Thu, 9 Jul 2020 13:40:07 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 325k3rucyn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 09 Jul 2020 13:40:07 -0400
Received: from m0098396.ppops.net (m0098396.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 069HZIBs007795;
	Thu, 9 Jul 2020 13:40:07 -0400
Received: from ppma02fra.de.ibm.com (47.49.7a9f.ip4.static.sl-reverse.com [159.122.73.71])
	by mx0a-001b2d01.pphosted.com with ESMTP id 325k3rucx7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 09 Jul 2020 13:40:06 -0400
Received: from pps.filterd (ppma02fra.de.ibm.com [127.0.0.1])
	by ppma02fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 069HWHqE024657;
	Thu, 9 Jul 2020 17:40:04 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma02fra.de.ibm.com with ESMTP id 325mr2s3tg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 09 Jul 2020 17:40:04 +0000
Received: from d06av21.portsmouth.uk.ibm.com (d06av21.portsmouth.uk.ibm.com [9.149.105.232])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 069He1ne26673344
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 9 Jul 2020 17:40:02 GMT
Received: from d06av21.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E331D52059;
	Thu,  9 Jul 2020 17:40:01 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.148.204.222])
	by d06av21.portsmouth.uk.ibm.com (Postfix) with ESMTPS id B27215204F;
	Thu,  9 Jul 2020 17:40:00 +0000 (GMT)
Date: Thu, 9 Jul 2020 20:39:58 +0300
From: Mike Rapoport <rppt@linux.ibm.com>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>,
        Abbott Liu <liuwenliang@huawei.com>,
        Russell King <linux@armlinux.org.uk>, Ard Biesheuvel <ardb@kernel.org>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        linux-arm-kernel@lists.infradead.org, Arnd Bergmann <arnd@arndb.de>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 4/5 v12] ARM: Initialize the mapping of KASan shadow
 memory
Message-ID: <20200709173958.GI781326@linux.ibm.com>
References: <20200706122447.696786-1-linus.walleij@linaro.org>
 <20200706122447.696786-5-linus.walleij@linaro.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200706122447.696786-5-linus.walleij@linaro.org>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.235,18.0.687
 definitions=2020-07-09_08:2020-07-09,2020-07-09 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 adultscore=0
 priorityscore=1501 mlxscore=0 lowpriorityscore=0 mlxlogscore=999
 bulkscore=0 suspectscore=5 malwarescore=0 phishscore=0 impostorscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2006250000 definitions=main-2007090122
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Jul 06, 2020 at 02:24:46PM +0200, Linus Walleij wrote:
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
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Cc: Mike Rapoport <rppt@linux.ibm.com>
> Co-developed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Co-developed-by: Abbott Liu <liuwenliang@huawei.com>
> Co-developed-by: Ard Biesheuvel <ardb@kernel.org>
> Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
> Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
> Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
> Reported-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>

Looks ok to me, so FWIW

Acked-by: Mike Rapoport <rppt@linux.ibm.com>

> ---
> ChangeLog v11->v12:
> - Do not try to shadow highmem memory blocks. (Ard)
> - Provoke a build bug if the entire shadow memory doesn't fit
>   inside a single pgd_index() (Ard)
> - Move the pointer to (unsigned long) casts into the create_mapping()
>   function. (Ard)
> - After setting up the shadow memory make sure to issue
>   local_flush_tlb_all() so that we refresh all the global mappings. (Ard)
> - Simplify pte_populate() (Ard)
> - Skip over pud population as well as p4d. (Ard)
> - Drop the stop condition pmd_none(*pmdp) in the pmd population
>   loop. (Ard)
> - Stop passing around the node (NUMA) parameter in the init code,
>   we are not expecting any NUMA architectures to be introduced into
>   ARM32 so just hardcode NUMA_NO_NODE when calling
>   memblock_alloc_try_nid().
> ChangeLog v10->v11:
> - Fix compilation on LPAE systems.
> - Move the check for valid pgdp, pudp and pmdp into the loop for
>   each level moving over the directory pointers: we were just lucky
>   that we just needed one directory for each level so this fixes
>   the pmdp issue with LPAE and KASan now works like a charm on
>   LPAE as well.
> - Fold fourth level page directory (p4d) into the global page directory
>   pgd and just skip into the page upper directory (pud) directly. We
>   do not anticipate that ARM32 will every use 5-level page tables.
> - Simplify the ifdeffery around the temporary pgd.
> - Insert a comment about pud_populate() that is unconditionally called
>   by the KASan core code.
> ChangeLog v9->v10:
> - Rebase onto v5.8-rc1
> - add support for folded p4d page tables, use the primitives necessary
>   for the 4th level folding, add (empty) walks of p4d level.
> - Use the <linux/pgtable.h> header file that has now appeared as part
>   of the VM consolidation series.
> - Use a recursive method to walk pgd/p4d/pud/pmd/pte instead of the
>   separate early/main calls and the flat call structure used in the
>   old code. This was inspired by the ARM64 KASan init code.
> - Assume authorship of this code, I have now written the majority of
>   it so the blame is on me and noone else.
> ChangeLog v8->v9:
> - Drop the custom CP15 manipulation and cache flushing for swapping
>   TTBR0 and instead just use cpu_switch_mm().
> - Collect Ard's tags.
> ChangeLog v7->v8:
> - Rebased.
> ChangeLog v6->v7:
> - Use SPDX identifer for the license.
> - Move the TTBR0 accessor calls into this patch.
> ---
>  arch/arm/include/asm/kasan.h       |  32 ++++
>  arch/arm/include/asm/pgalloc.h     |   8 +-
>  arch/arm/include/asm/thread_info.h |   8 +
>  arch/arm/kernel/head-common.S      |   3 +
>  arch/arm/kernel/setup.c            |   2 +
>  arch/arm/mm/Makefile               |   3 +
>  arch/arm/mm/kasan_init.c           | 264 +++++++++++++++++++++++++++++
>  arch/arm/mm/pgd.c                  |  16 +-
>  8 files changed, 334 insertions(+), 2 deletions(-)
>  create mode 100644 arch/arm/include/asm/kasan.h
>  create mode 100644 arch/arm/mm/kasan_init.c
> 
> diff --git a/arch/arm/include/asm/kasan.h b/arch/arm/include/asm/kasan.h
> new file mode 100644
> index 000000000000..56b954db160e
> --- /dev/null
> +++ b/arch/arm/include/asm/kasan.h
> @@ -0,0 +1,32 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * arch/arm/include/asm/kasan.h
> + *
> + * Copyright (c) 2015 Samsung Electronics Co., Ltd.
> + * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> + *
> + */
> +
> +#ifndef __ASM_KASAN_H
> +#define __ASM_KASAN_H
> +
> +#ifdef CONFIG_KASAN
> +
> +#include <asm/kasan_def.h>
> +
> +#define KASAN_SHADOW_SCALE_SHIFT 3
> +
> +/*
> + * The compiler uses a shadow offset assuming that addresses start
> + * from 0. Kernel addresses don't start from 0, so shadow
> + * for kernel really starts from 'compiler's shadow offset' +
> + * ('kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT)
> + */
> +
> +extern void kasan_init(void);
> +
> +#else
> +static inline void kasan_init(void) { }
> +#endif
> +
> +#endif
> diff --git a/arch/arm/include/asm/pgalloc.h b/arch/arm/include/asm/pgalloc.h
> index 069da393110c..3bf1905df9c3 100644
> --- a/arch/arm/include/asm/pgalloc.h
> +++ b/arch/arm/include/asm/pgalloc.h
> @@ -21,6 +21,7 @@
>  #define _PAGE_KERNEL_TABLE	(PMD_TYPE_TABLE | PMD_BIT4 | PMD_DOMAIN(DOMAIN_KERNEL))
>  
>  #ifdef CONFIG_ARM_LPAE
> +#define PGD_SIZE		(PTRS_PER_PGD * sizeof(pgd_t))
>  
>  static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
>  {
> @@ -39,14 +40,19 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
>  }
>  
>  #else	/* !CONFIG_ARM_LPAE */
> +#define PGD_SIZE		(PAGE_SIZE << 2)
>  
>  /*
>   * Since we have only two-level page tables, these are trivial
>   */
>  #define pmd_alloc_one(mm,addr)		({ BUG(); ((pmd_t *)2); })
>  #define pmd_free(mm, pmd)		do { } while (0)
> +#ifdef CONFIG_KASAN
> +/* The KASan core unconditionally calls pud_populate() on all architectures */
> +#define pud_populate(mm,pmd,pte)	do { } while (0)
> +#else
>  #define pud_populate(mm,pmd,pte)	BUG()
> -
> +#endif
>  #endif	/* CONFIG_ARM_LPAE */
>  
>  extern pgd_t *pgd_alloc(struct mm_struct *mm);
> diff --git a/arch/arm/include/asm/thread_info.h b/arch/arm/include/asm/thread_info.h
> index 3609a6980c34..02813a5d9e10 100644
> --- a/arch/arm/include/asm/thread_info.h
> +++ b/arch/arm/include/asm/thread_info.h
> @@ -13,7 +13,15 @@
>  #include <asm/fpstate.h>
>  #include <asm/page.h>
>  
> +#ifdef CONFIG_KASAN
> +/*
> + * KASan uses a lot of extra stack space so the thread size order needs to
> + * be increased.
> + */
> +#define THREAD_SIZE_ORDER	2
> +#else
>  #define THREAD_SIZE_ORDER	1
> +#endif
>  #define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)
>  #define THREAD_START_SP		(THREAD_SIZE - 8)
>  
> diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
> index 6840c7c60a85..89c80154b9ef 100644
> --- a/arch/arm/kernel/head-common.S
> +++ b/arch/arm/kernel/head-common.S
> @@ -111,6 +111,9 @@ __mmap_switched:
>  	str	r8, [r2]			@ Save atags pointer
>  	cmp	r3, #0
>  	strne	r10, [r3]			@ Save control register values
> +#ifdef CONFIG_KASAN
> +	bl	kasan_early_init
> +#endif
>  	mov	lr, #0
>  	b	start_kernel
>  ENDPROC(__mmap_switched)
> diff --git a/arch/arm/kernel/setup.c b/arch/arm/kernel/setup.c
> index d8e18cdd96d3..b0820847bb92 100644
> --- a/arch/arm/kernel/setup.c
> +++ b/arch/arm/kernel/setup.c
> @@ -58,6 +58,7 @@
>  #include <asm/unwind.h>
>  #include <asm/memblock.h>
>  #include <asm/virt.h>
> +#include <asm/kasan.h>
>  
>  #include "atags.h"
>  
> @@ -1130,6 +1131,7 @@ void __init setup_arch(char **cmdline_p)
>  	early_ioremap_reset();
>  
>  	paging_init(mdesc);
> +	kasan_init();
>  	request_standard_resources(mdesc);
>  
>  	if (mdesc->restart)
> diff --git a/arch/arm/mm/Makefile b/arch/arm/mm/Makefile
> index 99699c32d8a5..4536159bc8fa 100644
> --- a/arch/arm/mm/Makefile
> +++ b/arch/arm/mm/Makefile
> @@ -113,3 +113,6 @@ obj-$(CONFIG_CACHE_L2X0_PMU)	+= cache-l2x0-pmu.o
>  obj-$(CONFIG_CACHE_XSC3L2)	+= cache-xsc3l2.o
>  obj-$(CONFIG_CACHE_TAUROS2)	+= cache-tauros2.o
>  obj-$(CONFIG_CACHE_UNIPHIER)	+= cache-uniphier.o
> +
> +KASAN_SANITIZE_kasan_init.o	:= n
> +obj-$(CONFIG_KASAN)		+= kasan_init.o
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> new file mode 100644
> index 000000000000..b040f4de6b15
> --- /dev/null
> +++ b/arch/arm/mm/kasan_init.c
> @@ -0,0 +1,264 @@
> +// SPDX-License-Identifier: GPL-2.0-only
> +/*
> + * This file contains kasan initialization code for ARM.
> + *
> + * Copyright (c) 2018 Samsung Electronics Co., Ltd.
> + * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> + * Author: Linus Walleij <linus.walleij@linaro.org>
> + */
> +
> +#define pr_fmt(fmt) "kasan: " fmt
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memblock.h>
> +#include <linux/sched/task.h>
> +#include <linux/start_kernel.h>
> +#include <linux/pgtable.h>
> +#include <asm/cputype.h>
> +#include <asm/highmem.h>
> +#include <asm/mach/map.h>
> +#include <asm/memory.h>
> +#include <asm/page.h>
> +#include <asm/pgalloc.h>
> +#include <asm/procinfo.h>
> +#include <asm/proc-fns.h>
> +
> +#include "mm.h"
> +
> +static pgd_t tmp_pgd_table[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
> +
> +pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
> +
> +static __init void *kasan_alloc_block(size_t size)
> +{
> +	return memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
> +				      MEMBLOCK_ALLOC_KASAN, NUMA_NO_NODE);
> +}
> +
> +static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
> +				      unsigned long end, bool early)
> +{
> +	unsigned long next;
> +	pte_t *ptep = pte_offset_kernel(pmdp, addr);
> +
> +	do {
> +		pte_t entry;
> +
> +		next = addr + PAGE_SIZE;
> +
> +		if (!early) {
> +			void *p = kasan_alloc_block(PAGE_SIZE);
> +			if (!p) {
> +				panic("%s failed to alloc pte for address 0x%lx\n",
> +				      __func__, addr);
> +				return;
> +			}
> +			memset(p, KASAN_SHADOW_INIT, PAGE_SIZE);
> +			entry = pfn_pte(virt_to_pfn(p),
> +					__pgprot(pgprot_val(PAGE_KERNEL)));
> +		} else if (pte_none(READ_ONCE(*ptep))) {
> +			/*
> +			 * The early shadow memory is mapping all KASan
> +			 * operations to one and the same page in memory,
> +			 * "kasan_early_shadow_page" so that the instrumentation
> +			 * will work on a scratch area until we can set up the
> +			 * proper KASan shadow memory.
> +			 */
> +			entry = pfn_pte(virt_to_pfn(kasan_early_shadow_page),
> +					__pgprot(_L_PTE_DEFAULT | L_PTE_DIRTY | L_PTE_XN));
> +		} else {
> +			/*
> +			 * Early shadow mappings are PMD_SIZE aligned, so if the
> +			 * first entry is already set, they must all be set.
> +			 */
> +			return;
> +		}
> +
> +		set_pte_at(&init_mm, addr, ptep, entry);
> +	} while (ptep++, addr = next, addr != end);
> +}
> +
> +/*
> + * The pmd (page middle directory) is only used on LPAE
> + */
> +static void __init kasan_pmd_populate(pud_t *pudp, unsigned long addr,
> +				      unsigned long end, bool early)
> +{
> +	unsigned long next;
> +	pmd_t *pmdp = pmd_offset(pudp, addr);
> +
> +	do {
> +		if (pmd_none(*pmdp)) {
> +			void *p = early ? kasan_early_shadow_pte :
> +				kasan_alloc_block(PAGE_SIZE);
> +
> +			if (!p) {
> +				panic("%s failed to allocate pmd for address 0x%lx\n",
> +				      __func__, addr);
> +				return;
> +			}
> +			pmd_populate_kernel(&init_mm, pmdp, p);
> +			flush_pmd_entry(pmdp);
> +		}
> +
> +		next = pmd_addr_end(addr, end);
> +		kasan_pte_populate(pmdp, addr, next, early);
> +	} while (pmdp++, addr = next, addr != end);
> +}
> +
> +static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
> +				      bool early)
> +{
> +	unsigned long next;
> +	pgd_t *pgdp;
> +	p4d_t *p4dp;
> +	pud_t *pudp;
> +
> +	pgdp = pgd_offset_k(addr);
> +
> +	do {
> +		/* Allocate and populate the PGD if it doesn't already exist */
> +		if (!early && pgd_none(*pgdp)) {
> +			void *p = kasan_alloc_block(PAGE_SIZE);
> +
> +			if (!p) {
> +				panic("%s failed to allocate pgd for address 0x%lx\n",
> +				      __func__, addr);
> +				return;
> +			}
> +			pgd_populate(&init_mm, pgdp, p);
> +		}
> +
> +		next = pgd_addr_end(addr, end);
> +		/*
> +		 * We just immediately jump over the p4d and pud page
> +		 * directories since we believe ARM32 will never gain four
> +		 * nor five level page tables.
> +		 */
> +		p4dp = p4d_offset(pgdp, addr);
> +		pudp = pud_offset(p4dp, addr);
> +
> +		kasan_pmd_populate(pudp, addr, next, early);
> +	} while (pgdp++, addr = next, addr != end);
> +}
> +
> +extern struct proc_info_list *lookup_processor_type(unsigned int);
> +
> +void __init kasan_early_init(void)
> +{
> +	struct proc_info_list *list;
> +
> +	/*
> +	 * locate processor in the list of supported processor
> +	 * types.  The linker builds this table for us from the
> +	 * entries in arch/arm/mm/proc-*.S
> +	 */
> +	list = lookup_processor_type(read_cpuid_id());
> +	if (list) {
> +#ifdef MULTI_CPU
> +		processor = *list->proc;
> +#endif
> +	}
> +
> +	BUILD_BUG_ON((KASAN_SHADOW_END - (1UL << 29)) != KASAN_SHADOW_OFFSET);
> +	/*
> +	 * We walk the page table and set all of the shadow memory to point
> +	 * to the scratch page.
> +	 */
> +	kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_END, true);
> +}
> +
> +static void __init clear_pgds(unsigned long start,
> +			unsigned long end)
> +{
> +	for (; start && start < end; start += PMD_SIZE)
> +		pmd_clear(pmd_off_k(start));
> +}
> +
> +static int __init create_mapping(void *start, void *end)
> +{
> +	pr_info("populating shadow for %px to %px\n", start, end);
> +	kasan_pgd_populate((unsigned long)start & PAGE_MASK,
> +			   (unsigned long)end, false);
> +	return 0;
> +}
> +
> +void __init kasan_init(void)
> +{
> +	struct memblock_region *reg;
> +	int i;
> +
> +	/*
> +	 * We are going to perform proper setup of shadow memory.
> +	 *
> +	 * At first we should unmap early shadow (clear_pgds() call bellow).
> +	 * However, instrumented code couldn't execute without shadow memory.
> +	 *
> +	 * To keep the early shadow memory MMU tables around while setting up
> +	 * the proper shadow memory, we copy swapper_pg_dir (the initial page
> +	 * table) to tmp_pgd_table and use that to keep the early shadow memory
> +	 * mapped until the full shadow setup is finished. Then we swap back
> +	 * to the proper swapper_pg_dir.
> +	 */
> +
> +	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
> +#ifdef CONFIG_ARM_LPAE
> +	/* We need to be in the same PGD or this won't work */
> +	BUILD_BUG_ON(pgd_index(KASAN_SHADOW_START) !=
> +		     pgd_index(KASAN_SHADOW_END));
> +	memcpy(tmp_pmd_table,
> +	       pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
> +	       sizeof(tmp_pmd_table));
> +	set_pgd(&tmp_pgd_table[pgd_index(KASAN_SHADOW_START)],
> +		__pgd(__pa(tmp_pmd_table) | PMD_TYPE_TABLE | L_PGD_SWAPPER));
> +#endif
> +	cpu_switch_mm(tmp_pgd_table, &init_mm);
> +	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> +
> +	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> +				    kasan_mem_to_shadow((void *)-1UL) + 1);
> +
> +	for_each_memblock(memory, reg) {
> +		void *start = __va(reg->base);
> +		void *end = __va(reg->base + reg->size);
> +
> +		/* Do not attempt to shadow highmem */
> +		if (reg->base >= arm_lowmem_limit)
> +			continue;
> +		if (reg->base + reg->size > arm_lowmem_limit)
> +			end = __va(arm_lowmem_limit);
> +		if (start >= end)
> +			continue;
> +
> +		create_mapping(kasan_mem_to_shadow(start),
> +			       kasan_mem_to_shadow(end));
> +	}
> +
> +	/*
> +	 * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
> +	 *    so we need to map this area.
> +	 * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
> +	 *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
> +	 *    use kasan_populate_zero_shadow.
> +	 */
> +	create_mapping(
> +		kasan_mem_to_shadow((void *)MODULES_VADDR),
> +		kasan_mem_to_shadow((void *)(PKMAP_BASE + PMD_SIZE)));
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
> +	local_flush_tlb_all();
> +
> +	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +	cpu_switch_mm(swapper_pg_dir, &init_mm);
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
> 2.25.4
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200709173958.GI781326%40linux.ibm.com.
