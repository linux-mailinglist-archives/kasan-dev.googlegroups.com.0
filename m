Return-Path: <kasan-dev+bncBAABBLHC3PYAKGQEPDVSBOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AFAD1355B3
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 10:23:57 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id u18sf2642368wrn.11
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 01:23:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578561836; cv=pass;
        d=google.com; s=arc-20160816;
        b=BN6dx7U7m82zr8V6FVm/1hXMPGePwdATYLkLQwe46opSYfbfTUn+pEC8pTzqNtWEhu
         t7Eb6BGzfCq5CuTHDUquM5UR4/82Yrmab5F8N4xMx+twgPfMTRwxgX1/rEHrrGRdMmda
         Snrldpux4twraW2lWjqH5ME12c6Gy+rni7TpWULH7DCyI8/tWlU0Czj9DWtV9n3NfMMS
         OlwyQcq9L8XyGh3zLg1XetuiYyCNeQWErQkQ7ltYbgeNA/SD2xRk0iG/bkTsegk0L6O8
         AmuyMVBd+agTquhvP/Gyn9P00/u/Wj78xDKAxhn2BlBSYpvWX7faXK1+UTukKU7PnzIY
         dCkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=tOQCR1rLoh/2amTW2jkcxZwLtmTDSUJDkb7OAuGexmY=;
        b=W0eDv5yd5sFRmdJ36QRzptqPbTxZZV80oA3kul+qUQtwzti80P2RRxT4inGQ/nKg8x
         F/3DSdw8FZM8RCpu0lPSPX1A2wNjQdQRJmDMM9UghDO61VXdD/G9GJw4z9UkS1JP+rom
         hUr2z2GxQIk1rLO2D3kKqStpPE1v2Gxa8KMojj3Dy+7PykHdlvxE37bA7ZNAj3YQkQqf
         uIBmCFloY0mcZ5pZRMl9I2cVvLE+2MZHZKyYWvjRZAQ8BrQ+6iH23V3y60CkMFfQM/9O
         srDBB7+OCEs3T61nOgIx8FYEhnx2V065oR9krlGM8NG7HIOPydByizSm4+usXIYU4J06
         GtIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tOQCR1rLoh/2amTW2jkcxZwLtmTDSUJDkb7OAuGexmY=;
        b=LgB8V/FBlBaoqsDU6N4goTe+GZofELi/2H4j44z/qZUUbZTQ5Ns3bsffpdsMPhfU+1
         /Qw/0BTsDQyULrMpI3WPO8NMRJL1s+mjaxTkyIZoluT4r2Owb3Gx2h7OCYhz5xQnTnEK
         tGMLq4lN6QArdBrpfI7liCj4yDU/qAbzoQRNsJjTMGPkrrXItXl6Hat14kWaVH3R23p3
         QHiw/IvYdJh7S7vSp05JeKSLNvLeOBiPx3u4EKfZGJG4dRY3krI/BE/th/8vB/TpI4Wv
         H7kfmmT7waoYojcol++CrUl/S3P2igasqoqFE2ktCMIzcuo2rAyONBZEgZXDCSRaEHw5
         3nVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tOQCR1rLoh/2amTW2jkcxZwLtmTDSUJDkb7OAuGexmY=;
        b=V+P9ulGIzObCbE8NqG4Erz8MiJE+KhIeGkLEfoXsH3dNvW7sO9zaJxtyvDCAn/dfI7
         7ukf6+eZkSBh9C2IZAhodAwBmez4v0XV1GCS+AC3pdFZEzyvF3ZSRmBsNvxrGRefEENq
         7Xazb6/aHAQIwhbaNFR+jzEGi4kRUiZGLc3WiKWmpMue+BUiiBwtDheVDQoFRBnGndyT
         8Qm1+qIvb8pmkuqL4M1tdu814PMRfSRXxgPPG8BFoYS4ZLPpu+uKsfeirsMniE1d8N1N
         rkxpEiOP2G5nLcUnSx5o++GnyMH0r1JNz5tRhBbcUOUnfrhAi7Ii5c8bnAs0mLSGhP+j
         /XSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWptMyFcQ7VPcFVIGAp/M3CN/cmNuf/7xRsvDndw6uNvcI5R8lz
	/TNKSdQhg8azRoDpxX6pFTo=
X-Google-Smtp-Source: APXvYqyGnMCPNvfLvT4dMccvt+Fqqmu8t8XICSnYs8dLLCEDnA/DXUIDZp302tpXpF/2QoHbZgw1gg==
X-Received: by 2002:a5d:4d06:: with SMTP id z6mr9553224wrt.339.1578561836868;
        Thu, 09 Jan 2020 01:23:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fdc5:: with SMTP id i5ls410362wrs.9.gmail; Thu, 09 Jan
 2020 01:23:56 -0800 (PST)
X-Received: by 2002:adf:f98c:: with SMTP id f12mr9414277wrr.138.1578561836495;
        Thu, 09 Jan 2020 01:23:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578561836; cv=none;
        d=google.com; s=arc-20160816;
        b=qvoE8us3otydRZDUS8+hyAAo57KFhOUXtLCW9maRWZdBZ02UHc6d973C+56xpWMswd
         RUmGqYvgCIiv9lhQ/HykuHcuZ/ttA47cA/IS1fhlgJw0+AknE5etLhL+N5T3arUocTkx
         vrvZUpGnuD1Lz3NIl/0j2bn9SM9AKKblldSG+Qbgu9hPOJcXrFJ5CXQkCPNwlOqpEe83
         8KyshuFSxGZOSxOWYtYt+HukLuNqrNzOrhj40/IMft2we+X0LhLnGMHtntcq6iJjkwLx
         rgukdJde2SZX9aU5gl+Fhuk+SIvKfZeai4ha05atCxCOqrqJFYnFDzoykGXipP11A0ge
         GSVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Xt1xB7cKg0q9fA/Lk3zDCRSrgriFWa4w8FNQhviT++Y=;
        b=VayI93oSvXYM0Oq54wuWWzerZf4i4hv3qeYE1/7+no2bcPbVlPwUWu9NubSWTFhPE3
         /CMrkHE7TXPQvJDqUc9wCi+6XL2uyzZFZf/dajwJXUgO6gaU/x2jTssV0unOYTeupqPH
         dPHLuldxbg8pg4Zk7WN/EdPPrHQyuA4ivs6EG3DfKEsbHH0kxABK6P8eSN0ed5aVPNxM
         6KKgiregJWY3eRBvJzB215tavrflYIsncP5bkSlbDCIE7u/UXwraZcz4TpkAXQWgxmaJ
         fjbLcnyoaNfVV+s2lVc2otME0+t4uFomvNk7mBVs5U4jMsycyscXVMi04DNwETUCWqpF
         L0bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id p16si211976wre.4.2020.01.09.01.23.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jan 2020 01:23:56 -0800 (PST)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 1938ABC8D;
	Thu,  9 Jan 2020 09:22:51 +0000 (UTC)
Subject: Re: [PATCH v1 2/4] x86/xen: add basic KASAN support for PV kernel
To: Sergey Dyasli <sergey.dyasli@citrix.com>, xen-devel@lists.xen.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Boris Ostrovsky <boris.ostrovsky@oracle.com>,
 Stefano Stabellini <sstabellini@kernel.org>,
 George Dunlap <george.dunlap@citrix.com>,
 Ross Lagerwall <ross.lagerwall@citrix.com>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-3-sergey.dyasli@citrix.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <0c968669-2b21-b772-dba8-f674057bd6e7@suse.com>
Date: Thu, 9 Jan 2020 10:15:28 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.1
MIME-Version: 1.0
In-Reply-To: <20200108152100.7630-3-sergey.dyasli@citrix.com>
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

On 08.01.20 16:20, Sergey Dyasli wrote:
> This enables to use Outline instrumentation for Xen PV kernels.
> 
> KASAN_INLINE and KASAN_VMALLOC options currently lead to boot crashes
> and hence disabled.
> 
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
> ---
> RFC --> v1:
> - New functions with declarations in xen/xen-ops.h
> - Fixed the issue with free_kernel_image_pages() with the help of
>    xen_pv_kasan_unpin_pgd()
> ---
>   arch/x86/mm/kasan_init_64.c | 12 ++++++++++++
>   arch/x86/xen/Makefile       |  7 +++++++
>   arch/x86/xen/enlighten_pv.c |  3 +++
>   arch/x86/xen/mmu_pv.c       | 39 +++++++++++++++++++++++++++++++++++++
>   drivers/xen/Makefile        |  2 ++
>   include/xen/xen-ops.h       |  4 ++++
>   kernel/Makefile             |  2 ++
>   lib/Kconfig.kasan           |  3 ++-
>   8 files changed, 71 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index cf5bc37c90ac..902a6a152d33 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -13,6 +13,9 @@
>   #include <linux/sched/task.h>
>   #include <linux/vmalloc.h>
>   
> +#include <xen/xen.h>
> +#include <xen/xen-ops.h>
> +
>   #include <asm/e820/types.h>
>   #include <asm/pgalloc.h>
>   #include <asm/tlbflush.h>
> @@ -332,6 +335,11 @@ void __init kasan_early_init(void)
>   	for (i = 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
>   		kasan_early_shadow_p4d[i] = __p4d(p4d_val);
>   
> +	if (xen_pv_domain()) {
> +		pgd_t *pv_top_pgt = xen_pv_kasan_early_init();

You are breaking the build with CONFIG_XEN_PV undefined here.

> +		kasan_map_early_shadow(pv_top_pgt);
> +	}
> +
>   	kasan_map_early_shadow(early_top_pgt);
>   	kasan_map_early_shadow(init_top_pgt);
>   }
> @@ -369,6 +377,8 @@ void __init kasan_init(void)
>   				__pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
>   	}
>   
> +	xen_pv_kasan_pin_pgd(early_top_pgt);

Same here (and below). For the pin/unpin variants I'd rather have
an inline wrapper containing the "if (xen_pv_domain())" in xen-ops.h
which can easily contain the needed #ifdef CONFIG_XEN_PV.


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0c968669-2b21-b772-dba8-f674057bd6e7%40suse.com.
