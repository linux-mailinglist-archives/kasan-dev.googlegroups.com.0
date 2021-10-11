Return-Path: <kasan-dev+bncBCRKFI7J2AJRB4WYSCFQMGQELURTDVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A18DF428CF0
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 14:22:11 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id c4-20020a92b744000000b002592dabe954sf2724108ilm.8
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 05:22:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633954930; cv=pass;
        d=google.com; s=arc-20160816;
        b=V5mECLqZxmtdqbz9StlfgXgSm9556WGRB2oPY82kL0D3+prwYQAbcGnnSZhKnstBz7
         bmHcbB9mXwHQyaRNI8aKDGI8E+bej8IaWk497gnb+noCnetcCrkp+aVlFQCPc/zK6tyP
         wFzTeMvRtXexhwxNmB2n1q2nAXhmrXN+UUKjLRoTcP0GWokgSHiOusUhGQibKaJi+nBr
         /SjGq6rJSM3FsSGzYvXaKmSVFBsRvuirRk4xjB10QKU+W+nsFJbNThpIRMpsUegRaL1y
         j82pk39qMXBKWWqf5XOHIjjXQrCdQfjfz55xJ3oYViYLOYcnjhHb5oUTm3RR+G3NDtm2
         9yLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=/O8MWqdRJxtNsd1EuSELRBKMGIx/cNLwO4tVsTTijCE=;
        b=P1RdYCh115ECo+6y4W+swMfoLh+vRMftiwKUweq57VnPs2FOKGbqwUcnQCtmw9ifgt
         2gTFKAT93J1FfIQdDUVPwCAbd0J/Ztx+8Sx7xl4/vh+T9ljYg0JFBSUVuKYjzFijYPZ3
         JXP8dBFCr9WxgZxeWgQUWH5mxz2o4mpyMgC+dwzj5Z6N2T56HMpr75rixHVaUmXdUI2l
         i+JGcBJ0DVwBSvp6jsjbnqJilipmKHs+FDoUC5xyxnuRq2S46j/QPdsJ11GyH5iisGuV
         IqDyle7gfu6WdmiZRnBVrpg06WjQwCOVSNjQIYQXtfjAHc7rJdR8s9cDeNrvjRixwcX3
         47EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/O8MWqdRJxtNsd1EuSELRBKMGIx/cNLwO4tVsTTijCE=;
        b=t9AgZCf/IQrbmKYGrKPVA5g6Xom+S36i4AjM4c4ArdjjcM9bovm1HPjvFTwJEta/SA
         T0u5rtJ5pUd642RBkkz7dxtJyVjWPQRKJMrUJFzSh0P9LRIAHqPET3SWQZ1JAXI9xnt6
         ZD90XDEzJr7w8mZ+ZZKkOV+FxoKuX5AZwHV/uJXrKyjM5nTP2DVkkrprj/GlIza36O3Y
         PMo6/6BLFD5AY/yB0hZrY8xsDVJqeJAllhhOtZ/z9C+nflukEhSihJ2WA5lYH6fqxn86
         BmtjPjzra1WL1zzLbgUgZ0GGhkimx6CK8l5c1uiUCPmVaRvunpCoxOJnA3zS7PzHryar
         2HNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/O8MWqdRJxtNsd1EuSELRBKMGIx/cNLwO4tVsTTijCE=;
        b=bJsfTCgOWfM0JgfzeM3BV8OEXLk2N7ppmbGjvoEWkFsst/68Ffewf7SjoUblo44X4W
         yWQQq11r1RVmJDoxKySKc01uQaslT5W01kfaF+o21WaGC6/gCLsuLqCwEO2QsrSsGEvk
         r6sQ+szrWiTUg1N3KdghLuu6QZlHwWdMTaQOgU0VwJDcnAxsgIwlAGdlmLuZL5dKx6mv
         QSrdNx5Nu4mcQfgKL4rvxmxNO5XkpaRuJGqTQ33YgYXpvIxNh+5j9PnsENYvYPU/a512
         jg1df2BIA3ImL4FaP0HQEiPQpnZU1cU0kkEPg+FNcyWJiDreEN0MV8fsqKsuwVcTu2gc
         dgfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lYLR0d4e+a7EkC3YvxxUtCfSaAGK1hbhqzSjcA/1ZjajnfogM
	7G08WmIodrxwEGBIQCzfff4=
X-Google-Smtp-Source: ABdhPJy/pxXVLpEKKHZsK6Usvc2LoEJ/hgx7nUqN6RSEkAUG4Y4dyBjzt4eSRkiDB0jcHAiA4OajMQ==
X-Received: by 2002:a05:6e02:1a86:: with SMTP id k6mr19117182ilv.192.1633954930394;
        Mon, 11 Oct 2021 05:22:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7b03:: with SMTP id l3ls620992iop.5.gmail; Mon, 11 Oct
 2021 05:22:10 -0700 (PDT)
X-Received: by 2002:a05:6602:140d:: with SMTP id t13mr6006235iov.120.1633954930054;
        Mon, 11 Oct 2021 05:22:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633954930; cv=none;
        d=google.com; s=arc-20160816;
        b=WHnxvBhWLqe9YOF0u6C+CgKkuSwdpwmHbrfJWPSXqjcZItm57hh06NishkBny+ging
         ml5MO/wrL01wsGtm85NP3qdnKu2kWkimlQcY3bdzNioxAPg1MHu1UTQZZD1y7fzGgU9e
         sVSnU1IBJ/Y/54VgGWFqCZnXCmCs4W+mVy5b2/efhNgKHgl90OhqkGZgDVbIibwBVqOf
         Kthf6+TGFTqpL1J0jJwLpoROJtmYYoDxeb3Skzdu8UQ2M3agXIMiwfszh/gMvp4UcMfI
         7nF5HN25Eh3OTQlQYP5lDcLZRBdsvOmUkKuRYv8Nd5xvQIS9cNFtyaWBIZjtFtFnNiRp
         MBEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=iA0SHZX1gGZHbmmi5mE/pPb3XyW4EwqX4din08iIm0w=;
        b=OU4R/A+6E6McyfIhoTh51q6sysI7/gddf98+G5uJNLk/6ivqpawN3cbUgJoEaKtAB+
         uXo2OJjgMH7ilzkQMlsO2xiX4L3cHEEV6OD8yE5q5x9VkA0IXUCDfH+4yL+sbdOHOOfg
         f3hhe/Qp9/s47bCcgf+xkaDYGi9m63ZJeAXUda1q+Le64itjyk/CJ3d/8FRaOoXBnMS1
         AUxir/QOH7uBs8Hs/0bQua5HOM1HNGabpLuFPn2MYCr/Y+tGlsJjj8P4vLICNfLTkxES
         mtvMPTEGuOyGcdqgEyExgBd9u35eV+XwQn9zfE0DQmAWOr4jf3XpwL4S4aJdZ/Vx6YmZ
         Vrcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id h10si594504ilq.2.2021.10.11.05.22.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Oct 2021 05:22:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HSd8Z4KrBz8yVD;
	Mon, 11 Oct 2021 20:17:18 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Mon, 11 Oct 2021 20:22:07 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.8; Mon, 11 Oct 2021 20:22:06 +0800
Message-ID: <5077aa7e-0167-33b6-35f0-0ea7df8f2375@huawei.com>
Date: Mon, 11 Oct 2021 20:22:05 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.1.1
Subject: Re: [PATCH] mm: kasan: Fix redefinition of
 'kasan_populate_early_vm_area_shadow'
Content-Language: en-US
To: <naresh.kamboju@linaro.org>, Andrew Morton <akpm@linux-foundation.org>
CC: <andreyknvl@gmail.com>, <dvyukov@google.com>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-next@vger.kernel.org>, <ryabinin.a.a@gmail.com>,
	<sfr@canb.auug.org.au>, Linux Kernel Functional Testing <lkft@linaro.org>,
	Catalin Marinas <catalin.marinas@arm.com>
References: <CA+G9fYv1Vbc-Y_czipb-z1bG=9axE4R1BztKGqWz-yy=+Wcsqw@mail.gmail.com>
 <20211011123211.3936196-1-wangkefeng.wang@huawei.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
In-Reply-To: <20211011123211.3936196-1-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme714-chm.china.huawei.com (10.1.199.110) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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



On 2021/10/11 20:32, Kefeng Wang wrote:
> Move kasan_populate_early_vm_area_shadow() from mm/kasan/init.c to
> mm/kasan/shadow.c, make it under CONFIG_KASAN_VMALLOC to fix the
> redefinition issue.
> 
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
> Hi Andrew,
> Could you help to merge this into previos patch
>   "kasan: arm64: fix pcpu_page_first_chunk crash with KASAN_VMALLOC",
> sorry for the build error.

Correct Andrew's mail.

> 
>   mm/kasan/init.c   | 5 -----
>   mm/kasan/shadow.c | 5 +++++
>   2 files changed, 5 insertions(+), 5 deletions(-)
> 
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index d39577d088a1..cc64ed6858c6 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -279,11 +279,6 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>   	return 0;
>   }
>   
> -void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> -						       unsigned long size)
> -{
> -}
> -
>   static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
>   {
>   	pte_t *pte;
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 8d95ee52d019..4a4929b29a23 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -254,6 +254,11 @@ core_initcall(kasan_memhotplug_init);
>   
>   #ifdef CONFIG_KASAN_VMALLOC
>   
> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> +						       unsigned long size)
> +{
> +}
> +
>   static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>   				      void *unused)
>   {
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5077aa7e-0167-33b6-35f0-0ea7df8f2375%40huawei.com.
