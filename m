Return-Path: <kasan-dev+bncBCRKFI7J2AJRB5VY6SQAMGQEC6Y5IMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 020DD6C7657
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Mar 2023 04:43:52 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id p19-20020ac87413000000b003d2753047cbsf303346qtq.19
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Mar 2023 20:43:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679629430; cv=pass;
        d=google.com; s=arc-20160816;
        b=KZ994OEB3o+sO6o4ivUZ65l4apkJKduBcH6c4vCs/Ro6aCVjUnOfpj1LRy0uur8KLi
         kU1TihoN6L3VpX+h9rDzorR9e9QpAJ6OEXwoIeJKLxH3dwfHwMhlthGNIwZo4546y106
         9JtPrAHkLL6htuFUvD98LSwbSrIgie256c+pfdSRFBt2jlIZmdRizcpxG8zeDnNGggW2
         i4z3xNfsK7uHfcrvMynBm7fKkbjrTwPejIx+VYjzGZWIa9ZSEFnloZXimTxKLxjd4+Rk
         yy8XRMIWvrPTuDoMoBaWMBkXv9ZW5sCkRTUqmJpJd77T++65hXcr+9jQBk+zT1qp/Iva
         5kAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=tPANb6jWmIBvZw9QCp1tOB9Ae3motzoDTXY78Pecob0=;
        b=hQ9DbJ8nkS+Kmx4HPGi1QMJ7naUD3kn1xQHvA0CVudn/FRN5y2xFuRLghZMo3mCZyw
         bfd1ZwgraHQ+WJ1DtHW0fu50liDijsojcCE3qmnUwpU2A6Ygnk0KE64rhErqmbzOTO6D
         lhTEFTyRlO/w473N59uaWfO2ZQgkvcTvbwFK53lhbrn4TnZihgRSDrr0Fq7n4Xsqi69q
         qyUU3vuWGzXyDJ8Tge0ZXn0vzIw4W4fjWo5azXKboxjKGIPiG94szp70pi3lGW9nf7OD
         HOI2n0SBqaJ24FX9h3xBJIU46IBWGptXa9gUK9ggMILFtjHZZKGMstGt0O/sKDd8UeqN
         O3Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679629430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tPANb6jWmIBvZw9QCp1tOB9Ae3motzoDTXY78Pecob0=;
        b=bABKDP+BDWvutPa0Bnvvv+IE3i9lOvDeL/NPDDZe96g7LfSY0jxYCQLI/V99tgj5+J
         abF+1D90ljopp37fe2RU8A91BFMITu8bncMmrRYEI/Fv2EfX+vTm6whQUwSze9xhHDni
         GiUtNALbvlZEgpfl+9fMvffE15vNJK3g+AUeMzA++8wAAswz1r16qeh7uLKBC7d1RoX9
         iuYnOfdcEEdfguPlA226NsKcCzvh89Jzn2/fBORZMTHwo8o0ylJQIY+zbq47FUIYlUfw
         +nazqFFyA5MyFXDk3Tu/36LJJSRx1jnC/544l8vXkyF4IGLQgJySAgqZ6EilCRZK+4ZS
         mHEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679629430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tPANb6jWmIBvZw9QCp1tOB9Ae3motzoDTXY78Pecob0=;
        b=RJ8C1D2paxsWs7S6GUDSnd95y1gl/Fi4nL2WTWEv3NSwB3PL+Mm+0ogL1fVIgV0/AX
         fo8Cn7K6FwhWjgT+0izIi+P+IpvZ0O03PSFSvCsBplGkHEMV+Q7+vv/4Teh46RSP0U5p
         LRBj5sydHQtLAdmmkmXCoVjh/L/OtMXV061nybyYLswPOOJ/bjfsdjhcjdnuxiCuw9uZ
         JjcCYVFNTLSHG5hsGWKWmFpt0+7KGHTPQ3VPvAEcbhrsxuqKvPyIKJvVOWH88UoJJjDH
         ud+mGjtb1mg2lDpoLhwIR57sQnQUfSOaEVHR5jepbKriXdNbkUBdwkW+Ba5W+n82xUk/
         vAIQ==
X-Gm-Message-State: AO0yUKXniqoKncDhFIkKUl1y3ZTvIL85Cr0VHGJraADlNlUfZxyUUaUl
	kxgXVG/0tXgEQ6rHU9WaJEw=
X-Google-Smtp-Source: AK7set+Eni5HD3wrL6OGp8roJ9ts6msPnwvGYnwNuxNmtPFTDt88MvQCxkGi15L3ghFXhjeQf4S0uA==
X-Received: by 2002:a05:620a:f01:b0:746:8ebd:f6f5 with SMTP id v1-20020a05620a0f0100b007468ebdf6f5mr364490qkl.6.1679629430560;
        Thu, 23 Mar 2023 20:43:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:5a87:b0:3e4:8ca5:a210 with SMTP id
 fz7-20020a05622a5a8700b003e48ca5a210ls644903qtb.7.-pod-prod-gmail; Thu, 23
 Mar 2023 20:43:50 -0700 (PDT)
X-Received: by 2002:a05:622a:511:b0:3e1:1fe2:c6b1 with SMTP id l17-20020a05622a051100b003e11fe2c6b1mr2624705qtx.50.1679629430076;
        Thu, 23 Mar 2023 20:43:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679629430; cv=none;
        d=google.com; s=arc-20160816;
        b=A+YTD3mrNOkdCfQwldsJ/J3Wk9V6TnPEkL1qeFLLYAWOV2wuOZFijWJXL20XKLhYfW
         r2hGy60WhlFHZ0y8Lf8bD21j40HyUOlSGpQhSb6BgcQQnLrzCm2SZc8C7ClpZ54fsP4Y
         kGI3xVTpH2CHOH0f7dCxqMITxUvL3bv9sgSq9JZ7OIhEIgljvJOY68qzNzj05WdvW3oS
         xjXr/YZ+uPJZqhp/qnqjFAQZSFejqOv/P9IUlJzzEzHSH+9yd+PcCKQR6TQVYv4fkSu9
         9YHf/Ik6gQVFU3ydONTZBiTpCKGbM9L94r5ZdIYc2VDgLUg0G9GEjLKJRfUjTmO3s8hh
         bacg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=KK3VfphL9l3VIadEUlJuZiUfD9SetqZMav1K56yPxYo=;
        b=Qmgx4UFVG3fplN7ru46fd5HqjFxSJIRzvnL4AyhNLhuDcHc4EfXZDWVsPk22aEQA89
         QK1Y2VOV01OxGPcjKsjdaFm2mTVChOQhaW1wNXf556D7W9pONAR0UyNK4GFuJJpHcrwk
         P+7LU/gI9qgSCLDx/AcH804x1EiUYB92mTAL/CwmJCPs0WUb1wANHuRRzb0NHYg8LKNr
         gid6ACQzdzmlsfOr4waJF5ILFhgJmI9K+YFd9uacKeTQpMQPLLN+ou3nYjkGw9N4ZqRN
         fyJHhb3rLgzhM2X6LqXJn8Hp4Eq1wHdSqdf/HK2ojAUPQzai9GS1lXKHqcMx1vW9ffTw
         d5dA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id fc15-20020a05622a488f00b003e3876ed7c7si607652qtb.0.2023.03.23.20.43.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Mar 2023 20:43:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggpemm500001.china.huawei.com (unknown [172.30.72.54])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4PjSdh38bJz17Nrg;
	Fri, 24 Mar 2023 11:40:08 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.21; Fri, 24 Mar 2023 11:43:13 +0800
Message-ID: <15f4892c-e0dc-ff37-45a8-a1a025c2d929@huawei.com>
Date: Fri, 24 Mar 2023 11:43:12 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH] mm: kfence: fix handling discontiguous page
Content-Language: en-US
To: Muchun Song <songmuchun@bytedance.com>, <glider@google.com>,
	<elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
	<jannh@google.com>, <sjpark@amazon.de>, <muchun.song@linux.dev>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>
References: <20230323025003.94447-1-songmuchun@bytedance.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20230323025003.94447-1-songmuchun@bytedance.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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



On 2023/3/23 10:50, Muchun Song wrote:
> The struct pages could be discontiguous when the kfence pool is allocated
> via alloc_contig_pages() with CONFIG_SPARSEMEM and !CONFIG_SPARSEMEM_VMEMMAP.
> So, the iteration should use nth_page().
> 

Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>

> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> ---
>   mm/kfence/core.c | 4 ++--
>   1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index d66092dd187c..1065e0568d05 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -556,7 +556,7 @@ static unsigned long kfence_init_pool(void)
>   	 * enters __slab_free() slow-path.
>   	 */
>   	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -		struct slab *slab = page_slab(&pages[i]);
> +		struct slab *slab = page_slab(nth_page(pages, i));
>   
>   		if (!i || (i % 2))
>   			continue;
> @@ -602,7 +602,7 @@ static unsigned long kfence_init_pool(void)
>   
>   reset_slab:
>   	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -		struct slab *slab = page_slab(&pages[i]);
> +		struct slab *slab = page_slab(nth_page(pages, i));
>   
>   		if (!i || (i % 2))
>   			continue;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/15f4892c-e0dc-ff37-45a8-a1a025c2d929%40huawei.com.
