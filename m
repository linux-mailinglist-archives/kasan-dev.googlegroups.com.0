Return-Path: <kasan-dev+bncBCRKFI7J2AJRBSPDTCFQMGQEKPTXZVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id ECEC042B1D5
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 03:09:30 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id p7-20020a056830318700b0054749cce9bcsf690587ots.18
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 18:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634087369; cv=pass;
        d=google.com; s=arc-20160816;
        b=gajd8hHjAXZzJfzALe5L0058EZ346dWcpYVQC8DdaQEMlE07UK7yrp7UYEFaNd4hOJ
         EU4tQHCmYSzeZ57tG3wJsN52gIreBoH7NNhJWRK2ZcIKzifv8w6fPm8AswQxADZ8/x2i
         xMC3H4tPcPnozVi5zHf9h82rblzNMy1FNjePOhfjH2aCoQ3hFIavbJ6SPHGWnKaPvhyB
         MDJEPm1JI6s8/klE1+qwJyhin4ID6ewFBIA2VHU9VceHTGeHlBmlHgVU4vuFnLnhEhJe
         iV9KUoFuhGs1DY96X3VQps4FD4eH99v2lwk+aCieUbCYnjlgEmf3oCbcE7YOt/jwvl6x
         cNXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=u0mtZDciDcSHewq+bKFMlGjNwfbMJ3TYx5K+7zbrEUg=;
        b=U8jHwNXdKN7KNbtAvoIzRyMRA5S1hTyKyKi2ByehqlaPvedchvHn9fC+5epPJnAz3t
         mHMkXyNgZAIYz9lJmwva5TsFAl0dgcddbaRxskILuoDjVJQwUycjuyFNxclwBtHV1RWk
         epWixtP20yhghqpM7E5uFi81BYM1KQXsSZdCM8Jo0fPiDDSM6ShzdmB7E+BnaBou388o
         PqmTZhW5RNZOIUKKa1vNoqZ50uhwsUYmIZfdmprljGedyUNgs4h9R2Tzkpd1UGHEwyLv
         7yWHpm4A2x8R4urLsnQN9P8CBkWdTGD+R7va93Yup1s5//SxSqB0cGO2VKJr8wncCqoR
         vyzw==
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
        bh=u0mtZDciDcSHewq+bKFMlGjNwfbMJ3TYx5K+7zbrEUg=;
        b=MwbNy8+yBQkVv8RolIpvKtIRzokLbE7JXMp4XP7E+JHS7DL7W0gATMwhQUDH3TsiWb
         w4qk4Js6rjKkeuYkHky0SL4aBv1n15WDkcDMjq811sLbvBnrr+j1KXEIeu7malqWOk3o
         m0ufLqFoseJgkV6iQA7O2sfec8X02ovSx3trrun2w7Gbg4nfFPGyagRJriGhxHYfsIQQ
         63EdAH+RtZ88fnoNeL1gjIhxaqekjp8rxZ8NnzOnmbV+cp4+h2r6ITjaNO24TIZ5PtDo
         EkW5lQoNq+oZ1IAZzsw8WG059m54l8VLRn8qlgMtgaDJobF3mLdauXJgq0TJdr6d1trv
         O4dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u0mtZDciDcSHewq+bKFMlGjNwfbMJ3TYx5K+7zbrEUg=;
        b=s8egbXPs1LDEH98xfbWg5ygEihC9tqV0KUyxE6T/t0BcsqVE69dE7fHm8fiyIO2uOl
         BeLzyqS9VIM2w6CmtrzuNidmOHjWZ4Az5rkHmX9/jlKqgBMMq20o6BUtSZM8Xzi4KfZ3
         gLpCjinfui7usQSH5SBCG0+SHrWE+xWSYNLEBvvoMt1dTWRnePiZcr2uPVL9+W8RLZqu
         UH16lM5IW2DlzgAeRlbLYjDhftGtsw0uixX5z7Jt0aPWVxlMtfxMEBaklovzsNV/Jttl
         6nRAdnCI3/CfhRk2GCysoheAXahUfdmS31s7Oyzrs9J9mm7xCOlZCLQjf+BQZL1NnyZz
         RCaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nwwn8qZ+esdWse5Sd53ni0DM3SykYSLTpCmymorxBKQswVteu
	BZMdC6w0PH2FuAFrDmajr5Q=
X-Google-Smtp-Source: ABdhPJxjidXeLdRUAf80DNZptTKoe7ZU9qTKDtC3zD2D5pxcOHixA95mJij4MUJCwv+puioDXiJu9g==
X-Received: by 2002:a54:4d9e:: with SMTP id y30mr5965613oix.50.1634087369809;
        Tue, 12 Oct 2021 18:09:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2481:: with SMTP id u1ls206373ots.4.gmail; Tue, 12
 Oct 2021 18:09:29 -0700 (PDT)
X-Received: by 2002:a9d:7053:: with SMTP id x19mr13253311otj.276.1634087369481;
        Tue, 12 Oct 2021 18:09:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634087369; cv=none;
        d=google.com; s=arc-20160816;
        b=KspBFWeyzGuX50b/2bZ5oZC/N2h1vs1UvfW+Sj5rQeLDzIcK4PMIVYqWBcQCGwZxQR
         q90xNtm2m1ef4A/Wbqah9n2WOIl4KdSEU0ZEu8eu8BVtWigPX8TBfYYGK2jTBbf4Fbtk
         AwoLRYc0Rp4yIPKlwb+hWEq41FQ/4GE+4+xKO1EieJU9NZmesYByQoT++oA4W7domi4m
         pNCn5Vj+E+CaNMYt7HWuGqLQsD964ry1baHbAz/pN+LhFtDMMEj/BA9AxAW0Jr2YKAYE
         bV30kBmlodNQMqLHbv7F7hgiQpB+Gd6bKAdDRlKx9h3FYZ3RvYwiKSz/WAY4biJVFxQ/
         uusA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=TWt2whjQd/Y1LpA2iARMG4HA98271iEOouYEfEKn2Z8=;
        b=IiMNpbjGtVkaETVB1PnVE/9yA+gG8yrSEHcPRobJIeOpxZPQw6aCvNS3uHDbqZ2M1c
         Km2PW4TP0jXuO4wUNIrWxCFYefRlI30TRU4ExyKVvYRS7RE/40QTzIP8U2wGZ7zbffxD
         jefGsm4HtwFW+IbhBkXMCWNZuBpW36/YJi1D01dfAghaAGdoz+JyVDdXSzhzY/y6iDkL
         twSBTbp0b/4l84nxMsmWsnOzdTA1rhenhV/cpwkpq5X1hhHAUyRLDjsIzr3yPea/H5W8
         M9GO9lcN9+Y5Z8aUUDb01vajsuQPzjZrKplsZoPivoWn9H0tAfAAnasVXilUxoIgOdAe
         wqzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id v18si733881oie.5.2021.10.12.18.09.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Oct 2021 18:09:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HTZ7S3KlJz905l;
	Wed, 13 Oct 2021 09:04:36 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Wed, 13 Oct 2021 09:09:20 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.8; Wed, 13 Oct 2021 09:09:19 +0800
Message-ID: <a0106be4-2822-347f-dec6-7d43ce059e41@huawei.com>
Date: Wed, 13 Oct 2021 09:09:19 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.1.1
Subject: Re: [PATCH v4 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with
 KASAN_VMALLOC
Content-Language: en-US
To: Catalin Marinas <catalin.marinas@arm.com>
CC: <will@kernel.org>, <ryabinin.a.a@gmail.com>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>, <elver@google.com>,
	<akpm@linux-foundation.org>, <gregkh@linuxfoundation.org>,
	<kasan-dev@googlegroups.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <20210910053354.26721-4-wangkefeng.wang@huawei.com>
 <YWXRKFrGSkgLXNvt@arm.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
In-Reply-To: <YWXRKFrGSkgLXNvt@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme706-chm.china.huawei.com (10.1.199.102) To
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



On 2021/10/13 2:17, Catalin Marinas wrote:
> On Fri, Sep 10, 2021 at 01:33:54PM +0800, Kefeng Wang wrote:
>> With KASAN_VMALLOC and NEED_PER_CPU_PAGE_FIRST_CHUNK, it crashs,
>>
>> Unable to handle kernel paging request at virtual address ffff7000028f2000
>> ...
>> swapper pgtable: 64k pages, 48-bit VAs, pgdp=0000000042440000
>> [ffff7000028f2000] pgd=000000063e7c0003, p4d=000000063e7c0003, pud=000000063e7c0003, pmd=000000063e7b0003, pte=0000000000000000
>> Internal error: Oops: 96000007 [#1] PREEMPT SMP
>> Modules linked in:
>> CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.0-rc4-00003-gc6e6e28f3f30-dirty #62
>> Hardware name: linux,dummy-virt (DT)
>> pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO BTYPE=--)
>> pc : kasan_check_range+0x90/0x1a0
>> lr : memcpy+0x88/0xf4
>> sp : ffff80001378fe20
>> ...
>> Call trace:
>>   kasan_check_range+0x90/0x1a0
>>   pcpu_page_first_chunk+0x3f0/0x568
>>   setup_per_cpu_areas+0xb8/0x184
>>   start_kernel+0x8c/0x328
>>
>> The vm area used in vm_area_register_early() has no kasan shadow memory,
>> Let's add a new kasan_populate_early_vm_area_shadow() function to populate
>> the vm area shadow memory to fix the issue.
>>
>> Acked-by: Marco Elver <elver@google.com> (for KASAN parts)
>> Acked-by: Andrey Konovalov <andreyknvl@gmail.com> (for KASAN parts)
>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> 
> It looks like I only acked patch 2 previously, so here it is:
> 
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>

Many thanks, Catalin :)

> .
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0106be4-2822-347f-dec6-7d43ce059e41%40huawei.com.
