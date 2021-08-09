Return-Path: <kasan-dev+bncBCRKFI7J2AJRBCG6YSEAMGQEKAQQU3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F2BA3E46B9
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 15:35:12 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id t12-20020ab0688c0000b02902aa6d4f35a0sf3571030uar.13
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 06:35:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628516105; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICgVftyIqbs4QjzB1GuYvXHDf5DPykxKVMys1CCOybhPDJnlHFd+MOuJ7n8dHbyWdy
         fzodpEb9Cfc/fP6Jk177KuqaBXfIOdYdPdmqVKy/rFQGB44+B81yw2dJI7vvi47VI8zR
         8r6XjLQlE646z4CeLQfXxsHDSlfzzUIkSBmG2ZXM8WpMXgQNgA+nXaIwQ7hTp9oFAhGw
         81JuBILAle0zm1j1QUZls43OpO8Vu5F74Fi+gQZ5b3e9XO8Z59jdbeadVB9ExA58+rfi
         lk/lYtdT4QjQTur3E7f8C9wBSiF4oY2ne519jFwdZLcM3+6EKOZ+2QpfCWLht9rVEgqR
         CFOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=rFaFvtKWmaz34hnuM7bH6Dq2WSZpw6IHHA2s+2DWr8Q=;
        b=HsFdK+1HsE8AcEd5EVTvkfC/3vBMy7TK/rooiOcTD8vn+QCH4SlR/mihzpzY2jOX8W
         5XIPirI8EUdjp+kle4DKT5ij8gfuU/AAGjstdVEwy+SD6+dDCnJuTcnmqGYIJCqHk4RN
         TZmlf7Qi29AbycKC/JWAUmuwG5hK5RBBZjrUvlobPU8nBtRzDqmqK190KAoICKeLXlhV
         lW1eRORo7MbY4HDSm5CtGs6Z6cJwgzz0+Zqwh9yrXJ3qvQDZ637ltEcPUOlNjsKhhV4z
         kt6YrEV8/vXdMaRZ2wxHRfMdBIIXTqgq/JmKQPIjDHc+iX0BSZRXI4S3EsqOefLxrKv9
         CS4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rFaFvtKWmaz34hnuM7bH6Dq2WSZpw6IHHA2s+2DWr8Q=;
        b=QJ7VowAzMu+Lnt4Lz6CO7og98adxKcY9syDlmcl+cHT4Mh7JxPdqAsl6ALlPsqscN/
         /yu/7Cwu8jYPm0753pIYPMuNgltaoCsz4mW08yw7qepDJkm5Zr2Ej1P8EP4cfyhC650b
         nOfxkuE7Ya/g2gxTrOWzL2j135yKBhqckpo5kMnve7XUS+24lp+7qiHgAuOPWXTksTKT
         2/qE2FYo5Q8GuDqAmw3f1yzmZqNUdevmmid9X+/Xfm8V5emsnIXHkVCIClWn0O8cYndD
         /Sg9NdL5Um05GtIzb31mdWyZLBQqwgYVdJrKcMNWpqm1mUpVSU5fZ16jBA6O3egEOW0D
         7VGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rFaFvtKWmaz34hnuM7bH6Dq2WSZpw6IHHA2s+2DWr8Q=;
        b=aBVmfS5NuFE5074r85Ou4b5aOXNqEAENJ1pWdhcR3u7yoqHe4rNI5VDFYGYxqmulqV
         Lt/sGS9IQo5POPA7cTy6NGhfuITZ0fnNlgRlLEgvOCccHlIzpjznMoy6QlFyXnYsJCIB
         Oskkj3w4MYt/4WTxHqQ7ahBusl54xpfucAtqOlBIslUoKYZBDzEar9GOhJNop0pxecOX
         xdl/LlGDH7dMaX1QQqL0ge5Gvm+64w8WmCRGQVZgJDqZOqGYy3liW/RHOHKNFs+DFWQH
         ApPKvdIqXXdpv5VmTJVzcjcrX48xrTLcsTzUUup3vSwvAysq8QkM6M2ThpV8kUhHKLmc
         vFFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HmzrMW2k/dWoZvAuwNgEZW5Rt5IcIeNuwm0F+NkbAUR7ENBDD
	ySksXTu7PEYE2w09Z5nqTfY=
X-Google-Smtp-Source: ABdhPJxvwWvyvU4ZhDhbfPjL41nzD0T5ZvHfDHp+2ql5/Tu1e3WGRP1JCPHmnZuWuGqTeMOg7ZqOog==
X-Received: by 2002:a05:6102:3a64:: with SMTP id bf4mr357673vsb.34.1628516105087;
        Mon, 09 Aug 2021 06:35:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d51c:: with SMTP id l28ls44746vsj.3.gmail; Mon, 09 Aug
 2021 06:35:04 -0700 (PDT)
X-Received: by 2002:a05:6102:3c4:: with SMTP id n4mr2214027vsq.37.1628516104591;
        Mon, 09 Aug 2021 06:35:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628516104; cv=none;
        d=google.com; s=arc-20160816;
        b=OtuT0TNBIGvmySqX+BpM5Bxd2Mtb5AsIOiwpytOXCs3B5cnYjyINAVPof8Wgt1ytCq
         0ERX9mlPRk2X8jzdLYmCzTVrNDwq/Mays9+HTJhNkCtvuHqRpmPPf4BPoygtMOW7Ma7W
         KngsgFiHS35+DH0VLDCWaPvyotIje7djW6Ny66b84oJr20RmrQAkcexNlKCl4oWxpDFJ
         2ejJpC/rycxK6lcrb9r2kUxzR+XU450LrXOJMu4SFRwFHv5Z9nplFX5ampO/hqKKiJOS
         S89D1tyyRr8o4GnnJBZ5vG7k6YJQJOG2PzZWJMnJEKGMZOgqVESCWlHVXVF9Q5HYqJa0
         UZmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=G8XyvO3Ablvg7EiqmR8sJudEITFk6TS8djc+yncgCyc=;
        b=wvN9VqlwpBtqRGhYWRXdhPNRasNZfc3qriWRfwPi1HpiBvaQfljufinEotMPUHw5NP
         Bn83StgEBrgKq40QfNLbvIJ/de7nRxJwM7Qqw+FGUGWFNmzgqt0xEHNJFtjLE+q4trd3
         gsmdVajCDMsnEVSeJ9RgWRT3wjV5xxvGdacer2+3a4roUyGOSJeClkFhc2QZk3eEJt3/
         n3iXzp/Ou0ULG0P9HLPpsaPE2l2A4p7o8kQOY4VHp8p/VNVLc174n38G2eAX427WJHVN
         ntdkndMjxc7qtIK2wvnlimLNcjVehu1Lfgca0ladFdFR15EnH1dO1i1purpI/2/Jsrbp
         KGiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id m38si889204vkf.5.2021.08.09.06.35.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Aug 2021 06:35:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4Gjxs204Ybz1CTxx;
	Mon,  9 Aug 2021 21:34:46 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 21:34:58 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 21:34:57 +0800
Subject: Re: [PATCH v3 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with
 KASAN_VMALLOC
To: Marco Elver <elver@google.com>
CC: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
 <20210809093750.131091-4-wangkefeng.wang@huawei.com>
 <ae15c02e-d825-dbef-1419-5b5220f826c1@huawei.com>
 <CANpmjNOM-fzk2_q9LNLgM1wSReHWj42MxHBeDBLg8Ga5vv8HhQ@mail.gmail.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <03828e22-9869-7c57-3ad0-f266a435e427@huawei.com>
Date: Mon, 9 Aug 2021 21:34:57 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNOM-fzk2_q9LNLgM1wSReHWj42MxHBeDBLg8Ga5vv8HhQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
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


On 2021/8/9 19:21, Marco Elver wrote:
> On Mon, 9 Aug 2021 at 13:10, Kefeng Wang <wangkefeng.wang@huawei.com> wro=
te:
>>
>> On 2021/8/9 17:37, Kefeng Wang wrote:
>>> With KASAN_VMALLOC and NEED_PER_CPU_PAGE_FIRST_CHUNK, it crashs,
>>>
>>> Unable to handle kernel paging request at virtual address ffff7000028f2=
000
>>> ...
>>> swapper pgtable: 64k pages, 48-bit VAs, pgdp=3D0000000042440000
>>> [ffff7000028f2000] pgd=3D000000063e7c0003, p4d=3D000000063e7c0003, pud=
=3D000000063e7c0003, pmd=3D000000063e7b0003, pte=3D0000000000000000
>>> Internal error: Oops: 96000007 [#1] PREEMPT SMP
>>> Modules linked in:
>>> CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.0-rc4-00003-gc6e6e28f3f30-=
dirty #62
>>> Hardware name: linux,dummy-virt (DT)
>>> pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO BTYPE=3D--)
>>> pc : kasan_check_range+0x90/0x1a0
>>> lr : memcpy+0x88/0xf4
>>> sp : ffff80001378fe20
>>> ...
>>> Call trace:
>>>    kasan_check_range+0x90/0x1a0
>>>    pcpu_page_first_chunk+0x3f0/0x568
>>>    setup_per_cpu_areas+0xb8/0x184
>>>    start_kernel+0x8c/0x328
>>>
>>> The vm area used in vm_area_register_early() has no kasan shadow memory=
,
>>> Let's add a new kasan_populate_early_vm_area_shadow() function to popul=
ate
>>> the vm area shadow memory to fix the issue.
>> Should add Acked-by: Marco Elver <elver@google.com> [for KASAN parts] ,
> My Ack is still valid, thanks for noting.
Thanks,=C2=A0 Marco ;)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/03828e22-9869-7c57-3ad0-f266a435e427%40huawei.com.
