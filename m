Return-Path: <kasan-dev+bncBCRKFI7J2AJRBMUQRSEQMGQE7IJZLZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 98CC43F436C
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Aug 2021 04:30:11 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d23-20020aa78697000000b003e33ed83398sf5510766pfo.8
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Aug 2021 19:30:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629685810; cv=pass;
        d=google.com; s=arc-20160816;
        b=vLYvCepLTtnDMyl/6jW8Zm607klVSOLvfxwa2psyxBMsZW3cJELttUSB38MsWFjC2b
         u8n9IdGMf7JLhsc/gZpnGqmD4KwiRG2qaDi43UFaZW/i6NdlK5U5xcH04Ja39OmQHaQn
         aNXGbKqEX78hyxEnW42tTKaebHIzaje+5Nmq/qw4h3wIZz5lMqMagFy7yn0TIzSAviSz
         OqT9kELVJeSoO5KWnm31qsune8HBakwa4tLtLFmkdIg4C1rfYIP0kBz7QRCowwJ1EYAO
         ZB/6jcHP6W35U5rGB30iZySOjPXVUPflVUdnJxSG+UC2win3SdBZRYGEu8QPtxUDFL0z
         8hBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=WRObJ5Dv73941lsw6IwfYXUBWEgvkjLO4hyGihHgoX4=;
        b=kt79aMRg9uXBW7Wp/PLQ2A5XuVVJzkqOyO//3jipD1R5wr6hhpwKs1mvFt3v0Y5JcG
         Psseq6qGkgN1ykdUPgzZhuV2K2RJAYLgWnik0yM7XqI4sfVA6OqgpQDLWMf+iIar7xSQ
         c0dFX7fto5k/5WmZ3k1DzbvfI5h0xfYulZRZOftpKaqzXSytNez83w1wFU9hsWrYpyYr
         b9Jgn6kCMSO/S1gMB0rgOzgjSZKKQN27gvIuyFyWUc7zcHqhCBrpJnpY0L2/AaoYy9+Q
         b+fL/ETY10Bs0v5SrPqZtBWeDDjNwx1cPF0yKjYOkePpAKNhER6utOI+wDjzyBQo/z27
         0lWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WRObJ5Dv73941lsw6IwfYXUBWEgvkjLO4hyGihHgoX4=;
        b=rJKVbdpSTypi906jnsMj5KbiG0466fjlWbDIHpUdNbUvjoBFgEMG6YOYljYXCU5zbQ
         QTOU5X63CHuAhkSwRp2iGT43xMV1mnVJjSf5mitbhVwA4MnAD5Ey3Pu+4KsfCxlPJEXQ
         nsbjxXbySmmigN3pK8XsxyiOkbk8WT0CaGlrkQC2vywm8mOIEmWslGgY7btrLOxD0+vZ
         vbQTe9R2RSXP2+km/u47tLmYK757YZ+sbAJigXozDbrDLwD+cvqcDQraF9SC7pRdLlII
         C9SblN+8R+VoGZpIS6Xv3XxnaA/cLkg5fqMzVZ43420Mq2kufcx2kWKWrrFy6+nk0NEO
         RdpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WRObJ5Dv73941lsw6IwfYXUBWEgvkjLO4hyGihHgoX4=;
        b=gaHRpgH2hu7RY1w+hHV0h2H+T8iGUankuyiL76u0zF1lpbeW3oNzWjJM03lsqLPqDV
         lJaeZyRvbomgzW3Xd51YuCy3cfTuc+Geyeq7XWmKLLQEjX0rsNyOdJmd/nfgE8psLwSw
         kqlX+p+Fo5SB4wLdfQ66Wpk6BoUE43OqlQG4raAnMNfuayjY/3fFmPJYol2a/WnqIofv
         1lxtKh1Gls7aAHMoqqA7cA5BEzuTYuqe1J3XcbPAFdrbQ8+WHG8JVvHusCV7IXrQvIQI
         HTUMrOBqt/J92K7UAFfwWXUYADrAWNSDkzKEWbGLrsRXvN2k/5NXdqGQHfQl7gT0f6nL
         +d8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532v+w3hsfEkNE32eKpM0SYrWVUgLA3ZBnRgIkl2V3ME25abe+EO
	ROIC9cHZ6WhLFaH8NDdVCJM=
X-Google-Smtp-Source: ABdhPJx5DfueOl1mQTnEZdGelHFJNgXOyHVqfx6qvbT4KSSRvKFzdzcEzVjq+lLf0XjpJTWrqtDPig==
X-Received: by 2002:a17:902:ecc9:b0:12d:a202:76f4 with SMTP id a9-20020a170902ecc900b0012da20276f4mr26329177plh.34.1629685810313;
        Sun, 22 Aug 2021 19:30:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2345:: with SMTP id c5ls7645906plh.8.gmail; Sun, 22
 Aug 2021 19:30:09 -0700 (PDT)
X-Received: by 2002:a17:90a:4542:: with SMTP id r2mr17866884pjm.128.1629685809527;
        Sun, 22 Aug 2021 19:30:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629685809; cv=none;
        d=google.com; s=arc-20160816;
        b=AcmDquMcVL7dOgf2tdlzWjlELUmWTIT6rJjx1R0Qo5a0NSAEdMxzGB8zLdtv+RGlP6
         fP9SfPQdTUhvGmn32KWX6euvW12b37A8Nuyp2rkyutoUfC/yAcJmy8tdA965sA9OeqpH
         PGpYSKB4PGJ91ImdhYu1rMmUeXqDQT0fCQ0mRdNh41hf3/PTrm5CGUfCpjhsXW5U4Ebf
         bXRn4gczJZmve82hI4OKQcJTqhPCW2xRzkV9xHHFsKgoTMFqzA+JdFYtoobdJibzA4xk
         s/wk3JFRqkDkAORBj+j7B8gKE+o9kIb8lsJBHAGJIgh4DDWjiR3HEQmaqnvadB2qUJu8
         m9ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=WijtYuo0SxNB6zjgRDDVPuAC9zjwYpgUl0bMzfE/ewU=;
        b=nmYKoTn8TGta21uBxzsI48kiBsVOp+r4OAi1GhNKhyQZctei2fsL0jkIysT3ktaO8v
         WSEfidFDlv1X2hOtImprCj6CmiA6OjOlPCf7z1En9JjGRlQoPlJmHQk+445fJk0uC4us
         cl/Vicc52JhFHzdxRx0eaSfbqMAEvm/NAHTkZ7aXQHDVnfoFKVs3hzztY6KAvbywZVGK
         t78GOzTN2/9aKAtdCo1lap64/bHD08u83BgxeyG1tvxiJC5EiBu+gQdAF0NIzMBFEX4X
         yR4yoqMfBkQSQwYOTGXQm4K9IYr2tbVAqOkwdhTbX9RZhCAUjkrUH6iRD54rmQ0G5lnm
         jveg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id x124si787008pfc.5.2021.08.22.19.30.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 Aug 2021 19:30:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4GtGQp2j1wz8977;
	Mon, 23 Aug 2021 10:29:22 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 23 Aug 2021 10:29:33 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 23 Aug 2021 10:29:32 +0800
Subject: Re: [PATCH v3 0/3] arm64: support page mapping percpu first chunk
 allocator
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, <elver@google.com>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
 <9b75f4e5-a675-1227-0476-43fc21509086@huawei.com>
Message-ID: <7904a638-3ee2-381f-6dfb-3d011df42c40@huawei.com>
Date: Mon, 23 Aug 2021 10:29:32 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <9b75f4e5-a675-1227-0476-43fc21509086@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
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


On 2021/8/12 14:07, Kefeng Wang wrote:
> Hi Catalin and Will=EF=BC=8C
>
> The drivers/base/arch_numa.c is only shared by riscv and arm64,
>
> and the change from patch2 won't broke riscv.
>
> Could all patches be merged by arm64 tree? or any new comments?

Kindly ping...

>
> Many thanks.
>
> On 2021/8/9 17:37, Kefeng Wang wrote:
>> Percpu embedded first chunk allocator is the firstly option, but it
>> could fails on ARM64, eg,
>> =C2=A0=C2=A0 "percpu: max_distance=3D0x5fcfdc640000 too large for vmallo=
c space=20
>> 0x781fefff0000"
>> =C2=A0=C2=A0 "percpu: max_distance=3D0x600000540000 too large for vmallo=
c space=20
>> 0x7dffb7ff0000"
>> =C2=A0=C2=A0 "percpu: max_distance=3D0x5fff9adb0000 too large for vmallo=
c space=20
>> 0x5dffb7ff0000"
>>
>> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087=20
>> pcpu_get_vm_areas+0x488/0x838",
>> even the system could not boot successfully.
>>
>> Let's implement page mapping percpu first chunk allocator as a fallback
>> to the embedding allocator to increase the robustness of the system.
>>
>> Also fix a crash when both NEED_PER_CPU_PAGE_FIRST_CHUNK and=20
>> KASAN_VMALLOC enabled.
>>
>> Tested on ARM64 qemu with cmdline "percpu_alloc=3Dpage" based on=20
>> v5.14-rc5.
>>
>> v3:
>> - search for a range that fits instead of always picking the end from
>> =C2=A0=C2=A0 vmalloc area suggested by Catalin.
>> - use NUMA_NO_NODE to avoid "virt_to_phys used for non-linear address:"
>> =C2=A0=C2=A0 issue in arm64 kasan_populate_early_vm_area_shadow().
>> - add Acked-by: Marco Elver <elver@google.com> to patch v3
>>
>> V2:
>> - fix build error when CONFIG_KASAN disabled, found by lkp@intel.com
>> - drop wrong __weak comment from kasan_populate_early_vm_area_shadow(),
>> =C2=A0=C2=A0 found by Marco Elver <elver@google.com>
>>
>> Kefeng Wang (3):
>> =C2=A0=C2=A0 vmalloc: Choose a better start address in vm_area_register_=
early()
>> =C2=A0=C2=A0 arm64: Support page mapping percpu first chunk allocator
>> =C2=A0=C2=A0 kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VM=
ALLOC
>>
>> =C2=A0 arch/arm64/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 4 ++
>> =C2=A0 arch/arm64/mm/kasan_init.c | 16 ++++++++
>> =C2=A0 drivers/base/arch_numa.c=C2=A0=C2=A0 | 82 +++++++++++++++++++++++=
++++++++++-----
>> =C2=A0 include/linux/kasan.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 6 +++
>> =C2=A0 mm/kasan/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 |=C2=A0 5 +++
>> =C2=A0 mm/vmalloc.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 17 +++++---
>> =C2=A0 6 files changed, 115 insertions(+), 15 deletions(-)
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7904a638-3ee2-381f-6dfb-3d011df42c40%40huawei.com.
