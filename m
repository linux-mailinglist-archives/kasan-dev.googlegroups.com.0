Return-Path: <kasan-dev+bncBCRKFI7J2AJRBI4RQGFQMGQE7U5UB2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 35CF9426BB7
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 15:33:25 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id o6-20020a170902778600b0013c8ce59005sf4966813pll.2
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Oct 2021 06:33:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633700003; cv=pass;
        d=google.com; s=arc-20160816;
        b=z9CoTkahEtXkJ4e0f6nfUFKVFwXyvDWimuU9gBLa+qrsM8grnApEUz1qSj2Zw8T7DC
         Lo3lNkabb61B+gpKkc5BHVxzW8Z8HCQmZ/DAXRvWTN1hxJf8H7FpUynMUj+VK386gJlq
         lLlwKWahne3j4F7BOkSGaakTCPZibWmusvCdV3j8LUlOJcmp28pE++M2GPtwHPce/ya6
         i+WkOqiCxq44AAaQXwN4aPgT59hkGGAnTq2UkRtPuiEjvPGHogv+bzNbmpu4ZNR1/xGK
         GCDAdAPFWUUiuLLtafVXxEhDckxnog9tokVHELwSHKQmvaC6/v5bdE/Xbaej8TvMI9GF
         OhZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:references:cc:to:from:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=AyyYqe+Y7FKjzpDhpUQL2StCjCNTFROne6TLTpb/nsk=;
        b=z5PlV7P0rRljWYD/Dn/h18882v+b3K+3Fyykgly8rRKc4Hu4CLuev9r4HHJqI725Su
         biVELWEEDP3At/JtLzFatnoyg8tqqJUW9E79xR2JntpeTFTLCaTQaZ66jAQr2gx9l78S
         oBQASVLqGoe2amQpUczxTAvvpwRu+qSAdB+bF174D/jo2SrB61oDvfpe8Sx+imQ63Ywy
         3x0XDdlYlkL22MoHkocAikVdNsTxs8UWPMPhLOaItwyPIDlhizOo6EG4MeBoLpPKeeti
         iVsoABfjLt0u0gXVBcp0lMAqF+YY8x3IM+qKJc/JzSONKdGH7S++ZwasQO4W7kKxtDqD
         ioYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:from:to:cc:references:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AyyYqe+Y7FKjzpDhpUQL2StCjCNTFROne6TLTpb/nsk=;
        b=MzvaXHy4M1jf1/IG7+YAjjbvgtmSpunFtqm4OQ0eEspJYKtIw01UYaROkMC1FiYKs5
         JlXWKekZ2cCYCYfSxYxhhMOY4egxmFnDfqQfYihVv+n5x/cbplXB1RreHBg7OVTXJUXX
         pQ7lJz5FvUhkziyytH91KhnpkI7pzw5puhFXkMgPjjFNEmZluFOoiG4qfTi0ht5hhi2w
         F2CPP3UdICutwlLLRQmoqmsQoz/q0GTti542+zK5DDMAQXSoKFNzGWRBy/rPTjJ/56Ws
         wpHK9pl4JVD1gqx3H/1AnosG0EVcbFemeB6ylu6MZPD7dpDQifFg5aW+5ilDnGEcn1bN
         Wc3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:from:to:cc:references:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AyyYqe+Y7FKjzpDhpUQL2StCjCNTFROne6TLTpb/nsk=;
        b=eGcDTn925ByOsrDiaYnPa51tGAag4gBbE72O4eXAgA9472gjNf6IpBvHe1y53UR8E3
         Z51RJuR8Nlw9T1hWAgGWY7TQRu3FcW3zoGwVWLV8yVLVPKnWKvej9IqC2znNTrmTuSTa
         5gucXipvbZMK08oucxoW9FeEbwXNqQnoQbM/3UAYE8XvP8WqvbHHkzFKM6yjBh4A1gnR
         cCYg2RniZTTRpi1Gg8vZpUWIRldKwwcxh07qIoBBCrd8po9w+KCAwE6JNkoqyKehK63S
         HCIcZMz1OdoiU81cV7ADFQDeWJknGw8t7cLHjcpaXqjZq2uOw9zy5oj4VY3+p7g44okO
         9ttg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MT/tXHP98xqMWm8iUH5cMGjlPFIyVxaLt+dfNcBDOVM4bglea
	ucHzQdBNyO6Ro0snPT/hP9Q=
X-Google-Smtp-Source: ABdhPJweWDHZsWgKfcm+77wnybLvZh1N9hiROIkyBsJoh8Fji+kxj0Twr4MNn3UejMX3tLjaJzqeQQ==
X-Received: by 2002:a17:903:248f:b029:128:d5ea:18a7 with SMTP id p15-20020a170903248fb0290128d5ea18a7mr9497443plw.83.1633700003514;
        Fri, 08 Oct 2021 06:33:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2c2:: with SMTP id n2ls1837997plc.7.gmail; Fri, 08
 Oct 2021 06:33:23 -0700 (PDT)
X-Received: by 2002:a17:90a:4815:: with SMTP id a21mr11822712pjh.108.1633700002987;
        Fri, 08 Oct 2021 06:33:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633700002; cv=none;
        d=google.com; s=arc-20160816;
        b=qYmFpsFWVC3lLBzjv1nyG/LNANcabSnhkFWOAtvIx3GeMECTexR7UoX5N+hGAVhJ4U
         4SZZQgRbD/JbXVCdD6FhQVGrsz69I7DqdX+EkiMDK387fzfB4HAPdSLQ1gITqgwPumeS
         XnPUehX/YOzhRiMeUGK3vIAakNDogg7BIOI4iF4UaeljDtJdB80ooxB8a4CZu8H5azr0
         c5/KKHmlexP6ceDTLcv/nfLS/GC1uXUxkYVqn8pjfyuOWJKMzuwLbV5uAcqGCtji00wb
         XyW8Fb5NQF3noH1sPen9VojG+rzeEuPWnmbXnJ1S+Cer1NvmFmarPJd33cwOH+prSoY9
         5f5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=GHK3UNZ1k2vtyqR2A2i+z7ONFfQdKQVPoz0Eqk2WYo8=;
        b=cO6zUK/P3SeKrECW2LU/2y02kEWHsoUcFg82VNanFumPMxcTkLUXXCD+NBMKrALcam
         a2fWcNUa3FRHbKhB65QddqtTP4r9mNp+BOYeWniWMTSUxhXTuiJem0KcrEgda28k6PkR
         ykay3107oxpQ2SeMYnD02EfltZrpvnGI2l9Bo1Lo5YS9gUxQI+cZs+dRb5sIaIEiPugD
         1wpSFPzCJzo7qXeHVFs3wV6wcxHyhYZZJVyq5/w+AVYVoxX6hOEcnx7zPYMxn9SnTRv9
         xM3oQtwkKUdhZlPV3Z257lYEDRpviaDrb3Z2U4dmpqj80vlr89EA1P5Nw///kOLYAXJw
         Ixcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id p18si205621plr.1.2021.10.08.06.33.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Oct 2021 06:33:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4HQptb6nDpzbmq7;
	Fri,  8 Oct 2021 21:28:55 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 8 Oct 2021 21:33:20 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.8; Fri, 8 Oct 2021 21:33:19 +0800
Message-ID: <25c6cc97-f436-8966-9052-a1841f68e81a@huawei.com>
Date: Fri, 8 Oct 2021 21:33:18 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.1.1
Subject: Re: [PATCH v4 0/3] arm64: support page mapping percpu first chunk
 allocator
Content-Language: en-US
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<gregkh@linuxfoundation.org>
CC: <kasan-dev@googlegroups.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <5cd6631f-0bac-bd74-3369-1fa4a744687f@huawei.com>
In-Reply-To: <5cd6631f-0bac-bd74-3369-1fa4a744687f@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme709-chm.china.huawei.com (10.1.199.105) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
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



On 2021/9/28 15:48, Kefeng Wang wrote:
> Hi Catalin and Andrew, kindly ping again, any comments, thanks.

Looks no more comments, Catalin and Andrew, ping again, any one of you
could merge this patchset, many thanks.

>=20
> On 2021/9/10 13:33, Kefeng Wang wrote:
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
>> Tested on ARM64 qemu with cmdline "percpu_alloc=3Dpage" based on v5.14.
>>
>> V4:
>> - add ACK/RB
>> - address comments about patch1 from Catalin
>> - add Greg and Andrew into list suggested by Catalin
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
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 19 ++++++---
>> =C2=A0 6 files changed, 116 insertions(+), 16 deletions(-)
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/25c6cc97-f436-8966-9052-a1841f68e81a%40huawei.com.
