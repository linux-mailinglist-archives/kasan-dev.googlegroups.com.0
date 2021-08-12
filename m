Return-Path: <kasan-dev+bncBCRKFI7J2AJRBLHV2KEAMGQEB5I74BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EE973E9E42
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 08:07:42 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id a12-20020a17090aa50cb0290178fef5c227sf2709378pjq.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 23:07:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628748461; cv=pass;
        d=google.com; s=arc-20160816;
        b=OT9oIQGiixPHp1hv3VKVrSNOiiQsieaIHVJy2i1JUCXFwlngORMaLenVO4U7bl0/La
         Pe4DkCua5CG/n/Ky54nctCwvT1cKKQRLrY/7Ha4YbFmy7suRT/BwHxGwEULxxMuYNoUF
         yW8tXI9+UPcs28TpSC1Q2YXDdR64KQNtXgxgMsY/QFrw4Qhgo1fp3TJXyF8PT/rm+Y4c
         YTy2ILpXJJRdrEb32U2XfM+EE0UpMKkZnipwp0mUUx3xxM7nlCVrzVc6NqGSZRCT70Me
         TDakRYvT99ZtaqlrEHYjMu8flEgOUFs95kphEdeSbtuIfhCXmbWUiSjNZXuRzHVO43OE
         c3AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Pii4X4zC2VFHeCP77EUUxYLzu4C+KPcXMa+WZNAU7b0=;
        b=Qbfs7es/hywDT2DaQ4cQUUmF8wv+9Lp1G0F4rTyrpYNYnVKjmppRROOl/K7d9VE5Ri
         aJY59r7mB1i2o+ISLCUD0q2ylP7E+ZeziyhqP86bZKFUgNYZg/E7vkiuN24qU5N0c2/P
         DX1zkDknpqu9P2EOom2BfHal+A3pv3vllWlmo1SrpEKmrI5iTactwVWYvpzflqsstcBD
         YA0bcfZMXSWYmVfPJPErxaAyQoVxc5kZyB8edrElWYOdgHY/OrYxjdzXwt97J9y3SKp3
         Fpz1no2NPBXbcWz6CpyTUOgIhgQAAEPNpNCJJds4ov5Hb63hAAhRVZomYg+EFeJd4gqF
         RIGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pii4X4zC2VFHeCP77EUUxYLzu4C+KPcXMa+WZNAU7b0=;
        b=RyLPKF80NY5vFsfjNZORcLGc23DpBABHhr2+jL+xpNuCKIKJUeA6ei4M8JTKCP3Me+
         0PBRtB4ZIkc24fAkzEVUC4AG07B54jxBrms7BXMjxrbiWK+A0G6ZjNhhzoVaWch7dg4Y
         TGD51Ck6IyC4FNGvJtWRXYJx4FOjD5TOJ7k2PDFvE4GdBnPbhJW3NhstH0rTzNJOqg+2
         ykicd0F5h4PMK9HrAOgGfbm1HuemOETLhUveU4qwnW9/riiFMkmgmtSL2TQTAr4+KUVY
         Lr9EUspQcEHobZqP5IqVUdAZDSt4pfZRIFRnGoBr5OkfOCZToBPCDcn5p5/1rrDep4m8
         y/Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pii4X4zC2VFHeCP77EUUxYLzu4C+KPcXMa+WZNAU7b0=;
        b=eJYItVlQ4j3E7bayhf3m0oV2ofq+FqXpys8W4hrtviGi9OYvzNdpbr3drhjHSnhNNA
         NSa/5owxqvoGImzqrsv3+o3fAd335pvxWisXjvv1g+F21Mu3pQ5mgz3X7N0KKSxcx1R4
         iXLkGboYY8eSi07Cewu0JEWyQF9RV5rnRXaUFxHms9HE8icm+iJyjkyQLenUQCegAnwf
         UBA6xdx+lx1iuqrlSmsC6KQgnLNpzTKXxhVlMv8W7BxLh51ijZUxEF3JvghVDd25M/jn
         Ns7RavxIqMj5ofxgNh9ez5h+uLrdxF7GoGSl3Jyn4/Z5JbDETrcpILNlLP+bFc88z9nv
         WSnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309B+Yy4YJej4yX4ZyjFZhGzKJoBDvuaMPfuccwZaVaWqP8KH3d
	dC95h8Ayf3fCjlxBIpvoEkw=
X-Google-Smtp-Source: ABdhPJySFBV4OYAcftH8gd15Q69xyVlZ7pyfC6GFWbJhuqk+9tOEmw2XpeKbsq7/iQcMPoPk6zDhtw==
X-Received: by 2002:a05:6a00:84e:b029:3ae:5c9:a48d with SMTP id q14-20020a056a00084eb02903ae05c9a48dmr2634579pfk.20.1628748460943;
        Wed, 11 Aug 2021 23:07:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:600e:: with SMTP id y14ls2527698pji.3.gmail; Wed, 11
 Aug 2021 23:07:40 -0700 (PDT)
X-Received: by 2002:a17:902:7c93:b029:12c:b603:150d with SMTP id y19-20020a1709027c93b029012cb603150dmr2303160pll.5.1628748460312;
        Wed, 11 Aug 2021 23:07:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628748460; cv=none;
        d=google.com; s=arc-20160816;
        b=zUgFw7070ravNiBtNkebzqYJYXhuPhPqQYAZ7o4DMxTAbodPexoeo0VeC2WFIHl44+
         OLvRH0Nox3nwBxegLMl1mhb5LT2pTu4Aex+j9AgyrS2xRMIeKJRfja74R0rPxTeFtzOd
         3f3loYApWrKVytCVvuHmuczB1hPqNh0JdbWk/zCR8S6spEG9CPFljM4YNkC/15CYdsPr
         C8b2X5iHbaKj3xLyOice14HgSr1z4qA40vaKoTDU0rYM7qMNhqLrjjFX17mQa5lgK4Co
         E5xA9AmNji2bndM1wqkJZvKWUlSQ6EIxiBX1+ZI8GnVwkmHCai/IIuFRtaYVWzbXB45L
         PODQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=mvallon7wJAwbN8mLNmod2IYD1UK2Gf9RjVBRiCWEyc=;
        b=tvWiDbMmt6qE21Ofs9yOiP5JkHhRx8nSA+56Z9pgdHKzCC+OqM52+lDsSioRkvKuNg
         fxHF2pZ+JWFnUy8htHaEfguqf61bf65p13hPWg0AnK08oRPHGu6ui2VojvKoUyNhmvvl
         8F2MVqoeyUD9J6F8yOX9c+IljGObEdaPVeEFqf9sDAosqeXtK70BDHeGUUmRbmAkaJ6N
         dNh4mk321qy0eKJmY36YldRPoTtSwWyC9vsqU85odShnczLEv0x7ujZyw9xQx6fhJYAg
         6ZRHEF4XPrtc3aqY5xm078SrN+Q+EeZ5kTnvNBw0OkRKZSgNRiF/VtL9m3cAf0qtCe8z
         m7lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id m1si566212pjv.1.2021.08.11.23.07.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Aug 2021 23:07:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GlbnP6jhPzYnSs;
	Thu, 12 Aug 2021 14:07:21 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Thu, 12 Aug 2021 14:07:38 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Thu, 12 Aug 2021 14:07:37 +0800
Subject: Re: [PATCH v3 0/3] arm64: support page mapping percpu first chunk
 allocator
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, <elver@google.com>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <9b75f4e5-a675-1227-0476-43fc21509086@huawei.com>
Date: Thu, 12 Aug 2021 14:07:36 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
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

Hi Catalin and Will=EF=BC=8C

The drivers/base/arch_numa.c is only shared by riscv and arm64,

and the change from patch2 won't broke riscv.

Could all patches be merged by arm64 tree? or any new comments?

Many thanks.

On 2021/8/9 17:37, Kefeng Wang wrote:
> Percpu embedded first chunk allocator is the firstly option, but it
> could fails on ARM64, eg,
>    "percpu: max_distance=3D0x5fcfdc640000 too large for vmalloc space 0x7=
81fefff0000"
>    "percpu: max_distance=3D0x600000540000 too large for vmalloc space 0x7=
dffb7ff0000"
>    "percpu: max_distance=3D0x5fff9adb0000 too large for vmalloc space 0x5=
dffb7ff0000"
>
> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_=
vm_areas+0x488/0x838",
> even the system could not boot successfully.
>
> Let's implement page mapping percpu first chunk allocator as a fallback
> to the embedding allocator to increase the robustness of the system.
>
> Also fix a crash when both NEED_PER_CPU_PAGE_FIRST_CHUNK and KASAN_VMALLO=
C enabled.
>
> Tested on ARM64 qemu with cmdline "percpu_alloc=3Dpage" based on v5.14-rc=
5.
>
> v3:
> - search for a range that fits instead of always picking the end from
>    vmalloc area suggested by Catalin.
> - use NUMA_NO_NODE to avoid "virt_to_phys used for non-linear address:"
>    issue in arm64 kasan_populate_early_vm_area_shadow().
> - add Acked-by: Marco Elver <elver@google.com> to patch v3
>
> V2:
> - fix build error when CONFIG_KASAN disabled, found by lkp@intel.com
> - drop wrong __weak comment from kasan_populate_early_vm_area_shadow(),
>    found by Marco Elver <elver@google.com>
>
> Kefeng Wang (3):
>    vmalloc: Choose a better start address in vm_area_register_early()
>    arm64: Support page mapping percpu first chunk allocator
>    kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC
>
>   arch/arm64/Kconfig         |  4 ++
>   arch/arm64/mm/kasan_init.c | 16 ++++++++
>   drivers/base/arch_numa.c   | 82 +++++++++++++++++++++++++++++++++-----
>   include/linux/kasan.h      |  6 +++
>   mm/kasan/init.c            |  5 +++
>   mm/vmalloc.c               | 17 +++++---
>   6 files changed, 115 insertions(+), 15 deletions(-)
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9b75f4e5-a675-1227-0476-43fc21509086%40huawei.com.
