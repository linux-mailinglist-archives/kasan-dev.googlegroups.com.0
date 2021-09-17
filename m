Return-Path: <kasan-dev+bncBCRKFI7J2AJRBNMFSGFAMGQEII2CHNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C63A40F32C
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 09:24:38 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id c2-20020a63d5020000b029023ae853b72csf7293243pgg.18
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 00:24:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631863477; cv=pass;
        d=google.com; s=arc-20160816;
        b=EYOEiKWOUCOhqMXt0tof2bhYBdRwuDXuysifuKVXKWX7zTTsMN11g8bepuClkwv0/o
         M1H9FGmSrAQqp1hcLxYpXf7vvXyMYeobUF9ZyhblI4qCddwS8eWRVT7zthmMo7PRiyGA
         UYfZg9w6Omug+PSlMPDQ4V9h5dRCLWxl3eAnteMddg4wRe3BeeGhfYgLz9hpLPQNmEKU
         tTyxHGSVqONSJXtQUXM3o0lPKqJ6uLpNXNEXE2saUj/hMVbkubGXD/MU8Cv7HvmgFYoC
         YYODlf2XKqEo6nv4x6CvyNE/T8GprsJx9F0T2C3atMci8k5JXsPAA68VWniKd8//u0fx
         PCyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=MVE6LBsQndyp1OrkGZN6yboMBhOn92jmqfkwVQnyUWI=;
        b=iUXsL67gK3V0Vj6xdupiadEzynumQi87I+fQKU6xZl/fn9X0F9xIek6j6VG5NsvAKc
         zYbMOihrJHLgmvWK1+R28zYZisAoNIyUwJy0tgjnzPrm7JuJRNUGBtRp7SvFPLKMBAzE
         bjFyC6Go5HoQIiDTAQTtkqLTC2wkQRhDSTXr0LHQFefwV/WexfQsWZClw3edi9taZA7H
         +RYw6al6f8D2UkmyaQ4UaD7YdtJUGYv3rhyXtxEDCFyqCqe+O4i7aRXLZkNi7zhUbS7z
         cuOst1IRjHRoeuHJHhve4nVl3TFyWiKz+6EnSd+xY3wZzrR+vhXG05x8P4UNs2POKTSY
         D2Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MVE6LBsQndyp1OrkGZN6yboMBhOn92jmqfkwVQnyUWI=;
        b=UQrF0IXOk7HAMJDoz8pzG0wS38NWHOxsh3ait18F2Hae+XH0JhnyzvM+jvvRnIMnN/
         FopkQem/PBd9LGKWpFydo3Qsvm43UI53wGqpYAO2HjbLSLJZ1NfH1kUa6Gk0PgArZXYT
         36CEJ4vo2mCFSDFpUSzKhpZ9qmakhy+9ZsvrdPlKjANyZrQAlV3x5ln+DxIeE8OVZmDc
         ixZi8+ZJLTJjRgq25vBWWF3s1zwA6oSCVSx9qCg1nZjYkZQa2l5QsFjMdlKP/ehC5YbF
         jluwRnMzIkfmF+3EEUTCHoukPkPQS2YnLo9bmNfXJVTMNLFHYudf+OVY2Bm5YSDKWiOY
         DKew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MVE6LBsQndyp1OrkGZN6yboMBhOn92jmqfkwVQnyUWI=;
        b=0hAoe9o12Y0ne3K7qAVdG9hi8g6sTB6tXjmS74nYDtpz7NrEErYZxy1l4yJ3l6eMxz
         8eM5bX9mhoEQG9MFwNu+lH2yCvKopMw9vrEqktgzS6mlcZDy2wIBSqdEaxkJb6X4Mqea
         +xpaQHUEPtadl64LrSYmk0Fu8QJJp5Y1B8GTgUc6aFS28tyqCu1HyqEGKT/d8WIjMJOH
         +DazzwKu286hzRmnm5Xw5ihwWxL5OU08yzAGg+PlSiDgkDTTBbNNW3cYcf8AwskdR78+
         fJ+9BrVIKy5cLNtW/VoWMrOd4IRbvNiH5yX5GsNcrog4a43h7z+oZYU30TfaN7zFxhNi
         SgNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AQYXqyZDjC9DIw8txwEVEtVFdhjmJ0CuEvXygaQhuxiToqJce
	iL04zuq2y8Jaonmq+lk2rSA=
X-Google-Smtp-Source: ABdhPJxfXSXU8E3eufIzYpOdSpBxgbqEX+rWaq6xFUwz1QgFYGwValNO+8rn9sTTS3i6C+b6DUdE4w==
X-Received: by 2002:a17:90a:7d11:: with SMTP id g17mr10962525pjl.150.1631863477284;
        Fri, 17 Sep 2021 00:24:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:41c5:: with SMTP id b5ls2647573pgq.11.gmail; Fri, 17 Sep
 2021 00:24:36 -0700 (PDT)
X-Received: by 2002:a62:3287:0:b0:439:bfec:8374 with SMTP id y129-20020a623287000000b00439bfec8374mr9375725pfy.15.1631863476702;
        Fri, 17 Sep 2021 00:24:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631863476; cv=none;
        d=google.com; s=arc-20160816;
        b=R1p3eAZ+lsLXopjtaecAUqSi+A2q4CGf3r6adU3b6zJFUB+QMoAdl6Vw46/AoPi1bk
         fr6gc1aXOkYVQ13uKbbV6or5rlRO0IU7ann30y48Dth9vTiuIdlETYlQL2MyzBhuWijT
         9v02+q9/eEZyrk41Uqj/v80nxIq5m539XgqY9CCnCeUZML37N4ve1kGr2GvvOWr5ityS
         5jRJE2IRqpG1QxBxVrZlVf6wC5Ih1nbjC2svYst2WTt4+5RqblKD6k9v3eAdM/yt3IJB
         bH8E3MICHxLFpbdyS45AJ+/RFjLXdqS421SOqdjT5SAW4mk86Agxpu4LipBn175NHLs9
         3BZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PYCUEd2Zl61ZEgfeYO60hCtJyP9NA6PGleL+22oLO8I=;
        b=UL/LOoyitLtJKcissHPoamweNdERvXesqo8hVhRotrwBhkOOFdXGXyasye84yFFwbj
         PRE/fTYGirrRLQU2t+LjfYgMC//gSLOue1kDeV56Sgo4NOHoJeJBPj03xLc7wtxiIlMO
         7L0HHA+z4ixUihzgifrXYdxrfAOhhmwI/cnhkpSr3Jy+kGSMi865vfvd+C9urfYw9I0k
         wj7mowlaZergtVc+5TmG3vvOaO4EbKUvIWcNMLcKGfRc2XkYPyP6PZStQ1tGBH7qh/0Y
         NUUxsd52EEf4RwiWqJkFCKlbnNvDJOnoUh0RJvST1HbnobK1lxVYyAHNCoHLCGo/qBIM
         xgiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id r14si801093pgv.3.2021.09.17.00.24.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Sep 2021 00:24:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4H9ln74vYMz8tF8;
	Fri, 17 Sep 2021 15:23:55 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 17 Sep 2021 15:24:32 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 17 Sep 2021 15:24:32 +0800
Subject: Re: [PATCH v4 2/3] arm64: Support page mapping percpu first chunk
 allocator
To: Greg KH <gregkh@linuxfoundation.org>
CC: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<kasan-dev@googlegroups.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <20210910053354.26721-3-wangkefeng.wang@huawei.com>
 <YUQ0lvldA+wGpr0G@kroah.com>
 <9b2e89c4-a821-8657-0ffb-d822aa51936c@huawei.com>
 <YUQ95HuATcgtOgsy@kroah.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <dd6fb4f3-8baa-58b0-d4e9-6852acc82dcf@huawei.com>
Date: Fri, 17 Sep 2021 15:24:31 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <YUQ95HuATcgtOgsy@kroah.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
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


On 2021/9/17 15:04, Greg KH wrote:
> On Fri, Sep 17, 2021 at 02:55:18PM +0800, Kefeng Wang wrote:
>> On 2021/9/17 14:24, Greg KH wrote:
>>> On Fri, Sep 10, 2021 at 01:33:53PM +0800, Kefeng Wang wrote:
>>>> Percpu embedded first chunk allocator is the firstly option, but it
>>>> could fails on ARM64, eg,
>>>>     "percpu: max_distance=3D0x5fcfdc640000 too large for vmalloc space=
 0x781fefff0000"
>>>>     "percpu: max_distance=3D0x600000540000 too large for vmalloc space=
 0x7dffb7ff0000"
>>>>     "percpu: max_distance=3D0x5fff9adb0000 too large for vmalloc space=
 0x5dffb7ff0000"
>>>> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_g=
et_vm_areas+0x488/0x838",
>>>> even the system could not boot successfully.
>>>>
>>>> Let's implement page mapping percpu first chunk allocator as a fallbac=
k
>>>> to the embedding allocator to increase the robustness of the system.
>>>>
>>>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>>>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>>>> ---
>>>>    arch/arm64/Kconfig       |  4 ++
>>>>    drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++--=
---
>>>>    2 files changed, 76 insertions(+), 10 deletions(-)
>>>>
>>>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>>>> index 077f2ec4eeb2..04cfe1b4e98b 100644
>>>> --- a/arch/arm64/Kconfig
>>>> +++ b/arch/arm64/Kconfig
>>>> @@ -1042,6 +1042,10 @@ config NEED_PER_CPU_EMBED_FIRST_CHUNK
>>>>    	def_bool y
>>>>    	depends on NUMA
>>>> +config NEED_PER_CPU_PAGE_FIRST_CHUNK
>>>> +	def_bool y
>>>> +	depends on NUMA
>>> Why is this a config option at all?
>> The config is introduced from
>>
>> commit 08fc45806103e59a37418e84719b878f9bb32540
>> Author: Tejun Heo <tj@kernel.org>
>> Date:=C2=A0=C2=A0 Fri Aug 14 15:00:49 2009 +0900
>>
>>  =C2=A0=C2=A0=C2=A0 percpu: build first chunk allocators selectively
>>
>>  =C2=A0=C2=A0=C2=A0 There's no need to build unused first chunk allocato=
rs in. Define
>>  =C2=A0=C2=A0=C2=A0 CONFIG_NEED_PER_CPU_*_FIRST_CHUNK and let archs enab=
le them
>>  =C2=A0=C2=A0=C2=A0 selectively.
>>
>> For now, there are three ARCHs support both PER_CPU_EMBED_FIRST_CHUNK
>>
>> and PER_CPU_PAGE_FIRST_CHUNK.
>>
>>  =C2=A0 arch/powerpc/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK
>>  =C2=A0 arch/sparc/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK
>>  =C2=A0 arch/x86/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK
>>
>> and we have a cmdline to choose a alloctor.
>>
>>  =C2=A0=C2=A0 percpu_alloc=3D=C2=A0=C2=A0 Select which percpu first chun=
k allocator to use.
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Currently supported values are "emb=
ed" and "page".
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Archs may support subset or none of=
 the selections.
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 See comments in mm/percpu.c for det=
ails on each
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 allocator.=C2=A0 This parameter is =
primarily for debugging
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 and performance comparison.
>>
>> embed percpu first chunk allocator is the first choice, but it could fai=
ls
>> due to some
>>
>> memory layout(it does occurs on ARM64 too.), so page mapping percpu firs=
t
>> chunk
>>
>> allocator is as a fallback, that is what this patch does.
>>
>>>> +
>>>>    source "kernel/Kconfig.hz"
>>>>    config ARCH_SPARSEMEM_ENABLE
>>>> diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
>>>> index 46c503486e96..995dca9f3254 100644
>>>> --- a/drivers/base/arch_numa.c
>>>> +++ b/drivers/base/arch_numa.c
>>>> @@ -14,6 +14,7 @@
>>>>    #include <linux/of.h>
>>>>    #include <asm/sections.h>
>>>> +#include <asm/pgalloc.h>
>>>>    struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;
>>>>    EXPORT_SYMBOL(node_data);
>>>> @@ -168,22 +169,83 @@ static void __init pcpu_fc_free(void *ptr, size_=
t size)
>>>>    	memblock_free_early(__pa(ptr), size);
>>>>    }
>>>> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
>>> Ick, no #ifdef in .c files if at all possible please.
>> The drivers/base/arch_numa.c is shared by RISCV/ARM64, so I add this con=
fig
>> to
>>
>> no need to build this part on RISCV.
> Ok, then you need to get reviews from the mm people as I know nothing
> about this at all, sorry.  This file ended up in drivers/base/ for some
> reason to make it easier for others to use cross-arches, not that it had
> much to do with the driver core :(

Ok, I has Cc'ed Andrew and mm list ;)

Hi Catalin and Will, this patchset is mostly changed for arm64,

and the change itself=C2=A0 is not too big,=C2=A0 could you pick it up from=
 arm64

tree if there are no more comments,=C2=A0 many thanks.

>
> thanks,
>
> greg k-h
> .
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/dd6fb4f3-8baa-58b0-d4e9-6852acc82dcf%40huawei.com.
