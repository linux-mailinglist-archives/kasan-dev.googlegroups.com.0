Return-Path: <kasan-dev+bncBCRKFI7J2AJRBF4SZOFAMGQEEJVPS5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id DAFFE41AA10
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 09:49:44 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id d16-20020a17090ab31000b0019ec685f551sf1636111pjr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 00:49:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632815383; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlBXGph0EVAiy36dS4iL8geqn89vmklwiSWtfiVrIZTACoFwdslznSO9E+1Foz/4qh
         lNhsD7+LXGHlhTyi8Vek2lSMlnUOtsbOYtI/3O19Lw2gU39sZSk/azoSTszVvYQtMY9J
         1wSSpVUj0/9VTwIkJNULj1eh3E4O45HT12MOR+Pc4FFt0pUv4PfDnCYI4xfyZyNwMUdn
         CqIH1/kSLkJWwQWcIZnZPn/Oq/9NhNQQFtPp44CSKGpBonvtYJp9hrU8bnCcB4inl/uY
         +KQOBiQriVm+j3SMQCFGlSCbb6+hronc6f9k/ArrfzqVX7T0c5Hg+TrefiHsJTXAoRZW
         Fm5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=zlqTGwT/+KP9EgZUV/7CzjwfDlqjvFzbYfMc1sly4II=;
        b=W8rNKi/sAZ7gKFClFyHQp2GEU6MLrz5mOaE/OTisIn+zsqO+Q0pHS0zwArED4cRIPP
         PlNCq5QEOV2lD4DEjma1LkMhJIqIfei8BcL9I/zKN53LIg71aESreJaM2K5LmF8tWAM7
         bzWS1ew+nxwDCm/S2XiTzuQdQsQUwvmbTamZivpK4leG4iyc4x26dydFPZRujgjas1EP
         7vqEJ2H5POwoF6gdRfM/DKH5C+H7KEiNpMEZ8pXp0kCb17NU6f3SUWOEnJkBiByPHPaF
         lD1ohDsSDWKgRARcpKkUaTdI0WqXbN1j7OMQ6s1kf+hB2vmWQF2emZxvN9C+CC9m0b5H
         RT6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zlqTGwT/+KP9EgZUV/7CzjwfDlqjvFzbYfMc1sly4II=;
        b=tmouH41zK3FHSxaG02Hf9GTfvwgDPkV6CgVkL3bv2ZKlGEY0vDx2jxSIkMTuAHjcuR
         M6H5QRhyCkT6VU1meYDyju6kqa4kiwsg3DdzQkoSqODzVmiIl02CmNGPI288yXLXHI41
         +bvR1oaRJqFldcZ7lpWR/DD99KK0jObhnRfSFfpfBmDhzi0S/DlTaqPAvI2+8/aS+IrN
         XORiVNY1DqOunXi9AVRlLS6/0Fw4r9lxCLviPK5aA9q0X7ihwT/w0AiaF+JEl/KbqxKE
         7LvFS/ZEPJQA5nn+8shAw09r6utu1WxtUZ10aynt9bWb8vESMVaM8abcUs3oRHsCYbyo
         3rsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zlqTGwT/+KP9EgZUV/7CzjwfDlqjvFzbYfMc1sly4II=;
        b=lEstikxGikGgaJ+NRi/ySEJDVgc+Tr96BNYJ/Zg5HRyCAHU8yJ1haCF1p0SBDbE52z
         rgPpN3vDKUB9gEN0wnnKcl+I2fOvckhuV6WdHs7ZfopM4mLgJJzy8pZi0LgREYLxK5tD
         8BrEyVyxPHhMnVZIftrr/jkLQyPE12IWjZlzmd+RgdZjs1JViHaPb5CWKKf9WgmfzwAY
         +8kdGz+/1Y4QoIBugWaa8wSsMdH0qtC5SWl6k2wSx6dzuZyhXa/5P9eh4wNh1OvFvY2u
         ReH8UAxncHIIrBXFtAtM0Dj3aKZLrWGMU/tFHfzgq+ewsMpOOp9yvpwA96biHJznhWXs
         ESaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sHaQlEApAJJQrF5914htwVhADHlvXzr0EDt0MVoObrmh1hYWu
	Dgy55YbF36jDBDFcGJugWXw=
X-Google-Smtp-Source: ABdhPJzdgKyRRprLF8W3eNOmVZ/Dy6vxEJU640ymOWGavEKGSfkp7gsUa0AQ9c66boA7I8TTTdPP8w==
X-Received: by 2002:a05:6a00:2410:b0:40e:7d8:ad7f with SMTP id z16-20020a056a00241000b0040e07d8ad7fmr4316675pfh.25.1632815383577;
        Tue, 28 Sep 2021 00:49:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b78f:: with SMTP id m15ls101617pjr.2.experimental-gmail;
 Tue, 28 Sep 2021 00:49:42 -0700 (PDT)
X-Received: by 2002:a17:902:c406:b0:13b:7b40:9c51 with SMTP id k6-20020a170902c40600b0013b7b409c51mr3827057plk.89.1632815382821;
        Tue, 28 Sep 2021 00:49:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632815382; cv=none;
        d=google.com; s=arc-20160816;
        b=CnDN8/2csn2/CJ69U1fPyGgyFUrqanoq+z30ofRQ7XAzVx1YfeGq/S2Q2uhJ6ff+Rg
         tDidW9ERgPL8qheP8KyMaRAMR+m5mRgiphsTnnhlKEVFQFE2csF1bWvgSnwsOniRf210
         S1U3HyxAVSarKfJzFa5Pk9Ptz6qi09rsBp/bSy+CV5sdmsQ1t9G1YVmVj8Po0YRrDrNj
         7RMYLYS0kdqRPgz3kVf26G3iV/5MuuIhmhWL9gq3NsID/5nFClzqGXzA/DKGUDyDrKuE
         19QGxlAwTqtOkEY9QD7TtMl0P7WCfo+3KjIAl/R6+N14ns/YKvwsorLhV9cXv8A6hva2
         9LLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=6Gj7ad3kuu9/Ao+gtwNrNGemPRWxk3S5aIkYC6gJaOU=;
        b=kYMEIw5q1hDZK4Ru1PweVEAHWzMnKrIldLqfgfbveTRkVQz6xeT0jYM1AgcHRq4Gwf
         bw49ZSPpm1EgDgiIXtNuEmzRsUpV16VOb5jK8UUgb+v9hmCz+e6PR0/xFV14Ro6hxs8+
         0ZCIYY4lvgC5m9SjcWI26WFPf+KV14ckIbb7+e4cigxRun+bAMK6+LUQMTQAN7a1yGQp
         xT6qvgy6syt4eWPx5t4d7+BXnMCyIo4kjm24u/fQo+PbifW/B+7VyxxRRPs9X8ighljq
         JE6g+pbUaZ/ntXbEUeXyJ1jREXj/A/DcZJL7johG47lhvz3QpMfzBsPMylUktmT4Gu35
         fH4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id r7si298060pjp.0.2021.09.28.00.49.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Sep 2021 00:49:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4HJWpC334Dz8tVx;
	Tue, 28 Sep 2021 15:48:19 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 15:48:58 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 15:48:58 +0800
Message-ID: <5cd6631f-0bac-bd74-3369-1fa4a744687f@huawei.com>
Date: Tue, 28 Sep 2021 15:48:57 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.1.1
Subject: Re: [PATCH v4 0/3] arm64: support page mapping percpu first chunk
 allocator
Content-Language: en-US
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<gregkh@linuxfoundation.org>
CC: <kasan-dev@googlegroups.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
In-Reply-To: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme714-chm.china.huawei.com (10.1.199.110) To
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

Hi Catalin and Andrew, kindly ping again, any comments, thanks.

On 2021/9/10 13:33, Kefeng Wang wrote:
> Percpu embedded first chunk allocator is the firstly option, but it
> could fails on ARM64, eg,
>    "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
>    "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
>    "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"
> 
> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
> even the system could not boot successfully.
> 
> Let's implement page mapping percpu first chunk allocator as a fallback
> to the embedding allocator to increase the robustness of the system.
> 
> Also fix a crash when both NEED_PER_CPU_PAGE_FIRST_CHUNK and KASAN_VMALLOC enabled.
> 
> Tested on ARM64 qemu with cmdline "percpu_alloc=page" based on v5.14.
> 
> V4:
> - add ACK/RB
> - address comments about patch1 from Catalin
> - add Greg and Andrew into list suggested by Catalin
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
>   mm/vmalloc.c               | 19 ++++++---
>   6 files changed, 116 insertions(+), 16 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5cd6631f-0bac-bd74-3369-1fa4a744687f%40huawei.com.
