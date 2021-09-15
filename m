Return-Path: <kasan-dev+bncBCRKFI7J2AJRBSW7Q2FAMGQEQDDBUII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 04CC840C1D0
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 10:33:16 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id v1-20020a0cc1c1000000b0037c671dbf1csf2740387qvh.12
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 01:33:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631694794; cv=pass;
        d=google.com; s=arc-20160816;
        b=mV4BbmUrOLcT6KmVHdH7EDpRyRKFxFQAcpigh1Z/Fa0PQ7+M1jO2owxl7CDupOHKVh
         2TRl+85n7rVaoYi9yNhX8klQLcMp98YdQY1SQypbzJQM+BsqKUGJhluU+tVxPf0kWwnW
         KY015iU815VOUGeiX64IN3TzMaw3/kfXr6vIMPGlCRuoYO0ci8eAchSS0hn9k2VgAz8p
         dKEL5+yLZNfMNcjXFW1gB5ijeX6nS1M7djMuJW5HwgWMiEYCgbzHDPEPeiTiYMoTc7ZK
         b2D0DQkdCOzSrwyss+DWGFZsG9az79O5TYIFj1ewvilDVmt/lkt08e6s65tbjjfdR7UH
         K8ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=+tvmoLHTWRze6yBHfEtkqQrdVgfnnogdzCz2eQgPf1Q=;
        b=ufpQQK5z33wl7UJofmiHfjEhCS/fOvClzLJMpgVsQJhacgdAoEfsmtEiqRLh5Lh1Fw
         2VB9ChPvll6HWtrdG2Xxx9Ta3hEefc5cvl1+1kAIzxUVS9X8nrqFTN4s+iGQBKF+pTf+
         v6daLkdbauSUywylzCC0q5XGyx8RRTREqYQ7nYPCFq6jAlQstqgOwYoJiLRjJWKxf5HB
         wZEv175PIjYBOHhYPlBmKXAHHF8W9FbEJXF2qUazpw448d2fP7JNVzsMVlcpMkiU3pON
         0cF/nnlqNQwlzVqO8+2scuroILd5J3Xo/Sxzvs5gtZ3056m6OS5JIFLeOFodpRiITsDZ
         P1Hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+tvmoLHTWRze6yBHfEtkqQrdVgfnnogdzCz2eQgPf1Q=;
        b=IfvBtaR3WqHTPR268XMsr8Xs50Yemi5wEeUnemEJNKVAi9L7qb+L4/Pt31aAVJEvgq
         eAEF2Z1r12IAscC2PUrPIrXaAIUHqCPJsznMJ1B3E0df1kmQf7K9YXQAhvobF3yiPJf/
         GPu/9PZkqWC4Ey1cPnJ5uY+DAqfxM+6mstVdErkS4cCl1D39lwK5Y1753aEIbvOtvKuB
         A7YJcJVSAPinwbE/xyWj5RWET+QrpWd/ODtBzilTuVVHwf58zumjMAxSuqL0SabMQeLi
         i/n3WGlwvxPDB8YK5qeTuI0QV+bG1FDn3F6m+MCq1UtFO7/sADivlQb+YzkvviT728Hx
         CrrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+tvmoLHTWRze6yBHfEtkqQrdVgfnnogdzCz2eQgPf1Q=;
        b=CZ0rulsiyrP4WAW3pF4/t+wsVwTB0AFa3UbO5vpuiJQGxSbZ+Jr2t+jLiPexU25+Ek
         rywu+wmw3Tyf/xZT9vkmJtFHtHi3ikFaru5hQFIIL4fTzktv0UZmwBetU2fegKSmnXin
         I3WhxogNGlbQTpEikEQ0piVgjbYnDcvwz7vf8FGOk2COO8EKAl3zCmtJ1wAiD42J9UeH
         L2i3sc5eIX/XEEx7BnTXPztkWC/1Q6WtuoGHAeUeAEGhTYJHRxkU+/f9gqBd7vqaEvF9
         EiHXDUN2Sc+xgoq5RRw9vM6cSQQzDrdkIhQChoMzY2OkBDBCU3QS2avG0OvXisqTt0k1
         4GhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532a5+y4MtnkspNBxzF/CSXGchMybdsFSfJ4L7kyP3BTwfIQUymk
	PaQilFZoWan+uFXp3iuSzRI=
X-Google-Smtp-Source: ABdhPJzY+TdUPgnl2uCNuuhCCO3hyeRJ32KHl5F/dGCSccVsfhn3U1mtSvdzZpAi17DV3rukyvoqcg==
X-Received: by 2002:ae9:f304:: with SMTP id p4mr9115709qkg.334.1631694794826;
        Wed, 15 Sep 2021 01:33:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:444c:: with SMTP id r73ls1027687qka.10.gmail; Wed, 15
 Sep 2021 01:33:14 -0700 (PDT)
X-Received: by 2002:a37:f705:: with SMTP id q5mr8991283qkj.523.1631694794410;
        Wed, 15 Sep 2021 01:33:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631694794; cv=none;
        d=google.com; s=arc-20160816;
        b=mDYG1T7EXogDe0vYvoD2qzigzwFn7H/nTyvfx6ier32cGUdsM6NJldiiP8wKsNBxv8
         vf8DJNB+aptWJoTL3EDh3IqdtK4cHJZsYJPXvsaE81jHEPUKEI2y/PriiEq6Rk0f5s1G
         QjcvoVFvjeSYeCktv3ZXwhrIF2zZj9VCysqdGaD2zPEptWxK+Ol6ouhXzMCKnP2Y6Qfo
         JhD+dqkPk3wp6BA5bz9MIsur6BqdIInkeEYG8YNvA5ujb0+TDDACDXsztMY2Z540zs6C
         V9x7HiUTK8ceiutOuSFfYhJ4YFJTVic76tcWtxD7PkYRJpOBdVcvDl+bdgq5AWJt3c1Q
         6sCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=2gB2JsenUgF7X2sqpjmfXQMvAQTNpNnNtM/DzapDw80=;
        b=K3WXSuMaTBAALnq73bBX5Lo9Fk1dVpUpdDrVI+FbrWM/SfIAzEDVmMwRLhN3HCdbRd
         dFJM5HQe51juGmBcLGegCS7lJVSi8izxo5XqK2bJ7ADG76rS3c1eY0mXuZVmdj3NyiUD
         9KnMRC1LCPTkAYdub2wIqYkB+s+rT6ab87SoNdn4wHb9IzsNQcM1YWkU0SUWBH3NgzoT
         gjSqVREvnChybzIKubUnC2FGAE5i371YQvZcpddG9oJ0qjUtbbpXGUE4AkqytxPTHGEe
         YWn2JLXzRp2p06qcaJDqaZg96Osb38z3B3h03lf+5zI/pK+BO684FHLsKhs/TlDPc+8U
         UhkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id t12si1143769qtn.4.2021.09.15.01.33.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 01:33:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4H8YNp1lWzzW1dR;
	Wed, 15 Sep 2021 16:32:10 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Wed, 15 Sep 2021 16:33:10 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Wed, 15 Sep 2021 16:33:10 +0800
Subject: Re: [PATCH v4 0/3] arm64: support page mapping percpu first chunk
 allocator
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<gregkh@linuxfoundation.org>
CC: <kasan-dev@googlegroups.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <c06faf6c-3d21-04f2-6855-95c86e96cf5a@huawei.com>
Date: Wed, 15 Sep 2021 16:33:09 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
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

Hi Greg and Andrew=EF=BC=8C as Catalin saids=EF=BC=8Cthe series touches dri=
vers/ and mm/=20
but missing

acks from both of you=EF=BC=8Ccould you take a look of this patchset(patch1=
=20
change mm/vmalloc.c

and patch2 changes drivers/base/arch_numa.c).

And Catalin, is there any other comments? I hope this could be merged=20
into next version,

Many thanks all of you.

On 2021/9/10 13:33, Kefeng Wang wrote:
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
> Tested on ARM64 qemu with cmdline "percpu_alloc=3Dpage" based on v5.14.
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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c06faf6c-3d21-04f2-6855-95c86e96cf5a%40huawei.com.
