Return-Path: <kasan-dev+bncBCRKFI7J2AJRBMU37CDQMGQE2FIJIZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 517973D50E0
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jul 2021 03:19:47 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id h27-20020a056e021d9bb02902021736bb95sf3844326ila.5
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Jul 2021 18:19:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627262386; cv=pass;
        d=google.com; s=arc-20160816;
        b=KeNXJGxGiAEn7W50Yo95XcRdx6flA1GwL2y+YOCi1VT6M6KYB9lfsZ3EaLmcBpAmFh
         /mywPBJx+I97JDBfuzqYuhOYe0SY14eg6vqE7dGdGaSFHcAcRL+bbPefSF5nzIGq75Kj
         PD0+PByZovtzW1KspgABcfkOhDeKnH3HBgvY6syCPQZ9NdRWZt01JTTLvcXn4BfujrSi
         RynOYSQKMcgiRG79jo+kri3WUg8Edc+N6B5Yim0EbP6Iw5J7Ac5v1kQJYvbskl0nhJ1t
         q4XHoDaMJbrNFULu4AjdXsck3hLyX+R5tXz1qneIXW5PLIGWGRrL7ODbJZco7EpG39z5
         3+QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=UE9qbv4eL2AVQfO8exnKhJQrj24xF0GIGmr9b8/WuUM=;
        b=P5C1PLbvHLmcYOWEj+FFAUBqNWMZcHbCTNZrdveAmjXxsVNk/oV92VmvxUcPlMxhNE
         uncpDy/kYLm2jXVo7smKuCnz0uvfpOvORGmOUB/gSYPLa5lEV+zoyGiIo0Ll7aJXGyRr
         qhutf4ZiMHG1n2i2kkbqAx+fzxN07hXtoXuZxcc8W0xov6hzWjn7rw2y34crjNWXrH0O
         S2kCbbwS94NuwrzzPXdvIpTRl/2xWor9iLc/U2QY/xf8JrmhUM7IjKx3BXOIVTjQWb6L
         BgaLlA7HQQKtWaP2l+4Ny4bZ0/IeSA+TFulhtBW7MTJOyApFuM0Fb3P/dfrRE/iLjv0n
         VMSA==
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
        bh=UE9qbv4eL2AVQfO8exnKhJQrj24xF0GIGmr9b8/WuUM=;
        b=PLp91SS5B4M1/mhJ76Vj2ZmOw6Jv4n/xSIAQnSB4I9Ax+DH23b7hXXNPp9GamBgiWV
         nfmWvEI/Vj3eKIzeYgo9CuqaRUpsLMGV5NsUqVZI424IvwIMqgLFKh13q5rYdHOTYza3
         m7TUMGdlyN0M3tJA0akzZgLdrdFlJYiL+A5iC72BZ1MV1vO78C8kPepGl0CJujFfpSoP
         /RuXKUworXNQl1FHSh5rWg+SZuanB7upoj1oM90KuCVI47fZVHZxnFa3YtskSkhAv1SE
         UsTVGj0jDNuDbzgUrc1y44msBvi678wbYn9hrt5+MWpi1F0P9z1vjAyT1Qd0TVDuceUI
         Lm6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UE9qbv4eL2AVQfO8exnKhJQrj24xF0GIGmr9b8/WuUM=;
        b=dmcIY4cgfPLUduxo7EUZ63StEhdT0qm3vxtjkyQ8GiHDgspnKx+JS15gZcHScHXxcO
         ExrELM+ati1/0nHVoSRT480t5C9u7I9zw936Vf57QrJ2vS6cHBxu9BEsgGQjEYIgU6Sn
         oF1ui4vttduM4UW8dGKcwtD+IheRF6N2xdhsQn5+zmeMZOHluP1E4lFyPlFiH3BMmffZ
         oIsUx8lS7/A/iuuJ1UQ+ZTURcNUiJ8TMz3Ao91gHv9xYuJFonlE7e6oNKh3adw9GpyI1
         AHc66TSlj1LjN8BvbEGEQwpAbtAm8YEAppuFF7bsoKeuGxcyh9AM+CjViV3nNS9u6LGV
         LUig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+PDnl35Y4AM2HiK/iamECM8jy3EjOx2O8ri+WhWFE9GCZd2BK
	JqMa5HFbjY0m44GkBpqv59I=
X-Google-Smtp-Source: ABdhPJxeV9cZ2Mh1BIGdWl3PVJdLDvIk6jC+lb9Y98cqD9f75F3Y62kV/69re4nc+B9tJ5MW8kR6RA==
X-Received: by 2002:a05:6638:14d6:: with SMTP id l22mr13976644jak.99.1627262386327;
        Sun, 25 Jul 2021 18:19:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:4bc5:: with SMTP id q188ls2756029jaa.9.gmail; Sun, 25
 Jul 2021 18:19:46 -0700 (PDT)
X-Received: by 2002:a02:7f47:: with SMTP id r68mr14141986jac.127.1627262386014;
        Sun, 25 Jul 2021 18:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627262386; cv=none;
        d=google.com; s=arc-20160816;
        b=h5APpu/zV9Xct/5HUH44Re22t50bnjzIISeFq7OJdv2WInHciajLQXc5woRWYtDDhO
         7eXUfy8RcKjR4Ql+Svszc3QAzVEo0COHzzBanHwWbplS/9V0AgEGcMiYL4iLZSYz8BYW
         npPG4Gh3UbrDxUBVXD06LsFq+eqahn6Ip3cGJuYcplBlePA9bfrUfzcwBdqsRGCounW+
         Trk4yZdGgvGJWF0aoYv80pSMl/mwgL3dm+jzmvpOFkR5Eg4FLdkLyU9TWb/wYnr9XtVO
         90D/CqYAswSg8qOjfPK1TIhRiHxrGyyiWrvmFCn2tmLNXHKqEcfiHFrGkXsYd7WhveK2
         ZqhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=91BPheENokwDAdCAroYdoBQN1fb1SX4I6fl7Lj+pZNc=;
        b=CBAwuRxZjTSXZsR0ziCxF4cO5M8aruhYpVmDOBDxkN3uuv/QOnPj8PqW3i2Tk2PSKs
         rwkjiWXyldZcAKHCt/iP8n2eOYVpmOJt7VniqMmxtC0HWYHUaJkMm0TQMo2PbCMPNqhu
         E3WiTMe3mWqDQNV1T/mTM5Tv307qFmHPeIQufaaruqPQo6ACEoxlNvaIIA7gX6IUpFTw
         f4kTBufoLO223ZPdBk7oZvLAmZxNQa9WN+iO+H+83icTwmxJE9ZtoRzrlDHi5zhdf8PW
         EpEqNl2010DcUw6tGjvnQX2pELFcvm6UUo1Xkc9WR5YYxh9n5M4Yy0wfF5SbdsAHEX4S
         EWBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id k3si3398994ioq.4.2021.07.25.18.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 25 Jul 2021 18:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4GY23z5VKBz1CNpK;
	Mon, 26 Jul 2021 09:13:19 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 26 Jul 2021 09:19:12 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 26 Jul 2021 09:19:11 +0800
Subject: Re: [PATCH v2 0/3] arm64: support page mapping percpu first chunk
 allocator
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <2c1254a7-561c-9b99-444b-c2d9aefa7b55@huawei.com>
Date: Mon, 26 Jul 2021 09:19:11 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
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

Hi Will and Catalin=EF=BC=8Cany comments=EF=BC=8Ckindly ping, thanks.

On 2021/7/20 10:51, Kefeng Wang wrote:
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
2.
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
>   arch/arm64/mm/kasan_init.c | 17 ++++++++
>   drivers/base/arch_numa.c   | 82 +++++++++++++++++++++++++++++++++-----
>   include/linux/kasan.h      |  6 +++
>   mm/kasan/init.c            |  5 +++
>   mm/vmalloc.c               |  9 +++--
>   6 files changed, 110 insertions(+), 13 deletions(-)
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2c1254a7-561c-9b99-444b-c2d9aefa7b55%40huawei.com.
