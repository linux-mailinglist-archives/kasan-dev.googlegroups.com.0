Return-Path: <kasan-dev+bncBCRKFI7J2AJRB4E5R2FQMGQEUY577OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id D8CA5428472
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 03:10:09 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id x61-20020a17090a6c4300b0019f789f61bdsf11124928pjj.0
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 18:10:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633914608; cv=pass;
        d=google.com; s=arc-20160816;
        b=BSiM2FBxGaP9ABqap6yUHFVtgRWJRfel7+GFSN2JYv75sueZ1idLSPf4pJqkFm6RWz
         89uv1noYDSVUoiU1mCOby/D3BRvXdZvZylA/dpjnJMYP/FNDWAUfYxhg+IqJmdXUgNrM
         jz+PybBprZbUqhiB+2GLD3LDsEv9YDzM4lviCAb7RMXBX3wy9VOkdP+ciqiMVPox6PWF
         rysmPKaOhOH03iHzGE9Fn1+b448ZMHU7LmstgsySAhfj30xLFzLohYdx512RIbv32ZZA
         d762hvPsZhSNlhWp5JuXQTFyuOAEZsvjf1bgsoqs/S01IHyFKc5UtXtqHmNz7Y9wo21K
         tKIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=mGx+wOahpPr3Xn/FggykcZQuiff9wULkV9IElF9T5iY=;
        b=ghaCLNivn5XIyIubLMKktiUd1ExOIXnhXrh4uPEc5VrNhvKPZGVScS6Qaa4IhwPbah
         eKLs8G9+AMFcZGBxGU8Dt95cwJ0zDl6OxmgYMjmoGKUYyzUupGEQGW14lBg2V7jyaB4I
         lAmfq+aWN38my8rqz2JIjGLDFvTfTyqA4IuGN2IntMAiYCq8gma7jXYe9K3Kwep6Z4ps
         48f9s07hATMBy7S+ifN2XcsuEyI5o/qVYZZFzzog+zkrR1m81qv+N33fTHgM9ZC0VRIE
         uvTK4Fx9u72GmK+xOZWZfIXbK49zvtdvu8lbtCMXDVCYqwVA+5u9+09LvOAmrC230fAw
         GlWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mGx+wOahpPr3Xn/FggykcZQuiff9wULkV9IElF9T5iY=;
        b=c0qLlLwllAOnLNlcUxWEbbbX1j8N8HHVJ3GGrBX+JFbQUlOxV/d7GrsdBiMWxwwBpi
         ucHQUpQMEbAoE12bkkDktAoHhgQM1+opFgwpXXY44p+U3rT24P3ca6yC1pJS5JOFyZlF
         sRQscJTvw9CRrx9RFzOxeYvEugCITLDtcMgU2Fesj7yLhOmG3MVFK/NdxnbIloB7Kdtu
         gOGJk2jO9Gxg2dDa4z7ylv2Q7vEP00nAqQOi+l+w03vRTlmzuGkP2wUxBDRhFj813lce
         367prnNvRLgjZ1cuSLigAzmvKgo3l00HMDe4mETzZsBLorMdIJMshWjaiYwdYxN64FY0
         9mIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mGx+wOahpPr3Xn/FggykcZQuiff9wULkV9IElF9T5iY=;
        b=zOvlBCXQ6RI/IYSKSeM3VJS61zFlMpYDP8ZcZlroRCOAmeeVCz1kKSazhqBBTNiMBB
         YYCBJ7qvQLIWPt5/xGdcXOckkeGkMXChgoXl4IaR86w907vOuld/knBQWFTAuNhuXIpj
         bbnVjt5qceX/abwe9ekdA/VS8sG/2n75pl0QsxaB4a4O9BuFCZK72K5Ts+pPJf2M3iCr
         N8YlPTOHbTwbuQr9FDMvsMdx67VNhDUv0SaYSmx6uOjLAbEJaX5NUG0haIdR08uo0Dt0
         Uzj9kpCUX0KkDrHLTAmMtWh+JLsE95DkbRg6GE7MTo2zWQD/WwM3VFb4GVSQF/vKGcnv
         25Zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533brvqt4OgcrUPpzxEbDuwLPEsW+GUts8/HTlE9BBj+a9/WoZb+
	Xjc3n7GuX9bmcnV5i/1tenA=
X-Google-Smtp-Source: ABdhPJwzGuh7/CtiA95aUK1Gf7Rn0zK9w6bglReYNyOBuu/dYQEViLuU05KpbAT91v0yfhXolZ+JZA==
X-Received: by 2002:a17:90b:4ad2:: with SMTP id mh18mr26399821pjb.18.1633914608318;
        Sun, 10 Oct 2021 18:10:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6252:: with SMTP id q18ls3314587pgv.0.gmail; Sun, 10 Oct
 2021 18:10:07 -0700 (PDT)
X-Received: by 2002:a65:45cd:: with SMTP id m13mr16081167pgr.26.1633914607819;
        Sun, 10 Oct 2021 18:10:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633914607; cv=none;
        d=google.com; s=arc-20160816;
        b=rS0vvzq1qFxY2e1ksFgIg/QNxHnyaHiZ10IW11EOi98bDDiC8CUwS4x4FzceR7Iqmd
         EyhW7zPVWBYKtE0UeJgX2Q0dzkvhSZ+9Dlodsbtw6Gz//76u3gnFQXnFpPKh0i55RGZm
         H1Yo2lg1eMgWzKdhivkPaHbkL83SnYNvjdmsHVHOOoII0bwVkgG0se/KUzDdptTjuWDo
         JSJMIHPwLMzUKNMMBfd4CCD9krHtsHBNEX4yF1fD6EU4XWyEqjomNm1lEBNRKD2dQSHy
         usDwSaQwHidHNnti+6xKr93y4nDDBcszPHlfTC+/fXTGPvM4hDCSwiumO+lbaDPSBcFk
         6zgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=q25MfoLT0DO9vt02mYfEq+hrqkql9A+NH3WD98Wjrm4=;
        b=br71xeAE7x7tj6MylDkdB9TETkgEN+PW2mWgJfoQgEdeHbEi4ljP7zS16x6Mj1wt3Q
         hKuGmavovvHhanWDEdNdVNkgtQFhC0xL3SMpn5ZFGceAoevA5HtBbuO8wCX1T1UmM+C9
         NiaYEPrRb2NBAsZlYhlt2IBrWM8SmYflSoc+VXvvvoKbT2HsbAZpem93eKCCSPPBQX9T
         ErLCtXxLFU89wNuQ/rXGj2ZSYMcwpXCljVQpda1X/WjuknYRw4cK0QwcTvrJmpiPncW8
         UZh4bJArUJjA7QUw/9LP25oQH7LJHIsLbVvLTOlYL6Lvw+EyMix51hMReDyzwCJQKzih
         X8nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id u15si369147plq.3.2021.10.10.18.10.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 10 Oct 2021 18:10:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4HSLDz4x22zbn2h;
	Mon, 11 Oct 2021 09:05:07 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Mon, 11 Oct 2021 09:09:30 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.8; Mon, 11 Oct 2021 09:09:30 +0800
Message-ID: <6d78633c-8e74-1d84-5f02-90fc56c1a11b@huawei.com>
Date: Mon, 11 Oct 2021 09:09:29 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.1.1
Subject: Re: [PATCH v4 0/3] arm64: support page mapping percpu first chunk
 allocator
Content-Language: en-US
To: Andrew Morton <akpm@linux-foundation.org>
CC: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <gregkh@linuxfoundation.org>,
	<kasan-dev@googlegroups.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <20211010143622.18f491df5591d039cda8f7b7@linux-foundation.org>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
In-Reply-To: <20211010143622.18f491df5591d039cda8f7b7@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme715-chm.china.huawei.com (10.1.199.111) To
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



On 2021/10/11 5:36, Andrew Morton wrote:
> On Fri, 10 Sep 2021 13:33:51 +0800 Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> 
>> Percpu embedded first chunk allocator is the firstly option, but it
>> could fails on ARM64, eg,
>>    "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
>>    "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
>>    "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"
>>
>> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
>> even the system could not boot successfully.
>>
>> Let's implement page mapping percpu first chunk allocator as a fallback
>> to the embedding allocator to increase the robustness of the system.
>>
>> Also fix a crash when both NEED_PER_CPU_PAGE_FIRST_CHUNK and KASAN_VMALLOC enabled.
> 
> How serious are these problems in real-world situations?  Do people
> feel that a -stable backport is needed, or is a 5.16-rc1 merge
> sufficient?
> .
Thanks Andrew.

A specific memory layout is required(also with KASAN enabled), we met 
this issue at qemu and real hardware, due to KASAN enabled, so I think
5.16-rc1 is sufficient.



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6d78633c-8e74-1d84-5f02-90fc56c1a11b%40huawei.com.
