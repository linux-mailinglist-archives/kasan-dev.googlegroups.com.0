Return-Path: <kasan-dev+bncBD22BAF5REGBBKPZ3SLAMGQEF3S5S4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05DE557AA65
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 01:22:19 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id v4-20020a056512348400b0048a22a5f359sf4792865lfr.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 16:22:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658272938; cv=pass;
        d=google.com; s=arc-20160816;
        b=nY1b+SeSde0UgSIfJo8TgW7U1KL+93s6piy8xM2xLbdKNkTFkOj7XJ6wZ2D74ldcTB
         2ZdSjt2NrUCmrILK85jNdCYH7QWj9rHr1NNQXCayjlw024lVzF0mrFOWYRqBLUzkVobL
         CJ7AkMXhJQ1G+SA1nxiQz6tAgueZxOh0TbPaoLS2F8Rm3HUUF6bXMQI7OH7yeXgkTrnS
         foyuRQRCILH1Sqa05RzUxKGc47KOF/WBrzwINjNg//QFuo5LbeWwGUrIGrOBILR3lThb
         7+k4Z5zkJ82grUXx7uMN7R3wp+9nokrfAt4EttFqs3uZnQ6gT/oRiyGjGGnxRFKTlLuT
         Y50A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=2t/c/HNoYEOfLAtkbm4GZ5dtCyaQI7/ZQr0L9G6Zp9U=;
        b=ca6IZHb+VwAWNYTVKwsGy9BusoHflwti/QO1ZS4v/cBYrdRECYN6QI/vE9WDWzWYpd
         n14FKGFVxFZ1C9nZfu4aupULEJJgxs8VAr7izZhb87C9kpWnJ9PhtE3mBWsf/c0KU7Uv
         OsJd5+swXtOzbalSfHdof6qp3mQIpKx3vXLBO9eWidg0ABSOpuPnwm6/JjAi1ehnifp7
         Itcp0mMKnzKHqFpf75Ief3fJjb4ZWTEU7dJqgmODgVi+iRz1rlkr5IFYKe7+Syxg/1rq
         zTg2LiF08+Zm/tKKFHxtStrjIpvdfHLzHhLsUbUYTsumaXmevFw5EpRORoeSMnHi+o8a
         HEcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dq4abrfz;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2t/c/HNoYEOfLAtkbm4GZ5dtCyaQI7/ZQr0L9G6Zp9U=;
        b=mZe2RZAZIXYvd+YXb6OX1zYl8Kv1cnzsblbvJzjtkQ4A1o3tG5DyqXcwZFdFCtAGat
         ySyQDpHaDJnF77TBkK3vTezUYbKKAiwUy0op4qgz6DXxlTE93fUzYYjMMUGXNdSc86D2
         trtu3cUDSFR9h9u9XmA0xfecWP+3kByyAzGzAFyI9uhXuKsIZbc6VVrcqLDjwHXTSKxy
         rX0NCC1wQ/0IDss3C8KIf7uO8Xfvj/Hxp2dG4VO5sEr1EQ9ONgZk48DtenD+UaiJxAWZ
         bwU0Tn+9/Lg07OWj4x46mTnVrQvMXJ7RW0jFms3PKVTho1MXWz9rcHoM0Xf/wdWrHZdl
         2RSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2t/c/HNoYEOfLAtkbm4GZ5dtCyaQI7/ZQr0L9G6Zp9U=;
        b=jbT41w6ZRqSsZ2q+z4Oe92dFq3a7Jx2B2Cz0/8y4rqFwHwIyQVXf0akiOdM4XQQNzz
         6rbQqPGnDQeyM2NaEuHYpTwRGZzGwxBEoeIM9KlJQvVF+j6kfr5eVaYFLXEsW+NCEvSS
         KgcokG0J3NjsOGclEBelpWAbv4TbEvNs+WsIaBnuuAmAwEB1EigdWfQmb/uLCvBqLzYX
         kgKTmkgBeSbkXPXmssPFGxSKJoK0ZyAYBNQVoMDWNeAT+F3SHc6uph6Pd3KL4vEi4bF+
         Ynqn0+l3lZNI108n3ArA243G1TI3mr00jCk0b6SXYfxp05ANI8yRfy3mBraSGpPJTV0x
         iUJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/P3rN3G0T1TluY657JhW73C8ykxcFMVluVbPIoAQYmfiFdKS2+
	wjfcdJ90+HfORy6VShyPI9Y=
X-Google-Smtp-Source: AGRyM1tKLQuw4Hm12vEmcKg1LDpJWYOK393Y9OKVvYUjk3EN6kvkRVmPB/ibHOsb+ksw4QhNCaWCNA==
X-Received: by 2002:a05:6512:3f9b:b0:47f:48b:ae0d with SMTP id x27-20020a0565123f9b00b0047f048bae0dmr17843832lfa.27.1658272937542;
        Tue, 19 Jul 2022 16:22:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:753:b0:489:cd40:7a25 with SMTP id
 c19-20020a056512075300b00489cd407a25ls49152lfs.3.-pod-prod-gmail; Tue, 19 Jul
 2022 16:22:16 -0700 (PDT)
X-Received: by 2002:ac2:4897:0:b0:489:f2ad:1191 with SMTP id x23-20020ac24897000000b00489f2ad1191mr17540269lfc.25.1658272936076;
        Tue, 19 Jul 2022 16:22:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658272936; cv=none;
        d=google.com; s=arc-20160816;
        b=e8pl1SrESvbQNUUTrILtSf7aOS2hIAXRKyHqWWEo37l4ydo3c5lANMcFkl1LSDr9IX
         AWZz8HhNLDecBBMj8qC0+dWrR/9HDUmhmDvu5UEne1J2BvCTXcBoZjvx9P5Hkb06pX08
         AACLtYUwc6XsDAaCss9AOGjGKrJs4to8H961SLWf3sRVDmyYjRDZWQCp/Vao2wniYC3g
         NdEceustL4klbygG1mv3hff4wrYcZt8beh4CAP3M40EvJ2AxXjUgdgCR9Bw2FHeWQMeE
         GoR5qqgzzpi6sCMN/LYC0HpOpqLr8hqIy4NraV3yw11xSJ9adcWtn5SXazhpPVViCsdB
         txtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=1eAIWeFmZQqOIaWa0qEnwmG7+gddq4/fVT/CRZt8reo=;
        b=I4CsjmOcmXEK332MV44wVjUsEHQieS83fzF6HQUOVfptG89oVB3f5E8TiRxhKAv/jL
         Q8D4m7pzI9HKdsi5nroDZEcsI0jA5gF5PFYd+lWG04MJsXARdjfSj+gODU9T7Pfml4DJ
         L4ssOzsbRGLRPguwi2a8LWycbPwwDYiZqPtayGGhQdx8JYPzXnhkXTYbLkCcGAEfukrm
         ITjF5AvHeC6KRed8UL+RXJD/IiXWI+UmeCSVeNmkLAVYU7cp8i9ey/V2NCJ82umf+w9X
         +yhlEwxWZl36Y1/zQ0JTNnM70lG79pc4Vo4d7qTeH6qdEyWqLifsTDZDW7tFB8rTpvBC
         lUeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dq4abrfz;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id bg11-20020a05651c0b8b00b0025d57c8b793si401346ljb.2.2022.07.19.16.22.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jul 2022 16:22:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6400,9594,10413"; a="269658520"
X-IronPort-AV: E=Sophos;i="5.92,285,1650956400"; 
   d="scan'208";a="269658520"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 Jul 2022 16:22:13 -0700
X-IronPort-AV: E=Sophos;i="5.92,285,1650956400"; 
   d="scan'208";a="687299824"
Received: from twliston-mobl1.amr.corp.intel.com (HELO [10.212.132.190]) ([10.212.132.190])
  by fmsmga003-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 Jul 2022 16:22:12 -0700
Message-ID: <dc7800c0-43f3-6453-ef5f-1ceb659062de@intel.com>
Date: Tue, 19 Jul 2022 16:22:12 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.9.1
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
Content-Language: en-US
To: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>, yee.lee@mediatek.com,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 "open list:KFENCE" <kasan-dev@googlegroups.com>,
 "open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>,
 "moderated list:ARM/Mediatek SoC support"
 <linux-arm-kernel@lists.infradead.org>,
 "moderated list:ARM/Mediatek SoC support"
 <linux-mediatek@lists.infradead.org>,
 Dave Hansen <dave.hansen@linux.intel.com>
References: <20220628113714.7792-1-yee.lee@mediatek.com>
 <20220628113714.7792-2-yee.lee@mediatek.com>
 <CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
 <20220715163305.e70c8542d5e7d96c5fd87185@linux-foundation.org>
 <CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
 <CANpmjNPhhPUZFSZaLbwyJfACWMOqFchvm-Sx+iwGSM3sxkky8Q@mail.gmail.com>
 <20220719161356.df8d7f6fc5414cc9cc7f8302@linux-foundation.org>
From: Dave Hansen <dave.hansen@intel.com>
In-Reply-To: <20220719161356.df8d7f6fc5414cc9cc7f8302@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dq4abrfz;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 7/19/22 16:13, Andrew Morton wrote:
> On Mon, 18 Jul 2022 16:26:25 +0200 Marco Elver <elver@google.com> wrote:
> 
>> On Sat, 16 Jul 2022 at 20:43, Geert Uytterhoeven <geert@linux-m68k.org> wrote:
>> [...]
>>>> - This patch has been accused of crashing the kernel:
>>>>
>>>>         https://lkml.kernel.org/r/YsFeUHkrFTQ7T51Q@xsang-OptiPlex-9020
>>>>
>>>>   Do we think that report is bogus?
>>> I think all of this is highly architecture-specific...
>> The report can be reproduced on i386 with CONFIG_X86_PAE=y. But e.g.
>> mm/memblock.c:memblock_free() is also guilty of using __pa() on
>> previously memblock_alloc()'d addresses. Looking at the phys addr
>> before memblock_alloc() does virt_to_phys(), the result of __pa()
>> looks correct even on PAE, at least for the purpose of passing it on
>> to kmemleak(). So I don't know what that BUG_ON(slow_virt_to_phys() !=
>> phys_addr) is supposed to tell us here.
>>
> It's only been nine years, so I'm sure Dave can remember why he added
> it ;)
> 
> 		BUG_ON(slow_virt_to_phys((void *)x) != phys_addr);
> 
> in arch/x86/mm/physaddr.c:__phys_addr().

I think I intended it to double check that the linear map is *actually*
a linear map for 'x'.  Sure, we can use the "x - PAGE_OFFSET" shortcut,
but did it turn out to be actually accurate for the address it was handed?

I'd be curious what the page tables actually say for the address that's
causing problems.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dc7800c0-43f3-6453-ef5f-1ceb659062de%40intel.com.
