Return-Path: <kasan-dev+bncBCRKNY4WZECBBNEDSWJAMGQESWHPAWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A9674ED384
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 07:52:54 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id y23-20020ac85257000000b002e06697f2ebsf19273598qtn.16
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Mar 2022 22:52:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648705973; cv=pass;
        d=google.com; s=arc-20160816;
        b=pKGGERAwzKz4nPGmWU5wao7SaVF/FAdzgeEj2FZkkXWl1U2dIFVAhn1eCsC7wsKoPt
         RVP4VBbTvhdCOUC1y6B5PDvuMvbgfkPb6oLLzIwJkNCjrcwxAFFKmVQX4QRmP6sx1+pC
         KtJbdLjVfa0pY6yLkXmBrzj+EIp4ydr22GxEyl96LNJCoumMlMvgMndl5qmh686q5Vsb
         R55lwgxJtwZ992gSleMK7hxPi3a2RypUdMh4HpDoSGBMcmMe4UXyNF+ScvwfHjGMVu3Y
         I0t/wBfxlF86rcYejeCTGp8fyqCi1U0OtyO03JS121tTHtsw9VRNtPlC6fHUvMsHkjSR
         aV6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=i7Zg4upxFq6Y0n/BwCe1ZXLB5DzNnd3GFSPCA7CA9R4=;
        b=Cj2BT3kNCPjkw2ZM6E0H28NB/2iV+EFCOcZrHcD1hEtvZKr3Uu26aqhYVcqbrwzoB6
         az738D/XvZlhVSN+suxJt9uhNVKdVYWTBnaQE09wvCkOWiEeXhKAxpXWbnweuu+cREZ8
         MQsxQHGqXqguQCI8eolTcvmGHfXJah3kN+U5k51habbjQ6OgUnamKRhcAvTJhlUcJbRr
         k+WIGq9JqQZ/TbODVPi4eG8UyBNk8Gf/7Lnb5wMXNhnZymXfspStWepyG0Gn3DV2P6UP
         2C6jut3ML/S5hU6e6VRfDr4vLrIlYl1IIZkSNEWgHlKoJ10GjnFJ8PelqesjWVMtrCsN
         lYrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=UPS1UlTV;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i7Zg4upxFq6Y0n/BwCe1ZXLB5DzNnd3GFSPCA7CA9R4=;
        b=Ydg8ZhcMEK8Wf+ly+Jb/ZZkB8jffZaqu9aOpDzgdkDd0IktkDI4eKGL2hYlWNORON8
         Ojfh1SNsrtxtG3/aOCsEertR4BJUTu64VOfhHEPNR3opdpLtPz5TLMbf8z5izAWiNeLJ
         9aEF8H6sfB3M4vnoAgh00febf1Bdxdy7fLoqEshbYWggmMTgqqUHnMZB+km9V+TEX+Cw
         HG360Pmd0wsRPV8jwUDfEQlEOlAydHNfYMcxcghPLEbhhRQYqCsi5RJjqCS0WILFU+SP
         KnFVRaEAYJVuynat7xPXhnGIa3hJ81s4NFYqeQCiC0b2kyVKbLlTYvEVE20BmqOGDI8B
         otHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i7Zg4upxFq6Y0n/BwCe1ZXLB5DzNnd3GFSPCA7CA9R4=;
        b=otYfWMKtZ8n12RKSX9kczKrZ9JrdTr3jl5tc8l6P0g6oLox0u/dQRCy1C20BjjkoXw
         t5sxUUjRBk+xqsSNugrBsFP5J+6hj03Bjh+NG4exJ0si3FwmDTXJbrJW8l+rwIFES9fq
         08gkqN1P1HOsEh2eFMZNcUIn/HpnaA0CbZg8ZAYxoNuVi8tu24t8zsBhF6lJyH5uuDvs
         L8s6YeNmiJAipnbPKEtBPhS2/xl5K24MerPzuUp+aCeqA6JRAgGVyaZRco98EOQlZ/qY
         Wq6mKC5JVrcxzYZzAoxN5NYMEaVsKPtnjvLDqVUbieqtSr+x+f4imlRwtrT64mo+oGnV
         U3Iw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531oWsjDW63Mj0gRHpyTZC3mDHXLRdnsVw8ANnENWktz/fi1sB2Q
	ggZdkHJe9CsfgZAvPQFsT2Y=
X-Google-Smtp-Source: ABdhPJxYkflB8jnw5H83MOdYsRBRmvVFtqX3EdWikm8PIdGwJkkpQ59w1jMGlzCzZMNg5qbopzI+ug==
X-Received: by 2002:ad4:4e11:0:b0:440:f8e6:af34 with SMTP id dl17-20020ad44e11000000b00440f8e6af34mr2753043qvb.89.1648705973048;
        Wed, 30 Mar 2022 22:52:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:29ea:b0:441:6cd5:fec6 with SMTP id
 jv10-20020a05621429ea00b004416cd5fec6ls2126687qvb.1.gmail; Wed, 30 Mar 2022
 22:52:52 -0700 (PDT)
X-Received: by 2002:ad4:4eef:0:b0:441:2b3a:cd22 with SMTP id dv15-20020ad44eef000000b004412b3acd22mr2626003qvb.130.1648705972643;
        Wed, 30 Mar 2022 22:52:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648705972; cv=none;
        d=google.com; s=arc-20160816;
        b=wqJ1Mv5JKrDK5WburTu7ZsTSRCfKRlW/1pD+NOlHdeLWAoIxeBeJz+1GztyuArgq+0
         ZVNTfkoFN/daViTsZR9lKmtLbxmdhOUaRuHzrbQTPpjFlJvI7Iz4nkh+SLsULhl0Fdh2
         VrGqBSb/WhfHrg8rtY1pDhU6pm3kHNVPYgZ/NZhHF7EgfRBA5lhu7qtbx4VMR6WvUCla
         HBa6OGJ9xehAgXuj3ce6kAdo86r5/zAt6yxBoRTUiIQ4a4v8WS07uK5EteZ7Tlt1dcwC
         7pZRbxoQN0rZIUo82EI5isoa3O6WRv6mnVkKgBq/PCxUiZYhAqIfDMbHz0i8BVH0gMFg
         LZjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=qwc+ykWjf+iOc40PMNj72quPthV5FEgbg6mED7ZE66w=;
        b=jTfO+UHO02x6oEqjq7zKDsBLfGeO6EwH8uMQVfda3cAa3/Nqg7AaNBYlcyQzzsX2ti
         x/W5OWp4a/gjbWsKglG/jcpTv58rok8pKjMV35nFnr3DMGywjrIJvScipCmyhET95fXO
         xl9bGe6AkURwxzcnqC1ec9meVQO8TE2Wt1J1U/5Qd+cyH5yccF4raNly/JJm027v/7yy
         PVOYMsjs4QBwPVbklNTeP1pTNZfK6rWF5j/9O4UKB3JVN7vW9tEUON9EdlCK/ibCI2Yo
         iVgdODCxEpPojRZsY5g9WyhJ/LTQWQ41sDADxHsUQHwTwAfXVbpfwiXOe2I39efFkKiP
         vadQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=UPS1UlTV;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id p20-20020ac84094000000b002e1e5e87168si1457561qtl.1.2022.03.30.22.52.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Mar 2022 22:52:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id c23so22495758plo.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Mar 2022 22:52:52 -0700 (PDT)
X-Received: by 2002:a17:902:e5cc:b0:154:57cf:e393 with SMTP id u12-20020a170902e5cc00b0015457cfe393mr3420091plf.24.1648705971745;
        Wed, 30 Mar 2022 22:52:51 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id g3-20020a056a001a0300b004fa65cbbf4esm26661394pfv.63.2022.03.30.22.52.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Mar 2022 22:52:51 -0700 (PDT)
Date: Wed, 30 Mar 2022 22:52:51 -0700 (PDT)
Subject: Re: [PATCH] riscv: Increase stack size under KASAN
In-Reply-To: <20220314090652.1607915-1-dvyukov@google.com>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  alexandre.ghiti@canonical.com, dvyukov@google.com, syzbot+0600986d88e2d4d7ebb8@syzkaller.appspotmail.com,
  linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: dvyukov@google.com
Message-ID: <mhng-2038307f-4225-46a3-b551-e1aebbea564f@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=UPS1UlTV;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 14 Mar 2022 02:06:52 PDT (-0700), dvyukov@google.com wrote:
> KASAN requires more stack space because of compiler instrumentation.
> Increase stack size as other arches do.
>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> Reported-by: syzbot+0600986d88e2d4d7ebb8@syzkaller.appspotmail.com
> Cc: linux-riscv@lists.infradead.org
> Cc: kasan-dev@googlegroups.com
> ---
>  arch/riscv/include/asm/thread_info.h | 10 ++++++++--
>  1 file changed, 8 insertions(+), 2 deletions(-)
>
> diff --git a/arch/riscv/include/asm/thread_info.h b/arch/riscv/include/asm/thread_info.h
> index 60da0dcacf145..74d888c8d631a 100644
> --- a/arch/riscv/include/asm/thread_info.h
> +++ b/arch/riscv/include/asm/thread_info.h
> @@ -11,11 +11,17 @@
>  #include <asm/page.h>
>  #include <linux/const.h>
>
> +#ifdef CONFIG_KASAN
> +#define KASAN_STACK_ORDER 1
> +#else
> +#define KASAN_STACK_ORDER 0
> +#endif
> +
>  /* thread information allocation */
>  #ifdef CONFIG_64BIT
> -#define THREAD_SIZE_ORDER	(2)
> +#define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
>  #else
> -#define THREAD_SIZE_ORDER	(1)
> +#define THREAD_SIZE_ORDER	(1 + KASAN_STACK_ORDER)
>  #endif
>  #define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)
>
>
> base-commit: 0966d385830de3470b7131db8e86c0c5bc9c52dc

Thanks, this is on for-next (there's no fixes right now, I'm still 
collecting stuff for this merge window).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-2038307f-4225-46a3-b551-e1aebbea564f%40palmer-ri-x1c9.
