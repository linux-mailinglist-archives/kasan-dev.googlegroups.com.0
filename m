Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDNKTKAQMGQECFLXX7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EE5F31A0DA
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 15:47:42 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id f6sf8858594iox.13
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 06:47:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613141261; cv=pass;
        d=google.com; s=arc-20160816;
        b=CdmABv2gU5M0dKLhUnOFPpaVU+ma1/Hw2QosHGJ/O5KBAhzcdfnbl8Wn8WatoFMi0m
         cXtiQ8t//Sz2hhLPq4xBeuXRu7D8Pc8hRmD9ncsTEQ+y086yaube6DiKyBB6nw6a6gxq
         r9PPOnjF6ZFU32E4ECfcT2wok09CRkqwLFH4fvdrYMPIJ+yaKJLNvVnYai1HtEtXJpxZ
         o5CNx939Y+1TOOE50fBzJtqKPcmG0AOSZWeBXbFifZ2/FShMr/VQvYtaVbg6sZu9W2ZA
         l8l7t09BizT12S/rD3A4dPXlv3X0VAkhaEuFgfrM5ozFaEFtCnBVzgHaQhoVBO0QItmZ
         BU9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HuFzr4P19t9wsV6fH7b6Ug8QQlJDKBERYEAl9p22PY0=;
        b=0+pdrR/IUPahrJyoow625+glwRlwItUb2iJeNAml/Cnu+D1WNKVscU9EMEaPNH/P0g
         hTV6tXrmQHerNoWwAOSe2VYhLnrgVXx3UQ2CxPvfnB8pZidDnJpTVbx1qktzOE+j3dvK
         hIltaXZt9sB9+OaeTlEm8MEX/RqDr8Dp97l6QBjzXCp6zti3rJk+IRY+3lP0Fmx3vhDv
         y71Q1mQojmlPlxdUI3uxefBtAP/lXqSxYZG0U2yJkhdo6aPJX7It8KsF2za9aDKm/q+k
         4+je6D4Svu7LoHeB8SF4+8k/WCsDmZAq6f3e1NLKDIt5v1TOrQxIIGRsYi9ztmB2K4Kv
         EVkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QmVi+zHf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HuFzr4P19t9wsV6fH7b6Ug8QQlJDKBERYEAl9p22PY0=;
        b=SmQcKjmiPFXnoYOFc1pZQgNGM66MwhOrDHRhVlixovIEq9kJyFvH6B0O+Z7UVrJskh
         yLTSLH/5rt54LUeKGXqjoDVlHlOcRhQfnpo8QRWKbNxqLUo/ry1Go469xSnMQVz7Xb6R
         37PhudZfGH7kLIXKftCzVFHv1FaBs8KW5Qeprh7Rae/XSUR6oLW3vgo2bNnkvxpQ0xDr
         pMJ6wX9kdw6EQlsNGoXFrILIk/iUzK+6jpcekhN24l8gcUJDYgW9cQ0Z2N8VlF+VNzZm
         NRroeGTjMsfmmdQwnqdynCTpq2tZQvbFCOt4TPJZY5m4N9WK7iGuDp3ohlhlPLEoLI0F
         K0rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HuFzr4P19t9wsV6fH7b6Ug8QQlJDKBERYEAl9p22PY0=;
        b=EqYuZ2DFwQ1cg7JqtujkM3q9f1qAlRy2FYleJYk6iIURvBiIrkPNPtSXukKbRxhRgM
         mwW7E4xDvhVsGf8HdRIqBCvVuulKSr1S/krqAESvHbjpYnJjCyCT+d6wmm/Z14uDxEg7
         FAvgbweeGyGpyNTcBvf9xZWtdWd7LohC1+huKIptP5OrefQNiaK/zVLv7iIoU8f0I4/k
         b9Kba9JjKC1wEnbKZ3eF9mxmXvScM2nYrZBE37pZkUz9HFcCZOaCytsi0QvnVENCSklP
         y84C4Z3mqGS/aVcrrQM4V6AGMKo4WiSZmXc8mlvHCTTbig1yVFsnUaeCBJcq9HP2sSFh
         wSkg==
X-Gm-Message-State: AOAM532/jjACDc+Qo4FKCbymoS4XAGn5flJDQTh+l13jJCWHBKM2QBz+
	Ypa0EWfCLqN8F0JEkNq7GRY=
X-Google-Smtp-Source: ABdhPJzJu80elk8ZMOcixB6wAmGHYLCHfLdkx38B0d7YVZpybzO4ZDskdbrt89yh+VH93AS4pMl2gA==
X-Received: by 2002:a05:6e02:2196:: with SMTP id j22mr2588449ila.64.1613141261555;
        Fri, 12 Feb 2021 06:47:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1032:: with SMTP id o18ls1398342ilj.5.gmail; Fri,
 12 Feb 2021 06:47:41 -0800 (PST)
X-Received: by 2002:a92:d30d:: with SMTP id x13mr2622568ila.217.1613141261182;
        Fri, 12 Feb 2021 06:47:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613141261; cv=none;
        d=google.com; s=arc-20160816;
        b=TzIBa75IKTXi4LA78G+yRZHvrekBEPl5AUCU8qLUnQnn08rgwQnuCBZWTf6dIfpYeK
         fvXqW4OdO1spB7dBansvu55rC8GBzOITjLIom2NIZDWOzTZcCgxZcCbsXtiXvLtWwStz
         ecvAKMAT19ItUYoIUwYvR3SRHuXywjDYHkFbVBrSzWTv359UD5nSBNztOWhSqTaxWohw
         7WP2Svz/NWfwMY5G/tZvxOfN8+Hy8l3b/fuZ1VlxPBu2MuFPsiTcl//r0Sc704UMkxVg
         1isVMBatW3oNcdp2evG6cRS/czNhr3eYbOY8cAYncKd5SAR3gcLxdtze+IQCiV+gQdXD
         mQrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yUAtpo+jSz3YKQ5pQn8lc88X7VgrZAH2A2Qa2TULs9o=;
        b=Ft+lPYqTZrd7nbbyc98ISz1ND3tJCMWYicESFB1s6m4DhjjvOZg3uY1T4y8RhelzRp
         KyktnYpjz4yI2qP6qtnqj9+5vP8y6F34Kk69DsIJpxHu42nTVdh84Uy6uM4bytDhW4u5
         cxYAh9ZoR5L5EsPAqyox6shTCVyz/90gne9aIZZFPhO97ZjRroBD/QyNbHYzC5WG7iWJ
         l97ShPvBBclMpdRmTumIyyAloyd5oYfiQtPKkAq4C5oa6I4uKeEyKNLXVUfXpYwRmggo
         VZbr45vbC6/TpBjG7ANpGdjVVFYwzbNygm2la90iEA4wFLFWqT0EaDzeDJiP+FeR9xSS
         X8tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QmVi+zHf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id d2si484356ila.5.2021.02.12.06.47.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 06:47:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id b145so5961512pfb.4
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 06:47:41 -0800 (PST)
X-Received: by 2002:a63:a0d:: with SMTP id 13mr3394365pgk.130.1613141260320;
 Fri, 12 Feb 2021 06:47:40 -0800 (PST)
MIME-Version: 1.0
References: <20210211153353.29094-4-vincenzo.frascino@arm.com>
 <202102120313.OhKsJZ59-lkp@intel.com> <CAAeHK+yB4GLCn2Xu4z7FRLNOkVDFr0xXN3-D34BdJbRmWLpSxA@mail.gmail.com>
 <23dcb10a-7fc2-375d-2234-49f48461a612@arm.com>
In-Reply-To: <23dcb10a-7fc2-375d-2234-49f48461a612@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Feb 2021 15:47:29 +0100
Message-ID: <CAAeHK+y2kxnxD54b9gQOZ77daJGwffpk9mZs3PBf1PCTGAEO5w@mail.gmail.com>
Subject: Re: [PATCH v13 3/7] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kbuild-all@lists.01.org, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QmVi+zHf;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Feb 12, 2021 at 12:21 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 2/11/21 8:13 PM, Andrey Konovalov wrote:
> >>>> riscv64-linux-ld: report.c:(.text+0x5c4): undefined reference to `kasan_flag_async'
> > Let's do something like this (untested):
> >
> > https://github.com/xairy/linux/commit/91354d34b30ceedbc1b6417f1ff253de90618a97
>
> Could you reproduce this? I tried yesterday before posting the patches and my
> conclusion was that kbuild robot is testing on the wrong tree.
>
> I give it another go today, if you have more details based on your testing feel
> free to share.

I haven't tried reproducing, but the error makes sense. There's no
definition of kasan_flag_async for KASAN modes other than HW_TAGS.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By2kxnxD54b9gQOZ77daJGwffpk9mZs3PBf1PCTGAEO5w%40mail.gmail.com.
