Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH472GAAMGQEIRBW73I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 954ED308C2A
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:10:40 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id p24sf3905654otl.10
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:10:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611943839; cv=pass;
        d=google.com; s=arc-20160816;
        b=e103T+Rg6ECoYSf9p5rG1iICgep+MjbzXOupFvG74rXjkF1V9O3zL2ydHI31JSIr3r
         jwzdi6T1gTftSA/pSsXK07UJVre8T8AVKOGS802duBWkAMT++kaK7JZu3ji5BIQd8tk2
         L2s50MWNrx+Me7dMIhiWyAqLOkOrUEt6AQeAZ1wNLFrg2wfXfBd5G+3EBmp947mb2kZQ
         TVbhMC6AaEeaQW+s7Cb98x3njBvmiFX0DENcPXXWWS1sFMeocylywkqIuSFcPMTaQdoo
         M/PPYFEqUPQLAGBupGQWLjesOx94g/Fon9guBHYbGU/4Sw9pV0II8UrdA2AWGcxiU0rs
         Fh5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=v93E+0qvGcs5hr5J8QYaPB0yf/LzRadniDuPnnIjnSI=;
        b=eLT7GbGFp1+LLTYnHPtgN8y2+JbfuJ3sJzDQQ6AcS493tB+UVn7Z+TSwbq/XJuB+yT
         ILZWTMWTD/zCA+z1hIZ+EetXdJoebXRkJMNUKm6XYHXRVXYbiYRkpzAuJGm+c4gcjmz+
         NT+Y/nxxYPfeFX8JrbaB69HgUGUwT/Z/Twysjm8LvXTNavXPIXSOn0lT4XgUUzC+C+/C
         uMA6fz7Sz61whoSNvnW+1Go84uIcefv5vWGL4ucBnlOQyxAYPUfsWrbb00ZSvO4HIYyx
         5DIoI+Ns3hEYjfuuuqxqWo8U4cOqbIR66f202DhkFfNJhZDBcdK+1SrhHH7dqarivFnT
         GiKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uw1AfPuP;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v93E+0qvGcs5hr5J8QYaPB0yf/LzRadniDuPnnIjnSI=;
        b=PSLE1p2expiQUy7oAEt1XUS9z1CjWVgIh9/d2X60G2h/K3+umyPfFj0zRE2DtYJhW/
         ixmVm32tHiEOPPB4QRJJ/9J2Vu2+Nq1bzPkdi3vgi+i9lRojTUKE5rTd3NAkoZ09QoAu
         tdvOUVAKpEjczVwivjRZ+r+KtXrz1bdyf5SMTONTJkSkJlvvp2QHMrdpX130MvSSK/Me
         im3udVAVjJTsk4cGetStGE2xE4AVlIahMjYEIJT+zFNLdkt8lJZNkxITEjiPSzx4MEuv
         xY+ysMiRopgctuMUA0nD7fqp5kF8snADNFYyjLwNTggt5kCupwQmy/bphahOJUwp10NY
         XNiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v93E+0qvGcs5hr5J8QYaPB0yf/LzRadniDuPnnIjnSI=;
        b=WpVAVR9gK5qF3vwhNRIUtiEfnSUcKDo6X/dgz+GWGW82go2l8vlxl0zN+FXiyOD0k0
         XqQshylK9pHNE8ORB/IqbzfoPZGBG4UlISGMAXGq2LyGGOH4XtyQg+M4GMwLF+R5SxmZ
         sO6qbUK6Ri/khifEpZWPcbmm7Zx5Ueujn4rWxV9NY7dzPVOfy7VreIYA536ZjltyzBL3
         fyjHmN1n4RoTSPHZI6p5HZ2C+yhzXC6yrbJtuMOqyL6eG05JgpscF4QgcXKJZl5mYB9y
         2EwZ3Y3GiYlADPIEmO/NktQ04XcOE2hTB1jutfZ37yal+EGYntgd6+LI2UlVYGN2R6WV
         zWOA==
X-Gm-Message-State: AOAM5308kgaqgzicc9nvnFvXjhv8F/SJ1US6p90eOnnGbCisv2tD2+i5
	SGaLr70bkRl6DTNkwXWLi/g=
X-Google-Smtp-Source: ABdhPJwRqYJT1xh6X7ZFrKS39iCiv6762no6MDEAXKtUcY6KCw805TYhQJH+Ll9UWGntXHrrlWhpug==
X-Received: by 2002:a9d:2925:: with SMTP id d34mr3537444otb.291.1611943839419;
        Fri, 29 Jan 2021 10:10:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:3cb:: with SMTP id s11ls610777ooj.5.gmail; Fri, 29
 Jan 2021 10:10:39 -0800 (PST)
X-Received: by 2002:a4a:b387:: with SMTP id p7mr3874368ooo.82.1611943839047;
        Fri, 29 Jan 2021 10:10:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611943839; cv=none;
        d=google.com; s=arc-20160816;
        b=oMAk08VpRLKUmFHKaVTsGM6W1J8IeJSgUn7tRreaTxws7PApNlPS21iT2t5D+/V/WS
         n+uL59LWyzail7n3zsVZ2AlH6I0OIe9XOJClt3hb5D5bxvZwC7zYHBUwSgW5bnvcFblv
         USulP8a/dKjkis82S1tcnMfRLUukgUH3Jjvn63JVGeMsTgABZeRveXqibfvyY7azcEto
         w90iZVT959WejuD5L8XXM+0DahJ6Lab+TsgdRp61nIxhoqJNPnaYTzv+H1RpHWeShvXB
         ClSpcKr0gtRyeHAxmb75YiAtV9N/pFH/7dnHy/REpfid6K12edryP6m+cyUuFIqLEeEL
         M/Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ih9nZpFKdQtp/jnR4XaYa4e6X54Ve9TzjAXS7ra/gr8=;
        b=dLQm9TECHnKPQ7RJKwspP9igHLhdzc29TtG9sAoCIF+GY0hqCFsbzBaC4BclfhCF5/
         LxhDQrkwv+7II1Rok50qV/2wvaXRDp4L2LDzkve0BrGvTbEK+ACgESrTDFUDKH6yQ/XJ
         e0qrU3FJ5mJ3cWXncO28wsF6HLkRZNxl4jyZl8vaoFOdNfcyQ9+un5uEJvZxbM2YVc75
         i/bP9k2Nb4nagzjpBEwzIiZ0Pil07R1FxlzYRAeDOadU6Q3YhQfwr0Jq9HBe1MgSPGVS
         nB3fh7G8z8+W2RdSmkga0MqIUU8Kpgat8MQSibi9yAfrNBsXUVD7If/TX65lQhzxzgtq
         BuFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uw1AfPuP;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id k4si530401oib.1.2021.01.29.10.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Jan 2021 10:10:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id y205so6717222pfc.5
        for <kasan-dev@googlegroups.com>; Fri, 29 Jan 2021 10:10:39 -0800 (PST)
X-Received: by 2002:a62:115:0:b029:1b4:c593:acd4 with SMTP id
 21-20020a6201150000b02901b4c593acd4mr5465555pfb.2.1611943838410; Fri, 29 Jan
 2021 10:10:38 -0800 (PST)
MIME-Version: 1.0
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <20210126134603.49759-4-vincenzo.frascino@arm.com> <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
 <77de8e48-6f68-bf27-0bed-02e49b69a12d@arm.com> <CAAeHK+xMWXpfLs6HuKN73e0p61nm+QrZO1-oXphJpjZprKQVKg@mail.gmail.com>
 <7da762df-6df3-e526-bec1-dc770709c00c@arm.com>
In-Reply-To: <7da762df-6df3-e526-bec1-dc770709c00c@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Jan 2021 19:10:26 +0100
Message-ID: <CAAeHK+zrkLpOe2aJjWVMPHbvSFMXAEP2+fJVZ-3O4E--4-2KfQ@mail.gmail.com>
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uw1AfPuP;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e
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

On Fri, Jan 29, 2021 at 6:57 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
> >>>> +#ifdef CONFIG_KASAN_HW_TAGS
> >>>> +void kasan_report_async(void)
> >>>> +{
> >>>> +       unsigned long flags;
> >>>> +
> >>>> +       start_report(&flags);
> >>>> +       pr_err("BUG: KASAN: invalid-access\n");
> >>>> +       pr_err("Asynchronous mode enabled: no access details available\n");
> >
> > Could you also add an empty line here before the stack trace while at it?
> >
>
> Sure no problem.

Just to be clear: I mean adding an empty line into the report itself
via pr_err("\n") :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzrkLpOe2aJjWVMPHbvSFMXAEP2%2BfJVZ-3O4E--4-2KfQ%40mail.gmail.com.
