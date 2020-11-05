Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNOZR76QKGQEEQQ4SIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 902A32A7E61
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 13:14:46 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id z12sf1324854pfa.22
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 04:14:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604578485; cv=pass;
        d=google.com; s=arc-20160816;
        b=0fsMod2XKLDEZyeVsakdSod3xKn/N0Wfs876cKkbJl77yOwzfPO5Np+oDHgNWfVrC2
         2EpL3EPvd/sxvXYKPWXA4NuUyH8kuZQ4ycl01fx7lpXvHrC029iuhl6mNLPSD5en+u33
         jRTZb2AJla/ijHXk2t6jm5WJnHwKZZ4guJF0nMk22A1kDoa87XLx4cfexrgHccxpa9I/
         pNlfTo8UUIUY+DTX3l6NMxhXMRvxk4LiRK7j+VR9XTe1HYEsdOhp46QG9egUEF4cmdcc
         bOJU3l1TwfhHKa+tKQZXXGWz166zrzz46ACNQDL0gEqJvHGZKidyv5SKWvIJLzPkMCfm
         oGsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VTGLrOWitNBYARV46XdL0Nvr6qTJ1msznMtlfeq1zuk=;
        b=p8HRCEwDoeVxbaySeWM/Qg5gJoiY1sihZ1q2RI+MO7PIOcxOY/C8O1Oq2MoZIO24cW
         9eTZil5ez4SfyFFV1A+sSutX2TpWcw1KfvUULueGysFi+wbV31BJMc5/PLNCWaLuENPA
         nK9icyEyFfjuEsnt9zszVMKKIlZT5bNctu7Uq9bGleprd4SVnOJ70ngvmPCy0Ly9Sw/r
         U3zXAkpru2iduT6WD12ZRy9YhzHRmK684DZp/InlbcwPWq+U85Nu3e+2hJs6CSm6+ZYv
         2J+S+bmQ9aGAlezn65dE7t9X3Pheii0Uh0nfHOJ/n2+OyPLxYQUnFpgfdfHokV1KHCCW
         R5SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UcB9WgQU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VTGLrOWitNBYARV46XdL0Nvr6qTJ1msznMtlfeq1zuk=;
        b=JmB7ivAud8tbEt3ts/K1v3H20Atrk/1YAcw21kkmvANDj09CFCOU1h7G5tWGz3I7wA
         K3sRDe/M5q4oisqD1lPnrKvsJpS7T0BUDnQE2NxsK5kJXSpIa8Dsr4ys/b/Eu93vNAnT
         do3UInMOPKWBdbjqhSWjWlgiR8L0jPCX1kM8fW35gj2nGMhtrC+nwKRJumB4t11oXgDH
         Nr9ONlN4C0sqD8M+qkLodsDTrqORHZ/B7HcMc/skTNqT1P2+oRDRf6U4lY32iR5PTPxD
         d4a4P/D92SJCdVjufYdrq6SwMMKACQqgK1MzpfRgKlW7GCTq6lAd0cx2MHqGR8k+InfF
         4wWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VTGLrOWitNBYARV46XdL0Nvr6qTJ1msznMtlfeq1zuk=;
        b=JiJHt3CBasOA/x3bFyA5fH4U7ZLf9IvsmMjet+ZRdQfPejmlKEgN6zTLqqnnwSCNxU
         e1ulg0hqZ5j2wGS8/p+97vLVTB+JYMGT9fBGPb4QP78EwRy7nsFVlXrHeAAogAy3NxGv
         mBbZBYBfUNjUUkSnqsiaUK6xkxvPM9otbiPGCWwtHq2Gc/8LjVwe8i/XWFXw6Hc4gSKH
         NmK6A0cOhQB6ost/gjpuyYm2JmABjFuorWCMVKx81bK3aK0AIrdFHNcuvLE/aLpLpQYn
         Ur5oBenegsgp1fs/SoUJfi2Q6BHLGqRL+22LOnXSFfXuwj+1x4K1pJZHUrpzUQnomNEN
         pTrQ==
X-Gm-Message-State: AOAM533bg9cweVJ7ho2EasbDprnsvsO8yn2lNtY2TfuaH+VRA6zdFX3B
	PzDfBB96m61+cj6za3NZCng=
X-Google-Smtp-Source: ABdhPJySFSqlPAYSxhRAbGK8R+bDSdosRwSrmpuCbWvvHR07YjZm+001P4QQWSgpgO71BtFyc6XxQg==
X-Received: by 2002:a17:902:7408:b029:d6:8208:bc7 with SMTP id g8-20020a1709027408b02900d682080bc7mr2199906pll.82.1604578485246;
        Thu, 05 Nov 2020 04:14:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8616:: with SMTP id p22ls739841pfn.3.gmail; Thu, 05 Nov
 2020 04:14:44 -0800 (PST)
X-Received: by 2002:aa7:950b:0:b029:18a:df47:ef90 with SMTP id b11-20020aa7950b0000b029018adf47ef90mr2219107pfp.74.1604578484734;
        Thu, 05 Nov 2020 04:14:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604578484; cv=none;
        d=google.com; s=arc-20160816;
        b=yzUqGfNv+YBWcDghutG4XkcPHurqUqm6xvrozVFOqx6t8T1OHSxTki6t/QxQl2Ujrz
         H3uwU/7u80eYJoV5iwgPyeROSJ6UbWD8QodqUqUpAVftJ/Bm+4wFfwtwvX6iom3a/Erb
         zW7snDneRi66mdogI+EbCbLUz3irvtfq4Vm40iZ2CrINC1tYf1CLDaPca+bsv8ammLZi
         scBhwf+DqX/Q2yJZF0pFufG2B06kV/8qE7JpXlJUXAhkKrZcZXML7peEGqNzBeu+t4S4
         EeStJsmmOD8jYxgojDH+FX2ydr5D1cNMv9OaRMNVsu5roCZInfhv3/wXP1MHGhndyZOK
         SL9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ef2UKiaY0UPMW9RqmrlSoTPjHgSZ5RMf4W5kfRO/DMA=;
        b=Xor/DA7nJwolOJ8BO3VxPWgO1pciBWbeXiOLJi1TmqITAfVPOHv22F6IjbjQm7TFCM
         er7OHa0ITT1IrqUcD+qY3eqFQ/jcCNMyB8B0QQ3E0HQeIoRZSG82KnQ3fNwH6dGUDbtF
         d9peHIEqEbE3jA93OHzEvprpfkSpIN2Kz/N7ufHS3cN+VhUGjgx4uSmll/49HKRm6w/y
         ASpA59sR3TgDq6zYqe7YDYLbWelM7jlbwMpS+HVFCPWOCYK+yFlwGYf96T1QMTWIwPo+
         gp6lWm8XNHy5UiKtTJD7tYdkZA+bMiXbHFvrYeqMx5F/TI/SD3aag3xDte+gQdxcoUHw
         MW9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UcB9WgQU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id j63si125238pfd.1.2020.11.05.04.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 04:14:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id g11so685559pll.13
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 04:14:44 -0800 (PST)
X-Received: by 2002:a17:902:e993:b029:d6:41d8:9ca3 with SMTP id
 f19-20020a170902e993b02900d641d89ca3mr2100463plb.57.1604578484325; Thu, 05
 Nov 2020 04:14:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com> <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <58aae616-f1be-d626-de16-af48cc2512b0@arm.com> <CAAeHK+yfQJbHLP0ja=_qnEugyrtQFMgRyw3Z1ZOeu=NVPNCFgg@mail.gmail.com>
 <1ef3f645-8b91-cfcf-811e-85123fea90fa@arm.com>
In-Reply-To: <1ef3f645-8b91-cfcf-811e-85123fea90fa@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 13:14:33 +0100
Message-ID: <CAAeHK+zuJtMbUK75TEFSmLjpu8h-wTfkra1ZGV533shYKEYi6g@mail.gmail.com>
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UcB9WgQU;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643
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

On Thu, Nov 5, 2020 at 12:39 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> On 11/5/20 11:35 AM, Andrey Konovalov wrote:
> > This will work. Any preference on the name of this function?
> >
>
> I called it in my current iteration mte_enable(), and calling it from
> cpu_enable_mte().
>
> > Alternatively we can rename mte_init_tags() to something else and let
> > it handle both RRND and sync/async.
>
> This is an option but then you need to change the name of kasan_init_tags and
> the init_tags indirection name as well. I would go for the simpler and just
> splitting the function as per above.
>
> What do you think?

OK, let's split. mte_enable() as a name sounds good to me. Both
functions will still be called one right after another from
kasan_init_hw_tags (as it's now called) though. I think the name
works, as it means initializing the hw_tags mode, not just the tags.

Will do in v9.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzuJtMbUK75TEFSmLjpu8h-wTfkra1ZGV533shYKEYi6g%40mail.gmail.com.
