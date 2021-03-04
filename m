Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFNQQSBAMGQELOWGK2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C2EF932D888
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 18:25:41 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 74sf1825681ljj.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 09:25:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614878741; cv=pass;
        d=google.com; s=arc-20160816;
        b=SvSaUB9IdTAGd4poed9Etay0PpbY7ckt7h6nYH8TBBWeCOLuyPcatFp9ZEaDIsffkw
         +ii1rw3BIG3JjB2ovbOG7jO8YC0XmDiXdwhghub76jeemA/S76TGvkiHFAr/nRjjuiJB
         Ablghjs8hkMKzcA0eGovlAIiupiOF936Od6THyvRJxOTjPpuEEvNH02l7e738xWYQibT
         iw3WYYOFYqy1oVc17iQFKFmTnBwCJeQri5ir/bs28qnaHxrQT3bhZ0cc5HbH8tbtr3nZ
         FP8KEz3guJdRtDybigqpPmx3W1B68hU3DpWa6dee5cSZd4fjzurZtmmqfmrZoxs7r3lJ
         tigA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=X+tyV3dyB726Um/YswgaTIxZCO9NGXeB0GaO+QkXIzU=;
        b=gi1e9vFd7SkRsyE3dgGhZ+khdyao7mGOvUp68KxkJ6pqpo2FAolqJsJyrCeJKscR9o
         Nr9LCBxHkdON1RHLtmBqeOPjrP57Bq/2hEA41Bem0f23GfKDrx4PNqZQIQHRVexEB12G
         uH3RFyX34N518UFi+icqMiCQ712kiOEpx7YlPu3+zGzVin7qTB0xe4T0+T9VQvx/qngS
         JCmX+pT7cEg3P/Fmux6sHVlQ7ueFIgEFTASpiBGBCWv57te1zCZhuYLgXJUCA2p6ZyIZ
         e9OY+cBkDKceg4jZh/oqJLbcokyTcAJoUmGa5iRQZp5UWZJ98DOGsHYCzkCrla9Btk0P
         QNxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mZ9ESMDy;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=X+tyV3dyB726Um/YswgaTIxZCO9NGXeB0GaO+QkXIzU=;
        b=p9TQgdyqBVUaSUlryep59FJc6mx4z30NT7kdSuz/mPLw6yb2chTbFpsjmWEr9dOAg4
         FmrHNzPFb9cz4C5nZcH5Tk9oFF8Al4ETf2PLL7m3wAL8/+0XIoSwp8f+SHKzRUY0mqS2
         RFe/qEkvjUPBz6DC2boHJNE11gpwoJs+FNcqEN8VA+0N15BilmZwpand7tbChO79Tf+y
         x4eKkX2aozBtE0A4Yy5wDQcaWse6mlDxJJRt7iJyjCJsPPefjQ5ITHCj0cEyyJIMcc43
         OfAg/C/5acfTM+11YY4BrhRfcIXTvxW3Tye6X72R11SNlV9Rg12LYSQo0fTU+6nnM9tA
         KLmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X+tyV3dyB726Um/YswgaTIxZCO9NGXeB0GaO+QkXIzU=;
        b=Gs1lbcovbCMxSajGSsut6OOfNySjitmkiOfGjfN5tbm3ji3HbKlkQXN8ChfEkMSR9G
         67M89bztobAcnVv2W//tY1gTKgIJ9orKTMqxTfcuIAoJ7t5K9s5HzZ18TaJAmTFjSoDV
         yafltmlwhKMid0+WuFzZ06XXU3M4Owzz6DlHXn6RZZc6SpA4ZmwkPZnkk//awTjkQb+s
         ic17mfNWs65bWWyUoh8O7A0JjNrB/BLjNHbaKmOSWdEpuK+nhE56uttNcHixOhQ2B0mL
         +/avbMh7MjRHiZ7XuAieek8xaOVcFYiRyGTRhfx1ul+jF9hk0s+j8XUg2x6gaLyFnUg6
         JzMQ==
X-Gm-Message-State: AOAM533+B4gt/obPetoaZ6ZOMoixcwLtFBq2z1EjArj8EP97IynOGvfP
	qvkJqYKvKgx6erFQ8BEMM+M=
X-Google-Smtp-Source: ABdhPJw2kPEHx5MYtS855lzMhlBKAOXknqUunfJ+jigcgQJBxAHD1sFdYZk7loqMNHJ7f/mUDp6XTA==
X-Received: by 2002:a05:6512:374c:: with SMTP id a12mr2994939lfs.34.1614878741328;
        Thu, 04 Mar 2021 09:25:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc11:: with SMTP id b17ls1326028ljf.7.gmail; Thu, 04 Mar
 2021 09:25:40 -0800 (PST)
X-Received: by 2002:a2e:9195:: with SMTP id f21mr2838575ljg.340.1614878740159;
        Thu, 04 Mar 2021 09:25:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614878740; cv=none;
        d=google.com; s=arc-20160816;
        b=QJzK5ytoY6kWGj3DneO+ciYhy/4tb3r+CrhKhLT9/0Ppg7AHpOgBwNa5eFTygoQCUN
         ymWPcPfx4CskxVn8Mi26cqKPIwhBTwOCC5sA2/NlBW0C29qh100NvEf27f4Q22XTziB1
         yYfAHsZOSoyJT70bMwuLvlkM6SfGuF5dmS03kS5vuqs4lLDa5ofXu/C5hngOU1jAddaA
         QNQie0cSStKcjozr+XTOp6CDNNiNGxII1DtAPwxHa6ZflfiKLs6JyRgIttLFOk/t4ldv
         uelVPVh0SATNa0d104ZI9209aOX3LYNAxEhjGEvwiQjRgBfmNcDq7NYmjPZLvKPSN2dQ
         L0xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=rF5Y4qiLYG77iew1mU5Rkg3muHLgwxb+EueWczzk7UQ=;
        b=CYI3mlyxCaoiUSSNQqYKRN5U5W7vVSqaZDqw7/AZsxpe05QsvRyFEgvVoFhsopMY8Q
         GKCGaBmnZqWPIWPhVc0FWQoRgI43S80snKVlol9YYw4Yyg2cp1Az5vlWnNJXJMoOzufo
         /lLXeyvr/ZCkp8GyvKdqXg5zC7BZLpjXhVn30tz6OTNPkLU9h14z6OXebMGDPH3Ve4yH
         p7LCHrR53t50PZAB8uKZkMtO9XbhMuW/yvpsvgNazeENY3CkFIYSPuFkaZCH3kB5fLa5
         ZZK4W1ufKYa2xv8RehkpQRCftDFcDxR1QmTw+IVP85gldlNJW9P30dazdsYLV/i9ISfP
         vk5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mZ9ESMDy;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id e30si5575lfj.11.2021.03.04.09.25.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 09:25:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id e23so8772141wmh.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 09:25:40 -0800 (PST)
X-Received: by 2002:a1c:c244:: with SMTP id s65mr5000395wmf.96.1614878739431;
        Thu, 04 Mar 2021 09:25:39 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:adef:40fb:49ed:5ab6])
        by smtp.gmail.com with ESMTPSA id f17sm36439007wru.31.2021.03.04.09.25.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Mar 2021 09:25:38 -0800 (PST)
Date: Thu, 4 Mar 2021 18:25:33 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	broonie@kernel.org, linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
Message-ID: <YEEYDSJeLPvqRAHZ@elver.google.com>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
 <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
 <20210304165923.GA60457@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210304165923.GA60457@C02TD0UTHF1T.local>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mZ9ESMDy;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Mar 04, 2021 at 04:59PM +0000, Mark Rutland wrote:
> On Thu, Mar 04, 2021 at 04:30:34PM +0100, Marco Elver wrote:
> > On Thu, 4 Mar 2021 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > [adding Mark Brown]
> > >
> > > The bigger problem here is that skipping is dodgy to begin with, and
> > > this is still liable to break in some cases. One big concern is that
> > > (especially with LTO) we cannot guarantee the compiler will not inline
> > > or outline functions, causing the skipp value to be too large or too
> > > small. That's liable to happen to callers, and in theory (though
> > > unlikely in practice), portions of arch_stack_walk() or
> > > stack_trace_save() could get outlined too.
> > >
> > > Unless we can get some strong guarantees from compiler folk such that we
> > > can guarantee a specific function acts boundary for unwinding (and
> > > doesn't itself get split, etc), the only reliable way I can think to
> > > solve this requires an assembly trampoline. Whatever we do is liable to
> > > need some invasive rework.
> > 
> > Will LTO and friends respect 'noinline'?
> 
> I hope so (and suspect we'd have more problems otherwise), but I don't
> know whether they actually so.
> 
> I suspect even with 'noinline' the compiler is permitted to outline
> portions of a function if it wanted to (and IIUC it could still make
> specialized copies in the absence of 'noclone').
> 
> > One thing I also noticed is that tail calls would also cause the stack
> > trace to appear somewhat incomplete (for some of my tests I've
> > disabled tail call optimizations).
> 
> I assume you mean for a chain A->B->C where B tail-calls C, you get a
> trace A->C? ... or is A going missing too?

Correct, it's just the A->C outcome.

> > Is there a way to also mark a function non-tail-callable?
> 
> I think this can be bodged using __attribute__((optimize("$OPTIONS")))
> on a caller to inhibit TCO (though IIRC GCC doesn't reliably support
> function-local optimization options), but I don't expect there's any way
> to mark a callee as not being tail-callable.

I don't think this is reliable. It'd be
__attribute__((optimize("-fno-optimize-sibling-calls"))), but doesn't
work if applied to the function we do not want to tail-call-optimize,
but would have to be applied to the function that does the tail-calling.
So it's a bit backwards, even if it worked.

> Accoding to the GCC documentation, GCC won't TCO noreturn functions, but
> obviously that's not something we can use generally.
> 
> https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#Common-Function-Attributes

Perhaps we can ask the toolchain folks to help add such an attribute. Or
maybe the feature already exists somewhere, but hidden.

+Cc linux-toolchains@vger.kernel.org

> > But I'm also not sure if with all that we'd be guaranteed the code we
> > want, even though in practice it might.
> 
> True! I'd just like to be on the least dodgy ground we can be.

It's been dodgy for a while, and I'd welcome any low-cost fixes to make
it less dodgy in the short-term at least. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEEYDSJeLPvqRAHZ%40elver.google.com.
