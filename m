Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4N33GCQMGQE6F3EVUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 000573977D6
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 18:18:57 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id i102-20020adf90ef0000b029010dfcfc46c0sf5127296wri.1
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 09:18:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622564337; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gg0RE98hx9raEMbSuhsgCZZ+PrtGWy0ph7PakMHZQOA+okzfJH7Ru14/dYyAHmycug
         hTdBBPoNUqQS9f2alnFRg6bIe6fcPQDwRy/0hObRDrBiLyL9AfcakCjMZRO8EUPm2yIc
         eICF0jdBdx+XxIlE/Qc+e3gFlY1CfDqq+RzF4q/kjZSFSO+bb7LY9VJk7sw799DhW2h+
         TxpSuUSLKooLGOTBq9a56rxx7pl9bWPKECdv1UWnCVhCtEnXLxVjwvYUXIPcDti7i0GI
         WfKxU+/aguEwVxOCzSJD1LPneAOAARTqRCF7MkPrz1ZDa5zEiuPhWMJ3tVFfCd9SONwm
         a9Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xmgR7XITaet24K0vL5i5TJUt0fJit8TubNvNjCbdyjw=;
        b=mAN/DBQw2Sh3SCHtDHnJVoIJkQrChXrbTbNETU90qG9Std635wxtG3ZM3vjNAYf7uv
         bhyQJ7Y3kbg8gImE/5JbOf3vw7MXmrOA6nf3/CbqjgDNUM6kYG/+tGr2q6V5YWRaEBkI
         TujIMky3mYgIHXp2n8ydx+HnmLWTKTSfPs3mnnwaZ4BZWkHtbcdUUNv5dHvNQkBwlLpy
         A0ZOfGcyg7aoXvHQthXwKnjwp3fb9D+BqYczRingJ1iKh9xyphE8umMKcSDm4M/YYC0B
         50YvoaxV0btglV5PfuujsvlyWO3hz7fSXBaP0fflYdi+/etgh5xP01MzU7h3hZz0j6td
         IFjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JpgAT63u;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xmgR7XITaet24K0vL5i5TJUt0fJit8TubNvNjCbdyjw=;
        b=F24vSwtVeZgQtMm+xLkeLZhDut04RLlDFGPawcVkThlq1IWjlgPN/SG156BKlrh5Yx
         59grfcRCmwmp3hvT2GvXD0clGfdzFBYbnGBA0NAwlP6u3sgxXkfOyFyvAbj5si7hUFWP
         +D7vb7p6S6ODepT/VmvaE/iWbBgTSVXfi4I1t8YTUPU1+1BTnwJVT8UNoswMTDa1Hpqs
         ciBsoflzfNyB4vQPrfqnefAa47ch7lW3apfmma47xDZB1S5YSfdnPRiwx5iFoQ0WQrzj
         n7QIBUG36umkpWR4xLPUAFMNQSwin6nxRfhFo/Ty29B84jWhHDzGVpvs2yu0KSwVDc8Z
         lNTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xmgR7XITaet24K0vL5i5TJUt0fJit8TubNvNjCbdyjw=;
        b=RBIGqH/trg49SaW80Tu9ImrdMuBPlT4M3aNxw1dCEtCdIeoMXHpJzXA4a8prE6Jc38
         NZfHybyX9Dc+4adEmzJ51rFh8EyokNYrVyiZtuG3G/rTkBDskB8yzxzuv7+J35aMCiz4
         uiUD35qCdGS2S6mqy1Ve/2E3Ao3GrrC5dzEtAyOBlInH4yDKeK3cPpE+68qHFPR7Hk0/
         9Xd/7nGTMXPD3WsrZKgYvvAu98HCVuVVYoPFOlHJqQ7crncR5fPiYy2r74shQDxBDRof
         fHRuQ5/ELlER/uKPyBCGT0LaB+cYlPrns4Zqhn3e2Qz6g31eyyf6TgmSV0NVExVHrjxf
         FeeQ==
X-Gm-Message-State: AOAM532maTAbgsA1O0M8lfiK3CgbSn7CGDkUXcyr0oou0/uahb0UrqPQ
	3j0jNFWMefIbExkCRFPPDbA=
X-Google-Smtp-Source: ABdhPJx8/rB+Ie2lkomgmWsjjRBgaXVhXID1DhsgAmPCFEOQhp6lYu8wnaD5BVcEA3tQW6NCIn374g==
X-Received: by 2002:a5d:540a:: with SMTP id g10mr20031041wrv.254.1622564337538;
        Tue, 01 Jun 2021 09:18:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eac1:: with SMTP id o1ls2702226wrn.2.gmail; Tue, 01 Jun
 2021 09:18:56 -0700 (PDT)
X-Received: by 2002:a5d:43cc:: with SMTP id v12mr28919825wrr.215.1622564336571;
        Tue, 01 Jun 2021 09:18:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622564336; cv=none;
        d=google.com; s=arc-20160816;
        b=DauKG8ocd17dz9lI+GPBma1GO9+a5ZThTQj2Z7js5lNGemgts/VUtu/VZRxg0N5jcW
         p2xvKfFQR9+BjWeDhhZdpEzpFXoPbmGLsFh0tCA/ADte3dXhVPaFRyBXWTF7jicIm49t
         c+MlkcmOaZLkf4ldNZZYJruMBlNe1hbUpK89kDhgAj1X9eoklUa9gbL8uxQZINp2CQo2
         Vtc8W+PJ9v/+g3kPO9FPQCOC6viBZlJ8elmjn01LFc0JmyQZrBaek7aIxflAQJZv8Lci
         Q2ILbUwL1168RgWwcWhxaS+NTzpBTVF7/aUP1eBSOv6i4udCNxGCMysHm/hCSnMEXKH1
         PYmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UsBi4BTwK6C/LH3UWujbSRs4bcOQ4SZp9U47JqfClWI=;
        b=uNt0hz2Eji8AYJGi3nftR9L949rBw4JDiqY1CZV1RD2b/m1fOIxiWi9BZh3+Ok/8vK
         1AxMcaxJPVLZUOyof0shJzO4DmxaPhhzCf/0l2q6fsgejhNmBQNsxW92RFsZtIJ8b6Kf
         grz75/Kc2nDx4Sx8CLFQWaXSUHVxAs7hsdKO/IApqac5XO85sOqusBYSusMrhqSkgHPj
         gPjY/Fpj0FPa90AiMMVJ4JTy632VNu8hxpGhYatuCZBMhlaJI7PkllDpTgGhVulkZ0aA
         MkFFxmDMxvUdwrhMtZFzEeA8RGOtzTmVqYKYCYAo549YkmCAbkN4B8POucTL/s0Tq0ma
         tX+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JpgAT63u;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id s13si241634wrr.5.2021.06.01.09.18.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Jun 2021 09:18:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id bn21so12745018ljb.1
        for <kasan-dev@googlegroups.com>; Tue, 01 Jun 2021 09:18:56 -0700 (PDT)
X-Received: by 2002:a2e:9912:: with SMTP id v18mr21856163lji.42.1622564335977;
 Tue, 01 Jun 2021 09:18:55 -0700 (PDT)
MIME-Version: 1.0
References: <YLSuP236Hg6tniOq@elver.google.com> <20210601154804.GB3326@C02TD0UTHF1T.local>
In-Reply-To: <20210601154804.GB3326@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Jun 2021 18:18:44 +0200
Message-ID: <CANpmjNNOoVg5hcm0-omi-CB9zPVnKxBdCir1WmD0rMpoAQSOjw@mail.gmail.com>
Subject: Re: Plain bitop data races
To: Mark Rutland <mark.rutland@arm.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JpgAT63u;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::22b as
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

On Tue, 1 Jun 2021 at 17:48, Mark Rutland <mark.rutland@arm.com> wrote:
> On Mon, May 31, 2021 at 11:37:03AM +0200, Marco Elver wrote:
> > Hello,
>
> Hi,
>
> > In the context of LKMM discussions, did plain bitop data races ever come
> > up?
> >
> > For example things like:
> >
> >                CPU0                                   CPU1
> >       if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;
> >
> >       // Where the reader only reads 1 bit, and/or writer only writes 1 bit.
> >
> > This kind of idiom is all over the kernel.
> >
> > The first and primary question I have:
> >
> >       1. Is it realistic to see all such accesses be marked?
> >
> > Per LKMM and current KCSAN rules, yes they should of course be marked.
> > The second question would be:
> >
> >       2. What type of marking is appropriate?
> >
> > For many of them, it appears one can use data_race() since they're
> > intentionally data-racy. Once memory ordering requirements are involved, it's
> > no longer that simple of course.
> >
> > For example see all uses of current->flags, or also mm/sl[au]b.c (which
> > currently disables KCSAN for that reason).
>
> FWIW, I have some local patches adding read_ti_thread_flags() and
> read_thread_flags() using READ_ONCE() that I was planning on sending out
> for the next cycle. Given we already have {test_and_,}{set,clear}
> helpers, and the common entry code tries to use READ_ONCE(), I'm hoping
> that's not controversial.

Interesting, please do Cc me as I've been thinking about if we can add
more bitop helpers to avoid having to READ_ONCE()/WRITE_ONCE() or
data_race() the accesses, which thus far never looked too ergonomic.

> Are there many other offenders? ... and are those a few primitives used
> everywhere, or lots of disparate piece of code doing this?

AFAIK it's all over the kernel. For example all current->flags
accesses somehow suffer from this everywhere. Also various accesses in
mm/ (KCSAN is disabled for parts there for that reason), and a bunch
more in fs/ that I keep ignoring.

> > The 3rd and final question for now would be:
> >
> >       3. If the majority of such accesses receive a data_race() marking, would
> >          it be reasonable to teach KCSAN to not report 1-bit value
> >          change data races? This is under the assumption that we can't
> >          come up with ways the compiler can miscompile (including
> >          tearing) the accesses that will not result in the desired
> >          result.
> >
> > This would of course only kick in in KCSAN's "relaxed" (the default)
> > mode, similar to what is done for "assume writes atomic" or "only report
> > value changes".
> >
> > The reason I'm asking is that while investigating data races, these days
> > I immediately skip and ignore a report as "not interesting" if it
> > involves 1-bit value changes (usually from plain bit ops). The recent
> > changes to KCSAN showing the values changed in reports (thanks Mark!)
> > made this clear to me.
> >
> > Such a rule might miss genuine bugs, but I think we've already signed up
> > for that when we introduced the "assume plain writes atomic" rule, which
> > arguably misses far more interesting bugs. To see all data races, KCSAN
> > will always have a "strict" mode.
>
> My personal preference is always to do the most stringent checks we can,
> but I appreciate that can be an uphill struggle. As above, if there are
> a few offenders I reckon it'd be worth trying to wrap those with
> helpers, but if that's too much fo a pain then I don't have strong
> feeling, and weakening the default mode sounds fine.

Because I'd also prefer to avoid weakening the default, the new rules
will not be enabled by default. But in the past year, I've found
myself trying to keep on top of new CI systems, robots, or drive-by
testers trying to use KCSAN, and every time there is significant
negative feedback because of too many of these trivial data races that
not many care about at this time.

One recent discussion in particular [1] prompted me to have a think,
and I realized we need something simpler than writing long
explanations to avoid discussions derailing. Having an even more
permissive mode might be the simpler answer to those cases until those
folks come around (gradually, or perhaps not so gradual by e.g. a data
race crashing their system).
[1] https://lkml.kernel.org/r/YHSPfiJ/h/f3ky5n@elver.google.com

On syzbot we have several stages of moderation (although initially
I'll also enable this new mode on syzbot). But every time I suggest
moderation to other CI systems that enable KCSAN, they just disable
it. So I'm trying to bridge the gap from both directions: fixing data
races, but also making KCSAN more permissive. Once we reach a point
where KCSAN is mostly silent, we can then gradually make KCSAN
stricter again by tweaking options.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNOoVg5hcm0-omi-CB9zPVnKxBdCir1WmD0rMpoAQSOjw%40mail.gmail.com.
