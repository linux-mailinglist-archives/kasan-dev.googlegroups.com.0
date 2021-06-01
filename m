Return-Path: <kasan-dev+bncBCJZRXGY5YJBBNX63CCQMGQEXAOP5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id D093839750A
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 16:07:51 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id c19-20020a0568303153b0290315c1232768sf8791903ots.9
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 07:07:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622556470; cv=pass;
        d=google.com; s=arc-20160816;
        b=KC8fusjivnAYZg4lqjX9nF5XxjlPL2ibQg+9Od8tShtQFiYxHmajVXdSGXXCIp8YJl
         pWJU6ru28yQYs19ExVFjNovWorgudHdpeSkoLqS+kLA07OwckyA6dejNbLv9H4f0pkUE
         BN/KgYzwdkJN4D0BUplzPb2jexwL8Q6jtYUZ3kWrEMYK7pBopB5Aqkuy3kgYE/W1jrLZ
         BxFJPTbdx05Qx0+P43tN+GT0L6Z4I2QJIilXjPUag7j9BWO66vV9zX+0m4KMOt9dj+yM
         dxg8Of8XHTfGMeStcLHqcpFWlArSD5RPxw4RGQjZfCm0PsFA1g0VwPMhmaujCEkJHlZ+
         U+7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=nxYtR8yeXOqdXwym+eP/q6ZsJiHwBoJbumDeJrrpw9A=;
        b=s+pArzoZud5MuClkfA0HtYp3KCohBrZmMPHfcXMnVBZA+hEP49qmuKHyVcYPf4R4iU
         3ALAjusBQhLS9RO/x2lxhKfmMzvbAuxbFmfF4So89AqJuEruUBLM3DqMW/ZKeX+W5mR6
         FP7BQ6kpwZWsoWfaVGcQDLpcrurMxLU8sAuhC4Ut9R7S9CIyCbtTI5D3MhqNWYJ0JgRw
         fCPHnGw4oHQU8sl6d+Aev3uccOJ4atXFqeyDkZjU7Ijf4/wtT4t3xgHsClOxFLLe7iHr
         uPOBM/54fDvZ5N2Pq1MQQvqHTL/qbL8nLh1X2IeqIFvWP3+HNZhhdnbUifO+EDQUZ+95
         XhaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oFV0zJs4;
       spf=pass (google.com: domain of srs0=z9fb=k3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z9fB=K3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nxYtR8yeXOqdXwym+eP/q6ZsJiHwBoJbumDeJrrpw9A=;
        b=pPdYpNfpHYTKt/89yxWahjT/rnBVokbRn9qSqDenGFCGanm/Iir8uvIDrP8v48PwPg
         hKCCj/2Z0Awzeu1IWH+iIM5MJbTk0agPWBbq5KCU528uDBc0I7OG2BPtomteYwnRoSHa
         OnH81JFaBv0do9Kqs18u+Iun4FBvRezVNPQgw/83EF4xROZFudnEN8rksu+bsuIVqU+c
         9tsfqJ7aLP+GSAll8oJV1ndWsKQATR5s1fNfYf9AYarp+NaLG3BZp2izbZCRzTf77SxN
         sdMFwTRE5mS7ErWDfIcTzLLB9J+9Er0JDN2vTBWaYYsEBuU14WycXD+fIFbUOrGe0R5+
         AbLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nxYtR8yeXOqdXwym+eP/q6ZsJiHwBoJbumDeJrrpw9A=;
        b=YGdmq+Q9G5KsLoPh/pyE+dEYkSn/+fZvANwwg0Nicf8/ZcNZ6ef66W6LEIU9G/4bt2
         b0+xcnN9vyXVGbVHWBuErQEEUAuYEA+kDcE+7M7eYCT95wagZSNXPKEvrUNA3ZMhFBww
         raLFSzOT84v6pIVkVoXMuw3fS3HW4w7v00XpjyoQCtMyTVsvxFMSHRdM+8I/rVCakec+
         YTPF/o/rNAKkXuYYms415DAeFqL070rfpnXr0lpkgnCNoAJQLp6BIZzlUCuepE2C5VvK
         jlVGJNSOmLRm15Aq9rSsPp5kljOTX1H5yyOFZmZ3wAAEHjnm9NqEvbeCnBGEg390VMdk
         UBhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ojb/OrbjVDyR+teGe0MzxbbLNzXHVaa8G38V2E/EiZX70aHgt
	VSkdRmA8dBFGJqnMOyk/52c=
X-Google-Smtp-Source: ABdhPJyKw33sq5kaHCx55PtlP23+hVbg5BgI0jzhuEHB1JQjen0TiOHSxlHUZk9Iv7r9O4hkDLs1sQ==
X-Received: by 2002:aca:edc3:: with SMTP id l186mr10616275oih.43.1622556470818;
        Tue, 01 Jun 2021 07:07:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5903:: with SMTP id n3ls3778516oib.6.gmail; Tue, 01 Jun
 2021 07:07:50 -0700 (PDT)
X-Received: by 2002:aca:3707:: with SMTP id e7mr18041620oia.17.1622556470371;
        Tue, 01 Jun 2021 07:07:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622556470; cv=none;
        d=google.com; s=arc-20160816;
        b=lVso/pzWzN1MlUmsRQbRrDoVk+nblgW7zG1Xe2lPchY6YtSlu9EATU1OceyqFOCOOc
         /iREknJwHN5tR2+FmLFkxvD9nrBgebUJ/OwX5fXgKQr8KiG0ja6QMSCgRI9pcbcY7+ZW
         ALkR9vmou1yncJLT0ZvPjt8WJ3x8Mhc9AU/PqqzFLcPn9fku+BzkB+BC0eqdfg4WqwqQ
         ro80RWELAu5fi42szVvm9iq1oKP9P6AfMgDInpHo+P+iw7O9pu0/V1GZmmBhGHQnv++j
         qiYbre4kiIIsEPKmhfVjzAnG6vsb1JPKQGgyz0ghg/nEs7n2KNjE4hzpZPvQwb9kzRO1
         C/dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AwhVkRdEjXdckz0bdw+PtyE+IM93fNfuyV6PCPKn0Mc=;
        b=nz5ETsKEU+76FBu2dhCiutP0A8lOhsr6HVEnSaoKswhsBpqqMi9gQmGNG7HxdbKWmI
         KColJHlp+w/G76Xw0btyXvr7UYohfGkkTZPEJjNR+pdjzo2xuDaDFLQPb+6KDg32xyj1
         YsZ5FWk6k++8hUZe2FM5O0Svll/qHuDyIrNQyrjNgObTRIp2hjMka5u2rzK/7e6Kfwhg
         epmsOsi4cYt1lmjyqJYC7fecBr0u8gh8t6iDvoyOZ862HF0mh3fIbJ3nsB6raQJ2wZBK
         ZrOlD0bovHfmf/+YWHh1j8Xy0Jaxhp0xaZ3baed63HkN9EagZMWCfLNIMKhG3HGME+O5
         tp2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oFV0zJs4;
       spf=pass (google.com: domain of srs0=z9fb=k3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z9fB=K3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k4si1677615oot.1.2021.06.01.07.07.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Jun 2021 07:07:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=z9fb=k3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6D08B613B9;
	Tue,  1 Jun 2021 14:07:49 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 3475E5C014A; Tue,  1 Jun 2021 07:07:49 -0700 (PDT)
Date: Tue, 1 Jun 2021 07:07:49 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Plain bitop data races
Message-ID: <20210601140749.GM4397@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <YLSuP236Hg6tniOq@elver.google.com>
 <CACT4Y+byVeY1qF3ba3vNrETiMk9x7ue6ezvYiP8hy2wWtk0L1g@mail.gmail.com>
 <20210531160636.GL4397@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNNAUWtcmLDYFw2s+oePs+7N6nMeB7k2Mkm3RQQCbGxaiQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNAUWtcmLDYFw2s+oePs+7N6nMeB7k2Mkm3RQQCbGxaiQ@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oFV0zJs4;       spf=pass
 (google.com: domain of srs0=z9fb=k3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z9fB=K3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, May 31, 2021 at 07:24:56PM +0200, Marco Elver wrote:
> On Mon, 31 May 2021 at 18:06, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Mon, May 31, 2021 at 12:25:33PM +0200, Dmitry Vyukov wrote:
> > > On Mon, May 31, 2021 at 11:37 AM Marco Elver <elver@google.com> wrote:
> > > >
> > > > Hello,
> > > >
> > > > In the context of LKMM discussions, did plain bitop data races ever come
> > > > up?
> > > >
> > > > For example things like:
> > > >
> > > >                  CPU0                                   CPU1
> > > >         if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;
> > > >
> > > >         // Where the reader only reads 1 bit, and/or writer only writes 1 bit.
> > > >
> > > > This kind of idiom is all over the kernel.
> > > >
> > > > The first and primary question I have:
> > > >
> > > >         1. Is it realistic to see all such accesses be marked?
> > > >
> > > > Per LKMM and current KCSAN rules, yes they should of course be marked.
> > > > The second question would be:
> > > >
> > > >         2. What type of marking is appropriate?
> > > >
> > > > For many of them, it appears one can use data_race() since they're
> > > > intentionally data-racy. Once memory ordering requirements are involved, it's
> > > > no longer that simple of course.
> > > >
> > > > For example see all uses of current->flags, or also mm/sl[au]b.c (which
> > > > currently disables KCSAN for that reason).
> > > >
> > > > The 3rd and final question for now would be:
> > > >
> > > >         3. If the majority of such accesses receive a data_race() marking, would
> > > >            it be reasonable to teach KCSAN to not report 1-bit value
> > > >            change data races? This is under the assumption that we can't
> > > >            come up with ways the compiler can miscompile (including
> > > >            tearing) the accesses that will not result in the desired
> > > >            result.
> > > >
> > > > This would of course only kick in in KCSAN's "relaxed" (the default)
> > > > mode, similar to what is done for "assume writes atomic" or "only report
> > > > value changes".
> > > >
> > > > The reason I'm asking is that while investigating data races, these days
> > > > I immediately skip and ignore a report as "not interesting" if it
> > > > involves 1-bit value changes (usually from plain bit ops). The recent
> > > > changes to KCSAN showing the values changed in reports (thanks Mark!)
> > > > made this clear to me.
> > > >
> > > > Such a rule might miss genuine bugs, but I think we've already signed up
> > > > for that when we introduced the "assume plain writes atomic" rule, which
> > > > arguably misses far more interesting bugs. To see all data races, KCSAN
> > > > will always have a "strict" mode.
> > > >
> > > > Thoughts?
> > >
> > > FWIW a C compiler is at least allowed to mis-compile it. On the store
> > > side a compiler is allowed to temporarily store random values into
> > > flags, on the reading side it's allowed to store the same value back
> > > into flags (thus overwriting any concurrent updates). I can imagine
> > > these code transformations can happen with profile-guided
> > > optimizations (e.g. when profile says a concrete value is likely to be
> > > stored, so compiler can speculatively store it and then rollback)
> > > and/or when there is more code working with flags around after
> > > inlining. At least it's very hard for me to be sure a compiler will
> > > never do these transformations under any circumstances...
> > >
> > > But having said that, making KCSAN ignore these patterns for now may
> > > still be a reasonable next step.
> >
> > Given the "strict" mode mentioned above, I don't have objections to
> > this sort of weakening.  I take it that if multiple bits have changed,
> > KCSAN still complains?
> 
> Yes, the prototype I have would report anything >=2 bits changed. I'm
> trying to still report anything that looks like an ordinary bool
> though (i.e. value transitions 0->1, 1->0), because these might have
> interesting memory ordering requirements.
> 
> I'm still experimenting with it, but it does get rid of the majority
> of data races on current->flags, and various other flags e.g. in fs/
> that I think just nobody wants to mark.
> 
> > Should KCSAN print out its mode on the console, perhaps including some
> > wording to indicate that future compilers might miscompile?  Or perhaps
> > print a string the first time KCSAN encounters a situation that could
> > theoretically be miscompiled, but which no know compilers miscompile yet?
> 
> I think I'm too afraid of giving any sort of advice in console
> messages regarding assumptions about the compiler, because it'll be
> taken at face value. The part about "no known compilers miscompile"
> might be "good enough" for some. So instead, I'll try to just print at
> boot if KCSAN is using strict mode or not (and also suggest to enable
> strict mode to see all data races). Plus the various Documentation/
> and Kconfig text adjustments.
> 
> Given no huge objections, I'll send an RFC soon.

Sounds good!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210601140749.GM4397%40paulmck-ThinkPad-P17-Gen-1.
