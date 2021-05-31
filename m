Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5FX2SCQMGQEZVTP2EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B98A13966FC
	for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 19:25:09 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id q63-20020a25d9420000b0290532e824f77csf10867967ybg.10
        for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 10:25:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622481908; cv=pass;
        d=google.com; s=arc-20160816;
        b=l+LQpbOUn4YZbKgwAbfl/HqJhfXiv3ZOnN7Qdi6ZK1VdX+ymfcgoY/k9HnDBvM5j/r
         Dn9JHLFA/kS5yKD58w/KsLqi1yPiUlix9UJ4/macBUTc5nZnjGrf4k1X8rrTsBKXB1L0
         85Uck8v+Zpy2VQ2lp/hJliJBT5Fp8NIgMC2uyC7q3vHQ4T2fTvnYMqGl/VNrGqmtTFfg
         RzLzGzm9DF0T8V+r1M21wGzaXJ5nbpE72D8l2UIG01XKqLv6rfcMQHLx6G4YPoByj+pC
         dxOU08pJYpup9XSHMXAlKEuV+oiGHHSunzhCd1smWBG5AkdgFcrYhE5UQ53QofdaeLcD
         EyxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qE9lNNdmt2vwU2qqXq3TPWkSR5cTgL1d7J1jFY4uJcY=;
        b=ZalUQ/YH/Yxgkym8Bms+gUxC3qHuKw+qMIwQgxl6f+GqaOe3aqPDrEsIWSbe1PonDH
         dHwBOXuJhSYLOjzRwl5GZT4Nx8anJ9dhey1srLBVqZ7/1BG1YybLpmab7n3K/FmgfvLp
         rD9ZIO3tarmhpWRkm1hqDurmxDz0a4gzDD+FsUvv8kPIU+yF778cuo7ry3SyC8NU9Tir
         eF91d5ucuWyWV8uK+75DXVIxYyA4Gc3uR8kPhvWTknDzH0BGrXZeQFZvddSfrJVWMUD9
         oFnSZiNpTVc5iH/dO1MqxQTPEQUm9cHgYM7i9Ni410zcdnAtT//j+NN3/eRoex4p0a7X
         Kwag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y2jMA3vE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qE9lNNdmt2vwU2qqXq3TPWkSR5cTgL1d7J1jFY4uJcY=;
        b=Yu2VIB0HLckAV/sBSSeketYPNIJm3bskr/X0zqPAVim0jsusgCyZb3r+x+pDLaZ2Pb
         qB2KaI47ERFOosseAIqQImInckvCW5tvQZp5UNRQmAOaiC4s/ZzWjIyIlF4hdM1nNrLa
         DgJ+ZwF4JRyoF+pZ3ifDGUu46BClQgkTfT/1zF72nxglMNnpoxBYF5AWZEKr7DZ+JPlm
         28fFk29HX0kF2ls7rYJDKivrBesIWH8lyVuyw46Ab51zFHukOeDmgz9+9UjgvEWwe9u2
         BTTmbK3FZFoC6RCnzQI0tASvWHcddY75i2p1yuGth7+oafeqxvN/icpeSt/IzsTHRYei
         e/sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qE9lNNdmt2vwU2qqXq3TPWkSR5cTgL1d7J1jFY4uJcY=;
        b=RWF7ThXdZ43pS8BecFFfXaT79K96hdFat/vGOCTYsT5EiNAfXOpnivBPImafdJaOSr
         /WhSM/iGjPGt9P8/IeWYYrQ6kC9nm+suHGeNYKCY/13mZndo2i7hxKqd2OOLIkqayqtp
         EzUQWr/ACxA4V4fwwbfjrkurrueZQwpTnCW+Ij3Z8bFhh1d72Lb/h8Y3OdDkTd0vd8p6
         LtLLv8uuJmObC3/wqHOdVOP1Eq0J6msvTyeHb2E5+yTfhM4qKEbPBYga7cCTllxkle+X
         kLYERDmYrrHAe5DCtLkk59NzHdU8oDvoRoaWkdH2L7O7U+tfqVZ4eolVAFNorW0fKe5W
         yHKA==
X-Gm-Message-State: AOAM533c+yuAOT59y2lCRXnecFRprSnlCZmBTQVNLc4uRWQ5A8zvYM/p
	7k9HWcZIrJ1FDc4tlgVEnxU=
X-Google-Smtp-Source: ABdhPJwiNgd5ecEiOoleDv64+NuglSeVbGaAAwPIR2W45ciU5zGUMlNzVR3Ymbs1ksSOcMrwvCj23A==
X-Received: by 2002:a25:4182:: with SMTP id o124mr13862736yba.27.1622481908726;
        Mon, 31 May 2021 10:25:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:702:: with SMTP id 2ls7258584ybh.3.gmail; Mon, 31 May
 2021 10:25:08 -0700 (PDT)
X-Received: by 2002:a25:2c0b:: with SMTP id s11mr32190260ybs.205.1622481908201;
        Mon, 31 May 2021 10:25:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622481908; cv=none;
        d=google.com; s=arc-20160816;
        b=Sn2ACV54SYPkVuqygdiOKXG0UbXyuRGEQxe69GmgxQai3u3l1CcjaxeGmANgo7fPsG
         6zzugZZVxG8ZAgnrDUSbYcqGIx2Kt4x+TFqR5VrzsPvR9BSKWz2glBLvE25M+OucCYH7
         QM1aBWWQCH919CqXX22J1Dl8p5TmREe0Xf+cepdlKDjRUyEnd14IDKFsSEUz9gsUfnY+
         ZTeTKruMDVGknjslIQQ9jLEVWS6WfXS5prTZv9lAp9WROuCVxcfKmi03mETikk8zvU28
         HJJeeU4meXZpq0fpIJD5w3nrLz1A0E86Jkc2+zP36Vi+rKKIhlKCfjrArgWxZ1+DtQmy
         x3JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PCUjmIEvmpxTCUGSI+hlxS/HFT44jbjD9la9gpGBzpE=;
        b=WW/TBvRnLlcJrkpjZUpFQopYAbLVFa+j43Trk+IarIo1JhGXUHM89PmrhJ+Zd8AH25
         djAOBu0dXwHb0fzmgkSvzLVARsyw6v6aIwT6vmENm7MgrzaRypcDOsHWG+e+jRDWiqfP
         LxiPPrhrg93j7aYkS/Vkv1HnNoDa9o+yJom8IcPGCT/UjMmuhrgROtzCBPTyFbfR7Fuv
         qQwRrzVuGaVjXhS8ZSRMWzc0q2vhCj734/U3o4XrSKwuZOYTYPEFcHFwNTBzFf4YRpqY
         X4fBAR+fw4Df2jUZvmaEU2ymFmL25RKzIo0eh9d2Oj02nZNRLQenOW18S0t9rJyzH5HD
         gg5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y2jMA3vE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id q11si988275ybu.0.2021.05.31.10.25.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 May 2021 10:25:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id i12-20020a05683033ecb02903346fa0f74dso11694569otu.10
        for <kasan-dev@googlegroups.com>; Mon, 31 May 2021 10:25:08 -0700 (PDT)
X-Received: by 2002:a05:6830:3154:: with SMTP id c20mr18475020ots.233.1622481907690;
 Mon, 31 May 2021 10:25:07 -0700 (PDT)
MIME-Version: 1.0
References: <YLSuP236Hg6tniOq@elver.google.com> <CACT4Y+byVeY1qF3ba3vNrETiMk9x7ue6ezvYiP8hy2wWtk0L1g@mail.gmail.com>
 <20210531160636.GL4397@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20210531160636.GL4397@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 31 May 2021 19:24:56 +0200
Message-ID: <CANpmjNNAUWtcmLDYFw2s+oePs+7N6nMeB7k2Mkm3RQQCbGxaiQ@mail.gmail.com>
Subject: Re: Plain bitop data races
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y2jMA3vE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Mon, 31 May 2021 at 18:06, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, May 31, 2021 at 12:25:33PM +0200, Dmitry Vyukov wrote:
> > On Mon, May 31, 2021 at 11:37 AM Marco Elver <elver@google.com> wrote:
> > >
> > > Hello,
> > >
> > > In the context of LKMM discussions, did plain bitop data races ever come
> > > up?
> > >
> > > For example things like:
> > >
> > >                  CPU0                                   CPU1
> > >         if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;
> > >
> > >         // Where the reader only reads 1 bit, and/or writer only writes 1 bit.
> > >
> > > This kind of idiom is all over the kernel.
> > >
> > > The first and primary question I have:
> > >
> > >         1. Is it realistic to see all such accesses be marked?
> > >
> > > Per LKMM and current KCSAN rules, yes they should of course be marked.
> > > The second question would be:
> > >
> > >         2. What type of marking is appropriate?
> > >
> > > For many of them, it appears one can use data_race() since they're
> > > intentionally data-racy. Once memory ordering requirements are involved, it's
> > > no longer that simple of course.
> > >
> > > For example see all uses of current->flags, or also mm/sl[au]b.c (which
> > > currently disables KCSAN for that reason).
> > >
> > > The 3rd and final question for now would be:
> > >
> > >         3. If the majority of such accesses receive a data_race() marking, would
> > >            it be reasonable to teach KCSAN to not report 1-bit value
> > >            change data races? This is under the assumption that we can't
> > >            come up with ways the compiler can miscompile (including
> > >            tearing) the accesses that will not result in the desired
> > >            result.
> > >
> > > This would of course only kick in in KCSAN's "relaxed" (the default)
> > > mode, similar to what is done for "assume writes atomic" or "only report
> > > value changes".
> > >
> > > The reason I'm asking is that while investigating data races, these days
> > > I immediately skip and ignore a report as "not interesting" if it
> > > involves 1-bit value changes (usually from plain bit ops). The recent
> > > changes to KCSAN showing the values changed in reports (thanks Mark!)
> > > made this clear to me.
> > >
> > > Such a rule might miss genuine bugs, but I think we've already signed up
> > > for that when we introduced the "assume plain writes atomic" rule, which
> > > arguably misses far more interesting bugs. To see all data races, KCSAN
> > > will always have a "strict" mode.
> > >
> > > Thoughts?
> >
> > FWIW a C compiler is at least allowed to mis-compile it. On the store
> > side a compiler is allowed to temporarily store random values into
> > flags, on the reading side it's allowed to store the same value back
> > into flags (thus overwriting any concurrent updates). I can imagine
> > these code transformations can happen with profile-guided
> > optimizations (e.g. when profile says a concrete value is likely to be
> > stored, so compiler can speculatively store it and then rollback)
> > and/or when there is more code working with flags around after
> > inlining. At least it's very hard for me to be sure a compiler will
> > never do these transformations under any circumstances...
> >
> > But having said that, making KCSAN ignore these patterns for now may
> > still be a reasonable next step.
>
> Given the "strict" mode mentioned above, I don't have objections to
> this sort of weakening.  I take it that if multiple bits have changed,
> KCSAN still complains?

Yes, the prototype I have would report anything >=2 bits changed. I'm
trying to still report anything that looks like an ordinary bool
though (i.e. value transitions 0->1, 1->0), because these might have
interesting memory ordering requirements.

I'm still experimenting with it, but it does get rid of the majority
of data races on current->flags, and various other flags e.g. in fs/
that I think just nobody wants to mark.

> Should KCSAN print out its mode on the console, perhaps including some
> wording to indicate that future compilers might miscompile?  Or perhaps
> print a string the first time KCSAN encounters a situation that could
> theoretically be miscompiled, but which no know compilers miscompile yet?

I think I'm too afraid of giving any sort of advice in console
messages regarding assumptions about the compiler, because it'll be
taken at face value. The part about "no known compilers miscompile"
might be "good enough" for some. So instead, I'll try to just print at
boot if KCSAN is using strict mode or not (and also suggest to enable
strict mode to see all data races). Plus the various Documentation/
and Kconfig text adjustments.

Given no huge objections, I'll send an RFC soon.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNAUWtcmLDYFw2s%2BoePs%2B7N6nMeB7k2Mkm3RQQCbGxaiQ%40mail.gmail.com.
