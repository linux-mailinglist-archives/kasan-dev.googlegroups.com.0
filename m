Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOU7S36QKGQEG677NZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A1C1D2A9B6C
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 19:02:35 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id m8sf810916otp.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 10:02:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604685754; cv=pass;
        d=google.com; s=arc-20160816;
        b=b58WnIpaT2+y8ghQP+nJxumsbblmHQUuHPU2ALwTXj/6uXChnrCOOK2IHmhyO2h4Hf
         g2VWpIgYTNiRoSNKf7HH1hT7H3ZUOjnOXCiinpss/Pd17j5umkl8TgQckclNKsWJCWXq
         kVpuPD9jz+oQWq7v+5zkaubWLIgn74cX2L9eV8plE7IgaS2yDL34glMOmNhlkuam6xYb
         E4Fe1kiKF5wMQz/FiFpLYXcSmzRV/Mi4W1YktIti9Hsb+otA/2ZSduY0HnM+sZESDHoS
         EHKs+Veh9yVvBVySKE87sdHrjLtPmH2nGVHOuLRjyr8x9iQz4r8bnGwz7CPu8a+2xM0R
         Wcxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9DgBQ8A0iagjANWdJT1WZKqyTauNWBjNrb00xBjCIK4=;
        b=QnRuAMKsnX18ekIzbvLfAXuzf+0VDo/W0ov+LMVELxZ/+za0IDoSf4aYdjcgRfiXp1
         H59vaHbqmNpDa4IoMT1eNRM2EGkaBamAzCtVHSZ8TEZQS+4om1dBHEq/8nZvBEBrKzKv
         uiOiCvCUXeS4gDzZ0uOHQ8wHKAY4etCEDfSPDCif+CjBpNTEAAG2KzfYEaakHUSOAth/
         zBZCnEDwL8Tg/6b/r/9K8DhxXxF7OeCw5fWOh5WuvKzCLcaM4OpCcnTRWsngFvIaO2QC
         ga7PwQmSfLIaPydDzUpsARmMLxtTQSFVqSZ3zWCbSsJdZasAe6J0vb0DdH1FB1ZtuzqZ
         a+Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rJqQ+ezp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9DgBQ8A0iagjANWdJT1WZKqyTauNWBjNrb00xBjCIK4=;
        b=nJZYoE5yNDHLG6st1ADB8CssdsKS2DXZUt69SYSEDcudlH/C+RsoWI5PJnlflgX6rN
         kXecRawvNG7L/O1mZ6vhINUQiAhjQWqUy3pZcRwQCBNx2l4hGEu6t/eo18yeCY/P826m
         grjfvaSibdwVjS6+NGaetYKqPI8yEgN0xEst6ZqsIdvHmlWFhpfdlpW47MZiLXJvbZru
         WbC1fatVW53wKlBf8H/rDwEOcxdOsBrN/9QgcC3hemMBBCExs8sxPHt/CjF0yGYxsMsM
         HfW4/er1NgTMVFfqYG9GwiGLIz/N29lcDfVcfgGe8ZwVsXcyPWsjGX9Q1qCALfDLQUiJ
         v7Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9DgBQ8A0iagjANWdJT1WZKqyTauNWBjNrb00xBjCIK4=;
        b=Xr6ybPCaQJkzXvdid1D/FkPuRZ1skqmCJbcWQjbPZp1UwBAS+Lm6iatsYeVAGYxZOb
         zSk7GjmBiRGMsVN8BplDOL/AfZrh67YhItahJJrd3nBjELWPfI7xWC/qs1R3tYNBmCRm
         dANm1ZWr9MlbRvKhH6r/BWsQN0MuLSev3cXNvDCjC0512m5X96TEaOqi6ogoCK1/Jcy/
         QpsuSpEtcI/Ytt8fa52mK4YvX520QcFxxjKb6PhPr5J1aDlBPE7g+YfraIZk99PbYkMk
         mnlma6lWgftbZXySbaGatwMZposwdHBJmha7Gr1ANOWL6LbspQfCcdwy0wXAqXyOdacD
         +FBQ==
X-Gm-Message-State: AOAM530u9ejEWB2WJWWvkfq69XwQjoMm8BNFhnCoETaKwT64fCdVUV5z
	nrVrKijqCz+MfnzigDPd0WE=
X-Google-Smtp-Source: ABdhPJxd7fCwuNUKUbAxEkp8yp8TTycFDNY054e48P+qX11P4ALMTHYORZqKHZ7UD8BTftldf5gnzg==
X-Received: by 2002:a54:4092:: with SMTP id i18mr1868261oii.62.1604685754287;
        Fri, 06 Nov 2020 10:02:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1a04:: with SMTP id a4ls566546oia.6.gmail; Fri, 06 Nov
 2020 10:02:33 -0800 (PST)
X-Received: by 2002:aca:5ac4:: with SMTP id o187mr1889818oib.112.1604685753928;
        Fri, 06 Nov 2020 10:02:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604685753; cv=none;
        d=google.com; s=arc-20160816;
        b=z5EyXuwtORd5C0S9K13mIF5oDv0qCDJnQjC3JdtmTnupy4fW4tB9sEBkPDg6Q6HfZj
         qZqr2eJB5kQgPetfSZyRtfr/NweZTlzgnQnFJ8znc3j1KFwlw9c+L8VjGlgbu/iJ7ziQ
         6fU5aFDx5oK52SzHgHHUx1Y1cPlHGZY59Sn/WeEKAsiCd+kC8wr1ZxBAgBQmMHE8lIfO
         QaoehFkmYkvI5wH9SP/pClxGLgeGs9+LIKsTZ7MvNCnKQ7NwrUG56QBqtr98WgaIl0ni
         rNEMfISrTcOP1kXe6SiOkTzcb1rsaul3Yf+TSM5tdr/Ei1pBiDj1N/s7P23t/RLTASdG
         EKcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SuZnUXRV2lEs5naW6vWNbEdcVnedstrBJWzqIoTCQjU=;
        b=oszGUov6qRco7ju18se77ECuAGRq4bo0BC5dO/wm0A9d8J8nZJzFEV2h/pYvvwRsLg
         4NBgBBwQhrFrOzIAmMnw3bjj1LndkTzIuTs+h4QbaA2+8gtO5NAOxr/21p1aeLpPIla6
         PGbx9SQ6Lf/1aDwSzavZCykQxPtGpNPBrC9d3dMhOkXBkll8ZpdmVQKY1cXlF2HUWpDe
         8Ch84xqZ29t+382yrAScqatRlXQtZcvdjaRYkxGpqO8mONkxp4wevG04EVXCxkX9kW9H
         7K8O+c804/sQqDZYE595Kvi5ofTSd1bd7iKo3/DK32OMG8WDeGTiANw3aYVJwh4AMUMX
         mh6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rJqQ+ezp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id r6si259615oth.4.2020.11.06.10.02.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 10:02:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id t143so2183453oif.10
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 10:02:33 -0800 (PST)
X-Received: by 2002:a54:4812:: with SMTP id j18mr1895231oij.70.1604685753429;
 Fri, 06 Nov 2020 10:02:33 -0800 (PST)
MIME-Version: 1.0
References: <20201106041046.GT3249@paulmck-ThinkPad-P72> <CANpmjNPaKNstOiXDu7OGfT4-CwvYLACJtbef8L0f18qn1P4e8g@mail.gmail.com>
 <20201106144539.GV3249@paulmck-ThinkPad-P72> <20201106174756.GA11571@paulmck-ThinkPad-P72>
In-Reply-To: <20201106174756.GA11571@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Nov 2020 19:02:22 +0100
Message-ID: <CANpmjNPduS1bfieEEh5W+Apmq0+OQjOOTv_cj5E9jb1mwJfDqw@mail.gmail.com>
Subject: Re: KCSAN build warnings
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rJqQ+ezp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Fri, 6 Nov 2020 at 18:47, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Fri, Nov 06, 2020 at 06:45:39AM -0800, Paul E. McKenney wrote:
> > On Fri, Nov 06, 2020 at 09:23:43AM +0100, Marco Elver wrote:
> > > On Fri, 6 Nov 2020 at 05:10, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > Hello!
> > > >
> > > > Some interesting code is being added to RCU, so I fired up KCSAN.
> > > > Although KCSAN still seems to work, but I got the following build
> > > > warnings.  Should I ignore these, or is this a sign that I need to
> > > > upgrade from clang 11.0.0?
> > > >
> > > >                                                         Thanx, Paul
> > > >
> > > > ------------------------------------------------------------------------
> > > >
> > > > arch/x86/ia32/ia32_signal.o: warning: objtool: ia32_setup_rt_frame()+0x140: call to memset() with UACCESS enabled
> > > > drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_prefault_relocations()+0x104: stack state mismatch: cfa1=7+56 cfa2=-1+0
> > > > drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_copy_relocations()+0x309: stack state mismatch: cfa1=7+120 cfa2=-1+0
> > >
> > > Interesting, I've not seen these before and they don't look directly
> > > KCSAN related. Although it appears that due to the instrumentation the
> > > compiler decided to uninline a memset(), and the other 2 are new to
> > > me.
> > >
> > > It might be wise to upgrade to a newer clang. If you haven't since
> > > your first clang build, you might still be on a clang 11 pre-release.
> > > Since then clang 11 was released (on 12 Oct), which would be my first
> > > try: https://releases.llvm.org/download.html#11.0.0 -- they offer
> > > prebuilt binaris just in case.
> > >
> > > Otherwise, what's the branch + config this is on? I can try to debug.
> >
> > You called it -- yes, I am still using the old clang.  I will try
> > out the new one, thank you!
>
> Huh.  I have an x86_64 system running CentOS 7, and I see PowerPC
> binaries on that page for that OS level, but not x86_64 binaries.
> Am I blind this morning?

You're right it's not there.

> If I am not blind, what is my best way forward?

Hmm, chances are one of the other ones will work. I just tried the one
for "SuSE Linux Enterprise Server 12SP4" on a Debian box and it worked
fine. All you need is for the 'bin/clang' binary to work, although
there's a chance something else might not work due to missing
libraries, it doesn't matter as long as we can build the kernel. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPduS1bfieEEh5W%2BApmq0%2BOQjOOTv_cj5E9jb1mwJfDqw%40mail.gmail.com.
