Return-Path: <kasan-dev+bncBCMIZB7QWENRBWVY2SAQMGQE674YBKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FCA0322D43
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 16:16:44 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id o2sf9288535pfd.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 07:16:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614093402; cv=pass;
        d=google.com; s=arc-20160816;
        b=eWNsiSiVHVigZaJtttccoPw4moDe63H5+xXCpdHmnHtWn/NKdd27CtVE1KHU+a9v5J
         qcSWJE8EfmtbVv6mglRA3MNPjxDrPRB/m/fxsGwCzu5gNxhDqXWdugIjJY342LdcbZFu
         44vf2Q1Nqk1ACgmoQrGjC0qJ5gB/hTPvORmHfLJPb94WXKFng44m1waWbic6x8DVZCUP
         iXmfBbto590uv+MrPR4r0tZquL85f37XMeLYhbjzLcfp4J3EgYHiGbH8b/aLiY3lyjFR
         dgtXcj+H583DKmfqj5LlWmX4COdPQJI1C18fLfr5dQ1O1dH6ZbXvIGyqrate39YGoyp/
         vHUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yzLVi078GD5BPtAkyD5KGQCF1PA4X8963s2oUx8XFK0=;
        b=auNmbT7cIS1MbleKIVimr3cQF5N2JTtq/SzBos08JOMCpTj4xgcGs882vAlyV0iBuc
         trpo7OGxP6UVQOk5Zs/hHOsVPuWsvxUWvybVEiXp3fcnfwQ3SLKkRCb+HO/kymoJK2qs
         caYlFj31RGZgiqrX5qtIvpwIxodDlMhv28XuXtZ6ZXEmU85bax39P8tQBbzrIbtLRO6O
         qflOnz+GKon6GWhBFdFyEzCC8zPKGSi0k7Ah65S9ggp+dKfUEQcBkzqDCvPUXixIrTXQ
         XvjCg76oBhphpzEOKTDPyU/dPih+D4qjjiLCMjPnmB3kJ3Ap0TMxioXkVn1XlIl9RnLD
         pBSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uA/OwFba";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yzLVi078GD5BPtAkyD5KGQCF1PA4X8963s2oUx8XFK0=;
        b=XaAkUAyJakxc2fDkHXuf2pHo1wZSUPFcQZq44gI/x+z7aAmPTAIcja9RG0MNjntNzK
         /Ron2am/onH2qA3IYy8i1VcCxMikyQqc+2BYZ9fiTuX06qfAr0MNopvQDO7IxJC0YBWV
         6slkALYeehpKEKpqE4yGv1Lh2GWjFv1EtNY990Ugij/5oWEPV/JhcBnJUwm45V7OBjav
         OT1+Yi2eI+mH0ZyvQbCiaR3T70YZr9FGPTL6bmi+l015EcfsT3Ws9DtZ7smXeMxE7f7Q
         zfwo9mxSZmJX1Fe/wAz6SWxG5gHlFQwOgt0n67+MPrNhSguwIMtd2ZjYvEiJXEjXmmzJ
         8euQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yzLVi078GD5BPtAkyD5KGQCF1PA4X8963s2oUx8XFK0=;
        b=bsaTiOSChfXAElTOoy9OGstEV3F3t3a4K1g8y8PuM4i7fGdqEO5T2FIoaIz3H5yvdL
         yvqINsSCHqi9+xbq1E/jajQ2MoYKaQjTjsRQsovENNTs/nw2tbN37IJQGCZ/Htk/Re4x
         XaJpVe3yVBCpTQ+ATUeyWP/2ik/YEPl/jihqBabdhL+thIvf1cNf9FMogHERoM1Z3TAT
         j3gskt6/6qp/GW7IL5F1qN4tKPzbcqpAUM0911Ukp45vMaKOcUZSona+6dWvSHgdugGl
         xE8LG3pgo9DDsZyjh/abtRTPOLhD2VbuuOOyXR6WPRZVK7kDmDfSC0V3AcsGJ5Gf7O/J
         UtOg==
X-Gm-Message-State: AOAM533eKAirFVGsgBj46Y0DxRlp02JpmXJPsmv++c1DgbeGwdVyvM0W
	pEqVpXZF9+wrcpdpAQ7VPuE=
X-Google-Smtp-Source: ABdhPJwVdaMZUo+ArsDIhlqcAbSWhmf2mH/XsgeLqIx/fsgITzGs/80so0U+znM7Q6apgAaNQADyHQ==
X-Received: by 2002:a17:903:22cc:b029:de:191c:1bdb with SMTP id y12-20020a17090322ccb02900de191c1bdbmr28051137plg.14.1614093402712;
        Tue, 23 Feb 2021 07:16:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:300f:: with SMTP id hg15ls1553862pjb.2.gmail; Tue,
 23 Feb 2021 07:16:42 -0800 (PST)
X-Received: by 2002:a17:90b:1b4f:: with SMTP id nv15mr29923140pjb.105.1614093401998;
        Tue, 23 Feb 2021 07:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614093401; cv=none;
        d=google.com; s=arc-20160816;
        b=mtPRYaV6hSqbh36njatA2OhBPGZomi1qCXnJY6lI1fN0L0WjTfo6dcnlhSrKahjKLt
         r97HMcuvGWue6xg1mShCsDQbK/ASQM77oHa1vbsCeS26gOO+CNJeWhIH+fY2DZ/Gz7+A
         SASX9Krc9+hjW8ze9kKR6qL8M1Svcrlq57yYtv2j+aAbIVrdbw1Qq5hlVMwUc/NARPk1
         AJN7wkw6H9iaxbsFR2SaXm2iNKgCyf+Mo95FtfGN6Eod0SQtX1KFkegki37tpA/XJQ6F
         8ms+iDcj3HIMCGq+rIA3GS4E6xiJk3XoCObuU38KLNOyxEos9VIuj++ZElM8P9C/VImH
         VRTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3yeydPNUBbnBa03B4CtFFI71u/VogiWMTrnYPrUvA5o=;
        b=UKNov5Z5q010eJfDHCMPJSgIuLyOA7gcrnY7oCvv6tgcMjpc22pkv07QTL1wP8b3tC
         ZFW3FS4zQzSY6O03eKgYUSYL7ZB+/X/1bLFts6gcvbxS/9Zwo0NoXzqA8izGf6VijVp6
         YZ1pGgVA9mhAb9w4vdGs6LBEe1c/gxi6EHboSHqGOqNkaTdTnIJ2+63RCAJrwBuq4tQH
         ZZkCD0rS9D18g/3E7jHkRORtrGIuWUdVS45dGqjClILCzFQ6OlGLbPvQLKX699oWQqJj
         DKZ1fMDnxd9MyVGnToV4u+9HzgLz/C1nc1A6H6+8qrr2COUKMI8jJotwjCLKcg0OYCtA
         AH+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uA/OwFba";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id d6si1046145plo.3.2021.02.23.07.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 07:16:41 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id s12so7252755qvq.4
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 07:16:41 -0800 (PST)
X-Received: by 2002:a0c:8304:: with SMTP id j4mr25737289qva.18.1614093400799;
 Tue, 23 Feb 2021 07:16:40 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-5-elver@google.com>
 <CACT4Y+aq6voiAEfs0d5Vd9trumVbnQhv-PHYfns2LefijmfyoQ@mail.gmail.com> <CANpmjNP1wQvG0SNPP2L9QO=natf0XU8HXj-r2_-U4QZxtr-dVA@mail.gmail.com>
In-Reply-To: <CANpmjNP1wQvG0SNPP2L9QO=natf0XU8HXj-r2_-U4QZxtr-dVA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 16:16:29 +0100
Message-ID: <CACT4Y+ar7=q0p=LFxkbKbKhz-U3rwdf=PJ3Gg3=ZLP6w_sgTeA@mail.gmail.com>
Subject: Re: [PATCH RFC 4/4] perf/core: Add breakpoint information to siginfo
 on SIGTRAP
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, 
	Matt Morehouse <mascasa@google.com>, Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="uA/OwFba";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f29
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Feb 23, 2021 at 4:10 PM 'Marco Elver' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> > > Encode information from breakpoint attributes into siginfo_t, which
> > > helps disambiguate which breakpoint fired.
> > >
> > > Note, providing the event fd may be unreliable, since the event may have
> > > been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
> > > triggering and the signal being delivered to user space.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  kernel/events/core.c | 11 +++++++++++
> > >  1 file changed, 11 insertions(+)
> > >
> > > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > > index 8718763045fd..d7908322d796 100644
> > > --- a/kernel/events/core.c
> > > +++ b/kernel/events/core.c
> > > @@ -6296,6 +6296,17 @@ static void perf_sigtrap(struct perf_event *event)
> > >         info.si_signo = SIGTRAP;
> > >         info.si_code = TRAP_PERF;
> > >         info.si_errno = event->attr.type;
> > > +
> > > +       switch (event->attr.type) {
> > > +       case PERF_TYPE_BREAKPOINT:
> > > +               info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
> > > +               info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
> > > +               break;
> > > +       default:
> > > +               /* No additional info set. */
> >
> > Should we prohibit using attr.sigtrap for !PERF_TYPE_BREAKPOINT if we
> > don't know what info to pass yet?
>
> I don't think it's necessary. This way, by default we get support for
> other perf events. If user space observes si_perf==0, then there's no
> information available. That would require that any event type that
> sets si_perf in future, must ensure that it sets si_perf!=0.
>
> I can add a comment to document the requirement here (and user space
> facing documentation should get a copy of how the info is encoded,
> too).
>
> Alternatively, we could set si_errno to 0 if no info is available, at
> the cost of losing the type information for events not explicitly
> listed here.
>
> What do you prefer?

Ah, I see.
Let's wait for the opinions of other people. There are a number of
options for how to approach this.

> > > +               break;
> > > +       }
> > > +
> > >         force_sig_info(&info);
> > >  }
> > >
> > > --
> > > 2.30.0.617.g56c4b15f3c-goog
> > >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP1wQvG0SNPP2L9QO%3Dnatf0XU8HXj-r2_-U4QZxtr-dVA%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bar7%3Dq0p%3DLFxkbKbKhz-U3rwdf%3DPJ3Gg3%3DZLP6w_sgTeA%40mail.gmail.com.
