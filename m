Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOMT6D6QKGQEWW5JFCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7805E2C143B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 20:12:58 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id k4sf5266123ual.11
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 11:12:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606158777; cv=pass;
        d=google.com; s=arc-20160816;
        b=iJS+rPPEvm8SRSUoi/mS0HN/H8f4nKmiaKqF+9c2J9LN8s2CrOMObEh/yy34os7jzb
         buzCxqBhdlsZZAqrwUQIL4/9A8ExAmeVmurP/c7jdZT6Fchl3f2qBKtsvmUwdZNgtQav
         8UjkmUgE3hof+4Tp7k+YsRKkgX2IFJy8Z46YNP+xzYoq0WG7A8OzY3CmU6Xnpl/Pln5s
         JzCTMJLp/HRF49dKB/VI9x4PmTDpBGP3KnoyJIbAaCvW31eogQYD5N8SpneHzX3CDEMW
         nmpnMmwsmizRaKuHz/vIzGIEO3LhCPoZbTIOKDiUwoKlbXYoK7tLa9sX/6eXd70RLVsH
         TavQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VvyadyhaSLAJ5h9Tri5VdWrWriaPYBgN+H9e7xBqx1E=;
        b=k7wNqkRjoH5jBxN2slwrXxuuGIum++OUlGWBb1xz4BDVt5mxvaLfvBBhew49WAFrun
         nsHwOLbVjLHAEMg6TUYXzd6MC3TtC9M2bCiG/Gs4df18xkiC351he21viL2cX/ZCGyij
         96xY1J4B5+20IAJzp/WZQeCRWr+yX5DRIJDfS2brUYfWq7soAB5EyGJGFyaJJfzOLYnp
         yQbf92w53gHOYbrPAdFkwD689a+kykcCGNlXbP7U9aLpxDQIMTWHJqPI/Q2qAIla85XG
         wb5sYEpQaWu0iCtgTom//OwWdMKrgSd6+zXv6uxzOcg2753R/tN/AyDZFkjww4w/kMZN
         iHfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B0WPvS5c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvyadyhaSLAJ5h9Tri5VdWrWriaPYBgN+H9e7xBqx1E=;
        b=WwLTRtcPaweJWM/Ye2/2HS6vkQDMKDbgmdO+A88fRjHzRQL3z2D5MH8MuKZBaltluK
         HoNZAAwlGFw9dcj63oFiFTwuHOfvrZXm3LKcPgm+tWmFot6LTbt9d76vBse3I7XARgNy
         ckCiJzixdblLR9fSK2y+xF8J3trOFCM1QGPjkmLMovXTFLx3+x5kTuqmyPbr3uEP1BNB
         Vah0cWA4h/KWx9vh2cWpy+/RPoUikppcO9UQZoK6+zFk7TpGelmcYdqMC6tiBXqT83M0
         4c1Yqq8Sah+vHqyvzIxFH5DMXrOQ9xXMlZT31J/m35ZeKD25tiyPHl06LtoslqV4Zkll
         Qh0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvyadyhaSLAJ5h9Tri5VdWrWriaPYBgN+H9e7xBqx1E=;
        b=gtc6aXDpKJ3fvU4d6Kdy0EllobhL2A60hZ8/48i8H8/txqrC1sk3fgt0+vPH209ypZ
         GDOdvCnTlvQb/C/vxWFU/5T4ZjPEPKS2o2Wmapd1+AgDQ6j39xi1CY2VYOItWMsBNc9n
         WVwNQj95gPgJ4ehxzvW/duKsidJuJu/ZxD7E22DImy+fLdI7aKQcCKrFPaP90TZEKkPA
         JTyQUwvmk+Ev1eHp09xMOBpEXA85bSsjzNW0YbExye2V023fUu7L7W2g6VJOUnvv71l9
         97qjoUwJhE5wPWAIrc6DRgjwLd4NB8sZ8w9FmglJxZEmV+AM1igdumqF3Hq7PiKCVU/i
         hZTQ==
X-Gm-Message-State: AOAM531quutoUObNhAFhdWGDnXxNU76NnNM/uZvC4vVcuxx/AUXY4f03
	7QPh2xFoZED7OQcWsZSfsZA=
X-Google-Smtp-Source: ABdhPJzKKgGtc4FGX9j35Wa8NOLdBtnTcUlX9S6Lx1qrRYBfdCwxNgVgqAb/E5S0F67zmrcJN3brgQ==
X-Received: by 2002:a67:ee16:: with SMTP id f22mr1249657vsp.8.1606158777454;
        Mon, 23 Nov 2020 11:12:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fe4a:: with SMTP id m10ls2006819vsr.8.gmail; Mon, 23 Nov
 2020 11:12:57 -0800 (PST)
X-Received: by 2002:a05:6102:501:: with SMTP id l1mr1222730vsa.42.1606158776960;
        Mon, 23 Nov 2020 11:12:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606158776; cv=none;
        d=google.com; s=arc-20160816;
        b=jJCSx684anJvJhqPI1UIZUmCSKl33ITgYwrUSt1elfsnCDappRBkGH4l9dVXdH1Bgq
         grIUwFuZ6S2wAf69lr7L/fsreqNmjqjWMQfEd3b9hNwqLLP821tUJExeCgLteJiUAXwP
         o15B2O9pRmW5INiFLO3hLotqI5cB1buypCJ0tLTcBeHJlqL3W9B8fdreRK0gHExCmexb
         Jy8eUnoK+rUrtVsw7ar5FOmWRSdKlM94SjLSXeQrtp99KpLllg6SPtVqk2Vh22S4lnHZ
         B89qlQMtSTF+D5tcowoOFHUp2Ceb45d2Sac3HsNOy4ZgjWfmRxK4I7ICCw047Lv/EWnp
         RwGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jkFKVVE05DxxQZn8gUPCNJA2GtzoswBnLFvjycznboA=;
        b=dXFXbxMV2L5gwB3nVlerSML4tX6uEJdz3G8aAU/5eUirEpb2l6bO/KauwSWLZ5pHx7
         ywAWLb2Ek4Fay1LP7oYSeTENO01jASHovgXNlPvjJ3mmc85vpjY35FG1NF1iMHsbVQv5
         USg9n+mL7Pim+X1/G+IhRxJqQ9CQfG7MPaoI5HqJz2fsiE8dIvOT+YD0+YuT/TDxPMZF
         sAiRozZW899633UOSKhkV2863g/PENIk+Veqy1sbI2B0kTUIzgG88UMMcHuU9X8xX9Wh
         oEYdtcn6ZbqpRs16FdOwBNsGbR3msreMg/MEfLq1M1x7+k/fLaRZdxl7qWccHaoNuNyw
         vCFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B0WPvS5c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id k67si596742vkg.1.2020.11.23.11.12.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 11:12:56 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id t143so20846429oif.10
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 11:12:56 -0800 (PST)
X-Received: by 2002:a54:4394:: with SMTP id u20mr299277oiv.70.1606158776324;
 Mon, 23 Nov 2020 11:12:56 -0800 (PST)
MIME-Version: 1.0
References: <20201123132300.1759342-1-elver@google.com> <20201123135512.GM3021@hirez.programming.kicks-ass.net>
 <CANpmjNPwuq8Hph3oOyJCVgWQ_d-gOTPEOT3BpbR2pnm5LBeJbw@mail.gmail.com>
 <20201123155746.GA2203226@elver.google.com> <20201123160823.GC2414@hirez.programming.kicks-ass.net>
In-Reply-To: <20201123160823.GC2414@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Nov 2020 20:12:44 +0100
Message-ID: <CANpmjNMzeU8GBkNr-_6Rq8+9CNW476DBMpck9oeFw-pE5J0beg@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: Avoid scheduler recursion by using
 non-instrumented preempt_{disable,enable}()
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Will Deacon <will@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=B0WPvS5c;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Mon, 23 Nov 2020 at 17:08, Peter Zijlstra <peterz@infradead.org> wrote:
> On Mon, Nov 23, 2020 at 04:57:46PM +0100, Marco Elver wrote:
> > Let me know what you prefer.
> >
>
> > @@ -288,27 +288,19 @@ static u32 kcsan_prandom_u32_max(u32 ep_ro)
> >       u32 res;
> >
> >       /*
> > +      * Avoid recursion with scheduler by disabling KCSAN because
> > +      * preempt_enable_notrace() will still call into scheduler code.
> >        */
> > +     kcsan_disable_current();
> >       preempt_disable_notrace();
> >       state = raw_cpu_ptr(&kcsan_rand_state);
> >       res = prandom_u32_state(state);
> > +     preempt_enable_notrace();
> > +     kcsan_enable_current_nowarn();
> >
> >       return (u32)(((u64) res * ep_ro) >> 32);
> >  }
>
> This is much preferred over the other. The thing with _no_resched is that
> you can miss a preemption for an unbounded amount of time, which is bad.

Ah, I think this is rubbish, too. Because it might fix one problem,
but now I'm left with the problem that kcsan_prandom_u32_max() is
called for udelay() later and at that point we lose skip_count
randomness entirely.

I think relying on lib/random32.c already caused too many headaches,
so I'm tempted to just get rid of that dependency entirely. And
instead do the simplest possible thing, which might just be calling
get_cycles() (all we need is to introduce some non-determinism).

> The _only_ valid use of _no_resched is when there's a call to schedule()
> right after it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMzeU8GBkNr-_6Rq8%2B9CNW476DBMpck9oeFw-pE5J0beg%40mail.gmail.com.
