Return-Path: <kasan-dev+bncBDHYDDNWVUNRBUVBXH3AKGQETKA5EXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25B691E4028
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 13:36:51 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id n22sf9293711uaq.10
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 04:36:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590579410; cv=pass;
        d=google.com; s=arc-20160816;
        b=hYrg71tzq5WZZGUlwMw8cIjxl6gCybqecJ7SkTNuh9iEK3nThTFi2xRQrAg2n1PTYu
         ADIR4/TT+7qMsVAwp4vrUtOtqfuZVjpjgABgbwLpiSePZ9fo3YY9KG8p4vIHxn9wgxb9
         osPCHQ9Zt+1o4/uuYRSmAO1/yUZwgfwcE01PVVDk3Iy1XnHZZBTWt4YYP4OhfnexMUBb
         wHQVS7D/Ndo9JSLqLN6rZ+hDVxzBEr4bBd0ca6aCnYNNKsTg303Nm2leyw6ak4EtYlYt
         /UiO/11rU5svF/ILf+/4CDYMFMg8sW3bQCwfMIQBBO7h/cPNVXNPdwEIoDSG7d2iZRzS
         acwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :reply-to:in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/P9qq/d44wTxWzA99iHQRHXibgZS/e/wwj058IaYRxk=;
        b=E8n5k+pXSvb+1l/lJaypljvQD8LtRvDaO/nQeS9T2tqskOhRNan3J/j3z7Gv5O1pNC
         Gwefc4f9e7b5X8jZeDFF94tP843FTkoE2od4d8PImF28QNcn/1uE0n0In2VTycohCQZf
         ed1x5LlLiUy12xpAy8PZc2JpBjS4Q0s+bOevqBZU/v8IAmzVxfAtk8xvlUoHxcK5DxNI
         kRjgYAhzSH8y0niqyzP6vTq6eAYLSqUQNA1tJaBaFKgXDsqOqpds2OfdOACdiAJi8bNL
         X/B+ALdsNlBV+lcBsPrfhbHEKRGYE8CyjkYLxuC2NBqQFej3LwawS6JkIvoBfGuZi8j6
         RAsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=L1YBq2nY;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::144 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/P9qq/d44wTxWzA99iHQRHXibgZS/e/wwj058IaYRxk=;
        b=L3Q3FydNyEWKjhuUYOCHMw0vbCSjDnoPHnm0E1lBWUeEK/z37ePEP0yL4bnfwraGwv
         k/jI84p1AIY9QBY5ZFojQkbUohq4KO9tgHY8GDXA0/Qcnjft4aD7Pz0ZIz3v/1GGo0TI
         HbY6Y+uEnnTULCpt1/nSu4S3GNbujpMWB9HV4h4pn9yR2vUzYpCHhGxe47DWOWFPMHbi
         dgb7CgQ5vVdCGJ2AAGtYf7R7IvR4rTUOCwN+r6OMmlaExMkkWe/4+x6J7tCHvM1lERaS
         bi28ZC+2EIAcDYU4g/FmHW5C9D/gzhajfvHIfSWrU9ccs+PiCxNOb7tdz5jKvDOvTLct
         nxkQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/P9qq/d44wTxWzA99iHQRHXibgZS/e/wwj058IaYRxk=;
        b=rpo6OqnCo+9fw4PAk9Ul21B6j3o5SXXvo6fQQuGgU+/0kT0O/a4dWM9lhmLxxqqD2k
         9UMj4GOwyNtNN4r/NxsbgXgRy1ZKNPPDWJsePJwmsCRLoo/K9XY9SsJutdD6H1Y9WMgz
         x8s6CyxB1GUwrQIj3tOxFO1wIEmvu4nVwlP18GaT6tLlfFgJ/1eYPqrx+OlWZPcvxvNC
         ncSEJYhKscVhJglqk2TQkkWqtqCm5AUtDA+bPPaHiK7y12aqvWh5cK3w9sPcihWm4g9b
         QbXEGF+4522ZNX8YM8C+kICW1wD+Vc189TTfN0sr1dnY4txDOym/ZaAnMf8winKYKj/3
         OZPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to
         :reply-to:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/P9qq/d44wTxWzA99iHQRHXibgZS/e/wwj058IaYRxk=;
        b=oeKniHjK0yEYJd2I7HqevPhgcIpWll+gOUIX8YcUNXNK1DmOQ/4yZOdO0fxj53uj1z
         f/cYmvbxP3+PuFidDSQSkrnwJQNi3jofagWlpbYY4jE70jV7lRmnH5rCrr3yNdib78qm
         TdkQGOcEVGNACnaWLjaZCNkNGzoZtr619sAB1Pm5VzOC049/IrGpMoFT7WqE8tLx4EvJ
         8mZkszExvU654KWD1Dtd8I/hExEyO5UFAHZVeroTVOiNkNBpY8w2GJ751GwX6g4tRWvo
         4TnEc8sQ3gL8LiXkAsMBCcCKq4qGzbGmBAQLNeGhnjvTNmLtTTITVculSC0XMcel0Gwg
         ljHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DrBE191cfjdGMhPvgkPio8BH66t5K1HvJWu7clW3ADQbCfVzw
	vrgU35AE86CL8S7bfzij9Fg=
X-Google-Smtp-Source: ABdhPJwm2hLZ/DVU6HnPQlEv0CXLut8B6qYTiLW0/I51+BX8GeHH0+VlJI4ckjfBpfv7n1qo+kjswQ==
X-Received: by 2002:a67:e947:: with SMTP id p7mr4301261vso.199.1590579410085;
        Wed, 27 May 2020 04:36:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2203:: with SMTP id 3ls956765uad.4.gmail; Wed, 27 May
 2020 04:36:49 -0700 (PDT)
X-Received: by 2002:ab0:28a:: with SMTP id 10mr4276549uah.131.1590579409737;
        Wed, 27 May 2020 04:36:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590579409; cv=none;
        d=google.com; s=arc-20160816;
        b=QDe1uIRJwOZXH0TqCEKdB6iKfBVT9WNa8HGb8fIwSa6DqHEZXGqRadre0Qu04DeUJs
         qN3qpwy18cIu7A6VetgpgA9AlpTSX2or24MveRqfpgokmQ4hCszzUmEqy/iEfX8y6k/k
         5nCM+bgJJJu0h/KPSDykAvFV3SgjeK+JuJcDGN0mS1wf0e3f0IOvXwMEdyXNwbs9tZ0H
         MfBvWcP+VK6x8WQtOdmzB2FbLg41U2LwVqrEH0VeJalyBomMMbpP0FKtU2YI9383BVc+
         0qwTsHbKuYxMJq4o9OJCDOcPus7lSbS8tRQACasV4vscmnsYf0n8ntD1ca8q2RS5IBPY
         rbNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:reply-to:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z6go2Pe/0xHx8Ur0HnZIKTJ47Wq/ilnSzd2NqpRkWGw=;
        b=N1TJ0kTvTYBfCQ5++0FX9mOvNEE7iKBnVpgkG22p5YjCKyzaZ+TwPgiMpqLTs9u9lz
         A8/bETLMzcCpE8XVzCrD/4GO4iBu7DQon5LP1pC9rIDC4xupS9+Z/FXKKDGXX5mepyBW
         WrZXgQgg8YSjNmTU1hViVZkaue3IqP4im/++8chMWx0UyVSJz7JqSsQhrJihdO6kmTDo
         LhwS6/lvek0EirpBJMKxNBELjRE2iHwjUP7gJlDSVU/tp1JT25kSxiaj6HpC8bjSe8Nh
         93oRZQngGmrzsTQjGVbAyNW+4nFmF/9YlcUShi2rLl6OSRRb5ZnpfTk9/ZEaw7YsInqO
         hIpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=L1YBq2nY;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::144 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x144.google.com (mail-il1-x144.google.com. [2607:f8b0:4864:20::144])
        by gmr-mx.google.com with ESMTPS id j5si286169vkl.3.2020.05.27.04.36.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 04:36:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::144 as permitted sender) client-ip=2607:f8b0:4864:20::144;
Received: by mail-il1-x144.google.com with SMTP id a18so6352384ilp.7;
        Wed, 27 May 2020 04:36:49 -0700 (PDT)
X-Received: by 2002:a92:6608:: with SMTP id a8mr5465508ilc.204.1590579409205;
 Wed, 27 May 2020 04:36:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
In-Reply-To: <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
Reply-To: sedat.dilek@gmail.com
From: Sedat Dilek <sedat.dilek@gmail.com>
Date: Wed, 27 May 2020 13:36:41 +0200
Message-ID: <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sedat.dilek@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=L1YBq2nY;       spf=pass
 (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::144
 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> >
> > If the compiler supports C11's _Generic, use it to speed up compilation
> > times of __unqual_scalar_typeof(). GCC version 4.9 or later and
> > all supported versions of Clang support the feature (the oldest
> > supported compiler that doesn't support _Generic is GCC 4.8, for which
> > we use the slower alternative).
> >
> > The non-_Generic variant relies on multiple expansions of
> > __pick_integer_type -> __pick_scalar_type -> __builtin_choose_expr,
> > which increases pre-processed code size, and can cause compile times to
> > increase in files with numerous expansions of READ_ONCE(), or other
> > users of __unqual_scalar_typeof().
> >
> > Summary of compile-time benchmarking done by Arnd Bergmann [1]:
> >
> >         <baseline normalized time>  clang-11   gcc-9
> >         this patch                      0.78    0.91
> >         ideal                           0.76    0.86
> >
> > [1] https://lkml.kernel.org/r/CAK8P3a3UYQeXhiufUevz=rwe09WM_vSTCd9W+KvJHJcOeQyWVA@mail.gmail.com
> >
> > Further compile-testing done with:
> >         gcc 4.8, 4.9, 5.5, 6.4, 7.5, 8.4;
> >         clang 9, 10.
> >
> > Reported-by: Arnd Bergmann <arnd@arndb.de>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> This gives us back 80% of the performance drop on clang, and 50%
> of the drop I saw with gcc, compared to current mainline.
>
> Tested-by: Arnd Bergmann <arnd@arndb.de>
>

Hi Arnd,

with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.

Is there a speedup benefit also for Linux v5.7?
Which patches do I need?

Thanks.

Regards,
- Sedat -

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BicZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g%40mail.gmail.com.
