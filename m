Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFNYV74QKGQERKOIOEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 287F023D944
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 12:31:51 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id t11sf22210937pfq.21
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 03:31:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596709910; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dd3pnmyiDM/+E4OTl/OEByZmVo5JACRjeU8mCeEJsj8/Ct4KxW5hnFUAjijTW8IYph
         2jEccz0rxpifo1486GdZTo1J2YFLPOhp80rplj/5hhIkNGIY3eRNQB7aaKvlUwkSZ4yw
         kEWtvAET/pu2ysbdZ0eWHsqno1N4NPPisk3933xoS/c/7+28Ha71RETEjR8F2M2izh+2
         U+YCkt2HcQJt/b7ELaQpV1Now27hw+SQMDcRYFDsoPymQzpevEj0B01h2P19xtcfqq8h
         wae+Iectf3u5hZ8a6g+buMhWNvvByW4fE1hTWgGdYObKm5GfjcDthz+oSOLuxKMuyCzn
         4igg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UkSY5bCm5kFgVeFkQzJbbmDXsLYsrnO5x7DBQWUs4xg=;
        b=hI3XIMDfeKTR91UNlj7DOYOzc+aSqVDuj9bDpCPZFb04iz7QDHIUjyFyyIM7MeqDSj
         p7mo8grp7zzHY1FHNrYO3703UWnYD53kSjJ8poKiBA2oP9+ODO5+vZZrfYW9aypQnD9+
         Fmf+oE1Dz1jVJ3RP1i0Ke65GB/XzdTKfNIevDXmNemvJyBJqABjuej0h1sUC6w9T0ZMH
         s7fy/qti0bxS/QBk1Zk6/xFJhcTtnuvlq+r6GGzD0MJJbutYe0jtjAnd8JSTwEzep/ms
         WwCZg+n1B7FYBpsOdqwpDwfpVoRsAyImURcDs6Lyr9n1Fx6EnrJR/YSrd9M0m3C3A+Hr
         gXCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gOvhi5v7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UkSY5bCm5kFgVeFkQzJbbmDXsLYsrnO5x7DBQWUs4xg=;
        b=Bv274W4EmfHGTgoItpEM0xXzBPPctsUKpNpVQVdxo2kSBptbgn4ABsoq2OwXhD9xma
         W0FvCevMyYbaZmvc/jyplqCsLGm913BWMJxkMMayOVXT1Y6h37lR57XGKt0ghqyt0Yra
         4xymeQ++efTFv1AXi++GoIQxLVk35009RUOLUFeU9Ata0pI7Ky8a2IF4SX4qIpSrUBvr
         kQN9nd1qlfRrCBDuw+q7g9PZDK2BVH3RTAwUT3WZ1P4K0/IP7rWASEAkyvr9y6TvI77G
         jd/FDoiM1ekLoGCO5kCA3Irj3ewuUbrg8lH4NgYahWBQr7zewu87ewxawDhm1CZaAltO
         G0Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UkSY5bCm5kFgVeFkQzJbbmDXsLYsrnO5x7DBQWUs4xg=;
        b=hE6usOg0pebuGQc/ksIh1/MBYkXcCH+bY/x1WNZY61OUihg8bRQjpc6CgRj2QpndG9
         09+kwFutt5yR82jm6r+aEAvkewj+Gvok0HBRv/wig7EstWqwAd4oDVLa+e61NktKMUpw
         rTsbyTq9kleNE7yK3Svj7rHx57fQB59WtHeCK10pv/iuKPM3o7c56vs15Kbjpqm5pZxS
         uFiO3fiZyB7rFXU5byX33BwDviXBF6weRZKK1MyC6XbebeOnnKdVNBLJTbsW/Vfphyqa
         Z7lWCPFgfXxO80W9ap3gceFdodNivnWwPvFFCeaCpJgw6y3YdcgJ6Zz5GEXq1q50Rhmc
         AMYw==
X-Gm-Message-State: AOAM531QTP7fHhL7gKykWDthZQqIwHIDAcXXq/yqTgoHU2bUu+bqhQ0S
	po/YR7LYb91dVkpxazvdmzU=
X-Google-Smtp-Source: ABdhPJy+aEYNrZ8Y4GA+R0oIhghq7A7bqq4hjZzxeN+OkxQKHvLUpSzP4gy0TsVoIYwOd3SkBCqrKg==
X-Received: by 2002:a17:90a:4002:: with SMTP id u2mr7455402pjc.55.1596709909799;
        Thu, 06 Aug 2020 03:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b602:: with SMTP id b2ls2398922pls.11.gmail; Thu, 06
 Aug 2020 03:31:49 -0700 (PDT)
X-Received: by 2002:a17:90a:2c0d:: with SMTP id m13mr8137799pjd.170.1596709909320;
        Thu, 06 Aug 2020 03:31:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596709909; cv=none;
        d=google.com; s=arc-20160816;
        b=EgAZapTBpRtIf+N8aCYX39Zo3JT4sh8DBDy1KHbAG5SoLXSAwct48OoRb5vCWg+AyP
         V26zTkuGBJ1D5gZ5MqJbaJpC/05oI9aA7zuHQW+VMQaQOADXb6UQVbKTFlRFCDVTtNcH
         Mh6ky/rRDXLTLAb/gUVY5xDpcB5neyjRXdBARK51RmcFQKEPxiFpPYw4Ekok9ARdrUvu
         hm+NDBzS9EUPD5Aw3P70zSFRqWYVHYdF+S9T1bri+F3TEa5ZYCBJzVscY7DEICuvQeLq
         OQBzQOMKWSOdH969YwTTlGM49qIsuKrktRWL9qWeZSyfNE30zhU4WOW/fkZVG0clvz7Q
         SpQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ypy/qALQFzmq+pA0XvKiGAPjinMvR6vyLxRwEn3AJFI=;
        b=mGiG9Lh8hwB8MYlFTBfFhOI+Y0plEwuvIuatEceTKws6trFuSjD5j2FLZPB3jG9Ekr
         rOYCpYgD7od2uSkBmpHA032VO6266+X1+8v3iVmxJuwPuC1Dl0IAcb40H2JcJD76zpuN
         /2IOusaU6Ldqd0MK9xHhZ6B+q2PS6MHm8rOVyMMNeBzWYu3cFDqEH3WWA+ZMh3oZV6Cn
         45WdbHPgwWDaa2xuxVjvNtgZNDkdSJ58wODnYkwuaysrN2jfO0IurY6BmTjdHkYaRaxi
         hVEOfg20/Sd0Mezfw5cRNy4v2sEAYaGA5cQ3iRx5aLjggAgb4S69Xf/XcGiuqtiFiARP
         q5Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gOvhi5v7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id 91si172542pjz.1.2020.08.06.03.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Aug 2020 03:31:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id v21so28487531otj.9
        for <kasan-dev@googlegroups.com>; Thu, 06 Aug 2020 03:31:49 -0700 (PDT)
X-Received: by 2002:a9d:739a:: with SMTP id j26mr6861992otk.17.1596709908446;
 Thu, 06 Aug 2020 03:31:48 -0700 (PDT)
MIME-Version: 1.0
References: <20200805230852.GA28727@paulmck-ThinkPad-P72>
In-Reply-To: <20200805230852.GA28727@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Aug 2020 12:31:36 +0200
Message-ID: <CANpmjNPxzOFC+VQujipFaPmAV8evU2LnB4X-iXuHah45o-7pfw@mail.gmail.com>
Subject: Re: Finally starting on short RCU grace periods, but...
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Kostya Serebryany <kcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gOvhi5v7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

+Cc kasan-dev

On Thu, 6 Aug 2020 at 01:08, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> Hello!
>
> If I remember correctly, one of you asked for a way to shorten RCU
> grace periods so that KASAN would have a better chance of detecting bugs
> such as pointers being leaked out of RCU read-side critical sections.
> I am finally starting entering and testing code for this, but realized
> that I had forgotten a couple of things:
>
> 1.      I don't remember exactly who asked, but I suspect that it was
>         Kostya.  I am using his Reported-by as a placeholder for the
>         moment, but please let me know if this should be adjusted.

It certainly was not me.

> 2.      Although this work is necessary to detect situtions where
>         call_rcu() is used to initiate a grace period, there already
>         exists a way to make short grace periods that are initiated by
>         synchronize_rcu(), namely, the rcupdate.rcu_expedited kernel
>         boot parameter.  This will cause all calls to synchronize_rcu()
>         to act like synchronize_rcu_expedited(), resulting in about 2-3
>         orders of magnitude reduction in grace-period latency on small
>         systems (say 16 CPUs).
>
> In addition, I plan to make a few other adjustments that will
> increase the probability of KASAN spotting a pointer leak even in the
> rcupdate.rcu_expedited case.

Thank you, that'll be useful I think.

> But if you would like to start this sort of testing on current mainline,
> rcupdate.rcu_expedited is your friend!

Do any of you remember some bugs we missed due to this? Can we find
them if we add this option?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPxzOFC%2BVQujipFaPmAV8evU2LnB4X-iXuHah45o-7pfw%40mail.gmail.com.
