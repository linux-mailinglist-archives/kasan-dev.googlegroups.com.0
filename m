Return-Path: <kasan-dev+bncBDAMN6NI5EERBUXC2D5QKGQE634ICWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C748027E276
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 09:18:42 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 26sf277265ljp.19
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 00:18:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601450322; cv=pass;
        d=google.com; s=arc-20160816;
        b=p2t61zlHHxHTCp93P1HCgoeiyUXZyFhrsYRBbN+r38kfWMOQnQijdxsPX/yEGyhPrh
         ArJI5IkMslLIUqIf0GhXTM2Z+B85FnOhe4Z7NI7bGj1kvnQEjIh5qyCtDJHGlotGsclC
         5TGApIH7CwPFKAPEIGQ8vJmT00gqV1apfX9hy9lQRgi7FFofysBddewUGkslox4gg2uT
         6p02P7DzK5Um2mxkj/416a9fRbxmnI2RkpvOJKVZVanr9Kmmbpul7tlblP0sR1mTj0vv
         nTbPQ2OI3N1LAPZ8Au/Dpi8CO75HjwCz5wwhz1j8MfDzuNTTcywPB+jMlh6igpjVvNPs
         6Smg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:in-reply-to:subject:cc:to:from:sender
         :dkim-signature;
        bh=XTMOlmbE63L1xwgyDweKHHKwN+JbcAMjeImu/ONnPSo=;
        b=lJFzNPJo7OeJXHBQ3GCzIUuteDQaEPIWkMCgSutKqw1AtXAIjb9mevk07hZXMVAXUy
         nSzr21MIR4IM2AqfZwpNqU2j5qa/sykAg3MhItEayz2Jeb9nkWhkI2BGULS7K5PmKddg
         BMtNU99T88yone8KaWFaOECjrNFVff5DdzEkZHJMEpjr76lW5QHsG/Mbi8auPUhGUWgk
         x8ax/2AHiV9OkgTkABkStKspmo8V2me5S1QrVutxzbhxPW6DO4JdKy7zBA2caF8EjABJ
         U9g/ocmIZ7tlXbljQjGbTDItZOCL3mnBGQm7f+37giYMUGX3Ahd63BqCW5W33ICjtSKg
         tBuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=oiDx8cqR;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:date:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XTMOlmbE63L1xwgyDweKHHKwN+JbcAMjeImu/ONnPSo=;
        b=VRUldDMTX2TMLoOgdtiOS76pM7Rg2eKz0Mm6pPMhFZaihrOVvKgNfA30+mWbFY1/qa
         tiJB/RwgVPnWrGkfBd7lLJRadgUccCUX9hoZbtBzmyeTASDhxlRwsjQLjWwF1PraHAFM
         rTuleuJbGeqVB1Y9Lwjpai1ZTO3+o5i7ebtlQr2EaHLyo9MwA6DFJKKFX99uWf+J5cYs
         i98Yy87bzLsKjMRzgzugdFaT5IegzFKqPw2SEZzoZt/OgttN9evxnW7kmFULQTigCv5N
         2dd6CPJfsOZ6nltSicTabTLkY6DPpuC3dpaDiqq8yXxM+pX6rrjmAq8sfi5I+XZ0ajLp
         s1EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:date
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XTMOlmbE63L1xwgyDweKHHKwN+JbcAMjeImu/ONnPSo=;
        b=NOXFVKI95Y07aT9b77PzWGfFQd/Bn7lSh+M64Vp/p9tVhERthdACU1KH35BbaXIvJj
         WcrsWSXDlGFUUd20ZDicklpMS0dKFgKTvVRt/Cx2D6RHWPtuYuWjg/fNC7zRZ3a2e3iN
         07w3UAhKslk91bKXmxAAuyf6YQzhZrjZl+2oAYOSIVRbPCiTd3IPJ5x/1Lsay+YxhSKr
         72fF8fQoaiASp6yL3iBUCitnG8NSWi7AOCyquNXGaWuhhMurOcPXYvaZoLXcjcTNYP38
         DRzqCBlCmMJsDpr1Orhf3cY4xxpTgSRMlgGIaCd+mNvTNLtgwXUiZk6jZgj/Pr0V7F4C
         vl2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jGXl77ZYj1noZVKkaJ/i6KiMSLenO+5RSopGhpiu/DtoYoItZ
	uAQi3JiFhFvU5T9QjZdBSm4=
X-Google-Smtp-Source: ABdhPJwn56H/giXgpsYOdfxl5Uv7iku/skbf3Ex+Vp2zznW7Kbwu1hr6esVxlYpdmn8Z0SiYB0FqqA==
X-Received: by 2002:a2e:b4f5:: with SMTP id s21mr472471ljm.270.1601450322307;
        Wed, 30 Sep 2020 00:18:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls591353lff.0.gmail; Wed, 30 Sep
 2020 00:18:41 -0700 (PDT)
X-Received: by 2002:ac2:4315:: with SMTP id l21mr437281lfh.494.1601450321301;
        Wed, 30 Sep 2020 00:18:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601450321; cv=none;
        d=google.com; s=arc-20160816;
        b=ldGN8J/t4L4jbXd9xFEXiHR/0CvqLZDOMOLWsMms0xis5Ge6mPzcqirU9XC4l0v0Gt
         5WVoRBbrkjx+51d1dux67g1m8imoxi8wBpcR/AnxxwBUqkBkB3ssVY1CJ0O1sXI3dTfq
         IOg7gLs9ANRZNjVoT5A0kZZbqrHsSCOvaEzhoKjtNYHTL+ii17K32fd9/OSG5N1drxvK
         A8DQAei1APwMNNmg5UwC0VDDCmEiZ2cdqWY8DmWCXs7uOxHwtp31zJtD5dLhnKNeBxIm
         cWpRWJlZOxKizBbC4XD8KDTWRjd2jKA0aHouOc8WrhlPXsnOqk/NS2RugzClSWFZCMT7
         YKXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:in-reply-to
         :subject:cc:to:dkim-signature:dkim-signature:from;
        bh=qszLRp610KM1evPqkHZZ4TULFEPMDDCHrKhOHL9Calg=;
        b=EO0BBSU06Y3BNkdZqB0lcODNSmHSwLi4kURUy/T8YO2XLMBT4u8JeRR7eIcBX5wEhH
         B4MbVfcyv6eiLujIsMNijEM+RKKSYndwOlQaPsu3Rr5n6BJyDdWahYyGkuO7esNbJPiA
         sWfejCLlMZG9tX7XbNgMm/xD1jZNYq5KBA2Sws1s0g4jUGfJeWdnxhmIW9NlZW9TnuR4
         gTBPAFGYHTomFmRnsokP3tM1Xbr940k4dOW+zCkna/q1tyql+9fIkOZSJyN9X1TDCJ+c
         Jit+GjZBBCo0w2pfeRGYtYEZ4Lqgcu6y+hjiz47ORpgWjLPGdgOWXke06i0Y8FkkS34c
         6quw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=oiDx8cqR;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id y75si21760lfa.3.2020.09.30.00.18.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Sep 2020 00:18:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v4 1/6] timer: kasan: record timer stack
In-Reply-To: <1601140312.15228.12.camel@mtksdccf07>
Date: Wed, 30 Sep 2020 09:18:40 +0200
Message-ID: <87pn63ivfz.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=oiDx8cqR;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

Walter,

On Sun, Sep 27 2020 at 01:11, Walter Wu wrote:
> First, I think the commit log =E2=80=9CBecause if the UAF root cause is i=
n timer
> init =E2=80=A6=E2=80=9D needs to be removed, this patch hopes to help pro=
grammer gets
> timer callback is where is registered. It is useful only if free stack
> is called from timer callback, because programmer can see why & where
> register this function.
>
> Second, see [1], it should satisfies first point. The free stack is from
> timer callback, if we know where register this function, then it should
> be useful to solve UAF.

No. It's completely useless.

The problem has absolutely nothing to do with the timer callback and the
timer_init() invocation which set the timer's callback to 'dummy_timer'.

The timer callback happens to free the object, but the worker thread has
still a reference of some sort.

So the problem is either missing refcounting which allows the timer
callback to free the object or some missing serialization.

Knowing the place which initialized the timer is absolutely not helping
to figure out what's missing here.

Aside of that it's trivial enough to do:

  git grep dummy_timer drivers/usb/gadget/udc/dummy_hcd.c

if you really want to know what initialized it:

 dummy_timer+0x1258/0x32ae drivers/usb/gadget/udc/dummy_hcd.c:1966
 call_timer_fn+0x195/0x6f0 kernel/time/timer.c:1404
 expire_timers kernel/time/timer.c:1449 [inline]

That said, I'm all for adding useful information to KASAN or whatever
reports, but I'm not agreeing with the approach of 'Let's sprinkle
kasan_foo() all over tha place and claim it is useful to decode an UAF'.
Adding irrelevant information to a report is actually counter productive
because it makes people look at the wrong place.

Again: Provide an analysis of such a dump where the timer_init()
function is a key element of solving the problem.

Thanks,

        tglx

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87pn63ivfz.fsf%40nanos.tec.linutronix.de.
