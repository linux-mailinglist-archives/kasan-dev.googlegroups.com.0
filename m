Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5PT3P4AKGQEVDFBGVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id A6E672281E7
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 16:21:42 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 104sf10041464otv.13
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 07:21:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595341301; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVuePUAd8XpbJOpUhJqv4NkU7E1zWrYEImIj12ZZVMEGfUsrR4D4uiA4sB76Yq3a7n
         Jm4BL87uVaMRux5PdBAzpLuBLs3DAHqq/35KkIFhcj60e5v92aTnJ146vpiL2DL8vJ/V
         j0x5mayuANATEZ7I+nrGLmqndbUQ6+eg1udrbs61SxjsZrwkXU9+IKEHX56zhO9QIf5T
         GhC1xtVnADkGHzfASNmC/Z4NOjnBKsjjIA15VVc2qW7GDbZSrwgEC4XXRmh7o4JTcRjA
         x/iO1BKw7JY2elGDP2v7aMedjYzhmQ56q1ukStnkD2FoWt/4H1RG5nT6LbMRTZcEr+St
         60KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CwIQ2gyoMs8Drs/bK1zXmxvUVav06gCa87W7VNcDGnw=;
        b=l9SLnTxpnzMHox5EPPiI0VRnw4MUBqwA8BUCMeYG/NhwggthBTh8EjTEjedYffAxzh
         0/Zm2/v1P3IRe8mjcrCMXzqyTpH4VminJDIEt9tEOK7lcn0aDCTojdKhm9W9SbeDyqh8
         xib5NsPwr3l5hWTTqnGIy+wWFiq5LdwX7S7+4Zu5hUN1egCRA/peXO5RHDVoGXMiqH4n
         9Nxq+KBubgDDJUGLFXz9JoA/VtH1rYo+xtZf1NefbrOFFJ6D2sXz6rrxnU5MtYYpk4Vw
         lU0Z3rBYzl9L0Xfo0Ie+oCjcrHsHklcQYEemKim46KcFPO14roVLMMp+R6ir9MMFOimY
         Zgwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g7kYPNqC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CwIQ2gyoMs8Drs/bK1zXmxvUVav06gCa87W7VNcDGnw=;
        b=WxEKKT566ztoOiyBUDPiY6BHNp4rtsDNd1hgLAN2pvM0r/0S+Cay5Y/8dNn4vS/aGK
         kX1Qnibu88O8qU367uLCwYw7FLtHXnXMDxmMGy6ieV5gjX2tKWcaBcFTcq5ZW3Q3waYb
         /uY5pBoB0K6WD4mcRn+jnzpUH6AzWY5tulD/azQzJM1+gtFRbGmf5cKYR+Oj/XbNKhCv
         9URTzQ6fQYFda6mcwxuxERpfojtzbHOB992D1W0rao5I0DR6azEfrJXHEpa3qxkjyLzY
         MhyyXRp1j6FLA3tXZb4GAppbMBCIhg1MrciBDSgrBPGDg9WBhjFd9TrrM+PdKIcs7ZiY
         qvEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CwIQ2gyoMs8Drs/bK1zXmxvUVav06gCa87W7VNcDGnw=;
        b=tR8HRS8LBUoWaDWVrfYcN5QpYOwljPXPrLiBowztXUA4MXg8rPFhwrw0ypnJljHZI+
         4qjXr/D40txFwbqWVirDIOWGPMbjKwKtYFS7uSmJN/0BL0CoTuAx75lvF8dBaD0ProjL
         8Nt3ut6TyVuBh4t0d+rRTNs4WuWuR9vB0Ixl+pI1Lt6NufHWP6Qsiwpqrcl0KJPqnZXC
         a5bKtrr9yIR2eogZ4/tSYxFe5i8TVjGbXFpOvG7q1oKS/2j+SnGMaZmALUpQcc0IZie3
         n0hhe2Q/Y7ns5wfHaVHJtmRap/Au7zzvCxGy8WxggU6PqjbIBzAzyH4g1HHrtriFVEEG
         pQow==
X-Gm-Message-State: AOAM53075v78W6fHUWTwkuPd2wSej+kssxGEdFBM58bMneRXaE6r87e4
	B3SwliYbV80hwmYVGSHwxGI=
X-Google-Smtp-Source: ABdhPJzQwbgbVPhjlLXAbuaM/O9454KQD9sTmSYOemUYTHMpQheZ4yow/3M12Jy8+A7ysFlZ+uO0Gw==
X-Received: by 2002:a9d:6484:: with SMTP id g4mr25881856otl.103.1595341301655;
        Tue, 21 Jul 2020 07:21:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1599:: with SMTP id i25ls3969901otr.3.gmail; Tue,
 21 Jul 2020 07:21:41 -0700 (PDT)
X-Received: by 2002:a9d:634d:: with SMTP id y13mr24291569otk.274.1595341301316;
        Tue, 21 Jul 2020 07:21:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595341301; cv=none;
        d=google.com; s=arc-20160816;
        b=LMmccwXwgFL47QuyS9VKIOQAL49WRT2PwMCrFYNI0bD5wAwlO+TkGKuItmudVIFD1t
         xQKhR48j4PNlZj/vwdFqAPl+sQD6SEei4UnbzOi9D7hzlDrALQWsoQl2Ne5HbLbxKYfS
         D5abAmDg/KHkNg7R5vLJCTsXM8scEWSvxE5s2Pxvwemf6WfLFYVnY6agSWyLTVLk7Uw/
         sxzTurdjy8IQXqlEteZ8jmz6F5sjVWO4qRYNqIC2sqPZiBfCRF+N1tqBkSDGCZyjbt+r
         /YGcng79Qq8lIhdMpbNWeCI4ViAm4IPg1nDQMwdKywUs9HBXBZuGpIv8QfQ7hbO79Bhu
         5wDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h3blU9DE8kAEI9eRjgIJ+1oJjjf2jq7rcjTXCotUTV0=;
        b=hqOd61k4gZNrHqU5ib/u1k33FyGKc9mlGVZKv0PJozrZi30cBg6DH1E4awv9Y6gOSG
         aba6U9RfqDokAE34af/hTc4G3uNc56RlcBZWmqwME7o8Rx2q9kRtXAL2iBCDhs3I+POk
         0R87E47ypd4MphrBnpkhGXp1OTm/YrJXiIWhg9zZqu2ebP1ONVRFtnv4T32feThT26y9
         P9+s4YUn29lCdFha/Gk6hPsUvEiAt73W4jBRTFhASg6mHxMnu0adggm9EEhCGmv2Nvge
         s2OVNgMvgOfy2eKu436dY8hjbhCYRm0ZXloKyV3yFNy1z5zeVtKfd+fesVjsucETqrc7
         IyxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g7kYPNqC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id n26si132028otk.5.2020.07.21.07.21.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 07:21:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id k6so17309894oij.11
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 07:21:41 -0700 (PDT)
X-Received: by 2002:aca:cf4f:: with SMTP id f76mr3216158oig.172.1595341300634;
 Tue, 21 Jul 2020 07:21:40 -0700 (PDT)
MIME-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com> <20200721103016.3287832-5-elver@google.com>
 <20200721140929.GB10769@hirez.programming.kicks-ass.net>
In-Reply-To: <20200721140929.GB10769@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Jul 2020 16:21:29 +0200
Message-ID: <CANpmjNNCrz+d6FOWCkC68NKO3PFToY1seRRKVQmn_KHa4D07hA@mail.gmail.com>
Subject: Re: [PATCH 4/8] kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g7kYPNqC;       spf=pass
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

On Tue, 21 Jul 2020 at 16:09, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Jul 21, 2020 at 12:30:12PM +0200, Marco Elver wrote:
> > Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks for the builtin atomics
> > instrumentation.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > Added to this series, as it would otherwise cause patch conflicts.
> > ---
> >  kernel/kcsan/core.c | 25 +++++++++++++++++--------
> >  1 file changed, 17 insertions(+), 8 deletions(-)
> >
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index 4633baebf84e..f53524ea0292 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -892,14 +892,17 @@ EXPORT_SYMBOL(__tsan_init);
> >       u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
> >       u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
> >       {                                                                                          \
> > -             check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);                      \
> > +             if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> > +                     check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);              \
> >               return __atomic_load_n(ptr, memorder);                                             \
> >       }                                                                                          \
> >       EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
> >       void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
> >       void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
> >       {                                                                                          \
> > -             check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
> > +             if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> > +                     check_access(ptr, bits / BITS_PER_BYTE,                                    \
> > +                                  KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);                    \
> >               __atomic_store_n(ptr, v, memorder);                                                \
> >       }                                                                                          \
> >       EXPORT_SYMBOL(__tsan_atomic##bits##_store)
> > @@ -908,8 +911,10 @@ EXPORT_SYMBOL(__tsan_init);
> >       u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
> >       u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
> >       {                                                                                          \
> > -             check_access(ptr, bits / BITS_PER_BYTE,                                            \
> > -                          KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
> > +             if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> > +                     check_access(ptr, bits / BITS_PER_BYTE,                                    \
> > +                                  KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> > +                                          KCSAN_ACCESS_ATOMIC);                                 \
> >               return __atomic_##op##suffix(ptr, v, memorder);                                    \
> >       }                                                                                          \
> >       EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
> > @@ -937,8 +942,10 @@ EXPORT_SYMBOL(__tsan_init);
> >       int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
> >                                                             u##bits val, int mo, int fail_mo)    \
> >       {                                                                                          \
> > -             check_access(ptr, bits / BITS_PER_BYTE,                                            \
> > -                          KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
> > +             if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> > +                     check_access(ptr, bits / BITS_PER_BYTE,                                    \
> > +                                  KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> > +                                          KCSAN_ACCESS_ATOMIC);                                 \
> >               return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
> >       }                                                                                          \
> >       EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
> > @@ -949,8 +956,10 @@ EXPORT_SYMBOL(__tsan_init);
> >       u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
> >                                                          int mo, int fail_mo)                    \
> >       {                                                                                          \
> > -             check_access(ptr, bits / BITS_PER_BYTE,                                            \
> > -                          KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
> > +             if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> > +                     check_access(ptr, bits / BITS_PER_BYTE,                                    \
> > +                                  KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> > +                                          KCSAN_ACCESS_ATOMIC);                                 \
> >               __atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
> >               return exp;                                                                        \
> >       }                                                                                          \
>
>
> *groan*, that could really do with a bucket of '{', '}'. Also, it is
> inconsistent in style with the existing use in
> DEFINE_TSAN_VOLATILE_READ_WRITE() where the define causes an early
> return.

Sadly we can't do an early return because we must always execute what
comes after the check. Unlike normal read/write instrumentation, TSAN
instrumentation for builtin atomics replaces the atomic with a call
into the runtime, and the runtime must also execute the atomic.

I'll add the {}.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNCrz%2Bd6FOWCkC68NKO3PFToY1seRRKVQmn_KHa4D07hA%40mail.gmail.com.
