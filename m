Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKHXTO7AMGQEKHORW3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BF33A4DECD
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 14:10:02 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e5789a8458esf8321839276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 05:10:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741093801; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z9rTSmGBL6klbAtfRoEczmhZmKIZ39GJuCWJSTMk3pa+Tw09kiXvuY9uJPLMwfMivh
         hIwYanTRW1N4blAjs4AH91D92dyzCR//kWVeOYNnSlQ8Ak2lpbol+vLmvNF27N5No3Px
         rc+bxmNkECzKac42baohFzAOLx1LcsH2LyBd0XGQBg+shahsHjLqHHV+8+5syYxVxgYa
         KtbVRrTfv6ZondGnSUaslki5ig2l9Fg87HUTkismjtV7vsctJW+ZJDFOIEc6H3/HfrpL
         uDfNl94fW79Rt1wAJK268wQGh5Pj+Miue1vsScmLghGRuHWdIaPWkyFvMB5MS0ygdgo4
         O0Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hzm9mCFbGh/nXNOJuwFjpHWvoB4Z0iVxotsyP69x3pI=;
        fh=zE8Z4cdU2FGQ/tTrqQtM+sBCmq27I3JKWhPRTU//gGM=;
        b=BKtRk1bj2jZSgOj3C0PRGYDG3P9i5lRZUsA/L/MOlK+ZZ+RAO3dSXl9AaCTZLz11aO
         u4P/uY/IqJ+okdcPWKDTx3/Vh+mVfXUv6ntz3VkBrlqiRRfS20zdTpRViqVUj8Gyb/aY
         6gmOVJuM51vx7o2h4ZIgfLFMss6A3OEq72XWLew1PAXlD+awOgJCDyDGQzkI+2wbyBc+
         gsdBDrSlbfDFO/gcG3keT0UjxzVPANz9ga2ls6KfESFo4aWvxXfvR354N4tC+yndMeE0
         f5x1jrhHXyWBK2pEgtK9jHvOqmB7sgU5v8WgYC9qXFuRDfpcDQZag/tZnR88Q3aI3t3y
         +I6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q+fZLRV2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741093801; x=1741698601; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hzm9mCFbGh/nXNOJuwFjpHWvoB4Z0iVxotsyP69x3pI=;
        b=j0G5Wov87Befvhdgy6ECo7WgRD4r+htTVJb3ajZTexdwm+Lmaq6T8RAavycgPQWulB
         1045ZqI98tyFwCC6srXVCGPnmw/60j/9YtWjgaRAHwc0ONS1MM5QJlWa9zqtYx++qPUH
         krjw53iAdBaxD7IDOLbEuOw8NNtpaJypU7e6ecYKeXm3bjl4rErEr2Gyt9PamuYaK4Ho
         r7aFc4GFa0422IgOX4SNnyekiaqy7jTfQp9Q4DjBH1Fyrx1nym0W2euRkmUyYXRSLO9W
         obYO51mAdu28IXsOMPrB5r4EtJ8VlDk+LkyY9mTjKDmicsb3R+TcXgvW9B041+hnhCs3
         zm1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741093801; x=1741698601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hzm9mCFbGh/nXNOJuwFjpHWvoB4Z0iVxotsyP69x3pI=;
        b=YBBk+W9+sVR/NIdDVeUT2altKMEvu5mlKf4OrT/mDBR1y+vdgzkGdZ3G+9SXgmQu2n
         xnfXpTKhvbmpe2Ltxr+00rFXYzWbBulBmVEytnysplTB8G1bUO/2lJ9N83N73j4ayUMa
         kXqUmyRDZoD4cZlnyEX3BzUhjwZacZOmB9BoalUnhGy/If0NQxf9VZih5LqVc1dqxoCC
         Ckg1MaiczpB+VmZWHZDkBtndTi7kG6npsB3yyWD1rxgQeWx7f2CxOR4OJFsTpitOmmx7
         d76VejJMV/9SNX1w6cDRdBgmz7eo58Gg4B4J4sfu+4c5/9t9Pe6HhZv/tZy+vqG577Fj
         N64A==
X-Forwarded-Encrypted: i=2; AJvYcCXQQpeKD0O90lxhArUqxacoRFLQPJKrJ87VLQ4CTAgzwvaGStUyRNK0DjcNlFGc+13NQAlgfg==@lfdr.de
X-Gm-Message-State: AOJu0Ywhz+MhBasmfWqRuVKipxZNptcaaqmLsaFcGPNiMKyE1d53i+Df
	8YmPfUAk6CMSMfER6+SpSPQSNMTZigzo2/Yw79KjLmdVaw7Npwwv
X-Google-Smtp-Source: AGHT+IFsoG6Xr0UJkhrTzYn3SMM7eEht8gKG9dWqaYMmtyGf2+6eq0FlYbrY8HcyGdsLDP7VdlnjVg==
X-Received: by 2002:a05:6902:228e:b0:e5d:cc41:767 with SMTP id 3f1490d57ef6-e60b2f15ad2mr18181791276.33.1741093800639;
        Tue, 04 Mar 2025 05:10:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFFMq2oBtV2vX5y1rUajwNAzIz+Gw9Ekda66GJCEtDn8w==
Received: by 2002:a25:ab2d:0:b0:e5b:1119:fc5b with SMTP id 3f1490d57ef6-e609ef32b5cls483120276.0.-pod-prod-06-us;
 Tue, 04 Mar 2025 05:09:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVwkDSqMWLxT5OJHDQkLX9kARqBrOW/4W3DBil+HuPw1/4bMYO3Tr/LyO+Y1uqrIRNno6q+jq/HZ9k=@googlegroups.com
X-Received: by 2002:a05:6902:727:b0:e60:865e:cfe0 with SMTP id 3f1490d57ef6-e60b2f2edabmr20739587276.48.1741093799520;
        Tue, 04 Mar 2025 05:09:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741093799; cv=none;
        d=google.com; s=arc-20240605;
        b=TP4/vXg/Js1Q5WkpReFmrhCYIBOqwsERFjad8XlWkl4ZIPa5vzLoo/OvVLRAzDoGdp
         0GlubGwRwVNSoHdLIsTktkVultH7OKFuGIZU3r7EgYK8qCx+1tX8isYzXWsvbDf48OwZ
         vwiUChOAoMUNMxczMi6NVD7bAvd/M18s/4mYJJkur2aR7XwYB8B+V+czwh5etLTYgdFa
         uUXcLG/bCmRQkgCRmiXVm7Pv8T43xcHoc4Vl1byVLTMh9WoEhw8yNHRWy3lOtmp752AA
         /Gmf+x7HnYUaD/KtW9NJtIFULZl0vW3XcEF52Gh5uDHSWyjRedUqTcsyzw3Ao5Re0Zt3
         IGrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x117HPWY7hfxCsyRoomSLqnsp6TkG/IZ7mxFwBfWDy4=;
        fh=/lgw8t5KmF24SJs9XAIInSdecFmpSj6S52yrkvQTOEc=;
        b=ALokDlk2o3ZESInr7hbgyH/EkRz4W/bvVIWqZzFgOpZgAjjGzg73dQwMybFMzxJed+
         w2H4eMmvQpfuKetFT8DOYLrwNTeMw9rA0Qa2avhE/V2GNNN28avPUu8mSwi7BhTwHSMY
         3sXfwNE7ExIKSduXJOX61WLEBoxD4bg9qGNtsWyexp7sRfCgQX9FV3+lxoG8BORvAv5y
         PArzt29ku7IRDbXWb0TzDo4ZG+7DFLC06186kyfv97lQu9pvFdXxQYN7ovOU3yAMEMJs
         mYfrPgy8UhXB+Y92cdVRacY4E1T0COt3fg6tRB8prZ/4GTnMaId7EX0qjw9YIz17BWKp
         WTSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q+fZLRV2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e61123e19d4si68675276.3.2025.03.04.05.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 05:09:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-2233622fdffso105042915ad.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 05:09:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWNhk5ZMJ2rDa/S8waPOlWHgVlGUy1KzAPnWn71NBlFPmJbd6S5SnAH3oDID7Qs3+Rik8eIYOt+9Yg=@googlegroups.com
X-Gm-Gg: ASbGnctq/tnilLx/QbSSgCDfNGu7FjeEli/3LbpGEWjeS8ew18ThXDtOagY0g7b3nIw
	kZsIKFWWI/CTLujv7cSslqZdn+XGjO2+JVQH04lNc2TvFT8yLgIQ4rX+D1+RgtnmYc8356w7YIu
	OyK8nmTDHvmcyhEL/Cv69OOzYD34doVkXfD5Z7Tvz8tdhi+3S78kd0Kvx+
X-Received: by 2002:a17:902:ec91:b0:223:5ada:2484 with SMTP id
 d9443c01a7336-2236926e8bemr319887595ad.44.1741093798418; Tue, 04 Mar 2025
 05:09:58 -0800 (PST)
MIME-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com> <20250304092417.2873893-7-elver@google.com>
 <20250304125516.GF11590@noisy.programming.kicks-ass.net>
In-Reply-To: <20250304125516.GF11590@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Mar 2025 14:09:21 +0100
X-Gm-Features: AQ5f1JpRduzHYdRlbPZG29NFbDiaHAHst1RMQPMNTm3NjpUDRIeFlhtOLA45DL8
Message-ID: <CANpmjNNNB8zQJKZaby8KNu8PdAJDufcia+sa2RajWm6Bd2TC4A@mail.gmail.com>
Subject: Re: [PATCH v2 06/34] cleanup: Basic compatibility with capability analysis
To: Peter Zijlstra <peterz@infradead.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=q+fZLRV2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 4 Mar 2025 at 13:55, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Mar 04, 2025 at 10:21:05AM +0100, Marco Elver wrote:
> > Due to the scoped cleanup helpers used for lock guards wrapping
> > acquire/release around their own constructors/destructors that store
> > pointers to the passed locks in a separate struct, we currently cannot
> > accurately annotate *destructors* which lock was released. While it's
> > possible to annotate the constructor to say which lock was acquired,
> > that alone would result in false positives claiming the lock was not
> > released on function return.
> >
> > Instead, to avoid false positives, we can claim that the constructor
> > "asserts" that the taken lock is held. This will ensure we can still
> > benefit from the analysis where scoped guards are used to protect access
> > to guarded variables, while avoiding false positives. The only downside
> > are false negatives where we might accidentally lock the same lock
> > again:
> >
> >       raw_spin_lock(&my_lock);
> >       ...
> >       guard(raw_spinlock)(&my_lock);  // no warning
> >
> > Arguably, lockdep will immediately catch issues like this.
> >
> > While Clang's analysis supports scoped guards in C++ [1], there's no way
> > to apply this to C right now. Better support for Linux's scoped guard
> > design could be added in future if deemed critical.
>
> Would definitely be nice to have.

Once we have the basic infra here, I think it'll be easier to push for
these improvements. It's not entirely up to me, and we have to
coordinate with the Clang maintainers. Definitely is on the list.

> > @@ -383,6 +387,7 @@ static inline void *class_##_name##_lock_ptr(class_##_name##_t *_T)       \
> >
> >  #define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)                   \
> >  static inline class_##_name##_t class_##_name##_constructor(_type *l)        \
> > +     __no_capability_analysis __asserts_cap(l)                       \
> >  {                                                                    \
> >       class_##_name##_t _t = { .lock = l }, *_T = &_t;                \
> >       _lock;                                                          \
> > @@ -391,6 +396,7 @@ static inline class_##_name##_t class_##_name##_constructor(_type *l)     \
> >
> >  #define __DEFINE_LOCK_GUARD_0(_name, _lock)                          \
> >  static inline class_##_name##_t class_##_name##_constructor(void)    \
> > +     __no_capability_analysis                                        \
>
> Does this not need __asserts_cal(_lock) or somesuch?
>
> GUARD_0 is the one used for RCU and preempt, rather sad if it doesn't
> have annotations at all.

This is solved later in the series where we need it for RCU:
https://lore.kernel.org/all/20250304092417.2873893-15-elver@google.com/

We can't add this to all GUARD_0, because not all will be for
capability-enabled structs. Instead I added a helper to add the
necessary annotations where needed (see DECLARE_LOCK_GUARD_0_ATTRS).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNNB8zQJKZaby8KNu8PdAJDufcia%2Bsa2RajWm6Bd2TC4A%40mail.gmail.com.
