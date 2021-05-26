Return-Path: <kasan-dev+bncBD52JJ7JXILRBSGCXKCQMGQEHVUJIOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7808D3920D8
	for <lists+kasan-dev@lfdr.de>; Wed, 26 May 2021 21:28:10 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id z3-20020a92cb830000b02901bb45557893sf1554305ilo.18
        for <lists+kasan-dev@lfdr.de>; Wed, 26 May 2021 12:28:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622057289; cv=pass;
        d=google.com; s=arc-20160816;
        b=Liru8wG0kYpipApXZ55T3/a2pKtw7iPYEI+WmVIAdg9dM+4FJ4z7/5OLDlKeBlead+
         SXn8C4akaxoHauc8NsSzuxNkX0sdntZx0eG6MWTEMOmEjNhWLTTgy6JIgx45nGK6mjTw
         ZJlUPia/SBFAxE/R+oXmf3nlPvT6ZunsWD0X6G/g9jkAycYuti1uV3LTlgLokZ7NQbl5
         yWLzzc6dBeQxkpsWB+et+isHoqBHFWRIep1BqU9XeNPHJcWhAdF7/5sX0R1lRd5v7r1w
         hBorxdTfF/yqH19HqkPz5yAp9P296D4FxpV4uAwpWsf9mX/x8v1NedlF+aeJTxxH/e9F
         Jrww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+h7O39XKh6xu/QSGPbB2B022ZRLkNNHndrE5I5cXFME=;
        b=KOApoVVxLP6LjSXM8BAS+qA9ZeYAjlp0DQePLVXwzSo7MAOLWW3MJsq9HpN82sT+th
         z+o0rsu8x+DaHLkjhGxyMluIgMlIzK2fvUvCxx75CKMR4dI1A53klBvuKZdCGj59nivd
         tVqc9wLGzZe8H2aTZvCRFS2DNzmeVX2dlSS3zkbuKHY/9EDBsPbw5XjDEaVpxRC72aiA
         QyIaR04CDneq1zCf97p035Cy4z7qlz7CstVAHEEx+h+N31Y1Sgvb0RTQobXxvFFH2kmB
         dUFDjc2WqF6oScLuUu2Zwvfrv9JOAD/RUJTTAMVgDEsCKdBXDd76BeHKtVFWFlWKpKwU
         529Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tPd2PAnB;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+h7O39XKh6xu/QSGPbB2B022ZRLkNNHndrE5I5cXFME=;
        b=ewYNvGEchNqMNrzyjs7bnfoIbG/AmRos766Pax3wHgTCgBqOzrHIif2Tlfezv7TgFL
         hKfP3Mbhh2VBYm0R/5B/rkZL1iLGuNx4o1ySRN85wa2pbt/gQgnJlruoalf7BTgr2swZ
         JC/xc4yUahPvK2TYjq3XXHXmzsOAswunj3fMWgf+D4JuVztLo6a6oSMA3e88+KP1qs9z
         vadhky5+Ni9VyZyiJ6mXjyCTlJ+5cPK1ddmDijyE8/dpUTBp/X8mxESInVxa19PJYFE2
         HQAIHDnlY9YdcQYk4Ei2bP8fRLrQL4iU2gfu13Y5PtbduFmd45AAqU6HHCgzII1cuYLg
         /hFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+h7O39XKh6xu/QSGPbB2B022ZRLkNNHndrE5I5cXFME=;
        b=cDQvBh3AF5tc0EjNDo3LbcZRWmVCxozL5i6GHueCxT0QyNUTVQPPCb97g2YPef9Yw+
         rQirrkB2/Hjmh1N0Y2oLarpMEK44B51SkXkGirYFz6JukzJ3SGQO2iukHrP7YysJumt8
         ew88/2dXerQLX6vbcdn+NnBjiaeUdG1qcsno0wBKE4WsKXT0Hv3OjNuorkb8Wu0lLF5M
         s5ahRtX0hByqKsJrXIYQ63k/x0LWzIkjzYC45QTRqB00aJ4GKFQs5z4WTHj8pUqnGI97
         LqyCTZ53yWhituHSzz4wXMKYcXsIJegnjHnP+J0LYwBAsWe3VEhP0NBaVb1vFfj2ml5P
         UvWQ==
X-Gm-Message-State: AOAM5313+57j1f7azj6lxhGbjP6iaeRSSrJ9jwJqOcQMSF4/3nzpR4Pc
	LqRZxmdPN1z5fqY4qf/1uGM=
X-Google-Smtp-Source: ABdhPJwAEdNMhD32O+J424MxKeKF95Lvlt/Ji3Rp9DUQM1qivA1VgNgrwhQpIAfSH0bRtTaKtpevNw==
X-Received: by 2002:a02:91c1:: with SMTP id s1mr4707846jag.61.1622057288970;
        Wed, 26 May 2021 12:28:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:15c9:: with SMTP id f9ls111640iow.1.gmail; Wed, 26
 May 2021 12:28:08 -0700 (PDT)
X-Received: by 2002:a5d:914a:: with SMTP id y10mr26975948ioq.156.1622057288585;
        Wed, 26 May 2021 12:28:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622057288; cv=none;
        d=google.com; s=arc-20160816;
        b=zieC+xFRkTsftnCvP2SVvuU7nY6VihDeaH+qP1gBHNCPZ7hJVLf7MSJWE8q7NZDw46
         P411Vtt70TqJ0a8bMZR+VfCoCW8kvFFM+WrL+KouQMwzDBYDuhEKXiL+H6b7Xd2Pi2SA
         O32h7xSptZtkEkZIBwA0Mge4CJJD+lx50U2f9j8KwVvdujHLOUM/A5z00EZS55iJEkq0
         T7wuXSAn6FjwOKrXTXw9FEmlJkOCrLSlnq99nPF/BQSzQDsEJCQqGdVgN5R6WOwfXH08
         vZncZB4TvqPhqCkhHFStebpnQDLjmSa8Y6a+PJGdsIA9+g5qH4cy4fGOiXJ+qYk0FGuG
         mlkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gCq8NcQxXA6r8RU5X2XGNe+9K0cAkn6vm+7mYoaBAcA=;
        b=PUGyL23bqIOfCC2mBlsdA8PWI6BuFcJCjIlx0zE2+U6eIBBBRr2SawCm90/4Y43Z5W
         XrbfHanfOaec6G/g0VQ9GJ/qqVTlyiwcfydjhi+u/O3nxr1CMPZV8PV2CaVZZdD8Lx1R
         7+eaSCSkGUc0aryMCDAk74koRZ65VON7uEropQlhM8uTa+WL7n19ylYbHJaxzm1It5PQ
         sRr6p+LKGSW1D5K2f1TelSFOLW9BNOtYCvzcZDgrA3J40KTGlpDg8xjhSSSaEz85OYuQ
         SRSOX6t/vdn1QRT7ph3JonMm8Esz7dZGgLSB0k5r8f4XD4hrRKcvgWcPJ2M88uOkApBz
         I+fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tPd2PAnB;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id l25si739ioh.2.2021.05.26.12.28.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 May 2021 12:28:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id n10so2232828ion.8
        for <kasan-dev@googlegroups.com>; Wed, 26 May 2021 12:28:08 -0700 (PDT)
X-Received: by 2002:a02:93a4:: with SMTP id z33mr4660280jah.107.1622057288166;
 Wed, 26 May 2021 12:28:08 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1620849613.git.pcc@google.com> <78af73393175c648b4eb10312825612f6e6889f6.1620849613.git.pcc@google.com>
 <YK4fBogA/rzxEF1f@elver.google.com>
In-Reply-To: <YK4fBogA/rzxEF1f@elver.google.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 May 2021 12:27:56 -0700
Message-ID: <CAMn1gO6e_CG9FLoy-xDom7VgjrnPWAUNMMJNbsBz+3kiATdy8Q@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: use separate (un)poison implementation for
 integrated init
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Evgenii Stepanov <eugenis@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tPd2PAnB;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d30 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Wed, May 26, 2021 at 3:12 AM Marco Elver <elver@google.com> wrote:
>
> On Wed, May 12, 2021 at 01:09PM -0700, Peter Collingbourne wrote:
> [...]
> > +void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
> > +void kasan_free_pages(struct page *page, unsigned int order);
> > +
> >  #else /* CONFIG_KASAN_HW_TAGS */
> >
> >  static inline bool kasan_enabled(void)
> >  {
> > +#ifdef CONFIG_KASAN
> >       return true;
> > +#else
> > +     return false;
> > +#endif
> >  }
>
> Just
>
>         return IS_ENABLED(CONFIG_KASAN);

Will do.

> >  static inline bool kasan_has_integrated_init(void)
> > @@ -113,8 +113,30 @@ static inline bool kasan_has_integrated_init(void)
> >       return false;
> >  }
> >
> > +static __always_inline void kasan_alloc_pages(struct page *page,
> > +                                           unsigned int order, gfp_t flags)
> > +{
> > +     /* Only available for integrated init. */
> > +     BUILD_BUG();
> > +}
> > +
> > +static __always_inline void kasan_free_pages(struct page *page,
> > +                                          unsigned int order)
> > +{
> > +     /* Only available for integrated init. */
> > +     BUILD_BUG();
> > +}
>
> This *should* always work, as long as the compiler optimizes everything
> like we expect.

Yeah, as I mentioned to Catalin on an earlier revision I'm not a fan
of relying on the compiler optimizing this away, but it looks like
we're already relying on this elsewhere in the kernel.

> But: In this case, I think this is sign that the interface design can be
> improved. Can we just make kasan_{alloc,free}_pages() return a 'bool
> __must_check' to indicate if kasan takes care of init?

I considered a number of different approaches including something like
that before settling on the one in this patch. One consideration was
that we should avoid involving KASAN in normal execution as much as
possible, in order to make the normal code path as comprehensible as
possible. With an approach where alloc/free return a bool the reader
needs to understand what the KASAN alloc/free functions do in the
normal case. Whereas with an approach where an "accessor" function on
the KASAN side returns a bool, it's more obvious that the code has a
"normal path" and a "KASAN path", and readers who only care about the
normal path can ignore the KASAN path.

Does that make sense? I don't feel too strongly so I can change
alloc/free to return a bool if you don't agree.

> The variants here would simply return kasan_has_integrated_init().
>
> That way, there'd be no need for the BUILD_BUG()s and the interface
> becomes harder to misuse by design.
>
> Also, given that kasan_{alloc,free}_pages() initializes memory, this is
> an opportunity to just give them a better name. Perhaps
>
>         /* Returns true if KASAN took care of initialization, false otherwise. */
>         bool __must_check kasan_alloc_pages_try_init(struct page *page, unsigned int order, gfp_t flags);
>         bool __must_check kasan_free_pages_try_init(struct page *page, unsigned int order);

I considered changing the name but concluded that we probably
shouldn't try to pack too much information into the name. With a code
flow like:

if (kasan_has_integrated_init()) {
  kasan_alloc_pages();
} else {
  kernel_init_free_pages();
}

I think it's probably clear enough that kasan_alloc_pages() is doing
the stuff in kernel_init_free_pages() as well.

> [...]
> > -     init = want_init_on_free();
> > -     if (init && !kasan_has_integrated_init())
> > -             kernel_init_free_pages(page, 1 << order);
> > -     kasan_free_nondeferred_pages(page, order, init, fpi_flags);
> > +     if (kasan_has_integrated_init()) {
> > +             if (!skip_kasan_poison)
> > +                     kasan_free_pages(page, order);
>
> I think kasan_free_pages() could return a bool, and this would become
>
>         if (skip_kasan_poison || !kasan_free_pages(...)) {
>                 ...
>
> > +     } else {
> > +             bool init = want_init_on_free();
> > +
> > +             if (init)
> > +                     kernel_init_free_pages(page, 1 << order);
> > +             if (!skip_kasan_poison)
> > +                     kasan_poison_pages(page, order, init);
> > +     }
> >
> >       /*
> >        * arch_free_page() can make the page's contents inaccessible.  s390
> > @@ -2324,8 +2324,6 @@ static bool check_new_pages(struct page *page, unsigned int order)
> >  inline void post_alloc_hook(struct page *page, unsigned int order,
> >                               gfp_t gfp_flags)
> >  {
> > -     bool init;
> > -
> >       set_page_private(page, 0);
> >       set_page_refcounted(page);
> >
> > @@ -2344,10 +2342,16 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
> >        * kasan_alloc_pages and kernel_init_free_pages must be
> >        * kept together to avoid discrepancies in behavior.
> >        */
> > -     init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
> > -     kasan_alloc_pages(page, order, init);
> > -     if (init && !kasan_has_integrated_init())
> > -             kernel_init_free_pages(page, 1 << order);
> > +     if (kasan_has_integrated_init()) {
> > +             kasan_alloc_pages(page, order, gfp_flags);
>
> It looks to me that kasan_alloc_pages() could return a bool, and this
> would become
>
>         if (!kasan_alloc_pages(...)) {
>                 ...
>
> > +     } else {
> > +             bool init =
> > +                     !want_init_on_free() && want_init_on_alloc(gfp_flags);
> > +
>
> [ No need for line-break (for cases like this the kernel is fine with up
> to 100 cols if it improves readability). ]

Okay, I'll make that change.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO6e_CG9FLoy-xDom7VgjrnPWAUNMMJNbsBz%2B3kiATdy8Q%40mail.gmail.com.
