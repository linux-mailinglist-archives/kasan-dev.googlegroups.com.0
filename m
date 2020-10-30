Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPXU6D6AKGQECLJOWLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 195212A0AB1
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 17:07:28 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id r9sf4861405plo.13
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 09:07:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604074047; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhMEtI1J3vXpx/CEr9Z67w3an5wA8KyydD+B8o3lDBB4mE5U9j6Wrq5yVRrE2j/8st
         GqrlFYaycyf2iMCTurp5q42MKIVS0xoZcnx/wpvdbrIlxQgznGV3VjC2zOvsZiAZXNsO
         U9AjzBNzu+2TNpL2LvJmkxLWSJ9rlfmjz/M7TV1immAPEsYoWF1v49Pwi6wX85EE1Y6j
         EYjlm/5KbY9FzNb59CmPj+uHhcYc1Mzx9ELQty8FSww4jjJp7Tx68yC0/rjlHRko6uoF
         iWHYcxXNGTkaROkqx+0XecUfPK/d67M0rtnBzg/K6t4qtRoI9xBiWXR8i0cGMpN2XZnx
         mVqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/L6x16pODtQQd2D3pmwNW9yMwkZN/2fFMWPUlxX/XYo=;
        b=tAQwpwtOfAx8Zto8tIPCg32WTVVpdsjjvOrIzRMJwoDKoRKm/G+22YcmnP8Z0El4IQ
         /2G+TkRFli9Jj5Hy+9w+YNl0BeSxaHn4wN58FnesmPMsKxt4taujOkmn0zbiW453T76j
         2ZsguUTejpC3JKB/mUdat3gO1rlp8VrtCAtfE8LGqfROvaqAIdJPd0+MW3zoRK3cSFQS
         Lbmuq2AOLgNzQIUgJHN7TKUncsJAY4JjDdRaw5/m/wWwgqZoftHzmX8138+K8eX5Gw03
         3KXKzYIZ/pJwsqd986J7ye9xniyPpE52enZpecvqMBVsr8iU8CUQYdmamSa1S6tCL53+
         v5Kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GrPpfjH1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/L6x16pODtQQd2D3pmwNW9yMwkZN/2fFMWPUlxX/XYo=;
        b=aYyoR4K2VubvgGb07z/Pt3Z7cvOeD0Zr1avz+wGW5XdNt5M0oBH8PqnYlckdaD5dUq
         pf17ijp3NQ7N8as62wFbagKrg8k4DSOlSewiyNbN0NQNl/lncBoBIS9jA8NuF9WVW/vJ
         mK+xnvY47OqRrF5HOEKl+zsJ4cPOsxOsBuTnkxVZr0KOTUDWwffiLPtpDqZZMd1fOIJj
         v0k2nYqlGykVFL03ddY3KOPVfUqvoBkKbLvUVU7eh2KzgRq93obyeNMRsQ43zqP2ykSw
         Sc7Ff3ZD5GI6jLPzq86pIIHQBoEoqFVtIe2Z6UzlEOROn3E1d2LBbmCNSALUtSxT5dBq
         hDaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/L6x16pODtQQd2D3pmwNW9yMwkZN/2fFMWPUlxX/XYo=;
        b=hMBd7DBTvjGQpBWSdj2CpHHZFtutxg4s6AsInN1TOWJZZd+P0KW9rz0VnHJFnQ+b1B
         3rfjJFBxjGaUjBahw3xXWX29122+Xs7rHtFcRbsruwkvqVYfxYzwWkLZsTmPyJHAcWVw
         CUd7d3S5neo9qwGl7J5H9VIH26uE/Sl6ilEmjHvbIeHT+rK6xps/UbDSIn6HMfq0YlBh
         yuw9ZLp3cPveqq+zPxLTWBD3B5t1aB8AVzefIy5hY6IRmhqUPLU2GzQDe12C1TNHSgVh
         Bs1V8jK6UZBaOYo3bbW7kamAxyqV6bxz31c/5UkGzT0hHgQdv4QhvZQf5bljHxhH87hF
         MGPw==
X-Gm-Message-State: AOAM531pFi2Y2spwZoktKPkzoIbcGZyBPnM7A2PwFxoqxfyqf8yIZ9Bn
	TKyKenhbAdXSErtAiBzRWmE=
X-Google-Smtp-Source: ABdhPJxU9k+M0sdsfXVJsPdew8EjwffvS+tfOclTBsv5G4euu5mneAV2kTNiZ7DJyIfB/y+v9qXtAw==
X-Received: by 2002:a63:50e:: with SMTP id 14mr2829978pgf.115.1604074046854;
        Fri, 30 Oct 2020 09:07:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e416:: with SMTP id r22ls2470272pfh.4.gmail; Fri, 30 Oct
 2020 09:07:26 -0700 (PDT)
X-Received: by 2002:a63:7b43:: with SMTP id k3mr2862444pgn.25.1604074046316;
        Fri, 30 Oct 2020 09:07:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604074046; cv=none;
        d=google.com; s=arc-20160816;
        b=fjhGIwSiwy19TAlhuOYG2bxl8kUXCfS4FklO6VhR/W4TMYOovm1W6X71xJ/vOWC5vi
         qXjjvNZd1HTXbVaJWiQ1H4W4DayJPZeJSZbg4RT4Vkp/2X4os5YwYkfwCC5WHzRO7UE1
         SUnwIW6Oh2iI2DCA4FusAgx+gwuc7BMD6gQrofvrgamftFb8lVx0Rw7Ut6ePNkEzMSGt
         EAhJlXlZEJsV9d4t5zDG11ozt26ahluEDhaGHswx6UVWC7KYj3OMpm0ZvA6sCZGoxD4o
         r1Lb4nOddq8GDZsenv8mhPJpD/9xYzlW/pEQdu3moM400UzOxNaScy/ghElyBXd0a8lZ
         MxCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=65NdEmArmPn2nuNEZO88L62AlLpra/5W/MBvA6ISo6c=;
        b=ZTDi3xsk8DmyTjAYa9ncK9Hv6De4+x/nb2uxdtXFM9eWh2qt9LntjoyEE6/JTxmN42
         OZi3NHhjcXW8VvsuvVMVldlqwOpnIx/swCJ1FjSeyMSuQNFrpf0janFWFv3JclCYRV36
         qu+JO6arimGn6hWZi8Kqis6SxMxILx6YQnEXWYCGb27gN4rd4M1QI55ewomtlLvzxHU5
         3pC8VZi1DcXtvpbFtqPWfHAUpvSXpda8KQQPw/WNiUrr+RhPJOqjALGx/0C4dxsCOGx4
         34xyEMUaAEpzm50u+n77hYBh19UTV8+6CBo5tB2lGWcCzLsLPhGskEbzjGbHfbDrtgnZ
         /Tgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GrPpfjH1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id t13si425405ply.2.2020.10.30.09.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 09:07:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id p17so3144595pli.13
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 09:07:26 -0700 (PDT)
X-Received: by 2002:a17:902:d888:b029:d0:cb2d:f274 with SMTP id
 b8-20020a170902d888b02900d0cb2df274mr9313310plz.13.1604074045822; Fri, 30 Oct
 2020 09:07:25 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <56b19be34ee958103481bdfc501978556a168b42.1603372719.git.andreyknvl@google.com>
 <CACT4Y+ZVjEQaQExenOPg-tXQKRE5wUEm_iDn5DUQH_4QC-DBzg@mail.gmail.com> <CAAeHK+x+5EcgiS8wZ9mbh-a32w4_CVOdrzw8yrtpPuquaJrPQA@mail.gmail.com>
In-Reply-To: <CAAeHK+x+5EcgiS8wZ9mbh-a32w4_CVOdrzw8yrtpPuquaJrPQA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 17:07:14 +0100
Message-ID: <CAAeHK+wKp_foQz9vnMbKA5hMqTgMK4Uczy8ZEb33S3j1rHX=Sw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 10/21] kasan: inline random_tag for HW_TAGS
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GrPpfjH1;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Oct 30, 2020 at 4:48 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Wed, Oct 28, 2020 at 12:08 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > Using random_tag() currently results in a function call. Move its
> > > definition to mm/kasan/kasan.h and turn it into a static inline function
> > > for hardware tag-based mode to avoid uneeded function call.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
> > > ---
> > >  mm/kasan/hw_tags.c |  5 -----
> > >  mm/kasan/kasan.h   | 37 ++++++++++++++++++++-----------------
> > >  2 files changed, 20 insertions(+), 22 deletions(-)
> > >
> > > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > > index c3a0e83b5e7a..4c24bfcfeff9 100644
> > > --- a/mm/kasan/hw_tags.c
> > > +++ b/mm/kasan/hw_tags.c
> > > @@ -36,11 +36,6 @@ void kasan_unpoison_memory(const void *address, size_t size)
> > >                           round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> > >  }
> > >
> > > -u8 random_tag(void)
> > > -{
> > > -       return get_random_tag();
> > > -}
> > > -
> > >  bool check_invalid_free(void *addr)
> > >  {
> > >         u8 ptr_tag = get_tag(addr);
> > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > index 0ccbb3c4c519..94ba15c2f860 100644
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -188,6 +188,12 @@ static inline bool addr_has_metadata(const void *addr)
> > >
> > >  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> > >
> > > +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > > +void print_tags(u8 addr_tag, const void *addr);
> > > +#else
> > > +static inline void print_tags(u8 addr_tag, const void *addr) { }
> > > +#endif
> > > +
> > >  bool check_invalid_free(void *addr);
> > >
> > >  void *find_first_bad_addr(void *addr, size_t size);
> > > @@ -223,23 +229,6 @@ static inline void quarantine_reduce(void) { }
> > >  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> > >  #endif
> > >
> > > -#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > > -
> > > -void print_tags(u8 addr_tag, const void *addr);
> > > -
> > > -u8 random_tag(void);
> > > -
> > > -#else
> > > -
> > > -static inline void print_tags(u8 addr_tag, const void *addr) { }
> > > -
> > > -static inline u8 random_tag(void)
> > > -{
> > > -       return 0;
> > > -}
> > > -
> > > -#endif
> > > -
> > >  #ifndef arch_kasan_set_tag
> > >  static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
> > >  {
> > > @@ -273,6 +262,20 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
> > >  #define get_mem_tag(addr)                      arch_get_mem_tag(addr)
> > >  #define set_mem_tag_range(addr, size, tag)     arch_set_mem_tag_range((addr), (size), (tag))
> > >
> > > +#ifdef CONFIG_KASAN_SW_TAGS
> > > +u8 random_tag(void);
> > > +#elif defined(CONFIG_KASAN_HW_TAGS)
> > > +static inline u8 random_tag(void)
> > > +{
> > > +       return get_random_tag();
> >
> > What's the difference between random_tag() and get_random_tag()? Do we
> > need both?
>
> Not really. Will simplify this in the next version and give cleaner names.

Actually I think I'll keep both for the next version, but rename
get_random_tag() into hw_get_random_tag() along with other hw-specific
calls. The idea is to have hw_*() calls for things that are
implemented by the hardware for HW_TAGS, and then define random_tag()
based on that for HW_TAGS and based on a software implementation for
SW_TAGS.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwKp_foQz9vnMbKA5hMqTgMK4Uczy8ZEb33S3j1rHX%3DSw%40mail.gmail.com.
