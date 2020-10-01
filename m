Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6NC3H5QKGQEZKPCT5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D94772809CF
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 00:00:26 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id r128sf4910992pfr.8
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 15:00:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601589625; cv=pass;
        d=google.com; s=arc-20160816;
        b=bcE7A3woMrxTOAcxjvRnoa2IutUc3Ra71N2ZmyOvuTFqQaLW1A6SfneVgSAa2buLAg
         c7LI8dziGe4fmXaD/tHWCXbiBW+YeQpwevIVuO8zlB7Emux/fV/a5rx7nETzYJPC5HqH
         2YTERWzaaJwwX6Bb6tkNxb7SmEqbAdsiZEo2r+RTdAd+05Wus9QgKeezcyHa3ykIJeQe
         kY+i/ayBMCT7tUoems+BhY5kXniS9GEkubJobs8z/sjojsGVX4HN1OYxxIIoR0O8Zuk+
         dHAAYpQeZB0X83MHHAX0dh5ZUXrVjutlji0UW9Hqr9+MoqB256oEA465JpLI1hkVPu7h
         s/8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JJcscyFnuWHoihIILub0kupKiPV3B0AFrk6Ex0U1JQE=;
        b=03yi6KGubo+Njl94y5FUKlPOXjlSHfbVTnuWLTzJkqjIQSBriYa6hLjPTk3e9OZ4wV
         o3EOfV68C26StJqktNCEW8capaC7p7iQ5Jw/GT5TzIO6I90NOrdV9VoFyzG25/4zYA3d
         T/4rTbF+xLgXoqB+T6ZbuUHa2H0AKKXNxaJaUxqDsPcYjlU03S9bFu5vQKVkNPsjnraL
         ult0H+rD+ev6swzBwavguBmelUap/kmDGsGQ9q+Utmx0BdOHYTbDcA1NPFDKWwMcQSdM
         Uy8NGFpfCQ4E0iRbI7cYL9s/aem+T+5TJPFZE4wx6r1NzH81XhSdl5OUsaK8T9lKFKH/
         yayA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZSGA97mf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JJcscyFnuWHoihIILub0kupKiPV3B0AFrk6Ex0U1JQE=;
        b=UG1CTR6yMVboPv0pcbMrgmPHolX0ANbmTZvPgIUFGeP0COrY6fUimxYimKDLct+2VU
         XxOuZuC/NVrVTr98CpiKLdG6TkyfwFcOYUsZMjAKFq2nH8mnQIvArqS/ArMYam/eYR10
         E/dGrZTk4WF9JPOkUCQZsEZKMDVwo6pT0VJqedKtK/tDftvPtiz/ES5VIY3mISuTL5Ha
         yVNKGQMNCldh56VFvKgBUpkn/rJowym3729z1B0qn5fKKWJgbSYQtN/hE+XKKc6sIdrz
         4nTdUi4pm4ADkcxtyRo5vd2mscNoLvtXxkxBikUVdZCuPz4Q3vDtT0Rxlx3sMRwDGdxB
         fxUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JJcscyFnuWHoihIILub0kupKiPV3B0AFrk6Ex0U1JQE=;
        b=KbSvkVKSqL8I0Ocy1dLBFP125zICrAQ58BENmycDitpRUWyg3gpAzHK9SwNyCjxMfP
         8Ys+ziLTWAqr7lGDT0F/JXp+ZnrY16BDkmrrit9zQ6xv2/+9lUKbLlL+Ovt1i3Yh9aix
         qgN1e9DDCSFeJLqQ1B/CFvtUBXieINoiKrQBvKh3Iu3Yc8qXJYvjowzoTyQr8uSSMqRq
         7ZZOMFWHrOQXWu98BTiZoPpVlWSaOxv/Lgqqi8GcO6AiAhsw8A52u+nnMZZprD+DB2Up
         wQ+LxuWl9ZfWhQUEBgVCUho2hD5ajQuYpFcp5W56JNr0lpiVh6sMxI40xrkAHfhftmQd
         yH2A==
X-Gm-Message-State: AOAM532lP1gzZhI3s8wuFGSuUTYI3+J/agzmVDUTcjGKcFsnIm60/ELB
	4ddTwP31pRfEJWBMiq44gdw=
X-Google-Smtp-Source: ABdhPJwKoiuJTc/tpMmyVmjKJmYZ+2C3X6YMDQCIagF1weQttsu6uXSgttQ52SqRs7xN2Eo5dUbOyA==
X-Received: by 2002:a17:902:ec05:b029:d2:ab3c:dc4f with SMTP id l5-20020a170902ec05b02900d2ab3cdc4fmr6349331pld.81.1601589625602;
        Thu, 01 Oct 2020 15:00:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7808:: with SMTP id t8ls2747791pfc.4.gmail; Thu, 01 Oct
 2020 15:00:25 -0700 (PDT)
X-Received: by 2002:a63:ff5d:: with SMTP id s29mr8089540pgk.442.1601589624962;
        Thu, 01 Oct 2020 15:00:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601589624; cv=none;
        d=google.com; s=arc-20160816;
        b=DW+rlv+TYCVjIAP4L9duJ0c86IGHWJU+XM/iVm8OHTPiZMD3Ko2gE7PsVGZw80iU2R
         s+td9SlTPe/UT9YtqXB0JFqNOGpBImDuLne0VPoqHz81UsgfrJDNPWp8y1HvAS7Pp0PE
         v5FTxkWUjEFGfBf5d0v5aNBnSGEiG8NrdePUbbAK9Ml05b82IN44s0xJlW82CSjIrglW
         CNBdxjejHPgFw7uN2z80U7Cs45B/e9P8w9S6E3diaD085TjT/NTbUStzVMCY0XMiI1wY
         8DqhR5348iyzzW4mhgHEJ9Zm1eYcq4t66zvVnpolaOJtZV2qFhbUkYETw4a1CdWrx8Cr
         YqPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hBBalclCDJxdO5s6VuYFGVKLPJcYbuOqTzhejbkPQcI=;
        b=wd96sc4Nzf0mFYMq3D4t8ZlaYMc4ZMJgM11/1eIbEXmqgwNgOcG45p5FsBQU33MGZU
         B9rZx25EpJGZhfeU4syfCC2hMBNifvsQ/F55vYCB4JdQIjc49qIBGOu+hK+HeEGz8XuS
         3rysQkhSIf7LCQhiLA+EOZQApumONh9g63PghomoQ0yWTWITZiPxsk8k0J6kNLTe6iaf
         k2Uc9iPfX3ladzkqKYGAeaj+C4cA/5PKC3RvDTbt1VS8sS4e2QW7JzHtMGN1pYVaBDAD
         fzpYir4zRVUm+vF/DV7KOQT9xxlPXdvTa+Y4rZTm6kmR+iPdtQ63UnHDD512CW7/IhP0
         BOwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZSGA97mf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id r23si212685pje.0.2020.10.01.15.00.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 15:00:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id q123so5991301pfb.0
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 15:00:24 -0700 (PDT)
X-Received: by 2002:a63:5d07:: with SMTP id r7mr7817410pgb.440.1601589624408;
 Thu, 01 Oct 2020 15:00:24 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com> <a9229404628ab379bc74010125333f110771d4b6.1600987622.git.andreyknvl@google.com>
 <20201001180329.GV4162920@elver.google.com>
In-Reply-To: <20201001180329.GV4162920@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 00:00:13 +0200
Message-ID: <CAAeHK+wiR0o2uSqmvuoCbVQS6ZvcLVpGP-+OAC_K-6wMDQ3xiQ@mail.gmail.com>
Subject: Re: [PATCH v3 37/39] kasan, slub: reset tags when accessing metadata
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZSGA97mf;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
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

On Thu, Oct 1, 2020 at 8:03 PM <elver@google.com> wrote:
>
> On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> > SLUB allocator accesses metadata for slab objects, that may lie
> > out-of-bounds of the object itself, or be accessed when an object is freed.
> > Such accesses trigger tag faults and lead to false-positive reports with
> > hardware tag-based KASAN.
> >
> > Software KASAN modes disable instrumentation for allocator code via
> > KASAN_SANITIZE Makefile macro, and rely on kasan_enable/disable_current()
> > annotations which are used to ignore KASAN reports.
> >
> > With hardware tag-based KASAN neither of those options are available, as
> > it doesn't use compiler instrumetation, no tag faults are ignored, and MTE
> > is disabled after the first one.
> >
> > Instead, reset tags when accessing metadata.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> Acked-by: Marco Elver <elver@google.com>
>
> I assume you have tested with the various SLUB debug options,

Yes.

> as well as
> things like memory initialization etc?

Will test before sending v4.

Thanks!

>
> > ---
> > Change-Id: I39f3c4d4f29299d4fbbda039bedf230db1c746fb
> > ---
> >  mm/page_poison.c |  2 +-
> >  mm/slub.c        | 25 ++++++++++++++-----------
> >  2 files changed, 15 insertions(+), 12 deletions(-)
> >
> > diff --git a/mm/page_poison.c b/mm/page_poison.c
> > index 34b9181ee5d1..d90d342a391f 100644
> > --- a/mm/page_poison.c
> > +++ b/mm/page_poison.c
> > @@ -43,7 +43,7 @@ static void poison_page(struct page *page)
> >
> >       /* KASAN still think the page is in-use, so skip it. */
> >       kasan_disable_current();
> > -     memset(addr, PAGE_POISON, PAGE_SIZE);
> > +     memset(kasan_reset_tag(addr), PAGE_POISON, PAGE_SIZE);
> >       kasan_enable_current();
> >       kunmap_atomic(addr);
> >  }
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 68c02b2eecd9..f5b4bef3cd6c 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -249,7 +249,7 @@ static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
> >  {
> >  #ifdef CONFIG_SLAB_FREELIST_HARDENED
> >       /*
> > -      * When CONFIG_KASAN_SW_TAGS is enabled, ptr_addr might be tagged.
> > +      * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tagged.
> >        * Normally, this doesn't cause any issues, as both set_freepointer()
> >        * and get_freepointer() are called with a pointer with the same tag.
> >        * However, there are some issues with CONFIG_SLUB_DEBUG code. For
> > @@ -275,6 +275,7 @@ static inline void *freelist_dereference(const struct kmem_cache *s,
> >
> >  static inline void *get_freepointer(struct kmem_cache *s, void *object)
> >  {
> > +     object = kasan_reset_tag(object);
> >       return freelist_dereference(s, object + s->offset);
> >  }
> >
> > @@ -304,6 +305,7 @@ static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
> >       BUG_ON(object == fp); /* naive detection of double free or corruption */
> >  #endif
> >
> > +     freeptr_addr = (unsigned long)kasan_reset_tag((void *)freeptr_addr);
> >       *(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
> >  }
> >
> > @@ -538,8 +540,8 @@ static void print_section(char *level, char *text, u8 *addr,
> >                         unsigned int length)
> >  {
> >       metadata_access_enable();
> > -     print_hex_dump(level, text, DUMP_PREFIX_ADDRESS, 16, 1, addr,
> > -                     length, 1);
> > +     print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
> > +                     16, 1, addr, length, 1);
> >       metadata_access_disable();
> >  }
> >
> > @@ -570,7 +572,7 @@ static struct track *get_track(struct kmem_cache *s, void *object,
> >
> >       p = object + get_info_end(s);
> >
> > -     return p + alloc;
> > +     return kasan_reset_tag(p + alloc);
> >  }
> >
> >  static void set_track(struct kmem_cache *s, void *object,
> > @@ -583,7 +585,8 @@ static void set_track(struct kmem_cache *s, void *object,
> >               unsigned int nr_entries;
> >
> >               metadata_access_enable();
> > -             nr_entries = stack_trace_save(p->addrs, TRACK_ADDRS_COUNT, 3);
> > +             nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
> > +                                           TRACK_ADDRS_COUNT, 3);
> >               metadata_access_disable();
> >
> >               if (nr_entries < TRACK_ADDRS_COUNT)
> > @@ -747,7 +750,7 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct page *page,
> >
> >  static void init_object(struct kmem_cache *s, void *object, u8 val)
> >  {
> > -     u8 *p = object;
> > +     u8 *p = kasan_reset_tag(object);
> >
> >       if (s->flags & SLAB_RED_ZONE)
> >               memset(p - s->red_left_pad, val, s->red_left_pad);
> > @@ -777,7 +780,7 @@ static int check_bytes_and_report(struct kmem_cache *s, struct page *page,
> >       u8 *addr = page_address(page);
> >
> >       metadata_access_enable();
> > -     fault = memchr_inv(start, value, bytes);
> > +     fault = memchr_inv(kasan_reset_tag(start), value, bytes);
> >       metadata_access_disable();
> >       if (!fault)
> >               return 1;
> > @@ -873,7 +876,7 @@ static int slab_pad_check(struct kmem_cache *s, struct page *page)
> >
> >       pad = end - remainder;
> >       metadata_access_enable();
> > -     fault = memchr_inv(pad, POISON_INUSE, remainder);
> > +     fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
> >       metadata_access_disable();
> >       if (!fault)
> >               return 1;
> > @@ -1118,7 +1121,7 @@ void setup_page_debug(struct kmem_cache *s, struct page *page, void *addr)
> >               return;
> >
> >       metadata_access_enable();
> > -     memset(addr, POISON_INUSE, page_size(page));
> > +     memset(kasan_reset_tag(addr), POISON_INUSE, page_size(page));
> >       metadata_access_disable();
> >  }
> >
> > @@ -2884,10 +2887,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
> >               stat(s, ALLOC_FASTPATH);
> >       }
> >
> > -     maybe_wipe_obj_freeptr(s, object);
> > +     maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
> >
> >       if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
> > -             memset(object, 0, s->object_size);
> > +             memset(kasan_reset_tag(object), 0, s->object_size);
> >
> >       slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
> >
> > --
> > 2.28.0.681.g6f77f65b4e-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwiR0o2uSqmvuoCbVQS6ZvcLVpGP-%2BOAC_K-6wMDQ3xiQ%40mail.gmail.com.
