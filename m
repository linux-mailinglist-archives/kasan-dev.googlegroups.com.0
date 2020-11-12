Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZN4WX6QKGQEWHEKK5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B01382B0994
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 17:10:14 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id b22sf2680122otp.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 08:10:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605197413; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZO4iyVl14NgfqHPueUp4J4LY0by++r/MSQ7dJ5dqvgRjaP8m+4EhVRk63Q0cSebVfo
         eHHzNT/0SWar6781Njw9id4QIn+3oFZWb8/Fk10Qz4RTuPI5Zq2p1kaPZ10BPvbc9O/J
         odXusE06M2iZ0KJsOp0LMkVmw8K0rPlYiu6eH2E5R8ibOGgGi/6zIY/F+aGs3tpHMEff
         8VaxLkU/7fA0WaIyzHfbUJ/CjZ6TY7pMexGUdq6IykHzKnDMtmOg33uigOltYlQU3Bkg
         RNf0zxBInwMBlbU2yGU+2CFXXQLhzmQFiVUpxS0hQpJKPc7KlQwhtcQYVrZgW/CFTdan
         BsqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mzBZ7CY2PKywPnjzFN6XXIBBRrVyl132lHlP6NoTWu0=;
        b=Wiz9xctDPBXEAPjo2FzfKi7N9AovkwUJtO47HD3jCC8U4DJn770w5PfpWQcTcqQItN
         QtjX4cEYczbnzQ3CVtoYnBrHrGlMOxkedta7NCj7WLvuvi8E2eMgfwhlx8pMBDxS+Rs5
         Pij1AQoaCxr7IZPA6mrNRzHEvBqE62kv1pWyIyPfAyV73IG06a6uF8V2cbiKRxAptsHD
         t2mM9XNK0YeA/whLj0vQ9w1uxYhu1Yed9u+RnusZndut0ZF3I6NuRgdg77Wf5GO0/o8f
         atayLTLWVhLkQbLEtASiSZ4xlPVh1lJplcgImfwgmauRIoY4ISVtFCAXdzn/87Y7Mex/
         gPdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K9N+LydT;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mzBZ7CY2PKywPnjzFN6XXIBBRrVyl132lHlP6NoTWu0=;
        b=Lfj+4tCynvkjACicjxzyo5kmp5nGVGPn1ItMV3wcSBSPr8m/Q2ljRYqU+Cxn2feBSj
         gHo6GpObPK5+h5t9oqID6iOKp64gLA8Nz1X0NW0XKBPed67bwZUNAapFqKt2ZdzG5p63
         4lm1LSOZjyx+HVAhYPzXNGfPj/75ohpKRx77VSRNkMufkkVkaUxx50DiSG1TTDa72I6w
         Cvj7ezTcvv8hxhR8ZrWpKKAbq66T6oNJca3c88Ab+9vISPGgWyaaGRY2kDCJGzZuojh3
         mrhRzO3sTP5O0fym+30RCk0KkAle8FdeKz3eFwPlHUR1RptkSuELagIPpCncVGXqdWnb
         LrBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mzBZ7CY2PKywPnjzFN6XXIBBRrVyl132lHlP6NoTWu0=;
        b=m7liOasW7AI/bD3F9YmduUML3RfAsAtO6H9pRmCckzNxr2YJ+OOjRfNusD6txp3Bs/
         172BDe9WjKeaV/dFa2a3tnROgzIYijk2vvPriMRFafzPd6y+EDukhCv4wZBPe2RSrJSF
         pj+4vIst8jH0EWlN/6f8FzjmrKD+YFYDuqzeDZjQwv1AVrI1bwD7Io1bazyv64AMF4tW
         2qYZ0sgpy5m11CCYXMfF8Fygms2OmTwUOq97iTlUZd0W5roJV5x3XhFLHwZxo2aCiyI5
         59LE7KNr9BwMlgn3PmUv5z9lqFE5IBKSoGgO3A81r8eAOH8M4auRl2ZcLilWE0/cJ9mU
         SbOA==
X-Gm-Message-State: AOAM533l4UhCLk7Wb+vAeoeDhrS7eGUwXrkov3rqq8CVFOE/Xcv/lsvO
	ehRwdXE8mqptMX7uGUNrdVw=
X-Google-Smtp-Source: ABdhPJwKtCJB3leYpI4nXFOZylWgZsWpU+h29HajRGCFc454R6LtV/xFDMmymqw9QhoInhjNH6cbsw==
X-Received: by 2002:a9d:5d5:: with SMTP id 79mr20464748otd.1.1605197413431;
        Thu, 12 Nov 2020 08:10:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1118:: with SMTP id 24ls786785oir.10.gmail; Thu, 12 Nov
 2020 08:10:13 -0800 (PST)
X-Received: by 2002:aca:c188:: with SMTP id r130mr254433oif.99.1605197413049;
        Thu, 12 Nov 2020 08:10:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605197413; cv=none;
        d=google.com; s=arc-20160816;
        b=aHkEV5JItDiqwj6TkgZXe21K8xkL4L15wO9F84EnaMEOxUSADfL7uhepbANrFinPhv
         4LTNuUG3Sl/9PgpISLnFqo54wDYRCRerKHT4BzNW/Aji33lRA0eL0kTAmiIMxSiKUl00
         AFdkIh8aINmQNJyV1Qox9ML+rNru9489qDd1OCeJdI4Q3VZE31H6mvamxSpMtAtFf6MK
         j+Jadcl2R4iOq9+XL4cBAUx6VKzfO3P8AM1mgL6NkskqxhaxyD/JRVPDP3ynzsx5LQmd
         hwjDimTQjIMX3w3dSDHCIBwcMdYBeXmBoxlCAiCtAIJJlJox0goEu+8N3WwprsOzJlnl
         AAoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+3ppqmizYm8DpeBPL8i/N6SBpHLSBfkZuqB8tufUogw=;
        b=V6tZGO946D+n8MaZT7f0azrdMI1cDiNar1ZwH6dhMEs1AQX0jOKjPtYf6Gp+XnhI6h
         EvcBa9wAfj53Rlmw25UWzkWs97rbqJOf5PXxOahzWPT2z2FfV+HVphreTW9HDJzqN+rb
         fILn6nXjvTr33aX5Oj3IGkRe4ObKDCQTKmT5R+Ch/Zj0DQ74x8PerhnTaJfTwR3iZ2Hc
         NTO688yU1RTmkeRDOlxJFnBU3l42pzv9ZxqTTk8ssnz6ivX+ZXGWY2updn4AGFDdt4aX
         ZIj+/UtzckelTaCMeqTNKSA92QW49GvHub8AsHCg5iQG33LOMGeZQgowky5SA4Ay/RDM
         Qrkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K9N+LydT;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id e206si512468oob.2.2020.11.12.08.10.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 08:10:13 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id n132so5744240qke.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 08:10:13 -0800 (PST)
X-Received: by 2002:a37:bf04:: with SMTP id p4mr506714qkf.326.1605197412318;
 Thu, 12 Nov 2020 08:10:12 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <d0060171a76ace31b26fef1f2713da209099fb99.1605046192.git.andreyknvl@google.com>
In-Reply-To: <d0060171a76ace31b26fef1f2713da209099fb99.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 17:10:00 +0100
Message-ID: <CAG_fn=VixcPo9fTcn0QSRLkFRsC+gcy-w=96BPEjMUc=e5fc_w@mail.gmail.com>
Subject: Re: [PATCH v9 41/44] kasan, mm: reset tags when accessing metadata
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K9N+LydT;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Kernel allocator code accesses metadata for slab objects, that may lie
> out-of-bounds of the object itself, or be accessed when an object is free=
d.
> Such accesses trigger tag faults and lead to false-positive reports with
> hardware tag-based KASAN.
>
> Software KASAN modes disable instrumentation for allocator code via
> KASAN_SANITIZE Makefile macro, and rely on kasan_enable/disable_current()
> annotations which are used to ignore KASAN reports.
>
> With hardware tag-based KASAN neither of those options are available, as
> it doesn't use compiler instrumetation, no tag faults are ignored, and MT=
E
> is disabled after the first one.
>
> Instead, reset tags when accessing metadata (currently only for SLUB).
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>


> ---
> Change-Id: I39f3c4d4f29299d4fbbda039bedf230db1c746fb
> ---
>  mm/page_alloc.c  |  4 +++-
>  mm/page_poison.c |  2 +-
>  mm/slub.c        | 29 ++++++++++++++++-------------
>  3 files changed, 20 insertions(+), 15 deletions(-)
>
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 24b45261e2bd..f1648aee8d88 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1195,8 +1195,10 @@ static void kernel_init_free_pages(struct page *pa=
ge, int numpages)
>
>         /* s390's use of memset() could override KASAN redzones. */
>         kasan_disable_current();
> -       for (i =3D 0; i < numpages; i++)
> +       for (i =3D 0; i < numpages; i++) {
> +               page_kasan_tag_reset(page + i);
>                 clear_highpage(page + i);
> +       }
>         kasan_enable_current();
>  }
>
> diff --git a/mm/page_poison.c b/mm/page_poison.c
> index ae0482cded87..e6c994af7518 100644
> --- a/mm/page_poison.c
> +++ b/mm/page_poison.c
> @@ -53,7 +53,7 @@ static void poison_page(struct page *page)
>
>         /* KASAN still think the page is in-use, so skip it. */
>         kasan_disable_current();
> -       memset(addr, PAGE_POISON, PAGE_SIZE);
> +       memset(kasan_reset_tag(addr), PAGE_POISON, PAGE_SIZE);
>         kasan_enable_current();
>         kunmap_atomic(addr);
>  }
> diff --git a/mm/slub.c b/mm/slub.c
> index b30be2385d1c..df2fd5b57df1 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -249,7 +249,7 @@ static inline void *freelist_ptr(const struct kmem_ca=
che *s, void *ptr,
>  {
>  #ifdef CONFIG_SLAB_FREELIST_HARDENED
>         /*
> -        * When CONFIG_KASAN_SW_TAGS is enabled, ptr_addr might be tagged=
.
> +        * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tag=
ged.
>          * Normally, this doesn't cause any issues, as both set_freepoint=
er()
>          * and get_freepointer() are called with a pointer with the same =
tag.
>          * However, there are some issues with CONFIG_SLUB_DEBUG code. Fo=
r
> @@ -275,6 +275,7 @@ static inline void *freelist_dereference(const struct=
 kmem_cache *s,
>
>  static inline void *get_freepointer(struct kmem_cache *s, void *object)
>  {
> +       object =3D kasan_reset_tag(object);
>         return freelist_dereference(s, object + s->offset);
>  }
>
> @@ -304,6 +305,7 @@ static inline void set_freepointer(struct kmem_cache =
*s, void *object, void *fp)
>         BUG_ON(object =3D=3D fp); /* naive detection of double free or co=
rruption */
>  #endif
>
> +       freeptr_addr =3D (unsigned long)kasan_reset_tag((void *)freeptr_a=
ddr);
>         *(void **)freeptr_addr =3D freelist_ptr(s, fp, freeptr_addr);
>  }
>
> @@ -538,8 +540,8 @@ static void print_section(char *level, char *text, u8=
 *addr,
>                           unsigned int length)
>  {
>         metadata_access_enable();
> -       print_hex_dump(level, text, DUMP_PREFIX_ADDRESS, 16, 1, addr,
> -                       length, 1);
> +       print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
> +                       16, 1, addr, length, 1);
>         metadata_access_disable();
>  }
>
> @@ -570,7 +572,7 @@ static struct track *get_track(struct kmem_cache *s, =
void *object,
>
>         p =3D object + get_info_end(s);
>
> -       return p + alloc;
> +       return kasan_reset_tag(p + alloc);
>  }
>
>  static void set_track(struct kmem_cache *s, void *object,
> @@ -583,7 +585,8 @@ static void set_track(struct kmem_cache *s, void *obj=
ect,
>                 unsigned int nr_entries;
>
>                 metadata_access_enable();
> -               nr_entries =3D stack_trace_save(p->addrs, TRACK_ADDRS_COU=
NT, 3);
> +               nr_entries =3D stack_trace_save(kasan_reset_tag(p->addrs)=
,
> +                                             TRACK_ADDRS_COUNT, 3);
>                 metadata_access_disable();
>
>                 if (nr_entries < TRACK_ADDRS_COUNT)
> @@ -747,7 +750,7 @@ static __printf(3, 4) void slab_err(struct kmem_cache=
 *s, struct page *page,
>
>  static void init_object(struct kmem_cache *s, void *object, u8 val)
>  {
> -       u8 *p =3D object;
> +       u8 *p =3D kasan_reset_tag(object);
>
>         if (s->flags & SLAB_RED_ZONE)
>                 memset(p - s->red_left_pad, val, s->red_left_pad);
> @@ -777,7 +780,7 @@ static int check_bytes_and_report(struct kmem_cache *=
s, struct page *page,
>         u8 *addr =3D page_address(page);
>
>         metadata_access_enable();
> -       fault =3D memchr_inv(start, value, bytes);
> +       fault =3D memchr_inv(kasan_reset_tag(start), value, bytes);
>         metadata_access_disable();
>         if (!fault)
>                 return 1;
> @@ -873,7 +876,7 @@ static int slab_pad_check(struct kmem_cache *s, struc=
t page *page)
>
>         pad =3D end - remainder;
>         metadata_access_enable();
> -       fault =3D memchr_inv(pad, POISON_INUSE, remainder);
> +       fault =3D memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainde=
r);
>         metadata_access_disable();
>         if (!fault)
>                 return 1;
> @@ -1118,7 +1121,7 @@ void setup_page_debug(struct kmem_cache *s, struct =
page *page, void *addr)
>                 return;
>
>         metadata_access_enable();
> -       memset(addr, POISON_INUSE, page_size(page));
> +       memset(kasan_reset_tag(addr), POISON_INUSE, page_size(page));
>         metadata_access_disable();
>  }
>
> @@ -1566,10 +1569,10 @@ static inline bool slab_free_freelist_hook(struct=
 kmem_cache *s,
>                          * Clear the object and the metadata, but don't t=
ouch
>                          * the redzone.
>                          */
> -                       memset(object, 0, s->object_size);
> +                       memset(kasan_reset_tag(object), 0, s->object_size=
);
>                         rsize =3D (s->flags & SLAB_RED_ZONE) ? s->red_lef=
t_pad
>                                                            : 0;
> -                       memset((char *)object + s->inuse, 0,
> +                       memset((char *)kasan_reset_tag(object) + s->inuse=
, 0,
>                                s->size - s->inuse - rsize);
>
>                 }
> @@ -2883,10 +2886,10 @@ static __always_inline void *slab_alloc_node(stru=
ct kmem_cache *s,
>                 stat(s, ALLOC_FASTPATH);
>         }
>
> -       maybe_wipe_obj_freeptr(s, object);
> +       maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
>
>         if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
> -               memset(object, 0, s->object_size);
> +               memset(kasan_reset_tag(object), 0, s->object_size);
>
>         slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
>
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVixcPo9fTcn0QSRLkFRsC%2Bgcy-w%3D96BPEjMUc%3De5fc_w%40mai=
l.gmail.com.
