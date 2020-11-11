Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4PHV76QKGQE3CUI2MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 64FBD2AF371
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:23:46 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id z14sf1262605qto.8
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:23:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605104625; cv=pass;
        d=google.com; s=arc-20160816;
        b=ggaqRsqK9W1NK3JPIg4hX4wAaepCgs4IjHP5dBFX0zU0ENKNrMBAoVdC1pzG0JVYfQ
         k9vX6WlfoQC046Q8PnQEkLHlhYiNUYAfv+Xp6l8mJLdHPUb7QP11IExCr++6Oz2hWIym
         OHAIbE2GaYAjt/ijCkfjY0dGgUS8sq+86ZA/RhddjkbUD56NUnu+Wr4bHjv7s3yAn68a
         tTg21kYzqsxQKgoBoLE4TJV4yFFY/iyl9+fPKMD9rVUzWzCkxjdoyJ90Hdr5zj/Uqlal
         Mtpktx/aWO57iCKc2f5cB2urjQ92QD5RET0axalo+I+MbNigwM7QQv+YSrXqv3n20N2g
         OZOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZIIN7oADZ8S96itNRGo7CGG60iyWt5ek1WthPgu5FqM=;
        b=0vsTHMM9COlEcjbwRw/aGXMxKLCcxx/ySPuQnWoPZARkHhkt6zQzmPdiOxX/0W3jKS
         W9ZSvVGGFDlozjq9H09kLWGW+CE+/zGl3+r1boyglaUaxtUpdI5sek8I2Dq8blKZDO9p
         dVIaaxpQCx1T9zonqqYO4uuN52apmu/YhiW0/rHn7mvPyJVqoy2TGJLiSzk+SJpewX9U
         Zcyjo+ijYwgjg84EwfdjHBR8i25CITFm875LZGEEqPEuXZ/j3B8BCaPma22SJ5aAHGQE
         9jgzbl92sPz98iYiw1nAQJmMrfabym6GlPHrvaQfNXx8aUakyNrinV2wOs1GHR712lTx
         gulg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y3VD18rW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZIIN7oADZ8S96itNRGo7CGG60iyWt5ek1WthPgu5FqM=;
        b=SmRtwkCpMBDYJeuDBvVrLGuMw4l+FqUKNjdHARtQES1VA8ooqN192INHY140AOFL1a
         Q7hco1kYOflWrUjHoCsLgJkaOjatLAUwZD2EJFbmPx3l/8cZjC7LacePCem64WTYjVXr
         80GPbPyylyPeevb4ac4LgTv5MRs4QJWDKoKC1RS1wHeTKveJB4WMKiqdTewggxrHRe4o
         KAb/NAF0UsAn/2SjouNxFjJtksn1gvvY2D6iX+EYM6+aHMCSR80h21I4s3QhNAt2qpgJ
         S/05i4g9EAcu6PyqM98VySWOCDaEy9/zo3G3f3boJI9xRFBQ+KWNpXzAEm5E5vgZ4I+z
         2Vfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZIIN7oADZ8S96itNRGo7CGG60iyWt5ek1WthPgu5FqM=;
        b=IMq8rq4ulFZQzeyVxylAKIvYSUW8yxArm5gVPPjHmlF9Mwf59uCSqsit56xms4EtBd
         cCOxYqz/NzeBd+qdOiyJZ43BnKjN9+ozY8+asOt90EALjlu7t5ykQ65Mu4b6lMR2bLoY
         xoJq1TFd98PJti4ni4H2BBpl45Ag4BlFaPV9VM9m7SMJRkl2ImWcivv4RqisZtkpXkfy
         wULeIbvEs5kFydQXSFJleWxu1N/pFah/ElFAEI1ExhpplfFkSTaGs323p9SHHWhdVcTS
         s/ocBasmU3+c9zMXpfFypSpcfl2fXF1AoWwURenHUnaya3glkX1DBSDAOrl/bn+PoMYa
         t4vQ==
X-Gm-Message-State: AOAM533DTxTwJttjBGjKNNvGh+vvDRslnDro86JFTGYy3NvRnw+qDAES
	xfA9JQyAJDP8CnAwGZiFNvw=
X-Google-Smtp-Source: ABdhPJwKOe7HQkvIfzUZl4Z2Hryeiv3WB30I/Ts2CqqIPjW3q5jVA+mNJp1BZ3U2Oq04NsmyipfMLQ==
X-Received: by 2002:ac8:8b2:: with SMTP id v47mr23109523qth.332.1605104625493;
        Wed, 11 Nov 2020 06:23:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:152:: with SMTP id x18ls3539808qvs.10.gmail; Wed,
 11 Nov 2020 06:23:45 -0800 (PST)
X-Received: by 2002:a0c:fb06:: with SMTP id c6mr24752182qvp.10.1605104625015;
        Wed, 11 Nov 2020 06:23:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605104625; cv=none;
        d=google.com; s=arc-20160816;
        b=H5LiUCFCpZjSQ0D1tsIXa5hwDnVlztEB/f2nYs1M8r/kOxdghbEqKwh7Aim43WcvqB
         9XUDExxjkqCytxXETXyDEodpah1tMudxhTQZbuve/WPTLau7NVKMuwc8x9oXDpql5EIn
         /LbEj4LUzNgX/L4FAYEpWeisTPR5e2mjIfpM3A2xVtpn9zSvQq5zBukL/qt6Eu6Bqqv8
         /SZK6JUYtwbe1bQsDTfX/L85ZpYogIEot8Cm3QsFgC+jE90H8elJAgnMBoFP4cffgjwO
         vn2tITIBZjmBuiaGKUMzcILz83nJivYBzcDXxKqNUHBxHSuyORLKOt3gKipcpcqGqY2g
         UOFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UloFlAe4eE6dBOKuaOljn+MXY+P4+o9Y9O9NjdtVr4Y=;
        b=yeA5gkpdY6RsYYswXBtFnJ4lirCehmCG8yQkBQUBTnsx+mog0bRUSZZUKpw6LCAYk7
         r6GpWRH0BDgnEFVwAGGewlM6y0V8Ge1sRdKwAqiJQhSejKKIr9EimB1s4CyrwStctVJo
         zNXhZMmMdSnybtKtlCeSJ0WCIsUjixIscS2Jrd5dqVlF72uoOKya/JVdo93NrIzGJh6b
         J3Z54sxms9BiDeBZVi8vDYaFRnUpL20uL5jFgh1cmfd3LrBAS/cTU713kXALPH/sSN+c
         UJFfvc+GgvjpzlxYp08NU8RrD/vJbxRVZhXeTnLfqeA8C9oaKudYjocatGw+vVpyQYBC
         18mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y3VD18rW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id g19si139393qtm.2.2020.11.11.06.23.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:23:45 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id g17so1360088qts.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:23:44 -0800 (PST)
X-Received: by 2002:ac8:5c85:: with SMTP id r5mr18898460qta.8.1605104624442;
 Wed, 11 Nov 2020 06:23:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <427d46e86c81f3ec77147b0ade4bd551d878cf7a.1605046192.git.andreyknvl@google.com>
In-Reply-To: <427d46e86c81f3ec77147b0ade4bd551d878cf7a.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:23:33 +0100
Message-ID: <CAG_fn=XBE+aRBizrJgNGsJ5FGPtSAHWqL26k2pCRxvutJ-LbTg@mail.gmail.com>
Subject: Re: [PATCH v9 13/44] kasan: hide invalid free check implementation
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
 header.i=@google.com header.s=20161025 header.b=Y3VD18rW;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> For software KASAN modes the check is based on the value in the shadow
> memory. Hardware tag-based KASAN won't be using shadow, so hide the
> implementation of the check in check_invalid_free().
>
> Also simplify the code for software tag-based mode.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I5fae9531c9fc948eb4d4e0c589744032fc5a0789
> ---
>  mm/kasan/common.c  | 19 +------------------
>  mm/kasan/generic.c |  7 +++++++
>  mm/kasan/kasan.h   |  2 ++
>  mm/kasan/sw_tags.c |  9 +++++++++
>  4 files changed, 19 insertions(+), 18 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 123abfb760d4..543e6bf2168f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -272,25 +272,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_=
cache *cache,
>         return (void *)object;
>  }
>
> -static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
> -{
> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> -               return shadow_byte < 0 ||
> -                       shadow_byte >=3D KASAN_GRANULE_SIZE;
> -
> -       /* else CONFIG_KASAN_SW_TAGS: */
> -       if ((u8)shadow_byte =3D=3D KASAN_TAG_INVALID)
> -               return true;
> -       if ((tag !=3D KASAN_TAG_KERNEL) && (tag !=3D (u8)shadow_byte))
> -               return true;
> -
> -       return false;
> -}
> -
>  static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>                               unsigned long ip, bool quarantine)
>  {
> -       s8 shadow_byte;
>         u8 tag;
>         void *tagged_object;
>         unsigned long rounded_up_size;
> @@ -309,8 +293,7 @@ static bool __kasan_slab_free(struct kmem_cache *cach=
e, void *object,
>         if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
>                 return false;
>
> -       shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
> -       if (shadow_invalid(tag, shadow_byte)) {
> +       if (check_invalid_free(tagged_object)) {
>                 kasan_report_invalid_free(tagged_object, ip);
>                 return true;
>         }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index ec4417156943..e1af3b6c53b8 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -187,6 +187,13 @@ bool check_memory_region(unsigned long addr, size_t =
size, bool write,
>         return check_memory_region_inline(addr, size, write, ret_ip);
>  }
>
> +bool check_invalid_free(void *addr)
> +{
> +       s8 shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
> +
> +       return shadow_byte < 0 || shadow_byte >=3D KASAN_GRANULE_SIZE;
> +}
> +
>  void kasan_cache_shrink(struct kmem_cache *cache)
>  {
>         quarantine_remove_cache(cache);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 1865bb92d47a..3eff57e71ff5 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -164,6 +164,8 @@ void kasan_poison_memory(const void *address, size_t =
size, u8 value);
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>                                 unsigned long ret_ip);
>
> +bool check_invalid_free(void *addr);
> +
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 4bdd7dbd6647..b2638c2cd58a 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -121,6 +121,15 @@ bool check_memory_region(unsigned long addr, size_t =
size, bool write,
>         return true;
>  }
>
> +bool check_invalid_free(void *addr)
> +{
> +       u8 tag =3D get_tag(addr);
> +       u8 shadow_byte =3D READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag=
(addr)));
> +
> +       return (shadow_byte =3D=3D KASAN_TAG_INVALID) ||
> +               (tag !=3D KASAN_TAG_KERNEL && tag !=3D shadow_byte);
> +}
> +
>  #define DEFINE_HWASAN_LOAD_STORE(size)                                 \
>         void __hwasan_load##size##_noabort(unsigned long addr)          \
>         {                                                               \
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
kasan-dev/CAG_fn%3DXBE%2BaRBizrJgNGsJ5FGPtSAHWqL26k2pCRxvutJ-LbTg%40mail.gm=
ail.com.
