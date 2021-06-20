Return-Path: <kasan-dev+bncBDW2JDUY5AORBFOHXSDAMGQEW6FZHDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 82E033ADE18
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:16:37 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id k25-20020a5d52590000b0290114dee5b660sf7063531wrc.16
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:16:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624187797; cv=pass;
        d=google.com; s=arc-20160816;
        b=FOQEHypYAK4hVFXXpeiO7H9oLOnP2Is1NPTTrDEaohWnaBFSMAj2grFhtumXDuZaVD
         CjVwLINMOJn7HlFm+Mp8ZtldyEylIKUT62md+Xo/BG1sXP/GA2DoQQaJigiZ0/5Jl2Kw
         ar9vnl97PIZRoHnqiedzr8Xmrr1T7AY/2sA4ssFySjPZWThqO1I3v4pMZGjZxCt15GOa
         6zmMrGkXm/oGXPknZdSSM8BBjBQrmrScXzu6GX7s2RSeJ8QxTi54Mm5ypVXnbPujevn/
         oVD+V8RRinNel/kjwRiFEBt8LIQgBv172AMIOC3h0I0gwEFSJFa7l/qcfb3HmS+wd0nV
         HUuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=JGSEcurLwY7KviUPP6zHh/QJ/AxP45tR7fZj8NYoww0=;
        b=xvXS7AOldiF1MyRgKlqxgjuwPzkxj7orZQkbx5AHrapjyhm0CvxqSn54773zS+dlO7
         B84YT9GKO0Lugo2w4+MdCQL1Umg0IM+9/MoH0ebkfkKE+rUMFz0SH7IIublC5vEPt8kb
         hdidxj1XNLJO+ORT/B8uQrK2LKruvtZf6XJE5MvfaiB9JKE13edEQYHfSPCeWH2LG76f
         Y8NgeOy/G4ZdRKs9lxHZkeiFLycgZBt6jYa5BnHPbhsn43po9BYroipO8XIkR1RqqmbU
         h8qF+mFIITefGMFViZPrMj9ifhXjiEPSz3wLsdubIKN5bG801eJkR4YbWW2+eoYqoQI5
         F6ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=D6mAsQ+a;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JGSEcurLwY7KviUPP6zHh/QJ/AxP45tR7fZj8NYoww0=;
        b=nAGo63ujbb6s14UbBmNDqWZk9++IRS2B33Yc4I24RoUlvqRFaA/nj5yRIGYp/Qr2Pk
         uWSQ/rTqjLCObDeoSC5Mb9+kVuZAhkH+cQDKTwbzFoPFCx3y85ASTeaEqWsOnSwAl2b+
         kcsXMQ16W4as0DMHF4NbKcm5GNBr1S24Lmi4IJ+t44NNWQO4uminz8WoMuTtIY1FKBm6
         v2vyIiXmK7zVRU4uiZFD+DDLbOxW7ou8paXTtGRuhrSo3XfELbvqrUHK6Gy+NceDPWQB
         Lnxf/zSQ8K6BtZm5szKLYS9K3ga7hlcNglEmednNcotkq3DfSTL1br3iue7aj/i7r37C
         /nMQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JGSEcurLwY7KviUPP6zHh/QJ/AxP45tR7fZj8NYoww0=;
        b=tcplRVGEk7i537aGqubQ170rnEUvhC1nzM0rIwIxubWPB9QJJ+0BV/0AwZrOTZssAr
         4hpDCwz1ePDwE5rmF/mLpUi8czN4FQBcoaaiLQhtcE4IZi2QoWKMFLMQ0oUqNmbkC0Ln
         qQMw5rSk6Acf76g7bDOKxWtgVUPtnXM5E3ahyjOPhcOucWBv4st39DJcpfmJ1IkbuB7x
         g3gKBB4XcsC6lYit9Cn9/3ZaRBJuyM4/4P418PhZWnToQN+8dFsc5XdjBfx+N75AV6Gn
         0Ej8+2NnYZIqcusm4fjkE58YAAjCFrIBZeixQe0F4dXM8+mnoZEh2QUd/SK0oXaaUmyJ
         JaiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JGSEcurLwY7KviUPP6zHh/QJ/AxP45tR7fZj8NYoww0=;
        b=civaDKK0atZEtp6IDBSUyxqqKGcdhrkVYydaapSuaamEJGhuO6U+t5MOscB57AJcLc
         ROFO6Y0CmMp2a+oxwuRURDg6p+So4HqQITUb3qauAzvvoIZ/16gY+4iLcjkvzPCP9ksQ
         0NU4tRaRqvKseZCq0MHWzqIz1XTjMTvj1ITgkeh+fqgtc+0AjWTkGpB/dM/ewSwrPYtx
         M2PLVYCWjOAtRWUPT15xoZGSjdHEUrVx40ONIW458XH+2DrEJz2O6Bsylutub8Ed8cZH
         qnA96uvoF6jg9vy+FF7WRcWOtSPpSVgKKxNsIRQf0NsL/WNdvEbcU8C7bS0J+GC01yAc
         ZprA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326g19tn8slRbfllq8nQ6qjMOFrIs/+bxGiA8NChapskkLGqvaN
	9UNMZwLgk9PeqqGkcDp2TgM=
X-Google-Smtp-Source: ABdhPJxEq7mHzG0uyQaiiryxU5WxKocTi1pcXWwYUAHZ8t63P5ic5d5aEuj1dQufiGKzuzuE7GlQFg==
X-Received: by 2002:a5d:6992:: with SMTP id g18mr22579850wru.73.1624187797310;
        Sun, 20 Jun 2021 04:16:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a141:: with SMTP id r1ls3320351wrr.3.gmail; Sun, 20 Jun
 2021 04:16:36 -0700 (PDT)
X-Received: by 2002:a5d:5402:: with SMTP id g2mr21860270wrv.226.1624187796599;
        Sun, 20 Jun 2021 04:16:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624187796; cv=none;
        d=google.com; s=arc-20160816;
        b=Hsp411k44MP10atexIzOhWY93Q4WK4e7mmLB1KZkDUHYbSEe5UiHVQ9juLfiitlTI5
         +a0SsP1YCWS00rZhuyZ3XaDL1GHnJIwoHRDXtgi7tCoJPttZAxJ7okLoMvQQ7oRVRFqd
         VaGesOkO7NpKyfgeeQ7+dwAmDs/EQGGrmLKkTMF+SUXbLbTBo+1jUbKkvQ3jM7PIEVJJ
         p9O6T8wG8qZZk/dEr7Rg45sWqtcoKGPOIiiKeQJExTT1HwMq6bGEFvro7cSL6WfharUa
         FzjuJusRKRylb4XDRwgQVppG40vI8q5L2e4Z+E902u6HUMNoAeA0Ck4kkuvP5kS6Gdpw
         qJNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N/chto6jVnmlN7DfH7wDHpFEeSqaG7VTzK76gQyfhdE=;
        b=NBv+ZyoJCB8hij235umKpttDOBoBtf2PPf+Ghs7G5cYgdPaBwlQaTv0c1H6p2DTWIi
         3/kmnEZQFibFbXcmNjU7byv3HccmuMUJKU+FPjgpAq4cd1TJS9dlisHE0lc6Shv2MADJ
         vww2iMeDWgGUXm8gByVoSniq4fEADneaQNsIPmke0qK4ZuX1jVvtTycXT4GAXc/W9ej+
         XtEL+UqBbVz4dXSED5444zoL0gol4S6Jc9LNPXcYsA+TGRBG0A6mfoSlI4onrrGDqgpB
         rPw4irgtrWe49WNPJC+msA0dTKTkeUQsQd+koK+kLDP5nctbpU7Mx74C9G1H6kqvJ18V
         OWag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=D6mAsQ+a;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id c4si936862wml.4.2021.06.20.04.16.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:16:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id z12so14969730edc.1
        for <kasan-dev@googlegroups.com>; Sun, 20 Jun 2021 04:16:36 -0700 (PDT)
X-Received: by 2002:aa7:cd05:: with SMTP id b5mr2787046edw.190.1624187796446;
 Sun, 20 Jun 2021 04:16:36 -0700 (PDT)
MIME-Version: 1.0
References: <20210617093032.103097-1-dja@axtens.net> <20210617093032.103097-3-dja@axtens.net>
In-Reply-To: <20210617093032.103097-3-dja@axtens.net>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 20 Jun 2021 14:16:16 +0300
Message-ID: <CA+fCnZdJ=HHn1Y=UDiYJ2NagNF9d-bJfjQa0jmiDaLiqneB_rA@mail.gmail.com>
Subject: Re: [PATCH v15 2/4] kasan: allow architectures to provide an outline
 readiness check
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@csgroup.eu, 
	aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=D6mAsQ+a;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::529
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Jun 17, 2021 at 12:30 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Allow architectures to define a kasan_arch_is_ready() hook that bails
> out of any function that's about to touch the shadow unless the arch
> says that it is ready for the memory to be accessed. This is fairly
> uninvasive and should have a negligible performance penalty.
>
> This will only work in outline mode, so an arch must specify
> ARCH_DISABLE_KASAN_INLINE if it requires this.
>
> Cc: Balbir Singh <bsingharora@gmail.com>
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.ibm.com>
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> --
>
> Both previous RFCs for ppc64 - by 2 different people - have
> needed this trick! See:
>  - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
>  - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
>
> Build tested on arm64 with SW_TAGS and x86 with INLINE: the error fires
> if I add a kasan_arch_is_ready define.
> ---
>  mm/kasan/common.c  | 4 ++++
>  mm/kasan/generic.c | 3 +++
>  mm/kasan/kasan.h   | 6 ++++++
>  mm/kasan/shadow.c  | 8 ++++++++
>  4 files changed, 21 insertions(+)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 10177cc26d06..0ad615f3801d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -331,6 +331,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>         u8 tag;
>         void *tagged_object;
>
> +       /* Bail if the arch isn't ready */

This comment brings no value. The fact that we bail is clear from the
following line. The comment should explain why we bail.

> +       if (!kasan_arch_is_ready())
> +               return false;

Have you considered including these checks into the high-level
wrappers in include/linux/kasan.h? Would that work?


> +
>         tag = get_tag(object);
>         tagged_object = object;
>         object = kasan_reset_tag(object);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 53cbf28859b5..c3f5ba7a294a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
>                                                 size_t size, bool write,
>                                                 unsigned long ret_ip)
>  {
> +       if (!kasan_arch_is_ready())
> +               return true;
> +
>         if (unlikely(size == 0))
>                 return true;
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..4dbc8def64f4 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -449,6 +449,12 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)   { return true; }
> +#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
> +#error kasan_arch_is_ready only works in KASAN generic outline mode!
> +#endif
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 082ee5b6d9a1..3c7f7efe6f68 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -73,6 +73,10 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>  {
>         void *shadow_start, *shadow_end;
>
> +       /* Don't touch the shadow memory if arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return;
> +
>         /*
>          * Perform shadow offset calculation based on untagged address, as
>          * some of the callers (e.g. kasan_poison_object_data) pass tagged
> @@ -99,6 +103,10 @@ EXPORT_SYMBOL(kasan_poison);
>  #ifdef CONFIG_KASAN_GENERIC
>  void kasan_poison_last_granule(const void *addr, size_t size)
>  {
> +       /* Don't touch the shadow memory if arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return;
> +
>         if (size & KASAN_GRANULE_MASK) {
>                 u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
>                 *shadow = size & KASAN_GRANULE_MASK;
> --
> 2.30.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdJ%3DHHn1Y%3DUDiYJ2NagNF9d-bJfjQa0jmiDaLiqneB_rA%40mail.gmail.com.
