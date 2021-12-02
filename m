Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3OKUOGQMGQEEMWYYJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 65AB3466670
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 16:25:34 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id v13-20020a05620a440d00b00468380f4407sf168220qkp.17
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 07:25:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638458733; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jr2+2z80OYf0AsqdpC7xSt9wxFikH52pgcmdY2cG7atTJoxNCukbbzUsM0jZkrHKoP
         q80TVRmurqYh2omGAJ4NMIy93tJZgu5H5bbj59/hYusMYBmpF0hbRNtVTbxkrGyBrIDi
         fLlM8LlEgR/fSQKlF129L7zt+S05Ar1DAzdUxUU26ftkFyAaC7/6GF9JW2nCPfqykjWn
         SamL7OA3Dg2QqMi1TMufBh+3iBeAI4bUNrqIWDgVjmag0EZk1qakD/yim3fHhmv2TL2u
         HcyZ5kaDSOa5E+IIi8PQXuHa5lFZi8fghkZxxh0AZ2bzqzplnV2DFeqY+mmIfE1YhORB
         VwHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C3A7oMUuBi6DV9zCEBCPigNq8WgFdCd57NRCKzciWvg=;
        b=P8r/tM8WNus8heVG7vlyyw4MkaYzXIIURzI6RBdufCxXJUMZVAxni71gmS5T2LddIb
         G655/vqbokKCE1QuZozpvUlERb0gqa3NZI7sZbUoy85EJQk/Ilv23vnd65NN7hZeK2WS
         +8GZJ7mpRB/wf3pKP5VzeeLcVNEM+dBMVQTeXMa4vmHFDyPsWSiEYoOyZUtieHEU30i9
         5cZvqnjla8V7Ju3N/Fpt8JMV5utzER8Auo8ry61YBRrXKyO9ylRhT5SyXaIQEBncOSPI
         kRjDhiiASsZvwbNDjIBhcMmitwA4R1Gc+7nhM98yaD7btiixgYuxIk2zE1hmCDXKw1c5
         e17w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PPgXGZVb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=C3A7oMUuBi6DV9zCEBCPigNq8WgFdCd57NRCKzciWvg=;
        b=to732IyWen+blsRfpvVAQJLdZjdu5CAK3YdjapmKB+irpOP8UCDfk/rwpQvAAip/gd
         eohFEZ/X1z1R9ifje1TuJQVv7K0qSxlJhsR0g5X9OLc5BWb/TXn+uhnsszAeqqgV8zI1
         aF6VXPgYjqDRw7AyNg8YYieyXyawmiGKW7JpY9Oim695o7iBDnC5KwKNCidBZROr+4+m
         QnqYTL4JJ4+Kj8ws2yv4GSEf3MBVjjs3BZBy5N9tVs62+TBZs8/LZA8TZ8dld/aMI0CP
         UuA3ZJNmG668r0fZ6BCYxYMCh+J1y5Unqtc85gl1EyN03nsB8tJLtp4odZTjbYThHn5p
         qReA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C3A7oMUuBi6DV9zCEBCPigNq8WgFdCd57NRCKzciWvg=;
        b=N+3Q7VbY79ZAMw0uiGNoQjE3v5B2IjJ31wFBHLIKpFg4NNqdeIz3+G5qSqRUjYFHoW
         tBqnKUGKN7FCT4O20qz8l7+E73tXwLpdGKNZhoFLUJVWDGg4rOMeQ0iZybO6ytlLyzSp
         QmW5xtQrYl9pqMDlXwRR19SjJExoBpQW+kT9lgKcsVyoZq/kdMVgPpL9xMEcc0vWVyfT
         ZVIA8nLrKc2MhsQn+JxAbCbflubKfC4VyXwzjbRb1bsBwsiShO3h4VwBP1Dkj9D70iUj
         qu5qR6YdwXFcjYyPbtZvCsSiGSchjQPGCI5ktVcdqMqTtAwVtOtESGJqT6Fk3K29MtmB
         P4jg==
X-Gm-Message-State: AOAM532glZFKxpuJm60XferEZEFDgtgu51JXMFYIWrfPuJ7jCUvWKIqP
	vzuawV/dE3CH49G8znzif+U=
X-Google-Smtp-Source: ABdhPJzuFzXTJDE8eWjx7CwzhguHBiPavt+sPkdqSnYHEEWKSrF2gkqBkyHjB7E2VFTXHA5op9b2pQ==
X-Received: by 2002:a37:a956:: with SMTP id s83mr12758417qke.422.1638458733281;
        Thu, 02 Dec 2021 07:25:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f00c:: with SMTP id z12ls2987505qvk.9.gmail; Thu, 02 Dec
 2021 07:25:32 -0800 (PST)
X-Received: by 2002:ad4:5dea:: with SMTP id jn10mr13330846qvb.17.1638458732646;
        Thu, 02 Dec 2021 07:25:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638458732; cv=none;
        d=google.com; s=arc-20160816;
        b=EnYgpkiwgMCihvBTNfbtDKR170ry2NLBjhK6vj7ulEUEnkweBzKzPZl3ObhgQRkRxe
         Z2P9MuT/YjVLig73mzK9FmMRaMo0iGQdtWMaIZNR1giiceJcSbEm83ZawJl7koGqz6ff
         TsRJo/0ivZHUWoqr3Bx3UFmxAMbwNFy6rDkzikLCRalpJSWLMlZX/rij6W5TX4w6Z6BS
         Fzz5efzjqqd9lIZwFx1LTyWW1yJ0uVwcDNLtAS+7255p0tsaZpM9nPQ04UhABIbeQZYE
         GhBy5iwNlVUgtl0WXyI8S/W1Ox7i3PXbzCkA7qoA8hQcugqIWuT6YG8nxa3e72rc/tDT
         542w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OTX/WZkgF1pYK7eFLF3f7aWLqHA2vUJ/0VtDzBUjbo4=;
        b=TAJSgqMJzrS5DDo+W65r3ar72H0+kxm3UaqP4m4CaRIGGzwKB4HyK+62Hh/uvnbV/j
         1Ob3c3fIa45PMSv5cQeKI04eg+cZq+6n2eHzYbxUrxwEHjHX7sgZH6CAfjkOKIldkNq1
         d518bcfNMohG6emmNB5UNEF0QeSdOIAuhpIHbGMHCl7KRyahu6B87Ss3WjBPBeHSQ6tV
         lSKLPj0HX/dwfu8EqIo/xHJvDu7uIUzv82lmtgbtEo7Hznd01NxIc+9W9MSuI8+uqRn5
         eJiZ4GpFwnkelmUDdWNiG23NGPGuGbF4cLtNPg6Btk9YxfB32s9Q5vuS8ojHfCKax4vL
         pUDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PPgXGZVb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id d17si4797qtb.2.2021.12.02.07.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 07:25:32 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id q64so231612qkd.5
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 07:25:32 -0800 (PST)
X-Received: by 2002:a05:620a:2955:: with SMTP id n21mr12547975qkp.581.1638458731912;
 Thu, 02 Dec 2021 07:25:31 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <e64fc8cd8e08fac044368aaba27be9fc6f60ff9c.1638308023.git.andreyknvl@google.com>
In-Reply-To: <e64fc8cd8e08fac044368aaba27be9fc6f60ff9c.1638308023.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Dec 2021 16:24:55 +0100
Message-ID: <CAG_fn=Uigry=Ou2Msw3DmmuytePji6wY-JkXrGk1YzP=5EzJeA@mail.gmail.com>
Subject: Re: [PATCH 02/31] kasan, page_alloc: move tag_clear_highpage out of kernel_init_free_pages
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PPgXGZVb;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as
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

On Tue, Nov 30, 2021 at 10:40 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Currently, kernel_init_free_pages() serves two purposes: either only
Nit: "it either"

> zeroes memory or zeroes both memory and memory tags via a different
> code path. As this function has only two callers, each using only one
> code path, this behaviour is confusing.
>
> This patch pulls the code that zeroes both memory and tags out of
> kernel_init_free_pages().
>
> As a result of this change, the code in free_pages_prepare() starts to
> look complicated, but this is improved in the few following patches.
> Those improvements are not integrated into this patch to make diffs
> easier to read.
>
> This patch does no functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/page_alloc.c | 24 +++++++++++++-----------
>  1 file changed, 13 insertions(+), 11 deletions(-)
>
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index c99566a3b67e..3589333b5b77 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1269,16 +1269,10 @@ static inline bool should_skip_kasan_poison(struc=
t page *page, fpi_t fpi_flags)
>                PageSkipKASanPoison(page);
>  }
>
> -static void kernel_init_free_pages(struct page *page, int numpages, bool=
 zero_tags)
> +static void kernel_init_free_pages(struct page *page, int numpages)
>  {
>         int i;
>
> -       if (zero_tags) {
> -               for (i =3D 0; i < numpages; i++)
> -                       tag_clear_highpage(page + i);
> -               return;
> -       }
> -
>         /* s390's use of memset() could override KASAN redzones. */
>         kasan_disable_current();
>         for (i =3D 0; i < numpages; i++) {
> @@ -1372,7 +1366,7 @@ static __always_inline bool free_pages_prepare(stru=
ct page *page,
>                 bool init =3D want_init_on_free();
>
>                 if (init)
> -                       kernel_init_free_pages(page, 1 << order, false);
> +                       kernel_init_free_pages(page, 1 << order);
>                 if (!skip_kasan_poison)
>                         kasan_poison_pages(page, order, init);
>         }
> @@ -2415,9 +2409,17 @@ inline void post_alloc_hook(struct page *page, uns=
igned int order,
>                 bool init =3D !want_init_on_free() && want_init_on_alloc(=
gfp_flags);
>
>                 kasan_unpoison_pages(page, order, init);
> -               if (init)
> -                       kernel_init_free_pages(page, 1 << order,
> -                                              gfp_flags & __GFP_ZEROTAGS=
);
> +
> +               if (init) {
> +                       if (gfp_flags & __GFP_ZEROTAGS) {
> +                               int i;
> +
> +                               for (i =3D 0; i < 1 << order; i++)
> +                                       tag_clear_highpage(page + i);
> +                       } else {
> +                               kernel_init_free_pages(page, 1 << order);
> +                       }
> +               }
>         }
>
>         set_page_owner(page, order, gfp_flags);
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/e64fc8cd8e08fac044368aaba27be9fc6f60ff9c.1638308023.git.andreyk=
nvl%40google.com.



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
kasan-dev/CAG_fn%3DUigry%3DOu2Msw3DmmuytePji6wY-JkXrGk1YzP%3D5EzJeA%40mail.=
gmail.com.
