Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5X3V76QKGQEZDOIA3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id C66E02AF464
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:06:31 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id q4sf1323573plr.11
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:06:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605107190; cv=pass;
        d=google.com; s=arc-20160816;
        b=zK2iQOd+srVLHPHXfVq3OZD8LC+841sgSG36czj1oi5dqJn+pHzZoojCDVCBgY6CUD
         oPBqlQ3gkTAdqYs0zv6WPujhWeASNs5BTDDxJurMiLwuQz+0AQJWy+2Tfh5UAyO/ZHrr
         E8LVTfuqS6vstb0ihZvN8iI0pLq2A9ZKU5qwanniHPe7oeKwIrMgGiMWJnDk0t9Ylt81
         kd0FuM2BxnENn1NbHvpQgTjIyT73SFQZzxF3WSKyw22NCC3wwSEriOkyASK1egDx+J+z
         8FJtE3jUVAE0hqV9ot4IbHrCB+DAocByUUhxxMj7JUR9q4CDWKZQARcbgCyZCCihnAz0
         tGiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wI2E9W9HkoxeVPfK1aWflDYqxv6Gs9f4eBt0IhpQ3vI=;
        b=fc3LEEsY1wCT+D9IAohkZJVEOPiJbKRUg1BNhTF7LkjLySurjLPjQlN3cOadI9mmxU
         jDpqZYNqtBN644Lk5mRhQJQ2sdDAWySiRoUmvp6/jVw8Eso1U9Tfrb6SpH/jiF5cz3jK
         44ORVNFssY2W+oPgKr/oiznnnZ2NEspDMR4I7cYJgV7/YDrPh/Sja0XdonO6ietqlU6V
         gjl8JeJP0IPJlk/o96nzwGURD/R5N8y3LK4An1Wf9JZmiQHg0N0BneUvG4XYWYNGLGVd
         pi0v13gIMLqMbgsrXHrnkY1Bw2DQHps7kz70/Kow9CcgLLlkTMyvF81B50EX1eoH4v4z
         4dog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HvYqEhf5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wI2E9W9HkoxeVPfK1aWflDYqxv6Gs9f4eBt0IhpQ3vI=;
        b=O+r3KbWFIrVDwjGQXVxy5g8RhX3H2l0SLicf1OPILmfX6Om3JvtgqV3OgrspMzikfm
         hw8RjTZnT2jAfimHVH2tmSRy34JHCa3m4THhh6MKjSaWrbRdIv60c1jvwh0W9YeVc2Ig
         FZGHBglzE+ryLQOEoC7ATNXhEOqvHcmDjRxHE8E54JYV/YU7MvnAjsUeMUtLL0GVvE9/
         pFxKmsczmGLA2WQRYszfu/9auSKDoJ0TNREZ21ecbJhxh0TqpZbgeaS2RulVuJm7+ho+
         EBvTUI33Dm4oPOBrcKaJyYuLDTq4EjbOeP1Je1aNnXdM0VGW2BrJJihldIgPQvwFtR1m
         0GdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wI2E9W9HkoxeVPfK1aWflDYqxv6Gs9f4eBt0IhpQ3vI=;
        b=rPN4ub/jlbcqP0BAypCwiCJL2zf8XG0XWRyYjaBqF7eNjm+/tdaNTaMR+N8IsLoBE8
         szJeMmf44vixOjvt67pBJjXOe9Zh2nHTJFgj8Jw5c7QKOlz0oZW0mLKfoqDhiPg5ReI4
         vbFKg1JTvEQZdQT8QYb43MKtlGa/4Hjo5mgRfOj7qVM1VjDIyO9oxquagnFkbqy1I1F7
         /40wgfLZjz9gTZoX2Pjla++rQmwWs18TsOoBuq9F6v56ob802qt5wj1liDxMnRlv+Yzo
         m1pYrKPXt7MOUgiOEQHAten0fROz1qbubbFxcMLQNoNAuaTaMUZLTeXhvXtnXAjXBLNG
         1jFQ==
X-Gm-Message-State: AOAM530RnyqWHw3SiFCCYJ3kq9neaRSJkUrT6iYpZYaDM7OmPziRjCjt
	rQWvEaIYn4X1Rehd0vOV5pc=
X-Google-Smtp-Source: ABdhPJxTwgrUXqh6POO22y9VmU6GE4Frw3qwBwzPUT2cDiAehYaTPZOKOt3r9CqaH+bdFENhG+fwGg==
X-Received: by 2002:a65:6283:: with SMTP id f3mr22123426pgv.254.1605107190484;
        Wed, 11 Nov 2020 07:06:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8f0c:: with SMTP id n12ls6090211pfd.8.gmail; Wed, 11 Nov
 2020 07:06:30 -0800 (PST)
X-Received: by 2002:a63:7847:: with SMTP id t68mr17597765pgc.422.1605107189905;
        Wed, 11 Nov 2020 07:06:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605107189; cv=none;
        d=google.com; s=arc-20160816;
        b=zOdV/5/eOjQCvHoh30VKV8FOJ1Af1vq6RaiBaIJXcbzdUbXSAmymPmt1U/NwegvOf/
         umtomQCEhLZSyKuVvBhWJ2MzTuHoFvUoo4vKpa/cJhvwqHJkFEJHqiEZtTaoILXJGbv2
         WMkCaFUuoSFgPc2ruDRZAd0OsmPqTSb7FvCuj35oeYIWyDECbcjARuNueL7dwfLtR9Jy
         X5twGnIvmUTZZ1kz5eheS4VJieVke0paZ/Q5Lj8XhR0809O5gX7dbsR3zDF89tyBJIRG
         l3lurRkgI+ZazGoYRFH1390KxETqr7c8udufK48DETzv6elLStyZRrvgSR4MHzyH4vjI
         nqXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=58st//mhI/fJn9QMBMlM7AWMjgnTnsXCK83D1v/z6LQ=;
        b=IrF0+7rDiUYoRDwrktix4JG3a14oa1rxvb9vpI0Kbn1rVH3Ypmi2w0bLv1Gq+8dHnL
         h3TO8G4fHbCWGvI3Uber8pPxBszknJjq2G3OdXDfBnAarnur9z8nZqyxOiYKMZn357dP
         VAR94CAg/cRK75e6mgn0VgEPTej807hrTHyEnZYCYVmsQgZFe9r0LmhXXtRQyLwhWUZp
         GCsP7WJtEfncoOZa6NuS2LEAOxtq9Z8RSjYMpiIl3GXuI9yuU1sZJtub71Er9tdzYrrg
         CttEIauEq1iwMW5WT8IvtcpX07Fc/ZhaE2QdTHMkXSesetKfhXnMz3Pjz3IF2sUeNKAv
         Ombw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HvYqEhf5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id d2si169107pfr.4.2020.11.11.07.06.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:06:29 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id v143so1935389qkb.2
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:06:29 -0800 (PST)
X-Received: by 2002:a37:4552:: with SMTP id s79mr19370022qka.6.1605107188820;
 Wed, 11 Nov 2020 07:06:28 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <1034f823921727b3c5819f6d2cdfc64251476862.1605046192.git.andreyknvl@google.com>
In-Reply-To: <1034f823921727b3c5819f6d2cdfc64251476862.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:06:16 +0100
Message-ID: <CAG_fn=VZBf8QwocHwcupo-9b6BnikAMQTuKFe1pTZwimSViqCQ@mail.gmail.com>
Subject: Re: [PATCH v9 19/44] kasan: rename addr_has_shadow to addr_has_metadata
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
 header.i=@google.com header.s=20161025 header.b=HvYqEhf5;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as
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
> Hardware tag-based KASAN won't be using shadow memory, but will reuse
> this function. Rename "shadow" to implementation-neutral "metadata".
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
> Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
> ---
>  mm/kasan/kasan.h          | 2 +-
>  mm/kasan/report.c         | 6 +++---
>  mm/kasan/report_generic.c | 2 +-
>  3 files changed, 5 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d0cf61d4d70d..f9366dfd94c9 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -146,7 +146,7 @@ static inline const void *kasan_shadow_to_mem(const v=
oid *shadow_addr)
>                 << KASAN_SHADOW_SCALE_SHIFT);
>  }
>
> -static inline bool addr_has_shadow(const void *addr)
> +static inline bool addr_has_metadata(const void *addr)
>  {
>         return (addr >=3D kasan_shadow_to_mem((void *)KASAN_SHADOW_START)=
);
>  }
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index af9138ea54ad..2990ca34abaf 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t=
 size, bool is_write,
>         untagged_addr =3D reset_tag(tagged_addr);
>
>         info.access_addr =3D tagged_addr;
> -       if (addr_has_shadow(untagged_addr))
> +       if (addr_has_metadata(untagged_addr))
>                 info.first_bad_addr =3D find_first_bad_addr(tagged_addr, =
size);
>         else
>                 info.first_bad_addr =3D untagged_addr;
> @@ -372,11 +372,11 @@ static void __kasan_report(unsigned long addr, size=
_t size, bool is_write,
>         start_report(&flags);
>
>         print_error_description(&info);
> -       if (addr_has_shadow(untagged_addr))
> +       if (addr_has_metadata(untagged_addr))
>                 print_tags(get_tag(tagged_addr), info.first_bad_addr);
>         pr_err("\n");
>
> -       if (addr_has_shadow(untagged_addr)) {
> +       if (addr_has_metadata(untagged_addr)) {
>                 print_address_description(untagged_addr, get_tag(tagged_a=
ddr));
>                 pr_err("\n");
>                 print_shadow_for_address(info.first_bad_addr);
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index b543a1ed6078..16ed550850e9 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -118,7 +118,7 @@ const char *get_bug_type(struct kasan_access_info *in=
fo)
>         if (info->access_addr + info->access_size < info->access_addr)
>                 return "out-of-bounds";
>
> -       if (addr_has_shadow(info->access_addr))
> +       if (addr_has_metadata(info->access_addr))
>                 return get_shadow_bug_type(info);
>         return get_wild_bug_type(info);
>  }
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
kasan-dev/CAG_fn%3DVZBf8QwocHwcupo-9b6BnikAMQTuKFe1pTZwimSViqCQ%40mail.gmai=
l.com.
