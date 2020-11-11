Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKUDWD6QKGQEK6XCPLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EBEA2AF4A3
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:22:19 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id h9sf2700828ybj.10
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:22:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605108138; cv=pass;
        d=google.com; s=arc-20160816;
        b=On7gDIx1/c77QHtVfNtEvFmSz1b14xsjh6OoReM5y+pgNOXCcyNzHd/BUbuYh39RmT
         qjEUBZNnBGLMdv0lFgY4f43UgrCZE8WKtD0KGcWsrmhOsvMBhap6I3ddUhmH43cWrNL5
         PfBn2YmNcwtTuGiTZOopfmAhfFKE1QL2cRGrwfmNShhaT6xxLq8EDnSn8S9ZJOGqAuH0
         3Q7OAcHDcJgb3M4qhk3VEzpErrcRJmli0FNvIE6uLVuAG7gQM4l9ZB7fF2uiUrCdOOZF
         Vk2WlKsSB1N6LUvnuxEvxRfl1yizZCrYEtWDJReaJOfZ16vtnMHE7eb0pAySvhJL6pDN
         gZTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vsFQtjYbTwDJi7dyvKm3wzF+wnLhZgG81fK7nyI40uI=;
        b=yG6pxrC7O5xa820cVwEsl89dFUHN690V97D/lmXKXLgwIa15EdX68K68wCSlNlyO8T
         u3a0J0gDf5qYHxuCttOqeoPtKAT+3G6XUnc3QjtjMwVzJokOt5C2fByFJK46a++Zs1+O
         Ta0xlXcYtQxQdf0XU3Og1eL+skxULP+VrM/xdwD5I5iLqU56Dmc5WAXTveZ6QfwsHtkj
         S2apgJqtnL78lc/4Q9H3lBVlH+dg9ASqcj5TrcHZX4UHyBBMMWciM5KVIkfwCOq3spXR
         jJPFgO20/zA55/xX4FZS4GZhRzs383Vk+hfIeVBF0hBKGel09pDfu+dQ3LXfusCrj5Tt
         hSzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZsqrL7Uq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vsFQtjYbTwDJi7dyvKm3wzF+wnLhZgG81fK7nyI40uI=;
        b=R/N2lKRaDou/RQUOa1qI1nBI/wTyiwfOZIcu5VP3HIj2c35q3RHJ7+hrDv3GHW1Lva
         CyVpL006KcpNFcNDc9402HTKl6toXq4RLnqgjqjuJ8qkajOOoqzCkR9slg9OdbD4brFq
         W33XYG40u5UmRjQuG7reH5+aUmX7thnz2kmJvs46UzjHw2x9VSlhzYod3xpfFn9cDv3m
         SNug8NXZuNUnSZXmQmv4FutI8Pk14s4YIUVNsIWaNfGXkAjydzzNWE32a723r6vMPssS
         3hvpq99yPS0YcrBGBdG0LPByTG5+jdgsnZAxNGKhk7lgQx8CTOIokJmONdWz9VD5VIyL
         l+/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vsFQtjYbTwDJi7dyvKm3wzF+wnLhZgG81fK7nyI40uI=;
        b=TTjlha9Am5PK4EqY1KRBsgwgiKVFdGcFIyv+0J1LJD6X6oBkn1WXoqsLDd7xYl38db
         mdamLfeZHBtg0nsV9lxivya+3GGEVftLEroKj8WbCq7rJOBbQ1Fq8JsKoZGigt+g80Hh
         8T3IjbYBDrLvj0rtmdakzCyReBjxZndCQp0IhFDxafCfRm0fLAnHD/HasrZK+OO6fyer
         nJ/nZOqARICq+qirJsafox0IALltcfsXGEMywSTxD622A/p3T84ZrmIdBNvOHeHEn65f
         FOdgXESanDnqsPZ1pcTiKz9UTeKdvKgDJriLuBLh5FC8sh8TmIhDr65g6diMp55D2Fx9
         bELA==
X-Gm-Message-State: AOAM5309RW8vCxF+o/IJdWElmPbTJa29Ao68oKDsc0gbZvzoMydDlFm+
	PHpMeNEOR5TotrSJDY2/GcA=
X-Google-Smtp-Source: ABdhPJw110myq4Ekn72Yfy9TycREhYUY8ebAZtyloaghXAd2BqgdAa8s3JHywtnKsyF0khQE3m615g==
X-Received: by 2002:a25:bc42:: with SMTP id d2mr3247734ybk.461.1605108138206;
        Wed, 11 Nov 2020 07:22:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2d56:: with SMTP id s22ls92155ybe.0.gmail; Wed, 11 Nov
 2020 07:22:17 -0800 (PST)
X-Received: by 2002:a25:a242:: with SMTP id b60mr34777702ybi.353.1605108137679;
        Wed, 11 Nov 2020 07:22:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605108137; cv=none;
        d=google.com; s=arc-20160816;
        b=Xh2XJZfEVEA3EndgkGFh9otLMujK72DtriRDYWHPnVcp1QsI+QertUq0Qc7xn1lU+y
         aB3P5O1Yr62bufrP02SWl3VcbMTNSZ2HOi6scQAqZnLptQAD2paMpWIId+P47TWAeXRc
         +aUn0JU7HZFbtZjEl5SfHnGOw2n7lXdiA+HMnmf0LFolL/aJp3zxRudLNl4ZTlgl5ios
         AvUKYW9UgOR4ixpjdYCceKo5RhfqzjQWdLzR9ixUdLOEEz3W1nhv5TJVJnWHYMvJx6tl
         605v8bkGpOXBDp+6ZAolE0j6pema+gY+9vUsqNVRZSbmvUoSw9t+/51EPbq/KPbkHzP5
         VAZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qP4CSavCKNiU1+9udAKKC5xpzE+JMfMUoD8Vn5vSarA=;
        b=OJETi0KhTsSFZ71MSrcFGPyZVizc/ntqjwRqioEsVoUIxuA4ldMykSuMU5N36oixnP
         9nhNF2i5VRGc8543A18PfrsGMiqMX99g1GNc+W6LuU5bi29J9J87iQ2aF1jI0EzJBNPc
         NroB71Q1H2+3poW4jlx3K579FdQuAnIqwmV7MO4l1qIzCxfScSoLS4DavpNInjV8rWjE
         RIgXSKr1xjzC1Tckel1PEMjGPTEoFnRgEIvjUtpO6RikLH8kcdeQpEK3wqwuRaNCRJfj
         v3P0nuSDreQqdLMcR2e5gItPZJH4UGoSDNviRWG2150K+f5j/H6yPmp0ZugSfEo5+xjk
         rAgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZsqrL7Uq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id y4si172497ybr.2.2020.11.11.07.22.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:22:17 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id h12so1495374qtc.9
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:22:17 -0800 (PST)
X-Received: by 2002:ac8:5c85:: with SMTP id r5mr19151032qta.8.1605108137054;
 Wed, 11 Nov 2020 07:22:17 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <560e04850b62da4fd69caa92b4ce3bebf275ea59.1605046192.git.andreyknvl@google.com>
In-Reply-To: <560e04850b62da4fd69caa92b4ce3bebf275ea59.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:22:05 +0100
Message-ID: <CAG_fn=W-H8nHc_DmBOsnJOUygDJ+wg78K-QSY_wHTSHg-b8vFQ@mail.gmail.com>
Subject: Re: [PATCH v9 23/44] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=ZsqrL7Uq;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as
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
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> Rework print_memory_metadata() to make it agnostic with regard to the
> way metadata is stored. Allow providing a separate metadata_fetch_row()
> implementation for each KASAN mode. Hardware tag-based KASAN will provide
> its own implementation that doesn't use shadow memory.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
> Change-Id: I5b0ed1d079ea776e620beca6a529a861e7dced95
> ---
>  mm/kasan/kasan.h          |  8 ++++++
>  mm/kasan/report.c         | 56 +++++++++++++++++++--------------------
>  mm/kasan/report_generic.c |  5 ++++
>  mm/kasan/report_sw_tags.c |  5 ++++
>  4 files changed, 45 insertions(+), 29 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index f9366dfd94c9..b5b00bff358f 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -57,6 +57,13 @@
>  #define KASAN_ABI_VERSION 1
>  #endif
>
> +/* Metadata layout customization. */
> +#define META_BYTES_PER_BLOCK 1
> +#define META_BLOCKS_PER_ROW 16
> +#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> +#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
> +#define META_ROWS_AROUND_ADDR 2
> +
>  struct kasan_access_info {
>         const void *access_addr;
>         const void *first_bad_addr;
> @@ -168,6 +175,7 @@ bool check_invalid_free(void *addr);
>
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
> +void metadata_fetch_row(char *buffer, void *row);
>
>  #if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
>  void print_address_stack_frame(const void *addr);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 8c588588c88f..8afc1a6ab202 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -33,12 +33,6 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -/* Metadata layout customization. */
> -#define META_BYTES_PER_BLOCK 1
> -#define META_BLOCKS_PER_ROW 16
> -#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> -#define META_ROWS_AROUND_ADDR 2
> -
>  static unsigned long kasan_flags;
>
>  #define KASAN_BIT_REPORTED     0
> @@ -238,55 +232,59 @@ static void print_address_description(void *addr, u=
8 tag)
>         print_address_stack_frame(addr);
>  }
>
> -static bool row_is_guilty(const void *row, const void *guilty)
> +static bool meta_row_is_guilty(const void *row, const void *addr)
>  {
> -       return (row <=3D guilty) && (guilty < row + META_BYTES_PER_ROW);
> +       return (row <=3D addr) && (addr < row + META_MEM_BYTES_PER_ROW);
>  }
>
> -static int shadow_pointer_offset(const void *row, const void *shadow)
> +static int meta_pointer_offset(const void *row, const void *addr)
>  {
> -       /* The length of ">ff00ff00ff00ff00: " is
> -        *    3 + (BITS_PER_LONG/8)*2 chars.
> +       /*
> +        * Memory state around the buggy address:
> +        *  ff00ff00ff00ff00: 00 00 00 05 fe fe fe fe fe fe fe fe fe fe f=
e fe
> +        *  ...
> +        *
> +        * The length of ">ff00ff00ff00ff00: " is
> +        *    3 + (BITS_PER_LONG / 8) * 2 chars.
> +        * The length of each granule metadata is 2 bytes
> +        *    plus 1 byte for space.
>          */
> -       return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
> -               (shadow - row) / META_BYTES_PER_BLOCK + 1;
> +       return 3 + (BITS_PER_LONG / 8) * 2 +
> +               (addr - row) / KASAN_GRANULE_SIZE * 3 + 1;
>  }
>
>  static void print_memory_metadata(const void *addr)
>  {
>         int i;
> -       const void *shadow =3D kasan_mem_to_shadow(addr);
> -       const void *shadow_row;
> +       void *row;
>
> -       shadow_row =3D (void *)round_down((unsigned long)shadow,
> -                                       META_BYTES_PER_ROW)
> -               - META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
> +       row =3D (void *)round_down((unsigned long)addr, META_MEM_BYTES_PE=
R_ROW)
> +                       - META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
>
>         pr_err("Memory state around the buggy address:\n");
>
>         for (i =3D -META_ROWS_AROUND_ADDR; i <=3D META_ROWS_AROUND_ADDR; =
i++) {
> -               const void *kaddr =3D kasan_shadow_to_mem(shadow_row);
> -               char buffer[4 + (BITS_PER_LONG/8)*2];
> -               char shadow_buf[META_BYTES_PER_ROW];
> +               char buffer[4 + (BITS_PER_LONG / 8) * 2];
> +               char metadata[META_BYTES_PER_ROW];
>
>                 snprintf(buffer, sizeof(buffer),
> -                       (i =3D=3D 0) ? ">%px: " : " %px: ", kaddr);
> +                               (i =3D=3D 0) ? ">%px: " : " %px: ", row);
> +
>                 /*
>                  * We should not pass a shadow pointer to generic
>                  * function, because generic functions may try to
>                  * access kasan mapping for the passed address.
>                  */
> -               memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
> +               metadata_fetch_row(&metadata[0], row);
> +
>                 print_hex_dump(KERN_ERR, buffer,
>                         DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
> -                       shadow_buf, META_BYTES_PER_ROW, 0);
> +                       metadata, META_BYTES_PER_ROW, 0);
>
> -               if (row_is_guilty(shadow_row, shadow))
> -                       pr_err("%*c\n",
> -                               shadow_pointer_offset(shadow_row, shadow)=
,
> -                               '^');
> +               if (meta_row_is_guilty(row, addr))
> +                       pr_err("%*c\n", meta_pointer_offset(row, addr), '=
^');
>
> -               shadow_row +=3D META_BYTES_PER_ROW;
> +               row +=3D META_MEM_BYTES_PER_ROW;
>         }
>  }
>
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 16ed550850e9..8a9c889872da 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -123,6 +123,11 @@ const char *get_bug_type(struct kasan_access_info *i=
nfo)
>         return get_wild_bug_type(info);
>  }
>
> +void metadata_fetch_row(char *buffer, void *row)
> +{
> +       memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);

I think it is important to use __memcpy() instead of memcpy() in KASAN
runtime to avoid calling instrumented code.

> +}
> +
>  #if CONFIG_KASAN_STACK
>  static bool __must_check tokenize_frame_descr(const char **frame_descr,
>                                               char *token, size_t max_tok=
_len,
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index c87d5a343b4e..add2dfe6169c 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -80,6 +80,11 @@ void *find_first_bad_addr(void *addr, size_t size)
>         return p;
>  }
>
> +void metadata_fetch_row(char *buffer, void *row)
> +{
> +       memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);

Ditto.

> +}
> +
>  void print_tags(u8 addr_tag, const void *addr)
>  {
>         u8 *shadow =3D (u8 *)kasan_mem_to_shadow(addr);
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
kasan-dev/CAG_fn%3DW-H8nHc_DmBOsnJOUygDJ%2Bwg78K-QSY_wHTSHg-b8vFQ%40mail.gm=
ail.com.
