Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYEBWD6QKGQERVHKIBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F18F2AF499
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:18:58 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id i67sf1519308pgc.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:18:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605107937; cv=pass;
        d=google.com; s=arc-20160816;
        b=o/48Oiiv7aKYRcM7jN2hUdg4XSNihFunr075/WveOG3+0Spk1nulgRv7nxx8okzauS
         lHNPCEHqpkTaBwEx0FYRmAmvbQmIdz2ZbMJTCWjImX6yD80Ds1sXcICgZd4dIqiC++cz
         S9s5q8yy6FvyOswMg9KvgdPVPvUlPzr1on2Hp28DykmvnONEtBMHjUeoWX9RyqYczNg8
         KgNG8tjSZ5KWhJVsUtimsUhZpuRmONEzIJD43z6okkOzswcfpT1nXNIZqd3gAnUEH77s
         DvS+XIpxugGuMDWk7h6cVRLn2NoYy7joZB/D0D9CYIQmmvA+6/Xg0lzSTMgLtAcH1oQp
         9sJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2KFNs1++q0JDcqXK8Ak0lLJHSDuy8Vq7O7463qZh7Ok=;
        b=Xf142J99adMqdGSX3dP+zVnhW1zl3NiP9E7H6zuRuexw9gEqfRuK06fMk0zy6htBlY
         Zy+j9IfE36NWlVcbNMCYBUYWr5E6ZaDTm3Hql4ilnCdiqabZWlxNxpfALBCdxU6izJzQ
         Ajyado+gZQqASirMjG5WZpxJYNHOxojIeGFd8uqsgmhk3adyVPj1JbhVnfwFlo2E2ope
         wIZvk4OhFxaewpARJXoLO9FrpaNmDBs2CiZFlNjF6zBeCiaZtJXzkKPzPba9Lq/aSYp6
         /8FYQnPuPD+ZzBtwS7qix6bb5wwT3wtCWXqeSlOu6LdcU01SPWKg+KinyVtxPohpLd+5
         5WDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gyKbCHEv;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2KFNs1++q0JDcqXK8Ak0lLJHSDuy8Vq7O7463qZh7Ok=;
        b=Quczv8IqmBFJ71n5p7P1LahD49iLcd6xmm6KbkaBu+OW3EYRh+0wsbgzK3l6C6QMM7
         YJ0gQNSYrgDD8ErmCVV9B3F4PJ5T1u5wJ5IhMfPAzEPSbSvp0YWbiEttR+7K3ei1kdAX
         F2n1sD4Tk6iSCClEjEhTKVNg5gLsyBIHIxH6idNY9zwXOJX+P7t8yVlClYMWG/vuXPDm
         Ha0VblQdNKvwPCuoNsxR3ooB2j1bHq/gJnKLNkNvBfr1pfEZtgILBWefzBerH7E19a95
         DEwQ98LGPFJ72SFLxiyUm1Ov5NTiN12DXboN6EXE3nexi7GLgbCW721uzGg5F5qD19Uv
         5gbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2KFNs1++q0JDcqXK8Ak0lLJHSDuy8Vq7O7463qZh7Ok=;
        b=a60uulKd/h31XdKuiqPZktvnXCuGCxszmlGb/AKFOp13qr1XNVh4QPeHxCSp4eCWgR
         hq7pxL9QlSkf5DneU83XjfZKzr3LxymYD3gbjhyVI3bCTrFlEK4nx33HvSnu6PShqCuf
         RZtNz/JVEZy5oTQ5SQy73IEDdNWW+X/TE4OUYPsTncKTeSO8FUkqZR5/Sf/IqqCRruQO
         +PYz7kH2HAZ9Ajp4PZG9LLsPy2LwF0w9hByjP5PaYDUsqfOI3qtqijTtw+LdFvWgk82F
         1f1go+9MbLeDL278woqnSp8mAaRe4iaI6XMdZXpf1vY5YRhqaIGA6mRcdM0xx69PfSkn
         2Eeg==
X-Gm-Message-State: AOAM5308aPEp4lnIjHqnTxRgfiqN0K04ZAIVyLsFyEwjMFKqHVcSfD8J
	lpbbDWh36MISqmAXeslx7OY=
X-Google-Smtp-Source: ABdhPJwDiMgI+hsQr3RrPSEnlHkhMsIwTVa53+B9kGPEEpaxPN0adFF2jRpJsEtukF2N3++P1XJgZA==
X-Received: by 2002:a17:90a:11:: with SMTP id 17mr4371416pja.66.1605107936862;
        Wed, 11 Nov 2020 07:18:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls21615pga.5.gmail; Wed, 11 Nov
 2020 07:18:56 -0800 (PST)
X-Received: by 2002:a63:c43:: with SMTP id 3mr23204766pgm.222.1605107936311;
        Wed, 11 Nov 2020 07:18:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605107936; cv=none;
        d=google.com; s=arc-20160816;
        b=vU7mzkwpaFwyAPHyi08D1QyjzNbbLjUQEMnRqrba9Fn64tY205NTCJPL2tHil+faSi
         p00IQZ6op4T97gOo6RIy0rb+0tEOt+Acov4324eQ75uRKrrV+Df/UpZmGPj4NvofsaMj
         J9dM8ad6VoiddVTIs07KzbXKUN2jcgLKZ5R7zwrh+WdWDbCV1sSjTM9OwUYSu1/fMXdK
         ojL2kc0I8GDXLPbyWhuia5sIGUaeSKndmM2CKvW16/c0wKjNpGmByDcRwds6jL2EZTZO
         2S5uUDIGTdYOmj9mmMhi3ni0p+jJuzCmC/u4bekkh1QnV0z6/922VKx701ChszX28EuB
         jLIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3XxacOuX3QMvhk3diut0JoyxopS0EmCY/QAdadNPdVM=;
        b=I4EcGN2RWE0AeEZO85ItcpQcJN2rLSCL6UqmX737LSH6fRosu+23EPJwUhm+n4vPaO
         hA4fUljoacXq6cR2nei000OZDKMHAIJqZddzMmwbBQE6vH16JgPHOGOqhZGPXbiZvr0w
         DM/lKjccH67TwrjGctP52sh+wJ2sqBeMy3JRxf3q7g9OK5UQCoQUvwkntHAn555zxfNb
         +cYFRDrtj0WOWpwt+2dxWwPUSCQ/xFFq8M9ILTTwBExUS6nP5vsdyiKh6RSTfx5DgAcH
         arR/JiZ6Y9Dwc0qBdzKWk3cmD7vLfzyeSdRmve7QUTyJAZtZBTNXrsZutBOhWWQkP1rs
         XF5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gyKbCHEv;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id cc22si142239pjb.0.2020.11.11.07.18.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:18:56 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id p12so1491799qtp.7
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:18:56 -0800 (PST)
X-Received: by 2002:ac8:5c85:: with SMTP id r5mr19136944qta.8.1605107935487;
 Wed, 11 Nov 2020 07:18:55 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <f24f24cf8c75844531a01668b314aced88f5f3e1.1605046192.git.andreyknvl@google.com>
In-Reply-To: <f24f24cf8c75844531a01668b314aced88f5f3e1.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:18:43 +0100
Message-ID: <CAG_fn=UbOixaO_CZgNw8vqpzZJDdb5LFQgq3CWs7Shru4ZtJyg@mail.gmail.com>
Subject: Re: [PATCH v9 22/44] kasan: rename SHADOW layout macros to META
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
 header.i=@google.com header.s=20161025 header.b=gyKbCHEv;       spf=pass
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> Hardware tag-based KASAN won't be using shadow memory, but will reuse
> these macros. Rename "SHADOW" to implementation-neutral "META".
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: Id2d836bf43b401bce1221cc06e745185f17b1cc
> ---
>  mm/kasan/report.c | 30 +++++++++++++++---------------
>  1 file changed, 15 insertions(+), 15 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 594bad2a3a5e..8c588588c88f 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -33,11 +33,11 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -/* Shadow layout customization. */
> -#define SHADOW_BYTES_PER_BLOCK 1
> -#define SHADOW_BLOCKS_PER_ROW 16
> -#define SHADOW_BYTES_PER_ROW (SHADOW_BLOCKS_PER_ROW * SHADOW_BYTES_PER_B=
LOCK)
> -#define SHADOW_ROWS_AROUND_ADDR 2
> +/* Metadata layout customization. */
> +#define META_BYTES_PER_BLOCK 1
> +#define META_BLOCKS_PER_ROW 16
> +#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> +#define META_ROWS_AROUND_ADDR 2
>
>  static unsigned long kasan_flags;
>
> @@ -240,7 +240,7 @@ static void print_address_description(void *addr, u8 =
tag)
>
>  static bool row_is_guilty(const void *row, const void *guilty)
>  {
> -       return (row <=3D guilty) && (guilty < row + SHADOW_BYTES_PER_ROW)=
;
> +       return (row <=3D guilty) && (guilty < row + META_BYTES_PER_ROW);
>  }
>
>  static int shadow_pointer_offset(const void *row, const void *shadow)
> @@ -249,7 +249,7 @@ static int shadow_pointer_offset(const void *row, con=
st void *shadow)
>          *    3 + (BITS_PER_LONG/8)*2 chars.
>          */
>         return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
> -               (shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
> +               (shadow - row) / META_BYTES_PER_BLOCK + 1;
>  }
>
>  static void print_memory_metadata(const void *addr)
> @@ -259,15 +259,15 @@ static void print_memory_metadata(const void *addr)
>         const void *shadow_row;
>
>         shadow_row =3D (void *)round_down((unsigned long)shadow,
> -                                       SHADOW_BYTES_PER_ROW)
> -               - SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;
> +                                       META_BYTES_PER_ROW)
> +               - META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
>
>         pr_err("Memory state around the buggy address:\n");
>
> -       for (i =3D -SHADOW_ROWS_AROUND_ADDR; i <=3D SHADOW_ROWS_AROUND_AD=
DR; i++) {
> +       for (i =3D -META_ROWS_AROUND_ADDR; i <=3D META_ROWS_AROUND_ADDR; =
i++) {
>                 const void *kaddr =3D kasan_shadow_to_mem(shadow_row);
>                 char buffer[4 + (BITS_PER_LONG/8)*2];
> -               char shadow_buf[SHADOW_BYTES_PER_ROW];
> +               char shadow_buf[META_BYTES_PER_ROW];
>
>                 snprintf(buffer, sizeof(buffer),
>                         (i =3D=3D 0) ? ">%px: " : " %px: ", kaddr);
> @@ -276,17 +276,17 @@ static void print_memory_metadata(const void *addr)
>                  * function, because generic functions may try to
>                  * access kasan mapping for the passed address.
>                  */
> -               memcpy(shadow_buf, shadow_row, SHADOW_BYTES_PER_ROW);
> +               memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
>                 print_hex_dump(KERN_ERR, buffer,
> -                       DUMP_PREFIX_NONE, SHADOW_BYTES_PER_ROW, 1,
> -                       shadow_buf, SHADOW_BYTES_PER_ROW, 0);
> +                       DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
> +                       shadow_buf, META_BYTES_PER_ROW, 0);
>
>                 if (row_is_guilty(shadow_row, shadow))
>                         pr_err("%*c\n",
>                                 shadow_pointer_offset(shadow_row, shadow)=
,
>                                 '^');
>
> -               shadow_row +=3D SHADOW_BYTES_PER_ROW;
> +               shadow_row +=3D META_BYTES_PER_ROW;
>         }
>  }
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
kasan-dev/CAG_fn%3DUbOixaO_CZgNw8vqpzZJDdb5LFQgq3CWs7Shru4ZtJyg%40mail.gmai=
l.com.
