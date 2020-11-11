Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6HDV76QKGQE7PQPXCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1500F2AF351
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:15:22 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id l11sf648689vso.12
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:15:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605104121; cv=pass;
        d=google.com; s=arc-20160816;
        b=q9Y8L9QxL3cWKz0ThhQWNsag61Gb+AgrYA2mhZwbSP7IBRHDwkbHsfgmpUlBGGMF36
         h3dJJeaAwxn7Kxz2o/A3DlaWV5Ot+LquN8MMg8+Pdo6SLYJWz0iPOn4N7+KwS9tXIylE
         DYTd2JkCMwmBr28gLz+cGvTKYhaWUGDB0HN3PUNdnFnu3b+vB7z6KER7J4d484Dzrsyk
         Qgph7yBhbXrK2172TQlxGJHKjbZjXKdZYUdgYXyFxDV4kXQ94NZp4sRvBwlQnr7rgQW6
         5bG4vgHh5R5g3mdRedKCK0Ggpxk2hvr4OgjnhgH6sUcBUUucApLHI0f8QghszbhI77G3
         NwGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QnzywWJDwEJv4IFnQVXqQR6b5jMMLsZqsFZ5MGAfk60=;
        b=WfBJQMT4E2g+gERcRZ62Wgww9Rmo6qIQ26HvhUBJVj2RNDiOHhT9ZXnxBYGFzOEDNW
         Ndi+itxwvzwiUEezsDsKIt3OayN7/2WK41NwJ417NXZG0MOwhH1DSwUeHrVcLvuED3nq
         b1yf+ZZ9jQDVuNinU1rKQVmPbK+N2EAxqntuceoSlxWZ03AnGe1Y/lAWJPQVDjbuMIGY
         18tfDgVadx9k/EnHZ4Y/2Or7tw9qnSGgEIsK5pTcnSVu29LHO0w2pww9hJKcSFKu0nAh
         JKWTjASDx3sYRQzBBlb1GPtYwOMk6oA1nVAV9RTdp2VpwQTE4aUVL2samSTQPPnvS5AE
         nwwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JqgXE+q+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QnzywWJDwEJv4IFnQVXqQR6b5jMMLsZqsFZ5MGAfk60=;
        b=XQFM+OhmsD9IRjp+f17O2psCpDA1oYN4VsT/h7teQzQHqER4Eh1Oxn0shYbr7EN6FR
         GqCU8nx55UOTWIk/K/JEUBquylR1bSmm68WBw47zEiWuIUISH0H8Vj84Y+lHoNIJa+ot
         wFhdecqK6hvocuAMmN5LgN+RB9jzdxAYMEmZQVmdFv+axfEFj6uyT8tR+98z33kKIVz8
         pXjpoW71Wh2mzBcye/C7Q8SdOlfkn0jtCGojUhq2brP9CwdUY0vX+vZdcHGQiAIUtukm
         g+6yjZ/oIrDmW648YT2L7istlN8qji+vgh2qz3ut60oNuQwrn711j11U33FQo8lx5f+T
         g5HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QnzywWJDwEJv4IFnQVXqQR6b5jMMLsZqsFZ5MGAfk60=;
        b=QvwKPFcsKWAEEQPDGzLUwRlXLZjAEazMLx41mypeSfiTHD0JL8sxLWl7xrWOUV02nD
         sc9iXwVOlwa0i9joGTKibS06hF4J6fOwPR4OVu0+/IVcAKzvld0b9i82ubRW4KlUdK1r
         nUqOCc4Kz3BSWO6UrGNoR0nvVjlEbfoXFgwjQ5Z6C7FuM5II4tslU+9jVhGXQamR73IQ
         5jadDFc0bl0G95Hfg7GxG1myYt+5xYAjoLoKDp0WIOQafkbeaZ5+SBF6a4+8qOuLh1bp
         PIvty+ExK77qEmfyK4B5VZiieM1iUC6P4901NwR8wMAv9hgWPf7T3c2M8KNDNb8MVT1W
         H/lw==
X-Gm-Message-State: AOAM530xVwy1LIjCxMgD9SYGe3mTVmJH0yymkXwWSu4VbuseglLC43yu
	kF/TWGEGE2mj9kWtrumUab4=
X-Google-Smtp-Source: ABdhPJyflhIxrZUb7Otw//0uOtySt2UhMNaEWmopfzhSibFfXxL7TVSYrcWxorqNTtpGFDfWyr2/oQ==
X-Received: by 2002:a1f:5e0b:: with SMTP id s11mr1057594vkb.8.1605104121076;
        Wed, 11 Nov 2020 06:15:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6d95:: with SMTP id m21ls1042765uah.10.gmail; Wed, 11
 Nov 2020 06:15:20 -0800 (PST)
X-Received: by 2002:a9f:36a1:: with SMTP id p30mr13342050uap.64.1605104120528;
        Wed, 11 Nov 2020 06:15:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605104120; cv=none;
        d=google.com; s=arc-20160816;
        b=sAKOQo+f8Ufo21RU+TYtojnRH1RpNK/9nmtk+SKrTqs0jezjk2brQVzn1kGfv5tzNA
         vwuiK/JL/oVCN2MlGZhOIN5/U6vY6UraR3J1lThsClIVOltQ8BWkNyf3DPNz+iCRwSIp
         2aqVz+QhJPMbsUKN7+tKa0nknQQuQ92HcvELlxF3F1Gjg1/Dtg8Al4K6NNisr83OfzrK
         lNSZ7dUQTeCwDjYBqo9ZsXhdBd7KNMCRQbHsb7qqr21N6idjCJnSoaBIFh9Ig37eLAjo
         sx6Wg0+PwR3zn6RO1wyh91wDSnSnba6bD3mfrzRWXidwsqg7LkdGoqyZWtvyABV+BtmW
         SVSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UkBccG0kAG6ptvne6HOJOUn3nzbGkGD7oWbn2QDoT/s=;
        b=i/pSgBk5BFBqun7dqXT6leYZ9EIAs1wbfnnySDrzvdYiY/IVIcBtGKVYpmN8041N6v
         51B9tkf2R6rg8I69gS8n2Wl6+v7pNhx+cdjSYAJLPzXUlP4WutCwrc8CjUPZuCXK43eK
         EG9BkXHxiwSPlG8sWCxkYD+BuDF7vgYMMzNmx52iociB8AcpI4Sno3KSTglVyZJ4aqGz
         VvwJM3832WJcRfa8/Edv8AA0Nnp11gApPXa1qiOhWS7wU5M2BzbeBv5Dnvr/X4XKXwSL
         NX8BVG79q0Xr/0Hl7yvrUtDdz2zOpCd0env7cFZYw4kO+3I5VfbzkpOYZBhArYre3f89
         rotQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JqgXE+q+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id n1si125565vsr.2.2020.11.11.06.15.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:15:20 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 199so1714110qkg.9
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:15:20 -0800 (PST)
X-Received: by 2002:a37:4552:: with SMTP id s79mr19121371qka.6.1605104119855;
 Wed, 11 Nov 2020 06:15:19 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <37a9648ffa16572583a7513323cc9be88a726eb1.1605046192.git.andreyknvl@google.com>
In-Reply-To: <37a9648ffa16572583a7513323cc9be88a726eb1.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:15:08 +0100
Message-ID: <CAG_fn=WgBr=NxYTiPGq=0HADk5e=RO3BS-OTxVVT4w=pOKu_uA@mail.gmail.com>
Subject: Re: [PATCH v9 11/44] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=JqgXE+q+;       spf=pass
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
> Rename generic_report.c to report_generic.c and tags_report.c to
> report_sw_tags.c, as their content is more relevant to report.c file.
> Also rename tags.c to sw_tags.c to better reflect that this file contains
> code for software tag-based mode.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: If77d21f655d52ef3e58c4c37fd6621a07f505f18
> ---
>  mm/kasan/Makefile                               | 16 ++++++++--------
>  mm/kasan/report.c                               |  2 +-
>  mm/kasan/{generic_report.c =3D> report_generic.c} |  0
>  mm/kasan/{tags_report.c =3D> report_sw_tags.c}    |  0
>  mm/kasan/{tags.c =3D> sw_tags.c}                  |  0
>  5 files changed, 9 insertions(+), 9 deletions(-)
>  rename mm/kasan/{generic_report.c =3D> report_generic.c} (100%)
>  rename mm/kasan/{tags_report.c =3D> report_sw_tags.c} (100%)
>  rename mm/kasan/{tags.c =3D> sw_tags.c} (100%)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 7cc1031e1ef8..f1d68a34f3c9 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -6,13 +6,13 @@ KCOV_INSTRUMENT :=3D n
>  # Disable ftrace to avoid recursion.
>  CFLAGS_REMOVE_common.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_generic.o =3D $(CC_FLAGS_FTRACE)
> -CFLAGS_REMOVE_generic_report.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_init.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_quarantine.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report.o =3D $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report_generic.o =3D $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report_sw_tags.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_shadow.o =3D $(CC_FLAGS_FTRACE)
> -CFLAGS_REMOVE_tags.o =3D $(CC_FLAGS_FTRACE)
> -CFLAGS_REMOVE_tags_report.o =3D $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_sw_tags.o =3D $(CC_FLAGS_FTRACE)
>
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_sto=
re1
>  # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D63533
> @@ -23,14 +23,14 @@ CC_FLAGS_KASAN_RUNTIME +=3D -DDISABLE_BRANCH_PROFILIN=
G
>
>  CFLAGS_common.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_generic.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> -CFLAGS_generic_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_init.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_quarantine.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_report_generic.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_report_sw_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_shadow.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> -CFLAGS_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> -CFLAGS_tags_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_sw_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>
>  obj-$(CONFIG_KASAN) :=3D common.o report.o
> -obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o generic_report.o shado=
w.o quarantine.o
> -obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o shadow.o tags.o tags_report.o
> +obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o report_generic.o shado=
w.o quarantine.o
> +obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o report_sw_tags.o shadow.o sw_tag=
s.o
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 7b8dcb799a78..fff0c7befbfe 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains common generic and tag-based KASAN error reporting=
 code.
> + * This file contains common KASAN error reporting code.
>   *
>   * Copyright (c) 2014 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/report_generic.c
> similarity index 100%
> rename from mm/kasan/generic_report.c
> rename to mm/kasan/report_generic.c
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/report_sw_tags.c
> similarity index 100%
> rename from mm/kasan/tags_report.c
> rename to mm/kasan/report_sw_tags.c
> diff --git a/mm/kasan/tags.c b/mm/kasan/sw_tags.c
> similarity index 100%
> rename from mm/kasan/tags.c
> rename to mm/kasan/sw_tags.c
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
kasan-dev/CAG_fn%3DWgBr%3DNxYTiPGq%3D0HADk5e%3DRO3BS-OTxVVT4w%3DpOKu_uA%40m=
ail.gmail.com.
