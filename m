Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRWIV76QKGQEMK7B7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 86F452AF1D1
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 14:16:55 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id x20sf1111808qts.19
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 05:16:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605100614; cv=pass;
        d=google.com; s=arc-20160816;
        b=O7VMAFG5R17LoTT5GC81L1bCaRgK/EZqNC5TZIOwLgZXyX+LPf92CbEBHxD2oCUkRl
         DMzoo3VKfEQh7jhalw6NZItJbPyJqH/p2JAaB9FnDY/sbS6e6Jjykf9OapPU5Oy1Ed9D
         DFoYbfReL+zCnRTgRRdVt7w/jQMyKGfbi+v36H1hVrSCmyiqIFC2WGk3hUW74DTuGZW1
         dg0UpqZJt3BU9KQQJd/TnKQJwMne9FKjBUp2GfhyM3oUfN+ohgrka5XnmhOTaBk5vqzN
         axgJebn0H62myYegwlEbMXD15kLIlw5QINMotG4ygJ4PX2Fso0xlcuQI8FYPrh4uuhD/
         9bnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CsuaAhK15Y1LOiGYernm0cMmdK3ET1UlzVqIKzjNa4A=;
        b=0EzMstlZVcIFUGdKze8tCst1CNK2lPsmi10rix1E/Q03ZxYGkpn+VObPRBDb9HytGm
         FGKjr164eSqY1SF4fCZKgr2xvVQ85BmDi6kwyxasE4tpzporpzgoYoLrXlyA/F8699tW
         xlERUbo2N6oqpRj4s+5j0D9soKy1oJYxt5Ru0ljUR+mLrPpH2vSmeaibnZqYlJYrknjd
         wD2nk8PMuh1jcF9OUGqaTbxfmPCdDgo6xIQrLJe4cIiyi9nI79MByLYUt9trq5Up6kR0
         MvULkaH1Y5m+U//+9j1YimEhgAySkG2CdYDJ0/7LJXyRu/zpbczg+cxIvyv9sKWSk0OG
         wcGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eUne43dO;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CsuaAhK15Y1LOiGYernm0cMmdK3ET1UlzVqIKzjNa4A=;
        b=g6mRZlGAIUPeCyUc97+2/0L2ASTC6gmnS/FkKWwVSUF70J37s+ofpyEnNLkaNt803s
         T8Hio+Cx3Sr/Rg/zSbJ4fqmaLj2qGDYCkzDMA5d/7OdBRecNVEyQ8nmy3sCmpOcQJ3AN
         Ohh4veknQF25YRIFGDjB5dCsVfvMIIMHf4v1KS4WuoJ+WTEn2ZAUdRcDS+HybbhbeVfU
         Z1MY5Mt9ZbU3ic3l24B71Q86M2rJFz0hbwNll2E4eP/cJSP4VD5DuFGHNwB1qBB0U8SL
         ul1S3x+t+QEsRhlaYJqyDzhvw0E0EkwM0NXwbxf4LVggSSbX6ZEWBTy4GLfyXOiVP8YG
         tBKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CsuaAhK15Y1LOiGYernm0cMmdK3ET1UlzVqIKzjNa4A=;
        b=SlAFhLNpzJs+wbkfON7K76vRLZ0IqMpQStreR345a1e/KOi5gFMHVWRyvD8VHi2t2Q
         qRc3s1a46tbQJe+ynl6VG+ZkyoNOmEzEoOqNeTsE/3kPSfavVhoOaLYiVHeDyipRcHgt
         AEi/ihf1UtdI2Z7ujcTF/yLYmmTFdR3t2woe+JplY+ODUG34TKpetbk6Cp3fXPMBQDb6
         wGt0Fd4avDJirAYSK2NN2rOe35xAHeD2JEw187s/1oTzdyiqQ+gfVBOdNElV8oAsq1PK
         Z+p39iqDPMJs6TkxllKhCVMzzP9vkKRm07cPq4vheg0aS9N22B8g1KCDBavHG/Czbc2K
         CuvA==
X-Gm-Message-State: AOAM533ydDh9LutSUBVu4RKlMjhWvTIPSzJ0BYdq3sIPBFTij68Dj08p
	rxMpGVc6amW50Lv7j4Z9tpo=
X-Google-Smtp-Source: ABdhPJwquQMungZoGd7zHetG02fcQulQq36R+0IjGCZuRloh7Jv5jm+gU1ElZJrnmjh/FOmPXI8luQ==
X-Received: by 2002:aed:32c7:: with SMTP id z65mr23531254qtd.266.1605100614451;
        Wed, 11 Nov 2020 05:16:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8744:: with SMTP id j65ls7639039qkd.1.gmail; Wed, 11 Nov
 2020 05:16:54 -0800 (PST)
X-Received: by 2002:ae9:dec5:: with SMTP id s188mr25426038qkf.250.1605100613978;
        Wed, 11 Nov 2020 05:16:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605100613; cv=none;
        d=google.com; s=arc-20160816;
        b=0olyr2eh63P/PIQJOrug4TetxfKMShfPdm4JMlWLnnBRw3VLJivdi02xl/K7F+PFIq
         NVS0klAt+6AmtQFZX+COZ+mWvdLEIqRoZpqdw/hdg5wLtufKlBjBGDQL0Tw+URQJ/C1V
         d6eDdkdnahrJyTEcaPEVFcTNE1gHEDVKv6upC5lmZOqbaKTTqDXgZ2+r6vek23VSbq+w
         8rAa4sFJFQyrGIgFzjqmrYbiqMHJqZ0TdXXt4aUf+qZYOMzDWs94QYb6AAN5O6y63NuD
         MJjwiBRnWVB2T1+NsDdk8aAyNLC6WJuSxfN2N0b6U3wfn5SM2K+MbFaLOCNyDewrEWD6
         Ux7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=L3xr+vb4NAdkO7IgO4hF3798stqYlZQgH+r9DFyhSKI=;
        b=HQMocXtzFmpCWG/xUNh9alGoVA6aw+v07zTvGLeiXuh+AUwCOITeAHD/Baw2bByunB
         PCeVeCmerElyh3ErCSRk2okYFPGytKjdTHEMo89kpCowvq4a1oV5OgY4jYXBp1Yt+9XP
         RAFxaFNO2v9URQShWn/zxvUqg67AcRpoQknNnY3f0dX1uUjZ+h5bLtTo3t5zq4k/A/1B
         Grl9CWwSv9VSDCkRP++9V1/WsmjuE5hr79iCACAAQG87+CGqHTk9t7wlbAg1L5j/oK0J
         CVVbltrrKstibwrvPjYras8C6jA8A8e01fkmtXsNJw1rJ5yURdY/GKILwGnCJeQm3og0
         pNYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eUne43dO;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id s190si149116qkf.4.2020.11.11.05.16.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 05:16:53 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 3so1208397qtx.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 05:16:53 -0800 (PST)
X-Received: by 2002:ac8:364d:: with SMTP id n13mr2590612qtb.369.1605100613373;
 Wed, 11 Nov 2020 05:16:53 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <8cf064ae41eb86697bd3aff5adf6b546d05351c1.1605046192.git.andreyknvl@google.com>
In-Reply-To: <8cf064ae41eb86697bd3aff5adf6b546d05351c1.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 14:16:42 +0100
Message-ID: <CAG_fn=X-=eqBm6R5qrexxBhYvJAKFn3mFLvK6+89Gxz_sivACw@mail.gmail.com>
Subject: Re: [PATCH v9 01/44] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=eUne43dO;       spf=pass
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
> Don't mention "GNU General Public License version 2" text explicitly,
> as it's already covered by the SPDX-License-Identifier.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: If0a2690042a2aa0fca70cea601ae9aabe72fa233
> ---
>  mm/kasan/common.c         |  5 -----
>  mm/kasan/generic.c        |  5 -----
>  mm/kasan/generic_report.c |  5 -----
>  mm/kasan/init.c           |  5 -----
>  mm/kasan/quarantine.c     | 10 ----------
>  mm/kasan/report.c         |  5 -----
>  mm/kasan/tags.c           |  5 -----
>  mm/kasan/tags_report.c    |  5 -----
>  8 files changed, 45 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 950fd372a07e..33d863f55db1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>
>  #include <linux/export.h>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 248264b9cb76..37ccfadd3263 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>
>  #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index a38c7a9e192a..6bb3f66992df 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>
>  #include <linux/bitops.h>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index fe6be0be1f76..9ce8cc5b8621 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -4,11 +4,6 @@
>   *
>   * Copyright (c) 2015 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>
>  #include <linux/memblock.h>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 4c5375810449..580ff5610fc1 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -6,16 +6,6 @@
>   * Copyright (C) 2016 Google, Inc.
>   *
>   * Based on code by Dmitry Chernenkov.
> - *
> - * This program is free software; you can redistribute it and/or
> - * modify it under the terms of the GNU General Public License
> - * version 2 as published by the Free Software Foundation.
> - *
> - * This program is distributed in the hope that it will be useful, but
> - * WITHOUT ANY WARRANTY; without even the implied warranty of
> - * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
> - * General Public License for more details.
> - *
>   */
>
>  #include <linux/gfp.h>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 00a53f1355ae..d500923abc8b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>
>  #include <linux/bitops.h>
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index e02a36a51f42..5c8b08a25715 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -4,11 +4,6 @@
>   *
>   * Copyright (c) 2018 Google, Inc.
>   * Author: Andrey Konovalov <andreyknvl@google.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>
>  #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index bee43717d6f0..5f183501b871 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>
>  #include <linux/bitops.h>
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
kasan-dev/CAG_fn%3DX-%3DeqBm6R5qrexxBhYvJAKFn3mFLvK6%2B89Gxz_sivACw%40mail.=
gmail.com.
