Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQOFSWAAMGQEC27TUPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E04C2F9C4F
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 11:28:19 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id n18sf8668097ioo.10
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 02:28:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610965698; cv=pass;
        d=google.com; s=arc-20160816;
        b=vdTjSiQ4XWBm9Ma5WBhKEpJG2wvRn+IOOunmquhyuX1I6Rx9+s0ShbZIRougCcvfdd
         NKJmTHJS8uo/sl4fGxssjzVux0x69ySZLddC0Wh+vma50QMFHsSFz7xJK34NWWe1fiis
         IdpjvEpNNWEld51/v4x8LcO0xldLlYpPBwnETQGZsnT7nJKDW6L/SSDLcdlgrLidtawq
         K3JSKfMzJGs37I71Hl23D3uq70SLrCNsCZV9qQK7ejmnWMPghAZgM4btNHYAO95LI3L1
         jlDl9ZHxzQ2fri/uwqdwjgCNCBNZNu/Px4Sx/MwaxLk4a3Ov/kN7aeePP3fJJ5seCofy
         CN6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/IbeFw2//ImjkzV8uK6QG+JXzj20hsqNSQmKQh4eDSg=;
        b=wQDBXlYW92inGSNVHANZWmdb/fhmBcS41FQC1iF3K5enxeFI0MNIeUhezNMw92Z8Am
         7FcYZmVxJ3/YvZAHLkv0EwYTO6IiYG0uNFUnPIAKH0/RjLkVdnZs7GoZsthhCYgkIfFd
         hJqH0a4hoMZC007TuONhApkbI1A/8NXCqq4TGAFrf7Ot4WcKiBjiWZh9VWMEIWJ7tX+n
         W+Dt0TBck4AMrtBZILGP0fi9vzV+jnNuhdZc4a97vZd+gMDms4ttP+7Kq6P9NKAJCMCC
         MSbooAOSK4623hvJpZj49kNylNlhZozfqZsGwomq7IUAwFgatAF0mCaLVkoZ1/9cYaUN
         bymg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="DROzjAF/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/IbeFw2//ImjkzV8uK6QG+JXzj20hsqNSQmKQh4eDSg=;
        b=d9J6QeUrzxLhXB+SYEr3zu58hDsxwoUDMqxz5pb1Y0FbLTNqJXlwLwXgCnrex8lcNl
         ftLYFr3LMhIy5yF5cZvPB5BN4Fo8r3tRpOsFsmjV9GciMyUpvvaVl4w/13ORzxfytZkR
         VhJzzvMNOcQYbRdu3Won1e8PcU35/bHQz07GSBbhDgx6pFMToz9++9+TDEXOwu1XPGOh
         iX2dCYNJh9LO346WTo2Q4oxCGYmIwTyykCFxJZ8Fvm4wH9lGkr8qAyqN/4RrWTEc0KLX
         TKGuedZJ7YOWgwDsnsVpg5NrHcqm56IoaTCQcs746Yrl5h0JYGQsRU+AAGmmRCjCEXD6
         7Yyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/IbeFw2//ImjkzV8uK6QG+JXzj20hsqNSQmKQh4eDSg=;
        b=r2EpHyjV3FKQM/Rgl0+eEGY7qqHCKGHqL413yDcXBu6ijbZV0i2kT72VJ2HlF8xI5q
         PzTG3YfMBKrofs7Mz4p9vuf9XhZpwPJBYrp7pX7MWyPIR9LIyEK7cUoxBGQGbgFT1z8I
         ObYMII6Tova3ofR4bKgeCrGPQkMR0BSIxILlKzmIpBhZ3BO6n0MnDpaWrxK5UeVOrSHw
         s0g5Hip1uuviYQwhqoi3iWST4yudDFP5TAik+rwBoGtBxpJgFlXK9KXUmvHqiJyd/TcW
         bR1Kp4S4p9tfqX5XY2pZRBo5npVGKD8DhSEuKBoa3zAgkHVAexkbbaFJjPdoj0Bh6CSI
         OxKg==
X-Gm-Message-State: AOAM530P3bl9y1TT7eGlkC6RuhQTrijafhXWYnqKV7IJL9ecbjbOY52q
	sbIDHRbD2g+axulbXsmFb9k=
X-Google-Smtp-Source: ABdhPJxkirHT/daf8OIYNh9PGEmkjphrK6GFmi8ChKDYUHz/Dw9kH/2IlrhMEATPWIahtAROFM7PBA==
X-Received: by 2002:a92:8e0f:: with SMTP id c15mr19688718ild.224.1610965697968;
        Mon, 18 Jan 2021 02:28:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:170a:: with SMTP id u10ls4272272ill.9.gmail; Mon,
 18 Jan 2021 02:28:17 -0800 (PST)
X-Received: by 2002:a92:9f59:: with SMTP id u86mr20661585ili.205.1610965697648;
        Mon, 18 Jan 2021 02:28:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610965697; cv=none;
        d=google.com; s=arc-20160816;
        b=v7awzLZc6JUvTvJlyCjfXCS3RbwLWwlAirFf/iClwCJt9i+vib+0jHrL4oAioGfDAM
         hPBdY0Bn4olzBo0q6VqGzlagwwKORjS+iDeUN0cptaIXfn8RtKm9sB8/0mlX2a9/GVmA
         m1VxUGGjeluJtM/dPGoCwLVXBzCjyYd+jdgY+Ie+jX16o/CToEMElp6lGhmWOYrcerSY
         49z+b1cv8YjnYCffRemhXRFADFOB0FNU4MS51ugz59iH5LXY5UgKWa9t5SM5PCeLJ6tO
         1RPvzCfltYJ7RBZz/HtJpZnvq/VFG/etP3F464weHasBNNzrgoFEcbdWjaEWWZv/m146
         n2QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/TkzcR6kWeiv6t4IoqwMwIdTH7b0PFudFxRU7qciUjA=;
        b=jTwTqILn68noU9J7WvgaeQTvv8p8pgCKSbBb6p0Cw4VOp+QQLfPsUPc1ENbCFR6RyL
         BX6yXAXkXN0FCIqZnGR9hgYjaM3hZZqWD/nzt7LLJ9X4Xg79JGwubrkDqQo1ssOvoj/B
         f/gcAg9BUgwSsrTKTu9lUEQhKuDDMoizkr4XswHigUhot2POZqtwjj+DU3mx80vV9Gw+
         JlUE+s7ruv7IWut3P5hzV5CVn5s2nJrM1g9T53ut+Y1dwyOfQoNLMBZrGp+NW8ZvdgPB
         d/da9HT46pjPLvLB359e13111LK4ObhJMaBuSdJDM/8XC65Deqsie9Gun3Y1D6DwDtlu
         Ijpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="DROzjAF/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id k6si401571ioq.1.2021.01.18.02.28.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 02:28:17 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id o18so1223059qtp.10
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 02:28:17 -0800 (PST)
X-Received: by 2002:ac8:6cf:: with SMTP id j15mr22124864qth.180.1610965696933;
 Mon, 18 Jan 2021 02:28:16 -0800 (PST)
MIME-Version: 1.0
References: <20210118092159.145934-1-elver@google.com>
In-Reply-To: <20210118092159.145934-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Jan 2021 11:28:05 +0100
Message-ID: <CAG_fn=VDdRLmFaKDkrUk=evkQJDboMm50w6R53w2CWhNGz_o6g@mail.gmail.com>
Subject: Re: [PATCH mm 1/4] kfence: add missing copyright and description headers
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="DROzjAF/";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::833 as
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

On Mon, Jan 18, 2021 at 10:22 AM Marco Elver <elver@google.com> wrote:
>
> Add missing copyright and description headers to KFENCE source files.
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
> If appropriate, to be squashed into:
>
>         mm: add Kernel Electric-Fence infrastructure
> ---
>  include/linux/kfence.h | 6 ++++++
>  mm/kfence/core.c       | 5 +++++
>  mm/kfence/kfence.h     | 6 ++++++
>  mm/kfence/report.c     | 5 +++++
>  4 files changed, 22 insertions(+)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index c2c1dd100cba..a70d1ea03532 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -1,4 +1,10 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Kernel Electric-Fence (KFENCE). Public interface for allocator and fa=
ult
> + * handler integration. For more info see Documentation/dev-tools/kfence=
.rst.
> + *
> + * Copyright (C) 2020, Google LLC.
> + */
>
>  #ifndef _LINUX_KFENCE_H
>  #define _LINUX_KFENCE_H
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index a5f8aa410a30..cfe3d32ac5b7 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -1,4 +1,9 @@
>  // SPDX-License-Identifier: GPL-2.0
> +/*
> + * KFENCE guarded object allocator and fault handling.
> + *
> + * Copyright (C) 2020, Google LLC.
> + */
>
>  #define pr_fmt(fmt) "kfence: " fmt
>
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 97282fa77840..1accc840dbbe 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -1,4 +1,10 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Kernel Electric-Fence (KFENCE). For more info please see
> + * Documentation/dev-tools/kfence.rst.
> + *
> + * Copyright (C) 2020, Google LLC.
> + */
>
>  #ifndef MM_KFENCE_KFENCE_H
>  #define MM_KFENCE_KFENCE_H
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 1996295ae71d..901bd7ee83d8 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -1,4 +1,9 @@
>  // SPDX-License-Identifier: GPL-2.0
> +/*
> + * KFENCE reporting.
> + *
> + * Copyright (C) 2020, Google LLC.
> + */
>
>  #include <stdarg.h>
>
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
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
kasan-dev/CAG_fn%3DVDdRLmFaKDkrUk%3DevkQJDboMm50w6R53w2CWhNGz_o6g%40mail.gm=
ail.com.
