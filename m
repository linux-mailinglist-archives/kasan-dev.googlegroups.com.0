Return-Path: <kasan-dev+bncBDW2JDUY5AORBPMEV6QAMGQEP3BM3CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E3A76B5602
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Mar 2023 00:50:23 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-536a4eba107sf70017567b3.19
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 15:50:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678492222; cv=pass;
        d=google.com; s=arc-20160816;
        b=QJ+TI8/N6QMhSgyZ/hBOV8ylUV8gqTFr2bGTiK90lDhL308lCowYx66cvPFMBjazYN
         GwmREtTxWOYwwZqtHklmFAJEY8LIwlo2r0Db0uyy3mKxCZCBmQqzUwcqAa8lnHMhje+5
         3KDhlz+pZi5aSOqlQqjzs7KlQMoANeh1Z9XSw9Zd7UVyp8YxUj4D/novgURS11Iy00eV
         nRGIkEJbkibfzFyPZkz9GPOeEl+nLkxUonHAlIRUAIAeKWkUeKPO4N5AgsVBdt+/ygvi
         tOcY8c0rLRtS/4gXfjewt7Hs8bSf9ke4aM1YqYM+FbULv3lbUTEXz9WBGyk5Sf9m7a67
         yeRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=4XOEv18KnRjXfQT1UfraPswXz+9/xmE+LP+OVodEvak=;
        b=GQCHt3Gq9OlPTgZ17ncBXVAPW4qO45tKQtTz1++Q8hqUn6ZlwBIXvgiKBWSQhlgdfo
         MrQVMmZ5N8d2SUnK6e5fdk5EoI96lMDwrmS/IZliY55BHjDIT9fg8msy4T+jRTHT+xCR
         VWxrvw1dAb75ZwrGZPxZUI0S8xvVJ4liu5HgBSWiTQXe3xYX0yn/LwhF9JTD7+OsXs4L
         0kx3y+ScOp1IOPxR5IL4LXnyWu5vVz2slEWy4v4xPZ9DGiop4sjn4PMF9BuEbEqJi13N
         V2vvxhuS70cU89nwFgoPlE6+A7AZLjQaNmrGBDkhsOY/KjJ/DJBS21+BRbbdmMq/isj7
         vshg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Zb1mq1ps;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678492222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4XOEv18KnRjXfQT1UfraPswXz+9/xmE+LP+OVodEvak=;
        b=BP7mOGXUMesKS6//zvxDMLGURkK9J4FezfMcltrwvefn2juDRsGCKs5UFtgtQm4ck9
         Ffx5HqTvOMOCgwAstwepfm4Bqy2jJoaLHTM7y2JC5HgRV4MqOM6SbQGoOfPCULUo9nT2
         CP+Jqxq0qrdneiogmvobAtgQbJqsoULqVaC2aFDA+26yruuwB36KPYzDTM3prYxMpSaI
         skw+rLRpUDviNNeHdYSS1Fg5gHC3atDR8jZ7FCw2kBWkPh/OAS8S8Pe3WGMzK2IGKNtf
         YWiW9Fz2UoY4mFvqM5annf5vnr3TzjAsaMLdSCNQS8Zyz7dfCc5qWji2NEmhYO+o1/if
         3I4Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1678492222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4XOEv18KnRjXfQT1UfraPswXz+9/xmE+LP+OVodEvak=;
        b=VxDbGnSAGFsiOa4AveEf/Nd68Q0CKBbxWKLw/Mb/8t0bK4PssYMeFht/jn024bnpn5
         t5Al89r/Cbhs6oXLtiWVb+Y2VZ8UUCVTz2LNDEJOtMg0sOGP9GgQRgZD8NcBhjXgVPz4
         oT4Y7PAeAPDAJsCNHSgG6Be3rHymdzdgM4CZXxtGwnNa4weflPanlkTqzYo2cRp83cB6
         kEY0i+Pxv3PlnSgwl+PD3hu0YvkWHzRo5iO1VzEuha6HlZJAd/0LjpE6p6K1BXevWdmX
         o6W8xhlmmivp7VZreayVDLyyPSlzUa22H/s97YfhXA0okpJkUj1oXW9P1DhdKwZ4MaE1
         7Bmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678492222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4XOEv18KnRjXfQT1UfraPswXz+9/xmE+LP+OVodEvak=;
        b=mZvbMSX+wAHDfGmvp2ebx/3p7FoV/Ov8bZ86xFBxdod/P1FUMsvAaYETOBpJiGcu89
         Q5PIr66Eg161UZJBZmjMY4eXaI3ey1bi26cp0UamYnXPkeEinIqdpS2BH16S06baitQz
         94nubTVsbMFP66iTkiOUZDM/v3S0k7wLC5BNgVXJEPOduvGu9kxNr5RPz6QgHdTuEQs/
         RefTkNhOEawydOlrp41fBZc0IOTlRjq7e7i3W60O+EvqMYWmiV6bDmu+hk0H7IETWudC
         tVGTc5hh/KeWsoHyoEcdg2lvY2BLRMEp9eqc9NzbJP364wohmV4f1sUqHFei2gQRQuzu
         RZKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUS+lc6PQNvcYzrF83yqIgE8tq50cW1ahb5P91ImUwiLm3HPdLx
	l81PtgTZyhbPiksSeSeE+nY=
X-Google-Smtp-Source: AK7set+ASh0r/7zSKthOP3YKLKtLCbgi7c76HP72OL3RWUbr+hJTtEz8qgQ0ijlPuZmrtprW9JYWrA==
X-Received: by 2002:a5b:1cb:0:b0:a6b:bc64:a0af with SMTP id f11-20020a5b01cb000000b00a6bbc64a0afmr16697986ybp.4.1678492221893;
        Fri, 10 Mar 2023 15:50:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:ed6:b0:541:61af:e33e with SMTP id
 cs22-20020a05690c0ed600b0054161afe33els336199ywb.9.-pod-prod-gmail; Fri, 10
 Mar 2023 15:50:21 -0800 (PST)
X-Received: by 2002:a81:8545:0:b0:52f:169c:cca9 with SMTP id v66-20020a818545000000b0052f169ccca9mr26045069ywf.49.1678492221223;
        Fri, 10 Mar 2023 15:50:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678492221; cv=none;
        d=google.com; s=arc-20160816;
        b=xHZ2fY9du+64Qra8gNOOfGn8O+YHDr/mCFmNnrsBCFEgC+0m4b/ZAt8vBWMUlK/Mta
         JVNws43L1jLCyzfgBChIqkLPmYfcixNiisADyUo+YL9j0k6XZeoDiPi4x5uSSGnmuRPG
         CoxnS2yXtf21fQsIJSm5dnJXZsnnW6WfCjjqbsexku8+jrhc9h3cAf3ILb5hgiU9R4qW
         Pz9xNHhdVe88n/71luQXqbTY/RDn/I4nSWKp6saQSmdWri//sGt3Zq96CCAFEziZ4/Lm
         4TJEY76WHZzPHE0uBSin6GmRi/Om9wuQR/sqpTEEWygcddGDIVil/5DjXix9FCgaOzQH
         +RQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TWyYImSF4m0qt3ueUgGNFztvxSwHcqnFDOTOnYZc4d8=;
        b=mNd/wQnblyPwJpoo7J8EhKK5kaIeDA/axiHcVZWGK4lwJeede4cleZxZZzaavOiChh
         s91VZNH5ckhYR+7ev221njMMUXPrkS51V68Q+SCxTE/20jWM0+rGYBbV5sJJe2juq/WN
         akEG8dmjcNpU/+6X9PuAJHmQ08x/pcUYMisnatebB6zJAD0uzR+xMqjOmSHCNbABzkCr
         kdDvzjKIJJbJSSQC7C9Q13bCCjZ1A112wzVokN3w6VuGKsB37aLM0bAWkdq7Mtu99smd
         nxvZPmRyiaAVkBbxw3xEem6WRzPgTmHrw4P6Hk/O6ddejtEFacar7Zj00S+D1+2GTuJI
         8daw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Zb1mq1ps;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id bp19-20020a05690c069300b005343a841489si57119ywb.3.2023.03.10.15.50.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Mar 2023 15:50:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id y2so6807180pjg.3
        for <kasan-dev@googlegroups.com>; Fri, 10 Mar 2023 15:50:21 -0800 (PST)
X-Received: by 2002:a17:90a:bb8d:b0:234:b23:eade with SMTP id
 v13-20020a17090abb8d00b002340b23eademr9946913pjr.9.1678492220849; Fri, 10 Mar
 2023 15:50:20 -0800 (PST)
MIME-Version: 1.0
References: <20230306111322.205724-1-glider@google.com>
In-Reply-To: <20230306111322.205724-1-glider@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 11 Mar 2023 00:50:09 +0100
Message-ID: <CA+fCnZfENShgduZuu1xzrmCnNFv+ovHtcavGXKjYumsGA1kX5w@mail.gmail.com>
Subject: Re: [PATCH 1/2] lib/stackdepot: kmsan: mark API outputs as initialized
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Zb1mq1ps;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f
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

On Mon, Mar 6, 2023 at 12:13=E2=80=AFPM Alexander Potapenko <glider@google.=
com> wrote:
>
> KMSAN does not instrument stackdepot and may treat memory allocated by
> it as uninitialized. This is not a problem for KMSAN itself, because its
> functions calling stackdepot API are also not instrumented.
> But other kernel features (e.g. netdev tracker) may access stack depot
> from instrumented code, which will lead to false positives, unless we
> explicitly mark stackdepot outputs as initialized.
>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Marco Elver <elver@google.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  lib/stackdepot.c | 12 ++++++++++++
>  1 file changed, 12 insertions(+)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 036da8e295d19..2f5aa851834eb 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -17,6 +17,7 @@
>  #include <linux/gfp.h>
>  #include <linux/jhash.h>
>  #include <linux/kernel.h>
> +#include <linux/kmsan.h>
>  #include <linux/mm.h>
>  #include <linux/mutex.h>
>  #include <linux/percpu.h>
> @@ -306,6 +307,11 @@ depot_alloc_stack(unsigned long *entries, int size, =
u32 hash, void **prealloc)
>         stack->handle.extra =3D 0;
>         memcpy(stack->entries, entries, flex_array_size(stack, entries, s=
ize));
>         pool_offset +=3D required_size;
> +       /*
> +        * Let KMSAN know the stored stack record is initialized. This sh=
all
> +        * prevent false positive reports if instrumented code accesses i=
t.
> +        */
> +       kmsan_unpoison_memory(stack, required_size);
>
>         return stack;
>  }
> @@ -465,6 +471,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t =
handle,
>         struct stack_record *stack;
>
>         *entries =3D NULL;
> +       /*
> +        * Let KMSAN know *entries is initialized. This shall prevent fal=
se
> +        * positive reports if instrumented code accesses it.
> +        */
> +       kmsan_unpoison_memory(entries, sizeof(*entries));
> +
>         if (!handle)
>                 return 0;
>
> --
> 2.40.0.rc0.216.gc4246ad0f0-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfENShgduZuu1xzrmCnNFv%2BovHtcavGXKjYumsGA1kX5w%40mail.gm=
ail.com.
