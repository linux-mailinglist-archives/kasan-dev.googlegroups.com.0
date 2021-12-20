Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJHRQKHAMGQEKAXVQQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id BAD9747B1DB
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 18:08:53 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id y18-20020a9d5192000000b0055c8953444dsf3498403otg.20
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 09:08:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640020132; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kj1E4gRBsekngdTkTlrudOm1d6MjKk1AizQb4jOeEtSKtV8F/zcz494GDdJMHWkQih
         ZzzWMU574aERspALKuYLRUgye7rkcxPRSBDXEW2pvGqv3q1f6QOeSB4jj1KVM3X7jze6
         +KC0+C01MvUrL4rxl+VJY9T9vj3Rjru1apo+luWZvhzDkaZ2LdBdmJMi0A+MI5d+JUMo
         WUI+zFESO8BEulf/5oZwMr1ZW2hQrC1+tLPg9ackhaUo3wDp+qQIxz3f2zULc3i0A7xq
         /OehOnKCYjtRCpHmku7/qyCCFVjNPFMKHRi3tTgi8WXnoF7goJEAePWelrjUXs9PprEO
         BlHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tpm9r2nSjIZsdETu8g8d1MCotgg/9x9u8XI4jJ2JPB8=;
        b=IvAzwoc4eZW/U/uhDlFEit1wNhxwRpoxLzYmwWUDxLf+exJRTkcOGCJipHYKV8XZOF
         mslCNIQgFpGKI0v851uitsF/x0eIiJgXA2bBR6WgFXyvaeHTJymd1WONU4v06sPl/3oG
         OxWAjXO1t3Y2ElMI5ZkKeZP4J8Et8FTFxNwhGJaLaeNs9Fhu9vdQc66MKTveFH/EC0eV
         SZ60lbNKImj9eyXdTP3fXIPknDjecalRgSW69L7OroibhNaaQE7mvbS7BjWoV6FVOrlR
         fGFKgzbSGIKh5J0/tPn5nl1wP0pj5tzROWV7sclJ5wwNddC2bDyKQqLxVZPMdklGytZr
         kCBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qemlMel7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tpm9r2nSjIZsdETu8g8d1MCotgg/9x9u8XI4jJ2JPB8=;
        b=SWu9kUd0p9fEoZheXfFHwbmHOu4+K38vLRifjG28zUmslUvDahlNZOIA4XYRB5WwKD
         2VyTE3Zu1iqvkoFwhSc4KyYP8LnBRFLWHHnnWl6GH5GC1PYqCCqbr0pXnYQ0iA3xMJXe
         +v4R1etqwhQwvII0QGYQuyVtpwRgiQWSwtMXT3JpT2eOywqhxc1xGqcGM3dDSlMQTomz
         S1CXSF2G6V4OZeQgH7/SCOUwtiRXbg59T5w+ZbeQ/QPn4m3PY9AVZyLhFEemqacA8GLD
         dxQR7IcWpt8vm6ksoM6E3yprV1BYZgPYTTT9OJ7thPMtHfbYSey6YHjZeQz8ZWwPcy4K
         PPxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tpm9r2nSjIZsdETu8g8d1MCotgg/9x9u8XI4jJ2JPB8=;
        b=ZceCckYUyLIpDcutWRkv2bRk+DbJYxqHefJM8OnMKW8gjD0NDf+Fp4rd/yRVdjLDDy
         9HOi1nsFWBiv/n953FVwCAORzBXwSIq4wHdfSUZBn15uOokVHDmumFxXM79wfdV+xVhs
         l/H/QuzxgIJ7Wd73124lsbZBreKWrZm+TRAJFMRtkFylOpPDXcUVhfvB6z9qEnDcUpWF
         OofLiw2q5rKEANVi0dbKS4xLBLwhAXoB5qofpBRz0/0oCcvrnF45mQTNkgxpIXT6j+lG
         wt5HKqmG13UIf1UKlb+FchbiHirqQApGzwS3HXuLnlgGginj5NiWwkBOdg1cfQnQWvA6
         h/1g==
X-Gm-Message-State: AOAM532VE7V4eaS0Z3lSsEp5F4zPQEwk5JkyV/+lD8dzbjLCNhPtTIQV
	0LJDE1YngNHFlFZ/+p3Olbo=
X-Google-Smtp-Source: ABdhPJxS4eh++uHnhRrlEXTHebyHtgjb576dOAYawXZzXJxMyW9WXYJLj3r+gm2EVI1VKucb8hUzsg==
X-Received: by 2002:a05:6808:1485:: with SMTP id e5mr13291367oiw.156.1640020132648;
        Mon, 20 Dec 2021 09:08:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1921:: with SMTP id bf33ls4189769oib.6.gmail; Mon,
 20 Dec 2021 09:08:52 -0800 (PST)
X-Received: by 2002:a54:4401:: with SMTP id k1mr19201137oiw.143.1640020132304;
        Mon, 20 Dec 2021 09:08:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640020132; cv=none;
        d=google.com; s=arc-20160816;
        b=ecoO8QAKVAsZ7qzubcGFoXVhLWl+f5Erdr9uF/0d/RG6sRxm9s78ElPYSI7UCmk1LT
         F5lW4YHa7INj2mbgpfoqj4z4h8iIECzz76x3MTxi0FLxhma1oWeB+9LKxHUkc7jv0taz
         zKqPqLXa4RIdUDSlUpry08TD6EVpizgqDkeqM6PEr4+OU6zVmXRCB80nvm0UkrcM/Baw
         OdQdd/UOGIP9kg+gLWed7NE1d04ozoRbnYvyY/p8K+1etQsJ1Sh1An2hQMZ2FIDrtBPB
         wUy/E7BKocbWZ6VrVlHaNRMzq98Q4FwLCWYBlm7tKlp6Jl+E3uZmz/nRx0gBO/Vnhv4B
         mLzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fCui4qeVHQj0pbfWYsegbsAHNIi3Yc2XfX/ERhbLKTM=;
        b=M+1z3Mu2jhNvtg/gA3OkH9kKJKWHTXnwasK11LF/ZpMD86dUKPsUS/F3uAHnbsNQmG
         MyEzCZ2PVd6eFhIe/X9V7SVBIbF4N3OrUxtrvNNlCcNJoslW6FEAs4pWKDDST3LInpzQ
         2AkqmbbC0iTYzR0s38SkXkKsxphVRyyvA7S7MuQ3wCDU/YSgaujRbnAz9u60xxXfUqQb
         25DvVIq80l0pXaa/qoVHebbd0sqQd61gj7G8CtfAS5RO37/rrwuQHmdkj+UORMzGk7Kc
         20Vcl4Hbtt3C6KTPGm4wj+/kNK7+W1O0C84FEsLKbsnhwhQhLaRSIkmPfT/OF/nyoJhZ
         x2zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qemlMel7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc33.google.com (mail-oo1-xc33.google.com. [2607:f8b0:4864:20::c33])
        by gmr-mx.google.com with ESMTPS id u27si1499987ots.2.2021.12.20.09.08.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 09:08:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) client-ip=2607:f8b0:4864:20::c33;
Received: by mail-oo1-xc33.google.com with SMTP id w5-20020a4a2745000000b002c2649b8d5fso3253307oow.10
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 09:08:52 -0800 (PST)
X-Received: by 2002:a4a:cf12:: with SMTP id l18mr10659018oos.25.1640020131872;
 Mon, 20 Dec 2021 09:08:51 -0800 (PST)
MIME-Version: 1.0
References: <aced20a94bf04159a139f0846e41d38a1537debb.1640018297.git.andreyknvl@google.com>
In-Reply-To: <aced20a94bf04159a139f0846e41d38a1537debb.1640018297.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Dec 2021 18:08:40 +0100
Message-ID: <CANpmjNP_ctXe8hZz0K2AHdSGsxr7OEYGXsdT5exk3mifHXzCmg@mail.gmail.com>
Subject: Re: [PATCH] lib/test_meminit: destroy cache in kmem_cache_alloc_bulk()
 test
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qemlMel7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 20 Dec 2021 at 17:39, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Make do_kmem_cache_size_bulk() destroy the cache it creates.
>
> Fixes: 03a9349ac0e0 ("lib/test_meminit: add a kmem_cache_alloc_bulk() test")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/test_meminit.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/lib/test_meminit.c b/lib/test_meminit.c
> index e4f706a404b3..3ca717f11397 100644
> --- a/lib/test_meminit.c
> +++ b/lib/test_meminit.c
> @@ -337,6 +337,7 @@ static int __init do_kmem_cache_size_bulk(int size, int *total_failures)
>                 if (num)
>                         kmem_cache_free_bulk(c, num, objects);
>         }
> +       kmem_cache_destroy(c);
>         *total_failures += fail;
>         return 1;
>  }
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP_ctXe8hZz0K2AHdSGsxr7OEYGXsdT5exk3mifHXzCmg%40mail.gmail.com.
