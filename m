Return-Path: <kasan-dev+bncBCQJP74GSUDRBNWFYSLAMGQEN3YX3MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 55D46575D2D
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 10:18:00 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-10871dc7b21sf2484542fac.17
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 01:18:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657873078; cv=pass;
        d=google.com; s=arc-20160816;
        b=tBHQrYdU6NOi28pz7S6KuEojZymyC1oshNgNw/Z4U4fnNrNS5Qj1BzC2nYM52Qu24y
         DVg7WRxGvZgGpBvF/Aew7pZFpGhMxsIBpOWZ3+89P8y0TCap4rcE++SPQTnV+PZHkoyo
         pkiFC8hkazXR4252UrjzygcgRrt9KyOSLQo5TqWuuW4hQlPlHv0Y2lSF3cfHXzouNjWw
         FC6SvetEt0CgYw9lYw1NUJX0zbkgNKoUQd34WBHCsf5yidlwnUAegCgpjq4z51QFmpVd
         6mOh6+3928xrM1bi5ZjuLNHLkiJHlafpMvMGXHMr26QxrPGmvutrZLLZiBsVLYLVyY9U
         AXJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=iFqU8uFaHXY9mt3ldJQn6RDdArr7rBHZeL1zq/IX0Gc=;
        b=uhorQp7J8DcSsa5xrB9ESI6ZE3VHES81Hjb1hd2KUJ/yK2EdMGmavOwaFahCvW0DVa
         2e7NT2x2mrFl5DgTl6VjfV7wvffVizoNNF9/o27SdQLco2dKpRoy1KXG9JC7RF2MqFjF
         U5UQKW+xMwv18wqP+EyYhnl/u9VTA44pKhJOrWBpaQHTBTGUO7OzwF0iGCvYY9UzUY2E
         QgpkwxALuAh0RgIJ1/gm0s9C2tqfdTSRzEdC0pUYqXAN2bPtEq0xqUgu2zLeyLdu6n9P
         vRAYwDEitsex+weJ5GipQ9nsBBp1ZVcYpNNIz2qF+yafkijLauedhtHTPjn1Or+mYoi1
         cPQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.174 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iFqU8uFaHXY9mt3ldJQn6RDdArr7rBHZeL1zq/IX0Gc=;
        b=a9DAM2sdJCRfd5EHq0NMsVUVuaTFu8oct/loVfuDYNDFbYldunEp9qDzB5c88wkGEN
         PAfllwILiKPNZwRgBi9xi0ikJnGfMB2wy4UdofBzgVv6vtmcRtHQlMZuPeWCgQdiXIQY
         K2L3ICCze9Oin5pBeIP/xnYrzE84ox/4IBK6nJMIshpIudIlc+rSooZoDbwh7onP4v/4
         ZvmtA1892KjWgUGKnIa+f7/s8xmsKQPUT8qZ7EnUKegJ1bx+LwSWANxBJlb6f10plk2J
         DZ8Md/OWDvLw6k4EDAA61x6JDAGI71eJevlAfZFAJ22R/kl/RQDMi0ezxX/45EGkj28K
         cm/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iFqU8uFaHXY9mt3ldJQn6RDdArr7rBHZeL1zq/IX0Gc=;
        b=6pbFYs3M7y9+bZ092PjbEFHZgrjtHPVJpUgoZ/GrIWfqDHIdKojCfZHQaMmq+pXaRm
         k4EJBQhNkLVEmPY7V3P/jbmro/ZA7Zq/Hni7wOs18Or7jvNKFfOHWP8m3C6/E9VwNUbi
         +vF0ZYIW98n+JUQKmNMvvMDzgVl9a1lSSmebjaMv33IWABFjBeUC/KmafXk2YMcsuR0o
         bz5NT7XUl7mpgRsBqEY+hh4POfohuVxR+e5YTbZv2/xrEFodTWcqq2MH0nhyn/WzqoNw
         QQcvk9h/gO5M4IiyylcrHRm9H5536HHSIr9CWp5QubEgVC0mff11iJUbqySomTbwYmMW
         VXkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+HlTjLq/uDjYc74OT3wIdkhDZO73lLWf4b+RBE7IJEsBbfVdpv
	6tojBX5eEw5oa/ULAaPWFzI=
X-Google-Smtp-Source: AGRyM1t4Xc3eWiPXtyUK9GDURTe0QTq2KiBz4MFdo+DLp6b0W45CVUFmZg5fdGKYXpSlIrBfVawhIQ==
X-Received: by 2002:a05:6808:f92:b0:33a:441e:979b with SMTP id o18-20020a0568080f9200b0033a441e979bmr2466094oiw.220.1657873078729;
        Fri, 15 Jul 2022 01:17:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4e0b:0:b0:339:f6c9:f2e7 with SMTP id a11-20020a544e0b000000b00339f6c9f2e7ls209583oiy.3.-pod-prod-gmail;
 Fri, 15 Jul 2022 01:17:58 -0700 (PDT)
X-Received: by 2002:a05:6808:1153:b0:337:a486:f1ca with SMTP id u19-20020a056808115300b00337a486f1camr8936388oiu.264.1657873078233;
        Fri, 15 Jul 2022 01:17:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657873078; cv=none;
        d=google.com; s=arc-20160816;
        b=QoNKoB20ulwJ1XU1tFoak0q6qficuH8QD38pBHLaL2j4GfLbrY61wUNTmsDoNj4myQ
         eh06f0Da7MBk21LSFRIi0aJGihLCHZnkliAbq3Dy0VnlsnGyiPZOWRtqz22xoU6tLC7l
         D5RaMS42ga5cK0BmIZ32tnmH23d3qhpZi5MMCdlKI+q0x1R+xNzzkzXsvq9LRm71iJj3
         1n4gO89jydbuZAgFSkKt+zBAa7JJL63m3KP979cWR09Jdnol0TCdoLgoyEqloQJWSZjY
         COK8ZrFTo45EezU9S3O960KP5s5tlvcbUu39tsSRXE+H5i50/ObndDtymoRD4iJT0eF7
         8hFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=A8U10zfMg2MHnCiIBNObwk422GWQl02SfoTHfiQ0fc8=;
        b=hybVpBP6rX4ndAQtJGSeLtXoQoVd6v7iJA8u/NPykZrfQY+Ig1ZSzLJfdUdc92/Otn
         GD53ZDLcHEbeRUhGX1CEq6ZimC8jGTDAk/RkvoNKpgc+pgzf+34+KyzJl8lemqWfTNXj
         cufya4rGpsytePAyAKNZ6is38QB2Kyy+oc6vx5zWc9/ZlcTvqOOR87LGxWGksd97pB/y
         13fuHXoFtky5lAvyV4GyVsFpaSwq+ec2G0KT+XMuZRF3sg/OFCPd83mrwLfI9Zp57T4c
         DV1xUE4C2mD4jUh4oQ0v77QdJ647xuRazseCW9BOYlxhKaitq3zosX97O+YVJDcN4eF+
         3edg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.174 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-qk1-f174.google.com (mail-qk1-f174.google.com. [209.85.222.174])
        by gmr-mx.google.com with ESMTPS id y206-20020aca32d7000000b0033a2d497eb6si163264oiy.2.2022.07.15.01.17.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jul 2022 01:17:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.174 as permitted sender) client-ip=209.85.222.174;
Received: by mail-qk1-f174.google.com with SMTP id l3so857518qkl.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Jul 2022 01:17:58 -0700 (PDT)
X-Received: by 2002:a05:620a:45a5:b0:6b5:c94a:d16b with SMTP id bp37-20020a05620a45a500b006b5c94ad16bmr3216003qkb.267.1657873077469;
        Fri, 15 Jul 2022 01:17:57 -0700 (PDT)
Received: from mail-yw1-f172.google.com (mail-yw1-f172.google.com. [209.85.128.172])
        by smtp.gmail.com with ESMTPSA id l1-20020a05620a28c100b006a6ab8f761csm3619737qkp.62.2022.07.15.01.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jul 2022 01:17:56 -0700 (PDT)
Received: by mail-yw1-f172.google.com with SMTP id 00721157ae682-2ef5380669cso40145067b3.9
        for <kasan-dev@googlegroups.com>; Fri, 15 Jul 2022 01:17:56 -0700 (PDT)
X-Received: by 2002:a81:af27:0:b0:31c:833f:eda5 with SMTP id
 n39-20020a81af27000000b0031c833feda5mr14511861ywh.358.1657873075845; Fri, 15
 Jul 2022 01:17:55 -0700 (PDT)
MIME-Version: 1.0
References: <20220628113714.7792-1-yee.lee@mediatek.com> <20220628113714.7792-2-yee.lee@mediatek.com>
In-Reply-To: <20220628113714.7792-2-yee.lee@mediatek.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Fri, 15 Jul 2022 10:17:43 +0200
X-Gmail-Original-Message-ID: <CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
Message-ID: <CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
To: yee.lee@mediatek.com
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"open list:KFENCE" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.174
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Yee,

On Tue, Jun 28, 2022 at 1:42 PM <yee.lee@mediatek.com> wrote:
> From: Yee Lee <yee.lee@mediatek.com>
>
> This patch solves two issues.
>
> (1) The pool allocated by memblock needs to unregister from
> kmemleak scanning. Apply kmemleak_ignore_phys to replace the
> original kmemleak_free as its address now is stored in the phys tree.
>
> (2) The pool late allocated by page-alloc doesn't need to unregister.
> Move out the freeing operation from its call path.
>
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>

Thank you, this fixes the storm of

    BUG: KFENCE: invalid read in scan_block+0x78/0x130
    BUG: KFENCE: use-after-free read in scan_block+0x78/0x130
    BUG: KFENCE: out-of-bounds read in scan_block+0x78/0x130

messages I was seeing on arm64.

Tested-by: Geert Uytterhoeven <geert+renesas@glider.be>

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdX%3DMTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A%40mail.gmail.com.
