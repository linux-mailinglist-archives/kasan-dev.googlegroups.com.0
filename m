Return-Path: <kasan-dev+bncBDW2JDUY5AORBXN32OOQMGQE62FPVGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 66E4565CBB6
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 03:01:03 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id y19-20020a056a00191300b0058217bbc6cesf4518857pfi.4
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jan 2023 18:01:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672797662; cv=pass;
        d=google.com; s=arc-20160816;
        b=A8S3Egre0nX2S16v+gEcaDD7WJjic+fT7z4V6Mh7gfzzfmJPDEJtZ7afVcJidqmo1q
         Cx247m420s42M4LKyELs8lYCZFwBeb2iI3dcaSCpDRhDNC2oREbrw37RO4eJjbXI3WZO
         jqS7/XfcISpDMpUIfRGw0BAl3E+Gprz7fdo2Ywlne3mcMNSbegUKvoV0kxn4rNf7o7Rl
         8jFVnRhkyiBvAdDyb5/u7VeRuK7G1A3ishdcUEsW2FK4z/vvrDCTDrHQBLj0Tmu3wvzC
         99GHfuOpWvauq0j62KVJrgkDR9rtV8TzmNn0MQR5/Y9++hgrFc8Kwwe+/bebm/hZH1Dn
         tl/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=WvCiBcSd+o2SC4838U0OPketBGjSeNFs2G4XdZTKbRA=;
        b=0d7jw/asKYNT+fe4i7Y1jtU4qAXUCIHCUBq1fH/AE0Qy1WZ85kOQ9boFLYk0p7OgX3
         ILM+aIAf+umXPpZwlJW2ZePR/yytJHG6fhzD79zeFNBD3mww+tEnQpoUb5uQZpH56zNM
         IjQ39EtEWUDPA91PXzSDE48++G3LSDMuAKFCYx27OQF/08TuII/qwwHyTgJgDnhm3e0V
         Sl8H4iRIbZ2uLrh0xLjfQgogAJdJLMG9RRViPCch/UIzHgXydZ2plcgadDInsCIGQlef
         vHCwjgCl2BsrmmoU4kL8/sabSARxgdk4mKEgXIzxN2ntU0g/DYwxQuNOubbBMQs4a4sV
         5CDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dIntYs8V;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WvCiBcSd+o2SC4838U0OPketBGjSeNFs2G4XdZTKbRA=;
        b=ttwcpfLYLb6p2YcpzKuUugb+zT7jC7XRsU4hXbWPiDAvQYE39Rl5CfIYSSIOWvFarV
         C6vbAAkWZsaXuFA1x9yaUKP7cL+Hfn1Gw05ZxPBR3rd+sExjbpk1oGEhiz016btVgkFQ
         gHYi9d52/1+Kbdp9Cbtek0V2xWCyLS9IRMs5g8YIktsIAFpp9wkxBDRnE3KM6SzCajY7
         5pcQLoS52tcTP/mPRdlKFEc6d6ZJUoU9YXJkaDspyVXPBr50d0kRZJuOkX1kG+RJeJyd
         yolccap1psnt+CL8v8a0u0DW4Lt3gawzmuat5F5U6xtVdjC3/Q6Pn4EnwOjufQnnrGZk
         Z4nQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=WvCiBcSd+o2SC4838U0OPketBGjSeNFs2G4XdZTKbRA=;
        b=ewtyzudtfJ6PJ0QsCN7q+1pJmYJ4kGQhIeC2Y6/6bdg8AEFrwJCvbr99roeob1Uzxj
         Br34gCrnxY+FoMd0XRBnqpbbEwupuoOQJT2oJxyXMN/CV/jS0MtCWkcBEYXaYSuWfcXB
         mqAUDf4mka2em4hb0IqAWll09ZIHVl5QhoX6LL0iHVLQ4ag+0s1wSFMbpjYkJsVnX/CA
         HRMm6ZNo8z2z2hwueSmzN6PesWM4jdH7YZgH4vIH4ay+JXQV419LxSgVjvgz0RoBkaXC
         QiBU31i9kxKjZyPxQ7U3Bkv+9AgcaE4SNCIRKDvHIJYXRUhhJiRzC3KvgPWapiI1Axtm
         RdFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WvCiBcSd+o2SC4838U0OPketBGjSeNFs2G4XdZTKbRA=;
        b=fusI9/xfa7mEfO9EtjKskPb1XJWk55gHjQ+zsy6A4ltPQzPQlnVel7rwgN/kPCkcuP
         9o+AOYlcP4ZM8YytpFOCRz2sanh2foeN5RD2fndU3QKsiSVamde9fhRG52v4Dh+YU5qW
         41cHfuh+E3Dd4fLsJF3EvUDqK0cpxfmg6/SDlS9UkI3Kfd4oQjHEhcLmNotSbELdOpwW
         GnxnlGbq7DJkOdcXXKEUrrBOS2a+GAWZG2xHmhYwxnP/+St/G3BInyh7ZV8y0GK+qApV
         A+L12gx+P81dCqcj/CcAK0Q6HijRBKiD1g3lmC3Ooct7WsqukOGSnaOyLkTBt4Loe0AB
         AJkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koSkWIxOn0n8j3buMcl167068yWQUYCCdzpfagmaqFPGIB5d33g
	JeA6edJ3nCSc/9niqq71ZqM=
X-Google-Smtp-Source: AMrXdXs4fDXoi9D5t7TmCgoDIaw+FinkgZT/xbD5RinP7tyqNk5R9jwRa4fe0I+sABkkfX5BoiTBLQ==
X-Received: by 2002:a63:4f1c:0:b0:480:ffcf:b358 with SMTP id d28-20020a634f1c000000b00480ffcfb358mr2870096pgb.281.1672797661820;
        Tue, 03 Jan 2023 18:01:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:db11:b0:186:af8a:6095 with SMTP id
 m17-20020a170902db1100b00186af8a6095ls33144186plx.4.-pod-prod-gmail; Tue, 03
 Jan 2023 18:01:01 -0800 (PST)
X-Received: by 2002:a17:902:b493:b0:189:cb73:75f0 with SMTP id y19-20020a170902b49300b00189cb7375f0mr43387509plr.8.1672797661090;
        Tue, 03 Jan 2023 18:01:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672797661; cv=none;
        d=google.com; s=arc-20160816;
        b=pCKETf344OgdYqpb+ZEvBlvVm/xYulBQO/I1JmegVIFZ0ssfBgPMazuZfjqx1TuO1l
         8oMOuH7GNe1vtXO6I63hJGYZ9PFU+/iNyus7dZ45PV0cabhv0OSoFifbHucQfQs3qGOu
         Uhv8MaEYeDGU0gX3OEPdR7OMTM77c/7WS/L3IjDC7X33Ue3LH8EY+/B5h+3mPDazd34m
         DldBPjeo7i0MvvPmeRf2mzwWTwF1x7SXf/Jbe75XYlayoWKRCA1M231q5ylvyn/tGy1i
         jLFRaDiGE4Ag93QoSuTZlUXeR2YcGd0+AoS2/l7y0CzPCcnH3NWHhXYBGm1+H+sYiXGY
         Cqsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hHeFWn8psj8u8cGp1SABE4QnAQdoZWb4E9tsvr9oCvk=;
        b=Kn6N5VGGlzGqeB9ikwW8nj2ZelXf5ZYo0+3uGKWXnk7Od33541Sf5Qio6KVSdH6xi3
         2mjbTKEmZtzicECHE6S0Z3nACm508IhYHwmz6Sh0xyVwkGrxxer358qX8KviczAp26s3
         Pmoxj+3oSouNSuu3A6S1pwVQgtNKLO9cFM01LNbtFUxiDMallGoLfhJLOtVI0gnY4ReH
         JbTS0FsNnGD4lnL8ecKB5UOy48eOEAPQfkAE0yNEvMktNnR6tUSy1oREfriUuOG6H3jI
         eCzc4B2ye8zofXdgqfVUP8I5+uT5m2kAwbD2VHIEKs/LT9yL8Af3/K/svMjQDB/B7bY1
         gv8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dIntYs8V;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id n20-20020a170902d0d400b00186c372722csi2583205pln.9.2023.01.03.18.01.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Jan 2023 18:01:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id v13-20020a17090a6b0d00b00219c3be9830so32915496pjj.4
        for <kasan-dev@googlegroups.com>; Tue, 03 Jan 2023 18:01:01 -0800 (PST)
X-Received: by 2002:a17:903:3287:b0:189:8d8b:9db7 with SMTP id
 jh7-20020a170903328700b001898d8b9db7mr3112912plb.150.1672797660693; Tue, 03
 Jan 2023 18:01:00 -0800 (PST)
MIME-Version: 1.0
References: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 4 Jan 2023 03:00:49 +0100
Message-ID: <CA+fCnZdk0HoWx6XCbTsiNhyR2Z_7zv5JUdgNs8Q_tV4GRkkmCg@mail.gmail.com>
Subject: Re: [PATCH] kasan: infer the requested size by scanning shadow memory
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	chinwen.chang@mediatek.com, qun-wei.lin@mediatek.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dIntYs8V;       spf=pass
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

On Tue, Jan 3, 2023 at 8:56 AM Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> We scan the shadow memory to infer the requested size instead of
> printing cache->object_size directly.
>
> This patch will fix the confusing generic kasan report like below. [1]
> Report shows "cache kmalloc-192 of size 192", but user
> actually kmalloc(184).
>
> ==================================================================
> BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160 lib/find_bit.c:109
> Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
> ...
> The buggy address belongs to the object at ffff888017576600
>  which belongs to the cache kmalloc-192 of size 192
> The buggy address is located 184 bytes inside of
>  192-byte region [ffff888017576600, ffff8880175766c0)
> ...
> Memory state around the buggy address:
>  ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
>  ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
>                                         ^
>  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> ==================================================================
>
> After this patch, report will show "cache kmalloc-192 of size 184".

I think this introduces more confusion. kmalloc-192 cache doesn't have
the size of 184.

Let's leave the first two lines as is, and instead change the second
two lines to:

The buggy address is located 0 bytes to the right of
 requested 184-byte region [ffff888017576600, ffff8880175766c0)

This specifically points out an out-of-bounds access.

Note the added "requested". Alternatively, we could say "allocated".

> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -340,8 +340,13 @@ static inline void kasan_print_address_stack_frame(const void *addr) { }
>
>  #ifdef CONFIG_KASAN_GENERIC
>  void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object);
> +int kasan_get_alloc_size(void *object_addr, struct kmem_cache *cache);
>  #else
>  static inline void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object) { }
> +static inline int kasan_get_alloc_size(void *object_addr, struct kmem_cache *cache)
> +{
> +       return cache->object_size;

Please implement similar shadow/tag walking for the tag-based modes.
Even though we can only deduce the requested size with the granularity
of 16 bytes, it still makes sense.

It makes sense to also use the word "allocated" instead of "requested"
for these modes, as the size is not deduced precisely.

> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -236,12 +236,13 @@ static void describe_object_addr(const void *addr, struct kmem_cache *cache,
>  {
>         unsigned long access_addr = (unsigned long)addr;
>         unsigned long object_addr = (unsigned long)object;
> +       int real_size = kasan_get_alloc_size((void *)object_addr, cache);

Please add another field to the mode-specific section of the
kasan_report_info structure, fill it in complete_report_info, and use
it here. See kasan_find_first_bad_addr as a reference.

Thanks for working on this!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdk0HoWx6XCbTsiNhyR2Z_7zv5JUdgNs8Q_tV4GRkkmCg%40mail.gmail.com.
