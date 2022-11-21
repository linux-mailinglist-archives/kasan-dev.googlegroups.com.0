Return-Path: <kasan-dev+bncBCT4XGV33UIBBXV256NQMGQELKSRZLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 466C2632DD3
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 21:19:43 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id y20-20020a056402271400b004630f3a32c3sf7458227edd.15
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 12:19:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669061983; cv=pass;
        d=google.com; s=arc-20160816;
        b=xbjmGxjRStmGKJN6p+tdNhancMEyXq69duIlSY2fIlsHARjS9kKN3mD2TqxiHN3Yy7
         yMLVgZSNp8bKxwwTEJ1HxCXGaX8zI0zrXO2Pd/lghelUs8JMGcTWVUw8TiyRI+tk0tV2
         FfeasoxtsQiQn0VUEP+0bQERKVh862hA9Uk6FAcFLZYMx1RXfM4fizE1e62Nx6v6vsQo
         y1xJ/iQxvP+oUAw97YrtCQBfW9zPBP0t4KWwyK/pjHy/AY0zqM5rcecv67Z6tao3iQEy
         FY9k7FQ9L+jsC2ipqyUDukwYw4mVb1oAItWFvg2zs3vhm/jVFzOiRejaRmtePWEnAH4n
         Xqhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=22sl+lB5VjKPAx2xLjFM52ag67xn5eNgkDQmXGRPAJ8=;
        b=bnpkiaq1haMSHaTASJI8ev+c+Cv7xtN+x7G1z/xYKO8soRsmomqqYiesoVDVQUFG7/
         +587zJH9yxoi43WIZ6KG7ClfsKWfMt9UWD/TezK11L1WaEcI3LEp/1OZ8waOzPKRtp85
         JApPvnuUJ+xVYDva1O6Lh07TuOboCSDzv17tv9ThiGDOEhzIOMPGPTS7fRz8w4Em/df4
         eTsSZdrneeT+3woKqsZrKrLZmLdNVhA46IoV1F4K10eww3XI3Jl6jlem0IisHdzezo7P
         FfsjeZacTMlGYHuU213D1sbwrFQrFwrngvgoc1bmKJQsqnXaZohp6apG4FW1ciUvP7IM
         8gxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=1CV3abAG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=22sl+lB5VjKPAx2xLjFM52ag67xn5eNgkDQmXGRPAJ8=;
        b=XGcosohb5fUYxm7ykjzLZFTvWS7HqGdLvVZFGNVfhfsrRjdoKVldeT96fhmey1Y4gc
         Ao6/IsjSfipax9H+z4qDzX+4qCaUpX9oXGOgG9Az1AnH+h+zpYKvYGnAZiJVY1WkD/RZ
         LwIWIfMngMO9ro1D0kszM3mIGuh5DaIlTnqhOA+2zzKxeSYp16h/0amd31Xs6FssZ8IP
         uZoG2t9Jlf58WbwhfVYE3s+Cq9Sl9tQALomIppz/yjEjskrgFTtJsuctZpqizxhoBSD4
         tfYCOed+X+GaWPQCKAIpxSFZ2GzLEDwHDvFguxB1/AxGDgqMR0yYXbyPZw9btd3S2Rmp
         R78w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=22sl+lB5VjKPAx2xLjFM52ag67xn5eNgkDQmXGRPAJ8=;
        b=h9mvWxm5r447cmDTwrjCGw1xdPyG3xLf198pRukkJ6WjjDFGjzen4RoDwGgCnqjkJn
         6Y4DYsRgp9cT/kp3guRj+/pmoaOcukEEvbk90KgPfbanHC5i/1+MrHiBZ6aZFXiBbX1s
         1KzAgS+g7n4T5tTlziTA6MlbYfOXUSbqOjRjBYQ/PvMujDokrSpqnF+yjrDAYSg8F60b
         8Lg+TjRPQUmkGFQPzx3fSHM2g1HgresY5wxoP+fq1eE2LsrlI4QRIwypM11fQxcJKZuV
         njk7VsKUYateqjZtkgWSUbMu2sUEz8Ln3X0tfTcYhyXfyTBOIWR4/5NtYpn4yLQniJdx
         jm1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkiFQS5N5NaLtufacEmAxceO4Uplph85qjQ7WMDHpPcfqQdo5WS
	e2yDk21zCJ6zArTKTLLCSno=
X-Google-Smtp-Source: AA0mqf5PYGWOE/Wj8dc2Iuy8OCtMI/Bj48HhK/qvCPg69Z6DB0Q+jRvlaNZTvCScVbd/P6KLUyMrxQ==
X-Received: by 2002:a05:6402:3892:b0:454:cbef:c161 with SMTP id fd18-20020a056402389200b00454cbefc161mr18549816edb.365.1669061982815;
        Mon, 21 Nov 2022 12:19:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:71d7:b0:780:f131:b4d9 with SMTP id
 i23-20020a17090671d700b00780f131b4d9ls6796279ejk.11.-pod-prod-gmail; Mon, 21
 Nov 2022 12:19:41 -0800 (PST)
X-Received: by 2002:a17:906:b34a:b0:755:6595:cd34 with SMTP id cd10-20020a170906b34a00b007556595cd34mr3763196ejb.70.1669061981482;
        Mon, 21 Nov 2022 12:19:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669061981; cv=none;
        d=google.com; s=arc-20160816;
        b=BlTXJ/wp9SLZs25LRkLQtF5tXzfKPA68sQJVUj1+1/E7AFB/7qxdaz+FKjh2ksWvgU
         SQ6ntLTm5WHxmAfSt1qWLHEHcORcFZXUN+hbex8iO6KSfUzp907w9PMhhnBrEkJpTu8p
         XnUCYNGCnD9mEQs4RS4ko8s/BQwlfTFLKwSgj7z0Z11e4hrUZMiNF7Tvmm2NBwl79bLa
         vE6QJy7RXPOYYUX5Yfc39n7d62694xhObEaRAkePKg1mkB55M/9ppjno9InuXBsviCBS
         G2wis/xFzi/rcFxgMJUxItdTgIpzR6H1k5JR6DZieooNmyjPR+fhrB2Sb/4hSGKVurwt
         PE4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uATQpzDiOPp2o9enV6Z7rYGB9I6Dn7+zkegTL3HlS3o=;
        b=cZCMhdS5E1yMY2rW2wt546/AQD6RrTO7ltQ5FNbdQXsfOjF9c+er7WGwSonwFunQc2
         BoeoZ1jR9qGIhVszkQPh/80s0gC4dUJYwfNOtnPj+zFBzaa/lnSRRLtnPZx/rUAfyeoo
         XwXkeQzVXb3zgyjaVy/Q2BW5C4hpgMKoL+8xVFESFB/Qi4v2mwxyDgCw65Yuh8eW0tWK
         EwdrRq7byuHcXmhSattoSwDO/Y9M14NIoSS95uW8lyBiNSXOGZG3Oxr3fmapXX7nT7jV
         sTRtCDIs3+ueXnOxRTVLKNxR5V/hO0i73uAbGJY8+fUA+m50wODIZ/gHvlzdYscVuN5m
         7g+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=1CV3abAG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id ay14-20020a056402202e00b0045bcf2bacbasi422386edb.2.2022.11.21.12.19.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 12:19:41 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 3A02AB81063;
	Mon, 21 Nov 2022 20:19:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 73380C433D6;
	Mon, 21 Nov 2022 20:19:39 +0000 (UTC)
Date: Mon, 21 Nov 2022 12:19:38 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
 <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH -next 1/2] mm/slab: add is_kmalloc_cache() helper macro
Message-Id: <20221121121938.1f202880ffe6bb18160ef785@linux-foundation.org>
In-Reply-To: <20221121135024.1655240-1-feng.tang@intel.com>
References: <20221121135024.1655240-1-feng.tang@intel.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=1CV3abAG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 21 Nov 2022 21:50:23 +0800 Feng Tang <feng.tang@intel.com> wrote:

> +#ifndef CONFIG_SLOB
> +#define is_kmalloc_cache(s) ((s)->flags & SLAB_KMALLOC)
> +#else
> +#define is_kmalloc_cache(s) (false)
> +#endif

Could be implemented as a static inline C function, yes?

If so, that's always best.  For (silly) example, consider the behaviour
of

	x = is_kmalloc_cache(s++);

with and without CONFIG_SLOB.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221121121938.1f202880ffe6bb18160ef785%40linux-foundation.org.
