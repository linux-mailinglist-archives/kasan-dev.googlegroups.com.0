Return-Path: <kasan-dev+bncBCCMH5WKTMGRB262Y2DAMGQE6JE5TPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 83ADA3B0039
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 11:29:17 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id g17-20020a6252110000b029030423e1ef64sf2585107pfb.18
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 02:29:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624354156; cv=pass;
        d=google.com; s=arc-20160816;
        b=ex5eQawUR8PUi1f3vmZeQ1zfguISDVRcBd6LQXO7t4JtOVaBo2JK+m4O6vkQCzA96s
         Pymf0C7qdV+6C9DNTLgRrsLVjGbqUSjWiZv1yL0HKIMw9tyI0UPosTLdll3pOanwWa0d
         o+3Ehoa/Fna54XFkwgYWkDyJBIXCnlZOAtPBDBHztidsb9t6Pz6/Pp5qqfwHeO04b2Gu
         dk4/IYNCw8g6jh/8O34/5xdVhCl+MgvdoJ6aEOWyI/AppJkOIIagKC4M/BerVdqVQTWX
         YtrhpZelnGyEjjHn2o6RqyVkfu6h7ONYGhqbEgNw6qt7xhk5Wx9XVUyYVPfgVIdn2p4H
         i7Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3w7mrYHQz3dj9F4Ib4VBX3xMtQmcj/Lz9gPzb+72Wn0=;
        b=wIEBkyg9egpjBt8jKCfnfXWsyYI/Gxn+ZLQqk8tcDJXuybAgs06r6clNt5xcTrs+N0
         nbdyoYtRr5uOZHVUDwRW2zxT+4gz997ZTwKcdw9re1wW3YtJePXv3CwM8uX/pKJOO04L
         iKWJxnj66H6u5UHl812CiQtNomYeZ5kt9Bsjmc+UvydduY5JZQWiqIW+5wsgGC2UTZ4K
         KBFAnuVUDreLZthDUHpfkjZDOEGsidU339F37l9vVL7Owva2RPNz5E+xw3NzgH47ewqT
         eFfy172tn+HilmXz8JrSMHNjW9D8pkAbowkZBYgS1iOZ1LZVVSsb/LUI4cdD+APgsSZg
         k2AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p4Ae5VQQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3w7mrYHQz3dj9F4Ib4VBX3xMtQmcj/Lz9gPzb+72Wn0=;
        b=nWwRNfu12jMxXkJjz56zgqeabSwR0V5FXzs2ZlwvuHJ880rbbkJlOwU2c8DSXay+8+
         7E3TAGECPiwdN4pf1Vaxo3WGR6GTsslOy6N1JIQ3WVHLrT1+31vQ32CEtzFv/VFiur2x
         BBRAax/cG62V7VwJPmO/auEgcTbsHXjeQxm/7yfXoPFEc6o/2NRmDKDzY/9qEfABWiLm
         8HlP5QFiZqjQTHz6bptowfBj3woLcO1RN5gLyq70JJo0n5Mf8PQ8d22I8apUpV5DI8uY
         fXT0pkcXblAWjLPz6F+0AMIdEaCsRcn+plzJ28MPQAlLwcHClNDqM3sNnD9rbnL29/v/
         iItA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3w7mrYHQz3dj9F4Ib4VBX3xMtQmcj/Lz9gPzb+72Wn0=;
        b=FJfT263AUkgmUVBaNWfmi6pBEqXT27Fpu5fqmGb+PiDjK0IFKl8CorGrkf2PIeYPAt
         +ynrde0A81vOs8cKikPCSKXdAkjZuGDO9KmVVCAFC5i/JtJEoC/5xhjk+GYgjXlXMh1K
         UAEMx+F60Zc5h6WHvnIkchVe4sj+ouJXHYY9J0+GrUxrJjD8ti/IMyXTB3k2vlaHkeyV
         Bzo01FxDPFbw9sS0qrZBbwtjh7m6UKHytq5M+fmckl4PuWsZBEkj+Q2dmOIwbge+fb7O
         LYwa8M3aZ8AacN02TKIDxqJ1ctdrh/VZbLbqxy+gA0sur8DTQ6BJfqhQXRPB0lALBVxb
         MPmg==
X-Gm-Message-State: AOAM532n+dBd0kHAnfrQ4F8DbvqIX9b65zoRojsZkSHRpcJgVr4YcEk1
	K46IxU6jnTeQfduoKNEtE8Q=
X-Google-Smtp-Source: ABdhPJxjxPi+r8o2cmXNv1N+X3iWDMXgtv+HcFwQCIjQuyZ4jHCTYbJadhozFtDktT1SJztl2E0K3A==
X-Received: by 2002:a63:1141:: with SMTP id 1mr2923329pgr.217.1624354155305;
        Tue, 22 Jun 2021 02:29:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:968c:: with SMTP id n12ls535198plp.8.gmail; Tue, 22
 Jun 2021 02:29:14 -0700 (PDT)
X-Received: by 2002:a17:90a:708a:: with SMTP id g10mr3101545pjk.108.1624354154605;
        Tue, 22 Jun 2021 02:29:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624354154; cv=none;
        d=google.com; s=arc-20160816;
        b=Ioe+mtKXMYNHkypOzcdo5WTlb9IoH5+tqdSz6z2Py5TY8eR9Na9nMBlix48+6qTukB
         HmCirebc7FdEe/AKmLfI22tufjgo5FAk7Y2c+joBJm76uXiGGNVHAA1HBjXWCptvcN+U
         2mX7MQIls2Aglop7WEUjpGSwwFu8MwYhtjYRtD1ciLRjxvR5jrQPfWQs4KP/ekoBmcCF
         7fedNfBcW7trpUDHxe9Sz++1RVymavcmSl7F2JKmHVIVMkh7oaDn5BkicjMpDY89c5fA
         6zkwYF+RW+wMJKLU12bPB/xHYLRrLyvUtx+FMXyajXG4xmnUEnAFkRDnBYzIsiXokIkA
         1b3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iu3d+Ew+lBuYvRystq+F87ixcBpjW7lHGCUrqjjn8P4=;
        b=A6bFAavOuos27elXEnylH9hACrdgoTvQX1M1XU/YrEjP5WmG7oumW0tWbLnj8yoQ8r
         ZSin+1zmO0eOLDgRq1YwxWSyHjDr0EkVkMeoJ3JCI40IH7svjDnES88G0MVWv1rp3FBG
         3UQvGMWW7IX3OLdQq6LYxerXeffJjCdjYhHXXiC81TSkCFA+piqE424g/gMqfH/kstLq
         uFf3x7p5bZH54esRtVnOUGORaFLZalMofhIccKW+uCpRfEtvDGqz6Bc7QGgywVff/03D
         UdW9XIgP8RUqslZVEYXu9YvNHS8pYhZ5p94bg6ZesQZHimiAm1BJzyeqUHE5e2NLs1cL
         rHwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p4Ae5VQQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id a15si165217pgw.2.2021.06.22.02.29.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 02:29:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id bm25so22830883qkb.0
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 02:29:14 -0700 (PDT)
X-Received: by 2002:a37:e4d:: with SMTP id 74mr3207110qko.6.1624354154077;
 Tue, 22 Jun 2021 02:29:14 -0700 (PDT)
MIME-Version: 1.0
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com> <20210620114756.31304-2-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210620114756.31304-2-Kuan-Ying.Lee@mediatek.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jun 2021 11:28:37 +0200
Message-ID: <CAG_fn=U8HiKU28goM+yzNrgq_LeygS6m1bz+k_xqGEw8x58sNw@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to CONFIG_KASAN_TAGS_IDENTIFY
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p4Ae5VQQ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as
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

On Sun, Jun 20, 2021 at 1:48 PM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> This patch renames CONFIG_KASAN_SW_TAGS_IDENTIFY to
> CONFIG_KASAN_TAGS_IDENTIFY in order to be compatible
> with hardware tag-based mode.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU8HiKU28goM%2ByzNrgq_LeygS6m1bz%2Bk_xqGEw8x58sNw%40mail.gmail.com.
