Return-Path: <kasan-dev+bncBDW2JDUY5AORBR6RQKOQMGQEXXM4XYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E1441651184
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Dec 2022 19:09:12 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id x13-20020a4a9b8d000000b0049eeca57fbcsf4602015ooj.9
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Dec 2022 10:09:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671473351; cv=pass;
        d=google.com; s=arc-20160816;
        b=VegCQnyrT7AYpiGCy61P2677TYrFX+nx1LVSWFBLUwgPLVS6CMK7cwvHBIoQtZTacN
         o1BJ0olD+ij5I7ZcLT32hECN5D9UGD+QfThHSbDoDx2HN11cPi72tyPK5hiTvOkhiU7h
         tdiAhk1ORnKdPiipV0dGoKQ1c9WX7GSVTXHG++NQjw9FPIAj/ytlPtqIHgqAdosL9osj
         KVV6CsTOv10698JLavliipgQSFzqG98Tela5DVdcNEy9mwtL0Y9sJeUi2MOTC9mOnShM
         w3hM7MEVbXPSs9VsbfVbdMdryOG+4qyfbMeShoyP5JNM0Q6B25RyCYw32RhQ/Fpwads0
         w+xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=OsjQGGxz7IHLFTH71feII+mHJI7HAyL99Zfshq9lfas=;
        b=0bLzjQs8S9vhPLAg07lG1k5TSdCPLaU2UjEvl86uJ0Lvh+iwBvamEyiC8n6Q7rVa/N
         1VqoKvgfu5i12BQJzKBHpMqPwW6WaizzXwuW1t+Fuzmn+oCsWoNmfB6fsl+sDRlomfY+
         tUGAkEPmmXWaU3rpBqzbHp0GG/lGpAtCXqbxG0pz9A/GVBA6+FNti91VeSBJ3IsIGZ2P
         r3NePHm6rZtdPmGTV1EbXjYD8ULQUlX8IEm+ob+PPzIODOxIFrNCZotyvc0vRnhOcoD1
         wjpQv9YIkjjwQ01PZqrFlOXYowsnVLuEzWOpvw36zM3vhHsUYPFeiOO9cCr3sBkZhnEM
         71MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pTBv6akZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OsjQGGxz7IHLFTH71feII+mHJI7HAyL99Zfshq9lfas=;
        b=W70rEqaFhGF8tlFSo3TcH2vKtNGej+WSA8/7TQNBuR+XxuFweZF7ysnnSwNxmDZyZJ
         GHttorN6XuQNJWX3PbR/IOT1iWNGDzTOxfVYxiogGYK2Ya+fQi545FywD/Bx9v7zODig
         SrWUi3Z+KKQi8/qByotNyW2YUGbc5PtjTiNsBqeuPyFXryxuAOFJtDyZT+n9LCF5ofUc
         Z/hAmvyfmQoyNQuFk9pQjCBevOLi1TrgoWp7B79XPAnATMATg4mNViaNWYbmF9aKDg8G
         s/hqDtwlSAXe/IrwAmAcOb1PzOKnzVPtQ9RZ0/SKQKm+O8A4RxCoICdXg8/cmoYp/e1T
         NKcA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=OsjQGGxz7IHLFTH71feII+mHJI7HAyL99Zfshq9lfas=;
        b=j0jz+x/REoKO4ubOKTVxMD9857wDWcLVL9muJBfmmhd13NF2bv/RaHs6hn0X4paZKE
         ENY/xhCgQDsxAKcbQ9kwLPKcU+spXXTdABu8jxiOapibgF0Yy3cjQGYo7/1FJzK28rSy
         N9wUo7jUqy6hQjjoXsPRSpHRrn5xiUiQq4AWoIKNKml+BoH8jWK8fhLPoKXPVpa1HFkR
         yL6mSRv0wbiI3mlL2md99mXUFZuPMfRiaoy6PIrd0P48MUU8vZ8/wEHn7aaUpnnGEHIR
         eMQ+qjc27/n0U8XuawQi8cHTJDZlxHBVjid2+OKL8iKEeF7XKKjuzH53i5i06Uc2QsHR
         KfKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OsjQGGxz7IHLFTH71feII+mHJI7HAyL99Zfshq9lfas=;
        b=Xg8nl0YYnhPZ5wm28Zu0uxFnbbPJ0xYHVslyLhHj0eU/VtBQcrKBNZDNqvi1fMz/eq
         9srvAndRRRQFWdGF6Uo3gRbPX76G3muQxlVegv/f8nEvFO8xXu2hhtgY+ILyc2s+L9Px
         8h3XVlVLYeJoVREy39yjC6PFiJ4w1ovkIcehFlOXPmIrb0cGcKyxW4FmLRDZQzF0CBPe
         I0g01I3QG2Ag/SiFFoENvIRqbURik9mOJ1+zhJpUpkgZZwraKUQdoUYIWANpsMn5BFjp
         XqLbPlB4yBYvWOAyQwROksJCFi4tMw45aLt1cU8RxS2m2YQZmJjT4Oh1dlo+9gC1oiKk
         p6Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkKJjoMDPk5D0lQRtxUN1dwkga60Bp41AVw4FLeIoqioOyFGGCX
	9l7S4fu4zoMv1Co0VJsnb7E=
X-Google-Smtp-Source: AA0mqf6LTxSwaLKNE8mSiRcZAEEACudXS3g//wP0mWxNdQXSG+T+ly2rE0xpbih8ayYkZUDYqISrDQ==
X-Received: by 2002:a54:419a:0:b0:359:c652:ff7e with SMTP id 26-20020a54419a000000b00359c652ff7emr1006787oiy.254.1671473351263;
        Mon, 19 Dec 2022 10:09:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8c18:b0:14b:ee4a:23be with SMTP id
 ec24-20020a0568708c1800b0014bee4a23bels2354402oab.3.-pod-prod-gmail; Mon, 19
 Dec 2022 10:09:10 -0800 (PST)
X-Received: by 2002:a05:6870:c101:b0:144:77eb:7bb with SMTP id f1-20020a056870c10100b0014477eb07bbmr21541607oad.51.1671473350876;
        Mon, 19 Dec 2022 10:09:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671473350; cv=none;
        d=google.com; s=arc-20160816;
        b=a2XWVVcOHEZxiPUew5UlCHCk9r/DrMCpMOYwhwCEhjsY4lVbgp5y3FbyV18150DH5n
         /bdi5dTOf6fiMUT3NtZLYxJO+ZAZdhHXap+TZ6OvNjzNdWO3mLkow8FE39GIwwMdBy3C
         VY/Pcz3BakF4bUo3utKWnmqb72EHEXdIMG0g22cnv1tiU0Jz9eBmlPii0s7wIru8dxEc
         dTXo9h616WNgya66ORabHpAxIE5pM+LmTx8WJS9e1qWNy6RsqYTmt7aoJaaqMPoQf+Aj
         8x37x0V6dFq0Vk2VTNprk7skYXdZA0svGN0ApUnO8ArP13R+nnHtkUGBEJ2o8Z0MgQ/w
         xUiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ztWy+TAPu9znv9bYACdxKCT9vj/i9mvgkta/yxexP28=;
        b=h2Bu33RFAjghJcf+aekpA1ezPOejyKtuCtSZIfcN5zovmtWpt2dA79NeHKTCxXlatr
         HTOXxOAd/c7uwAYImUaJ5BXokZJvri8C/JfGOUBn1jcGPZ61grcDTVyj6HZwxyY3nySw
         w3QVpqcYoI0p5oZgjmkFpDJHse1RNPy2z4wwBP0z43y1/wC7CtHp35N+i7SofNcjD16S
         6gUouR5OAWOPGG7U+fDuU7zkSH7gKqHP31InI2HWG9prZy4wsptJbPWVl1j9Z2BBqgXB
         X/G0N3fqt7km5RB47N+pzq/B2lVrwiFxBNRT+XpsApYEwRmBtJroOf5ofTqEkGGg1hAk
         4KEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pTBv6akZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id ep13-20020a056870a98d00b00143cfb377b2si1014564oab.2.2022.12.19.10.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Dec 2022 10:09:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id t2so9832232ply.2
        for <kasan-dev@googlegroups.com>; Mon, 19 Dec 2022 10:09:10 -0800 (PST)
X-Received: by 2002:a17:90a:fb83:b0:219:932c:febe with SMTP id
 cp3-20020a17090afb8300b00219932cfebemr1875071pjb.47.1671473350453; Mon, 19
 Dec 2022 10:09:10 -0800 (PST)
MIME-Version: 1.0
References: <323d51d422d497b3783dacb130af245f67d77671.1671228324.git.andreyknvl@google.com>
 <CANpmjNPKYEohPBnQ59GVKfCYc+dRUo-YtaR0PzPiwtALNghdFA@mail.gmail.com>
In-Reply-To: <CANpmjNPKYEohPBnQ59GVKfCYc+dRUo-YtaR0PzPiwtALNghdFA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 19 Dec 2022 19:08:59 +0100
Message-ID: <CA+fCnZcDEV4hmeyLb6paTvR7Z3gjQOTJn_M9wTMN-cy+9DKUTw@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: allow sampling page_alloc allocations for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Jann Horn <jannh@google.com>, Mark Brand <markbrand@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=pTBv6akZ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::634
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

On Mon, Dec 19, 2022 at 12:31 PM Marco Elver <elver@google.com> wrote:
>
> On a whole:
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> This looks much better, given it'll automatically do the right thing
> without marking costly allocation sites.

Agreed, thank you for the suggestion!

> > +- ``kasan.page_alloc.sample.order=<minimum page order>`` specifies the minimum
> > +  order of allocations that are affected by sampling (default: ``3``).
> > +  Only applies when ``kasan.page_alloc.sample`` is set to a non-default value.
>
> "set to a value greater than 1"? The additional indirection through
> "non-default" seems unnecessary.

Will fix in v4.

> > +  This parameter is intended to allow sampling only large page_alloc
> > +  allocations, which is the biggest source of the performace overhead.
>
> s/performace/performance/

Will fix in v4.

> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -59,6 +59,24 @@ EXPORT_SYMBOL_GPL(kasan_mode);
> >  /* Whether to enable vmalloc tagging. */
> >  DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
> >
> > +#define PAGE_ALLOC_SAMPLE_DEFAULT      1
> > +#define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT        3
>
> Why not just set it to PAGE_ALLOC_COSTLY_ORDER?

I've been thinking about this, but technically PAGE_ALLOC_COSTLY_ORDER
is related to allocations that are costly to service due to
fragmentation/reclaim-related issues. We also don't rely on
PAGE_ALLOC_COSTLY_ORDER only, but also on SKB_FRAG_PAGE_ORDER. (I
guess some clean-up is possible wrt these constants: I suspect both
have the same value for the same reason. But I don't want to attempt
it with this patch. )

We could add a BUILD_BUG_ON that makes sure that all 3 constants are
the same. But then the only thing to do if one of them is changed is
to remove the BUG_ON, which doesn't seem very useful.

I'll leave the current implementation in v4.

Thank you, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcDEV4hmeyLb6paTvR7Z3gjQOTJn_M9wTMN-cy%2B9DKUTw%40mail.gmail.com.
