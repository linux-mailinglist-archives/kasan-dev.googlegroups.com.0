Return-Path: <kasan-dev+bncBCF5XGNWYQBRBLV4YT7AKGQE4KKUEPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id E0F0E2D4995
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 19:57:51 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id j30sf1660799pgj.17
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 10:57:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607540270; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kpe+PLUlNriYouTAZG73YmVjQ1MgKL7rB9LzvNzQs0evzu6XGHe52A7nntsCDV+Ujl
         o2wG47HYhWmkI/Gtv2pCcHVI45NMleQPUuzVa5KDT4E8Rifh+SOMX/f4d27suWeSy5d6
         fXn7l6ll+S4+LKQbVR/cF64Uj+E8+03ck5D4ahwVtu/+OMZkXdGUewOzSvwrI/MQjT0W
         bMFlSmdR2gcEal4q6n65yKcJR+E/y/ibcrwdwz+CsiF3GD4mFf6KzqnYUrhKZYsJlQem
         2haWszKMgv9s+X+YSaEA7TmCBv/bzqxHs03srM/pCqeaEnAaEds5m8ADKhxC+ZOH+o3F
         69Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DTuZeziAndhVYY46yXgERD5K5itQDARqHKjli90rZtc=;
        b=Rajd/sryTIXhQKvVTzUh3fcuXENZyJ52lHTZYcQuwC3ydXNmfI0HbuZmF4GQltLMxR
         GfBJxoSP3/bI1j5nHWNNtJfDP4n/n2WJdR19eLlQ/taqeLrfN3hYmen6p9w5At07ETS8
         qxqGnSRGm7tr/u+gx8Nm6iJx2zr1dr1bKGCW03r0myV+2ZOYDyrdMog6lvqX4eXhnao2
         X+oGzX84ID16vlSoe5zdl7W+lyJ3MHbwydvCgL4AlnbwvLJSwOkqoymFV9ktLSk/Vq6t
         NsNSbl+8Wehqy9G57vpTtxPOKGyf9LNreRbpC3AEejAQZ0YFyE+NfWgMtmzVrFjjwLGn
         MkiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=cYU5nt87;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DTuZeziAndhVYY46yXgERD5K5itQDARqHKjli90rZtc=;
        b=kgmJq1SPMlT08UDcI15jSFgahDEmzWzOuuOzV8y71tPYHV3pSqGlZ3tDgsIejGw83+
         /HBRtYabHdtXmN7MwAoyUR7yxQmQ633EjDEzynFprmQoumc6L36juAiO5g2nZ8S9TI25
         sRC3k6AA/Vt4Kt4xLUqyUU1sVZV3N4Vc9OSaXsGjDI6a/i7y8h6tmoZ44w+ShJ8W52Om
         ONzfQ9BLBP0gZ0GwrZZfEM9dnCbZI6p1Z5zr72eKjPPd32Kk6wiI/AW9zmxRStq+P9k7
         gCXxCyy4R6pVRLdFm1hqqPnl+kFbFOuWu6DuVqO/WAvOd4+m595kji/7m2gsJlHJg2Q7
         NoAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DTuZeziAndhVYY46yXgERD5K5itQDARqHKjli90rZtc=;
        b=YgSmeKhHnDgXlfivdGcoqYUAVoasxGf75XdrP86iWIXB10YyflJQ/4rcQIU4E5o3T3
         E0Rv5Kjcixo05gQ6io8sP2gaTX+iT5L+YZkw0UE/pF+p9GMiRxldjRwZ1yu14iX0nTQu
         rviBP8pufL/SspCaLd2KmY7A8I0Y2zV5RqmDGNP4RgaWW0/clGXaYqAalWfVIiQ90Ljv
         YzlrVcvjtMQPMwYglcUDUHngayH+Lq8HvffIPmXZHBCp+T4eJI6v+KjjpSvFPUn8mc++
         ESdjbsKWaL2/qPVyrwjlfedWubYLxyg3GAwxOQsVqNrQAKyKsI/DPhgr3sEIVywdtUfu
         tV/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GGSVVgO4xUKt8819fx51d+sEsN8JRhjQpzhzdeRvjSOz9puRI
	Bb/P8DhvxhwNpP43m+n8HtY=
X-Google-Smtp-Source: ABdhPJz1I+STJFD3pqbqYSQEa1B3sK7inZ3NP0PFzcc7fE3CWKSVyGmczxcbnHPh5hNjwkWbwWCgIQ==
X-Received: by 2002:a63:4b05:: with SMTP id y5mr3217348pga.342.1607540270697;
        Wed, 09 Dec 2020 10:57:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5381:: with SMTP id h123ls986853pfb.1.gmail; Wed, 09 Dec
 2020 10:57:50 -0800 (PST)
X-Received: by 2002:a63:6e45:: with SMTP id j66mr3275787pgc.238.1607540270143;
        Wed, 09 Dec 2020 10:57:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607540270; cv=none;
        d=google.com; s=arc-20160816;
        b=LN3/9m+AYzkHVSn10y0rJaQgnYoLIRXVgABn6CJXu0wEfMOsHNPglJMKMBTGGJII/j
         d/zenNg6NAl3A4QeEoIatPv1KOr2SsXkcdxhkVWZRgHOpWRmsnMrcArWXvwmkp2d7e03
         R3HGb/Gd2VJK+cTno2EgeOKCVou2htIfOCiWN5ba6O6eNTj8jNKc9PSubz8Jb8k9toUg
         mXhSpRQR+p2k4AhhBX6NNyveAmIhaASIHV502EXi1Hez2/ATQE1avPMzoEC+fGalXJWY
         xP5f8gLmUkbR9DzdEM5aWFE8MdJM76T/PGEa1JF5sj806ycO5xxcw9DCjc4mx3zkEtcf
         Uzvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HbHFCoB8R2U+BDcqEYlrw7gF+YPMUNiEZ6niPgfo8aU=;
        b=qQj0cRJKB7SE04fTQYEfgcSDIHy+GGN0p143ttNSatUyzUo+DQhXUidSOjRObWjM68
         8Zh16gmKnQmiGnqkcCSq9IWXUdzjGx+675zXDQeICopbFjut14zlehRzGMX84fpi5MPu
         ZFqj8YNbVQmVHC/CmdREvrKxYcPuEiZKW3UUgh0u26Ng+Rknt5XakqalCAVCVZ+FrR/H
         Il/iKxwL2mICFixuh028K6gdl1WJ+JBVaIt1gOno/JbGyBAuksv3OerUBUMVnIC7gV+H
         VSsS7Ln46kkqjXDyGNQM7Sw4tioC+LdfvMhGQ6jFLdQmAfYLul4irV7M2wCW/8Tq5v8A
         yW5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=cYU5nt87;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id d1si195596pjo.1.2020.12.09.10.57.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 10:57:50 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id p6so1433553plo.6
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 10:57:50 -0800 (PST)
X-Received: by 2002:a17:902:bf44:b029:da:d0ee:cef with SMTP id u4-20020a170902bf44b02900dad0ee0cefmr283733pls.12.1607540269922;
        Wed, 09 Dec 2020 10:57:49 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id y21sm3609122pfr.90.2020.12.09.10.57.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Dec 2020 10:57:49 -0800 (PST)
Date: Wed, 9 Dec 2020 10:57:48 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH mm 1/2] kasan: don't use read-only static keys
Message-ID: <202012091057.50DEDCC@keescook>
References: <cover.1607537948.git.andreyknvl@google.com>
 <f2ded589eba1597f7360a972226083de9afd86e2.1607537948.git.andreyknvl@google.com>
 <CANpmjNMf1tOYTFojUQrHoscFxPPEed_vkBufgxVLduQ6dBvCUA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMf1tOYTFojUQrHoscFxPPEed_vkBufgxVLduQ6dBvCUA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=cYU5nt87;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Dec 09, 2020 at 07:49:36PM +0100, Marco Elver wrote:
> On Wed, 9 Dec 2020 at 19:24, Andrey Konovalov <andreyknvl@google.com> wrote:
> > __ro_after_init static keys are incompatible with usage in loadable kernel
> > modules and cause crashes. Don't use those, use normal static keys.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> > ---
> >
> > This fix can be squashed into
> > "kasan: add and integrate kasan boot parameters".
> >
> > ---
> >  mm/kasan/hw_tags.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index c91f2c06ecb5..55bd6f09c70f 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -43,11 +43,11 @@ static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
> >  static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
> >
> >  /* Whether KASAN is enabled at all. */
> > -DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_enabled);
> > +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> 
> Side-node: This appears to be just a bad interface; I think the macro
> DEFINE_STATIC_KEY_FALSE_RO() is error-prone, if it can't be guaranteed
> that this is always safe, since the presence of the macro encourages
> its use and we'll inevitably run into this problem again.
> 
> >  EXPORT_SYMBOL(kasan_flag_enabled);
> 
> DEFINE_STATIC_KEY_FALSE_RO() + EXPORT_SYMBOL() is an immediate bug.
> Given its use has not increased substantially since its introduction,
> it may be safer to consider its removal.

Right -- it seems the export is the problem, not the RO-ness. What is
actually trying to change the flag after __init?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202012091057.50DEDCC%40keescook.
