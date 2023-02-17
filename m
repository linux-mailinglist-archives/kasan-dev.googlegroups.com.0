Return-Path: <kasan-dev+bncBCT6537ZTEKRB6WZXSPQMGQEDZLYJXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id F33BE69A61F
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 08:30:03 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id s7-20020a05620a0bc700b006e08208eb31sf2624754qki.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 23:30:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676619002; cv=pass;
        d=google.com; s=arc-20160816;
        b=CUj0gIRFkq8E9H8jcJJsJ15S916HwxUP6YOuPIDWJOY+J6VjSz93Np1xQwE0NepjHv
         H4QsDkm55EROifCKmYX+Pj9dYHvheXFjMVoY3EmltowJiWjwm3SaTsNPIn1LJXxf4Zld
         Big1Imym9CVxSc1R98cRcwq/ksM+DpF7jY9/AaJyQ2PtpZhBz+7Xa4od77aQywC8t9SF
         bicXxUtBZEeKcLtoK5U6b5fcViPWhHSqKCamupeHpZ4F/XMB8ZC6nUz4sZR/Pb7I4dgZ
         87WBGu0l/O+XNxdcKro/6KR70RGVyKUysN4Ge3JHumGmDW5twrtnAVTnnyKBdQz7tbuh
         K20g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Atm6WicjM0rlMNFJoY50t82QW8Gr8mdOxp0sz9ohFEI=;
        b=U6l3M4heEW6iZI+oxcN9nsQCUkgMD8KSq5Oo/0HhbgQrh6aFMceGV6zCGjJeIyKJQP
         YnapMImIrl5NLaqkyNahWkAr7UuGqmBQMtYcx+SOXL3i2tnibJws7RsOnGYQhOPImCQx
         hNtDRLbNVoIQz/AQkS5K9X8XJjKVP7orL9mNci8zsMAGDOrM0FQSUSFzUIbTdmVQL2IX
         T/1YEDsdqy4AwWwyHhM5FGDfjLjnU66hifizy+SkfIzXMA3zLi0/+7B/5D3gF2hfGwTU
         lKMTXGvcbmo6rmVQgU75BXExArOLOOOdbbxYWABQ/4y8mgKUJZZp7nMKQjuOW3VvBP+c
         w3tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=TSXVN4RA;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676619002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Atm6WicjM0rlMNFJoY50t82QW8Gr8mdOxp0sz9ohFEI=;
        b=MxgSnvT0qxM1kBE7Z4xf7z2fx6EW1p7Ve5G9r86Mq/mIZ45ss/EoxOIAb5wRsQDivs
         D6huiK+uUh4hhH74yQ/QHC+IGeLuzBJjGsOALrBMREEHhr/QthnpL2dvhXB2L8F0sOiV
         OqLgQ7qAu6pji5ImNQup/SIwv96XhVeSSLjh06+i8BZFxuXI7vwxKFHpVGBJp1+4benW
         tjeI2UhcdiCAhNdzd1POKF5Lga3wv80SZy7IfBzfN2zpC34x/PvQ6mTY+n1d6deKqUjE
         C0vNsjfGUIR+hEfHggma74MdR3+3D9uqIvdTpfa2OAWP01NyiXU2moMmrcBNvUyFaM4z
         teNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676619002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Atm6WicjM0rlMNFJoY50t82QW8Gr8mdOxp0sz9ohFEI=;
        b=sfZVAVLDENw5OsMLkJOhkz9cPZof47fRuWvzI+LGbnK0/6xup9KIOXE+1EFUeZ7UKe
         IpkR6wJHnhgwezUK5ipCp4jEV4SYKB/PcmzsXWyo/Knh6pBOxy20boiFnBEizNIOo+zq
         TzpFvL/35TYE9RqmnVq2VW6gjYukrEUqyK3OJfusp9TX3HEG+3d+6OJidUT/ByDKkEw2
         FznaTq13bpKm3MwtAUh9I6uNuw49Zrq8lc4ielCev3GpQM0URAN0YbnFwizCCVC0Gisf
         ywtRL0/VUf4i4MQCyFlsrAdt9lPfYVi6UltWko1aQ6+CPa6EcyZjtJFzLdU1xcPmxLVT
         qDHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVTPx4v2GJDzJpvdyBFPSqJg38AKJiEK87BuclZ10G1nMD98th7
	OjxKkJnKc2Uk2iQ8ehuhH7o=
X-Google-Smtp-Source: AK7set9XULWvvueGmTLwhiGee7OXUsw0GOn8iW+9/kFEar3lwgSFl5HpgFkZYRJRuCXbif2ge8ytDg==
X-Received: by 2002:a0c:cd07:0:b0:53c:a723:f1b8 with SMTP id b7-20020a0ccd07000000b0053ca723f1b8mr949163qvm.20.1676619002702;
        Thu, 16 Feb 2023 23:30:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7196:0:b0:3bd:1b92:edd1 with SMTP id w22-20020ac87196000000b003bd1b92edd1ls781469qto.9.-pod-prod-gmail;
 Thu, 16 Feb 2023 23:30:02 -0800 (PST)
X-Received: by 2002:a05:622a:295:b0:3a8:11ab:c537 with SMTP id z21-20020a05622a029500b003a811abc537mr713825qtw.63.1676619002041;
        Thu, 16 Feb 2023 23:30:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676619002; cv=none;
        d=google.com; s=arc-20160816;
        b=BttriuOQrSNHziCsdtBrK1mm+Y1qPjHaTiTMsdj2MDHeTTQAxPho7X/IkyaZReqfQM
         Wrbel+Z/Fd+bXc/HVSzxNwNEBSnAEBDzUIK8zPriOpyiiiXRvLc3oeSANUktdohRWSE6
         q8IPD7EPXIH5YeaNUdPhL487gwYUed3w2alEjC88vKA9L4HvIboXzRGbYcUx7TWqJtPE
         1SIEbfrczwWgkmOexhA8A9cbKztYnMlyu6GFDjJy3RvQRH94DJMFV0Zq0orUDzT/jIW6
         U75IW83O5VCWdeYU3RbADIeQ7XLWmtTx3FAwMAj721NY4hm8gPeYtGcDOmxGW8Vnnqsj
         EgsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AaFc9U9vYkJWTuUxQlSrpWrlwRWSsnO1tJS6q4VH5W4=;
        b=j/B5BbIf5Mtz6xegqPIGd6X2CzOtyObl5cCuEsHpcOP5jBP+K6/OEPKziUTnKJCzZZ
         Sl9aMembbAfZzwVJiLfS8ej7qIvgPXh21Srl7hdrkxGtP/Chlhqwv+RNd5+UqM6Nh5e7
         KA4S7wNYoo0hI54uhLQXG/QuuaFs3qndUIgoRnuKcc4/QtJGlDlo925MdoYvh2daiyCX
         ejj3DNbWg97QFKRu+UzkKsNKRuF7sz0Z3/dBKl+imcR7jwq39c8XsYgdPJu7Iie3roDc
         /oqdmkcVNd5ihP6h103xqPcJ1AWXLBpOAbss6uQ+rRKBymaAx4ZEpZ6PsV4mkVsFrLEz
         fnMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=TSXVN4RA;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ua1-x934.google.com (mail-ua1-x934.google.com. [2607:f8b0:4864:20::934])
        by gmr-mx.google.com with ESMTPS id fv16-20020a05622a4a1000b003b82ce6a004si263255qtb.4.2023.02.16.23.30.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 23:30:01 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::934 as permitted sender) client-ip=2607:f8b0:4864:20::934;
Received: by mail-ua1-x934.google.com with SMTP id x6so9uai.11
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 23:30:01 -0800 (PST)
X-Received: by 2002:a9f:305e:0:b0:68b:a181:563c with SMTP id
 i30-20020a9f305e000000b0068ba181563cmr497812uab.0.1676619001255; Thu, 16 Feb
 2023 23:30:01 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
 <CAG_fn=V3a-kLkjE252V4ncHWDR0YhMby7nd1P6RNQA4aPf+fRw@mail.gmail.com>
 <CAG_fn=VuD+8GL_3-aSa9Y=zLqmroK11bqk48GBuPgTCpZMe-jw@mail.gmail.com> <CANpmjNOciiDNkWDrkQ+BEgAj=rSYGQAuHVS1DTDfvPHSbAndoA@mail.gmail.com>
In-Reply-To: <CANpmjNOciiDNkWDrkQ+BEgAj=rSYGQAuHVS1DTDfvPHSbAndoA@mail.gmail.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Fri, 17 Feb 2023 12:59:50 +0530
Message-ID: <CA+G9fYvLmhfw7dk_rhXBHd7YESGtAndmhdcW2=VGANfk0ho9Uw@mail.gmail.com>
Subject: Re: next: x86_64: kunit test crashed and kernel panic
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Jakub Jelinek <jakub@redhat.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	regressions@lists.linux.dev, Anders Roxell <anders.roxell@linaro.org>, 
	Arnd Bergmann <arnd@arndb.de>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=TSXVN4RA;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Hi Marco,

On Fri, 17 Feb 2023 at 05:22, Marco Elver <elver@google.com> wrote:
>
> On Thu, 16 Feb 2023 at 19:59, Alexander Potapenko <glider@google.com> wrote:
> >
> > >
> > > > <4>[   38.796558]  ? kmalloc_memmove_negative_size+0xeb/0x1f0
> > > > <4>[   38.797376]  ? __pfx_kmalloc_memmove_negative_size+0x10/0x10
> > >
> > > Most certainly kmalloc_memmove_negative_size() is related.
> > > Looks like we fail to intercept the call to memmove() in this test,
> > > passing -2 to the actual __memmove().
> >
> > This was introduced by 69d4c0d321869 ("entry, kasan, x86: Disallow
> > overriding mem*() functions")
>
> Ah, thanks!
>
> > There's Marco's "kasan: Emit different calls for instrumentable
> > memintrinsics", but it doesn't fix the problem for me (looking
> > closer...), and GCC support is still not there, right?
>
> Only Clang 15 supports it at this point. Some future GCC will support it.
>
> > Failing to intercept memcpy/memset/memmove should normally result in
> > false negatives, but kmalloc_memmove_negative_size() makes a strong
> > assumption that KASAN will catch and prevent memmove(dst, src, -2).
>
> Ouch - ok, so we need to skip these tests if we know memintrinsics
> aren't instrumented.
>
> I've sent a series here:
> https://lore.kernel.org/all/20230216234522.3757369-1-elver@google.com/

Thanks for sending this patch series.

I request you to share your Linux tree / branch / sha.
I will rebuild it with clang-16 and run kunit tests and get back to
you soon with results.

- Naresh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvLmhfw7dk_rhXBHd7YESGtAndmhdcW2%3DVGANfk0ho9Uw%40mail.gmail.com.
