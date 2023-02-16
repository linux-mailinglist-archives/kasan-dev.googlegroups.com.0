Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSUDXOPQMGQE57XIZNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D8E969A2AC
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 00:52:44 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id ip9-20020a17090b314900b0023445cc3e08sf1691690pjb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 15:52:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676591562; cv=pass;
        d=google.com; s=arc-20160816;
        b=heMdBDA2Aoc3PP3M0xvErx89mGKhtnOMYIyzSQ8THEUxhZsnBGrcE96cGW37eP+vkz
         2/F7/uCajh45V//qJ9OWWbxj2uXjNGxdGrD5rGCgMUBgvIHFACQV73Ly198COp5ibMPv
         oWG23bVyyefu03cyngYmaN+pOpEeZ2SzxRLzbO+ekOPZxT5h71iPjOuYWpX+PZeOqcTb
         agVsHueFfBgrFUfqy4Hjj5tPbY19E/FA2MfKB0bZqa7/+oVLtEK9d3s45jR7iDOxaN7U
         YdESWVy8vjEyyRCNN1FX30vv2pomCQ0PJWQ6xgRhGmkG/2+5JEoFzPJCviUhLzICpWho
         KaSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A4Q52zobQZxbsQVY9Y6xtTSTP3ecuMH1of6/zPH31Vc=;
        b=qTdy5MDm4r7wjPBGN3an3Fq7/3OOEDZSOgiCmfK0KCZ857hreY1VgcWa5Oskwu+vgx
         czec4A+8PrFVvjcyqIcnF4JCHyHVM63EDo2aClDeQJz9wOUjuxvcjpwWvUjI43CSlaJa
         qTTuGQEj5JZthRcZHtgsLXWa+VvaU+a6tHEPX8wksP9N6xLZrO4ZgPJTSp9jTJTadEeQ
         IxlVwu1d4UO4SXtWF1/Ug7mw99EptJMobL21ficewwhdHI115k6YXn8ia5bFhdltceUc
         o8qOU/4etCks8j3EfYESK3otAIjhzcMuvCCzsaRugQpZRuG9TAhi9TWRjBvePZpa/JW2
         83PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="BWv/RC5R";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A4Q52zobQZxbsQVY9Y6xtTSTP3ecuMH1of6/zPH31Vc=;
        b=hK9P0N1SsyP/W0ZHqmipcxZEqw5R9xVSgWbTOcs9ghZOyG7h6dxp861nARHp20Thbd
         0ArhkM2IsePwi5z91DRN1u0wHDRuuMXhq1aoV6jMhJvBsnvNDsjAM4PckeqhSI8s2zLB
         ROlG72F76209FHahWLhNzE95iU0H0oT6R2EAoz5UQ139C2FgfQFfp+ouSdMyGnQL3ZZM
         t8tNusmx/D8qGOaD+3CC8iZ2kd0LHJPfj94SltP/g2Zbbe3ed2VA/fv0ZV5wQoojF0PP
         9ZULjjeyJTKsxLUEJ0/kmVHieeNWM8hK5Yw9FjwRT+q9x7JmwwkgQwQVBXaGH29Xf3UQ
         GLMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=A4Q52zobQZxbsQVY9Y6xtTSTP3ecuMH1of6/zPH31Vc=;
        b=GEDTcnZ9+w4anCUWfl3oa40Ov6KCVrVj0s+DXH1NuzhMx8Bzqm+a3+Bx7BDRa/0S54
         6VU64jYyBMAFqKNjqRnDJ7mfpEI6Fx9FjRC8ltN0RZyk/jdSwtGZGLkeJ44I0Tdbyfhz
         HSV7f/nRZ1O4mZnSD1kWmirWidfSstoS4YBUKwJ1XS/zdddbMk71JEmhilsK2pA2PNZV
         C8V5D952G15TGL/CVimatXwbetGixMMLXqocH8dsaTaf3440VQJ63emz8zg+Tr5XFY2Y
         9fDxGo7W0SkRBuT0Se3H8dZo49QsiEprPWvGKym41Djv7KaqOSO75UfwqLaxAlOUUOh3
         A02A==
X-Gm-Message-State: AO0yUKXdbr0Rc+rjuumCWVB5WqlG6TbmZA5bOMnT2oFpCZMxFXRkIHz7
	VnEz6sZbpC57HyREFfP2JHw=
X-Google-Smtp-Source: AK7set9IY2rNKsEBKfbr+3mzAw7G+y51LAB/bbXv/ZKyKjS31o3rVKkq0VZe6H/hZfwyaB7kzwO3tA==
X-Received: by 2002:a17:90b:1d4d:b0:234:8ad5:3e48 with SMTP id ok13-20020a17090b1d4d00b002348ad53e48mr951677pjb.119.1676591562572;
        Thu, 16 Feb 2023 15:52:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8641:b0:19a:a6bf:cc9c with SMTP id
 y1-20020a170902864100b0019aa6bfcc9cls3600374plt.4.-pod-prod-gmail; Thu, 16
 Feb 2023 15:52:41 -0800 (PST)
X-Received: by 2002:a17:902:ea09:b0:19a:9a66:9030 with SMTP id s9-20020a170902ea0900b0019a9a669030mr4036815plg.4.1676591561750;
        Thu, 16 Feb 2023 15:52:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676591561; cv=none;
        d=google.com; s=arc-20160816;
        b=IAwtPt982i81/2XHVkvneyNWvKqVKYu7GX9+ZBmtcxOZeDYMomElTjMBkLk8WKt5az
         5tciXz/k8MgBGGyluM3hnqGbKtyfLO8tEGmCxfAojHwiA9emqhzhcGKd9n0nqg6PzUzM
         pcDKfg33YcWgh/rSo1d+2u8OnytBf/qgAYqQakRAq2JFc77QqQllu4H/qiU2q/GwACVv
         M0vb3iOP0jhLUGigHXK/SRL141i2rHnn22HSBn/OeSrRaQAzUYiSNiwXLX9TR7v836UN
         ivGDO78U06vLG9884zF/qGPYUymCOkVKxjNjTSBou0BsldD/eM2ELeHVxpc+ZARqv2ip
         0WSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=r8AHC9C5MjMuHRim+xbd7khMCwzT9fB8DRzXrlAFNl0=;
        b=hxo7fxYWoMO5wnaYZm7DVRP8AVEEW5z0k3R4OsHKBhOgRpTNlKPpXNf56KBHPAlTXr
         ia3y88JOLxPSJm8v//4PU/NYwNCLUGKWZiFQg08pGacSpMWWGdoGLxCz0PmrZiz1LOVE
         iSoHxjKrN4tXkR1gR5eAA3/YpcViyUR+tuArhpjEL8r7s/6gka3yfcOGoNqrE1ixLdtT
         KBP3m2wxSKWYLmbl2WyEjyd6wuTT0u2GAoTq9NcdHX5T9OB5OZ0vhNi8/azGl/gIdJz5
         7ppOkIASlZT1BIxSr7yM4YqJez+OAVl7DKbHRtTmFAnq6V0IIkz4RvoL32JtJM2PVtBj
         EI5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="BWv/RC5R";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2f.google.com (mail-vs1-xe2f.google.com. [2607:f8b0:4864:20::e2f])
        by gmr-mx.google.com with ESMTPS id x20-20020a17090300d400b00178112d1196si166090plc.4.2023.02.16.15.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 15:52:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2f as permitted sender) client-ip=2607:f8b0:4864:20::e2f;
Received: by mail-vs1-xe2f.google.com with SMTP id j40so1781091vsv.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 15:52:41 -0800 (PST)
X-Received: by 2002:a67:70c6:0:b0:412:2e92:21a6 with SMTP id
 l189-20020a6770c6000000b004122e9221a6mr1433170vsc.13.1676591560792; Thu, 16
 Feb 2023 15:52:40 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
 <CAG_fn=V3a-kLkjE252V4ncHWDR0YhMby7nd1P6RNQA4aPf+fRw@mail.gmail.com> <CAG_fn=VuD+8GL_3-aSa9Y=zLqmroK11bqk48GBuPgTCpZMe-jw@mail.gmail.com>
In-Reply-To: <CAG_fn=VuD+8GL_3-aSa9Y=zLqmroK11bqk48GBuPgTCpZMe-jw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Feb 2023 00:52:03 +0100
Message-ID: <CANpmjNOciiDNkWDrkQ+BEgAj=rSYGQAuHVS1DTDfvPHSbAndoA@mail.gmail.com>
Subject: Re: next: x86_64: kunit test crashed and kernel panic
To: Alexander Potapenko <glider@google.com>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, Peter Zijlstra <peterz@infradead.org>, 
	Jakub Jelinek <jakub@redhat.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	regressions@lists.linux.dev, Anders Roxell <anders.roxell@linaro.org>, 
	Arnd Bergmann <arnd@arndb.de>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="BWv/RC5R";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2f as
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

On Thu, 16 Feb 2023 at 19:59, Alexander Potapenko <glider@google.com> wrote:
>
> >
> > > <4>[   38.796558]  ? kmalloc_memmove_negative_size+0xeb/0x1f0
> > > <4>[   38.797376]  ? __pfx_kmalloc_memmove_negative_size+0x10/0x10
> >
> > Most certainly kmalloc_memmove_negative_size() is related.
> > Looks like we fail to intercept the call to memmove() in this test,
> > passing -2 to the actual __memmove().
>
> This was introduced by 69d4c0d321869 ("entry, kasan, x86: Disallow
> overriding mem*() functions")

Ah, thanks!

> There's Marco's "kasan: Emit different calls for instrumentable
> memintrinsics", but it doesn't fix the problem for me (looking
> closer...), and GCC support is still not there, right?

Only Clang 15 supports it at this point. Some future GCC will support it.

> Failing to intercept memcpy/memset/memmove should normally result in
> false negatives, but kmalloc_memmove_negative_size() makes a strong
> assumption that KASAN will catch and prevent memmove(dst, src, -2).

Ouch - ok, so we need to skip these tests if we know memintrinsics
aren't instrumented.

I've sent a series here:
https://lore.kernel.org/all/20230216234522.3757369-1-elver@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOciiDNkWDrkQ%2BBEgAj%3DrSYGQAuHVS1DTDfvPHSbAndoA%40mail.gmail.com.
