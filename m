Return-Path: <kasan-dev+bncBCRKNY4WZECBBIFEQKFQMGQEZAHJNVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 602CF4270ED
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 20:46:58 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id x145-20020aca3197000000b002986e47af95sf785872oix.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Oct 2021 11:46:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633718817; cv=pass;
        d=google.com; s=arc-20160816;
        b=TIujAKm9F97Zk0xMpFAN4otKNPc3QapUOv50Gb9X8QBecdbiGdzH4O1fKj78Z8SKya
         E99slfKMX4KZYttxkCEy2sAtjhFmpaQ5rcwEdZoODuty4u809mW2S6VB746ybCgUZpWV
         d4YVdCFeQd4oC9M4AHVFlXWW/lgY5puuAkCz4qhSWAbEKsMcm/wkzVoa0NN1oNx5Fdec
         aOalt49jYGim6eRJFl6h+713K+BFvoTYN95iQJwbiG+Iae+7VBqWjOD6Ie7dOHreuNJl
         xavDF9TFWyDl07lCQC58oOlPEQYAAZlSV57NaTDgcDPgCzTwkdxHIXOK+BxLOIDLgrhg
         ejDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=bpCdmaPCGaYrzR/U0nMGdvvi32yBPooiZzSb18NN8ls=;
        b=K55kfghANM7ajUTfnluIQRuUB7Smgv0XGCysrbXz8ArMtDsJAzaZ0iLKHgdFyvmbwz
         i297BQ4K3Wh7oaDIrVEmrXpByRkDGe2UtS8yOonT2t/4yo2r/wcH1u8agPGeJuUlTAKQ
         /7k51PFOg6XlzIwvo4bluD+M4WxJ1WqrUtl8YdFSVkBVOFCQ/uroRSNw8hS3NkclILRu
         BGbRuwmFxmhMWgE5oRrKzc8kfzRalmL9MVSKd6PMnXFR+ZFQZiLYCVdZhOInDd3Tmur9
         aa2cn4QstjSv14Tf2JnTed7nb1/CsE2maundSMgzlVqB+gHFdSIs+7YernBAt7pENR2X
         pjkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=VP3FxMvb;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bpCdmaPCGaYrzR/U0nMGdvvi32yBPooiZzSb18NN8ls=;
        b=DAX1AyjekFSETtSBkrHgtV/ipP232zX/CmJYNccg9ht/htKxkRA59wPVszcae/sH+T
         FMtnKKlJHB+fiJpZ8ZOs7asbc6yoAKiDC5OuskuWayduG0U/UIqw/XsimCgvg1/XQbX8
         rGIjYc19Cb2895MuLxE9IQXjl40IcL65y7dS8aWD1fam3fTvEih/e70mdM0j02PAX4C5
         0SZg74XIu0GXpAzJgAqUZbMK+tW1sn5BMcW/P4NZQGX8ItMFOuePgAqBm54n/nBmrnnR
         k8RjzNp3b4xhAOufQnp/CJVcwb+cWJpaeNOL0lqii3BcOavB+xuKvfOcC4qDe2XgnlBP
         N3Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bpCdmaPCGaYrzR/U0nMGdvvi32yBPooiZzSb18NN8ls=;
        b=AIilclpfVQsIbtf6SCKE1ZGf8SFL0VZUL/s5dFVE84h3ruPEwiN7Flteq+SqncrTl7
         lH3JeUKIEvOz9FpIDrFmMK2eWM31/IQQM8iWPULVlQTmAsOorONQhG2pzG3n65xZATbu
         XWENi+tsvjeePecJOaqM2tly9rZ3Pk+V6pDKQA1WPpX/nHy73V+S2XTjGYBjjRqzvwSm
         wS6PCHZoRveUMCXuUb4Ow9Xb/s7Uy2w/3o1CgAp9Kb17JaL6CKy28Hekl5s0rDMxVbP3
         HEp2IMY6LYPcbVexQkJQ6b3hdVobcXCYf/4cWzoz0CrYzeyuVsbQaZPHKm+NRgHijy8k
         eS3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532edQwchX/RmKI/+9h9VIUxqsIGjIRxTCJKlsCjFBCJpNZ7jXTS
	1UtGre8DEtshsCSu1ICj0/M=
X-Google-Smtp-Source: ABdhPJzruyl2qH6FCS5ralXF7l2DhZdoYd6cYMnBT432FTOnGsWMGhs6Fr8ugo3IRkCov2S/8LlesA==
X-Received: by 2002:a9d:86e:: with SMTP id 101mr6987816oty.177.1633718816892;
        Fri, 08 Oct 2021 11:46:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1219:: with SMTP id 25ls1234171ois.4.gmail; Fri, 08 Oct
 2021 11:46:56 -0700 (PDT)
X-Received: by 2002:aca:d1a:: with SMTP id 26mr8813740oin.166.1633718816547;
        Fri, 08 Oct 2021 11:46:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633718816; cv=none;
        d=google.com; s=arc-20160816;
        b=pZJaWpvregaS0Va7dX7TCNCy5iVJQ8jh7w3P6wXosS/wnuPW7J5RcALPl08HZEr69J
         6SxP8zmBU5KLLTk5JEZ5PLpGlfRuz7D5/8XppW1Hm5/AG6rKj80q7qkfxK8UcUTh2AUN
         iV5Lj4+D47y06OYj7ixLt7rGp5dMy2mMKy0nr7gzlW/MDmDdKZUDsWz9L1EkMxm9zkTD
         Wrj2F4gqvTZTZOKCFZolptuBKFmY8GQiXtZYxvywQSP8qkM75vF6iAo5wmMaFhPYB3Sw
         g1ofnRC3a89EsZbVwTfjK4reUz0+cTzOP0J9pn7C+16PfAa9bcuZMCZYLQ4s3CzbTQMW
         +xjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=quuSqZ0dONVuv9mo4TeP3YIzWz+O416I07kQnnw7STA=;
        b=0yDfzf0OPmcg1YX+Gq0XxsToL3P6K6rQfo2Qvbn/thgorXfRDMmRWSfVEC3dV1l36f
         p+a1wLugrGZRaB7bH/HL8HSlMpVQSdbWiLGNPyjvKFsTFOkOMCcT13R/hN9HFvsptHtt
         EkvuVt/cfPzLcrMmyRy3Y7sZ7A9NLQKaMHoHjOeFH3/bSsAL4LUQ2alCufz+bf9meGTR
         5sSNeTqMO4qr1CkCGVa374BQ0H8TkZbo+XaKgOys0r6HgNjwEhOW9gobyMCsREt/mBTP
         pCfKvSL0+yHkCHO5G1n/fIZgSxCMaa7pXXmisssrTb+c5R3AQ3HtP+xN0+QT9DkjwlVe
         Aa0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=VP3FxMvb;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id bj8si28167oib.1.2021.10.08.11.46.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Oct 2021 11:46:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id h3so3937022pgb.7
        for <kasan-dev@googlegroups.com>; Fri, 08 Oct 2021 11:46:56 -0700 (PDT)
X-Received: by 2002:a63:b214:: with SMTP id x20mr6037587pge.460.1633718816009;
        Fri, 08 Oct 2021 11:46:56 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id k17sm73056pff.214.2021.10.08.11.46.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Oct 2021 11:46:55 -0700 (PDT)
Date: Fri, 08 Oct 2021 11:46:55 -0700 (PDT)
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
In-Reply-To: <YUyWYpDl2Dmegz0a@archlinux-ax161>
CC: elver@google.com, akpm@linux-foundation.org, ryabinin.a.a@gmail.com,
  glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, ndesaulniers@google.com,
  Arnd Bergmann <arnd@arndb.de>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
  linux-riscv@lists.infradead.org, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: nathan@kernel.org
Message-ID: <mhng-b5f8a6a0-c3e8-4d25-9daa-346fdc8a2e5e@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=VP3FxMvb;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Thu, 23 Sep 2021 07:59:46 PDT (-0700), nathan@kernel.org wrote:
> On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
>> On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor <nathan@kernel.org> wro=
te:
>> > Currently, the asan-stack parameter is only passed along if
>> > CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET t=
o
>> > be defined in Kconfig so that the value can be checked. In RISC-V's
>> > case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means that
>> > asan-stack does not get disabled with clang even when CONFIG_KASAN_STA=
CK
>> > is disabled, resulting in large stack warnings with allmodconfig:
>> >
>> > drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c:1=
17:12:
>> > error: stack frame size (14400) exceeds limit (2048) in function
>> > 'lb035q02_connect' [-Werror,-Wframe-larger-than]
>> > static int lb035q02_connect(struct omap_dss_device *dssdev)
>> >            ^
>> > 1 error generated.
>> >
>> > Ensure that the value of CONFIG_KASAN_STACK is always passed along to
>> > the compiler so that these warnings do not happen when
>> > CONFIG_KASAN_STACK is disabled.
>> >
>> > Link: https://github.com/ClangBuiltLinux/linux/issues/1453
>> > References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 and =
earlier")
>> > Signed-off-by: Nathan Chancellor <nathan@kernel.org>
>>
>> Reviewed-by: Marco Elver <elver@google.com>
>
> Thanks!
>
>> [ Which tree are you planning to take it through? ]
>
> Gah, I was intending for it to go through -mm, then I cc'd neither
> Andrew nor linux-mm... :/ Andrew, do you want me to resend or can you
> grab it from LKML?

Acked-by: Palmer Dabbelt <palmerdabbelt@google.com>

(assuming you still want it through somewhere else)

>> Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET in
>> comment (copied from arm64). Did RISC-V just forget to copy over the
>> Kconfig option?
>
> I do see it defined in that file as well but you are right that they did
> not copy the Kconfig logic, even though it was present in the tree when
> RISC-V KASAN was implemented. Perhaps they should so that they get
> access to the other flags in the "else" branch?

Ya, looks like we just screwed this up.  I'm seeing some warnings like

    cc1: warning: =E2=80=98-fsanitize=3Dkernel-address=E2=80=99 with stack =
protection is not supported without =E2=80=98-fasan-shadow-offset=3D=E2=80=
=99 for this target

which is how I ended up here, I'm assuming that's what you're talking=20
about here?  LMK if you were planning on sending along a fix or if you=20
want me to go figure it out.

>
>> > ---
>> >  scripts/Makefile.kasan | 3 ++-
>> >  1 file changed, 2 insertions(+), 1 deletion(-)
>> >
>> > diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
>> > index 801c415bac59..b9e94c5e7097 100644
>> > --- a/scripts/Makefile.kasan
>> > +++ b/scripts/Makefile.kasan
>> > @@ -33,10 +33,11 @@ else
>> >         CFLAGS_KASAN :=3D $(CFLAGS_KASAN_SHADOW) \
>> >          $(call cc-param,asan-globals=3D1) \
>> >          $(call cc-param,asan-instrumentation-with-call-threshold=3D$(=
call_threshold)) \
>> > -        $(call cc-param,asan-stack=3D$(stack_enable)) \
>> >          $(call cc-param,asan-instrument-allocas=3D1)
>> >  endif
>> >
>> > +CFLAGS_KASAN +=3D $(call cc-param,asan-stack=3D$(stack_enable))
>> > +
>> >  endif # CONFIG_KASAN_GENERIC
>> >
>> >  ifdef CONFIG_KASAN_SW_TAGS
>> >
>> > base-commit: 4057525736b159bd456732d11270af2cc49ec21f
>> > --
>> > 2.33.0.514.g99c99ed825
>> >
>> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-b5f8a6a0-c3e8-4d25-9daa-346fdc8a2e5e%40palmerdabbelt-glaptop=
.
