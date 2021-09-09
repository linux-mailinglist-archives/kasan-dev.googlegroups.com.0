Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7HG46EQMGQEQUG2CMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B8754049FF
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 13:43:58 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id o8-20020a0568080bc800b0026bf78d5d98sf842152oik.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 04:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631187837; cv=pass;
        d=google.com; s=arc-20160816;
        b=TzB51qRC9Qq6ucE19s0mjIzl9NkPjb+BT9b42CQ+9b+QIFs0FriFpFAM8CXIVYGpxn
         Z+VaL4BXklJDc5f4sv3zVQ7HGTnHt74eMYcEyCeOHKPqTNq9304fGMXU01bMAXoGh4vY
         fwp+Co3lMIl8m5wT1nprh9U/F3JKm2d9cbELGe/IHehXdckv+0Dac3lDRB32ELduktKE
         jnWBw1Fmc13U196i2ksZ4wzMoEr8juMTqgpj97HJGRFbTTRBkGtetfIB6YvYw/5nwmDp
         rPJaKznENMhR4oP/2vSVjA2yJNpTx6ohOPPUYd6ikIIqylKVTFjxJW1zFiztCdG628xS
         P3rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oNVHYKNsyt1GyoVRl1PlZzmZoYVqURtyXjfvXVq/J38=;
        b=dzs+C3mzN2imkRdvjcYrW7OLQNHgP9tkA+HRj4eXmFIJ6MUlTHeOZhptEiv7vZCDU8
         j03EzUNtscI+fsq0An2F7iQz1I41O5AgKY6XmARlCt4ZIayDqOejGSAdVYVgZo9WiwQg
         ilmZznk0ccJ+d9RJRkdIDDEWddPp4Sz7gpoLpN9Q/NhwPLL2BFw0g6S4Gx8h+I5nchdm
         vJBfH/zp+RibjVQBXbBpf5gOzK+157uVIx3LF8WjMdxNq+pzy/nJA2KeVIlVpuTNP5am
         R6qPyc+Bc0OcWazcfZQ7kHdBrNjTnCRuW47bnngXJVc6f21p+zlKMT41GSDs3Zh1hhSw
         N+rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AM0acIeR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oNVHYKNsyt1GyoVRl1PlZzmZoYVqURtyXjfvXVq/J38=;
        b=J4Ga/ZckBzKSkZXqqtvoojYSdR7XUON2qjY8+8v9kG1utdX6hcOlEV3an5Tn9bYaJo
         g9BYk+X1PQ63zJqo4AQRc70CG6rm4NGWGXyOyO3qIVw0nYR8wsO/z8TeNIn+SIXzzBFd
         +fkum1k8vDezYSQ3m+mqF1gNQKEArYWi4srZradIMvDMkaV5j8/pYm+TUVqRm+7fCa+v
         fx3E1bqn5QeUULvQEGt3+r+1QnAHrQI/FiYfDZlFfUnVDrCYD9eBlV84jab41W/1rdNX
         facEjCtboaD+fsKugWoEev7TI+GXASG3j528GmVVgpSsBPYMBRYb5p2O1xuzRzkAe0hZ
         6+DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oNVHYKNsyt1GyoVRl1PlZzmZoYVqURtyXjfvXVq/J38=;
        b=DBz5h9gz+XqAUcYV7wLbxlMd6hupKjdlUql/EL50/K9vrsPolyxcbWPrkVuzFJNay5
         RPhtKk+KdOLvsld1HJdcAE3VowLE1mTcSsZ7v2LlJREyH/VGlfr19QHvkCB3rj861XYg
         sbjW+FH/infXxGomQqYlBvE9C3E6ptDCuPazFabuaRua7sG6cvMo9aiw8MfpW1FdMwt5
         4jjjTtj/mxOUM4VDJWKMpAfLmrsBk9mTzuyLB7AHSczUgVY3XuDJ3IWRdXjUyY2hg7w8
         Y8GRMHqi+TN7WoKXRUJQt/vlMIEkjJlSP9mOgn7oDOlafH7qAvPVF4e0mCdf/1El+Tgk
         RfuA==
X-Gm-Message-State: AOAM532MZB6s6UR6x+gqwU6TYpDldWNPm+e6UX75YqMVan10WpEu/dLn
	zZGHOeGrhReuiBuuIqD7l4o=
X-Google-Smtp-Source: ABdhPJzdbANa0bLxt4pJOgGobkwEM1QhA/bl9exgV4g432sjwc9Aq/lh2RudpP/At2HesQsj/88FTg==
X-Received: by 2002:aca:f386:: with SMTP id r128mr1661493oih.168.1631187836983;
        Thu, 09 Sep 2021 04:43:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a8e:: with SMTP id l14ls404026otq.10.gmail; Thu, 09 Sep
 2021 04:43:56 -0700 (PDT)
X-Received: by 2002:a9d:6f16:: with SMTP id n22mr2052108otq.29.1631187836642;
        Thu, 09 Sep 2021 04:43:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631187836; cv=none;
        d=google.com; s=arc-20160816;
        b=DBeQMIXSi6zOGDCxPoWnERqYoUG75INmD62eVw0B5W5Iad9ba3q/WH4mq4QmE7LNcv
         g6LnwkuNBqrcF5+o21w0oWYJtmDubFrkID3CnU9gJfIF1IxdsyKypd19u3Jkzh3Imhv/
         1B2XuENTYfc6Gb0UE/4LGD9iESFfTQz8X4e4KtfjMq2Z6e/x36UZavXnkOFVOP70VhA6
         QwGo8w/TKWn1N174PUuCTEagLpfsWbZdtlnwOJfJLOiUg+48WqYHmVha4J8yaQIbvhM5
         sLFKoNVpnrF4OIYAkecJT0iBx+oREJzNaBS/R0mN+VuicJorCyfsXWv1aBTsjcT0Kl71
         Qv9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ge0i4MysJLg7UB+Yx2AaDOSBAP1whBCQ4nJVOdEAFfQ=;
        b=OJt0PnO5cJJ39zF5DAiEwZns3A/KnVJV36lkssGLBPOILMucmnykHFMPH4rcLns64N
         olJAsaiddzC4C6dVktWBadnvrT7YZhgWuQIiDcKBmkJ9TTJJ1T89+gLPbZ7y4iXNnVrn
         8/FM+UwzgDCkpNIofEh+1x1EZUtK9xAyq87KR6R2umLyGVssITACNRro5tIRVejzJXoi
         TSt768i2QJJOAP0+ZjhoR/9MsvRXE5kh9wZRJqe7v9o0oN/G5wJoS/5wRR+rEhk/v83/
         Om+ZS2jNz2HujS3BGkwZ7TMw6dDtmtsT5DePTyBpe/FEkijTk3YrZaAkLcLTUDxuvyF8
         R4pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AM0acIeR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id h24si100655otk.1.2021.09.09.04.43.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 04:43:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id s20so2105946oiw.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 04:43:56 -0700 (PDT)
X-Received: by 2002:aca:4344:: with SMTP id q65mr1645122oia.70.1631187836164;
 Thu, 09 Sep 2021 04:43:56 -0700 (PDT)
MIME-Version: 1.0
References: <20210906142615.GA1917503@roeck-us.net> <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain> <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161> <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com> <YTmidYBdchAv/vpS@infradead.org>
 <CANpmjNNCVu8uyn=8=5_8rLeKM5t3h7-KzVg1aCJASxF8u_6tEQ@mail.gmail.com> <CAK8P3a1W-13f-qCykaaAiXAr+P_F+VhjsU-9Uu=kTPUeB4b26Q@mail.gmail.com>
In-Reply-To: <CAK8P3a1W-13f-qCykaaAiXAr+P_F+VhjsU-9Uu=kTPUeB4b26Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Sep 2021 13:43:44 +0200
Message-ID: <CANpmjNPBdx4b7bp=reNJPMzSNetdyrk+503_1LLoxNMYwUhSHg@mail.gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Arnd Bergmann <arnd@kernel.org>
Cc: Christoph Hellwig <hch@infradead.org>, Guenter Roeck <linux@roeck-us.net>, 
	Nathan Chancellor <nathan@kernel.org>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev, 
	Nick Desaulniers <ndesaulniers@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	linux-riscv <linux-riscv@lists.infradead.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	=?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	"Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx list <amd-gfx@lists.freedesktop.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AM0acIeR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Thu, 9 Sept 2021 at 13:00, Arnd Bergmann <arnd@kernel.org> wrote:
> On Thu, Sep 9, 2021 at 12:54 PM Marco Elver <elver@google.com> wrote:
> > On Thu, 9 Sept 2021 at 07:59, Christoph Hellwig <hch@infradead.org> wrote:
> > > On Wed, Sep 08, 2021 at 11:58:56PM +0200, Marco Elver wrote:
> > > > It'd be good to avoid. It has helped uncover build issues with KASAN in
> > > > the past. Or at least make it dependent on the problematic architecture.
> > > > For example if arm is a problem, something like this:
> > >
> > > I'm also seeing quite a few stack size warnings with KASAN on x86_64
> > > without COMPILT_TEST using gcc 10.2.1 from Debian.  In fact there are a
> > > few warnings without KASAN, but with KASAN there are a lot more.
> > > I'll try to find some time to dig into them.
> >
> > Right, this reminded me that we actually at least double the real
> > stack size for KASAN builds, because it inherently requires more stack
> > space. I think we need Wframe-larger-than to match that, otherwise
> > we'll just keep having this problem:
> >
> > https://lkml.kernel.org/r/20210909104925.809674-1-elver@google.com
>
> The problem with this is that it completely defeats the point of the
> stack size warnings in allmodconfig kernels when they have KASAN
> enabled and end up missing obvious code bugs in drivers that put
> large structures on the stack. Let's not go there.

Sure, but the reality is that the real stack size is already doubled
for KASAN. And that should be reflected in Wframe-larger-than.

Either that, or we just have to live with the occasional warning (that
is likely benign). But with WERROR we're now forced to make the
defaults as sane as possible. If the worry is allmodconfig, maybe we
do have to make KASAN dependent on !COMPILE_TEST, even though that's
not great either because it has caught real issues in the past (it'll
also mean doing the same for all other instrumentation-based tools,
like KCSAN, UBSAN, etc.).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPBdx4b7bp%3DreNJPMzSNetdyrk%2B503_1LLoxNMYwUhSHg%40mail.gmail.com.
