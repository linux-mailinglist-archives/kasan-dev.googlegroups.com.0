Return-Path: <kasan-dev+bncBDAZZCVNSYPBBUFKXD3AKGQESHJSD7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 990D61E3A46
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 09:22:57 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id b22sf17593988pfi.23
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 00:22:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590564176; cv=pass;
        d=google.com; s=arc-20160816;
        b=tD3VcbwjXJQhxUUoB5J3J7yr+lWtFuKbmusV2NlJM9dkBSRSIlCl7Pzwhk65Uvj6ww
         0ytkMDvgmdQqx/TXuDUEMfbd4qFPTcuVAodNNjUP1XESSnxO/kkDCCtrhaNF12wptxLn
         27OMj1tx6uYMJSKkd65eBSs6HTP83gcLsxqiWKX3xhHv44FvG2mTC+YId5vNVt5Li/JM
         +8dGrRZZAiWWfxs41PXl5irfsAjFNmRhasDSxkXMmHo2aC8UCCSD920JLPprtKCFp4u/
         zuZFjoSqbHYokwNTFYrmXNQqN2n8R9018YsxnGtl7KdsMSSJEBuF5QREvBipzOmArxrP
         MOGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=eMwSg/8ryA7qsgVyw3FehJPrRWOXrTHMpa3CJADUyAo=;
        b=hktWeqI12tGgrKrdBBNPVewEguW5U0UbSA3qVTPXFaLS3JQNs976pRz/fSBBJMoI1X
         wdTnzYqQy6QzYslDH13HgTasXlehEj580RSBfVD+fYDGM1ynwqj4F7YhPU4W8QbwlvXW
         hRQNG7wim4Vi//1ZIWUloOkiSOXTtjE3Kg6Afr5ovkwsplyBKZGG0q3FRAMNbgX0ml6l
         zSD3GGJDuWEIoEnwXK5J7+nIjqb6/CCccMA2D4TBymnmpD7+qe0+xpco17QhNYsWoro5
         /aesyNxoQOU62Bc3GZ/iaN11+eljp5sRybu483753x4RPgqYlXQucgi8S3FQljaBekvl
         w40g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=JjMYLITu;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eMwSg/8ryA7qsgVyw3FehJPrRWOXrTHMpa3CJADUyAo=;
        b=OY+1d3dy3KJv1agThDLghF/A6Cfyv8olpLbTx9TF5sPkTSu2pj9OB80Idub+HQCz0u
         Pkku7C5vvIt6N0CoD4xvcLVEcSCFrD2LAZTIt6nR2MaAAG2hRATRz/7PkYP2Rra1fJeT
         R4djSI/kzrdd7vTtpENGeZVVqE34ZmydZO6s1imiZdmyKggXpt0X/yTtgtZSPfo1eyED
         29ihLbCGU82f+oY5g95eqrh3p4xd5XveHmrMtUuycqWNYiZG5kSxEQjfqMqNhUG0b1m2
         EnKvqF9yE8CBf8amocdCHv/yMeDh94zSI5aiBWbWtLln5h0CcUQ4i1JMeVR89cEyPU/V
         Me8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eMwSg/8ryA7qsgVyw3FehJPrRWOXrTHMpa3CJADUyAo=;
        b=rZMkMJFVdt0+j8jfijdB98f4SMC1kFj8Af0PAWtwbgtSIr6Q0+zMYsQmW8j6nmMAWf
         bqiSCe/fq98uwDRcwnFS4QyIcqeJdvLU3ljTz3Uk7IuuedcbyvPrzg8EfbSXT1vE+b4C
         10m4oksbhprMvSbX7Pn2vVqyY0do/8Jr23qkAwE87URmOYb4wp/Ieo3dzEpaqDCSVSgG
         YvU7+nTigNzrEXywla37DkO6hCF4fyC8kFpA10GhL5btsJ+lVSPziDPwJapF+8D24Zg7
         7O4uYaTQ/EvMZhj/b3PztmtxYOx+39mgQMjcKElx2OYlW4EBEovYB2OJF0QocrTsEluv
         ObpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OYx7pdwG8svhqlCrbdHF/lZDCbXH5+vP1mxr1eY7+trPVKx7B
	V0y2IRSTHQTshxAWOloKplY=
X-Google-Smtp-Source: ABdhPJxzMLJvaWs7E4tvTbGL5HFwHABVgQxtrFKkfA++Je6fJeg2wpa+VLuyPv/ikk78jK3HtZ5Rnw==
X-Received: by 2002:a17:90a:f304:: with SMTP id ca4mr3466703pjb.184.1590564176246;
        Wed, 27 May 2020 00:22:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7697:: with SMTP id r145ls1857946pfc.1.gmail; Wed, 27
 May 2020 00:22:55 -0700 (PDT)
X-Received: by 2002:a62:7e8e:: with SMTP id z136mr2615483pfc.309.1590564175848;
        Wed, 27 May 2020 00:22:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590564175; cv=none;
        d=google.com; s=arc-20160816;
        b=JPfELaeI4o4Fcz7TG60bdyqTXIdXL5AEX1jElHDHtVPnAd2SG0SYmSaTaH14OTd0wH
         hGsUifn4zotN9hQamHT4yoCOFDXGbatCBwDkhMy4aHT6O4DBytP8VOwdU0VsKyzheSA1
         LV7f3fCtZxco24RcvDg7QD1wZZM6oIOHcpPJVFIIc+xCF7JR1CeYZjiqwxH/0Y4v3aAG
         7S2B/O+o7j56x6cCKT6NF5Vhoo9YZn9AG70S/FELhI4g8TGyxjQWqk++tYCkLL+/FYcd
         JL50r93t4AoL2uCoDY6LFJhJzmB1pM5kicsi62DUIlFXBEnpcwxbd7mLrL2hXaD/PVGY
         8eZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wXNgw/9N1yLecXIMKo58F3VQTu9ecWYXXeWvi6fmpEY=;
        b=KihuZOoYVQ4+FGlnIe9/5WGQZ69Z5i5xAlK5hKx0ceg3BY+rVGgfeM3LcAiSCqUz2M
         NCIszr2Jm9fhhiosZUc3ivmdnmEee55onuF4u6XFeCIBkktS3/MgTc7cnhOuZtaKR77/
         tn7efkyu0O/GrlAdrOUsYnbxRBVuVYuLwZf9V0pKADmLKTufTuZzwqvHaVrRJN5ESbY3
         TS6EwqgL2WNqy1gKr26maib7Fp30C/j9ePH4OznNVrQzF7PgrHzxeM33OOM+oaIMaip4
         Dqj7FECvqP1dDoPob+TsJEaq0hQu2LUVF9r2022ij4qA422wWkZCUrK3srLoNshMprTQ
         j5qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=JjMYLITu;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q1si134682pgg.5.2020.05.27.00.22.55
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 May 2020 00:22:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4F96B20C56;
	Wed, 27 May 2020 07:22:53 +0000 (UTC)
Date: Wed, 27 May 2020 08:22:49 +0100
From: Will Deacon <will@kernel.org>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Borislav Petkov <bp@alien8.de>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement
 expression
Message-ID: <20200527072248.GA9887@willie-the-truck>
References: <20200521142047.169334-1-elver@google.com>
 <20200521142047.169334-10-elver@google.com>
 <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
 <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
 <20200526120245.GB27166@willie-the-truck>
 <CAK8P3a29BNwvdN1YNzoN966BF4z1QiSxdRXTP+BzhM9H07LoYQ@mail.gmail.com>
 <CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com>
 <20200526173312.GA30240@google.com>
 <CAK8P3a3ZawPnzmzx4q58--M1h=v4X-1GtQLiwL1=G6rDK8=Wpg@mail.gmail.com>
 <CAK8P3a3UYQeXhiufUevz=rwe09WM_vSTCd9W+KvJHJcOeQyWVA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAK8P3a3UYQeXhiufUevz=rwe09WM_vSTCd9W+KvJHJcOeQyWVA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=JjMYLITu;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, May 27, 2020 at 01:10:00AM +0200, Arnd Bergmann wrote:
> On Tue, May 26, 2020 at 9:00 PM Arnd Bergmann <arnd@arndb.de> wrote:
> >
> > On Tue, May 26, 2020 at 7:33 PM 'Marco Elver' via Clang Built Linux
> > <clang-built-linux@googlegroups.com> wrote:
> > > On Tue, 26 May 2020, Marco Elver wrote:
> > > > On Tue, 26 May 2020 at 14:19, Arnd Bergmann <arnd@arndb.de> wrote:
> > > > Note that an 'allyesconfig' selects KASAN and not KCSAN by default.
> > > > But I think that's not relevant, since KCSAN-specific code was removed
> > > > from ONCEs. In general though, it is entirely expected that we have a
> > > > bit longer compile times when we have the instrumentation passes
> > > > enabled.
> > > >
> > > > But as you pointed out, that's irrelevant, and the significant
> > > > overhead is from parsing and pre-processing. FWIW, we can probably
> > > > optimize Clang itself a bit:
> > > > https://github.com/ClangBuiltLinux/linux/issues/1032#issuecomment-633712667
> > >
> > > Found that optimizing __unqual_scalar_typeof makes a noticeable
> > > difference. We could use C11's _Generic if the compiler supports it (and
> > > all supported versions of Clang certainly do).
> > >
> > > Could you verify if the below patch improves compile-times for you? E.g.
> > > on fs/ocfs2/journal.c I was able to get ~40% compile-time speedup.
> >
> > Yes, that brings both the preprocessed size and the time to preprocess it
> > with clang-11 back to where it is in mainline, and close to the speed with
> > gcc-10 for this particular file.
> >
> > I also cross-checked with gcc-4.9 and gcc-10 and found that they do see
> > the same increase in the preprocessor output, but it makes little difference
> > for preprocessing performance on gcc.
> 
> Just for reference, I've tested this against a patch I made that completely
> shortcuts READ_ONCE() on anything but alpha (which needs the
> read_barrier_depends()):
> 
> --- a/include/linux/compiler.h
> +++ b/include/linux/compiler.h
> @@ -224,18 +224,21 @@ void ftrace_likely_update(struct
> ftrace_likely_data *f, int val,
>   * atomicity or dependency ordering guarantees. Note that this may result
>   * in tears!
>   */
> -#define __READ_ONCE(x) (*(const volatile __unqual_scalar_typeof(x) *)&(x))
> +#define __READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
> 
> +#ifdef CONFIG_ALPHA /* smp_read_barrier_depends is a NOP otherwise */
>  #define __READ_ONCE_SCALAR(x)                                          \
>  ({                                                                     \
>         __unqual_scalar_typeof(x) __x = __READ_ONCE(x);                 \
>         smp_read_barrier_depends();                                     \
> -       (typeof(x))__x;                                                 \
> +       __x;                                                            \
>  })
> +#else
> +#define __READ_ONCE_SCALAR(x) __READ_ONCE(x)
> +#endif

Nice! FWIW, I'm planning to have Alpha override __READ_ONCE_SCALAR()
eventually, so that smp_read_barrier_depends() can disappear forever. I
just bit off more than I can chew for 5.8 :(

However, '__unqual_scalar_typeof()' is still useful for
load-acquire/store-release on arm64, so we still need a better solution to
the build-time regression imo. I'm not fond of picking random C11 features
to accomplish that, but I also don't have any better ideas...

Is there any mileage in the clever trick from Rasmus?

https://lore.kernel.org/r/6cbc8ae1-8eb1-a5a0-a584-2081fca1c4aa@rasmusvillemoes.dk

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200527072248.GA9887%40willie-the-truck.
