Return-Path: <kasan-dev+bncBDBK55H2UQKRBO65VCPQMGQENLKJGBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id CE6106945F3
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 13:36:12 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id t13-20020a056902018d00b0074747131938sf12324949ybh.12
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 04:36:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676291771; cv=pass;
        d=google.com; s=arc-20160816;
        b=dNkjXCZKzmyOqfEMvom+H44YLwbPZsOFid7ZENpKWLhb0b5fDKO+KDBEVKgA/55FCi
         wlYSXfKAxCALE0eN7mxbtxyFvSDLxae5HUcPZlFzEmn/4320ui91DSaRj7C6EcBxDatc
         Mr8GrELSWeUaov3g7Sh+zEYXytiTOynAFP72ekvWgchIrWwN6U/ZHx8+rLwwYNwzPQ36
         jo8kqSoM4we7oETFU2afrAiyxw2Ic+XuagJlkKntAiJJk2HrfAgZlCmER/57mvTkUqJS
         VA+P2kqec7YWjYnxpf7pgzHhGqOo7MMAcLxL6s/nR5c9+/SsvTyMmYF+1YD5OSu6L56J
         SJJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wDpKL/6qOuqOmsgw3oSuzunWb6Fiav8lnUx7wBmIU8Q=;
        b=StKLAJuXo8XSSih+yTlhI00oV2zt0EDzGEfPNdL77H769xgP7m2JIU71x0pOf6GZUG
         UYk6KwA23EXNZdfvLArntihD3TQvqit8o0/hGngNmzkTBFpwz3l1FLJNj2mcR5c3nCQX
         CqS58LsnZfd186aa6RZso96/19XOBmkZ5M9tNHsPRFv8o2Ye4nb7YMXGD01z0jjmm3B2
         iUup4fTVY2LXX/zuWaUybbN75tifY/ucedY6H72R2/CbzHYBxXkyAmxq3/3+ye4pKexw
         0GIPJw3ns0xCxVq36Ge8FZUa7H5vH6iHfeeWiy4LyvKWi5U/YU7gz2cU+OSIbNGm949J
         bKpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=B7CX2K17;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wDpKL/6qOuqOmsgw3oSuzunWb6Fiav8lnUx7wBmIU8Q=;
        b=mnjORm9HyyvEJsMkrEtu39WO13Azk04AKoI2F2Eh1+gdARkcdkcLcpGlQoBWOD0bR5
         YxIWPSgzlVe7K4T8zTilWh92dYFxXagqEo75eczXpDtIerICUzvWrOSMCSMfoF6ayjma
         VgEGFA7j5uDvQpghRagcx08i30bKxdpw7blrSCoUrcdajyilbKjsjC1KmdSSF1l6bFWa
         UL6HrSVgnfnl3R+LVqWIfOimu6U4RggtVCY8eSz8tmTGQihqycTa+SZq2SGKA3iR//nj
         D9aXR3rEtoprmJM5cAfOuL4mdJhs9mY/lE5aS8AK0CzChW4jh6lydm8Hz7AHzX3BHW+q
         GADw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wDpKL/6qOuqOmsgw3oSuzunWb6Fiav8lnUx7wBmIU8Q=;
        b=Kw3gZQH0nFsNv0MkrSviuwJpmV3+SIPXnsGYeMlZbzW3mQsBk6I1WspDIWXWvq/n39
         yUS3ApceXZrsNKnn7AB9rxLT6tZiQL+VVzazQTlxCSql3Xv1I4ag/Ro/WRuNFse8Dhtd
         sTJggVU+gvYIlJWxP6WuDeE8gN90Es643xT3FQmxsbRUSkor0ShOWASGNr/UBxLblGIF
         YO1fmyWlyjkL1wwi+ZbjNzOs/LE1Fc/UV7/83jIltOXHr3x6l5rm0sU13Tg/JseFv8Kd
         GlUmo9znIVLpyj7uTmHYB252MDxiLjwuL1YJIso7tEArcMjl7dP3yXq1TfTSCkxAVdBe
         LnbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXe/PJHKq7gD9WF+QHOfJmnQ3TzS16aO5UMgrJiitMrUFbU/pK7
	VM1wmh9ZjDsS7VIyUm9NHoU=
X-Google-Smtp-Source: AK7set+08UkbUj6vsnNDdRU7U00isW6j4T7VU8pYsvotPSsIQo1j/pQj2qXBV9QK1kjTBrS9CCjGIA==
X-Received: by 2002:a81:6305:0:b0:4ff:e9c9:73ed with SMTP id x5-20020a816305000000b004ffe9c973edmr2642365ywb.478.1676291771743;
        Mon, 13 Feb 2023 04:36:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b31e:0:b0:8e6:dd4e:351f with SMTP id l30-20020a25b31e000000b008e6dd4e351fls6036573ybj.2.-pod-prod-gmail;
 Mon, 13 Feb 2023 04:36:11 -0800 (PST)
X-Received: by 2002:a5b:18d:0:b0:927:1fed:19ba with SMTP id r13-20020a5b018d000000b009271fed19bamr2616391ybl.31.1676291771024;
        Mon, 13 Feb 2023 04:36:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676291771; cv=none;
        d=google.com; s=arc-20160816;
        b=NWMAQpQKbae+i5pv42wKk6rT2V3JcMCuu4NTLtI+1/yG80gyGZVBJ4VltVfdffW9rg
         qJGvjMaxaiJIVLNJadKiQXIw588nLncIqmSSxWGdONLf00RwpUcPzI/bOW1MC8jPH7KJ
         gCZa9+z+QWEIB2qjcs+ZUQc/pAZnJOyEpxkqY28Rurtk17dH3LUZWUpvXd1AK/9DL/W/
         Q6EYWkgf/MqqaV5iRABS2UMaBufgmE8Z9ukm6bUIu25pXkV0oxAvAV3QDYAZj5zdy7xJ
         dDlaAb1JaLXksVN6Lv83uZGCzmy37Hk5gZB0/HiBM6ehQBcobLHR6c1F0havelTRgvYQ
         GSSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dwTZwIt/s082g2VJHyhB1aVLmAYe+39YavUh4WqOoto=;
        b=OoaERRLrdvzYWdhKchMZp/PJ6XoQibZ0BJcUc/p6FFEs6/vcuADw9G63jUyNftPFK5
         pBwMvE292BNpNkHZPO9vnRXJN7qgKrLlHvvx802YtdV8Z8MzDdrC3r4T0BN6FST5IZdM
         yW5KheVQ7M89am7K9PZGG4PtxE7YERpgoekN+ZhpLSkOIanyABCLaZ1uR17ZsRXHx82B
         4TT1it1ktRJt/z5aZSoi0CYNEJdCT7b6Upu/PwlCSvb0pCo/ibQMozqaYFIMUUVosNRM
         +2pCSuCztlXnmJJsH6QuK4+5hru08RTRtuisQ/WvgE9q99XWBAibeWgQYQ2fyL9AOueh
         +zMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=B7CX2K17;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id e22-20020a25e716000000b008d8389795eesi1251261ybh.0.2023.02.13.04.36.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Feb 2023 04:36:11 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pRY39-009IPX-1r;
	Mon, 13 Feb 2023 12:35:15 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 079C9300033;
	Mon, 13 Feb 2023 13:35:56 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id DBC1E2010F0F0; Mon, 13 Feb 2023 13:35:55 +0100 (CET)
Date: Mon, 13 Feb 2023 13:35:55 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Jakub Jelinek <jakub@redhat.com>
Cc: Marco Elver <elver@google.com>, Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Ingo Molnar <mingo@kernel.org>,
	Tony Lindgren <tony@atomide.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable
 memintrinsics
Message-ID: <Y+ouq8ooI7UH4cL+@hirez.programming.kicks-ass.net>
References: <20230208184203.2260394-1-elver@google.com>
 <Y+aaDP32wrsd8GZq@tucnak>
 <CANpmjNO3w9h=QLQ9NRf0QZoR86S7aqJrnAEQ3i2L0L3axALzmw@mail.gmail.com>
 <Y+oYlD0IH8zwEgqp@tucnak>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y+oYlD0IH8zwEgqp@tucnak>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=B7CX2K17;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Feb 13, 2023 at 12:01:40PM +0100, Jakub Jelinek wrote:

> The current gcc behavior is that operations like aggregate copies, or
> clearing which might or might not need memcpy/memset/memmove under the hood
> later are asan instrumented before the operation (in order not to limit the
> choices on how it will be expanded), uses of builtins (__builtin_ prefixed
> or not) are also instrumented before the calls unless they are one of the
> calls that is recognized as always instrumented.  None for hwasan,
> for asan:
> index, memchr, memcmp, memcpy, memmove, memset, strcasecmp, strcat, strchr,
> strcmp, strcpy, strdup, strlen, strncasecmp, strncat, strncmp, strcspn,
> strpbrk, strspn, strstr, strncpy
> and for those builtins gcc disables inline expansion and enforces a library
> call (but until the expansion they are treated in optimizations like normal
> builtins and so could be say DCEd, or their aliasing behavior is considered
> etc.).  kasan behaves the same I think.
> 
> Now, I think libasan only has __asan_ prefixed
> __asan_memmove, __asan_memset and __asan_memcpy, nothing else, so most of
> the calls from the above list even can't be prefixed.
> 
> So, do you want for --param asan-kernel-mem-intrinsic-prefix=1 to __asan_
> prefix just memcpy/memmove/memset and nothing else?  Is it ok to emit
> memcpy/memset/memmove from aggregate operations which are instrumented
> already at the caller (and similarly is it ok to handle those operations
> inline)?

I'm thinking it is trivial to add more __asan prefixed functions as
needed, while trying to untangle the trainwreck created by assuming the
normal functions are instrumented is much more work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2Bouq8ooI7UH4cL%2B%40hirez.programming.kicks-ass.net.
