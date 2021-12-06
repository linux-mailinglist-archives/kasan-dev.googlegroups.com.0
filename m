Return-Path: <kasan-dev+bncBDW2JDUY5AORBR7ZXGGQMGQEYROVR5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 91ED146A93D
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:12:41 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id j9-20020a17090a31c900b001abe663b508sf258713pjf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:12:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638825160; cv=pass;
        d=google.com; s=arc-20160816;
        b=MN0GXssGT2oSa4URvoLeDmIkUA6ik6hoi4T4vrfG+cQ3eB5tfQn2gb3K+boBppZDER
         RDk0qjb8IwNclzPQskbgDbB7zUGOayx7/h1ST1RGHzl0QKmGL2N8t61+7/YK0Q3Kioy+
         OBJXfPcwYk/Uk6zfp5snekqcJwebaxmpWiuPzzBaka9lwXhXdExq9divqAWRecO7yzRP
         1jOj/MVK9KZQ44iXY2ZSYRMm4tinb8tcr4/xUgDPkyezIGfYk+y+B2HmQDfmvSxh1xXT
         m4WOEJNYvWPBVSs6IcU5b7+A1QTqso36/0hIoYb5ECKMsKZXtVfWFTihSU3eYxakAkvi
         lc5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=orIcLEkCbYQ1ZMgrkIyV1hQBVLIRBlspIsGKntMXlJs=;
        b=gVFTuTnPgJV8pU3wUbj5L1XkbyDHdM7f0D2zhNqutB4NW83/Z0y3oqR0yHMxEIGkMa
         6DSPo6e6Ro66Qpg32hsU3ptAsOrKv2SJ6tpBlh69VunzLZH5/AzT2wGzc/yscPzH/FLL
         dXg4J0DxHNDdkzbavH15mtAsBLNsTIiRfO4GOmngM6lOT3lXZBno/vowVFm/sE9haZNe
         /iy2tq2eaYCztJNmVAus3xvo2Uo44hpaOo6aRxYfPn3INQpmJaG4pYkihuauJAmv+2hY
         J/aQMgviHLERWgnRqww14mqKyk5ei8XWVEJZ+hOW1y95akUAJeVr9xqAAZAYOjAcAAyu
         vvAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="a7s44yX/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=orIcLEkCbYQ1ZMgrkIyV1hQBVLIRBlspIsGKntMXlJs=;
        b=Yyf9aYnirabywtunKS6IMU9r5jblkCQGjxAtr57G5afCjr46hip0+y4iOlmXtkGV+U
         WqO2ePmYBx2Kx2rDOHgyuRNoN11tpJ8QR4HHQP6tv/+bgd8kPg0zBKPf95u0m5KTNHXQ
         FtpNlftkUrK2+1vERqLtvtSpUhcCDBCx/Mi3T48qQzAQrz1VGSErnupNkcPgAeenWjbH
         XsNTykrgfvsvtox+ngvMh4Hv5DfhlCpLqAspTHaLaeXQSemw1gWe/DoXR0yGCVXvhRS8
         oBMmBfweeBZdfFa3XKOX0/FnLLgXfe5Fh32DaUx7E0DBBa9KeHp8bSegAwyyNMGAwTzl
         GSuw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=orIcLEkCbYQ1ZMgrkIyV1hQBVLIRBlspIsGKntMXlJs=;
        b=LyF+NWeBQx3IWUW3K1ObuO5AsJd1uP6A45vVvQRDs3UexRdDk593PdSZb4ggFYIiQG
         fjOn1WKWWyZddWYhsqE8XnUN1PacpToL9hbHgpt/BEGK8BewDDXhLlZOlaLGJsUPxl/x
         uKIqzHBpxrH/wWjIa9iOIZ4FG+KbbLDo0dLmtWYmc5bbYb2wOiqWR4DJvnsgULlYvtrQ
         C8+prJrZylPvolDYSrYXHgiawLuDRuEbFP0wES2CGMnFKgjQ3euq5Tv066JZGgXNy1Tw
         zZqRgvNjVbMiSNdgx3yCnclSMMPn6P3rQTauZzX8JUX3hd4uKgarAjbjgssdd8xzEJtl
         OTWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=orIcLEkCbYQ1ZMgrkIyV1hQBVLIRBlspIsGKntMXlJs=;
        b=ZVaY0tW/VEzN7ELdI1BTbjS6VEE9dQK5JQuvWAvpcAnDFwpVy17+NtrXwUK74zL675
         0hgZQ/IG72hRBSKRArnnHYsQx6Bra9BeRafZekUu8mTMtKWWIjAeVs2/IuX79oH9erwH
         XStv2i/s6AK+5nIZq5xcOSLXQps1Lofpcz0LAekeSFHNSp4G/eG+hJvMrT8gGGpEgw8l
         bJE8sCqrKI6DzunBI5eGpg/zjBSARV3b1D/45QdPvETM3v0Z3CQp7Vzc5xSs0gUtpFdf
         e8pvGhKXLUWfJegZKun+ZEzz7L2cHUsQKO4A216gN2zSC9g55Y8vqmIJm60+PqxBYZBw
         YOyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531K9hb/jD18GKnIHDM+J9uDLVbTT1I9O8z/r41fE3vg+7R9HJTj
	xEasAa7PX7o7iQKeqxpXSJw=
X-Google-Smtp-Source: ABdhPJwdLat8k8x5YbLrrZ5c1YyndPxShiXeRGEvryxnNhXWBsjFljckOI/5TX9koOLnlYIuR853qA==
X-Received: by 2002:a05:6a00:1389:b0:4ad:528b:bf86 with SMTP id t9-20020a056a00138900b004ad528bbf86mr13696434pfg.80.1638825160050;
        Mon, 06 Dec 2021 13:12:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1946:: with SMTP id s6ls7003585pfk.5.gmail; Mon, 06
 Dec 2021 13:12:39 -0800 (PST)
X-Received: by 2002:a05:6a00:1c65:b0:49f:d8d0:c5d9 with SMTP id s37-20020a056a001c6500b0049fd8d0c5d9mr38265159pfw.72.1638825159469;
        Mon, 06 Dec 2021 13:12:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638825159; cv=none;
        d=google.com; s=arc-20160816;
        b=XQ6PGPYBkEefyywMyjwzpNSh1Ixgnz4YMQnkBOicaZSFTdki0jK6QWNgvSovzeLuN0
         wRKvbhnodYd7Dk4896bHkTnurwvRovrfqZqKEeZiWLT3TkiGHF/dOszg0FcPPTjS+aDC
         0OCG5e8tT7fIObHzXs9OZ4kIaqqVGcpAqP7OI9ILuPOx2FAU6z9TJBivGwLGlz3mugyW
         053hXf3LTHtw1EhSRNzaQBcXO9FjRVtiABBlM7b03bMr8Sv4XJ4jnX9ZyOIu1qr8HgN3
         FEyQ4ZWEh7yWfDjt5Z0qQWYn3Ahq4YiOhzsXqKW4c++yeOFEE8HATJfemCP2cXpDfsfx
         UT7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WX4eafM7XhN/ysEQz94cWOqdqAJNO4s4yHfaCN6LFrM=;
        b=jKOU91x1Kbt26GJmAVkpdflfed0bjLe7EUJXXaIE6OfR5w5fq3qJbYg4w/Ht5C0mWo
         Rm8vp7jJSKbEPGyK1f5O/x4rY1aGZLvJt3MQ4i3t2G+8HFEZptY0Qf7PahBE1D+EnGIq
         Og3U46C8fMeUBsFzwp7fBVjPZxtFz1oBlegj6P/TnGAvHRphWRZ8rtUKd1/LLxyxGlhW
         MUkI0l9pn4vLXOsW5bDFZarREqkVow2xb6sr5ukvtQgrnchdRwMSCcJfiVT1ZmnqSC7K
         awbqsVMAvIF02OaBjQFUywxuXpQk06pVnsQrJczODexl1NiaRzDdSGAFD7w1TX9YYH8G
         eTdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="a7s44yX/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id s29si1074088pgm.3.2021.12.06.13.12.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:12:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id a11so11652992ilj.6
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:12:39 -0800 (PST)
X-Received: by 2002:a05:6e02:1d1b:: with SMTP id i27mr37229873ila.248.1638825159053;
 Mon, 06 Dec 2021 13:12:39 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <8557e32739e38d3cdf409789c2b3e1b405c743f4.1638308023.git.andreyknvl@google.com>
 <YaoQos9Fevz32h6+@elver.google.com>
In-Reply-To: <YaoQos9Fevz32h6+@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:12:28 +0100
Message-ID: <CA+fCnZdOuQCCTphqnfUP3Us+fgXpA-arS+z3avHAtNVybhxMSA@mail.gmail.com>
Subject: Re: [PATCH 24/31] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="a7s44yX/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b
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

On Fri, Dec 3, 2021 at 1:42 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 11:07PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > HW_TAGS KASAN relies on ARM Memory Tagging Extension (MTE). With MTE,
> > a memory region must be mapped as MT_NORMAL_TAGGED to allow setting
> > memory tags via MTE-specific instructions.
> >
> > This change adds proper protection bits to vmalloc() allocations.
> > These allocations are always backed by page_alloc pages, so the tags
> > will actually be getting set on the corresponding physical memory.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> This is also missing Signed-off-by from Vincenzo.

Same here. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdOuQCCTphqnfUP3Us%2BfgXpA-arS%2Bz3avHAtNVybhxMSA%40mail.gmail.com.
