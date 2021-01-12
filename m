Return-Path: <kasan-dev+bncBC7OBJGL2MHBB56K637QKGQECF6XJZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 29B952F31CF
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 14:34:48 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id u9sf433604wmj.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 05:34:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610458487; cv=pass;
        d=google.com; s=arc-20160816;
        b=fxyR8FPGYSQS/slJW5AhiV/8789+l4YzHP8JaAwN0uf5ktmPvnhaCnDV2qez81ewkR
         Ue//pWsrxvZrDfxMRHmXiXgKdgskNylXYeZgfiqeqFTQ+2vVnhduurtK5Mcg7dTkN9uL
         Ox6V0ZSpHDubYdycvJjLbTAUMWrQHNklGPv+tDGY5KYXGdHGaDu5F2PmYqXwTIPmgaF5
         GniQpeUCiV8wzdJSQ6PdHt9yDADdfXJ1EcnBjQYgW1bMTP8T03yJjr4HtP1RqpsWIZYS
         ZzHiCnfsnxfZEqaB1Uy1himYvkFc/bxrDd2jVpGAYhOIp3hJ1uXlV80NyMaVAruhuFMa
         gk6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=mp4hHyEQpjollXUPmVbRY3P29jAHjbphAS/LO3bNXXQ=;
        b=IYKvdT+VGThVhVxWyS31nL8mKElQbcgY1l3Xo/DueYo2TZ4nSPcpf5N14r8RCMxWQR
         PAe5weHYplB2I401QheMg0TJrzpJ/b5/oRjkj7/CDeIzjxdtPvBqfz+BTOWGGfvSHGdn
         aGvnCBeTLoOCu306zUR2qQk6KZRxLdknIs4K//DnlBXucrXbqFLtQZyHXmBr8gh5vUnr
         k3IwhcwfV1dLouNcuV/O3tW5GRsdng5+xkvyGS11oLcz6vD24dH7MVt6fioGd0LWXZsf
         WBkfj1qhTFWHVswu5z5GcWs3qfuESP06gpvoXTxQIyCHM7KqnA4AeLXcqowr/o0QX56H
         Za+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W+nxBakC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mp4hHyEQpjollXUPmVbRY3P29jAHjbphAS/LO3bNXXQ=;
        b=XuOldHHP0rJfRbBT6+jCqtNLb7iNy4EQzt5++TNvaznF8tZqH/785wi2lxJzJbiQee
         hI5XwU4ARx3d+bFxXKT2WdfhBpJWYY81xm3n7qcg7pemYTIJLHFRB25rv42lp+37Ngnv
         biSsHUVjiRmOkyHpi4gbKzgORX3hJBPGnhWMg0Bp39g0zzLcCRTPe8SBSUeaNRwD7MJs
         z0E5cXiOt43hcSrIelqC0EvwsM8RFf52djcTOoOxAa1pqT12aZKZd5yOR0FglEbAjAp0
         ouKlZ2kTtE9YsVfx3diXriuP/HNxG5Xc2S0sOI0bfB5caHtBZIpfMgzFQlFDMsl5mVTW
         nnBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mp4hHyEQpjollXUPmVbRY3P29jAHjbphAS/LO3bNXXQ=;
        b=DvEn9wUbuW7pJqdXdb67F3m9zTSs4U0eYudMkNnpqFOrmKPRPrvDXYF8q5Pah86Wyi
         q3zlbELpgafp3sztDNYlqDMutYH+XZVA1t1BnpsI9rMqf9RYM/GF+5XmfMpBx63ueB8A
         vLtx8V1/OQkbm9gASlztT9hhl+3ltr7/RDSUgfmZMkQLWpjho2UUpJfqcWms647hHYkA
         OKFopquPSVHpenxY2sVd5zyJpDMZMAaqo+kA+taRBgODfeLz7reRkVbTVbvQWm+ikhVV
         uAI2xxL8HvTtoB8Zy7B7U7r/XvVzApsfxW5S/JnGWg8XzTMel2YJcD4mFhKq0sotqoG7
         2yJw==
X-Gm-Message-State: AOAM531lyAC4lSgELHdg60D5uHiq5vvnQMzrxT0Aw9FTwTOFP5bgm7UV
	3OUtGxIGuXfygnm+4z9uKgY=
X-Google-Smtp-Source: ABdhPJxVhLDV7XvXTYETuR/atFD3GgGuq6Vg1G3wPnaSS/5OIe8hbnszEcH9juAB4CGfPqnTS4eoQQ==
X-Received: by 2002:a1c:40d6:: with SMTP id n205mr3756134wma.0.1610458487878;
        Tue, 12 Jan 2021 05:34:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:66c5:: with SMTP id k5ls3629983wrw.3.gmail; Tue, 12 Jan
 2021 05:34:47 -0800 (PST)
X-Received: by 2002:a5d:50c3:: with SMTP id f3mr4314106wrt.287.1610458486924;
        Tue, 12 Jan 2021 05:34:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610458486; cv=none;
        d=google.com; s=arc-20160816;
        b=rZzzKZmNvC5Ec1MC+V/hcMAITrYc+3oR1ahY2sPbuHMTw/8HOkvR6r+5JuvLmcfriI
         x9ggAkQrasHbn7lRXcivQjFXgfxPuSAD04M7GVGR0esZeXMyYKjRBYsRWbsDV3aLPEKx
         5C7HcP6qqiLb/ktTwbtRujGtPgKJx4CucmKExGFaeOa683I+2DDDtdDdhY+3rSIDMD4m
         o2ACUHFIJr6kJ8oocVAhcohShuhdc2l/eiWv9butC9s+Yo/CA5Kgg5z7LsZuV/WyxEb8
         j/6LJ1SFp8/lWfjH+XKZaT8YrgDNuDKpw1eFIbG1WaNwyddfXPD9tb3f0ezyoyn/ODlQ
         fP1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=z9FwHUycumOs6t3SGrgS7cCKPT7xvNasenz8IWyWKdE=;
        b=Qap6n6UEZua19ihFyocQlaPFIWDDCNuWwUQXBDX3jlTN8jYd/8U0F51zUaQ9FyAbav
         oPZ1QWfc9bKqWPR32UDoGMYtZCFmKgQB8pdIyrBK7cgkNZIOP/ODUYA8DSN9A1d+sPdy
         POAmCgAcODnBpJTqXsEEz9YGj90k5WusrISkEcU1s+JKu1eC3DPGvhXQ74yUNCLwCdfS
         RwyjRIigWJOfIm5N+frH4By5jzH5GlV5GK5Kx2S5EGPr0Fwoyz6KBMAEfQ3ASEpzLzqg
         meXF7k6YTkWjo6whGFYC7oddhkwTuYYmS1sN/oySk87P8hSZ9WbBFOXUqOBy8B6u0eeU
         NTLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W+nxBakC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id z188si167107wmc.1.2021.01.12.05.34.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 05:34:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id d13so2485896wrc.13
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 05:34:46 -0800 (PST)
X-Received: by 2002:a5d:6a88:: with SMTP id s8mr4508931wru.118.1610458486541;
        Tue, 12 Jan 2021 05:34:46 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id h184sm4218719wmh.23.2021.01.12.05.34.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 05:34:45 -0800 (PST)
Date: Tue, 12 Jan 2021 14:34:40 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 07/11] kasan: add compiler barriers to
 KUNIT_EXPECT_KASAN_FAIL
Message-ID: <X/2lcAQE4ia21uRj@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <a37dab02f89ad93cc986a87866da74fb8be1850d.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a37dab02f89ad93cc986a87866da74fb8be1850d.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W+nxBakC;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as
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

On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> It might not be obvious to the compiler that the expression must be
> executed between writing and reading to fail_data. In this case, the
> compiler might reorder or optimize away some of the accesses, and
> the tests will fail.
> 
> Add compiler barriers around the expression in KUNIT_EXPECT_KASAN_FAIL.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I046079f48641a1d36fe627fc8827a9249102fd50

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index dd3d2f95c24e..b5077a47b95a 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -79,7 +79,9 @@ static void kasan_test_exit(struct kunit *test)
>  				NULL,				\
>  				&resource,			\
>  				"kasan_data", &fail_data);	\
> +	barrier();						\
>  	expression;						\
> +	barrier();						\
>  	KUNIT_EXPECT_EQ(test,					\
>  			fail_data.report_expected,		\
>  			fail_data.report_found);		\
> -- 
> 2.29.2.729.g45daf8777d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2lcAQE4ia21uRj%40elver.google.com.
