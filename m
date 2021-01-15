Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKGFQ2AAMGQELJFB4WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D92B2F7DCD
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 15:11:54 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id v138sf5976705pfc.10
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 06:11:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610719913; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ssVt/mGmNDd+l5YnwutwrRzPRhWQGbUjdeDqp6NcQodRVkf6tpOh19UfH6iWQwhN5
         HXXiSG84Q/GGRt8yrUCxNTGj9TA4jPGdpjd1md99pvdQXgVMCg9pEJlNRIbuIT6AMUTy
         kEM+SfIe4LVn5RYY8/OLp/E2HBNxrEhEpdK2EwG2fOPf7g8U6sUuiXpn+FMM/IlxSV+3
         0DsH7zyMGF7OoKeOsTxANm9Hf1c2mhvM6L3OsGWXOd92kfK7pEhNgNdU46SGJp/eFJa4
         SSg0peSvTPDO0VvT+bkM4piDWr5rikICHNz0jbYHLm4aNH9N9JtOMvSoUQU5GePIMnnk
         ZEXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Y5yqEt9hmkby8I98LtgjFbRi1byN2+EZ+JaWnsfPF4c=;
        b=LLogPVfiq3hKT0Jkng6vB7DgERFzt5iihcy8hswU5IdBZS4cRvlyFbRq5TlHNHXelN
         d/+aOK8A/odbHcG1BPPjyG9kFxMlJoXxRF3xAlag4xszuVqzmZEzWXt2NvV7Odzc+aed
         roCKoznbuZPV9KnvWwesg39IYM/HhRmZXd9Gp3jUHBeEIzKY8xplkUSq2LTS/SE3iKoI
         mQxZ7i1ZsLf+GR9bziCOwGTMExpc48c8XFCcHFg7XxZiRfp0GLqx2zkQqX46vSy6REHN
         aza+iS4sjiW7priEGaW10if5CDonywVt/ngM4YZ2fHtGBmBj4YbF6IiXb4Qt+IVRRksr
         /FWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EZ8VlQWZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y5yqEt9hmkby8I98LtgjFbRi1byN2+EZ+JaWnsfPF4c=;
        b=gdNjOOH7dBdZKJd5ZraxbDZlO8j5WFP2mgNEqN1foybCHlH/2o46RMDGV/pw/X5KpY
         /jh9pQV7DMVFwkUy1hVrCLNEz5VBNXsbfXSJkRTYMA6aQfjVD8lVLyxfgtoR7BWIczsw
         FVGNiyHerbBEklgy26zVNkt/ZNAdjEKLNKgQIl7V0ENebccXqypZJ9s67UdVTELodfi7
         X4hVY/9MwVk+VMwJnjoc8jGJFtWzzv0n8I2At8kdTyG4NRVaqLBRaDx/XbmF4onzNKs+
         qS+lBwVvdhLNYEOe/pRViV8yeyM7fZmLIl5110jrNJAB7o1h7EGD+TJfI1fmwFW+C6JA
         yAtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y5yqEt9hmkby8I98LtgjFbRi1byN2+EZ+JaWnsfPF4c=;
        b=ISK2ZLCIbVqBcGThYUNMR3ry07UbODsVVF81DfQkr1TCqDQ0wazVg5b7Umf6MoRdYF
         Hl5NGVd70JXuhlrJbZXaP/HCk3dZEdP/gj5fDG3fN/ziR+68Jq1RH9I9zdJKBX+rCMB5
         9rmWGg5Aq/0cBHj45jtli5H6m7fzSlSSgrrbqyf4h225MvLG+46eYFRxgnh5f3Bm4BDh
         HWUYxK2vrmoYtN+pHSkfHCjR6XaanEs0exw1YZ8mxlS6nTivjSEPKQdTmeEJpv30/6DS
         8j3yMn4Lb5ujll/wRXt1+cKr0Obn5bZewEjfzUVD39zcxkgQNbdboKsrTXvbR8e8JYwY
         XqgQ==
X-Gm-Message-State: AOAM530qkjoSZI2JXrdGAK7HI0QcCSf4at0xBLXe59oHyXtXpTUWxiM2
	rAIBwwnVjKfPbUAT33TABSM=
X-Google-Smtp-Source: ABdhPJxsKDsS7fGUowPtfPkCNY/g4d9eMa8NxaRSVFOzIuHylptbRMj3Q/gAS/hHJZAy5G7I1/AxAw==
X-Received: by 2002:a65:4906:: with SMTP id p6mr12644506pgs.173.1610719913015;
        Fri, 15 Jan 2021 06:11:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:78d4:: with SMTP id t203ls3599499pfc.6.gmail; Fri, 15
 Jan 2021 06:11:52 -0800 (PST)
X-Received: by 2002:a63:5858:: with SMTP id i24mr12750055pgm.212.1610719912466;
        Fri, 15 Jan 2021 06:11:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610719912; cv=none;
        d=google.com; s=arc-20160816;
        b=r29oDEj0upEODB17EDN24Sl8RUB9DGzZG2oJ0b7VFw59I2VPSoxlUiQweyiP/UPSdN
         Kk7SNEhxPmh7BjFzmSe7ss6hKj2+//ob5tt/+XOjXQyuA3yR5qnOGxhiofn1eqq2dvLj
         jiWdDwb4fClLfhq93X9fgLcJavxA8mYcExv97vxlxc134cUY9gjDQDAUKdFhokgeVSO+
         YVY7cEfgDuv6cCTjPn3UOojHdGOTryco13tkYQIFgFoUFYYpRqs/WN0oZszpNnfGwQNU
         SCQ48dN6CID7eXK5ISAT4/gKPPHz3OKG3AvOiUfw8iNIbMgbIKhqjROcKhfFAPCu04h2
         rGDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2gEonePWvzu8OtY+gNiF+A5sU1b7iiv5oXrRT2xFrUA=;
        b=K82ZH/dG6iDBmeteklDUUvA+/Jvwe6YHolfHJUsKGRH81hVattKIs+/Qdc7fy/8HqA
         /SqPc+TyWtkQmuaTVwBvuodQqLJ7p71OI+aPC3SruYiM2sAIBLEEIajb9fEdDRMsyehA
         bmE6mYkcZny3S3TIRjR0zm1dyfix5XEl5q3qSJAJz904Ab54EhTjAYkmbdJKO69xw3EL
         od2B+A8ybgoATcMzqdIWTtmypQT32hQbqJ4Hk+X9ZdqfNJswbfsOlwVF0nJsSYzEyMWG
         /AKQIoLoHbfjmoWvPJDm3mysdR8pTL7w+DDxS04NhEVekqwOpDEV3bhgxb8TmrqamczP
         5z+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EZ8VlQWZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id 15si92550pjn.2.2021.01.15.06.11.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 06:11:52 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d15so606999qtw.12
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 06:11:52 -0800 (PST)
X-Received: by 2002:ac8:6f32:: with SMTP id i18mr11814637qtv.175.1610719911742;
 Fri, 15 Jan 2021 06:11:51 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com> <73283ddcceed173966041f9ce1734f50ea3e9a41.1610652890.git.andreyknvl@google.com>
In-Reply-To: <73283ddcceed173966041f9ce1734f50ea3e9a41.1610652890.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 15:11:40 +0100
Message-ID: <CAG_fn=VC=UPtVWfz81KeX+hEO1eC2PkZowWyFJbqz+jmiEeOQA@mail.gmail.com>
Subject: Re: [PATCH v3 08/15] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EZ8VlQWZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jan 14, 2021 at 8:36 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> It might not be obvious to the compiler that the expression must be
> executed between writing and reading to fail_data. In this case, the
> compiler might reorder or optimize away some of the accesses, and
> the tests will fail.
>
> Add compiler barriers around the expression in KUNIT_EXPECT_KASAN_FAIL
> and use READ/WRITE_ONCE() for accessing fail_data fields.
>
> Link: https://linux-review.googlesource.com/id/I046079f48641a1d36fe627fc8827a9249102fd50
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVC%3DUPtVWfz81KeX%2BhEO1eC2PkZowWyFJbqz%2BjmiEeOQA%40mail.gmail.com.
