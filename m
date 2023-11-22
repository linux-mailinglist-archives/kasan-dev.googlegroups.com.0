Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAXR7CVAMGQE4G6LGQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id ED6EC7F4E33
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 18:21:07 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-544b5d65a1asf2358a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 09:21:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700673667; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xlc9XFr1vqOUYXO42BGntI3ZaumrAimxm5aclKOh0UHPhgqH3zDO+38BjgrurFozWg
         fpP8TiNF4Hyq3+PuLHwcGcQFGllckBam95ZwOAQPhOhLSViuOE9fXnXHy5N9yWZKBTL5
         goHydrjy61UdhAzLQ0T6USbNcJX4oQNnRMESrLhMocRkDUnGz7wrCMgoWGAAltiCuAlw
         0UPV4U5HL/qPE6WQW6ViLXDfU8UEMh4ck4vavxTpOp8tVMu8YkOe6eXPxV/6CZwzjznt
         uYljn5AsDT32vIDe5byxo9XRCUOb7fdG4zSBP+9lpyNzmxI6PvvcHsyUZxZdJzNhKpi0
         AjhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=y76Hev7pk2OVxFV7rMVuvkSGxsUDwvjZyPMaYQZMDLs=;
        fh=Avg7wGSBRsZ0DIpZn8URTxt87FNBdQgwxmFYDqTvEPg=;
        b=UIsdRRp5v16UWp4tmzbn/vDMpiHDwjHeIMeQUo66erFkP8lcuPxTXBWWjyW5Pi5tYG
         anPyvyfyGlZw9WK1lISFY4Ps4uTO6GfwwI42cRqju4Iwy3PbrNEVEpuAIEoY0dhPVRMs
         glEVaiRoKIMvbMdxHDQxqsB1xL+oAiJB14OTpzi5+3WaUcohNeidvo/XsFA57FAxQF6J
         L95Q4rjmf6UJOZCOELTD5vUytkaNPsEI8egAgKWvUQJFN9/gOU048x0t9tXzE6BSfbma
         OSicVvhW2MqyFNPA5wvdPrUq5/GxOFTRAicyCowvRZFg0941I32/h+fEH0EHyEaDCV17
         FvqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Om+ci1+l;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700673667; x=1701278467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=y76Hev7pk2OVxFV7rMVuvkSGxsUDwvjZyPMaYQZMDLs=;
        b=kpL2DJHmEu4/7VexKiSmX0ewv7nr5FFRXPG0stN+xlK/hWhum0zcmh/zDVZmkbmXtc
         TlLF+9PLWOlaQdbipH+MbfrQuyGwO6XCCfDTWrOWv6miumRS1oX2yyFyB1/tBp91XRol
         Qy6Pb+eWE+2wFE+G+ivx10PAL+/BBN1bd1rPh9vVYeEEbpL32Wd6uvrl5Q+pO5fy93kv
         qy2jD2OrVJ3XIfEXCA2VrEnK0lCdvrDPWgo3AIqRo269pLsNruuPWJUPz8jn7MeHrBxU
         1NDcvBfEHFKwQ/a2RlO9mb8qQcJCtgThzGtZjcU77p+//tfrSU12nYWvQ0kY3/PISOAA
         rkNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700673667; x=1701278467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=y76Hev7pk2OVxFV7rMVuvkSGxsUDwvjZyPMaYQZMDLs=;
        b=ZGNBj6CcVONPPUheNR/GProN23bbG1mLtgGRaWMu6caFKrvbXQb1Pl4KmhlGhvFYw8
         cD0SpEF5DIPo1T1GTe+KQ6MLja9XsztL9EXonK2F3slK5UXsy17bWslsMCZ2+Nz8ik9x
         8pt5rNL05ffv0dHBVr5NrpyEeMUffLPd/fsl/G1M8kNIOR8c5ugaUZ13ErfApZAUn5s9
         Z38SgMxrOKaYeRPK26l5+8EwhwDU62uqjXMEXpVZ25DvcvEmgyeUBNin+HT/IsMGiH5d
         L79K2RQObAyofZqPb/DEqvbqfTZ+Q3WkKLpOQTkVfSVmpG0RWZ4+AnAt3Vi62EnfMh1a
         yF6A==
X-Gm-Message-State: AOJu0YwNweO2dWo3Qu32rDNEOFpnjKN0/bXIJdQNUNyaxxbpgAqGrw4C
	U26cRsNaD+co3Ol063ThB80=
X-Google-Smtp-Source: AGHT+IHEylaLVe3K0GNcBKYhHW/1dVPH8bAKmoaJQfOAcJmcE0TycY1XZOK9BFr0AAvY0dy9CF0fuA==
X-Received: by 2002:a05:6402:796:b0:544:a26b:dfa3 with SMTP id d22-20020a056402079600b00544a26bdfa3mr1992446edy.6.1700673666699;
        Wed, 22 Nov 2023 09:21:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1caf:b0:548:5534:dd36 with SMTP id
 cz15-20020a0564021caf00b005485534dd36ls47605edb.0.-pod-prod-05-eu; Wed, 22
 Nov 2023 09:21:04 -0800 (PST)
X-Received: by 2002:a17:906:cc:b0:9fe:3447:a84d with SMTP id 12-20020a17090600cc00b009fe3447a84dmr1944050eji.23.1700673664459;
        Wed, 22 Nov 2023 09:21:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700673664; cv=none;
        d=google.com; s=arc-20160816;
        b=gkBfHIp3NSFZQyMiKZ0o58evXKeU828KTwMu8wmi5W1g72mVXkqI5IO92VWXeQwfkf
         G4JMcorR0zvOlULr/7DVkyMvAtF8x7dVTmyt+ymxsCqQBCZMI8y16MnPi1gzDNnSe0RC
         xNomzaYbusT0uQV50ZyBNbD9H7ytF2/CVP0FAxOCM2vS2QFq9lT+MD9uLzAtkh0HW9E5
         HQLKMjgv+GgSTWeZ2/fG/iYt9W8sGL0e1QiOCOSkGpymbRAn1z4HOfs6vw3vrvafgjNK
         ooAKph3rCTEVkGOZW0QZgmKjvKlBnRPdnKustP/dcm6Br1lD4ELg4XPOnkgSPJ+gy+SH
         l8Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hVowPfOdM8wVDD7Ux+I97nRKLe3FJvmMPxWZObEYXX4=;
        fh=Avg7wGSBRsZ0DIpZn8URTxt87FNBdQgwxmFYDqTvEPg=;
        b=0V8rVgnDSDDSf3xWzEMCAYmUHOZZ8v4mXNebTKedHyr9KURUfu1LjnAEdBNc5oUUoM
         eftestf/VWXUSnaPSp41RUTBhN8wmPcYI5xl6nWP86mkf8sSPT06OWec/z0ZFn6fLHg/
         /ruy8UYpYDjI1eFKLYOinL0srAcbChxbdQ0e026heFN6yr1Dtn6KlYtRLYeoGfl8QXZ5
         Gho27i+k0iHala4glkuFvkWvOpHXZ1QdcV/9beUtWeCrihvTqimA41v3ZPrfi8E5JNtt
         aKI8Pm+PjiPL3UvBBkK+9KVmIejcZaWUydA4a31fODlt17b7Vm++RkxlFmxJWGxSDLId
         HtVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Om+ci1+l;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id lf7-20020a170907174700b009e2c2a65c8asi1830ejc.0.2023.11.22.09.21.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 09:21:04 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-32f7abbb8b4so4732927f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 09:21:04 -0800 (PST)
X-Received: by 2002:a05:6000:128e:b0:332:ce86:cc35 with SMTP id f14-20020a056000128e00b00332ce86cc35mr1828909wrx.71.1700673663968;
        Wed, 22 Nov 2023 09:21:03 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:1dcf:36df:c2d9:af51])
        by smtp.gmail.com with ESMTPSA id d19-20020adf9b93000000b003316eb9db40sm15549737wrc.51.2023.11.22.09.21.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Nov 2023 09:21:03 -0800 (PST)
Date: Wed, 22 Nov 2023 18:20:57 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH RFC 14/20] mempool: introduce mempool_use_prealloc_only
Message-ID: <ZV44eczk0L_ihkwi@elver.google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
 <9752c5fc4763e7533a44a7c9368f056c47b52f34.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9752c5fc4763e7533a44a7c9368f056c47b52f34.1699297309.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Om+ci1+l;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
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

On Mon, Nov 06, 2023 at 09:10PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Introduce a new mempool_use_prealloc_only API that tells the mempool to
> only use the elements preallocated during the mempool's creation and to
> not attempt allocating new ones.
> 
> This API is required to test the KASAN poisoning/unpoisoning functinality
> in KASAN tests, but it might be also useful on its own.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/mempool.h |  2 ++
>  mm/mempool.c            | 27 ++++++++++++++++++++++++---
>  2 files changed, 26 insertions(+), 3 deletions(-)
> 
> diff --git a/include/linux/mempool.h b/include/linux/mempool.h
> index 4aae6c06c5f2..822adf1e7567 100644
> --- a/include/linux/mempool.h
> +++ b/include/linux/mempool.h
> @@ -18,6 +18,7 @@ typedef struct mempool_s {
>  	int min_nr;		/* nr of elements at *elements */
>  	int curr_nr;		/* Current nr of elements at *elements */
>  	void **elements;
> +	bool use_prealloc_only;	/* Use only preallocated elements */

This increases the struct size from 56 to 64 bytes (64 bit arch).
mempool_t is embedded in lots of other larger structs, and this may
result in some unwanted bloat.

Is there a way to achieve the same thing without adding a new bool to
the mempool struct?

It seems a little excessive only for the purpose of the tests.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZV44eczk0L_ihkwi%40elver.google.com.
