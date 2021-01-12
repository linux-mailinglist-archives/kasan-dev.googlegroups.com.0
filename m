Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTWU637QKGQENUGUG6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 158752F3243
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 14:55:27 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id n11sf1187369wro.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 05:55:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610459726; cv=pass;
        d=google.com; s=arc-20160816;
        b=mIK1I9YCftO4on3xqwRa6vsiNzlasmNQfBhFV04Ob/ZuH8ViQ21OgOTCHnGR60gJbr
         KvR11WRlQoFqLBepJ/qxYwRyeqfFYx6UOHc0pjEdbuoTcNCFBJTCUqrzMoqlvv+1A0S/
         1UmS7hAruxp2oL4JiX4U1q97QZekSI/dbjNI0nYyJ1cbUiW0H+1bLy5JVOoF4PTcpKos
         zQdvvA+anQ/0U/8Ar1FuTv+pgBwVwK8TsyTYrHfjENoEKq3apnHpMlSvDlVboUpB3mxy
         ireTSjGH2FL5Ur1cUzQoxdOEopblnClk7cMYNfn0jirP5/nLX++Jy2b7yWzZQi2+X21G
         ZsCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2NdmIDcNpiKxHGxdfDusFlHjkB2VqCc7ZqtcDt6FlAQ=;
        b=Q8Jt3H4L84MBQ7kUCMdyH/1XD+4K1Ksif9IuzdNP1IMzzOg365WQlK+GDLF6y4UTy7
         E0zeuyvRkxhUQL07iVkDH3jaoRphpcKOxYeR5AX5Zsp1g2Oly+UipLn1GQqcqZgWBPKj
         ol501DnIMvS2serl8fh6yTR0IdOacfwsF6hBxyxsoiwXuSbRIW5x+hCrkmTz7vQR93NR
         MpaE+qkjxEv0nNAsxWIxmuL5n4UkzPOCeyZrIumSALoGmVOxZexJlBw7TQwXKeTp8F2d
         9+QstGutxLfWr67d3rgwocPjXZX292SJRbPC7AwV0/EmtalTSEUh5QVI9tIpbhurZazE
         zTPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=USJ1WbcW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2NdmIDcNpiKxHGxdfDusFlHjkB2VqCc7ZqtcDt6FlAQ=;
        b=fWbQf/go/nhxHUNVulGzvs/sWkZhJHeW7Z+NSjftuUwUYYmVq1JB3PLC9WDiROxnTR
         ojRp4EHlRxOgJ6T9LxFw+h0ee9mDgyCtdj0+PJJIpHRLxDq+i+HQwDc7CsgG8zcdn7Xt
         dNFpP4poCBuTvgZ3JX8oV+ZJeoLdm/uJnRZMLgkfXyisAiqx4eWox91KfFN26YTyANCp
         shpSrX1xRei56I8UE59ja0uHtmb70dcR/CCHUt5fN6dd2+7GqeQnhHBcwiWj7LFvLTR2
         rmRIVur5j+atCqeCikLe7ulARJwtXrUIcIBQTkDjfyVg+fbrueWLhuy7IYLGlP+9vY/D
         e2gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2NdmIDcNpiKxHGxdfDusFlHjkB2VqCc7ZqtcDt6FlAQ=;
        b=NRlqa/bnVOKkU+FuNG5HbZEbH5sV+olpAWNwPiSbumgHZhfmWppVtcH3ZxVQe/y/bG
         yOuPO3K/g/Ef5NqMlSdrPtqsf+kUJei8+l6crliEDhBV9Ioh2qTrkqmXOt8yAO4pmGZi
         5G/wVT47wT2vyAutCFN54BIvT5Qnpn0FC4jQhm+lTWPYDSXE8HS15w6qYbpFYiez8T5/
         b5xhLXtfvhBD5sN6cpTMjIwcA4IO/7kHRVEpYO5eYhsLqelWezykFlWlhV+xp2pseSGP
         D9LWiruUaP4tv+JEoUvBVf5Pq4Ys7dtiRWMxHSg+RhaxFlRjfGz34vzSUZwDBBmIfNhQ
         NoSg==
X-Gm-Message-State: AOAM530s8+wtxXSv55zTvpnTQUzxE+sm+cL+d91uQU7DC+tOEEQHHVXa
	ZyLbEv79/oFlmelbc34D1fw=
X-Google-Smtp-Source: ABdhPJzUj5ItJlQc8zONWSeG7fIRFQad3iPNBcuIOatDLF5EWIiXNXu47pFdH4BzwqWBEOJVu4rN+w==
X-Received: by 2002:a1c:e0d4:: with SMTP id x203mr3830202wmg.68.1610459726895;
        Tue, 12 Jan 2021 05:55:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6812:: with SMTP id w18ls3730413wru.1.gmail; Tue, 12 Jan
 2021 05:55:26 -0800 (PST)
X-Received: by 2002:a5d:4f82:: with SMTP id d2mr4456003wru.87.1610459725998;
        Tue, 12 Jan 2021 05:55:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610459725; cv=none;
        d=google.com; s=arc-20160816;
        b=bOhmf9pujjcNzuE34UVGd/giHnX1VwtadLEbRGC37aL0G2TzcFG4+HF81lizvSLotJ
         hjGNadjRLTYNjPR5fSwFWTQLYE01X6pq2UlIDOCKSCq5eyskvGuTH1OOy5TXk3LB64NB
         yCmq5jIYzX2fVsBsCOqRn2tM3oxWsRMiP9FAsko6c2o8/LCVNJZZw/Iw4CgDAXryMt7l
         otx5BomfOckoQFFlpG43tIlsTBkNlFs9D44a37vRCHdWWYrV83mBp4RSI2+DQsGs3W/R
         LYTIkfI6lGeI0IHMFgMOG0nHojgdw/cCXrKk+SJtUPBpJGWNLbEhWSmSWxWrJbq1k6SZ
         tZWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jU0ycsEdEyG12FaOCf2AucocFaDBPHhikig1gZJxSS0=;
        b=KQLyuAFpgYg3VW6HR1xhSX48/o2B+BIyeTr81rjtDPvAy+fBlzQAwzkR4UGodECOis
         SZ+QSAHesp4fEXHcgG/hfeH9dyQyJop/QVs7ka8zV+qEWF89UlXT1riyRkp+j8BH9zwO
         zK0lyW33PU4U+v8fzUxnjCvLzQsdCPvyWml+k0M3Hu/pdbkQAVdlSTee5Gfy90ycLEOU
         T8ZA5b03YYJwh0d76YuLL+htMUKOUHdWCoVOdcvda6a9VtVSnRY+PKz5NPdgyGHSjimt
         yw8jUMUoAzT67FAUsdJJDm/4IM/roakQIBjbZ5OEfHyRCwxlpS1H8WGIqIM6ublhJIqc
         naRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=USJ1WbcW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id d17si130489wma.4.2021.01.12.05.55.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 05:55:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id i63so1971644wma.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 05:55:25 -0800 (PST)
X-Received: by 2002:a1c:356:: with SMTP id 83mr3856521wmd.31.1610459725577;
        Tue, 12 Jan 2021 05:55:25 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id w21sm4052524wmi.45.2021.01.12.05.55.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 05:55:24 -0800 (PST)
Date: Tue, 12 Jan 2021 14:55:18 +0100
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
Subject: Re: [PATCH 09/11] kasan: fix memory corruption in kasan_bitops_tags
 test
Message-ID: <X/2qRlGsBj06ellk@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <0c51a7266ea851797dc9816405fc40d860a48db1.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0c51a7266ea851797dc9816405fc40d860a48db1.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=USJ1WbcW;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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
> Since the hardware tag-based KASAN mode might not have a redzone that
> comes after an allocated object (when kasan.mode=prod is enabled), the
> kasan_bitops_tags() test ends up corrupting the next object in memory.
> 
> Change the test so it always accesses the redzone that lies within the
> allocated object's boundaries.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I67f51d1ee48f0a8d0fe2658c2a39e4879fe0832a

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 12 ++++++------
>  1 file changed, 6 insertions(+), 6 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index b67da7f6e17f..3ea52da52714 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -771,17 +771,17 @@ static void kasan_bitops_tags(struct kunit *test)
>  
>  	/* This test is specifically crafted for the tag-based mode. */
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -		kunit_info(test, "skipping, CONFIG_KASAN_SW_TAGS required");
> +		kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
>  		return;
>  	}
>  
> -	/* Allocation size will be rounded to up granule size, which is 16. */
> -	bits = kzalloc(sizeof(*bits), GFP_KERNEL);
> +	/* kmalloc-64 cache will be used and the last 16 bytes will be the redzone. */
> +	bits = kzalloc(48, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
>  
> -	/* Do the accesses past the 16 allocated bytes. */
> -	kasan_bitops_modify(test, BITS_PER_LONG, &bits[1]);
> -	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, &bits[1]);
> +	/* Do the accesses past the 48 allocated bytes, but within the redone. */
> +	kasan_bitops_modify(test, BITS_PER_LONG, (void *)bits + 48);
> +	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, (void *)bits + 48);
>  
>  	kfree(bits);
>  }
> -- 
> 2.29.2.729.g45daf8777d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2qRlGsBj06ellk%40elver.google.com.
