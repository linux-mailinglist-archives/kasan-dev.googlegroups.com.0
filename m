Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBX25KAAMGQEUILLDUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B4A430DDAE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 16:11:03 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id k20sf64967ljk.19
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 07:11:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612365063; cv=pass;
        d=google.com; s=arc-20160816;
        b=osTF3/lfqPaT0y36YG+vjb8VErDiWGXy67Kh3FKKiH1YhTYEQisUP/6j6cryd5saVT
         Gf7PkRZvE1M64qJhxNsJZmUfpgpvpUuhaMgWG7V50p71V1tZ35qDjZ90Qr3PQk16IxnV
         ygNCE+A245xZFJ0/oL/1CqTtR+aOQz+uezISU6Ki/aMnRe/xY4UydvfwK+voR3wZE0hs
         lohJzJuLEk7iVsksQ4c3EKuwFojfCKJJ1v5docIBP2ZAm9hK6OSvldn0kmRpZx6FBVld
         E6J9O/iikwi75yF1iseypMrANohK/EJXhySVWKRb50WcnrBJc1ChS0A69tat//8UM/p6
         CeTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=BF5GRMQvkORjkxlSWQ5xpWNXtu0Vvx1c5z/aU8d8+a8=;
        b=JPvGjCAurJAGO3dWEu7RAim1pFOtZUR4Y7COeWk792SxKKQMT4AOC72k61KU3ttMVT
         cUMkTxqv9dK33RCuGpBLUPk3XIw5mqTChWeqVzhWpQwYj9qGXSHr1LUPkkTEOBqN2xlI
         9XEUYPUoD1S0I/uaPFljOfEhtCic5fwfyOYL41XUv8gMRW07A/dOT0hrT4NKoozzh7YR
         S00GouW+F2GF/Fe3Xfun5UQzMhxuZqtqpz6C0qbbTjpcpTGh00RNzY4wijgwMrc2jTKw
         NKMQA1DX4VGfZen40CUlrVHBUsaVQuH8eYBG9Xywhwlu8jQ4yAeACsl06MbhbAYZxmJh
         3unA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J8iayzDT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=BF5GRMQvkORjkxlSWQ5xpWNXtu0Vvx1c5z/aU8d8+a8=;
        b=d2nbD6+0+YMILMLyE9Mri0by4J2Mi7b3n0OF6gKdoUc6E3jMEcO1FuEHwvUEt+4SQH
         Mj3FhXK42l+pEvIHA2KUVeuEiMUTeysOJbbXm+1peDapUnYi8eD/sbMZmhVlneJvkvVW
         T9LYsza735mR2CP62mQqoybDT5mzGRFuYievNwqj6EBi7DfjoMHQ4yZwnrhgBWUIYNqX
         Cv41+hvGWwLJKK9wB7IMhofZVBqIbEoTSLchPvx2pftwVh+M60m81NFDVBu/b9U/Ga7B
         gVyWJMbexWfjx60DtyOjFuqDH9fxOayl66nu58Tblbr0oeEl+gyJGIkzew4CJ2szADAR
         9xtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BF5GRMQvkORjkxlSWQ5xpWNXtu0Vvx1c5z/aU8d8+a8=;
        b=C2/U7mvsH47D6qFMYFfDBbm/fkWOcUyAY6IWvxTKvOYXX5sB0YYkgVTZ2sWKw5eAK/
         pAMHvja0DrbHmm2lxbOIpizmAm3pHhjp8GqXKcuitUPFUP4s0eFYFoe8tmJbji7elXUt
         9LQIQwgFzk87hJ2BUXiygkAdxWtvXZdjhNlc1OAOfT3sVXRHfDZpjOnd0Gy27LcHI26e
         LRg94m1h1++ZxW96jEa6IdG6f6aVLDNYCQCgByB+xUrUa9g/ODESIJd1imnNjIUd2cQW
         uKwQr9yL6sn9gxmjA/XtpPzeK06CHQ1yStnMsJjc8Fq1a9PFObqeSAuqrtJwdwc3uC8U
         +A/g==
X-Gm-Message-State: AOAM530YgBKi8hAG9RoLkY9jD5sHhvF89n6clx+CvMB1p/Rirj1zKy3Z
	iBpw+F3tGOuxb+nvSuhKheg=
X-Google-Smtp-Source: ABdhPJzd2zmEZOsdWXvNemHQsQhv2dlCY3cZQZVDwl/MuupYOX20bZ1QiCniI7XFNN1DM64O+d7gwQ==
X-Received: by 2002:a2e:90ca:: with SMTP id o10mr2031617ljg.150.1612365062688;
        Wed, 03 Feb 2021 07:11:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ad2:: with SMTP id p18ls452083ljj.5.gmail; Wed, 03 Feb
 2021 07:11:01 -0800 (PST)
X-Received: by 2002:a2e:86c2:: with SMTP id n2mr2012094ljj.90.1612365061530;
        Wed, 03 Feb 2021 07:11:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612365061; cv=none;
        d=google.com; s=arc-20160816;
        b=dryg9ZbETdX9ZfpLNq/EHgS2MOVHZj7lL2bIXolzWxlJZF5uQ/WcbmieKJ3DYPoOya
         0L8Py41Uj8XQoZYYMNr7A0fdhFYkKG8+XqM+PZWt2cgJC2zGwe5HMVEyTXnsMHZHbYKJ
         OgrT1tnlcEba8H82IeADI8MlyxenPDbmMBQ9GG3zr+MXE7Y0zp/7A0YcfGtUAjS/QSps
         VGEicLHI0pzVlHYnfCdqFvHHe2IpWQR+TF8f6yehgpf80f9AxOgqJVGswHytOft5Kq7O
         gYfA3HBz6cirYFQMCy753501gqvrzuaPpXrop3wNgP/fsy5JOlxuDM7htb0CeiCGtRRU
         QTdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=euglhQuz1fv7wELuChhUgZYArcEjvEFCsjQV+iKDCRk=;
        b=YtXi0mIC0jlRE7YS+kqpRv2FbkZnZyVNEVulsmfFL3MZ4wuoaGun04CkizAYFQHXRq
         NVGp+LOaHpukZ+HAcJFdCLJTHU2t5YgZqM7cAbCXXWZf56qQMEyY7YgO0IyZP6aOMgvq
         NlD40XHI8Sbh5Xh6UXjshd73AxLXTZWg05Z8HZ7YL5LZcKB5oVhpLKLiXQUIBTpgzpKl
         sTio00ogfS2wCi53xkAx4yxRIT6GqsAdcLhqfAYFAizDWXUf9O1z3M1uLVI8LwMnDTpJ
         i4IydxXuA868P+a7L32PL2D8yVc0W+xxBtZFcJfN68IT21gT5dWHM+k5JauWUTgPgxND
         EGhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J8iayzDT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id y6si86421ljn.3.2021.02.03.07.11.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 07:11:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id m1so5587101wml.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 07:11:01 -0800 (PST)
X-Received: by 2002:a1c:107:: with SMTP id 7mr1939842wmb.28.1612365060776;
        Wed, 03 Feb 2021 07:11:00 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:b1de:c7d:30ce:1840])
        by smtp.gmail.com with ESMTPSA id i6sm3730145wrs.71.2021.02.03.07.10.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 07:10:59 -0800 (PST)
Date: Wed, 3 Feb 2021 16:10:53 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 07/12] kasan, mm: remove krealloc side-effect
Message-ID: <YBq8/e0iUpUFMhvO@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <884e37ddff31b671725f4d83106111c7dcf8fb9b.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <884e37ddff31b671725f4d83106111c7dcf8fb9b.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J8iayzDT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as
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

On Mon, Feb 01, 2021 at 08:43PM +0100, Andrey Konovalov wrote:
> Currently, if krealloc() is called on a freed object with KASAN enabled,
> it allocates and returns a new object, but doesn't copy any memory from
> the old one as ksize() returns 0. This makes a caller believe that
> krealloc() succeeded (KASAN report is printed though).
>
> This patch adds an accessibility check into __do_krealloc(). If the check
> fails, krealloc() returns NULL. This check duplicates the one in ksize();
> this is fixed in the following patch.

I think "side-effect" is ambiguous, because either way behaviour of
krealloc differs from a kernel with KASAN disabled. Something like
"kasan, mm: fail krealloc on already freed object" perhaps?

> This patch also adds a KASAN-KUnit test to check krealloc() behaviour
> when it's called on a freed object.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 20 ++++++++++++++++++++
>  mm/slab_common.c |  3 +++
>  2 files changed, 23 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 2bb52853f341..61bc894d9f7e 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -359,6 +359,25 @@ static void krealloc_pagealloc_less_oob(struct kunit *test)
>  					KMALLOC_MAX_CACHE_SIZE + 201);
>  }
>  
> +/*
> + * Check that krealloc() detects a use-after-free, returns NULL,
> + * and doesn't unpoison the freed object.
> + */
> +static void krealloc_uaf(struct kunit *test)
> +{
> +	char *ptr1, *ptr2;
> +	int size1 = 201;
> +	int size2 = 235;
> +
> +	ptr1 = kmalloc(size1, GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> +	kfree(ptr1);
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
> +	KUNIT_ASSERT_PTR_EQ(test, (void *)ptr2, NULL);
> +	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
> +}
> +
>  static void kmalloc_oob_16(struct kunit *test)
>  {
>  	struct {
> @@ -1056,6 +1075,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(krealloc_less_oob),
>  	KUNIT_CASE(krealloc_pagealloc_more_oob),
>  	KUNIT_CASE(krealloc_pagealloc_less_oob),
> +	KUNIT_CASE(krealloc_uaf),
>  	KUNIT_CASE(kmalloc_oob_16),
>  	KUNIT_CASE(kmalloc_uaf_16),
>  	KUNIT_CASE(kmalloc_oob_in_memset),
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 39d1a8ff9bb8..dad70239b54c 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1140,6 +1140,9 @@ static __always_inline void *__do_krealloc(const void *p, size_t new_size,
>  	void *ret;
>  	size_t ks;
>  
> +	if (likely(!ZERO_OR_NULL_PTR(p)) && !kasan_check_byte(p))
> +		return NULL;
> +
>  	ks = ksize(p);
>  
>  	if (ks >= new_size) {
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBq8/e0iUpUFMhvO%40elver.google.com.
