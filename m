Return-Path: <kasan-dev+bncBCZP5TXROEIKZIMUZMDBUBASM2QSG@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2EB3D13937
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:18:06 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-3fdac464300sf6683872fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:18:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231085; cv=pass;
        d=google.com; s=arc-20240605;
        b=fhymg7fRiLtpYs5OmlByW2E8/ulsXIgrBbskIz0N6/mCSXWr1ffdxPe5waBOcuwibb
         5R9ndXZpe5z2iI/zzPSudjDkP50Jt/Ua5b5uKGCduNepdlS+xyaD657cOfCZUjVUk7aP
         bt6x0GWURK7mktjOGCy975EV2BZgWZ6zCGobt3apoykgT91cWUElsImcVgJN1VF7ZDpt
         yYo4B/fPz1QwxFyp3LIc0LgqWoVq1nvejW3DM8HcusW7lu+t7XZ+VLAEZLQ9gyx3Ize0
         5OHl/QZuQutl8zMxgqMXN+xR8p9BGLL8xzv9BeENlblVRSG0hr3Se11QDh5SFHLZ5fDl
         5FFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=kqA3K29zQwG3mkryUoMMAxAD++sWfHA9WtBuQ1Q+q/M=;
        fh=MbfJ3k+DfsKgVSWKQWcUWQdaEa3HQjfphImwDY7Qgz8=;
        b=dDSjkxVbUiGCq+2HDQMup2ejKVp0TG66242MJLaufTd3dgBTz4Hy9MBKwudV+5mpeu
         qNxn+8F2Jb1ivFjdd98NMQzn40586+Hhfb6Z8a1pVAwR9EJpFyEC0Q4r3xBTVJdAUQL0
         xosIkrmnxJi7hucdvPJdPU1A1lcnG2PxzIpApxbYWg2GdIK0Fs6V+kpqELMWPZuv5ym6
         q8Kfn27E1yT6giWYR2oADAGey47jLWH0HrSCiWI6DVum3fR7/gkMbB/RCLRSrdvh/74w
         lXxn0izdRJS2Etv/SuRFK2RIdE8cXeWyDbMbQCRuLmYHeshwbuOz+CMk+QKDFCPHTQsk
         Enbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231085; x=1768835885; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kqA3K29zQwG3mkryUoMMAxAD++sWfHA9WtBuQ1Q+q/M=;
        b=EILkdctaOwTj4S7rXmh5U3D61EfTcAqmWnCUH9p110NIhutKu3XbTbh3W6wp5tIekF
         k7akMD9GfnPW4SW60a5vChxV/AvOfTN23SqHEzxF1muzWh+jlNTGxSdeuvKgLZetk/FG
         VnEslkEqvU7wWMMO2XfL8vwjhhb/qEsx+sbWl5yYj8008zLGbOzymB58oxXvpsocN/p4
         0Y403DktiJfDxVi8Nvuoht/DALJvNbTMbSmHyqSv4qdjPYlVWYTZG94l6HmL3ZfksbAx
         ghHTi0a9GW2Bke/1UR4Y7w2bN4oybJMeG2yA8rHst/Vwo2imYqVl+eNf3dZoFlpSWP2/
         G3sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231085; x=1768835885;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kqA3K29zQwG3mkryUoMMAxAD++sWfHA9WtBuQ1Q+q/M=;
        b=As9mQcAwqRIx6ZGM6y0gSTXG0XaK3qCOZiMBSqAuI2Nsp3nBSp+NOq6sQliQtqIvqk
         1hdC8ThLkHgVElVbnlOPtxJ64Isn8HV6ph9nPbLi5jYnfGG4xfdsKt8jo12D+DfeP+2v
         k+WrogyV7Iv0KsQuz7MnkzSIDCRIiIzABuVMIQo5G8LFxRuwZXRsLVu492C4G1wRkQnh
         U1ALDKNtxqPWCIRUHNBfGyqTJ7TXVBNm39GJWpMr6YtGxmRbHkktX/83LtMLJsbsgh26
         FTXZd7LSPcoaE5GsKMUnyIQlAnynY3htZtFYfy5TUFb3Pz/GV65bkQA7WqCnI7D+C3Mr
         HXBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWoqrfeJnR/6MRls6M2M9hnknnQnb6Nr5bxpygBwLphF7/B+vAAMly8bPRfRh6Sdcr6UypPRQ==@lfdr.de
X-Gm-Message-State: AOJu0YxBJmXapD250JsLkaKRfpiHBU0ON/9OvbMy/VXI/XctJ/PLlbgd
	/hGz4biaLrllxWo+MFNYgFJr5sqOitq+P+sV1xEhYsqXpTBhwrzY9a7g
X-Google-Smtp-Source: AGHT+IFukgq0LjCrntghG/g4jDbSdPgxX3oTXFJ2mMZDs3tjh0dmWATHtw9tKdyWZNWFhIoRkJESIg==
X-Received: by 2002:a05:6870:70a7:b0:3ec:2fd9:7657 with SMTP id 586e51a60fabf-3ffc0980717mr8002061fac.12.1768231084997;
        Mon, 12 Jan 2026 07:18:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EgPhO2rH28P6snLf+MCZ/Odg51kDW97VPgmxORa05Jkg=="
Received: by 2002:a05:687c:4a:20b0:3fd:9a1d:4743 with SMTP id
 586e51a60fabf-3ff9dd1e5a3ls2538336fac.2.-pod-prod-02-us; Mon, 12 Jan 2026
 07:18:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX4jpQ0W9HhFaQ1yhEN8KCDjSMXizpOcQzwMaPJ+JyApdzeQscaaMbq0Lc//UsmnuRgoQp4KUNwaAk=@googlegroups.com
X-Received: by 2002:a05:6870:1687:b0:3f5:4172:220 with SMTP id 586e51a60fabf-3ffc0c51b14mr8924312fac.59.1768231083927;
        Mon, 12 Jan 2026 07:18:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231083; cv=none;
        d=google.com; s=arc-20240605;
        b=BNGc7daM9r8mdgYKwjsntz+LoitJD3aUdWjUOeKx9WB0jbrMXdn3jqsgUvybQhMkFJ
         m+YZa8AIrJDuL8dwiSKos38DOBJ1p7Gmgl15HjMdqyXR+x20DXEkX5cZ9t3+Yms6Fct2
         KIkAPmPeNlo75c6x7mvucDjKS3NYP1Po8+PuEsKDAcP7rfS9VgtD1wBH8Vbsa6otBolk
         qMf8d9s/45QnC+dCwesGiq4B+LgQnoEC0QhPiotkTBzBLm1KWDsimuRTjoDMSa1nMNC+
         J3muarYzp/Bda3YMyPNCTTdyuTxirFY/bFMqlydQydEI9FNJ0XVpMakH71JpComXspJA
         Ve/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=IG9ja2+bxsL/bb2xoXNKNEkZ4+2cAFzoZkTz7V/9QxQ=;
        fh=WhYBIDcTjwc27+GqwYQiS/yQ9Aq2lqGShGL7PrqJTWQ=;
        b=OwDpGN2KNpZ4qVolLqhH3IlOm4l2qUPZJnGT95tHeV5n1tayYayuJNEUeJwLfD+Tsi
         PeU6dixvgjVKqQTqiKm1YpTtgdM+/6k44r5MBOAiG2bfyPMbYRW1LXO1AVpF8MThuCRi
         AHsEfudylqCk7G9NCNzwI7ZPc4vg5SdplRd9HwmdQGcLHHdrpEtDhw3gOxFojQfhxdNV
         +BIsu7MolMS7+YR/dHhAjgXrqdvSDTJde6o/bRwpQusbSKoPRuIAqM1Nl/SJFIY9z9FM
         vyilHZI7VB1W1oyyYHxyg1tZwWm3K2MSgxEV6OKjjO76MtILTmG7p/uXddMY4ofPt/yT
         pqNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-3ffa6dddb3csi586890fac.3.2026.01.12.07.18.03
        for <kasan-dev@googlegroups.com>;
        Mon, 12 Jan 2026 07:18:03 -0800 (PST)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 877E7497;
	Mon, 12 Jan 2026 07:17:56 -0800 (PST)
Received: from [10.57.95.123] (unknown [10.57.95.123])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2B6053F694;
	Mon, 12 Jan 2026 07:18:02 -0800 (PST)
Message-ID: <aa38c43c-0907-4b49-8e76-a2ade35089cd@arm.com>
Date: Mon, 12 Jan 2026 15:18:00 +0000
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1] mm: kmsan: add tests for high-order page freeing
Content-Language: en-GB
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, elver@google.com, dvyukov@google.com,
 kasan-dev@googlegroups.com
References: <20260112145150.3259084-1-glider@google.com>
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <20260112145150.3259084-1-glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 12/01/2026 14:51, Alexander Potapenko wrote:
> Add regression tests to verify that KMSAN correctly poisons the full memory
> range when freeing pages.
> 
> Specifically, verify that accessing the tail pages of a high-order
> non-compound allocation triggers a use-after-free report. This ensures
> that the fix "mm: kmsan: Fix poisoning of high-order non-compound pages"
> is working as expected.
> 
> Also add a test for standard order-0 pages for completeness.
> 
> Link: https://lore.kernel.org/all/20260104134348.3544298-1-ryan.roberts@arm.com/
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/kmsan/kmsan_test.c | 48 ++++++++++++++++++++++++++++++++++++++++++-
>  1 file changed, 47 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 902ec48b1e3e6..25cfba0db2cfb 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -361,7 +361,7 @@ static void test_init_vmalloc(struct kunit *test)
>  	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>  
> -/* Test case: ensure that use-after-free reporting works. */
> +/* Test case: ensure that use-after-free reporting works for kmalloc. */
>  static void test_uaf(struct kunit *test)
>  {
>  	EXPECTATION_USE_AFTER_FREE(expect);
> @@ -378,6 +378,50 @@ static void test_uaf(struct kunit *test)
>  	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>  
> +/* Test case: ensure that use-after-free reporting works for freed pages. */
> +static void test_uaf_pages(struct kunit *test)
> +{
> +	EXPECTATION_USE_AFTER_FREE(expect);
> +	const int order = 0;
> +	volatile char value;
> +	struct page *page;
> +	volatile char *var;
> +
> +	kunit_info(test, "use-after-free on a freed page (UMR report)\n");
> +
> +	/* Memory is initialized up until __free_pages() thanks to __GFP_ZERO. */
> +	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
> +	var = page_address(page);
> +	__free_pages(page, order);
> +
> +	/* Copy the invalid value before checking it. */
> +	value = var[3];
> +	USE(value);
> +	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> +}
> +
> +/* Test case: ensure that use-after-free reporting works for alloc_pages. */
> +static void test_uaf_high_order_pages(struct kunit *test)
> +{
> +	EXPECTATION_USE_AFTER_FREE(expect);
> +	const int order = 1;
> +	volatile char value;
> +	struct page *page;
> +	volatile char *var;
> +
> +	kunit_info(test,
> +		   "use-after-free on a freed high-order page (UMR report)\n");
> +
> +	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
> +	var = page_address(page) + PAGE_SIZE;
> +	__free_pages(page, order);
> +
> +	/* Copy the invalid value before checking it. */
> +	value = var[3];
> +	USE(value);
> +	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> +}

test_uaf_pages() and test_uaf_high_order_pages() are the same except for the
value of order. Does it make sense to create a single parameterized helper that
gets called from the 2 tests wrappers?

Functionally looks correct though, so either way, feel free to add:

Reviewed-by: Ryan Roberts <ryan.roberts@arm.com>

> +
>  /*
>   * Test case: ensure that uninitialized values are propagated through per-CPU
>   * memory.
> @@ -683,6 +727,8 @@ static struct kunit_case kmsan_test_cases[] = {
>  	KUNIT_CASE(test_init_kmsan_vmap_vunmap),
>  	KUNIT_CASE(test_init_vmalloc),
>  	KUNIT_CASE(test_uaf),
> +	KUNIT_CASE(test_uaf_pages),
> +	KUNIT_CASE(test_uaf_high_order_pages),
>  	KUNIT_CASE(test_percpu_propagate),
>  	KUNIT_CASE(test_printk),
>  	KUNIT_CASE(test_init_memcpy),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aa38c43c-0907-4b49-8e76-a2ade35089cd%40arm.com.
