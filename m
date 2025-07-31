Return-Path: <kasan-dev+bncBCQYJOPHAQILZZNMYQDBUBFQ7MTEU@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C6A4B16E22
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 11:09:18 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3b79629bd88sf117029f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 02:09:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753952957; cv=pass;
        d=google.com; s=arc-20240605;
        b=aVxbKgSlIG+0SmrpGzHXK/r285lX6BIsIUgi+bQGl70PLZP6bkIMyRPxo05klbhNTw
         M6+AJapwuMKenuSDJXkIKgU3mskahGTq9WGB3sqi5zIsH4lj2jQ0P6AX6rfyg+HlznwU
         L7FWz5NP+/yrhEGEVT3k52MhcYM2lY1f3nzurxQSR5RDNiTDb+QoN1fq/tcSeitjvOng
         exE/K6+YGpJwrWIq9b5el3Oomk/P2oyNTEjNq0qfwrrhZrMMKwnwv3ovX2aQ2NWk137w
         juhS8eW0PnSBWA+HEwHwQ+NTJgQ+KRbS8iO7EXtmjRJltcbRNkh+iBNbGjWchf6f7FaA
         lVjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+XskTWN5y7mEahnVxV05GIglPmybH1id+c8MqK5eXBw=;
        fh=ogbySL5tmwO5FBmMqHu9o9dV6A0AAZdjStyNPrsN3Cc=;
        b=SuBvoxL2fcc5QB71BZ4g1wWeDszxWW67pbk/74P2rbJqu/5bFWkC6xgbMFlym1pvxC
         jMJjH5YPJJCHGGx3dW+c7Redd1FHxD4eV/NMTriDWghOa8xmkp3NLxlK4oCqwuty2Scm
         lgFSRnOJR3NEZCeUaRnwXO2/ky5zI8akLz2aYzl6AWHzJKTEnpF5C3Hi8PzJNZHY3PHa
         Z+j7OjzNbvCSZUwNLAu0Wa1nmH9wvcGJ98LNxXmn9KvgK5tNrMVHLRN5ruT3NTpHurVD
         Op8jxGw9TZ1LBdPvk8Bo3RXhhxEnGgqcDaWtTysKZEn+rEI/JUufHr7+mTRF1K6RL3pi
         ouYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=rvtxKfq+;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=t-8ch@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753952957; x=1754557757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+XskTWN5y7mEahnVxV05GIglPmybH1id+c8MqK5eXBw=;
        b=LybF2EtF8C7w/cyMk4ZrE1dDhdVEAuOoz9oPsq8nba2TBbh1OENnLGPYC22u2vkM/Q
         j8xz92naRRnVk7Hu6WlpDBmWW1LjStOMK332m0HBw+oW2VGW48sehS5E3ZrzQPK+gk2Z
         1s8Ai2QMBBTFc2pOKI3Mt894BqBMKLYBw2xwfK35kXkMzBa+4UwiuqJ2we9ager5Orla
         7L+vSw9H0IKsJioLUROBZ71DzPfAWzzTTYx/oWulOikisQVBuarYAer10h1pU542+Jec
         UknzM1szwiRk6fgajqRgHKWEHPLRVtc3VUZerDHeRJmniOVkiBC7yb8iG8ckCP8r5qzL
         syxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753952957; x=1754557757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+XskTWN5y7mEahnVxV05GIglPmybH1id+c8MqK5eXBw=;
        b=gpvXYjPuVRNNX1orNXFVAvrET4K+F9HbSsb4nydpAhuZE1KRIhbT/5d0d+q7sSaHDi
         h0xfMl8x9ZMhJBY7JkSICiTGvzhiIkw3Dpb9D9lMBT1HuHwIEiUvkD26ki7eJkK2rWkE
         M2P5SEKLHEn/olSv4Ib8k7KVOJ3V+a3vGplTQ/05lljR9ciaJpi6fOnb0ypqJrItSvhb
         jkjmujgNBChU0lY2rdNuu64mk5qef74/8UmMqfXkyW4GvkAZ0myBfehstp1iFB/sAgg5
         Qv2uTIwlR3P8qOL6nnSUe5ph++i+lWq5yh9KNdEOlnujeBuZxc5jNRf/h3UH05VKgW+0
         n+3g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUthyANNziQfM+1fRaHePJtBggoabiQfc6n2hGmDOlqPlNiQF2a31XpqAO5aFXe8j1roxtd9Q==@lfdr.de
X-Gm-Message-State: AOJu0YzfkJXRDoueVhMAtcvru/cAhQvX4ZMaSvWgYyt6luI3+z+8JyMj
	xhTDIGo2QIoCPEZbMUAJO2H910+BBKQ5iXLMUSLSUhpDt4LGu97LLrjB
X-Google-Smtp-Source: AGHT+IFSSdW90idOO1UFtjKvuM+Mo8jWgPEGxgjU1MQaMTAXptTNSuYg6kBOHT0PQoJw3QN41ccPxg==
X-Received: by 2002:a05:6000:1788:b0:3b7:9af4:9c75 with SMTP id ffacd0b85a97d-3b79af49ce5mr2252191f8f.30.1753952957180;
        Thu, 31 Jul 2025 02:09:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcuesW696yNamwpN8rpfVJYshlaene7Nfcl593uVxexMw==
Received: by 2002:a05:6000:400d:b0:3b7:8a12:d1ef with SMTP id
 ffacd0b85a97d-3b79c4068cels222642f8f.1.-pod-prod-06-eu; Thu, 31 Jul 2025
 02:09:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLKQKFTSHUXlwRzabxqmrpeAcBlFjMAvqGnCAcSZq29je0blUGyPrHUr1UO2sKJJY1ECyRm6BOCXA=@googlegroups.com
X-Received: by 2002:a5d:4ec6:0:b0:3b7:8d70:ed05 with SMTP id ffacd0b85a97d-3b794fb587fmr4681904f8f.5.1753952954412;
        Thu, 31 Jul 2025 02:09:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753952954; cv=none;
        d=google.com; s=arc-20240605;
        b=L23SgdiBZPWmSfcq5DPWmG1QgRdLY3g14EnYyYm7XGu3JjHHNaxZt+lK8CGJeKaN/v
         dq+nK0WurCt1K3gpYhKBFyr+GAmRXlvY0ED/d7jfo9PTgLdJuRCEd4PSiUrT1ZC0LRtG
         19XszXc2D0bDDRpqEHskCqV+nJKZOBm+xgvEvatL1RWu4uvRCoXBftEiOXkKmyJQjYFF
         gx5a+izRSFHwY0be94pcFA/uZC86P6Ra9ludmULaN5TVkoItAiUMpAyWJV/qeFpWVE4z
         7YJb1vsXM5qmkg0UA3jyh1CfT9e0Ith2LDrNv7MauSoEeBzt+h8Cn6iXi3RU/iVXFmAY
         52+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=c+e/K9Hj4Zr7iR3DYQKSK1puSA9rY8qyq7/7F17Bvos=;
        fh=XQIM03cM5vRfQUaTYiZlU3vNX1GZFFIMxQz2Y+AaHKo=;
        b=efGnNfpRAnrhQsk3DZ1dRZKE3L5Z7TImO0hyjBQgFz7YC7VH16zZAQsqAOO1PTtjiN
         E+u7b2ntJUuhpTwobdqw8au1/0y77Si1DX5LRHEBi5D7/X465B1tAh5aMZWNX5pvTugJ
         LQBWdOBtkTO4WpeEnG8CSD6QxZ+uA0q+OZJ6C/STQu2qpXKq+YhbLQydw58T4Sclki7F
         tKhD8kOzbxbyc9VTCgz13cURc0TRO8ckoC9I9pXiF18mqMXMPbhanqV/WMhoGmhaiWy9
         B0i+i2UsHz3YqTgP5oH7vFzwFJNY+hj8oSfJcjFrt5Cnvi87V/FiFlNRKeRt+H463OwE
         /GPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=rvtxKfq+;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=t-8ch@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with UTF8SMTPS id ffacd0b85a97d-3b79c48d27dsi30853f8f.8.2025.07.31.02.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Jul 2025 02:09:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Thu, 31 Jul 2025 11:09:08 +0200
From: Thomas =?utf-8?Q?Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: disable kasan_strings() kunit test when
 CONFIG_FORTIFY_SOURCE enabled
Message-ID: <20250731110823-9224fbee-6d66-4029-9e92-19447cbcda64@linutronix.de>
References: <20250731090246.887442-1-yeoreum.yun@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250731090246.887442-1-yeoreum.yun@arm.com>
X-Original-Sender: t-8ch@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=rvtxKfq+;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 t-8ch@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=t-8ch@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Thu, Jul 31, 2025 at 10:02:46AM +0100, Yeoreum Yun wrote:
> When CONFIG_FORTIFY_SOURCE is enabled, invalid access from source
> triggers __fortify_panic() which kills running task.
> 
> This makes failured of kasan_strings() kunit testcase since the
> kunit-try-cacth kthread running kasan_string() dies before checking the
> fault.
> 
> To address this, skip kasan_strings() kunit test when
> CONFIG_FORTIFY_SOURCE is enabled.
> 
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---
>  mm/kasan/kasan_test_c.c | 6 ++++++
>  1 file changed, 6 insertions(+)
> 
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 5f922dd38ffa..1577d3edabb4 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1576,6 +1576,12 @@ static void kasan_strings(struct kunit *test)
>  	 */
>  	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);
> 
> +	/*
> +	 * Harden common str/mem functions kills the kunit-try-catch thread
> +	 * before checking the fault.
> +	 */
> +	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_FORTIFY_SOURCE);

Would it be enough to enable -D__NO_FORTIFY for the whole of kasan_test_c.c?

> +
>  	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> 
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731110823-9224fbee-6d66-4029-9e92-19447cbcda64%40linutronix.de.
