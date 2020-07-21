Return-Path: <kasan-dev+bncBCV5TUXXRUIBBH7O3P4AKGQELAPS6UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 107602281A7
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 16:09:36 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id b13sf1277502wme.9
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 07:09:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595340575; cv=pass;
        d=google.com; s=arc-20160816;
        b=ncFp1h8fQAPWYH+SBqAaeeY5e2HZBL8zCfpF9Zf9JRgIvLUSJdWOkpXz8bq089ZTlX
         QPkbtcJ2JjL9EDYcJxBpi9A+uxzgs4AFxNZPYVXZBTK2Q1KX4uE44uAo8IyY2hsSFqD7
         nKKn9fzbVikdC0vjq7TTDUdpI+VZKUy+T/8IKP1kE6aWGL5mSsXSyMROlxYCvPQ+WaWP
         LIssJ4I16ROODPxgd81nVTTWSNChQo2qrvKjW4QbYtB0/NNA7mrJzeGhDdtcI2mNMUF6
         /EyO0scbfM66/kvHDkdP16xeJiJdTXtexiPschYI71/Swfgo8RMZJ1zdop2rr1nblPRK
         SVbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hA/HRtyyuv/zUT2XLpiu+ib8Ju33vaV+IiBKeItpalA=;
        b=jdcY+1pF9h5qglCMijq6o35n3sXFob0RC3UTcW/BL5JSS2UyIbhYmVdUmcnl95Fi9l
         XkcFJmYMeky1Dc16TgisqqDV01r3MZWJrRswczE/bpjrT5nDXcvlM7kt5OriTge16xXl
         aafA+44KxrjjCcO8t5hoWr1x3P8ztvbgk1lzSu3HGTwkZLZCcaQ2yPiLFitXTLV8Gj49
         mLjzkkJXpucLWFB/Ab2PMjDkz/TxW2iZHjmWECmo6JdhPYjDFR7BVXqapdinWv2OMAlw
         KsQJG3LMmkqfA5rz8oIyBaVNNeWIFViHMTmO6gVS6JFvWt3UcdoacQC/hQ+tFq41oLMO
         ++UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DG5AbKr2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hA/HRtyyuv/zUT2XLpiu+ib8Ju33vaV+IiBKeItpalA=;
        b=dff+k2jPaT5mk7iQuLS4M7BRRrQKVwPawz9LFo4yDyicSCIzPmbqLAHk7zGrdvbIk9
         ApNJ24vVEVWjyhDkZ372dA5jfUCnKZTv0Hi398QHUuqbe/OS84aeS3A+dy3+JB7B8sLT
         vcqI4ibvc6N0ljmEsc/KVk9ujsbwqLP9uB49hv0K/ABywV/mGEgvmkxQi3RTIF86UOeS
         haGCYNY4SRmDAp/xUx8+Kqjf1i1ikCLEKU+icB6hC2y9BfA4iPbZnLckdkxhIrkPljPH
         mJSwsp/6SiRRDQWsvuB6rW+JdQjZj34aIm4Yj3k9pv2kI3Eawx1Zow8OoFZy7LcSA674
         YC4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hA/HRtyyuv/zUT2XLpiu+ib8Ju33vaV+IiBKeItpalA=;
        b=DCrOptbR5cvr/Xvyefqg2tZjyp8OcUJmsuxdDngBT2mTIPFw1Rq2UC7Mn+Yfyj48wf
         ZSl7GgqToZpc8MzNVQbnZn9rxCGuuLXp/6hfcX4M1Q0kHvqFQ5d2HL/vhIM3MNwgzy92
         2bypxEQEBrUNl4+WvVz/xKUdEeR6gvsXfySEzVyQ/HoChRwQkmTLgRULyU53e1064wjV
         zLNUJ2GfZtQAod9m/d0Wn1Ovn5a+r3vB+VIXV1ldCuFkGD+gVk2dTOYd2HbTsUTaiV43
         17pfe8Pihd1/KpZVJI8casxBSE0WPpE2nVksqLPxYTFsWEof0afYjQP1yFNslUz+6YEX
         SaqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VMlLYgnHzTvFQeMx/56H5rhPsBy0s8m3aPEnBwF+j+o26lrp7
	DTP4g//sGxeaTnXsfjoJypE=
X-Google-Smtp-Source: ABdhPJyY0xq8nNdQgBBN2/aG23RLy4WZzVkQlRi+otn/dXM9BzGkxYtjF67/TUPbM9D7Ya24AhjMEQ==
X-Received: by 2002:adf:edd0:: with SMTP id v16mr7068387wro.271.1595340575634;
        Tue, 21 Jul 2020 07:09:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2049:: with SMTP id g70ls1368834wmg.0.gmail; Tue, 21 Jul
 2020 07:09:35 -0700 (PDT)
X-Received: by 2002:a1c:e405:: with SMTP id b5mr4554976wmh.54.1595340575174;
        Tue, 21 Jul 2020 07:09:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595340575; cv=none;
        d=google.com; s=arc-20160816;
        b=XWetPCoGUSLzxbAeyZdZPpTTKQiNDXjkUYZUZdzQymf72ZB5lZbTHelzsc+vkMNgh2
         GeM6PVkYZvNUziR7bBLWMGH7ucqSY0hKu5FVzBlcTu29IA+EYHnjHtisnzydrtaEecHf
         Mywz26CT8gDMu6gip8CmU5HO8gaM99Q9dlV5fjhrlsrbPocx8ZGcMSwWvBit1YXgTDjK
         CoIhQV+EOl5pYHccE4dmm564demkvfOEv6mrB1Rc6XtJwxRYMev0NPEmZ9yYGY949kMQ
         Dr4R5zNCdcEBBfNe8WPvjdonBB0xnjgwrInEos6964OwR1Z66bdMaMTREjnbXEnNyqfP
         IonQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bck5iFe0qNEfND6yPrfltx4XHg11WKlZZGgqWSXEbeM=;
        b=lRUB/hPQLKAPuH9to5abVtyWhoC7tekH3k6nkR8L7neMOZquuAF9QMKVpK18NBs9Fq
         Et5NQX1q7XRWRSWH/1QN2wi6uZ6RTPe6khmFfzMxUeNuKTRqTp7gHPaRfefn1/fEzAaK
         jWGQ77FkQSNh7ZNwdmxFjW1AxJWEweTSoRXWaNdisXw2l39rcQ3ORmc2QmLVqDpaEjgO
         Sn9/e0prgIMmcrhE6WO8s/Vm4dc+SViF5lyQnP7DhS4BwIxbqsQebLGoee0OVvFkayE5
         4eFK9YwFnV/BbHVfhih82EYpDZ6nFqilaQ0310uWZAdYCIb+PBuGPSuYcB82LuxzW7vl
         LmLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DG5AbKr2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id m3si138396wme.0.2020.07.21.07.09.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jul 2020 07:09:35 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jxsxW-0007Zu-U5; Tue, 21 Jul 2020 14:09:31 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 18E353011C6;
	Tue, 21 Jul 2020 16:09:30 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 03D43203C0597; Tue, 21 Jul 2020 16:09:29 +0200 (CEST)
Date: Tue, 21 Jul 2020 16:09:29 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, will@kernel.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 4/8] kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
Message-ID: <20200721140929.GB10769@hirez.programming.kicks-ass.net>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-5-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200721103016.3287832-5-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=DG5AbKr2;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jul 21, 2020 at 12:30:12PM +0200, Marco Elver wrote:
> Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks for the builtin atomics
> instrumentation.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Added to this series, as it would otherwise cause patch conflicts.
> ---
>  kernel/kcsan/core.c | 25 +++++++++++++++++--------
>  1 file changed, 17 insertions(+), 8 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 4633baebf84e..f53524ea0292 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -892,14 +892,17 @@ EXPORT_SYMBOL(__tsan_init);
>  	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
>  	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
>  	{                                                                                          \
> -		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);                      \
> +		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> +			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);              \
>  		return __atomic_load_n(ptr, memorder);                                             \
>  	}                                                                                          \
>  	EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
>  	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
>  	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
>  	{                                                                                          \
> -		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
> +		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> +			check_access(ptr, bits / BITS_PER_BYTE,                                    \
> +				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);                    \
>  		__atomic_store_n(ptr, v, memorder);                                                \
>  	}                                                                                          \
>  	EXPORT_SYMBOL(__tsan_atomic##bits##_store)
> @@ -908,8 +911,10 @@ EXPORT_SYMBOL(__tsan_init);
>  	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
>  	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
>  	{                                                                                          \
> -		check_access(ptr, bits / BITS_PER_BYTE,                                            \
> -			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
> +		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> +			check_access(ptr, bits / BITS_PER_BYTE,                                    \
> +				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> +					     KCSAN_ACCESS_ATOMIC);                                 \
>  		return __atomic_##op##suffix(ptr, v, memorder);                                    \
>  	}                                                                                          \
>  	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
> @@ -937,8 +942,10 @@ EXPORT_SYMBOL(__tsan_init);
>  	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
>  							      u##bits val, int mo, int fail_mo)    \
>  	{                                                                                          \
> -		check_access(ptr, bits / BITS_PER_BYTE,                                            \
> -			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
> +		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> +			check_access(ptr, bits / BITS_PER_BYTE,                                    \
> +				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> +					     KCSAN_ACCESS_ATOMIC);                                 \
>  		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
>  	}                                                                                          \
>  	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
> @@ -949,8 +956,10 @@ EXPORT_SYMBOL(__tsan_init);
>  	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
>  							   int mo, int fail_mo)                    \
>  	{                                                                                          \
> -		check_access(ptr, bits / BITS_PER_BYTE,                                            \
> -			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
> +		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))                                      \
> +			check_access(ptr, bits / BITS_PER_BYTE,                                    \
> +				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> +					     KCSAN_ACCESS_ATOMIC);                                 \
>  		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
>  		return exp;                                                                        \
>  	}                                                                                          \


*groan*, that could really do with a bucket of '{', '}'. Also, it is
inconsistent in style with the existing use in
DEFINE_TSAN_VOLATILE_READ_WRITE() where the define causes an early
return.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721140929.GB10769%40hirez.programming.kicks-ass.net.
