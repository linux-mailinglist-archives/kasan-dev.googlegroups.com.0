Return-Path: <kasan-dev+bncBDAZZCVNSYPBBTMFTL3AKGQEVY3HPFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 29C981DCE0A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:31:58 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id dm14sf7138610qvb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:31:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590067917; cv=pass;
        d=google.com; s=arc-20160816;
        b=m3bA6dG21gTzNa5sBo+PntvyfNubsLNgZNWsqQiStUGctY04DpsbpYwoNu6qIJm0NF
         z7WUoboiO7EO097YFsOk/OL22YtnsBGBIwiU1jmtN1af2ilaGKG5+QljWHEp/fYTB1Ai
         enGIvjFLFvbVkFNyHdPE5FBfW7pYENHdiJVLhBS6u6tX5aMQybE7HQd3gLhrTcwlAGEH
         u9jBXioQTS2PQqmxvX3Ut2aUlm5e5zRU6dn1L9IsyEnMVK3/SP0Iq2EfyFKWJds69ctB
         sCJHyRkiT9FVKd5o8Fs7KMTUQP6ZR0IQCT9e4ospKcYX+cpKlxwNHc2JMg7d0vfgHG5L
         DfiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=JBc9QYzMwy6QirHGI7fEhuu37tfjveMq/xgMQIp+wRk=;
        b=k4lZyJ6cn2LG56NzWPhS60N/QVy6VGAqILRS1zE2KujDAxUVcZwBximNsfc6t4dpm0
         QXpFcM+6YqXOBWHXTH4IgVb/OW0zIkHf84pF4fmD39IQ2PZtWsh5iG/F7fgkdWLMZ4Hf
         fWpHyrHHklcwRoBCX7er9lUsLv7C9Urs5HEk7T36KCNqXha82rzRs7PuNdTUJY4qCY/t
         3KrC5ackRm7KVx6PgukTKLVdlJo8TWz43uf2npZ2c/W9juiqyRMbKdopqIeGrTvKYdq9
         VrnBjpr2sNZA7r29ai5+07Ws0RqrYWcSbElHqwLyn8onMlAy5eivSW5U5NTdfTfRXn0o
         +reA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=GtKd6Mpi;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JBc9QYzMwy6QirHGI7fEhuu37tfjveMq/xgMQIp+wRk=;
        b=m+xFAeGGQ3CYj1NGcHgXttZ/tVQG2UD9jTMIgMRbiksDg3uXHlBVg0oGZ687GT8ygM
         nUL96IGHTppQFmANMs5GXch3KMFcDr3kPt+98CG5qGanFctZupmoyTkQXewBxWNTrDvu
         oE7BJqaRqakoZ8ExY+zn6zeuivFRKwc0ew/FqBIMusJVowhzQ4I8pSg2vxeHIqJGcBs+
         nM3JSicgGTJ9YMfG6Gzu3bqKlg3EmJfskuT3tXTiHVyOznYnca2S1eTr9p6MGSLprTE7
         3PiSbLgQRb3JrSsEZhp/2IiWKHZ4gZZl+uP+cKVsvnw8kuPCA5O0h+Fcetv42bcfpM6B
         nheg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JBc9QYzMwy6QirHGI7fEhuu37tfjveMq/xgMQIp+wRk=;
        b=UEOOW1lgdGKN2daW+1cB1kq+HTeg1RR4dTEB1McMOJZC7gWi4PpnqYljSy0GvPc9Ze
         UyeK5bL8LRkNNGL437wcHo5Fxo+YWYHKFYJ09p7VmTRhp7aMp2mmpSWxaL2Oq9v4s1IV
         e7EOb4SP265LsITDhaVBDh0/pxDxRNw3WS9QRieQNFrWEb3yGVa7Km3UA29JEEYTK0Sz
         EtIPypndpYz9i7vW9q1H8GJTFACth08mwHwTfDb08vg+OAuyD5bCsT3jaXOsNXZOvaH6
         McgJNN2ua6+bI19JQpUuSM7lCgRWUa4cHdyMQUE7+ulvjbPatoDV6n4s/SqwpmmdJw8T
         qBeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cscxQfxlUWovDyJ9duOY8goiI+jg9jTFJt3O3kVyJNHj9VgdX
	sTO3u6D5hTxl6rjp7Jkb8mU=
X-Google-Smtp-Source: ABdhPJwqLGm9ziMJD/yDu9AV/D0M3Xj6sgkmWAycaMyLOdcGwbsINgWmuqs1LfrjJ4A6iffhi5m7ZA==
X-Received: by 2002:ac8:fb5:: with SMTP id b50mr10519049qtk.164.1590067917249;
        Thu, 21 May 2020 06:31:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b85:: with SMTP id 127ls617072qkl.6.gmail; Thu, 21 May
 2020 06:31:56 -0700 (PDT)
X-Received: by 2002:ae9:f214:: with SMTP id m20mr9885144qkg.232.1590067916671;
        Thu, 21 May 2020 06:31:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590067916; cv=none;
        d=google.com; s=arc-20160816;
        b=Y+45QNi65ufGdXYmZWRRiFqKeZff8DLI75aaAWSBTaQL1KSuL49WsABZsNed2UYRl/
         JV7s8bKe27SajjJEvyOsedtaPHeGU8VV5JRcJztIiPagxgefSa7obYI29kfNGceKaxeV
         UVF0x1mI1WqHYryw/hksvW2r/kI7Y9/kU1E88kpIbVMsNXtrVu00tjSphxxRcyqO6GJr
         6roBUo10lvkIzCCod51UY2Y0KBGOe7n9N6xV70jJbf5CpsZRJPUfKLXq3OHqdT2dBIvX
         JlErO91gCdO+Vm3HlFQenC0HexlfoZRbU5f1vQ27T6l4rwr/PFT4MVZ3/nlev4xNRUsw
         aBSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Y9oT5LJ56sVLWLUeDHVQXC+f3+Bd0ET3FwdKC0MDxtc=;
        b=ehMbGA8ZnaF8FCJdtfFhhwhhiNY8Byxc/e60qtElg2edkPXO9EVD4v3PVSaV4IPcPE
         HSP/bYNF5iqTfqe0Rvu3Q3fkT9msvjuvnX+TK7VxNRWZXLFzuYgci8NaiwCnrxu7MNjK
         GQJ928PpibrBFBa/8z9vXs+4UUjvU9WXE3d7Y9YsZUcGKaa7adyxO4gGcXfZNKkhqZmv
         ovFWsL8y/kfrgd131HNdPk65rxGxcOHgovuU3bHzCJdgEgRWy9rR+7tOGoECrI3TGMEn
         WpWOtuUHILSYHtCxVGs2I1tTOaocWkMFOhRUYbR0j7wcWmdTnZ8HzLVKcmqAQB28v//z
         wlcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=GtKd6Mpi;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w66si406176qka.6.2020.05.21.06.31.56
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 May 2020 06:31:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8EBBB206BE;
	Thu, 21 May 2020 13:31:53 +0000 (UTC)
Date: Thu, 21 May 2020 14:31:50 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org,
	peterz@infradead.org, clang-built-linux@googlegroups.com,
	bp@alien8.de
Subject: Re: [PATCH -tip v2 09/11] data_race: Avoid nested statement
 expression
Message-ID: <20200521133150.GB6608@willie-the-truck>
References: <20200521110854.114437-1-elver@google.com>
 <20200521110854.114437-10-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200521110854.114437-10-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=GtKd6Mpi;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, May 21, 2020 at 01:08:52PM +0200, Marco Elver wrote:
> It appears that compilers have trouble with nested statements
> expressions, as such make the data_race() macro be only a single
> statement expression. This will help us avoid potential problems in
> future as its usage increases.
> 
> Link: https://lkml.kernel.org/r/20200520221712.GA21166@zn.tnic
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Add patch to series in response to above linked discussion.
> ---
>  include/linux/compiler.h | 9 ++++-----
>  1 file changed, 4 insertions(+), 5 deletions(-)
> 
> diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> index 7444f026eead..1f9bd9f35368 100644
> --- a/include/linux/compiler.h
> +++ b/include/linux/compiler.h
> @@ -211,12 +211,11 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
>   */
>  #define data_race(expr)							\
>  ({									\
> +	__unqual_scalar_typeof(({ expr; })) __v;			\
>  	__kcsan_disable_current();					\
> -	({								\
> -		__unqual_scalar_typeof(({ expr; })) __v = ({ expr; });	\
> -		__kcsan_enable_current();				\
> -		__v;							\
> -	});								\
> +	__v = ({ expr; });						\
> +	__kcsan_enable_current();					\
> +	__v;								\

Hopefully it doesn't matter, but this will run into issues with 'const'
non-scalar expressions.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521133150.GB6608%40willie-the-truck.
