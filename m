Return-Path: <kasan-dev+bncBCJZRXGY5YJBBN7F3KEAMGQE5KRGERI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CD5C3EBBBC
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Aug 2021 19:58:16 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id n13-20020a5e8c0d0000b02905a890e11005sf5789440ioj.4
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Aug 2021 10:58:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628877495; cv=pass;
        d=google.com; s=arc-20160816;
        b=xI2kegeWhnr0xvOfVD8tITsAu4dbtH0AIC5zEiSgR8U9Tw0TU3pczO1FzraUMnY4SL
         kHoIM3igU9qcPHKKZ4dFQarzByGink4jfV6NnF1j9u61RpKT8tZ0iX1VNR1bgincqfMq
         abssEHDjFZqgAUTPQH155nb3E2sWf72bOq+MKIoEIJu9nGIm16aF5cYoQ8qTi4i0SXVs
         1oLZdpkSqHtKyOAQZvZOZYRbeHSX86X7Tm9PB0JpmQBNYqa4igUvcQzVBLl8dlM7bpwG
         8OBLRlo2ENV3tJL6GxOtk8AiJFd2Yj9tQ1rDkPAOWZE9THWAomnWU4pL1MbmbiTb2stv
         Be2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=z13O8VpG9eQ+PJJirZybrumYv/2eU/xqZwmGDLZ34fI=;
        b=pBUK3S6rbtwphJrgk4AiuGq3yHQY4m8iVyJ4wJ6AcjtHD+H6a6TiJHoj/NumQV+dFZ
         fzWCRaWOifuH0kCXN0XpEaRlqY0RUfwuKlZ9MWHyZL6MlxEjA7whl2377TQf9IgE+yLL
         uFF+QhNqvVcpWAOykuypCopbgOw45aK6XafmHLVhCrQBHcAvjU+U5NWWQiYVrza6F52e
         LNPQ+t1lYYYoC3ycHNrNUBAyTsF4cnsYW/UQXuYg/MsHn+zbn8t974H7muL4FO9RfB2O
         jaJw0qbJD/R1pJbbgRqDcjUE+fJSDWyUh8tlqZT9/wJb2kB9n8WFd8hXTM9CYl/P6wHi
         JM4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VBi6zU+6;
       spf=pass (google.com: domain of srs0=jdey=ne=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JdEy=NE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z13O8VpG9eQ+PJJirZybrumYv/2eU/xqZwmGDLZ34fI=;
        b=btlSRkYLCusfoYL8As1m0YOPcrx4wS/JkOuk0HN/q5fjgUjtGMtAHY0j+S+rY1w2wv
         odRzSk8PHgC/dZM+WFbfqgSwwdHpYAXNc/VT2+fe+wXRI5tuZJtDyc0jaxVq0PkcKOv6
         4UuOzZ6utokb5KEyFzIqW1kJWAjQsHLOTncCyGRk3xE3GWac4wZmcgWNaxWcy7L3GHCe
         hpHf8E0vo7nfcNktG474o6Twd5B3fDf20P3KavYYOkfi1QkwPMuWOcWvsA8okPOiGuxM
         7zlpL8XgxjnouvB+6YP/DHTUbS8JqO6/KvY/2S4ZHm/Hlofv+8HF9NylCsjfDh1Ac7o5
         ABrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z13O8VpG9eQ+PJJirZybrumYv/2eU/xqZwmGDLZ34fI=;
        b=Jw+ORCUo9dsxPNiJEMDkQSGyHLP1SxfbnXU3nfGq5AHx5zBsI6aJOIRZplLK+Q8aMu
         Tyr3D5ENeiHxY7bh2LHWaVtjkUjfWEjTjUhd3Vh55rsPmw+QWhx+KKILE/2VEAPw9l2m
         UPCAxTaA7P4YCJFFaEbvn2MKn/cwVHM9vKtXMjhVYgGJoOLexAxMhf9r87cwp1s2/HAn
         OsPYc5xqYS7WgibKJM9aaaHsI9m2oqJAc+6HkaRZpevNeZskeHzmQ2x4bKN26Eul9hV1
         ZrNpEsGTK6EjM9fDnkocLD786j3zDAeifB4cc5bUQTZ6CyV/wpsHHMcnuWpMzdQj8fGr
         v1FQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PQcby6vGlEvEDFugl3XXEoAIu2dXjXzo2V487is5pllMjW3+E
	cjo9hAcqVqZlP0nysewPhco=
X-Google-Smtp-Source: ABdhPJxdTA7jVMRKMG2kXXumTd1yLGBn1dJ7qk3+krhiRiL31HKaE1jQvvkyxHYzJUuNWXhCVzFZPw==
X-Received: by 2002:a92:c68a:: with SMTP id o10mr2597683ilg.163.1628877495122;
        Fri, 13 Aug 2021 10:58:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c83:: with SMTP id w3ls433816ill.9.gmail; Fri, 13
 Aug 2021 10:58:14 -0700 (PDT)
X-Received: by 2002:a92:7304:: with SMTP id o4mr2570882ilc.75.1628877494767;
        Fri, 13 Aug 2021 10:58:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628877494; cv=none;
        d=google.com; s=arc-20160816;
        b=hEbkF/qaWe+gynW50jvfh2OVltK4YiWhYxSJIYnWA6aS9/4zwpSV5bs2R5vTejKhEm
         GdZbTGzEkFhcZyhCwuxOiS3x9M66HHNRlGHdsR7bIOWIVCUgpE7YKqJOpTflpcoDQmoO
         gQ3X8I/SFIgLKlrD3H0GYYRc8Uwt9U/SAV8GWMYAqczVbmoC0ikQYddA8n3rXKHA36Mg
         rsEPhNAbKhBrUSjG7DpfwES9MI6NJXgHD2iqbKJet2HecCiTtCiaXnZb3XqIubqkoxMf
         Vse/5WT5zV1yih0+WLWNUJ3nYUUpr3AUDnks2diGFVJMyXW7hoUWi/O7PdVG1l54tA3n
         +qeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AjNVcTWgTz7ZCsB8YIeskwDAfb52MNjdkz5pTEAIwv8=;
        b=uGxHA181VheuQTK+cFGkDIWFfokQrmRQRFuG6qrXSATz3DG7VrUz68e7ugI/pUe9ca
         diQENitZwwmpjppF5ipRiULdIx+cAWRonsvwXVMyekvVIVY9LnqF3gMgAm5Q9idYVYKm
         BgJT8Mw6JaHPOF0C0SBo14ZCJ1OB+uBuXxao8Y7iZCG2sDLzrEv0XTNEzsCBD1+2tmmy
         FzcBynpZ7Vd2EoM4mQcHficocj2MjlsJtpN+PDbjry8Vt9gdpMfPK83tJ2sn4OLOX3Rt
         HGLIx70IAMFij/hyg5eZqfcpVKE2zExm8BU36ZKrBFmHJXtR1piJcmHzw+X67jbvKtbM
         IIqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VBi6zU+6;
       spf=pass (google.com: domain of srs0=jdey=ne=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JdEy=NE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y11si131861ilu.5.2021.08.13.10.58.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Aug 2021 10:58:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jdey=ne=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E11C360EFE;
	Fri, 13 Aug 2021 17:58:13 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id AE51F5C0373; Fri, 13 Aug 2021 10:58:13 -0700 (PDT)
Date: Fri, 13 Aug 2021 10:58:13 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	boqun.feng@gmail.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: selftest: Cleanup and add missing __init
Message-ID: <20210813175813.GC4126399@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210813081055.3119894-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210813081055.3119894-1-elver@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VBi6zU+6;       spf=pass
 (google.com: domain of srs0=jdey=ne=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JdEy=NE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Aug 13, 2021 at 10:10:55AM +0200, Marco Elver wrote:
> Make test_encode_decode() more readable and add missing __init.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Thank you!  I have queued and pushed this one as well as your previous
series:

https://lkml.kernel.org/r/20210813081055.3119894-1-elver@google.com

							Thanx, Paul

> ---
>  kernel/kcsan/selftest.c | 72 +++++++++++++++++------------------------
>  1 file changed, 30 insertions(+), 42 deletions(-)
> 
> diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
> index 7f29cb0f5e63..b4295a3892b7 100644
> --- a/kernel/kcsan/selftest.c
> +++ b/kernel/kcsan/selftest.c
> @@ -18,7 +18,7 @@
>  #define ITERS_PER_TEST 2000
>  
>  /* Test requirements. */
> -static bool test_requires(void)
> +static bool __init test_requires(void)
>  {
>  	/* random should be initialized for the below tests */
>  	return prandom_u32() + prandom_u32() != 0;
> @@ -28,14 +28,18 @@ static bool test_requires(void)
>   * Test watchpoint encode and decode: check that encoding some access's info,
>   * and then subsequent decode preserves the access's info.
>   */
> -static bool test_encode_decode(void)
> +static bool __init test_encode_decode(void)
>  {
>  	int i;
>  
>  	for (i = 0; i < ITERS_PER_TEST; ++i) {
>  		size_t size = prandom_u32_max(MAX_ENCODABLE_SIZE) + 1;
>  		bool is_write = !!prandom_u32_max(2);
> +		unsigned long verif_masked_addr;
> +		long encoded_watchpoint;
> +		bool verif_is_write;
>  		unsigned long addr;
> +		size_t verif_size;
>  
>  		prandom_bytes(&addr, sizeof(addr));
>  		if (addr < PAGE_SIZE)
> @@ -44,53 +48,37 @@ static bool test_encode_decode(void)
>  		if (WARN_ON(!check_encodable(addr, size)))
>  			return false;
>  
> -		/* Encode and decode */
> -		{
> -			const long encoded_watchpoint =
> -				encode_watchpoint(addr, size, is_write);
> -			unsigned long verif_masked_addr;
> -			size_t verif_size;
> -			bool verif_is_write;
> -
> -			/* Check special watchpoints */
> -			if (WARN_ON(decode_watchpoint(
> -				    INVALID_WATCHPOINT, &verif_masked_addr,
> -				    &verif_size, &verif_is_write)))
> -				return false;
> -			if (WARN_ON(decode_watchpoint(
> -				    CONSUMED_WATCHPOINT, &verif_masked_addr,
> -				    &verif_size, &verif_is_write)))
> -				return false;
> -
> -			/* Check decoding watchpoint returns same data */
> -			if (WARN_ON(!decode_watchpoint(
> -				    encoded_watchpoint, &verif_masked_addr,
> -				    &verif_size, &verif_is_write)))
> -				return false;
> -			if (WARN_ON(verif_masked_addr !=
> -				    (addr & WATCHPOINT_ADDR_MASK)))
> -				goto fail;
> -			if (WARN_ON(verif_size != size))
> -				goto fail;
> -			if (WARN_ON(is_write != verif_is_write))
> -				goto fail;
> -
> -			continue;
> -fail:
> -			pr_err("%s fail: %s %zu bytes @ %lx -> encoded: %lx -> %s %zu bytes @ %lx\n",
> -			       __func__, is_write ? "write" : "read", size,
> -			       addr, encoded_watchpoint,
> -			       verif_is_write ? "write" : "read", verif_size,
> -			       verif_masked_addr);
> +		encoded_watchpoint = encode_watchpoint(addr, size, is_write);
> +
> +		/* Check special watchpoints */
> +		if (WARN_ON(decode_watchpoint(INVALID_WATCHPOINT, &verif_masked_addr, &verif_size, &verif_is_write)))
>  			return false;
> -		}
> +		if (WARN_ON(decode_watchpoint(CONSUMED_WATCHPOINT, &verif_masked_addr, &verif_size, &verif_is_write)))
> +			return false;
> +
> +		/* Check decoding watchpoint returns same data */
> +		if (WARN_ON(!decode_watchpoint(encoded_watchpoint, &verif_masked_addr, &verif_size, &verif_is_write)))
> +			return false;
> +		if (WARN_ON(verif_masked_addr != (addr & WATCHPOINT_ADDR_MASK)))
> +			goto fail;
> +		if (WARN_ON(verif_size != size))
> +			goto fail;
> +		if (WARN_ON(is_write != verif_is_write))
> +			goto fail;
> +
> +		continue;
> +fail:
> +		pr_err("%s fail: %s %zu bytes @ %lx -> encoded: %lx -> %s %zu bytes @ %lx\n",
> +		       __func__, is_write ? "write" : "read", size, addr, encoded_watchpoint,
> +		       verif_is_write ? "write" : "read", verif_size, verif_masked_addr);
> +		return false;
>  	}
>  
>  	return true;
>  }
>  
>  /* Test access matching function. */
> -static bool test_matching_access(void)
> +static bool __init test_matching_access(void)
>  {
>  	if (WARN_ON(!matching_access(10, 1, 10, 1)))
>  		return false;
> -- 
> 2.33.0.rc1.237.g0d66db33f3-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210813175813.GC4126399%40paulmck-ThinkPad-P17-Gen-1.
