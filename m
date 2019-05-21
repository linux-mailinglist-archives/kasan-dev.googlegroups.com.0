Return-Path: <kasan-dev+bncBC5L5P75YUERBLFZSDTQKGQEGE2IZMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2717825442
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 17:43:41 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id z13sf8252121wrn.14
        for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 08:43:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558453420; cv=pass;
        d=google.com; s=arc-20160816;
        b=sV1Zqs4hto+Q4EXLY/Us3wZhE0c5PwrCykp5HLtXJGhueAbFJnkzXlkHRjxL8LZ4Mb
         d6Z9A6fmaH85m+ydS13oYp85cp2lGZzx8GpKTx3oeQ8+SETw/TVMvkhdvr9nvOVn6Vbu
         OK5iDD/x3FC37ZjZKa6qrE2bzIrnPf6r3qT5F2Idn5R6Q6qIzo3nKrTAhTL2ggIYC13X
         a8KtR7NQwVCFCimjA2cxRIpf1REvDwunq2T3cjo1n1IMztZGOyRbg0d6GRhysSK6kNVn
         NRKijcFBOY/NKXshHQaSfBpYuu8ajXznJOPajRPoPAfKb7WkWPYE3TkYdzH/V+DNaJ+C
         yq7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=BuDWwxA3Q77h46QA9oILlmdf4GLHX2DALVpGWE8Vc7E=;
        b=w6ztBUfPQ+YTy5BptGHLwVDgu/ccO6krPSZVkrw+TJLr5sdhuPOsvbElvRV2T4Jy1m
         lrtNDHFV5cxzKJHz2hPWjeS2RdCsfGKnccMjwaKwfixZ0prqUc34ZDxPcJbGrGmjRTx4
         U0Z346gIKPfcBYkm5jkyWKSwNWvogvp4fd60W/hIa8Hb+SlazoS8kzFre9qbYnzQwmkz
         VM7wrrlbKRN0OWfm+hcmkb3+QKbnTPNoizYgTkyz1OFdYb4fH9y/t7XOTBlQ8H1BsmEd
         Nn+0oz57hQ6wDlWOoGR+gscvA9xbEFV7DpD/hgPKXQjQczcSjLMETHySBSozpdUtLMoE
         HzMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BuDWwxA3Q77h46QA9oILlmdf4GLHX2DALVpGWE8Vc7E=;
        b=JDKOz4+4BM06chha/YlMiHrwZHrhoEYLPJC9JVcYv0g4RuU+AwyHtfE5OjtU+99Lwy
         aI7/leIDAlKKb15PkiMSvbrg3PQLSyz3e42nAjbhzNdt3cs1IiAD40HS1sG1in6Jz95Q
         6FFRRbAJfh8CfLAd2EJzS2ulQhbnu2dExymUkXw4fBGIVS7azyq737iw8aPsi/xWXT4b
         ra8Mgwf2FcG0MTnnJfjCsnXucc84Uo3jd2dWy4kVgFqViEBUHhPCg4Ye2gucbEK41cqz
         ISVr3OGcuPa/vFXPmq1I2miOfpUIUCSH4zHgsfmA9AdzILeM96FI7wDTR8x0k4HdHidA
         o3+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BuDWwxA3Q77h46QA9oILlmdf4GLHX2DALVpGWE8Vc7E=;
        b=AZ/MX6lWcI6BLiImgrWIEUygPVat8D9lp9vCC1JBW1Y/TaVXr5CpK1+f/vwbgx63rs
         nGE8fkM1KhGJ2eBna4B0qQ08Kx5NO2jFvQVh4h5NkAik8mRg43DIOL5TYUn595d0WRik
         s6eT9bR+eb7/D3z2g+47119k99YSQ+wYgxdLQSkmtQ1IAj+8SS/mYNV2ouSnhbf1CovL
         c4RUS1Ad3GIek2En9CIR6zFbThKn+deZOO4SSUpkfYNNNJxDesocEBolKY26u95qs1Ja
         qlYkqut4kKoF9M/JE9XbjrE2mducNC54ZKVHpKr4EIrLuf4a1TL5YU2C64V3ODKm7PeF
         2Sqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX3/5/E7WqG3ShDCNNMzRKnpsGXZCzA4gVVMVfRjn5M8r+2zBLD
	631MbjaBffLkw2gWAONN1hI=
X-Google-Smtp-Source: APXvYqw7ZgQLCq80NFoqI75vbFLTIiRdc5/MldJRuMttuqRr04l0bisy0r2yWmUuQuHf/gDA6+gK7Q==
X-Received: by 2002:a7b:c4d1:: with SMTP id g17mr4073942wmk.103.1558453420889;
        Tue, 21 May 2019 08:43:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca45:: with SMTP id m5ls1105503wml.1.canary-gmail; Tue,
 21 May 2019 08:43:40 -0700 (PDT)
X-Received: by 2002:a7b:c4d1:: with SMTP id g17mr4073915wmk.103.1558453420507;
        Tue, 21 May 2019 08:43:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558453420; cv=none;
        d=google.com; s=arc-20160816;
        b=oDaCCT5iTKiJeA81bZQXVwCoPzt6GBVzYh1WPuTEFNZIE2fclgNh5T7bQyvT9HPBYK
         MPbsZCSd9X/yEJxzSjKZxVCM5JrhlVg+75Wsh9dfvpUlRxTmT0dDdaZqf3wAQJcHdhbY
         eOUtRg94V44BvXXfwO57ROk29iiCrL7cXf4KkNWHKTxSjH5lUGhP6oE9vHPlMwPX5EBj
         jVIGArujLt9reVCEBO8UtX87tfJhaFq28jvsMX8Af1vRgY59c1D46HY9yP/rx9939iXw
         9GgvYG8lZjyksR7g6kzjdOOJaVfI4Kj44YPwTVXdmE4eqooo4fb3fxdY+ylst2tEXkyo
         czpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=We2uypiPNmCU7rL3l9J/wgnfVgJk7qbDKDVJyLe1/Pk=;
        b=NjfoPzx9aJxTrJthkqbP7Rg4ktTLK0SVeqpCG+Md94Srv4Ga5zckxbiVTMIu7ZgxFd
         apSgEt4gbny/xJ+iHFPgMz3FOqTM55N9UB0DczeBFkkOpr8+reudbuy4sVhk9vf9AFAC
         l0y2Ws5JE0Ed8qIonanqGc+V8YhMwxwY2fzNfrso+eFymTbabyTTdLVkj/WjjzNTYMcw
         7R9PtFwxAM8/7iuo4VNw9CS6ZYGhP3O6BHGlaXTnw6envoUnq2mSDQ47nfjQrTWUg/2Z
         1j2+me8wahEltUGHkuc6tI+ChKyOGlAbM+wp062sRY9q/a3avmokmXtfJdJu7Li26XrL
         K+8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id p18si177335wmh.1.2019.05.21.08.43.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 May 2019 08:43:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.91)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hT6vS-00073c-UC; Tue, 21 May 2019 18:43:39 +0300
Subject: Re: [PATCH v2] mm/kasan: Print frame description for stack bugs
To: Marco Elver <elver@google.com>, dvyukov@google.com, glider@google.com,
 andreyknvl@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com
References: <20190520154751.84763-1-elver@google.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <ebec4325-f91b-b392-55ed-95dbd36bbb8e@virtuozzo.com>
Date: Tue, 21 May 2019 18:43:54 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190520154751.84763-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 5/20/19 6:47 PM, Marco Elver wrote:

> +static void print_decoded_frame_descr(const char *frame_descr)
> +{
> +	/*
> +	 * We need to parse the following string:
> +	 *    "n alloc_1 alloc_2 ... alloc_n"
> +	 * where alloc_i looks like
> +	 *    "offset size len name"
> +	 * or "offset size len name:line".
> +	 */
> +
> +	char token[64];
> +	unsigned long num_objects;
> +
> +	if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +				  &num_objects))
> +		return;
> +
> +	pr_err("\n");
> +	pr_err("this frame has %lu %s:\n", num_objects,
> +	       num_objects == 1 ? "object" : "objects");
> +
> +	while (num_objects--) {
> +		unsigned long offset;
> +		unsigned long size;
> +
> +		/* access offset */
> +		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +					  &offset))
> +			return;
> +		/* access size */
> +		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +					  &size))
> +			return;
> +		/* name length (unused) */
> +		if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
> +			return;
> +		/* object name */
> +		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +					  NULL))
> +			return;
> +
> +		/* Strip line number, if it exists. */

   Why?

> +		strreplace(token, ':', '\0');
> +

...

> +
> +	aligned_addr = round_down((unsigned long)addr, sizeof(long));
> +	mem_ptr = round_down(aligned_addr, KASAN_SHADOW_SCALE_SIZE);
> +	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
> +	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
> +
> +	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
> +		shadow_ptr--;
> +		mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
> +	}
> +
> +	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
> +		shadow_ptr--;
> +		mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
> +	}
> +

I suppose this won't work if stack grows up, which is fine because it grows up only on parisc arch.
But "BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROUWSUP))" somewhere wouldn't hurt.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ebec4325-f91b-b392-55ed-95dbd36bbb8e%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
