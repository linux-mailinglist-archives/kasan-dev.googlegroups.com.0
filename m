Return-Path: <kasan-dev+bncBDBK55H2UQKRB6OKR6PQMGQEPVIOXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BC0568F69A
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 19:10:02 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id v190-20020a1f2fc7000000b003e1db6f41desf8541700vkv.19
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 10:10:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675879801; cv=pass;
        d=google.com; s=arc-20160816;
        b=BK7gb7BmWHxg4H0LpqOy+BpB9tH/T0mX5GAYVJgczpwt5D/JWzd7nvdMusC70ZTZf0
         lTtcPKGuM58iEeidx0DgGNlngRsQmWTuPlMFgMZMDOGGsDc6IneRjvU/C42a1Zkg8iNV
         jhK68Hu7mvc52jTMQo9LBkAHqswAt9Om1Frjtbs8PboaiWUldt3spS6RCjfiJ05ThNWV
         8jV4kFAFkuJk0bCezILvbIIQMl7m0OzN7G5PI1oBcLMEsWZUJxMWcwgoez5DlzrxgCMp
         lT7IbMZzYuaUHnXPa11HHFJo+3antP9Mrr0QnzhiTm7blaDJjkj4ScypjZoC88xr4vgl
         k77Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HnhoNl0FfjAS88uEMSf7sn4lYd/SRE2G0TpB7W2RDzI=;
        b=yZ3weXwmSdmkMTQXdOqLWXGVJ77HSIjBRPrZYHtYQ5uLB4GekEMyuLR8D+aJ+SHwvv
         +nfYXTse7tFGd7/phFU7O5FJJiZe0fyyFwcM5KWPcSXechfX430+TDnLDtwOuxagGh5y
         Gz/+5zm2sYA6HvtGdFiP/s9pnWGW59wfZKqhHU5ydQaPl1p7pQ6ui2gpcnc5jWVYJQTI
         zfVqkRl13L4Vm+VT2hV5s4QVhp6yxgZIEt0KbYjVIwLGyoj/D/8Ft4GaEYf7L8KbWBO3
         DLmuxDTIu4rFw+ryLGQbgDmiWKAHDS9kfHhRUu4/8tJiNigxfqQ57cKFxklYmKEF8Fsy
         ThIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Nb7AmXOo;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HnhoNl0FfjAS88uEMSf7sn4lYd/SRE2G0TpB7W2RDzI=;
        b=KSDtV1mkvTejtXLvUIlvoeKCpBWNjzLI3a8xl1qYqAmfMLq8BYkPniaJ0gLIFZoX+6
         nwrJNMfOEoOJ87seAbJwG3nRZshzA2Qh74Ot44d4ET36kSZAhrgj4tBbmYIXP28umBmW
         2M5kh4bWPKE3m6OwtMepYQsEB6IccSIr/qMjLkNTzQQbdO+YAPFkjxOYE5v8SX6i448F
         GdNfgUcKbSLqX/Dqeh9FjwGI3pff7o5c1s+8gCuIznfNUh7jV0ScickNOoqFAhHiXaKt
         D7fFHWpBRbNiWUfFUP30qv7k7+fnMD7aKgPrOvhNvIqvu/+vIZQ0jJd32zcgnsT64Z0u
         oY4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HnhoNl0FfjAS88uEMSf7sn4lYd/SRE2G0TpB7W2RDzI=;
        b=4Ud6kTX08kdnO8UEYHF9t6wpqaGTd2TbLPvL5el8KVKNaFWpWu9w4J8FqvI594YzO4
         y+QzLjAS5Q4QploCEmFLPtJo6qggANSXWrIxa2xSR6pqyguQgZpqv7s243tmtGmnc3D0
         izMnX27zRvEYO+DsDgVRSUZRRgDzcUuDpy2XKSZH9LGP+8cv0SUY+u0uZUcg1PeCJhp8
         WbZl1gF8kz9JHSf2JS70FWyn2z+0EWzQisPigsm310qKq+ZPdto7zvWMyJCqKglmGjWw
         jXWBuoXXmelX1qgd/ixeZvpDM8V5ROw8iYM8ntQ5LcIanhsmWZ39a3dNF53jq4VH6F4Q
         UDfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWUMcviLXDfNzzVjKRTEKtp4Iri3I5TFi6X5AHZxuqMJm7y/K/0
	3sgev6ZPqzQVvjf00JAcqE4=
X-Google-Smtp-Source: AK7set/3QWfQiQ9WVe18SROG1u+R/JxwTgnUy0T9ddil2ArZngDApAz3b2LLy9fok9pIgLbncG9izw==
X-Received: by 2002:a67:b90f:0:b0:411:be45:fda0 with SMTP id q15-20020a67b90f000000b00411be45fda0mr750738vsn.13.1675879801275;
        Wed, 08 Feb 2023 10:10:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:cbc6:0:b0:3b5:df37:23a6 with SMTP id h6-20020ac5cbc6000000b003b5df3723a6ls589707vkn.7.-pod-prod-gmail;
 Wed, 08 Feb 2023 10:10:00 -0800 (PST)
X-Received: by 2002:a05:6122:2210:b0:3e1:d23d:d544 with SMTP id bb16-20020a056122221000b003e1d23dd544mr2527316vkb.7.1675879800558;
        Wed, 08 Feb 2023 10:10:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675879800; cv=none;
        d=google.com; s=arc-20160816;
        b=bTZQeGkQNKO80+0vZM9mAco2+5UmaqV7Y4NuM0VdLlIbmnkLQUg8MZMrxdj5ITSNTA
         EgW+RzkbxrnrgWu1z0WnUsLTSeuaScxkSmAe2ce2labGwNfOUIAKW5vT82aIN3IqjFnP
         Vkxj3NipiOiwzY+/QDk0oTPndBzKtZPY6uVyB43UCrBbP1OGrAAE8c6+S3u7a3D9cOBn
         EEQNuix0zdEFMivJ6nprcs3jqalQQ7mU7DuHhN9twOOBirM11QP25ezsdMU55KwxfdhW
         8daOKyZcnoX/xrnfhBxwLtQFsYbC4Sx/S0aInKgCKKUbTUIHyUtAit3lVv+5G616gzxQ
         gMhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3eN7aIzkLFLIdp/JFL79Wf1u+TIujhiGAfM1SS+nUFk=;
        b=Z/IDCz/02Q6r9CSKYAH/w0AXj7QTHXNnWK66S0v4wCtySgNLK2pY1hi0TcOf5typJt
         mZAvTsWTzNchjg6ZZCY8UmfFShRROZIjG5lEGFK0ptfJZkhhlEpdJNccUs5fpvpEYtY/
         jFpCpU7cLdkOIXAhMrRP0A2O/EMzR3XtcKZdwTBYTZakcjxfTv5+Z7B/lRO6juUV1l5m
         OTa5k/M8SlggLKCQvwg5bNiVu/5DCv6fpbWbvO0sD4EIUfW0GuKkJXT+VJAbEsXSl4Um
         6EQCI/aXEqJNTl9b0/E9Qc+wFN990x4cvySC0iz7B6IgUhis6YXa13wDr70QLFwFNDFc
         TGUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Nb7AmXOo;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 28-20020ac5ce9c000000b00400dba9ad27si530947vke.0.2023.02.08.10.09.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Feb 2023 10:09:58 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pPot6-001RGK-Lj; Wed, 08 Feb 2023 18:09:45 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D6D663001CB;
	Wed,  8 Feb 2023 19:09:42 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id B7FB320F05D4E; Wed,  8 Feb 2023 19:09:42 +0100 (CET)
Date: Wed, 8 Feb 2023 19:09:42 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>, kasan-dev@googlegroups.com,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@suse.de>,
	Miroslav Benes <mbenes@suse.cz>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Sathvika Vasireddy <sv@linux.ibm.com>, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 3/4] objdump: add UACCESS exception for more stringops
Message-ID: <Y+PlZi8mrHray92j@hirez.programming.kicks-ass.net>
References: <20230208164011.2287122-1-arnd@kernel.org>
 <20230208164011.2287122-3-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230208164011.2287122-3-arnd@kernel.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Nb7AmXOo;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Feb 08, 2023 at 05:39:57PM +0100, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> The memset/memmove/memcpy string functions are wrapped in different
> ways based on configuration. While the __asan_mem* functions already
> have exceptions, the ones called from those do not:
> 
> mm/kasan/shadow.o: warning: objtool: __asan_memset+0x30: call to __memset() with UACCESS enabled
> mm/kasan/shadow.o: warning: objtool: __asan_memmove+0x51: call to __memmove() with UACCESS enabled
> mm/kasan/shadow.o: warning: objtool: __asan_memcpy+0x51: call to __memcpy() with UACCESS enabled
> vmlinux.o: warning: objtool: .altinstr_replacement+0x1406: call to memcpy_erms() with UACCESS enabled
> vmlinux.o: warning: objtool: .altinstr_replacement+0xed0: call to memset_erms() with UACCESS enabled
> vmlinux.o: warning: objtool: memset+0x4: call to memset_orig() with UACCESS enabled
> vmlinux.o: warning: objtool: memset+0x4: call to memset_orig() with UACCESS enabled
> 
> Add these to the list as well.
> 
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  tools/objtool/check.c | 7 +++++++
>  1 file changed, 7 insertions(+)
> 
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 0f67c6a8bc98..e8fb3bf7a2e3 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -1248,6 +1248,13 @@ static const char *uaccess_safe_builtin[] = {
>  	"clear_user_erms",
>  	"clear_user_rep_good",
>  	"clear_user_original",
> +	"__memset",
> +	"__memcpy",
> +	"__memmove",
> +	"memset_erms",
> +	"memcpy_erms",
> +	"memset_orig",
> +	"memcpy_orig",
>  	NULL
>  };

Hmm, I wanted to go the other way and remove __asan_mem*.

  https://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git/commit/?h=sched/core-robot&id=79cdfdacd5b8d1ac77e24ccbc178bba0294d0d78


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2BPlZi8mrHray92j%40hirez.programming.kicks-ass.net.
