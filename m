Return-Path: <kasan-dev+bncBDV37XP3XYDRBMG4XOXQMGQEPFKWFHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 91783877F35
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 12:42:42 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-221ec825643sf1290439fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 04:42:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710157361; cv=pass;
        d=google.com; s=arc-20160816;
        b=tzwtc1B4fuQVjQ7uxbOHMjOoGGcFvR9Dknk7f4KrIFcD/yPwbc+6UJJXLBJ6Nvsgml
         xvjA9a0N4KN9tZuvecdZmcbTz7/H374bMh4cA83qBC/4/UleG2eFNOPFYOEfwtz08sX8
         xspu2KgBMxM7V3rtCTmWO+3aiRTh0OyBCGvugJbc9HVIaPqOpiiB9ovUWavDpyq0hLcg
         K3i2pHmrhGsNQ9mt9BdGsJf9rXOx2fJN+KV6q9wPn4zn6P2Sr5iwuJS+uNbqwExyc1LM
         A3Yj3kY6yCN7NV7xhudpDu/3gpnPqogp3FMYjdpNDdP5rJeoLsYZvu1RlDA20q2u4UYm
         1bdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qZW3TPldVpHzc+BGPaMyF3f/5Qr4KL8y7cxyCzNuUQw=;
        fh=rFvBbkyryAsDDqF0iNL2kakpZGoHAH9PN10in1Z/MTs=;
        b=X11h5GWCEAdpHwWA9DZMztw8Q8ROoU37CntevftC8s3TBCNEPJsdyxoHCMzgLYV0RS
         gGY1RR6fDcTGQoYu5W+7HFMdaGpCzHTDP5hbV7VeS12c30/w2Z0C94PbyKW+lWlwsgrF
         Ci70Rye7JViGkwNJ0MCBL3/9YDKLNt14pcGIV+gxUPmo8o/q4o3OFnFm5HEhiy8np1oK
         Y91Za5d+kuqPgUGOG+toAfZt/tdhJbfyWiP5cyjADt5p2A8Dy+Fyko43VPB8Pm42OTdw
         iiVA4LpxTWe6WzcCpzgjouQ8tGsZVHxEBvenPp2GbZY0oXp8opB/JefWdq1GkgLAiHKj
         KXkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710157361; x=1710762161; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qZW3TPldVpHzc+BGPaMyF3f/5Qr4KL8y7cxyCzNuUQw=;
        b=Vk9uChevGXg9u7TDQcIFzDa3Fw/rbrQzaOz4bRSkp1yLg7dGhlzxSxJkcnX/msdMFU
         OQ4vjfLSwxo+NVlBW61mJk+h1Q6PeKzjHiyvCG7AiXKasYrxZS7Ktz2pfi6Lm6t0T+/P
         sltUk9KSVw0yt1lE7t9e+vuHHhDkvDXxdYEA6tj5rh4v1MafRhKENb8XxizlJRT/8EGa
         9wu2qNbnwYOdTHb5LqG89neS5F9CIbCKW4Nd/q4VgzqXlpDKqUiTRMEGqGrbQjEyvAjl
         Kf2a1tgTUuA4msVB8nhptaDwdjOgKFoP64enz2VMFywTVT5Ib+2CEZ9evVUch2fyPie6
         56Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710157361; x=1710762161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qZW3TPldVpHzc+BGPaMyF3f/5Qr4KL8y7cxyCzNuUQw=;
        b=FdyaUu8zItb92769aTboq2GDw6HK+raRZjjVIhJCxPmUn9GspQOCjIXOWyIgCR5K2v
         WUaHC+cJbOuZpnOGHUJIiU32fhA/sjg27osXO7ul5JurghSDvMt9+UapLHNHyLqL6R4u
         pnTQdpZHzWKvMANGMZEwCgM8uo9oY5lCNBslplMfUxVuGlptBkr2X/hmKi8l0hWImh5k
         Y+PCPJwj0cO6x7qz+vl1HUyFAvbRHoIaKs4KOFWBaIJ4VZDuyNqYpQw6tvM5iS0JP1VG
         tms7XwF1539E/ROHACy8K4YUTAtNlk0mmgl+UbnVF3OWZarxEHmLVuGItRor6tC3t7Lg
         AczA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXHTfIG6WRV6ndwHn4/KNJShhaL/AsLlq16ix44TY1mEVilJ+mHo1lhUfq++v21hfY/GN1XWPLTxRtAWtIPVOcAWLIc9rgicw==
X-Gm-Message-State: AOJu0YyYQniPMLdvmyQ+HX+/liZ70XisHmkwoR5l8H1ZfxvQMkYxFdE5
	JnWGr5yGcYPaJ0Q4LndZlpVsZxC5BY2WSfeVYQdnFANwNnaLN/XH
X-Google-Smtp-Source: AGHT+IFUGF4yRNEeIbonvJuiod0/TkFZRAn63RHgoQRnPu4fdBM+6YsufjoJDsw3B3OC69hejrS9lQ==
X-Received: by 2002:a05:6870:f14a:b0:220:daa3:4800 with SMTP id l10-20020a056870f14a00b00220daa34800mr7349920oac.40.1710157361021;
        Mon, 11 Mar 2024 04:42:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:15c8:b0:221:d6a3:f36b with SMTP id
 k8-20020a05687015c800b00221d6a3f36bls1311768oad.1.-pod-prod-05-us; Mon, 11
 Mar 2024 04:42:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXmhCBM5sttm1JSwgrwQITuWGTik9+7ij8GBdT1SgzDjngLcetUko99PIAsePATFidJStyWeTdzBi5R7AX2zVlRuOwQ8LH2+dOFvQ==
X-Received: by 2002:a05:6358:e483:b0:17c:1bef:4082 with SMTP id by3-20020a056358e48300b0017c1bef4082mr8318144rwb.7.1710157359956;
        Mon, 11 Mar 2024 04:42:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710157359; cv=none;
        d=google.com; s=arc-20160816;
        b=t77ZeCT4ZJw7ymZj37C1akBH3RLn5lT22F1xGN8gvjUkQegDAbimBOawFfyWPCfzEq
         gIgNZfhO5VUBwC0jWQ9AmC4C1Galz+inbiRiC0b1E2ufIWDSNllHdqOe1BoULUxIz5DD
         2Lkaqc5Scv9xaA3lavkbsOK9gdFaR7HVBQR4lcVNRhJL/FC6xWK/pfHy6V1eRlA7Jlk1
         sfDUozCTBnBsW2qNCH0noyUAsmDEMOe+WH/o701zyxjXxTqFkJUyZzNCBI4N/t2wtQHt
         md7DVsi1eHtR1CYoX+YVFECZAkiqN4Und7Kf/ATgk33ScgVi+tdKT8P/pWy7cZNbultY
         5/Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ncVKbw6GBZAvrt90E0UKrZxVpZkp6sKd5gTkgXa2DW4=;
        fh=Jbpof72zdeNxbh+lHI4jJv5pNucIsO+k1TTDszHfpDo=;
        b=VIWUxTyhOW/AWUN1h7evZ6uoAvPqWNV8qcvcDuDq+A/MYYFUzvWA3YHksF2u3ZvJGq
         yZSNQ8E/cr5KGBv2A2zqD49Eo/ZdEqelfNsqUIzpOarJyuy4LqIyz/jvClV3rQmgKxBe
         n4Kscv+KSsqf4tndqMg9P7i0du2QtgE2RyPfVEKK75fIWgRGBFfq9B2jJAob39S5VDhr
         GgSO4socRTkOHnXmvxQiRM8J8weDubM9tB/pH/lDRavDDoniKqTCom4yQ/Pr4btfzSU/
         U2yYmGNT5iIKokYPE6c0Rm395BEANtsTA5T9R+uLpuAoSTBWRofk2aNmF+Hywm+M5h1F
         hKww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p25-20020a05620a113900b0078854e3203dsi465740qkk.6.2024.03.11.04.42.39
        for <kasan-dev@googlegroups.com>;
        Mon, 11 Mar 2024 04:42:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 42127FEC;
	Mon, 11 Mar 2024 04:43:16 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.70.189])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id ACF2E3F64C;
	Mon, 11 Mar 2024 04:42:36 -0700 (PDT)
Date: Mon, 11 Mar 2024 11:42:29 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Changbin Du <changbin.du@huawei.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Alexander Potapenko <glider@google.com>,
	linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>
Subject: Re: [PATCH] mm: kmsan: fix instrumentation recursion on preempt_count
Message-ID: <Ze7uJUynNXDjLmmn@FVFF77S0Q05N>
References: <20240311112330.372158-1-changbin.du@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240311112330.372158-1-changbin.du@huawei.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
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

On Mon, Mar 11, 2024 at 07:23:30PM +0800, Changbin Du wrote:
> This disables msan check for preempt_count_{add,sub} to fix a
> instrumentation recursion issue on preempt_count:
> 
>   __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() ->
> 	preempt_disable() -> __msan_metadata_ptr_for_load_4()
> 
> With this fix, I was able to run kmsan kernel with:
>   o CONFIG_DEBUG_KMEMLEAK=n
>   o CONFIG_KFENCE=n
>   o CONFIG_LOCKDEP=n
> 
> KMEMLEAK and KFENCE generate too many false positives in unwinding code.
> LOCKDEP still introduces instrumenting recursions issue. But these are
> other issues expected to be fixed.
> 
> Cc: Marco Elver <elver@google.com>
> Signed-off-by: Changbin Du <changbin.du@huawei.com>
> ---
>  kernel/sched/core.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 9116bcc90346..5b63bb98e60a 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -5848,7 +5848,7 @@ static inline void preempt_latency_start(int val)
>  	}
>  }
>  
> -void preempt_count_add(int val)
> +void __no_kmsan_checks preempt_count_add(int val)
>  {
>  #ifdef CONFIG_DEBUG_PREEMPT
>  	/*
> @@ -5880,7 +5880,7 @@ static inline void preempt_latency_stop(int val)
>  		trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
>  }

What prevents a larger loop via one of the calles of preempt_count_{add,sub}()

For example, via preempt_latency_{start,stop}() ?

... or via some *other* instrumentation that might be placed in those?

I suspect we should be using noinstr or __always_inline in a bunch of places to
clean this up properly.

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ze7uJUynNXDjLmmn%40FVFF77S0Q05N.
