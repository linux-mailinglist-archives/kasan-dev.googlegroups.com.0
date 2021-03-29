Return-Path: <kasan-dev+bncBCV5TUXXRUIBBC76Q2BQMGQEDRPJHWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id F097534CF5C
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 13:50:35 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id j3sf4222440lfe.13
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 04:50:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617018635; cv=pass;
        d=google.com; s=arc-20160816;
        b=nz8Rpn/0jdm7NUH/10hfwk12apKKaeQtU3GuI7rjks7e3mCPpwg+/eFTrJ9l3ydsn8
         9nIuWp8wk7nuwlvU9mw0UnsIZRiLEPr8l+WauLY5sc66AbHMNPCWfrCm85NKyp6BMDpI
         RXiplyxQto6LYFFsrjvj955t3i+7S9WIBBZqqjI382qnvjvyZrMbAXCFLqndFPKCKuuI
         Tk4s1cgQ1KIUfr9KXV1KNm1Jihf2fU86kla9iryxOf035aaPT81RczvPCphjbRjWWSEF
         nQwIfASzszohupiC58WC2+Q2AbCvlPh5pgP7yJiDMwIa/nfodWUolEXpTsjeBuY/yp7Y
         JxUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=l41CS4B5ocI28ToicNF0VJrFZvn8da0lVc1IliKg+fA=;
        b=bG3G+yF4gbEJJk1Uhw9hspnKDMmlAVTzGIZBzM11d0APFujhBISVU+gOuFjRojfnt9
         MpGwjAh5jk/HwguL7SzQ9fWRQO+RLXjD/AtYVi2WUcrvl4k0WJiBCEGHrlB+qMK5FjlY
         aQdDX99VIMrclPbGRmG5eI2hNnei01OF1NctjOAHOi4cDkcQ+n6BefEH20CgqG7drFCp
         ksEHAn7g0b1D/GpIcSS6ZzTI02rUmQqEXfcr3swGh1KlqHJU3bal+hmPlfE9F3h/0NeM
         VjWVKLuZUvLbb80CnfKAVdLJUDdRgq2muFZlZ2FWKFQwd+v55GB39CbE5VHB8Kef5Tuc
         9u5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=d1jazCfp;
       spf=temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=l41CS4B5ocI28ToicNF0VJrFZvn8da0lVc1IliKg+fA=;
        b=rUrcH+oh3A69x7tuYycpXJtHNZp5ABubAtGsRJLwHjlQtzTu7C0bj0cqECSFMX/rcN
         8cKce95mwVOIPqpJOnf+/g7iNwZzaTIcPNyPBwNH26OdFt8gCBmbL1Cv2zvvSh5daVrO
         ZFYBArTsbJjTW0vw1YHCOaudoQZYK4PKajriOCZ6g2zZuXfqpfd4weYjFQ6hM6IYQ2wX
         MgGFkXKh56/wftUK+jhBPpObeD7d/2Cmx+RuZmMyPXytBryctBSEpzrRVO8bLIw2AV1Z
         uXaDEfn0dDNzrxJLZMubyA5d95nWzZm36gG6rmhbv+CjaZeuDj/opuHJOmSMgERAvjeU
         KYnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=l41CS4B5ocI28ToicNF0VJrFZvn8da0lVc1IliKg+fA=;
        b=WcYP8wOrcVHMQCgbzLcX/asclkUW8ZtbhquCTQ+X/gmI44QurcMlBmNZkoCLcV2Sp9
         apP06Eyt1Aqmm+asp/OO4uIliow2nFcZytqvBAyy9uSwEaFO//KNDXkFzDHWT48lKXTA
         l4Esrzwf4Yi3V2cPqQYNiJlReeYOu7sjlmK1Yb8+KUuPZjuRX4xYp9XamLrKW3jyHgEO
         J5pbvOtmwDlu22oWI9jVBiYf/ngRza6T+6cBQ/hW8v7Xf9srcdQgB4+upiBCjR+VMx/J
         1jPpMJP9ZbL8ubA9ZAlHzJoOYYNr6RfAqvINPQ/Psaz+kutleauj15bfve+/2wht0inr
         V87g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Rht8ab3COp0/9L8UlNljkqupffZRGbcL9pv4RhXXHPtGUfOCr
	WBtwIOm/Q3P70/atWwxtAHs=
X-Google-Smtp-Source: ABdhPJzI93LKtnle6g9hfbNsuVcw6ZXBIJcC3JRKA1CaiywCuUihNVBkulSDR5NncDEwsruq2VAqMA==
X-Received: by 2002:a05:6512:3e20:: with SMTP id i32mr16518835lfv.257.1617018635479;
        Mon, 29 Mar 2021 04:50:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc23:: with SMTP id b35ls3107854ljf.7.gmail; Mon, 29 Mar
 2021 04:50:34 -0700 (PDT)
X-Received: by 2002:a05:651c:1117:: with SMTP id d23mr11963768ljo.220.1617018634322;
        Mon, 29 Mar 2021 04:50:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617018634; cv=none;
        d=google.com; s=arc-20160816;
        b=FHfypk3kYd7Nt57u89gkxxWgM0+WWABarshzh+ebYsEpER0i0jTynmKBUtN64ooSSX
         Coa+grUWiqLAlS+sE7qxjHUSlaN3lDlTfi6XHxmrdfwlxyWVA1yQCAM7Tr13Q8iuO1U2
         YCz+lNRGnmBkvFLgWL4fhob40FYw+0wS9hdViATzIg6/dwVg2Ls6c1Qd8X9o3MyObAx2
         sAQiU52wIzBvLQBrSL6E/EWpgydzMX1TvU3brevBhuXR4r4fev2zRRSfGRyaUCU8OohX
         GqUD0xOOKadcHjPHCn1+EoJRlrt+sosrePzsMtguT9dmkiV/rTQX2gmIhmjN67hys+uF
         XAag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7UpbfvkQlofjez1TPOd4UNQFXQ8qN4tvk7VAKOS6IdU=;
        b=zVW9ZwspWa+LmNBnBJubeE+KeZtxuvvVqJZ9tPRLNI3sNevTW2Hky7BKipKpoAeKud
         avVlV6iApD6yxNtP5KDjR2KIwzY+5/o1IcQdRuZVFqs/1OlCil5EFRKQD8IpPZvxfUdD
         GVV8vJoGTejHSHhlfmhi0egmVEPBmq3gCv573KKQ57/pdk1FPSbVzO8aZoldhshg7LLG
         z2m3ZQbegxY3f0Pu9qg5TyI5ZJh/P5mZtWLOOiQogxtJoz9mowW0ONuqZ1wpCzZwHuit
         +BVr9I7NzPGPBh2enZN3XafzRYkdUlo4Q+Y1uarEPoRwI4NtN7BzwGh7QIksWlx2723L
         mVlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=d1jazCfp;
       spf=temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org ([2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id f21si734223ljg.6.2021.03.29.04.50.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Mar 2021 04:50:30 -0700 (PDT)
Received-SPF: temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lQqPU-000cyZ-G1; Mon, 29 Mar 2021 11:50:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2D0E3305CC3;
	Mon, 29 Mar 2021 13:50:19 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0EFE92071A3DD; Mon, 29 Mar 2021 13:50:19 +0200 (CEST)
Date: Mon, 29 Mar 2021 13:50:18 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v3 01/11] perf: Rework perf_event_exit_event()
Message-ID: <YGG++nxhvVBSEphQ@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-2-elver@google.com>
 <YFxjJam0ErVmk99i@elver.google.com>
 <YFy3qI65dBfbsZ1z@elver.google.com>
 <YFzgO0AhGFODmgc1@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFzgO0AhGFODmgc1@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=d1jazCfp;
       spf=temperror (google.com: error in processing during lookup of
 peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
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

On Thu, Mar 25, 2021 at 08:10:51PM +0100, Marco Elver wrote:

> and therefore synthesized this fix on top:
> 
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 57de8d436efd..e77294c7e654 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -12400,7 +12400,7 @@ static void sync_child_event(struct perf_event *child_event)
>  	if (child_event->attr.inherit_stat) {
>  		struct task_struct *task = child_event->ctx->task;
>  
> -		if (task)
> +		if (task && task != TASK_TOMBSTONE)
>  			perf_event_read_event(child_event, task);
>  	}
>  
> which fixes the problem. My guess is that the parent and child are both
> racing to exit?
> 
> Does that make any sense?

Yes, I think it does. ACK

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YGG%2B%2BnxhvVBSEphQ%40hirez.programming.kicks-ass.net.
