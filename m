Return-Path: <kasan-dev+bncBDBK55H2UQKRBZMAQ2NAMGQEMAWLHLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 194055F857D
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 15:51:35 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id u24-20020a2e2e18000000b0026dfd4bd721sf3004354lju.22
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 06:51:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665237094; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ll8IrVmeNxLQbH9Hoc3SCieiBR9JmCUVRPC0S+N2MnWCIGXd83mUCQvyPdjBG3odTZ
         IA9BK8f/fnc5KXaO4Whdufom3vY5KmmBy6+NINsLjvn8sTWjEaAR74XeyS+Y2mjRXehc
         4sG1EFRXwt4RXPAtdTqQBcJ+pEQE87jmtUnbLkU+Y2Kvepr9m0cjHZO+Izbs62s5Dm+L
         QlHSw5b8heh6bXCzsuxquZn/W+rVq7aJ4VnikgRHUWFvD25fI6FdqDg7Tx6jXTMO9GmU
         2G0/hchPbojA+8kHXezYtj2pEiAWCqcImkeajm5w8ZpVLRlujWkCKTkg9wcRq8xijkWl
         xtKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=820JQkB+7Be4ZZPogVKlZp89jCAWTBvRSHMnLLbWvBo=;
        b=BJuSvHxs3JMXRV5xKMAG43SiVJSt8rxU50OFseThoFO6YaZaDjlCnyTuYE8lPzeNdz
         iYCPauKIHDEjcsTjTlIKduheTgOIFNXMkK4W67UPIko8e89f5WPy3XcVSs8ZII6Gsxe/
         gL4vQqGoWt70xLCnBAh1PBxvzfCbixKIyXAemF0bnQjTQLybIbchsKtT+DndtukeclUH
         p+4zC5JM1xNaRJ/jr9XKIA9gjmcc5nkLBR5XyG16mAAz335vJUr0bFV5zJuqpyMoGC8E
         QtLFFvvpe7VrjVuCux/PSzf5yX+aFZhEJDHe0Herg0b9UUs/HAmN+PloKKlO/Xa5RpHg
         JWvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=pCwuzjOU;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=820JQkB+7Be4ZZPogVKlZp89jCAWTBvRSHMnLLbWvBo=;
        b=YvB8Y57jn/7hwsnV4Vb9h9wsUWTRmXVsp1xI0BWpX2hmBLffWniI88K/Z8cl2/z7Lg
         FVXqzcm2QaUhLXDo3jLedEmHhIl2NpoOsIUd2Yr3ZCGy/BCRarTfi37IEbb7c+mnLyZN
         wQCu1tjMwOqy5ehGvMFjAGRUiwilq8q3iYDEScVa+linSs3/sVoMxfK284jzlOG+EFFN
         okARu8eWqg928ndMFx869HuxVMEJVl0sNvCnvVjSiM7Fbm1AklYZkWRBCQaNyXzYl9KG
         on6EkSQK69DQkAmQnVfo9PFPj/E1ml4VhQmMafFm+6KXFreLnrqHZ31TgeAoKbg7HPtR
         HpDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=820JQkB+7Be4ZZPogVKlZp89jCAWTBvRSHMnLLbWvBo=;
        b=CLwnYuDB5bI6JrrS9wLWW1aSD+hkSMCi+vqbJdCwwOaURUHECupw1Cq8g0yFw9tzjg
         +CS2Y46uY7Uzse/jzH0EbpxfbleKGMRcBL9UJeQG5suzY2iZX3n7uPS1nB41J2TxpaVD
         UyX1Tf2lI0VcHrEBmuOKWC5yyrNVsPIhB0HKkt8F0w4U6nCo1W/xs2ZaygIrzOoACx/t
         Zqjg9pqfZEAeJvoYQhfMyxw2Ek88iCxZgVLCXNyayzETNB8NTTxQJJLKTrPrJvkrJMVL
         wFdYmx20wryyPbSA2DLZ/tgaWTlPmhwu+xEnMqxBkmw09xrfkeV3wHcr/NuZStI7GMsp
         8sGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0hc4NdkXN2veT8jhcU45v/6lKaVcuSO6BPh6nPJ4R3peb0jjmk
	NctIXaMR9Y/KWmxV3UYhTFs=
X-Google-Smtp-Source: AMsMyM6hvRS4O94h5Yz6qD/DnNCkjUOCXNVcV/kRurQp5azmdt/mesBOuOTXdepcObOEIYwUuRAWHw==
X-Received: by 2002:a05:6512:114e:b0:4a1:fcf1:c3d1 with SMTP id m14-20020a056512114e00b004a1fcf1c3d1mr3299369lfg.248.1665237094198;
        Sat, 08 Oct 2022 06:51:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4ec6:0:b0:4a2:3951:eac8 with SMTP id p6-20020ac24ec6000000b004a23951eac8ls2773346lfr.0.-pod-prod-gmail;
 Sat, 08 Oct 2022 06:51:32 -0700 (PDT)
X-Received: by 2002:a05:6512:2290:b0:4a2:aa4d:b281 with SMTP id f16-20020a056512229000b004a2aa4db281mr2746870lfu.616.1665237092397;
        Sat, 08 Oct 2022 06:51:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665237092; cv=none;
        d=google.com; s=arc-20160816;
        b=GDU4H/eeBiPTfC6zOySVM9JGX1plRJ0ugRMnOYW//7/IHnAGjhUKKfhmudos+eyelj
         TBDacXsxptt8v1ptpORY6aYmtDLD7HW10o4hIlokyIiWoKZBq3UuSRQQQh93J8arLh6D
         eAK2w7Frghfb4oS4+p888qeUIik1+pWx/QlUFSXblBVzj37I7FbwBTqUc0hBcvtVD1li
         MUfPY1Vs8oOkBxd+DvpNq4jK7n25WmmsiscaCzTPO4dA8LNbDrXxojhjxRaJx2fIZu/d
         LThNYAMCY6zhPFYAxPDhq/XPseOcfzl+Z14jYQF/1O+JiStr9km9pkq1Xg6MUje681ov
         OEBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=AwbDRp9Us0UrL0zD8MoR0o+YWUfajcsfFiC3fOiNTTM=;
        b=iyniwTLC0vMO3Cp3Nq8Qo6XMa/uwdvZWMyatx+X2gxuspq73piFnGWrw8+mFcLlOn9
         vmOoYT3kzTD0UP11KD7U51TjCl9YHETrG6kCKMx55MLL7cUJbpXgCD2/fWkMr6pLTOj1
         l0MKA9siFuSAekY6dSUqLCnatOT5GD+3/3mONw9yYFTiVUTbZpxmCTVaa+unFzmnk6LI
         /HNF2xniis+cq9QTJoc9+6h+Sl2qk3LM4tbk59E8Y9uw99/kYIUeaAmmTV4KySSP+oog
         n2Nkz/CFdA0TphPrOKjLpEKlNviB920vkUkGKvmdUCWaqEHALhWwW3EUDDy6keVrf8Ja
         2tNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=pCwuzjOU;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id o10-20020ac25e2a000000b0049ade2c22e5si181516lfg.9.2022.10.08.06.51.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 08 Oct 2022 06:51:32 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ohAEj-002ijA-Nd; Sat, 08 Oct 2022 13:51:29 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 65D62300445;
	Sat,  8 Oct 2022 15:51:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3CD5C2BE948B4; Sat,  8 Oct 2022 15:51:24 +0200 (CEST)
Date: Sat, 8 Oct 2022 15:51:24 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs
Message-ID: <Y0GAXJkwK5nXeFfG@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
 <Yz/zXpF1yLshrJm/@elver.google.com>
 <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
 <Y0AwaxcJNOWhMKXP@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0AwaxcJNOWhMKXP@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=pCwuzjOU;
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

On Fri, Oct 07, 2022 at 03:58:03PM +0200, Marco Elver wrote:
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 9319af6013f1..7de83c42d312 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -2285,9 +2285,10 @@ event_sched_out(struct perf_event *event,
>  			 */
>  			local_dec(&event->ctx->nr_pending);
>  		} else {
> -			WARN_ON_ONCE(event->pending_work);
> -			event->pending_work = 1;
> -			task_work_add(current, &event->pending_task, TWA_RESUME);
> +			if (!event->pending_work) {
> +				event->pending_work = 1;
> +				task_work_add(current, &event->pending_task, TWA_RESUME);
> +			}
			  else {
				local_dec(&event->ctx->nr_pending);
			}
>  		}
>  	}

That whole thing can be written much saner like:

	if (event->pending_sigtrap) {
		event->pending_sigtrap = 0;
		if (state != PERF_EVENT_STATE_OFF &&
		    !event->pending_work) {
			event->pending_work = 1;
			local_inc(&event->ctx->nr_pending);
			task_work_add(current, &event->pending_task, TWA_RESUME);
		}
		local_dec(&event->ctx->nr_pending);
	}

Except now we have two nr_pending ops -- I'm torn.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0GAXJkwK5nXeFfG%40hirez.programming.kicks-ass.net.
