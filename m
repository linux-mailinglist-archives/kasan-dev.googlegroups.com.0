Return-Path: <kasan-dev+bncBDBK55H2UQKRBV4IQ2NAMGQEWYYHI5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 086F45F858A
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 16:08:24 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id h129-20020a1c2187000000b003bf635eac31sf1227382wmh.4
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 07:08:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665238103; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qpjgo0Hkv9L8M8r4/QdZkEqYh6CPQ7diYo0S1BkfozRyG/0t9e+qEHX99UMP8Qkq12
         3r6UrYBr+jfHTmQcKX/TGSgEuhEirxzA/nSZd48WRkOCHSQePkMeRzVoY9SJChw1Lwkv
         bqokiR5cgyExffkeEOi7xjNDrskufjwVov7ZZ5m8+yezYDfolxi5AdU0RQ1Ha2iCNH+z
         JuzkWfTNmDIfUxp7ZvNNkDh9g78KJpGryqyvwxdY4vtUEk94olG31nd54wJRYtiGeyo3
         I0GGRXi+nIe/kK4+UllBBvAUnZGyn3mhuf+YDWbzRXcx3ieP6wIGqeFfTgosVK4cbFB2
         vn9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VKs+g/yB3Qig+vyVAFKQ7MSxI6IADQ0N2O5xhNmu+cs=;
        b=N6XT/QA9+QcYzvxyDOQgaMEzKj0lrITOLN875VzKixIazDRB7ZtaosMDj95tnf8fi5
         OxXCcr09SIkw6Y5fSaLXfTEni+MHE3Z/4DgQXCjiyDkajYo7J/ZSSHmXSKTGAfDJM2Jy
         tNGouOQPwYF8/oJG0A8b15lhsHyodtKcRK2E4jasXe6nzf+kJqTqypx0lwalu5FLJ0+s
         aTPyRcZhrdCjJfsBIyVbRv0Un1gJUIerGVa7HRlPnyfYi+F+HqgxmmmLEUhcV9buamB0
         Thik7Sm8a1vgLOaQq55eJtNnTIno/HKibi55N4vCnoLP2FgskoqRLdBLPGc5mjre9Rsi
         uzMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Tc+b8pBy;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VKs+g/yB3Qig+vyVAFKQ7MSxI6IADQ0N2O5xhNmu+cs=;
        b=gxv2FEeNo7PvJFN2PHpfokzUB/qZGI9iynKylW2JHULF1pu8f04TR1BmbLsnaPiljy
         8G7q6RxGxVMKJVa/hC+zam2Dx15S3C5DtGKlmWT8IW/Ks6Yddku73avf/gt0Y3kz2F//
         PLAkIXIV67HCxvS65xcr04oMvQgjeRA3l+2VczWY63YDB5022fi+izoIegnVbemP2f59
         /3KcpkkpCZj34FQ+JbUjDDMpR9BhcaorFlM6m6Qx07UyuCjHA/rzoWwMjmL7VT6KA4xD
         4ssBs0MZ+pGujtHYypA/bZLcet0706WCQ1P5zhIajG7ooHvcHd8fEv9eyVOwjjWuCpu6
         1tjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VKs+g/yB3Qig+vyVAFKQ7MSxI6IADQ0N2O5xhNmu+cs=;
        b=7OcIQqmMbcTrLTSZ2aEnEdtzEqpd3lCroc6IeBtNqFO2YcWn4QoU5P+J8YBC939XhE
         TI8Z1ZY6G/tj4gbPO84Rl4bFO+Q+VxDiT2dRu2mG5Dcf0aOkpjrKsyzVztdhuKagQFCr
         jRdmwx3awdoTEZy01rMFqbzgI7fxvIoSdLDS0jNTg4CT/lNDRh0kHbI4q7nLF5E+2pk2
         SVw+GAdroXHuXz0LZhbqsQ1+Hlg4mz+dDgPuCbcfHIHKajhqFW5S3ocdIK6hBooTDpU0
         Hq/8NwYhcFP40XnXMFfBVm0Ojo/6gyir9Wnw6KNeEFsnNmlHkp5k5thalsjEyJpkgFxw
         OHaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf23P/XCM+a4Fuch8E74bSGcq+v6rYgXlrm3m8SbMwBBNI5alTev
	p/1Yj4kcXbjuSb1CVEY+DPE=
X-Google-Smtp-Source: AMsMyM5BGLpqsL7EwI69b2Z8vQD4sAntTCxKdvGTrjbg2zwKxF2Uwww1K/DTqb8Z1kbgC/9LZLjadA==
X-Received: by 2002:a05:600c:1da2:b0:3b4:856a:162c with SMTP id p34-20020a05600c1da200b003b4856a162cmr13362726wms.28.1665238103574;
        Sat, 08 Oct 2022 07:08:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f0a:b0:225:6559:3374 with SMTP id
 bv10-20020a0560001f0a00b0022565593374ls3929293wrb.2.-pod-prod-gmail; Sat, 08
 Oct 2022 07:08:22 -0700 (PDT)
X-Received: by 2002:a05:6000:1ac7:b0:22a:906d:3577 with SMTP id i7-20020a0560001ac700b0022a906d3577mr6570456wry.33.1665238102282;
        Sat, 08 Oct 2022 07:08:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665238102; cv=none;
        d=google.com; s=arc-20160816;
        b=ElKA2RvlIXvnGm9Shj46I5q0Pid6wwE9hIOFKdtf3NLfIuKYvNfeczKvOag9+VFBnh
         /dBl7pHr3uUSi7g9xmQlfsRSfwfyrRI2DEI28lRmevOF0jtrMLAo2oXxnm/Fa1s+rpMa
         cVaaHAI3+AhDe79BlaAJo20GZ0uGJPkJNjb1MLwCvHQ8NhqX6D6U6IuP00v6c9BipRjq
         sVoGMYJj7cHvQpOZ9IQf3WQgWH3qq8ZPaGD35U18C7mUqCV54rA3wRYLJwcO/fbCKN4C
         +N04KgHIXnn4z+hnPuMUdwZj7NHnS153iVtlnuA8cA9a7jq61GGC7PadCCldttqgpW4F
         2cYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wD6pqrT2g8oCJelnKZKJ0EZlxxhJxKsk3kEfOiAnIBA=;
        b=fblymq+ONpi6G3e8fo0yfzl4Makep3b5dnB5zPiKBtjo1SXFC5Q054oNLCl9EQQjlO
         jaN1EgTs06F2m6anK3lb4iTaeltldEFfummp441QQPOUJpT7E62EBKzwARfVBCwnCxqO
         ulm4lKiaLBdTjsSdh3iNNOImZ6F+C/ic1CBRN/srjYV2o8U9Yx1HPE1X2pqevsCwJ93d
         KbVupNlttGrB8CWPnAWXVtPN/eTnxtZYhBaD5O8Q1DSgyNOO7zETSNqOe/BGYwPAM/wx
         R4kTW4NPkuV0crn26IDN2hPHmAxdGrzDd/wrLnUN/TPB9/NISQLjb7CM3vepJBkfMBLr
         Fupw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Tc+b8pBy;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id az23-20020a05600c601700b003b4924f599bsi468260wmb.2.2022.10.08.07.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 08 Oct 2022 07:08:22 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ohAV5-002jXU-Jy; Sat, 08 Oct 2022 14:08:24 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2E6C630007E;
	Sat,  8 Oct 2022 16:08:19 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id DB4AC209DB0E9; Sat,  8 Oct 2022 16:08:18 +0200 (CEST)
Date: Sat, 8 Oct 2022 16:08:18 +0200
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
Message-ID: <Y0GEUkLWDvU34h9f@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
 <Yz/zXpF1yLshrJm/@elver.google.com>
 <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
 <Y0AwaxcJNOWhMKXP@elver.google.com>
 <Y0GAXJkwK5nXeFfG@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0GAXJkwK5nXeFfG@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Tc+b8pBy;
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

On Sat, Oct 08, 2022 at 03:51:24PM +0200, Peter Zijlstra wrote:
> On Fri, Oct 07, 2022 at 03:58:03PM +0200, Marco Elver wrote:
> > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > index 9319af6013f1..7de83c42d312 100644
> > --- a/kernel/events/core.c
> > +++ b/kernel/events/core.c
> > @@ -2285,9 +2285,10 @@ event_sched_out(struct perf_event *event,
> >  			 */
> >  			local_dec(&event->ctx->nr_pending);
> >  		} else {
> > -			WARN_ON_ONCE(event->pending_work);
> > -			event->pending_work = 1;
> > -			task_work_add(current, &event->pending_task, TWA_RESUME);
> > +			if (!event->pending_work) {
> > +				event->pending_work = 1;
> > +				task_work_add(current, &event->pending_task, TWA_RESUME);
> > +			}
> 			  else {
> 				local_dec(&event->ctx->nr_pending);
> 			}
> >  		}
> >  	}
> 
> That whole thing can be written much saner like:
> 
> 	if (event->pending_sigtrap) {
> 		event->pending_sigtrap = 0;
> 		if (state != PERF_EVENT_STATE_OFF &&
> 		    !event->pending_work) {
> 			event->pending_work = 1;
> 			local_inc(&event->ctx->nr_pending);
> 			task_work_add(current, &event->pending_task, TWA_RESUME);
> 		}
> 		local_dec(&event->ctx->nr_pending);
> 	}
> 
> Except now we have two nr_pending ops -- I'm torn.

I've settled for:

+       if (event->pending_sigtrap) {
+               bool dec = true;
+
+               event->pending_sigtrap = 0;
+               if (state != PERF_EVENT_STATE_OFF &&
+                   !event->pending_work) {
+                       event->pending_work = 1;
+                       dec = false;
+                       task_work_add(current, &event->pending_task, TWA_RESUME);
+               }
+               if (dec)
+                       local_dec(&event->ctx->nr_pending);
+	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0GEUkLWDvU34h9f%40hirez.programming.kicks-ass.net.
