Return-Path: <kasan-dev+bncBCV5TUXXRUIBB74D5WBAMGQEYZCHISQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C86873479CA
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 14:43:27 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id x9sf1091184wro.9
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 06:43:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616593407; cv=pass;
        d=google.com; s=arc-20160816;
        b=rOAPyVhfM5sETS0hFdKGmFDfZk3xdawcaGOyYkB6Mrg4ZdBly4cka5MTmNNS8kw7sm
         BF5Z63twY5j6Z4ntwo6VR0YS3WYxKh9bI12M54vxOZrX770hrKZNHxcyQthUheP+8ksq
         hdfadQpEBUM8ZAMfjOKSrnB44n3nrvm7YGvUxWlpK/x/DL0NVKm58ouMAsvqrlDCgYCb
         SbgJgBpuDH7ZzBUiqxI30bGpLSNfTpWhl/TT/y4HawMN0k7OAY+ZY5+EVqVhZAz3s47n
         OyVr7faQePGcnMhKs/bmRGUDyu+5+Ez/qofzWA6bK+P6wXEEP5wP7WTneqUPkENnCl+e
         0gMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OCXSwLiQ0sWjmB9wCACS0k+riI7iuvQ1gOEgHfVRC0A=;
        b=0GvlCSbG9fg2MrPvaAIfu3fsacotWdkJ/KSKkMgN2Pf2q14wGfzFX9pnAQMrggLrpv
         c+DOnDNPrIuRqBdEA9N3PDeqA4MgV+IriWojmVPrd4OZf4PTiKyCiBwzJ/vfY7EJdMO3
         CHCElYyoJdHKQ0VUHYjyeQmP3PFERYJMfFTYadjBjRN+3w57XxaTZdioY6v9JCEn/RII
         APRs1DniFn5Bpla286ATPtEGqUhot6bZYKzxh4YFvKdtFZYv/l6nItj6I3S2zphMvfEk
         r2CDwd+rYr1OkUDfx8M/duP0ajdYwEN995Y/qSnoq84yUqyg6lR51d7ceVGQcq+v0DXm
         icNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=dZ9ouZTw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OCXSwLiQ0sWjmB9wCACS0k+riI7iuvQ1gOEgHfVRC0A=;
        b=S1mQiMxD+4aOp6HpnMljZPo8H10ryK+tYj6jA3phlIQUAAZ5TSAqb1RHgUDxVgK/Yu
         Z8ZxISb4IX7PKIfdtAttOwKmKKLr2moLABjNhJPjArNBOASJmKd9RBwF55b2JC7+HzM0
         bT/5tusFYgTD48WyfSh517ff2tCw/jkhbcdPJLpvvMhMG/KE3J1B+YME8efzRUxrtBDs
         okE60ijhliIb0KhN2Q1vg9hybXgwY3jhScDa+y1fbBkSNPsKsU/36H7iaLWWzLCzy9NL
         EHQxfJ3QG3HBlLjjnsYflunZ3X/lX4YLB688kwbbwC4lo6ir9KE1g8mFi9sEoZmM7Ujs
         iDQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OCXSwLiQ0sWjmB9wCACS0k+riI7iuvQ1gOEgHfVRC0A=;
        b=JhIm5kRxZOdlxGZYQpvZ8cy419cjtmc97pHY0O80KBSl0otjysPp1y3ItulLPkSazV
         /1i9geldUckGAlk/2F1uUP9V7uW1nmX2Ihn2A4fCzWTE7l/VpSoxHdktMdSd5zsv+Yis
         g9hV2M9rZaXAtA8iEGJ5RpaUtPjy1DWKsjMLgplsXIr7eIpSJ6IWxOtA0QhwgqoxxhNQ
         sVrU6B3YNjT4qqmPYRxhBq7axjpozPJa19zk23hPn/NYZ0qTG8unusC5Xej8lLeoSN+q
         a2ZkXED1e1q+nt+PvuL58vsOClfShhu/jN1fwCB6nMRd4UqRwMZqcUYYO0Bq7e6bKNyl
         i4CA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jpz456RYwnTilOSo8GUwRALrq2FUQ0Saw43COLJ6ZlDof+kEu
	jAjvEE/2oegNa7cTgY2gMEo=
X-Google-Smtp-Source: ABdhPJzAc012ANqulpfRgbkpFr3xfPhvP2Awwkv/ZkQGqlOdPlhicA0mZm+R9EedGCXhUpZw9Zyg+g==
X-Received: by 2002:a1c:b783:: with SMTP id h125mr3036238wmf.106.1616593407557;
        Wed, 24 Mar 2021 06:43:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce14:: with SMTP id m20ls1027568wmc.3.gmail; Wed, 24 Mar
 2021 06:43:26 -0700 (PDT)
X-Received: by 2002:a05:600c:4305:: with SMTP id p5mr3007833wme.58.1616593406743;
        Wed, 24 Mar 2021 06:43:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616593406; cv=none;
        d=google.com; s=arc-20160816;
        b=aCfgDOW5nzdHG59EyKn84FkObQvByqJaJwvMBrxqGztKGr7WBfL+Y0LzIh6X+7pPXt
         zzTinBgQQMl6blrOh7ireyIhmEcTbCFymbQqV8xidCU8LBvOub2t82OFRcPiIzXwft4j
         envrbnnVivI+3bYgP+VgASDxxH2ZwvveVwC0BjHF++ri53NvdU0FntuiSnbkdgwVVvoR
         W54PDPADu5yrFJD21kyt1//NwQwHZumlVVFP39YEInzEk3RvRcv9os0eh1Uh6Dvf0lcK
         RJ3HIlw3IaKGFKpFkjEUYXbB/0u+0DJa/wOxhShvzVqOabNfWmAOXxBq5TTzM/4zwDBY
         HCNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Z6YnZKE8JuXjPtE8/pNf6OtFYxSIiBBingu1TKjuVH4=;
        b=HLsNckmrrYRlI8/WZc0d42NdmePPLHf8BtvGbEVRDucYQM8S9ENyAi9RY6D7G/dNWe
         qjqoTLN3Z6PJ8VhhTzVtsvs/j7AQz5c4NBH6mrWoY9UO4NJK36Mp/Z68YsJUeYhYhcob
         org41h0N2+PCwkmztBAG+rnoR7LNNIsmg5aP6LbhapS99tRIkpCRoO7WT6n1+wbUEdH3
         6c8S3xLDhRNquL1VCUuY3J8a7fvIh5IFXcuSf66QssE1uWMZgQPgkXO11DFKZw3c1mRX
         L3JzPjLMbXO+DnYAercgbzCLQHwr55oeRmwbcE+4ZdILV+n2iOUtanubMkvP/jscfZA2
         pR4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=dZ9ouZTw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id z202si81357wmc.0.2021.03.24.06.43.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Mar 2021 06:43:26 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lP3n8-00HATU-Ix; Wed, 24 Mar 2021 13:43:22 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7FC843003E1;
	Wed, 24 Mar 2021 14:43:21 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3E23520CCE90A; Wed, 24 Mar 2021 14:43:21 +0100 (CET)
Date: Wed, 24 Mar 2021 14:43:21 +0100
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
Subject: Re: [PATCH v3 07/11] perf: Add breakpoint information to siginfo on
 SIGTRAP
Message-ID: <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net>
 <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=dZ9ouZTw;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Mar 24, 2021 at 02:21:37PM +0100, Peter Zijlstra wrote:
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -5652,13 +5652,17 @@ static long _perf_ioctl(struct perf_even
>  		return perf_event_query_prog_array(event, (void __user *)arg);
>  
>  	case PERF_EVENT_IOC_MODIFY_ATTRIBUTES: {
> +		struct perf_event_attr __user *uattr;
>  		struct perf_event_attr new_attr;
> -		int err = perf_copy_attr((struct perf_event_attr __user *)arg,
> -					 &new_attr);
> +		int err;
>  
> +		uattr = (struct perf_event_attr __user *)arg;
> +		err = perf_copy_attr(uattr, &new_attr);
>  		if (err)
>  			return err;
>  
> +		event->siginfo.si_perf = (unsigned long)uattr;

Oh bugger; that wants updating for all children too..

> +
>  		return perf_event_modify_attr(event,  &new_attr);
>  	}
>  	default:
> @@ -12011,6 +12010,11 @@ SYSCALL_DEFINE5(perf_event_open,
>  		goto err_task;
>  	}
>  
> +	clear_siginfo(&event->siginfo);
> +	event->siginfo.si_signo = SIGTRAP;
> +	event->siginfo.si_code = TRAP_PERF;
> +	event->siginfo.si_perf = (unsigned long)attr_uptr;

And inherit_event() / perf_event_alloc() want to copy/propagate that.

>  	if (is_sampling_event(event)) {
>  		if (event->pmu->capabilities & PERF_PMU_CAP_NO_INTERRUPT) {
>  			err = -EOPNOTSUPP;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFtB%2BTa9pkMg4C2h%40hirez.programming.kicks-ass.net.
