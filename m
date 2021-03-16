Return-Path: <kasan-dev+bncBCV5TUXXRUIBBZ5WYOBAMGQEHL4QORY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 154DE33D927
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 17:23:04 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id a24sf13631394ljp.16
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 09:23:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615911783; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mc2WaNH2hd/OCpfgJaT9mjtiGd6c4aCw/iGetlPoVm0IbxzxUf7ImaQ2vihBJPlYdJ
         uluccIuQcYAnVPbgAC+zU42ECCIQaZ+mQBMi4wfbarKqOx2xHvH5aipqDswE4eI+vZp2
         SwRSWeQNlWsIUWgd8t3k4D1m294Il9pzx6cd3Eifb6/Kn+tmw+HOsZ7722nl81ADvNdU
         j4anhEh40PYOlhtE6wVqyN5o5sOkDJq2+QLG10op6P2qOc1+f6nFgHtLwiM/6EnaXMXa
         uhb2JE77FmCuItQiY1HqvJIUiztHK1ameXm423dgvGY8+hcLfgiCKhuKXF+JVHRMHjmr
         WAZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mtocE2M87EhRIQwu3V2CPlo2qVbHVBCWByF4/2bxu8A=;
        b=eoRzDrU/42iv8PL77kv9k3HMNndEf5mKvTpBFN6RDELCXNol5XeEXUCL/CG59pywgu
         vrVopApuv4fy9xFoZo6vD+s/mKllNt6BtllRzOW/UuhYuLDegkDU389fDaazd9Ht7Lyf
         L0P5QTC3Cq/b7l6xP93YFHu3DlRUjapj4R+2EM/gpps65RaPLRdkeRi9QzgWKxfBFXpy
         b7/tBiQ6h6Nxh6/QSfmgv8qFW6XmbpjC7NbezfQvKpxQ6K0YmIuR3EncHECE7wN2gXq8
         7MKR6i/q4LdXXRjFdsfFYegKFljUQFwLQx5B4pQGNoulq2A/89iNWdr3PcyAb3z3MI2y
         vWGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=e7JSqiKn;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 90.155.50.34 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mtocE2M87EhRIQwu3V2CPlo2qVbHVBCWByF4/2bxu8A=;
        b=hrnhONrwpU7zPIR9kn1rkTScB4d/cddQDX8l0QplUB7isIMCxvrH55nJpc2c+oUQc8
         3rHSG1MQ+E/DWpMlqoVPCc/r7ugXL8gduDIOM1Xw1+7CcBxuA4qQASf28k39/kl7sSQJ
         Zy9CMT1qoYCQX0Cr7JrM69jJqxErAlWBA905WNFDoV9eeUOEcmiwVnIyVCYf4dXgrFMj
         xaNSWyRw+AbuTeQ1k3WwHkBNLLIqtCv3hNulN9VyE/0V63t2IPOs3PFQLpqtBMq5RNxb
         9yQNa9VMVP6AUOQAbI0PAWLMBxQh4QxwTSteKHjZInKqB9NHBHW1POnDbMuuBzAbRBM2
         HRwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mtocE2M87EhRIQwu3V2CPlo2qVbHVBCWByF4/2bxu8A=;
        b=quchv1/ZlvvpRrEQKvqueLTAOE2uFiSih2V+i/2Za5jj4/7fF1/9CnYJZs2jcA0G0H
         XV54cKhSCAi8h1oi17bWGcVF1Q3lIGTJyu5qQSX0o+Qe6FMS49xdi7gJfiM4d2kV3lMt
         EpSsNUYwYQqZJejZunMljhLlepHe0SAhc2lf+We/ffe/s/p1W6fNlVqg2PFU1gM/wor/
         8xAreW7P43dD1Y377BJL/eLrxPpeF5qWVxnw4QfYbf8OdUokdr2xvI1pn8X9dwPyDnfH
         jVJmdM1DJzB+qrkoo5hwRZxLZkiDrM66ZSA1Byeo367pm3lC6Ne+JxB1K8Y6RexLPC0G
         Kisw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x140z5wYYqnRjxpKnd79Q0OrCbN6+A8LHGCB4dTtBGdM16YDQ
	sn+J4Md367wl/F3SPE9fhP4=
X-Google-Smtp-Source: ABdhPJyHtH8NsV69ZKbO+D5QkX8HcO1HIMCGzyH9QdAtKIfW6mvkDnMcLTfwLnhIcdZEplLUQqC+7g==
X-Received: by 2002:a19:7e45:: with SMTP id z66mr11745074lfc.612.1615911783616;
        Tue, 16 Mar 2021 09:23:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a409:: with SMTP id p9ls4301189ljn.0.gmail; Tue, 16 Mar
 2021 09:23:02 -0700 (PDT)
X-Received: by 2002:a05:6512:1054:: with SMTP id c20mr11465687lfb.170.1615911782638;
        Tue, 16 Mar 2021 09:23:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615911782; cv=none;
        d=google.com; s=arc-20160816;
        b=YksgAgGRjb1r4+M1Jpq5KL6b+lOOXNkcBps98J4olXSS1rgrQOBmvNXcHJmy1u4sbQ
         0aQRMIrnbSFe0qx2ZGe+GuIJ7nTAx9UDNsVNWU6XJ7vneRBVafpecykahSCTVy2WflcB
         CfHusGQ7JanCVfwIdbNqXDXS9zjPKE59hU4yX4Wk79+ZjDibfw2wyiEbb7vceXpCU6Zj
         HxaiM40PhNByARny0hw0NKKb3NE7bS9fnZmjZBMc1iLqiMTNA3dPR3endhR63001Mboc
         mu+TtuXXhYmEJ1wU/qZWB9gME0MMdFJN+WN3IljXgcUUxJKwjZZzgxeWv6Qt6Zl8bB3d
         kH/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DBugU3Nv275YIe120uunlkMX1JrxtNo2cLcdJHIRRa8=;
        b=GK6YdrN1Boa/g6So7CJCqvg5bzZOAn4FZC2nj061XoGMQ6JsZHpTOZRSNsGZht3Wod
         yDUbC/36qiedzgviox2j4XJRZumpxZXwuKCdYHw2aUpN1NG+ghxvtTa/bcl/FkVTwq73
         BVmg2dKy2fWWVpL1mOTC6uMgFo6Bt/k+Q1GZABQV56c9+ouP9P7Acz4nkRi+msC/qd1B
         6SoXrzX/tkiHHY7kJmNVeGZzBUUMc3pyxUIGix5OkVQvREZhhx71E7dDr+P/8ab4weVi
         4QGX18pRYkH+2JyacK+jJ7tBboj1Yfgk4GpwLmYndrc++kstmAPSgKOaIw29smwI6anV
         hBWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=e7JSqiKn;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 90.155.50.34 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [90.155.50.34])
        by gmr-mx.google.com with ESMTPS id p18si653207lji.8.2021.03.16.09.23.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Mar 2021 09:23:02 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 90.155.50.34 as permitted sender) client-ip=90.155.50.34;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lMCSf-000J72-0j; Tue, 16 Mar 2021 16:22:28 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 81C26305C22;
	Tue, 16 Mar 2021 17:22:23 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 52EDE20B05D7C; Tue, 16 Mar 2021 17:22:23 +0100 (CET)
Date: Tue, 16 Mar 2021 17:22:23 +0100
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
Subject: Re: [PATCH RFC v2 3/8] perf/core: Add support for event removal on
 exec
Message-ID: <YFDbP3obvxn0SL4w@hirez.programming.kicks-ass.net>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210310104139.679618-4-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=e7JSqiKn;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 90.155.50.34 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Mar 10, 2021 at 11:41:34AM +0100, Marco Elver wrote:
> Adds bit perf_event_attr::remove_on_exec, to support removing an event
> from a task on exec.
> 
> This option supports the case where an event is supposed to be
> process-wide only, and should not propagate beyond exec, to limit
> monitoring to the original process image only.
> 
> Signed-off-by: Marco Elver <elver@google.com>

> +/*
> + * Removes all events from the current task that have been marked
> + * remove-on-exec, and feeds their values back to parent events.
> + */
> +static void perf_event_remove_on_exec(void)
> +{
> +	int ctxn;
> +
> +	for_each_task_context_nr(ctxn) {
> +		struct perf_event_context *ctx;
> +		struct perf_event *event, *next;
> +
> +		ctx = perf_pin_task_context(current, ctxn);
> +		if (!ctx)
> +			continue;
> +		mutex_lock(&ctx->mutex);
> +
> +		list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
> +			if (!event->attr.remove_on_exec)
> +				continue;
> +
> +			if (!is_kernel_event(event))
> +				perf_remove_from_owner(event);
> +			perf_remove_from_context(event, DETACH_GROUP);

There's a comment on this in perf_event_exit_event(), if this task
happens to have the original event, then DETACH_GROUP will destroy the
grouping.

I think this wants to be:

			perf_remove_from_text(event,
					      child_event->parent ?  DETACH_GROUP : 0);

or something.

> +			/*
> +			 * Remove the event and feed back its values to the
> +			 * parent event.
> +			 */
> +			perf_event_exit_event(event, ctx, current);

Oooh, and here we call it... but it will do list_del_even() /
perf_group_detach() *again*.

So the problem is that perf_event_exit_task_context() doesn't use
remove_from_context(), but instead does task_ctx_sched_out() and then
relies on the events not being active.

Whereas above you *DO* use remote_from_context(), but then
perf_event_exit_event() will try and remove it more.

> +		}
> +		mutex_unlock(&ctx->mutex);

		perf_unpin_context(ctx);

> +		put_ctx(ctx);
> +	}
> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFDbP3obvxn0SL4w%40hirez.programming.kicks-ass.net.
