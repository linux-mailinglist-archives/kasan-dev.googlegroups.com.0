Return-Path: <kasan-dev+bncBCV5TUXXRUIBBI4M5WBAMGQE2QRDC5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B24AE347A17
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 15:01:08 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id v5sf548221wml.9
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 07:01:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616594468; cv=pass;
        d=google.com; s=arc-20160816;
        b=QpZjurwq6nOm92Yi22nki6ZQ2C8NUJsFfUHDbc4YtqlGnrX4O6YgGeWPh9UL0UyUmF
         jQtevEI6w6IBH6zwKa/0CbeMmTzENBkSBlCbuEurmhBDF7YsAt3Gmy3CUuwrlpDdGS7S
         C8uLyXBRgWf9lPz6ZhQVoCmHZVg4DpseX2YyJIfXfHVxQrSHWjJuvAaviRWV8H0w8CIN
         3PlUzdJ94X0Gi9HRTj95U9cWI0UvHsG+xmujXG6sEEXbza/EX0WHazynAbkWLZZPHV5y
         m6KavM8WJsPZo4bYnvdMXeGZHX1Z8KEvaxjedd3Hm1/HR2L6V1S7BkaH7B9RPDuT+ldi
         xt3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gM66nrLn3mZlRAcVifXkUVMOubv+0nPvOwUSxiPZdis=;
        b=sf6hFYP/wtL4hIoOnKihKQrX8nb5B5d3Mgrta+fbasnYx97mEo6GsNVGGCsJNivVxe
         KAJ5DCYqrcg1ZsgoBHuGDirj5+ANmotWRWTjeTYIKrNnsF300kkuwxDuaUifpeccYuI3
         hoI74CnyZwdtPHrE2pRu0UBMjsq/7n89xkQpOf0p0w3vNVelgCTZsPVNv2lJHPO7dHrR
         4LyS0MuZbdH6tRwSR7ZaKan2ZXEu9Rpi42ss4/kC5t+AuD7RmfG5OJyFo1YKs+9FwRzw
         IpSQAIEvhDawESECtLd8aWOtbvrI/l3D6Ugw1liVXk5jpL4m98gd2lfMuCuT2NfLIQPU
         Hncg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=NfULNOrZ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gM66nrLn3mZlRAcVifXkUVMOubv+0nPvOwUSxiPZdis=;
        b=bff4gEug6ebpS81BhBimua6ZLwKAyfbi4YPU21zwQ7Ad744dIU00bGgHuGgKkl9rGu
         BflD0uDHdOoIyZFFK+oezS9lfqA9U/KBo3FL4P5/U4tWcAqShUWo4jjRsRNfQfe7KdM1
         1G0ezOsBLacu8s7MrVOqZuhlRzB+gOsA8ePMwJ5P+kNfT4G6UMSSngZjzlZn38JW0ext
         BxVCppnj0poCzBq4pWbzr+v4T0+hwY9fBidf9Lsm6y/sy1quAnQ1xDF9nNb7Z9q1HSq7
         RSKDMSChJztdWCTjfW0I1USat+qyXfpk7YcJr7/Yz/Db66SibYJvH1Hr/CIlcfegHrLY
         aslg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gM66nrLn3mZlRAcVifXkUVMOubv+0nPvOwUSxiPZdis=;
        b=EqiJfjKPykRfhXbHym59OXv5tc/wXv7QOp6LgOOxul3Pln8sVxwt8Cg5AxHHPzIA/j
         dX3bUC41uVmG6YfKs9CulG8BIzHN46CTIzvddOY0NpYuDcSCpjbXvArl9rCtewd36i9e
         rIIIBWAgCkpcxd3j88XpOti2g0nq+PLzbyCaMEOLLzKh7MYNuwDW7u1zV09W7lGFfjGw
         MRqtQwfpUIdqb0PFqDpFrTvBhnwkKRt9A02/qnaGl5R2xhepw+XWOss1es7jko8C86Ye
         n/cMcqbHzMmPVo0Xl+xT9c729IdHMtOFYtcbEbP38bhFkSJC5CNVJPDcUCaH7NLn5zbq
         /4Yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CgqsFxDzfwloTRmT6TKt+VA6nza47E9nPb2h0N6b0rvHsxi4J
	8INRD3g601bCT16T0TEHxjw=
X-Google-Smtp-Source: ABdhPJxR02Dqdk98E13OuStFhOyupqx/2QxglbmWWSGmnmdZ0IiSMNPB8NigZ2IQ9BwmDBhKWgcU8Q==
X-Received: by 2002:a1c:5f89:: with SMTP id t131mr2977913wmb.173.1616594467455;
        Wed, 24 Mar 2021 07:01:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1c8:: with SMTP id b8ls212179wrd.3.gmail; Wed, 24 Mar
 2021 07:01:06 -0700 (PDT)
X-Received: by 2002:adf:f843:: with SMTP id d3mr3601483wrq.55.1616594466280;
        Wed, 24 Mar 2021 07:01:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616594466; cv=none;
        d=google.com; s=arc-20160816;
        b=iPZrF6U7M3PhG60AiUnThSoom+Cuq/7Qv8+RBCIr5UM8WhZPkK5pCRVD8R5oxg5Cyv
         WUi6KssHzbwDAANF3rAP9f2r18oK4pu4ZvHcmqQ0svPSKWFpt94O5OxIUncsyCDg36Nz
         AuuBfuld7Bwk4L3AFUU0gvY56H4jU9I4uQgPw5EbCFYCsKh8GLSZBHmieysQ5Hv8RSpR
         V646zB/y4t3eD8FSP8FwUs++lpLDOW5A+17bwuokYex4PPYWnFn+dswcNt9odtgOhmlQ
         nzslYovMKvh7syQczyZKeH38WLeS4TrfgfNcTydQvsMDdzIHT5BUJt9zfhQQnrwG2TEw
         grZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RLK0n+vWBgvQR+BSn/9+/c3c8WKIPg/Kphk7CJk6G50=;
        b=JrsreAD9ku+mqqeDXe0dirp1aT5bYmhd8EV9Ldnf7VnrGA8b7oJns+z6j4mA3lqfgE
         zVWSmsslCgIJmgXUzEuZt2dB+i7u0dc1RDw3fbp+sBwPT7GBGMI7xBUWvzTe9iP3zrGu
         AVtD0z3BybGY1PfYi4eJe5mxKVkZbNwH+/tLkFf3lYHL7CqZttqdDg2mk9JrEJcvqd9C
         7F7gWCPivsBC5AMHYLNs2s/TRqHVu9R1I+3WXj6/jDiSGQnfaaQbh9z68l8PH0MM3wh2
         4KpYqnvjbLEZyqk3DrUHLKkHU299/X2j+mlxApky0IDux91Kb8julTsjSbpFSGQwB5Jb
         el/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=NfULNOrZ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id y12si117487wrs.0.2021.03.24.07.01.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Mar 2021 07:01:06 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lP43Y-00BPZ2-4i; Wed, 24 Mar 2021 14:00:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A5041300F7A;
	Wed, 24 Mar 2021 15:00:18 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 6B92A20CCE903; Wed, 24 Mar 2021 15:00:18 +0100 (CET)
Date: Wed, 24 Mar 2021 15:00:18 +0100
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
Message-ID: <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net>
 <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net>
 <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=NfULNOrZ;
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



One last try, I'll leave it alone now, I promise :-)

--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -778,6 +778,9 @@ struct perf_event {
 	void *security;
 #endif
 	struct list_head		sb_list;
+
+	unsigned long			si_uattr;
+	unsigned long			si_data;
 #endif /* CONFIG_PERF_EVENTS */
 };
 
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -5652,13 +5652,17 @@ static long _perf_ioctl(struct perf_even
 		return perf_event_query_prog_array(event, (void __user *)arg);
 
 	case PERF_EVENT_IOC_MODIFY_ATTRIBUTES: {
+		struct perf_event_attr __user *uattr;
 		struct perf_event_attr new_attr;
-		int err = perf_copy_attr((struct perf_event_attr __user *)arg,
-					 &new_attr);
+		int err;
 
+		uattr = (struct perf_event_attr __user *)arg;
+		err = perf_copy_attr(uattr, &new_attr);
 		if (err)
 			return err;
 
+		event->si_uattr = (unsigned long)uattr;
+
 		return perf_event_modify_attr(event,  &new_attr);
 	}
 	default:
@@ -6399,7 +6403,12 @@ static void perf_sigtrap(struct perf_eve
 	clear_siginfo(&info);
 	info.si_signo = SIGTRAP;
 	info.si_code = TRAP_PERF;
-	info.si_errno = event->attr.type;
+	info.si_addr = (void *)event->si_data;
+
+	info.si_perf = event->si_uattr;
+	if (event->parent)
+		info.si_perf = event->parent->si_uattr;
+
 	force_sig_info(&info);
 }
 
@@ -6414,8 +6423,8 @@ static void perf_pending_event_disable(s
 		WRITE_ONCE(event->pending_disable, -1);
 
 		if (event->attr.sigtrap) {
-			atomic_set(&event->event_limit, 1); /* rearm event */
 			perf_sigtrap(event);
+			atomic_set_release(&event->event_limit, 1); /* rearm event */
 			return;
 		}
 
@@ -9121,6 +9130,7 @@ static int __perf_event_overflow(struct
 	if (events && atomic_dec_and_test(&event->event_limit)) {
 		ret = 1;
 		event->pending_kill = POLL_HUP;
+		event->si_data = data->addr;
 
 		perf_event_disable_inatomic(event);
 	}
@@ -12011,6 +12021,8 @@ SYSCALL_DEFINE5(perf_event_open,
 		goto err_task;
 	}
 
+	event->si_uattr = (unsigned long)attr_uptr;
+
 	if (is_sampling_event(event)) {
 		if (event->pmu->capabilities & PERF_PMU_CAP_NO_INTERRUPT) {
 			err = -EOPNOTSUPP;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFtF8tEPHrXnw7cX%40hirez.programming.kicks-ass.net.
