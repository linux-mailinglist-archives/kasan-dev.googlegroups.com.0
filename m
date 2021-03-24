Return-Path: <kasan-dev+bncBCV5TUXXRUIBBZ7Z5SBAMGQEELM63HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C5AC6347976
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 14:21:43 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id r18sf504675wmq.5
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 06:21:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616592103; cv=pass;
        d=google.com; s=arc-20160816;
        b=tgNa4GK3A11o0UJsgvr/2JU9z2OeoVWuJzNdBIsuUWv1K7ho5x/8G09eH8uijJ4Gpc
         YlcZjCC2c6BnZh2o+KgJNrLKuqHSwgoW4+bzdXjqT/r+ck4pFU2NUmba7tiMdlMyN/ie
         DCW0QQmLkXh/vDQIXD7hTd4ivP5oqTEqQjrtfmzCK8C+3vkyM+lZKp9Qs0NvYaBki+fK
         FM869r99cgyvGGrbZPgkIPtjn22mkag1avv9eCr1mc8Z3Bnt7jzj7iqhWkOTGwmL+crS
         GUdC405sLIFXJmEti/bQpHa00ZDV1m7zjQJYcRXZjtdSUcvyRxe27sgbJmALUoanjhDN
         pnDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=brGkDhQaJIRLs4BqHJ5Ub5JddpD5pUh3EXJD48Xqvs0=;
        b=VuWzC63AVPSyh+p9fCuhRGnlbpcG4c/JCimAj+CqhKpUxFlKtLffBzaYQ1K+INOJSJ
         TuGmMLfancfTc46PdC+TbqICcKR6IL1cdh6gjOshbbDUe/RPErbpnab8LJzOr7PAo74D
         v1+n4xhnAaJY6Rwm7KLUvTlRxEnpfyJcw5GmpyQxDI1ft17dvTfbqmvkgcj1sG+1Us0u
         mAy7PJM57zRdboWloZMaNLPwG35ss9WRS4mzr+D/oU9fnhcIAMSOAGwjWwJyKgtVmHdq
         MLiOfh7uBo9zboqrmFu8h7vy4P0Nkx0kYq+IAbFdu9jMOaWWe8ZDtkjCy9B40yhvPm0F
         nBkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jjJOyq5e;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=brGkDhQaJIRLs4BqHJ5Ub5JddpD5pUh3EXJD48Xqvs0=;
        b=V04N/+WZMtmiXI0EIYq3PgDV3TeI1mpPlLTFzcvn/JAE1auu1sxxljKOqLrfMbjVzJ
         r7Rs+nBJYWMHEsAnEv9NcTfcU+OZmoB8H1m6vO54Svmqo9InOR42otEUt4QKsX6QJbsK
         HMr86lOTAAaFOIUouRuz6ETv9ZvCnCIJn81x72S1fAS+yZzo3rBP99IxbOMPyvFSet+m
         cwcupw132tnn0f0HQ5MylH4sPNjaBODRj3lJzzxahCr61MXewguuH35vukPOs1i3Zluk
         ckCm4Iw2P7FBR4Wec5e5pSB4/ApjwratfchGyuUNbgYehqkf1QM9pYHcxvUtm3jRqm1m
         q27g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=brGkDhQaJIRLs4BqHJ5Ub5JddpD5pUh3EXJD48Xqvs0=;
        b=EU6eEqdMnxJFX7HquZ3LJykBW6YJDud0UzCJFDyJlcVTBmJYebR9RmdsYScXAH1wCR
         FmQpj8WGzXmFH7Ld7h9r7V0kndpBl2T51IfpC6KoUTiPrRMCavLxC54GMKQrjFqV5Jzg
         JMx0MVs1Nf5eQ/VKDxw9sAjWQsH7JFyrvGO/gWc2t3LesXRevDIODcvCkM+KBzFjC3tY
         bpFdcIr6M3ilNQs94SiAmrpfEmZVs6l+lT45YbuCZkHnYCc2Gsufkae3HCIQE2/+ywgC
         sMoNWIubVt/u+6e8ZPYxw4spaAupOyxWsu7u1aLwJDcDjQLQ1HPG1CF1b/VBagmIGrk5
         9Nrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qdLCAsFI0nfwFUS8xKWPtvsPHPWFFvLEXX7hwAeL6Uu+l949I
	wNeIqaTfU9QYDnw+fc43a7c=
X-Google-Smtp-Source: ABdhPJwmSqGzs2jQr8LYEW/USOgJH4sMQUxJ8q5DE2kQ0C6w/9SQ0gfNT/vscYsyBvTIDMeA3aGI4A==
X-Received: by 2002:a1c:2308:: with SMTP id j8mr3029857wmj.45.1616592103587;
        Wed, 24 Mar 2021 06:21:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:bd84:: with SMTP id n126ls990175wmf.2.canary-gmail; Wed,
 24 Mar 2021 06:21:42 -0700 (PDT)
X-Received: by 2002:a1c:68c5:: with SMTP id d188mr2862538wmc.119.1616592102695;
        Wed, 24 Mar 2021 06:21:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616592102; cv=none;
        d=google.com; s=arc-20160816;
        b=IxBwCWrihjxI0lfmfXv5cAuIRm8QKt8BjEDLy68hDaKEJCH+thN0mCltqFfqn5UKhZ
         nRrjzZBy4HNB9JUepPWBu/v6yGzs9nXF9FUYfc+lG+TmSCXhjJpl3DaZjDxzJxcr9MpF
         w4NE6Oef9Q58vnzKOUOGWw92Mbk9iFOvCeokWqF9cTpKO93+lqSnLW7Ekv37HfjIL1z9
         0y2uirneh7XtY+jJejjBqzwBeOzGj1VYRv6qcrEHg3iKzkb+HW/CPEGZgULL4ZppNpCo
         wHpHaBGvxhhIcLBki9IVnaBiLcz6AHzWe64n+cuxspOTnpsFktrqTrKOUSK0zP2J3l/e
         hijg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4WpXJrjstIuowWonzq4eFShaVDE/4VxJi8AtBgBCg04=;
        b=ymc4GE5OBznbzpisy71jd9S3HyC3OUy79UanYjupxts4+Q0jnNvU6lrxoRATOgHgaB
         +2maOliZ0hhaUqQ4DwlBapd6GmO4NkzxsSU4mPJzlps7DFoISxJo8KdFrwbTT5Nn2F6y
         Lp7T7nuwKYrbv55s3dkB8uR1AOiLpOXU3bCiGzkXcqZd8mk0bzRiGRxwQnzhFcR0wnQL
         4xPGA2fmLwHs39wiXEVU5y8AydXCarmA0ALd4nxFRlNaNE1FGJrfWO2yC/HTtyJp9lOM
         /hefcS5Ijtuxc7ntjo1Ic+YX+robiRu4t8tMM9tYH5DBYgEuxwJpMcDDAGQG0fStKQDF
         ZtKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jjJOyq5e;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id y12si93260wrw.3.2021.03.24.06.21.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Mar 2021 06:21:42 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lP3S6-00H977-Bb; Wed, 24 Mar 2021 13:21:38 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5A15F3010C8;
	Wed, 24 Mar 2021 14:21:37 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 129BE20693989; Wed, 24 Mar 2021 14:21:37 +0100 (CET)
Date: Wed, 24 Mar 2021 14:21:37 +0100
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
Message-ID: <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net>
 <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=jjJOyq5e;
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

On Wed, Mar 24, 2021 at 02:01:56PM +0100, Peter Zijlstra wrote:
> On Wed, Mar 24, 2021 at 01:53:48PM +0100, Peter Zijlstra wrote:
> > On Wed, Mar 24, 2021 at 12:24:59PM +0100, Marco Elver wrote:
> > > Encode information from breakpoint attributes into siginfo_t, which
> > > helps disambiguate which breakpoint fired.
> > > 
> > > Note, providing the event fd may be unreliable, since the event may have
> > > been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
> > > triggering and the signal being delivered to user space.
> > > 
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > > v2:
> > > * Add comment about si_perf==0.
> > > ---
> > >  kernel/events/core.c | 16 ++++++++++++++++
> > >  1 file changed, 16 insertions(+)
> > > 
> > > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > > index 1e4c949bf75f..0316d39e8c8f 100644
> > > --- a/kernel/events/core.c
> > > +++ b/kernel/events/core.c
> > > @@ -6399,6 +6399,22 @@ static void perf_sigtrap(struct perf_event *event)
> > >  	info.si_signo = SIGTRAP;
> > >  	info.si_code = TRAP_PERF;
> > >  	info.si_errno = event->attr.type;
> > > +
> > > +	switch (event->attr.type) {
> > > +	case PERF_TYPE_BREAKPOINT:
> > > +		info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
> > > +		info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
> > 
> > Ahh, here's the si_perf user. I wasn't really clear to me what was
> > supposed to be in that field at patch #5 where it was introduced.
> > 
> > Would it perhaps make sense to put the user address of struct
> > perf_event_attr in there instead? (Obviously we'd have to carry it from
> > the syscall to here, but it might be more useful than a random encoding
> > of some bits therefrom).
> > 
> > Then we can also clearly document that's in that field, and it might be
> > more useful for possible other uses.
> 
> Something like so...

Ok possibly something like so, which also gets the data address right
for more cases.

---
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -778,6 +778,8 @@ struct perf_event {
 	void *security;
 #endif
 	struct list_head		sb_list;
+
+	struct kernel_siginfo 		siginfo;
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
 
+		event->siginfo.si_perf = (unsigned long)uattr;
+
 		return perf_event_modify_attr(event,  &new_attr);
 	}
 	default:
@@ -6394,13 +6398,7 @@ void perf_event_wakeup(struct perf_event
 
 static void perf_sigtrap(struct perf_event *event)
 {
-	struct kernel_siginfo info;
-
-	clear_siginfo(&info);
-	info.si_signo = SIGTRAP;
-	info.si_code = TRAP_PERF;
-	info.si_errno = event->attr.type;
-	force_sig_info(&info);
+	force_sig_info(&event->siginfo);
 }
 
 static void perf_pending_event_disable(struct perf_event *event)
@@ -6414,8 +6412,8 @@ static void perf_pending_event_disable(s
 		WRITE_ONCE(event->pending_disable, -1);
 
 		if (event->attr.sigtrap) {
-			atomic_set(&event->event_limit, 1); /* rearm event */
 			perf_sigtrap(event);
+			atomic_set_release(&event->event_limit, 1); /* rearm event */
 			return;
 		}
 
@@ -9121,6 +9119,7 @@ static int __perf_event_overflow(struct
 	if (events && atomic_dec_and_test(&event->event_limit)) {
 		ret = 1;
 		event->pending_kill = POLL_HUP;
+		event->siginfo.si_addr = (void *)data->addr;
 
 		perf_event_disable_inatomic(event);
 	}
@@ -12011,6 +12010,11 @@ SYSCALL_DEFINE5(perf_event_open,
 		goto err_task;
 	}
 
+	clear_siginfo(&event->siginfo);
+	event->siginfo.si_signo = SIGTRAP;
+	event->siginfo.si_code = TRAP_PERF;
+	event->siginfo.si_perf = (unsigned long)attr_uptr;
+
 	if (is_sampling_event(event)) {
 		if (event->pmu->capabilities & PERF_PMU_CAP_NO_INTERRUPT) {
 			err = -EOPNOTSUPP;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFs84dx8KcAtSt5/%40hirez.programming.kicks-ass.net.
