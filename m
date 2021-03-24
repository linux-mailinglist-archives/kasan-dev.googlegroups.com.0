Return-Path: <kasan-dev+bncBCV5TUXXRUIBBTPQ5SBAMGQESV5URUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 25F52347928
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 14:02:10 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id d11sf442177lfe.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 06:02:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616590929; cv=pass;
        d=google.com; s=arc-20160816;
        b=V1Dh2wMcmYOQwdwG6+dAlPICWM0E5SQS7mJVU4DoZ35xZYwmlmzI6WjCVBlIODLnk2
         mcaSpMzXWi8DZq+xxQ2QjbVuSJaXY/bw+5sKba2gLNjP/8TvVFTtZD/7ydOgESw6O/XV
         ypS6a3eIGVOhy1WfcU9BYPxMaFi510X7S2uZBuDwjkAbaDWxE7nIlaU+uwSxr2hubVO+
         nZMPopFrDTH6/K4Q6ABaW0tK0m+vTGKfe62g2P1We7kSHV3M581mpbVMbO3hSAHcwqP2
         ggNU0WkjU67FyWoo4/g/KD6bZYR3IcXvI9bK9pgQbp8ktkyRT4q3ZfG7fYV9LtvwaNTA
         LxhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IGe1+6FCdeavJlR1De0FB2xMeQynLWC0zkZlhOuvIbQ=;
        b=0JD1ZxXp4rY3joyDd+pnqBgi2Ov3O9z5Bku1gQtN/bzvYelALIdVldRQM7T9uS9p59
         po9wtsTDCa+bJnHW4dmubb+iUURRyi87l2fIy1FarxAsfBMEodp0Uk5EZEm8S9ejJoKG
         cg1MUh+wmP3zJErrPO1aDRdNO4alqs7zNBcUGyp2yoeGhBYfKdrKKkxCMg347hIyYNkO
         9GtPnitPHfurxyZk7u7Nl8jfVzKubM5C666XWJSpDYdgm4hRPg9GO3BYEnAwoHGhpxkL
         Oozqeuo2lDpdLEY/sC8ZeXrYOLuY0muL8B+qfwWBELaig/TmEYJ4o9IfLUUih2rd1457
         0dAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ilqZmQXN;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IGe1+6FCdeavJlR1De0FB2xMeQynLWC0zkZlhOuvIbQ=;
        b=i933pkyyPdkRaOAVSE1fhlkG0VuSYC97vwroJtp4tfSRjbmAE+4c9C1C8LsBiDBecB
         Z93wXecc4nv9AkM7ah610wz5JIZeuOPOpG69vXXi17SEruFDse8evOCl6FcMtlGqTAPd
         g9VSpF0pug/4FrEeDoNYv3nhCO2vT3llWc+71kpGuQh66KwfGGia2afeQMVFT+jtpYZ7
         p7ZBDIi/enGo/r2fYXxpH8f2zcGHq9OfGhTAQTJmKBpePEQ3TLm1MvDKLU0v00zR7ZCm
         ZCnz71m1v6qVUxp3XdVZdeAyVe6MXD8SVouQbiZYDYqM0TykO2wjS3WqhEccxFkshp6j
         PT6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IGe1+6FCdeavJlR1De0FB2xMeQynLWC0zkZlhOuvIbQ=;
        b=cblkn3SlK5htkOZG4AH5WA6O6//ucfw8/epeSk++OSTCcNfcOtyLQDqJI2dwYkpjxi
         1Li0zD8m2ttATavUAbGExlvoyRBzRn6rFhpCPF1hBBO4KYw3TAq3l8Le4zTcChXELvqt
         GMmet581NTc2/BZdAV+NAgUQxTeiR1KgrsNoNz23GzL4ziPPRDGn+GhjVHWUfcSM4UxT
         ujXD6bkZYU+lz5TQTmlAZWXfg0+dOliX3UZfnBH3lat3+UX/55umgUq1fYIUOmFI9a4y
         iaj3P+f+/rBLGFiwUMM3l/wNke2izCawMaNnkOWqgkL7Qj/yAIVFBd2D/tRQQ6AONtDb
         PCwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KPa4WgqyPi83pL9yyOF4/NrzluHbdA/zh4sL7VRhYB8hy7AUV
	WV1n7oa6B8PmXSrlKZMbxhQ=
X-Google-Smtp-Source: ABdhPJxy2LIR282QYoGHqkiuHSPOFMQo4ip2LL3LBp5oitpL+ciGiZ7t76i1ZR35YQmK4jjSR9noRA==
X-Received: by 2002:ac2:5fa2:: with SMTP id s2mr1890226lfe.486.1616590925269;
        Wed, 24 Mar 2021 06:02:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls1542099lff.3.gmail; Wed, 24
 Mar 2021 06:02:04 -0700 (PDT)
X-Received: by 2002:a19:3850:: with SMTP id d16mr1974510lfj.473.1616590924028;
        Wed, 24 Mar 2021 06:02:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616590924; cv=none;
        d=google.com; s=arc-20160816;
        b=vvmT5AIBkpDLlhu1aE0XYaBZMfuRMqQgmY4foULRsSr6fFunZ2He9yBZfcbZps/R1J
         izbrzUCFnhwM5i5oO6SO2q391qLLcaWlfGK/vfnAtImhf8lTBF6dpdE86iOnkgcdcmx3
         S0vGxX+qkVpVPJYXB37WGacE4dtJPmM4buVurGFNK1Uk498+o4Q9u+BxXnPx3yKmXKOv
         IKp02bRSQcDByrOP7XjKzBBWStBsluiKJoOrJuMOJMUBt1xQQnW1TAxq3MNJgrpz45s9
         GZtjR/Fky9S6mVWwz3EzAXnIPn7BVa17L65JTPpMGMESVWmg1p3AxVmXpLAaB+AL+C1L
         opag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=q9wleIY7+buN1IFhKM1BECXFztpC8QTUjzTIYy6/pPc=;
        b=n90tUvQ+z84kmxQbbvQDvu1z/MNIHp2Yvzz9UyAe5ITuJKDE29hLu7jRleZbJWI2Ug
         tiDFha6yM1xUHQeJjSDAWf5/XpxcKQ2kCYdgZs5Bon5KsIPv4/9fIc3bKBfVdf/AVgiO
         awO61Ubwj6g/oU5ukegGju0kao/QG5kiuoOX+E8GhPe6lm3ZA6tl4QKijU4X/pjPVFGO
         2km6C5gFaNGEH9poKGFSlxkGkYL7QloEuYZh46bI/SCNJdczQiQTTvCfJN3yq9n6Ep3K
         vW1OO5FbSnhzen+PlvJ9NWiExvaQv0/z9fpOfNkB19k41NbGgo5q7J6hBBnENSsDESNs
         zhbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ilqZmQXN;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id d19si87741ljo.1.2021.03.24.06.02.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Mar 2021 06:02:03 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lP393-00H8Jl-AG; Wed, 24 Mar 2021 13:01:57 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C504D3010C8;
	Wed, 24 Mar 2021 14:01:56 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 87DA920CCE91B; Wed, 24 Mar 2021 14:01:56 +0100 (CET)
Date: Wed, 24 Mar 2021 14:01:56 +0100
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
Message-ID: <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=ilqZmQXN;
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

On Wed, Mar 24, 2021 at 01:53:48PM +0100, Peter Zijlstra wrote:
> On Wed, Mar 24, 2021 at 12:24:59PM +0100, Marco Elver wrote:
> > Encode information from breakpoint attributes into siginfo_t, which
> > helps disambiguate which breakpoint fired.
> > 
> > Note, providing the event fd may be unreliable, since the event may have
> > been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
> > triggering and the signal being delivered to user space.
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Add comment about si_perf==0.
> > ---
> >  kernel/events/core.c | 16 ++++++++++++++++
> >  1 file changed, 16 insertions(+)
> > 
> > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > index 1e4c949bf75f..0316d39e8c8f 100644
> > --- a/kernel/events/core.c
> > +++ b/kernel/events/core.c
> > @@ -6399,6 +6399,22 @@ static void perf_sigtrap(struct perf_event *event)
> >  	info.si_signo = SIGTRAP;
> >  	info.si_code = TRAP_PERF;
> >  	info.si_errno = event->attr.type;
> > +
> > +	switch (event->attr.type) {
> > +	case PERF_TYPE_BREAKPOINT:
> > +		info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
> > +		info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
> 
> Ahh, here's the si_perf user. I wasn't really clear to me what was
> supposed to be in that field at patch #5 where it was introduced.
> 
> Would it perhaps make sense to put the user address of struct
> perf_event_attr in there instead? (Obviously we'd have to carry it from
> the syscall to here, but it might be more useful than a random encoding
> of some bits therefrom).
> 
> Then we can also clearly document that's in that field, and it might be
> more useful for possible other uses.

Something like so...

---

--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -778,6 +778,8 @@ struct perf_event {
 	void *security;
 #endif
 	struct list_head		sb_list;
+
+	struct perf_event_attr		__user *uattr;
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
 
+		event->uattr = uattr;
+
 		return perf_event_modify_attr(event,  &new_attr);
 	}
 	default:
@@ -6400,6 +6404,8 @@ static void perf_sigtrap(struct perf_eve
 	info.si_signo = SIGTRAP;
 	info.si_code = TRAP_PERF;
 	info.si_errno = event->attr.type;
+	info.si_perf = (unsigned long)event->uattr;
+
 	force_sig_info(&info);
 }
 
@@ -12011,6 +12017,8 @@ SYSCALL_DEFINE5(perf_event_open,
 		goto err_task;
 	}
 
+	event->uattr = attr_uptr;
+
 	if (is_sampling_event(event)) {
 		if (event->pmu->capabilities & PERF_PMU_CAP_NO_INTERRUPT) {
 			err = -EOPNOTSUPP;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFs4RDKfbjw89tf3%40hirez.programming.kicks-ass.net.
