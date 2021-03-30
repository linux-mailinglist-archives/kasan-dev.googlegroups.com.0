Return-Path: <kasan-dev+bncBCV5TUXXRUIBBFE4ROBQMGQE46BWIBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FAB834E1BE
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 09:07:00 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id n2sf300235wmi.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 00:07:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617088020; cv=pass;
        d=google.com; s=arc-20160816;
        b=S9VZIoTBNn0JZvTYRuH+W7t9PpzhlmH4PKUDpm/4iGQiEa9KGH6MNkUHBYD0eUdxQx
         CIgI8JGToxe/1ZdZNQTbhDNlKElpoDF+SK5LRxiEiYXv0u9V4AH5D4/iA8egZBZ6/HKx
         11hV5bRg7tMea1MzygJb+Mu1RsqEg0wtOlD+dPTjbR9coyqF53n0EiWQ0iAzrEVzN3uJ
         26U87pkay03jsTXioa/sDY0BXU8JXlBmJX/oC6iRA/ARfawv+sYD4ekfTkmNtn/JWqro
         Tsxlxx/17scrbsjqID4snI+G02SHebBqCbmxIFZdvX7OvM1Pka6Whg2HIew51w625o8X
         9XJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cPD9GCNuQWnqibdFtVJIoTQllNmnG7OJRmXHV2BBLO8=;
        b=GjnfTI4AP373BnhMmXH2dWg8chOmL0lQo45eOa8IQAcVs1L3QUh2LvVLWZwrDVCeDQ
         qcTGBz2TeT3Q5JezMSp4AYo6Gj5wCNcVq8vukz8NuUIwl7LDC3hbKtVpTWSsiHjtyL0I
         4aPu9tqZ3+8UMFdt4R8tmtkn3gOmrJxn3+G1sT+SUoELqaXmK4LX1arpzIjUzUfL+1W0
         0+h4nSjF3mEuDYhTlZY4KR0iRLZyegEmbprYaUff87CF96lJzlkvKUt7SCKihcmFaChc
         QbOvwhcW5vl5orkVbB8zJRDSDFN+O06OYFyQmBsw/1PvRjcsnLilcXz4mJ0n74lkleP4
         KMqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=mEIz6zmn;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cPD9GCNuQWnqibdFtVJIoTQllNmnG7OJRmXHV2BBLO8=;
        b=MChsk2xqm90erXI5JkSTFmSdkNI1YUGHcXyKmT3oZzvFRbqG/T0lrJQQJZHZroEae3
         jOJzHQVeVbYAAYxYz3yaFgw0tfx9mXsX9nv9MhQBpABE2bPM4Xhiq4eCn2e34TaDtpEL
         XKtyx1P0ixrfLWpFcdGY9G2tsljjWQVIeB1mqMZUm+EBWX3Y2scS7Y8Gy3GpbaGpDeV4
         TRdmtQz8E+suysr6NFxQJYWGaMgqjIvxVpCAf63IQR4t+JE6TzD90fUyhfizJRmCXz6+
         wpvCfDTjQBm8v2HSJkV6tgpX0Rqf88zEnNYGYPxSGNflc749SwoL8rT7HNpABxOuSyum
         HrLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cPD9GCNuQWnqibdFtVJIoTQllNmnG7OJRmXHV2BBLO8=;
        b=anTCCsvKtpC2DdWU163YeFi8INKz9cKtFlmIpRZNGZt9iwKg1BctygjSmtkmuEUFQa
         +R0+aaQRRjMHNZXIe1Jey6SLp3T/ECVmFqgmZGpNUZmZ5UYjUuBRCKYcrJB/5xXrjc+2
         UI9T1Q8I1f0OcwRtczsFvB5MjYKQ1orUXGJj0/VwhdY/FYhowHObnpc2JPSsD85ojbom
         hmTVYiy1qoqWaqSOLSwGlvN/cHFxQc5+R1Bh9RPLM8ZbgOIy5Pn8diq1DwJ4gUKgCX7s
         sUEz5O02dLy4dV9HzipAK4NFwhZDFraQgnCdVRaS0EdxSAw+Q8gyorpbt0eXVqnjS31D
         56+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eO7Z9efTvmOj+MsWBEGf/JrP2zFhK99udnRa/I+Z3k/q6BglY
	UbPf1g3ZKnNIjsvowkxP2Io=
X-Google-Smtp-Source: ABdhPJx9N8o5tZBk/qTN3ekmLmZTM44jftUMpF4x9ovNeluOeILGaHyseSj23h62fePgrwV3AuZKAA==
X-Received: by 2002:a5d:5492:: with SMTP id h18mr32856053wrv.340.1617088020270;
        Tue, 30 Mar 2021 00:07:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce14:: with SMTP id m20ls755098wmc.3.gmail; Tue, 30 Mar
 2021 00:06:59 -0700 (PDT)
X-Received: by 2002:a1c:6309:: with SMTP id x9mr2480946wmb.62.1617088019506;
        Tue, 30 Mar 2021 00:06:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617088019; cv=none;
        d=google.com; s=arc-20160816;
        b=SXVKYAQQkxHFJ6gVkl5rTQUexeTUi1MGbrBb+lDEJ768bkXgpItBZDSPSWNUOjehCN
         /z08bLmNxm/cU2AgzKim2QFaVuMA2vvWPTj+0sACzjtt8XH9/CXEyTYbRPS/XTwcvCTw
         YtDf9BcTVMZezmHMNqhomAl9vYoGee0JtC7Ndwa6Zo/sBCaY8dFPwCBJXUM+Wkk69ytS
         02APdU6jcGThqdSTtMaSwQooYSWYHiit7IPtPfIQxOYfpYAppQZqMbKaxGfEiBMzVemY
         nlaBFS2Yb+CZSjQ2nSFQ0NLkx6MdyaoUS9hJ+MpPFeus0hXwLLtib6osFQpE9ycdlblV
         IJxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=X166VgoQn02EMb3f8ykwCC49d3dYou3bLIcu1kP5us0=;
        b=l3Gv/fkgwLiy03qcnxp67xx7b1P33QYaneZo1Z0PxPGvgvPQAzshuMhmNGTcKOgKzW
         hzZ86PtdEyHeDa+X3Kdo+rykNG1X9KCJZP0A9nF91WFm4tcgtHcyePv/URqxyj8DwGGm
         M+EIzuD2fP61JQTBT61oNCDl2a+TwO/H144Mlo4UaJXF3lLeVXKLyt0yloWApSEZRmX7
         B+ndciyPZCUxj1uh7uHu0aMScekFZFS3/Bcnm0wQmoZM47EkPFJ5C/Hw0vFNQOP/nA/k
         zZc3hgTAmaFGmmsE5Bz92Yv6RTub0aaH2o2R+E08mWR6H0b6pUMOw004z2zS02JP4hmK
         Siqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=mEIz6zmn;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id k83si94354wma.0.2021.03.30.00.06.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Mar 2021 00:06:59 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lR8Qa-002ddk-BT; Tue, 30 Mar 2021 07:04:56 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id F3363307001;
	Tue, 30 Mar 2021 09:04:36 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id BBF922B960A7F; Tue, 30 Mar 2021 09:04:36 +0200 (CEST)
Date: Tue, 30 Mar 2021 09:04:36 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Oleg Nesterov <oleg@redhat.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Namhyung Kim <namhyung@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Alexander Potapenko <glider@google.com>,
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>,
	Christian Brauner <christian@brauner.io>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Ian Rogers <irogers@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	linux-fsdevel <linux-fsdevel@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>,
	Jiri Olsa <jolsa@kernel.org>
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
Message-ID: <YGLNhKnx4wR38XpE@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com>
 <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
 <20210329142705.GA24849@redhat.com>
 <CANpmjNN4kiGiuSSm2g0empgKo3DW-UJ=eNDB6sv1bpypD13vqQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN4kiGiuSSm2g0empgKo3DW-UJ=eNDB6sv1bpypD13vqQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=mEIz6zmn;
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

On Mon, Mar 29, 2021 at 04:32:18PM +0200, Marco Elver wrote:
> On Mon, 29 Mar 2021 at 16:27, Oleg Nesterov <oleg@redhat.com> wrote:
> > On 03/29, Peter Zijlstra wrote:
> > >
> > > On Thu, Mar 25, 2021 at 09:14:39AM +0100, Marco Elver wrote:
> > > > @@ -6395,6 +6395,13 @@ static void perf_sigtrap(struct perf_event *event)
> > > >  {
> > > >     struct kernel_siginfo info;
> > > >
> > > > +   /*
> > > > +    * This irq_work can race with an exiting task; bail out if sighand has
> > > > +    * already been released in release_task().
> > > > +    */
> > > > +   if (!current->sighand)
> > > > +           return;
> >
> > This is racy. If "current" has already passed exit_notify(), current->parent
> > can do release_task() and destroy current->sighand right after the check.
> >
> > > Urgh.. I'm not entirely sure that check is correct, but I always forget
> > > the rules with signal. It could be we ought to be testing PF_EXISTING
> > > instead.
> >
> > Agreed, PF_EXISTING check makes more sense in any case, the exiting task
> > can't receive the signal anyway.
> 
> Thanks for confirming. I'll switch to just checking PF_EXITING
> (PF_EXISTING does not exist :-)).

Indeed! Typing be hard :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YGLNhKnx4wR38XpE%40hirez.programming.kicks-ass.net.
