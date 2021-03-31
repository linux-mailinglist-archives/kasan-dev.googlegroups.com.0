Return-Path: <kasan-dev+bncBCV5TUXXRUIBBAUZSKBQMGQEJTZKAGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 825353502BE
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 16:51:47 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id z3sf1034738lfu.8
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 07:51:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617202307; cv=pass;
        d=google.com; s=arc-20160816;
        b=H+rurMfz/cbMqdJqKQw0IUKleHRaX643etp/NX/843xLwdPDzow9k4fFfDsYgM9c44
         D7vAduopx4oj8HQU0N1fInu/HA4sWPP7JJZiO79fR1pfDhIMY6XzyOiFK2fxTaoAVYwl
         zMs3D6y7Ww0UnE+QqO82vsBYkRYNpc6k29M22EQTgyxuW5IDFVUP+l0xcBGUL0ieFeif
         6QAXXvEakx9oi9iKXdXeJppQE0cYdJBNgT9TZXhjMmUdcYQOINssf4SZRp2hyDnYMCp8
         AsFq/OWhEQDAqxioyW3a83FaKtTGk35Y7FGxL8qguE+fVvzJx/eccebv4KzI9LR7AIMl
         xRqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=W6bvTgk5mWB0EGd83eGsbPVlpxLo4lc8Yi1aV6QtUqg=;
        b=FGB3wTatoxhhJcDS/Y8vCOWUD4AirM8qjYk45gx1STATz00w83VWYKath9sFfruj5W
         cpZ4uIVXAfxTZraxQR0LD37uPgsewoSWEGynFlb/AGdOEhHH25TK3SVeXGNyrnrIX7/v
         YJ5vcMtfV7GJc3v3HvYw8h9inegQMCyr7yRuP953TW6mS1N/fFlT+GIvWkUBkPKiKu8m
         4FUcktAeb8dI3VtDi8/Klp0Obhk9uea4cUqoaeFT/Y7cO1Rpho8bHRfe0qSrdMYVskan
         MsIJrs/061ElUIjDGdgWtsTTGPQeNkRKZPZ2nanhL5Tr7b6FKs6GecZjUZdzzd/83yxF
         WIbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=nJV214+J;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=W6bvTgk5mWB0EGd83eGsbPVlpxLo4lc8Yi1aV6QtUqg=;
        b=c9RUhULnAHlEtNDWtupTW2RA+IWiLCjQ44UPW00ExMEQnDmiqtoGyaXBT4TztID7qU
         L1fshVvmme32Bu9FfYUFcoy8FywfLT6Q/05TY91lAmP7ghjAxyODPxezQsPJrIWgfKfS
         scFpOhu8iRAYhMX4xRL/Ya4cPS1umpevXz55GOmEB2J8qMDJ1j2XMxbrkscLPJ+YotBL
         8KXM9hXAFwfYrggrLKM/MdGkDIHPVjEePBVVzWQkM+Sy2xhYMxNQixvhfTxikbjNlPoT
         On+OvVksBbPv8VJeQilF52PmuuSXVO2RJPd8Tata/b7VgoTfaqOQSoLy68bcTweUHYUz
         sPAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=W6bvTgk5mWB0EGd83eGsbPVlpxLo4lc8Yi1aV6QtUqg=;
        b=EBLqr+hHKMVZyQpr9RCSCFzhvA5QVUoHvmAQ0e4O336bKRyTt7/zM2pyJmLLGlrcno
         2xHF7n0jj/caK8lwNXklj+zgu0MwJtlAKsD+yt8xbGK2nJoa0QGnYr7UDoSm9b//S24B
         oJA+VnfzHc7+64T8yoE2yQ10KDaFiXNkcbGJcRAR1FUUkDEFC06jlCSFIs90mAYSFU+B
         bbEGOG7ELompvdseaPikr/JPUSefa+WLslQ0NRN497ouXyXc92RWNDslYc8lJSfxvzEI
         NxJU49nvFQwIZEMIiMjvs7DdzauC39VoCP7uww/jAdTtp1l9CD+Ix1HqNRezdS75ppkP
         NyLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZysiaEOVxd41CRUl7FZYIdkpo9Al38OIb2tVGO5fhtjofuRKc
	ud7+mCDCMB35Edz7pFQ2qYE=
X-Google-Smtp-Source: ABdhPJywyaQYfFxp1TBVQdnFH9WGrmrHqBdakVh4BZrV8LxCsq2mCB4+Ax97/yuGA6c2pdXjI39fWA==
X-Received: by 2002:a05:6512:ce:: with SMTP id c14mr2541446lfp.64.1617202307072;
        Wed, 31 Mar 2021 07:51:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a409:: with SMTP id p9ls507626ljn.0.gmail; Wed, 31 Mar
 2021 07:51:46 -0700 (PDT)
X-Received: by 2002:a05:651c:201d:: with SMTP id s29mr2291397ljo.315.1617202306004;
        Wed, 31 Mar 2021 07:51:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617202306; cv=none;
        d=google.com; s=arc-20160816;
        b=Pu+5TDpov8LOmKhD3DGyrxvZiEgCJeUj01H4TJHnHdi93gHrIWYE0oPLmIsqup+Nuy
         JEMJrHKnJ24h4vP5LeK6Nnhey1UmjECZXbUywWcl+8HnaoC/55a72JtqAzxHUxCz5M23
         WFpyGPnVn0YXT3GlOgvb1DmbZEAKWf7G9FinIZHU1TjBHXOF3tevV9kX6m9DjhTfRLE1
         XtbMxOnkDCPIfyApELjMTsPlLIsq7efrzgSb5HnhXWhObKYmIvHhBMK2TIJR9tVwmdTq
         JjaUIzmniX0GYyLb+UXljHYTBAYDpLPfGX94k8h9hTieUgEkXkRGlFFMjawSzl3zvleh
         61eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=L5geNAyQH+boxxpn3CD1XfVTlUhklOODJ6Oi2N1dlJs=;
        b=V/dzzWHSoxtK+MAvqPGrNI3vmh1UYHWSPSKlv3rWvv+vTBGLLJ5z4ENwGKAYciCyow
         K8FrYwataR3jnRAN23hCsjc5gB4Ltcq9J8bkJnHwwuDir7+A5UbjaX81bQHsK5qE3zub
         +xeJBW3ccvZT5IQB2wvPB6vUX4M1cnBuUEcGkUio7HJ3JoaCVFiKlhRCk7yJi9pXtGsb
         D9HoOtFzDfrL0xvRW/uUnGT9K3sh9wy9/G4daczWgUPLX83E0Rn/H0ZogDI6VjUItsXP
         +F0+3lPJCEczpnupHoH5P1CWlqKLLwdiQgVQG3suuqprLu6fiZjZIVe82mgXnydJ1kWx
         oSfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=nJV214+J;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id i30si188771lfj.6.2021.03.31.07.51.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Mar 2021 07:51:45 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lRcBd-004hOd-H9; Wed, 31 Mar 2021 14:51:18 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id F091230705A;
	Wed, 31 Mar 2021 16:51:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id C4D762B867506; Wed, 31 Mar 2021 16:51:08 +0200 (CEST)
Date: Wed, 31 Mar 2021 16:51:08 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Shishkin <alexander.shishkin@linux.intel.com>,
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
	Oleg Nesterov <oleg@redhat.com>, Jiri Olsa <jolsa@kernel.org>
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
Message-ID: <YGSMXJvLBpQOm3WV@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com>
 <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
 <CANpmjNOPJNhJ2L7cxrvf__tCZpy=+T1nBotKmzr2xMJypd-oJQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOPJNhJ2L7cxrvf__tCZpy=+T1nBotKmzr2xMJypd-oJQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=nJV214+J;
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

On Wed, Mar 31, 2021 at 02:32:58PM +0200, Marco Elver wrote:
> On Mon, 29 Mar 2021 at 14:07, Peter Zijlstra <peterz@infradead.org> wrote:
> 
> > (and we might already have a problem on some architectures where there
> > can be significant time between these due to not having
> > arch_irq_work_raise(), so ideally we ought to double check current in
> > your case)
> 
> I missed this bit -- just to verify: here we want to check that
> event->ctx->task == current, in case the the irq_work runs when the
> current task has already been replaced. Correct?

Yeah, just not sure what a decent failure would be, silent ignore seems
undesired, maybe WARN and archs that can trigger it get to fix it ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YGSMXJvLBpQOm3WV%40hirez.programming.kicks-ass.net.
