Return-Path: <kasan-dev+bncBDZKHAFW3AGBB44RY2LAMGQES7HVO4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id F387C576478
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 17:34:11 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id z1-20020a195041000000b00489cc321e11sf1921847lfj.23
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 08:34:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657899251; cv=pass;
        d=google.com; s=arc-20160816;
        b=sjO7J6OCn/c+4U2ciVq/v63UKp8/Dm8m+QMUu5eEuEclS5OBf+8NJHIE+6Z7CAscmY
         7sAP8r1KqbM+Br0/sJg2455L6KZktDHi3hR+jaaGS+SQGL3mXQi9P+IwhKdfWQeYMcn+
         Am/JIesaNmeejRTNS2A8qWCBDio3mhiyJdBF0KiXPfq/nfXD6J01g8p99LyYuQFLA2U5
         4Jdz+afjH6/TxAxG3iii8381rkD96RviykmEJAcqBV482h8UCS4+RIfp2NdB0AC2UYX8
         51dSHvsK7533s/8G4BRWKh+PLnELpD4D+5MJte2IRAaIpZuTHVJJuBkXChUh32v8v+Fx
         5K5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=IE93xTyxptv2012Mull2ynixRTytuEyzyW8biD0fhxw=;
        b=zk/h095P8ajEBR9aq4KC9fprh23UyWjcnJF4tQiJFvssdYPCpnTof6A3Mhs6xVtf7H
         ZpBsGh8u3omd9S8UUX1EwT3tl+B1Hq1BcZJR9a/Q4EDBAE+1PZBQs6/6Y8wstfrjGvyF
         VpYMakcDBH0zsJWdHp+SBW9pIWjl3zLVLGuW2GSVN4sY28nmiu3ybNpHuGMvnLvDSehE
         8U+cxFQ1i4gev1EHdNuT0qbUEiuQ9kayIoE8TJPJ62JQaPZRXheBWfHYcgraJeZzURIa
         Opkd2pHb2z3qjnGQlan+zz9kEVhpRajFozkshdlky9XpxAN/4a4r6S3wPX8NAQ+0VQVG
         uEJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=r445NMOx;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=IE93xTyxptv2012Mull2ynixRTytuEyzyW8biD0fhxw=;
        b=MQqAmP1pVqTGqPwPBr+wr7WaXSMwoVMbvDHnaKEIaOFHJof7t0kXMAlcKKvAoAktRC
         ojY1/xZGWX9Ms72s9J7obFxsChLcxXFaotkGp/EzQUHb1udbsWS3JDUvDeoQ+46HFC/8
         XnPiWRoWM0OxBtKe2+KKhYd6CHGPzZ299SLQ2wlUyjT6Ot9hp8COUUSftKI6ZfZttinE
         QKw9hr1UiPRxtVjPh4oNhbvAn+RsrTsZOE1ust+wVIPV9j8G5cHKbYkKHAiei5xiKBDV
         tTOBIBYNBIguOJRc6zLP4NNyIhGiqw1dHBSfcN/Uoxj6zVdwosXlVZdXrANxAAS3qvee
         lk9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IE93xTyxptv2012Mull2ynixRTytuEyzyW8biD0fhxw=;
        b=e8lBr3aWCP4AVqm0n8c0C3Wc1vLQY12WvHyS2NvvP6Vg5o95yAP49gCWZlBYGDKwzQ
         wVqi9woUFuSuV1Mx0z0MyB+u9RrJh2ctrOS68JbWnWC9wJLkd3OlIvdQjRMONJMOPw0I
         TNdAazi2MvLMblWqTB1Q7DYaKVrMdl9vCAKiTjNjs1OfASlipQRAMAKH0q7OEC2tQEfW
         E2qMEAwTjgP3fTUN/WyHUAU4ZX+oApM1VXG+2ls8dzDSpMaW+1N+Ts+SJhPj4+KkW1At
         EkLMKCZ2aaWt+6FlDYjJELZUh49tgTaTqDyYPd2jLEI29DjAKWnPGPMxNtA5u1php+B9
         9L+A==
X-Gm-Message-State: AJIora83EA6QHM0UJLe0WxOfEXr0YyQi5rOZvJ3yaL9VIoVQnepQGdtm
	fZDR0qYAEpx8diBoxVHuM4I=
X-Google-Smtp-Source: AGRyM1uqGDfC7yVZgfLolF5W75uSC8cJOFh+qbXqUlbPVWKcqhl9cVu776dtOtLf9OcEklch1BSxow==
X-Received: by 2002:a05:6512:3f84:b0:47f:673c:31b7 with SMTP id x4-20020a0565123f8400b0047f673c31b7mr8826320lfa.473.1657899251360;
        Fri, 15 Jul 2022 08:34:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e14:b0:487:cd81:f0e6 with SMTP id
 i20-20020a0565123e1400b00487cd81f0e6ls1412631lfv.0.gmail; Fri, 15 Jul 2022
 08:34:10 -0700 (PDT)
X-Received: by 2002:a05:6512:32c2:b0:487:ad20:e0e6 with SMTP id f2-20020a05651232c200b00487ad20e0e6mr8418107lfg.492.1657899250236;
        Fri, 15 Jul 2022 08:34:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657899250; cv=none;
        d=google.com; s=arc-20160816;
        b=CRoSKbnIrlfR/LI7qKCh30i70M9IYxEWK3MuGFAPB9Afwa9Si3nfui6BRc2GI3L3Fa
         /RPZmJ5Q+UO4z3RfImMCZ+uRi1WVodnQSb2ONpzeq6ANx0SLEMcDLefpSV+smChjL8TT
         HANCNUbxsslx59DSrlVH7m0JvfM4glpW8sC9e1QmVv8hlD4KoX7cqFqgN1qmwpodvvdV
         ZpZzPAvzrrhzH7K5hrZ/iPX3Do0IFUOqtEbA1Ur9fW7IztCl13bZjTrwub5+6O1AFTS0
         1GKitYvZbZ0J0XgRsChAWUjYN8h/qPqxyJ2kypJkdmSDtVSlc7a/EanV6PE4yNvqKGJs
         z4Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dHkyYdvPMihubQc6LwKfvGIMJV7WAc+es/B12KkQGCM=;
        b=lum1Jt9ck4kC6SUb32EQtuUUCa+NBbc/+KAt9a3E4UDYw5MK7zkybv7U8Ip/B+AClm
         Ez8Q/wOQKVLgjTRn/qvomlm57RqwhgiRyuA9PEnRAo4oub/J3zTw/QwnKCB5d+pbfg0Z
         1kutFFZ7s+mh7jWoTf7mM3gpbZvBEKbPntrxBOiss6l+LdOD1uapX18Ob5Jgly4QquQx
         rWJ2K05OBf+NjJZ8ur/WTEhfntDTFthoh3hwUo85FbKiB9M1RDBjQZdF38PqR+okyTHg
         n7voJfDc6TX63cNkYKusp+fTYiIw7bxH0Jgmm8xuFgGSdhzn48oBkK84bLdS6gZN7nGB
         Qn3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=r445NMOx;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id k13-20020ac257cd000000b0048a29c923e9si17560lfo.5.2022.07.15.08.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jul 2022 08:34:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 80F60201E6;
	Fri, 15 Jul 2022 15:34:09 +0000 (UTC)
Received: from suse.cz (pathway.suse.cz [10.100.12.24])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id EF9442C141;
	Fri, 15 Jul 2022 15:34:08 +0000 (UTC)
Date: Fri, 15 Jul 2022 17:34:08 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] printk: Make console tracepoint safe in NMI() context
Message-ID: <20220715153408.GF24338@pathway.suse.cz>
References: <20220715120152.17760-1-pmladek@suse.com>
 <CANpmjNOHY1GC_Fab4T6J06vqW0vRf=4jQR0dG0MJoFOPpKzcUA@mail.gmail.com>
 <20220715095156.12a3a0e3@gandalf.local.home>
 <20220715151000.GY1790663@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220715151000.GY1790663@paulmck-ThinkPad-P17-Gen-1>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=r445NMOx;       spf=pass
 (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Fri 2022-07-15 08:10:00, Paul E. McKenney wrote:
> On Fri, Jul 15, 2022 at 09:51:56AM -0400, Steven Rostedt wrote:
> > On Fri, 15 Jul 2022 14:39:52 +0200
> > Marco Elver <elver@google.com> wrote:
> > 
> > > Couldn't this just use rcu_is_watching()?
> > > 
> > >   | * rcu_is_watching - see if RCU thinks that the current CPU is not idle
> > 
> > Maybe, but I was thinking that Petr had a way to hit the issue that we
> > worry about. But since the non _rcuide() call requires rcu watching,
> > prehaps that is better to use.

I actually saw the warning even with simple sysrq+l. I wonder why
I have missed it during testing. It was probably well hidden within
the other backtraces.

I was not aware that rcu_is_watching() and rcu_is_idle_cpu() did
basically the same. I used rcu_is_idle_cpu() because of the "idle"
in the name and the function description ;-)

> In case this helps...  ;-)
> 
> The rcu_is_watching() function is designed to be used from the current
> CPU, so it dispenses with memory ordering.  However, it explicitly
> disables preemption in order to avoid weird preemption patterns.
> 
> The formulation that Marco used is designed to be used from a remote
> CPU, and so it includes explicit memory ordering that is not needed
> in this case.  But it does not disable preemption.
> 
> So if preemption is enabled at that point in tracing, you really want
> to be using rcu_is_watching().

rcu_is_watching() is the right variant then. I am going to send v2.

Thanks a lot for the detailed explanation.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715153408.GF24338%40pathway.suse.cz.
