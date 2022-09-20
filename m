Return-Path: <kasan-dev+bncBDBK55H2UQKRBCMBU2MQMGQE3CXN5AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id C210F5BE0DF
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 10:57:46 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id v4-20020a2ea444000000b00261e0d5bc25sf643452ljn.19
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 01:57:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663664266; cv=pass;
        d=google.com; s=arc-20160816;
        b=nyLT+ZZJRhJ4UA87MBFat8KglCEDZKF2imPm6F5zpQo3T6kg2+PuzERpQPD74+iJBS
         JpiN5onvvo9pTEcviaCBTYHkhh3eqNSVI3IuxmnTgCcOjItAINCEsAv9aIkCt62SKu2/
         yOOhp+z51fBi+dxx/SlbNwOddjuzZyMoNIfrIrc2V9glixsyXJjSHXS+v6q1pCg7RLPv
         f3kq+p2JeBNO8e2cr94SWZToJfjvz3DcPvMSvdRlWYHCF5uigXm1BjfogATURxoqyfVo
         LihWhfFGR8NYf22Yt3AbSqV59O8qC9s8UXbTUS3pyGbs6/H7f3pBjN3eTh7HoBn8ylnY
         kDsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=U8Jj3s7Qgk0cifyp1UehhjF0Vg3k6nirRPRY/vLf2nE=;
        b=Hkm9nNaLR5gInbssEoptwxLbMIyCZgp1qKkRL8Mhd2cwGLW29+A87lSr65KBRjk0UH
         Ce9i/XW2KdfTRO0z6Wjy7AJtC1e1qFXtinX8z060r/wJCiwrKKwWc8ozbVvaozDWXpPO
         H1PRZ/T3ZL74VuNGE+zCpWYC2p6KcYvZSRkmtqG7uYkxRtvQmjIjh2YnhyQ4AVIuu52Z
         bVLs8QvDTvKlVVVP+Fktt3NzZKwP7tUWleJck6mWeT0IHiPIkJ56itq1s2bNSMwYTBfO
         3dnO27Be0c8JojgcX8WBhvYFUwAVy2VDr/yKtj4yNbPixZjFV7nkVjKHRvfDvy8VMxNK
         /gEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=dwq7k7OL;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=U8Jj3s7Qgk0cifyp1UehhjF0Vg3k6nirRPRY/vLf2nE=;
        b=RlJ8mK6rqypRrfPlvlkR4gLJL5QZhAkc0gfvR9e0LUtyt0+ehcNbNm3j43+w1XGoza
         dLJlmQOAH96L3GZpaj6Svxmd5xKDDWLb1tdd6LBN4/DwRnO2rRxbYqYBkliivAmmnhMp
         czpcIag88o8uKirWutVUz3eeEsevaAnbrkv4CcwQIlp6BaeHOEBb7xtOU1eeG3UrkopL
         Ch9wa+xI3hyVMPfYrlb5u4RZiJrXRqQCYMAgivkpxpocWqL2g0gUAwEkKUtFAAun+FCH
         qgrnxwTG6RpupmhQsnMQVNKPs55pOsGMtdG/tHgaaB+Tc/k/2egLhGCqB+MRPtsRy2KX
         8SDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=U8Jj3s7Qgk0cifyp1UehhjF0Vg3k6nirRPRY/vLf2nE=;
        b=A/qIbbsnwdyxugf1et7D9ZLh2EmjNQ6AM/3F5p9Uhp0mR7BQFCJheYmIuwV7vJSQWr
         yhP9TTlFS8qxkC8uiWNbecjtgzEjLv2uXywE8MC3+kTYHWFhFF7AS2/f0yxT0+rZ8CDo
         UkKPAaZv3inmXpCz5Hn1OEdeh0oKeDAuhxk94vSkcJZbtUrk0AGcTTl12eSzVsX1Nynr
         QKASOdhHIzijTtR/u3g0I+ODrU/n/OVLWd7U/hmQWVGuCq6JWZNWSrHK1yBdT2K1TcTI
         M5N0D63OUFdgS0CsGa7ZBdsXQuKJlaNucmCbI0413YDif2WXfUw68a9EsSJoCQalzg1q
         WivQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0ndT0Jk43CQto2d/EBj0ht6gFxqmKDXPpuzlFm2x9V2nhvqpEV
	75AnOiVB78Qt+zPJc/ghMeE=
X-Google-Smtp-Source: AMsMyM7CLOnkCUk1BECnxZZXcGz3By7SyTpbhVR+X6YomnbIExMhMwBIWaQCZ9kes/XHTW85BqyA/A==
X-Received: by 2002:a05:6512:3184:b0:49d:6b29:201c with SMTP id i4-20020a056512318400b0049d6b29201cmr7617826lfe.363.1663664266218;
        Tue, 20 Sep 2022 01:57:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ed:0:b0:494:6c7d:cf65 with SMTP id v13-20020ac258ed000000b004946c7dcf65ls1761290lfo.2.-pod-prod-gmail;
 Tue, 20 Sep 2022 01:57:44 -0700 (PDT)
X-Received: by 2002:ac2:4c18:0:b0:497:a76a:66cc with SMTP id t24-20020ac24c18000000b00497a76a66ccmr7504954lfq.586.1663664264738;
        Tue, 20 Sep 2022 01:57:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663664264; cv=none;
        d=google.com; s=arc-20160816;
        b=rAj65kfqmJFl29SZMvF1FJ6aS4mmK+Bzv17dYHHciPSDLdmgiOSDeth8ViZKrI97cQ
         aOtw8cOZ+Rauicxq8Ki59lKTtmDgmnTZWkadbY+GMg0h87pRiFNo7EVkS9QMI4twVpt1
         lJLSU7ciEtARaH2+kvYeHV8LGi8Vwl0ah2NBC0NsGdhIhTwB+8bEJhbQWmyGHgUE8fkF
         EK4/jygHuoDCQSXPHaLY3cZz8SyQeqXnHBzSjPMG3iKHUbsCAUDhy756OXi6NX8fAYMU
         YMQBPq1zgKxddXaGcPt8mqGxUJT4FCRNCUS/2wDyXB/0MlZHJUR0NAKfAL0CnXkJ/S7p
         73pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/nDDP1N0D4CAKFG1jjZ0nUCcb4Cwi+2XeLNzAB5a/3A=;
        b=WOb23Zb8z8zehKvp5BpOTWfaZ4nzWzNWHuG1lEh4vkPEt/X/T3m7pR16tgihkk5Byj
         rMQpHsBXDfBY3E/9xbWaGWlppz4b1cAud4on9gVEaiZq9XVhbvCjOp0D+xC0whez1WVJ
         p0bHanAXeVi12exN7tmGu7kvfldGYaIiFcLqOmHeRtx48zjMtOGstVEd+cG87m+QbDKJ
         ShHtYWMKki11hAm10IzP69M2HuoTULOw610WqBgii/vpLwWlrFpOCDOnGeGm46s8EMFo
         62x/lZDtB6LmP8d8wp3ePyx8RhQY+hDVVMyv+iSh5X8Y6dZ54oVAqC+rAXgQ0H0xTUL3
         wz3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=dwq7k7OL;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id m7-20020a056512114700b0048b224551b6si26765lfg.12.2022.09.20.01.57.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Sep 2022 01:57:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaZ3v-00EIvM-Sd; Tue, 20 Sep 2022 08:57:04 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B50CD3001F3;
	Tue, 20 Sep 2022 10:57:00 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 892F82BAC7A92; Tue, 20 Sep 2022 10:57:00 +0200 (CEST)
Date: Tue, 20 Sep 2022 10:57:00 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Frederic Weisbecker <frederic@kernel.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	tony@atomide.com, khilman@kernel.org, catalin.marinas@arm.com,
	will@kernel.org, guoren@kernel.org, bcain@quicinc.com,
	chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org,
	sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de,
	dinguyen@kernel.org, jonas@southpole.se,
	stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
	James.Bottomley@hansenpartnership.com, deller@gmx.de,
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com,
	ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net,
	richard@nod.at, anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org,
	hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@kernel.org,
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu,
	amakhalov@vmware.com, pv-drivers@vmware.com,
	boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
	rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
	gregkh@linuxfoundation.org, mturquette@baylibre.com,
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org,
	konrad.dybcio@somainline.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
	vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org,
	linux-ia64@vger.kernel.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	openrisc@lists.librecores.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org,
	linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com,
	"Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: Re: [PATCH v2 03/44] cpuidle/poll: Ensure IRQ state is invariant
Message-ID: <YymAXPkZkyFIEjXM@hirez.programming.kicks-ass.net>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.534233547@infradead.org>
 <20220919131927.GA58444@lothringen>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919131927.GA58444@lothringen>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=dwq7k7OL;
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

On Mon, Sep 19, 2022 at 03:19:27PM +0200, Frederic Weisbecker wrote:
> On Mon, Sep 19, 2022 at 11:59:42AM +0200, Peter Zijlstra wrote:
> > cpuidle_state::enter() methods should be IRQ invariant
> 
> Got a bit confused with the invariant thing since the first chunck I
> see in this patch is a conversion to an non-traceable local_irq_enable().
> 
> Maybe just add a short mention about that and why?

Changelog now reads:

---
Subject: cpuidle/poll: Ensure IRQ state is invariant
From: Peter Zijlstra <peterz@infradead.org>
Date: Tue May 31 15:43:32 CEST 2022

cpuidle_state::enter() methods should be IRQ invariant.

Additionally make sure to use raw_local_irq_*() methods since this
cpuidle callback will be called with RCU already disabled.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YymAXPkZkyFIEjXM%40hirez.programming.kicks-ass.net.
