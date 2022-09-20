Return-Path: <kasan-dev+bncBCBMVA7CUUHRBUNSU2MQMGQEDVSH32Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D68F5BE382
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 12:43:31 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-126cb03a64esf1408927fac.23
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 03:43:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663670609; cv=pass;
        d=google.com; s=arc-20160816;
        b=ybAWYyJLbjqVOxTUtjZePvV1D6WG+JYBuwimxNLfwVE2Q20tn2cWy8Dh+2zHFhmRuE
         otFXFV1lmEwDARwk9MFVyeph84l1TeUugFA8vwp74vCt5HSvf6Bp6f6McnxjABeOtFb8
         fUtDufn2NEWi8kxPtiS7cDGPb80dvqjA1QjZH7Sn1qVwEz5R564NgYOdhm6zRCYyxHXM
         E1HrufhyrRyCNocG/nReHrtVzjPf+5UygrXkR9iwFSPuMr1A+cJbtW8Habu4TqVH6rP1
         AWr2TLP8mtXiLNQGbf2Jx6bPvlFAVfKpBMcxjNyk40zq7+DTZ5Ki7a98RTXMcDNltQwx
         SShg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=miZXvKwWjsTtCZP8rKOCd8r/6k+RJtbmpnWGcBN7SfU=;
        b=Aosu8lFTOs1b+O+BGLEiLuvcl6byZjGUn4hm9terwFpxrKya00FajlVeNuIsA7bg2y
         vOdFryGSe70uS6MH/VY21HDn040dW7dELu5OhdHyjViXpOna1qDl2vEsVltRZyoCWiIj
         eoG7G1c15qe5XM/VBMWSDjCN9E43zRQ9Jrg5xn7YSY+FO4Y44Ru8akgRKWdNk+5MnYlq
         aKd26wo2UPs9qop2ZPOA2lARx8rAIo3M7xTzd9hRlwpSvjvAba6R7llIOakqJOaNYpTf
         QL/XTe4Cs0ATRymFeKz2Nd9o9c5EgsiXBZ21zdjGpGu+SerV0OXHQ1jv0oKi3pvDrnwR
         aIsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=B5dAVjAu;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=miZXvKwWjsTtCZP8rKOCd8r/6k+RJtbmpnWGcBN7SfU=;
        b=awytbTNc2Itje2B7VwBIqoICptjkPGZUC8EBfyahiIkWPRBfDw9iXZ2c4MaqnLWlKT
         57OqtE3StHDEWaLYKE2u7NbSpDe6V8jYkYh4rGXt5zhWIyq5TJtFOvyd/8rshRu954kp
         ua1iqdcEyB5ypEMcYACf0aCCWQMHeWMrv538WWDztAcyKb4GOvs6Vg2iCmAFOqGdFCLL
         wrtwbsC2U6wzc5gBuXnoN0pHt0QdQKGargLr6svMktfQ+iCHskDTIZ93KHNAFprxonUR
         ho1W+0DqfSB/EplQ9RV9h/ao1FVRvX7POAUFH8Xh+h1NmeD/T66a2K7Wbs9wfNS5oFhM
         3xoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=miZXvKwWjsTtCZP8rKOCd8r/6k+RJtbmpnWGcBN7SfU=;
        b=vI6U4AOPaQ19lTkX5Rq9c8WuP4CVxmmgnfpEfxlvySJn3XPJxs+fKGhSSBhLK5rxDq
         08QFzxCMORBVjx2767LJSUVM1hXf3nihdOMjlW/hKM4EgOLmQ4B0XCFvzkJ+BhSx/hic
         OK+SQKAQpk9Jfcj9mwRYUqMTM2C41bb1SfsY9gfSdx3wVFT27tiUJCbOMjx8Ip2Hbu9n
         XEMvHm03aUvB5AK1TA9wyTcIz7o7RZIywk4wZAfWbj/tTKRgjtkv9pxfBZ4tkdyjoZEx
         A0kZET6faYZ9xeDcRVSaKaKq5pH17xJXkwyiGJSSv3fkuZFym8u5PKkydvuSXgO9eGon
         6+Gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3Qrfg3d+EWBLaUwwYZfeo5E3N4Fm9XhAwzPYaw7qEIVjf5yaYi
	gUUxENdT8iayai/hR7nDYx4=
X-Google-Smtp-Source: AMsMyM46xTGXUnRTaiaAt2o2mqmDXiF2g4sXFxjE2K35CDoA61wWewNCLNrPbljtGk++tx75m/I49w==
X-Received: by 2002:aca:eb03:0:b0:34f:e155:4223 with SMTP id j3-20020acaeb03000000b0034fe1554223mr1195840oih.66.1663670609708;
        Tue, 20 Sep 2022 03:43:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4395:b0:129:f282:924a with SMTP id
 lv21-20020a056871439500b00129f282924als3719059oab.8.-pod-prod-gmail; Tue, 20
 Sep 2022 03:43:29 -0700 (PDT)
X-Received: by 2002:a05:6870:8917:b0:127:8962:ccb6 with SMTP id i23-20020a056870891700b001278962ccb6mr1596889oao.221.1663670609280;
        Tue, 20 Sep 2022 03:43:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663670609; cv=none;
        d=google.com; s=arc-20160816;
        b=yFqIUnv6jdbBlHs92UG00zlWDOjVIB4Cv75Px1hOS5yGJlnv/sUvNYuE2/I8pAYC3L
         eshCJNB54gUYQE0cXR9iwMafA76am+qr/YE/ACfwvzXHpoPNzfflJCdbN1DOR4oTPqCH
         WB61LQky66t69Tl7xG7AIZMOWyRY7JeQYU3EOJib7K82pjXq1cyJMVmmq9Tz/W2KYLBp
         v90aYGEOA8rqd6PgTwQVBHfDUz+d3xq0E/DkWwDp5VrT08uKIhj4V5N4vG5u2jhs3Ojc
         QSHF2LzpRRKwlAS+8UtAIFSOEj/vdgu0IjKsp8gVfqvY8nZYwDMamgbwwmBYMhDNjqla
         uzDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=v9WW+cVAlfRUtiTqpU40bql2fWPHDaEhDifryFeHujk=;
        b=ONglxaJ5n51BGFRbpilPH/VaLWRBMR8fw1rF0VtlFgXcgxEddmK+uBjkV2uMFRIF68
         Dh7iLbu6gcRpXEgkfxHdtyhtS6Plu5ERFEROw0ymSEPI3eCXEsd9aGgph8O5hPDvXVKr
         buoDb/SGJ6mH0zgl3iL8GL5ue7hD+u/C3X1s8zfBSBtaXvlUx3z5t5Mxl9Xk89RJo+6K
         RmEEjHRhviEmSwadyN2Nz9ASBxFnrAC9OOvx4U884/URUu2nTSRTzR1Vrd5wVmCJA7/0
         uX1oaAZ6Ax5CWyxuJtRLVRtokArDqc5qrUXigVoBsgh1UkeL2OFM6zO88dwf8ro0FnKN
         XWjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=B5dAVjAu;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e184-20020acab5c1000000b003504d4fcb12si63703oif.0.2022.09.20.03.43.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Sep 2022 03:43:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 0BD4062908;
	Tue, 20 Sep 2022 10:43:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5A744C433C1;
	Tue, 20 Sep 2022 10:43:27 +0000 (UTC)
Date: Tue, 20 Sep 2022 12:43:25 +0200
From: Frederic Weisbecker <frederic@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <20220920104325.GA72346@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.534233547@infradead.org>
 <20220919131927.GA58444@lothringen>
 <YymAXPkZkyFIEjXM@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YymAXPkZkyFIEjXM@hirez.programming.kicks-ass.net>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=B5dAVjAu;       spf=pass
 (google.com: domain of frederic@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Sep 20, 2022 at 10:57:00AM +0200, Peter Zijlstra wrote:
> On Mon, Sep 19, 2022 at 03:19:27PM +0200, Frederic Weisbecker wrote:
> > On Mon, Sep 19, 2022 at 11:59:42AM +0200, Peter Zijlstra wrote:
> > > cpuidle_state::enter() methods should be IRQ invariant
> > 
> > Got a bit confused with the invariant thing since the first chunck I
> > see in this patch is a conversion to an non-traceable local_irq_enable().
> > 
> > Maybe just add a short mention about that and why?
> 
> Changelog now reads:
> 
> ---
> Subject: cpuidle/poll: Ensure IRQ state is invariant
> From: Peter Zijlstra <peterz@infradead.org>
> Date: Tue May 31 15:43:32 CEST 2022
> 
> cpuidle_state::enter() methods should be IRQ invariant.
> 
> Additionally make sure to use raw_local_irq_*() methods since this
> cpuidle callback will be called with RCU already disabled.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>

Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220920104325.GA72346%40lothringen.
