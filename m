Return-Path: <kasan-dev+bncBDBK55H2UQKRB4UBU2MQMGQED33NNZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id F16455BE0F7
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 10:59:30 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id g19-20020adfa493000000b0022a2ee64216sf880553wrb.14
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 01:59:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663664370; cv=pass;
        d=google.com; s=arc-20160816;
        b=WdJpuieMBKFnvKK4ClBO/rsZLTv078tPqogJMuTbFcnvETHrwcZRhm6vI7uhiOZj1N
         bEImRc02aAzVJ5STZS3ywkakq2BI8fE0c7lkKOEOzRXIh72ya6+uFVs+C5SgbuH/RRNm
         5723Zywueia42dPP5ulXuTYrCNALmmV9tY5QArFzB6XgGuwl27eH+7tbFJAvNPedyBLJ
         q3gden3a5+nL4wjaU6gbxijdOXnTJ0YiH54YoYNbbgwihT/d+eHVeB1ds9PBDoC2ECbV
         iBhFdOK3q/LuO91yV7fabh+xOJOB/RoRzLzOxQjnuXkHAOp/VUcqRNAk6sUWOw0VvLlc
         v6uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hYOlrOtPLtI51KjB4EM81RDJASl2M8w69rGPLWjyRu8=;
        b=qY7x/AGjY+4N+MiwZq8N0Yj+SVV6avuwePlUT2HYmJkg2fzKew12PxK7NkvQqFI7Rl
         wj9iiwSgvQxiX0TjHc1p+VVqsf6Fw+SpuvmpMQeTTke9Zi5ZiTQP9LvWnE5fC1t6gtYA
         9qd2nSVnWO7e9RNnwNDiHfcKV4b06mvO8TwVQ/tqmQ2vp+1LfDbuXl7hJHcGoOnTM+H/
         6FUlx3MGpq1Dwain+FTmx7205XX8VdHR+jT/wzH7JFc5I35IzWEK95PD6rmsR0LWnyzA
         mfpakBFv1aZuVne9PAlJfAxX79KD8jXPa1VF+Dqli1KCQqYzZIfGE1VQXjThBbbYEvNU
         tYhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=W1sdVyg7;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=hYOlrOtPLtI51KjB4EM81RDJASl2M8w69rGPLWjyRu8=;
        b=aKmr8weTEbQdX6k5sXW2yGWBwpBqZBcYwmA8HYrmK8WyFYie7JcmbLlfV9orqxJiyr
         Oha2tSj+98FoUgirdeIG12KLZkSmtvlX6LoP4EAeASPr1TywC5GCC/+ix2JAvD32w9IY
         fPYjwxewAo2ttzi+9CzQ3x9SwaKZ08wka7OEKqQFsRYdUiPOqG4S0eQXhFwpvw7uFXeY
         ir2XLTw2NhJ8fPaJ08bOol/IwHXv/YCd9LA9CjTR0nH8ESZiQp6wgm+qbQir/KLw+sI5
         CoNqdB3ZtMSNvzr1RY9oc4L9Re84hbHsEKp4//oPL02kPXe67P3LjLsnHX2nN0uRtQCU
         8iDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=hYOlrOtPLtI51KjB4EM81RDJASl2M8w69rGPLWjyRu8=;
        b=cwlla9xXVyVlgZvZgPJWgrMxmAfLtgp4AlWJ39/bQiYmNVxhRG9urRLFfpHeqGJW/v
         sawc1yb6cYi/x6QEx0dBd8d3o7kEgV0EkRsBUDUtOpMyGVW5cBriCM6oA/nT51+Ktpvd
         jfydI33mUbJZjiimQWM8XeS5yCQgerhLq2Z2LH8SmgEhoXJpvikZALIloa8UOoNK9uwH
         IPbsFXZeM5oNE+yFUDaxdq2tWLdg/KZ33ztgjzNg67vZWj9Ew6bIdPzd7yg5NUQ/nI4O
         mHdnA9m9WjKvlPZU5pfFxxlA3PjoiABt20aVD61otlY9adBo3VdMlyglHvDESEhqzFRb
         r6Yg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2aOC0WfW65WmCndapPPearjrCtfuUR8Sp4kvqKt7r7qju72mvx
	HFNnpcP7Dz6o1vypV7rjofs=
X-Google-Smtp-Source: AMsMyM49tUktCkBL9ECecvrXjB/mao95/VDxhYj8iyPBfV7aSOoGyHuLFlw6e4FAk2pa3ahEa1lCbw==
X-Received: by 2002:a05:6000:1842:b0:22a:4d1d:4bd6 with SMTP id c2-20020a056000184200b0022a4d1d4bd6mr13183720wri.603.1663664370603;
        Tue, 20 Sep 2022 01:59:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:490a:0:b0:225:6559:3374 with SMTP id x10-20020a5d490a000000b0022565593374ls1547587wrq.2.-pod-prod-gmail;
 Tue, 20 Sep 2022 01:59:29 -0700 (PDT)
X-Received: by 2002:a5d:4f12:0:b0:22a:47ee:7378 with SMTP id c18-20020a5d4f12000000b0022a47ee7378mr13624007wru.672.1663664369423;
        Tue, 20 Sep 2022 01:59:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663664369; cv=none;
        d=google.com; s=arc-20160816;
        b=o2sZ/9vsQMuU8+dz9TM6UXbtMB0PlvThUIV3deTgxmwk4DYeIAbdt0nHfMbGdMc7Fw
         K86U3C7GrJF79FFbm0ncL7cKBCfI0/RzZyvePiisboofwlhc6tgBmCrHrpzYGE9V6C01
         ssB2/8/uvlydrs83dypRNeERvH2dODphwB5di/rtzPQJLNfXVi1FUqytvF9cGo+VTrF1
         HWImrxjFOw5TmymyrkdvbluTUXoM1LfsrM7bn3ewhp+b1oLVXA/Xw0zvsJpF0n1LcIzy
         wk9FpgCCHfTAG/rQwlJ+xjqWheF5/d+vosWnfcXLAjzGuJ9KYlpXtvJy8NVSLbTuMIiN
         RNMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=W0WuIu+jUoS9XLKKaCH8kQp1fmQssrlCtEm/el88ozE=;
        b=MAtuNPmgmqA3yEZBMd2LiLGdoZkbp54UlkKf1CV5y0HNNisurwC3y4AJyzs3fuyno4
         gCgIvQsiNpUhbwSTf7HS+9rx+PH9xilak2LVuLlgX+6WUxYfYIaOtj4+roAD7q0Njeun
         DV2sTyvJt8P+5a7/v/+KRim6jleoTfkNXUPQTc01uuUMp9fjnoZEOVRDNlyfjbwxCDwC
         nZiqu9glB1BHoK2OlBscvib8XEMxnLP1JGmgF0nP9PIJrAjVmPLpKqzmUhtu1PGHzwGS
         N1qBs4AC/9EHIqaJN7l8csuutK0QwRgflBM0XcC4qq8KjdS4vCXDwW9NmahGWcgRSjw+
         8mtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=W1sdVyg7;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ay21-20020a5d6f15000000b0021f15aa1a8esi23292wrb.8.2022.09.20.01.59.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Sep 2022 01:59:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaZ5n-00EIzm-Q6; Tue, 20 Sep 2022 08:59:00 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4AA353001F3;
	Tue, 20 Sep 2022 10:58:59 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 211C72BAC7A93; Tue, 20 Sep 2022 10:58:59 +0200 (CEST)
Date: Tue, 20 Sep 2022 10:58:59 +0200
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
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 08/44] cpuidle,imx6: Push RCU-idle into driver
Message-ID: <YymA0yJybIWLco/v@hirez.programming.kicks-ass.net>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.869531945@infradead.org>
 <20220919142123.GE58444@lothringen>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919142123.GE58444@lothringen>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=W1sdVyg7;
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

On Mon, Sep 19, 2022 at 04:21:23PM +0200, Frederic Weisbecker wrote:
> On Mon, Sep 19, 2022 at 11:59:47AM +0200, Peter Zijlstra wrote:
> > Doing RCU-idle outside the driver, only to then temporarily enable it
> > again, at least twice, before going idle is daft.
> 
> Hmm, what ends up calling RCU_IDLE() here? Also what about
> cpu_do_idle()?

I've ammended patches 5-12 with a comment like:

Notably both cpu_pm_enter() and cpu_cluster_pm_enter() implicity
re-enable RCU.

(each noting the specific sites for the relevant patch).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YymA0yJybIWLco/v%40hirez.programming.kicks-ass.net.
