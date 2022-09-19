Return-Path: <kasan-dev+bncBDBK55H2UQKRBCURUKMQMGQEBUPU7GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 251905BD08A
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 17:19:39 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id h20-20020adfaa94000000b0022af8c26b72sf828327wrc.7
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 08:19:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663600778; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jo28DzQAf6oppE+tPntXO7k7NdzFr4o8XsucYbmf8GPVPBz1xIuQcX0Y9+3WTQVYBK
         eiweTXFtKo8o4e6UR38coGev8FUxRYrq/Isugdu3juhqna7oRGWYN8EeesO2rZG+XrsT
         jlaQ3l4dH+UiPWtAwowl5P8x6LILCbfWXMkZ7yQMV6sT+XoEVPqirQuRbv5ugFf6PRM1
         dHtI6UfO3VE3ta7TAvvwQf0741Lqxb5jjqCjS4+PFZHJYEUAVE6KQap3b+b5cRM6G7jQ
         J+w/4P+AD5nIUGvjb3CS6sapAAYcYAFMbOsfzUK+NPU2pcUypyoY2jNTrevV6R3AsX0E
         BHgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=j9VNXfMpd55+miaemZHUhUzmeqFSMY0aQvPFIgB46uk=;
        b=Z9oMtiOCa8JoKVv0dN7c0dhCB+Z8umfVQRs+ueYCige/21iICdIeYytvHdUAmdkX+5
         frHiLNcTJ8u42BmDac2QS3r37aGn8smgxxmQCf7RtjZsGWvLkktEUlZQ3tQqAZ85jQcL
         YrkhaKobFkPMXDbMTblNVq5FoBq0sHF+ZNF/I0KGR3zFWBF6O8Xv3QPYm4GLwlqRwghE
         1qduD05vNYjHT3JF4QVX67HKa2Njq2Is6wZ8LRbr0vuV44GQNVzxCfIfgi6U8koP1x3A
         6yRUKu64+S+0xRvFx+hvf5BbF9QXuC4WPqWekp2swD48mGNDrXMSqCvDTz5tp4JYGfiJ
         IyIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=XPfGWCYB;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=j9VNXfMpd55+miaemZHUhUzmeqFSMY0aQvPFIgB46uk=;
        b=Ofb3yApU19xLKtD/wl65g0NdI9nIZE19dFBup6FeJ52g//NtedkUkN6p76vfFdWsVK
         rDV7N4XGjEMDz79kfelr+BfDYG8lYWkV3r9ncYfP/yUtfVVZgISFnMId7kCvtDFmcPEd
         vVJ3STUlkA7m15ywCtlJZvw7Sr4HF7cm0ymq6Ry2G330q2M/Nm/VYdfv1FrPbaBvWgBU
         FNR5pLM5iPJrQPVXWDcOyV4SuPazzh8GKbU3fq23RtlDhBFHk76xF+JqcejSnBlHKqYM
         oboOSbHiHqEK9bRtqMT+1TZ0+pwYTx+am6xqjGCjNWcZtYHO0rXDdHcnvsNth3RW7Nbr
         WoUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=j9VNXfMpd55+miaemZHUhUzmeqFSMY0aQvPFIgB46uk=;
        b=mnpv/NoaB7rJEQ67qPvE+/MS8lYrd5tJJVyYeUx4I03JZgk4dAdY+hcyUwD7sa3vwD
         ija3pCK3JwbT1Tme3ljVtp6Ygj/akPK23Ao3pgbFaCWu7SRgZYHtDmTm6DHZNU9vegEw
         upLpfWIToODm1So9FHQt566FY9lYuLTiWCG8V4wGXqiVyzpryLkEQ7AmGFXfUbJBC47G
         3VL8Jf6PFBt2wCuC3YXKs2VtHAMz3G1UPboXgfmxo+Q1Z7nMiG0GMzbxaGO7pYZf2bGN
         jLU6VYgRG/HDArutwcs5ZJTmgGe2eqpt2WzlbUYXfv37M5YRsU2XRTJJ4YTg7yZmXX/L
         kcqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2IkpuYUmqaE+oSTM5GFX/MtwA0ELiXzffOV5a1gSuhZhwueTB4
	QKghrZ0+vuYCdX2GLFunXfI=
X-Google-Smtp-Source: AA6agR58OBiSEoCnYnYhjX+o3kKHTD+YwWNNLuO7fqhj2kbUo/7Gq6FOmdGKjpxySRy4dgCxYGfn0Q==
X-Received: by 2002:a05:600c:6018:b0:3b4:6c30:d9c1 with SMTP id az24-20020a05600c601800b003b46c30d9c1mr19176018wmb.144.1663600778714;
        Mon, 19 Sep 2022 08:19:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:490a:0:b0:225:6559:3374 with SMTP id x10-20020a5d490a000000b0022565593374ls8858785wrq.2.-pod-prod-gmail;
 Mon, 19 Sep 2022 08:19:37 -0700 (PDT)
X-Received: by 2002:a5d:6385:0:b0:22a:e533:f715 with SMTP id p5-20020a5d6385000000b0022ae533f715mr7896327wru.88.1663600777557;
        Mon, 19 Sep 2022 08:19:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663600777; cv=none;
        d=google.com; s=arc-20160816;
        b=Ti+kBxk1EIIXng+eBxRmPczOTLikwUmyGY9aDijytiTF/CIw/TOBgK0pLInaHuZzZu
         DjUxoKsl26s1lvWdgYifhZRCUWuLaGHsS0T/tnS/X7bmwaEgQta5Sf6GMebpoTTSmWv2
         BQk4Ath3xGh31BgjRvi2bSYS1Shh6nY+QTsR46jTi3WBKcozdTsjAlT1bnCJ2MDxrVe1
         UcOx/4Qcyfcy1PZxuCTcREWWoYHAtEN775eUEgc+Smp0ZWVcTjsWsRUdWUviRMOIO+ex
         5i66XWx15Elv6BqFNAhivjzNr+EiJ8rrjW4F1O8cQfgOMVYkZ0SbepjEOUGE+DqeEn2P
         YxaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jX68leu2S48Jr9/Ow8JXapSFFP60f/i61NXz6aPsf+I=;
        b=mVIzM+Gzop/Rfe6pU5gtM4EvHtXUVXE6/gMu6ARw+o0asm22/+0lRbcOma2hKyrjQD
         EmplE23EVjlObgRo3+ljgcTd2XMGXs/vSoL2o4jStPJMKqTOsKTTZf6Q1+1NN4jYHHgW
         N5VpONSs3f6qTkustY1LiAcTLFEtQNmIyv3SK1iyfI2et/+piIXHzTPV/hB2BiSpufG/
         sLwk8VvrOaSk7v25G5PI6Zcdba6mDDrpuAnMFym0JV9ZH8xrvhGP7SsbNYxY6TB9AaE6
         zCV05T68uLuySMx9ow7FH8JKN6So6cbGweQiV/CJUX9SC/42njKIpl1XDcpaTjnvCGku
         OgRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=XPfGWCYB;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si509845wma.1.2022.09.19.08.19.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 08:19:37 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaIY7-00E6tU-7a; Mon, 19 Sep 2022 15:19:07 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 046D83001F3;
	Mon, 19 Sep 2022 17:19:06 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id DAFB72BAC7759; Mon, 19 Sep 2022 17:19:05 +0200 (CEST)
Date: Mon, 19 Sep 2022 17:19:05 +0200
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
Subject: Re: [PATCH v2 09/44] cpuidle,omap3: Push RCU-idle into driver
Message-ID: <YyiIaeQY8STLK0d0@hirez.programming.kicks-ass.net>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.936337959@infradead.org>
 <20220919143142.GA61009@lothringen>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919143142.GA61009@lothringen>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=XPfGWCYB;
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

On Mon, Sep 19, 2022 at 04:31:42PM +0200, Frederic Weisbecker wrote:
> On Mon, Sep 19, 2022 at 11:59:48AM +0200, Peter Zijlstra wrote:
> > Doing RCU-idle outside the driver, only to then teporarily enable it
> > again before going idle is daft.
> 
> That doesn't tell where those calls are.

cpu_pm_enter/exit and the power domain stuff, possibly also the clock
domain stuff. It's all over :/

I suppose I can add a blub and copy/paste it around the various patches
if you want.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyiIaeQY8STLK0d0%40hirez.programming.kicks-ass.net.
