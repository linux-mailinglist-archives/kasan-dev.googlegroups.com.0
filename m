Return-Path: <kasan-dev+bncBCQPVKWLVAIRBNNRZKMQMGQE2NQBFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B5905EBAAA
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 08:31:18 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id v17-20020a259d91000000b006b4c31c0640sf7771073ybp.18
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 23:31:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664260277; cv=pass;
        d=google.com; s=arc-20160816;
        b=hDrjwm1Lg1aaQoz48+QPfym0xqA+fwzh4L/UOp2y04WK4TqTxVUEx1sVg8k2/wdBO7
         NMcJUXe3pPc/O8jgc95vmCsxF9XS7G+Jvm6SjPXkHw9Wc9WjfLYWvgMZs4iNFrfn+IvH
         oCEpyvPxpBt+WzKoV57cqK6EEZ65oX9qlqpNi/Mo5qAOHt2GAZazpVG/lq0UQUpyHn/M
         WhiLi/l/lHUmlKCyWDKgyhBHlyRNSXdOKbhI1xWmrn+ZQZxNFaBcTT1mOUp1zPfmsCbI
         TcVO36KmGHHUe92pW4DcS850Rr5pFwwmBWfG6Y6ib6yOKaCGc/hoGbhcYJw2rRNXUn08
         A+pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tVZ+gR3QMUAp68HIU2wRHd4/o2MpXTsFAp0z2k4CGrs=;
        b=T+h7lCoHwVe1hJR51ahGlhO5dfs/vscMBqHVFqdyWJYuP9zwcwwTQ/UzFTEAWqBV7d
         DxQx9XaHd4KmgkXYe/NtUa7cErojHaEDyNyerj23CeeAfeQJR/7+xfDZCHTOMCYe8H6k
         CqVfQkcc6PDIln7gRmyNktKVj2kYHQUcWBuBMqPwmTo/bvNxRGn4Gqhp32OMCZWpXKfL
         SYjmPciMgC8MkneqhXBpr6+YAk/bqTQiYo+rKTgGKn3Fl58ERv34Xg1Hc6U4jkQ/3e+c
         cGG1NV08E9OCt2st2IpOkNjN3PeEzoYNWcDYqcxB3xHwwY3mBpveO6zoSvV/dTvPkx5y
         GiCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 72.249.23.125 is neither permitted nor denied by best guess record for domain of tony@atomide.com) smtp.mailfrom=tony@atomide.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=tVZ+gR3QMUAp68HIU2wRHd4/o2MpXTsFAp0z2k4CGrs=;
        b=JfssHj5dB/6kFUtiDRUXqvbXm+TwBn838/XKrUejxxkntJ+4PD4g+D2YnTOtuR6qG7
         DTeYz2BoRJG+pjO/hpYNqYS3v1HzoTpJAOgAYe2QWIZ2cwq4/2bEdtkdt1n/zL0cEcr+
         k/3203lrFnODItCr7C5eAXMxddsquqenfYRZ7wAmSCg6lIHJNoXQQky7YMzNqNHnWmvN
         tR+uV+8Beb0VuPUtHvte8QhJtUNOkZtMf6zY3zYDuueYeV4qSxjk0RmvgvJmXcUZXKPu
         86/OSpkKgvHbhD7PwdPTlJJnOm3kXSJvBHOiN/Tc32ijnu1P6wI0XFu0h2eIYVn4CCzc
         lKXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=tVZ+gR3QMUAp68HIU2wRHd4/o2MpXTsFAp0z2k4CGrs=;
        b=DMrcm74oAtaIdjQKl83PotSDnchnM8y6TyL9v0R0+tUektCb8rHbODg75JtPPPkN8J
         Lt9e5h7wCzzjE/VYGV6kil55KBH57nL1bFvPvwdHo1UP4ozAPksfkhVjR3bWrSAnFUF6
         RozgqXXPkSC9KfGpUwTJpfShdIoZ0ZeDlBIw5v9f31ZvWLTsq90qjVQoagKehF50QcQ4
         tGNftYB7y0S8USQNnkhGQnajOCT0aJgsTMrI+Ly9Qrlmw5RBG/nloMpTynkY1XsSvRzv
         3iBGDIcR2iiVexQmyDWHV85Dm/bH1Ob+HzAwq4zpuQZsNAokmJ4S9igbi3SB0FVGTMIC
         tZgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1PwWgTZVrrDyawB6Rx0vEjLQ4JlT5LzZuAz/2h3WD2H8ODRrfm
	XsDTcRUUXpM3wHN3nJRjjK4=
X-Google-Smtp-Source: AMsMyM5YBuM67q3qjMD5yEdprXZ8UJcOv3ux7h3c3EStAByd3dnONh8ULZ8LsYTdd9nurtPT2kga/w==
X-Received: by 2002:a81:4c45:0:b0:345:4178:1805 with SMTP id z66-20020a814c45000000b0034541781805mr24747202ywa.114.1664260277333;
        Mon, 26 Sep 2022 23:31:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a342:0:b0:6a9:454a:4e83 with SMTP id d60-20020a25a342000000b006a9454a4e83ls1008717ybi.11.-pod-prod-gmail;
 Mon, 26 Sep 2022 23:31:16 -0700 (PDT)
X-Received: by 2002:a25:e311:0:b0:6bb:bf9a:e762 with SMTP id z17-20020a25e311000000b006bbbf9ae762mr6822421ybd.110.1664260276726;
        Mon, 26 Sep 2022 23:31:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664260276; cv=none;
        d=google.com; s=arc-20160816;
        b=aFUDPAUKv9tqP1RwzfqhiPq40eynZLoBksemrjb5nGNI36PQ0rvGvdRh3ZYbT3JoGs
         u1QCM1++0QBBisco3LcxMg8fSJNLpOnDkS+RktCIX2ORVQww+krM1Y/4jxuSwnYm3Bth
         n5jf4KHeIHPASj9yzPAYGZYG6dHIMi1gLW8bM5TtuQ0T93TJD9MPtV4IeOjc4trzk5Sj
         eG8b8vvzSvay4q4pLUXVWdh/5tZswF6+hbncr0gv3x8D1PlFqNqpRyHvPJ7Ty8fI+zGM
         vW+O+5jeQsx3tfR17l4Gz33hnSD2noILDB+3z0peMKbhJuGzbUPhGoqNPtfAkOpykZH9
         lAMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Qo1+uET5gHpcCBtdQyHI5fAdMrtG4s4iexHkHEsNJ9A=;
        b=FXMmLlL7mBObu0XRz1UK5TeVpNckHezKdkRL6VdWOd8pVNB10J9VDTE5myqnGZ8nP1
         ERpI5f7jUAWWze8GK8C7ZegJakaQsu2bxsAEdxv5KWxMI3tEBAm0J6SuAjVYT2y303QT
         nA5Y8EBX+5Mob1Ajboqd2DCJzRzYa/88/abnyuk6Ji0o9wRheIYYPLo3EepG+FjARnpJ
         2gNTrZ2t73Ap3qrdEa4WcjykB6dpL34HI5snRDUDHtKuEmsNeUyGgt3TdLznWk5bTcJ3
         k0ve8c4RGNi2VbCY4KfhFlgWlRRv8rFV9XgljYCDzoZbExaRa2nzS4aP2+qYqRhQ0xrw
         sb/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 72.249.23.125 is neither permitted nor denied by best guess record for domain of tony@atomide.com) smtp.mailfrom=tony@atomide.com
Received: from muru.com (muru.com. [72.249.23.125])
        by gmr-mx.google.com with ESMTP id t195-20020a0deacc000000b00349f81a2957si33074ywe.1.2022.09.26.23.31.16
        for <kasan-dev@googlegroups.com>;
        Mon, 26 Sep 2022 23:31:16 -0700 (PDT)
Received-SPF: neutral (google.com: 72.249.23.125 is neither permitted nor denied by best guess record for domain of tony@atomide.com) client-ip=72.249.23.125;
Received: from localhost (localhost [127.0.0.1])
	by muru.com (Postfix) with ESMTPS id 5E7B081BD;
	Tue, 27 Sep 2022 06:22:54 +0000 (UTC)
Date: Tue, 27 Sep 2022 09:31:11 +0300
From: Tony Lindgren <tony@atomide.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	khilman@kernel.org, catalin.marinas@arm.com, will@kernel.org,
	guoren@kernel.org, bcain@quicinc.com, chenhuacai@kernel.org,
	kernel@xen0n.name, geert@linux-m68k.org, sammy@sammy.net,
	monstr@monstr.eu, tsbogend@alpha.franken.de, dinguyen@kernel.org,
	jonas@southpole.se, stefan.kristiansson@saunalahti.fi,
	shorne@gmail.com, James.Bottomley@hansenpartnership.com,
	deller@gmx.de, mpe@ellerman.id.au, npiggin@gmail.com,
	christophe.leroy@csgroup.eu, paul.walmsley@sifive.com,
	palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com,
	gor@linux.ibm.com, agordeev@linux.ibm.com,
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
Subject: Re: [PATCH v2 00/44] cpuidle,rcu: Clean up the mess
Message-ID: <YzKYrx8Kd9SBYcUg@atomide.com>
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919095939.761690562@infradead.org>
X-Original-Sender: tony@atomide.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 72.249.23.125 is neither permitted nor denied by best guess
 record for domain of tony@atomide.com) smtp.mailfrom=tony@atomide.com
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

Hi,

* Peter Zijlstra <peterz@infradead.org> [220919 10:08]:
> Hi All!
> 
> At long last, a respin of the cpuidle vs rcu cleanup patches.
> 
> v1: https://lkml.kernel.org/r/20220608142723.103523089@infradead.org
> 
> These here patches clean up the mess that is cpuidle vs rcuidle.

I just gave these a quick test and things still work for me. The old
omap3 off mode during idle still works. No more need to play the
whack the mole game with RCU-idle :) I did not test on x86, or on other
ARMs, but considering the test pretty much covered the all the
affected RCU-idle related paths, where suitable, feel free to add:

Tested-by: Tony Lindgren <tony@atomide.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzKYrx8Kd9SBYcUg%40atomide.com.
