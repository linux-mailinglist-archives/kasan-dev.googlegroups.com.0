Return-Path: <kasan-dev+bncBDBK55H2UQKRBP4DUGMQMGQEJSWXQGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 098765BC673
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:36 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5-20020a05600c028500b003b4d2247d3esf1108129wmk.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582655; cv=pass;
        d=google.com; s=arc-20160816;
        b=ofQpd6w894JLqOlnBEt6qgJ+Aadxi5jCBF6h1/1+9Slr+7UZscNiehYGxea365HBgm
         8hV4NpEaUSHLUWuLEqKkG+pp0uraN+0vWw84tNFH+yxbqFHXrvLujFZ9v0v+9zQ+Jfk4
         tRKntmIqbqbx6UuAmBsbqakUAbfd1ksZbN8jKubM2c/t1SOWSgAV8qf5c+QprLNpegg9
         T9wDrVWHPYsQ5tuWaV69oiKc0fiospsmEHFFzZ6IhvsNQEDveqB8Mc+VxZEaG8I6TLal
         lLho5xsqoOViQT1+AcLBt9forgwCmavtOXhSYcFefbGLfMrhdaPoXZ9HM2qwrDuslf+e
         upNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=tXG29aw4S8Xm47nuirfVLR1Eb6sHgq+nu9FVPLTLfIg=;
        b=C2/E/5dLSVfOIHUjw/sk/Rm3iUjs5hpJvtZOzkvFR+7ekKKr19M//oguNnh4w1BGF6
         47fPYMC+Q+UrmAH7V+6PxCmOoa2v4eizoEk9p96DBsY/BE5VIUBC7Ef5Mk7oJ9c8ObnO
         jhuq6JAx8Lin7ruh5Eue7qjOo8GXX5V0gAAu49HyFnE2+rBqSAyomb3RLo2s+2efXUnv
         W2bW57Wip5bPyhx34lUT6dbFrORPGaMHOxZt0JtNX8Q+NZuOGVoJeUFX3ylnBF5TdkCX
         jcLC+OLh3g0fiP1GQUmbaNfNrSUC7fbV+E4DDc9Ap62ay6Z5jvaomByc/V+gUCuxZjOn
         dXwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=jqHZgeFh;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=tXG29aw4S8Xm47nuirfVLR1Eb6sHgq+nu9FVPLTLfIg=;
        b=Ev+dvUrP+7xuiXa3lyr0LirxAt/oX9QeLFIyzGCuPv9bJVeErAckL7mCAhI+AcyLZg
         Y5yQ6EXx3v4MyV52ayKgGqpnmus4kFx8AeU1BQ/OF63X/4Eh/C6hq2ESFyFB1D3opb11
         NRepnVDFNkGJ7BBW2QPcS3FzIrU6aNsIIl/OW1EZmAX4UeJSmq/KojwyCAGCvfSPo0by
         Gb/z2LgXQ686tVDMrq6H2xpW+FSSabWveufJoH5ew3p2+KIBpdQkWRM4eN3yQvhbmb5K
         JGdeLnfjVZ8TLk/tOY/cWDPkPvs+vNuZT7WBIJ+lKa2bBEvDoIUKMkyrIsE7VM60ap9j
         5QDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=tXG29aw4S8Xm47nuirfVLR1Eb6sHgq+nu9FVPLTLfIg=;
        b=Qf52SDRGXGseQtChFSfc8anMBAeYTU2jR1pW3chaaZXvB4wJ1jbtJu7TNwF43flYVU
         mr6UCM5iuYhyk/v8sVZF087ihCO+YIQ8ePunmERl8DLE0kYNNqCUt8GfbN3CYJ610bHX
         NZzeSivnphDJDxA92Pv8A/hPfoA9Fy11p9xN6wTQd+yIVeNOCPnrUyB033Dj3kAGiibc
         ZyY8YA4/nUFbn5qvLqRYSXQKCzFwi2hEXsINgdHWQhkqOv/33PyMpvUFOU2+Ue3Urokf
         7p9+hheESytocCr4vAQn8uP9EpmxJ5cYl/IXhtlWo7AT4TjVUEFgMZCdKSmMc9z7U7dR
         f9AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0hkVNqTZ0Ft4oVzhzl/hHlf/OiQdXY5oXRwpMaO3ynQz+zwI9B
	fLqIqDzL+msQceoXHtOWw8g=
X-Google-Smtp-Source: AMsMyM7KyCBp+Hy/ixeg3qGBwJpR/Oamigk1AE4LFoPl9x9MGVyfnfO4ltL8VFc2/ABNPEExQUTpJQ==
X-Received: by 2002:a5d:64e4:0:b0:22a:4997:c13c with SMTP id g4-20020a5d64e4000000b0022a4997c13cmr10801243wri.621.1663582655647;
        Mon, 19 Sep 2022 03:17:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels2881575wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:34 -0700 (PDT)
X-Received: by 2002:a05:6000:68c:b0:22a:bde3:f8cc with SMTP id bo12-20020a056000068c00b0022abde3f8ccmr9996425wrb.556.1663582654514;
        Mon, 19 Sep 2022 03:17:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582654; cv=none;
        d=google.com; s=arc-20160816;
        b=A/eTt/ayL3tede0RdM9T/+Iw7kQHIJBo5bevrhHgDJFSWXV9SJ4M3Cdtai6QbJIPcx
         MIhIqzql10PbJ3lLDPRHpto1r/LxeXs4sYyGvUr0bcorYENa2rlRc9A8VFJVu7wouxug
         C005T7NHePODCjWGFLN564fe4eE6RE03CK0OHNRpbi8gsuVlCyP8nRlFNh5XmR2J4xin
         AD99Obojgq+CZhhgoXV6qeW68bdnf+8n1XPCBCFYaBgLg9lvvRRyDfW2vxwKkzsGDmwg
         CPSjAZhJ2fJRZlAOxTqU3m1MI2hc16rdUf11Ll6OW7nUf2vorzmNAwdV2/7l9B6/8RyJ
         m0jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=DdEsMVUZF4If17doP56YIzy8DGEaYRA+HGcY5bau4R0=;
        b=emPM5vQArgzclCH195qX8qOqCqgu4/BdSIrxtiYHCGWaP2IPo01L0SS6GVFZPHC5dQ
         +rY24mDjci41cA/LhSrmIXcJEOfxVhreYYbpo3q2pvZjg4I1oyuQbtUEI09NNnfDG0zt
         PX+9Xbfihn2OZGLHBbhpdGQpXclywkQ+dCfL5BlSJT7qTClD5I1L8BSlfTUyguhCtCy9
         qBrQnysCwQ54+AeiCRKcg7kWZjorIqWd+YfTAJEO/QKuhTrbGfi34+p4eFzv6Tfm4dKL
         lOqKIXFQvTLOP30/uC92PA14rDRBdIATHG2Eve3BjY8MF4Kq8cPRiclzDNtLfVjchLwJ
         b48Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=jqHZgeFh;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bk9-20020a0560001d8900b0022a69378414si350947wrb.0.2022.09.19.03.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:34 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq5-004b7f-AP; Mon, 19 Sep 2022 10:17:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 08BAA302EF3;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 251012BA7B0F1; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.543128460@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:57 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 catalin.marinas@arm.com,
 will@kernel.org,
 guoren@kernel.org,
 bcain@quicinc.com,
 chenhuacai@kernel.org,
 kernel@xen0n.name,
 geert@linux-m68k.org,
 sammy@sammy.net,
 monstr@monstr.eu,
 tsbogend@alpha.franken.de,
 dinguyen@kernel.org,
 jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi,
 shorne@gmail.com,
 James.Bottomley@HansenPartnership.com,
 deller@gmx.de,
 mpe@ellerman.id.au,
 npiggin@gmail.com,
 christophe.leroy@csgroup.eu,
 paul.walmsley@sifive.com,
 palmer@dabbelt.com,
 aou@eecs.berkeley.edu,
 hca@linux.ibm.com,
 gor@linux.ibm.com,
 agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com,
 svens@linux.ibm.com,
 ysato@users.sourceforge.jp,
 dalias@libc.org,
 davem@davemloft.net,
 richard@nod.at,
 anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net,
 tglx@linutronix.de,
 mingo@redhat.com,
 bp@alien8.de,
 dave.hansen@linux.intel.com,
 x86@kernel.org,
 hpa@zytor.com,
 acme@kernel.org,
 mark.rutland@arm.com,
 alexander.shishkin@linux.intel.com,
 jolsa@kernel.org,
 namhyung@kernel.org,
 jgross@suse.com,
 srivatsa@csail.mit.edu,
 amakhalov@vmware.com,
 pv-drivers@vmware.com,
 boris.ostrovsky@oracle.com,
 chris@zankel.net,
 jcmvbkbc@gmail.com,
 rafael@kernel.org,
 lenb@kernel.org,
 pavel@ucw.cz,
 gregkh@linuxfoundation.org,
 mturquette@baylibre.com,
 sboyd@kernel.org,
 daniel.lezcano@linaro.org,
 lpieralisi@kernel.org,
 sudeep.holla@arm.com,
 agross@kernel.org,
 bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org,
 anup@brainfault.org,
 thierry.reding@gmail.com,
 jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com,
 atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>,
 yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk,
 dennis@kernel.org,
 tj@kernel.org,
 cl@linux.com,
 rostedt@goodmis.org,
 pmladek@suse.com,
 senozhatsky@chromium.org,
 john.ogness@linutronix.de,
 juri.lelli@redhat.com,
 vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com,
 bsegall@google.com,
 mgorman@suse.de,
 bristot@redhat.com,
 vschneid@redhat.com,
 fweisbec@gmail.com,
 ryabinin.a.a@gmail.com,
 glider@google.com,
 andreyknvl@gmail.com,
 dvyukov@google.com,
 vincenzo.frascino@arm.com,
 Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org,
 linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org,
 linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org,
 linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org,
 linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev,
 linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org,
 openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org,
 linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org,
 linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org,
 linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org,
 linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org,
 linux-arch@vger.kernel.org,
 kasan-dev@googlegroups.com
Subject: [PATCH v2 18/44] cpuidle,intel_idle: Fix CPUIDLE_FLAG_IRQ_ENABLE *again*
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=jqHZgeFh;
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

  vmlinux.o: warning: objtool: intel_idle_irq+0x10c: call to trace_hardirqs_off() leaves .noinstr.text section

As per commit 32d4fd5751ea ("cpuidle,intel_idle: Fix
CPUIDLE_FLAG_IRQ_ENABLE"):

  "must not have tracing in idle functions"

Clearly people can't read and tinker along until splat dissapears.
This straight up reverts commit d295ad34f236 ("intel_idle: Fix false
positive RCU splats due to incorrect hardirqs state").

It doesn't re-introduce the problem because preceding patches fixed it
properly.

Fixes: d295ad34f236 ("intel_idle: Fix false positive RCU splats due to incorrect hardirqs state")
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/idle/intel_idle.c |    8 +-------
 1 file changed, 1 insertion(+), 7 deletions(-)

--- a/drivers/idle/intel_idle.c
+++ b/drivers/idle/intel_idle.c
@@ -168,13 +168,7 @@ static __cpuidle int intel_idle_irq(stru
 
 	raw_local_irq_enable();
 	ret = __intel_idle(dev, drv, index);
-
-	/*
-	 * The lockdep hardirqs state may be changed to 'on' with timer
-	 * tick interrupt followed by __do_softirq(). Use local_irq_disable()
-	 * to keep the hardirqs state correct.
-	 */
-	local_irq_disable();
+	raw_local_irq_disable();
 
 	return ret;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.543128460%40infradead.org.
