Return-Path: <kasan-dev+bncBDBK55H2UQKRBPUDUGMQMGQEJ7SHGYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FDDB5BC672
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:35 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id y1-20020a056402358100b00451b144e23esf16074920edc.18
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582655; cv=pass;
        d=google.com; s=arc-20160816;
        b=0WXS2fAjtpi682GLsUBMeR8Qh0YFZEMA8pnXyNxxbfpXomH90MIOlpThraD4Se5hEo
         fQ4kmmxvBtVp1SL0/hbySPj8P5ZDRBfY+/25Hti6Th1xOG7ChbNU2nPuxKjtf4NtBWTm
         O8FlUTFejNdK2DEBnua6psRPXsD4igrr/cA2zPGqWVPu7HDAqGdNsrVNNfzF10jIB+8S
         VBooZtRCpWFGUI0iuyNENhU6TdkexY3iLEpIimQ1AAmRl5OLX/K/YfwUrDNVX1U+fi0R
         3damVX2SrlRXPFFm9M2rYgy09Xmg2ly5iDoNX/l34Sm+h7IvcNb2vN5Jm5yXIVYOJwyp
         3gjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=wBe/Ln7oKMEeUBCulHrWRHzN8UrNiqiFDVkevs4+Qd8=;
        b=l/9y9tA+0RDuHfcfnwcmDMhdhEM3H9RyU8lIN6FvQPAmqLLeGF1trq3HiT7rj+mwNP
         CnxUR5kcJ1DIEDtrrzLr6vFd5E4Gfk7hsUL3J1KqPDyRj+4DJsi8/5YOeFTV4VhEhQwf
         Cy/Us0EH+tF/RcULDCHFA6myuwRZHWZsTu1L7U7xSXdEpZLHm9TlwwC11gscHDgoEz02
         ZXMgGuIQ5+DyHUsTM61rJLP0Z0MLSvE4+8Ha4bG5Q89KBu/eBtXAV5gNtfl7A3AGCYHM
         RiC7gtmm2R0nwEZf2zkz5IfoXvlwOqYNj/kUIHJ/SB4rzJhzDUgomIyPCM+9pM7r6r/B
         4pww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=IPV8VEqS;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=wBe/Ln7oKMEeUBCulHrWRHzN8UrNiqiFDVkevs4+Qd8=;
        b=cmMC222Q/Xt2v0Sz4SIxQgaJCjeBWyAF0GyiuQgGw/96bVtpemXjlG0dQjxU1jO+Wr
         Xprzy99rT84y1BaJ1dw0DIYvXNQcou02oO2Dm55H9OISjvi7ZX9tPqFLDduFZmP+SoNi
         WHoGhmKaXPzpW9p7QzWSo9OQKgLYQuUQMFL5qKtZjxnj3S/4Tz2oGYjPzE86T5CIuHIw
         w71Kt0mgBZg0fHrRWJHLmYU25kKsor++k+p1R8pf+WwWPmymWNPRyCrkvHinwalwNTFF
         9mB794iRw6ld/tgOcSKxrnVnohAe5HpuJNwacnYKM73ilsWC22OSFt+X/Ck0EgUIp/zr
         F6pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=wBe/Ln7oKMEeUBCulHrWRHzN8UrNiqiFDVkevs4+Qd8=;
        b=VQTc1AHDq+MRkRk2Vnp1lHHEPXd/HU8VuPn1x9yH1xyXANOgXxso9hR6r20MPGIoJW
         lWY2+o3IZkQjOAIRd1rUF7mT0FHBDGusRMxfvUfCo0XvkxDtOZM0gL+5XoykbiIvJwbu
         x/6WfliuBTAfE0KCAJ+4PMDGxNoy4cHroMQLGq9t2tjExTGeZfqCbuWoX/xWmFDjyaIM
         PhrikCLTDFnwYoX7Z2UhdLIavyCdJE4wGm2XYQX5uM5Aqlw6koTPzKCXt7uYIehx+Y/E
         rgoEiqjAHVdffrLhjJTBRrJgKp7eq3aP9VjooONvnicf+7d7OwTvK+pnwqbJ93G0xs6z
         QfUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3a38KIGl8pJ9PX6GqadER0QPERNhQ8oy74X21Vaa8ou9witjRH
	UoKlvFqRQDVvonff+3Lg9q0=
X-Google-Smtp-Source: AMsMyM6UR5I/J7QOBC655yb2CoTPQf82lQ8cNLWMJj4AOyC2AkN7HMjcL5ikpgJ3ZcOPMH/VtLtLSg==
X-Received: by 2002:aa7:d785:0:b0:452:dfa2:bb17 with SMTP id s5-20020aa7d785000000b00452dfa2bb17mr14701948edq.407.1663582654980;
        Mon, 19 Sep 2022 03:17:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34cc:b0:44e:93b9:21c8 with SMTP id
 w12-20020a05640234cc00b0044e93b921c8ls4361523edc.1.-pod-prod-gmail; Mon, 19
 Sep 2022 03:17:33 -0700 (PDT)
X-Received: by 2002:a05:6402:190f:b0:452:d6ba:a150 with SMTP id e15-20020a056402190f00b00452d6baa150mr14893037edz.126.1663582653891;
        Mon, 19 Sep 2022 03:17:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582653; cv=none;
        d=google.com; s=arc-20160816;
        b=RWNb3sdys/Cth45rV6gt/dsYTyEz06JQteWoQx/hSDCGcefxS7/BXWFtNLZQkkbJnm
         7e0t+vnImPkXfiAWTCioyv0Z5ZY27x95Z5kzpn5QIoGmZuB27d6xWo5AETGaHPB3glE6
         VOiud/jOc8DX0jxZSPE6U4VV3O2ERmXqKevLFDUpPMaqb4yaUyLXIYn6XxFjzz01t1rv
         JcwKFZb3wbF43EzyhV8sNyzqvGBt8v17rVAuyoeLEGGNc0MtUl8X2+4NRDBz5sAngU0l
         MvhCbV3wHFBZRdoZ/tI+9ObzHWiIefNAvojtB16q+FJUKkZ6ThICRprPRhxgELFGsdLq
         WzWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=egsvZxpcWuzc2m7IwsV6/F25N5YaTkcmJRSjKuAk/t4=;
        b=oHZ1ELqC3ujiAi6Kf2u5lwqw0BXoWh/37I+smaSQFi/ro28LPGtkLT/m26EcWpEbk+
         U8l8+kPK4OIqZIwB6i81/Y4hXAnPgW8BPakAjRpJHIfh5UvGHmUCYO4p62Asq3sZjhUP
         u6jextL8ZhdfItTxcrJ1b9cMhS1v5qDZJ/FQllRFDHDL2GDJYjkdzXEDeC7pKJsMLa4W
         cbdLKvLJqLxeqKnh7t/MdW2PeJoKMcAYWnFeAC6oNR1ruLxKVWDzVfP4vM1jsoZ3TDmR
         FtCew16mqJslsIZKIzdgU30BFuSwt02BWfZiD/FtSIFKsrL4LNJLRI6vGtcZcNiqfuZY
         wrmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=IPV8VEqS;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id t8-20020aa7d708000000b00454412dc7c5si22256edq.1.2022.09.19.03.17.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:33 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq5-004b7Z-6a; Mon, 19 Sep 2022 10:17:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EA6E1302EDF;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 1966F2BA4ABC6; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.407822201@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:55 +0200
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
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: [PATCH v2 16/44] cpuidle: Annotate poll_idle()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=IPV8VEqS;
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

The __cpuidle functions will become a noinstr class, as such they need
explicit annotations.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
---
 drivers/cpuidle/poll_state.c |    6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

--- a/drivers/cpuidle/poll_state.c
+++ b/drivers/cpuidle/poll_state.c
@@ -13,7 +13,10 @@
 static int __cpuidle poll_idle(struct cpuidle_device *dev,
 			       struct cpuidle_driver *drv, int index)
 {
-	u64 time_start = local_clock();
+	u64 time_start;
+
+	instrumentation_begin();
+	time_start = local_clock();
 
 	dev->poll_time_limit = false;
 
@@ -39,6 +42,7 @@ static int __cpuidle poll_idle(struct cp
 	raw_local_irq_disable();
 
 	current_clr_polling();
+	instrumentation_end();
 
 	return index;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.407822201%40infradead.org.
