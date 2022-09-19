Return-Path: <kasan-dev+bncBDBK55H2UQKRBP4DUGMQMGQEJSWXQGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 25F585BC674
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:36 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id w18-20020ac25d52000000b0048af13b6ef6sf9634291lfd.7
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582655; cv=pass;
        d=google.com; s=arc-20160816;
        b=A+60QPnMV2X6v0tKuNFoomyyNizRhYbBuE61yXpRf8M+/gy/A/4k81BKW28u/fqJmM
         45OK4WAHAAi4SQrKsnwJ6QeAQjrHgnPQ72W2/NZYmw/UMv4ZYtAnPTSrkxBT0TRu3/iF
         88r4In9Ah+30Xfhw5C/rCEfu+pzMezIfGFSLksaFtw5mDJr2/dcnJYNFW8q2F1w2jf3A
         S05j/Gr5jfopmStoF7UY3hoLyXs4SLLO++SCTZzk8q6b2I3htbp3fqHQMDDWIK1MuHp5
         AuOWFwxecB6wAhABTji30oRIg+LVSsOx9Ovl96gRi27l7LJcRwFTjkaEgNc5YeIxvD/J
         gDoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=nZOMS/lbhYhtOjZKcwWVRi6x9o6FcgUOX8unY9d3aag=;
        b=eMsCiaJYKeAwA/1RhMAfuBjmgaiI5GSs73oNKPyd4t2c+jFM97KTWI7H2z8ilaUJoP
         cpKVNqLCBfyXVpWpwqCw36Ovxaz0bsLxvddycEJC1ab6F01zALzh6hKHsdDOmi+Hl9Q2
         eiciS1CV9F9rQ4j2BU/AdRjAXaB7XXOTY0+b57LXGXIEhmamxLw6qrAv3R3Cf9XI+wYS
         5i0BKm8RHe75Tt1xXfYS/ss2IlIsIbGv/M/8M8jT175jrlipkZO62U2OjxXecabSO333
         NFMQUP2nQq4SzwISWt2vkUQLm8RX+vC3w+LDhPbXAwmYj0LqVUkeqikj6yEwZEiyVQtV
         F8Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=wAsW36ir;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=nZOMS/lbhYhtOjZKcwWVRi6x9o6FcgUOX8unY9d3aag=;
        b=nVh/uOfgIIr+QsMCA+42GcHPhtm97zs6SdKh+MSCLlIoqYqfOKgfnQZwEmFq29Q+qG
         1lAaR6T/i7bOwpTPGp/sV0ffY5Kbo08HHNu2kfPTJhWM0I6S/I2X9+UbcFSTsaeLLXg2
         k93unMa7+41mWcRnP8QnT63nOv5WvD5VUqJYHrfiZIgS0swM79OH/iKuytxID3epCXPK
         Ge5wHtPArydhCQ2g9Vn+tkuhUxofX8hCIihBveVs1OW3ZUqTHppDM4UKdVTP6nFcWXHR
         JyH7dcBluyWO7J5AT0mDOSaeqQepJWUlxrfZY8yVbXmH7ySWVfnNSjKEUWlqIfpw9eIj
         8U+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=nZOMS/lbhYhtOjZKcwWVRi6x9o6FcgUOX8unY9d3aag=;
        b=NGBwjes+IvyO5OMxvqLf6bZ1KpEII5IRqM3s4P7iApwIrMjyIZ0ohjRXX8XOeoSTX9
         kvgDW6ztlVI6yHvhPJ2j8t4K52Zq3AqCjzH6WAGAdwbpqLdk37nYJGSbmsgPmaLAeC1l
         etXYRQa/3G9hCwrXoHL/CvyHjtNMTYSDtJienWV1GGB4T2XU6dxwFQ1ELh2Z9WErSSl1
         R4a0zj3jBdPyvydONsipF77SQRAWLbs9s9XOwSAINtCtfNMs18wG0Yb4N6owiGGC2Yze
         21168G/NifGzet/hv458PjAQIUWWdxRM5c06U7mPaZDSPblooeJx6b78JKa0/Go9nMTA
         +3CQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf174uWjZ/i8UzEpy7EWUPyWMYok873skKDrXJInisemUif2Pw9B
	hbWCy9EaPYCBzfB2fGehjbU=
X-Google-Smtp-Source: AMsMyM5SHyeFy8LVQdAVIDVY1u6mpVQNigt2hvaolVYE+N7oM7XmR3xv3RBng7m7jCJ3K5k4J32Lyg==
X-Received: by 2002:a2e:bd0e:0:b0:268:c03b:cf56 with SMTP id n14-20020a2ebd0e000000b00268c03bcf56mr5242002ljq.393.1663582655532;
        Mon, 19 Sep 2022 03:17:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ac5:0:b0:26c:50e7:2c36 with SMTP id p5-20020a2e9ac5000000b0026c50e72c36ls205522ljj.2.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:34 -0700 (PDT)
X-Received: by 2002:a05:651c:4c9:b0:26b:ffa5:b37a with SMTP id e9-20020a05651c04c900b0026bffa5b37amr5241547lji.319.1663582654096;
        Mon, 19 Sep 2022 03:17:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582654; cv=none;
        d=google.com; s=arc-20160816;
        b=D0VQERcT94kv+z+83eWmM6qNjh8OuXxO7byMyi6z3Juxwi0LMgkB8A6Gm3tqOWYcSI
         48Q1GBZKvS57cIxcN54BIvL4DX1i3XTTi7i/seo6IfpspVD/Nk8Bo0guTpg4Q1sxezxw
         AXU6DKVswqiv2KQKgQ5fqEOZFqxj563JcZUm7IKF1AW0tv8RCw5qCOpqQ4BbOoxMmWAg
         3WPOHdmDKpybQu93g4y9EdQ9lCVJNMNkWxmOE8E424QVG1dB+QYHMgsXGSMylS7tz21K
         oaqbojzuhjUeTH8HIFjBGjAYu7p9LK/wv9AOJg12Q6cD7x8BfjYDSRws1IdV9eOoyQZF
         7a1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=KSLnjMu353Hxa4O11Me8JnVia/sjgKM0LDIwoSdP0MI=;
        b=yJS7Q2Eyplr8bifY9Xy6amn+OTHKVxgyIpBSv/QurQtH8CC4Tmjv9YyP64dP9J0RPc
         OkCXidT9a81agZCr24jgma1Pl+RnTa8kN8Rjage+IzhFpPWu3SKaM00qBStF2dcrMj8L
         Mp8FzXwMAkvnXaPyNdNs0Q9VoFjHgaAa4X77oXB8xcrxNOCN4Tx2SwyTOC3VhPApMbOD
         I1rZZWmXnhSl+2EAzZiqXhBoZGV9awcn+ZOHQVWdXJw2GT8yFdkhQBnff8gtng3gobld
         YjaLm0GTbmKham1X8yR+SSxG1B+WI/DNs3Ctw5iwYp1zLN6sNhZWVWEqqiaLL4qF8MIz
         0wzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=wAsW36ir;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v9-20020ac258e9000000b0049495f5689asi671981lfo.6.2022.09.19.03.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:34 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq5-004b7z-Sr; Mon, 19 Sep 2022 10:17:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 194A2302F0A;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 2E67C2BAB86FF; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.676713943@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:59 +0200
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
Subject: [PATCH v2 20/44] cpuidle,intel_idle: Fix CPUIDLE_FLAG_IBRS
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=wAsW36ir;
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

vmlinux.o: warning: objtool: intel_idle_ibrs+0x17: call to spec_ctrl_current() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_ibrs+0x27: call to wrmsrl.constprop.0() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/kernel/cpu/bugs.c |    2 +-
 drivers/idle/intel_idle.c  |    4 ++--
 2 files changed, 3 insertions(+), 3 deletions(-)

--- a/arch/x86/kernel/cpu/bugs.c
+++ b/arch/x86/kernel/cpu/bugs.c
@@ -79,7 +79,7 @@ void write_spec_ctrl_current(u64 val, bo
 		wrmsrl(MSR_IA32_SPEC_CTRL, val);
 }
 
-u64 spec_ctrl_current(void)
+noinstr u64 spec_ctrl_current(void)
 {
 	return this_cpu_read(x86_spec_ctrl_current);
 }
--- a/drivers/idle/intel_idle.c
+++ b/drivers/idle/intel_idle.c
@@ -181,12 +181,12 @@ static __cpuidle int intel_idle_ibrs(str
 	int ret;
 
 	if (smt_active)
-		wrmsrl(MSR_IA32_SPEC_CTRL, 0);
+		native_wrmsrl(MSR_IA32_SPEC_CTRL, 0);
 
 	ret = __intel_idle(dev, drv, index);
 
 	if (smt_active)
-		wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
+		native_wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
 
 	return ret;
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.676713943%40infradead.org.
