Return-Path: <kasan-dev+bncBDBK55H2UQKRB3GMQGPAMGQEEHHDFPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9509A668001
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id w2-20020ac24422000000b004b567ec0ec1sf7348041lfl.15
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553517; cv=pass;
        d=google.com; s=arc-20160816;
        b=HnETFpwFnEhy7G6lxPwexPOQDx8ELbAi65yPl8wc9jMU7Vhwwo98uBrvTsk7Lq7Tk+
         PLp3gggvLhm/HGHllhDaOpbmx0qIKqT0409I88FGYdlNZQOESloIp1pYMKs2N8VSUy2u
         pReJenhFL02ISQSDncOkqemNmWPM44LZU5Aqh2qU+1v+UBRsN/4Qvn1btthB7V0nMjcK
         tWk0S+G5OprA+khWDjjIgCyb/Kn3q3brH3418goK5Bro92tzUmywgWlowqpo9dgGe7jt
         rbX13XTVi/EJRkBTmoRWyG8lG1sfNx6C0AEo/jZI26IexK8yZ8RPMfA5uwrcZg2dHcAi
         c8uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=DEuaJzPFMe+uslHL90DgL0PuHrgieyuIJG0MA2LSDv4=;
        b=Is9FTU3QMCkdbqkGTlFBcn6MlWC1JA8zcxCbd0q9lXNcxX4KNs8f39IFYjKWSWj157
         rxkdGGrzWECcPAiSuDFruR7g6jbzDk6drljOSvC0fFGe3d/XCjMUHAy8eCv1y/4DeV+c
         zetCrMhFQQyEQw+rysq4CDqaGbsHUmFbRKo+UQxkTVfUytFAjKWEFDH87wVaRS4l/8Pb
         R/1GsJyou1rHl6kHCdXYeXZdmdIW6ntLjQjE3iyPq9Ge3s5ji8lfVZiYJeCkcvUfQvfV
         RbWNuVaTfs1NmJslth/8XeUbnfBGJVLhD2BfcA4dSwq5yRfFPlokwrznwgYFORqtnGTy
         ebqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=g8GqpZrZ;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DEuaJzPFMe+uslHL90DgL0PuHrgieyuIJG0MA2LSDv4=;
        b=Sb/W8eMn2S8IVCkuJLCesvEOyJpPWK28hL99fODsuLJ6oAho8U4+nbiq/qEMzcv2Az
         I5ruarOrLLVDOjEBHla7Pxll609LhAaj6fnU/A5DoJYb4D392RAFicPNRc4+KsAUzNl+
         e/45Z4yu6ySkzmacxrM00pDGexvuB9WmWUZucMY0G5nvDWxzxfrgEltJiiHdKD9/WBeE
         yu9Hgjdn3dz6JxaomU2hknruPmsd2A7ichMtaVIe0yZAVedVac2m+JlTpFKn1tN/YAym
         9lISycsYqNRjJiJn+ocujMT3MZ9WBBeNygneR6fYhKcq+ulhhtVxaMcFSrPRNWPsJ11q
         BH4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DEuaJzPFMe+uslHL90DgL0PuHrgieyuIJG0MA2LSDv4=;
        b=cw20bHqAQHJuHBfMgMm+yc/w2gNVc8+j94NOCtD4RdCq9Juib62h+uf73pyUIyOfon
         sXvUZhAmXs0nEv5rvGQvEerW77rhon2xdfFE+5YaqlfOnjCZHb5LR2V1uckuTjcwqnif
         m8yXSOmF87gBDx3rnXjR0y6PJC4Re1+Hzam9WhRoryIa8ZANfD/glSaMYcIzzs0b6Lso
         BfVVGAy4xJ+EesBY+WCBTAPkUY9Yi0hFIGkvQcAsGIxMn6rtd4dQgdVcc+glBaKh8LvP
         JGbyquteAks9ObEoqEAMKDs+FlbOKvx6nNkoYJd2E1d7oMNQ+WhWcyL9pYoIate8O66h
         8i4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krFcieR44NgWUujkFhh+TlswU2YLApaQet7cK7yLzXG2iZOiswS
	sub2w3HONhSxY10SW7mz6S0=
X-Google-Smtp-Source: AMrXdXvtegx0Y4aQsiusPR/iAT86M1O+fRCUHkmYagdwfyLM9f/U3bV6Jj1kaD8zkWyddX+gt6+7PA==
X-Received: by 2002:a05:6512:308f:b0:4cb:ce4:7bf0 with SMTP id z15-20020a056512308f00b004cb0ce47bf0mr6423887lfd.78.1673553517177;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:314f:b0:4cf:ff9f:bbfd with SMTP id
 s15-20020a056512314f00b004cfff9fbbfdls13155lfi.1.-pod-prod-gmail; Thu, 12 Jan
 2023 11:58:35 -0800 (PST)
X-Received: by 2002:a05:6512:368a:b0:4b5:b90a:829d with SMTP id d10-20020a056512368a00b004b5b90a829dmr19556293lfs.66.1673553515852;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553515; cv=none;
        d=google.com; s=arc-20160816;
        b=xUXQ2VSYbK/48IR1Yr/BjjHT007nSpEboqlYDwWNTx5SQ6JZz73fBjrpUDZV16+j+d
         F5fSCozBUegU9toWyL+rp7G59bBAfMb5u3EwbQyTYXA/jxdQIAYhCVHZO4lJ9jN5v2Jm
         62DrSe5ifeckDZcDFdY5Xk8DqqdcuKFQIU87aF2fH0a44qkMH9SnAlnMk9BA1V3f9MV8
         99XexmzhMGg7/xIFBakD5SC0MT0xB8Sn3AeJhiPN8DAPKGFF0QW+15dfz+TgxKdxXcjy
         SU0hYZ4yNmcRJzfATIQ7E5+62UmjuXcB0TWfxdboGfJUi2AfHV4mhX6rwlYz8KeA5dUv
         h8HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=jJDEZOhAk9N+ZSaOA6QuB1P1t6S4a5Fqf3eoW7G5up4=;
        b=Z8LnKZqTxZBknqeDWDvwXwZQw4EkuMeFYoVrZraEJhWFg3jaWbI7ALqErPTQ/r7jub
         36veOctm3VFH8vdlWaUVT3DRZKtFR3EsPlnI7EE96dSBpMyr38HRfYZJuR+cKtzvs3wx
         lgZkyZeoIOdS/M6v8136sVDKXZCBH3hNYypzVGfHS9T3ZvP6ZtPU8nOkSJk+Cuhp7Bue
         gwaO+20/3zW6FvK04/QwyMzIqKWMTTkfv5KAHRFyyrWqm3+Hyhh8dIYeqB8llSB6mG/U
         O1nST3gg0Yg6bkW4tdTivGBgcq8M8LPMlUVEgc0c61LGI6DqMLU//suZYAGthgjBkJxn
         xVcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=g8GqpZrZ;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id v9-20020a05651203a900b004cfb4a3fc7esi13619lfp.8.2023.01.12.11.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hF-0045oe-0t;
	Thu, 12 Jan 2023 19:57:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5191730341F;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id E64E52CCF1F79; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.434302128@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:32 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 nsekhar@ti.com,
 brgl@bgdev.pl,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 krzysztof.kozlowski@linaro.org,
 alim.akhtar@samsung.com,
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
 andersson@kernel.org,
 konrad.dybcio@linaro.org,
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
 mhiramat@kernel.org,
 frederic@kernel.org,
 paulmck@kernel.org,
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
 linux-samsung-soc@vger.kernel.org,
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
 linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 18/51] cpuidle,intel_idle: Fix CPUIDLE_FLAG_IRQ_ENABLE *again*
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=g8GqpZrZ;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.434302128%40infradead.org.
