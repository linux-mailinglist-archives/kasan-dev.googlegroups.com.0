Return-Path: <kasan-dev+bncBDBK55H2UQKRB4GMQGPAMGQERVECTBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D98A4668011
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:40 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id z8-20020ac25de8000000b004c66d7fb5basf7475780lfq.21
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553520; cv=pass;
        d=google.com; s=arc-20160816;
        b=pTmou/usfr1iBSWI3L5n35oQnfywxoEPTvNBdEJ6MQEAJ1Gj7fQjfVJe2y7hI3OgZO
         pGWeGXpwPycj5CL988kBSVrWpCKoywBqw7uSUjqsfpysowrdNqar5NZhAon5KExBtf2k
         1LWLI4Dlv8y9XVLUXWsABzEYmtR7bzl516K0Vu5ehhZaih3xdXh7FdTm/q0HkWJpZLRq
         YMrzw3OWHUXlp2JwxuH6C+RqXKV7Zgd4qCVJfMQcfymTliyTr2+ZRQQGlsaQyG03heb8
         jq1leXZ0X8kgOzYj0+cjh1G0MiybhZxioSpPDL/e1P85dxPxJdr+60xBUkGCTN8R/ZJk
         d8dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=eWgNmzbViKxTCjzoy18408BV0MIAR8Z78cN/78IHNL8=;
        b=BHUOXJ9Wd1ZMN9j+mBI4C/zb1deSqbs2yXXIhvnYTk0IpPar5mLMFtUVj+HmZuBSs1
         oFiHvOFrOeEbcLCGGPvyh/itl7/30hR+MxKVpMQRsFzhnry8AqO3NCOUYjH7cctkCzLL
         heQUlQfPpBJDlXdAp8Wsk3lCaJWvFEYKMBqGh0lx8y1WGUNIIGdTOzbJ6JD38Zp61ORG
         yQOphS45iouo97djfgOTjrYxLZytaDlrZ8uUfH2zyFlLe5Ebph3K3LtUDrvIr7iZt2/f
         tHyI5CwcYB1Nt18e7CX9JbapNKZoiVKfyPicXS9g6L1B6TwzSV6oWpenbbE72nH1TgXA
         RbGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=dnEhyaW7;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eWgNmzbViKxTCjzoy18408BV0MIAR8Z78cN/78IHNL8=;
        b=CzQjJMUF1xvz3YCBJU4tmz6izirpblHouy9SJc+zpUXoQAqx7eq3/8utpp1CFyB4IP
         m6V4cpNeIl7IMTBvDf4Zj6fFvmUBpI4bDYb2ORet6gQoN/MRRsYUBS+rcrwzxUiSkVQB
         jXQoeq2hum0IqOS/MnnEkdVuVaBnGfGKcGGm8n7rHfApl5lUufDKMGY5jqMJas8sLsVr
         lT64D/vxmM23H5CHNOB6F73UYth2P3VDYDNuwBJo2HwiH5449JKAUQTrNtnVOVMdmgeD
         Gl1ffeWYI881lynvznC6lddh4XVjQXe/LdFqRHgYrSo58nIwrlvpMoFu65KVw/jmYey0
         MVQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eWgNmzbViKxTCjzoy18408BV0MIAR8Z78cN/78IHNL8=;
        b=bQYCmsRy9tKnMThu8Ql5NY8f3WlNsrp/y82URUcqs4nGv0WP3fuCXP9sNS2ywgj7iw
         EIz0iovKi7JLpmpL+ue+r7oNUub+tc1JhHzCZXIzj7xYZT9AgkXI52A7mi7gGG2bRGOw
         qxIojtAWFejsyrEOOs5ooEy1PCPpE9Gm+JACnX7T+QQIJAOoK+BIPbn8QlBegGQOs3hw
         UnCxzxeuy7CuQUtJ0X02EuNUDUBivAS/JvxZSLkewfOa5hjN/1mEMy+U0KjshN1n6XS+
         JGP1/FxcJmRK72AZnqZop2gLIhXc4nBxmKNndsG47oZsFmu3iS9W2cSfLV+lyH2ljlLo
         Pmjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp9mFq0HEdMvd40lUyU/mqdd72oZVKbnM9XrcNH3yTnOpznd4C3
	rejPauatqL3AvBocfz/UQFs=
X-Google-Smtp-Source: AMrXdXtz9vGjW6gG88MwBsL4/wVf8RUXCUdf3xGhsAoWsCJVXkDy2yDkHpEGJDk5NxKXoIyN45xOkw==
X-Received: by 2002:ac2:54bb:0:b0:4cc:57dd:ad47 with SMTP id w27-20020ac254bb000000b004cc57ddad47mr1815216lfk.366.1673553520201;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2024:b0:4a2:3951:eac8 with SMTP id
 s4-20020a056512202400b004a23951eac8ls1935502lfs.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:39 -0800 (PST)
X-Received: by 2002:a19:6b15:0:b0:4cc:7adb:1c20 with SMTP id d21-20020a196b15000000b004cc7adb1c20mr5245395lfa.48.1673553519002;
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553518; cv=none;
        d=google.com; s=arc-20160816;
        b=rY8ln5nL//jc7HxM1OSJpZteAbcqiWdpuMpXMIeW76jdBbrH840jKt+SgiOmHrXMau
         1Iq95eKXZVAr948jNsDKg+oBOP6M/hPutZMZDZaDNWxUrEeqYuJZWb6UOX9/fhsMbWdh
         yvczEoUj61fuXlPojivr9si/L9l8ckG6VrHLnTvLf2WBCn9IsSEu7wk1Hu9qksU7A3Fo
         ClySg7mdfkG+F86aR1JuZFJk+CEMkffBPf/jmAjDRnUVTGnC2uVR0Ec/+9c/eslCszKC
         A6XThpKEHJgFMBa7uhRoXXCHGM+X1g873deC30hDBFCs/dXWtF/Bn2fFMpZkvrd6C9PT
         M/vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Z3KKcWa6kIo8XxnBPrwezUQgJ6x9WmWZQX/flafg2tU=;
        b=Yt4iFBVyofAhpnSM6yefuKtsW0sHIYTQgjH/DdH151JGdQCARRh4qkaqXJmT9mQgnb
         E9ka7fXpb+aGIZg76y1Ev2BVuMhrfMkjFzpbgAleQHsqvHaX7cl9ahGdNbtXGnSOkPFy
         WyW2sCtZg8hu4KdQtyHHzhDVoc2UXi5YDQcQAcfq8fw5PWWx/0yN3ZnNqSSOe+jjP7VO
         pOIH3vOWvIGnG2Xf+1RS/ihP8v0qrFLAmgjN3MYHj+ZtUCF8akoXFqsO8tffnaetEsr3
         F5/9JwvO2xvrhQHLALFd8EtosaKipgwZOqAUMoi5YgA3LZ8WG55IxfPmi8WL1zz4s9fR
         zvkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=dnEhyaW7;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id s4-20020a056512202400b004abdb5d1128si687383lfs.2.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hC-0045o6-1K;
	Thu, 12 Jan 2023 19:57:07 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id F28963033DC;
	Thu, 12 Jan 2023 20:57:12 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id A39622CCF1F58; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.699546331@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:20 +0100
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
Subject: [PATCH v3 06/51] cpuidle,tegra: Push RCU-idle into driver
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=dnEhyaW7;
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

Doing RCU-idle outside the driver, only to then temporarily enable it
again, at least twice, before going idle is daft.

Notably once implicitly through the cpu_pm_*() calls and once
explicitly doing RCU_NONIDLE().

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/cpuidle/cpuidle-tegra.c |   21 ++++++++++++++++-----
 1 file changed, 16 insertions(+), 5 deletions(-)

--- a/drivers/cpuidle/cpuidle-tegra.c
+++ b/drivers/cpuidle/cpuidle-tegra.c
@@ -180,9 +180,11 @@ static int tegra_cpuidle_state_enter(str
 	}
 
 	local_fiq_disable();
-	RCU_NONIDLE(tegra_pm_set_cpu_in_lp2());
+	tegra_pm_set_cpu_in_lp2();
 	cpu_pm_enter();
 
+	ct_idle_enter();
+
 	switch (index) {
 	case TEGRA_C7:
 		err = tegra_cpuidle_c7_enter();
@@ -197,8 +199,10 @@ static int tegra_cpuidle_state_enter(str
 		break;
 	}
 
+	ct_idle_exit();
+
 	cpu_pm_exit();
-	RCU_NONIDLE(tegra_pm_clear_cpu_in_lp2());
+	tegra_pm_clear_cpu_in_lp2();
 	local_fiq_enable();
 
 	return err ?: index;
@@ -226,6 +230,7 @@ static int tegra_cpuidle_enter(struct cp
 			       struct cpuidle_driver *drv,
 			       int index)
 {
+	bool do_rcu = drv->states[index].flags & CPUIDLE_FLAG_RCU_IDLE;
 	unsigned int cpu = cpu_logical_map(dev->cpu);
 	int ret;
 
@@ -233,9 +238,13 @@ static int tegra_cpuidle_enter(struct cp
 	if (dev->states_usage[index].disable)
 		return -1;
 
-	if (index == TEGRA_C1)
+	if (index == TEGRA_C1) {
+		if (do_rcu)
+			ct_idle_enter();
 		ret = arm_cpuidle_simple_enter(dev, drv, index);
-	else
+		if (do_rcu)
+			ct_idle_exit();
+	} else
 		ret = tegra_cpuidle_state_enter(dev, index, cpu);
 
 	if (ret < 0) {
@@ -285,7 +294,8 @@ static struct cpuidle_driver tegra_idle_
 			.exit_latency		= 2000,
 			.target_residency	= 2200,
 			.power_usage		= 100,
-			.flags			= CPUIDLE_FLAG_TIMER_STOP,
+			.flags			= CPUIDLE_FLAG_TIMER_STOP |
+						  CPUIDLE_FLAG_RCU_IDLE,
 			.name			= "C7",
 			.desc			= "CPU core powered off",
 		},
@@ -295,6 +305,7 @@ static struct cpuidle_driver tegra_idle_
 			.target_residency	= 10000,
 			.power_usage		= 0,
 			.flags			= CPUIDLE_FLAG_TIMER_STOP |
+						  CPUIDLE_FLAG_RCU_IDLE   |
 						  CPUIDLE_FLAG_COUPLED,
 			.name			= "CC6",
 			.desc			= "CPU cluster powered off",


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.699546331%40infradead.org.
