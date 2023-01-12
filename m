Return-Path: <kasan-dev+bncBDBK55H2UQKRB3WMQGPAMGQE6PN6WFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 49E28668008
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:39 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id bu42-20020a05651216aa00b004cb3df9b246sf7305772lfb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553519; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z0BhUtiACeHOJigt1HCCn3Im5p2JGJxe1grNzhOktky/y2E6WiChKePVXOhADZWx6f
         73nNPVWX2J/gdsFhzN4FiT/rZPjbf3uZPcUlxzEOE+HLndVeK+sBYGC52mFho7w+8C8H
         BnMP4dLU6mOKCPNt4UdBQ+0Zar5utwRr/4US2qRraDxFyo7KpP9b1fJ1Y62FJMsuUSfL
         3E8qJkgXh/eovCzsE2fd2hieUAflB4zuV9h2pHwx3VBw8Z3Mn8zQQuVj7YHqxBL6slvU
         DhWa7ZQEyd4HY2OtbsHNf1RbxFwiKRweSf1YcuM/e93/5+WpgF+7jv/xEj5Edp0csGJu
         zs3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=S5QXAB2e1FARuIPbKLmRHl2mXCA0kqG/TDdRmkyeAGg=;
        b=yTM8x6pKfrZmHpmEZgLlu+a2W/pEmaAIsTQVtk67/DlHfFO6lGZTn9JPnjRmMQRuu2
         WFYzJljNO4VD4r8MsmDkdy2jLYNg23C+j5Bpk0WHckY8Z+FPjCE0NzkJ8/K3msI0inYF
         0VBgB3AcCYrTMANmDrTMX2z10hsrqfGWJ2J07UDvS3sqdBir2jvGsgL3CCGBlF9rIOib
         z/YMESLu5TCyokh2jLzvbH3atQkzWW8Mq0nbOQa8+o/JAZ9ORNJLILbUMDSM4uxp5jhw
         9DAHCKD2WOMCLei6uOV4borzHNoPBmKnaL8f1Uh5IOvftJVbH+kAOH6S4kggMmPg5YcQ
         s+Hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=lU+pE8XR;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S5QXAB2e1FARuIPbKLmRHl2mXCA0kqG/TDdRmkyeAGg=;
        b=mtqIId3qa7iJagGWANCokaMoKxBVoii8iYoOXbMdM9NXxmhCgj4LO84Fc3MGotqmkD
         +ufJVUUVJQhaBfLOLZEUePsLGVihaBGBNkfPwNgAvM+UjbP7Nh1JvPjq8mssigrWOUOO
         PHwsUTTKMLtRHSpJfkwM+hMMqSpT/bZsyUxy5am0XmWRt09uVFvl0gP+NV6APqGfKuvM
         GeBgqtTo/cp70g7JuNHQVQy+k/62UELEhJY5Vu3BBufaR/FLQO5a9hCqSk+f+THDyDoV
         uP9k96C+/HeESA18DBrxqrHE0gPg0o8XWAsY4tGFI+CeZzXwwPMZR+L2znS+S0GVvQzi
         TUmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S5QXAB2e1FARuIPbKLmRHl2mXCA0kqG/TDdRmkyeAGg=;
        b=z0Eh08eXiwq8wqrciCK6e53Y774c4Ey2SXmeVvhlzskARo5hFsGRiUT2Rz/I5a1YNS
         0wYVj/T83HVDQXyez0CT7L3FdQ1Y2SRGBeWO8SbmXY7+uWA5FTr2mDbJsKvtMML/Qclx
         1dryPmd10EjtdrV7DFFWwPvFokeaYyTH3099WsF0IVUvLFRCPy9mNhfTCx4ZIjn52eTP
         bo9f/KbmopaEoTw9IfLhiBDyemhN0FXphQL6walq6u0HbpyZHddNooiRWaP0tuBm/4Fu
         4VOQ+f7kPMhJvec8kQvLBEoQM0djyohOX9HxjMtRsv3XiPkTUtpgXXTeF+AQrxc+c4VL
         TMmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koR7mR8yr5u6uQvBtHYv71svlkMpee4HVGsLk+0ni2hWmUp+3U+
	JSDk9dvRY2l5hqmdfAuh/k0=
X-Google-Smtp-Source: AMrXdXsCfmONyQZMQAs4Zory9s70CdZAa+sf3F46fEHmDfDOxQjxcpHPUVmr1WeIfZHywaUDK2yZsQ==
X-Received: by 2002:a2e:8ec2:0:b0:283:9a0a:a0f7 with SMTP id e2-20020a2e8ec2000000b002839a0aa0f7mr1473009ljl.81.1673553518983;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2024:b0:4a2:3951:eac8 with SMTP id
 s4-20020a056512202400b004a23951eac8ls1935471lfs.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:37 -0800 (PST)
X-Received: by 2002:a05:6512:15a3:b0:4b1:3970:43da with SMTP id bp35-20020a05651215a300b004b1397043damr34509966lfb.51.1673553517777;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553517; cv=none;
        d=google.com; s=arc-20160816;
        b=jw7zX2n22nMhkBW1yjNFlS4D+Kd1jFmIGvoUFp3QcWDB64cVopqcn676DtE9vrmESZ
         EGC5ZO5SulU2QRmd1vPK61AscYmlYDOHb0N1gvHHSt6TXexW4/1BijTvyn+SyL57usFu
         sbxjgzK6r6/PwzAPcv9r0UsbXJrhgvULmAiRcQMPunHF7nafd+XhJka4nZezzQJwD7i+
         Np82F1fMSPbvj6nwQil8NvFaEhaBZpgUUElfbgtt3NrTPAxZv/xfNMJl0ER8h837CGCu
         DE8Hs7rghOnuPbj5N8pAbOlq7xrWgJy4WzDRa/H2czSaI13K82ixfOG5VeVg7WrOLtp5
         iZTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=DVmthOBTi8Yd+1hoz4bpY0hqbVL72Y+E2XHDdN1zqxc=;
        b=Q6ia8nPLOc/cA60hKfhlV5sCt13RRPg8KOQTwTErm5rT02G52eZjd3quAJNsnaBPat
         YLc9fcfMECD0lNjisNYDwAzCnVE3oa9tIDR3/T+t1rLMv3GyyDzQC9M/qwPqOj086Nda
         7P6PUWTTXrzlLB6bShy9tW1m7VpTQjqMiEZfacFVoojd3n1AbHos9JdwbQ458cuHph3L
         sSXUTz4C5YLu6LKFWpafyTg9Pj4UC4AiBoHrHdFKQSE0U6315Gm2u8ToAADjQdvRBdIB
         duoOv/mOAvElmZ8caNtProu2+5ZiDhuEjNh9lbVdh7xqqrmG/F1mEmga9gwODcgw2hpM
         /0Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=lU+pE8XR;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v9-20020a05651203a900b004cfb4a3fc7esi13626lfp.8.2023.01.12.11.58.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hd-005Ofm-HD; Thu, 12 Jan 2023 19:57:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B806430344C;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 2D82F2CCF62B9; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.294846301@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:46 +0100
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
Subject: [PATCH v3 32/51] cpuidle,acpi: Make noinstr clean
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=lU+pE8XR;
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

vmlinux.o: warning: objtool: io_idle+0xc: call to __inb.isra.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_idle_enter+0xfe: call to num_online_cpus() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_idle_enter+0x115: call to acpi_idle_fallback_to_c1.isra.0() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/x86/include/asm/shared/io.h |    4 ++--
 drivers/acpi/processor_idle.c    |    2 +-
 include/linux/cpumask.h          |    4 ++--
 3 files changed, 5 insertions(+), 5 deletions(-)

--- a/arch/x86/include/asm/shared/io.h
+++ b/arch/x86/include/asm/shared/io.h
@@ -5,13 +5,13 @@
 #include <linux/types.h>
 
 #define BUILDIO(bwl, bw, type)						\
-static inline void __out##bwl(type value, u16 port)			\
+static __always_inline void __out##bwl(type value, u16 port)		\
 {									\
 	asm volatile("out" #bwl " %" #bw "0, %w1"			\
 		     : : "a"(value), "Nd"(port));			\
 }									\
 									\
-static inline type __in##bwl(u16 port)					\
+static __always_inline type __in##bwl(u16 port)				\
 {									\
 	type value;							\
 	asm volatile("in" #bwl " %w1, %" #bw "0"			\
--- a/drivers/acpi/processor_idle.c
+++ b/drivers/acpi/processor_idle.c
@@ -593,7 +593,7 @@ static int acpi_idle_play_dead(struct cp
 	return 0;
 }
 
-static bool acpi_idle_fallback_to_c1(struct acpi_processor *pr)
+static __always_inline bool acpi_idle_fallback_to_c1(struct acpi_processor *pr)
 {
 	return IS_ENABLED(CONFIG_HOTPLUG_CPU) && !pr->flags.has_cst &&
 		!(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED);
--- a/include/linux/cpumask.h
+++ b/include/linux/cpumask.h
@@ -908,9 +908,9 @@ static inline const struct cpumask *get_
  * concurrent CPU hotplug operations unless invoked from a cpuhp_lock held
  * region.
  */
-static inline unsigned int num_online_cpus(void)
+static __always_inline unsigned int num_online_cpus(void)
 {
-	return atomic_read(&__num_online_cpus);
+	return arch_atomic_read(&__num_online_cpus);
 }
 #define num_possible_cpus()	cpumask_weight(cpu_possible_mask)
 #define num_present_cpus()	cpumask_weight(cpu_present_mask)


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.294846301%40infradead.org.
