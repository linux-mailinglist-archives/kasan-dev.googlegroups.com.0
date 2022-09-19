Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B290C5BC6DC
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:09 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id e4-20020a195004000000b004979e6a0c88sf9774354lfb.22
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582689; cv=pass;
        d=google.com; s=arc-20160816;
        b=G1GtEZ8DvJgK/mqfxRyzt+N/CWOve/0qxDS+4Z3DzJ3L9rRJ/0KRcVQoZ5XISTZgX4
         Bz3SRusK564f0vhhelnNpxpBcKNEL0tq3N9aUEELLGdx+ba6IuzXkWaQQecqBQOhNH7a
         hlmX2xGKcJwBUHt0Uuc/9S6/PU+DfMFU+M6WLHm9jVE6R6jXjHlpY07BxNaNDW+V1IUV
         oD13Li0xfQQJivA1SQGSTreU3W3L0Wv1ECzOnYDAdmQEhppvNBtH/KyZKrl+WKuCEznk
         g5ELN/1qe0hxlXPhiQrBY/FuoOOYQrMDgCoWPBqjqfhvlb7gMWZElEhS+IFE4Xpj+Uds
         gQgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=7ClMPWQ+RrUib/RksJbZUWazaeHWYMXCPrIptNKjGJU=;
        b=G034jwBkZSCA+2AB8vAwaAmChxZ78O+lveEwokhWWB4gFaEFfhPLXyKsQAPRldMbe0
         HIOrfyHLT0t+XgCrrsiddMvuZC4zIbzLO1Vbiya+UeunGiICY3FKNRXdmw7xqX+jBnUr
         5oBRQeQyCxGI96WVsKnCH4ZmtvAjsuEMm17fSt5vnx8Kl9ILAxt06ZaLuomZXj9mrGiX
         aMKhUPi/+vXzOzqI24jIXpxs1mnS6p4tOuulrg8WctVp8oXC9ywlT1XfmnQk2uAf8Qf+
         Hs0c1Wwq/CcnDYK+yLdgUNGuqpefZ1aORfUyBrcXzdt6m7jo/+eAO+3JkEx9Pmj2muS8
         3JsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=i2csV9g3;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=7ClMPWQ+RrUib/RksJbZUWazaeHWYMXCPrIptNKjGJU=;
        b=a4rQbOmf+4ND6kPNQ3NjFFEDx8AlROB9JBL9MqPQ+lxUu9RP4Iu3UgR3EwvYvHGoph
         7QXQPKAkOAX9Y87O9h3h+ySvcymoEgEmhDvcdouasz+nfbCrL16OGVQhgosIuw43gkwV
         eUHRcai29sbrF8lO6w/BJ6SLni+WQa+a7pwj2PYVn7kL8fM13dyqv+2S51R/IkYQ1Fxf
         6DyaLMabTn7VEV7r4Rq/moWxtkcWjjeRHAEQ/HiBipasN/bD0bI0Dk5LtqmbbJgz5L9x
         oZelc8ch6LmsoIbxqHs7LgYa0YsEdilZ61CjUOwbyjdo4vn3ioA4/nhDFV+wHu4zVjQe
         JqWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=7ClMPWQ+RrUib/RksJbZUWazaeHWYMXCPrIptNKjGJU=;
        b=2nMYc9JDKRy1ZBxxscjMOvdROpY0CQ5hr/TUS7jp/PeCBpNoOts+x5XLcWHC9AYOVh
         j8f6w6TJMjsOgRcK+9B7qHI8pCE9ld7cOH0zFM0++7KvEAHRWzVFO80/4hl6DTQkpdJE
         lnJCiy7yUWvEuf7MZBJkNDApgeqF/HF3OPJq2FwOlWsoch1cNqVEtRin+uhn3JMxFC/I
         TM0lQ55JM+oDtG4nx5B2VhP2Hm980oyHHqpcfJDUquICGQohiNFpmYOxKt8MkEcVu9vO
         PShPzOt64dig1binuih18orbnDNKiYewh/Z0jtQzvscrIZgLf/4rbRwxsq3JKQSqR7sy
         +MCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1FsaXXEiLIZVqIujEe1QOmSI+esiBdTcc+F8nhkEEn3+e3lCbe
	J5b3vmbk7KqCUaM3Jf1JncE=
X-Google-Smtp-Source: AMsMyM55nIIraI4hTqVgJvV9jCTWuctjoFn3S1DOE5WHbVdEeSENOlbULASasgyTO2ONTaseRgIYZw==
X-Received: by 2002:a05:6512:6c9:b0:49a:51d4:d517 with SMTP id u9-20020a05651206c900b0049a51d4d517mr6109363lff.329.1663582688970;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f7a:0:b0:49a:b814:856d with SMTP id c26-20020ac25f7a000000b0049ab814856dls556136lfc.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:a05:6512:1150:b0:49f:54cb:3554 with SMTP id m16-20020a056512115000b0049f54cb3554mr5507838lfg.38.1663582687738;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=OyRgYJricQtf82TW5lUTRfIgF2mT/7DqdHJKwU/i2wbLcQbvvODpz3xDMYF98O7BWJ
         6w6MaVPUu2Vd/OwaUb6xzXnzjcY2bYN095O2XhvcZQ74l4L/hbRu+1649mbZEGx7UdAk
         9LXOIIVPETpT8i5BiGEdIEQ9ETDNzxe/efaixoT54FSVfgSSZYZj/6EaCYkRre+DZ417
         Rbi/wJCw16eqW9ncdKPYzDy4V2BD074JuoaV0gRaxHjzOkSndP5ihgJLH4RwwFinNcUL
         7AlkChrI3PIGW5fgyNKJXRYUIp5voRPGUI5nAUOj365d7P/j2JJRu5Rr0W53E1eQDlsC
         sB8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=iz2Rk0uC5rGU+Kb0LRDsuPxksHM6C3EYKvZGNmPgVNM=;
        b=NRtclI6M4uMjjlzxtuh4KHR7teodMwNZ3DPszAPGNZ5nHZPj6J53CT4yF5PQI/P5u3
         3DNz4HiHKPi8JxDJp3njZssZlwxQZCWYCUAEPyZ3IEPD3ng4BZCR012P9G0FUz3+pzcB
         NoJJ/55mlqkLMhcsTEcJATOMeEcZ5By11c0ekY1n06h30Uw01WVYWQ7wWi9/wALfBrG3
         QMgTun+iqEYwTEQ/fm45mDLC7k20Eifl0+O/qfmNcv34Jh7pjMIF5qe6NVM+hsxU7EVE
         ZhW/XFeyFa4DrGgzawb3C8JCuBU8SbZjr1ycxaIY8aJHlxckGcxccaOD3c4637H/1DO5
         PCJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=i2csV9g3;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id a8-20020a056512200800b00498f2bdfdcdsi849479lfb.3.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq5-00E2BH-UR; Mon, 19 Sep 2022 10:17:23 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 51231302F4E;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 736AC2BAC75AD; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.497914983@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:11 +0200
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
Subject: [PATCH v2 32/44] cpuidle,acpi: Make noinstr clean
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=i2csV9g3;
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

vmlinux.o: warning: objtool: io_idle+0xc: call to __inb.isra.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_idle_enter+0xfe: call to num_online_cpus() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_idle_enter+0x115: call to acpi_idle_fallback_to_c1.isra.0() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.497914983%40infradead.org.
