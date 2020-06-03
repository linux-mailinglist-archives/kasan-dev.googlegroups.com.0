Return-Path: <kasan-dev+bncBCV5TUXXRUIBBLEZ333AKGQEWGEJL4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id A504C1ECEAF
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:37 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id v23sf1232072ioj.14
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184556; cv=pass;
        d=google.com; s=arc-20160816;
        b=v3/tchZqhA9kOtfcZJCxdlGoVvDMjWGHRR0etl1byWPI9s8uez6fp0MdH/Lua7jdWK
         eTeLlbzZT3z3JtPmB17iprzSa6+JlF2+mYdDZllUyqoOa5cwzrp6OWMlIOLPlc+Z5quI
         PVOqQyB4skNwyYspSupyLnrlLYMdbAiJ0FBDyIuTgf1oa55uv4TFJpZn7coJoXWU8MyT
         uUaTOp4BQIKi0Qu9eOVCa3iNvFDwDjednS2qySEK4I26IM4Mky9ZrU0x5v5ZUH/6uXzH
         XDiB4e9KYcm1saouytjbsGFbfY89ofMlR0YWl4dXP4EmM2F2AauO+cg8cgM6lEEh71Bc
         VAtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=HefwWM19fuKDJJcF+qlJ5gWbRdD8d2SUHbAgZy0kCdA=;
        b=ejL96UWYnf4lOn2m73DQdJ0iG7FmnpwhtGtBbOC0BHuNq7fHYBcd0C4iwbgRX/woXU
         3XF3sEQb3Om23p0taLLQ8WZW6UR73wirfagoUMCKUYrGN/X9VKsd/8KZTpcnIgCDcX3X
         oQYxCBifNJOaA7WX4NO+yH3VBmptOedCJhhZ1/2qh2AdSoLCveb0BBbz32/7sDML0hBU
         831TOnZo8oujUsKw5qZ1J3R025IYe9w1I8IduL3MY+JEp+2TnWDQsEnQk0D9XUgq4Ax/
         b8r45Kd+aCxmh1ywAhgGKtO0ft5C7EiRSbtHMrYgGVEKLRijnSESwmOXWwabROUAkoK1
         QRtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=tl+Go6jN;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HefwWM19fuKDJJcF+qlJ5gWbRdD8d2SUHbAgZy0kCdA=;
        b=JagIFL3T/TUIa702tSZLaGCLGR6oCc/+DNSJ9wgW9BtZSb0MuRwbLLbtk1L98LbPgG
         yA1ns+CcH2A1+MMwQ9o93pCdxWWpq73KcAgXUDuFERiQX9tHNyINBrbTB4JRpm+V5QMS
         ZIHs3i0sML9BN2l0Ot0Op2kSnFemkl9co+bMMp9QBwmXMEDnklFn6n1S78b0cufy2ALU
         5mqHTmreffQc9rC+H5UNQ0qMqsPmXEmGfOUBIQCKiP3UIYKaBJ7qlslcyWP3ujETrw15
         3kCaJIsojcb9OXRMiYeMDNvWh9se5505B868ioYd1ODdY05kJzTx58qcZmOkfU6QokEY
         LzDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HefwWM19fuKDJJcF+qlJ5gWbRdD8d2SUHbAgZy0kCdA=;
        b=ECZ7ikx9PZCin1eYI+0jwCspivEYvD9OdO+Rjgczg+dEE9bM5WozAqz/zd0sPMl+vH
         TFpNwkONt1BD+q9c2193RzDH6lnJWYq9Sd4gQ8LDFsbuOhc5zUmXa9eHldHmdLq3tRpX
         Ii8/LVfFMyL1TiykUoMfF4v2ABu4g7eoog9deLNhwAQ8mA5SnKiwHyYFYr1gNSZ2M/Le
         +159tn9+BGpAe/ApgIfAXDgZV/bHlxVx5mAwGOpqfycztKrctxuvIwRvO3JbkSkyjdWa
         yrfdk7C3d2wSNsM99FctmzXop1kjjlPhBiUimhyMtL6LASf3OJOflbCu9BE4dsXTFQ4p
         /MKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xvvgouECatzFV6RZKxxHVDyswkyI2p7YI5D7cDwOmZaFpjStR
	lPQsbR1hW5azezm3RG3Aaqo=
X-Google-Smtp-Source: ABdhPJwbDSNcCEjdJxuvSBtBzWkLU0IBuuljGW85h1IFrGk5wxIXtJ9yEF8xog5e4/vcRpVXkW2OOw==
X-Received: by 2002:a6b:e215:: with SMTP id z21mr3160549ioc.115.1591184556384;
        Wed, 03 Jun 2020 04:42:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7207:: with SMTP id n7ls282903ioc.3.gmail; Wed, 03 Jun
 2020 04:42:36 -0700 (PDT)
X-Received: by 2002:a5d:9dd2:: with SMTP id 18mr3156276ioo.196.1591184556024;
        Wed, 03 Jun 2020 04:42:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184556; cv=none;
        d=google.com; s=arc-20160816;
        b=FBzKJCRQhpCjfvD3eU3NrYu4vKyd8ZR19oo2GGwyGfAHr0OLgg/lJ9JY+3P4U9dUwn
         HiCXa11CpAx+sgV7+mvylpZ9ORwz+vWVgDR5h2OmFsGrszngbJXVHIrqk9PG2B5IZGgj
         oG1n1qveu3lfOe/tyRY7dpmAosgIcKueMzSuh6MJ0ZU3YUOooU2VhPQbYzB6Dfo+ceup
         2BREgKyXHY3nVXPLtz9uocXsWHrmKHyLs+/s4azi1QNPJ42iACgaVjwrJVS+EVZfKEg7
         Tp5HOAYg0+ksWZeC7tPQnRZpdk9hyeVsx3BPvtV1jqSTGBv2MC0wi95MzSwtIPEbVgET
         qLyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=DZFIrEVCB225to0ilfsUv+WkHWiGxuEfVVcHeS1Uxeg=;
        b=GzZYu2PU2SjtHQMtUoiXjNnUE1W1jurD+QB0IO7hHpNB1/3eVT94Uyz2SUTf8moXQE
         SIcbT3CT2cDJOaEaOxTQ0hOaFCM7UyRL0wsLpsGuBjPIWRvxMSu8P6oFqdlcYxzY+Omu
         h/JMj8MQAjsCTIdt474zKWS7hZ4ljmDTZXfKh5EVANvqD0F7WVqdjKAtA2SSX//innks
         a8YXBSjnP8umIZ5HFhzNO9MdzaWZx+tmNSiYoxi0+ZJEjLUzy6uQjEcbLhv94pYzq19Q
         WGT57Q8utaQAJHUqC+x7SGblmWmrnelJ/6RNV3P4tB/f/ne74ptNamU2PHas8LJflbB8
         ms0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=tl+Go6jN;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id 2si80421iox.0.2020.06.03.04.42.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:31 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRms-0005og-UZ; Wed, 03 Jun 2020 11:42:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 10600306FFE;
	Wed,  3 Jun 2020 13:42:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id C2359209DB0DC; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114052.300804240@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:23 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 9/9] x86/entry, cpumask: Provide non-instrumented variant of cpu_is_offline()
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=tl+Go6jN;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

vmlinux.o: warning: objtool: exc_nmi()+0x12: call to cpumask_test_cpu.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: mce_check_crashing_cpu()+0x12: call to cpumask_test_cpu.constprop.0()leaves .noinstr.text section

  cpumask_test_cpu()
    test_bit()
      instrument_atomic_read()
      arch_test_bit()

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/kernel/cpu/mce/core.c |    2 +-
 arch/x86/kernel/nmi.c          |    2 +-
 include/linux/cpumask.h        |   15 ++++++++++++++-
 3 files changed, 16 insertions(+), 3 deletions(-)

--- a/arch/x86/kernel/cpu/mce/core.c
+++ b/arch/x86/kernel/cpu/mce/core.c
@@ -1083,7 +1083,7 @@ static noinstr bool mce_check_crashing_c
 {
 	unsigned int cpu = smp_processor_id();
 
-	if (cpu_is_offline(cpu) ||
+	if (arch_cpu_is_offline(cpu) ||
 	    (crashing_cpu != -1 && crashing_cpu != cpu)) {
 		u64 mcgstatus;
 
--- a/arch/x86/kernel/nmi.c
+++ b/arch/x86/kernel/nmi.c
@@ -478,7 +478,7 @@ static DEFINE_PER_CPU(unsigned long, nmi
 
 DEFINE_IDTENTRY_NMI(exc_nmi)
 {
-	if (IS_ENABLED(CONFIG_SMP) && cpu_is_offline(smp_processor_id()))
+	if (IS_ENABLED(CONFIG_SMP) && arch_cpu_is_offline(smp_processor_id()))
 		return;
 
 	if (this_cpu_read(nmi_state) != NMI_NOT_RUNNING) {
--- a/include/linux/cpumask.h
+++ b/include/linux/cpumask.h
@@ -888,7 +888,20 @@ static inline const struct cpumask *get_
 	return to_cpumask(p);
 }
 
-#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
+#if NR_CPUS > 1
+static __always_inline bool arch_cpu_online(int cpu)
+{
+	return arch_test_bit(cpu, cpumask_bits(cpu_online_mask));
+}
+#else
+static __always_inline bool arch_cpu_online(int cpu)
+{
+	return cpu == 0;
+}
+#endif
+
+#define arch_cpu_is_offline(cpu)	unlikely(!arch_cpu_online(cpu))
+#define cpu_is_offline(cpu)		unlikely(!cpu_online(cpu))
 
 #if NR_CPUS <= BITS_PER_LONG
 #define CPU_BITS_ALL						\


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114052.300804240%40infradead.org.
