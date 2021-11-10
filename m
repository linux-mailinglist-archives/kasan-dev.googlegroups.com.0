Return-Path: <kasan-dev+bncBDAOBFVI5MIBBO6VWCGAMGQEPOB2X5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CDE9244CA87
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 21:25:31 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id r6-20020a1c4406000000b0033119c22fdbsf1627644wma.4
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 12:25:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636575931; cv=pass;
        d=google.com; s=arc-20160816;
        b=Okk8Jx2R0L1y64GiVIBMivRE3LTCoNKDvXVwpYKMr0PxxRXS6tgxHHrWupyjxbT8v2
         bj9tpwVk4u9DzwtSnw9qOsqvkuG7yAcqft8kQTLiB+gnKHomG3ndJMFRR105v0VzGmtv
         Vocq/Gdfv2bP210sPvnWAIpVU5yNACsb54MjRAqWjxjEmjFn+zpP3YkULbniOjqmD+Co
         DYjBXkA2R/TWwo0DggakGKYZD/JwkJ3ZXYQ4eowMn91VFb3YM52BEP8vw5PCc9jkBhPB
         2hwouGluIux9uNGPvfQvpEDMvRMxPQpuRQXhwe4+pbhy6TRSh8PTvMkJ7eRhEMTmbg2n
         19Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=58JtzQFzSraERn4Bopu4OqV5/NkNxYgu28we5OLIN3M=;
        b=eS9BBP9vgR2P+h6V5WtiGM22sQTo2AT8dG4PP+PAeR5YRLDLe6MC0Nzc4EkqYr5HZq
         8UDRS1HffMUluJ906dhlMcI2cKWCurphRdGjOz1uXnnkMmp+tavb8t7QFCD4nWAlO2Kg
         8qlkAdxBLzIqZDSzl9fZXvaGUDlIU2b6E9L0Z1UubWAMEl6+k72oh45+wsE1ZCaVfp/f
         qvJuUodnI/FMJ1dvxt9GpwYCiRsqX9Zcxnofwa41NWLWSM6riwU16FE4SAyL2eINVMVR
         gG5e90a+6rdTjfphN8WirOiCJM7SvemGsGgkcVx7jM3uXmyE5iLheUPbuZ5rb/1Y+28T
         YVTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=58JtzQFzSraERn4Bopu4OqV5/NkNxYgu28we5OLIN3M=;
        b=asAKLya0z3aGeOcZQ1Ln5wAxpbaZL52JzYiRZmtt2tas8CFZumtUDFoYsAWETXDLdR
         ngI1J3V3ROKWxZvYOAOLf5pGB6yPJIZww9HaznjZq2m10+VGtKFRNB1i0PTwpSSG7CH5
         5KE+lcpeCH0ONQm5Or49DiOEnrY/xNGmaDHmkJN1+uozdJtq4/l26FDBs5TxfYuO7s90
         wSqV8pnSfmqOLMqsZ71XjBQnSHDl3+vacF9VZW77MAi6F4b8Y3vTskrsPsSplG7xTvQh
         1PvAyhXtDUFE46FmBpghwQHo0Wydvdp1w4wUETnPk+7vmA+kmeolxKpIZcigiCjt+jul
         WAUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=58JtzQFzSraERn4Bopu4OqV5/NkNxYgu28we5OLIN3M=;
        b=XtkHZ96GirkSqlLAJQyhyWd0vnEsYWdFv1CP0x2UZGaoVdnM2JvUCLtJWw2eLktHLe
         eK0EIFCHOY15rCt5eVOhzC+iKM7m6NSNJG6J57PNxlM4eU4w0qpMQdthqQQ7z7h4VxYS
         uBxOitP/7el4PWDUFmBltiUxu8kJG/xSYdbr8r/0yWy0CIWrQAjTC7K/ntA8OSJ6d5T3
         Li9LAtmwWz6vawNxRWl7J/oBTLAd6zU3GrP57iFPF0KJdAvTNLmmh7uWfegPADifgwqd
         gNJwbllozpfd1oTj0y7lp5SqPLPpdi5dqkJQcX7s0IlU/VzoVCd8cdYTWW+gxd++lKnK
         cBQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533kcb9K0PKyxMRAW5yfEAT2G4PIJRnyRAS/KDkGhxtXkpbd7yit
	gU11q9j1e7D3t3McaKLYfKw=
X-Google-Smtp-Source: ABdhPJz+n4lX5ikvRPMv+VTNndbVj1WRUtJGZE1Jgnjue4wiFeNLjoC79hjMR5LJwCPE/GjCxiaIgA==
X-Received: by 2002:a05:600c:290b:: with SMTP id i11mr19489765wmd.137.1636575931547;
        Wed, 10 Nov 2021 12:25:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:ed0e:: with SMTP id l14ls384396wmh.0.gmail; Wed, 10 Nov
 2021 12:25:30 -0800 (PST)
X-Received: by 2002:a1c:f402:: with SMTP id z2mr19647263wma.53.1636575930704;
        Wed, 10 Nov 2021 12:25:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636575930; cv=none;
        d=google.com; s=arc-20160816;
        b=H8ObAaO4x8RA30ACJeZRVTlsYCEgJ2iiRkPrQYPjmJPt6BYkabE3v6gVc/HLAzOsfk
         TN11mtT0qRmWsh9vb05BRJX5DPIxKUJQeodmCvmJpnbBi6MXBC5253u3DmMrhzwdJVNi
         zFlJx+a1ZpxtsPIxiPDrOjdvNIjPd82e8WE/lQqU0nzt4Pawl79j47FvJeelezYQbfSD
         AbTNmw/62eNOhhcWqnTDX5l4GY4d7E2IjkWEXgvRcTJqf2L7NILEcPPMMERaieceiJIV
         w5fF8FTufy12kn7db6NGzIQGVDrDOo0llnvWDZx7iW0HA6KBbCaEEHHspzma5tijD9eC
         j+Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=V+GOr8drWkNsqFPyqkQppYvNqni9IyUZCWPPyfY4+Rg=;
        b=CVO/1fUUouNVnUNskBrlZBYsmLT83CNRl72KskPesyMWtDo8UPxaOHiQomFzDGr+d4
         gbHgvvUvbZ9eil4Qbsagc40LDz3YnKVWwmFzs9UBwivyTFdefSX4KTdjeW0gu9G2kdQR
         QUE9KuIBziclD11z4Wt0Evx/hPG34pDyO2kTOXkEpMwxaf/Nf1IgOk514NdExawqliUV
         2D9GB90zdx7r4XBQptWVM+7FlsOotVS9/o3Hrv9XjixvfFbG3PuIvJM4Ke81jltaSSYp
         7ccD/zkM74F+i/NmAaLBdMIBkZ886nkGbKZY83xVpNIEf2uWNIzjv3CLbaiWEzTDP4bR
         gb1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d9si63797wrf.0.2021.11.10.12.25.30
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Nov 2021 12:25:30 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 05175143B;
	Wed, 10 Nov 2021 12:25:30 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id BEBB43F5A1;
	Wed, 10 Nov 2021 12:25:27 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org,
	linux-kbuild@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v2 3/5] powerpc: Use preemption model accessors
Date: Wed, 10 Nov 2021 20:24:46 +0000
Message-Id: <20211110202448.4054153-4-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211110202448.4054153-1-valentin.schneider@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
preemption model of the live kernel. Use the newly-introduced accessors
instead.

sched_init() -> preempt_dynamic_init() happens way before IRQs are set up,
so this should be fine.

Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
---
 arch/powerpc/kernel/interrupt.c | 2 +-
 arch/powerpc/kernel/traps.c     | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/powerpc/kernel/interrupt.c b/arch/powerpc/kernel/interrupt.c
index de10a2697258..c56c10b59be3 100644
--- a/arch/powerpc/kernel/interrupt.c
+++ b/arch/powerpc/kernel/interrupt.c
@@ -552,7 +552,7 @@ notrace unsigned long interrupt_exit_kernel_prepare(struct pt_regs *regs)
 		/* Returning to a kernel context with local irqs enabled. */
 		WARN_ON_ONCE(!(regs->msr & MSR_EE));
 again:
-		if (IS_ENABLED(CONFIG_PREEMPT)) {
+		if (is_preempt_full()) {
 			/* Return to preemptible kernel context */
 			if (unlikely(current_thread_info()->flags & _TIF_NEED_RESCHED)) {
 				if (preempt_count() == 0)
diff --git a/arch/powerpc/kernel/traps.c b/arch/powerpc/kernel/traps.c
index aac8c0412ff9..1cb31bbdc925 100644
--- a/arch/powerpc/kernel/traps.c
+++ b/arch/powerpc/kernel/traps.c
@@ -265,7 +265,7 @@ static int __die(const char *str, struct pt_regs *regs, long err)
 	printk("%s PAGE_SIZE=%luK%s%s%s%s%s%s %s\n",
 	       IS_ENABLED(CONFIG_CPU_LITTLE_ENDIAN) ? "LE" : "BE",
 	       PAGE_SIZE / 1024, get_mmu_str(),
-	       IS_ENABLED(CONFIG_PREEMPT) ? " PREEMPT" : "",
+	       is_preempt_full() ? " PREEMPT" : "",
 	       IS_ENABLED(CONFIG_SMP) ? " SMP" : "",
 	       IS_ENABLED(CONFIG_SMP) ? (" NR_CPUS=" __stringify(NR_CPUS)) : "",
 	       debug_pagealloc_enabled() ? " DEBUG_PAGEALLOC" : "",
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211110202448.4054153-4-valentin.schneider%40arm.com.
