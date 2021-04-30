Return-Path: <kasan-dev+bncBCALX3WVYQORBIFMWKCAMGQEKU3DXXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4983D37042D
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 01:43:30 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id q18-20020a056a000852b02902766388a3c5sf159039pfk.4
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 16:43:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619826209; cv=pass;
        d=google.com; s=arc-20160816;
        b=hxD2LQBSN+LCjWrwfPlfeu4AOEHiLW2Jur3yeftc1Ywx6aaCslHUjsYb0rsMsHyRCS
         72e7WSrc/IyV4fDtqEAVy1cx5miHfyggpWFNrLbrS/dW/xBFjAkFugOO0ka2DoVkue3H
         jzJrf4Uj0Ij43y7KfcUvbCxengUKPEXEkMMsYWvHKFMSLxT9G6bOdYE1t3IqfwpLk+o8
         UYlgK+19CowQkzkuVT/2JeTijV84MDhO0m0G8CXB2l0HhOSBx2L0TZl/qLrQBOfoQWE4
         0dFXEpT6P57hXLkSE4UsMAtLCAF9HuQUZyojnWbKQoDgKqbkgELdWiCQgBYuOvTjc7xi
         zknA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=J2sD6ejFfXrmw0MzUhg9Vg/2ZKbG6JWmy38yv0HBHds=;
        b=u5rS8NO9GeIvEk0rXAXixyTb7fii5fpo093C17DzNpVlW6HIXqKcOcf0brSrnpQKsr
         HW61+8GhFK9mH2qYFdr8WKhBfBUNqfRXxk1NJG5BcQa6aOGoXn8K0tax6ka6kbWSAEl7
         Juu05lqZtHkwbgV/gAQszH60hTfY7kzwwktOf2jJzWpU2Gj91c1Xw31v0FiWh+36dzCz
         a++xSKQCmZfIxNBOtdXaJ9Mb32ZIEKz63s5LET7++Bfgok3eXQ0E/SYuDjCueGd9boZZ
         WY4ntUanFxYffeWsn2h1t4q8dZA1VuZlOdnDjIKL7jDC6Bkyz7oq0l0MFuxZldBNnpoQ
         4KqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J2sD6ejFfXrmw0MzUhg9Vg/2ZKbG6JWmy38yv0HBHds=;
        b=Wi6zpgD2d9PdgBUK1ktdKWdzqVTr4M2jLuumMypoWf9n1RFPEKzyEzj8WWMt9nzEbS
         ChlDA6zoPJpyxPsBjfktBAO+1orP1dwDGiepY1KBYnyxw7NL47xKQgnbsr+HYxqL9/7K
         Uvthu3S7RsKBUk9DLpuUAYlmBchOb4fyul1gVmtCmiGTeYt1WcEOhRwTLFxhAEHdJEqb
         XLRQGUlM3Mlq3oWvWyyo9dOrarUGFe7SSaUiIpAsFajXT2EjuDKKY5P4Y5L+rkukCKZp
         3EzIPjatsRdyI773IsZRVDurszZQudG9ARZPfA58SaqK9Etyuhj41gQYZN3DvFe31s7y
         lLJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J2sD6ejFfXrmw0MzUhg9Vg/2ZKbG6JWmy38yv0HBHds=;
        b=jTfKKRrWXlnkF4zAjE2x5E0qirhekBcyFKWiwP5cbUPXIc42Lrgg+/uorxYW0pc1D2
         FouX0fUYQ47+9rFK1HCkeagWfeY9seCY2nbZbezayxFOaKm7vNEkqpgocW/OtxtK8nBp
         NmWel1hlY2wQHuD5NnxvK684cEtUpEX9KZ5Vn/PBwQZxjGEIU+J+zJHlmQuYb1oPd0PK
         WDfXuyK3FKZbFFzAF/co1dwGKEBEw0liWIpjE3D1OUwDXIu9eow+fDY0ZgR048p/1VBY
         0n1iJqLzy4UmdCVExJNZVDRFs4dnUPJDSxd1zlTJxUC7H6+lVJTB3jL4VNS/IjMiLgZO
         tkTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533wipMBzTA0PkLw2tgH4SktA7jfhr3zIkVGRqTc4VUUnS+kbLIB
	3qEbsgtgzvbINmakS6tuNCs=
X-Google-Smtp-Source: ABdhPJzfMj+ntlPL+VyP+vuNpyiDjfohz+/jfWm+gveSuNdN6xb8t4lJ0WlQho1zsrt94HBGiNKACg==
X-Received: by 2002:a65:4d49:: with SMTP id j9mr6798787pgt.113.1619826208985;
        Fri, 30 Apr 2021 16:43:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1c59:: with SMTP id s25ls3096182pfw.8.gmail; Fri,
 30 Apr 2021 16:43:28 -0700 (PDT)
X-Received: by 2002:a63:f252:: with SMTP id d18mr6933561pgk.20.1619826208491;
        Fri, 30 Apr 2021 16:43:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619826208; cv=none;
        d=google.com; s=arc-20160816;
        b=fr8hMGIRgLR1W/9V+2vGncH6BPEfLiQcuTEncfZxxJ91fJBTzX8PaQLntfGL222oeW
         9R/bA/23zhgMlbYB9vtk0ErB8Y/ObLWHAIZJeLsRPqasUz2kW1Kepbw9mFQfin2u+Pmk
         2ujyOWSc7U8JBjPlQUej30eiwjhhyvKxu2w0TKcR/OZG2O72yfhZslHjmSpDWPijfxG+
         XES2qa2b5lC0AyjjNzRNo4Lb9jNnmX4Q6edlvEAfHPPOAsEly/cGILJKQNbFMwjvH3zs
         wcztocoCxrhbDStsad7pqOxkH3qdCTCN0dO7MfKrZw9S08Y2RldU/8dMH5f+YVa890sq
         cJnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=V1UEcC4GKwMn/io4hUsM78fMaB+9Zq5s8yDXXuEz0PU=;
        b=WPAKdGB0QwzUrIFTIM96wzGZ9XMByVXhQT8oCW9pV80xlP+KpwZH/NXUO2bWtpFiZb
         +nGq9/XnoFQQRUKR8zB9sxeUYRR2Xz4XkaCOAmw+4A5kPEOopP3lQXr2udNpyFXVjxqA
         1OIOkykU6T8j3bFuuBEgsNGK7wiEtY+1hGXdYGARLpgkisv0c1NrxdcP6w1weZMmYj/N
         tvCcCsMsT2so39UhayMMliejRClSbKqY3hONXFT46O7AQ4Jdvc7kA+wjMaDe3dkcj+oC
         wAHrgOS2/UQiHu1UbJYPBCwXc/ZTbEe7DTZEbpAg6mA0+XgSHw02WdctrmZZGP+NWIl0
         71Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id x9si985313pjr.2.2021.04.30.16.43.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 16:43:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccn9-00Cty4-Kg; Fri, 30 Apr 2021 17:43:27 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccn6-0000UE-Es; Fri, 30 Apr 2021 17:43:26 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 18:43:20 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <m17dkjqqxz.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lccn6-0000UE-Es;;;mid=<m17dkjqqxz.fsf_-_@fess.ebiederm.org>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+W2OA1W2SlAwE5XeYrhZGR3rJ/oNhsGXY=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TooManySym_01,XMNoVowels,XMSubLong
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4178]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1450 ms - load_scoreonly_sql: 0.06 (0.0%),
	signal_user_changed: 11 (0.8%), b_tie_ro: 10 (0.7%), parse: 1.04
	(0.1%), extract_message_metadata: 12 (0.8%), get_uri_detail_list: 1.66
	(0.1%), tests_pri_-1000: 13 (0.9%), tests_pri_-950: 1.32 (0.1%),
	tests_pri_-900: 1.09 (0.1%), tests_pri_-90: 106 (7.3%), check_bayes:
	105 (7.2%), b_tokenize: 9 (0.6%), b_tok_get_all: 7 (0.5%),
	b_comp_prob: 1.97 (0.1%), b_tok_touch_all: 83 (5.7%), b_finish: 0.83
	(0.1%), tests_pri_0: 1292 (89.1%), check_dkim_signature: 0.61 (0.0%),
	check_dkim_adsp: 2.7 (0.2%), poll_dns_idle: 0.99 (0.1%), tests_pri_10:
	2.2 (0.2%), tests_pri_500: 7 (0.5%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 6/3] signal: Factor force_sig_perf out of perf_sigtrap
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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


Separate generating the signal from deciding it needs to be sent.

Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 include/linux/sched/signal.h |  1 +
 kernel/events/core.c         | 11 ++---------
 kernel/signal.c              | 13 +++++++++++++
 3 files changed, 16 insertions(+), 9 deletions(-)

diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index 7daa425f3055..1e2f61a1a512 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -318,6 +318,7 @@ int send_sig_mceerr(int code, void __user *, short, struct task_struct *);
 
 int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper);
 int force_sig_pkuerr(void __user *addr, u32 pkey);
+int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
 
 int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
 int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 928b166d888e..48ea8863183b 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6394,8 +6394,6 @@ void perf_event_wakeup(struct perf_event *event)
 
 static void perf_sigtrap(struct perf_event *event)
 {
-	struct kernel_siginfo info;
-
 	/*
 	 * We'd expect this to only occur if the irq_work is delayed and either
 	 * ctx->task or current has changed in the meantime. This can be the
@@ -6410,13 +6408,8 @@ static void perf_sigtrap(struct perf_event *event)
 	if (current->flags & PF_EXITING)
 		return;
 
-	clear_siginfo(&info);
-	info.si_signo = SIGTRAP;
-	info.si_code = TRAP_PERF;
-	info.si_errno = event->attr.type;
-	info.si_perf = event->attr.sig_data;
-	info.si_addr = (void __user *)event->pending_addr;
-	force_sig_info(&info);
+	force_sig_perf((void __user *)event->pending_addr,
+		       event->attr.type, event->attr.sig_data);
 }
 
 static void perf_pending_event_disable(struct perf_event *event)
diff --git a/kernel/signal.c b/kernel/signal.c
index 690921960d8b..5b1ad7f080ab 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1753,6 +1753,19 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
 }
 #endif
 
+int force_sig_perf(void __user *pending_addr, u32 type, u64 sig_data)
+{
+	struct kernel_siginfo info;
+
+	clear_siginfo(&info);
+	info.si_signo = SIGTRAP;
+	info.si_errno = type;
+	info.si_code  = TRAP_PERF;
+	info.si_addr  = pending_addr;
+	info.si_perf  = sig_data;
+	return force_sig_info(&info);
+}
+
 #if IS_ENABLED(SPARC)
 int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
 {
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m17dkjqqxz.fsf_-_%40fess.ebiederm.org.
