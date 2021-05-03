Return-Path: <kasan-dev+bncBCALX3WVYQORB556YGCAMGQEWDGZ5PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 54C4A372189
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:39:20 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id h190-20020a3785c70000b02902e022511825sf6067308qkd.7
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:39:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074359; cv=pass;
        d=google.com; s=arc-20160816;
        b=JkW5NwPEOWz1pbx/OXC36IEb62t9JAWHQTgV5dt5Ku2qKepZc6OFwcpVbcLd1IeWoJ
         PFz91EoJnIOcGsSXVWy/Z/uCPN7eKgbOhMWjuhWstnd1S30qIi48+TknhZCU/3c1k19W
         jn0rNXNZwLu0KClAUXKeLS0OeqMaimFDmAkXMHAVVcAj1P/EgTN+KFiNckAFz6UGL0Wm
         207CNnWYixHnsW7t1xzoBJ3xs3xpwVMPswbjIRj21qUt818v5MLMxnHg/ZzY6fug7q3Z
         dCmFyOtia9N9tv4IFEjAOsxBJ1gBqu0qBb7VA5m2DpDj1irvOSMimQ7jfeSuC51hgXIL
         FuWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=imprEh0DMrE21lNc6X64hcJXuarzLd6fu6t02gV5tOw=;
        b=OoSik3JRF50Ad9q9IKAwLC6Fk2JrvZY7+yLMmp5+O2w7fL46Jq9DtpvFBxHU+8clIz
         vezEluLPekeHQFES/vifZK+uT8dEGiUpms6SnrQhqvAoRJ0ghROqVChGaIxV9G3uNDeJ
         /qXx1UQA8UAtNy132W2tWbwQF0YPdoRy9QwmC3X2IpQ9ef4PmHwAaQu8VTnUE83oo/0h
         OoqdpCO1H+f9A0UeKLH1hQ5JVpuN+Pbucclh6Yp+KZR4Qbg2opEWT2XIbXnBKklk+6+5
         51DSGdTDtIdPP6M9UJrYitrK7tBWo+qdRtFS5GOIdRbJgwiayRtsae8eXSAD6B3+LpZM
         a6VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=imprEh0DMrE21lNc6X64hcJXuarzLd6fu6t02gV5tOw=;
        b=l5hR1aHF+WV91GoRdNAEfCIHBGAIr68Hd28h50K5sp1SJLfUvJxhjCAYNZQhczqG+R
         HXOW6mVxJGurKOB6/IBgSnuIp23eRnBTT6xUOTEpZnkp3KDPSevx0xgxX57wU8yH8cWn
         QGcbZrb8NjxoQNqijkwRWCmOQAc2kwUeq5jgjV+BRpvO+YqifzR6tZu0BKRNXH3BJrkX
         CsA1mS+EqM4QIgBWXY33hxL1cuPh8q0cLSuqRCFpbF6CbF5ntIrzFViV5XM5Wg2o/eor
         JrddYIi01SsI628n/uKR9XxBoACLzGuNIrFLPnnXP4wclNQla93IcUzNhy7Wv7bQa8b7
         3KoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=imprEh0DMrE21lNc6X64hcJXuarzLd6fu6t02gV5tOw=;
        b=O45X0w6Paynv2gKWzWRgaaD9yPj8LQQzYwj4yDjFiy2jCcQAG84uwWPHEWuOS14YsE
         y+ma/7GZQ25VLYKUP6SBIdZPKvCQzkgNDdRfq3+JUgNTmSfYUk7wvH1wrVuZmUbLWBaf
         sGsTcXrbUeXiSBRjVi/kU6pNSIfi/m7B6uFcA4G3NPyxhfXPTTTKdXJZTiSQ82kHLSZM
         rYZxmEK3unwOLGxzpJobIjWz017Zy/P5OT4ydweY4/IPB5KqAl+x4wmVVvF8rbv+JiLR
         ZoExUc/gdToH9Psbku8Czg6fvbABnqSg9coEpHD2v7Hp0aEQXpI1fhtA5q2F//jfwAfB
         8XmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TH1pssRkLzxnF1Ud1qfWulZFJuWJpulOBjE36INaozYMHikq1
	rtd+fNw1VRcAPCJQ4PW/ugs=
X-Google-Smtp-Source: ABdhPJy6tFRz1AI6rNslJUavlVyerSXN04V3gdvbAy99aDoTOD+jTqaNrfyuAKsBIXmqMiiwsHs7SQ==
X-Received: by 2002:ad4:58c7:: with SMTP id dh7mr21361427qvb.37.1620074359501;
        Mon, 03 May 2021 13:39:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7f0c:: with SMTP id f12ls6481212qtk.7.gmail; Mon, 03 May
 2021 13:39:19 -0700 (PDT)
X-Received: by 2002:ac8:75c2:: with SMTP id z2mr18524654qtq.265.1620074359093;
        Mon, 03 May 2021 13:39:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074359; cv=none;
        d=google.com; s=arc-20160816;
        b=TzNMu2sPreIPmm41lqu5CqlMo4x5Cv/Hg/AsjcuIMzc5JB9oYuQkcsG5Ap/buvxW+e
         hLhBhyuC4keczoIuUm1lV/UIc8M2WjwJnoQsWvEUKUjLoCfmkrPa43biAwywjV1dx6+7
         JxXIlMp1k/VR7GHSQlECeW1CP8hsNbq0uUK3PCkJXT73eyuPhqdYI8/GscKn2Mcu13vE
         ASxhen8AhOyNxxCQ8LCMC8nvRhZhpCrkKBqdoLETODNfacz9UKabrXSmcRc2eKGLKeBT
         thmpa/pfs9I8/EmnZXsZZbrLDiscc2wA2lJNqXsHwJuL6ZpwbGz7k2eV4edJq8by7sRf
         byyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=S27LTPs3VHqnPJoLFM/cX2upb1TOa5mQrgQUDfrnClA=;
        b=eZhXwypWlK1Ul6eqrWUvu/XlIL+UM0muiW4ZVL12e7INEcerPQTKMJNQI3MBnfJ4tA
         yGYXf1shneAVJqCNI4rLEDBQLnnJAu1Bx7unX34bhg2/EM0yjNjQTZnbfXZsof4h7xDc
         Gs8cwntsdHOikZ+LnJquO5FiTymmWxg1RAponInbarW0Z8CJa8S8/RLNEIDguezzJ4bh
         onfidrYrP8vx6Ob7NY3Uv/uLJ+hcMZOKOGvlvvIoRcVVDJoKizf1cGPNdnrvc5QzU2on
         EgVqF0LhkwgKrkeeMb2+cagUYb3lEY5UDjRek1TN2nDpfrPvbBficlS0iooSRjGGHTnD
         cmMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id s65si61111qkc.2.2021.05.03.13.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:39:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLZ-00GyjR-DQ; Mon, 03 May 2021 14:39:17 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLY-00E76Y-8K; Mon, 03 May 2021 14:39:17 -0600
From: "Eric W. Beiderman" <ebiederm@xmission.com>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Eric W. Biederman" <ebiederm@xmission.com>
Date: Mon,  3 May 2021 15:38:11 -0500
Message-Id: <20210503203814.25487-9-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210503203814.25487-1-ebiederm@xmission.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfLY-00E76Y-8K;;;mid=<20210503203814.25487-9-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX189tUaecX/QCvyNBX6HfKNGmtKwTn+Dm1Q=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.4 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4997]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 574 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 11 (1.8%), b_tie_ro: 9 (1.6%), parse: 0.90 (0.2%),
	 extract_message_metadata: 12 (2.1%), get_uri_detail_list: 1.84 (0.3%),
	 tests_pri_-1000: 13 (2.3%), tests_pri_-950: 1.25 (0.2%),
	tests_pri_-900: 1.02 (0.2%), tests_pri_-90: 237 (41.3%), check_bayes:
	236 (41.0%), b_tokenize: 9 (1.6%), b_tok_get_all: 7 (1.2%),
	b_comp_prob: 1.90 (0.3%), b_tok_touch_all: 215 (37.4%), b_finish: 0.89
	(0.2%), tests_pri_0: 283 (49.3%), check_dkim_signature: 0.49 (0.1%),
	check_dkim_adsp: 2.3 (0.4%), poll_dns_idle: 0.78 (0.1%), tests_pri_10:
	3.2 (0.6%), tests_pri_500: 10 (1.7%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 09/12] signal: Factor force_sig_perf out of perf_sigtrap
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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

From: "Eric W. Biederman" <ebiederm@xmission.com>

Separate generating the signal from deciding it needs to be sent.

v1: https://lkml.kernel.org/r/m17dkjqqxz.fsf_-_@fess.ebiederm.org
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
index 697c5fe58db8..49560ceac048 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1753,6 +1753,19 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
 }
 #endif
 
+int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
+{
+	struct kernel_siginfo info;
+
+	clear_siginfo(&info);
+	info.si_signo = SIGTRAP;
+	info.si_errno = type;
+	info.si_code  = TRAP_PERF;
+	info.si_addr  = addr;
+	info.si_perf  = sig_data;
+	return force_sig_info(&info);
+}
+
 #if IS_ENABLED(CONFIG_SPARC)
 int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
 {
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-9-ebiederm%40xmission.com.
