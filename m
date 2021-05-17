Return-Path: <kasan-dev+bncBCALX3WVYQORBD4YROCQMGQEFOE6TBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3588A386515
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 22:03:29 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id l6-20020a056e021c06b02901b9680ed93esf7314851ilh.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 13:03:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621281807; cv=pass;
        d=google.com; s=arc-20160816;
        b=kHbEAHPXhTmRo43gULNgxSH7B435npvslsuJa8WTrGOrZIbKxWEudRtGHRfXIE0XMH
         F0BNWNUd3b5rli6NAN9FL0RCxvj4+w+GUftlB9947NCbN3PdHAhLpFXCHE8AP7Nc1CPi
         jhhXt1X6/4MI4hvY+bYrDE0jU71of1aITPSYD+Qo6zW6esAVimnhPVO4J+f+nn7HIghk
         PWttBrT1Ey4w34q6lGsdPThy1Sir2t/S8I/dodvw89oreyegwiB8e6Ma2aPlfV6Oh8HV
         m92jNdn1Oz3nfdaq0dHA7oGkA70OBP0bBUm/MPnXwppTxA0krgzk9I+oUyI9qqFOYUlf
         21Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=IF4MuMC7fdK2Jfn2viFAbaEew19Ar8LG27Y/I0m5Frw=;
        b=maiLFlQdjpvwjdY2Qoz8IwT1iE0maPqhhs6XWRad2iZ4bPtqMHYujTzMrsk3M+O7CG
         vApkahhgGqtk8gUxgIswLi8koKTtWPjmORpcUBsV1mRt5kvd4Gdim8B1gqk/lhOFnplB
         V3eb0WnmB/8CTXJi2Xex/ZF1DNNE9SoMB/cTf02Mk2wVA/+yAyZ6PSiEPEwn+ID14Gy2
         7WGgABysBPInRywNx1L1syA1vD6pDSzJcYWP4pFD9ktB4xVo6+RIMFB8do5X9iMTuM1c
         MT3E6UQkoOl3mqmgsBYt4/2KYsFaQ3jGzeqZzAJDSH5pzFF8oM4o0ERmfUDx9HL8ntGZ
         QIqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IF4MuMC7fdK2Jfn2viFAbaEew19Ar8LG27Y/I0m5Frw=;
        b=sfxQuEuQNmWOoyh96pbzB69tu225FMUH9gd1yZYg6w1pDDS87bTxt3cvI++ZjNIpSJ
         EtF86Q1O8WS+LmV7ESTItm8aKcp+DpXtclK0ci6s7gsedFahLYq8s73wIiyvbCglsJRS
         iUm9cSOYiU0lECazfO1ql6UtNpLdAD8G83EPdflqfZbIATMyZXoA78d57z3Ez5DpkBqH
         8AaWotOTr3eM0FoojKB4xwJv7j14vF0NB3bHO067/MqmbxAo83yPzG4FwrnWtP3DN8PO
         NYCcOllhH07itgcIpH7Ty4Bn8Q/SAy9OpZIF4l37cEs3DT4wS3aXa32C66E3/QFHMe+6
         YlDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IF4MuMC7fdK2Jfn2viFAbaEew19Ar8LG27Y/I0m5Frw=;
        b=kia3jaXKeP1m49vo7GQltkwZ1haFpxXPIy7YhN0r+7GT4zavCw/c3hEg4gLDxqHjs8
         j9fpThCdPU0ee4cZ9iPia4o1pHmZdeP3oXfoNcqh1KxOvmFe8qcQUxN8RjUFtxhE9+HV
         okjUG6Thy9V0kgOdD0eZBnCLrOb4quBj5sqT3pmTXucXul6+LOIP64lY/Qu6OZKrjDsu
         0okUepdQfK20aaq2G+WMNM/aF/B1bfHEgmJkHtdc7eZskkOSqbyW822wLhO9a5KGnBbO
         pmHKw7prPw4Dp+So4vpQuSx9c2UxKzOEjR+uca2Yz5KdGvOcRXrsFKpH7dvVKb5hE7ZM
         l2UA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5337JmOoXq32S1CxDGsiSa7KyzXwuP/sCxfW0TjOoHGKPwkcBJ1v
	AgaPpRjRMdCpYa1+76Y5nRc=
X-Google-Smtp-Source: ABdhPJzLS5s6xrdJya0Zi2PW3NH9Bi6asgM9tYbifi6ZxWxAOhmMxzQ31S5mx7pRmKjUM7Bf57sDRg==
X-Received: by 2002:a5e:dc49:: with SMTP id s9mr1411803iop.202.1621281807801;
        Mon, 17 May 2021 13:03:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:964:: with SMTP id q4ls2943970ilt.0.gmail; Mon, 17
 May 2021 13:03:27 -0700 (PDT)
X-Received: by 2002:a05:6e02:6cc:: with SMTP id p12mr1221657ils.244.1621281807438;
        Mon, 17 May 2021 13:03:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621281807; cv=none;
        d=google.com; s=arc-20160816;
        b=EqM93j6WacMhpwK85qlUU50XE2mw79M2lUjFR1PaFDjjIlWjiOQM1yrF4YUkDJ20nJ
         OxaJ1ugefGoc/zleOam+9OX8xpvKDmQdYaARdbi2FWKovlzjNl3lF4KoGfggqx7Ir4LV
         owMotMcIBSSgz8yNsdjTqf3U7kM4f0u+G9zj8g6JmycxpQ6/y3QU6At3BwRfeEfLneGB
         WT3CPx0lICIhtDTlYXH6EIamlH6DZcCg6inhs2RQRol3VAhHzdq/qFRhgjp5I4W4X+5U
         ST5I54GoR78krmO45QJJRlyEtAg7HtiXu1tZjhC5dmOMKRaIjGrR7H3ITbo/OezpCU3y
         M4Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=MSxjiTj0Bs1+ekPwIQ2uI/1hn+FENwIiBY9li4B6/zk=;
        b=wUQ/n0SfNxWo+ALU3boSfP7DCoL6o7rlqA3b6m4VTVrjxtIEAaOe6XCbWDml20JCJQ
         fyHf3NHzmc3fe2tkUscGw8+pUBUyQ9H3G/Z/mBy++NQEv1yt5/bexKWbM1+4368PTT6A
         KArXg7iYH51zNNLxIg6nze3ekVcUdyqMZT4W7LSvxKvkBq7MpBWQ0++1+7qt2YlZNyoK
         A8bwzMhP6LrdpeMFrKBr556l9ZsPZoG3zvsStXyE05jSDECwOG/CAlrVdpyOBHbsstTk
         3YNbzJdGQbhIorK8LaDM7428oNx2GUS0ojfE+ELnBfMmreWWrsylcbo6+8wAig9IqGFi
         chTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id v7si924004ioh.1.2021.05.17.13.03.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 May 2021 13:03:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijSY-009hJl-4f; Mon, 17 May 2021 14:03:26 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijNw-0001rb-Fk; Mon, 17 May 2021 13:58:43 -0600
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
Date: Mon, 17 May 2021 14:57:46 -0500
Message-Id: <20210517195748.8880-3-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210517195748.8880-1-ebiederm@xmission.com>
References: <m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
 <20210517195748.8880-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1lijNw-0001rb-Fk;;;mid=<20210517195748.8880-3-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18fYPk1LCSdXRWjF81+VdMO4wVqvRKe23A=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.9 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 2202 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 10 (0.5%), b_tie_ro: 9 (0.4%), parse: 0.93 (0.0%),
	 extract_message_metadata: 15 (0.7%), get_uri_detail_list: 2.4 (0.1%),
	tests_pri_-1000: 21 (0.9%), tests_pri_-950: 1.18 (0.1%),
	tests_pri_-900: 1.01 (0.0%), tests_pri_-90: 75 (3.4%), check_bayes: 74
	(3.4%), b_tokenize: 10 (0.4%), b_tok_get_all: 7 (0.3%), b_comp_prob:
	3.0 (0.1%), b_tok_touch_all: 52 (2.3%), b_finish: 0.81 (0.0%),
	tests_pri_0: 351 (16.0%), check_dkim_signature: 0.77 (0.0%),
	check_dkim_adsp: 2.3 (0.1%), poll_dns_idle: 1711 (77.7%),
	tests_pri_10: 2.2 (0.1%), tests_pri_500: 1722 (78.2%), rewrite_mail:
	0.00 (0.0%)
Subject: [PATCH v4 3/5] signal: Factor force_sig_perf out of perf_sigtrap
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
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

Separate filling in siginfo for TRAP_PERF from deciding that
siginal needs to be sent.

There are enough little details that need to be correct when
properly filling in siginfo_t that it is easy to make mistakes
if filling in the siginfo_t is in the same function with other
logic.  So factor out force_sig_perf to reduce the cognative
load of on reviewers, maintainers and implementors.

v1: https://lkml.kernel.org/r/m17dkjqqxz.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/20210505141101.11519-10-ebiederm@xmission.com
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 include/linux/sched/signal.h |  1 +
 kernel/events/core.c         | 11 ++---------
 kernel/signal.c              | 13 +++++++++++++
 3 files changed, 16 insertions(+), 9 deletions(-)

diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index 3f6a0fcaa10c..7f4278fa21fe 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -326,6 +326,7 @@ int send_sig_mceerr(int code, void __user *, short, struct task_struct *);
 
 int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper);
 int force_sig_pkuerr(void __user *addr, u32 pkey);
+int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
 
 int force_sig_ptrace_errno_trap(int errno, void __user *addr);
 
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
index 597594ee72de..3a18d13c39b2 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1763,6 +1763,19 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
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
 /* For the crazy architectures that include trap information in
  * the errno field, instead of an actual errno value.
  */
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517195748.8880-3-ebiederm%40xmission.com.
