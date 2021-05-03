Return-Path: <kasan-dev+bncBCALX3WVYQORB2V6YGCAMGQED2E5NZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B9492372185
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:39:07 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id z14-20020a170903018eb02900eed5c11984sf1835333plg.16
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:39:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074346; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZl78aK6kLycPqKRGlK/lMFC///qHEa/HkvSCAs/mlr2cbG0LIyjEPBHz4oGmMh5bV
         lh92VbvwC2yAXT8HQPxmSFz4A5yDl0H2KfZnu5H7dvd0lgpjAsWW33M+bO3MuxrA+r2P
         imaGiSufyKPbV/84DVfi9I+8DvlstDQllvacabpcwu2V07GZdJiSO2y+aGcxyVf2aeKH
         jWfXE/zDWd/sh5rPyS4Wwns50Lq1sp+f1zemYnbPT2AdTqGBqY4LgtgK8mnEsUp2LOi6
         7wsjKOsO2a6wsb14vFHnuuJTS7M7gt06/lrVO17XCLf+vvlQzfDkdsczHzLFhIOM2TaJ
         92Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=BsLaBzwpxfM5Ra00cR8rDj/Vft8TXg/DEp+ipt5wIdU=;
        b=A1qQWGx+XVV+8v+G8XVsHSR3NhzauG1KTR+Z0yrt1ntwZKzj3w811tds6bxoeUVOEc
         J8JI/SwCu6pvO0F1R4bOgE/270CAUq4m0Jo2g0tGjkEHQs+12ccE8MtoXUp8mdCO4iKJ
         KpQ91+j1Ug3tmzAGSYePFKx9yk6Tw8bUi0ib/1ItkbM3VfZ2y/WVgBAxBOWzjP3rbeCX
         ha9Pxggxop5/nKa1mTf4h2Xf2XV3WnAAZAzyPEIy0rItVItlqEcTk4gTuc/CCQQ+/WTf
         V/6I8tQUIafYW54mRccUth5pEstLQu+fbx1ug+yiyOGLdBwXd8Q4ztj7t+M4kqfxlQfC
         Padw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BsLaBzwpxfM5Ra00cR8rDj/Vft8TXg/DEp+ipt5wIdU=;
        b=rkB44rJc04/77b9cowcnPd9QKMv4h8E5Wb5kze6FSH7wUR23X/2CmpBzoAYhqIwjDq
         hg8gSNDIOkZOMgB/3yLgFPbnAnsugDHhZnKkrUm7rPPs1Vnm1WyqfkWJaDRULQNeo9v1
         lAx+VfKzpbAItgdqBiUMACZC1nzi9aYAPm0zXVUGo7oUWgLLddI8NI8DawG7LECcvGBh
         a/U/i8isyufaWJQRW+o5wnrJ9wRMjZF/FE0w5jUy1mZMYHWZABGrTTj88DXFyXiltzTT
         5vOY6GFqxAebFnr64ZtNNVQOB9FNQrB7TJ6sXbzPpf2XAhw5LL+GbBRpcflfh3F+0oPX
         LIig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BsLaBzwpxfM5Ra00cR8rDj/Vft8TXg/DEp+ipt5wIdU=;
        b=k66UBb27xpbL8N34KdycVZVYcmZnW2+nUVCHAjsY61MQP6tLlDsCPuw9B3oXacJoME
         y4O7ax4GTn2BQv5TU7bSHew8J7dBPLAjJJItsFHpvrGOk45ausQN+a/0N9UrQNxaJIAn
         3be34EGeyI1mt0R4O4oP1uDIBG484rPR+vkVmJXPb4VSoQG24biO1AqVslp1x0FETju9
         at0onLGLEygcTgQLyLCCHaGc2fjJtZZoHFC09jqYa5TfJIvHDwUOsJv0lCUSTxwIT4Xk
         yhE3uNmkolWeYZMh0upTlTSSBMdRVIo4IWYQb4jbtszZ5RuWMkmEAyf5Psyr1GLN8BxR
         Lseg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532B+BEVorD39Q7KmFJYBIJIiivrVRKv3UUiRSvoq8t7+5RM7PRM
	vSftXWUO8+jmS8ljWIMXZYg=
X-Google-Smtp-Source: ABdhPJzR38jzZ8HlAXFxmb8AU6Q3aHTnbfhUQl/d9VJrdnL2MT+NB0hd7GBS8IUsfQu4yUPqpwERZA==
X-Received: by 2002:a17:90a:590d:: with SMTP id k13mr6096848pji.68.1620074346330;
        Mon, 03 May 2021 13:39:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fb4c:: with SMTP id iq12ls4801687pjb.3.gmail; Mon,
 03 May 2021 13:39:05 -0700 (PDT)
X-Received: by 2002:a17:90a:fe3:: with SMTP id 90mr526156pjz.215.1620074345854;
        Mon, 03 May 2021 13:39:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074345; cv=none;
        d=google.com; s=arc-20160816;
        b=aFAVHWO53KXeyO104pP9P3pH7Uu8LzHQxE7eQmTK8c+IB5Iunbt7WiHbYcirAtDKlu
         ufWs1ErP545qdg75cztD17uOsJq8+B0FeeWzitISIF/oChjVy+xBEEoO04P6/YApvB93
         fwfnIvJnEseqg2EFsGk3xHixQo5381UHj+zbDDxerXsXY+0HayLXbGOPHSGLEl7tQoA0
         dGg2URnaDERUEDGVTiGUPqkWVOC4UFKM79t5u/toUNB0A7VECW78eQFTv3J+6P7W84qE
         WeknKM6iv7rYzlGjgl5T695TDHnVOSAobCS6/5fy5IwYS2fzYGy92yCVOTyAaUtfif7a
         NnwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=q3uAWHlrVzc3PbW9E9zr8qdGyUjb6NVzmXmpgZFKSc8=;
        b=05Cxoz7JYKNRAcvy84VyLhlbk2WluM+NHCVOeM84ezvjfR4VLE6SnPqVFZHTLnJvpS
         2LXyTKtVp90QG9RyvUOCGkh0TSNYhlRNuIiShiVR97CodW8FRwrOswJzl/Zdbqcpa8oc
         +dR/p241muYifR7as6RVaOULQpb9uAildTZ1VqPzyzufmgiorlpKQGhrVOe/lzJUArKB
         H0rSgYM89wXM1d3FbIv8bZ0YPlevP+HBCks01gO2fPl4eeLZJUm/mVulCzqgTJjUJqx1
         41XZ9yM1yj5THPaWVT9ZYcueg6I0IdLeOiFYxTNMVYpBL4QLOe4uhvaE1EJosfPu3EF4
         VDLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id e20si51877pjp.0.2021.05.03.13.39.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:39:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLM-00HIYk-AP; Mon, 03 May 2021 14:39:04 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLK-00E76Y-OX; Mon, 03 May 2021 14:39:03 -0600
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
Date: Mon,  3 May 2021 15:38:07 -0500
Message-Id: <20210503203814.25487-5-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210503203814.25487-1-ebiederm@xmission.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfLK-00E76Y-OX;;;mid=<20210503203814.25487-5-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/vZH6HqlAizbFBYIPV3kdC7tQgXzT10tA=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMNoVowels autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 634 ms - load_scoreonly_sql: 0.22 (0.0%),
	signal_user_changed: 17 (2.7%), b_tie_ro: 14 (2.1%), parse: 3.7 (0.6%),
	 extract_message_metadata: 24 (3.7%), get_uri_detail_list: 4.5 (0.7%),
	tests_pri_-1000: 20 (3.2%), tests_pri_-950: 1.88 (0.3%),
	tests_pri_-900: 1.44 (0.2%), tests_pri_-90: 160 (25.2%), check_bayes:
	158 (24.9%), b_tokenize: 15 (2.4%), b_tok_get_all: 9 (1.4%),
	b_comp_prob: 2.7 (0.4%), b_tok_touch_all: 126 (19.9%), b_finish: 1.26
	(0.2%), tests_pri_0: 373 (58.9%), check_dkim_signature: 1.09 (0.2%),
	check_dkim_adsp: 2.4 (0.4%), poll_dns_idle: 0.61 (0.1%), tests_pri_10:
	4.0 (0.6%), tests_pri_500: 21 (3.3%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 05/12] signal: Implement SIL_FAULT_TRAPNO
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
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

Now that si_trapno is part of the union in _si_fault and available on
all architectures, add SIL_FAULT_TRAPNO and update siginfo_layout to
return SIL_FAULT_TRAPNO when si_trapno is actually used.

Update the code that uses siginfo_layout to deal with SIL_FAULT_TRAPNO
and have the same code ignore si_trapno in in all other cases.

v1: https://lkml.kernel.org/r/m1o8dvs7s7.fsf_-_@fess.ebiederm.org
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 fs/signalfd.c          |  8 +++-----
 include/linux/signal.h |  1 +
 kernel/signal.c        | 37 +++++++++++++++----------------------
 3 files changed, 19 insertions(+), 27 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index 040a1142915f..e87e59581653 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -123,15 +123,13 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		 */
 	case SIL_FAULT:
 		new.ssi_addr = (long) kinfo->si_addr;
-#ifdef __ARCH_SI_TRAPNO
+		break;
+	case SIL_FAULT_TRAPNO:
+		new.ssi_addr = (long) kinfo->si_addr;
 		new.ssi_trapno = kinfo->si_trapno;
-#endif
 		break;
 	case SIL_FAULT_MCEERR:
 		new.ssi_addr = (long) kinfo->si_addr;
-#ifdef __ARCH_SI_TRAPNO
-		new.ssi_trapno = kinfo->si_trapno;
-#endif
 		new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
 		break;
 	case SIL_PERF_EVENT:
diff --git a/include/linux/signal.h b/include/linux/signal.h
index 1e98548d7cf6..5160fd45e5ca 100644
--- a/include/linux/signal.h
+++ b/include/linux/signal.h
@@ -40,6 +40,7 @@ enum siginfo_layout {
 	SIL_TIMER,
 	SIL_POLL,
 	SIL_FAULT,
+	SIL_FAULT_TRAPNO,
 	SIL_FAULT_MCEERR,
 	SIL_FAULT_BNDERR,
 	SIL_FAULT_PKUERR,
diff --git a/kernel/signal.c b/kernel/signal.c
index 65888aec65a0..3d3ba7949788 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1194,6 +1194,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
 	case SIL_TIMER:
 	case SIL_POLL:
 	case SIL_FAULT:
+	case SIL_FAULT_TRAPNO:
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
@@ -2527,6 +2528,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
 {
 	switch (siginfo_layout(ksig->sig, ksig->info.si_code)) {
 	case SIL_FAULT:
+	case SIL_FAULT_TRAPNO:
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
@@ -3206,6 +3208,13 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 			if ((sig == SIGBUS) &&
 			    (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
 				layout = SIL_FAULT_MCEERR;
+			else if (IS_ENABLED(CONFIG_ALPHA) &&
+				 ((sig == SIGFPE) ||
+				  ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
+				layout = SIL_FAULT_TRAPNO;
+			else if (IS_ENABLED(CONFIG_SPARC) &&
+				 (sig == SIGILL) && (si_code == ILL_ILLTRP))
+				layout = SIL_FAULT_TRAPNO;
 			else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
 				layout = SIL_FAULT_BNDERR;
 #ifdef SEGV_PKUERR
@@ -3317,30 +3326,22 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 		break;
 	case SIL_FAULT:
 		to->si_addr = ptr_to_compat(from->si_addr);
-#ifdef __ARCH_SI_TRAPNO
+		break;
+	case SIL_FAULT_TRAPNO:
+		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_trapno = from->si_trapno;
-#endif
 		break;
 	case SIL_FAULT_MCEERR:
 		to->si_addr = ptr_to_compat(from->si_addr);
-#ifdef __ARCH_SI_TRAPNO
-		to->si_trapno = from->si_trapno;
-#endif
 		to->si_addr_lsb = from->si_addr_lsb;
 		break;
 	case SIL_FAULT_BNDERR:
 		to->si_addr = ptr_to_compat(from->si_addr);
-#ifdef __ARCH_SI_TRAPNO
-		to->si_trapno = from->si_trapno;
-#endif
 		to->si_lower = ptr_to_compat(from->si_lower);
 		to->si_upper = ptr_to_compat(from->si_upper);
 		break;
 	case SIL_FAULT_PKUERR:
 		to->si_addr = ptr_to_compat(from->si_addr);
-#ifdef __ARCH_SI_TRAPNO
-		to->si_trapno = from->si_trapno;
-#endif
 		to->si_pkey = from->si_pkey;
 		break;
 	case SIL_PERF_EVENT:
@@ -3401,30 +3402,22 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
 		break;
 	case SIL_FAULT:
 		to->si_addr = compat_ptr(from->si_addr);
-#ifdef __ARCH_SI_TRAPNO
+		break;
+	case SIL_FAULT_TRAPNO:
+		to->si_addr = compat_ptr(from->si_addr);
 		to->si_trapno = from->si_trapno;
-#endif
 		break;
 	case SIL_FAULT_MCEERR:
 		to->si_addr = compat_ptr(from->si_addr);
-#ifdef __ARCH_SI_TRAPNO
-		to->si_trapno = from->si_trapno;
-#endif
 		to->si_addr_lsb = from->si_addr_lsb;
 		break;
 	case SIL_FAULT_BNDERR:
 		to->si_addr = compat_ptr(from->si_addr);
-#ifdef __ARCH_SI_TRAPNO
-		to->si_trapno = from->si_trapno;
-#endif
 		to->si_lower = compat_ptr(from->si_lower);
 		to->si_upper = compat_ptr(from->si_upper);
 		break;
 	case SIL_FAULT_PKUERR:
 		to->si_addr = compat_ptr(from->si_addr);
-#ifdef __ARCH_SI_TRAPNO
-		to->si_trapno = from->si_trapno;
-#endif
 		to->si_pkey = from->si_pkey;
 		break;
 	case SIL_PERF_EVENT:
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-5-ebiederm%40xmission.com.
