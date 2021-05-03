Return-Path: <kasan-dev+bncBCALX3WVYQORB5F6YGCAMGQEGSJPN6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AE8B372188
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:39:17 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id l25-20020a6357190000b02901f6df0d646esf3595820pgb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:39:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074356; cv=pass;
        d=google.com; s=arc-20160816;
        b=bn5vXMrAhbHGoCipecKP6tnNTZGipUTyrMHNiO+pHHZ8kFjoh9fryGeOG+kMg5O0yb
         EI2MMGt6qZhrr8rxpNP0UzaRjwQz2NlvpNzqot+28Ib9uz1Ql+4F+EfINEVndoEeEMRA
         31EhI37mRaDUAS99ZxkR5b7L9y/xpZ/kkb/U/Lt+VkZHMbJvc4isV/2bg0n1R0bULxt1
         B+foQIOtaxu1epOJrVoqlR5OjEBTuH6y7AKBvccB6bGVSm9DwqJMEaSNd0wcCD090Zgf
         Sj54MChLri6evn3BfEf5qdRYQjH6V1rm7RQ8UiljXIBA/2PyUjIiImNYSR//dZzwW8YY
         fKyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=oDgYMuu5xQGndlI6gooW9wSk2Ym3QMDXR35xM3w5V4g=;
        b=aeucEjy7OmpIhyDJ12N/gNyarEc3zTBtyo0++QXuSSVgxG5HZV0NjgRSe3kkUYDftg
         EeayLuQE2y6XkSx8CUdfvD2aq3ukPMJGowkLWoY4y8u7PnKEFSRl1zCXk2mlIJWezjAa
         hY0NO9oT+J0vrja9keWh5S47wP0UyV4AcZcktP1yYHRduyag9Tw0Wugfk7aWEcRqh1xR
         AoyNG0BCeV5EppRVJgQ/S+FWoSj/sHPOVp+8A7t1uiUUklFx+/taMfuxY/l+EaRtQbrg
         gf8MURRD9r5o+gJ3Iw9zq7wQMD018dz3L+nRY1fh/wY6I6H095PryXyWKpax1FLb151K
         R8iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oDgYMuu5xQGndlI6gooW9wSk2Ym3QMDXR35xM3w5V4g=;
        b=hsv/cHUFO1iNU6asZMDONa5uIYskUMrXR75U+Q8pISnm+D1bxLNSlvBOlXO2HvbrNw
         LeBUoxO6HgakTIfxnGmc9xktUf9dAe7PdJCrAxQ0RFb8ltpAFMl1LYNgjZZcUQ8ycwCw
         2qxUQ1yklePvCMbRqfKLm7nhfoKwuKNgBBT/gkcSlz3eIec5IuSrapsUmVfkP8RHbA2f
         lbH+s81IiJIR2Yn1HR4ZXrLYda5XcEe2evhZMo0Qu+SUXrZk5/qx/i519qnod2rddsG5
         pAAA6WJwiVZDFCxOnjjRAuoDVc79JafW+H+r3xL4+4gQb9wTTzrxdbt767hLkVi+cl5S
         5OqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oDgYMuu5xQGndlI6gooW9wSk2Ym3QMDXR35xM3w5V4g=;
        b=HBo0dItdTkpBtp2rD9rHnOxwR3CzjgSHFfcKSbFij93xWU3lmb7XufHQBxEnT0fhce
         Rv0UJijzlX5u+l3xTspMq2n+yVPjPux+3RBOhGPuE13JKjmcYohZYiMEdUiKa0aFTU1+
         j3GYF2u0AmkuKjNsDdsDFtFyF/8i06TGZYtjZGEUgq0Wisy0iHaB5uwenl3cEoOwYhVa
         zz1CfuQqORpJqc0SCrXJ9lc2bW0DU5r0wOTcwsXZ4FUgjxa2thfPFhUdUU4BARo6Z2uh
         K778niiX0n4rCmtkPDD2kz++VCPF1ws/YfKaf0lOLBzMNNO8RwKWEp9RfMe65SyTXzgB
         QG8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ShlPxoX4HIKYNmIsLZcabDrBdTagAzjxv0pL7+lR5p47cbjFp
	Bpw8RVlzv7b/Eoq4q/E+BEo=
X-Google-Smtp-Source: ABdhPJwM3LUvhwimaYadYYyP78oTe/yV6aa3zkbq1Ihnmpcys8PeSH4LX8loLluLTE4ZkM5dHVSiFg==
X-Received: by 2002:a17:902:ed97:b029:ee:af8e:3a0a with SMTP id e23-20020a170902ed97b02900eeaf8e3a0amr16810002plj.52.1620074356167;
        Mon, 03 May 2021 13:39:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3014:: with SMTP id hg20ls152703pjb.3.canary-gmail;
 Mon, 03 May 2021 13:39:15 -0700 (PDT)
X-Received: by 2002:a17:90a:aa11:: with SMTP id k17mr554726pjq.60.1620074355686;
        Mon, 03 May 2021 13:39:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074355; cv=none;
        d=google.com; s=arc-20160816;
        b=u5/n04PoWiR5hgSzNv+CzyL27Qy5LkgLc/H3WyqFWw4y/tcCbH3bdRZl29YmEGXlop
         0H6BfOArWIDTxj3aQk/TE+oFdNw/+4+FdqLWSzYQJuy678i4MrNc7oVscsOdp+x9BK2m
         HbnvdniTeCvc7qWpry+hbNEU33CGyW6FmjYSMY8DbWLZ3EjAeg5xMlOxb2ots0U280NE
         1reg/DRUZQChD8YknOJ5hUzkun+A/27wPvnp7X8CvtMFzsXsANoJQQzT+dZ4Xn+0Q8gZ
         dWgPRmF+03WU1u/9SmOWTvn7eXzxlCHdHyQDgjtBw1qjLSWeCqygB9oChvpNjYcQkS6E
         aHTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=QMX+qp65XOa9G+4yWYllyq7RhINkwIG6/PTo2273kRM=;
        b=eDrPnLY9xkQ0WBtwQeTdiPHHoPGlok1t8+14UiZXX5Jfj09o8GDkPNYb+9N2MDCgXE
         rV4Krn9oXqOZJ/sBJ710GmC+EjI9WGXvxXQUHFmBRc1vcgX2lmiAUYRqqiRYQyfCuv3/
         /CDv+QpiwLK350r9h43rciduxXUtebvXbaKHVGHeqpBx+uj/2aNZiZQZ76OdkyiHKF2M
         dGQ/zupBDixWCHExnBrP8yrCaiItfhIhP//Grj8+nTEe/w096W/wrrbGwwYrNVe+x4Cz
         vWOlhaIRNELvvP9YqoD+BlypHc2AlaqUue29L7UUwE09zLqBkizYh7WRxqZZVgiNYL7t
         I7rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id hk5si118963pjb.1.2021.05.03.13.39.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:39:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLW-00Gyj0-Lw; Mon, 03 May 2021 14:39:14 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLU-00E76Y-3p; Mon, 03 May 2021 14:39:14 -0600
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
Date: Mon,  3 May 2021 15:38:10 -0500
Message-Id: <20210503203814.25487-8-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210503203814.25487-1-ebiederm@xmission.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfLU-00E76Y-3p;;;mid=<20210503203814.25487-8-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/sil7XAjMfE6caN/d/T+dcJfVbuHF1QAo=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.7 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMGappySubj_01,XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.5 XMGappySubj_01 Very gappy subject
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1918 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 10 (0.5%), b_tie_ro: 8 (0.4%), parse: 1.44 (0.1%),
	 extract_message_metadata: 14 (0.7%), get_uri_detail_list: 2.3 (0.1%),
	tests_pri_-1000: 17 (0.9%), tests_pri_-950: 1.26 (0.1%),
	tests_pri_-900: 1.03 (0.1%), tests_pri_-90: 1527 (79.6%), check_bayes:
	1525 (79.5%), b_tokenize: 13 (0.7%), b_tok_get_all: 6 (0.3%),
	b_comp_prob: 1.96 (0.1%), b_tok_touch_all: 1499 (78.2%), b_finish:
	1.06 (0.1%), tests_pri_0: 326 (17.0%), check_dkim_signature: 0.56
	(0.0%), check_dkim_adsp: 2.5 (0.1%), poll_dns_idle: 0.69 (0.0%),
	tests_pri_10: 3.1 (0.2%), tests_pri_500: 15 (0.8%), rewrite_mail: 0.00
	(0.0%)
Subject: [PATCH 08/12] signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
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

It helps to know which part of the siginfo structure the siginfo_layout
value is talking about.

v1: https://lkml.kernel.org/r/m18s4zs7nu.fsf_-_@fess.ebiederm.org
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 fs/signalfd.c          |  2 +-
 include/linux/signal.h |  2 +-
 kernel/signal.c        | 10 +++++-----
 3 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index e87e59581653..83130244f653 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -132,7 +132,7 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		new.ssi_addr = (long) kinfo->si_addr;
 		new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		new.ssi_addr = (long) kinfo->si_addr;
 		new.ssi_perf = kinfo->si_perf;
 		break;
diff --git a/include/linux/signal.h b/include/linux/signal.h
index 5160fd45e5ca..ed896d790e46 100644
--- a/include/linux/signal.h
+++ b/include/linux/signal.h
@@ -44,7 +44,7 @@ enum siginfo_layout {
 	SIL_FAULT_MCEERR,
 	SIL_FAULT_BNDERR,
 	SIL_FAULT_PKUERR,
-	SIL_PERF_EVENT,
+	SIL_FAULT_PERF_EVENT,
 	SIL_CHLD,
 	SIL_RT,
 	SIL_SYS,
diff --git a/kernel/signal.c b/kernel/signal.c
index 7eaa8d84db4c..697c5fe58db8 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1198,7 +1198,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 	case SIL_SYS:
 		ret = false;
 		break;
@@ -2553,7 +2553,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		ksig->info.si_addr = arch_untagged_si_addr(
 			ksig->info.si_addr, ksig->sig, ksig->info.si_code);
 		break;
@@ -3243,7 +3243,7 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 				layout = SIL_FAULT_PKUERR;
 #endif
 			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
-				layout = SIL_PERF_EVENT;
+				layout = SIL_FAULT_PERF_EVENT;
 		}
 		else if (si_code <= NSIGPOLL)
 			layout = SIL_POLL;
@@ -3365,7 +3365,7 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_pkey = from->si_pkey;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_perf = from->si_perf;
 		break;
@@ -3441,7 +3441,7 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
 		to->si_addr = compat_ptr(from->si_addr);
 		to->si_pkey = from->si_pkey;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = compat_ptr(from->si_addr);
 		to->si_perf = from->si_perf;
 		break;
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-8-ebiederm%40xmission.com.
