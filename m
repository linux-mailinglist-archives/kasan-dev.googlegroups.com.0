Return-Path: <kasan-dev+bncBCALX3WVYQORBHUVWKCAMGQEI7YBFSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BE3493703C7
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 00:54:23 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id h22-20020a9d6f960000b029029e185197c1sf20484797otq.0
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 15:54:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619823262; cv=pass;
        d=google.com; s=arc-20160816;
        b=Neo5PM1PZv8INg1lu1+WX//vwQTgJrQDjaXERQBI+zTnFqbtPNPdu7WKuWiX78bMSP
         6J4O+hJgwlP4J+gRidU9pq3BgxYAgiEmy3Eacco2vvwPy+Vn3iwYn/naCJBkoVWbPOKc
         G8jmlPis9OpWHYEOcHYMvXYNiJzFNF+FiZe/kFdBQbjOu+4FL8ghbKN7inp8hfSOADbS
         J8npKT2iDjjx9yDxYMzdPAE51GRiFkd/kGSU/3QrxsO2GJkUA4eJeum0ABT3xblAZhWn
         hAtTeyiTdEHL+HbL9p/Vtjps3dVAKnY7yd40DGl7OXCj46FI7BkoCYK16pCyy9nUkPiv
         bUPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=pNuJUCUx6QyApy1D7ZFSpzHCcH8JKDeXzEDd6dbKMlc=;
        b=xnDE7koyaUH3n2nSA1D636GpuJieaZSb7lEMxLIHcGQ1/UYn+3f+xGw56GvF2gGPnP
         dAKtjSWWXqiN7dELeO+DElGt7X00FvAxpD16LWsICPZY+wNpYwUa+7jXpXMx0LhQeJ/B
         7dBCNNE9f/lT52IhJZXFFWizlDWSX/MM8pHCOuriZavYYP+ilZIC7rC8QmC1tr6UKTQf
         O+davi85T7dQvm8S0cdHhPWRvXFnTxuTB1L0U0PZpB4dxLWmFiDCClu88x7oC2NK5FR6
         gzFqx+T4srZrA9KVjidvF7Nwwg8UJ0AoAut4WkCdukDadTmNDHZQbD+wiZkZ/wVx946f
         x2XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pNuJUCUx6QyApy1D7ZFSpzHCcH8JKDeXzEDd6dbKMlc=;
        b=Kbrfpuzzgn7Y8LgKI837xK4F9V+2pGV/iAhIuXunKnBRG3q/zd18zOxYzV58AOEn6Q
         ZA8IJxLY+4Az2vxGjA4t1ThBrVU/cdRf5wzufkO8LOeF/2r8AmOfddqi8cLVG8r/y5kP
         PVxe2XW85TRzndFvq3A5YdT1QuGmBPuN44YbW4enxcomj9RDlmG2gAgDFn4bnHPo0OCp
         pz2Ts7XMNWJVN0+EOw1WCup3WIlmGHO11anR0GtwQ6CK9bDrIDaCgUZTj407MevRc6rr
         nya2sDZBH9OEu8SI6SAoRkKbD+4jqRqZ1u8cvALTApwHR6immxvJY59AG5sWA+b6yCGf
         B3+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pNuJUCUx6QyApy1D7ZFSpzHCcH8JKDeXzEDd6dbKMlc=;
        b=Fy2PjSbBS7rcVOJGNYEaQ7Ja6t08zFoMD62W2ayZ1v7doKwxG0F2u5bqkq040MBK87
         jbQNEBYAieMT28s4GSPvAWTjemOD/L7ZitUY3ijNc5hp75UBJeX4b+ihIMMba3fopdYy
         axHheKIrzc5xAVH9QhQPO1xZUMvt6Pkj2S++1q10kManZk/dAi3KvSidLYDxO8kXFzqR
         zXCJBgn7G+hYjK5v9UIKFvKB6OzIaNEtGm9GTv8/FMXk6BWtXqMyVt2jwSCrDygq6FKl
         8a0lEz7WMeUDkzUqVunZ8W56U8ZEyD46+M/T/8KtXsdUGucPxBpu1qlBc6F3NV2uROPE
         pLww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PMxLDVbBRCpQ+6nVZrQ+3hnL7Nk5/ZIWUcgo8ti/9CayUvqMl
	9iYZAhr5ndNTSZJYhjX8yxc=
X-Google-Smtp-Source: ABdhPJx0chJfs7plVuW8MMilX7F6NAuygi65bPfZeGpXRkr4xbaRem6ZHtmcPusx5sZPUWkReYbGRg==
X-Received: by 2002:a05:6830:108c:: with SMTP id y12mr5579802oto.276.1619823262612;
        Fri, 30 Apr 2021 15:54:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:724f:: with SMTP id a15ls2153788otk.4.gmail; Fri, 30 Apr
 2021 15:54:22 -0700 (PDT)
X-Received: by 2002:a9d:6c58:: with SMTP id g24mr5039728otq.315.1619823262290;
        Fri, 30 Apr 2021 15:54:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619823262; cv=none;
        d=google.com; s=arc-20160816;
        b=kOeNnwcqXiRmuz8owdRaG35f6dUqwAwgvwJdWYr3OJnWYmOOvEkD4CqXZxiChG29WB
         5PRfzSxX3vnzbr6mxmfqIaoPACr01/RSEfmyFAaNuNM2gSb5CnYem6gfJ8Zlno9+TM/w
         y4XTuhdmZZHWdNLSTcB3CFRvjAQjGt4A54Y3UpOFyNOkwmczrgKEfrCQ1Tnw3bbAc4nr
         z3RULOCWAdBvvALmvReESIUQCllK76iWzf5GBsQl5sHYR4jNsfIZPUI3zhLvlO9nXger
         P+u4f57bd+/0FI74pPtMRlyGgNyYEhEoSDj9s2zMmyfO1U4CcSWveSNi0+8mPeGULf1u
         ZwZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=2S8GQbQ1hnVEHKYJvH/T0L/33ChTY2KVuAjO2V+v1pw=;
        b=l5hdHK+mGmps9xXgjhRJ2q+SXqNb1XmF98HW/LplUSd4WdDcTToKVH/hCImkVtM6pl
         7K10Murse37xTc7l2rs+t/YaB0Fl4Vpu49T1OD9Wx96241g1KESm7xVHshHg0dNgC6fu
         vEpR81pdsYkWEP/GR3urZaHfRwaVocPtXNfrovAKPNNu/riKLRg04oh4ky5BIZEVHloi
         nVstySKSKqfFFtezkU5q7/sqg3Ft3IbyxRofSst+c36glkrnyxOR/rNwbNA11q4tf1Kn
         A7gd9eO8DWD3u9xe+CqzFXjcD5kDKblAAKMAEKtkzooy1ctwA3rMtJhVjSJfic16KW7Q
         EFYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id a5si671629oiw.0.2021.04.30.15.54.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 15:54:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcc1c-00CRcp-TS; Fri, 30 Apr 2021 16:54:20 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcc1b-007EL6-J3; Fri, 30 Apr 2021 16:54:20 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 17:54:16 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <m1o8dvs7s7.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lcc1b-007EL6-J3;;;mid=<m1o8dvs7s7.fsf_-_@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+P6+76RffWGTINLEazoBLyZeYoCYYvG1k=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TooManySym_01,XMNoVowels
	autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4977]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 552 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 4.7 (0.9%), b_tie_ro: 3.3 (0.6%), parse: 1.30
	(0.2%), extract_message_metadata: 11 (2.0%), get_uri_detail_list: 2.8
	(0.5%), tests_pri_-1000: 11 (2.0%), tests_pri_-950: 0.99 (0.2%),
	tests_pri_-900: 0.81 (0.1%), tests_pri_-90: 164 (29.7%), check_bayes:
	162 (29.4%), b_tokenize: 9 (1.6%), b_tok_get_all: 8 (1.5%),
	b_comp_prob: 1.55 (0.3%), b_tok_touch_all: 140 (25.4%), b_finish: 0.77
	(0.1%), tests_pri_0: 348 (63.0%), check_dkim_signature: 0.45 (0.1%),
	check_dkim_adsp: 1.90 (0.3%), poll_dns_idle: 0.54 (0.1%),
	tests_pri_10: 1.73 (0.3%), tests_pri_500: 6 (1.0%), rewrite_mail: 0.00
	(0.0%)
Subject: [PATCH 2/3] signal: Implement SIL_FAULT_TRAPNO
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
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


Now that si_trapno is part of the union in _si_fault and available on
all architectures, add SIL_FAULT_TRAPNO and update siginfo_layout to
return SIL_FAULT_TRAPNO when si_trapno is actually used.

Update the code that uses siginfo_layout to deal with SIL_FAULT_TRAPNO
and have the same code ignore si_trapno in in all other cases.

Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 fs/signalfd.c          |  7 ++-----
 include/linux/signal.h |  1 +
 kernel/signal.c        | 36 ++++++++++++++----------------------
 3 files changed, 17 insertions(+), 27 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index 040a1142915f..126c681a30e7 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -123,15 +123,12 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		 */
 	case SIL_FAULT:
 		new.ssi_addr = (long) kinfo->si_addr;
-#ifdef __ARCH_SI_TRAPNO
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
index c3017aa8024a..7b2d61cb7411 100644
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
@@ -3206,6 +3208,12 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 			if ((sig == SIGBUS) &&
 			    (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
 				layout = SIL_FAULT_MCEERR;
+			else if (IS_ENABLED(ALPHA) &&
+				 ((sig == SIGFPE) ||
+				  ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
+				layout = SIL_FAULT_TRAPNO;
+			else if (IS_ENABLED(SPARC) && (sig == SIGILL) && (si_code == ILL_ILLTRP))
+				layout = SIL_FAULT_TRAPNO;
 			else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
 				layout = SIL_FAULT_BNDERR;
 #ifdef SEGV_PKUERR
@@ -3317,30 +3325,22 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
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
@@ -3401,30 +3401,22 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1o8dvs7s7.fsf_-_%40fess.ebiederm.org.
