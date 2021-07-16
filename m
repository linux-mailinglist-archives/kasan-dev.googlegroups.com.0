Return-Path: <kasan-dev+bncBCALX3WVYQORBTG5Y2DQMGQEFOA2BYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 497263CBA51
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 18:07:42 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id l20-20020a17090a5994b02901725eea9204sf1554686pji.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 09:07:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626451661; cv=pass;
        d=google.com; s=arc-20160816;
        b=tujXYTMG3Yu7hpKx3llM6YIBvF6wrU/GOAKLmWk7AvAijOHrNT8fabU48XOenTWTDy
         guVDTgGMdM85anM8/kjTU6+5Chml/JS67IRiws8f7eTqbS5gIlNLWtiEGe3ZA+ATzlBA
         fRa5cSorS0raHMOqEXvxyE7W7JmIGhiapJYK8TOhB4klOYLy9CyLIsYWZu1FGLENI7xf
         Vc7+UQE2SZ0FZ1LL8S0ZhSs5thbmTDvTObv2cueF4py7aP4I84K0bP4UVj1UNLJPX6/D
         W/EfgtyICqOHpoqngsznj2mdAHp2eHlXiBJvQm9PeAhEiLdXHtJBQJvJNY3vca/P36QW
         hiMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=wzo/PiDlGOo+cTH/fo14l7EBZYsWa+LL15/tSrF9W3Y=;
        b=w74OlN9EzRehHACGEEm8Ux/zITgkIoiqoilW57aaR64z7H/dBlDPp/gCBuhaY44LnC
         5Gj0QBwqJAF/MgjC9QESSP5C9eMd5rYiWDd0xsdNzFSk/3IthAXXQzEalEYhUmQgGof4
         VnZOGuHhAo3ArjiZbVsCAuRkHamkQUbzemGG5CruEBGW+whipWU8FQzl0IJ71/QxklIn
         GlCtDOkzjGGhx+WBHXyYq7xNSlu8BcunvlhUHCz6iexh5ybT8TZqKFVUYP4HAtODwHku
         0U3SkEP2zqp4/y5iA+kYvanA7/mfSfbsXVlg7nrFznd3Qk10/XTdDAjNE0ZwwcfWTycy
         471Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wzo/PiDlGOo+cTH/fo14l7EBZYsWa+LL15/tSrF9W3Y=;
        b=oBULA7RFhbvLJmXxSlWc7jXv0gc4eC1fdIdm8KHImHZcjrTAXviz8TA7gOyuRO7eJC
         PJV9s9t6ipkNFPCxg2Ra0SEEKGhMiDxOnX7w5TAz5niH1mp3oy+8RyzXteWAIiz3YM/O
         nPJf90egNjs7wQZA7KFJ/U8zYJ9TJEh49P0T7coZeu78ybW8AnrNHeMVQ49hdoE7uVJM
         dfZdSYh/lCNnrP15mUv8RGm37DuOgpkvbAyP+v0sjqCbhsABmOMkGIMNoO7BDPWvfcQa
         tai4QLKA687MEGo7si3iHvDjJxFEItD+Y6ewFUffACoInEOnzaqns6Y/ISpquZBd/4Qn
         NzFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wzo/PiDlGOo+cTH/fo14l7EBZYsWa+LL15/tSrF9W3Y=;
        b=R7oflKAuXKZjhM7iloL6SCOvIJ8/7B2eMqRNs99bYhO76YgqBgmwoTI9j1t57DjrKC
         DBxdYcXIwD9PkIjNulwoitzKqTzwa0jRUoOxqnESUPk8PNd5WA2Umx0nZc3TQ/vOoAXL
         JO0hAeChgMxEHzluz/BA/fsYkFhxvoOFj1eZGvCGIWzZyTfUMrT4NXKVZh37pAZcLsE5
         FA+5n4m+jGMNiLYnUUTnt599DvJ4A8yz4tjDKic9TXAJB4eWNnLKqMLaTuda5aY1K63o
         ruQAlW05Co1kM3H2CRsKHGEgoOH05dnrsqZvwYZ1A2iAIR5C7MFxGNWtPF2ree9tXi34
         3DVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Ik4WtCp/htHT/QNPYW56nvVrozc/Yu4v3dU1m0zx/370ECHg5
	QYGBEjXcVCG9W1t4M7mIxeQ=
X-Google-Smtp-Source: ABdhPJwyEB6zgQmJl806fVZy5xqbNGcrfSoPQB/jROKa2WWGXn8kafnWJiszCasKqXrc/mj1uAEblA==
X-Received: by 2002:a62:e90b:0:b029:30e:4530:8dca with SMTP id j11-20020a62e90b0000b029030e45308dcamr11366847pfh.17.1626451661020;
        Fri, 16 Jul 2021 09:07:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1203:: with SMTP id l3ls4958018plh.9.gmail; Fri, 16
 Jul 2021 09:07:40 -0700 (PDT)
X-Received: by 2002:a17:90b:1215:: with SMTP id gl21mr7856502pjb.73.1626451660442;
        Fri, 16 Jul 2021 09:07:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626451660; cv=none;
        d=google.com; s=arc-20160816;
        b=mYIIQ2ZmwDXphd7t0msNdwUXMM7jpBHqH0hn9RpFwcRtOj8sG79Vf5VE4PTXNueP3t
         KMUb2q237mt3m3sbU3btOuWZKTXFJs6Z9FgOscrhlFVFDjtszcQnhbIAVApn4JjtC4bI
         xiWLZgUHNMl5p616xoIFUiWs6190mP5Yk76cw0c0MggvJIHyVn527b9L9CTxACBSwMiR
         3/FhYbu7hgBqpTPSsDSkXrBbqU5BpsqOoVxsZQFVnWbe8eqkL6P2A72nqJ17+sVwSNrp
         qfq8vNv+aTDAMmI7ZJq/n466A2oJw8E7OE9/9wXFm+BVFbn0xIshXNTC7W+TQ7yS7gj8
         hqKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=7o+ZXiY1x4HxG0NX7nQFj0s+5uNTIRTu5mkV45m8eGA=;
        b=ELmYMmgULbS5lMDl4Mu4lAOeSnVqTdNpW1S6C3KCyVzA8XfHorzCi0IpAd4aRAaiAl
         jDiDP3R5wp8SjtdfoNzk0swbRKUf/H82VcOAgcNrvJgeg7qNM1yP7GbmztY8wjxasflw
         xFQqIKPy82BGP2xkxZNVTXmhUaS37GZACOI6eZrxlrizUSKEABsV1dIT2uZQ6VzppzVL
         +qqDgcEfUg7FJQP66l9Q6usy+8nx6v13BkzvL3XL43vshUec+P5ZYwlZv8xO9KepIJ1A
         /9aNH3Q4+VDslWhfEvXKtI/NrcpzForuDjSF2wYOxrsg3QZXoMBkFI8DRPIS/OQJ5PrW
         irVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id r7si1020180pjp.0.2021.07.16.09.07.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jul 2021 09:07:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m4QNH-00EEks-IT; Fri, 16 Jul 2021 10:07:39 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:59864 helo=email.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m4QNG-00DJ88-HV; Fri, 16 Jul 2021 10:07:39 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133>
Date: Fri, 16 Jul 2021 11:07:31 -0500
In-Reply-To: <87a6mnzbx2.fsf_-_@disp2133> (Eric W. Biederman's message of
	"Thu, 15 Jul 2021 13:09:45 -0500")
Message-ID: <87zgumw8cc.fsf_-_@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1m4QNG-00DJ88-HV;;;mid=<87zgumw8cc.fsf_-_@disp2133>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18CKNIyNviV1k7gAbzUP2/IleOeAtTE1RM=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.7 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMGappySubj_01,XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4972]
	*  0.7 XMSubLong Long Subject
	*  0.5 XMGappySubj_01 Very gappy subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 482 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 11 (2.2%), b_tie_ro: 9 (1.9%), parse: 0.91 (0.2%),
	 extract_message_metadata: 13 (2.6%), get_uri_detail_list: 2.2 (0.5%),
	tests_pri_-1000: 14 (3.0%), tests_pri_-950: 1.28 (0.3%),
	tests_pri_-900: 1.01 (0.2%), tests_pri_-90: 117 (24.3%), check_bayes:
	116 (24.0%), b_tokenize: 10 (2.1%), b_tok_get_all: 8 (1.6%),
	b_comp_prob: 2.0 (0.4%), b_tok_touch_all: 92 (19.1%), b_finish: 0.94
	(0.2%), tests_pri_0: 313 (64.8%), check_dkim_signature: 0.62 (0.1%),
	check_dkim_adsp: 2.7 (0.6%), poll_dns_idle: 0.71 (0.1%), tests_pri_10:
	2.1 (0.4%), tests_pri_500: 6 (1.3%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 8/6] signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
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


It helps to know which part of the siginfo structure the siginfo_layout
value is talking about.

v1: https://lkml.kernel.org/r/m18s4zs7nu.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/20210505141101.11519-9-ebiederm@xmission.com
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 fs/signalfd.c          |  4 ++--
 include/linux/signal.h |  2 +-
 kernel/signal.c        | 10 +++++-----
 3 files changed, 8 insertions(+), 8 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index 167b5889db4b..040e1cf90528 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -114,10 +114,10 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		break;
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		/*
 		 * Fall through to the SIL_FAULT case.  SIL_FAULT_BNDERR,
-		 * SIL_FAULT_PKUERR, and SIL_PERF_EVENT are only
+		 * SIL_FAULT_PKUERR, and SIL_FAULT_PERF_EVENT are only
 		 * generated by faults that deliver them synchronously to
 		 * userspace.  In case someone injects one of these signals
 		 * and signalfd catches it treat it as SIL_FAULT.
diff --git a/include/linux/signal.h b/include/linux/signal.h
index 3454c7ff0778..3f96a6374e4f 100644
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
index 2181423e562a..332b21f2fe72 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1213,7 +1213,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 	case SIL_SYS:
 		ret = false;
 		break;
@@ -2580,7 +2580,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		ksig->info.si_addr = arch_untagged_si_addr(
 			ksig->info.si_addr, ksig->sig, ksig->info.si_code);
 		break;
@@ -3265,7 +3265,7 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 				layout = SIL_FAULT_PKUERR;
 #endif
 			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
-				layout = SIL_PERF_EVENT;
+				layout = SIL_FAULT_PERF_EVENT;
 			else if (IS_ENABLED(CONFIG_SPARC) &&
 				 (sig == SIGILL) && (si_code == ILL_ILLTRP))
 				layout = SIL_FAULT_TRAPNO;
@@ -3394,7 +3394,7 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_pkey = from->si_pkey;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_perf_data = from->si_perf_data;
 		to->si_perf_type = from->si_perf_type;
@@ -3471,7 +3471,7 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
 		to->si_addr = compat_ptr(from->si_addr);
 		to->si_pkey = from->si_pkey;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = compat_ptr(from->si_addr);
 		to->si_perf_data = from->si_perf_data;
 		to->si_perf_type = from->si_perf_type;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87zgumw8cc.fsf_-_%40disp2133.
