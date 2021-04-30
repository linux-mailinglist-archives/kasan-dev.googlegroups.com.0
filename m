Return-Path: <kasan-dev+bncBCALX3WVYQORBA5MWKCAMGQEJYRPLFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 7900137042A
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 01:43:00 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id m7-20020a6545c70000b029020f6af21c77sf2314447pgr.6
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 16:43:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619826179; cv=pass;
        d=google.com; s=arc-20160816;
        b=i6kbn+NAd/g9TvxZ4BbXWj4ZgvWjzFZ8lJyVXi72lTbHPrKhgctlSp8NkKuGYVNhm5
         +cNoGp3ieuTCQXkRJzEIFxH5tzgt9b/Th3fBuNHCs94t3ncL5etURVwdLLC4s3fGEHwa
         KVnzheZ3byAB2VGyxzirFSRrR/ZfmGK3s1fie70TixIG47mEtygyvBOAuxOWrEvCEbeQ
         R+2qVbicw6buRJWsg1JtZiW6/f+S9AxynX9Ow4jhfr3Bz5kLWPtFvTmZd8kY/8xU6dLz
         gPqmSvbfA8g+S85xM39meLbDnm7sEN73SkjnXac+ncoq/loPs9kuhwDns4lqCmAvzp8Q
         Ib1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=YlBCJYAmSJLDoqqJTNLUy0bRFmr2uK5ipNm0JUy9uss=;
        b=vZI1CVuqDxXhVsjbCYYI8+dBhTJg9ffu7SrqFJQBvM4BPV/cP5QqrcqPjyygZ9aUXJ
         fQkp1z1e3tsDwwIhVvHjs7fsC22k5Fn0DqUZac6B5Mho02ms1Cjmx1ZZT9keoUe42/8x
         Tqh0hr013PIHFKTyUM5mJImvV/8lYNqRs+PX1Vd8d5CpJccfXlQKSmvS1i1QnMsauvbr
         G3KcArIZEXIsfAhwsO632mbX3H9mbhPCLJOM3xCSkoiBbmVIa1LF/bLz3YeNyVrngCOi
         AAcmVRu9nvS16XCYPef8LTmo9zq0Cge7f+xarBZkVi5DYXOOhcmtwpdkPjBsw+P4YnVo
         PFkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YlBCJYAmSJLDoqqJTNLUy0bRFmr2uK5ipNm0JUy9uss=;
        b=PSzDDv2+uzLxZaxAunagTRKXBYzBRcHxh0EHz/51LQkyK7SQ3c2kyc8PNJrB5SiaMW
         suacTXZfmtC9sxVctdlzoECJDRp+VQb8GPBIhzEK+ZVJZUJ9T/9rKBxRrFrbmNneWwYv
         +mZY1OqzyU9nph94uJU/HWcyY47I8evF+HdzQ6F4h4lJD57cxhJP7bxpQE0Xx6eUUdNf
         dYCe/f6ClHwczuuAv4eXh1CaXL+L3KF2BVOvYUv4OktBXdqhU/mWaPncTHe3si7AgbPI
         fGNjwjfZmCVkG2JgT646tK7ieQ9NdfNWp62bLSgDKl6omeHygfWPyuoNpl7yLXt1/sex
         xHog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YlBCJYAmSJLDoqqJTNLUy0bRFmr2uK5ipNm0JUy9uss=;
        b=DtbL4N1DConYS2hIxa5CBGAnzghhyuvw/HnyhSRCstPY+/zaOmIhU5HF3+/noc77gS
         R9BySE6cFHpJf+Vsx4PNMaon7KQaajAmQ7Nmrxf0XvsINp57kHWY+yTsUehEkCKeacE6
         LpmsaDoNLbZi/FFFpM9bJIqaYuzAGBNk4sbxja7sACqQN3LMhNAIkI10F434Jj6D8ooR
         6vw7RJJdTQhbFKvT05s7DWlORr4qMsW5LY8ZjlRlUud0pbuIDBqhi9eQu5kfjIuI3Rou
         Ncha6cknvGVqcsto4WaTAw8sRV2Tvmtr6HaedHxJrSWBCVkTuLhTAtsOjCHOqIYCQ404
         nfLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320W5aoCxgGZVHcGEe3RknWbLmXe3+kONx89tiVaZAQPeDst3uf
	T29Gz7XpoIlQhA5Ll/Fnpbo=
X-Google-Smtp-Source: ABdhPJxryTim1bsxhogUCn8cxd/ozFcoKYUXTIPiZYa29MIEM6VADufNw2ab6qzE1tTOZxIQNCo0Dw==
X-Received: by 2002:a17:90a:8c8b:: with SMTP id b11mr7758811pjo.236.1619826179182;
        Fri, 30 Apr 2021 16:42:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8f8a:: with SMTP id z10ls4153085plo.1.gmail; Fri, 30
 Apr 2021 16:42:58 -0700 (PDT)
X-Received: by 2002:a17:903:1cf:b029:e8:c4ca:be6d with SMTP id e15-20020a17090301cfb02900e8c4cabe6dmr7804543plh.39.1619826178397;
        Fri, 30 Apr 2021 16:42:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619826178; cv=none;
        d=google.com; s=arc-20160816;
        b=jZbkTa8STfm59+lGMYjEYXH0QgB6ndMdSfUHEov9PzC5rTGS2Nv2M/720wXYg7WkXq
         KBGELOxQXpr5uNt23ezfJSvbpWkPKI43d2Ax88lAl/xLsrYfDArmy26RzWPurIbnxRCs
         MOPQAkHfBGogRPPrBy4sNWFv16xHJxUShMj7nlvouklEKcWdmE/9RMqarKHiG1mikLXo
         vCyA0e4Qi949xtlc19y0SMeyYai/Yq9PNiU5ODVOUYCWkCt1VUekAThMuIQys1t2LxEx
         OoDvdEDV/Q/Xy8h7iAXddL/NFOabMCvjiOQnt7h6f4/PsdEnrLo1E2KzP+DlBlnHrXjI
         Vu8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=s5I+R4RUq9FVHCkDh71Kn64ttMDth8OiFszzN0AEOz4=;
        b=SwLTW4PU6ax5IYK8h/HyHgxcvmLmNOJhv238LuDKQ6F7YmurYiv4DVHKLpqjKeI4bc
         FXi93UnjBG1Da16zSRbWcL8yk6mF6z+ZtwMdDg/OUorCS9Rc/LEntsKJZHimTwPnwoTv
         9klOTPJTLj6eVtnjuFwlDadPfYNeax8EYdKr3aYzITkeYazvxAOjWzJXq/dByrLXc3hb
         IYKWHZ8c1o/yNZTtU4dc835kJCTvw8058c9kxcHOUTMlDwHYePtF3FpCzdjtsZ+o+eRs
         eSRY5aoPCNrrM3q7On5fUfMcqhDICpoPdoqqhbCviUYPWGkrRffWUXTVnRu2fltAJLUk
         zj5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id y17si634556plr.4.2021.04.30.16.42.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 16:42:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccmX-00Ctw7-Ct; Fri, 30 Apr 2021 17:42:52 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccmV-007JVW-DO; Fri, 30 Apr 2021 17:42:49 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 18:42:43 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <m1czubqqz0.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lccmV-007JVW-DO;;;mid=<m1czubqqz0.fsf_-_@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/kf+yGDzUX0CpCd2ph7fHuiNjnEXad7QU=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.7 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TooManySym_01,XMGappySubj_01,
	XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4942]
	*  0.7 XMSubLong Long Subject
	*  0.5 XMGappySubj_01 Very gappy subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1414 ms - load_scoreonly_sql: 0.06 (0.0%),
	signal_user_changed: 13 (0.9%), b_tie_ro: 11 (0.8%), parse: 1.51
	(0.1%), extract_message_metadata: 6 (0.4%), get_uri_detail_list: 2.3
	(0.2%), tests_pri_-1000: 6 (0.5%), tests_pri_-950: 1.75 (0.1%),
	tests_pri_-900: 1.48 (0.1%), tests_pri_-90: 64 (4.5%), check_bayes: 62
	(4.4%), b_tokenize: 12 (0.9%), b_tok_get_all: 8 (0.6%), b_comp_prob:
	2.3 (0.2%), b_tok_touch_all: 36 (2.5%), b_finish: 0.98 (0.1%),
	tests_pri_0: 1281 (90.6%), check_dkim_signature: 0.84 (0.1%),
	check_dkim_adsp: 2.5 (0.2%), poll_dns_idle: 0.68 (0.0%), tests_pri_10:
	4.4 (0.3%), tests_pri_500: 22 (1.6%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 5/3] signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
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
index 0517ff950d38..690921960d8b 100644
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
@@ -3242,7 +3242,7 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 				layout = SIL_FAULT_PKUERR;
 #endif
 			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
-				layout = SIL_PERF_EVENT;
+				layout = SIL_FAULT_PERF_EVENT;
 		}
 		else if (si_code <= NSIGPOLL)
 			layout = SIL_POLL;
@@ -3364,7 +3364,7 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_pkey = from->si_pkey;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_perf = from->si_perf;
 		break;
@@ -3440,7 +3440,7 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1czubqqz0.fsf_-_%40fess.ebiederm.org.
