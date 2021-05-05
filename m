Return-Path: <kasan-dev+bncBCALX3WVYQORBAWPZKCAMGQEFHWLKQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE092373D1F
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:15 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id h4-20020ac858440000b029019d657b9f21sf1119738qth.9
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223874; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwkvzoEhoFwA8MmJuVzzUNdhDHDRgcYnsyjMxQb7VPAMVD3HqLDUPBJQmI6bo9Hnl3
         bAXPuHQovEbpo9siYOx7qUW1rHmXrW0phsK/yrXPQSqJ3iaCsyxw0t4F9otTqEh+l9ox
         VMlUYqFdI4HupdLlyTmbErvtNLr6Jjx6p+/uuF1xS/0jeS9YH8aMohniRvZjCHWe1Hl1
         CEpZAOoSq3dnb/ZwcmucE9+g+iOVcxrUZojJzcWUqibJ3jENWwBkU1ya9AqlLD7LoSI/
         V5p5JqexpbCziT+ITQ7z2iqsVrjzhA2Xv9JPElBE9SrMvBPLPnW53b4eHl8OyW5ZbIwI
         Te4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=U9UjihFOZyi6tlNc7dNJUGvnRcBo3po82RLWib/tCdQ=;
        b=sSjuXtlk2S7Mi7aQP0JdSgyMgtZDfecfPLpJLFVbR5655fP9YotK42eZP+hbh1bqey
         DSrxbqVgrSrfc2ykTeB6H1fJiZCeCg3Iosw9WccevzMtCkIUDgY+buHhzqCTFT7JcTBY
         KEaG/lRB0upO7eSHHnIE0+M3q2oPU+MLNywX9EeQB63Prh7h1ozl+0fgC1XaBfcVgmz8
         J94WKGQIps1Z50dFFcR1cV64G48WyTI9pEpW5byMk3KnwUxS7WwBqszP61wAaQMd/T8I
         rkGzTu6SUcvjnqoz1Zp5fulmcnpxK21ME+ghQcPQH5SLQPrzSOMaNCEMz7403xspCMql
         4CXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U9UjihFOZyi6tlNc7dNJUGvnRcBo3po82RLWib/tCdQ=;
        b=Bzdfz9OAZ5YLzCX/bKpuCUXpe1aqe1O8d+iL3ajM/kbFZ09LTImXC1G5QntLrsk5oH
         EpQ/vGhqShTwqhLzbFQPWdARcvi+pbaEblt2yqbyzQg4tCeIf+gdCOTYKNOg3iZmUCJE
         e6O0HxWF4rBrQtmY0X6cU7+HAAOx1Spw9TFRlmuec6m+sLVmfDmdbBT7kmvBQUwPBgVC
         bQzlJUmwRyeMg0xU/rpNaV4rx1/x1striVMNQ5FHDh6k26C9SPB8xoh/I5ZgGrR58eDE
         3hI6Ued1HYssMrWEtDCL6z2gmD3JOEQN9QEfllNcjpyp69s2NuZJ3sqLgrS2xuudJYrS
         SKcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U9UjihFOZyi6tlNc7dNJUGvnRcBo3po82RLWib/tCdQ=;
        b=k2ySw5AVXXNrj4p/lGCXoKzVS38S7XMHM04TvxKsdendfsWuKwYjMoLRuuVJk112al
         jO7p/P5hBTNupSDWUP6TdKgboYpytMb2vaztfRY69Yr2lJ9GU0QXbybtrjd7lP0dArl3
         IjZeSibNZzckVXvrHhxAk3xl+pzL0MmJvgMfsscSYGVoir669KGU/n7XN2DhQCKLIfb1
         3A2+4SGQJ3KTSub3Z2sEewzgNXYzIdKUdW532En0n2q/uGC1EUqs6bIrvIRCfLQ6Ocmm
         ULphep6lDznajS1WC0UJTdz+ZtCmPBdJcdo5fMbwYui91HoUrl/eEUMrA1M7shEkcmGV
         tKSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315JyoTdTYZhpMarHHMCsJOLmWGrT6pejvwZk3I2dU7aCdBvawt
	ZswgH/UuTGmC9IBcso36FwM=
X-Google-Smtp-Source: ABdhPJzRHwA22/VbXIRe7h6/x8cWoHGJTeqx3zBvihmYFnvelWxwQAJo+YzkfFpdC4sz/UxFPxfhPQ==
X-Received: by 2002:a05:620a:70e:: with SMTP id 14mr30610082qkc.278.1620223874670;
        Wed, 05 May 2021 07:11:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f28a:: with SMTP id k10ls6380795qvl.3.gmail; Wed, 05 May
 2021 07:11:14 -0700 (PDT)
X-Received: by 2002:ad4:4f82:: with SMTP id em2mr31224241qvb.55.1620223874093;
        Wed, 05 May 2021 07:11:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223874; cv=none;
        d=google.com; s=arc-20160816;
        b=0wflIWZ00YnIquVwG/vp8Tco0FrixduHOWv9/qB5fF3cZyuQi2n/+exHrmolT9PplU
         XsewUy8FLNO036BXgqFtq8uLA4/CGRIRlYb2/9UJruyNqYL2zLWFBxFtRim8csh7rXPD
         kTk0wjE7hwmWYEbwKNfzPMyOxMyS6ZeEUZKNRsy7WOosG9nZ5VPZPJLjEqDMORZJCe+g
         ry3odGAiU2i9m2u9PQ3QNMLPeMp1Wzl4T9kWmrDifv8e9BOjBBqU7RY27CBZAGRQOV6S
         MXLn6pJEfz/hQUwJQu+iA1kJl+Em1wL5NROjnZlF7oJCqHLP17Kar5vohxCnOQCTK0oW
         rMSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=CyskUuvvhXODkGP4ciR0aasP5HyyA8WbvwLPbiDDhfc=;
        b=rLztQKhkc9loBBA6RHbTDQSqhE/5JXNCeo+J7Iqqm0FNqlhXX8vUvcvJU6/6g3xP6R
         VCv7uA34YzPSTOjrRmnATKvWCtx/Pa5Y/fK2eTCuoDJaKjeXvayGftrpkxyABsNxibsm
         pCcAOAze2xMLB+bnjVlNUGmI3FdQK9/D8qi51eBy0E+2KYyVDtS+YAu1lfSUtG9KkEgI
         x9n4JjpO2oQnzRvEaZhV/vjUSufEAtCMdjFp7LLStZhJTgIRGcdqfKy8yb1LBj+VoSR0
         pCidZVc+0LpCp4WZ4Up3gbSSh6Xw1T3DVObdwrsCOgZ9BfuDp61jCJDNT2OvOwnZ5o7Q
         lr2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id g22si162522qtx.4.2021.05.05.07.11.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out03.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIF4-00CGM5-7L; Wed, 05 May 2021 08:11:10 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIF2-00007y-JL; Wed, 05 May 2021 08:11:09 -0600
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
	"Eric W . Biederman" <ebiederm@xmission.com>
Date: Wed,  5 May 2021 09:10:50 -0500
Message-Id: <20210505141101.11519-1-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
MIME-Version: 1.0
X-XM-SPF: eid=1leIF2-00007y-JL;;;mid=<20210505141101.11519-1-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+YennuAj8fnPcv5xPYkUhr4IS6Rpjrrvw=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	T_TooManySym_02,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.0 T_TooManySym_02 5+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1146 ms - load_scoreonly_sql: 0.07 (0.0%),
	signal_user_changed: 11 (0.9%), b_tie_ro: 9 (0.8%), parse: 1.77 (0.2%),
	 extract_message_metadata: 26 (2.3%), get_uri_detail_list: 4.6 (0.4%),
	tests_pri_-1000: 23 (2.0%), tests_pri_-950: 1.96 (0.2%),
	tests_pri_-900: 1.70 (0.1%), tests_pri_-90: 271 (23.6%), check_bayes:
	268 (23.4%), b_tokenize: 21 (1.8%), b_tok_get_all: 9 (0.8%),
	b_comp_prob: 3.3 (0.3%), b_tok_touch_all: 231 (20.2%), b_finish: 0.98
	(0.1%), tests_pri_0: 787 (68.6%), check_dkim_signature: 0.95 (0.1%),
	check_dkim_adsp: 2.7 (0.2%), poll_dns_idle: 0.43 (0.0%), tests_pri_10:
	3.8 (0.3%), tests_pri_500: 14 (1.3%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 01/12] sparc64: Add compile-time asserts for siginfo_t offsets
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as
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

From: Marco Elver <elver@google.com>

To help catch ABI breaks at compile-time, add compile-time assertions to
verify the siginfo_t layout. Unlike other architectures, sparc64 is
special, because it is one of few architectures requiring si_trapno.
ABI breaks around that field would only be caught here.

Link: https://lkml.kernel.org/r/m11rat9f85.fsf@fess.ebiederm.org
Suggested-by: Eric W. Biederman <ebiederm@xmission.com>
Acked-by: David S. Miller <davem@davemloft.net>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 arch/sparc/kernel/signal32.c  | 34 ++++++++++++++++++++++++++++++++++
 arch/sparc/kernel/signal_64.c | 33 +++++++++++++++++++++++++++++++++
 2 files changed, 67 insertions(+)

diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
index e9695a06492f..778ed5c26d4a 100644
--- a/arch/sparc/kernel/signal32.c
+++ b/arch/sparc/kernel/signal32.c
@@ -745,3 +745,37 @@ asmlinkage int do_sys32_sigstack(u32 u_ssptr, u32 u_ossptr, unsigned long sp)
 out:
 	return ret;
 }
+
+/*
+ * Compile-time assertions for siginfo_t offsets. Check NSIG* as well, as
+ * changes likely come with new fields that should be added below.
+ */
+static_assert(NSIGILL	== 11);
+static_assert(NSIGFPE	== 15);
+static_assert(NSIGSEGV	== 9);
+static_assert(NSIGBUS	== 5);
+static_assert(NSIGTRAP	== 6);
+static_assert(NSIGCHLD	== 6);
+static_assert(NSIGSYS	== 2);
+static_assert(offsetof(compat_siginfo_t, si_signo)	== 0x00);
+static_assert(offsetof(compat_siginfo_t, si_errno)	== 0x04);
+static_assert(offsetof(compat_siginfo_t, si_code)	== 0x08);
+static_assert(offsetof(compat_siginfo_t, si_pid)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_uid)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_tid)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_overrun)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_status)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_utime)	== 0x18);
+static_assert(offsetof(compat_siginfo_t, si_stime)	== 0x1c);
+static_assert(offsetof(compat_siginfo_t, si_value)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_int)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_ptr)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_addr)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_trapno)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_addr_lsb)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_lower)	== 0x18);
+static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x1c);
+static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x18);
+static_assert(offsetof(compat_siginfo_t, si_perf)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
index a0eec62c825d..c9bbf5f29078 100644
--- a/arch/sparc/kernel/signal_64.c
+++ b/arch/sparc/kernel/signal_64.c
@@ -556,3 +556,36 @@ void do_notify_resume(struct pt_regs *regs, unsigned long orig_i0, unsigned long
 	user_enter();
 }
 
+/*
+ * Compile-time assertions for siginfo_t offsets. Check NSIG* as well, as
+ * changes likely come with new fields that should be added below.
+ */
+static_assert(NSIGILL	== 11);
+static_assert(NSIGFPE	== 15);
+static_assert(NSIGSEGV	== 9);
+static_assert(NSIGBUS	== 5);
+static_assert(NSIGTRAP	== 6);
+static_assert(NSIGCHLD	== 6);
+static_assert(NSIGSYS	== 2);
+static_assert(offsetof(siginfo_t, si_signo)	== 0x00);
+static_assert(offsetof(siginfo_t, si_errno)	== 0x04);
+static_assert(offsetof(siginfo_t, si_code)	== 0x08);
+static_assert(offsetof(siginfo_t, si_pid)	== 0x10);
+static_assert(offsetof(siginfo_t, si_uid)	== 0x14);
+static_assert(offsetof(siginfo_t, si_tid)	== 0x10);
+static_assert(offsetof(siginfo_t, si_overrun)	== 0x14);
+static_assert(offsetof(siginfo_t, si_status)	== 0x18);
+static_assert(offsetof(siginfo_t, si_utime)	== 0x20);
+static_assert(offsetof(siginfo_t, si_stime)	== 0x28);
+static_assert(offsetof(siginfo_t, si_value)	== 0x18);
+static_assert(offsetof(siginfo_t, si_int)	== 0x18);
+static_assert(offsetof(siginfo_t, si_ptr)	== 0x18);
+static_assert(offsetof(siginfo_t, si_addr)	== 0x10);
+static_assert(offsetof(siginfo_t, si_trapno)	== 0x18);
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x20);
+static_assert(offsetof(siginfo_t, si_lower)	== 0x28);
+static_assert(offsetof(siginfo_t, si_upper)	== 0x30);
+static_assert(offsetof(siginfo_t, si_pkey)	== 0x28);
+static_assert(offsetof(siginfo_t, si_perf)	== 0x20);
+static_assert(offsetof(siginfo_t, si_band)	== 0x10);
+static_assert(offsetof(siginfo_t, si_fd)	== 0x14);
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-1-ebiederm%40xmission.com.
