Return-Path: <kasan-dev+bncBCALX3WVYQORBBWPZKCAMGQETSEXXQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D9D2373D25
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:19 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id l5-20020a0ce0850000b02901c37c281207sf1735368qvk.11
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223878; cv=pass;
        d=google.com; s=arc-20160816;
        b=JuQQwqw16WtCccaednutSfrgHzY332LX4zan35cwmOCGIK/BtIveTFQVcw+zW2HxQK
         LCn+EE6YznF8xpYSk4+I2ycBGNjUk9FsafVoY3o2a3BQfj4ZeMRN3ismnRcNDLpUSjJg
         lWlJuBuLHCMDQtWQM2vUHn7qEvn408IVfAxcMUKDKz1tZMRrs86e8EzhKzTWxQJHIet6
         sMxJRY1p7l0dn0qp1Gg85lSCcYvwkzmWwXB1otRnXFjHbmNnGmCCy6vUrucNF8uZAFyP
         oSU5ixn5edmYen25eGzVW7D6UBuLcotKRqMyKvLKMxaMUB+P94E8b0jm2ZSTgMytG/6z
         ffJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=yNAUyhpa/Dlk7uls35DBKRnLW++im6Gyipj6Ve93i+g=;
        b=hD82CSkBaFa76zjUoLzbUKxpdZxhv33i5JM1zLqgvFHr/V0oDfQqb+0PFjVetygT5A
         Dm7boYNH/jtDcBz4jcM3ZYTyBMY4SqlooRCtWoqADDTfzKnqJkNWUlIGLLrSKwL9OHeh
         Af0Qu8rIlFxZkHfVpjRJqllxiufoiFA1ejz+FCHNV0e49dgZTB34R4kO5AZ8nwUOF05A
         TC80ACStPaaxTcLLISPdae6q5yWvG1wTiesFN0l4Xmva9GknTv0bH1UvEeUjuy1z2ZSw
         qCaXVHW/k585Un8c355clhWElWOai3wbjkwnVYNyRbQensWo7k29LZn96Lq6Pf77NpDa
         FQuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yNAUyhpa/Dlk7uls35DBKRnLW++im6Gyipj6Ve93i+g=;
        b=gnCn5IO425gybgjM6wzZintPtIy/aIfEb/IFiO2MhP6ukqMRRrQHlOpVjwnBLU2v3e
         XqGVAlbCF5J3v36RO87puS4PplF9Uc2PqO7AXZclkA5B/uG4+NcD7RP3WgPBdgn4GaJD
         jGzmlqNC/v0hruqUl743DxkwXwWbJbVP4tyPS/qRiBoLlWsB7PLewC7JYc80peDRV9aj
         6HgH1xUUMP8VfzjPECl/RVFx5jag3CT/R8PGb+NEcDkr0Dl1zMnp6UE83UYGkbcUiH+X
         fSuIeu89w9HPMeO74Tf9E2YBirBLsgRa3QruNzBei5BygQtccmZ8YD0YbU9buvXZyOgz
         ebuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yNAUyhpa/Dlk7uls35DBKRnLW++im6Gyipj6Ve93i+g=;
        b=qxmk5VWYBqcJmKl7jj47uhwGlMeXOSBaEpwR0SEGZJ31j+ylXj3yQPwBlY5bxYphtt
         E2niqi8ZUyboi31LsCUtck/FNCH5WUn+4xUMxsxXdhfrQfB0e9Gcrq9Eb6OrGARaifRg
         36DErpodpA/vhm8fmEGfGHiCpeqlJBUp3VRR7X+ut6iIu6NQFxPuCIG6zDBb71NgusNS
         1Zk0/onYumsBfkOLMYqmneeDXAJ7ha+qJCoUS5wQG53P4AEyTUk8CbWxDITc54n//h3w
         Ft+fXvYsGwQE4Th5MgC2leeP8ALByuTZRUFJXUFm03OH68hU9d2wWFtrr/3RAR9sPViO
         zlSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GvlwkyNadu+99hOUDtElLUx44WtVgs2FhfBuXjewB7cQcVSCg
	46XwS5NXl8o/8A9AY9aPv1A=
X-Google-Smtp-Source: ABdhPJw9oo9+/gvk8FmVaaRPUXElHDsXk1qLlT1DTc+fY76tOV9zvCf1pP5q70MMmAYvdwjurwPxDA==
X-Received: by 2002:aed:314c:: with SMTP id 70mr20920806qtg.364.1620223878162;
        Wed, 05 May 2021 07:11:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7681:: with SMTP id r123ls4407060qkc.6.gmail; Wed, 05
 May 2021 07:11:17 -0700 (PDT)
X-Received: by 2002:a37:9ec4:: with SMTP id h187mr13859737qke.200.1620223877716;
        Wed, 05 May 2021 07:11:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223877; cv=none;
        d=google.com; s=arc-20160816;
        b=bgNIhRuXcqs7pUbaq8g8lcPIymqcH4AJT/nb9Or5Mq8s2QfZxkne5Yo0OL4XWhOi5k
         PEfgfLLjcuYyIS7huqnPurixTE+0BZj6DhAfISvyLrDBF6mMPleSIsz0qUl7pMZDAaaW
         B28aM3/Og8a06L53Cml4OeJ9XfQuUFKYKf4q7Fj+kTC8tXAsk2B2a5j0kOwbbVon5GAq
         av70uJ0/U9C0fD3Yt2FukHtOTuxviYM92KmbtNC8LJ9RxR/5j4HBTn7jHy1Xqk2g/Afw
         f8tQokzrEQKHXC47hqqh/Uy8fyfRPxbm6rL5eyg8h4NS0fv0H8CK4yelacy1idicMDqK
         T5PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=dn7AvFl/JnkAuhxQgsh+STg+HqsuBRo/BtQuioqDot4=;
        b=udQXea4ch6PudzKSZrCKmYua8Oo5jeg/9o+kn7wnKupD7uyZopLxsnPt3kCSev1N1Y
         wNEnPXVppLMRMFZJceVftWSITvX2NGG+AhSD9Ls072xfTYRcf23TFDBYli4D1arKhW1y
         h6xU8rgM6ewQE3rdlSi0BM1U7wTUfpfl01ptRS/q2EJLaRniyaJlwLgf/QCaIeSyJbZm
         +Zk0HohgSsR4ogn3lG9aiCEK1MdUzDVqbm+9Xddwhf4duEmlNf/FvhHt9Z2C9U+M/Scn
         oy/xUdAKM9hjZlbr94vQsOgGbDJavgIoAsxjs9Hnp2mlckTbUYPjWyDmmOHK4lMg6l1W
         wSaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id k1si907807qtg.2.2021.05.05.07.11.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFA-002t7g-4X; Wed, 05 May 2021 08:11:16 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIF8-00007y-RE; Wed, 05 May 2021 08:11:15 -0600
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
Date: Wed,  5 May 2021 09:10:52 -0500
Message-Id: <20210505141101.11519-3-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIF8-00007y-RE;;;mid=<20210505141101.11519-3-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+Y8qFMI5/OgNAO5HO1YL2oS8W5frXUgSc=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	T_TooManySym_02,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.0 T_TooManySym_02 5+ unique symbols in subject
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 540 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 3.7 (0.7%), b_tie_ro: 2.6 (0.5%), parse: 0.77
	(0.1%), extract_message_metadata: 9 (1.7%), get_uri_detail_list: 1.85
	(0.3%), tests_pri_-1000: 12 (2.2%), tests_pri_-950: 0.98 (0.2%),
	tests_pri_-900: 0.92 (0.2%), tests_pri_-90: 114 (21.2%), check_bayes:
	113 (20.9%), b_tokenize: 9 (1.7%), b_tok_get_all: 6 (1.1%),
	b_comp_prob: 1.85 (0.3%), b_tok_touch_all: 93 (17.2%), b_finish: 0.66
	(0.1%), tests_pri_0: 385 (71.4%), check_dkim_signature: 0.42 (0.1%),
	check_dkim_adsp: 2.0 (0.4%), poll_dns_idle: 0.73 (0.1%), tests_pri_10:
	2.9 (0.5%), tests_pri_500: 7 (1.4%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 03/12] arm64: Add compile-time asserts for siginfo_t offsets
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
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

From: Marco Elver <elver@google.com>

To help catch ABI breaks at compile-time, add compile-time assertions to
verify the siginfo_t layout.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 arch/arm64/kernel/signal.c   | 36 ++++++++++++++++++++++++++++++++++++
 arch/arm64/kernel/signal32.c | 36 ++++++++++++++++++++++++++++++++++++
 2 files changed, 72 insertions(+)

diff --git a/arch/arm64/kernel/signal.c b/arch/arm64/kernel/signal.c
index 6237486ff6bb..af8bd2af1298 100644
--- a/arch/arm64/kernel/signal.c
+++ b/arch/arm64/kernel/signal.c
@@ -973,3 +973,39 @@ void __init minsigstksz_setup(void)
 		round_up(sizeof(struct frame_record), 16) +
 		16; /* max alignment padding */
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
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x18);
+static_assert(offsetof(siginfo_t, si_lower)	== 0x20);
+static_assert(offsetof(siginfo_t, si_upper)	== 0x28);
+static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);
+static_assert(offsetof(siginfo_t, si_perf)	== 0x18);
+static_assert(offsetof(siginfo_t, si_band)	== 0x10);
+static_assert(offsetof(siginfo_t, si_fd)	== 0x18);
+static_assert(offsetof(siginfo_t, si_call_addr)	== 0x10);
+static_assert(offsetof(siginfo_t, si_syscall)	== 0x18);
+static_assert(offsetof(siginfo_t, si_arch)	== 0x1c);
diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
index 2f507f565c48..b6afb646515f 100644
--- a/arch/arm64/kernel/signal32.c
+++ b/arch/arm64/kernel/signal32.c
@@ -457,3 +457,39 @@ void compat_setup_restart_syscall(struct pt_regs *regs)
 {
        regs->regs[7] = __NR_compat_restart_syscall;
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
+static_assert(offsetof(compat_siginfo_t, si_addr_lsb)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_lower)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x18);
+static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_perf)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_call_addr)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_syscall)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_arch)	== 0x14);
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-3-ebiederm%40xmission.com.
