Return-Path: <kasan-dev+bncBCALX3WVYQORBY56YGCAMGQE5RHPVMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id B68DC372177
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:39:00 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id v3-20020a0ca3830000b02901c56555f64bsf1748777qvv.1
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:39:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074339; cv=pass;
        d=google.com; s=arc-20160816;
        b=vvmUuUP9Z8qr0CIw8ckL6BAbaNQKqTU0OANyatHm/fgRe8wW0i0i9AFnACxS86aote
         V7/xuktNiqfV5J7Y/vkpxG0nJHICxN2FrXcVPavAcqqe98SsznMRs1uWsm2oUamObSp1
         7WLAh6tvKP/ffm3NIzIZzpNXs7Iq3Nube2Dux0RxLS4BQD4Os8wMKpCrJbnYq53gYPUj
         zDALdpbwiQexJEp3ObcS59m/13aBEW628YBy3qxkHpEpnjJ/34u8YH6ywNP1XIN144/O
         dwrk9NWP2QOIAccsmxbvqtCCkksTNEYIWpNMP/iZzn5eWlsokGyNXtJMx8Q5xhmwYIyP
         GhVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=Z/4teEQ8LDJyOGW20HXEPrAjo/9S0k+uFyO+dRmfRtE=;
        b=wXKa1P6BOU9cU4H7Q53Ai56+2/OcGlLz4m51hYrasVUcygKYtvnyzQyrFOHRNfZQtD
         RR9KtIJXDzvGlwlGy2VqTkVhx8oYQ3BltU3ZNXlr1CwodiUkr2jbSeUwXHmVPGRrO63W
         mCDb8kAhWJg2fEOm2BvYI6W8+UeAfWIV7NmRMVxmJ4mrj7s5cuWgn55L9uXWtzGztQs7
         e6kNhu1sX5Oztuh7D7J3H8KS2N4l2qSxI7wsaPADO2d8l3/vA5dnEgr0Rziu7zRAaQJI
         KzQq05zeuuaeZKzaHsKAoonjCqYcCBfiBk4VfBjYvn4rNr2HomAuSchR0blGHlTa54tR
         4NOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z/4teEQ8LDJyOGW20HXEPrAjo/9S0k+uFyO+dRmfRtE=;
        b=axPK7hYZGLa+67pBq+dGiyCk+jpamS4Z+LwQJPgF32VBpIRdnB+8zut874xQsbJYwO
         pLskKxWqksGNq5mPbCvqB2qnVzrVpeNwAl4ywCDS1h9q2ClD3VfhIPS0WGncVPT4xeZG
         8y35B76l0GycDHJ8y3CTpS+9PYQwDSkZH5Ics9Z0eTDuEnYExRdr2Cp3sGQt3vEQOcFL
         1Tm758etOiD1i16ahjlP2RRI0ey8cu5DE4w6dPBzcg8s6ZACpqvxfk09OlQgl2vN66cF
         0X+lNNLaBDMeq0qvHfk402sDcIQC6XUeLhxFfShT+g1r1iVuOY9o7ioV5oOy8woJdMIx
         6rWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z/4teEQ8LDJyOGW20HXEPrAjo/9S0k+uFyO+dRmfRtE=;
        b=HRe0JPX6nE4yjWFNXfmCJwSxBGofcomZfy28GQ/l9zYpKZnGOGu/9MF5Wp80zAExob
         LwS4fwfFQdvOLA+I26tQ8PrBGEjV5qEGoCfILfHYPNARih9cwY2BJNC9rb6GHEC23TXV
         uF+VR92jx+YwqsT1p9kuFCP8LXSPLqciP7GaIJ4mXQ7GoKji0Z0myU5GOpHuktxzGY9f
         pJvJZFbqzxlAXLepGgSrc35K6/BLZXEPqxY49MfmptLnU9jCmWP6AwVh2OFku9SPKem4
         b/kuIjtIcup18gfOEFWfEnuL2VC94u03XKBdnFZIrZhL+FeUTQ6K2IBCK/W58crADeu9
         DW2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lm649GJM1E3mXmmwqbzi+6JuMRtqjf6/ypJmEMPLvfG8Nx+WQ
	gN6WfE4D5+wk2oiW1Q5f+l0=
X-Google-Smtp-Source: ABdhPJzZI5c3x+33KvwzBOIym0gg/SziiW/KoZ0k4RP12PIEH5r7R8x/+mqLk3SP7s9mADlx03bGsg==
X-Received: by 2002:a05:620a:2089:: with SMTP id e9mr21796369qka.85.1620074339840;
        Mon, 03 May 2021 13:38:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f20e:: with SMTP id m14ls9000863qkg.8.gmail; Mon, 03 May
 2021 13:38:59 -0700 (PDT)
X-Received: by 2002:a05:620a:228b:: with SMTP id o11mr20887554qkh.489.1620074339410;
        Mon, 03 May 2021 13:38:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074339; cv=none;
        d=google.com; s=arc-20160816;
        b=OBvaqnZYL1Z75CIWblR4Rm1gFbNL6uCGGmk1qVsUMaiHcVZ/kdE+JZ04huNhvspHKS
         B8Mb8eftBApMoyqAADh+7xn6AdE7OlcXuZAZS172Mfbe+qFNIFQ3MHB+08x/px+dsyDn
         dUnmxG/Sk33eUmRgmnkvJjGYiGutoOSq8M8eBrxoN+fv0bFGePfwF6q++kQriGBlU9W0
         QkxkHbR3YvlWj0OoEfXJqBnfXv5mNY3AQ9LY7qRPVdw5F1dvHdP1MTVzHz2Hh0879NKz
         TymAIbHoinWBbKdVNeX5qehXbhbbRvPBx6T32wb49Od9LI4+QYUlVraH82VfkzRTUXXO
         yFpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=dn7AvFl/JnkAuhxQgsh+STg+HqsuBRo/BtQuioqDot4=;
        b=FlpQr3l2Gwq3Dcx+kqiJz2VxqYee7r2OYA5dz+TPnoRhJSWEYUjfDBMAkWdICV+d7J
         omI9uTI/k2oUjxkSe70ux4mbxT8BW0F0K+vS+j/yt7mNZxRuopyY6Ws6+cnCLVytp5u6
         TGoE9/VuKVMvR8UaSDgKcj4L7cLgxGr1INbqdlQ3rwEP4X7eVtRjyhwO19DF1FHMSTyf
         YP5wQ1H3VDBKwM7GmB8T79AqXT4JwL4cq622cI9t96QpulH0u2fSsC6oQreSM61PBKcp
         B6XP933em1rr5ZTV+Dnbzm7tvXAtGNuf0+2WVIlUDvzfOTjA85yHGpiAigPBIBQl6RGZ
         DENQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id c26si77489qtq.1.2021.05.03.13.38.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:38:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLF-00Gyht-Nu; Mon, 03 May 2021 14:38:57 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLE-00E76Y-EF; Mon, 03 May 2021 14:38:57 -0600
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
Date: Mon,  3 May 2021 15:38:05 -0500
Message-Id: <20210503203814.25487-3-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210503203814.25487-1-ebiederm@xmission.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfLE-00E76Y-EF;;;mid=<20210503203814.25487-3-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18aqVjhVCfZ9EPyVLBUkpnE5ieCrnKAZ+w=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa01.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	T_TooManySym_02,XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa01 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.0 T_TooManySym_02 5+ unique symbols in subject
X-Spam-DCC: XMission; sa01 1397; Body=1 Fuz1=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 652 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 3.9 (0.6%), b_tie_ro: 2.7 (0.4%), parse: 0.76
	(0.1%), extract_message_metadata: 9 (1.4%), get_uri_detail_list: 1.90
	(0.3%), tests_pri_-1000: 11 (1.7%), tests_pri_-950: 1.05 (0.2%),
	tests_pri_-900: 0.83 (0.1%), tests_pri_-90: 219 (33.5%), check_bayes:
	217 (33.3%), b_tokenize: 9 (1.3%), b_tok_get_all: 7 (1.1%),
	b_comp_prob: 1.35 (0.2%), b_tok_touch_all: 197 (30.2%), b_finish: 0.72
	(0.1%), tests_pri_0: 395 (60.6%), check_dkim_signature: 0.43 (0.1%),
	check_dkim_adsp: 2.4 (0.4%), poll_dns_idle: 1.04 (0.2%), tests_pri_10:
	2.4 (0.4%), tests_pri_500: 7 (1.1%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 03/12] arm64: Add compile-time asserts for siginfo_t offsets
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-3-ebiederm%40xmission.com.
