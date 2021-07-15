Return-Path: <kasan-dev+bncBCALX3WVYQORBRPUYGDQMGQEQGVEKGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F9BE3CA505
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 20:11:18 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id b200-20020a6780d10000b029028a15393c64sf2220496vsd.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 11:11:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626372677; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mywp4NikfnmYwrOP4cgRlOlzBIJjhtGFJkNwQuyAN1zzL25ErdjLg4ERiV5w9KlodE
         wcgHK4khWbyQPGiDiHf6yVxKGGhNG7tWOEDixje5RIpDz5LzSQ9CkQtB1S/SzfX6+owh
         zWTafR5alwvlLJXRBKoOSUXFOliKpPTe+4kvsSdtRK1Z5PQSnusvfTrK9ow6dI1XXRQf
         bmBOhPfOn7Nr3DobUqU2x1x8+Zi7f20smz1+qFISIMaLEIkyLgtZ2VIuunfDdehr8Rb9
         Yra1dH1aRnc7INx8BkOlpdNFjp+3Zrh+yhUf0nEobMjOLtyIJyH4FKeD66F+W/cLFOHg
         5U9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=RBvYW6Ld87yaVtJ3u2VKu03Gq5yV6Jtqqrr4TNCed9c=;
        b=PyP1kPY7hLY5sHW+zhkdx+varIBLmlosQ7X8u0STRiet9rzJKPwaK1ZG9JBy2UqOs/
         5U0cwQTvoMkpIO20w0wzaXpFfoHZm4+PqaIdFpo7mTeyCc1ueC6Jv2WWOzzvtvGU3SUO
         D+ZuCw1LpY9c/hWela2pzwNYXtM2o8Fg4pde8GfmFWoVbHlXfm1h4D2Qry9CdlSbtqpC
         q0dSpZ8eaNchG5QZd8egbDHCbK2pqblDSmK/3PwYNy72sVXI9I0+P5zDERLisEsTsrr4
         FmkdzMCVFSaV3ORn0drowflqk4741Uwhy+IUmM5Uvue0bOv/KklxNRprJoP56N48N+xu
         GWjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RBvYW6Ld87yaVtJ3u2VKu03Gq5yV6Jtqqrr4TNCed9c=;
        b=luqMRPHNtA9jAgWmcryG0WOIw0B+4h6cv26yTLloANwfMUWt6dqyslT0879mqW2Ubm
         zZk47bmLNqD/TWxAmnHHHiY3BlBbWQBDI9/y1zmd+NgHwHgpXcTdgoT7p0EvEs9SdFee
         UlfTC3n+npYgxRi2/y/q1R0jBfk7147UmuIyauG1wdACroYQ352KzRwtzXPhbC831GOV
         8wgC+JMeWKN6bjGj6IZxwrwv1OjASnmUv+23SUUq+7hu+h+GruQHq6GjQRdCMPLyVMPy
         HCpyu4T4k9Zr1lpB0ay+GQXaTgD3uck4cBoZBzNRgv+cqgk1MAUSDdG7Pc0Sc94yrztW
         6Dbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RBvYW6Ld87yaVtJ3u2VKu03Gq5yV6Jtqqrr4TNCed9c=;
        b=qGotYrhZbb81Ghv67tKOfUcXD4XJxMDmFKnr6D5sMqOQps1/ruZOgvhENfzuVxrZQv
         feu5DIAC5JOelqdIB3UeJHIiJXeSO/8WPJooGpbDhC2dm+IFatUZTcVS7QHU/ZS/UaTa
         sv7xYqbwXuQG5sxHrpkz3wNCPQNn6R/2/eDmjN4AvqOvXGK9mf8X+H/5rP7uSqJoqMVW
         rLe1o9EuiC2hP44BbafHs4T5jfy+i0K6wlMu02XRlMPps8ztjiroi0VVk89F28FUd30B
         vZvPW6pKLn8nmZGw6Aht2gVAVQduezDD4mUf034wxD+0DGBUpcHcb7nRbvEnfsubnYAD
         i7iQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/mdoegWiVE1x0unBPMBH352tt3gGCfJWdXTI7FKyVL24asxQk
	XnMFyRJkb8uXeNo2ZUPGt18=
X-Google-Smtp-Source: ABdhPJxZZwOfN36zbjEufLuDwRxMWmQdtNmVPaUkFJ9whLuu01BvMIRoxwp7bKKg1x00jA++AV16FA==
X-Received: by 2002:ab0:378e:: with SMTP id d14mr8929182uav.18.1626372677568;
        Thu, 15 Jul 2021 11:11:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:45d6:: with SMTP id u80ls1525389uau.11.gmail; Thu, 15
 Jul 2021 11:11:17 -0700 (PDT)
X-Received: by 2002:ab0:77c7:: with SMTP id y7mr8692346uar.119.1626372677034;
        Thu, 15 Jul 2021 11:11:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626372677; cv=none;
        d=google.com; s=arc-20160816;
        b=nMTGM9LzyCYFfPHU+fVsiPhubcUBw8/NQPKt/4YhgV6YvBu9IOBKyItbGIXE6gqS+s
         LdvYKeDe86A0ecUisVudsXD/s/yw0ROVlUrSPNMchFwOUbd4+RFFY629zHlrodFJp/9W
         nkCmiaHEObPyhfKxBxT134zWLSn4+Weu/ve3o907gwpQ/6eqjuIp8w9k2OKjeFR01x+O
         iPY/nv8qfS8l4nzn31vEihkHunNXpmbCG3UJfPVShVrmBjigUh9pEilnXyB03PdtBLwC
         BoBmF0AWUmTn90ThEhadyZ68Ga4aeji6/2thUcfQE5xC3f+Ipg+SXDBoW9rI58kBAqAd
         Uzpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=mzT/B7KrHYXD6QnNvLTVM/hH7rM8cTmezvcQu11FtA4=;
        b=J9mVIuhDJvhJ8/Uj+mGVIW5M9Dx7jOMEdrjah0PhsEoB+MTr+yiHDhGi9Pajultfsj
         xIHHV7RoQUaqOcUubhO+YMYz7wRJk6F9fL5M52B/JCHUsXIH903o912EOXp0bD8YqEvc
         J0rot/o5nqmrHPdSxSC9rCHOTVSjApU4UfuTNJdvseYx3fOBXT7Uvu0+ihNDIgWv0A7U
         P1Ue2czWZIMEw+Fo16YNYmpVb0Ws+jIPeNimUTwt99DT0oXOAr4KfJCpagP88kIm/0z8
         at/KAckDbluHJ8fFNl8Qe5rCKMHnH62/N7MpIBZ5F2V03Pbx6KOxal/dm8lX1A0uaUlL
         txTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id p66si232997vkg.1.2021.07.15.11.11.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jul 2021 11:11:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45pJ-009SpU-G8; Thu, 15 Jul 2021 12:11:13 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:57000 helo=email.xmission.com)
	by in01.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45pI-00CT5W-8X; Thu, 15 Jul 2021 12:11:13 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133>
Date: Thu, 15 Jul 2021 13:11:05 -0500
In-Reply-To: <87a6mnzbx2.fsf_-_@disp2133> (Eric W. Biederman's message of
	"Thu, 15 Jul 2021 13:09:45 -0500")
Message-ID: <874kcvzbuu.fsf_-_@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1m45pI-00CT5W-8X;;;mid=<874kcvzbuu.fsf_-_@disp2133>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18a4jAe8ApXzxWke88h7F8ue9rCS+qLdbk=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
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
	*      [sa03 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_02 5+ unique symbols in subject
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 556 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 4.2 (0.7%), b_tie_ro: 2.9 (0.5%), parse: 1.21
	(0.2%), extract_message_metadata: 15 (2.7%), get_uri_detail_list: 2.5
	(0.5%), tests_pri_-1000: 13 (2.4%), tests_pri_-950: 1.05 (0.2%),
	tests_pri_-900: 0.85 (0.2%), tests_pri_-90: 102 (18.3%), check_bayes:
	95 (17.2%), b_tokenize: 10 (1.8%), b_tok_get_all: 8 (1.4%),
	b_comp_prob: 1.54 (0.3%), b_tok_touch_all: 73 (13.2%), b_finish: 0.68
	(0.1%), tests_pri_0: 408 (73.4%), check_dkim_signature: 0.42 (0.1%),
	check_dkim_adsp: 2.2 (0.4%), poll_dns_idle: 0.56 (0.1%), tests_pri_10:
	1.74 (0.3%), tests_pri_500: 6 (1.0%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 1/6] sparc64: Add compile-time asserts for siginfo_t offsets
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
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

From: Marco Elver <elver@google.com>

To help catch ABI breaks at compile-time, add compile-time assertions to
verify the siginfo_t layout. Unlike other architectures, sparc64 is
special, because it is one of few architectures requiring si_trapno.
ABI breaks around that field would only be caught here.

Link: https://lkml.kernel.org/r/m11rat9f85.fsf@fess.ebiederm.org
Link: https://lkml.kernel.org/r/20210429190734.624918-1-elver@google.com
Link: https://lkml.kernel.org/r/20210505141101.11519-1-ebiederm@xmission.com
Suggested-by: Eric W. Biederman <ebiederm@xmission.com>
Acked-by: David S. Miller <davem@davemloft.net>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 arch/sparc/kernel/signal32.c  | 35 +++++++++++++++++++++++++++++++++++
 arch/sparc/kernel/signal_64.c | 34 ++++++++++++++++++++++++++++++++++
 2 files changed, 69 insertions(+)

diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
index e9695a06492f..65fd26ae9d25 100644
--- a/arch/sparc/kernel/signal32.c
+++ b/arch/sparc/kernel/signal32.c
@@ -745,3 +745,38 @@ asmlinkage int do_sys32_sigstack(u32 u_ssptr, u32 u_ossptr, unsigned long sp)
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
+static_assert(offsetof(compat_siginfo_t, si_addr_lsb)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_lower)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x18);
+static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_perf_data)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_perf_type)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
index a0eec62c825d..a58e0cc45d24 100644
--- a/arch/sparc/kernel/signal_64.c
+++ b/arch/sparc/kernel/signal_64.c
@@ -556,3 +556,37 @@ void do_notify_resume(struct pt_regs *regs, unsigned long orig_i0, unsigned long
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
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x18);
+static_assert(offsetof(siginfo_t, si_lower)	== 0x20);
+static_assert(offsetof(siginfo_t, si_upper)	== 0x28);
+static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);
+static_assert(offsetof(siginfo_t, si_perf_data)	== 0x18);
+static_assert(offsetof(siginfo_t, si_perf_type)	== 0x20);
+static_assert(offsetof(siginfo_t, si_band)	== 0x10);
+static_assert(offsetof(siginfo_t, si_fd)	== 0x14);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/874kcvzbuu.fsf_-_%40disp2133.
