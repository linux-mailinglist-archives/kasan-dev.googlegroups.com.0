Return-Path: <kasan-dev+bncBCALX3WVYQORBQNMWKCAMGQEMUCI7RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1544E370434
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 01:44:03 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id j3-20020ac874c30000b02901bab5879d6asf10910794qtr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 16:44:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619826242; cv=pass;
        d=google.com; s=arc-20160816;
        b=tA0W0z/iQfMtxNzsFQ17xqBfI0EYFRxRoO5rIMVWLBprA6m8N2BfPSdRD43w83Sqij
         h3ujT877+6NvvEK7RfOn/ayQjopr2PDjJHmKIYUEb4joQx0ZwIdt2WqbDUmRMTfuMagk
         rGTRhBgk5HT9/gndmWjUDK7rIzVb8Okiwnq2v090ztynUfwTHGUE+pppAr6WxUQbmKdC
         kcESctJ7nH386ysJF3aujtFwr2Ef9joAOB5iGF+uWGPwiUMecuYgDh4Cl6ECsZa9j4Vl
         I0xeaMv6SRIf+6HDKJX34iOLmMjrN3NfRgadAaThtiPZjgCWkV8CZbv5SHp+Fdi8UC6g
         /jGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=Ih5DssFfhhPeHBlIej3F42BZdqVsyUnoZO0ZQ0MQ570=;
        b=a2VoRkuaQ2kQt1BlmvkBk4wFumtBSQksmshteiPc8kIXlgWaxeVmoQHtyC2uLo+kLc
         pxLjSHmnhuNXyCO43/0OBLO8qEJN3cBUz3VxKplAVv1h0HlmmKnU6CD1+xcxIbhNW7kn
         TlwpRMXHSH5IeAG4/RgthC4PXzqb7vWRLNzqboWgfwr86lCKt0HkHxZUS20AM9WgNirf
         DkvCJ4ZPYk5bdm2dE1SWpoROoVE5OE0kl9MefbU1zxmA5x7nwLQU8AAgP2Oxe7eWtH7J
         Zcla9YwH2kVwkz5TxJHFz60ILvnkZI/AJKIe4sGfHLIq4IFCfkio9aJs89jsV29rtKf4
         nc8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ih5DssFfhhPeHBlIej3F42BZdqVsyUnoZO0ZQ0MQ570=;
        b=HC7iAoOjWKYmiarFzkpWrsyTWvkNJwK3Qty+JGphrH19AZNtSx9lUV0PD2867fhMqA
         uwyfFB8b9pwLdL+9hX+5GT4DLlgtyq91uIcTB+SMPupjImk1cSki1c6iZjK2V8grlGMm
         ax7ZvbOy2QrTyr1Cd/KZFxQ+TKRcnPBdcC9MizbMVsooOXTtb6LTHdI2BqsIq1UgTm4g
         Jch03VPnC1eVdeieg5uBIkfrs37qKo7edKnCzh2lNcEfeJPzRyCcIMheQJixVL01vQX/
         tj2mZCDEe/8V9ArvdRMzy+/X4pYFCrv02HRAKSLyukSXBJ/67eGzpIP/WiURLjI/i8Ux
         3jig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ih5DssFfhhPeHBlIej3F42BZdqVsyUnoZO0ZQ0MQ570=;
        b=kC2MnBUFyw1h2OoIo/v7t92ogojxxp0aNzhrlw+yVNvJFAwUX+O/4qjKWSqo4u/xmt
         eX5ESG9DL5R2MFb7jctWgqF7RWNW/ZxUAy4DrDi2c+aq6Z0coa1GA9fKeuwj5pzOd6bS
         qi9thhHbQoJHlt7R30O/rNfMmIg/EqhdCxyQZVT57IvaFD2IvIcegjt6nj8VtTwga3g6
         44pzqxbJeX7uiD9fdZ9nqwm/U4zF5PQssFf0nUrxq8KUVav61zoTgcwQQ0Wc+3/2J3rZ
         DRNDtLDEXvQTvum5yGLfu3AiuuLIVHFqRPidWeCg5QBBSG5B5PQI8AoMRiH430593eOf
         elHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Aqix4SNPCy9pRshODooU6y6UI+PwbR6XRIIdY2RFsdpFBmnKw
	arphrOSDLBISnrOoMsg5jdE=
X-Google-Smtp-Source: ABdhPJwiKCPOT5NCIIZJGk3tJCpzZWiCYLCqWuZug+508QFgoOkOvYX1tWqcOYHv6zdxFbEg1+8LPg==
X-Received: by 2002:a05:620a:1471:: with SMTP id j17mr8165706qkl.43.1619826241942;
        Fri, 30 Apr 2021 16:44:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:eb15:: with SMTP id b21ls782354qkg.10.gmail; Fri, 30 Apr
 2021 16:44:01 -0700 (PDT)
X-Received: by 2002:a05:620a:6ce:: with SMTP id 14mr8177061qky.423.1619826241576;
        Fri, 30 Apr 2021 16:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619826241; cv=none;
        d=google.com; s=arc-20160816;
        b=wwm7ECMOzlF0o6qE3+fQSMbxAlQDA+bNphM6QfA/ju6IOMtTCGtJlnxDr4noIKCQcF
         gkWaMFoB7pu6ZuMpcRRizDEsSYwNQHSzamvDkIUH+MlxEJIR/L/PlxBtwCzpWZTA+6qF
         mb0CHY73bTXGcoX34ECqXeeF5Yq1FGOMH79UCmQtHVnTxAYKwfthFY5AmzFmAetLMzyR
         8yFdaX6BLcF+QZBjylIwNU+fiCyP63+PJuSuRHxki1mGPWRFek8VGXnn3VEZbDMMgHwc
         g055icOqxfkRDbHNfjrQGmfq+3/SYvoqc8Grea8puCUwFBvyzioZs15LJfnbW9fy58Er
         bzbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=S9S/vgp1O0RJMCrvZ5kKS/Si99MAuDtBd7U5Q2ZgepI=;
        b=a+46B0G8U6B4QMfchZgSovzjYCGB+A8ZyYxnOcqSJAmo0zUfCZokX0AlFCz1OGqMgX
         nVV6vKaw8Dk1QIe4Jgg34BuGv9XX9stlDmj+omIuHNgi3XnxIbAECAjA95PQMR+y+vVK
         QSOhYR09Y/dSwGgrmCvw6RXorTVmhmC9FcoRR2A33qMzb4bySfvWqw9dV8sa1XMLxBng
         DdZ3N63PCWb04el5+HuddJlMgM3I6vXw2yE8FHFW076OUEV0JJN1+LEGi/GzUfrw9PMt
         f6l29QU6Eqn+Idjm/zBxHwHc2ZtUAnSdIRwk/y50OUfJTsuRTEKL6Uw1UrAca03gNQoE
         R22g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id c72si716926qkg.6.2021.04.30.16.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 16:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccnf-00Cu5Z-I9; Fri, 30 Apr 2021 17:43:59 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccnd-007Jf6-Eo; Fri, 30 Apr 2021 17:43:59 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 18:43:53 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <m11rarqqx2.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lccnd-007Jf6-Eo;;;mid=<m11rarqqx2.fsf_-_@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+OKY5uq4AN0zHsCQvL3j6iEdy1nC28rBg=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.3 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TooManySym_01,T_XMDrugObfuBody_08,XMNoVowels
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4990]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1486 ms - load_scoreonly_sql: 0.06 (0.0%),
	signal_user_changed: 11 (0.7%), b_tie_ro: 10 (0.6%), parse: 1.13
	(0.1%), extract_message_metadata: 15 (1.0%), get_uri_detail_list: 1.98
	(0.1%), tests_pri_-1000: 21 (1.4%), tests_pri_-950: 2.0 (0.1%),
	tests_pri_-900: 1.67 (0.1%), tests_pri_-90: 84 (5.7%), check_bayes: 82
	(5.5%), b_tokenize: 18 (1.2%), b_tok_get_all: 9 (0.6%), b_comp_prob:
	3.2 (0.2%), b_tok_touch_all: 47 (3.2%), b_finish: 0.92 (0.1%),
	tests_pri_0: 1331 (89.6%), check_dkim_signature: 0.67 (0.0%),
	check_dkim_adsp: 2.2 (0.1%), poll_dns_idle: 0.55 (0.0%), tests_pri_10:
	3.3 (0.2%), tests_pri_500: 11 (0.8%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 7/3] signal: Deliver all of the perf_data in si_perf
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


Don't abuse si_errno and deliver all of the perf data in si_perf.

Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 fs/signalfd.c                      |  3 ++-
 include/linux/compat.h             |  5 ++++-
 include/uapi/asm-generic/siginfo.h |  5 ++++-
 include/uapi/linux/signalfd.h      |  4 ++--
 kernel/signal.c                    | 18 +++++++++++-------
 5 files changed, 23 insertions(+), 12 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index 83130244f653..9686af56f073 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -134,7 +134,8 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		break;
 	case SIL_FAULT_PERF_EVENT:
 		new.ssi_addr = (long) kinfo->si_addr;
-		new.ssi_perf = kinfo->si_perf;
+		new.ssi_perf_type = kinfo->si_perf.type;
+		new.ssi_perf_data = kinfo->si_perf.data;
 		break;
 	case SIL_CHLD:
 		new.ssi_pid    = kinfo->si_pid;
diff --git a/include/linux/compat.h b/include/linux/compat.h
index 24462ed63af4..0726f9b3a57c 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -235,7 +235,10 @@ typedef struct compat_siginfo {
 					u32 _pkey;
 				} _addr_pkey;
 				/* used when si_code=TRAP_PERF */
-				compat_ulong_t _perf;
+				struct {
+					compat_ulong_t data;
+					u32 type;
+				} _perf;
 			};
 		} _sigfault;
 
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index 2abdf1d19aad..19b6310021a3 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -90,7 +90,10 @@ union __sifields {
 				__u32 _pkey;
 			} _addr_pkey;
 			/* used when si_code=TRAP_PERF */
-			unsigned long _perf;
+			struct {
+				unsigned long data;
+				u32 type;
+			} _perf;
 		};
 	} _sigfault;
 
diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
index 7e333042c7e3..e78dddf433fc 100644
--- a/include/uapi/linux/signalfd.h
+++ b/include/uapi/linux/signalfd.h
@@ -39,8 +39,8 @@ struct signalfd_siginfo {
 	__s32 ssi_syscall;
 	__u64 ssi_call_addr;
 	__u32 ssi_arch;
-	__u32 __pad3;
-	__u64 ssi_perf;
+	__u32 ssi_perf_type;
+	__u64 ssi_perf_data;
 
 	/*
 	 * Pad strcture to 128 bytes. Remember to update the
diff --git a/kernel/signal.c b/kernel/signal.c
index 5b1ad7f080ab..cb3574b7319c 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1758,11 +1758,13 @@ int force_sig_perf(void __user *pending_addr, u32 type, u64 sig_data)
 	struct kernel_siginfo info;
 
 	clear_siginfo(&info);
-	info.si_signo = SIGTRAP;
-	info.si_errno = type;
-	info.si_code  = TRAP_PERF;
-	info.si_addr  = pending_addr;
-	info.si_perf  = sig_data;
+	info.si_signo     = SIGTRAP;
+	info.si_errno     = 0;
+	info.si_code      = TRAP_PERF;
+	info.si_addr      = pending_addr;
+	info.si_perf.data = sig_data;
+	info.si_perf.type = type;
+
 	return force_sig_info(&info);
 }
 
@@ -3379,7 +3381,8 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 		break;
 	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = ptr_to_compat(from->si_addr);
-		to->si_perf = from->si_perf;
+		to->si_perf.data = from->si_perf.data;
+		to->si_perf.type = from->si_perf.type;
 		break;
 	case SIL_CHLD:
 		to->si_pid = from->si_pid;
@@ -3455,7 +3458,8 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
 		break;
 	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = compat_ptr(from->si_addr);
-		to->si_perf = from->si_perf;
+		to->si_perf.data = from->si_perf.data;
+		to->si_perf.type = from->si_perf.type;
 		break;
 	case SIL_CHLD:
 		to->si_pid    = from->si_pid;
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m11rarqqx2.fsf_-_%40fess.ebiederm.org.
