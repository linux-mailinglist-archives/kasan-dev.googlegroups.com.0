Return-Path: <kasan-dev+bncBCALX3WVYQORBZEYROCQMGQEL2XN6HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 170F838651D
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 22:04:53 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id q16-20020a0568080a90b02901e8a29e2caesf1969484oij.16
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 13:04:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621281892; cv=pass;
        d=google.com; s=arc-20160816;
        b=UQ+Cw45gzfmSAarAjeTHqatelH3IUdtMx9FEBGb2imuq6fSyzC4jstTMvIwf8W2YW/
         uyyTrLOW836MfMjnurWFbj4V+3PxQv+3JJER0bG+vNpyI2xxg9S4n/Rtg14wnxbnu24t
         C8eYAb1iuB5thL74F6anTTSuEmJGLm7iHwAW7zRPEsCFPmDovxJN64WMp0KM+QHw/PIH
         sZYIM0HKKE3BdY0h1PX33y5XXz024TWDDXcQdVkvtQUaX1obtzLvQxioh+3rAOCWAzZk
         oSL/0SJUbv9sXADyZcZLkMuFBorT8sbSEzs2+pzHujTMitxbgIGnQDq/sjr88ymr8QrX
         oWNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=wB48LsX5z5cgOfpkCBtwhfFD2VFt3oCrl43o5rbWkJQ=;
        b=X5bCV928qqEcX5bNsycGUWKfA3IqS+h1s3txAkyCbw1Vp5s/uVT+rcsspV/jPeNWiz
         pZO3Ed053Rxm/f5UE0VKyDVYMdQK2alsliSi7rjj30tAhTOyXc8skuo9cEh2IhB65efc
         wGeHwsw0p1WI/3SoVYxXZYEPn+PtNf5JCdZOP/o9sl717vsQQ1Rb0bBLZ66eeseNUb6K
         1e96I4szl1MPVo3AueyMO/NlhZH9WNO1lXBknXi5832TvMY0nv0GnECSaMg/rXDqJkS3
         pB/AbLbEjoOhggLDbFe8kvnWwPX6lGMe6Va5vSFpCApw4TIOqJkMph+WTJp2jRS/yZkD
         iQow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wB48LsX5z5cgOfpkCBtwhfFD2VFt3oCrl43o5rbWkJQ=;
        b=SjNbqk4dwa/c8PpEdvDvtfJ2kcBKLbw+DA3BCg5xsoZ12D+UQEoQtGJB2ANogHW59A
         eL73InSS1Zgg1JVrdARKM8lKLI8AQJ649pkD+CGdaL1sDolM9/aTfvWD0m/SS1D2XCDc
         mh0zJmft5LqfYyM+4SqwdA0INoNrOHKJa9pBkqLMH/fLfTNjhGr8LdcjdxOWgzhMBAFJ
         AzeNo8YEuBb/eWQVuPbw8JOAmm3Sk9XMxGrfZZDqzx1EiFtnhlMn2Yag9dBrDE+JYMOC
         M8qHV4o8/9xio85JD5dEnZBuI0s9q7Ge8QxhQCCXzGJabWerAetEb35WdGWgq1QQZfDS
         ktOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wB48LsX5z5cgOfpkCBtwhfFD2VFt3oCrl43o5rbWkJQ=;
        b=N8G+jpqv2L10U0HlNvUdSRJE07iDt8jyFx9slUDsgaieJYUCt8n+P/FDp3pOnIzUWz
         DNT8cVaeIMQUbxwx/KdUrZWt5Nc4rWg+ExiRyaD1ozi/2PI2ZfXhMagY8MhvCPEIgaIE
         FqwfcDdvEisVQFCw9GrjRHvvE0oAMMErBsly806zAa82Wyk4CDU0qsSysouE76ZQPSvm
         6KXcPvCcwpyp96nFjDq81RjH6C57Dypiim3oqMbyp1esaIIskSQdcRJ6fKaIIzL9aOmD
         xTRi35LJTBcZFXED8TLOuO4Nao96PGgA6+992D+yCLlRSceNr23hpgGnY9MW/xjDRa3J
         WkUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531isimjorTe/grZFIPtmGZ73F92K2/gNluW+kh9jHUSaT9HmVc/
	lN0O0HH9QP7XgZCdicPlDwg=
X-Google-Smtp-Source: ABdhPJxzwJfN5nzaQ46beDP4tSBmA9Xah+zJotCkyr4gLRMsjYOKPTOx8/Kri812HPGpGxCuhO5s/A==
X-Received: by 2002:aca:c207:: with SMTP id s7mr627340oif.94.1621281892077;
        Mon, 17 May 2021 13:04:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1e0a:: with SMTP id m10ls4732684oic.7.gmail; Mon, 17 May
 2021 13:04:51 -0700 (PDT)
X-Received: by 2002:a54:450a:: with SMTP id l10mr1101656oil.135.1621281891757;
        Mon, 17 May 2021 13:04:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621281891; cv=none;
        d=google.com; s=arc-20160816;
        b=iXLTMmSCYHPQos++gVKjyj9h0MSfBubvJ0HUVf6+0k1BqZkwjrZPMmoW4CqWvw4di0
         dTC2t5ny8SahRTPVWxjJjhhRAG6gpD6dwXxrfuTMgv246j+YgOl+nsnOKtbUNwg6Zcud
         2YqfHPANBu8u09VD79KbVNPrzISK1lvZ+14xmGlXXGDD/KspV7AnW6Y34mxYDqtARwtu
         eiiWcWmfS/rTnFKZmWCd++aoJeJLLxb9831NpjrBKFz9EmJ3c0ERWXTvpgCSK4A72jZT
         oWeSEmoArdMl/TlYHxO/+JR9Z8amLEC908fiMgsXMrrFEPUpOGVJFscIzvgdDF/683Bi
         6UyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=VXTA+SW4qgBmp6jyLGdv6PvzZv4iwo2DAYFgouFQJQE=;
        b=vb8Z1uXn5OHbORaklYtcVIiDUQOEFeBG67g2Qcn8EFq+0v3QRx06klwMDZ+4EAffh2
         D/iDuhEjiBrJwW3Vk3q6QzYtXjhpDSDINAm/nQvbSWlsjzGewj2hdyjU77NA7R/KhYyz
         XLxEMmPM0h5WS69B1hkAIQFEZw4WqmH5TT698Xpf2gh/PlFGZ8itms3WuKFYdpRWEtYC
         aHe1kjFmAccv6/oJfS4jRrW/E1+QgVPHFDCtVQRRAysGhqc0gkcdu6XFaIXlPRkeaaqX
         i3U54NIOALKG9Kuw7ELajc0jdnL3NWa3uP+N+ucasrGY/fKHrQ16BbCWRL+fBYHb5kJL
         cJeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id c22si982956oiy.1.2021.05.17.13.04.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 May 2021 13:04:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijTu-008wj9-4L; Mon, 17 May 2021 14:04:50 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijNt-0001rb-NV; Mon, 17 May 2021 13:58:38 -0600
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
Date: Mon, 17 May 2021 14:57:45 -0500
Message-Id: <20210517195748.8880-2-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210517195748.8880-1-ebiederm@xmission.com>
References: <m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
 <20210517195748.8880-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1lijNt-0001rb-NV;;;mid=<20210517195748.8880-2-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX194fPbXzQwXcxoLTFYeBTMTK+9PCYjh1k8=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 595 ms - load_scoreonly_sql: 0.05 (0.0%),
	signal_user_changed: 10 (1.7%), b_tie_ro: 8 (1.4%), parse: 1.31 (0.2%),
	 extract_message_metadata: 14 (2.4%), get_uri_detail_list: 3.0 (0.5%),
	tests_pri_-1000: 13 (2.2%), tests_pri_-950: 1.29 (0.2%),
	tests_pri_-900: 1.14 (0.2%), tests_pri_-90: 126 (21.2%), check_bayes:
	124 (20.9%), b_tokenize: 13 (2.2%), b_tok_get_all: 9 (1.5%),
	b_comp_prob: 3.6 (0.6%), b_tok_touch_all: 94 (15.9%), b_finish: 1.06
	(0.2%), tests_pri_0: 416 (69.8%), check_dkim_signature: 0.75 (0.1%),
	check_dkim_adsp: 2.5 (0.4%), poll_dns_idle: 0.79 (0.1%), tests_pri_10:
	2.2 (0.4%), tests_pri_500: 7 (1.1%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v4 2/5] signal: Implement SIL_FAULT_TRAPNO
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

From: "Eric W. Biederman" <ebiederm@xmission.com>

Now that si_trapno is part of the union in _si_fault and available on
all architectures, add SIL_FAULT_TRAPNO and update siginfo_layout to
return SIL_FAULT_TRAPNO when the code assumes si_trapno is valid.

There is room for future changes to reduce when si_trapno is valid but
this is all that is needed to make si_trapno and the other members of
the the union in _sigfault mutually exclusive.

Update the code that uses siginfo_layout to deal with SIL_FAULT_TRAPNO
and have the same code ignore si_trapno in in all other cases.

v1: https://lkml.kernel.org/r/m1o8dvs7s7.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/20210505141101.11519-6-ebiederm@xmission.com
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 fs/signalfd.c          |  8 +++-----
 include/linux/signal.h |  1 +
 kernel/signal.c        | 34 ++++++++++++----------------------
 3 files changed, 16 insertions(+), 27 deletions(-)

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
index 65888aec65a0..597594ee72de 100644
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
@@ -3214,6 +3216,10 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 #endif
 			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
 				layout = SIL_PERF_EVENT;
+#ifdef __ARCH_SI_TRAPNO
+			else if (layout == SIL_FAULT)
+				layout = SIL_FAULT_TRAPNO;
+#endif
 		}
 		else if (si_code <= NSIGPOLL)
 			layout = SIL_POLL;
@@ -3317,30 +3323,22 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
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
@@ -3401,30 +3399,22 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517195748.8880-2-ebiederm%40xmission.com.
