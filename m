Return-Path: <kasan-dev+bncBCALX3WVYQORBAF7YGCAMGQEMHEAPMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 36F3237218C
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:39:29 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id s4-20020ac85cc40000b02901b59d9c0986sf2243356qta.19
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:39:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074368; cv=pass;
        d=google.com; s=arc-20160816;
        b=dse56gasVceGOInB+QjHMbF0ow8qfF9BJXK0T0AZsyPcRHiZgdwvfuQ8Wqjm77PyCd
         gDs17tLi5Wjvt7kbPMb/a1YwlNcV12t7CxlAlkmeG9Fa6CY7V/Hz/i2jXXAtN3LziKfC
         k0jecL3NBMJvefW+Q22ibBfUUigaFcB4KuT9anQPp4C9vXyPbq5WoZVQaXTSZLGANj5A
         S8mst6ot8i1FXLBqhyQ6gOK3pZM8uC4pUbH92COFMubwe2UooE/QwxmtbJEz+B87Qu5c
         iho/WAleoaCDx8+rZugu8NJkbnZCqdhd40c1wUsYLdBdxC3a1lChx5i4Tng9+wghnntv
         LWuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=eK1/oyP2Ct+7SjAg5GeD+OJdehNRMGxTFs8M1JukoWA=;
        b=IL3fZunxhwVXdCZYej0+xkPgbRUITrb+X0/ZEIvhABRwRKZVhbaZ5Ct73nnlUVYwV5
         C5Wr7kbrG2rzswym4+YG6EdQ4LRkUXstGM4NTJU2Sy5fPJvf0r8qXbedT3chuHAq2tCU
         QQaQYeaLv3Fea3j/XSMZpqbh9Pi815Cjnq5AHc8aGs5B+U1+cvN/vKs4ZEkp3D/pLZql
         U3wPOREYHy9k7k/+tAB40yYtomFVM/JRkT7in7enhC4hL6TOSucxQUEkyLSrb+45Muaf
         8UVlkmi3iyXyv6NeJfapH8tQVE0T2oK7vEoiB+5P3roMNgbvzap/+dSvYqJShEWS1Sqh
         Allw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eK1/oyP2Ct+7SjAg5GeD+OJdehNRMGxTFs8M1JukoWA=;
        b=jWMOfKDwZLZuXOJvcU1gRnxKy8e/vuUmTkPLzU60tIFjbTQAHPO0UFz5/F+r2jnP5Z
         rzYqnDRYpLB1DLfITS3zE8M3jIoAbAb/H1fPuPPTPlFejU+xiU84x6FZ3ut9f/YCclgG
         C7JulpLHnKiJzhg1/+aeALjYd3Z5eXREnz0NWoR557YMdHPcwN+NU3dPqCHwUcOuUBC3
         7S5bPF908G9Aqh49UGFh30wY6wWh854wUrurmG0w1LTlg+x3GJYIP0IIsXWShg8I4HB2
         rARSUBZ995rKJ0nxRLTLaNFm4zeSTG9TB+YIVtIyXGXmsfw5POrC4eZlGWN/gGbAQkNU
         kBxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eK1/oyP2Ct+7SjAg5GeD+OJdehNRMGxTFs8M1JukoWA=;
        b=bxQfz7CuBuEyf87U+XsK9kjbume8r4C0Ap8FFDc0/PPHNh+sLW9Ngvjsg1jwDDbKEG
         ZS7OMi5SSO+50CaamNV0FZ95gpVg8eeODQ0KF4WlyEPJfXPLXsslKpVhHXZvKhG4EpDi
         Ybk9i2k9w9UiFjoHh6dhaWeSuIIbuPi9E3Gg7mewXWA1AkVVsaR/W5B98J+a6YKuOmvp
         jJ4j6vm1Gf9ud4EZGQnONOflxRyhKJVC03MQPZ+tVVaXwG3VpcqsAmVjRqu58hEXzu7B
         0nhrkp73ns6i0sVVTAI4cIIUEzAQk+RLw4gH8v8UtOVuDRotbI+KK/KkjxWmJwuzvC3+
         hmng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325LVYg1kZ5XW7TeOf0M+UZ1uWonHNDFWHaH9y5Rue6B12AUYCy
	TPHLxrYwjBPV6pTO5PHUOBk=
X-Google-Smtp-Source: ABdhPJz2F4bt4Og8XHAOj+S8mNwIsw+INKEAAoQRJGoKIGUQfV6/KrE67yXzi+CtozCO7BMMn69hdw==
X-Received: by 2002:a0c:f00d:: with SMTP id z13mr21714821qvk.0.1620074368325;
        Mon, 03 May 2021 13:39:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1d0d:: with SMTP id e13ls1244352qvd.5.gmail; Mon,
 03 May 2021 13:39:28 -0700 (PDT)
X-Received: by 2002:a05:6214:2268:: with SMTP id gs8mr21196497qvb.35.1620074367944;
        Mon, 03 May 2021 13:39:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074367; cv=none;
        d=google.com; s=arc-20160816;
        b=ewuqZTcGDCFzCe4Ny7Cicv6HY5XeTBObQ2p12TMTtimHWXoaBpdF1D2d0m6RKzcbnl
         UaGcYWYjHSSl4b4Shg5n3+S2KjmM2ZdYfDID7WjzuWYhdqYw866HFHWM40is+dQdtDZ9
         0a1gQMq5m/cTKZFCgvH8fvcp32prYgkoDn3MI136iEOlgkAOWJNaeo6MDYJPtY++9JYv
         LimEQz9rISQULfrq+MqWueLVogHRacU+ib5d7IoZqqv0AL/wZeSK+kxSvtePhu5CeBb2
         NiXoOCXSNTs2nlJwH36EDPhCirlv9AUWlzlsdaDRVfUG6BxiYgFeZmDIsb4q8RErvoec
         dI8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=ukgaSP3pPa8tfVL0VASNOAnEHqZRqsHN3UWyFjwUWL0=;
        b=WQ2xYI+TsEaPzwjX+/NVmRqZoagqKZ4hJKQR7yitQl0H0Uf2I+50pdFegI/QhjUHEA
         Gu+hmr7kuxdbCoX2U/OK+tAzlFzttevS4x0Lo8W1coG7tkEn+AsJjFUIxavTreJStWTR
         rfXE6+uT6vdVWjOBxoyZt5ekKKth6k/HWo+TzLM68B8u4u+qUh8qd9j/cKqwGOniH3Jg
         klWYS+CuZaPkAjnEGx5KzZrMCRnFcxh5TdVokuIieiKXOBh7I6XK1la6BHnPCfH3O99m
         n48YToR2RMA4fOoM0id8WlxeKW9kNsoXrMjqggh0kdC6PmWEc39jARXJr+c/Mg8cAzwr
         8C/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id k1si86187qtg.2.2021.05.03.13.39.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:39:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLi-008idl-2w; Mon, 03 May 2021 14:39:26 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLh-00E76Y-3k; Mon, 03 May 2021 14:39:25 -0600
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
Date: Mon,  3 May 2021 15:38:14 -0500
Message-Id: <20210503203814.25487-12-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210503203814.25487-1-ebiederm@xmission.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfLh-00E76Y-3k;;;mid=<20210503203814.25487-12-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18ApcIKZTcHjAhTtt02Vp3dyDFJvqVtnoc=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa02.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMGappySubj_01,XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4756]
	*  0.7 XMSubLong Long Subject
	*  0.5 XMGappySubj_01 Very gappy subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa02 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa02 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 368 ms - load_scoreonly_sql: 0.02 (0.0%),
	signal_user_changed: 3.5 (1.0%), b_tie_ro: 2.5 (0.7%), parse: 0.67
	(0.2%), extract_message_metadata: 8 (2.1%), get_uri_detail_list: 1.30
	(0.4%), tests_pri_-1000: 10 (2.8%), tests_pri_-950: 0.93 (0.3%),
	tests_pri_-900: 0.81 (0.2%), tests_pri_-90: 56 (15.2%), check_bayes:
	55 (14.9%), b_tokenize: 6 (1.7%), b_tok_get_all: 7 (1.8%),
	b_comp_prob: 1.37 (0.4%), b_tok_touch_all: 38 (10.3%), b_finish: 0.63
	(0.2%), tests_pri_0: 278 (75.8%), check_dkim_signature: 0.38 (0.1%),
	check_dkim_adsp: 2.1 (0.6%), poll_dns_idle: 0.78 (0.2%), tests_pri_10:
	1.62 (0.4%), tests_pri_500: 5 (1.5%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 12/12] signalfd: Remove SIL_FAULT_PERF_EVENT fields from signalfd_siginfo
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
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

From: "Eric W. Biederman" <ebiederm@xmission.com>

With the addition of ssi_perf_data and ssi_perf_type struct signalfd_siginfo
is dangerously close to running out of space.  All that remains is just
enough space for two additional 64bit fields.  A practice of adding all
possible siginfo_t fields into struct singalfd_siginfo can not be supported
as adding the missing fields ssi_lower, ssi_upper, and ssi_pkey would
require two 64bit fields and one 32bit fields.  In practice the fields
ssi_perf_data and ssi_perf_type can never be used by signalfd as the signal
that generates them always delivers them synchronously to the thread that
triggers them.

Therefore until someone actually needs the fields ssi_perf_data and
ssi_perf_type in signalfd_siginfo remove them.  This leaves a bit more room
for future expansion.

Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 fs/signalfd.c                 | 16 ++++++----------
 include/uapi/linux/signalfd.h |  4 +---
 2 files changed, 7 insertions(+), 13 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index 335ad39f3900..040e1cf90528 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -114,12 +114,13 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		break;
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
+	case SIL_FAULT_PERF_EVENT:
 		/*
-		 * Fall through to the SIL_FAULT case.  Both SIL_FAULT_BNDERR
-		 * and SIL_FAULT_PKUERR are only generated by faults that
-		 * deliver them synchronously to userspace.  In case someone
-		 * injects one of these signals and signalfd catches it treat
-		 * it as SIL_FAULT.
+		 * Fall through to the SIL_FAULT case.  SIL_FAULT_BNDERR,
+		 * SIL_FAULT_PKUERR, and SIL_FAULT_PERF_EVENT are only
+		 * generated by faults that deliver them synchronously to
+		 * userspace.  In case someone injects one of these signals
+		 * and signalfd catches it treat it as SIL_FAULT.
 		 */
 	case SIL_FAULT:
 		new.ssi_addr = (long) kinfo->si_addr;
@@ -132,11 +133,6 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		new.ssi_addr = (long) kinfo->si_addr;
 		new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
 		break;
-	case SIL_FAULT_PERF_EVENT:
-		new.ssi_addr = (long) kinfo->si_addr;
-		new.ssi_perf_type = kinfo->si_perf_type;
-		new.ssi_perf_data = kinfo->si_perf_data;
-		break;
 	case SIL_CHLD:
 		new.ssi_pid    = kinfo->si_pid;
 		new.ssi_uid    = kinfo->si_uid;
diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
index e78dddf433fc..83429a05b698 100644
--- a/include/uapi/linux/signalfd.h
+++ b/include/uapi/linux/signalfd.h
@@ -39,8 +39,6 @@ struct signalfd_siginfo {
 	__s32 ssi_syscall;
 	__u64 ssi_call_addr;
 	__u32 ssi_arch;
-	__u32 ssi_perf_type;
-	__u64 ssi_perf_data;
 
 	/*
 	 * Pad strcture to 128 bytes. Remember to update the
@@ -51,7 +49,7 @@ struct signalfd_siginfo {
 	 * comes out of a read(2) and we really don't want to have
 	 * a compat on read(2).
 	 */
-	__u8 __pad[16];
+	__u8 __pad[28];
 };
 
 
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-12-ebiederm%40xmission.com.
