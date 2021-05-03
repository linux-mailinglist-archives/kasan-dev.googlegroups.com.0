Return-Path: <kasan-dev+bncBCALX3WVYQORBYN6YGCAMGQE24JAMBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F122372174
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:38:58 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id w4-20020a0568081404b0290102a1fd05b2sf3762938oiv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:38:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074337; cv=pass;
        d=google.com; s=arc-20160816;
        b=O6nSgb2LFQ5fqr1iAo2RYXeKFHKdr0pcbLvby5WyVhWhTZA2KeI61YYVaWzFwb0Rr+
         cohxYjt0cxC9KAiCEFLIwn+BoKEWXMwbDlQA0hC9Elx+JgblXH3NjNolV1V5d0ij37PX
         AQazLKUABbEUe2JbZXttBF00rF0zM8gxDc2+4ajWtUt0oV+qVlPeXiahfWM3k1Pyt/4/
         uZET1vtwqtCCnJkybiu7Rb+DzU763BYUCuM5LPY3SX00rwzp1pZAxOmRpdgQ8SvmpLCX
         bV3w+w8S3K71LjOn4kaGJYEOey/OJsudeqV172pJHSMKE+08oKhNHXaoLD8a8WYWEMPp
         msZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=RusjEfGEmwgMtFDlyR//L0IVmyuR69q/P5Xs0tA9rqE=;
        b=LHCnwjvzdQ+bqLcMztMHPSzWEu+w4FA2ylCKxBMc3Gsgk2oGSS39XnM0jcsQHnHwtu
         Bw97HpCiayhnP//HX26ZKQB06+iFOJkmKERgVugGDIzDtxb21wXPpxSZY/tP+v7Mr+Li
         Yr80FI5A/vnie2bVYOC5LCwcayQq6jRRkFNdvN8TYo6AdDNy3SWT/3ZZLPE6wZYsC8qd
         W1TX/V/3vhBUj7d/CXtMcqrlAjKjj39p4iekYnNZ3AolrBUA+VD9eEOVU2FVDP0fVUpJ
         BARv/6aQfzLDVpawJFS1h3LwkLcAjnVDbIukH4FOMmhI4OKkrh0UH67T+vvT9fltUxZt
         LqNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RusjEfGEmwgMtFDlyR//L0IVmyuR69q/P5Xs0tA9rqE=;
        b=Rtt6dXPJG1hVRIn/SJrrsxLHH/rR4Fg3bpZhDbBwODjJqFBGK1E0+5f0Bytffl0Ao+
         hEy4LaOTcFJnJ5BeYxOwrSFrjlX+axm+nVUZf7cnWF/NNS6dzO8Kjd3jRmJfipolTOJH
         WZ2qcEB7xOTHfEBR9GDVw1qDOhA9GVaYe4nRxPEwd1gWVtoIk6g/iGHKetuyghdxqmwJ
         qktMAzSpTeqewGepEzdYQlP4uJkZHUAs/rqfOQb+n6g3Mjp0mGGb/Bd4zEAGvZ5ncmck
         ukl4zfoDhZZdDWKrNhdTcKir5sr+9YbuJiNN1HZeWMS6QnRriRt872GQy5WXCZ382CQ2
         ZDww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RusjEfGEmwgMtFDlyR//L0IVmyuR69q/P5Xs0tA9rqE=;
        b=UhznhXvLIHPPn7KCbkSphbkVLwot6MBio9rBJuT94e9id0r5/vKr5MbXF4gmIHzE6Q
         515d99a0kkCKouTnk1SBsI0AAC67IVJpkA5N86Eu8l9mBrJvg24OcAQRu+Ustq5c4shx
         q9Z5VzrgJWGIpChNZgMVCd8sQj64OD9ewS77PQTPvNbnMj5M2izJFkrP224L5LZEVTK5
         P491hdus5gmrV8oKRecB5nlZ6amgA8d0c8QAF7cEfpFFXWhbPg3wwtD/rf3UjhVU91Pu
         WEPjxUKl9pmO+OTe72W+0rn4EVaZozGN5ag/41nB4aFzEMx6o7tEzf2yApSOV7CqvUcw
         0Zjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ocS2DeE0E/SOaXIPmsS0wVF2nvWZF6fb2xROSeEBAEgNOcFEA
	kcrrQqV2L854lc7Jk6UhGLU=
X-Google-Smtp-Source: ABdhPJzCAsr+ITCmSkYUI0qci2JqAdyhL9R80YJFWvAw/4AXY1kkuS9YJzvlBnhyV/jG44sPOk6acQ==
X-Received: by 2002:a54:4084:: with SMTP id i4mr311030oii.34.1620074337443;
        Mon, 03 May 2021 13:38:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:926:: with SMTP id v38ls4147698ott.5.gmail; Mon, 03
 May 2021 13:38:57 -0700 (PDT)
X-Received: by 2002:a05:6830:410e:: with SMTP id w14mr15038596ott.251.1620074337095;
        Mon, 03 May 2021 13:38:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074337; cv=none;
        d=google.com; s=arc-20160816;
        b=TwDhVYqlPOYkVRrN2fT3rcmugfqW7LdHCoAXJP6i93cbP1zYTbOnzpnN3FBcULgTEk
         kBLpZviZuBA7hD7roB5EudxSE71KQTJ/BY1fVaSGxmCtEIEMJSxAz2c9quak2+lg3/8r
         uWP/SQWrLrHhkzberpEZx+y2O5oBDkcSCk0cKeQESaUvTXrBm9yA/RAnTnBNp/kaGVU6
         RdjE9fbG0mpDNGZ0fz2ng+AKoU4pr0ERF0N/qFTj3xGBrsV6V80mws5LZivqWiG2StAT
         znvU0fmSEC8HU93U8jSczWFD4LT9F+FUuaNCNWRnCe2r9M7d+uH6CVmeUNP5DV6w8o6e
         KG8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=CyskUuvvhXODkGP4ciR0aasP5HyyA8WbvwLPbiDDhfc=;
        b=UitQFDaFVufrEFOw3vMDI/DKjX+vafKqiqq+8iasfMmc11lwxp8o0qeKis/2NNAf6U
         rdRAIW9uOhPMRvqEcLUpRbPv3RbcUNnRNQGiZKja5vNL8MtfNe+Zqco8TMv4dGaMGgCQ
         32kYqR5GyzwHzIf2LDOHsytjG/GelU8PcCfV7+SQck1p44dVxr2Ao4i6E0weTC4eAMzn
         DyGryUCCtAvkhlVGZQNe3bApld/fGo1OoQxY2NPtcc4L2kvDyymGEJ7Jt0syUFIpk4ts
         TGf+t452jAvpLqc3+EMpwxKfI4JU4N2HTetSwc7WSss/PqqN9LiBoUoapKmfdXyJ8GWv
         qxWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id c26si65374otf.4.2021.05.03.13.38.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:38:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLA-008iZv-9j; Mon, 03 May 2021 14:38:52 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfL8-00E76Y-Uu; Mon, 03 May 2021 14:38:51 -0600
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
Date: Mon,  3 May 2021 15:38:03 -0500
Message-Id: <20210503203814.25487-1-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfL8-00E76Y-Uu;;;mid=<20210503203814.25487-1-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18STfyarBjtdliqv0clSO0JOJDgI0ahPbM=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	T_TooManySym_02,XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.0 T_TooManySym_02 5+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 544 ms - load_scoreonly_sql: 0.07 (0.0%),
	signal_user_changed: 12 (2.1%), b_tie_ro: 10 (1.9%), parse: 1.31
	(0.2%), extract_message_metadata: 20 (3.7%), get_uri_detail_list: 3.7
	(0.7%), tests_pri_-1000: 15 (2.7%), tests_pri_-950: 1.31 (0.2%),
	tests_pri_-900: 1.09 (0.2%), tests_pri_-90: 64 (11.8%), check_bayes:
	63 (11.5%), b_tokenize: 12 (2.1%), b_tok_get_all: 7 (1.2%),
	b_comp_prob: 2.0 (0.4%), b_tok_touch_all: 39 (7.2%), b_finish: 0.83
	(0.2%), tests_pri_0: 414 (76.0%), check_dkim_signature: 0.82 (0.2%),
	check_dkim_adsp: 2.0 (0.4%), poll_dns_idle: 0.44 (0.1%), tests_pri_10:
	2.1 (0.4%), tests_pri_500: 11 (2.0%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 01/12] sparc64: Add compile-time asserts for siginfo_t offsets
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-1-ebiederm%40xmission.com.
