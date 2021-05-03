Return-Path: <kasan-dev+bncBCALX3WVYQORBYN6YGCAMGQE24JAMBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id E492A372175
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:38:58 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id c5-20020a0ca9c50000b02901aede9b5061sf5881868qvb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:38:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074337; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ht+q/C10XjetzcZENClNEQYBp6O9H7AtKGakXdMvl2Fpy6invDOxitrqVDl0OAu2ZW
         XO1P/8N70MW97DCR6e1CGSBNGQERiRPqoCq4w5Vk2p4Zu4HRIAOP7iOPyJlYEo6o4wth
         pKJZ6Jkhut7ozg23oq6DA9Sn9kF4ySumBCCioxrPk7Rw0XjG1KLw7kXbTsdkB0ySUDIP
         itVJ6VfPI8Kx5KmimWHdRc+HdE5QH96JtrAA/fN8ZbRNNIu6jqAzeddd/WvUiTvIm6Fi
         HKx/7VDGorlK6IUYzZlbIV5brh03Av4fW65hesPr+U4WCAmSQ2/UiYUUs/ZgUIHhUh84
         MX1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=GJQw3e+5elEVUPI1tiOYgHKBmF+igqQIXtRKCzWZZTs=;
        b=qx6au6njJA0tfmv3yWR10esQI3XxHZJpRwRpuxikgU3QN6cTtzPfy1HH80tgoSpALb
         PfsACFL3fO9qf55TRH5vIkBGbkR1j6xVsUYBstXxhV9POhaE3TPL0aijrA/FfpIk/4Et
         FOQt7pEgCaTxz7PapmGODmVm/pnk0jkwRugQuLuJp52jQA9UEreTQMI07zlINH5qWkhw
         PGznR7yP7SNOSE6HevmgM8LiJume01VOJZFuKvT63azsv4jazqdFx1f31A3HEKuO0J33
         WlN5/GKnvZo2w+Tl9sE81k9VJw1d5g2WKbl/3v13F8IHYgexybw0ZtNlhTyY/FdwZ+Nz
         b0fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GJQw3e+5elEVUPI1tiOYgHKBmF+igqQIXtRKCzWZZTs=;
        b=S7zZTfRRJMeTy0V9hivlwrjd/oS9ynS7YXjpnkmXsKiZPFwqThieb7EsSjGbe9DWm9
         UPDj+Iioo2Zr/ppZFVaLHzr63Xne90zERwRH8RdLVfG6Z+ZyELOgX3ylbwHWpMLQPjw7
         Tz5NiNRQfLM5yn51Y9qSjsFmhXw2YUlBQShlrL9hP1w9Grf2OdIxgo0I1yIC4tMQAjzJ
         hU/gkf2ZRGcIXc5K+BjXv0i71w681H3yV9AnCPhhPDvjl/eu0ArlDgrqAx8l1aqshmZC
         VQu41WCEz7gBjL7LVGvSgId77fzZdrluLrI7XIXjbHx4YHCEj+7/PyTH1Tejmi+HbhmX
         eVYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GJQw3e+5elEVUPI1tiOYgHKBmF+igqQIXtRKCzWZZTs=;
        b=FELX2qJCE6qORiQtAm+XuqVyMx/q4a6IYu5KcyykDVGT61o/Vcr3dd07Lh3+01xQ+9
         Vhaqk4Db97NWa2qjRRQkI0/BOIBVRQ5gAMZW13h7XjTODrBIfraV9GZCGma7JP1J9PEK
         KzmshkpgDydJ7dM0atWrx8x0iMgCzzEHD3FMTUK3tjEeNYoUTLREhIdBveYn9VzIGOe4
         PcCZoOeENq+cMemT1knco1UMNJMf332unGh3ZiyiqUBy/hc084NlREpCY6IPLFnHnhAR
         aHHLzyDuImKWQpgk+2i+nkU05+Ks2wL01R4JOcN/3y9EbCEvI2+t5g48qGUd7IcuMoV6
         GXnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530YsBN120QSupMdRoq3I+AF3ndP8aSG2i8FKOYuKbVce4nMFCfQ
	YPApKXi9yOnGOy4Z8QlcCgA=
X-Google-Smtp-Source: ABdhPJxoRzLb739FUQeNRA9BY3RbTSQmgEWvDD4oDHykh8aBJ9DeW1ZkCdXX0/Mfivt+JRHOiWcCrQ==
X-Received: by 2002:ac8:7b26:: with SMTP id l6mr9112739qtu.136.1620074337696;
        Mon, 03 May 2021 13:38:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5810:: with SMTP id g16ls6470371qtg.11.gmail; Mon, 03
 May 2021 13:38:57 -0700 (PDT)
X-Received: by 2002:ac8:51d7:: with SMTP id d23mr5233183qtn.74.1620074337255;
        Mon, 03 May 2021 13:38:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074337; cv=none;
        d=google.com; s=arc-20160816;
        b=EXKlPG5et2sm8xIyZZ9aYEK7wkUw6kg7aw4m2jUzAU3nyQ8wNAuu3VroGlucL9V2qe
         VrhdQAF13zCWRA8pryt++Yt2w6dVITRLvWxuwshGdiZTjqnSUcRXDeyeZjxj0S259B6v
         +J9ROcEyOw6upUs1Ulp7l/gO5sTMhzogBZ5tF9WnwpG6a/fcINETjjFASMEHmXz3a9TG
         dGPMZy9Djedi7yYU8DD/okAdDLG1d4e/zzD5PqoDL6U7wrTYQjHyMs9kT3zfM90d6rHN
         CX14Mm20zNaM+YBla32RQmP/ex0gMd72SKGol0UjF1jOem/Qd0eBmWXY1yHfNWM/Y0+D
         8Q+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=0Vu3LLzjkWLam3hLWJknx7FW/nuXeN8VtHkpMu+zsbM=;
        b=FlksvLLFsh4kTuwyJW7/o/6TuERksrk/nEe5JDuuWPZs424J6Jmosmg8w4BNWMg29r
         5US7HSTz0205IAQDP4nofevPgXQMM/fV2bATxOi2b4UxwnzcEYtE7Ds2kWLjGOcgWwME
         h1wk8PCwYZMSMV8Ey1BqdYMKt56v5xaWZDObWFjOLziEZ0YlJH17nBkcjFfzMmSYE9Js
         nUbaMF8/9e3lXGtRcImNgChYPpcJrPKxhNzBDrPl/UD0gE71gSW7kmBZNLB9iwxOeYf2
         n1RsTFetdwvzUuRe55864ts1FADdBnZ91KkM5QnKOkNJr2CN+VSLV2Bt9/e5mGcYmQKp
         +rzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id y8si43994qti.5.2021.05.03.13.38.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:38:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLC-00Gyhb-SW; Mon, 03 May 2021 14:38:54 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLB-00E76Y-RV; Mon, 03 May 2021 14:38:54 -0600
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
Date: Mon,  3 May 2021 15:38:04 -0500
Message-Id: <20210503203814.25487-2-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210503203814.25487-1-ebiederm@xmission.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfLB-00E76Y-RV;;;mid=<20210503203814.25487-2-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/4zhIRBt7xIq/JpUB9A8MZN6cAuKB/qQs=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
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
	*      [sa04 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.0 T_TooManySym_02 5+ unique symbols in subject
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 438 ms - load_scoreonly_sql: 0.20 (0.0%),
	signal_user_changed: 12 (2.8%), b_tie_ro: 10 (2.3%), parse: 1.06
	(0.2%), extract_message_metadata: 12 (2.8%), get_uri_detail_list: 1.82
	(0.4%), tests_pri_-1000: 13 (3.1%), tests_pri_-950: 1.26 (0.3%),
	tests_pri_-900: 1.06 (0.2%), tests_pri_-90: 82 (18.8%), check_bayes:
	81 (18.4%), b_tokenize: 9 (1.9%), b_tok_get_all: 6 (1.5%),
	b_comp_prob: 2.1 (0.5%), b_tok_touch_all: 60 (13.8%), b_finish: 0.90
	(0.2%), tests_pri_0: 294 (67.2%), check_dkim_signature: 1.00 (0.2%),
	check_dkim_adsp: 2.2 (0.5%), poll_dns_idle: 0.34 (0.1%), tests_pri_10:
	2.5 (0.6%), tests_pri_500: 14 (3.2%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 02/12] arm: Add compile-time asserts for siginfo_t offsets
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

This could have caught that we cannot portably add 64-bit integers to
siginfo_t on 32-bit architectures like Arm before reaching -next:
https://lkml.kernel.org/r/20210422191823.79012-1-elver@google.com

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 arch/arm/kernel/signal.c | 36 ++++++++++++++++++++++++++++++++++++
 1 file changed, 36 insertions(+)

diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
index a3a38d0a4c85..2dac5d2c5cf6 100644
--- a/arch/arm/kernel/signal.c
+++ b/arch/arm/kernel/signal.c
@@ -725,3 +725,39 @@ asmlinkage void do_rseq_syscall(struct pt_regs *regs)
 	rseq_syscall(regs);
 }
 #endif
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
+static_assert(offsetof(siginfo_t, si_pid)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_uid)	== 0x10);
+static_assert(offsetof(siginfo_t, si_tid)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_overrun)	== 0x10);
+static_assert(offsetof(siginfo_t, si_status)	== 0x14);
+static_assert(offsetof(siginfo_t, si_utime)	== 0x18);
+static_assert(offsetof(siginfo_t, si_stime)	== 0x1c);
+static_assert(offsetof(siginfo_t, si_value)	== 0x14);
+static_assert(offsetof(siginfo_t, si_int)	== 0x14);
+static_assert(offsetof(siginfo_t, si_ptr)	== 0x14);
+static_assert(offsetof(siginfo_t, si_addr)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x10);
+static_assert(offsetof(siginfo_t, si_lower)	== 0x14);
+static_assert(offsetof(siginfo_t, si_upper)	== 0x18);
+static_assert(offsetof(siginfo_t, si_pkey)	== 0x14);
+static_assert(offsetof(siginfo_t, si_perf)	== 0x10);
+static_assert(offsetof(siginfo_t, si_band)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_fd)	== 0x10);
+static_assert(offsetof(siginfo_t, si_call_addr)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_syscall)	== 0x10);
+static_assert(offsetof(siginfo_t, si_arch)	== 0x14);
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-2-ebiederm%40xmission.com.
