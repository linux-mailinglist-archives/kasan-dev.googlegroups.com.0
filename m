Return-Path: <kasan-dev+bncBCALX3WVYQORB54YROCQMGQELKMNHAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D5D8386522
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 22:05:12 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id l2-20020a5e82020000b02903c2fa852f92sf4280063iom.2
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 13:05:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621281911; cv=pass;
        d=google.com; s=arc-20160816;
        b=FiISreBW3WR3I5z0vzoH53z0V9toOIn/naPKxcYudo5bfpHYAsC1+xvLK6uw1cPRFC
         dtNSFssn0pc7lfyYH0fCEMtIrJlD2ZU5XLURkMUjdP5ZQhyLLHc87tEQyw80l4WOviQS
         mIpcz4rdml/YytvPURlw9MnofGIgg9zbfn077B1mz6F2wjHDe4dyUrNdx84txSBn39p6
         MGXUMTIYTMqanWyro6njU/qzM/CCRo1WAWSI52+H6FVoxWbHRJNQN0aUs4oEaiPhig0y
         Cna+tReMlEchR2U54csj1h3ljQ2MHRhdB+up3aznb7BIb+vvjln3tDN8VDykNzannzrB
         7JSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=WoNGDrH8QdOmVlXJD46GuLOf1QY+xi1ezCU1ZkPka98=;
        b=iP8bFgVgE/qa1KIXbQqQShAXT4rImUuOmNEdZUjYAwWm+ABiUhOY8L7lMkwv3p26RP
         wJIWfSz1pfWmtWey/2yOqD3/ZXDEmpOCH3/bckf8zXCo30WoXwAuyFHTdhTdYWn+Idps
         gF45T1hYSIwiBDO3zAGwDjEvT59Y/LoF7dRuy/EpFn5Ckxhlb3PbuVxunUUg0cLesneF
         LbFx7lBREYQEc1LlbOpfwwElUwdebBapU3EDWs3cDyJpalsRJQTiEAMcvLXrsRAgBHQo
         Plz07jXatFznUiibRcFuPYosS/oovTzX2lRZRigWwlXcTgdJ9HES3eldwSn+y2hGgFgr
         gHuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WoNGDrH8QdOmVlXJD46GuLOf1QY+xi1ezCU1ZkPka98=;
        b=iUBk+1v8vCv/Gm4MEXvM6MmSBYl/Kry0+YIcYKsqEL5WAAdPJ8Gi6h5MvAjYYn6IST
         c492yWGK1FDJoVmq/vr+XlOUbS6LwnMjZw6Iy3iiFYrCziTIh42UPpdFiCRuUi8nqr3K
         m7kSOPLv4coQzgoH2Gh+WaquyPsfuAU1fWislxPj/8ro+4qfE6OoDLZsDyG+mLRQjc96
         Uo/u/M1M7U92VPSOUngAKDRX3/OAV2OwXS8Comf/Y9yHeB8sDSGro9sG4C7D/i7mQSb4
         7JCCOJwrPGmuTSIt+mnoS4a8wMF312gm8WdExFtJ0Re86Zf7EKtOYWt9BPvE21q5UlD0
         oIfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WoNGDrH8QdOmVlXJD46GuLOf1QY+xi1ezCU1ZkPka98=;
        b=d18e0lEM+SZbUOxsxHV24v59Mak2jpSqeCSX0FxdM+FePmuKb8sA/ZycYaJc7TTAww
         3nD+u3HWYe7j9O0eW3vPLbpNtexeYrABmO2mKvEfPQqtRJVm3c0psLF9Y7oLYDKnVCMj
         7GsF81MbBpPFYU4r2i8fIpvL6nJwlCG7vYd/mfnjfUXlFz303dXWMnSHiLgruvqZ6lWp
         I14dIPKftMXJ9MnmskFZcUbexN8jPQJpkoBQw/Mp5IQA7k0hVlQpO7ZpbvCOy6pWESBx
         gw1ODuk1cvltLDinwvSvdzWCzwdS9RlZoAhRmRcWKcStLLR5Oy5hiMrRwpBA7LozODzO
         fUTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532emSRUx+iSZdAeiLUgFeO89ZZm21dIA5iMT54RLqU1hctcQF68
	alaCJ3gTa2fIwC8+Exwmo1M=
X-Google-Smtp-Source: ABdhPJzv9KSn0JszkSgvhEkooc9sPBFCwYFMwPIkEl5kfHHFmDcZx0heTzlz+mIECVc6PQqGKy/qDg==
X-Received: by 2002:a05:6e02:11b0:: with SMTP id 16mr1177152ilj.63.1621281911280;
        Mon, 17 May 2021 13:05:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:4a3:: with SMTP id e3ls4546606ils.5.gmail; Mon, 17
 May 2021 13:05:10 -0700 (PDT)
X-Received: by 2002:a92:d6c2:: with SMTP id z2mr1229942ilp.246.1621281910880;
        Mon, 17 May 2021 13:05:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621281910; cv=none;
        d=google.com; s=arc-20160816;
        b=Vi9po4Q+yolGuQewuSlzImuxlmyHAmyncw4GDFRRAVNX2OwSj7+5LvK3T71DU1MKDX
         cj0obNz3C+ms9zIEkOd8NicJcWp2JzqSc1AJA3qNI6pmX0u6LmnsmkQFvq7PcyI8VmzF
         0Rm4BJglyJ8fW51HcyMjzK2l6m+57fjXG+FbCi/ubhANxkJl2HDnfA9OQs0/VhJrZALl
         DT9VJ6F5BkuPnn0wIpcy6ZqnSUGXuMdBZRkPw3aOz4GvWdlc/O1k3oEOR8k6pVAP74lR
         tPv7MWRhyShBnJ9ttTYTD7ZcZenpWUGpy7bmp/TVxdosUmvZR/MKo6Bsl66A+EBy3HIS
         xsvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=963h0PQKQ7kO+TfJLVjP1sWX3psOvbsbRhzpqEOKF3Y=;
        b=OeX6PMKoAAHodfeN/aI3yzKmdCLegaYyF27evH9dXqWGEcVD+rox07gkdslLUfg1M1
         1eh19VVE34VUo28WpYMCcV1LsnSNJodXM1kTK+AvIOA2Bk0fnKiMgi9ud8NeOJ4ZmcqQ
         lYt15CML7uh9d6n8x3BoqctVR5H945e0niTBr2l5WPhj+cUpLZu3SQAWGaE1m9R6Juw3
         IBVLp33xTW0IDBMBwkjD4bQ4N7v3qzpFDQL5dqhUMlAdnKEvfThF/NG+hNaf+07CuhQL
         0lF0U/sXbAda13ZdOCq/K7qKUO2cP/b+wIr+YlMtnaPDOMmQPg0FHpqAyvwIYVd9LbEH
         EmwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id f13si1247623iog.3.2021.05.17.13.05.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 May 2021 13:05:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijUD-008wn0-6v; Mon, 17 May 2021 14:05:09 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijNr-0001rb-0e; Mon, 17 May 2021 13:58:35 -0600
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
Date: Mon, 17 May 2021 14:57:44 -0500
Message-Id: <20210517195748.8880-1-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
References: <m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
MIME-Version: 1.0
X-XM-SPF: eid=1lijNr-0001rb-0e;;;mid=<20210517195748.8880-1-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/fN9eCwd6Pf3euOoMd6UjKgwMo0ARlihE=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.9 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,T_XMDrugObfuBody_08,XMSubLong autolearn=disabled
	version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 599 ms - load_scoreonly_sql: 0.07 (0.0%),
	signal_user_changed: 10 (1.7%), b_tie_ro: 9 (1.5%), parse: 1.95 (0.3%),
	 extract_message_metadata: 23 (3.8%), get_uri_detail_list: 6 (0.9%),
	tests_pri_-1000: 15 (2.4%), tests_pri_-950: 1.38 (0.2%),
	tests_pri_-900: 1.13 (0.2%), tests_pri_-90: 90 (15.1%), check_bayes:
	89 (14.8%), b_tokenize: 13 (2.1%), b_tok_get_all: 10 (1.7%),
	b_comp_prob: 2.9 (0.5%), b_tok_touch_all: 60 (10.0%), b_finish: 0.93
	(0.2%), tests_pri_0: 438 (73.1%), check_dkim_signature: 0.71 (0.1%),
	check_dkim_adsp: 2.4 (0.4%), poll_dns_idle: 0.65 (0.1%), tests_pri_10:
	2.2 (0.4%), tests_pri_500: 11 (1.9%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v4 1/5] siginfo: Move si_trapno inside the union inside _si_fault
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

It turns out that linux uses si_trapno very sparingly, and as such it
can be considered extra information for a very narrow selection of
signals, rather than information that is present with every fault
reported in siginfo.

As such move si_trapno inside the union inside of _si_fault.  This
results in no change in placement, and makes it eaiser
to extend _si_fault in the future as this reduces the number of
special cases.  In particular with si_trapno included in the union it
is no longer a concern that the union must be pointer aligned on most
architectures because the union follows immediately after si_addr
which is a pointer.

This change results in a difference in siginfo field placement on
sparc and alpha for the fields si_addr_lsb, si_lower, si_upper,
si_pkey, and si_perf.  These architectures do not implement the
signals that would use si_addr_lsb, si_lower, si_upper, si_pkey, and
si_perf.  Further these architecture have not yet implemented the
userspace that would use si_perf.

The point of this change is in fact to correct these placement issues
before sparc or alpha grow userspace that cares.  This change was
discussed[1] and the agreement is that this change is currently safe.

[1]: https://lkml.kernel.org/r/CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com
Acked-by: Marco Elver <elver@google.com>
v1: https://lkml.kernel.org/r/m1tunns7yf.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/20210505141101.11519-5-ebiederm@xmission.com
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/x86/kernel/signal_compat.c    | 3 +++
 include/linux/compat.h             | 5 ++---
 include/uapi/asm-generic/siginfo.h | 7 ++-----
 kernel/signal.c                    | 1 +
 4 files changed, 8 insertions(+), 8 deletions(-)

diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
index 0e5d0a7e203b..a9fcabd8a5e5 100644
--- a/arch/x86/kernel/signal_compat.c
+++ b/arch/x86/kernel/signal_compat.c
@@ -127,6 +127,9 @@ static inline void signal_compat_build_tests(void)
 	BUILD_BUG_ON(offsetof(siginfo_t, si_addr) != 0x10);
 	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_addr) != 0x0C);
 
+	BUILD_BUG_ON(offsetof(siginfo_t, si_trapno) != 0x18);
+	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_trapno) != 0x10);
+
 	BUILD_BUG_ON(offsetof(siginfo_t, si_addr_lsb) != 0x18);
 	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_addr_lsb) != 0x10);
 
diff --git a/include/linux/compat.h b/include/linux/compat.h
index f0d2dd35d408..6af7bef15e94 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -214,12 +214,11 @@ typedef struct compat_siginfo {
 		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
 		struct {
 			compat_uptr_t _addr;	/* faulting insn/memory ref. */
-#ifdef __ARCH_SI_TRAPNO
-			int _trapno;	/* TRAP # which caused the signal */
-#endif
 #define __COMPAT_ADDR_BND_PKEY_PAD  (__alignof__(compat_uptr_t) < sizeof(short) ? \
 				     sizeof(short) : __alignof__(compat_uptr_t))
 			union {
+				/* used on alpha and sparc */
+				int _trapno;	/* TRAP # which caused the signal */
 				/*
 				 * used when si_code=BUS_MCEERR_AR or
 				 * used when si_code=BUS_MCEERR_AO
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index 03d6f6d2c1fe..e663bf117b46 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -63,9 +63,6 @@ union __sifields {
 	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
 	struct {
 		void __user *_addr; /* faulting insn/memory ref. */
-#ifdef __ARCH_SI_TRAPNO
-		int _trapno;	/* TRAP # which caused the signal */
-#endif
 #ifdef __ia64__
 		int _imm;		/* immediate value for "break" */
 		unsigned int _flags;	/* see ia64 si_flags */
@@ -75,6 +72,8 @@ union __sifields {
 #define __ADDR_BND_PKEY_PAD  (__alignof__(void *) < sizeof(short) ? \
 			      sizeof(short) : __alignof__(void *))
 		union {
+			/* used on alpha and sparc */
+			int _trapno;	/* TRAP # which caused the signal */
 			/*
 			 * used when si_code=BUS_MCEERR_AR or
 			 * used when si_code=BUS_MCEERR_AO
@@ -150,9 +149,7 @@ typedef struct siginfo {
 #define si_int		_sifields._rt._sigval.sival_int
 #define si_ptr		_sifields._rt._sigval.sival_ptr
 #define si_addr		_sifields._sigfault._addr
-#ifdef __ARCH_SI_TRAPNO
 #define si_trapno	_sifields._sigfault._trapno
-#endif
 #define si_addr_lsb	_sifields._sigfault._addr_lsb
 #define si_lower	_sifields._sigfault._addr_bnd._lower
 #define si_upper	_sifields._sigfault._addr_bnd._upper
diff --git a/kernel/signal.c b/kernel/signal.c
index c3017aa8024a..65888aec65a0 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -4607,6 +4607,7 @@ static inline void siginfo_buildtime_checks(void)
 
 	/* sigfault */
 	CHECK_OFFSET(si_addr);
+	CHECK_OFFSET(si_trapno);
 	CHECK_OFFSET(si_addr_lsb);
 	CHECK_OFFSET(si_lower);
 	CHECK_OFFSET(si_upper);
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517195748.8880-1-ebiederm%40xmission.com.
