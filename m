Return-Path: <kasan-dev+bncBCALX3WVYQORBW7UYGDQMGQEDD4V7WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 91C683CA50C
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 20:11:40 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id w191-20020a62ddc80000b0290318fa423788sf4878423pff.11
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 11:11:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626372699; cv=pass;
        d=google.com; s=arc-20160816;
        b=VQS3BlQEP73DPzJKjPFaiFV62U7TqRh4nNFK3li+8oPfLE+V7Op18ugJXBKz7fFJol
         YNa1gT3jL50yv1TF+NINyiSTIEbkvR65IeOKJG4kQynDSjnMa3U9U5CzCexWITEwcnNb
         hlrhwSv65ZXm4eA86mAJNBmGG/Jn0mPw7QcRhfbV1MudNl/QAsGUJR517OEq5d12UNUc
         disnlC8Itq0NWWnuiSxzgOzg3Qu7vF056GYCORuRJ44IgKrfRSQbzBWeJkJnDjZ50cUK
         UZ/PixhC1wgBOurytZp21a03ExVCxo0REB+81t4nTdBabuWj+gdaM9fdvhnpNt7JwmBs
         EDLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=glj7olNDS56P3N6s6iEkBHCazRDijuOac3U3zNO43Rc=;
        b=YnBC8byqglCDSbiFGopJ82ieW76kklshxnvtpBusxaLysZYEhwV8I697G9UqsFxj7z
         Q5HYUb3Zvro8bOc6LOpI5rQyQxVAt8Mr+QHyGZKdhqwf1hQckMDO1pEPADCYYRlQmy6x
         mvMX2SqROvggXAdlQlbcN0KYNVXFK7vtJz7u9UR6ImzL/FKGr778ekJv6OM10T12ZHHA
         j1JyyQjpIRN1aQlaOPH7+5IrsypmKjHi0LStJ7Heu/k7kz4rAEL9JfaM48P8OpSK1FWw
         lnciafGJujT4rEuG9xvUxkkrQfdTNOPc0h6DdT/e30ehce3LMB4AVh7YfvS1nfpXBnDb
         EqpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=glj7olNDS56P3N6s6iEkBHCazRDijuOac3U3zNO43Rc=;
        b=RMtKBNUQJJ89wN2Lk82mY4c+OTuRriEk2KyomdBv8jWkOebLEcAUI2lxcuaIREUeoS
         9tz2mjBq4wQ/Rb84Eusdn3ETqGeW3o8cnk8/UXk19Ez7IwXvmGVvOCpfEvxGNrwcLxbj
         vKs8K2oiaEFYvbM3uGvk9b/AYnJ/tgxmfNvFxsFLRdZiUmbRKsr0rt03QLapS1ot/the
         qTjcSYAQBLoE9YVmY3/sFPDHYia3hBsnghnB7ZCVao9flVhf5XwhXIuYl6gPM9bC3JCL
         ookfh1KdstNRSVIoPVO8CJIBSNWicH6jopokcufO9qBKs+iv83uE4XQv9Z5DU9/fGA2o
         n9DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=glj7olNDS56P3N6s6iEkBHCazRDijuOac3U3zNO43Rc=;
        b=n9kThZKTnD2yJB3KIxoSuEZbSd0op1sgYTHhdutNyFJ90mNJUforS6/PpmRLzCN2sh
         e4afmvdOmItG/PjZtk9PHsRJJpcdBOsa1CMA6Cw26sIWwiogjj02jA+fP65a+2BRWzmR
         eW75d4bF6o1Yx+eW0Pl8t/CQXCu1xeXeQzcawL1LaxBb4PmMM3tJ/32PqFr5KgG+2BY8
         CTp9tkH9fT49KQGEci3T1t0QjqomZIEmymU66VQZmBMTFbVxb2OoL8qCTPiY749n6O1m
         mIATf9m5/jYlSHw8EuS9s/xjbqrGokUMV/PWnr0wPQw5k9sGrfxu3T8dT06uD+ejdRUj
         wKug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532t8r/oL2UHYzaxsnT6uiCybMLE7leV5QMu/WJvUwpinHM5mO5a
	9JuLcSC2wk6biCAYqEVlJWY=
X-Google-Smtp-Source: ABdhPJzYPHe68jZo2rZoZeeQVn8YdRE/2PCRvKnq2Pja3Vwu3kZ63FlMQAcceoZgJIP3pw8zB4ZSRg==
X-Received: by 2002:aa7:8683:0:b029:32e:2a35:941e with SMTP id d3-20020aa786830000b029032e2a35941emr6047674pfo.44.1626372699211;
        Thu, 15 Jul 2021 11:11:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:c96:: with SMTP id a22ls3314690pfv.4.gmail; Thu, 15
 Jul 2021 11:11:38 -0700 (PDT)
X-Received: by 2002:a63:ed50:: with SMTP id m16mr5859299pgk.231.1626372698707;
        Thu, 15 Jul 2021 11:11:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626372698; cv=none;
        d=google.com; s=arc-20160816;
        b=zQ26pGCWBgv/2ohkhFcueTrVuOQgli1ec5veWaGa0unte4xnPFX49ekj+dbAqLny5B
         BEQ/lBTXcZne9a/LhEgBKgvgIlpBp3/bLr/FuRBiua0okRnnHXwcrgRjYZSrQZAH4Skw
         XvgVV7HQtHjVq1QTstpVMMm3j7uu92vWbVH9UYetx0hdwbRJVCrJSKui6boUqAoLi3do
         n6b4zfxyjunTrUedT9TQmWDBKkf4imY9b+xM9kx9sIsAYmqO0azUm6Cj/06IBIfrsLNI
         maMji0MKTg3S77avcrwWSSRpClfswyKoYmVhcqHdgNvnO1NCJEcmOPb9UDVIUkXU9/Y6
         +3tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=+LyX8cMI2EEHE/Y2HID/uKOM5Mpz4iJQ85dLLK8CQ/c=;
        b=bK/uNsxQPLdA/6m+Zl+CnXwT8wqZHND+RnP5o9uOKB/37vPFFlJOLC7DaTuSkBRJbK
         D3j8UihqM/IClTOKE+MWkgnnba0pyrvKF5ePBsvrT3EVEQJYNDHKfzfnC8iQk0MnwLjt
         19KegcOUYMd/qYKF8GRfiLyr/LtupHV8USI4wh07oOhcc6JawwX1USx824mYg46uxcfG
         nshCZWtWBFvMTZkD7ZGYpxhu9u82/tS9jSxS++jXI7vmVoNdMiP1mHQv9xilxxyL+PD1
         Gh+jHrpKDAbtM68By0xrSH5734dZrYDOjeVtO69XjCU3QhCYONvGXVo3R3ilew2Apn9e
         jcmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id y190si971359pgy.2.2021.07.15.11.11.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jul 2021 11:11:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45ph-00Beo1-Pm; Thu, 15 Jul 2021 12:11:37 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:57024 helo=email.xmission.com)
	by in01.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45pg-00CT9t-8u; Thu, 15 Jul 2021 12:11:37 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133>
Date: Thu, 15 Jul 2021 13:11:29 -0500
In-Reply-To: <87a6mnzbx2.fsf_-_@disp2133> (Eric W. Biederman's message of
	"Thu, 15 Jul 2021 13:09:45 -0500")
Message-ID: <87y2a7xx9q.fsf_-_@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1m45pg-00CT9t-8u;;;mid=<87y2a7xx9q.fsf_-_@disp2133>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18F+kMpLYBfdBjbPofyGBUsL5UJA13sRFA=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	T_TooManySym_02,XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4957]
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
X-Spam-Timing: total 546 ms - load_scoreonly_sql: 0.07 (0.0%),
	signal_user_changed: 9 (1.6%), b_tie_ro: 7 (1.3%), parse: 1.17 (0.2%),
	extract_message_metadata: 13 (2.4%), get_uri_detail_list: 2.3 (0.4%),
	tests_pri_-1000: 15 (2.7%), tests_pri_-950: 1.34 (0.2%),
	tests_pri_-900: 1.11 (0.2%), tests_pri_-90: 74 (13.6%), check_bayes:
	73 (13.3%), b_tokenize: 10 (1.8%), b_tok_get_all: 6 (1.0%),
	b_comp_prob: 2.8 (0.5%), b_tok_touch_all: 51 (9.3%), b_finish: 0.91
	(0.2%), tests_pri_0: 347 (63.6%), check_dkim_signature: 0.69 (0.1%),
	check_dkim_adsp: 2.7 (0.5%), poll_dns_idle: 0.40 (0.1%), tests_pri_10:
	3.9 (0.7%), tests_pri_500: 77 (14.1%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 2/6] arm: Add compile-time asserts for siginfo_t offsets
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
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

From: Marco Elver <elver@google.com>

To help catch ABI breaks at compile-time, add compile-time assertions to
verify the siginfo_t layout.

This could have caught that we cannot portably add 64-bit integers to
siginfo_t on 32-bit architectures like Arm before reaching -next:
https://lkml.kernel.org/r/20210422191823.79012-1-elver@google.com

Link: https://lkml.kernel.org/r/20210429190734.624918-2-elver@google.com
Link: https://lkml.kernel.org/r/20210505141101.11519-2-ebiederm@xmission.com
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 arch/arm/kernel/signal.c | 37 +++++++++++++++++++++++++++++++++++++
 1 file changed, 37 insertions(+)

diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
index a3a38d0a4c85..7ef453e8a96f 100644
--- a/arch/arm/kernel/signal.c
+++ b/arch/arm/kernel/signal.c
@@ -725,3 +725,40 @@ asmlinkage void do_rseq_syscall(struct pt_regs *regs)
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
+static_assert(offsetof(siginfo_t, si_perf_data)	== 0x10);
+static_assert(offsetof(siginfo_t, si_perf_type)	== 0x14);
+static_assert(offsetof(siginfo_t, si_band)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_fd)	== 0x10);
+static_assert(offsetof(siginfo_t, si_call_addr)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_syscall)	== 0x10);
+static_assert(offsetof(siginfo_t, si_arch)	== 0x14);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y2a7xx9q.fsf_-_%40disp2133.
