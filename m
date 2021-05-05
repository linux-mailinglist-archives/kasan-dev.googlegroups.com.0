Return-Path: <kasan-dev+bncBCALX3WVYQORBBGPZKCAMGQE6XLXMDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 688C7373D22
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:17 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id a22-20020a0568301016b02902a60679231fsf1235288otp.6
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223876; cv=pass;
        d=google.com; s=arc-20160816;
        b=crjnqSeeiwRtesE7SLfNBMEmie97K/lpXoUKPzx512VUF1erpxXIQFHI3B0QKVZ4Aw
         zbCyj8stgnQaMXY+e7zTJ3v/XYaKGIVhs1Xvc5QPzAfECPKiZKmPjdvJxwMX0I38Cqeh
         S0lPrQ1b6BbWy+uK1QX9qdnGjZQvhPCJfBeF0ola8PdLkcfXHGIKay+V5hzuX8keR+aX
         0AYwlxCOR3/XWuLZ7fG/JecMH8yKKLzGzd2A1w20dKnYnafxBDtFhbdCNT1914YR193E
         k49zkNxz5XrZjexxhIo0Wg1AH5hPyuoBBE3N9K6Z57q/1nnDsV0oRk3Vw3dwAy1z9lE1
         AdvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=bHrlIwl4nX6xYceh8NRLJtpFiL6NPN8YKytns/5Atgo=;
        b=OuajoqDFt1/P1d/uaRZGCGdd91kJihoBg9ZG8hAC1RHYnVws9uhulLWNFvOiP2f+cG
         eXSXFDbcyba6cC55MRCTeB+lQStFGx1w6pwLYOBDeNePiW5plwnqQ4hnptIX36T93wZI
         kzRop+kn2F2j21nKTrUZpEmMzC2gnLyHjrHRduiXNJ2PGqN4FBhjPb9B9OW+tSn/lJVu
         1mIr17Zo0CoNFpRkRp/ZcdbkmPbOh5xByyW8QyWfRlWHyzrqc7VDInSTvBIpAiv/Nu0k
         pLlbBZHYAlvp3oDe1DfQMKxJ1UD5d9inDOZbijKnMT3hlwkrBSvRPgE+FwqR7zrMowca
         Fjhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bHrlIwl4nX6xYceh8NRLJtpFiL6NPN8YKytns/5Atgo=;
        b=SY3RIYqo07oArDDZJ8oIvQIOKAZEmY+8Z56TBVTia409Mb7cljoToWZJ0aggug/77x
         3E9McFB16FpAKvO3Sj+qDzO8fe3IhEIcHt2dDujuvoJKwhizUCQzLhjr9I8YLWhpnWzr
         LCTGyawhBeK3jD2hvyrofOqvqkl8hbBpj0TN9MYPFnyysGPnuDLXMv2cq3fwtM456s7k
         YEHRfaE76rrByzN+9lUcW0drAK+IycqAkFBS2ukv+SiM3/mHfzuz/hdgvS0IffMxcYED
         ulX9uS7cM2aGyrpw5cVdPhqggRWVx/duo3ZM8yiFGaGYzR7TMnAtua4J7RYoNosRyYuQ
         pfYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bHrlIwl4nX6xYceh8NRLJtpFiL6NPN8YKytns/5Atgo=;
        b=k/HN+thTYt/GOEyKFqX7RQD3PycWjxxCKKUj7PWo66NpX4F4qLrirYw71aq4c1zkmq
         PAETHDIa3UH2UYZo7z/dEUpHvZ65KnOeUB2go60oQHD1U+UZIZWkSbwmfOs4sjj9Z6Br
         Z8w0IGov7dVuX4M09bMPl371AixOx2XAzFwNJMJIwXS9gxcEhqxaHTK2ReVbOYJWyCvx
         +pymXYdus7nannkplxcu+yiA8lvf8bnVarM6zZZfRTcNComR0Y03Kw2BOlyt/Ck4/ri+
         PzTZraH7g5cMxqMdHNL+oXcls6eKRgSqfhzpXMIBrr2gIjlatU1Om+2tjzTNrhTDkMWK
         jY+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FXUJxp89vzYx2rVohCQUXVwsdlXqu5G1jZdQcE5URq0AFVTiq
	aiUYqffJAcNMcbA+E2d27sE=
X-Google-Smtp-Source: ABdhPJyoXh42+E6SWcmCPCCY+5F1qlMBMb/NR8xFtAChCulL4pDY5AmMzeFa5B3foz1yYNXNiXw6MQ==
X-Received: by 2002:a05:6808:6ca:: with SMTP id m10mr20841927oih.166.1620223876216;
        Wed, 05 May 2021 07:11:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6c87:: with SMTP id c7ls1781908otr.3.gmail; Wed, 05 May
 2021 07:11:14 -0700 (PDT)
X-Received: by 2002:a05:6830:1103:: with SMTP id w3mr23569068otq.304.1620223874411;
        Wed, 05 May 2021 07:11:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223874; cv=none;
        d=google.com; s=arc-20160816;
        b=RjUTE6W6Ge5ZMDG80JfOVMqU16e/ubsjbzHVASbgxKN8r2wYfmYbabwEpTHmbJNRDe
         dh6RnLkz4AuweUjUz7Noi3NelKUsato8JFa18Tczgf9JdllHXBFcfQ78AaIvyWvWadLc
         hf15XI+yK0uSy1Dpn8XkhhlQXdyHpDmfEXS0cweRmvhD6YtRCoRquCNTJNAMMsnMuamW
         2HPIGdhJXlmhE33G/m85q4/u00PsK3HIRRAixjDxQzOI4Q8GgjxLpuIKPOa+8gz5iKED
         IOJC4k0RAiaLhj2yKS0ra6JbuLt5D5KhkeEe4Jh/0uT5bnf7jM7o3K8GpzrkMhmCHARa
         8rPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=0Vu3LLzjkWLam3hLWJknx7FW/nuXeN8VtHkpMu+zsbM=;
        b=bFPsnNhFIt4fHr9Lpe84BUSKpGFLzA2YyMvnNG0RHD92QmFa+lc5CO0uhGnDw7//jX
         NsDb7cf/+cAszYywwMYT+Dklf5OiRmto2h1tTeH0YdGKLidt4kjDQ/gGgXndh0Eexbzp
         G12vr8zH6gyO14D++RI6+oNwWYaOFZnOf8WmIlqz8gVpQiDvLwd5ciV2uVLiGi1nrBJ2
         OIkKBSV5UE1fC90zVf7/qhRNUXkYxeygDFOgobD05CTZhuWPlpBMwTbeYML5eUlXmrvW
         iQlG/dGiNb1syo/CwxXjAF+gus7B3cJXKOQlOiC9VuTKUjJ8j5yRNVK6CjjkkctU44Fy
         YAGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id n10si409267oib.3.2021.05.05.07.11.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIF7-002t67-5Z; Wed, 05 May 2021 08:11:13 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIF5-00007y-UW; Wed, 05 May 2021 08:11:12 -0600
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
Date: Wed,  5 May 2021 09:10:51 -0500
Message-Id: <20210505141101.11519-2-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIF5-00007y-UW;;;mid=<20210505141101.11519-2-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18/u+QRnS8C937fZUCkilLDlSg2BWeDY0E=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	T_TooManySym_02,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.0 T_TooManySym_02 5+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 565 ms - load_scoreonly_sql: 0.06 (0.0%),
	signal_user_changed: 10 (1.7%), b_tie_ro: 8 (1.5%), parse: 1.59 (0.3%),
	 extract_message_metadata: 20 (3.6%), get_uri_detail_list: 3.1 (0.5%),
	tests_pri_-1000: 22 (3.9%), tests_pri_-950: 2.2 (0.4%),
	tests_pri_-900: 1.79 (0.3%), tests_pri_-90: 74 (13.1%), check_bayes:
	72 (12.7%), b_tokenize: 16 (2.8%), b_tok_get_all: 8 (1.4%),
	b_comp_prob: 3.3 (0.6%), b_tok_touch_all: 41 (7.3%), b_finish: 0.98
	(0.2%), tests_pri_0: 414 (73.3%), check_dkim_signature: 0.93 (0.2%),
	check_dkim_adsp: 2.5 (0.4%), poll_dns_idle: 0.33 (0.1%), tests_pri_10:
	2.3 (0.4%), tests_pri_500: 12 (2.1%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 02/12] arm: Add compile-time asserts for siginfo_t offsets
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-2-ebiederm%40xmission.com.
