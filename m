Return-Path: <kasan-dev+bncBCALX3WVYQORBMUW2CCAMGQEMCVO3VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E961B37570B
	for <lists+kasan-dev@lfdr.de>; Thu,  6 May 2021 17:28:52 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id l2-20020a5e82020000b02903c2fa852f92sf3813654iom.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 May 2021 08:28:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620314931; cv=pass;
        d=google.com; s=arc-20160816;
        b=UFZeoozNRvNDg6z0Qbe1TchJ6aVAE7T64MTpU90S6ixx0DPKDT9fkI4d1yoF9cbNKS
         Y9vTwM4zc7Gjo8+ABTF7+JDhrZQjEiZDAjZMKE8nU+bMMDmATwPXf2H4ceCPm3bQfLc6
         gfEowRmkv1FnMLjFzm6mywJnyvjnLE/3zLFxoMiXxQyCRu5Mf0PiTSXYDPON31I277rB
         xLtkFj/3iaxs7jS98LzOiJoPADn5CrGouJ9lenXxPYJ51OnuFUl5Wqp0Fdor5qRCV1eO
         uWOlSNzzmQ/GWISM5yhZFFkh6mclZT5rr0j8IYWyGGo49p9TxF5QgjctrnDZWftn8TQY
         xEgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=FMieQmmDQ1lCLPf4ITKLlJEnHraew5v5+904nRZSjyY=;
        b=uZGoJNWmT+GVp4q+mTDQOHW5sFNQYfhjnwP73DxQZo1r+P2cj7/6/Eqs+k9OR3tjrP
         aYmG02L/nKkzgxnIz6I+oiQF703KKBClkCQNU4ty9vQPu0g2FBUvebBXr1dF7F59IEbY
         2vmN2rXrXttPDo+zW+SjlLgffC9MySEbj8LNXRHG8YS/ssv3XfWb1HD1CvN62STGekPw
         jL3jyq8/329W4HJF3mxe+SbHkqorzRy4NtH4BNmgrwXtuXz2lKna2HTPHfzpBtgeOtX7
         jYGzqm7U0VVrB0fqHUB7f8rugaJ2dIv9Hy6PRH+iyEKhDO9B0lnQeB1uUXuRLYXZsXrG
         tjQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FMieQmmDQ1lCLPf4ITKLlJEnHraew5v5+904nRZSjyY=;
        b=m9I65OrIgV3kK2rsKGAPS4fzxfyhignwc+L+3gxzNtXW/qgYd8Grertl+0vWlV8P9W
         qZf3vm7o+JrVHZo8Ya7LEC5EOrOtKwxxh7EsIXMYPw7ZKuFcLjBZL2d1wdFt7jkrJ4s7
         kL3+geeCsF3divAS9lsWshSgrku11qPV1+uNGPmHLV8eRgXVHEJqZ1xidtgPTVAEvxIS
         fYvB1LdFn5KTYGWi/Jp/7Kcc2QqvqAztRlaMKWG/vxoQYZSapQVdKc6Ofs8RnAa68InL
         nubFZZ/j79eipw9MMA0hxg8PM+U9zSvkGaSx9qGHO7/ilWJlv3+lUMMdJeoSLTrPSJ3I
         VLug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FMieQmmDQ1lCLPf4ITKLlJEnHraew5v5+904nRZSjyY=;
        b=NbbOPvXZexSi/lP4sIDN8yXWTf6EKOBoka2VqP4c1jqZge3a4hlZ96x8zMkMwzH1uo
         mMGgyB1ijwwPiuTf1/4D7aMYGoXGy2Jw+C7KwRNgbHkuhp740qdtQdaTp5WZpLcx+z72
         N9iHwsByQkoBzSqWCsCNUM2Ifcv1xJaApw/PnLNeajcy6BjsQHPqUu6t4j2YYt40x2zY
         sGvPlvGfOQ8+AHHbKraJYvjfxYjakYzU6JjqQDpZVT957j9MgsoXq1/rwfJSJZPlVmd4
         uOR8m02K5BsCC6fom/tAc9g5Tg5b8KitDRe+q55aIrNa7fzCAsWgWP2d7HkKBjG3BV0+
         4puw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dopCDpULeAxydeFBL+Oiqpu9F9El/AkkNelytdFtX6fnVrKrZ
	3m+o3Jy+JN91wCJhAv/OI9Q=
X-Google-Smtp-Source: ABdhPJw9FLgegNKnvXH4oyZ/hFX0VsFG+6yDvgdTr2Jtiq8zm/PARX+rhgyc4OCDWoibiHipqTaQVw==
X-Received: by 2002:a92:c566:: with SMTP id b6mr4939384ilj.162.1620314930156;
        Thu, 06 May 2021 08:28:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1845:: with SMTP id b5ls888356ilv.0.gmail; Thu, 06
 May 2021 08:28:49 -0700 (PDT)
X-Received: by 2002:a92:2a12:: with SMTP id r18mr4838108ile.170.1620314929859;
        Thu, 06 May 2021 08:28:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620314929; cv=none;
        d=google.com; s=arc-20160816;
        b=Wzsgp8aDxF9DNayYg7UfQZqJYjHxSqsN9aV8bqjTpq/0T44yXSci2J6NTs0O343465
         xdUXs8ZtvUDDJQeTNuBk3BQ72LTMxwhGfs/XaFz9OELumYno72e0AibwTlkYN11usBc+
         PVus8NMGhmoofBs/LHymLSng0AXUUdie9MzDpt4hOH0gVi6T3c9erZ4wW9mvQ/YUYK3q
         kKrcuz1oAlP4MIt7xAWjD3mv5YuTTQ9n3zJxaHGGJGDBQdvGMyoaVhnvHkq98ySG1QPW
         1ILdcgUNsEfEI5OyVjqUe8HUR110idhKpVJbXK8BqGrH/tQEY0Sl2d8+Yh9J3rIrT2tb
         1w8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=ObKdHYz0GNsx9Q1/PQcQPJ7oZbF+ozEe9tNwXBjq2/E=;
        b=PUeFdn+c8ejp+vuIeiM9NcfXDMGAuqt9kclKRbizLY2rvm8laLKHVKL/oSdRhCoyU1
         tptndGJvCJFwjjRj2z0m4Pquwq/LGK0uZ2Ug1HEHlSzoA18WNNQYehVKVi6AiK/kOm7l
         79eqv9s9WGtokSj+nRl3Zd4RkSECFiF85IC0SWmjQMdTwOy7RUhHnHmH+lSeNwpjSGTz
         Ia12ckVkFThGrQgagZtl2ceCUbQr5zia3qg7gCICAPm15vb51Lm2VLrzRgkFj5xnorOT
         D9E77BYlNeck3GtUHf1aXYtSS8yvo+Vhd6QARxgToZx41xLu/+kdxGIPDXKfaNG3Xb7B
         AhBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id s14si242092ilu.3.2021.05.06.08.28.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 May 2021 08:28:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lefvf-005iqR-MM; Thu, 06 May 2021 09:28:43 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lefvd-006sGN-K7; Thu, 06 May 2021 09:28:43 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>,  Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <m15z031z0a.fsf@fess.ebiederm.org>
	<YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m1r1irpc5v.fsf@fess.ebiederm.org>
	<CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
	<m1czuapjpx.fsf@fess.ebiederm.org>
	<CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
	<m14kfjh8et.fsf_-_@fess.ebiederm.org>
	<m1tuni8ano.fsf_-_@fess.ebiederm.org>
	<CAMuHMdUXh45iNmzrqqQc1kwD_OELHpujpst1BTMXDYTe7vKSCg@mail.gmail.com>
	<YJPIO7r2uLXsW9uK@elver.google.com>
Date: Thu, 06 May 2021 10:28:37 -0500
In-Reply-To: <YJPIO7r2uLXsW9uK@elver.google.com> (Marco Elver's message of
	"Thu, 6 May 2021 12:43:07 +0200")
Message-ID: <m14kff6fve.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lefvd-006sGN-K7;;;mid=<m14kff6fve.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18VBUwGkvjVT/EuvDccLGPbA1rUG9welZ4=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01
	autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4999]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1433 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 4.1 (0.3%), b_tie_ro: 2.8 (0.2%), parse: 1.17
	(0.1%), extract_message_metadata: 11 (0.7%), get_uri_detail_list: 2.4
	(0.2%), tests_pri_-1000: 11 (0.8%), tests_pri_-950: 0.96 (0.1%),
	tests_pri_-900: 0.81 (0.1%), tests_pri_-90: 78 (5.5%), check_bayes: 77
	(5.4%), b_tokenize: 7 (0.5%), b_tok_get_all: 6 (0.4%), b_comp_prob:
	1.88 (0.1%), b_tok_touch_all: 58 (4.1%), b_finish: 0.68 (0.0%),
	tests_pri_0: 1313 (91.6%), check_dkim_signature: 0.39 (0.0%),
	check_dkim_adsp: 2.4 (0.2%), poll_dns_idle: 1.07 (0.1%), tests_pri_10:
	2.9 (0.2%), tests_pri_500: 8 (0.5%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH v3 00/12] signal: sort out si_trapno and si_perf
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


For the moment I am adding this to my for-next branch.  I plan to
respin and fold this in but I am not certain what my schedule looks like
today.  So I figure making certain I have a fix out (so I stop breaking
m68k) is more important than having a perfect patch.

Eric

From: "Eric W. Biederman" <ebiederm@xmission.com>
Date: Thu, 6 May 2021 10:17:10 -0500
Subject: [PATCH] signal: Remove the last few si_perf references

I accidentially overlooked a few references to si_perf when sorting
out the ABI update those references now.

Fixes: f6a2c711f1e3 ("signal: Deliver all of the siginfo perf data in _perf")
Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/m68k/kernel/signal.c                             | 3 ++-
 include/uapi/linux/perf_event.h                       | 2 +-
 tools/testing/selftests/perf_events/sigtrap_threads.c | 2 +-
 3 files changed, 4 insertions(+), 3 deletions(-)

diff --git a/arch/m68k/kernel/signal.c b/arch/m68k/kernel/signal.c
index a4b7ee1df211..8f215e79e70e 100644
--- a/arch/m68k/kernel/signal.c
+++ b/arch/m68k/kernel/signal.c
@@ -623,7 +623,8 @@ static inline void siginfo_build_tests(void)
 	BUILD_BUG_ON(offsetof(siginfo_t, si_pkey) != 0x12);
 
 	/* _sigfault._perf */
-	BUILD_BUG_ON(offsetof(siginfo_t, si_perf) != 0x10);
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_data) != 0x10);
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_type) != 0x14);
 
 	/* _sigpoll */
 	BUILD_BUG_ON(offsetof(siginfo_t, si_band)   != 0x0c);
diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index e54e639248c8..7b14753b3d38 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -464,7 +464,7 @@ struct perf_event_attr {
 
 	/*
 	 * User provided data if sigtrap=1, passed back to user via
-	 * siginfo_t::si_perf, e.g. to permit user to identify the event.
+	 * siginfo_t::si_perf_data, e.g. to permit user to identify the event.
 	 */
 	__u64	sig_data;
 };
diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
index fde123066a8c..8e83cf91513a 100644
--- a/tools/testing/selftests/perf_events/sigtrap_threads.c
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -43,7 +43,7 @@ static struct {
 	siginfo_t first_siginfo;	/* First observed siginfo_t. */
 } ctx;
 
-/* Unique value to check si_perf is correctly set from perf_event_attr::sig_data. */
+/* Unique value to check si_perf_data is correctly set from perf_event_attr::sig_data. */
 #define TEST_SIG_DATA(addr) (~(unsigned long)(addr))
 
 static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m14kff6fve.fsf%40fess.ebiederm.org.
