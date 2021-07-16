Return-Path: <kasan-dev+bncBCALX3WVYQORBLW5Y2DQMGQEELUDW4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 57F473CBA49
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 18:07:13 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id u20-20020ab021d40000b02902a181c33654sf3902379uan.17
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 09:07:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626451632; cv=pass;
        d=google.com; s=arc-20160816;
        b=QyM/WALKy3n1RcMt+7FRsDSGG6laiuqr5bAUnNNC2AWvSQuu/WAuELeZmBrEM/zmHV
         TdLDbey2E3aB0+LO+KAvtCDowySTfuoLwyWKObGqCGV9LRJIQxzojqoXuOOQGarhQkS7
         kShvqEM+b53prDG7us2S51gqOBpAUP6IV3CqjSrnN4hKIYafM0yvM2GG53SwRq5ZEBYS
         5bTVXVeGmLuTFsuKtdOkFZTTvYb7YQSEIdM+u2A5zGVUcelSeGyhhqGDd/WAr3z72fIo
         U+kA0dqmqMl/brYjZ3KYhxaZ58fZ0/yDzOoMkhqjHQhLYyqR1NSR2RJYIlzsTakoYQxj
         iOGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=zLlXCA8UkCte8ErCzDeloiB2nIYahhY61LiDOC5r96Q=;
        b=rAdXNHu4oKbjWf6wILxhPxP5AP4uZE7JybxSYsH5lPKmpi5lYvGaC5LqZ71qKxJgv8
         E+wOyG0/qeHM5UdeF3mns+yf/6fC0/Ewuv5xgFwDmnHc+EjOD1a05v9CgQAkXsD5TjvA
         2moFoBLkgOXhsCJCSz+Y1MUH1WqM/zBNH83E3TZoSKWb2fPHHDZm4ytOaC/zIm1SAYD6
         JjkZS7AXfDUHaTblQFdLUXcIylIZL9AP5vtZH7LGGzJ23dZIwhO/J8INZnqLquh/6y09
         v+mE6xXvZV84Hb57OoxphnrwmkUGmnoKD33BIQoN16irGPHaRc2gd41F4qZikZ/k6cVc
         67HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zLlXCA8UkCte8ErCzDeloiB2nIYahhY61LiDOC5r96Q=;
        b=IEQEjQC01nPN+SQsHtcRKGqRtTQ85RWsh78YgWQl9bWomA4++0M2QpGj8PYuUjsq4H
         2nl7K4yHYaaBMZ0Ajwy7JYK8vj6NyVOjTzEA2wpUJsdbE9uSAiug+IWKDKuXJIbsKQTI
         Umq2g4CcKZImJ7PiXhD6kwWKgrfl/+KIN4sc1GV1PlfENl0fGgk4MrdMFZovl/Rx/mA6
         t+Bbnn0KDRE0MU3IA5vAKRTwwQ32xXYiraILicC2Ad7DVnBuRn2l8SH5LlYrwevDObOf
         cIYWUJVS0mf7724mWbp+8yowNNxBn6gQwfxIWLPeS7iDKgvL8tNbnb9F5F17Gj1+PvZg
         rAbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zLlXCA8UkCte8ErCzDeloiB2nIYahhY61LiDOC5r96Q=;
        b=mZQeOwvSGnpDHzcOFLTnpmucYpF3cZvbug3DTSBCEIF8+W3TbHIoUboxIQ36xeJksy
         raPw2PdUobv0CahgbTn0sJgWwkfDHmOE2y/vIaEoMFo3v4WPllYOrE8/s6Rqbg/aMAXA
         8J2RO9H7cp+QDsc2hHVcR3ReOOSOXgXeQ8q6buVK68o9kt6HtoPfUZDo/I6Vmy6UZiAg
         vWu05yHRrnWgKSl7qUXTJH3GxlFjMh+tH/j2E6JhL6WOpcwcons4CRnDz7PfpTMzT7rY
         Ll5tG2qVKpqg48c/uXhu/K56LDPJHmc5nSsVeqdK+LDq7JKBPLpFD8RhxPw/4Qd79JCD
         u07A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531z6aPTlxzb/xJ3Y5owjc0wKp14d9wypU6E+oa/b36pA3XO2WT6
	jaNg0asHTZC2xBtCRSm7Lm4=
X-Google-Smtp-Source: ABdhPJxrirYM+vFbn99mhqVKmNrca5qXjT9MvG82TIlEjsJfi+xuXreSMzs5PjLOhiu1ccuUEWiSDw==
X-Received: by 2002:a67:fb55:: with SMTP id e21mr13623453vsr.46.1626451630288;
        Fri, 16 Jul 2021 09:07:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c88e:: with SMTP id v14ls3105000vsk.0.gmail; Fri, 16 Jul
 2021 09:07:09 -0700 (PDT)
X-Received: by 2002:a67:7142:: with SMTP id m63mr13432407vsc.59.1626451629824;
        Fri, 16 Jul 2021 09:07:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626451629; cv=none;
        d=google.com; s=arc-20160816;
        b=Sx/WNhlI2gGiuQdNQsVLEw3tFPrbqd8hJsZwPS8S2cu+ed2Kzl3dk2tut0iqAZ2CyZ
         cXpHFuq3P5jgKnvI8wt5VF/IzfgZE2ZGTHoev1/DTyVcefDZdgiXGpBAE0OCYUdN/3+F
         unSJV0pTdrtvHTkT7FAX5Fi/QL3XLgL79BhNwqDPqkofVk8jXWd+2ireW6Svf7TDWmdh
         BfAORGSBX+ESsceNI9dwFhK7SiiDCZRo2FN6NVLO/6KBAUvHzDkdVh/qimhAADU30NF+
         it2M0ULdqZ1ZeuUbO/KKavLqmFgznhR0fzDa9dPS+Bkw829+/chBQqM2C7nIm6kkUQtP
         mFkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=ygHyxQaA6662ie0AjW7xSjosdpi8RC9yFt+/5cEQd6U=;
        b=WdbqkEF/qy8bidJSpsq1YCrsYI6tndFjuy8UppCs2xczC0fX11eB0oEYPrg41Ie0wl
         mc2PONfU5RmRRIXAQrcUoHzxTIAQ2zWYa9Mst0g18ie8Tdcr3YGCun4nChtRYzjcT8Ym
         2WeLBJuEdiI1Y3GNADte5BUNroaOl1RguJVyQGysHX9mv+cjHNNjxVitIO8ZnDFYo8/G
         OslKHAFVPkuWDXV8IMZoM/8KX20nfhqPLcaIhrrDCbMP4Wsx9al7xuMhV7hTf9sjgkP9
         MCgeTZUWD5T8Iql6djEDzH2p+73cqCcQ+Xnxrlya/H0GdcKUIZ2krk0L263r11+p+cN5
         TKGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id l6si1140443vkg.0.2021.07.16.09.07.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jul 2021 09:07:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52]:60690)
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m4QMl-004cav-3N; Fri, 16 Jul 2021 10:07:07 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:59832 helo=email.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m4QMj-00DIze-Nq; Fri, 16 Jul 2021 10:07:06 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133>
Date: Fri, 16 Jul 2021 11:06:26 -0500
In-Reply-To: <87a6mnzbx2.fsf_-_@disp2133> (Eric W. Biederman's message of
	"Thu, 15 Jul 2021 13:09:45 -0500")
Message-ID: <875yxaxmyl.fsf_-_@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1m4QMj-00DIze-Nq;;;mid=<875yxaxmyl.fsf_-_@disp2133>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/qXW5a3TFDnSO7his2S9IbRRvEYot9giY=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: *****
X-Spam-Status: No, score=5.6 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,LotsOfNums_01,T_TooManySym_01,
	T_XMDrugObfuBody_08,XMNoVowels,XMSubLong,XM_B_SpammyTLD
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4994]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  1.0 XM_B_SpammyTLD Contains uncommon/spammy TLD
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *****;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 766 ms - load_scoreonly_sql: 0.16 (0.0%),
	signal_user_changed: 10 (1.3%), b_tie_ro: 9 (1.1%), parse: 1.71 (0.2%),
	 extract_message_metadata: 20 (2.6%), get_uri_detail_list: 5 (0.7%),
	tests_pri_-1000: 15 (1.9%), tests_pri_-950: 1.37 (0.2%),
	tests_pri_-900: 1.11 (0.1%), tests_pri_-90: 235 (30.7%), check_bayes:
	233 (30.4%), b_tokenize: 14 (1.8%), b_tok_get_all: 7 (0.9%),
	b_comp_prob: 3.4 (0.4%), b_tok_touch_all: 205 (26.7%), b_finish: 0.90
	(0.1%), tests_pri_0: 469 (61.2%), check_dkim_signature: 0.71 (0.1%),
	check_dkim_adsp: 2.6 (0.3%), poll_dns_idle: 0.64 (0.1%), tests_pri_10:
	2.2 (0.3%), tests_pri_500: 7 (1.0%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 7/7] signal: Verify the alignment and size of siginfo_t
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as
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


Update the static assertions about siginfo_t to also describe
it's alignment and size.

While investigating if it was possible to add a 64bit field into
siginfo_t[1] it became apparent that the alignment of siginfo_t
is as much a part of the ABI as the size of the structure.

If the alignment changes siginfo_t when embedded in another structure
can move to a different offset.  Which is not acceptable from an ABI
structure.

So document that fact and add static assertions to notify developers
if they change change the alignment by accident.

[1] https://lkml.kernel.org/r/YJEZdhe6JGFNYlum@elver.google.com
Acked-by: Marco Elver <elver@google.com>
v1: https://lkml.kernel.org/r/20210505141101.11519-4-ebiederm@xmission.co
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/arm/kernel/signal.c           | 2 ++
 arch/arm64/kernel/signal.c         | 2 ++
 arch/arm64/kernel/signal32.c       | 2 ++
 arch/sparc/kernel/signal32.c       | 2 ++
 arch/sparc/kernel/signal_64.c      | 2 ++
 arch/x86/kernel/signal_compat.c    | 6 ++++++
 include/uapi/asm-generic/siginfo.h | 5 +++++
 7 files changed, 21 insertions(+)

diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
index 7ef453e8a96f..f3800c0f428b 100644
--- a/arch/arm/kernel/signal.c
+++ b/arch/arm/kernel/signal.c
@@ -737,6 +737,8 @@ static_assert(NSIGBUS	== 5);
 static_assert(NSIGTRAP	== 6);
 static_assert(NSIGCHLD	== 6);
 static_assert(NSIGSYS	== 2);
+static_assert(sizeof(siginfo_t) == 128);
+static_assert(__alignof__(siginfo_t) == 4);
 static_assert(offsetof(siginfo_t, si_signo)	== 0x00);
 static_assert(offsetof(siginfo_t, si_errno)	== 0x04);
 static_assert(offsetof(siginfo_t, si_code)	== 0x08);
diff --git a/arch/arm64/kernel/signal.c b/arch/arm64/kernel/signal.c
index 4413b6a4e32a..d3721e01441b 100644
--- a/arch/arm64/kernel/signal.c
+++ b/arch/arm64/kernel/signal.c
@@ -1011,6 +1011,8 @@ static_assert(NSIGBUS	== 5);
 static_assert(NSIGTRAP	== 6);
 static_assert(NSIGCHLD	== 6);
 static_assert(NSIGSYS	== 2);
+static_assert(sizeof(siginfo_t) == 128);
+static_assert(__alignof__(siginfo_t) == 8);
 static_assert(offsetof(siginfo_t, si_signo)	== 0x00);
 static_assert(offsetof(siginfo_t, si_errno)	== 0x04);
 static_assert(offsetof(siginfo_t, si_code)	== 0x08);
diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
index ab1775216712..d3be01c46bec 100644
--- a/arch/arm64/kernel/signal32.c
+++ b/arch/arm64/kernel/signal32.c
@@ -469,6 +469,8 @@ static_assert(NSIGBUS	== 5);
 static_assert(NSIGTRAP	== 6);
 static_assert(NSIGCHLD	== 6);
 static_assert(NSIGSYS	== 2);
+static_assert(sizeof(compat_siginfo_t) == 128);
+static_assert(__alignof__(compat_siginfo_t) == 4);
 static_assert(offsetof(compat_siginfo_t, si_signo)	== 0x00);
 static_assert(offsetof(compat_siginfo_t, si_errno)	== 0x04);
 static_assert(offsetof(compat_siginfo_t, si_code)	== 0x08);
diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
index 65fd26ae9d25..4276b9e003ca 100644
--- a/arch/sparc/kernel/signal32.c
+++ b/arch/sparc/kernel/signal32.c
@@ -757,6 +757,8 @@ static_assert(NSIGBUS	== 5);
 static_assert(NSIGTRAP	== 6);
 static_assert(NSIGCHLD	== 6);
 static_assert(NSIGSYS	== 2);
+static_assert(sizeof(compat_siginfo_t) == 128);
+static_assert(__alignof__(compat_siginfo_t) == 4);
 static_assert(offsetof(compat_siginfo_t, si_signo)	== 0x00);
 static_assert(offsetof(compat_siginfo_t, si_errno)	== 0x04);
 static_assert(offsetof(compat_siginfo_t, si_code)	== 0x08);
diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
index a58e0cc45d24..cea23cf95600 100644
--- a/arch/sparc/kernel/signal_64.c
+++ b/arch/sparc/kernel/signal_64.c
@@ -567,6 +567,8 @@ static_assert(NSIGBUS	== 5);
 static_assert(NSIGTRAP	== 6);
 static_assert(NSIGCHLD	== 6);
 static_assert(NSIGSYS	== 2);
+static_assert(sizeof(siginfo_t) == 128);
+static_assert(__alignof__(siginfo_t) == 8);
 static_assert(offsetof(siginfo_t, si_signo)	== 0x00);
 static_assert(offsetof(siginfo_t, si_errno)	== 0x04);
 static_assert(offsetof(siginfo_t, si_code)	== 0x08);
diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
index 06743ec054d2..b52407c56000 100644
--- a/arch/x86/kernel/signal_compat.c
+++ b/arch/x86/kernel/signal_compat.c
@@ -34,7 +34,13 @@ static inline void signal_compat_build_tests(void)
 	BUILD_BUG_ON(NSIGSYS  != 2);
 
 	/* This is part of the ABI and can never change in size: */
+	BUILD_BUG_ON(sizeof(siginfo_t) != 128);
 	BUILD_BUG_ON(sizeof(compat_siginfo_t) != 128);
+
+	/* This is a part of the ABI and can never change in alignment */
+	BUILD_BUG_ON(__alignof__(siginfo_t) != 8);
+	BUILD_BUG_ON(__alignof__(compat_siginfo_t) != 4);
+
 	/*
 	 * The offsets of all the (unioned) si_fields are fixed
 	 * in the ABI, of course.  Make sure none of them ever
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index 5a3c221f4c9d..3ba180f550d7 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -29,6 +29,11 @@ typedef union sigval {
 #define __ARCH_SI_ATTRIBUTES
 #endif
 
+/*
+ * Be careful when extending this union.  On 32bit siginfo_t is 32bit
+ * aligned.  Which means that a 64bit field or any other field that
+ * would increase the alignment of siginfo_t will break the ABI.
+ */
 union __sifields {
 	/* kill() */
 	struct {
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/875yxaxmyl.fsf_-_%40disp2133.
