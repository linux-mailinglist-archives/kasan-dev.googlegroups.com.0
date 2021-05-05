Return-Path: <kasan-dev+bncBCALX3WVYQORBDOPZKCAMGQEDKRN7XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 740E7373D2A
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:26 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id 76-20020a62164f0000b029027f27f50e56sf1497576pfw.16
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223885; cv=pass;
        d=google.com; s=arc-20160816;
        b=i+zvYBdTveo1i7quWDEvpCrKxh6RxUD3lRzC/fvheL9KPT8iRV9paMX2BpbIt3gB6Y
         vXus81WvvNFX8r/9QEmRRXZyUe5WcnKaqzmUpbcWnhxM0+VzF0q2ma63X1KfC58lvgPP
         9/vcVhRqpwYJsouZqo6Selzf2VX+vcnVp+wAwSn19+TB4YHVXNaEHjirEW4K22aa6eZA
         wu8i2ifRbtMutCJdsqlC0tqfPS+4E8BSrgaJbNrdhO6IoG/yziwmxZW0W2cizFktDUzM
         CwDXv/szsMVwNsqtqLZ4NXqkpR8eBU5eJCHIpDtF1eAo810gCncDjbKQlhQ7gVPVFgqW
         3Jjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=2yHYIP4v1MwJvpZfbu5Anq+pvMoSryPUYao8NgidmyA=;
        b=hwu5B4NcSOmGeDuFD2Gv0XmMJcsSAN4KqHbsy+cvqd++2fvT6NuwyF2vScQbBmFLVB
         klNY4jvwAvd8PkNclaI4AGalN4uqW59wUICR1YJGcFa9ChYyXXcM/GPFtkClx3Tq6bGR
         56qnHPf7eqfuwZhpjyWsSpQ2abXNiROGMfllW37zLrpAGs+Qbt9e3DHhZ64dPCcf7E/+
         WYZ8+q0rhkC2wRrtXImIXCezvLvrqJXoMuB4e0GxNGFtTnPHHxdAwPNrYXdUksPOfR1/
         9/8H/RhJ/lBsskhhhGtYkHnBmOo9+hive7VJJQJt6QU1ZK2FwTk69FZroOih6VpxHy34
         O1Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2yHYIP4v1MwJvpZfbu5Anq+pvMoSryPUYao8NgidmyA=;
        b=hCo+s/WtpWSwoVWc9ddZm9qe/CtpYuxpqbOKv4ASCFNR706tlGfJfJ/gqkoQj+H3rL
         tUvpC3XxxFs0tgnyp8Zgk4p2V1hj1YNrp0K9YpawqqWfzz2XXfIgk7m1JLgNHbLRHily
         YsIR9/y3lRid6ZGMzy5fSJQ5C5zcv5Y6V/8L0axQTGJ9XCOAP670wi5Ns5EQxHlWnowU
         Jj5g+Cav8aob9sAxkj+VfuN0oZyLF/N/M3ZmlC6gJJvbAKdBrMOJGBchI1hLu/BTz/Ob
         ortdo51siCbbx5qIJNPsaeprRaMKusaC5RepwS/VySYRwCCw5nuM0JWD7ACZBcgSOhpn
         VZAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2yHYIP4v1MwJvpZfbu5Anq+pvMoSryPUYao8NgidmyA=;
        b=EI6+ws+D9fEJZr1Ghi3GPifK63IrJRCV0vz8jTcfDGZSoziaZLBMKdmgAFuOyW+Iya
         TlzcELxIE20YSiX4iSw32ytZZxYD9GI7blODBZAVmTbXJKLizCqaYnNS6LlX2g5ZBGBg
         WF3yZP+3DkXCCPbZ+ZURYLb7sNt4VQl9S6GgkEuyBDyD0BFTXTaPsoUNIdaQxLFUWwnK
         xgv6qIR+IGt/zx31NYQ+q6WIR8tFDVchOi+Ly3qzHfWverDBqqVltdavJiQoyV4a0/2y
         a5sVKNETj0bjUDpRbg5yc3PthPntcWmhyz12mEki+XLe2JYWlYyjgpLPMY5AzwxMHVUF
         rgwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CnkubYcbKw1kzdC8H85Q42t9u+IxnvKZIg0h9n3xX8kMlVDsw
	mZHRctERI4wyx9DSKYdvxes=
X-Google-Smtp-Source: ABdhPJzQR5MP2oWdVYRcrukWLcPe5nS0jxHpwAYqkx+CWeiFIBQfLIUEPVxSv+yfBI6GMR4ti6AV8w==
X-Received: by 2002:a65:530c:: with SMTP id m12mr19717766pgq.425.1620223885214;
        Wed, 05 May 2021 07:11:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:144:: with SMTP id 62ls11245087plb.11.gmail; Wed, 05
 May 2021 07:11:24 -0700 (PDT)
X-Received: by 2002:a17:902:8303:b029:ee:f005:48c with SMTP id bd3-20020a1709028303b02900eef005048cmr7923022plb.71.1620223884590;
        Wed, 05 May 2021 07:11:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223884; cv=none;
        d=google.com; s=arc-20160816;
        b=dmhvN4rWpDz9kJwY/rF2424a+nnjz60hSyhPThPOBK7vbewZR5VAkkfbUDTYr8XXOm
         +Y3XQ74F61FG3aeHJtFWko0mjxUzc4t4XMBUTDG272YoBOMyp6KqxlIZEf0xjPDvDo3Y
         EANuzWwvLzuXDL2pV8fxqgQuSZeAZpF8Z1FhEVH75I7SsAaf7KYkJZwMUVaA6lDnI15/
         AHDFjz791hiPvrq5gMPZ3/gT74eSRtxLk5dlGHrdUnkHgR74k6dBmucTsNqNsCGIAZxu
         z2zxed/OLi4WATxn5S40W9kNEBOW9z+aZEY9aSAQ3sSH2Gvs5Xf5uOYXPtF34Wv0nd/W
         oSwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=D5oTUxyjwhOtbV7vNL5ba1kdRf3RJ/8YZDolmf8/95g=;
        b=o7SZmjP6MeeQEgB0y1KfwF8K4/GsLFIdhNYQk+bTvCXcdpVytf5gnVMLql6UYr48z2
         8ycC8VPuBKkspyOFqEVW3AhVUnIX6YuSwJOK9VZNi7ZFv35h6AtzYH95sp0TmjiJtZ20
         YvQKqDyVUhY0RKWq7SELswlUakU788UmEe25hxAbXPCEad4ZTYD2QiXrHQswRaEnQVHu
         KBukz4LttVPHGGrjJcuJPmBYNim476Lp1iKXx7LUT9SCZxGsTat6akHBt2pFvAUGo5k6
         BhGgc4kYbeLZAuES009hwNj/BUSVdDm/ayJS0GibtH6UP/RgH4h7GtQzkHAC/d/sLtS/
         wCCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id n35si548866pfv.6.2021.05.05.07.11.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out03.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFH-00CGQe-KR; Wed, 05 May 2021 08:11:23 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFB-00007y-QN; Wed, 05 May 2021 08:11:23 -0600
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
Date: Wed,  5 May 2021 09:10:53 -0500
Message-Id: <20210505141101.11519-4-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIFB-00007y-QN;;;mid=<20210505141101.11519-4-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/JGDMvjy6XiN+Ew7kFPT6FL7zERSVABb0=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.1 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,LotsOfNums_01,
	T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,T_XMDrugObfuBody_08,XMSubLong
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1864 ms - load_scoreonly_sql: 0.12 (0.0%),
	signal_user_changed: 12 (0.6%), b_tie_ro: 10 (0.5%), parse: 1.85
	(0.1%), extract_message_metadata: 21 (1.1%), get_uri_detail_list: 5
	(0.3%), tests_pri_-1000: 20 (1.1%), tests_pri_-950: 1.90 (0.1%),
	tests_pri_-900: 1.61 (0.1%), tests_pri_-90: 1039 (55.7%), check_bayes:
	1036 (55.6%), b_tokenize: 22 (1.2%), b_tok_get_all: 9 (0.5%),
	b_comp_prob: 4.1 (0.2%), b_tok_touch_all: 992 (53.2%), b_finish: 5
	(0.3%), tests_pri_0: 743 (39.8%), check_dkim_signature: 1.01 (0.1%),
	check_dkim_adsp: 2.6 (0.1%), poll_dns_idle: 0.26 (0.0%), tests_pri_10:
	3.6 (0.2%), tests_pri_500: 16 (0.9%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 04/12] signal: Verify the alignment and size of siginfo_t
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
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
index 2dac5d2c5cf6..643bcb0f091b 100644
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
index af8bd2af1298..ad4bd27fc044 100644
--- a/arch/arm64/kernel/signal.c
+++ b/arch/arm64/kernel/signal.c
@@ -985,6 +985,8 @@ static_assert(NSIGBUS	== 5);
 static_assert(NSIGTRAP	== 6);
 static_assert(NSIGCHLD	== 6);
 static_assert(NSIGSYS	== 2);
+static_assert(sizeof(siginfo_t) == 128);
+static_assert(__alignof__(siginfo_t) == 8);
 static_assert(offsetof(siginfo_t, si_signo)	== 0x00);
 static_assert(offsetof(siginfo_t, si_errno)	== 0x04);
 static_assert(offsetof(siginfo_t, si_code)	== 0x08);
diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
index b6afb646515f..ee6c7484e130 100644
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
index 778ed5c26d4a..32b977f253e3 100644
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
index c9bbf5f29078..e9dda9db156c 100644
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
index 0e5d0a7e203b..e735bc129331 100644
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
index 03d6f6d2c1fe..91c80d0c10c5 100644
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
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-4-ebiederm%40xmission.com.
