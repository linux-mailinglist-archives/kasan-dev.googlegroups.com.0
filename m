Return-Path: <kasan-dev+bncBCALX3WVYQORBJ6PZKCAMGQEMVUQHZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B137373D44
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:53 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id s82-20020a632c550000b029020f29c9e921sf1398398pgs.17
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223912; cv=pass;
        d=google.com; s=arc-20160816;
        b=std4ZNx0Vi2oM3bgQTCwWgN9TE3e90RDolcZJLDdW3mBM+p5Hbu1nRxudxozgSLWgA
         zWoNKA39x06ynxhvP2IeWCVPAWNDyZzGMf3YgP4gM+ZcMhFarv8x+s103VInUPrO9Vna
         xYM6JLvcrtXLVqZv0kBPIjypFdQapSeldJLKCIr6NlGQcYDe0k1aqoKAYj9dE4zPV9Sv
         LD9pmMuNS91eQCQl8F2x7n67dFbM37TYjpIOrKIaecLleHjmhobClEUDPLCOjjIuMuir
         5G3y0oqD1bW/C5Kafy40a3RTf8RJDhk3pCE2VwvVyGwRzeav3CgBj6gysi8WCSlf10nA
         iNqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=mgqXlZqZ03BATfpyN/SAfztQt05OkOTJHcERCJ1CHR0=;
        b=F5J+89fuUsSGs8/PaheKEsVO+zE1sfm7tDIwDYU8d5ODE/H7kWER7cigp+HDM5LFot
         ycAzscVeLQUaeoghVpBhEoXRN0qy4WtBGrR1a2zPYF6A4izlKW5rylDEDYrKliAr6GNa
         ODqfYpjejhGBZyWLaLB78GZNOx76FQlCIAt9cMfLI+UkbrRAcyAsPn6cAXPm/F731iZI
         MqVXnFodsNzFzFkfTkOZkRMQTTk8vkxKJmC42oxVlZ6Q2FkcEcHI2HGEvGaiQFqE1grr
         QDIyHipsZCIsIWD3Jg7ynR3bNy4Oafk08VV9Ul2h3jcxM46cvybYrhlJCzgALLCY1mfI
         FbAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mgqXlZqZ03BATfpyN/SAfztQt05OkOTJHcERCJ1CHR0=;
        b=VGocS/BXXulXtd52tPbLyucu/P3u7V/jut5uUxBHzRPll1X/+W8Nb8JngaOZ7540SO
         81H6RipDcqsAB/uYMm35RB0QI5saH1HGkw5mzi+fPAXfIg53KJP6yAANrO+1j46V/ie2
         zrGpbN2zlod6NG/mOZxPFQJNfWA84+Exbo9ARwD2RGppycL6fiRdbO97JvKvBPt0a63C
         JIP/cW0sHB09DwGCfVhTv/pGenR4u5DpdRel80dSZkK/vkjEdETSvVyfF8W6RwF0s3Bl
         BhrhXHtMQ5qNRDpRRs+Dlb9hKph4/mRq2qobIN1kRah4nhm69P4TOhMUCTPqM1GdKpcx
         IEng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mgqXlZqZ03BATfpyN/SAfztQt05OkOTJHcERCJ1CHR0=;
        b=A0o/WBqUD9oaf9ffOOWOvaGmtxY85A+90BDDVImqWz+WRilKZQn1fDq8XBVZiVz/Yt
         EUzsfNYfA/DBLhVw4b0ufU3sXn/nBxKWMMv4F/MooYKT1LTvTW0xfbFvvMg1h6pBg6Ls
         cshqUo1A+JvfCk0qNJzJKGFJqxOQtWRADZ0ksYSWSzXKVgxqRbx8x8I2UA8VOhdlpC7Z
         U2Vd6xXUeQwZOmNRBEyAcEnzjQFLochFHUQ5pnd2vEOUt5Hbb5xOoVdkvsjD9dVZMFvw
         En/bwMkRbq+dvzvq1AE0FcMHLw6ycIyetR1KPSKSmOMFAg8jEzi6D4wrOP4b7n4lFaF3
         3sYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+KZ4OtHFzq2HHpNC1qJNINJ+yfqeAbCJysZTCYHBgXZX/ffv8
	hsGoVoXzveDRUz6EObEz6lU=
X-Google-Smtp-Source: ABdhPJwbcuBj1Nq6Q2N+gwP+Gq3oWrQGbStHZ+uTU5YbvzqHLvFDkjyUoWgCRf8Nsu2eDZvDvnSegg==
X-Received: by 2002:a17:90a:7897:: with SMTP id x23mr11685396pjk.133.1620223912025;
        Wed, 05 May 2021 07:11:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1393:: with SMTP id t19ls7481227pfg.1.gmail; Wed,
 05 May 2021 07:11:51 -0700 (PDT)
X-Received: by 2002:a62:6142:0:b029:28e:b072:6b7 with SMTP id v63-20020a6261420000b029028eb07206b7mr12774043pfb.65.1620223911484;
        Wed, 05 May 2021 07:11:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223911; cv=none;
        d=google.com; s=arc-20160816;
        b=a15GQCkbT0WyiiX7hocUyOeoPGr8qRfXxuV1EVBdv93rXhdJXClmCf+lNg0LasohHF
         8sj4vbDNcUaetesrRJOLg+PjZZ8lUkuaFxxY0pJ+K1BANQwM5J3xrcxr8H7/8xUJchdC
         jv4e0MP3nqmufXwv+EGmRYcK7v2P7HUsEwZbDuG4z4I9C5IHaKRFsaD+w462bIe6DXn3
         qtj8XElizBP7UL4vILBQNa93yDXPOk7dyBaFWwqTFcp/2wXACdX+/YSpXazT14R/wuTo
         5DDuO16es0AdxePWdbDCS+T1i6sSGPLrYasfM2m1xRWnJ9lnMQPSAn2lCSCQwIBUtFPE
         I+zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=yYvSdTQBJe9uvEE+AvylM2wSoGy6ug8yzRrD0h+od6k=;
        b=NDtpbTqPxhGON3mrphwNgkTa5FyGNlQJ5ZIk8GpJAD1mqrUKMr4eII6TD7kI5dBDif
         4cb/RVgK0zaVeEicJ2czUgGM+N9FeS9bIZAGqJtK9sCespIP0QL+iakQx9G2WP6uyvee
         2+FbVwU0ivMZ4K1NlEglnINTqNqH2ejLSFJ83obl0BcNoAv4tAoFVGgG/8moaUREY9ko
         W+LDSVgdPvTuUTMsny9CY+rD6r5g2P+4anTEy9SD20FnrGv240HjCJnB1dX/GYW2ujX/
         07fCacuTgz9c9R1QWnvamQfCufNH6HvLVZ4k+7Jvp1K+Z1uzVvmL1ROMzmLDT2JCw756
         YNFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id j17si552956pfc.5.2021.05.05.07.11.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFi-002tQj-IN; Wed, 05 May 2021 08:11:50 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFh-00007y-27; Wed, 05 May 2021 08:11:50 -0600
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
Date: Wed,  5 May 2021 09:11:00 -0500
Message-Id: <20210505141101.11519-11-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIFh-00007y-27;;;mid=<20210505141101.11519-11-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19KMXubSJ5KgKhTfzVyS/RkLj21FSwLbrg=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.1 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,LotsOfNums_01,
	T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,T_XMDrugObfuBody_08,XMSubLong
	autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1002 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 3.7 (0.4%), b_tie_ro: 2.5 (0.3%), parse: 1.00
	(0.1%), extract_message_metadata: 12 (1.2%), get_uri_detail_list: 4.6
	(0.5%), tests_pri_-1000: 11 (1.1%), tests_pri_-950: 1.01 (0.1%),
	tests_pri_-900: 0.82 (0.1%), tests_pri_-90: 282 (28.1%), check_bayes:
	281 (28.0%), b_tokenize: 18 (1.8%), b_tok_get_all: 10 (1.0%),
	b_comp_prob: 1.80 (0.2%), b_tok_touch_all: 248 (24.8%), b_finish: 0.70
	(0.1%), tests_pri_0: 681 (68.0%), check_dkim_signature: 0.61 (0.1%),
	check_dkim_adsp: 2.2 (0.2%), poll_dns_idle: 0.84 (0.1%), tests_pri_10:
	1.73 (0.2%), tests_pri_500: 6 (0.6%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 11/12] signal: Deliver all of the siginfo perf data in _perf
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

Don't abuse si_errno and deliver all of the perf data in _perf member
of siginfo_t.

The data field in the perf data structures in a u64 to allow a pointer
to be encoded without needed to implement a 32bit and 64bit version of
the same structure.  There already exists a 32bit and 64bit versions
siginfo_t, and the 32bit version can not include a 64bit member as it
only has 32bit alignment.  So unsigned long is used in siginfo_t
instead of a u64 as unsigned long can encode a pointer on all
architectures linux supports.

v1: https://lkml.kernel.org/r/m11rarqqx2.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/20210503203814.25487-10-ebiederm@xmission.com
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/arm/kernel/signal.c                      |  3 ++-
 arch/arm64/kernel/signal.c                    |  3 ++-
 arch/arm64/kernel/signal32.c                  |  3 ++-
 arch/sparc/kernel/signal32.c                  |  3 ++-
 arch/sparc/kernel/signal_64.c                 |  3 ++-
 arch/x86/kernel/signal_compat.c               |  6 ++++--
 fs/signalfd.c                                 |  3 ++-
 include/linux/compat.h                        |  5 ++++-
 include/uapi/asm-generic/siginfo.h            |  8 +++++--
 include/uapi/linux/signalfd.h                 |  4 ++--
 kernel/signal.c                               | 21 ++++++++++++-------
 .../selftests/perf_events/sigtrap_threads.c   | 12 +++++------
 12 files changed, 47 insertions(+), 27 deletions(-)

diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
index 643bcb0f091b..f3800c0f428b 100644
--- a/arch/arm/kernel/signal.c
+++ b/arch/arm/kernel/signal.c
@@ -757,7 +757,8 @@ static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x10);
 static_assert(offsetof(siginfo_t, si_lower)	== 0x14);
 static_assert(offsetof(siginfo_t, si_upper)	== 0x18);
 static_assert(offsetof(siginfo_t, si_pkey)	== 0x14);
-static_assert(offsetof(siginfo_t, si_perf)	== 0x10);
+static_assert(offsetof(siginfo_t, si_perf_data)	== 0x10);
+static_assert(offsetof(siginfo_t, si_perf_type)	== 0x14);
 static_assert(offsetof(siginfo_t, si_band)	== 0x0c);
 static_assert(offsetof(siginfo_t, si_fd)	== 0x10);
 static_assert(offsetof(siginfo_t, si_call_addr)	== 0x0c);
diff --git a/arch/arm64/kernel/signal.c b/arch/arm64/kernel/signal.c
index ad4bd27fc044..b3978b468bd4 100644
--- a/arch/arm64/kernel/signal.c
+++ b/arch/arm64/kernel/signal.c
@@ -1005,7 +1005,8 @@ static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x18);
 static_assert(offsetof(siginfo_t, si_lower)	== 0x20);
 static_assert(offsetof(siginfo_t, si_upper)	== 0x28);
 static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);
-static_assert(offsetof(siginfo_t, si_perf)	== 0x18);
+static_assert(offsetof(siginfo_t, si_perf_data)	== 0x18);
+static_assert(offsetof(siginfo_t, si_perf_type)	== 0x20);
 static_assert(offsetof(siginfo_t, si_band)	== 0x10);
 static_assert(offsetof(siginfo_t, si_fd)	== 0x18);
 static_assert(offsetof(siginfo_t, si_call_addr)	== 0x10);
diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
index ee6c7484e130..d3be01c46bec 100644
--- a/arch/arm64/kernel/signal32.c
+++ b/arch/arm64/kernel/signal32.c
@@ -489,7 +489,8 @@ static_assert(offsetof(compat_siginfo_t, si_addr_lsb)	== 0x10);
 static_assert(offsetof(compat_siginfo_t, si_lower)	== 0x14);
 static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x18);
 static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x14);
-static_assert(offsetof(compat_siginfo_t, si_perf)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_perf_data)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_perf_type)	== 0x14);
 static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
 static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
 static_assert(offsetof(compat_siginfo_t, si_call_addr)	== 0x0c);
diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
index 5573722e34ad..4276b9e003ca 100644
--- a/arch/sparc/kernel/signal32.c
+++ b/arch/sparc/kernel/signal32.c
@@ -778,6 +778,7 @@ static_assert(offsetof(compat_siginfo_t, si_addr_lsb)	== 0x10);
 static_assert(offsetof(compat_siginfo_t, si_lower)	== 0x14);
 static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x18);
 static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x14);
-static_assert(offsetof(compat_siginfo_t, si_perf)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_perf_data)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_perf_type)	== 0x14);
 static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
 static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
index a69a78984c36..cea23cf95600 100644
--- a/arch/sparc/kernel/signal_64.c
+++ b/arch/sparc/kernel/signal_64.c
@@ -588,6 +588,7 @@ static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x18);
 static_assert(offsetof(siginfo_t, si_lower)	== 0x20);
 static_assert(offsetof(siginfo_t, si_upper)	== 0x28);
 static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);
-static_assert(offsetof(siginfo_t, si_perf)	== 0x18);
+static_assert(offsetof(siginfo_t, si_perf_data)	== 0x18);
+static_assert(offsetof(siginfo_t, si_perf_type)	== 0x20);
 static_assert(offsetof(siginfo_t, si_band)	== 0x10);
 static_assert(offsetof(siginfo_t, si_fd)	== 0x14);
diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
index c9601f092a1e..b52407c56000 100644
--- a/arch/x86/kernel/signal_compat.c
+++ b/arch/x86/kernel/signal_compat.c
@@ -147,8 +147,10 @@ static inline void signal_compat_build_tests(void)
 	BUILD_BUG_ON(offsetof(siginfo_t, si_pkey) != 0x20);
 	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_pkey) != 0x14);
 
-	BUILD_BUG_ON(offsetof(siginfo_t, si_perf) != 0x18);
-	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf) != 0x10);
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_data) != 0x18);
+	BUILD_BUG_ON(offsetof(siginfo_t, si_perf_type) != 0x20);
+	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_data) != 0x10);
+	BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_type) != 0x14);
 
 	CHECK_CSI_OFFSET(_sigpoll);
 	CHECK_CSI_SIZE  (_sigpoll, 2*sizeof(int));
diff --git a/fs/signalfd.c b/fs/signalfd.c
index 83130244f653..335ad39f3900 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -134,7 +134,8 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		break;
 	case SIL_FAULT_PERF_EVENT:
 		new.ssi_addr = (long) kinfo->si_addr;
-		new.ssi_perf = kinfo->si_perf;
+		new.ssi_perf_type = kinfo->si_perf_type;
+		new.ssi_perf_data = kinfo->si_perf_data;
 		break;
 	case SIL_CHLD:
 		new.ssi_pid    = kinfo->si_pid;
diff --git a/include/linux/compat.h b/include/linux/compat.h
index 6af7bef15e94..a27fffaae121 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -236,7 +236,10 @@ typedef struct compat_siginfo {
 					u32 _pkey;
 				} _addr_pkey;
 				/* used when si_code=TRAP_PERF */
-				compat_ulong_t _perf;
+				struct {
+					compat_ulong_t _data;
+					u32 _type;
+				} _perf;
 			};
 		} _sigfault;
 
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index 3503282021aa..3ba180f550d7 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -96,7 +96,10 @@ union __sifields {
 				__u32 _pkey;
 			} _addr_pkey;
 			/* used when si_code=TRAP_PERF */
-			unsigned long _perf;
+			struct {
+				unsigned long _data;
+				__u32 _type;
+			} _perf;
 		};
 	} _sigfault;
 
@@ -159,7 +162,8 @@ typedef struct siginfo {
 #define si_lower	_sifields._sigfault._addr_bnd._lower
 #define si_upper	_sifields._sigfault._addr_bnd._upper
 #define si_pkey		_sifields._sigfault._addr_pkey._pkey
-#define si_perf		_sifields._sigfault._perf
+#define si_perf_data	_sifields._sigfault._perf._data
+#define si_perf_type	_sifields._sigfault._perf._type
 #define si_band		_sifields._sigpoll._band
 #define si_fd		_sifields._sigpoll._fd
 #define si_call_addr	_sifields._sigsys._call_addr
diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
index 7e333042c7e3..e78dddf433fc 100644
--- a/include/uapi/linux/signalfd.h
+++ b/include/uapi/linux/signalfd.h
@@ -39,8 +39,8 @@ struct signalfd_siginfo {
 	__s32 ssi_syscall;
 	__u64 ssi_call_addr;
 	__u32 ssi_arch;
-	__u32 __pad3;
-	__u64 ssi_perf;
+	__u32 ssi_perf_type;
+	__u64 ssi_perf_data;
 
 	/*
 	 * Pad strcture to 128 bytes. Remember to update the
diff --git a/kernel/signal.c b/kernel/signal.c
index 49560ceac048..7fec9d1c5b11 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1758,11 +1758,13 @@ int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
 	struct kernel_siginfo info;
 
 	clear_siginfo(&info);
-	info.si_signo = SIGTRAP;
-	info.si_errno = type;
-	info.si_code  = TRAP_PERF;
-	info.si_addr  = addr;
-	info.si_perf  = sig_data;
+	info.si_signo     = SIGTRAP;
+	info.si_errno     = 0;
+	info.si_code      = TRAP_PERF;
+	info.si_addr      = addr;
+	info.si_perf_data = sig_data;
+	info.si_perf_type = type;
+
 	return force_sig_info(&info);
 }
 
@@ -3380,7 +3382,8 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 		break;
 	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = ptr_to_compat(from->si_addr);
-		to->si_perf = from->si_perf;
+		to->si_perf_data = from->si_perf_data;
+		to->si_perf_type = from->si_perf_type;
 		break;
 	case SIL_CHLD:
 		to->si_pid = from->si_pid;
@@ -3456,7 +3459,8 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
 		break;
 	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = compat_ptr(from->si_addr);
-		to->si_perf = from->si_perf;
+		to->si_perf_data = from->si_perf_data;
+		to->si_perf_type = from->si_perf_type;
 		break;
 	case SIL_CHLD:
 		to->si_pid    = from->si_pid;
@@ -4639,7 +4643,8 @@ static inline void siginfo_buildtime_checks(void)
 	CHECK_OFFSET(si_lower);
 	CHECK_OFFSET(si_upper);
 	CHECK_OFFSET(si_pkey);
-	CHECK_OFFSET(si_perf);
+	CHECK_OFFSET(si_perf_data);
+	CHECK_OFFSET(si_perf_type);
 
 	/* sigpoll */
 	CHECK_OFFSET(si_band);
diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
index 78ddf5e11625..fde123066a8c 100644
--- a/tools/testing/selftests/perf_events/sigtrap_threads.c
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -164,8 +164,8 @@ TEST_F(sigtrap_threads, enable_event)
 	EXPECT_EQ(ctx.signal_count, NUM_THREADS);
 	EXPECT_EQ(ctx.tids_want_signal, 0);
 	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
-	EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
-	EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
+	EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
+	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
 
 	/* Check enabled for parent. */
 	ctx.iterate_on = 0;
@@ -183,8 +183,8 @@ TEST_F(sigtrap_threads, modify_and_enable_event)
 	EXPECT_EQ(ctx.signal_count, NUM_THREADS);
 	EXPECT_EQ(ctx.tids_want_signal, 0);
 	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
-	EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
-	EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
+	EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
+	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
 
 	/* Check enabled for parent. */
 	ctx.iterate_on = 0;
@@ -203,8 +203,8 @@ TEST_F(sigtrap_threads, signal_stress)
 	EXPECT_EQ(ctx.signal_count, NUM_THREADS * ctx.iterate_on);
 	EXPECT_EQ(ctx.tids_want_signal, 0);
 	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
-	EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
-	EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
+	EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
+	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
 }
 
 TEST_HARNESS_MAIN
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-11-ebiederm%40xmission.com.
