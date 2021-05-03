Return-Path: <kasan-dev+bncBCALX3WVYQORBZV6YGCAMGQEJZUAERI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F2A237217D
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:39:04 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id v6-20020a6261060000b029028e72db2cfdsf2472286pfb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:39:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074343; cv=pass;
        d=google.com; s=arc-20160816;
        b=wQFAn1/1eLtWleOyvXTPnrSbSDEagwi9pR5GOO/jZ0M8kJblIlD8ULZpDZgKkVPQYQ
         43coEMdM0GBPDA0SHNk7wwuc+V0nSTdN/50QuUxAYKk1ij5C+TH6JSDjbvAtBhqo41I9
         XiK89BhJ8ZiLQrvdQ2/xH7ORAjjMouoMNZD5aJRJ/mSdBcwL7KhYwnSasKPgTgcv0xu6
         FDZbUlYxDyXI+OaqaY2GwP8YstBrnE2Qkey8c+TCIx4OTbkKFdcjetsrNFQkQmEnXm/Z
         tQREJ6HP5il+2ShU+a/AVJ2qXVX4sYtO3bEHvm4F+jzu2N/4hbO5pR71Zu37s74KDd2v
         t9ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=ydBOy1/5Yeh5GVkds7g3WEeR8dlPXBnSWi0ouLx4Ev4=;
        b=km+IABqDl3cet1fBp3aJFw6oSu5QnMy+9llZJuObIBz8UvhhHZcrI1M/42Umd4X3lz
         jQTjZcKMusqrsDb39gC9oU6BM9pMqi2u2iXkruFs2LnPzckACQRB8edp1TI7ZFD+7EGL
         aNzeFIgxKwzJ7BpZvKB39lQvVYVc4v++j/jRxtQKg0tDzsyAQbXfP8/45uZ3MSKzYGRr
         FfpEr1SbP/7xuzVbux8irvGlmLKEl3uLF2hmk7OttNM66bTP0gjVPnnSxzrJgbJ/cN5V
         SE2/b42ESdT9qnEPFw2F2jINBBHvOVz/gJ/Ms5VogioJkapDxA1sx3xYIDceK0my/XQR
         ltKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ydBOy1/5Yeh5GVkds7g3WEeR8dlPXBnSWi0ouLx4Ev4=;
        b=DggvANAHrne1ysEjo1wJUT79VIvFRZWl7T4hQqvyzWi3NTTTYKMFVZnDGYDan+5VgT
         BtQ88AQTtDLxAXZwTf04zojCrL5TlLsfrZh69rJUfIsugmie92+91mwlBf+LcwS25QKE
         FVBQFW+KSxpdj4Zbj5juU5IwH014Nx2cwxWkeudv4oe+Az0ZBbHpNhYdOwRqopQcA02J
         sBVtVFbtQutIpjfuzJfi3wVPDYFRpbQCdtRsySdG7BkCHOoWR4Eau9ASVHgYeLeo3sTK
         OgjOzJLHwJqWbkSq4ScLxhHUwC7MhH+U0mJblgP/fLZOa3E3/BXwHTX5CRicuJVZWnjN
         LltQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ydBOy1/5Yeh5GVkds7g3WEeR8dlPXBnSWi0ouLx4Ev4=;
        b=r43WbULbrCsY7Ogogj+CPxh3NE/KYzS4q9rkOXBDlz/D1ljN58m7lfkll9jPtV4pKc
         9yJ9+lgw+6JosANYyUwcRnB0veYCjrbleD8xtr6403qv1mVVYuDSEgwUiIgfbeumCb9c
         LLalENqBY+TbddHYQH/oSKXLN9uqXc4WlCHqtw4P9l0urrFEVsARMRcVVeT2iLRP+rHU
         f5orc6g+b4RY4tPD9IiTaCruj1pEJ2WCopW1UCNk6/YQq4Pzq4HY0slz8KqPRUWcQ/Kg
         gxXNB0o3bLgamop/w6EqTJ7dKsT/Mc71Vpghbd6ZHKJ1nFSG7au63YiJItMQoJlSNriy
         SClw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532LIG8tSvcs7O1JTQhjqOp0vOpk/dJunPGxlEmGehKsm4jr/HgH
	VitRUJ23OA5txQo4pQPT5Po=
X-Google-Smtp-Source: ABdhPJy1F8SIPwIyQInbk7W4colUyTIkj6FXMstCavZuXlEiUdWG/oYjzKFgz6a7niQAEXml08bFOw==
X-Received: by 2002:a17:90b:360f:: with SMTP id ml15mr564206pjb.26.1620074342919;
        Mon, 03 May 2021 13:39:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:89:: with SMTP id o9ls3761343pld.8.gmail; Mon, 03
 May 2021 13:39:02 -0700 (PDT)
X-Received: by 2002:a17:902:be02:b029:e6:bb0d:6c1e with SMTP id r2-20020a170902be02b02900e6bb0d6c1emr22234703pls.77.1620074342228;
        Mon, 03 May 2021 13:39:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074342; cv=none;
        d=google.com; s=arc-20160816;
        b=Q53BU5ZY4lQHooh6a4hCvPxaTdOgGd8+I3rbUlMpYHzMlc8AM/YLxnOZ51mUP7j6kJ
         bw4ttNjlVjBvv+MUQAkTjWh1FvS8zpktE+bu+jDuJVS6h/u+BlLosVCQREsV+zz9/Pcf
         BEUWwBS4OxdDxe6gJWxOVZJdpNq/zfo/UlyBQ1cCizN2E7OlR0VXyJRwrJnxN8YMW2cr
         6rs6eYL2XWXMXARrtlNE03avGGzUkBy3FyHF4Try+QKwAkIaz/Da/efgm9Qk1CMNe51l
         cZpkoFkT22/zFoFXzPSLrlTw6dGa/n3eudTyuUxbCNndlHW5v9g0Gry1JNjsD4Hc9nsM
         3UcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=yIJqY2PZfMEjcN0oxc6Tb+UFw9Tr8RfKX/mUKf09D4Q=;
        b=FrdqKfg8epYPWrC9DEwnjECW+oLIl0Snm/Bvm4JW1ZlxfoeSN9vSwJ13NtNaFMUaE2
         p64Kb3Ebwoa5fNoiJ8Ce3GWeQFmGDjBQXtw7PBEYucXiMycbHmHgAwT4qZRs5ajfe1XL
         /EhnV7SgokrTyPi1Jrtj2BlBBVoRmy2mkQeSywVSJ3pO588lx6kf7zjaF3F+J3Tq3iwv
         l+ooezp2uIoYwPG5X8vxdDJMuDJxDBrZtmcd0axQeO8m1yuLE2mMslZiJW2CDtBGyZTE
         Y+omgqMBuXRQuryIZcpw8FIKhvEpBPXRiTT2TJfFhdUtfefcaPXOuEK0EproNyRoQty/
         3udg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id md7si57875pjb.3.2021.05.03.13.39.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:39:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLJ-00HIYI-46; Mon, 03 May 2021 14:39:01 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLH-00E76Y-Jc; Mon, 03 May 2021 14:39:00 -0600
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
Date: Mon,  3 May 2021 15:38:06 -0500
Message-Id: <20210503203814.25487-4-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210503203814.25487-1-ebiederm@xmission.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfLH-00E76Y-Jc;;;mid=<20210503203814.25487-4-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX186YKRMudYyrGqdB/6JL/jwCZDR82Moz7c=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.4 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,T_XMDrugObfuBody_08,XMNoVowels,XMSubLong
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 711 ms - load_scoreonly_sql: 0.08 (0.0%),
	signal_user_changed: 11 (1.5%), b_tie_ro: 9 (1.3%), parse: 1.09 (0.2%),
	 extract_message_metadata: 14 (1.9%), get_uri_detail_list: 3.8 (0.5%),
	tests_pri_-1000: 13 (1.8%), tests_pri_-950: 1.26 (0.2%),
	tests_pri_-900: 1.04 (0.1%), tests_pri_-90: 138 (19.5%), check_bayes:
	137 (19.2%), b_tokenize: 15 (2.1%), b_tok_get_all: 10 (1.4%),
	b_comp_prob: 2.6 (0.4%), b_tok_touch_all: 106 (14.9%), b_finish: 0.86
	(0.1%), tests_pri_0: 515 (72.5%), check_dkim_signature: 0.69 (0.1%),
	check_dkim_adsp: 2.2 (0.3%), poll_dns_idle: 0.50 (0.1%), tests_pri_10:
	3.3 (0.5%), tests_pri_500: 11 (1.5%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 04/12] siginfo: Move si_trapno inside the union inside _si_fault
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
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
is no longer a concern that the union must be pointer alligned on most
architectures because the union followes immediately after si_addr
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
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/sparc/kernel/signal32.c       | 10 +++++-----
 arch/sparc/kernel/signal_64.c      | 10 +++++-----
 arch/x86/kernel/signal_compat.c    |  3 +++
 include/linux/compat.h             |  5 ++---
 include/uapi/asm-generic/siginfo.h |  7 ++-----
 kernel/signal.c                    |  1 +
 6 files changed, 18 insertions(+), 18 deletions(-)

diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
index 778ed5c26d4a..73fd8700df3e 100644
--- a/arch/sparc/kernel/signal32.c
+++ b/arch/sparc/kernel/signal32.c
@@ -772,10 +772,10 @@ static_assert(offsetof(compat_siginfo_t, si_int)	== 0x14);
 static_assert(offsetof(compat_siginfo_t, si_ptr)	== 0x14);
 static_assert(offsetof(compat_siginfo_t, si_addr)	== 0x0c);
 static_assert(offsetof(compat_siginfo_t, si_trapno)	== 0x10);
-static_assert(offsetof(compat_siginfo_t, si_addr_lsb)	== 0x14);
-static_assert(offsetof(compat_siginfo_t, si_lower)	== 0x18);
-static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x1c);
-static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x18);
-static_assert(offsetof(compat_siginfo_t, si_perf)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_addr_lsb)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_lower)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x18);
+static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_perf)	== 0x10);
 static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
 static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
index c9bbf5f29078..17913daa66c6 100644
--- a/arch/sparc/kernel/signal_64.c
+++ b/arch/sparc/kernel/signal_64.c
@@ -582,10 +582,10 @@ static_assert(offsetof(siginfo_t, si_int)	== 0x18);
 static_assert(offsetof(siginfo_t, si_ptr)	== 0x18);
 static_assert(offsetof(siginfo_t, si_addr)	== 0x10);
 static_assert(offsetof(siginfo_t, si_trapno)	== 0x18);
-static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x20);
-static_assert(offsetof(siginfo_t, si_lower)	== 0x28);
-static_assert(offsetof(siginfo_t, si_upper)	== 0x30);
-static_assert(offsetof(siginfo_t, si_pkey)	== 0x28);
-static_assert(offsetof(siginfo_t, si_perf)	== 0x20);
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x18);
+static_assert(offsetof(siginfo_t, si_lower)	== 0x20);
+static_assert(offsetof(siginfo_t, si_upper)	== 0x28);
+static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);
+static_assert(offsetof(siginfo_t, si_perf)	== 0x18);
 static_assert(offsetof(siginfo_t, si_band)	== 0x10);
 static_assert(offsetof(siginfo_t, si_fd)	== 0x14);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-4-ebiederm%40xmission.com.
