Return-Path: <kasan-dev+bncBCALX3WVYQORB47UYGDQMGQESRA3CEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D8913CA514
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 20:12:05 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id a10-20020aca4d0a0000b029025a01bc9839sf4465986oib.13
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 11:12:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626372723; cv=pass;
        d=google.com; s=arc-20160816;
        b=WBBsYN8q9eb+RmMrepdvvuEFSTflyi4zo6UcAaW5ldmpCbXaDbVe0ZxCb4SiAct5tH
         VnbYE34njHjYjg2dJRyoqjV/uxqfcuXdEXNX4V5zvfYUKcZ/tYe9rrdnW9OeuVOm1NBB
         TRLUnLmDJGmKuXg/HVuxGV0I+3jru1SiTQrtmvjXK4iXQijZh7TucMujgv39VbuY8QIz
         zJ5Cp4Hc53Y/3fYt7sEUYCFMoeuh1EYeISEe0hFiy7HvyQUbKIUaRx/7gD0WciBmp3m6
         S9T+tez2eEUF7pVShRJmzoVrw7OYwVNtoU069fZ0RBZ/B+C6MESsmsRGg4mB9xtZP+L/
         zHgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=ocsQHbS7uceVe+NFv37N8xQmJANpA1zUOGq/Zb34dRg=;
        b=Eo79G5v+ektNXZQzURDSDsBwfVm3kLfsQstr+iP6pDBuEDGkKgygpOmb3aTsI7wdMH
         LO1CWjx3HySCW/CrbgtsgfY2pEB2z31WB7oNRL422/QAHVcR407LstPNhiGLynePv24w
         sn3ZCTAiVGBtFJ6PGgzZUu7e5H9rtwax9SSZBHB7NHRENDbrQrw3h2UUVq/JtHhBuOrR
         LP6u8S8996EoqIIGETU86ZIF2DW5idUkXv+GrtNRUQ4FxcJ/2ik2k+rAhlFoe/4xmFUC
         QiAzo7aEy3CM9iG3m8D9i1RYvjy4b2Rkq/kzhiYxs0xHlg+bLOIYc9OwvVilx758T8qs
         Z9/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ocsQHbS7uceVe+NFv37N8xQmJANpA1zUOGq/Zb34dRg=;
        b=GAPyzv4xHFe07krh2W5eToruUEudKDhresWZ5FYGmSFSI/OHrmqQDpItPWKgT/rOta
         Pt2ZDIyMxPpS+NXRZ/N6BdcQ8LI/j+FPa1FJ8etRWZZZYpQMMMCJvJI/oLKs7P+m9Fn2
         mtElWN5uSqL12HPlYJ5zxjuegCGsR4yvTTsgY0LlRarF4U5lFs0EgFE78ptbACHfpNYS
         2coYpNiD81ANbJk/Qm49jtoeFVrmyEu2LyOvvTcm8YNcwDvynexBiPGZmgyxbilUXSyc
         Mo+73NHiHa6QerR1uNZ2RdR1GtDR7Xt00tLChx0PsRyH5rO/Jz6DiQvr+Ni7Sm+/wOBP
         bwyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ocsQHbS7uceVe+NFv37N8xQmJANpA1zUOGq/Zb34dRg=;
        b=dSwg5NgedDXFmg6lTEgYl24FYwW2l0FikGaSsHTIWg0hVv0qVHWuVCEE+EXpS6UFEF
         24CuQQITRmPjOzqHuLN82lYtaAal3JqjYWp31ueoxt4vN8Eu001BRpgtIajgu8QF1Ox7
         BvYpLhLseZ9x/2mQ88C+pHQMIX1cTydNyNcKkSHV5cQBMG4GVoH7NsYwXw9EO6ktwNVt
         TU4TZSUFkB/6u696gDpw8z5aqvu50dTJ1cDgXqA8AjClZAbhPErmGAqPXBu+hV3v8eX8
         dS/CKAkB7NDzxgAKaJVeono2camyEudoVtmkeHiRQsy0ycxGWW9AhprfDGXHd6B61K3N
         VAcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531mKg8H+hVW5pUfT6DnwC+spyMDvZ8SIuf6q+ta2E3qNRli6z3L
	Xg9alqE8Wg/A3k7bn0Cq1TU=
X-Google-Smtp-Source: ABdhPJwpkXYWFgISQNQD07hv9SoVDlaZJMEjgvAySRXd0YKyoptGPyVXCnGcSJoUJV4XdmMXGkT4sw==
X-Received: by 2002:a9d:8c7:: with SMTP id 65mr4845391otf.25.1626372723643;
        Thu, 15 Jul 2021 11:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:352:: with SMTP id 76ls2949516otv.0.gmail; Thu, 15 Jul
 2021 11:12:03 -0700 (PDT)
X-Received: by 2002:a9d:6484:: with SMTP id g4mr4885669otl.331.1626372723118;
        Thu, 15 Jul 2021 11:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626372723; cv=none;
        d=google.com; s=arc-20160816;
        b=Eda37tZQkzietb5jW9znfvgRx/2lb/JWkSil5m2HV8mXv7gMK7G5NXiW7IhGRYZu+A
         y9kf9xav+Q2Bs3VXEoMCTo2NQ/sb2C1NbVLPEE4cXwWZvogGaBlyWE7adi+XZ6paLbfq
         SR62+JGO0RAP5jwjub1ua5Q8Xe/v8YCgJpqVuiIlbr7rjnK7bH5LcTY/8Tu+dfDlI4zi
         ZXlPI3C3pGiIg1Rdg9J+7HLNCGB56o4S30gLY+eym8KvLRuE/O803JRQQWUj9JYtH8p5
         5/RPj+HlUAm5LGpBGhiZaa2kdeUkaD9/IJTTB0Y/Xjx44irmumKe3GisPMo8Syn5cGBX
         jCdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=xD1h6M4k5Bex9ZWMY2jcQdixo3kP7JIy46tuXGrLf5U=;
        b=goUnWLLTuLKDD/uGC95o2Mm/2s4BEyYn7VCbfnKgxLSSOBMs49W83jpUPhNaXxvgIS
         SZwAjHkn4Tw8phdzwC6YLXGM/vyRgQxrqHbbsQQakTQTexjbiWgDjAmEzuk3SECMHxZQ
         tKfbpVFC6xhWDHNh0JJnPOJGUeg04Uz6Lw7OfNTIE/DC+EmZaLGWEwyYXj2a4/oy7m9q
         cB1jj3zU34T+iNIclYJxoUN3YrwKO0kPScJXFgX5UW5g9SNkGbKhrSodvBAGLw5K/mEb
         a9RysJ6Px6kza2NgY/HIbHzkzentYyBmp6ViHcGfXq41aTC5Av2hfMe6Y0Y2tsCKVQV3
         BHuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id j26si1093229ooj.0.2021.07.15.11.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jul 2021 11:12:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45q5-009T6b-O3; Thu, 15 Jul 2021 12:12:01 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:57052 helo=email.xmission.com)
	by in01.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45q3-00CTIe-Nd; Thu, 15 Jul 2021 12:12:00 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133>
Date: Thu, 15 Jul 2021 13:11:53 -0500
In-Reply-To: <87a6mnzbx2.fsf_-_@disp2133> (Eric W. Biederman's message of
	"Thu, 15 Jul 2021 13:09:45 -0500")
Message-ID: <87sg0fxx92.fsf_-_@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1m45q3-00CTIe-Nd;;;mid=<87sg0fxx92.fsf_-_@disp2133>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1974iVOcDju+dmQt3PhQUuiNXDLAPV3Zrw=
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
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_02 5+ unique symbols in subject
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 493 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 10 (2.1%), b_tie_ro: 9 (1.8%), parse: 0.80 (0.2%),
	 extract_message_metadata: 10 (2.0%), get_uri_detail_list: 2.4 (0.5%),
	tests_pri_-1000: 12 (2.4%), tests_pri_-950: 1.03 (0.2%),
	tests_pri_-900: 0.81 (0.2%), tests_pri_-90: 135 (27.4%), check_bayes:
	134 (27.2%), b_tokenize: 10 (1.9%), b_tok_get_all: 7 (1.5%),
	b_comp_prob: 1.57 (0.3%), b_tok_touch_all: 112 (22.8%), b_finish: 0.82
	(0.2%), tests_pri_0: 313 (63.5%), check_dkim_signature: 0.52 (0.1%),
	check_dkim_adsp: 2.3 (0.5%), poll_dns_idle: 0.75 (0.2%), tests_pri_10:
	1.79 (0.4%), tests_pri_500: 6 (1.3%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 3/6] arm64: Add compile-time asserts for siginfo_t offsets
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
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

Link: https://lkml.kernel.org/r/20210505141101.11519-3-ebiederm@xmission.com
Link: https://lkml.kernel.org/r/20210429190734.624918-3-elver@google.com
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 arch/arm64/kernel/signal.c   | 37 ++++++++++++++++++++++++++++++++++++
 arch/arm64/kernel/signal32.c | 37 ++++++++++++++++++++++++++++++++++++
 2 files changed, 74 insertions(+)

diff --git a/arch/arm64/kernel/signal.c b/arch/arm64/kernel/signal.c
index f8192f4ae0b8..4413b6a4e32a 100644
--- a/arch/arm64/kernel/signal.c
+++ b/arch/arm64/kernel/signal.c
@@ -999,3 +999,40 @@ void __init minsigstksz_setup(void)
 		round_up(sizeof(struct frame_record), 16) +
 		16; /* max alignment padding */
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
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x18);
+static_assert(offsetof(siginfo_t, si_lower)	== 0x20);
+static_assert(offsetof(siginfo_t, si_upper)	== 0x28);
+static_assert(offsetof(siginfo_t, si_pkey)	== 0x20);
+static_assert(offsetof(siginfo_t, si_perf_data)	== 0x18);
+static_assert(offsetof(siginfo_t, si_perf_type)	== 0x20);
+static_assert(offsetof(siginfo_t, si_band)	== 0x10);
+static_assert(offsetof(siginfo_t, si_fd)	== 0x18);
+static_assert(offsetof(siginfo_t, si_call_addr)	== 0x10);
+static_assert(offsetof(siginfo_t, si_syscall)	== 0x18);
+static_assert(offsetof(siginfo_t, si_arch)	== 0x1c);
diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
index 2f507f565c48..ab1775216712 100644
--- a/arch/arm64/kernel/signal32.c
+++ b/arch/arm64/kernel/signal32.c
@@ -457,3 +457,40 @@ void compat_setup_restart_syscall(struct pt_regs *regs)
 {
        regs->regs[7] = __NR_compat_restart_syscall;
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
+static_assert(offsetof(compat_siginfo_t, si_addr_lsb)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_lower)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_upper)	== 0x18);
+static_assert(offsetof(compat_siginfo_t, si_pkey)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_perf_data)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_perf_type)	== 0x14);
+static_assert(offsetof(compat_siginfo_t, si_band)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_fd)		== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_call_addr)	== 0x0c);
+static_assert(offsetof(compat_siginfo_t, si_syscall)	== 0x10);
+static_assert(offsetof(compat_siginfo_t, si_arch)	== 0x14);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sg0fxx92.fsf_-_%40disp2133.
