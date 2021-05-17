Return-Path: <kasan-dev+bncBCALX3WVYQORBKEXROCQMGQEGKCCX2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 67F593864F5
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 22:01:46 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id mw15-20020a17090b4d0fb0290157199aadbasf205677pjb.7
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 13:01:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621281705; cv=pass;
        d=google.com; s=arc-20160816;
        b=YDCEPhpginwJLiiBnlZkQrqI3Ghdx3JmkKf8+zABZa0F3w5XE9D8a6PkuSb5uxnX0M
         2SVFUsN4VOluMFHPkyyyrRaPK/NIDrhFbW77QkVZ8U65I1SfRTMXpIGbA7doRwEk3v2n
         OIl5W2fdAbqnM2mZl2Nwnv82Xesm+e4iQ1KHUUwJAG46wivJfzg/+bVP1kmupYxRVuHW
         SJWDYGYd9ZZqtSzAA554MEVOaAuZuYGNoOY2VSFMQpDcvpFXwmf2ditYkD+/AMdsErLo
         kjR1BUT4+LYodlNEsrRHlQQf9MHLq9HQhWcazoFUgxjqh9RTZGXSYoiHSIll8CLae759
         9+rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=fcQNJ1Y9sJof316Yhz/yp4BX1t0Oe/NIeDYIh/VKqQI=;
        b=0sBEyWmtDXts/c0f2QHpmLruLqdWPKBeI5tRMWNoC4/JajVnWGVtyZ2TkGekK/eZ6V
         lagxRpIQZLrMF5LgO9S4hUR1LmPYWJ+KLJGGJZh9i1Um2r1ovjtEIwb5bF0ubSGN8zXu
         gDweF9PqzNRG2P+yUqLJthgBWy8k/bQeWt6l5SYjhCCdHsK0LCe65TINH9jN8t5yBcSw
         u4F5b54ybpch6q9MCmnT4M6Mno6o0Ae1hXyqwNYkMmm6BjQReJRG1YYFmvwNbg7V2zmH
         TDytlS+VoqrYpnMU4AHRZA1nXY8dzf96A3LkQj++2hBYDoDuSdJLuv0PXIn6UssHO3MU
         mmeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fcQNJ1Y9sJof316Yhz/yp4BX1t0Oe/NIeDYIh/VKqQI=;
        b=HMcl2161luLCjQ+PAeDdyI2dtQ/E8elUE3ZvGb7VAfG5NnpCPieKn4m8DBN6BthkUk
         +RW1OPhleH5U1QxKurIXe8yr/b1w+G3SGpODqbt+dhVdRbuE+XkKLhKe9ZQzoaT7+JAs
         a0eUtMIP3/Jmnw2G8WPjTkSjZmL39Aa0iUEPP8zcZDgX4L7fl0dfByhfPTI9HGVIX1H7
         dz+1HVxuB/8e8HKHRSztZtP3WkqKJw4js11nNmTiA+zD0xEFTPc+wiyfJ63s4BM+t5/y
         mIRakTmVWKMc12zyXbptptfdMKoyYBuEk4tmoHG7+t6GhT+ZF56pq2DmlyCf8qO8huLP
         i+LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fcQNJ1Y9sJof316Yhz/yp4BX1t0Oe/NIeDYIh/VKqQI=;
        b=FTwayM0p9qj3B6Gm1biFF6q1oAyTX5UcEnND1K3fptURvTskx30LiG+ORzpyM4mUj1
         dcb2NrcEteqIathj+ItLkT9aP/siUJfrE8jssL0TOpCDXWcDGku9b4dp6w0BBE+Cn/v7
         vO+arOC98JWlhRRAdxiuwUKvv4CqTuWMLXMKJMGE4oVUBXPw3Au7th+bzI1qAOiMd/ac
         7/rR1WalW2XLeqYCGGk711DWVA5SxNw4BWE1ruwbRylOqrRq7incrDGsw7suSq9FsF/q
         cl0qZMxcwM5TQ2ArgNEuVSUzxX/kpEyzhdKmQTo9WQcd1/mLvtQoVtD/I4GgDyXSHxoq
         QWZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gCBgR1sFZYTv/2sdw70Kh887nFJGYFCYD6zXGPwU2XzCoBrSd
	H4xEg5ZSUYTELdtiP7gQLSw=
X-Google-Smtp-Source: ABdhPJz8IY/UOtKgIs/OWlTesXipldjM03aEYWJzfu+5PICI195mGan+0clI+hyExlCpD52ldeSoyg==
X-Received: by 2002:a62:3242:0:b029:2d5:5913:7fd with SMTP id y63-20020a6232420000b02902d5591307fdmr1171831pfy.30.1621281705081;
        Mon, 17 May 2021 13:01:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7208:: with SMTP id ba8ls9772250plb.10.gmail; Mon,
 17 May 2021 13:01:44 -0700 (PDT)
X-Received: by 2002:a17:90a:aa82:: with SMTP id l2mr1204626pjq.106.1621281704572;
        Mon, 17 May 2021 13:01:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621281704; cv=none;
        d=google.com; s=arc-20160816;
        b=tyEzptuF5TmvDNshMlqEM2ZIyy+ijDEOfogLODjB690fAAZ/VcaRpYwGizbCphR17M
         pOLS+/Yj6UWM2iWaqLWrk1SFSnD19SlXIvvnsH/rEoC6D6SxKnE7Mpq4BOA/CbPD106n
         J7f/otZ4sTI1wzQL1ikSYdjcXXmRVuwqWct9Gqo0VvypZ9979X4V2S4fAF6c+xtY0N2m
         7ZTdS54NLgcugZHbqpkE3riYglmc2DqAb6nhQbbFz1b/emZZ0yEIU8TlsDy1+iU1h+y4
         TK5+P93XJMZQkiQvh/sNQRCgCQEbmIO/CFd7kX3g+8zOGdo2Cjq0xuzvalxO3MZTA33M
         CJGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=li1hDIAW4yr7U13heEsHYKw84+E2fyUmu1Ia56HYOK8=;
        b=Gymzz/OsSXdYHeoWtH4p6Qcy47PeLICu7AkDOGgRqHc+G2YxBO1WXgQOEu0CMWEZ9s
         gXfLliVMhqWp/2x4ECFT/wxkMokG/226dtwqmm6CbqATNPTcUm4XJnnUZKm1wsU+VVka
         J9bFQ0SH1ABDa+UQj0O7Y5lb9uR2woqPkLBlGX/0J5eRgmfbaPnhmyhsA6ScHXh8vCN5
         p4wwQeALm20FGFoGB0taTsKlOxtjAm5CyJD9UzIIy+xU6sJPBKbwiJSLNfDkatZFnj7c
         TQBQyem+HnrLyKbC02pQsZxXnsEydyWL7BM/R1DQYqcpiZ/gh/smQynOSb+TzAMPaAfj
         MxJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id a10si1331954pgv.3.2021.05.17.13.01.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 May 2021 13:01:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijQt-009hBO-Mz; Mon, 17 May 2021 14:01:43 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijO7-0001rb-7N; Mon, 17 May 2021 13:58:52 -0600
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
Date: Mon, 17 May 2021 14:57:48 -0500
Message-Id: <20210517195748.8880-5-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210517195748.8880-1-ebiederm@xmission.com>
References: <m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
 <20210517195748.8880-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1lijO7-0001rb-7N;;;mid=<20210517195748.8880-5-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+Gk9/Q25EzHZWDw4yyzXzOF7lOvQ/rQjQ=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,XMSubLong
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 448 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 11 (2.5%), b_tie_ro: 10 (2.2%), parse: 1.27
	(0.3%), extract_message_metadata: 14 (3.1%), get_uri_detail_list: 2.9
	(0.6%), tests_pri_-1000: 13 (2.9%), tests_pri_-950: 1.19 (0.3%),
	tests_pri_-900: 1.02 (0.2%), tests_pri_-90: 66 (14.7%), check_bayes:
	65 (14.4%), b_tokenize: 9 (2.1%), b_tok_get_all: 7 (1.6%),
	b_comp_prob: 2.3 (0.5%), b_tok_touch_all: 43 (9.5%), b_finish: 0.83
	(0.2%), tests_pri_0: 327 (72.9%), check_dkim_signature: 0.58 (0.1%),
	check_dkim_adsp: 2.2 (0.5%), poll_dns_idle: 0.65 (0.1%), tests_pri_10:
	2.8 (0.6%), tests_pri_500: 8 (1.7%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v4 5/5] signalfd: Remove SIL_PERF_EVENT fields from signalfd_siginfo
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
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

With the addition of ssi_perf_data and ssi_perf_type struct signalfd_siginfo
is dangerously close to running out of space.  All that remains is just
enough space for two additional 64bit fields.  A practice of adding all
possible siginfo_t fields into struct singalfd_siginfo can not be supported
as adding the missing fields ssi_lower, ssi_upper, and ssi_pkey would
require two 64bit fields and one 32bit fields.  In practice the fields
ssi_perf_data and ssi_perf_type can never be used by signalfd as the signal
that generates them always delivers them synchronously to the thread that
triggers them.

Therefore until someone actually needs the fields ssi_perf_data and
ssi_perf_type in signalfd_siginfo remove them.  This leaves a bit more room
for future expansion.

v1: https://lkml.kernel.org/r/20210503203814.25487-12-ebiederm@xmission.com
v2: https://lkml.kernel.org/r/20210505141101.11519-12-ebiederm@xmission.com
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 fs/signalfd.c                 | 16 ++++++----------
 include/uapi/linux/signalfd.h |  4 +---
 2 files changed, 7 insertions(+), 13 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index 373df2f12415..167b5889db4b 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -114,12 +114,13 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		break;
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
+	case SIL_PERF_EVENT:
 		/*
-		 * Fall through to the SIL_FAULT case.  Both SIL_FAULT_BNDERR
-		 * and SIL_FAULT_PKUERR are only generated by faults that
-		 * deliver them synchronously to userspace.  In case someone
-		 * injects one of these signals and signalfd catches it treat
-		 * it as SIL_FAULT.
+		 * Fall through to the SIL_FAULT case.  SIL_FAULT_BNDERR,
+		 * SIL_FAULT_PKUERR, and SIL_PERF_EVENT are only
+		 * generated by faults that deliver them synchronously to
+		 * userspace.  In case someone injects one of these signals
+		 * and signalfd catches it treat it as SIL_FAULT.
 		 */
 	case SIL_FAULT:
 		new.ssi_addr = (long) kinfo->si_addr;
@@ -132,11 +133,6 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		new.ssi_addr = (long) kinfo->si_addr;
 		new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
 		break;
-	case SIL_PERF_EVENT:
-		new.ssi_addr = (long) kinfo->si_addr;
-		new.ssi_perf_type = kinfo->si_perf_type;
-		new.ssi_perf_data = kinfo->si_perf_data;
-		break;
 	case SIL_CHLD:
 		new.ssi_pid    = kinfo->si_pid;
 		new.ssi_uid    = kinfo->si_uid;
diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
index e78dddf433fc..83429a05b698 100644
--- a/include/uapi/linux/signalfd.h
+++ b/include/uapi/linux/signalfd.h
@@ -39,8 +39,6 @@ struct signalfd_siginfo {
 	__s32 ssi_syscall;
 	__u64 ssi_call_addr;
 	__u32 ssi_arch;
-	__u32 ssi_perf_type;
-	__u64 ssi_perf_data;
 
 	/*
 	 * Pad strcture to 128 bytes. Remember to update the
@@ -51,7 +49,7 @@ struct signalfd_siginfo {
 	 * comes out of a read(2) and we really don't want to have
 	 * a compat on read(2).
 	 */
-	__u8 __pad[16];
+	__u8 __pad[28];
 };
 
 
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517195748.8880-5-ebiederm%40xmission.com.
