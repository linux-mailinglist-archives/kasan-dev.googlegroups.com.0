Return-Path: <kasan-dev+bncBCALX3WVYQORBI6PZKCAMGQENEADRUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 05046373D42
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:48 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id i62-20020a3786410000b02902e4f9ff4af8sf1213036qkd.8
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223907; cv=pass;
        d=google.com; s=arc-20160816;
        b=laYmLZx4lxWEcgZaqbP05IiwPcngF17eFbPdwviT6gQ4baUmiEoYrv1kmmqkotvslh
         CLgbJ3tgpRsWP1XYZX9V1WhTDFnUitpSpT1/A80fRTnNlpN8Q3KWzrnCjN1FgYDjg3xU
         FtgD8uTas/m1D0QdH+mVjZ1E5ZQnMEvUIMcY3wgtHKn1HiOYOO1jZ8wq4U0paymiwqA4
         EFMnUjyg4XdN5Yr2sTc9OVHAYAz7lQYsw7699eo3L514Gptu//uzOuqiuBP+kxaDtlp6
         8okaHs1YtPEtqfVHjlPqOY8SwJdZR6F/6hBt/JWGHFfgwiprD83S74w1CjgY+4H8S0Xo
         B4aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=QFJ922SL5ZuVLDknsKiKeX/72A33lfQk+AFbtmi+OVk=;
        b=HcQNBXzNiuojyEjrgvSW4KcvTZdYe85VhvgvLXZHjiYRlJKxonEMENKF9PiNQF2MMo
         8UxqBopZU2Em6PRK4oud9h+e1U/P/EK4CN5jULdF6nKYWMqJygWX1YDKvVoANJuyraJ/
         lv5+kmrqZjSNwRfx4fMmUWsFnjjKdWFWWfLe4mP32wtJdI8zWNMCN4MbBdPt887fyNu3
         NLagWSPmxCFvur+rTMQAVwtGPwZPzKDtiGsY/XemjSeIn3aX0hImW3sB+oefeJTqy6PY
         RTjkyGp+GFDYgzzbtziqNyrLOh7ehVMeVloVh8kJOS0X3x5Cyouvq0K4AbagxHUtJkFe
         Y/WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QFJ922SL5ZuVLDknsKiKeX/72A33lfQk+AFbtmi+OVk=;
        b=fF4piVp0x5WA4UPBUMdt2L4x3fS3sGVR+MQ1ufHNtrdC4ytnNbIazXhxKsg4ZlZvEy
         FmlhiV1kPB7R/4sg663YpZAyRIjJguN9XCiKb/DuC9ZqYpCMaEYs5YJhTnUPqbeFFQnT
         6M5ntLOFw8WC/ikV3TzpCcBhgU7ucQPhS0Sk/jlbVjOnjyZUX3XaD5weKRIczcIcEJBK
         Bu6VwJjeb8iSxWxBlLhmbns8/c27i4zRiwrQrFj6kC8AaT7UjNTpSsYIaXylyORazGFm
         7/vwJczbqemgonpwFpHTdEdVT6nqqg65qcQJIA7//T64CtZzCuW8x7QaH2arlku/WKac
         2vDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QFJ922SL5ZuVLDknsKiKeX/72A33lfQk+AFbtmi+OVk=;
        b=g7bDNJAxAxjN19ZidJzLLuO9kweJxfnceo8lZTM7lwvruPBr2/Nb99/jKFq+fxS5DD
         tdH9Ips28l04DVdZ/Ip7LhDx5deOYjDkpMQDRj7h1F6q9EmWaWzeD3hV7vxyt5hlBj7G
         ChX8PBrVKMZWuEGulQjusfl/B6X0J0CH0/4Rovp/xGo35yEPTpgCYr6vvDhF3f8Felrx
         81PTv9X9K5ESfy5RNOQW6NLJKvX56tW79DAxiJapgdvp2R5LL6idmSRaBQMstI17Osre
         P0yoY+TEOHGM0mOd4xEeb8ZuN6XpeKqu5BP4E3590qBCZJcsVvj9iK/uLynweIH2XgOi
         IdNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HNcojOjuNyigyjVjhKSvrZWEDBeLtGvUpzxd4XcReFMRSZN1+
	/GSHmRdNd1PeyWhrfo4V23U=
X-Google-Smtp-Source: ABdhPJxR3Q7sMaPoBBU49LVbsKik/+luXNVbosy9HlA4zzIC1EyfAbtlqfatpLCYEJfbgB5wVwXtwQ==
X-Received: by 2002:a37:618e:: with SMTP id v136mr22135675qkb.143.1620223907115;
        Wed, 05 May 2021 07:11:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7a82:: with SMTP id v124ls12490867qkc.3.gmail; Wed, 05
 May 2021 07:11:46 -0700 (PDT)
X-Received: by 2002:ae9:e00e:: with SMTP id m14mr29229063qkk.460.1620223906522;
        Wed, 05 May 2021 07:11:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223906; cv=none;
        d=google.com; s=arc-20160816;
        b=t1Yazw7t+TaSUzVr02buF5lVb/ZlCDITY3+1WGUmbsikxkqNfYN1nFMfgpDYAFQBHt
         USFqSAGA9nFYMvhPHjbCC2a1VKxqHLo96QGl5pplte2Mt0FHJwlSiStvoj08r/MITLYV
         TaA1exXwC5wePNfmSy4JzAqN55Jwdq3W6dipffB0tgL1FzyHolpLrgHGbzuNcoqDa/YD
         ROiMVQpNw4pFJ2sOHRQpXILr5MLk/zMuSljQ6snf2unZVxWRfMQls5Ok2F/VFkJ90ecP
         DqYPz2ap7mtJMqrBSOSvNES26Ndz6NTO2onFcP7H9+PGv32CgPs0zgg9sx8U66ev6Al3
         8RsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=QMX+qp65XOa9G+4yWYllyq7RhINkwIG6/PTo2273kRM=;
        b=FeAiG1mJ8H6nGDWO/py1uJ3cNq0Sfuw4i1b8dyPBH7+e3rVELCTSRIksmmW+bFyVfZ
         eyuBtnGvh57qorczgAXKUQACZnoTe3h7jXTg1S2wadRVQKm1MhmwbiiSQVwq8UdCqWrf
         5E1sJ94W5zwonzCWRZczt/0D3pWnxbGvrlfpylM4w1O+4v9j+LloCA8gLoAvpJy+qr89
         DRzY0Nh/u1dpP4tqM7Hb1A7xFp/IXxlOewfyxZchipKGY/8l0+JwQ/6gchtISemgzk6q
         eT9NGGsCNjcXdDkXxoZHdk29imqK7yyQ3wp5zt5PABhti+zCWJh5BVJX+GKAt+1jt4EX
         tOZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id c64si560598qke.6.2021.05.05.07.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFc-003DNj-OZ; Wed, 05 May 2021 08:11:44 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFb-00007y-4X; Wed, 05 May 2021 08:11:43 -0600
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
Date: Wed,  5 May 2021 09:10:58 -0500
Message-Id: <20210505141101.11519-9-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIFb-00007y-4X;;;mid=<20210505141101.11519-9-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18coKjiiiBU6l9p4gly0Wdj13arBoebgrI=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa02.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMGappySubj_01,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.5 XMGappySubj_01 Very gappy subject
	*  0.7 XMSubLong Long Subject
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa02 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa02 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 433 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 3.3 (0.8%), b_tie_ro: 2.3 (0.5%), parse: 0.75
	(0.2%), extract_message_metadata: 9 (2.0%), get_uri_detail_list: 1.57
	(0.4%), tests_pri_-1000: 11 (2.6%), tests_pri_-950: 1.16 (0.3%),
	tests_pri_-900: 0.84 (0.2%), tests_pri_-90: 112 (25.8%), check_bayes:
	111 (25.5%), b_tokenize: 7 (1.7%), b_tok_get_all: 5 (1.2%),
	b_comp_prob: 1.30 (0.3%), b_tok_touch_all: 94 (21.8%), b_finish: 0.59
	(0.1%), tests_pri_0: 282 (65.2%), check_dkim_signature: 0.41 (0.1%),
	check_dkim_adsp: 2.4 (0.6%), poll_dns_idle: 1.02 (0.2%), tests_pri_10:
	2.9 (0.7%), tests_pri_500: 8 (1.8%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 09/12] signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
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

It helps to know which part of the siginfo structure the siginfo_layout
value is talking about.

v1: https://lkml.kernel.org/r/m18s4zs7nu.fsf_-_@fess.ebiederm.org
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Eric W. Biederman <ebiederm@xmission.com>
---
 fs/signalfd.c          |  2 +-
 include/linux/signal.h |  2 +-
 kernel/signal.c        | 10 +++++-----
 3 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index e87e59581653..83130244f653 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -132,7 +132,7 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		new.ssi_addr = (long) kinfo->si_addr;
 		new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		new.ssi_addr = (long) kinfo->si_addr;
 		new.ssi_perf = kinfo->si_perf;
 		break;
diff --git a/include/linux/signal.h b/include/linux/signal.h
index 5160fd45e5ca..ed896d790e46 100644
--- a/include/linux/signal.h
+++ b/include/linux/signal.h
@@ -44,7 +44,7 @@ enum siginfo_layout {
 	SIL_FAULT_MCEERR,
 	SIL_FAULT_BNDERR,
 	SIL_FAULT_PKUERR,
-	SIL_PERF_EVENT,
+	SIL_FAULT_PERF_EVENT,
 	SIL_CHLD,
 	SIL_RT,
 	SIL_SYS,
diff --git a/kernel/signal.c b/kernel/signal.c
index 7eaa8d84db4c..697c5fe58db8 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1198,7 +1198,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 	case SIL_SYS:
 		ret = false;
 		break;
@@ -2553,7 +2553,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
 	case SIL_FAULT_MCEERR:
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		ksig->info.si_addr = arch_untagged_si_addr(
 			ksig->info.si_addr, ksig->sig, ksig->info.si_code);
 		break;
@@ -3243,7 +3243,7 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 				layout = SIL_FAULT_PKUERR;
 #endif
 			else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
-				layout = SIL_PERF_EVENT;
+				layout = SIL_FAULT_PERF_EVENT;
 		}
 		else if (si_code <= NSIGPOLL)
 			layout = SIL_POLL;
@@ -3365,7 +3365,7 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_pkey = from->si_pkey;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = ptr_to_compat(from->si_addr);
 		to->si_perf = from->si_perf;
 		break;
@@ -3441,7 +3441,7 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
 		to->si_addr = compat_ptr(from->si_addr);
 		to->si_pkey = from->si_pkey;
 		break;
-	case SIL_PERF_EVENT:
+	case SIL_FAULT_PERF_EVENT:
 		to->si_addr = compat_ptr(from->si_addr);
 		to->si_perf = from->si_perf;
 		break;
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-9-ebiederm%40xmission.com.
