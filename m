Return-Path: <kasan-dev+bncBCALX3WVYQORBJGPZKCAMGQERRCRXIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 399B7373D43
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:50 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id x10-20020a1709029a4ab02900e71f0256besf746329plv.8
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223908; cv=pass;
        d=google.com; s=arc-20160816;
        b=t/ZeBn9XWidH72ErTzKqfEUIpSAjTmBxZ3ChzoQSnX7K/TlW9ryyH9mRIe2IcK8v4r
         lZGoOkcgf8aSGide12+odt+jIGkw+yLDRiLP1Y1jBXD8RwdXQ4psxovv2Y6DdnST/7Mc
         SrvvVUbYQaF48K7xNA4B1wcO45Sb8p0jYFRfNEnI50lXACGLpA2v0mkhtxYXfFplQ8N5
         9kWIiwihiAa+3KkPtBnapyY/V90c5WT4tJJXtOUm43KbSxLsaHdO1qAFsrJZ9ciTj+1c
         bZuoG7PSRvCXeOaEwylMTNZLZ2vNXUKOlmebzhOlS/7p5v62VnqLxntAAIF1Jfcr83n7
         WuMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=XOyI+CgJlWw6kvaXIw6p+qY7LkEO5rqgcoVc56/44sw=;
        b=KrtjdyzvIKPkA6AY3QAZ9PERKazaUCbOayf6qC0J+kPRlwlYmI4RounW3gJ0nk4roq
         HAVEn5+FCdZoktuJaINK7NRiEhK7fBlDFlVvBWpEaP6ZI5GenxY8b5XEklxKGuIX/FWm
         s9tYvdMU8fqISvmNOe1+jEwKB3GEEfgfit/5Fh1aC+qsB/pm97OK0pzaWaz93kzBB+rR
         4Xtgkr7vAmfFt727hHYhtWyV//V9im088gsoxF69tLhpDXPVE94sYpBrzk7stNGGYlDx
         nTMxKTN8mJWALJUFsizvhwZaaLGoo8NlaF0Q69yX7wulaPvfFMy900d5sMyHidHX8REI
         1dqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XOyI+CgJlWw6kvaXIw6p+qY7LkEO5rqgcoVc56/44sw=;
        b=ck72e4Wf3rrw6y4C0AogwyLRvJ0gavzA/LXw16EOO5WZUP1K8GgXecZhdqQFGiliea
         UQP1+RmJG5uAYCe6xkriA3j6HgIBl4CNHSDc30BV0SO4M1ZyTZdNTYFEWrtBf+W7wOaM
         15RGOTUeX/A3+Lc0awDhfk5P0sRdHV6TtjKOKWiBBn7rKZlvcwaalZ7aGK8RuV484vU1
         QnYpogSVleon0xPIk7GgSINUxbossuAKPA4JC1EkCbVBT2n1uVYDWtS9yyUY2bU+WHrd
         m8+mxJBPs0qI2kRJkBJnNiiNjGJczaY8rfgde1ltRyyxFE2YX51QJwd99MzSDBUfniIF
         aG1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XOyI+CgJlWw6kvaXIw6p+qY7LkEO5rqgcoVc56/44sw=;
        b=dHbH0Qmfk9IJOWUaSp/UQluMqtGCKuSV7sz3DoX3yH4QpMwzpEt7G4FwvawL3Ewmfx
         R5QHCnCZaq0ahCTzc4jgUMKMpEKidZIcCAVF3tJDXJXThI1K6JvhuXqimWbVl1erb7xy
         YmtWUTJ9Ew+HCVO+dvTegohSmxR5uO4YOtDXUxv/Cs8JYS1Td1ofj76Qhf6qocwHc1za
         +9hKzWvRc3m2nOACXdrwmgswzuilrR7YpNzdeJrxbPezyIr31RXjxI4egq6Uk0hmd9Hv
         DX6csu2kbJFKVUuM85a3ibLx3D2dWtBNc5ysY0DO9J6UUqIrFW/A5xUAP8CSGIyahhb2
         B0nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530b2FKogg9TZdmTZwcL5ntMsl0FDuWrK8VhtKggI3zCdU7TkplX
	KGJnpqzXUXl7vuu9nNu10ew=
X-Google-Smtp-Source: ABdhPJwCM9nqD7Ow/h5aJGGlCOR4z4OxfstO/DkVnCVQcc1nS4vil+Pdf2JJ5xKRwhykBkwDafuR2A==
X-Received: by 2002:a63:f502:: with SMTP id w2mr15895397pgh.197.1620223908698;
        Wed, 05 May 2021 07:11:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7208:: with SMTP id ba8ls11247683plb.10.gmail; Wed,
 05 May 2021 07:11:48 -0700 (PDT)
X-Received: by 2002:a17:90a:d98b:: with SMTP id d11mr10586152pjv.33.1620223908115;
        Wed, 05 May 2021 07:11:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223908; cv=none;
        d=google.com; s=arc-20160816;
        b=QM51zPqrLJW1aTbE+Sz+4JfQAGx4HQ//ka32s2Sx+CYNYrmVPznw3lfwMMHmB0WFi0
         99dhja7TrYSgJz1IZeYAMQ0ToeIbDyd+YQuRFFJdn1SXBD9AkRbF1HBABAu9Wd/tjPN5
         HKI/IoGTZf1+7C5ukKLFEUdr+W4E4D2jASqyqLSK2z9KqUiT4OXOrXwqUXYxPtbg/AvR
         OBEr0se/HzoGcUsrT3qt0TeIVIGcMzA1ed8h/tImjIDgUKkubHcjhCSwLChF5E3Mv4vM
         O3vHQGiUx4S08APYyUzKtvmzpQr+Yd2jIfv/1ggt1VwPnN+SJHIlGqDusXGKZpAwzgC6
         l4bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=S27LTPs3VHqnPJoLFM/cX2upb1TOa5mQrgQUDfrnClA=;
        b=FPRnY/yNtBZB37IYWW/eGngSZ7xVeqN5FY0jN/qtmWu+7PHDZlOR4G8oVnkeQwdPui
         XUIskWtouIkd581mEw6pV/MTpk6ffeLM8dKrRyZC3lf81y8xluuPMMJyRD2aUVd4MPiL
         SdMq603RYUPUbHY5gHgdqSUPHFUEvaWtGizx+20CgFR7KBnfl2Q6VJ+pWPM6nWEgMtIb
         wulaDWImuRI+J1v9sTOnThXtGNJGJhWpt/0iKzaJ9PfyP7B0SYSY3loS4/pwLZ6B/+Gh
         z+OZigdddfIzEGNPXBHA+U4vMFVSGV3LB5OOr8YCxd0v9sVJSRr1ocRfczf+RCwHd+s0
         sSRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id q62si532715pga.0.2021.05.05.07.11.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFf-003DOB-9a; Wed, 05 May 2021 08:11:47 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFe-00007y-Cl; Wed, 05 May 2021 08:11:47 -0600
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
Date: Wed,  5 May 2021 09:10:59 -0500
Message-Id: <20210505141101.11519-10-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIFe-00007y-Cl;;;mid=<20210505141101.11519-10-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18/BcOddtsgsGDN6U/7RxhaSYKdZmJUfIA=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.9 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4997]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 526 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 10 (1.9%), b_tie_ro: 8 (1.6%), parse: 0.94 (0.2%),
	 extract_message_metadata: 12 (2.2%), get_uri_detail_list: 1.83 (0.3%),
	 tests_pri_-1000: 13 (2.4%), tests_pri_-950: 1.22 (0.2%),
	tests_pri_-900: 1.03 (0.2%), tests_pri_-90: 136 (25.8%), check_bayes:
	134 (25.5%), b_tokenize: 9 (1.8%), b_tok_get_all: 7 (1.4%),
	b_comp_prob: 1.87 (0.4%), b_tok_touch_all: 112 (21.3%), b_finish: 0.89
	(0.2%), tests_pri_0: 339 (64.5%), check_dkim_signature: 0.61 (0.1%),
	check_dkim_adsp: 1.94 (0.4%), poll_dns_idle: 0.35 (0.1%),
	tests_pri_10: 2.3 (0.4%), tests_pri_500: 9 (1.7%), rewrite_mail: 0.00
	(0.0%)
Subject: [PATCH v3 10/12] signal: Factor force_sig_perf out of perf_sigtrap
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

Separate generating the signal from deciding it needs to be sent.

v1: https://lkml.kernel.org/r/m17dkjqqxz.fsf_-_@fess.ebiederm.org
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 include/linux/sched/signal.h |  1 +
 kernel/events/core.c         | 11 ++---------
 kernel/signal.c              | 13 +++++++++++++
 3 files changed, 16 insertions(+), 9 deletions(-)

diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index 7daa425f3055..1e2f61a1a512 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -318,6 +318,7 @@ int send_sig_mceerr(int code, void __user *, short, struct task_struct *);
 
 int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper);
 int force_sig_pkuerr(void __user *addr, u32 pkey);
+int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
 
 int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
 int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 928b166d888e..48ea8863183b 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6394,8 +6394,6 @@ void perf_event_wakeup(struct perf_event *event)
 
 static void perf_sigtrap(struct perf_event *event)
 {
-	struct kernel_siginfo info;
-
 	/*
 	 * We'd expect this to only occur if the irq_work is delayed and either
 	 * ctx->task or current has changed in the meantime. This can be the
@@ -6410,13 +6408,8 @@ static void perf_sigtrap(struct perf_event *event)
 	if (current->flags & PF_EXITING)
 		return;
 
-	clear_siginfo(&info);
-	info.si_signo = SIGTRAP;
-	info.si_code = TRAP_PERF;
-	info.si_errno = event->attr.type;
-	info.si_perf = event->attr.sig_data;
-	info.si_addr = (void __user *)event->pending_addr;
-	force_sig_info(&info);
+	force_sig_perf((void __user *)event->pending_addr,
+		       event->attr.type, event->attr.sig_data);
 }
 
 static void perf_pending_event_disable(struct perf_event *event)
diff --git a/kernel/signal.c b/kernel/signal.c
index 697c5fe58db8..49560ceac048 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1753,6 +1753,19 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
 }
 #endif
 
+int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
+{
+	struct kernel_siginfo info;
+
+	clear_siginfo(&info);
+	info.si_signo = SIGTRAP;
+	info.si_errno = type;
+	info.si_code  = TRAP_PERF;
+	info.si_addr  = addr;
+	info.si_perf  = sig_data;
+	return force_sig_info(&info);
+}
+
 #if IS_ENABLED(CONFIG_SPARC)
 int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
 {
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-10-ebiederm%40xmission.com.
