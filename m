Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFENRODQMGQEB6JTZJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id EA9BB3BB98A
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 10:45:08 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id d4-20020a0565123204b029034f05620e9dsf745948lfe.20
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 01:45:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625474708; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZchIamVev2c19/LUjAdnjGAcsCuZnZNzXKVtL01Vs1BQsyAGKF/kPDNo8UBxAJMnvM
         uZjKSCvvMvJeHw5NHjRI7KkVKiqKODxKc93ETKdQXYzYNzyvMJovKCsfadhbP2ohqme5
         9jYRDmtc3mNZXt36jLqd5Y4aUtttrGUr2xKQQDSMo58Kmv03WyOogkl0E6ShTuy+T8ZA
         Jg0LvVusMWNKYMs4IyfD28An8qEBXVw3TEbpor6inYVVR05D0LfmmJJ+wfJGYMBmUQ4k
         FSCrOXNBQrbXkAIaGEUTfMK+Om28snV/vnho2UR+VFJP9snHGig/B8ke+iA9DOegyCt0
         dGdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xaqEgkNekAzPZltdQFDaUDYbCHiE7gEZB8uwa9FCMYA=;
        b=oxJCBFlkQW68sOXn/pm4LNeJQ/lvJ993PC3I2y557diCrSWFsjskxdExiLA3LPF+KK
         oVMNvnT73anWldQFMdRXI+OL2QqOUFloir9sbTaUG9TahfMG6tbZ03XT42y6k99VlTtz
         DcGD2uTu8brPwVD9oWl2EznwM+jDHv2oCk3mqez7/Xnf0+7ntuLx7AWkPGezyV44SUYi
         cISGBmxC4JWTX75JfLLrNxALmaT3O0IAdPk6As2oo+xw07NrR28AYtFdMwamz/FOiBhk
         PdfxG8Suuq+9uBFkWDhJPGxPNfu+9wjLC0EhFrT68Nms+oupPWBndk1o0Nc5V387SGaq
         sAjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="gIPZ/pki";
       spf=pass (google.com: domain of 3ksbiyaukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ksbiYAUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xaqEgkNekAzPZltdQFDaUDYbCHiE7gEZB8uwa9FCMYA=;
        b=cAar8+DUNyTB6tAZfgHNbObtYfju5MzbC7qPOuQ0Bdq7ZHHziXJhZGyf9tfUlsC+9f
         kfwuXgvRmABrGjq9GF2p0Qez1foUd8cIR9BB84KZT7XbRpYJqs16mLZ8B+rCP648je/T
         GHzIOe6nGAyltFFUIIYRsyno4g1KkGrBky+rH5llfY48iMR/aAASoML42lQQ6+zm3AP4
         VblcKOY/baLb6ct2EC/bI2bfMdKbdstRefNtmSc8Iw7pKWCgyLhoZ79ufV0EpJSVGKoy
         CX5VyIOzcmVG0LmlcCd+LZqFiRS767uXWzSTfgRpS5fVWERLMTCrPddeGsYpYBlGV27R
         NmkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xaqEgkNekAzPZltdQFDaUDYbCHiE7gEZB8uwa9FCMYA=;
        b=eVpafdleE/UwF6o4oNHMEzeYKSCN+0rgxm7uXadfiMzMS3T1sGM+QjUrQJGiN2tIU7
         zexnRLw8qLVue/TIP/O6VUoumeimH8jkS0wNUYLbMTDfUvqlJBLawisnegxbFZtqYBc9
         7wr6+4GxsvsP/H5d2t38freLsA+mr2kg84Df6FBqDwcRERQ1ZixIkLGqop76grhvekb8
         rzpDO6Ux0xd2th6xUqT5nhm3KUDRgfosD1galatDWx3V3zx5BSjEE4NyuRWVAwzWx0l9
         f1Bn/uTJnI7MErcUDLtqW3Cvvzns89vwD6qM+3WElcN3+yVhU+4qESQKg1e++fx462lE
         47kw==
X-Gm-Message-State: AOAM531I+pjX7dJBqYVkgkf4Wh/9qH+PM1thVxuTsFZpTfj0p6FGz2R5
	ZbUs6wKOFhbHRvOukXb2iuU=
X-Google-Smtp-Source: ABdhPJzwKPF+bB/elJF8oOemuMcufh/W201Kzx3nmabeES0SBGenHpuxS4iibswDPN3Cp+nJ6rLRpA==
X-Received: by 2002:a2e:6e15:: with SMTP id j21mr7170602ljc.223.1625474708484;
        Mon, 05 Jul 2021 01:45:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1025:: with SMTP id w5ls2868694ljm.0.gmail; Mon, 05
 Jul 2021 01:45:07 -0700 (PDT)
X-Received: by 2002:a2e:b88b:: with SMTP id r11mr10131353ljp.24.1625474707319;
        Mon, 05 Jul 2021 01:45:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625474707; cv=none;
        d=google.com; s=arc-20160816;
        b=t5uctYSfOGG8MqjzC1+0wGzSAe7HrD7fX/0/US7xI7aZt81oa7jOn1u5p0AGYWVicC
         w+P8rNO4aP+6L8wp6fsffHzxuwcKEaJi2AH/XMvTIiKtBoYjWME0aDHQ7z9DRRX4ysxR
         FzWdM7Xwo/CdrGZnJs6gbKNdNfsYaXf/lap27Aa0/mIDfSl8tSIrhUlAZNoKWR9eOJuI
         0ApBM34aYhdKy50wypNXUR88GdN8CvGyOBggyVYud+MpTvUlkSChpunIUJrSXgBcpunr
         gfSTw+VYXfrezrX969ZZLSDYGbJCWXlSPYD4wi4XXAXviv7zOjl9bsWE95c5D1E2+Obg
         Iq3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=4je/SN/KnbWSxzkZDr2TBnIQKjzyK1cJT3ltaKs0hSk=;
        b=B8v4F+gBz0/yM9qn58oR1kSitWhL7878hUVDlrfgk51y8kUrOdIVTTMIfGUm9TPs+K
         E3lBfmfcRk1JAK70XrC8K7E89jlhNjvbmM9MIp7E5VRpMxEL/ylzBgJLi0sXy0G8ypS9
         BnU+ckYEF3q1JsWkox5zQIZX73WcYFO9D+9ighUwl1oQNVbMvEF9AympIWm1scGJnTk5
         xmNdPsuCwUEKkr4PUiNvrk6tjyjU3VXibTHvIzgrxXB6LnsSZ6Gk17M/+T0q2z1JzLez
         1nE8uvrnlIpqmMo4cxRoHWWUs7YGDmUjArDp+wC9e4SEZaXJvOn1CNYz1cRbgwUBqPJa
         brog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="gIPZ/pki";
       spf=pass (google.com: domain of 3ksbiyaukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ksbiYAUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id m18si459915lfl.1.2021.07.05.01.45.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 01:45:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ksbiyaukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id k1-20020a17090666c1b029041c273a883dso4998081ejp.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 01:45:07 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dddd:647c:7745:e5f7])
 (user=elver job=sendgmr) by 2002:a05:6402:845:: with SMTP id
 b5mr14691508edz.266.1625474706620; Mon, 05 Jul 2021 01:45:06 -0700 (PDT)
Date: Mon,  5 Jul 2021 10:44:53 +0200
In-Reply-To: <20210705084453.2151729-1-elver@google.com>
Message-Id: <20210705084453.2151729-2-elver@google.com>
Mime-Version: 1.0
References: <20210705084453.2151729-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH v3 2/2] perf: Refactor permissions check into perf_check_permission()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org
Cc: tglx@linutronix.de, mingo@kernel.org, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mingo@redhat.com, acme@kernel.org, mark.rutland@arm.com, 
	alexander.shishkin@linux.intel.com, jolsa@redhat.com, namhyung@kernel.org, 
	linux-perf-users@vger.kernel.org, ebiederm@xmission.com, omosnace@redhat.com, 
	serge@hallyn.com, linux-security-module@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="gIPZ/pki";       spf=pass
 (google.com: domain of 3ksbiyaukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ksbiYAUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Refactor the permission check in perf_event_open() into a helper
perf_check_permission(). This makes the permission check logic more
readable (because we no longer have a negated disjunction). Add a
comment mentioning the ptrace check also checks the uid.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Introduce this patch to refactor the permissions checking logic to
  make it more readable (reported by Eric W. Biederman).
---
 kernel/events/core.c | 58 ++++++++++++++++++++++++--------------------
 1 file changed, 32 insertions(+), 26 deletions(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index f79ee82e644a..3008b986994b 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -11912,6 +11912,37 @@ __perf_event_ctx_lock_double(struct perf_event *group_leader,
 	return gctx;
 }
 
+static bool
+perf_check_permission(struct perf_event_attr *attr, struct task_struct *task)
+{
+	unsigned int ptrace_mode = PTRACE_MODE_READ_REALCREDS;
+	bool is_capable = perfmon_capable();
+
+	if (attr->sigtrap) {
+		/*
+		 * perf_event_attr::sigtrap sends signals to the other task.
+		 * Require the current task to also have CAP_KILL.
+		 */
+		rcu_read_lock();
+		is_capable &= ns_capable(__task_cred(task)->user_ns, CAP_KILL);
+		rcu_read_unlock();
+
+		/*
+		 * If the required capabilities aren't available, checks for
+		 * ptrace permissions: upgrade to ATTACH, since sending signals
+		 * can effectively change the target task.
+		 */
+		ptrace_mode = PTRACE_MODE_ATTACH_REALCREDS;
+	}
+
+	/*
+	 * Preserve ptrace permission check for backwards compatibility. The
+	 * ptrace check also includes checks that the current task and other
+	 * task have matching uids, and is therefore not done here explicitly.
+	 */
+	return is_capable || ptrace_may_access(task, ptrace_mode);
+}
+
 /**
  * sys_perf_event_open - open a performance event, associate it to a task/cpu
  *
@@ -12152,43 +12183,18 @@ SYSCALL_DEFINE5(perf_event_open,
 	}
 
 	if (task) {
-		unsigned int ptrace_mode = PTRACE_MODE_READ_REALCREDS;
-		bool is_capable;
-
 		err = down_read_interruptible(&task->signal->exec_update_lock);
 		if (err)
 			goto err_file;
 
-		is_capable = perfmon_capable();
-		if (attr.sigtrap) {
-			/*
-			 * perf_event_attr::sigtrap sends signals to the other
-			 * task. Require the current task to also have
-			 * CAP_KILL.
-			 */
-			rcu_read_lock();
-			is_capable &= ns_capable(__task_cred(task)->user_ns, CAP_KILL);
-			rcu_read_unlock();
-
-			/*
-			 * If the required capabilities aren't available, checks
-			 * for ptrace permissions: upgrade to ATTACH, since
-			 * sending signals can effectively change the target
-			 * task.
-			 */
-			ptrace_mode = PTRACE_MODE_ATTACH_REALCREDS;
-		}
-
 		/*
-		 * Preserve ptrace permission check for backwards compatibility.
-		 *
 		 * We must hold exec_update_lock across this and any potential
 		 * perf_install_in_context() call for this new event to
 		 * serialize against exec() altering our credentials (and the
 		 * perf_event_exit_task() that could imply).
 		 */
 		err = -EACCES;
-		if (!is_capable && !ptrace_may_access(task, ptrace_mode))
+		if (!perf_check_permission(&attr, task))
 			goto err_cred;
 	}
 
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705084453.2151729-2-elver%40google.com.
