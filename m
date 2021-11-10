Return-Path: <kasan-dev+bncBDAOBFVI5MIBBOOVWCGAMGQE567PGEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 233A544CA86
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 21:25:30 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id p19-20020a056512139300b003ff6dfea137sf1710064lfa.9
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 12:25:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636575929; cv=pass;
        d=google.com; s=arc-20160816;
        b=o91PDLSBdwLedu12tRtkXdzjWG+ZvdN2gdYPsVt2xr8qjAOjb2/74pU5jMv3c462Hy
         /wCsShllun6RVXvi8YZh+qnGptfNmQ4g5GDGgWE1tUMbccRr0uriirnLDuc8rnzV5K07
         bTdI7nQ17mdHYKjYMJBJIEZDgOwmdHfhN+vBUSZASI6z8LRW0bB8jg9oOJPlQkR5yST6
         MMkah9XheiVNpzCBHZBdfwbkeHaUCGwGAwCiXxc2YfMm6Xz79YsKdCrLdajEzV4niVMt
         wDrq+Bnd5j6hVpmL8x05NGBkNqPLmMwcCxVuUMq1DZUd8wAeptW7KZr+l4oKO4Bwm6zN
         XEaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tK80CbRfa8wWGvFV+JNmhiYOIudFkwkljwHMCYuApxI=;
        b=OAPx4kMWd/kNJSwAxfeS0rZWpY8+AbOVmnPNNkq2ve69Y6/zHJmEntFBPXzHT/6KZ8
         iI0C0rk6NAhUObC0NtwSZEgi+AU8BkiEx/AgFpfPWCAL417U9lBklBecCTLrDZ7kUga2
         MXCxYgHHIXkg6zsen6ZveJakfIBcyHPRkAV56Qe/qGPSxQ9xORDQcw7lc0N7KldenQ0N
         KL/yYv/JAmZGYJWsjrkoh/PBC/hxUJmL1HydbNImyOlCYaJTZZbV5YfBnP3ll6xm+AV0
         UkwMp+NF4L8n9lrO4bZfV82I0cPs9kSTAIKNf5YcUEXaJbgVBXnYUVGR7YpY+m3H2XBB
         MZtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tK80CbRfa8wWGvFV+JNmhiYOIudFkwkljwHMCYuApxI=;
        b=owHN7J2so3LBKZ+3yC5FnJu2tn1v8kqh7a91ety7tsPKsq1THE4M4eYY+gOjhDy+Lj
         RO33M2qZPElF/S6xnv9wFrIEGDoh/cNOB9S62T/F7MVaPc0rXXV0ra5wcPTkoWyou8bp
         rnE2nsfstRWLIdjRJuR7Fdt/KgzldK1coNOT4R9RT3TKkGeALjUKTUM0KqbnyFpekNhU
         +dpgovw2ULIxkCsoXZlUFEC0WpISztahzfHxdKKre1mMmz2YnV0E3y6JSfacSqswkIAI
         FjbisuKn92xpo6srEYt4dJxcnjllvvDOAQrL+j6xdKjCX7Yrq8hk0hQq9hwRn9qQEG9M
         A77Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tK80CbRfa8wWGvFV+JNmhiYOIudFkwkljwHMCYuApxI=;
        b=TimTMJGuBvy6qD10gp8A9twqqRcLj5/QzUqZPxtHVtxQ4FeMGnIh2FX8e/9AqKSSh2
         63a1Idiv6wG2gvk8BCL1wj+kX1KsXbrBn3bzLAzeLmCdGlnbj4XHkNVjGEtEOP1VA/uf
         Sw+RTYGLOc/29vmFAKt8SsDDWS5cOoW+55pxVwJQwiMhMrRXNFfpO8ZnXONRerIb4DbU
         uPWU+3CgkEI/BpDHZmz/sY4p9i9Jf1Y/0SDnyDXFMQjO+efm7by9vQA9irAFk3waN2xw
         8hKiDnLWATQkhWHR3Nojp/I4gBp2rxKZHXDzdusNf+YYv/9dEzSpL7M4MUIdBNkO5ghk
         npyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cTuylICAK1BhKHq/uSRdZ46/5WZ2kAPQ3OdGXYvVgAnfdIEte
	wf8H4Nlvmfv0+U97rOjjCpk=
X-Google-Smtp-Source: ABdhPJx4QPMIFKW41UnXixEAqhrCCh9wu9WJ2dGLA+UyLczp7zOGHPeCA7rruSPp5fDipfrlDWxWCw==
X-Received: by 2002:a05:651c:503:: with SMTP id o3mr1654260ljp.249.1636575929640;
        Wed, 10 Nov 2021 12:25:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1251:: with SMTP id h17ls173741ljh.6.gmail; Wed, 10
 Nov 2021 12:25:28 -0800 (PST)
X-Received: by 2002:a2e:9e07:: with SMTP id e7mr1672128ljk.457.1636575928657;
        Wed, 10 Nov 2021 12:25:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636575928; cv=none;
        d=google.com; s=arc-20160816;
        b=O9giYsrNnDICOTk1JyeYx+5fRrvq30udIt+Z8pn+xxvMoMlADDDSXcBfTVkWvsAGnA
         7Hte++ORya61F+K8Qg4wIeDVHd6B/XPTC7J4kWH3GqfYYlHlpmFfPGbv0DKJUPz6JW1r
         W+MjDWXPw4agxt9qY4xFBzFxScD3VEcTY6u+atrrZQ+33kqmId3guAGdxKov+oU4C3kE
         OF43sO54vLDA4PPd/zpXrgQYa0v9S5kR3CQdw2JVQyqVyfpma9lPdtGAOEnkuhh4/qM4
         6laKj/Sl49CcKjcgFVEdkwFx0wFbxXtCfOcmlqWhjabizrsWXD7KcRzYEBOZ+qp8ck2q
         acGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=3HaXY73ihfpskTj9j0pI9M6hMuGkezVST1fktm/y4z0=;
        b=cfTtWdpWa7V0oqEKvanfMK9WT+ocSRTZ2CZPLG+7qJlVzWMn7l8F1r+oYDudThYkCx
         xNU3/NZkOOxANzyTjFDQ+dpFbhHAnCKCf3MUjqZwyL9MVsSekGt/VagCGLBD3r5vCoRx
         GsnPr3FH+NdmxlvhmTEeiUz7dWKYBYaOvq1L5fD4zCFWhWa1O3wKMjB8Hsj+0BQvil5D
         EgQS2T5jD1oxQ0PtpQ/3+FqUrhodG+0H5NzmpBnHumG6ggFAqwMzngvgZrUUn+25xEYm
         Kt7Pn+kOK0/APcA/a8scp8OOTWwyla6x4Trne5nzVVDp3NTOaMCveeotxhtdKnzCjkwB
         XZYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z12si84276lfd.12.2021.11.10.12.25.28
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Nov 2021 12:25:28 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 88E0C1435;
	Wed, 10 Nov 2021 12:25:27 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 5863A3F5A1;
	Wed, 10 Nov 2021 12:25:25 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org,
	linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
Date: Wed, 10 Nov 2021 20:24:45 +0000
Message-Id: <20211110202448.4054153-3-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211110202448.4054153-1-valentin.schneider@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

CONFIG_PREEMPT{_NONE, _VOLUNTARY} designate either:
o The build-time preemption model when !PREEMPT_DYNAMIC
o The default boot-time preemption model when PREEMPT_DYNAMIC

IOW, using those on PREEMPT_DYNAMIC kernels is meaningless - the actual
model could have been set to something else by the "preempt=foo" cmdline
parameter.

Introduce a set of helpers to determine the actual preemption mode used by
the live kernel.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
---
 include/linux/sched.h | 16 ++++++++++++++++
 kernel/sched/core.c   | 11 +++++++++++
 2 files changed, 27 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 5f8db54226af..0640d5622496 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -2073,6 +2073,22 @@ static inline void cond_resched_rcu(void)
 #endif
 }
 
+#ifdef CONFIG_PREEMPT_DYNAMIC
+
+extern bool is_preempt_none(void);
+extern bool is_preempt_voluntary(void);
+extern bool is_preempt_full(void);
+
+#else
+
+#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
+#define is_preempt_voluntary() IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
+#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)
+
+#endif
+
+#define is_preempt_rt() IS_ENABLED(CONFIG_PREEMPT_RT)
+
 /*
  * Does a critical section need to be broken due to another
  * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 97047aa7b6c2..9db7f77e53c3 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -6638,6 +6638,17 @@ static void __init preempt_dynamic_init(void)
 	}
 }
 
+#define PREEMPT_MODE_ACCESSOR(mode) \
+	bool is_preempt_##mode(void)						 \
+	{									 \
+		WARN_ON_ONCE(preempt_dynamic_mode == preempt_dynamic_undefined); \
+		return preempt_dynamic_mode == preempt_dynamic_##mode;		 \
+	}
+
+PREEMPT_MODE_ACCESSOR(none)
+PREEMPT_MODE_ACCESSOR(voluntary)
+PREEMPT_MODE_ACCESSOR(full)
+
 #else /* !CONFIG_PREEMPT_DYNAMIC */
 
 static inline void preempt_dynamic_init(void) { }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211110202448.4054153-3-valentin.schneider%40arm.com.
