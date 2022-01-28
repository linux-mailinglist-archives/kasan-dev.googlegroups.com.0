Return-Path: <kasan-dev+bncBAABBJVNZ6HQMGQEJLBMZQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 51CB549F876
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:42:32 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id u9-20020ae9c009000000b0049ae89c924asf4601793qkk.9
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:42:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370151; cv=pass;
        d=google.com; s=arc-20160816;
        b=f6K/yjT5NvwxbFf8XnDiSEwwv7qUD8aElAxbjF2Q1aRIpz3o0njBrHb2jlEnKwE+K8
         t2wxPdij63DgLM4FVicd/DKd3pk0QZG8XX8gjt+BUMdH4GGNnBVGfugyGY3SlsbQ/WQw
         FhPom2V1ZYqycfzgRSW3bAXeOx1wneizJGNbxseBgqsHEhnoKmJGFRwgf5Cjfg/P8D1+
         930eSTOxeNi0mxC1ZbkvNL1m8gAGZgHRVggThBWu2aQRZkq35Ggn2NLJWb9JTwb6Ztg0
         ZqBHHiXU5I70lh9BvUyP46YRF/EpRguWrn46qt91AN+egkNbBOcBBWxgS2qG9wTxO8ze
         Jflg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=RtRz01WAGohKgmHJftcD1X6HCj2Xp88Qzosc48fBtq0=;
        b=FHocZVZDoq84SJXUuzwCZiPm3tz4TOJgBUjLuV59jWtFfckqnzVs4ra0shrAE8dm5f
         bodIx+MYxzbO+i8wkVNUkZabqnIijyPw1fXbbs/I9vmouRsp2nhUm9jnJdS9CRFyG8N6
         y3CU9RYg64uZEaV709Nl5nnLNcEfdPT8vsPM0rPsi0uR0V+60Xxf5GouxZr0+qKMnKyK
         uTgH2l63XiaXFeDfDVk0pYqPdJWlXtWECwHPdhR4AOQXIJdM3P/9It7hMU8MNRTbtj4y
         ENx6pH5AtSdHVLk+/mWa10St+IpXtgyqy5LuJvcfrMfHJquYW5mSkFydXZyMfYKa+5Un
         xWOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RtRz01WAGohKgmHJftcD1X6HCj2Xp88Qzosc48fBtq0=;
        b=J6rankOYstAKOvd8GMpqd6sKGdHXimM7lmoMDHdajOXzwZiah+dy+V1x5PmLeZrC6W
         LFOi3bIcg+RdPdSyemJ44glIbl4GOEEYYT19XoT0clF6xs0Qdre2dLBdXqkYUNSDFt+c
         fUbWgIDmlTivCpUydH4N0XBuSmo2UlqImEDnAesdj4fWsPRZDsQO0QkSkslzbDuqVXam
         c0VPfEZ1mLWd6Z28zMSTatWOeORGo9BU75ydFHMOoVslgwDg1B2+fL56P4/Koi96OWfR
         VWio7/u5lnw/fs3DuBjhHJiVddcN/gAG7Py5uKzXPG1EJa7auK0qkyWhO/s6Kxt+ape5
         rPWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RtRz01WAGohKgmHJftcD1X6HCj2Xp88Qzosc48fBtq0=;
        b=py9ETO52deUY4n1NF7+EX4AB1zH24b3SjSBoPTpPeHwSL31VrG8X8ghqx+p0nduABt
         vAfo+9srnhU2sJR9G2CtHuorPmFWIVbUJBuhkfmz071ldA8J/gdI58RcwHg5nYxsy2uy
         BadZgxPU6DnSyoeQic2pQBReHPi/i0i+QDgTu/qXdalJD6asALXFHX922YaIvtp95opA
         EUChTmQxtAn9vqP5gOikhUqRDSvnCWmjhtkLo+5ldj3zwcPW30mqZYraZ4bcZfaATU2L
         TO7N7M+b22/49t1k9HnxIpOHiUwQlERAFEcZTMg6i8Iqn1M5Y4Z8EqBaV3jW4weSB0Kc
         EjQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Br8x6EfB8RnmHpgDUQmJ82AXFm4lukpZzFrpDVK4X9cBwOK6P
	iruvr7pfu61m4DeK7p8knaw=
X-Google-Smtp-Source: ABdhPJx73YVRCiOhHoI9Nubl5hE0H1QkKTbjD0cXy4XM0ifIXRljuOWwf+3fBu6kNRyNGTt1NUVj4A==
X-Received: by 2002:ac8:5983:: with SMTP id e3mr340957qte.306.1643370151291;
        Fri, 28 Jan 2022 03:42:31 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:40c5:: with SMTP id g5ls4645814qko.6.gmail; Fri, 28
 Jan 2022 03:42:30 -0800 (PST)
X-Received: by 2002:a37:3c4:: with SMTP id 187mr5344481qkd.718.1643370150600;
        Fri, 28 Jan 2022 03:42:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370150; cv=none;
        d=google.com; s=arc-20160816;
        b=bsf4m9Tvb3oP82b9L/DadxJSE9cBY7+7EijMtVZc77MxIfpv4fA6HSxC34UGbEsKr4
         qnlPAe4tZoqQPJLHRtoUlRVvZKnZRL3T2VNCC9LGLech1ZjFvC8m2ZKN85Rmcc42hwSo
         oHuRSkObvDFZTvS2psweIntj+6OGzTVCFNJGD0tGQcKBwrpmCjUKN6dTfVsQQq8Fj8N8
         tpxVI0cHnqocZpvc6f5NXEPvIGnBV7t/zFvLQobsnD7vqi+B5gKt4NGAzxjrClFRRj2O
         vqiDqy7+SBKFQ9Yww1PCSdOxCBbwjJo20+uaSMAdOD93HzXOMcTYIfglzx4jUIS/4xSn
         ZxZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=4QlCRjw6E8PPuKf1sx/O8EkHYVn/cqzsxsyQfUDKpXU=;
        b=JYXbVgrerwVAl1WZJDjfBbTiIDWkQYlNMMfXgKptrLUbekKKOavYx4F1g4gFh8+HoO
         BLZTNcJm7+nO3O+ZVpsyL16KJT/k0vjXQQQxhTCMmOIyO619uqSO9nmqilb9iJz90o46
         +nUvOq1wKPb5pyYuKh15CES2+xoUKp5ikamX0j9Pd2q3vAKSrtJHMxES2Db0DilHeW1w
         NkXeALvxVe4nqcIdWWPuc/k7dw9vqua9PKTsvv2T8Ope1rGdS+eJLABMLedyDkbBysJ+
         b6kqiCQ3M93ruuea6xSzkLGO6gp3+tMpQdI9sWtaxhKxgUKQdSWa2NiJz88FvNK6C76L
         gnbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id i7si3031200qko.1.2022.01.28.03.42.29
        for <kasan-dev@googlegroups.com>;
        Fri, 28 Jan 2022 03:42:30 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9Dxb+Kh1vNhREgFAA--.17556S6;
	Fri, 28 Jan 2022 19:42:27 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>
Cc: kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 4/5] sched: unset panic_on_warn before calling panic()
Date: Fri, 28 Jan 2022 19:42:24 +0800
Message-Id: <1643370145-26831-5-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9Dxb+Kh1vNhREgFAA--.17556S6
X-Coremail-Antispam: 1UD129KBjvdXoW7Xw4kJF18XrW3KF15CFyDKFg_yoWDXwc_W3
	4Uuw4DKF4ktayq9ayYganaqr92g3yjvF409a1DG39rt3yktryDXa98AFy8Zr95Jr4qgFZ8
	JrZrXF4vkw48CjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUbgxYjsxI4VWkKwAYFVCjjxCrM7AC8VAFwI0_Wr0E3s1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l82xGYIkIc2x26280x7
	IE14v26r126s0DM28IrcIa0xkI8VCY1x0267AKxVW5JVCq3wA2ocxC64kIII0Yj41l84x0
	c7CEw4AK67xGY2AK021l84ACjcxK6xIIjxv20xvE14v26r4j6ryUM28EF7xvwVC0I7IYx2
	IY6xkF7I0E14v26F4j6r4UJwA2z4x0Y4vEx4A2jsIE14v26rxl6s0DM28EF7xvwVC2z280
	aVCY1x0267AKxVW0oVCq3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzV
	Aqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S
	6xCaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JM4IIrI8v6xkF7I0E8cxan2IY04v7Mx
	kIecxEwVAFwVW8KwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s02
	6c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw
	0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvE
	c7CjxVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14
	v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x
	07bFKZAUUUUU=
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

As done in the full WARN() handler, panic_on_warn needs to be cleared
before calling panic() to avoid recursive panics.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 kernel/sched/core.c | 11 ++++++++++-
 1 file changed, 10 insertions(+), 1 deletion(-)

diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 848eaa0..f5b0886 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -5524,8 +5524,17 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		pr_err("Preemption disabled at:");
 		print_ip_sym(KERN_ERR, preempt_disable_ip);
 	}
-	if (panic_on_warn)
+
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
 		panic("scheduling while atomic\n");
+	}
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1643370145-26831-5-git-send-email-yangtiezhu%40loongson.cn.
