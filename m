Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKXYZ76QKGQEYRHUW3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B26862B6A63
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 17:37:02 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id a134sf1775726wmd.8
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 08:37:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605631022; cv=pass;
        d=google.com; s=arc-20160816;
        b=UGWzdve/WQ2ao30g4OXZCbVgk0yvclL/Y8QUmPG5p9fpvwOfwQi0cR8drSLzLq0wk4
         C0Hgx4fTDP/9Q/Xlky/zYDMnxXjXX9QSa4NaEZb+aWYcGmqKhKjleU5qo7dMQfAmqfEQ
         EcEFBdDRWqLUkwSb83hZ6do2jmTDbD58SFfV5Kie+H5CRGsAAxqj4vuYbY4eeXBlKiEm
         ptoBpIBbpdUGoha09uzLMmaQh6fI/Ntm/vGzTk3FJNh+6GHpLDQWB3DB6z2wysG+OBtB
         4nxeHW3IOnw81DvPhOKtABJjEn5NrY+V4/pM9bTDXoko9dHbzrfkagegQe3OajwEF6wF
         W9mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=De3fPbndjemGb7IXvRA334L1dXamOUU7OVZtYenISyE=;
        b=RzDnsEK5BQnNIJfHFRG065B5eqiv1gb/9rlF7ZaX02aTvq9auBfHHdUoA2U4TjVM3N
         C3u9vtN33vGYiEkk9jTnNbZDU/+L98DsG2u1MJxnVFPNGcojoz4tIRLg5e3XATRDdBlr
         fim7drbn+0yZIZTyRAVgoVG2tMSJAkLzIGNPPa8yUvjOat2mp6hjd4oVJycqNRSzu17f
         rlsnJQi/zIdkrIP6mrvYtGR9BVe0M+dzeNq77G+0SZ00U5Uj+Md8axRXof1YjzrYsuY7
         WPXSmzP0yMLFxXASYlS22ZTqEW+NYGoMgAN5jGoFNDDEVcyUn/h4NzZqgnH+liY/OZKr
         eOVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NgPOtLVr;
       spf=pass (google.com: domain of 3kpyzxwukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KPyzXwUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=De3fPbndjemGb7IXvRA334L1dXamOUU7OVZtYenISyE=;
        b=JpFLKB1t7h5h8E8QzB3MellIfzfAUuS3PMuktwl3Zp2gDNGlQuEjY+X+ciYJJGSUzz
         BXdYWVm+taI5pmmFVWoXITtyf1pmEUv1wG0yCgun3SDk7PteGKCnBZ1wBDNmnRBGEx+t
         OvuVgaJXbGqNP+3wUZc5i4Glp8vUOUzc4QjRfnA552wddYFZDVU660ylO7KP+z/S8TT6
         fkioDX63SJsssDxG3EOyZxpHlIj6BhgEwRwKbGLnHRpIo2CrEloL+iDnvAEqEgWsvvVP
         ZWW1W+nbWq4PwUnLWHA0wi2OnoP0W3KVjF7YoglDl9huUJG2SBdMMXr+0J8CXbN+yd1u
         ovmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=De3fPbndjemGb7IXvRA334L1dXamOUU7OVZtYenISyE=;
        b=S9Y9XV2vT737tvcXdrXXeBiK9xiR5GNCVNdxGrpcpihfXwSokOgxVDcXc+lUekWTzk
         ZfwsDI7B2ZqEixBJriQRGCxJem2YMBlhXpyhfD+TKZSflaApXjs6GWW8SGzW7lffjxIm
         pghkZNGsIlCYyVPgS2tSeY7FcZHFNZ8upTcr5Ynpt6Qzj5LVuB46Kd3LskIBvrLO+vyt
         cLmltSyJ0wXeBsX2qWptR3AZjdZEqvpjMYUkuzp+DOXAeQk8HVorj4gfvV/qX8BQhDEy
         AwKhslcgIH13NY2tRO803liEcvdVmK3zQdX9VFrzfJfE6weMxdTf20otmw/ZFK/IM7NA
         ft4g==
X-Gm-Message-State: AOAM532FNuaK1M+7utp938n0W+cSlmHsRDBdi+TfcwIiPCSvKwq3x3zY
	9mJ6JfgFUk3yjZ98GrPs3t4=
X-Google-Smtp-Source: ABdhPJy9OYscOS0QM9IZCqaN78pc7A8ptD/LOT9SIBuH5jMkMF2tYBtnX33fuPnyS/Xd+1KjThZYAw==
X-Received: by 2002:a7b:c3ce:: with SMTP id t14mr172712wmj.170.1605631018582;
        Tue, 17 Nov 2020 08:36:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3d87:: with SMTP id k129ls1602939wma.3.gmail; Tue, 17
 Nov 2020 08:36:57 -0800 (PST)
X-Received: by 2002:a7b:c3c7:: with SMTP id t7mr550438wmj.114.1605631017436;
        Tue, 17 Nov 2020 08:36:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605631017; cv=none;
        d=google.com; s=arc-20160816;
        b=IqCkLzUevoO98Hygr1bAmtnMtfdbcKPmr2yzoImdt2d1frDAutmazZ0yAZgbNpyQVR
         UFwnwcE0Pv1/k5AZdEiqqmyv+CZ1SvugbwdRgGOolxCiIxlKLAKg+kv4YQaRAvLS7TC7
         cldUMr2WSCGngwDeGD3BTUnPHKcK67bWGfPqYp6Zea/5a1ItbuCI0JFq79j32TARiUxB
         PdUFV4poML+g+pbAQCjMWbE/0JpjM6n8qFgLHtAGxBJwDuDaYHZfoDaI0DMZEDIkxzwa
         ucwcyzHHcZYq4qNXso10NEH2e9aNe+yE2na3BlGidzB7D1hipj8VmMSHs+eDBhyK2nwG
         zLxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=1AB7jWGDKqYLUDgu1C5v3wJ4U1VEzQNUsWCkMQleGjc=;
        b=xJK5qa+bFkcLYEkcbCj9GI72056+FNEWo4wwAW4XsdqZkRHx2iWsJkpDFubNwk2uVg
         omb30OuiPOZp4mbuM9zsZml27LS8X6qnpxtPIvW0oLGqLfRn2BZeVQON/IDcmhPqOUJI
         CIP9VNDNdPp1NLujUToaMVpeqaGEVlT1+vdIlThcQru4bNkkfLWuFQfXXqQDBoW1ySVm
         BC72hQCWCvSPqLm9V9YmV/r+m9jpwiUnVvkQZXnQ+BTwBO6SyTYFofo7d/hNG4bne8Yq
         tb1ERpfx2r9TSulN3kMsdoglMOCAGU8/h+8kyi5WVzxnz0InKjElOkp63uch3lYoO4pt
         R+qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NgPOtLVr;
       spf=pass (google.com: domain of 3kpyzxwukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KPyzXwUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 61si67649wrq.0.2020.11.17.08.36.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 08:36:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kpyzxwukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y187so2008517wmy.3
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 08:36:57 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:791a:: with SMTP id l26mr22568wme.1.1605631016587;
 Tue, 17 Nov 2020 08:36:56 -0800 (PST)
Date: Tue, 17 Nov 2020 17:36:41 +0100
Message-Id: <20201117163641.3389352-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH] kcsan: Avoid scheduler recursion by using non-instrumented preempt_disable()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, tglx@linutronix.de, 
	mingo@kernel.org, mark.rutland@arm.com, boqun.feng@gmail.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NgPOtLVr;       spf=pass
 (google.com: domain of 3kpyzxwukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KPyzXwUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
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

When enabling KCSAN for kernel/sched (remove KCSAN_SANITIZE := n from
kernel/sched/Makefile), with CONFIG_DEBUG_PREEMPT=y, we can observe
recursion due to:

	check_access() [via instrumentation]
	  kcsan_setup_watchpoint()
	    reset_kcsan_skip()
	      kcsan_prandom_u32_max()
	        get_cpu_var()
		  preempt_disable()
		    preempt_count_add() [in kernel/sched/core.c]
		      check_access() [via instrumentation]

Avoid this by rewriting kcsan_prandom_u32_max() to only use safe
versions of preempt_disable() that do not call into scheduler code.

Note, while this currently does not affect an unmodified kernel, it'd be
good to keep a KCSAN kernel working when KCSAN_SANITIZE := n is removed
from kernel/sched/Makefile to permit testing scheduler code with KCSAN
if desired.

Fixes: cd290ec24633 ("kcsan: Use tracing-safe version of prandom")
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 14 +++++++++++---
 1 file changed, 11 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3994a217bde7..967b0b2f9d59 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -284,10 +284,18 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
  */
 static u32 kcsan_prandom_u32_max(u32 ep_ro)
 {
-	struct rnd_state *state = &get_cpu_var(kcsan_rand_state);
-	const u32 res = prandom_u32_state(state);
+	struct rnd_state *state;
+	u32 res;
+
+	/*
+	 * Avoid recursion with scheduler by using non-tracing version of
+	 * preempt_disable() that do not call into scheduler code.
+	 */
+	preempt_disable_notrace();
+	state = raw_cpu_ptr(&kcsan_rand_state);
+	res = prandom_u32_state(state);
+	preempt_enable_no_resched_notrace();
 
-	put_cpu_var(kcsan_rand_state);
 	return (u32)(((u64) res * ep_ro) >> 32);
 }
 
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201117163641.3389352-1-elver%40google.com.
