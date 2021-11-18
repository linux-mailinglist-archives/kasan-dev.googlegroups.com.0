Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFUV3CGAMGQE2BTK4QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 02603455654
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:03 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id b133-20020a1c808b000000b0032cdd691994sf3994931wmd.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223062; cv=pass;
        d=google.com; s=arc-20160816;
        b=aebgcFKktTC6zYDH6GnylgMwpFhpqA2SIrqYXsi1iqOBU055TXnafb+siqFd/X6HJS
         mQiQVXzdtbRP3jbO9crWAokweYRXjpZHJ99feFDz/7YaqlfYMy/o0fnu+/qePx6V76gt
         8GRpcn0rz3SueZY8H+5box1DHnkFQ7CeamXKG0akTwhwItAjkbxBGkJxmUDypnJySEMa
         UADO1kA9eijNjWLyzsW0OrGqb9CkMDRQ1PCRCTJdXhf1MAfunP5FGHiiL5FyuiK/xiUt
         YIKncfpkz+wnsJ9PDr14K7T3jxotmcIx3Ct8kRQyR69obiu1E9WqCYUhU7BiJ7y05dEI
         33HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ciRopITJDbKuVCevYNRtUhAw0gK9FhWOXoVw9He+7fA=;
        b=pWoMYgopJo0RY7FN/wBLNoCR95YbOL2YGcb21eCImqUPjF7cS+uK02SAf1n5ro2DmX
         3hRw2sMF0koddFezvt4KIBUKOveJ5suICeBrQsgF2U9assMcaz/5GSNjq3l8mfd/uD9L
         pokeBc3PNnpkOBpeecKNtAgw5B7jJdn8BuOjXDbHTqBPHp4ZBzThFtWS0gpFaw8Lj3h4
         L2HWDesHEITqD5h/EB4Pt6veG6Xjq1e+KGIbgWoi6kJM0nauSSLUHdzA2WrILzvjL7yj
         TPqhGZN9wbZhzhHnU4T5Uxads+yS7Vt0D47nK+nVM76wECOUjdRI3hPyqb/EPVOzdudc
         d9fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D3oVfd2Y;
       spf=pass (google.com: domain of 3lqqwyqukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3lQqWYQUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ciRopITJDbKuVCevYNRtUhAw0gK9FhWOXoVw9He+7fA=;
        b=Yd4pMo34Qz8YjbJL85uayH0qBXHHZcpUjSvZZPBpopb252Edu7xB2BfO6+ziD1ivg+
         rNor2ykVLgZnu6gowBJoeVcfjYgJdtOcN2PKzqShizXO8cla9OXQ8zTJ2BcuOH6b6QrG
         xm/gV6Ec+GauHFFc3lrxP/vHZwC+/Q3/8y4XkCEAjKLkqe1C6GFa3b7cP0zQ0q+pb4Cj
         vA0UgFGcX0pJnIqJ8pVv4FCRJEf6ulOq9ppsmbWVVum6IDW3zJlIg0HxrYGEdya9Vwda
         kOPt3GKd5laPBfBzE+f4U+804CNAC6Zf3jYXlKI4/DGj3ypEl9lQiUlVB5IFvKKd7vaL
         GhqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ciRopITJDbKuVCevYNRtUhAw0gK9FhWOXoVw9He+7fA=;
        b=lmKLdgYVTG30kwbYIkQyQhdzeKF8PbVHCk2Pk1M9NMY3/Twk0L5qPFwdvymKuKwNOA
         ar7Id+wTBp2KlZALNtYmQYeiSanBXudtDtFAK7l8PjAOSr3zvDpL76B+tpEiW5WPOenF
         g5TC2WAmD3eRJrZrBaD+XPx6i6pz1Mb+KFt52ac5puvj4KhrdRw7OtGVP3wA4FBohgFV
         uKCGWv6sHSdcgbB94BqlhrgZksuG2oxuvTBPWmwXOGMSYZbc1tzidHkKyDP404cadMeW
         Be34ifSodtcwP690X8rpnuMVMaLsjHuEEBYmftPNKPDnl8g4bu0jdoYW6qkcSReVl+g0
         WQ0g==
X-Gm-Message-State: AOAM530Vls2IPgrlY/89cZ2By8rq3V/ercMjW8XQ75pAzl57MWQLV9QC
	tXJ4SfcNmbKK6sqit4vL0sQ=
X-Google-Smtp-Source: ABdhPJzWNFocXlE4iF949EdwahmT3vxyl6YDNUkItEJy25bAl8tft8d/YxckUc1AwGQFyaNyvGLY6g==
X-Received: by 2002:a05:600c:34c2:: with SMTP id d2mr7926605wmq.102.1637223062802;
        Thu, 18 Nov 2021 00:11:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ad6:: with SMTP id c22ls4709333wmr.1.canary-gmail;
 Thu, 18 Nov 2021 00:11:01 -0800 (PST)
X-Received: by 2002:a7b:c92e:: with SMTP id h14mr7744804wml.135.1637223061871;
        Thu, 18 Nov 2021 00:11:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223061; cv=none;
        d=google.com; s=arc-20160816;
        b=brs1k1m6La92tnkS8UprMHzwBy2mKegLarcpixGNab3tcMcKsWlAfTbsV+4FrFSvMG
         fPPQlYtUNldWdgrf/hP4qZDB/foZIbSvnFZzapXN9cB+bbDcrO+Y88A5WmY+m6vepEgo
         xlgTnM+kZYDt9xy1bvV01J/3tZwo64ShegnGsY7ve5TLy0o686m/Et2CCypCVGWaPKvP
         ijlT4FglTlyM4PsWYZ1ZzeYvkh8Wbbf+UDYCupd1+25ooq4GuuNvZldSuL3oSe+39Di4
         iCMAUieaiqkpAgcYJIopa+C1SS26yIHRLprYOHK9hfLjVWKDo2mIqzSeaHdsGHvpxdZ4
         4rQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=tuhyQwzlfQERbV6yctXDUlEPG1hDRNoinPlUWTt5/uo=;
        b=gNWcpjSbl2rnLN+rIpNMe1DUX2Yx4R38i3n58XKjFPX7ebIJfhkj06BVuhIWWoyYGF
         4KEDNrCEHdzTtOcwHG/TQz4LB0oLCyPYGMnKKikin7JTEG2AxmEj1bsWk+AeAAmYhyqR
         Qy/9fYQgh3lFunpWAjuhgHFn9wzbAGtmLhcB74+3AmaT99saAT6VPzPj1zkEeCK4bGYG
         z8WQoYaZqB+Ctf/c5ALRi8RRtZVe+K06OoJbRws2oyW8xHeanp4Dbhms5V0e2M+JI1RE
         0jN2CK4hJ27WAAG9lN8UGtoefzAmxAIyvT4Dw9Eyt1fWht/jcKUMouN+Gs22UZBQAz1O
         l7mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D3oVfd2Y;
       spf=pass (google.com: domain of 3lqqwyqukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3lQqWYQUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 125si574941wmc.1.2021.11.18.00.11.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lqqwyqukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id l6-20020a05600c4f0600b0033321934a39so2706586wmq.9
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:01 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a5d:452b:: with SMTP id j11mr28008131wra.432.1637223061543;
 Thu, 18 Nov 2021 00:11:01 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:06 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-3-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 02/23] kcsan: Remove redundant zero-initialization of globals
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=D3oVfd2Y;       spf=pass
 (google.com: domain of 3lqqwyqukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3lQqWYQUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

They are implicitly zero-initialized, remove explicit initialization.
It keeps the upcoming additions to kcsan_ctx consistent with the rest.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 init/init_task.c    | 9 +--------
 kernel/kcsan/core.c | 5 -----
 2 files changed, 1 insertion(+), 13 deletions(-)

diff --git a/init/init_task.c b/init/init_task.c
index 2d024066e27b..61700365ce58 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -181,14 +181,7 @@ struct task_struct init_task
 	.kasan_depth	= 1,
 #endif
 #ifdef CONFIG_KCSAN
-	.kcsan_ctx = {
-		.disable_count		= 0,
-		.atomic_next		= 0,
-		.atomic_nest_count	= 0,
-		.in_flat_atomic		= false,
-		.access_mask		= 0,
-		.scoped_accesses	= {LIST_POISON1, NULL},
-	},
+	.kcsan_ctx = { .scoped_accesses = {LIST_POISON1, NULL} },
 #endif
 #ifdef CONFIG_TRACE_IRQFLAGS
 	.softirqs_enabled = 1,
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 6bfd3040f46b..e34a1710b7bc 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -44,11 +44,6 @@ bool kcsan_enabled;
 
 /* Per-CPU kcsan_ctx for interrupts */
 static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
-	.disable_count		= 0,
-	.atomic_next		= 0,
-	.atomic_nest_count	= 0,
-	.in_flat_atomic		= false,
-	.access_mask		= 0,
 	.scoped_accesses	= {LIST_POISON1, NULL},
 };
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-3-elver%40google.com.
