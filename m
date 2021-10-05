Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJHA6CFAMGQEZN6QW6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FDAA42240C
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 12:59:50 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 41-20020a17090a0fac00b00195a5a61ab8sf1710763pjz.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 03:59:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431589; cv=pass;
        d=google.com; s=arc-20160816;
        b=yqptAJKW6UX43ZH4iWCwULzD4l+XrrXKfMdkqlGE7uCX6BDNsVl2andEnwWv4MpmGK
         vO3v32l4et1g1DhayGnmPZo1v8Y7pyHkdjynaWiYiI0nXvhj9VQOSLhZ06xVZIYlAZYD
         vCJJN6XpouFalDIqy5i8IAJfftsy2giFP1wnUuMu5d3GtrpjRSrGz+nuZ59ax7nY+swK
         iDoFnSe5X6V7dzrdI8vPiAYaBupO0zkMfYG6EBDVtUBci8IyH0S0MW0NuGTezc6XToAc
         TJvsrjABX7HUbH2BQxTFKwbTV8elGyz7byhg7LmiB8VxAeSw7cU8q7aVtZHE+b7K45EI
         kocQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=CwQk7aPEMh94ikkIV2JKITxBiBUPvtDjzwGZPuBNIgs=;
        b=DcRTSpTUPf98WHuBDnOs6YlBg0XpFNRYxvBOKugczutBqLgUH/Kz//5nStLWgaUcwD
         Er0eW2Sm48YT1GynX8yApC8X6inTJkqjPgow/znYTGHlApkoC65RseSEY1Hzbm9z5SFR
         s/MjUkdc84D7G+TOMLaDPruxYc+9GlXZU3UmggNVgrwUWCyo5KCyPrSCGk15F8al2CBH
         szTfJAC5lr6M3q5SenWvdpIDGsBoDlpwbbj1vLQw9mYlyA9fdNQqip8/2SJmjsucC7BJ
         e6hcI/PsKnKcydOTuOZaNlnokZ1reqn0wP/CHAIl7ONVAZImZdZd10gdU9w/AUptbJz+
         LASA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qOYA0jMM;
       spf=pass (google.com: domain of 3izbcyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3IzBcYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CwQk7aPEMh94ikkIV2JKITxBiBUPvtDjzwGZPuBNIgs=;
        b=O/tIIM7+ZtcDiqKnI00PpnrX68A8IbsxU0328lQfCAVmfQKdf3U8n/5NeB59OIaeHg
         XhILbUflVrpePgOR5YZoY25gukyAWk5KT5iMTtGcw+KADppJNs89LRdSw7wSxVbVJgiU
         hc7sJ1+13pR4XCTU0rl0P7DB7e8klAjQ/3HAOKdnZH50eTCYneYZ8lRLQTSneLQx8H4d
         qQB7aqJyG4fi/8BSejtvvI5P2iRpA3ej9RGaDRKNP4iu5TCF7kjkxeuZKAIsO0xtgaa3
         VeccDCZFz95RafE2/YwjOsW07UvJja8qEbw+uDshGX1mT8J1W2hy+VpvpVQg9NitUiyN
         AXcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CwQk7aPEMh94ikkIV2JKITxBiBUPvtDjzwGZPuBNIgs=;
        b=5I8cKwCjuE9/+X8syM6rWvwBwveGWW4lpMCm6G/cfojnHKJJhaVgekrxUmZYTfQwXn
         6H2ciMTDT6ele+DoVWocRsvrzBXnpwzMB7FUzGldOKnsJKUE3MpWgoiHQu/g5HGrAzc0
         GbvD/6SXIIPhCzNmdR1bsoAuMMJw/g1wNXpeXa2UYt0fHNwaJqWy/l+YgUvShrnsgKUZ
         J7XUQf4aH5d4qBsed0iX1kw4xYIpBDv9ctWu6UpG0OXoiffpBaiJnb4nyosn/MglLkAB
         fWZIYkJVrkkqu7DP4lSWYDjk9bQh8JfhgEFjhiiq8PNcCoHky+ZrbXHhGQn35zbyxEkZ
         sNDw==
X-Gm-Message-State: AOAM53258M8Y0nDLMpT24zJyzdt6yc04l/p3dU1lbPkWDmgapuKdGY0A
	MCrMN+ng9s/sJfR6xUQB+0M=
X-Google-Smtp-Source: ABdhPJwyhgP4rCG1M9i2DVZbRQUZ2jHEsuL9J5fP5oaeVBDjrtUMfVYhzFmYmRLCHpvuZYsDLHSMPg==
X-Received: by 2002:a17:90a:4502:: with SMTP id u2mr652754pjg.186.1633431588930;
        Tue, 05 Oct 2021 03:59:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6252:: with SMTP id q18ls7643817pgv.0.gmail; Tue, 05 Oct
 2021 03:59:48 -0700 (PDT)
X-Received: by 2002:a65:44c5:: with SMTP id g5mr15294151pgs.39.1633431588347;
        Tue, 05 Oct 2021 03:59:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431588; cv=none;
        d=google.com; s=arc-20160816;
        b=0L3PSXP8ieSuzv2pK/OL2BjgsSwbk18W7nfxziSnX9S3iilGPMz8R+jAP8e58w7AFm
         YLsK+Ck5ruyxSNBif1pz+aWeKJaSE1NWA0XiQQePiglWSU8PVESWwEzytN1uPyHEQ1wB
         hTUzgePKOKSFg1BZGEy75u4Lf1YPM0e9S6+X7qcKoveDJcQx5S9Q0d1PGqACnxAVHo2j
         IT0DUi6aGq7ZslwdaIESxpAZ0OyMbqHna1lR3Hg2Y/908/EnVKw57KF24d5ax78oR1fa
         18EUdk4PzHbSIxvgZHEchfKBCTuuSTYxFhd6JI8MBDqGp+9MYWMT4NcsFGL5GIpOIwYH
         M1Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=o6tCUIHZ5VDO2w0cRCfWBwR+yqfihIBzxgT5IEbFQNw=;
        b=g4QqaSKBHY+6rwegcbKXG5bDXmPkb0e9YuO9z9zYvx7WLCPgmQPJBo63OVOlzUW6vc
         jL6NEVQsy02Yp+PK9yOGdVw7vIxaxwdKAD9qwb93SnUByrRPA5RT5Z5urX6y7ex8+qqn
         K9jlyHfps/MGDyoZE7x4HhCbuCsY2cpOiYnFX/MXdNmJRDuS9Er+4wqT/ROB9s1WESuI
         6fUCo5JHTj4lYjbjh/9lR9aM729EX6Bg1uwk7EwAyhjqlVAQUF9o3v4rj50cn41zawa7
         +OtPw/iofsi7wyKnuUF16Lb/lcc8MoBQ/mBbsX6cD8liY43+jx4YH5N3KdZdyQbRsJ0t
         QWbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qOYA0jMM;
       spf=pass (google.com: domain of 3izbcyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3IzBcYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id w20si1200111plq.2.2021.10.05.03.59.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 03:59:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3izbcyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id t9-20020a05622a180900b002a71f83a1cdso11334895qtc.17
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 03:59:48 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6214:c1:: with SMTP id
 f1mr7500180qvs.9.1633431587608; Tue, 05 Oct 2021 03:59:47 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:44 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-3-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 02/23] kcsan: Remove redundant zero-initialization
 of globals
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=qOYA0jMM;       spf=pass
 (google.com: domain of 3izbcyqukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3IzBcYQUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-3-elver%40google.com.
