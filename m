Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HK7SEQMGQEA4R5KSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DDC6408A13
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 13:26:34 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id x7-20020a4aea07000000b0028b880a3cd3sf7445256ood.15
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 04:26:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631532393; cv=pass;
        d=google.com; s=arc-20160816;
        b=DuecOzCo2J8FmcVCOApiC0KJHM+imWB1wBJuW1tQuzYEH1JQGnPz6bMQjG6/7Z4eow
         06OZjqcDE7piVIRfE3v/GDRYgGPya96oEItJRmBldXEPUo2JEVXrKgYeYXpQfBnFWxCi
         ARr5Ze+dqUQeeEwHgNNPw8lV0+Y3gfJm7VvZnQA+AFDi4IA69tl9Z4XPsyxAcaThMJxS
         UI0s+MXR4nuJsISlTnP+IJmaTZVqSdvT1tWOfjs79XzYF0W9gJNmngQLmgBwEWYQj3nJ
         47A7LbtBZUWU4hF4SpWfH4K6Lv4dStHolt/vDGixXMBas5QvVqEd0GDczPbXoSk5e66/
         Ubzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=/jKa/ZSsIH444DYkTl3jHGjhx9hwDSGC+DI+4EwoTQU=;
        b=vgxy3coCtqNxczwAOi/T5ySiDW1vagaz0CyxAX/qpjmIrXDnZNGoUw7DSUV+AIV5lW
         nadPKgqoC6Xpzuq4x4X3LHPXt3QGysCJ5gkwnVvtRegvpu6BPCNIlZHC5gl57UI8wDiq
         mx/lJy2q8y/PWl05BZb+GKUUd1HJoMNpECJHHZyYUUuk5dA1ddIotFSCaQE27srQtLYB
         leWwMjmDU2HJCvABjVYb5XgUttb+2BoCpM6d+qDDnLHh1B6b2ByhbHIN1lfg4MO3n18j
         uPLEfg39OtUra76ukbKTllFD0t0A5L2zMwAKGlXViBBdnrkWOEx2tEWH1V8UJfGzcEhC
         zvPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=i2hbw8Fe;
       spf=pass (google.com: domain of 3zzu_yqukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ZzU_YQUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/jKa/ZSsIH444DYkTl3jHGjhx9hwDSGC+DI+4EwoTQU=;
        b=nHYJesFdNWNW4Lwpu3Dc1nbGvFg3zQ7ShOawNaHo9iaR8yKy3/Pf/t3Dp5Cww4+L2K
         1hw19+Du9fgtstpBRv3KsW8QN54Iom9rt9b8jarLbjz/Qjpd1VpzWY2p7/SsjYo552/Y
         pakgJfLwoO7Y84zmBQDuUvWtRwAqpqyT/kwkF6VEWqKGt3lbEmbRovVJDsKpAWDybRCk
         dJ8p4LGubuNAYmlO0EUg0EWeGQGcqGqr25k+TT3s4ouBO8v8l4HBD+YHwq/3s9bUKHbh
         xlQ9go2jhbDpZ51nccZUPbkSuMeIsErVsx7FUtU3GyNUXr4ZGVrA07UsfceMpsgOxwWX
         TOjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/jKa/ZSsIH444DYkTl3jHGjhx9hwDSGC+DI+4EwoTQU=;
        b=EvtdVgu+KZSiQT0e3rMxGz6Ae8oYqdP3fEoniNMQGbdJSSKM5RVWJiPoiPn8zt7A0d
         5PalXmeIvDNlXko5eQtq4jt94Btzf0Ml7397Exb7QiBO27RZsGJMpp0TSaKtA5qK3ALH
         pA52OgWMq9YZFfPOzFCyTrJyTmtD0KSo/i7xeFL5CwswfAcn/kKC59c+d36xaEFt04z2
         ZRLr2PA7XbKl/MyCTFEsnoktP2WrlhhsAtPQR8dw9syhXYhZpaUcz9t0k+59mga2iVLT
         4WeJXoKuhNiDKs/P2/l15d8TT7bhu7/b7Msemmm1jnMVF2jGlqeOfQ06wz5NSth8Ot1n
         /RCw==
X-Gm-Message-State: AOAM531TvCCaKI1Qz5I6psUO9kIMhqHkaFYCvCz4j97w97jpwWEHE+OS
	3xNwzeVAndwOHTzVpCf4MoE=
X-Google-Smtp-Source: ABdhPJwb7NBWP7L7zopt275oTBMakd+3jo1E7ivo9BS4q7pb6rInBhi74AiEKX7KSkWCWzhL29m52g==
X-Received: by 2002:a05:6808:1918:: with SMTP id bf24mr7334816oib.50.1631532392967;
        Mon, 13 Sep 2021 04:26:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1e87:: with SMTP id n7ls1744795otr.4.gmail; Mon, 13
 Sep 2021 04:26:32 -0700 (PDT)
X-Received: by 2002:a9d:705d:: with SMTP id x29mr9198169otj.260.1631532392445;
        Mon, 13 Sep 2021 04:26:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631532392; cv=none;
        d=google.com; s=arc-20160816;
        b=HHq3yYi1gjKSGuYYEYMjmg7Xb4vyucdszpfDL3B9hVM4xE6Rzh8k9uOwkWk5BaFrYI
         Xqm2oJgg8ZDd2Rlmnaj2MNJ8bFZ2N32C6qGuX4hdamOyPrsne877ikvsCrTkoR+NI7h2
         HoltXlnwjS/Rkt+k16FVd9DEUAHeb89GJg6fqdEy316dmbo/wfTwFafTcN3Mfwrpw5p2
         Eblorx2PXDWxszDI+e+49yeDJI5CCYMzW8gBwiFauAkrQOKGO+AWk7pSZsM2SwznIQzl
         kzMaOVjmLra6AqcgcOGyD95r8KhbgMrV9OeKysKRd46PFsJ4i0GZytJmeFyYQV4EbdK4
         oQzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=heQI9hJRYZNN0F3wqdwBsNM0iszmJ1+UNOx43ei/BCA=;
        b=baroxfnxs9eNENH2dg6dp0yU6dVtcTCZilmHMqTHjfiGRcEsf5/D8Nrd+nxp1VLukS
         B2z+CtGiBoG1jwpDNKUmXA0dE/QgAEskyAtculC/MKHxBORfVQmJqfefsKBDrr0+p200
         ZppHMPH/nf5e3f0cmKiLExVJAMWM1PBLwEayCDjcIIjEt50PWr60I493wy0zo5723XLl
         9OqTOovMkSlBdv/HHz5ykwZGw/OZJZiIBT+LDhU5oLJtA+9Mjh/bDcfQrh4sLc46n4uh
         mXjAhsAvXMam6dUJiEVEeDSxybM9JCSDb6AP4j44HCTtXSMzBvVTk+dVJlnepMuaNrNe
         FKOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=i2hbw8Fe;
       spf=pass (google.com: domain of 3zzu_yqukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ZzU_YQUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id v21si510823oto.0.2021.09.13.04.26.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 04:26:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zzu_yqukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id c22-20020ac80096000000b0029f6809300eso54865169qtg.6
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 04:26:32 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1f19:d46:38c8:7e48])
 (user=elver job=sendgmr) by 2002:a05:6214:250f:: with SMTP id
 gf15mr10095078qvb.2.1631532391965; Mon, 13 Sep 2021 04:26:31 -0700 (PDT)
Date: Mon, 13 Sep 2021 13:26:05 +0200
In-Reply-To: <20210913112609.2651084-1-elver@google.com>
Message-Id: <20210913112609.2651084-3-elver@google.com>
Mime-Version: 1.0
References: <20210913112609.2651084-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH v2 2/6] lib/stackdepot: remove unused function argument
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=i2hbw8Fe;       spf=pass
 (google.com: domain of 3zzu_yqukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ZzU_YQUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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

alloc_flags in depot_alloc_stack() is no longer used; remove it.

Signed-off-by: Marco Elver <elver@google.com>
Tested-by: Shuah Khan <skhan@linuxfoundation.org>
Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 lib/stackdepot.c | 9 ++++-----
 1 file changed, 4 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0a2e417f83cb..c80a9f734253 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -102,8 +102,8 @@ static bool init_stack_slab(void **prealloc)
 }
 
 /* Allocation of a new stack in raw storage */
-static struct stack_record *depot_alloc_stack(unsigned long *entries, int size,
-		u32 hash, void **prealloc, gfp_t alloc_flags)
+static struct stack_record *
+depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
 	size_t required_size = struct_size(stack, entries, size);
@@ -309,9 +309,8 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
-		struct stack_record *new =
-			depot_alloc_stack(entries, nr_entries,
-					  hash, &prealloc, alloc_flags);
+		struct stack_record *new = depot_alloc_stack(entries, nr_entries, hash, &prealloc);
+
 		if (new) {
 			new->next = *bucket;
 			/*
-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913112609.2651084-3-elver%40google.com.
