Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAFPUX4QKGQEHANNFAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 819C423BA86
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:41:37 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id b16sf11574444lfs.10
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:41:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596544897; cv=pass;
        d=google.com; s=arc-20160816;
        b=nCQTtRRXjNm7qOQ35KV03o2bVogIKiPxIp9U60wVkWRt4cO8owWELmQobgZtv7H9aN
         fy3nl4Il0VaNHO9W8EpQ1Z5TXP4TAm22mP1K54p4I+mQV5OIydBot9H8rwyyoUnpB9Uh
         P7GI6WjcP+RZzcIw30OVr3dT56t65ASz/ef/OAx/C3TfQzgb4g3hs6D4G7C2PPWOblto
         AbqfVvmnnUuk5ieMFCoApzNYFf+PJ/0aduea8hg+qdmKTjm7XUshkPQVi13A+McP1gmm
         1NuYnFRYnSWg3qWRzXwTIx3fcZDmi2KpeoSKvDh4EUbPPNqFl+JiBTk7jIUDkUDkgLsl
         XTUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=eIJxFn44jgd3XgeaIhZMNjE2/Y1crmbI1kOrhjVITXA=;
        b=KjqA1ZTKpgbNziZvT+hpa5OiVvFIX1rsjXPQVmlryLd4Md3fnUyWWEtSQB5BRfsb9e
         0pUZ18D3zOK9GM8WG7KV6N80QqFOKLMUwGD8iK97q1h61KmMzxdFOC5wY6JSdvZwTkUZ
         /f4BD/F5oatbR3I59/y8VRe9mpMK85o3ojDQu5oPVLLFDxR7seOJZdzJZ6JHaiq1b5vv
         FkAjTr17saOwisrGue3QtbCC5kfM43eq1NWIHJS0sNQnhbrbmv45oib+CE+o7X/Fopsm
         r+AtfQp6nYd4G/MA4GkNH7OLgcN4g/LJAdXLDZiw7eZe27eNUQ+y7GjFW7MaAhsAZ2GH
         Wvyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="e/emAKRK";
       spf=pass (google.com: domain of 3f1cpxwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3f1cpXwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eIJxFn44jgd3XgeaIhZMNjE2/Y1crmbI1kOrhjVITXA=;
        b=KvAQ+hhN/ycy5Veg/jgd6IH+6V756YptTB4LREFLvyONQqHY/fc+38LaQ1uRwPB/6w
         gai/8Chm3797tETSvZCbla7m3iS5Cox7upyvjMhODAYHm8F2TPlNOcZ9o8h7qJMCmXSY
         EmQASRldQ4saoezV2L5op9Sg9yI4fmqXiLUeGB9ksYm1CBObV5jhmJ5x5rCccu+Qwdln
         QfIOyustubUYpvJC3pX2vMcr3uOOpoYSek/J06AYn4HF1UXOn8tfQ0Rg/p5g89MmxrlK
         i+gMngxp8D9Ok2pSpOlIctdhyBqEmxU9YcdDiN3UM+SwBWw5paor3MfMv+8rvg9iDcND
         I6WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eIJxFn44jgd3XgeaIhZMNjE2/Y1crmbI1kOrhjVITXA=;
        b=VoTkBBEsHd/kRx0ABS2WgIgVV4sAhEjhvSg+Vd+OIucnN7N9wQhkE530rYr9yGCuZG
         QkJTxZRA5qqhFbfwIzg5cxwEdp0ReJ2Yhtdu+4XZA0tZl7f73SZn0VD4T2uegwPGLzh5
         n5Vg2hoUkScssfXqyKH5Vh1bEbZSJwBjqqFIUHZupK/WxYJpabKqMfFnzR1eGw+V4dau
         i4USmXHRerqEzdZkB/3jeR02UUn+4kfMxuYYnM2RQ0KAFX8L3k2/w6NVD757NwdpUkCr
         M1re8rBoqJo6Aq1zjKeomJlWvH33PfNhqoOHONCywUYlU4YMJSIhMPXDgNMrWpOGl1NS
         R/DQ==
X-Gm-Message-State: AOAM533ov9/v5hvQ7lv8UApwHhEfYhUvyvc8wBri/kPkCISb52L69yov
	iLJds/mV9Dt13AVQsLyxOgA=
X-Google-Smtp-Source: ABdhPJy1Tm09oG/3roDyDltl/FX33ZtHros+DWopxeLK6GKTX4lwoQeNfbelRZftg+WRcXy9eolMxw==
X-Received: by 2002:a05:6512:358c:: with SMTP id m12mr10679567lfr.18.1596544897038;
        Tue, 04 Aug 2020 05:41:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:889a:: with SMTP id k26ls66242lji.1.gmail; Tue, 04 Aug
 2020 05:41:36 -0700 (PDT)
X-Received: by 2002:a2e:900d:: with SMTP id h13mr4844231ljg.426.1596544896466;
        Tue, 04 Aug 2020 05:41:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596544896; cv=none;
        d=google.com; s=arc-20160816;
        b=fLqnlQYM7pZxLQJi78Mf5MANiYglaXH7tLcC3H+lfX1VhbBp6bMWaH/oPM4AA/+rrb
         0X4rrJqhfspxtDk5H01r0sHO8c8TWtjWfYQY36ondKaidfGJb98P+6mnOWNX5looP+X4
         KWcD5lbj+ul2OF97SKfA6DTLkEBZ+z/CEb9XdpgL1YukjP95NqOPlwIqpf4pXpN8MHeU
         CUxBhDNa+5zP36JbexPr1NaKCeMrzGaqPX8SXncD7z7Q34Paglr9Ci/9WHpu15+LOtur
         lUUufqf+COqhCSmgrWIWauxtpsZXVV62jyIdNv+ozP2WuTPGEFiUYfI5c+5Dv01wyXmL
         K6Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=FcKp4QRyFHBBCVHpXykl5mFo5C8EtuBz90+P1+03xoY=;
        b=DDWm1PPcAAqWhIF5AS9tGCbFzYNzoCw1a18GRFPiJ3AR42Hdi1cDy2LpJ+5kwhFI2X
         2kfOhjfqIq4WWtQ62Lu2D9IkU679WzgUphxzDFrCkZ9p1bbJrSFXEshkDPz8X4wQ2TxO
         3SYViAxlyKxW6I+7bk9yulEe0KTgyjAh+tkhnx0ZstFUhuKaN7naTg+lMdaUBP7Ccmj0
         c+RBnmS1YDOnZPaSnL8s5z6Iq5bCcQXf2SZPke4CAtUi0X0Uc5Mdos6B9KMCyvZCzDIY
         r0Vslp16naQwS69EnwXkNFZkMVZQ+0VlbHYppOb7PUtxfXac5Ls7byB6S+N+WlvrbGbY
         wRhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="e/emAKRK";
       spf=pass (google.com: domain of 3f1cpxwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3f1cpXwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id z21si1022762ljn.0.2020.08.04.05.41.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:41:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f1cpxwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id b8so2964661wrr.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:41:36 -0700 (PDT)
X-Received: by 2002:a1c:b443:: with SMTP id d64mr4329306wmf.68.1596544895842;
 Tue, 04 Aug 2020 05:41:35 -0700 (PDT)
Date: Tue,  4 Aug 2020 14:41:24 +0200
In-Reply-To: <cover.1596544734.git.andreyknvl@google.com>
Message-Id: <12d8c678869268dd0884b01271ab592f30792abf.1596544734.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596544734.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v2 1/5] kasan: don't tag stacks allocated with pagealloc
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="e/emAKRK";       spf=pass
 (google.com: domain of 3f1cpxwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3f1cpXwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patch prepares Software Tag-Based KASAN for stack tagging support.

With Tag-Based KASAN when kernel stacks are allocated via pagealloc
(which happens when CONFIG_VMAP_STACK is not enabled), they get tagged.
KASAN instrumentation doesn't expect the sp register to be tagged, and
this leads to false-positive reports.

Fix by resetting the tag of kernel stack pointers after allocation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 kernel/fork.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/kernel/fork.c b/kernel/fork.c
index efc5493203ae..75415f5e647c 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -261,7 +261,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 					     THREAD_SIZE_ORDER);
 
 	if (likely(page)) {
-		tsk->stack = page_address(page);
+		tsk->stack = kasan_reset_tag(page_address(page));
 		return tsk->stack;
 	}
 	return NULL;
@@ -307,6 +307,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk,
 {
 	unsigned long *stack;
 	stack = kmem_cache_alloc_node(thread_stack_cache, THREADINFO_GFP, node);
+	stack = kasan_reset_tag(stack);
 	tsk->stack = stack;
 	return stack;
 }
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/12d8c678869268dd0884b01271ab592f30792abf.1596544734.git.andreyknvl%40google.com.
