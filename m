Return-Path: <kasan-dev+bncBC7OBJGL2MHBB27K7SEQMGQE2CFOJVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 714B0408A15
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 13:26:36 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id x20-20020a9d6294000000b00519008d828esf7481466otk.19
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 04:26:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631532395; cv=pass;
        d=google.com; s=arc-20160816;
        b=wBfKDYepNi4HMGzxrqciJH+xFnB4wD5AKzwojP5RYM38TYQ/K6Jbjs/7Pr+jeIhTX4
         9el0VYkklzFqWmv7RZAv7AcvfXiubi8cQOldssw8eJF1lSQ3HVnkR98TI4H71zWkpZ+z
         LJEKF5M8s2frqsfDhYKp1HniheJjP3oZBf6p50OgJ1JpUm6LuuqHQNHpg7YZlINOT9Hf
         iKkuBuJEgonPRUtzkdX6jtAj3nensxidVrqUreovYuXjfT/wzAqUopBTOD5qHjRXVUIH
         maKLx+hibLoDWdGBu0A7l4A0QvTpi4Kd+vdAUju6IU4SKv9UGaALmVjcUdA2ufXirSx5
         +HIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=jC6NDV7AjUhoOFalLEJTKtUFWCyFiWhBz9ogChz1WVU=;
        b=Z8WxLVq7BwIilpAILbTgwjuDnGRW+tE1CYEWKzoD3iUfMfRvrY4GFt/arWYTvC5XBI
         1RVSevaLxZDYLWlZ0j+iaRHNYteN6qDwNPS2lZDFd+5qkUXhL/Vw1VhLYPcTiAzAo1XF
         VyHxxi1e7+II3vO/1yLa4h4GfoIoxRT0SA7WWdcbhsrHvrqM2IiDgD9BhLtIcaWiZr3b
         oG6G7HRcl36mQp6T+PmDQGXUpSHtaKbFpCoXIUvuXUH7d2LEOTuXAL6Phf5Ny8wNr3Sx
         2b0gKs/LPdv+tsllcRxeOw1XLvWDErZpJcTbWmX4Dx/VryhSxPakE90JduypdKAXn8dN
         WYKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rfFKZJW7;
       spf=pass (google.com: domain of 3aju_yqukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ajU_YQUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jC6NDV7AjUhoOFalLEJTKtUFWCyFiWhBz9ogChz1WVU=;
        b=kL8B87QYdszp4PurPHfl07vkx0Uqev6U443VkLRIaAVBibfqMkSCMzRSptoLSsrVOO
         gN/y00Skl3dVhEWIRB0TeI4ljQGItv9JyXGPWAUGwpKzt8MdMgmWBe+qqpSfAyhkeP64
         PufMg4BpHuXW/mAaCY3X3jAUcX7TzkTx5a0WQrLX90bPYknPueYwugQCk2KkMhLRn3mk
         xwdFnMEYYJYbm3sE7Rjg+Eh7znGiFX9yPrQSxorzTuTfWKdZBt9X+k0t9oIINph8yDQh
         VelCAJMG5RH3RSsbqMoK2GTsu6gOIFi+LO23uL0gqHLn+qQqCwHhwcwvAabxTtSBmyfR
         aB2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jC6NDV7AjUhoOFalLEJTKtUFWCyFiWhBz9ogChz1WVU=;
        b=O/eXIgf2tCTSiei/jGbtTC+4lBx5xxZMjFl4Et3yawACCitsxPLeJOm221vcWdZZAh
         Y8zqblNECzaq+222up/v7ST7zxNpDta7r+UfyKN9HnHZAgBogrvW4mkAv4CwTAyFQiEL
         gcH2x1LMQFPOWlLkDQllAsVzs6/Lm0n/C+mwokMzJf01e66YprHrMpR4xHCKOWzTNxPt
         rpIchS0Vavq4O9/JyJbgxKXd2IBZ/Bb6+yJj4U33TMpagDdOn6FH9N0jN0QHpnw34p9h
         FNspo+d8VXnG0GUI6s5E7mNeOnXFhU1SetAFisQwhgOSgJwXWj6pm9BEFctRQzjiAZQp
         459g==
X-Gm-Message-State: AOAM532UuHrPMVNilQealCesmsjiKqhJ6jFwaTBT+/Kh2DsvXxP4Ts3Q
	+ig6/C3eLIIDtOY0HXIT9j4=
X-Google-Smtp-Source: ABdhPJykshOvcSrtRYl9BbbbW/MTf6FzCB/EXyksL3GbzgAAdcJ0wMQycJoW8zXPGMonasSqqjU/FQ==
X-Received: by 2002:a05:6808:296:: with SMTP id z22mr7307286oic.99.1631532395363;
        Mon, 13 Sep 2021 04:26:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:c10c:: with SMTP id s12ls430549oop.7.gmail; Mon, 13 Sep
 2021 04:26:35 -0700 (PDT)
X-Received: by 2002:a4a:a40c:: with SMTP id v12mr8611822ool.72.1631532394954;
        Mon, 13 Sep 2021 04:26:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631532394; cv=none;
        d=google.com; s=arc-20160816;
        b=lFuolfs9cxcWnI4jNqysMg077WTS1VJPfjgmSFig5ASvbQ7vPUTn/wz02/jxq/ZGc/
         LZB5Cn/UTWmubMaR8+vPeJFlyAoPTcH3MhHKsuawHEydAMvIV9kLA+CIXUBiHJxiRhP3
         bApPBmqVa4CQdQKzEevgHZmuYvrWHpv3RxsDqcBQiCHB4xmP8FTsUmGS0nA0wRroXhSa
         4uPfGdTPr6rRZC4Zu2hkzt3EBtw0IBiq9876kvqxXT3hbvRR8M9clTLLB1nuhecYHOJX
         gdHtG0zpA32mydu/0InfgUzYmLukrQYmIaynam4CbMRU2EN2Mbo1xKgEUOMQhZsP1oWF
         XbSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9lBuIl0uPI1ZQBCrnGIbYZD+uvnKuUY9gwGZHXFGUeM=;
        b=xSpa5rqC9xM+6Gep2Skor9u0N0AvP/dZTcUBwvon31cfe1Q/M11/NhXjPZOZwQSgCJ
         n0fegdPDT0zMXRO3mBpqkgDiyp29KI4PhYwMW4iEk0cEkZBLnD/oCaKGucxpDbvvjkbk
         wDNi2MYS2ApegOk9kuuh9UO5rnBwBblLcV3U+l3wXFwMXoVKymDuhXqCSdfIepgbyF6y
         qnvi/QXPLb04b6jTDATSwWtmxZbj1NqqatvfglKpuAA0rlVALDqASM5zMQvj8Xzu8P9p
         6OdwWLfXTz02OrWdkJ3OGtmaOY7XwLk4FkHfoHZuUwa57uUQKrgu9x5j1hni9cF79iyt
         MXjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rfFKZJW7;
       spf=pass (google.com: domain of 3aju_yqukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ajU_YQUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id b1si738629ooe.0.2021.09.13.04.26.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 04:26:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aju_yqukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id h186-20020a3785c3000000b00425f37f792aso40635372qkd.22
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 04:26:34 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1f19:d46:38c8:7e48])
 (user=elver job=sendgmr) by 2002:a0c:ffc3:: with SMTP id h3mr1804390qvv.22.1631532394351;
 Mon, 13 Sep 2021 04:26:34 -0700 (PDT)
Date: Mon, 13 Sep 2021 13:26:06 +0200
In-Reply-To: <20210913112609.2651084-1-elver@google.com>
Message-Id: <20210913112609.2651084-4-elver@google.com>
Mime-Version: 1.0
References: <20210913112609.2651084-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH v2 3/6] lib/stackdepot: introduce __stack_depot_save()
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
 header.i=@google.com header.s=20210112 header.b=rfFKZJW7;       spf=pass
 (google.com: domain of 3aju_yqukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ajU_YQUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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

Add __stack_depot_save(), which provides more fine-grained control over
stackdepot's memory allocation behaviour, in case stackdepot runs out of
"stack slabs".

Normally stackdepot uses alloc_pages() in case it runs out of space;
passing can_alloc==false to __stack_depot_save() prohibits this, at the
cost of more likely failure to record a stack trace.

Signed-off-by: Marco Elver <elver@google.com>
Tested-by: Shuah Khan <skhan@linuxfoundation.org>
Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
v2:
* Refer to __stack_depot_save() in comment of stack_depot_save().
---
 include/linux/stackdepot.h |  4 ++++
 lib/stackdepot.c           | 43 ++++++++++++++++++++++++++++++++------
 2 files changed, 41 insertions(+), 6 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 97b36dc53301..b2f7e7c6ba54 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -15,6 +15,10 @@
 
 typedef u32 depot_stack_handle_t;
 
+depot_stack_handle_t __stack_depot_save(unsigned long *entries,
+					unsigned int nr_entries,
+					gfp_t gfp_flags, bool can_alloc);
+
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries, gfp_t gfp_flags);
 
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index c80a9f734253..bda58597e375 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -248,17 +248,28 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 EXPORT_SYMBOL_GPL(stack_depot_fetch);
 
 /**
- * stack_depot_save - Save a stack trace from an array
+ * __stack_depot_save - Save a stack trace from an array
  *
  * @entries:		Pointer to storage array
  * @nr_entries:		Size of the storage array
  * @alloc_flags:	Allocation gfp flags
+ * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
+ *
+ * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
+ * %true, is allowed to replenish the stack slab pool in case no space is left
+ * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
+ * any allocations and will fail if no space is left to store the stack trace.
+ *
+ * Context: Any context, but setting @can_alloc to %false is required if
+ *          alloc_pages() cannot be used from the current context. Currently
+ *          this is the case from contexts where neither %GFP_ATOMIC nor
+ *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
  *
- * Return: The handle of the stack struct stored in depot
+ * Return: The handle of the stack struct stored in depot, 0 on failure.
  */
-depot_stack_handle_t stack_depot_save(unsigned long *entries,
-				      unsigned int nr_entries,
-				      gfp_t alloc_flags)
+depot_stack_handle_t __stack_depot_save(unsigned long *entries,
+					unsigned int nr_entries,
+					gfp_t alloc_flags, bool can_alloc)
 {
 	struct stack_record *found = NULL, **bucket;
 	depot_stack_handle_t retval = 0;
@@ -291,7 +302,7 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 	 * The smp_load_acquire() here pairs with smp_store_release() to
 	 * |next_slab_inited| in depot_alloc_stack() and init_stack_slab().
 	 */
-	if (unlikely(!smp_load_acquire(&next_slab_inited))) {
+	if (unlikely(can_alloc && !smp_load_acquire(&next_slab_inited))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -339,6 +350,26 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 fast_exit:
 	return retval;
 }
+EXPORT_SYMBOL_GPL(__stack_depot_save);
+
+/**
+ * stack_depot_save - Save a stack trace from an array
+ *
+ * @entries:		Pointer to storage array
+ * @nr_entries:		Size of the storage array
+ * @alloc_flags:	Allocation gfp flags
+ *
+ * Context: Contexts where allocations via alloc_pages() are allowed.
+ *          See __stack_depot_save() for more details.
+ *
+ * Return: The handle of the stack struct stored in depot, 0 on failure.
+ */
+depot_stack_handle_t stack_depot_save(unsigned long *entries,
+				      unsigned int nr_entries,
+				      gfp_t alloc_flags)
+{
+	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
+}
 EXPORT_SYMBOL_GPL(stack_depot_save);
 
 static inline int in_irqentry_text(unsigned long ptr)
-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913112609.2651084-4-elver%40google.com.
