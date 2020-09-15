Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTX7QL5QKGQEGIHMNXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6014526A62E
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:19 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id li24sf1276288ejb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176079; cv=pass;
        d=google.com; s=arc-20160816;
        b=F2SAdE05sp9xDHK0gmwxC7FO55g1IKfHddZtf1p0V8SphXUmY9dTm2Gni3Dj1+mHTF
         2eCwaAXGNBvI/amI1gYPydoPWRb2nEmIIWPFRyZ2QPzEFRUEiDhBa0oOv6dN3C3AIckQ
         dohHlvJGQeAoE8SU33bE7NdwktDR3O4Uq6ReIukxeh9D+kd1oOYg+ov+MVdF8j59qWcl
         f5GVhtHlZx3OqTgep2sFgfhK8qrLv/AgXhWeQVRGARp8Zuav6ln3wRYBpQqCksFxyx4m
         ZotfL0wWFB/O4VEULmFdyaPILjTzY2BwB8HQ2BUx/76mTJhF57gPfQSQWpbzuA1udu+t
         QxOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=D27jDUeZmK3DIV8blZAUbfk2P2oTy91Lm7gLwEdxqxA=;
        b=z/odMh2xEpQw181doZ3St0V5M5cC1QQXccXGINTBXlpqafhDuWBbc0gMEnxye+EoGo
         GcgLcWZhJjslAEML2WJ9B8cEPcjb0knJaUNe2frxonpzu+ZuwEfEQmaPdH/swjPh3Vru
         Vg/rdGkKcjF1RQrAIgWmJs+FCaYJA2HXdSngmT1tkDikH+lpq00D1uw7LG8HGnou2QgJ
         0IhCKjJoNS8kBCP3Ujy8okIVeAzmbbm8gynO0O7h5RADwNjuHT6+x1gfSSYIsM6oSC4g
         pwMfYz+Xy92rkaEqEQcvjzi/5JxJgI9ZRoBwVu56l9HS7DiEdNH0ik8caSj/1CaR/uKo
         /zIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iMvsBbNh;
       spf=pass (google.com: domain of 3zb9gxwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zb9gXwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=D27jDUeZmK3DIV8blZAUbfk2P2oTy91Lm7gLwEdxqxA=;
        b=de7ELTqU4+Q/sVDHPHbry/4sgYbz3CcN41QBcPXzzPUI7NVdfM02j+Thyvgdv0LSt1
         ZX/rhyindvcwxZQffPHFU4mIVYzsLXxuRxHcd+zS54WNW/3rYLpFQYt16QxX27BMPNP3
         oFFF55K28xrZoDwYtTxm/Cf6e61sHdwVKCFl3wgm/hEs18z5x+Q0b6iLImWynAMUiaNa
         8er3TWowy60zYkRw+Pcd8F76CN622MRE6MaEt6B4ZDdaGB+LZ7/6PPO6lC1qaYbcEFVW
         ZvtlXCYg+LM1o8lMocHwnT3jP63jrIgOVrKykRJlZRqN//UVSihG7wVrqRsFUkMMW80g
         cBJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D27jDUeZmK3DIV8blZAUbfk2P2oTy91Lm7gLwEdxqxA=;
        b=lLoA41zbMdPY2+jIafOb2WsNYYskWum+0K9H9dH5j05P6moiVSE4H1E18gvzxm2tgN
         MkWZPGhPk2aZ9VoPfWh1faXHQrOLOjsk7ebn4b0eH2SON8/bO8gD5X9mmnuhPQh/f8ju
         pT5UQHTYOHFBwb4WzBdRCMXgOviWN0sSy9ygHxd/MkOxQ5bspwJcgm0t5pR5or2zg82J
         5SHD1W7pmt8+zSOn0lLuQisfdREaSbesmYWvCdNGOU7/1v0ZzsgWb3ThmETYUjc7Izs/
         ktJ1c3lAob+jvbvpRrYVHvRRwDxgtDIgXoaMnwl4maugPU7cdIHdoJiEPvWAvSmLCMqo
         /d3Q==
X-Gm-Message-State: AOAM533fJoyVkeuKZwDm/eKn0yXmmej4Sd0zpQCPOpAMyydSZSfcYm5+
	Yd/drMKjjA1NwU6zm9rWHmw=
X-Google-Smtp-Source: ABdhPJwHdOPSj+Nhoras0WnOk9uOBsJDCF6YlF2hLANXoP35tiYjfa+dvUq1XXG9lZKX0Y0N9rU69w==
X-Received: by 2002:aa7:d4d4:: with SMTP id t20mr12839079edr.229.1600176079163;
        Tue, 15 Sep 2020 06:21:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bc05:: with SMTP id j5ls2968475edh.0.gmail; Tue, 15 Sep
 2020 06:21:18 -0700 (PDT)
X-Received: by 2002:aa7:d68c:: with SMTP id d12mr22789548edr.274.1600176078066;
        Tue, 15 Sep 2020 06:21:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176078; cv=none;
        d=google.com; s=arc-20160816;
        b=eFPZEjn7XOxt/hWAK/2ErFRvCxfPZ4POpfOH1rQWda4SosVc4z8nmSWnFG6rhbM+D6
         MdfqemBL3TPAbe22iHg8S/e4R9fy/2fSNpqFtfRwKEofmhodOZr3R2/96dyl3ik9mkUV
         1nkW6jSifbqWZR8P2TBvQIf1QhpjXAlK6RTgOxDEiXJYDsnQPSzEk3kEbA7i66J1FpfX
         co7sVIWWeAJ7MriLvrQMlt/SDnlZZ3pid+6gDq17mOp+v3ubLXCPUuHyY/bF8FnK2Xvs
         qwbxRZgAmpkJwgTxZx8eDErIgXh//oNdOH2SLOsAAWe6bp3/UXPbGFZfSfkPn23eLqSD
         FSDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=a8meNz/QEeXxbn8b6t9gmGleu286u2hc+BNFU326RBY=;
        b=MXKjBfQF8YA+gXx4ptzBfVCezpGQ1zjIyN2E5LQX+J0QyZKMuMd5JTZ1eyIAYII5yU
         zl70ePIazwddKCuB0amM6XM13LhQlsnics7UBpcCvxFVA34UpBpUpUueotevIFNtHCMI
         LR4nm9V6zW1F1R79g6WlsjXW9LqSfApo+BPrL68PdMwfTOqHZy7E0x3btGh2f05u8I2T
         l0NobdVUFhZWO5U8LLnEDXkSBs95Bl04xJ/oWhKvLMFvfypWfzp82N16xExoCUa1YlQj
         vn34Ei9Sgu4QNcGJDcFoljxL/2EMxNKdh6Xz1PLJSMB0o1de8uCY5YBJKLJ18C5dQoBJ
         iqQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iMvsBbNh;
       spf=pass (google.com: domain of 3zb9gxwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zb9gXwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id r5si370384eda.1.2020.09.15.06.21.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:21:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zb9gxwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id p20so1173896wmg.0
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:21:18 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c749:: with SMTP id w9mr4491690wmk.29.1600176077770;
 Tue, 15 Sep 2020 06:21:17 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:44 +0200
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
Message-Id: <20200915132046.3332537-9-elver@google.com>
Mime-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 08/10] kfence, lockdep: make KFENCE compatible with lockdep
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com, 
	keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org, 
	peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, vbabka@suse.cz, 
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iMvsBbNh;       spf=pass
 (google.com: domain of 3zb9gxwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zb9gXwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

Lockdep checks that dynamic key registration is only performed on keys
that are not static objects. With KFENCE, it is possible that such a
dynamically allocated key is a KFENCE object which may, however, be
allocated from a static memory pool (if HAVE_ARCH_KFENCE_STATIC_POOL).

Therefore, ignore KFENCE-allocated objects in static_obj().

Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/locking/lockdep.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 54b74fabf40c..0cf5d5ecbd31 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -38,6 +38,7 @@
 #include <linux/seq_file.h>
 #include <linux/spinlock.h>
 #include <linux/kallsyms.h>
+#include <linux/kfence.h>
 #include <linux/interrupt.h>
 #include <linux/stacktrace.h>
 #include <linux/debug_locks.h>
@@ -755,6 +756,13 @@ static int static_obj(const void *obj)
 	if (arch_is_kernel_initmem_freed(addr))
 		return 0;
 
+	/*
+	 * KFENCE objects may be allocated from a static memory pool, but are
+	 * not actually static objects.
+	 */
+	if (is_kfence_address(obj))
+		return 0;
+
 	/*
 	 * static variable?
 	 */
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-9-elver%40google.com.
