Return-Path: <kasan-dev+bncBCLI747UVAFRBH6RQ6KQMGQEN2BHTOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 11821544C15
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:33:37 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id 206-20020a6218d7000000b0051893ee2888sf10499003pfy.16
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:33:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654778015; cv=pass;
        d=google.com; s=arc-20160816;
        b=ya94ci2Im3l94KVHcC8G/DKJfu40hUZif0qWwbi2DUJ8NlUjjsmZ12pWERUHq7TQmS
         q87ZNS+c19p/7x6hIEYzsuncffF/dkVKtdJZM6flznW4XUWKQlebEfU6osbP6niPSQYS
         ifvXwbZW5p6arfYei+GQW2I92EgBBW+qttdPF/40ttgHthdSNNc4qaRtD3w5pppsR0Iz
         oV/Zq7I9dmlT1bSCmiLQJx1kEIXklO22hvxtW72YYRu/CnxmPhiHfiQc5YnQ+ATWF4Io
         N2Sxetc1e9qA2UVv2AVmH5nOzqhBxxa6U5l0jJ/Pqc5sj8Scx+2peMX9UZWvA8JwWHqL
         iOzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3wDJA2ABieXk9lOr94ILxLWuXM8hrU9m6daiosn9FRc=;
        b=qmqoqhfQ1jnS1Nm2JoNpW0Ak9bYMItcNkEgAINkQUrqigJvJsEMM0AbBrZHMmqkaE3
         7e0yAeYAbQybG4ZAQyK6GmvgPmsev2vVu0vgwEkBRWisr4vQEYFKrOMwAngi6jqBWOZ0
         KsyAlkKn3m/m00waTSDSvmCNYBg5wRETPwRt0Jz9b/ly9xkbTILoUqlGagolysa/0+BI
         WvOyRfPUIejiUps4R5VQfdoPjW+aP1/TVTp5t8Bx4VwidphRCL5h4V85AmAta8MxHRQl
         +xzz6Z1Jf9efh0j5VJioZFZ3hgGefbzLwHAJrw4ff5DTuTnztNrOaXJQhzWJUqt44yrw
         A0uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=mPLOVvmm;
       spf=pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3wDJA2ABieXk9lOr94ILxLWuXM8hrU9m6daiosn9FRc=;
        b=f/KABOk5IKSlot5lSINJ+TCypLesZdLVOTq2gYbhtjxKQTXEH/GC0RFZk1Hfl0myRV
         TrZFFALp03U3sov4r4yleVR4NVk2vcjGEKdsfZ31RwfMFVy2xnmCfpBggkiGuQAcFZe7
         dz4jp4YgR5itqdUDdlZB+Q9BNk8GEINJ+HOroRzlr/QnkO78KAMBPlqstwnorRTSJRZT
         DWQaavBYh6N/aY7Qx+asDg8GzWUedl/T9TUA1whb9tRGKnW3S4Scarb7XwOedcoox0mm
         WDig5c5l/R3XaalP1yqYKZ6hXBfNGreeJlt5XKheA4dEZyU4qgjMUfQ/c/WJuk1ae9t1
         kufQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3wDJA2ABieXk9lOr94ILxLWuXM8hrU9m6daiosn9FRc=;
        b=EK9G2XVikbA9qqzhJORD13g+Rm80/9E2SPNJ2d8qC4ql5ubvm/XtOk7XCBI1Ws2YcO
         QKer2pEi3n57zI+gGI0okD1+erkXdED9K5K7vs02ju/Y/oakQVq1i9W+O2Tnf4mJdmLS
         g7Oba1YXObxBfojAc1meflp7D+ICB9OcsGU8Ty9US9ykaKwH3FFt7BcXMaXbpEChlrrF
         xVvqnx4sokWz5MWlSLljDQK/7yBZNof/Ml5iL6/F/BuJFl8cO+LRDfvZN8upDYWc4yo6
         MOc+wb6mKrr1+JnSy8GDwTawz3h0M4SbtnsFkksF2rhtgbkD0m7BYHMptM3SaPgm1hu5
         dELQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xgoytDoDxQBUW/MrtEivXu0NC8tpBHmOQDqCEgzNhxu+4yiS0
	+iONtUmzwauu9Gq0ejt3+sA=
X-Google-Smtp-Source: ABdhPJy6s96J6R0j2nPPUkIaP5IrYy3iG1uw6Zvgas7I2o+7/MwqgMA4POrN9zTbK3Mi5dNi3mAkVA==
X-Received: by 2002:a17:902:a413:b0:156:15b:524a with SMTP id p19-20020a170902a41300b00156015b524amr39185298plq.106.1654778015557;
        Thu, 09 Jun 2022 05:33:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6691:0:b0:3fc:826f:4443 with SMTP id b17-20020a656691000000b003fc826f4443ls7247126pgw.8.gmail;
 Thu, 09 Jun 2022 05:33:35 -0700 (PDT)
X-Received: by 2002:a65:6954:0:b0:3ff:b00a:8a53 with SMTP id w20-20020a656954000000b003ffb00a8a53mr3470420pgq.451.1654778014905;
        Thu, 09 Jun 2022 05:33:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654778014; cv=none;
        d=google.com; s=arc-20160816;
        b=X1nDI/fizg0RPHZwBpipbZoJEhH2qJ/NQMgmdO/xYtzCaqybUwGaBMx9XaHtKztZiU
         ZohJXJ3TNMpmnypcfgjo/vs53UO2w0qxUmdh8GC1RIAU3RGK3FrJoCL5UVljorVz8GQX
         jsU+erly5mLWRZzXpUWscgdgldnUGdj3OviLWePu7rqyFhmrAppFM3748p+9fMp0ujJR
         7DC4upH7iD0Aw+3UeOFvcgOq7O6O2CUjyiU+SI56YXmZvFZBMfvveuwXqxQVVnBzX5cB
         NN9aHnjk3PaHLlB3PT5JJsbXlibqo0ZU0/VYIUkK2p10dxgAZeiFuhRW10v3NtjwQo2N
         yU3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZSYQGAKV0NAoJGNwfFuUVE9nqijGNSU8b+ZISJRatmU=;
        b=kIq3l3d7rGxEp438uOPuNV9Li8Xj1rlgPqUeLnpPOrNmEfNXpJPlE8d5tnnyuLupll
         vka+2wFgUmNBwZkwGL68xcbQUcmG8CMtGfLY8ApAmuPonh2v7t2VlH4Be7eZCs7K2T4g
         +wMmZ9RP4Bl1Csa/6lfo4BcI1OEvlsJYnCLsIOWkE+HYHe+uE0M/X7/B6SSwjFwsmaVr
         LRwN1YHrjgxtEoTd2ZpCG9DzTFESGQrs4O7XvONEjoPLwxIoK/AwQrAoJRxTLboMxRRM
         vYBPGcpZ1z8AQ8lPJNgoZTyqHLI/0K8adoS2Fm3OVPmVrnhx3c82yj4rXOTl8WVXrRVd
         zXhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=mPLOVvmm;
       spf=pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id y203-20020a6264d4000000b004e1a39c4e87si966659pfb.0.2022.06.09.05.33.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:33:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 6418260BD6;
	Thu,  9 Jun 2022 12:33:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D437CC34114;
	Thu,  9 Jun 2022 12:33:32 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id b86d10e9 (TLSv1.3:AEAD-AES256-GCM-SHA384:256:NO);
	Thu, 9 Jun 2022 12:33:30 +0000 (UTC)
From: "Jason A. Donenfeld" <Jason@zx2c4.com>
To: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	John Ogness <john.ogness@linutronix.de>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Geert Uytterhoeven <geert+renesas@glider.be>
Subject: [PATCH v2] mm/kfence: select random number before taking raw lock
Date: Thu,  9 Jun 2022 14:33:19 +0200
Message-Id: <20220609123319.17576-1-Jason@zx2c4.com>
In-Reply-To: <CAHmME9rkQDnsTu-8whevtBa_J6aOKT=gQO7kBAxwWrBgKgcyUQ@mail.gmail.com>
References: <CAHmME9rkQDnsTu-8whevtBa_J6aOKT=gQO7kBAxwWrBgKgcyUQ@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=mPLOVvmm;       spf=pass
 (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
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

The RNG uses vanilla spinlocks, not raw spinlocks, so kfence should pick
its random numbers before taking its raw spinlocks. This also has the
nice effect of doing less work inside the lock. It should fix a splat
that Geert saw with CONFIG_PROVE_RAW_LOCK_NESTING:

     dump_backtrace.part.0+0x98/0xc0
     show_stack+0x14/0x28
     dump_stack_lvl+0xac/0xec
     dump_stack+0x14/0x2c
     __lock_acquire+0x388/0x10a0
     lock_acquire+0x190/0x2c0
     _raw_spin_lock_irqsave+0x6c/0x94
     crng_make_state+0x148/0x1e4
     _get_random_bytes.part.0+0x4c/0xe8
     get_random_u32+0x4c/0x140
     __kfence_alloc+0x460/0x5c4
     kmem_cache_alloc_trace+0x194/0x1dc
     __kthread_create_on_node+0x5c/0x1a8
     kthread_create_on_node+0x58/0x7c
     printk_start_kthread.part.0+0x34/0xa8
     printk_activate_kthreads+0x4c/0x54
     do_one_initcall+0xec/0x278
     kernel_init_freeable+0x11c/0x214
     kernel_init+0x24/0x124
     ret_from_fork+0x10/0x20

Cc: John Ogness <john.ogness@linutronix.de>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Reported-by: Geert Uytterhoeven <geert@linux-m68k.org>
Tested-by: Geert Uytterhoeven <geert+renesas@glider.be>
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
Changes v1->v2:
- Make the bools const to help compiler elide branch when possible,
  suggested by Marco.

 mm/kfence/core.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4e7cd4c8e687..4b5e5a3d3a63 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -360,6 +360,9 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	unsigned long flags;
 	struct slab *slab;
 	void *addr;
+	const bool random_right_allocate = prandom_u32_max(2);
+	const bool random_fault = CONFIG_KFENCE_STRESS_TEST_FAULTS &&
+				  !prandom_u32_max(CONFIG_KFENCE_STRESS_TEST_FAULTS);
 
 	/* Try to obtain a free object. */
 	raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
@@ -404,7 +407,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	 * is that the out-of-bounds accesses detected are deterministic for
 	 * such allocations.
 	 */
-	if (prandom_u32_max(2)) {
+	if (random_right_allocate) {
 		/* Allocate on the "right" side, re-calculate address. */
 		meta->addr += PAGE_SIZE - size;
 		meta->addr = ALIGN_DOWN(meta->addr, cache->align);
@@ -444,7 +447,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	if (cache->ctor)
 		cache->ctor(addr);
 
-	if (CONFIG_KFENCE_STRESS_TEST_FAULTS && !prandom_u32_max(CONFIG_KFENCE_STRESS_TEST_FAULTS))
+	if (random_fault)
 		kfence_protect(meta->addr); /* Random "faults" by protecting the object. */
 
 	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCATED]);
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609123319.17576-1-Jason%40zx2c4.com.
