Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRUCZ26AMGQEGQLGLYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AEEF6A1B518
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 13:02:16 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-5412ceadaa3sf1021027e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 04:02:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737720135; cv=pass;
        d=google.com; s=arc-20240605;
        b=R04e1KRL9Osl60q8pND7w2W4N/sFeBQ9oADY5rIlREM39nq933JQkTqqi2fj8WU4Cp
         vUAcrQdXChDEfXM/zW6vAxfU7iXBkTSFIGSDGiNvOQ9JEIdULmYG/1daS72Jtp9VbxiY
         v7RIUaIyYqCVgkuqFGYHWeJKXmir+7UrP0ZDpx+gYjjJQtOh39PQpL2KoFYKR4THwlOe
         hD8jLTbKV2qZyAHl0J91vstytT/7VncZndjPnMwqsJ1G7y6xTSsZ6AoEzdZZ8mAiZHij
         YsLhvxbH+XkVYIe4cwVaZjex3eB9ggkIwqJo9Ib4ALFIH/YL12IwsKSbqfyobyaCmvyG
         Qrzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=52sTxafG+AWNLNd8Wozcdu+mpuYMjvEzubr9/ZF9xzI=;
        fh=MM4hrOWP8chyrOZIqUCrso7IXea97cOsEC9m5rPxqF8=;
        b=Gej811XGrLNOproGAxo/wpstr4XSbzJ4Dsif1WtcsqaK3iMySgBjwRyPgttGvNbYB+
         9QxyqYLVld24iEJbhMNR/w3zzRfFWclZwv24aOZKzUwRsnY1JhaoVo55Mj/oJDYrJ9ZS
         PPdPO8be2tC1UCKnmIbEChoN62UtaWavDpfeH+CO9B0vuQfbLzQ4R2rdV02DF92TEWfz
         NztuRaxkMf8abyovXT6eE31Wy4GcYx49FF5AspxTp4rEqMxoQBkXfnBi1ClYHkvvoPNI
         l0SkNruFCTxubizBYwPxIIBhWlE/+ej3R6+2H+8zD7d08G2OmtCq4ivvCKviWVIRV2zx
         0ecA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h1sWEfj5;
       spf=pass (google.com: domain of 3qogtzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QoGTZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737720135; x=1738324935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=52sTxafG+AWNLNd8Wozcdu+mpuYMjvEzubr9/ZF9xzI=;
        b=tZ5hAh8r+XuRb5CI3pagH0voZvb1x7NbLUKlRXaJbyfVRDo62xtM4O9A7+10MyR3Ub
         xaeYeUcxOAXwQJBNZ9KEDwraHKzucZdAi91iQHPIML2AIpN75Z3Wi/qbCWLBcacpJ3pk
         7Eov0E8WgiLzEo4vYXx6ENDtRd4M5LX7v2Hg2G9uhCd9LeJSZCZPe5orZ3+8dKBeE/hU
         c4pwe3k78nGOaeRGxwFXTAPbkeYOfsOC35yPr4fRdY2h0sddnxEdfqtdYWGbwYcYrxMw
         boyGIgmel3/OJORWV7ors4bQVs+nSpKj7Bhch6JvNsUw7pwnx5O0FZj44M9nI4TfsH0u
         otkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737720135; x=1738324935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=52sTxafG+AWNLNd8Wozcdu+mpuYMjvEzubr9/ZF9xzI=;
        b=eA6HXJimXoftytprd7QhhN6Z5vtKfT9G5RYa/Z+97BbLrV4JhXgoEOZZkVMEsPIOs/
         /sBexeDyvxTloMejQFwzfyRbEIHX8gg6dmC/ddLqdAosNh+fdFnGuxTqV/CWhsbBrJA6
         OdjWdbpbERUjHVfIoaxfe+z+y8QkGVFBxmcshW2OK3HFfjp62458JvN4Y89kVxxyO+Fz
         IONDmZ0INGTx4EwT4uq1NTefFYO2d+t08cfU2QZdmuP+I9ipSdRmuk7VpCtopND/10R4
         xBB5+cNGv04V+iShS3ejVEYeGEvEjYz+Kmt01PHeQTwRSQmyEH2d5+3kUfdUrl7VpSln
         aUjQ==
X-Forwarded-Encrypted: i=2; AJvYcCWI+nDT0qyK7VTVuFrX2cy+SkTHWQbPysk+WMKCVuc0bbBwxK93A/35Hec5Mw3UiUhb6dELvA==@lfdr.de
X-Gm-Message-State: AOJu0Yw2NbxcUAsbMcKK5uELr7717PX4pXoBsSOh7+6bfAcb0UTU63CX
	pJYrq8E+6DDsUxC4ehw6SVfOLx/3O0Yy6u1tRTIh4o6Ls7lOf1RD
X-Google-Smtp-Source: AGHT+IEx4CkDUGD/9R8tDWe7fBrgUppt216uXTZebJHXEzh745vd9wa0tBtQFHyaA6B08f20Wo0XeA==
X-Received: by 2002:ac2:5de4:0:b0:542:2990:5d61 with SMTP id 2adb3069b0e04-5439c2539a3mr7491350e87.25.1737720134751;
        Fri, 24 Jan 2025 04:02:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e6b:0:b0:541:1c48:8c0a with SMTP id 2adb3069b0e04-543c23dff88ls356797e87.0.-pod-prod-05-eu;
 Fri, 24 Jan 2025 04:02:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXMW5dkEZJhx3GQew1IuiCrxc65lj32cTY7yShFF6VIRFUi+KSqDR8/qTtMdPEZZG+TcKuIIM1CLD0=@googlegroups.com
X-Received: by 2002:a19:2d4a:0:b0:543:baa3:87ab with SMTP id 2adb3069b0e04-543baa38912mr4662242e87.47.1737720130884;
        Fri, 24 Jan 2025 04:02:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737720130; cv=none;
        d=google.com; s=arc-20240605;
        b=lNZaHN+Ryllklm9L90PeWRvW3zP1UArBGF9Sm9JLDCAb3GKlhK1LcvRFNnrxrZLuzw
         UMG69tpRMwncsL18zEazr1R2FGSsHVFL0lrt4m2Txtn2jMS7NFRDShx2G3Wh5vmJRM2h
         v0Eame0o9ErXS3om3btmAfJZLICG6CNpn5IN5eFMEXD8M7gorxRV/I+QNmnhVQdRIWGN
         5gppTUJvfODyIutd4UrXeoyG8+h/yxRXsLToQCR7CdLsyck7i6ySdlESZM56Bzk0D+PD
         d9j0VXcDpQHmkxBDLMQnRzVixWcADMyk0eLrpaNRi1F43Gdi3fLcJN+OQBwDRkyBemxT
         zXog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=zD6StW0rYzOmQ2GqSmARPsItuuT3+0nfZNTObiJebWo=;
        fh=n0nbDqynjgvoEP+FHj8+fXcC9BSAQZ5h9fBds5vadVA=;
        b=V7owUi0J3q6vkkZlYPElXW45aUJ3k0XWbSfxsL2DIS9+2bUmviX8ymXYiByXwavJH1
         MtUcETYDNKyafgIsss5sPiFslHWRJjKN3d0h72vAJwGbZTd7+oBhctZ8QdKhrPLSpd65
         STOG5WXPxWT9wgxE/nLOHRbVfFhoXRl3GXnprWDcnxaOe+XpSltUiiSKrOrf06PUvHlf
         uy0l0CwvGbxGY7LiWG2OZ5R5sS1VgxhwxXx957g5LWeawucRg0HSQ4Np5weRyGWUrU+o
         I9pvVvD70zistdELQT0gdWKpY7imafUooJB4rT8S3h8JBs9G2TitSQcuNUrObstQEe6X
         xxLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h1sWEfj5;
       spf=pass (google.com: domain of 3qogtzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QoGTZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-543c8231e51si42580e87.5.2025.01.24.04.02.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jan 2025 04:02:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qogtzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5da0b47115aso2038298a12.1
        for <kasan-dev@googlegroups.com>; Fri, 24 Jan 2025 04:02:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW84HGm60omCB3i25ZhMjnorbRm0eNQt1qx0XXJgUWAAKFvjFrcZRMYPn7lQxYtKobss7Hme0Kv2ek=@googlegroups.com
X-Received: from edbel15.prod.google.com ([2002:a05:6402:360f:b0:5db:e8e8:da25])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:2803:b0:5d2:723c:a568
 with SMTP id 4fb4d7f45d1cf-5db7d2f105fmr25991316a12.10.1737720130343; Fri, 24
 Jan 2025 04:02:10 -0800 (PST)
Date: Fri, 24 Jan 2025 13:01:38 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.48.1.262.g85cc9f2d1e-goog
Message-ID: <20250124120145.410066-1-elver@google.com>
Subject: [PATCH] kfence: skip __GFP_THISNODE allocations on NUMA systems
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=h1sWEfj5;       spf=pass
 (google.com: domain of 3qogtzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QoGTZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

On NUMA systems, __GFP_THISNODE indicates that an allocation _must_ be
on a particular node, and failure to allocate on the desired node will
result in a failed allocation.

Skip __GFP_THISNODE allocations if we are running on a NUMA system,
since KFENCE can't guarantee which node its pool pages are allocated on.

Reported-by: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>
Fixes: 236e9f153852 ("kfence: skip all GFP_ZONEMASK allocations")
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 67fc321db79b..102048821c22 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -21,6 +21,7 @@
 #include <linux/log2.h>
 #include <linux/memblock.h>
 #include <linux/moduleparam.h>
+#include <linux/nodemask.h>
 #include <linux/notifier.h>
 #include <linux/panic_notifier.h>
 #include <linux/random.h>
@@ -1084,6 +1085,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	 * properties (e.g. reside in DMAable memory).
 	 */
 	if ((flags & GFP_ZONEMASK) ||
+	    ((flags & __GFP_THISNODE) && num_online_nodes() > 1) ||
 	    (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32))) {
 		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
 		return NULL;
-- 
2.48.1.262.g85cc9f2d1e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250124120145.410066-1-elver%40google.com.
