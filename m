Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7NJ4SGQMGQELIIP4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3355C474D7E
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:46 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id t9-20020aa7d709000000b003e83403a5cbsf18246988edq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=RvLHFTjKFvaozfgrqHy/K7Z+sVCelGecKsTd2ZOca6xbFL+eai6A7KXwZyeY7fH9tx
         6IX4y1+RmTE3IJoIsrDM+5XGq0dWCNk0YV4phDr2NZXHlJ52KVjaGSoMTgQkAg1z6p2O
         psniC0msDuGYxGyHl3+7GzsBRaSbAOBRPyUBfus5kjLBckQ1Gscf9HNwAMC7KqqbcrR4
         QybpCjYLxm6nLfi1TCbNRrs1pVNrVaDKlyMDly932tXS7pjhREi1q8YrSM9a7tj4Zqnv
         BJnrUEHgEZmq5njaoaOzjahgyvnlNumfBG9P4UVtZiyQsd+g08IjUgVVQi9dPYP2bvKC
         WmUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=V/yRbjgeLkuNrblZBALujIxju+H+jFsmLieih/jXd9M=;
        b=vbn/K1Z2WFF2FvbqUX44Eol6m2xSA8zys6Qy8oQ1E77DmmNlQyfPrKOT1VFN1MkChg
         McjgJA0OIt2EO4iHx5cUvk32LY2nObnpr3lcDHrWAzAHecE+YJCw2virFi7pqwaudOGc
         s67YjYRncL+BOQKYt4YSNFppnwDU4ZtMZ1URWyQINOQyN5G2azUP+h3pZmktTuuu0ePg
         ua9V3AWjmhZFSjiyMxFwe3oCFIOVny/u32GQGcrvKlaTYlvkkfbT5uNtbjl7lEDppJS9
         Wmhq1BAhl4vxyQgs7GLnvyz1g0ONeYDf50y5tq/7oNjfcDOvdgg/Izt0gT2ze5ukuEDd
         H5Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UEmnFyHs;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V/yRbjgeLkuNrblZBALujIxju+H+jFsmLieih/jXd9M=;
        b=grN0aOyI6F2i25Cps4xEO+u+ydfSq0b8Kbn5k+VL0hlci3sJ5yNeXZqx9ApHd3oj1e
         MUkI2ac/lzbFUbPJvdCmIBTTXvNpDA20VA1WZ/h+sQP/M317kaFrlAY4Cg39M6KZaP2c
         EE9tHp74jgsIGQFK9bml+3/Pfv3RIVu+1D/ziYqsIlqD1a4bVTZ7g7T+q2vOJX/a6Rm6
         JKmh6IvUXBSljo26nNW3DoBZ4mnIpHiiExdY8DciL5IFYzLFGU8MTQWHx/0U3rC+0BFv
         +k6/DHFxlVLTIvj2zEmOZuwkzG3faELbX3hr7eXVESlme+w+Zw9ywZ85H1T5YC6Q//RS
         hn4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V/yRbjgeLkuNrblZBALujIxju+H+jFsmLieih/jXd9M=;
        b=0IY2x6v+oFcwafyS9TyxupDObADnkqpTHSnbDj8BRKzcH4kmwkEIl3pVWLGyB76qFm
         HKbMumCrT66jRDXX08ie7PnUzECB+2rEIRi291+/MwjOsFaips8mVAKrjL91kSRf2fSj
         tqAOEYxZ5BuyK2mc7NMP74OoyUzW/dAaAQ6v6NflYXnbyWVMTzrg4v4y1fh3z+O8O9H8
         X0/bjuzgNM/SxOFS3yGKr85/vy0yi/TMi+gmOJ0gEICdc9vm5CJszO5yVTzLTimhu8nF
         ur/ajLjKcAYkUV7CLowbJ5l8xkaJP1vavRWm0O/B/7j2x2ULG5xQWwG6Hg7D0M8NtO6s
         UyuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GJr81x9KVmfGC1Xi6cisqsXsJIQnbjOlsc/CoJFSkIMMWdEiX
	ASw2xxRDJ8/dpFUJGUVK2Rg=
X-Google-Smtp-Source: ABdhPJz70RamQdta0OEi2a1bAmOaut8c8zPPNrr45CjhGyxCgVsYan/jQ63dHGqdIo6q2yqkgTOQ8w==
X-Received: by 2002:a17:906:685:: with SMTP id u5mr8271848ejb.543.1639519485958;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7294:: with SMTP id dt20ls20831ejc.10.gmail; Tue, 14
 Dec 2021 14:04:44 -0800 (PST)
X-Received: by 2002:a17:906:31c2:: with SMTP id f2mr8538803ejf.341.1639519484869;
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519484; cv=none;
        d=google.com; s=arc-20160816;
        b=XDrskdCOXpu9QDhiC8YrX84LFWk1EqnBcbroM4kvuPmok+oabI9AcoRTqEpBgcR0vI
         ssjByED7Wb0r8BtjSHswK8VZoVTUQDxdo1uekXF+SsdpojeNC7cupplzgOkMjpaXD0/N
         8ULg/QuxOdcROvnDuo8ld044W1S4G5hr94MiNXkFpHKGGYKcasc4cI72eEEigOUodIc0
         bhP+ieVVNbAahb1omfZdJgBPDC5z2W4/oNr5VLTi7PlKgi+gOF6dEe8nzS71JcW6dHY+
         aokmDGCHrDh35GhzE9CSl01bAPJOqwzcnjGyEWr5yR2oPhQsUtLPMeOIIj0NxVhgsLSb
         goCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nBf3/LEb81JFAhRAibwuws5274SZcOtqg9g6wHBEjyM=;
        b=Y9vEs/WfGjal3FqLrT1rSeKFuz6atTjH5xsLFaFJcJxnBsl4V9TGBEhtjDzjCxcg2y
         w8jQrcpuGl/HJs99epUGWN0FQgTQ23QExUYD88YRAQBgBrDVKyI4Q2lURPl1Lw2EVmLG
         GSLKA2eRk5/s+xDQF06KNNSKt8YvosE0QBPk4ckqpNxX7SZIDOat6b7KB1dt29AouEbg
         SRvsrreDqygFhjxdrJxByL0D9TPNcGXDl7DCJQnisv4IBpqBVxf/phxg8OvNkbixS57B
         1qbFt2UWasOLiwYDm8eeltP7uvmY5D9u+8ZrlaRO40cLx8KI6F6ukgZKFknsua9EmDA6
         lDmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UEmnFyHs;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bs25si2734ejb.2.2021.12.14.14.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id AA89F6171D;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 03667C34621;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 74CD75C17E3; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 14/29] locking/barriers, kcsan: Add instrumentation for barriers
Date: Tue, 14 Dec 2021 14:04:24 -0800
Message-Id: <20211214220439.2236564-14-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UEmnFyHs;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Adds the required KCSAN instrumentation for barriers if CONFIG_SMP.
KCSAN supports modeling the effects of:

	smp_mb()
	smp_rmb()
	smp_wmb()
	smp_store_release()

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/asm-generic/barrier.h | 29 +++++++++++++++--------------
 include/linux/spinlock.h      |  2 +-
 2 files changed, 16 insertions(+), 15 deletions(-)

diff --git a/include/asm-generic/barrier.h b/include/asm-generic/barrier.h
index 640f09479bdf7..27a9c9edfef66 100644
--- a/include/asm-generic/barrier.h
+++ b/include/asm-generic/barrier.h
@@ -14,6 +14,7 @@
 #ifndef __ASSEMBLY__
 
 #include <linux/compiler.h>
+#include <linux/kcsan-checks.h>
 #include <asm/rwonce.h>
 
 #ifndef nop
@@ -62,15 +63,15 @@
 #ifdef CONFIG_SMP
 
 #ifndef smp_mb
-#define smp_mb()	__smp_mb()
+#define smp_mb()	do { kcsan_mb(); __smp_mb(); } while (0)
 #endif
 
 #ifndef smp_rmb
-#define smp_rmb()	__smp_rmb()
+#define smp_rmb()	do { kcsan_rmb(); __smp_rmb(); } while (0)
 #endif
 
 #ifndef smp_wmb
-#define smp_wmb()	__smp_wmb()
+#define smp_wmb()	do { kcsan_wmb(); __smp_wmb(); } while (0)
 #endif
 
 #else	/* !CONFIG_SMP */
@@ -123,19 +124,19 @@ do {									\
 #ifdef CONFIG_SMP
 
 #ifndef smp_store_mb
-#define smp_store_mb(var, value)  __smp_store_mb(var, value)
+#define smp_store_mb(var, value)  do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
 #endif
 
 #ifndef smp_mb__before_atomic
-#define smp_mb__before_atomic()	__smp_mb__before_atomic()
+#define smp_mb__before_atomic()	do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
 #endif
 
 #ifndef smp_mb__after_atomic
-#define smp_mb__after_atomic()	__smp_mb__after_atomic()
+#define smp_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
 #endif
 
 #ifndef smp_store_release
-#define smp_store_release(p, v) __smp_store_release(p, v)
+#define smp_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
 #endif
 
 #ifndef smp_load_acquire
@@ -178,13 +179,13 @@ do {									\
 #endif	/* CONFIG_SMP */
 
 /* Barriers for virtual machine guests when talking to an SMP host */
-#define virt_mb() __smp_mb()
-#define virt_rmb() __smp_rmb()
-#define virt_wmb() __smp_wmb()
-#define virt_store_mb(var, value) __smp_store_mb(var, value)
-#define virt_mb__before_atomic() __smp_mb__before_atomic()
-#define virt_mb__after_atomic()	__smp_mb__after_atomic()
-#define virt_store_release(p, v) __smp_store_release(p, v)
+#define virt_mb() do { kcsan_mb(); __smp_mb(); } while (0)
+#define virt_rmb() do { kcsan_rmb(); __smp_rmb(); } while (0)
+#define virt_wmb() do { kcsan_wmb(); __smp_wmb(); } while (0)
+#define virt_store_mb(var, value) do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
+#define virt_mb__before_atomic() do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
+#define virt_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
+#define virt_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
 #define virt_load_acquire(p) __smp_load_acquire(p)
 
 /**
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index b4e5ca23f8403..5c0c5174155d0 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -171,7 +171,7 @@ do {									\
  * Architectures that can implement ACQUIRE better need to take care.
  */
 #ifndef smp_mb__after_spinlock
-#define smp_mb__after_spinlock()	do { } while (0)
+#define smp_mb__after_spinlock()	kcsan_mb()
 #endif
 
 #ifdef CONFIG_DEBUG_SPINLOCK
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-14-paulmck%40kernel.org.
