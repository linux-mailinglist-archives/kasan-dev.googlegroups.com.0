Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSVO6D7QKGQEN3UQEHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1357A2F0ED2
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 10:15:55 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id s23sf16521517ilk.14
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 01:15:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610356554; cv=pass;
        d=google.com; s=arc-20160816;
        b=xHKAKu0FJF11z5upjK+9j8l4y9bZtm56yGan3Coa9cW3Fpv9hfxgDgO1lMED0Sg29P
         tt5RpazVmIxZiMU16BIEqaq+uZ9t9YqNO1KWKnAWth2BKhSHyPsQtcjAi9IoXSCyfT2E
         kUZb0wbucrmJBVfVINfK6WVuN0ZvIAvkqbEWNE6L5Hd47FKYgs+7SD1B28O3T499pbq3
         KiXUOgUVsK0ocmDfMNNqdi/cKD9p2KfRc0bPriRHCtP1QanVOETSqxXvaiP/IkU9UkTx
         NwtxqrpB5BpC1SWbPIOwWnnKFd6BnpeYYujysvlecfvolURm6T57vvX01YVDW1E8Rmfy
         u2MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=0txe2Yn8XaIsZRwgSnlXKII7EepKnRP2+7log5KdcUg=;
        b=lAoee7/SzUZTMooBqw3pY1HmXW9AR/Mc0KZzde7IVcvqze0C2m1tH7y8VKXdUslqHt
         WtVm47jnLhOH4DcSbCF7yZgwJi2r47VccouNCJHdPI9shTOUmdKA3pgU4FD9Rbq5hE8y
         RFrCzIphYRnFwwgpDlVZ8MSFIYr76/f5Id4OVUPw8nGFQNSMnJhkG4gdFMrV7BVIlfsZ
         TvWlbaaBWjGnpFQlcmktzey9IpWtLktxyiZBum0U1/00Hdb1sVXy78EBJATIPoAFH8QI
         BBsAHqX6tJ6SQ+5/Qodv4mxgJfZWnMePWs6W+Tw2ygBxsvE6+m71Yka8NJieYScMGWaX
         flQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sSWE8ojT;
       spf=pass (google.com: domain of 3sbf8xwukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3SBf8XwUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0txe2Yn8XaIsZRwgSnlXKII7EepKnRP2+7log5KdcUg=;
        b=J8fmgtyQEuNlbuNw8lZOPUvIHcy76ZasIVIi4Fi9AkhlDXtVepJqCnZH+vjSepwDNK
         N6/rOdXiweEypXbu9zkagLCEM1R+pZ/dF4wLTf5Btl7ancYcOJZe6OobzcJVrCkT6oVM
         SRm/ufOTKuEbSIaNsdOlidleVNi8PUocpByvBnB7Y6Y1r5nGOag+BD/VWfixAIoSUxcI
         4d3AeDvO8kdTOLIccBcjyjhUkk2x4t8EXdmB+SRNC95PyR+vvlAzp1pUp606eu97MHZN
         6weqJgrb76q/kYhYer3QdlkpLhx43RnIj83P6C+1g8sVKd9WEaD0rPrgjeae6TFMUA7k
         InYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0txe2Yn8XaIsZRwgSnlXKII7EepKnRP2+7log5KdcUg=;
        b=teG5ZUfO2fzbjAc+emQ+U8SsU4m0GfvdujIXybJ1mZYQaPxiBt3S0OKD5z7IvnuBum
         HItGJgrbT8VsEYTwsqB5jwvzq8ME1YkLi7yZh1b65Q6TilmmKQw9euyKYMGMyvvcTK0g
         1N5/6Biy56ZudQCUHYzIgLyU6H3U/x8OPUvi3wBq32ZJA9YJ6t1i57g1tkXbt6DuxfVZ
         0QP84elQ/6c+3TlNHvYiz6nEyTx0WT3I+YHLQf09kLIfYw1kQjzDA6AoO0oJKIwDNfAJ
         bIdFBwmDqho+/onHr/+9vqj5+eNqPIqvREEPLvzi/eFgY9NPWdSNd5rlFwmUm9IMb1gq
         BNzA==
X-Gm-Message-State: AOAM533D7/nx8A7r0oyllrG4xjEq9b+OjSqAW8gR9P1SC2T4NIM24/km
	rsCyYzXKlAAc0uGI1e3UKPk=
X-Google-Smtp-Source: ABdhPJzw4xTo3b6gtM03jAd+8nK4O2YnoCH/sFG3BxG05MWgzkJSZjBuEeBlIkaUMRjkDxUGAFCvFA==
X-Received: by 2002:a5d:994c:: with SMTP id v12mr13913528ios.201.1610356554106;
        Mon, 11 Jan 2021 01:15:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8c86:: with SMTP id g6ls2809132ion.0.gmail; Mon, 11 Jan
 2021 01:15:53 -0800 (PST)
X-Received: by 2002:a5e:9906:: with SMTP id t6mr13791924ioj.183.1610356553676;
        Mon, 11 Jan 2021 01:15:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610356553; cv=none;
        d=google.com; s=arc-20160816;
        b=MlWhupx6ga/UZqWGvo/aQtcNhx70LfbBNaFbVGukFDEjALe3ZvKafEXeM4lAzvK3gA
         HomCnBfFrEIbmD2+fwi6t6JSbXcEOU0PFeds8GjV628npheyBk1ncNeHP08ZFebap/5z
         niiFxu5DaBfkPioywBoeWDV9qqtC6Sm0jHllorY70cIjvHjsySLNL4cF59tatr6lUGY6
         Wxihs3g0m0QhqXX5HAhGgPsiEA+WsDsRjMUAWnoMdf5sO/KxbfKG0hFLOwhLQ2uG/rwV
         +5gzmC2ZmerSA12qOPEn0zdRC9to6wZHHSw2Ra4FLe76i6wi01y/XKe21lyfMlUFROJ4
         Hnig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:mime-version
         :message-id:date:sender:dkim-signature;
        bh=mA0JHK6xgqVKJnr+4pNXEncnoduYcHjsc3imT7Uizfs=;
        b=SBzMkCtqZI5WOMRkm6OuGD5Tyv8lxDXesDjyqBJrdJH7niHmKTtc2169WG7Tkl5Rb5
         K5pAlmtuhwGYxgmY9O0wM/tlSiJub9DMhdM1TyMQcBKVAE9PUMgZ3WfmI/L9dTsJzlN1
         j53Q0tRq4k6UUa3zxlG31Uq7YuRcxaYIiyMw/Ugv/EOGt86Xw8BCNj6EZU+0/m41gB3a
         i6wFsXSEsJujXZhJ1633LdFZF2ddY9d+pZEcJUHu0YaMhxOIszVcknOxipzN1pzP9yBB
         QV+bwAtFMk47ebZ4MME2txpLa0NL9Z23Fe31xjxYAdVE04j4njs3UQ4/FGsIa9RnbBvp
         70vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sSWE8ojT;
       spf=pass (google.com: domain of 3sbf8xwukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3SBf8XwUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id p16si798970iln.2.2021.01.11.01.15.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 01:15:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sbf8xwukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id t20so3450595qtq.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 01:15:53 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:438f:: with SMTP id s15mr18357736qvr.13.1610356552994;
 Mon, 11 Jan 2021 01:15:52 -0800 (PST)
Date: Mon, 11 Jan 2021 10:15:43 +0100
Message-Id: <20210111091544.3287013-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH mm 1/2] kfence: add option to use KFENCE without static keys
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, mark.rutland@arm.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	"=?UTF-8?q?J=C3=B6rn=20Engel?=" <joern@purestorage.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sSWE8ojT;       spf=pass
 (google.com: domain of 3sbf8xwukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3SBf8XwUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

For certain usecases, specifically where the sample interval is always
set to a very low value such as 1ms, it can make sense to use a dynamic
branch instead of static branches due to the overhead of toggling a
static branch.

Therefore, add a new Kconfig option to remove the static branches and
instead check kfence_allocation_gate if a KFENCE allocation should be
set up.

Suggested-by: J=C3=B6rn Engel <joern@purestorage.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kfence.h | 11 ++++++++++-
 lib/Kconfig.kfence     | 12 +++++++++++-
 mm/kfence/core.c       | 32 ++++++++++++++++++--------------
 3 files changed, 39 insertions(+), 16 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 76246889ecdb..dc86b69d3903 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -4,7 +4,6 @@
 #define _LINUX_KFENCE_H
=20
 #include <linux/mm.h>
-#include <linux/static_key.h>
 #include <linux/types.h>
=20
 #ifdef CONFIG_KFENCE
@@ -17,7 +16,13 @@
 #define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
 extern char *__kfence_pool;
=20
+#ifdef CONFIG_KFENCE_STATIC_KEYS
+#include <linux/static_key.h>
 DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
+#else
+#include <linux/atomic.h>
+extern atomic_t kfence_allocation_gate;
+#endif
=20
 /**
  * is_kfence_address() - check if an address belongs to KFENCE pool
@@ -104,7 +109,11 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size=
, gfp_t flags);
  */
 static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t siz=
e, gfp_t flags)
 {
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 	if (static_branch_unlikely(&kfence_allocation_key))
+#else
+	if (unlikely(!atomic_read(&kfence_allocation_gate)))
+#endif
 		return __kfence_alloc(s, size, flags);
 	return NULL;
 }
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index d3ea24fa30fc..78f50ccb3b45 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -6,7 +6,6 @@ config HAVE_ARCH_KFENCE
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
 	depends on HAVE_ARCH_KFENCE && (SLAB || SLUB)
-	depends on JUMP_LABEL # To ensure performance, require jump labels
 	select STACKTRACE
 	help
 	  KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
@@ -25,6 +24,17 @@ menuconfig KFENCE
=20
 if KFENCE
=20
+config KFENCE_STATIC_KEYS
+	bool "Use static keys to set up allocations"
+	default y
+	depends on JUMP_LABEL # To ensure performance, require jump labels
+	help
+	  Use static keys (static branches) to set up KFENCE allocations. Using
+	  static keys is normally recommended, because it avoids a dynamic
+	  branch in the allocator's fast path. However, with very low sample
+	  intervals, or on systems that do not support jump labels, a dynamic
+	  branch may still be an acceptable performance trade-off.
+
 config KFENCE_SAMPLE_INTERVAL
 	int "Default sample interval in milliseconds"
 	default 100
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index f0816d5f5913..96a9a98e7453 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -88,11 +88,13 @@ struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NU=
M_OBJECTS];
 static struct list_head kfence_freelist =3D LIST_HEAD_INIT(kfence_freelist=
);
 static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freel=
ist. */
=20
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 /* The static key to set up a KFENCE allocation. */
 DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
+#endif
=20
 /* Gates the allocation, ensuring only one succeeds in a given period. */
-static atomic_t allocation_gate =3D ATOMIC_INIT(1);
+atomic_t kfence_allocation_gate =3D ATOMIC_INIT(1);
=20
 /* Statistics counters for debugfs. */
 enum kfence_counter_id {
@@ -583,29 +585,31 @@ late_initcall(kfence_debugfs_init);
 static struct delayed_work kfence_timer;
 static void toggle_allocation_gate(struct work_struct *work)
 {
-	unsigned long end_wait;
-
 	if (!READ_ONCE(kfence_enabled))
 		return;
=20
 	/* Enable static key, and await allocation to happen. */
-	atomic_set(&allocation_gate, 0);
+	atomic_set(&kfence_allocation_gate, 0);
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 	static_branch_enable(&kfence_allocation_key);
 	/*
 	 * Await an allocation. Timeout after 1 second, in case the kernel stops
 	 * doing allocations, to avoid stalling this worker task for too long.
 	 */
-	end_wait =3D jiffies + HZ;
-	do {
-		set_current_state(TASK_UNINTERRUPTIBLE);
-		if (atomic_read(&allocation_gate) !=3D 0)
-			break;
-		schedule_timeout(1);
-	} while (time_before(jiffies, end_wait));
-	__set_current_state(TASK_RUNNING);
-
+	{
+		unsigned long end_wait =3D jiffies + HZ;
+
+		do {
+			set_current_state(TASK_UNINTERRUPTIBLE);
+			if (atomic_read(&kfence_allocation_gate) !=3D 0)
+				break;
+			schedule_timeout(1);
+		} while (time_before(jiffies, end_wait));
+		__set_current_state(TASK_RUNNING);
+	}
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
+#endif
 	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_inter=
val));
 }
 static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
@@ -711,7 +715,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size,=
 gfp_t flags)
 	 * sense to continue writing to it and pay the associated contention
 	 * cost, in case we have a large number of concurrent allocations.
 	 */
-	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) =
> 1)
+	if (atomic_read(&kfence_allocation_gate) || atomic_inc_return(&kfence_all=
ocation_gate) > 1)
 		return NULL;
=20
 	if (!READ_ONCE(kfence_enabled))
--=20
2.30.0.284.gd98b1dd5eaa7-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210111091544.3287013-1-elver%40google.com.
