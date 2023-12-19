Return-Path: <kasan-dev+bncBAABBPFSRCWAMGQEIPTDFBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B9794819382
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:29:17 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2cc84eadaf6sf10715681fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:29:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703024957; cv=pass;
        d=google.com; s=arc-20160816;
        b=GcksuoBkWqwZPOV2klXoSWy+LQsQ565FVQtlrdoM6r2J93IbK2Gydg1dLk2+ofPxw2
         RKeuZzBDyVL6yZN46DPb9220WpoY22+iNbob/Q0iJPSdfxM/mBC2A64c3UO2nZijfT/K
         liecvVgJDkindnyrX8a6xbj/ioijtieoklY+OxkRjgHIT/0/Utap4m9s5vy+S4njk/+M
         HSvgakud/oqkXsXd7xT6auT2QYNpgrlzP56UshjsZwKIkBksbNtuNxcXHs/9PWycQF3x
         jFTvd4cwtMlvVHLkyTH+MqLEJLOIBhRe4J6qHGQ/M+iwbNLl4KmwleNxmFuJWSIbzuW5
         v9Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CyQfwFYDjg0iqPQR2kuzRPnhZ8apu+NqiFKiE7pM0kk=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=Gzsyh+EpdV4wyXMinY28K7vzUD+O95shB18l+V+e6aOSLNCwmSFYKVXbgIQtLD1Fab
         RRIY+NP4kmeqqdrUo45wBF2twWru+yeOOyX29j1WHWzh3Blk40D9xs8EHAHfqRuVYJ4c
         byaisT/UR43fMpCPLP/lx5iZYZuAr47ZbUxXU8v7r0+j+gCm5Bi/TV6ZJ2Mgijj/bgKl
         foTrnsSfJs5P+djXj4TULjSgzo+xDGl2gx3m6+TWHD8Eqp+D0RsNvLDlLuFKJdyG4hiO
         m3tok8QbzdFbTbPH+3X/6aFzTcHEtWDBxCyFP3y7BqcjM8gun0ztHOciP41zij0C8v/b
         Eqaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="F86/EPhH";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ba as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703024957; x=1703629757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CyQfwFYDjg0iqPQR2kuzRPnhZ8apu+NqiFKiE7pM0kk=;
        b=nN+/35/WpiNHJ4/vcBynxyJCWSJtAvWy4FgHFKddJfkLLjeL/SkSJDol7P3JOAghrf
         fTTdtZjvWwHbeOPLWyjRBfJ34EnLZxekfO3x38uQaVL21LMF4t3ZV4NXHNtO960vg207
         YK09giCYTOqRwpXStG7fv7lMPiAJQjUGXsRKn5TICoA8ZisJyhs417blj41V5FxbYIFF
         sZbOHjBVuB8lciQh277xTomcZe5DR5f0YuSbcz6+0i/g/7DoyLjc2wuxBa4D9JgttBC8
         nXAfHtbziuzXMIZTymokzKPsma8UI/dicxIjd/P4pO6ibjhtX+AJyfNpsoubmOxWeikn
         YrCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703024957; x=1703629757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CyQfwFYDjg0iqPQR2kuzRPnhZ8apu+NqiFKiE7pM0kk=;
        b=hiKDCn7KjdD/4OQuIM4KOtk0yVrbyd69oNPNPAneAKi2u1TxNrETnfz+DtzREp+UER
         07v81vAAX3xZMXzulVdtuBdKDHROD8efaOAt7/cuxGd6hShaPggZlxayoRtvqaZpdkTP
         DV6vPDJaZJN8Spm/mjB6tuagfDgcEr5AFV/hXELoyc2CovNyIVlKpwlwxwjf4KWvCQlm
         l2Uwd2TZxbYNc+Db58l0ZWFwTew7BDQAVQMrjfafnLg92cR0tTYdogRFstZm5i68unHC
         2oqJic3HLXKADzEZG/teKTg9B+0kEsajaSnEt+iV5N6yJYCZCR8/mOv+Z0ZKuk/flELE
         /GqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx+/ft0S80cFn45LpW1ygKZL02c2uqiHOh++z5qtuXXNYgDfFid
	Wruifp8CwWrGpsfq9y7eLAY=
X-Google-Smtp-Source: AGHT+IHMaeI/+xiIYG/a6G7i3A5LllI+HIDBGQjX2Q18bu420yCF4KlVoEU/wEwuSXxdu34GSyvATA==
X-Received: by 2002:a2e:8ed3:0:b0:2cc:67bc:14f9 with SMTP id e19-20020a2e8ed3000000b002cc67bc14f9mr2468250ljl.85.1703024957097;
        Tue, 19 Dec 2023 14:29:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a454:0:b0:2cc:6f45:8ae0 with SMTP id v20-20020a2ea454000000b002cc6f458ae0ls1162425ljn.1.-pod-prod-04-eu;
 Tue, 19 Dec 2023 14:29:15 -0800 (PST)
X-Received: by 2002:a05:6512:3d11:b0:50e:3df2:c7c0 with SMTP id d17-20020a0565123d1100b0050e3df2c7c0mr1842631lfv.21.1703024955491;
        Tue, 19 Dec 2023 14:29:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703024955; cv=none;
        d=google.com; s=arc-20160816;
        b=ygmJoxoaQIHvYTcTLA1WAFfjgaA5Hf/MgXHrEN2e7V/CZUExwVl7DudVMQtrAeqakG
         wRNDpTE4AIpAxi+n2oi+CKIgTMx/3XIASiW/bgKzNDIFxgkid+AUc5tHiHiXcW+QmU3p
         g2t7G1TZb/fl42jbDjZ8wKwsokLOJHFgUIR/uh74EBVkIIiDrW0E8l307KEzmS8pE51N
         u0FJCMjvssZDsPr5u3JvJNj1jBliwucPWIN89rZ/FjT5EeafxUX4ypfEbB1ACdp9vf0s
         IRW4k5V4sSFLo+DcVS1sEjYqk17SNSvRDSPudVkm9tMRJguOgUJi4NeXoPoM/cG6JUwn
         Wu8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DO8tjmS9YVd+JQvWum2ppGekXJiIG6c57s1H7fN9b9c=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=w+pX6+92zy1Rp6NcCOm27gyRufCvG8MuJce5O4BpqDKEPpSknvNJMuvyEcESK5aLxN
         k5EdfRf7K+AZTxPFyespOk+88/mWCmGx0lv/ZZPj7bmdE3O2dpzteC34qo6dQwicImdv
         jewrmm20H2Y9ROvRDvem9ijJHgDgAsNlj05IUrj36guyRuenQ5CZfUpkEgrMpKgwmVxP
         GbKv4PXO5qfEe1uAbk1p0QmpSpKL2xy+vULjjuOr+vOwDSlILPJODVv3eBZnuM9mPE9o
         FiuMl2ZJhbAZpeNYeWgnaCZ95LvjOSk6dSet5jufCflztBvmBVZ0zUe1t2eG1HHHQpk7
         QXxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="F86/EPhH";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ba as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta1.migadu.com (out-186.mta1.migadu.com. [2001:41d0:203:375::ba])
        by gmr-mx.google.com with ESMTPS id p14-20020ac24ece000000b0050e1c5be1b4si108906lfr.6.2023.12.19.14.29.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:29:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ba as permitted sender) client-ip=2001:41d0:203:375::ba;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 05/21] kasan: introduce kasan_mempool_unpoison_object
Date: Tue, 19 Dec 2023 23:28:49 +0100
Message-Id: <dae25f0e18ed8fd50efe509c5b71a0592de5c18d.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="F86/EPhH";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ba as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Introduce and document a kasan_mempool_unpoison_object hook.

This hook serves as a replacement for the generic kasan_unpoison_range
that the mempool code relies on right now. mempool will be updated to use
the new hook in one of the following patches.

For now, define the new hook to be identical to kasan_unpoison_range.
One of the following patches will update it to add stack trace
collection.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 31 +++++++++++++++++++++++++++++++
 mm/kasan/common.c     |  5 +++++
 2 files changed, 36 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 33387e254caa..c5fe303bc1c2 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -228,6 +228,9 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
  * bugs and reports them. The caller can use the return value of this function
  * to find out if the allocation is buggy.
  *
+ * Before the poisoned allocation can be reused, it must be unpoisoned via
+ * kasan_mempool_unpoison_object().
+ *
  * This function operates on all slab allocations including large kmalloc
  * allocations (the ones returned by kmalloc_large() or by kmalloc() with the
  * size > KMALLOC_MAX_SIZE).
@@ -241,6 +244,32 @@ static __always_inline bool kasan_mempool_poison_object(void *ptr)
 	return true;
 }
 
+void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip);
+/**
+ * kasan_mempool_unpoison_object - Unpoison a mempool slab allocation.
+ * @ptr: Pointer to the slab allocation.
+ * @size: Size to be unpoisoned.
+ *
+ * This function is intended for kernel subsystems that cache slab allocations
+ * to reuse them instead of freeing them back to the slab allocator (e.g.
+ * mempool).
+ *
+ * This function unpoisons a slab allocation that was previously poisoned via
+ * kasan_mempool_poison_object() without initializing its memory. For the
+ * tag-based modes, this function does not assign a new tag to the allocation
+ * and instead restores the original tags based on the pointer value.
+ *
+ * This function operates on all slab allocations including large kmalloc
+ * allocations (the ones returned by kmalloc_large() or by kmalloc() with the
+ * size > KMALLOC_MAX_SIZE).
+ */
+static __always_inline void kasan_mempool_unpoison_object(void *ptr,
+							  size_t size)
+{
+	if (kasan_enabled())
+		__kasan_mempool_unpoison_object(ptr, size, _RET_IP_);
+}
+
 /*
  * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
  * the hardware tag-based mode that doesn't rely on compiler instrumentation.
@@ -301,6 +330,8 @@ static inline bool kasan_mempool_poison_object(void *ptr)
 {
 	return true;
 }
+static inline void kasan_mempool_unpoison_object(void *ptr, size_t size) {}
+
 static inline bool kasan_check_byte(const void *address)
 {
 	return true;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2b4869de4985..4b85d35bb8ab 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -451,6 +451,11 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 	}
 }
 
+void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
+{
+	kasan_unpoison(ptr, size, false);
+}
+
 bool __kasan_check_byte(const void *address, unsigned long ip)
 {
 	if (!kasan_byte_accessible(address)) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dae25f0e18ed8fd50efe509c5b71a0592de5c18d.1703024586.git.andreyknvl%40google.com.
