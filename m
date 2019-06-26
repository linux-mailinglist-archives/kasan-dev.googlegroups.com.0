Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP6HZXUAKGQE2JWYODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 14725568A9
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 14:23:29 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id i33sf1351377pld.15
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 05:23:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561551807; cv=pass;
        d=google.com; s=arc-20160816;
        b=e0a35BShg785ukZQ02rvd9st+ZLd0medPg0alVKqnvkzZ2t6JM3/n0YIujRspipOcL
         hSb8IRVtiNoi+O3wC2Vgc1Lft/5ubLaw+arSU3sDrvt7W9JmVIwZjy1mgJb7aa7696Ws
         WSTXdhy1SwJ9H2Wg74ji3bP7JEsI6z7TBU4/xW38nYHfhuJDnlZ4okZ0kkhPAO2GveDL
         TE3X3CTANY19KXSyFP6esOZDWjeqki9CCv7SIaomHLgvF3D+aGW/n9CWk1lrFItSuXUl
         gxuMaPnzsb9CuXYoOyEcZeWMIvkc0IAVSigwakjzeJ7WTBVdunQIFzuafAWdROI1qeGP
         xcbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=JTQlItO0eMPTnG5xpYQoBmMoCSIxNI54ZZbgnA98FCs=;
        b=bgitPeH9ukuG0syvNBtvI/2XrcxTeIKMj8Yuc9OI6QhZvvnVjw/HfEPW5D6yZA8dwr
         trZNY+4/33tOZyPpvXtgEnvG5UyXwZ9H92GDuCEhdIE4zPzBK/D2Y9ae+8MiSDJleUt/
         OdQSwl2Yb+25Rah6b5SQvso94bMleDSMzSrp1BMko8wPbjacYUiOKXG1sLUTD21kWjjq
         vPzT3/ECkKFwy0+Ian1s+1/ftATrUoawdlsPg/lhUiyPeyBiCwGK3bgKzVWOvMIi8uDw
         yQiqFq7cpRlkNP3qNwpTroj4RLoPb3Pdk11nrH8TmUyDGq2/HgY0OPAOAqR2u757+3el
         h7aA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="R3K/eMQJ";
       spf=pass (google.com: domain of 3vmmtxqukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3vmMTXQUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JTQlItO0eMPTnG5xpYQoBmMoCSIxNI54ZZbgnA98FCs=;
        b=ZdNQL/e6gpDDqcPkMzEKtX30Gijhv4fkQegFLJOy5bGELaZkk/4LDVwf1oFQH7eyF+
         SunFEepK6mNN9YRfkO9ZZ9lIyd74I7VP6WJpBuBjJQQXm/avKKzIiGWiUJQwOwqThzi/
         OE4wySskjQhAblovMHBQsE09s21eB7szVurjCDfcJsFluDklotl56qf8x2ArloH7j9Pl
         mt57BlXhI+dbTEKYFvYxOJCSnwNrSGCEUMiVFLwLMKxoJ3+C+HsLDPdx5EEiX8dUWynQ
         0ZRjmAoEdWEfknvsadqCiF76wqza6EktWTMlGlL05d9D//gCbQZDo/ukUKGsMzB6vTiy
         sVTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JTQlItO0eMPTnG5xpYQoBmMoCSIxNI54ZZbgnA98FCs=;
        b=mtKN6Igv0ACBt0ChO2SR18EoL+C/24OiVMrPORw39julJ7zs4L4KC+CpgXFeuKBD+o
         qWBNggi37VwEiMXs7Gy7xqjtxcsnP6N1HkSAkFI+0LW23WljPm9pI3gv2aF1G76iKN/m
         v1e4T7qsREEjg5zS3qpA2rw/Krw2akUFlOtQx0Ose922RMWc9+Ljn8rqOFMBd2mPcRJx
         NiH+WvWo0jZwjKs97em2JMIsSjD1SUgYowldgIYRtS+LOOzr75Bxf9lLivLweIVouWir
         8LBghHINQqgfxAooYTM/TVRo16ZxGywVR8/4Zj8f1sxUwjTFLmQCuzh2x0OVVtao8p8X
         OMHQ==
X-Gm-Message-State: APjAAAV+/0oBNTNZHkedUC0N1xz0o91gwzDnPJhBc94+s3ueOJSgZq5m
	X7k8rMzVvO/cuzBJHLvAzFg=
X-Google-Smtp-Source: APXvYqzxDmgEqbhEQGObX6ADSQCAT+hX7hQUl2aKV5XjUESdOyRwASsyLxw0uNawzu+w5yuCaLTg/g==
X-Received: by 2002:a65:64d6:: with SMTP id t22mr2806295pgv.406.1561551807668;
        Wed, 26 Jun 2019 05:23:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:1021:: with SMTP id b30ls680972pla.1.gmail; Wed, 26
 Jun 2019 05:23:27 -0700 (PDT)
X-Received: by 2002:a17:902:2983:: with SMTP id h3mr5199469plb.45.1561551807308;
        Wed, 26 Jun 2019 05:23:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561551807; cv=none;
        d=google.com; s=arc-20160816;
        b=x5OLn75YNHgLa0A721SZaIQ+KeDeY4bhBuiQDwLHExoY/2uYywNc8ISBO/kRuw5Yp9
         9xyxmjMx7WVz28icX6maHCNbCk8Uak+WuxOZXUe0DQdmiPbmGT6Lx9OU0KsytwJ+2Qtn
         80k2YbfOm3wAxsqFcN0e/a6f0ACFrVwt3zX4eHGJl2oPUfKQpJ9KD6q83PzV5vmSSM00
         HnW6wfvl2HUojb16d+WoDVTy5kcekC7gM1TB6FjdU2APh7GmRvCEbKWMlk4XNHEWaOXk
         FzlbGzkIsiXtCrA7weoMA544g/L3cCPKR17QhXRkPaW6wTwK+Br6EkwwfhN8tQQMgEWh
         1P1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=VZ1Nu4TClKywlJIX2MtkIO8a/JcUzUmevX6rOfNTQ4s=;
        b=PDLPInmP5FA+MhqYMxMrWu6Mx5TTfqXWc/t09JBXjmnGf6wRSxbt5htJbqh6psxfSB
         3kg2PVe43TVaQzNPJPoR1U8y6xfZjsfdHzUfklLKrP/6f0yk+91AA1DJf6/HIM/pq5fo
         q3oemwS6tcuSJzt3svJYXE1Zd55sZgiqgxNFZqNE1EPb8R/mHAm9nLes6pJ6Vmm/Dxa1
         xLxgOZdoiQhad+Hg0Qos4MlYKGXcxgMOT3Q1S2pY5nqYgB01hjt1jDUE6p8Ahw7XMDiH
         jpaos81zEobcnRS5V6PBdEBzAsThhE1GMA6ChSmwG8FRqeATbFMWTlGccU/K6ALJa1hL
         or6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="R3K/eMQJ";
       spf=pass (google.com: domain of 3vmmtxqukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3vmMTXQUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id s60si31625pjc.2.2019.06.26.05.23.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 05:23:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vmmtxqukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id w23so407432vsj.22
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 05:23:27 -0700 (PDT)
X-Received: by 2002:a1f:a887:: with SMTP id r129mr1048981vke.75.1561551806136;
 Wed, 26 Jun 2019 05:23:26 -0700 (PDT)
Date: Wed, 26 Jun 2019 14:20:19 +0200
In-Reply-To: <20190626122018.171606-1-elver@google.com>
Message-Id: <20190626122018.171606-5-elver@google.com>
Mime-Version: 1.0
References: <20190626122018.171606-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v2 4/4] mm/kasan: Add object validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com
Cc: linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="R3K/eMQJ";       spf=pass
 (google.com: domain of 3vmmtxqukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3vmMTXQUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
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

ksize() has been unconditionally unpoisoning the whole shadow memory region
associated with an allocation. This can lead to various undetected bugs,
for example, double-kzfree().

Specifically, kzfree() uses ksize() to determine the actual allocation
size, and subsequently zeroes the memory. Since ksize() used to just
unpoison the whole shadow memory region, no invalid free was detected.

This patch addresses this as follows:

1. Add a check in ksize(), and only then unpoison the memory region.

2. Preserve kasan_unpoison_slab() semantics by explicitly unpoisoning
   the shadow memory region using the size obtained from __ksize().

Tested:
1. With SLAB allocator: a) normal boot without warnings; b) verified the
   added double-kzfree() is detected.
2. With SLUB allocator: a) normal boot without warnings; b) verified the
   added double-kzfree() is detected.

Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=199359
Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 include/linux/kasan.h |  7 +++++--
 mm/slab_common.c      | 21 ++++++++++++++++++++-
 2 files changed, 25 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b40ea104dd36..cc8a03cc9674 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -76,8 +76,11 @@ void kasan_free_shadow(const struct vm_struct *vm);
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
-size_t ksize(const void *);
-static inline void kasan_unpoison_slab(const void *ptr) { ksize(ptr); }
+size_t __ksize(const void *);
+static inline void kasan_unpoison_slab(const void *ptr)
+{
+	kasan_unpoison_shadow(ptr, __ksize(ptr));
+}
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
 bool kasan_save_enable_multi_shot(void);
diff --git a/mm/slab_common.c b/mm/slab_common.c
index b7c6a40e436a..ba4a859261d5 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1613,7 +1613,26 @@ EXPORT_SYMBOL(kzfree);
  */
 size_t ksize(const void *objp)
 {
-	size_t size = __ksize(objp);
+	size_t size;
+
+	BUG_ON(!objp);
+	/*
+	 * We need to check that the pointed to object is valid, and only then
+	 * unpoison the shadow memory below. We use __kasan_check_read(), to
+	 * generate a more useful report at the time ksize() is called (rather
+	 * than later where behaviour is undefined due to potential
+	 * use-after-free or double-free).
+	 *
+	 * If the pointed to memory is invalid we return 0, to avoid users of
+	 * ksize() writing to and potentially corrupting the memory region.
+	 *
+	 * We want to perform the check before __ksize(), to avoid potentially
+	 * crashing in __ksize() due to accessing invalid metadata.
+	 */
+	if (unlikely(objp == ZERO_SIZE_PTR) || !__kasan_check_read(objp, 1))
+		return 0;
+
+	size = __ksize(objp);
 	/*
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626122018.171606-5-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
