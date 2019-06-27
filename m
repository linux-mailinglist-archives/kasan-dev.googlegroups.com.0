Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMFA2LUAKGQEEA4AX7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2409057F89
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 11:45:21 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id k10sf503563vso.5
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 02:45:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561628720; cv=pass;
        d=google.com; s=arc-20160816;
        b=DfCKBnuJZs47d7dTI5+m2i9+hs6a3RNEOFJIUickbwD3Yi4c13quad5oJ27l6UWhtR
         fer5KZw7arT9uYKsxtX9vFQ9qbzAliV8HMmVQKchgL3HmRLO0pIWacpknqOr+Vv4Stx2
         szW45cHb538PmEsxY0oLzb4KVqz9TzVWP0fwCYvz5X1vNAaelssFmggE41GH2F6/L45V
         ng8ns3aRVIcaNAphhO2nYv99sEeniLxL4/0YAeCtwabjXUNIL8yS4ZkpvPyvDKp78ht0
         XaKc87QaL+zO2VYIH4+BK/4lNyCDLjgAyNIH4/ULL5cUC0tfrrnp0sOMXv/GChMZCpXY
         JSsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=In6Hr+s2MvchQ/hOiO0mKP+AZSit8SEAxsmqq/5HeZs=;
        b=NQ6hq7T1gtzxn4ujNYJ9zbsjTkPAJsvoSwtxEXJ17vw23CjBV/kipjiYCq87N/rUrL
         keNZtmuzl3NAUG0HtAfZobQLhCgTRWJ/8rIkwb14aExhP8/1XztWzW1tf7H2VAtKAhnx
         914TMhP47vGZEuYCyxFLo6L1Caclmb2cUhzVrfKRtd0uCkodBMmqpB7Azb01vJD8B2J6
         ALs/ut8klgTzmHjftnrp9VLXtw7By63S7VVAHK+VflEYZ2iNnKFpFEeM3LJf2araelRl
         B15Blh0j/7dOFTX+0aiBcN9kmQCAZyoY7fHil7zDZ6lTibcqQ9xExusbT6MBQmCe69j8
         hdtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WhKnnvq+;
       spf=pass (google.com: domain of 3l5auxqukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3L5AUXQUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=In6Hr+s2MvchQ/hOiO0mKP+AZSit8SEAxsmqq/5HeZs=;
        b=AN+my8zLIdbQ2TJTy6whEhIH9VEDeBJyAXwdOoQLx7nIC74PhJWsbB6pAaLUHUkB/1
         w8YR0yEaDOZSzjhYC/f9fD9ID5RdEN4xcWhDVDOu8lPfX8otaOXzkt62pMhgpG9hsT1t
         4hRgb8TLRGZz7QwluqdbW1Oi/+7Zp/Sb5jgfq6qf0xKsQCGSm/udLKf/AcF32egKeBth
         jRyGv96Jsu1TV6AcirO6g/hO/jZTttvs8eJKxIQOcT/VbUWlKWOmugBoRYxscRlXmOEY
         S9y+KVv4qunMnsekaMVLiEahJxdXYhTXcRG8QWE0a5Gxla8iWJcGYuq+XuDPsKNHUPk8
         YW8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=In6Hr+s2MvchQ/hOiO0mKP+AZSit8SEAxsmqq/5HeZs=;
        b=KFykSAPAHEvf6xsVCMZWRBYIN/RVwC7SWLahOA232P5936HsKRplA/bg+YpgvtQlly
         aLXgKB82z4AtL7KKASoYxGIA0GcLKQxKCCXbQASUAm/0O3Rim3ur03koCkiTsTrvvwZZ
         2NH4Zgbsd5wRdVA9j2GmADr/DFmIVFjEfMH5fpX3ZQdmW9ca/36waylj2ZYAsLHxG3i5
         Q5xH8a34N5hmAGz8ZZ9UIhKhPqv5lEGcOC/eloc181u6bRpKDT8ntm1xqx5y2txvSE4u
         +sQExAB+oM42l+dTs+xiEVr95wrZ0nA1FlV/DNJKbKPJN+TO1I46qBfGPwsK9YuXIfo/
         T2kw==
X-Gm-Message-State: APjAAAWyRshiyttktQ7V5I2gpTfgg6AQiDTTs9m/1EyoBmBl26U0xlbF
	QJZiWaf25oFYP9ubyrqNrH4=
X-Google-Smtp-Source: APXvYqzv7nTwrtNuDm4MRNVKBiShph++KCz2pPTcLazDgHQVq0dsMGb5y6SisM/ot0WIWaPAj2Mm9Q==
X-Received: by 2002:ab0:751a:: with SMTP id m26mr1589961uap.11.1561628720202;
        Thu, 27 Jun 2019 02:45:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8cc8:: with SMTP id o191ls490945vsd.15.gmail; Thu, 27
 Jun 2019 02:45:19 -0700 (PDT)
X-Received: by 2002:a67:ea49:: with SMTP id r9mr1947691vso.223.1561628719968;
        Thu, 27 Jun 2019 02:45:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561628719; cv=none;
        d=google.com; s=arc-20160816;
        b=L1dgUk/9hj2zxsdxA3WzFS7iUrbTpiEbS7xCdvYMnzwAZ6p/YmMmrCECHF6sfOfGFa
         tYun91YwRL3kgxgoPr1oZesiNqUKehSlUoHoNS7alMU1U4ZjCKjHKmQemOhPSYhu3rBD
         UmWV7dMtdMTnShKNw+5GCGgOPhM0REF5pwY9nB5NU7BqvIKhYTX56XQ5Psxk87nGyCn4
         vrQ0HoGtm3qhhkDNsylQE4YSniP3mbUXfAJ70Q7R9hg486dsn1zccHwUJTJdiLyb6z5R
         DV6m9sn6iePh4CoKCpt7OSoCSb/FSf61yPdksM+1gTfiABw+ydQaKAYdW7yctunN3zLP
         2j0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=dExuKDG1Vocm7R5NxDrIVnD2CUOvxrQiPu2P2B60v+w=;
        b=MwO5yi7quXI2Y2rx2ZgCQSxVXyhbIq5D+lMqA/yElF8teFow+JpQd2YodeMiyagNYk
         6ajAwWDq0AkBOLwudWnVG4tCr6+8Zr6/WYi1ACipXo2M74ZKv5dCYNT36/P6EZqZNGmB
         meF118HMbG062f0vaLxh3BLF3HX8ni2zR/ZfTdcMPc103yQVPKpmU9EhCM49jrSfFLvs
         Mtrk2I5EPhYsBycuWlzkDD2JCTUm/qjM81cNCn7Zos8YBRkgRdu3OnorUk+1cwluKrQg
         WHLD+5btnVuk6fqlK52ua98jAkHrItuz6G0b7ZVf/yVfPnY9BCulvpsFZGz/4+QMXn1r
         Lbvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WhKnnvq+;
       spf=pass (google.com: domain of 3l5auxqukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3L5AUXQUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id b5si43066vsd.2.2019.06.27.02.45.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 02:45:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3l5auxqukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id y19so1814571qtm.0
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 02:45:19 -0700 (PDT)
X-Received: by 2002:a05:620a:1228:: with SMTP id v8mr1133045qkj.357.1561628719562;
 Thu, 27 Jun 2019 02:45:19 -0700 (PDT)
Date: Thu, 27 Jun 2019 11:44:45 +0200
In-Reply-To: <20190627094445.216365-1-elver@google.com>
Message-Id: <20190627094445.216365-6-elver@google.com>
Mime-Version: 1.0
References: <20190627094445.216365-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v4 5/5] mm/kasan: Add object validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WhKnnvq+;       spf=pass
 (google.com: domain of 3l5auxqukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3L5AUXQUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Kees Cook <keescook@chromium.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
v4:
* Prefer WARN_ON_ONCE() instead of BUG_ON().
---
 include/linux/kasan.h |  7 +++++--
 mm/slab_common.c      | 22 +++++++++++++++++++++-
 2 files changed, 26 insertions(+), 3 deletions(-)

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
index b7c6a40e436a..a09bb10aa026 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1613,7 +1613,27 @@ EXPORT_SYMBOL(kzfree);
  */
 size_t ksize(const void *objp)
 {
-	size_t size = __ksize(objp);
+	size_t size;
+
+	if (WARN_ON_ONCE(!objp))
+		return 0;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190627094445.216365-6-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
