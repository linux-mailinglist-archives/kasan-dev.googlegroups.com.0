Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN7RRXUQKGQELWI6IJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 86A30626DA
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 19:09:12 +0200 (CEST)
Received: by mail-yw1-xc3c.google.com with SMTP id l141sf11274317ywc.11
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 10:09:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562605751; cv=pass;
        d=google.com; s=arc-20160816;
        b=zvOr/wrdSndl3V+UHNOKz854lS2UBvy9O6HO9GV8hvD70AqG2eJPiByrG4ryCPrnDK
         sYkRir7/Ewr417rHJHg0RtVMQAkaYbLINGsmHQVCg+s44Wn8bvdBupLrG0Z5zqlAzD8q
         vWTQ/ghH2zsxrpC6uJ6iziCQu5vr+g+UAx4RWqzXdUHni1U95nlvXFFO/02JbpY9OrRC
         iYeQDPd1IsJC5vibgSqa3bvws2glQqraOLzLCggZJ3otXx97EzTQG+yYDHa6Xd99A8w5
         z0Albxx8Ma141kaxBJWilQUPst9Y0VbULhGBGSWjajwRbJbj42vR9CJXlod92SHq4kqu
         so6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=LKcV2CqNUbpWQ2m/qZm57WhecsNzY0/6dNTdktU4NfM=;
        b=a7pyxM5HxRMVmtT9fpYYitZ+e2d9gQ7B1fTru8y7Pvz2TOIOkZnSKp+NcCCkicGM9v
         ZszVrIENvgCoyOwPbBHho3/Cqj2GsW1XypZ8iVx4JS5o8GhW7JN0Qq86DByohCmWvULE
         Bz0GL/NbYbVMCHogyR5cHoh5/jJp7lzcMrwjjLOEkcpAHLDLjO+LfAl/V10OahAymRCP
         mCGr5asSrgdbnTpXt/9UvZmdA9wpdaCMjUJCVv0XLMQyYObh9PEC6j3DSY/7e6wNVAy1
         h8wZcDRFZXvEKksXN2QhtwCpzdnEqpalioayKSzWsb6tCHHOJEpbkMq/ba66tpxYiJFh
         qPnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B62llil3;
       spf=pass (google.com: domain of 3tngjxqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3tngjXQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LKcV2CqNUbpWQ2m/qZm57WhecsNzY0/6dNTdktU4NfM=;
        b=TQ3BMv5JsKC2G4UnjpXxoaDqHkMEP2SQvEKH2FqtRMHHQuDb+YL8nRtVJWkaR1bdbU
         ms47Eo+UpZiUx52reStfiWXpCMvtajFWfJ8pDu6Gqka7aL627A1cdH1/WyPmbUr8o3A6
         zBbSCqykTgNAZeIEg2h8TnAP5GPOKvkuIkI/syM50UJa2OODV6KlJZgz1hfvOxxi934T
         7vM03NyVvqKTZqCLG+K53T3Ld6Q+dvVQCpGobTWCAjI0e2oj5H5vhsqsSqOlbO/kXKqi
         t5T4eXW1hTUCr1FE7B5nMoJGbc7vtkZMKr0pScKSQnFVyqbtzwBn6AZI7IHrWDjHPinY
         yL3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LKcV2CqNUbpWQ2m/qZm57WhecsNzY0/6dNTdktU4NfM=;
        b=i7JVwh6eW3aX7kdAglE/BpO/lIRchEOxvpluijQeNl9w2gML+QwSYl0GBhx/kkzzIM
         RtZHh1i6MKSdp04q/Mh6ee2xLs4czIxhLb7lBjF7qRAvjcx+B0muCMxN+Z8fCk3SEcjn
         ryoO8H0aDhhY55WpLZvCGfCgrr7hYozZDVox3gcSRsy9DYOXJlhSvBG3JRNuWcyyG5Uf
         30SvUW89xZcb0CHq7T1GE92nQm/rNLX3TQTAsUrqI2wgWF49JLisT0sGpuUc+fkKSrKy
         8GIzanH6bITE2luDYo5JAD+PhWP2Rpmp/oBpfmqlONjvQFygHON3paVVIexp5EJ1fK9h
         AbUg==
X-Gm-Message-State: APjAAAVYckDrNO3av7vh/JVGCoSkLmnbQFQFaWuHmxq2mP7N28iAxzPZ
	v+fqQR218KUTJu9q+SwDda8=
X-Google-Smtp-Source: APXvYqwPtg9Y3JvpzErt1sZDU5YYo+mPu1LZJZWGbW8rTBNWz/stxioF8J/KT3Y0BNgt1M91UBOJhQ==
X-Received: by 2002:a0d:ea06:: with SMTP id t6mr7377260ywe.186.1562605751297;
        Mon, 08 Jul 2019 10:09:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8544:: with SMTP id v65ls1690544ywf.16.gmail; Mon, 08
 Jul 2019 10:09:11 -0700 (PDT)
X-Received: by 2002:a81:117:: with SMTP id 23mr12231570ywb.255.1562605750990;
        Mon, 08 Jul 2019 10:09:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562605750; cv=none;
        d=google.com; s=arc-20160816;
        b=NEPGkkS6qwaEzOBofvlgF7dFY8/y7EuqXK7U+gRY2DF6HG+pjrB4ORevJhvgduqZNb
         WnrT7GgSmKPmqg9mofZjgitolT8DNW/vjddzOQi/46vAxZO2MTjIxk1s2eWdX8dgpCIO
         +BMFjKEGryNGtMNGTBHz65tuwv90gYRNV4zarLDzEVc6Vlqn0h2NxJkCDiAm5CFNxSer
         ZVOH0JlGm8RG5W72TaRJBb7eEYirBKwBqOil87F1QkXgVw5t1sm3VTtX+folcK7TxitB
         EWHDS3s8XW8/qWY1cbAcoL1qSarSdpj3yZTwA2cjJSfU3A4R0tXHMTwLGslJE5r0lq2G
         HmYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=va2IqGms4zwARolaxGifymkA8dWqhnjJfJEjqFTqRUA=;
        b=bhLnAM3uS/87E0HWyd7XMVlhUveVYFqjEGeqBPE81JAnmPY/z58xsve1CwM2t7vgJd
         Asy8jvf0awTFeN/GnGFfMnDcNPfv8Re5QdWWsnL2Y2DOWEOojnHeRI3zPCwJbNw43p4G
         fs17DsIQ4VUUYEtdKml/PoeVUQva+vnYZ8HoLBLQ631dnHaLkFil1zEX5hJgKkT4QTin
         f5aWrEnXVFUPineAtxyaXO0EPPaYPmPA64D1itJWwRIuo9ClCWNYSjbfXpLT+/aNvZQv
         1mnwcGIdy8k9nEqqoznmBiHZvSmDU+/smiXbf0l6F2qM/J1zOB82bnIp0YFso3ksEcIF
         oBPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B62llil3;
       spf=pass (google.com: domain of 3tngjxqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3tngjXQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id v127si891180ywv.2.2019.07.08.10.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 10:09:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tngjxqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id p196so6811094vke.17
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 10:09:10 -0700 (PDT)
X-Received: by 2002:ab0:66d2:: with SMTP id d18mr10407237uaq.101.1562605750505;
 Mon, 08 Jul 2019 10:09:10 -0700 (PDT)
Date: Mon,  8 Jul 2019 19:07:07 +0200
In-Reply-To: <20190708170706.174189-1-elver@google.com>
Message-Id: <20190708170706.174189-6-elver@google.com>
Mime-Version: 1.0
References: <20190708170706.174189-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v5 5/5] mm/kasan: Add object validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Kees Cook <keescook@chromium.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Mark Rutland <mark.rutland@arm.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=B62llil3;       spf=pass
 (google.com: domain of 3tngjxqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3tngjXQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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
Acked-by: Kees Cook <keescook@chromium.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190708170706.174189-6-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
