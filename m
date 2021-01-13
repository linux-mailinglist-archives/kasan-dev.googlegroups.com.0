Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWNT7T7QKGQEWWPEKII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 249D22F4F6A
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:03:39 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id a2sf3662041iod.13
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:03:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610553818; cv=pass;
        d=google.com; s=arc-20160816;
        b=a4VJhHKg9MdtguvS+zuvuWS0lZVcHVVSO1Q8LvSyrGcBV5IfsGZy6Oa55NL7abKuEy
         hKONxYSJgF4Ms10RxidWMQLVX0YW2tAVc/9wDQDkAyyCNw7FNmJTZzAHxu5VJdTGJlDO
         5oTS/khXqW4khnGos/d+QELoKbgbic6HGrf4bFTPnOyR7ps8lE8bXvhI44p40+NAxu+O
         os8Ve8PhhcV/QrnDnt6nD8v4zwaPUGvo6lCNN9mxxmVZLxClhtgkVBgio4qsQu3UGeZr
         W2Ge+SrFEzswNcgVlCU+Zwin7Djhhs8V0IrD/Zu/LRNtjF1huy3uYzo0pnEY9VCFJimO
         5tZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5o7fJNisPpZ7jBsGEcJYnAmDU/+T32pWaW+aVWLfK0g=;
        b=UgPk2gEI/5snJoEKi5Lww/1ScaNi36BNtofT2lyviBfmlY/5JaVHXDkZ7ejn3eGb6C
         ZxHv3AeLcArtjYN2wbfrHpLM6F71ICmPkpAg2v4LpAe+D0AMF36+y9UXVh+Pr08m8iY+
         2LJbrupaP9fQp+otSG07yaiQWMZ9DX3UH2lzdLvATs3evuLiAXHCdz3KK41Z+9iWcpam
         Xjh+GhBgRKxDj5OAzL4kWjqKuf3FOhXLNJq5LMpzUmw9lFXa/lQpNia5dFoA8bvQH57E
         zRKRuNOgoDuGdoI4SI8eQATurj+oW6tYD6pnmnysSFF7SBuzzDUNrPBKhBN8DzVhIqR2
         1Ihg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="onsW+t/Y";
       spf=pass (google.com: domain of 32rn_xwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=32Rn_XwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5o7fJNisPpZ7jBsGEcJYnAmDU/+T32pWaW+aVWLfK0g=;
        b=cpBO0W0GVFJRZjIi+2FMX5iqzVO1HVsnPpOEnIi8BUdI7iDey2+tLQJRZPekywqAhn
         A/atDkJEjyevMwLbD57LrAbtUVShZsqe1ENgFw4rkvyzUf8HVgT5gESfrRJxdjqDeDMq
         qej+e3CKau0Tco5lfmUCpC3lihLLRgeZiYeGX7gwIEaC2n5fo4chKqUxbEzxRaDwlEo7
         oniAqjzqP5lEs8Wkx09Z10z3/bXhU5GgKrxe6nSZZCsVuX0oX2GTm3pGQBDPCnwrQyeN
         MxeogpV5TPczOIJmSd6IA3vKuEDFhhjgzT7iOxlj9oGvIWp7k2i6sitGh/YK3Y8NGdrX
         qRLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5o7fJNisPpZ7jBsGEcJYnAmDU/+T32pWaW+aVWLfK0g=;
        b=gb5iSp6cbfU5J2t46IQETZHbTt3mSvu1Rk1UyZ11vc91hiVsS7GVmC29gh0cAr8d7Z
         ww0xiA40IQLxlKWySxEO4E7OAKUL3BnJr5UnaQpOtEFqSZRtXSiI+w5aNHqmQ7NLPTcF
         P/0hTfLZiGcF0W3i7MiQ25CJEYNLlYwjCUXy9S3sI4tqyY21uFf/0BF2WNbHABa4oIW4
         /+zZD+NbayT1dJ6tQ48N2/7oVmwc4saN1JJviEr2VbQpFmZFlQ89uccrcxIAq/qt3+1s
         eJEYXRIUgvIX5YddNLnEjAnr9wxcX8OhYgFCwT8aT6pPEp347eQ2QodH06nqrpD/XZXA
         Vxhg==
X-Gm-Message-State: AOAM530FJGaVQGJ9RyxL75I9wmJynHFAWodzxuFg9GPfikpuQxr7IiPB
	e+usk/U/ACPezSDZtAnL1oo=
X-Google-Smtp-Source: ABdhPJzdbZHTT0mkcyURC1Wx/i+29R4oBIap8Inw5SJzpE/4VdelEK4E3YUkDAtiJnNktraWS/t/Iw==
X-Received: by 2002:a6b:8b84:: with SMTP id n126mr1401469iod.189.1610553817944;
        Wed, 13 Jan 2021 08:03:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:d81:: with SMTP id l1ls280714jaj.2.gmail; Wed, 13
 Jan 2021 08:03:37 -0800 (PST)
X-Received: by 2002:a05:6638:3012:: with SMTP id r18mr3029549jak.13.1610553817543;
        Wed, 13 Jan 2021 08:03:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610553817; cv=none;
        d=google.com; s=arc-20160816;
        b=NGIo/pkNH98fZJGsJU826PRQhnpGJYFRNGztPCJTGcgUntteYPKH+4LSOKIYOb5G0j
         eL9ibvvpkTA47CbnaUb4i1GATu+tmLhmVrpdZjalqXkQ1r02fvOuR66LzlU9S52EHRrU
         n8dPp7gjB5FxmMOzCPkMGPsof8Lf6pilrzf0TGx7vYp4X0Pq20BwomdiShY+s84fOVRW
         lWer8534/dM8KkzYef0Hllp7Xqy19WOBHTpOrIj+bTr9mMF4+Ky7mT3zonj+HE35T3Qe
         tEGCiDomArI6ODRF23P3+T27Ew08dAUyDBwdZsA+l+bImqv/LAU6MLxVMJ7l9l77k8L8
         NCag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=S1gB0mX83HDDRDaVYmLzCgZEsoFxFZ697ly4fdy8+Ks=;
        b=BA+1PwmgED6MhzcBj/5xFmykVjw16OW+KfrYR52cPxdTFCPlzcJBHzn5asjTmI3U9Q
         Q3/0lgY09YR0y4EcnyOEgu7Vxf/dIvmHu4QZ4XU/bNSdR7bmFgYGtd94hfBfI01PvNir
         7STZVPqoGOBFzjTrct6mawp0oCqcOAkQUVU94ThdGX6OtmIPNkBQdIrCa4i821Bbjz8B
         SNFsLH7MifDPCuakqnLoZzjjGWQK1zIZr+manc6B5xY3sFyicKt4rZ/iK1fb/mBt8Pwt
         ei3osyxWoGrZTmj0tOYLgzq8uceXBSk7HgCkM2Kc5IMuZwW1+NNNfIMhPm0SwFJggPlH
         hq3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="onsW+t/Y";
       spf=pass (google.com: domain of 32rn_xwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=32Rn_XwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id s10si134910ild.2.2021.01.13.08.03.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:03:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 32rn_xwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id d7so1643254qkb.23
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:03:37 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a25:ac1f:: with SMTP id
 w31mr4193358ybi.87.1610553817007; Wed, 13 Jan 2021 08:03:37 -0800 (PST)
Date: Wed, 13 Jan 2021 17:03:29 +0100
In-Reply-To: <cover.1610553773.git.andreyknvl@google.com>
Message-Id: <7fbac00e4d155cf529517a165a48351dcf3c3156.1610553774.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610553773.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH 1/2] kasan, mm: fix conflicts with init_on_alloc/free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="onsW+t/Y";       spf=pass
 (google.com: domain of 32rn_xwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=32Rn_XwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

A few places where SLUB accesses object's data or metadata were missed in
a previous patch. This leads to false positives with hardware tag-based
KASAN when bulk allocations are used with init_on_alloc/free.

Fix the false-positives by resetting pointer tags during these accesses.

Link: https://linux-review.googlesource.com/id/I50dd32838a666e173fe06c3c5c766f2c36aae901
Fixes: aa1ef4d7b3f67 ("kasan, mm: reset tags when accessing metadata")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/slub.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index dc5b42e700b8..75fb097d990d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2791,7 +2791,8 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
 						   void *obj)
 {
 	if (unlikely(slab_want_init_on_free(s)) && obj)
-		memset((void *)((char *)obj + s->offset), 0, sizeof(void *));
+		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
+			0, sizeof(void *));
 }
 
 /*
@@ -2883,7 +2884,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 		stat(s, ALLOC_FASTPATH);
 	}
 
-	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
+	maybe_wipe_obj_freeptr(s, object);
 
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
 		memset(kasan_reset_tag(object), 0, s->object_size);
@@ -3329,7 +3330,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 		int j;
 
 		for (j = 0; j < i; j++)
-			memset(p[j], 0, s->object_size);
+			memset(kasan_reset_tag(p[j]), 0, s->object_size);
 	}
 
 	/* memcg and kmem_cache debug support */
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7fbac00e4d155cf529517a165a48351dcf3c3156.1610553774.git.andreyknvl%40google.com.
