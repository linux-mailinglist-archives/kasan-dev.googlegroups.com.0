Return-Path: <kasan-dev+bncBAABBENFVDEAMGQEJ5VMEFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id BC098C319CC
	for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 15:49:55 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-4331e894f41sf4514795ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 06:49:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762267794; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y3e2eCEadC/9MQa8pfAf5/BmTPiHHPlFetNpFZswyurUqLMi8QfqX8J3mRTMQ9Z4lW
         9Eb2jUW1oWj6MOvl+vBVcH/A5dYu1imCxzBJlqGXlsvlcW9rrd/zhxfFaLrUO7okDFIf
         qU1ueHsKQWMXuf9rD+idg/s97XVIss0C97g8gh3VUZu90ukUwLfGw7QV6zD6SPx5ihpl
         YVp3v19ksBkVFgoaf7/GJqGd/D9q2MwUtbR0Wy965jgJx4gVQsL0vuW3YhUzQpt6yM6+
         T6Gfew6BQuj8uF/51UiH8z4IoZr7DTKgrS0AJJrGNNBoDUb0G5T8GFbU2j81bUGFN9hb
         7zAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=r+7CC17VSRDGEC10Z7VU6d8PX1CERrebeEnbJgUVEjo=;
        fh=oQnSFnMer2vNnExBv6VgmNu3f+aUuN+p675EQEE+q3s=;
        b=I20bomtqtXj2TLxJFA64Th7flnkBfpZPsGk7s/0eZgj/FAwx3YgG3gzQEx9MOlN8Gy
         3GLoV6gyClFpNPU1xXPb8Moum+WGPkBn97d5c+K+2bHJveJ615lzZwE449v7fTUJ/tYk
         8h1IDj19IrPDZdDFgB2W8LRN9p32XpBhooeEgffdKIpXBeWXOFv4fKcVpHkIP9kSVcik
         l74VVqEoZNktXK9zJ/Lvf5W2u4B6fUEQbYiQGpqenjJ5J4rNuEbC6/tDsYVRzZI/HyUQ
         S2rejMbzmXB156/RWdaSdzaeM7KU3HDRN8/22qEEkg+2zvvfVSQfm3tHgnkJ7rFx2gqK
         Lx5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Q45ZqZeY;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762267794; x=1762872594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=r+7CC17VSRDGEC10Z7VU6d8PX1CERrebeEnbJgUVEjo=;
        b=IC3xU9Z6VSwVzHg19Rqx+b+k1/T701veJMnZqiDpYHMQbsQ4ydSv/I9kjUe3Lj0YU3
         VjMqE6pTCxbt6Yy34M6RBx68qIeu0fmoqmohtiSbZdIV4THOvBGrJskdXDR4CXGyF3Ex
         66PbB1SQdnTWQHygQzxwlfzofuZbl+U/OQaQG+2gAROWwQ8D/ZmFIN5OqTQFo3bBxeZL
         aRq8VAp3wDvn6eLeZ6C60FgdyYD4QVJQIJRPQ8ERYUdRn9WjQQWReoRrOxel+mDi9TQT
         dfJaZhoENh6tZ1xLnlu9bYE3qcw1Y7AmKIMVeg46qj5w6LIjK6p/y752/xhg8HT8U0Po
         BU5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762267794; x=1762872594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r+7CC17VSRDGEC10Z7VU6d8PX1CERrebeEnbJgUVEjo=;
        b=P7xFK4IJOCQC5rnrlo4g+f3m3bXvoQRPDzGH+laX1zmnC5q1TVdWoqBi45FcY5O9lc
         6006nd8K296YH0Av5cRjzyM0tNBdZdkyoDLZyKVbzLeawGmVucsj/A2y3MzXaO8nkivq
         EN5yxEzngWFbEXJJQM50+mBNZMlplhLs6/CS4xxFMnLQ5eAXJWsbgj6mD2wiedCD7vqV
         RCRRtNoerxH2xMnvuaTx/z+rUbPumcfDSQ3VFibjSxvvah8CkljQ38gcmhzga3kRz8gH
         VPAkzvwHozqax+aE6lgGebRmBl2k03AoWYqHUGwQ4flwq4oJ5CK50LemmMFn8iaOtPQt
         xrTw==
X-Forwarded-Encrypted: i=2; AJvYcCWfT3nlmmqxxUv/4zl48Kn3g+YIkkEy/SSsESCHC6cVRSLPEB6sFxy1RpdYJQZNijQKyRoKZw==@lfdr.de
X-Gm-Message-State: AOJu0YxILkPQ1CI3De3lMErtMZLD6zvrq3a5jba+n4zslVV0Ocp9DYat
	xwd5DLAScaIM1258O3lNWxAbPpiqYUSyexldN6rGE/Cc78kRefP2St3L
X-Google-Smtp-Source: AGHT+IGOvR3XnNpiWwOzg0JY5qGdNB/pwBNgQkq5E8/NqF5Z86Eb5QyA8CftMqCiIHXhOcT69k93IQ==
X-Received: by 2002:a05:6e02:3c82:b0:430:a38c:b750 with SMTP id e9e14a558f8ab-4330d0799c8mr83475895ab.0.1762267793851;
        Tue, 04 Nov 2025 06:49:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bMbyqDO4PDTFtPKPHdcNVfZvGagliejO0vUbLePQvYpA=="
Received: by 2002:a92:c26a:0:b0:433:f64:7345 with SMTP id e9e14a558f8ab-433342ff775ls18678145ab.1.-pod-prod-01-us;
 Tue, 04 Nov 2025 06:49:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWwg6NOy4vqQ43oc8HGWV3kAMlY90+LNBUPRRfsIfHyeM/g0q8pljQST64Ur5wIrBV74HLfP7E6XI4=@googlegroups.com
X-Received: by 2002:a05:6e02:174d:b0:433:2b33:49ab with SMTP id e9e14a558f8ab-4332b334a10mr99369265ab.16.1762267792825;
        Tue, 04 Nov 2025 06:49:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762267792; cv=none;
        d=google.com; s=arc-20240605;
        b=b2jd0TGxcKH2FXuI8VhngR7KGZixWVqrlCr1I9bXUk2VOJWcdIOjaSYSkgI838FBvK
         +HVg5U1eAr3AZyuqGDyFL0O+TpkYo6afkk+HD8AiEj8mA3i2rjHHmNQodIjyoHxNz9h2
         vnXEtXzGDiLRwjHjaYEunhrw2hdfH5f8ZYrwTAWorqMdhiaMGs2n20wG0bliFtrV+/BG
         AZswgCOKv0WJ1z1wX7iyMq4cWDEiGCBCflmTF8/brC2KfRFn6rTpyZAIei3u64X+Pb8u
         u44ijw4YAXi+ZcrxNjDoEIqhm2I6BedXQ+WE7arz+veyb0gU/F+VAAPRoPqV1vywPN7i
         r2KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=6toufJLKljGqaHG5WZqQpO38Yv3Ls2e+KAx9dPrtmiw=;
        fh=4HLZnY/LwkQ1NZaGUlwkqPkg7boVQaaCQhIJz1rbYfI=;
        b=aJELHhEAvMCg5UwZkgGRaqF+6Ko8UdrTXiwVw886FD2/axPLiG3sNrN5GlRDP/+mHP
         YN/SsC1qMr/N3UggFOifCTf6NK81Ck0pjc0OXqZqdQMl7CLuA5pf742fLYCMqPZlk+QU
         15glEwVYThuQ3Z7w7yOuI5Xnz/ExisUDQuG4n2onOMswZtgHrzdvOkYCCD+5p8hHQJk6
         6+Gvo1uoLJlNO+vs3MEYClY4KcoSvnghgZsTKUNNFj+kk5bq95z7s1NQiTHK2pfiBgD/
         YLOiFF+FL+hI7nL7td3RQjMj9VWjlE/ONmAku9duHhVm4CiCFekzR+TyxhbLUhhoZt3v
         6jLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Q45ZqZeY;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5b72269f27dsi135302173.7.2025.11.04.06.49.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Nov 2025 06:49:52 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Tue, 04 Nov 2025 14:49:48 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: [PATCH v1 2/2] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <cf8fe0ffcdbf54e06d9df26c8473b123c4065f02.1762267022.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1762267022.git.m.wieczorretman@pm.me>
References: <cover.1762267022.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 55cd5ebacaac83958431436550ff0c47705cb95d
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=Q45ZqZeY;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

A KASAN tag mismatch, possibly causing a kernel panic, can be observed
on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
It was reported on arm64 and reproduced on x86. It can be explained in
the following points:

	1. There can be more than one virtual memory chunk.
	2. Chunk's base address has a tag.
	3. The base address points at the first chunk and thus inherits
	   the tag of the first chunk.
	4. The subsequent chunks will be accessed with the tag from the
	   first chunk.
	5. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Unpoison all vm_structs after allocating them for the percpu allocator.
Use the same tag to resolve the pcpu chunk address mismatch.

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: <stable@vger.kernel.org> # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Tested-by: Baoquan He <bhe@redhat.com>
---
Changelog v1 (after splitting of from the KASAN series):
- Rewrite the patch message to point at the user impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

 mm/kasan/common.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c63544a98c24..a6bbc68984cd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -584,12 +584,20 @@ bool __kasan_check_byte(const void *address, unsigned long ip)
 	return true;
 }
 
+/*
+ * A tag mismatch happens when calculating per-cpu chunk addresses, because
+ * they all inherit the tag from vms[0]->addr, even when nr_vms is bigger
+ * than 1. This is a problem because all the vms[]->addr come from separate
+ * allocations and have different tags so while the calculated address is
+ * correct the tag isn't.
+ */
 void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
 {
 	int area;
 
 	for (area = 0 ; area < nr_vms ; area++) {
 		kasan_poison(vms[area]->addr, vms[area]->size,
-			     arch_kasan_get_tag(vms[area]->addr), false);
+			     arch_kasan_get_tag(vms[0]->addr), false);
+		arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(vms[0]->addr));
 	}
 }
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cf8fe0ffcdbf54e06d9df26c8473b123c4065f02.1762267022.git.m.wieczorretman%40pm.me.
