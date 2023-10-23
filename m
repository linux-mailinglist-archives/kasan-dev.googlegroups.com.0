Return-Path: <kasan-dev+bncBAABBJ553KUQMGQEFPLTBIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D7E627D3C67
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:26:17 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-50483ed1172sf3382966e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:26:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078377; cv=pass;
        d=google.com; s=arc-20160816;
        b=jgqRMp87feEPDdU7zaX1Uzp2WXs3AmwokbyJ+0Ue3CVnibDmnkKh+OPm38IqO9dEhR
         Kg9V2BImgdpOa/xUaph5BWs6YipQWcTjntqrMv680W7owR8P3P2wSPuB/zuOOGKky2RG
         rdEvppGjr6mBknLUrjW4akOlUo7jjyic9vEaGfjHTUwMf3BUuW8RKn8ejOm822LdpR5V
         aKHePUPByiBkoOGij7QHcxxBAFFiNBsmERofnEKoJe7kOn5LZNUhyPE+K6KEtYzA31yt
         xv1K/wPMjXU2qBUjHpwLaXl+/XZLlb+QEjCeqCJq6uuu3Sz0fTRhJDVDllzq4/3hGe8Z
         F45g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=28R8ZGtF26VXCWrHeuD+9q/NyJV4EGjYQ89KYa9cP1A=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=0aWIGDUDgzNmnxrXpCgRWcvBnYJoBnwnYiHfQSMtYhmcegRVBmi6f52uv6fdt91xS0
         KWBMVwAo1RP5Ib7+LEhTb4folrzInirupElDduBG0ILLqfxpXyTOhd9AQCOkvyNxOrsZ
         PI+nZPTJYX2vYxPfOaWyuBn+PdX4bj12CVMfK4iAago42KBBl31lkgxDOUDr31o6EY80
         XbwbE48N1grrD73+Rlo5bsyLGSmBAFS7FiL8m38HWcVV/i22nMhX5KwvuVGgF7Dv3yZg
         /SsXAxXmqp4qKIputOz1WKq2OLAvJyD+lUM9Rj0LpITc8u0Ja5npjAGi+sL0NK4WzQyr
         EVIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Tr/G6YIY";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::c0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078377; x=1698683177; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=28R8ZGtF26VXCWrHeuD+9q/NyJV4EGjYQ89KYa9cP1A=;
        b=DlYz7RcH42UvoxGo2Ki5/u/aMG7FWmoiwzIK+uyiuML2+ByNI4vkJ99N7hMuFdWOem
         KX+XmGi4q5zDKOGchYFiQSrALLEBhZ7tJTzAhyJtfhGhbqt/7JC2I4BB2/2TZaOjjzim
         mmUwLaFAC0/GBveMHij/wrruOrqpJ9kO6fb5rTh1hJ03XdOjMt5TXoudkqusWV/iZcop
         sUsawJMmEe9DdVbYRfIMu9OPOQtBZwleiNgnMOF/J7Ce49dBLs4xuYsyakVGzzFn4Qe/
         FVp8tSfXHEs1nuPj9mcQtEl2IIgTbjufsC1RE8uL9kCi4pyCbmFVYdQgdiLbYGzZJgSb
         g0QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078377; x=1698683177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=28R8ZGtF26VXCWrHeuD+9q/NyJV4EGjYQ89KYa9cP1A=;
        b=YXrHpGO6zGfiroh5zk2rPIaDCMpMez6WOW37h2V2+qJ/ivgCyBwK2yvS1FulVT44H5
         oxCA1oiIslKJ4JVoSWZ8XpPyZi8XOHkIld2jqxSHePoSG5LXS/jPjsZIgnVVu+GtuIIG
         KIlw5NLMDKGNGY/p5yXdIEzAOc8gIHRI2GIKgRoMEm+MQQGrH5X0oSjqJMH9OkkX38d3
         VOvDJGmSe9fRNKkgux45Cm+L1peRDwtf93ydfMxpOEted+QyHKmXM4zUTysqJ67B/dd8
         rbVGEZd3zCl7aZtxYrrrnVu5SwsFVjlqEBdRBpyqcG7G/zwIyAVGlBPbqXwcJMEdzaTF
         dyvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyyOwQFzEjOmElXQLaxx0R0OtqQyIxMZiHb+8f9wCFgThKdczWD
	5BDONXjAC17DVwu2EL0Mf/U=
X-Google-Smtp-Source: AGHT+IF8OJrUxn+F2EP89KIx5PNOkQ2/E8FX3Xpm0qKGdiEuuvfQV+3RFXQoJg3BRYcgtHmnWsxpbA==
X-Received: by 2002:ac2:5df0:0:b0:500:75e5:a2f0 with SMTP id z16-20020ac25df0000000b0050075e5a2f0mr7149352lfq.51.1698078376187;
        Mon, 23 Oct 2023 09:26:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:52b5:0:b0:507:c72c:9d86 with SMTP id r21-20020ac252b5000000b00507c72c9d86ls409873lfm.1.-pod-prod-01-eu;
 Mon, 23 Oct 2023 09:26:14 -0700 (PDT)
X-Received: by 2002:ac2:5a5d:0:b0:507:a6e9:fbba with SMTP id r29-20020ac25a5d000000b00507a6e9fbbamr6176991lfn.63.1698078374612;
        Mon, 23 Oct 2023 09:26:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078374; cv=none;
        d=google.com; s=arc-20160816;
        b=jYKFr6IHEsfxASIoHOzC0/gq8f9tOKv2HzOnuiZmROmUkmbRqdFsS6Wq5vEFwyFV2R
         w8VRvBEKwpa9DrcypliIWiwoxhhGE2aPtxmnKNa3XtmpqRfTnsTmov4o4D77TB6jCDzw
         aEkaSe0XyhdlgqUVXOnfoFPDssJ+NA3ZTynRRhMQa8wwLocfOyPBO1RdwslOipB4HATW
         TjTOlTDbL369dtc7TkxMmbyU40E9C6FDagJWwGfT9zbFtGqRdCAXbaHzEHc19QEZ4Pwk
         caN0SlNslRaN8+6BLA8SIW3dGUcbHEnDXZkOWiEPskMqfffgfihaQmfE6kQKfjwrXEcM
         YGQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Qc2DDhk7eSddbt2Q3kjJLSbCNGbLZWOl9JsGZF81sG4=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=zuhmrD8M643m9Eapo86BP5KKa03UD4iKh5Z+wZTDDPp+0UoyFAMztaVrLyciDlGkvm
         VXoJfjZctWHi1FdPj2JlNr2OrxGTe7lrRZi5bD7opYPnuqRH5p8+4dKbjoC/GZH4aM3I
         EOZWbSBdkS1f3uBDFAuydElj23tx5S4T4FZkAPV5iU7cYFmSN43JfJnQfKCY5nows7AD
         L5YB/VvlprDmCbQkvHHjWagvg8BmzoO89672OHbLkoYBomyKGHkrCd/bter5VITxYiSL
         UfccNZi6nktzWGbt6jP8qxojf1UviCYf4imNcJLoJSV3YcK4KjNerohLRTP3F+MKDncL
         rFHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Tr/G6YIY";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::c0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-192.mta1.migadu.com (out-192.mta1.migadu.com. [2001:41d0:203:375::c0])
        by gmr-mx.google.com with ESMTPS id bp28-20020a056512159c00b004fe3e3471c8si309753lfb.10.2023.10.23.09.26.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:26:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::c0 as permitted sender) client-ip=2001:41d0:203:375::c0;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 19/19] kasan: use stack_depot_put for tag-based modes
Date: Mon, 23 Oct 2023 18:22:50 +0200
Message-Id: <c4219b3f0a193b224a93a6dffb191f212c4eee4d.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="Tr/G6YIY";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::c0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Make tag-based KASAN modes evict stack traces from the stack depot once
they are evicted from the stack ring.

Internally, pass STACK_DEPOT_FLAG_GET to stack_depot_save_flags (via
kasan_save_stack) to increment the refcount when saving a new entry
to stack ring and call stack_depot_put when removing an entry from
stack ring.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Adapt to the stack depot API change.
- Drop READ_ONCE when reading entry->stack.
---
 mm/kasan/tags.c | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index b6c017e670d8..739ae997463d 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -97,12 +97,13 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 			gfp_t gfp_flags, bool is_free)
 {
 	unsigned long flags;
-	depot_stack_handle_t stack;
+	depot_stack_handle_t stack, old_stack;
 	u64 pos;
 	struct kasan_stack_ring_entry *entry;
 	void *old_ptr;
 
-	stack = kasan_save_stack(gfp_flags, STACK_DEPOT_FLAG_CAN_ALLOC);
+	stack = kasan_save_stack(gfp_flags,
+			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
 
 	/*
 	 * Prevent save_stack_info() from modifying stack ring
@@ -121,6 +122,8 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
 		goto next; /* Busy slot. */
 
+	old_stack = entry->stack;
+
 	entry->size = cache->object_size;
 	entry->pid = current->pid;
 	entry->stack = stack;
@@ -129,6 +132,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	entry->ptr = object;
 
 	read_unlock_irqrestore(&stack_ring.lock, flags);
+
+	if (old_stack)
+		stack_depot_put(old_stack);
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4219b3f0a193b224a93a6dffb191f212c4eee4d.1698077459.git.andreyknvl%40google.com.
