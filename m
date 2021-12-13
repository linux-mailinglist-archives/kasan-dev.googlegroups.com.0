Return-Path: <kasan-dev+bncBAABBM4C36GQMGQE7P6ZJEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E1ADC4736F6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:59 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id h7-20020adfaa87000000b001885269a937sf4190507wrc.17
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432499; cv=pass;
        d=google.com; s=arc-20160816;
        b=nMZkB2N5u0jUQiqnm57wEAVgfFFoq+u5EpmeW/LF4DdHOqWYvHWZSFFYR/5RHVSk9j
         JgqJoAn+nTvy5YjrbzKIieCjV3GzWfp8LnfpQylGzlH6KYtoJz4CM2Hnajb+0IXPeyjd
         vawKzmw+5sYztJDeiPgh8g7iD8H9u3j2Cr0wD2rzkIdVvQbe9EbY875CmC+L/d6EDLyb
         g1NJDd4sS/bIPUWVGNBBl8LGynW78eT7erhTacfiX1tvaPU9fJmh+FUAmR5pKdqgMiR0
         g9pHD2eiaDnqIBRGM/ZLngKaX4FBgCwFKqvyzHGHceX9m3I/H8osgEg8unUrt/mzacix
         NmsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rUpTxJCttFqjD0d766HzPh7pHfmK7EBZHy39KzJhink=;
        b=Y0awpd24BiLsO7kNLg/Al/6Ar8Yqio/IYDe1HH+NIsBn7kEq+qKZQ1hY7ShcqWRqD8
         jLLHTyg5NY/nnT+f/uA7ZDnvNKbO+6yX3NOaI826UIvID2z4h0Q2fBxzoFhZBRit8HYD
         Got9lO9EeipekAVmY4BUZbPJVNyOmbr9Zbb0342SO3//jsSgnANUJX24/Gkg4MlX5XfG
         yMySyBs8MPdNrq1zhqTpvt3WZW59BVyPRvPK5oLwBvHkp3ARq5y5LRYY29Xa2kVKoByy
         hCcNbUtLLX+LLwtxBZVBovnQtB5q+rh75s02MmExfwmqr4Fbgzj5K8kYRwkBjFhK6URt
         JMNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iD0YJWJt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rUpTxJCttFqjD0d766HzPh7pHfmK7EBZHy39KzJhink=;
        b=KSaNNIsjxkRnsLRTWx+MGJdjx+//oNEq9pgsikfqzHdjMalU7HFR0OFZRtTKBBU+iJ
         vJnj5SmRMC0/VT4xjdMY2sgLKfGIXdU89wgzizaRZFAMx9+TZapwQaJCZD9aeoZHxfyq
         lDPp0GY8+HSXOOwPjczb2iwvib0QgOzXB+VRl2/674N2PnvFZs5zBJi+jq+kMfvfE/dY
         Y0kF4v6M6giNElIHwhaGsjxVJsS0fCqBwsN1wd6vOpX9MeLOX2NiU37bdSiSqZpnMrEE
         21Wr+o3M5XOEMCjGbaUD1jU6ICxMA9bSbi1ZnsDG6n6vq77NBCBU55VBKWPuCAW9dryu
         ssRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rUpTxJCttFqjD0d766HzPh7pHfmK7EBZHy39KzJhink=;
        b=Ife7Z4CKMM5G4zJq9hlOhCbyYQH8gT0eC01e1DVbDzN11rMxDxpNviyerOYLcxpT6F
         IH/GUJW1bngAQPZtsj5mrlLP4ElB6ntr9smBtt7WbdrGdkgGqzkaprA4N/ansbNPzoU2
         uUN2lEPjLPGE+sUJ8BzmFfpvOJjdvlJx/So/K+bFkr262gqnqgNjL5+hjUilatQbhpXc
         wvQQxI0WN75JIMtTqk780mhuEpe1YpOT7dbKYrxujelRBHkmU0gb7qFFXavl8zvbeZk0
         jyIWy9aCU7JLtUuLzfzFeRlQP+Sawl0nOpANJc32auos1QwWQuepS2RUigxR3iwHz3FA
         /szw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PL5aRqy4exbdSSxo9yD24v05pm/+2/UZl+IJEKQbhjVFt2nvA
	cG1igAYMqWors92cvTGa+CA=
X-Google-Smtp-Source: ABdhPJxXWw3E72/DEH96z3VRyZlNRcCLQZ4FU3sGalUh9tousH4pJzhwTvgpkhrytx3CFavCM53UaA==
X-Received: by 2002:adf:eb06:: with SMTP id s6mr1312990wrn.96.1639432499657;
        Mon, 13 Dec 2021 13:54:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls502297wrr.0.gmail; Mon, 13 Dec
 2021 13:54:59 -0800 (PST)
X-Received: by 2002:a5d:452c:: with SMTP id j12mr1281777wra.430.1639432499002;
        Mon, 13 Dec 2021 13:54:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432499; cv=none;
        d=google.com; s=arc-20160816;
        b=aUSiYnVH4igyiYB+24kJkeXt/6W/WkOADqcuuaXHRmkIgTGQFFehNBSTDo3penLX27
         WUM3bzfwJdmbKJezVfpmTVVWHCoZdEgtfLqO/rP/0xvQ9jgzSAB8K4+TsRxcEaMVdCdm
         tBts9J9K2wEwBH9LUPStulVQfjvtt+zKPY/7HnW2CIEQL7wI1yjRnbsTrZF0+YHGbas3
         3gX5dNQmzBXCAeU/q7UELieMS3h2DpnKOWWUOUI+Zl59TInBwpUSIJxowziS/zZQmyRo
         wRF6aVvEYoxJE6PQSl6jXD8iyVepY1tHLUd6S8SVxymVWVILZ/SVEN8PVmFHoGiUa6s9
         56uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TZxZRDJ7HgDBWryoV/MM4OEPaVEwd2Xw9Ku4jQ5lqks=;
        b=biTWPsQUJVJP7jubg2mkI8P6//vb1UOjkyERkkyQw5i4ou+kyG6/bBOQI5daTaBOQw
         8kVc48AOLaM/Bn1BYnihK9R/KzBJAwh+l7w5Whwb5DyKEUMpSKF8g0QlT3u/TiHylK3f
         nRIZXEQ53seM5PtIfwWEBqUjVK1D5MGWiRfmdb/UpeZZ7LSnB40USqc1eqxOh7pb8kMP
         AJceSznzD/GMSa7rBd0V0zDPkAEsbaokswgfOFglW35AD5GGPWY1Oi3t3PSl78i0Uuz1
         hhIeKmIyj5UJMRLIVXBNL1A4ZbUjg5+fBuAD+ZCz4fQD9Y5KsM4v2NIcYsrLmjthja5Q
         HnDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iD0YJWJt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id a1si570448wrv.4.2021.12.13.13.54.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 30/38] kasan, vmalloc: don't tag executable vmalloc allocations
Date: Mon, 13 Dec 2021 22:54:26 +0100
Message-Id: <c77f819e87b9fefcb26c6448a027b25c939f079e.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iD0YJWJt;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

The kernel can use to allocate executable memory. The only supported way
to do that is via __vmalloc_node_range() with the executable bit set in
the prot argument. (vmap() resets the bit via pgprot_nx()).

Once tag-based KASAN modes start tagging vmalloc allocations, executing
code from such allocations will lead to the PC register getting a tag,
which is not tolerated by the kernel.

Don't tag the allocation if page protections allow execution.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Add this patch.
---
 include/linux/kasan.h |  1 +
 mm/kasan/hw_tags.c    |  7 +++++++
 mm/kasan/shadow.c     |  7 +++++++
 mm/vmalloc.c          | 10 +++++++---
 4 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 499f1573dba4..11f29c121bee 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -30,6 +30,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 #define KASAN_VMALLOC_NONE	0x00u
 #define KASAN_VMALLOC_INIT	0x01u
 #define KASAN_VMALLOC_VM_ALLOC	0x02u
+#define KASAN_VMALLOC_NOEXEC	0x04u
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index de564a6187e1..bbcf6f914490 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -246,6 +246,13 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	if (!(flags & KASAN_VMALLOC_VM_ALLOC))
 		return (void *)start;
 
+	/*
+	 * Don't tag executable memory.
+	 * The kernel doesn't tolerate having the PC register tagged.
+	 */
+	if (!(flags & KASAN_VMALLOC_NOEXEC))
+		return (void *)start;
+
 	tag = kasan_random_tag();
 	start = set_tag(start, tag);
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index b958babc8fed..d86ab0a9dcc3 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -488,6 +488,13 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
+	/*
+	 * Don't tag executable memory.
+	 * The kernel doesn't tolerate having the PC register tagged.
+	 */
+	if (!(flags & KASAN_VMALLOC_NOEXEC))
+		return (void *)start;
+
 	start = set_tag(start, kasan_random_tag());
 	kasan_unpoison(start, size, false);
 	return (void *)start;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 4171778922cc..75afd6c9bc3d 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2219,7 +2219,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 	 * With hardware tag-based KASAN, marking is skipped for
 	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
-	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_NONE);
+	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_NOEXEC);
 
 	return mem;
 }
@@ -2458,7 +2458,7 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 	 */
 	if (!(flags & VM_ALLOC))
 		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size,
-							KASAN_VMALLOC_NONE);
+							KASAN_VMALLOC_NOEXEC);
 
 	return area;
 }
@@ -3133,10 +3133,14 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	 * (except for the should_skip_init() check) to make sure that memory
 	 * is initialized under the same conditions regardless of the enabled
 	 * KASAN mode.
+	 * Tag-based KASAN modes only assign tags to non-executable
+	 * allocations, see __kasan_unpoison_vmalloc().
 	 */
 	kasan_flags = KASAN_VMALLOC_VM_ALLOC;
 	if (!want_init_on_free() && want_init_on_alloc(gfp_mask))
 		kasan_flags |= KASAN_VMALLOC_INIT;
+	if (pgprot_val(prot) == pgprot_val(pgprot_nx(prot)))
+		kasan_flags |= KASAN_VMALLOC_NOEXEC;
 	addr = kasan_unpoison_vmalloc(addr, real_size, kasan_flags);
 
 	/*
@@ -3844,7 +3848,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
 							 vms[area]->size,
-							 KASAN_VMALLOC_NONE);
+							 KASAN_VMALLOC_NOEXEC);
 
 	kfree(vas);
 	return vms;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c77f819e87b9fefcb26c6448a027b25c939f079e.1639432170.git.andreyknvl%40google.com.
