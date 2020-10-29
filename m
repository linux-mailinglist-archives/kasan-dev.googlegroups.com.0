Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW4B5P6AKGQERO3N4KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 89A0629ECA1
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 14:17:15 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id b23sf1095881wmj.6
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 06:17:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603977435; cv=pass;
        d=google.com; s=arc-20160816;
        b=TtjDBHde7IiaGbMTqrYv/fHxshQdRr6EkuZsV5yRYVByLo8+FO5FblL/2rl+YyOmsi
         lkGxOsyg+ZpHHp6tU6zD8VEKYgW4CIhpQU9cAyHxMl+itESVnkL+TQ5uV1FwgBOt+ezT
         i0Fto2bnOEYH8npul03CkTEUdH+jdHTT0IBFciBqsfAQ9bIugzgnAuRNsg4h7w4M6SCS
         4E4wpBBIlpFksVKBoffvjEDtEhnrqMqorlDTjb3AqCwkXHOEdnFfe9y9T83kTtp9GaTH
         5lhKlwHey/zpVlUzr96Y17yh5muSs6T04Ay7wblJeRVmlmOPbuW5JVLJLMS/JLujjZ8s
         ShxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=HwrafxEPh3YA8kKReCrfIujOoPwx+HkVGP2zRl1tu+c=;
        b=cL4gWkFmJmZG8Sg7BDE/UFjgl7nh/vu1BLj7H+O9Bmq9qGQnpM89VCYnvaRRkZhXNr
         pTbtjVmuiM6egvHKvscPCijy5RdvQW6X+4vilxoqRkp0sDGfuP0gA45kT1kSVoll07Uh
         2Uio+Qe4wRqXKKbMtgOYAQZ57U4x28bRBbWRdN4ikTc5dYEOMhrN7PQYJYpf0MYgEmdt
         Y/8JyXYhdcN75FAFAeY/X8z+6ZGRaTK4aT2eKGubZHkvk18FW/UySFNQj0LFc8BV3r9z
         Ocd9JcIFBym50nQNX36iwUhhhyqmmzqJyZt4f8321/AfLsOEiNWNoydxqIBFEh0U+2rv
         H2oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kQJZtCyA;
       spf=pass (google.com: domain of 32ccaxwukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32cCaXwUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HwrafxEPh3YA8kKReCrfIujOoPwx+HkVGP2zRl1tu+c=;
        b=LbEKDRgUB3fcLa++GQbcZZ147XHK1/wx/JjxzPonq8jta+1y7nj2mzX5NIg5c2wB/8
         ZQXpeIZC76hlV4yX91g0HsIjzluxF0gQd8DSDW//Mkyu9A44pjyT47d/5GBPIQkEYVzw
         uCs45HQOwG978nHxf09APqFMow5z/S7A1PBmYn98RqPG/d5cp2lmJn1CZnhtJdEKDTF6
         DItaSEOpsIQ5NJ4MMD6lX9zjNF6SeOsQ9qEV2lwgd1Hg5vyrCWgjQarc0JgREZY6x68/
         EiN1VaL7jfatajmJQrrwSfeMvgKDGAueJm9f1dnLXcCYW3M8r8py1rCAeKlstg3azf4u
         gSCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HwrafxEPh3YA8kKReCrfIujOoPwx+HkVGP2zRl1tu+c=;
        b=MCy++hNBVa3P53lBJeUyiatoQ7eyDhypt+av3h/WHqX6KJwzZ5V0ytfmQ9pQm6GaG8
         QCSb9btjvT0WZ0PG6kBI2zqHBB0jRyvO83EN6elBGSvlMFtsyPzVxjpVR+BJ0ULOuI6h
         zRuLixYtTzupCOdNLQpasqilUUNrkC5a/ErqP0P3KyrAybDVJysTGIpS1Y96jZBYGxNv
         DmwtTPmojeyF5Ob4bwHURuV/yZDMa/iMzhyFKucOSs+yz/PVLK4dLDxYgQb9ZxXPBt1Z
         11HuMNZjKQElimWVwSwltEl8vCiPMjNxQyXxrnupGm6+ohmwc4gQ6lVR2VfFVuNsVSur
         oHLQ==
X-Gm-Message-State: AOAM531vlMFQwJrJjVCHltMPJ9+zF0qPNi7b6QEKstq0b8vTrt+t4JwB
	leMnsORF7HCs/mWAfJx9DXE=
X-Google-Smtp-Source: ABdhPJyrF1E2NOK1vNBllqfFk/WTKfIpddbb4zSCwW8rTz5bmIIBLgYrsR91nSFxwEtHrCWByqwK7w==
X-Received: by 2002:adf:ed52:: with SMTP id u18mr5846882wro.357.1603977435232;
        Thu, 29 Oct 2020 06:17:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f7c4:: with SMTP id a4ls1159383wrq.1.gmail; Thu, 29 Oct
 2020 06:17:14 -0700 (PDT)
X-Received: by 2002:adf:f212:: with SMTP id p18mr5755875wro.386.1603977434287;
        Thu, 29 Oct 2020 06:17:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603977434; cv=none;
        d=google.com; s=arc-20160816;
        b=QCdMJ+Q1uhs9rssus0J7pdAmspAw+x9dgYIAeC+h076dY1tKq2NxLGX0waHt/ULPgO
         Y3Bm71JYHuh/f8/iBu+t0ytJgWEZWzIatqQBcj9lCzG5fDYdmfceJJoiDtGuzsT4Vo/z
         pfTuxWfqKljc5y9L5jbP5kwIcj0QUM18E8nb+PqTY/hdipuZ+imE+Zqy+xhP3tGfURUc
         7jy+j1Dz5xiZoQcZSs7+eeKEgx4HQpFHKLNYJ4Bt5JP8xOoeOSt7ac9k+5pWz7SNAB5y
         YAZwQMjRMTnngyxzc9qU6Nnus16mWo+n0kQ5S63n6K6Y3HV1DmG3fLfcsBmJRL0X2HYm
         iUCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MDxWQURSl79g8vKPdG5uHAVWcBR/CQ6D0GDay6Dns1U=;
        b=LCf2V8A/dhqa/CIul51Fw2iRCuajfekryz4AcSVckwxR8ZY/5MvJDBlvAzgzPrhPR+
         aQHp2ppnK/pgsISlTcSM2EO9Al45JPqGPe4yahTOj8yJyAGnLc8DhCXRT3fARf0QzynL
         Tn15fIQxtQbfy8bUb5l2Wj7AFx/x0fCSUOoRSJ7Li1ZstfCxVKlTJzIu+uQHpQ/CcPdc
         RrOsXnb99YbMcKpo0rzLRniGuDky9RIMAoJI2owe96cLTY1oXm70xxy15bA3fU+wFncq
         T/ixp/XnYDtpOl93z2sG39mdIVBfMffADz4kNTh3cd9NI6CsFyf1rQAt2a6E01KGG9Yd
         jf0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kQJZtCyA;
       spf=pass (google.com: domain of 32ccaxwukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32cCaXwUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id w62si67625wma.1.2020.10.29.06.17.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 06:17:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32ccaxwukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id e15so210265wme.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 06:17:14 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:2901:: with SMTP id p1mr4533662wmp.170.1603977433686;
 Thu, 29 Oct 2020 06:17:13 -0700 (PDT)
Date: Thu, 29 Oct 2020 14:16:46 +0100
In-Reply-To: <20201029131649.182037-1-elver@google.com>
Message-Id: <20201029131649.182037-7-elver@google.com>
Mime-Version: 1.0
References: <20201029131649.182037-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 6/9] kfence, kasan: make KFENCE compatible with KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kQJZtCyA;       spf=pass
 (google.com: domain of 32ccaxwukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32cCaXwUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
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

From: Alexander Potapenko <glider@google.com>

We make KFENCE compatible with KASAN for testing KFENCE itself. In
particular, KASAN helps to catch any potential corruptions to KFENCE
state, or other corruptions that may be a result of freepointer
corruptions in the main allocators.

To indicate that the combination of the two is generally discouraged,
CONFIG_EXPERT=y should be set. It also gives us the nice property that
KFENCE will be build-tested by allyesconfig builds.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v5:
* Also guard kasan_unpoison_shadow with is_kfence_address(), as it may
  be called from SL*B internals, currently ksize().
* Make kasan_record_aux_stack() compatible with KFENCE, which may be
  called from outside KASAN runtime.
---
 lib/Kconfig.kfence |  2 +-
 mm/kasan/common.c  | 15 +++++++++++++++
 mm/kasan/generic.c |  3 ++-
 3 files changed, 18 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index d24baa3bce4a..639b48cc75d4 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -5,7 +5,7 @@ config HAVE_ARCH_KFENCE
 
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
-	depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
+	depends on HAVE_ARCH_KFENCE && (!KASAN || EXPERT) && (SLAB || SLUB)
 	depends on JUMP_LABEL # To ensure performance, require jump labels
 	select STACKTRACE
 	help
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..ac1d404fb41e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -18,6 +18,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
@@ -141,6 +142,14 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	 */
 	address = reset_tag(address);
 
+	/*
+	 * We may be called from SL*B internals, such as ksize(): with a size
+	 * not a multiple of machine-word size, avoid poisoning the invalid
+	 * portion of the word for KFENCE memory.
+	 */
+	if (is_kfence_address(address))
+		return;
+
 	kasan_poison_shadow(address, size, tag);
 
 	if (size & KASAN_SHADOW_MASK) {
@@ -396,6 +405,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	tagged_object = object;
 	object = reset_tag(object);
 
+	if (is_kfence_address(object))
+		return false;
+
 	if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
 	    object)) {
 		kasan_report_invalid_free(tagged_object, ip);
@@ -444,6 +456,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (unlikely(object == NULL))
 		return NULL;
 
+	if (is_kfence_address(object))
+		return (void *)object;
+
 	redzone_start = round_up((unsigned long)(object + size),
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..1069ecd1cd55 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -21,6 +21,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
@@ -332,7 +333,7 @@ void kasan_record_aux_stack(void *addr)
 	struct kasan_alloc_meta *alloc_info;
 	void *object;
 
-	if (!(page && PageSlab(page)))
+	if (is_kfence_address(addr) || !(page && PageSlab(page)))
 		return;
 
 	cache = page->slab_cache;
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201029131649.182037-7-elver%40google.com.
