Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJXD2CNAMGQEVACEJUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BA79608EE9
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Oct 2022 20:08:40 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id b13-20020ab0140d000000b003e39e1390f9sf3424277uae.18
        for <lists+kasan-dev@lfdr.de>; Sat, 22 Oct 2022 11:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666462119; cv=pass;
        d=google.com; s=arc-20160816;
        b=eTLWDGVlarYCtPPVl5PPh98cwSuPJ9uXBv0drf9+YszccalhoxoOZOFvfOPR/kIbI2
         rAidz1KGrX2EOoGETnspeHgltyRKEM4xQv8iZmXM+19qUnWNTgrzHBJIQWdjvt3N0ev5
         WPrOq1IxliIKdFbKnR36YrFLNMWYLGRz31rW0vnWyNzeGpjl7e5XkDyUD5EhYRI7e523
         VFya8hjcMYxVLeFJi1jzUn/bzOA+bclOVSPKlfNDcebL0OUNMdkUZ4SMgDC9moHOnMIt
         U7umQI7FpfAPKlokyRizp1S8rEu07HBfD+56Y+0REmXhXAcKELYbYH3XDObeMItD6w2a
         EA2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=igQL/VV4Wa38DUon2J4YforIwW4mB9eZyyqmavcphfo=;
        b=tgoXmoDls5VpzwoXOznTCre3FqNYseH1ujGj2xNt0B9GjhynrRoyk2QqoGt4cNHBR2
         rrsPN/GObasN6kD0PMLD2TjqMDGLtCpSU3A22/r3VBdq4qS5mjlCOEQZr0ywQOsSb0Ki
         FgBG80d98IYOm1xyoIx85aex8UHKEN8yx4PxRwYWXfc1ZdH0mBp7grMIhuKTKjPWV55w
         oKic8LHPrxZYJ7kJQ6DphHNzk2QT0v1eLGg0ll46DE0g73cDgro8mTfPzL3Q9vlfwzjv
         NGoWp5T1kge4Os5t+8jRJKVlVt8ArO4zNqfv70XMG4RnAOsyjvJaTm9su+O4QQc063tM
         EJ5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Hzo7fVyD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=igQL/VV4Wa38DUon2J4YforIwW4mB9eZyyqmavcphfo=;
        b=sOQPGbcYQyC1qsRMzo97l+rY6g24jsod1lNAUcya2mo47RWxvqPk7lLq2tEhaBMOKv
         Rwax62vv4+1yHw8MGmv89Fbs8FkWWLRwjEN9tmVcD7BkfmYdquXRSkmSoc6564RuhRLD
         AZo63OF2MDPqxTLFDqLa0ZcxVVI0F9bViP03K9rDCwPx8qTDaqpE0GAXnnbYjucY53WB
         u/WX215ucqib4S7+f3oZRuw98Xb0bLzPdQfCC4kla1Ng6ohdJB5tJyfNEIqj+gmNhWYf
         /utmN+NoRp6I08mA0UWlV7s8PGR2WzcevoLkN3gT4fFqDc6TpqBng5sqt5y9J5jTw3X7
         W2DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=igQL/VV4Wa38DUon2J4YforIwW4mB9eZyyqmavcphfo=;
        b=f5ywWrJz7XllUrDyy/gbw55KbBNrHV1oBrRSlv0onxOLTUuAymFSICmzsyFmrZpHQ+
         1Oy3pRD3tYw3UXAfUBM8Tk6iNO/l/WK9xJonQYK51jANfHimi0lY41URWuikmfKLa5vw
         K3hAf0w2/aE7uAo8FJttAnvw0ewjLnv+lCA8BX5MvHMEMfkImh8NJcP0/DCbypooclAA
         QOBQX5TX4+phFiUkfs3uxMHTa3+HfxigK41CXYdmyozr+lAN2602/1eToXUoQ5kJarOt
         vDRYh1acINMBsc5/HNRQnlLIieOPfgFQ8e4UXNL1vxQl2HgBld5wY6uhFRg9I1td/XEX
         jNcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1IVSzV9uuN3yHyOD3pqVUb+Ozw3ZS7a6sFB7v7I5FSpg6VxiVL
	uqdGSvplIsfaOGgTTAGO5Sc=
X-Google-Smtp-Source: AMsMyM6WFBA5TlR8BW3sdjArh6/z0Bap1LQElHRtttD5crU4lYGRdzUrM66Rr79FRszOxlxUx69pjA==
X-Received: by 2002:a67:ffca:0:b0:3a6:d6f6:302f with SMTP id w10-20020a67ffca000000b003a6d6f6302fmr14463376vsq.28.1666462118799;
        Sat, 22 Oct 2022 11:08:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:278d:0:b0:408:c6de:ef4d with SMTP id t13-20020ab0278d000000b00408c6deef4dls30055uap.5.-pod-prod-gmail;
 Sat, 22 Oct 2022 11:08:38 -0700 (PDT)
X-Received: by 2002:ab0:7789:0:b0:3be:fd5f:768f with SMTP id x9-20020ab07789000000b003befd5f768fmr16028672uar.109.1666462118085;
        Sat, 22 Oct 2022 11:08:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666462118; cv=none;
        d=google.com; s=arc-20160816;
        b=wKXbuxH5wcs26M/ppFy3YxzMxPi1gxzmVF+uVbAzp/aVX3XeJUoZZPx4ndRXdly+Mh
         ZabflmsRR0Kyu3v+2MzZif+VPPlUKwlJ72YTt7ECp+PoY4B4gTGaH1belX0vdb8GnzxP
         NR7OitYrEaY8+5jp/xAc/FY6HiHEBb51RtO6wosgVSZyyKLLsJlaKOD0UYvVsIGyOUYi
         dHejj4u7hjJXycVMFgb4bpsAbh5i1PwBfM/ZK6tl+ZoW2XOosbJ9lvFAC1GiirFooHnl
         p6zh6udwVyEPlQVImuNMWOgm2DQjOFpCpoD7zx/BnfE+PcdOcoQKvcTTMN7NsEzS5FYU
         6jgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=1a2EeARYSnWxiJw6oHJsoY33Y0se207PXHB1ow0Ga1Y=;
        b=K8LaYuCVng22/3qohaeEth3C8sbUncbV7NUU9EV3SEgjPlcMLdKHG9Xf/2MMfIyvbj
         YBfrHe4HSDpixK44x6axpqBheK298HibbZTKL2ltMH3No6ZzcPPuZlQlLCxy5IW7+iT1
         B+mwRTnhOSYGg87tW82HgZ/6vuFREt7z8+0slLfqN3uX5i1MpbLdfS9qpA4urSmZHdeO
         2YF7EymdQLUU3fq3dQOV326LZjypGcfkJtkc1QPxkAOtL51GPDUk6KswdJJZhLRBFPUQ
         Z7DJL688DltuE7QVkZwz54ipnZoiFhrGS2fWPD80+gE5OCloCrgQNFAC3/CVWMrBzf9Z
         Ug6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Hzo7fVyD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id n130-20020a1fa488000000b003b3b114b8ffsi233016vke.1.2022.10.22.11.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 22 Oct 2022 11:08:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 78so5258347pgb.13
        for <kasan-dev@googlegroups.com>; Sat, 22 Oct 2022 11:08:38 -0700 (PDT)
X-Received: by 2002:a05:6a00:2485:b0:561:c0a5:88aa with SMTP id c5-20020a056a00248500b00561c0a588aamr25296071pfv.51.1666462117133;
        Sat, 22 Oct 2022 11:08:37 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id w9-20020a628209000000b0056276519e8fsm10507248pfd.73.2022.10.22.11.08.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 22 Oct 2022 11:08:36 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Christoph Lameter <cl@linux.com>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	netdev@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] mm: Make ksize() a reporting-only function
Date: Sat, 22 Oct 2022 11:08:15 -0700
Message-Id: <20221022180455.never.023-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=5852; h=from:subject:message-id; bh=HZuoaDzt6/LPxyvOVuzqy3FtD9MM88oVQvBYI2b7PvI=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjVDGPT373RHlxlNzRB3FSVMPSd+3N5IOFs8nbEih6 a4JcCZSJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY1QxjwAKCRCJcvTf3G3AJg0sEA CJQgeNhzT7kGutiZ6DfvUQ98sYDiSG8cy5fz0XvctLjXFa0E+0jHWMYAU49DaTSiJAPjvkJtC3eGqU 6H9Yhzx9OnK6+3Pf6CkgpLB2j2roioL0N9/uKNk3O/B2Zg1vC5X5WSChvXQKKYa/DWRZFjm1hYuSe6 eJtnb4TJbTlAswbsKtrfUiRdurXNZNeo93YLboPpjS3Oui2Zmkjs3yXUfQ0wbI1EAg7/Lt76SiyOEk xNIhZchALtO+3yxGXJbt5/E4CJQNgHyzMQ3zidIrYmZSMr0kRDJiFI7yTRmMMI0lBclAXkUM9DX4qW hRRkLsDseezDlETYXdhqTUlsufdXvAkrRPatPCnP/z66b+G0HAlR4Op/K5RMvloMen54XAbuXSCb3f szujhc7zJ0Ivi0uis3misDev9gs4NVzX6jAIfK9HQaWVf5ybskYfX13uIDyQUgrDAJ2zz9nkWvzhs2 4hTLhJWpQfeMm38oPVkvCP7IbG6I4mdB1J5OdiYiA8VeriacD3+wR/UupDY/Jj8Jg7UfZ1mOVC8sv5 om+rocuJfmZOlkrezs1scXeeSujkP68ukOUtcdRMlNVkHBcNBzjUQ0SGgx0J2ToE0V2CFsQEG4XXjz 833VvH5PsOTeK7/T5CefUcbv4z3/iq4+gl9YtUf8Rd5EvVizs2QIsOzNYy2g==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Hzo7fVyD;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

With all "silently resizing" callers of ksize() refactored, remove the
logic in ksize() that would allow it to be used to effectively change
the size of an allocation (bypassing __alloc_size hints, etc). Users
wanting this feature need to either use kmalloc_size_roundup() before an
allocation, or use krealloc() directly.

For kfree_sensitive(), move the unpoisoning logic inline. Replace the
some of the partially open-coded ksize() in __do_krealloc with ksize()
now that it doesn't perform unpoisoning.

Adjust the KUnit tests to match the new ksize() behavior.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org
Cc: kasan-dev@googlegroups.com
Cc: netdev@vger.kernel.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
This requires at least this be landed first:
https://lore.kernel.org/lkml/20221021234713.you.031-kees@kernel.org/
I suspect given that is the most central ksize() user, this ksize()
fix might be best to land through the netdev tree...
---
 mm/kasan/kasan_test.c |  8 +++++---
 mm/slab_common.c      | 33 ++++++++++++++-------------------
 2 files changed, 19 insertions(+), 22 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 0d59098f0876..cb5c54adb503 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -783,7 +783,7 @@ static void kasan_global_oob_left(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
-/* Check that ksize() makes the whole object accessible. */
+/* Check that ksize() does NOT unpoison whole object. */
 static void ksize_unpoisons_memory(struct kunit *test)
 {
 	char *ptr;
@@ -791,15 +791,17 @@ static void ksize_unpoisons_memory(struct kunit *test)
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
 	real_size = ksize(ptr);
+	KUNIT_EXPECT_GT(test, real_size, size);
 
 	OPTIMIZER_HIDE_VAR(ptr);
 
 	/* This access shouldn't trigger a KASAN report. */
-	ptr[size] = 'x';
+	ptr[size - 1] = 'x';
 
 	/* This one must. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
 
 	kfree(ptr);
 }
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 33b1886b06eb..eabd66fcabd0 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1333,11 +1333,11 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
 	void *ret;
 	size_t ks;
 
-	/* Don't use instrumented ksize to allow precise KASAN poisoning. */
+	/* Check for double-free before calling ksize. */
 	if (likely(!ZERO_OR_NULL_PTR(p))) {
 		if (!kasan_check_byte(p))
 			return NULL;
-		ks = kfence_ksize(p) ?: __ksize(p);
+		ks = ksize(p);
 	} else
 		ks = 0;
 
@@ -1405,8 +1405,10 @@ void kfree_sensitive(const void *p)
 	void *mem = (void *)p;
 
 	ks = ksize(mem);
-	if (ks)
+	if (ks) {
+		kasan_unpoison_range(mem, ks);
 		memzero_explicit(mem, ks);
+	}
 	kfree(mem);
 }
 EXPORT_SYMBOL(kfree_sensitive);
@@ -1415,10 +1417,11 @@ EXPORT_SYMBOL(kfree_sensitive);
  * ksize - get the actual amount of memory allocated for a given object
  * @objp: Pointer to the object
  *
- * kmalloc may internally round up allocations and return more memory
+ * kmalloc() may internally round up allocations and return more memory
  * than requested. ksize() can be used to determine the actual amount of
- * memory allocated. The caller may use this additional memory, even though
- * a smaller amount of memory was initially specified with the kmalloc call.
+ * allocated memory. The caller may NOT use this additional memory, unless
+ * it calls krealloc(). To avoid an alloc/realloc cycle, callers can use
+ * kmalloc_size_roundup() to find the size of the associated kmalloc bucket.
  * The caller must guarantee that objp points to a valid object previously
  * allocated with either kmalloc() or kmem_cache_alloc(). The object
  * must not be freed during the duration of the call.
@@ -1427,13 +1430,11 @@ EXPORT_SYMBOL(kfree_sensitive);
  */
 size_t ksize(const void *objp)
 {
-	size_t size;
-
 	/*
-	 * We need to first check that the pointer to the object is valid, and
-	 * only then unpoison the memory. The report printed from ksize() is
-	 * more useful, then when it's printed later when the behaviour could
-	 * be undefined due to a potential use-after-free or double-free.
+	 * We need to first check that the pointer to the object is valid.
+	 * The KASAN report printed from ksize() is more useful, then when
+	 * it's printed later when the behaviour could be undefined due to
+	 * a potential use-after-free or double-free.
 	 *
 	 * We use kasan_check_byte(), which is supported for the hardware
 	 * tag-based KASAN mode, unlike kasan_check_read/write().
@@ -1447,13 +1448,7 @@ size_t ksize(const void *objp)
 	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
 		return 0;
 
-	size = kfence_ksize(objp) ?: __ksize(objp);
-	/*
-	 * We assume that ksize callers could use whole allocated area,
-	 * so we need to unpoison this area.
-	 */
-	kasan_unpoison_range(objp, size);
-	return size;
+	return kfence_ksize(objp) ?: __ksize(objp);
 }
 EXPORT_SYMBOL(ksize);
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221022180455.never.023-kees%40kernel.org.
