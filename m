Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSUJXSAQMGQECMNBW6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CF5E31F34D
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Feb 2021 01:22:35 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id j2sf2520906iow.18
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 16:22:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613694154; cv=pass;
        d=google.com; s=arc-20160816;
        b=rIDoKpflwiMUnICE/b7THqJm0bgWWoPdDi4utvhMtwz3Ca/wg8DFFW1ScicuNijgwN
         /pb2Tlg+3fcYkdzMrZW+DTfORS2HkcYokWE4K5BD9inRBx/UwM8HvlxYjmi4e8l+Lfjx
         Y6okXCYGzj2+3W/2z5rFi8SFgXNre3ETg0f052U1y8os3a7eYiuNmR/h97gg1MPL4tUF
         Cq8EjoDpnSg0f262yaKbBdE9O0Oryyi9sFP6hgyeUJ+TxeO1h3fdH1JDUa6Arb7pwr1T
         Hpujq4JJXPTuluIYeOr/d5XQQXbCCob0JgVyxB6JEo3vv9akBkzS32T3QJvnTn1UTYwZ
         WMpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FqMp89OU6SaHfY11TY2v+ZJQMXgYIYqje/QckXXXDuA=;
        b=ecz5LOzSAKVgAdMeQNm+HR3bbF7V05DzY1n4hVz2SzE/SmB3E9LTFo48OoLlvTywQg
         EXxWAFpltpy3nyxwMJXXd0iaQV1PZzCR8OKHl2qN4fI1+GZ0aU6jUy6t1xC+bUmE2sxF
         VNNE/Y8Urn7cHX6WwRtZgnnjqMKDnI2M3ZvHNF+Oq5ldNOxNT0+jRWA5TaO85Q+7B14p
         v7CNwjXIueKU9f3blUzieZGfKNEKuntlGpG8GJHa+4xG9I52isQjprjXPtE7tDSN8wbI
         WJRCDY6+mJs0b/wOKBCCUaCVWB9Xs8h/g+Zqs/ahjuL7djaNermOn6Cz2fuXWqMZTDtE
         jlEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ak7Lim4r;
       spf=pass (google.com: domain of 3yqqvyaokczy0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3yQQvYAoKCZY0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FqMp89OU6SaHfY11TY2v+ZJQMXgYIYqje/QckXXXDuA=;
        b=e3TGsHKzTiu382S1izJ4Kmz47tYmBlr6dAlP5kzcJCtYTYERg24EdDMG90o4O81LEy
         qrFFDT/sQIam7U2dhs+0TGVhPwgb61JblCAczUcktACSogy+IUnOb8+VLWTrzUHBz7SQ
         el0cw1+xeENsqCzAED8GlncTeXwyQjaEf4TAKtl929tZiASuDZGgH97z/0aXNN49MNPb
         dYQkiAI7Xty/YgWr96GrFLAmKMHjxoDMLNQ+9v7R9TRq3QKslc/ZScejkQprUy1gwpmR
         egMTGmGN8bpRWaoYYxUMj/FKYTQR32UMIvSnqux1cV0srqyniTvN/csBjsrgQtRoCS7j
         u8pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FqMp89OU6SaHfY11TY2v+ZJQMXgYIYqje/QckXXXDuA=;
        b=J/fXqCuPUJbAehHzs1NcuxUl1hpspdeK6OTULuLr3B+I3w4Hdlq6btESRLHjJlOsdZ
         smKP2hf49sv+FpSW62LmAjL/OW8b+/YrFRO4BG0rfiQznEmVbFP9ldI8iVnc1R1CQiq7
         k3GlFeJLYgqjEzeamP+eA0aa4QIN9QkKu9/RKWft/eSHWU4sxO4XXmTio/SWNTwUoujt
         qstq6PqOjDfmxDoqPmCb6VRfe9ce6gq0tG2AEoVqoF1xOhmykSy9Y0MfK+Rw55QBes2S
         9BhjU9uFAkEQ2fAkK7le+4nz+RJQEULVqEIH/19s0/z/G3odXaiaSWPcrDlhl0K7M6h+
         7QYA==
X-Gm-Message-State: AOAM531oOSdMZvg5N8cmWt+2GYcjE7VtqfC1sM9+Lz2RJoIyzJw4T4tE
	kvCXqwalwFb75+OqRp4wi9g=
X-Google-Smtp-Source: ABdhPJz1x8Ofc0tDmHg1GJokpojg1jQadbbNMU5N7D8gunbb0ua3znO2Mgn/uyfzNk3KNEcFo7rDYA==
X-Received: by 2002:a02:30cb:: with SMTP id q194mr6987638jaq.57.1613694154368;
        Thu, 18 Feb 2021 16:22:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:13c5:: with SMTP id i5ls1073038jaj.1.gmail; Thu, 18
 Feb 2021 16:22:33 -0800 (PST)
X-Received: by 2002:a02:6049:: with SMTP id d9mr7016925jaf.125.1613694153888;
        Thu, 18 Feb 2021 16:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613694153; cv=none;
        d=google.com; s=arc-20160816;
        b=e+0aMFvTk5bf9eMGm6/wHA8/erMaxf0PvqYHcRtcbEyzLK7ef40W4TEYALsVlmSVYL
         3D+JYCEgr2qJkCF01QpoA4i0O4c5h8jQNJn0+Z6tYbiZJ0aLpOb9I+pOHah14VvzPbHZ
         Z3yNtlLTuasoWDrOqZhjPk4o1CAIU/4TYx37bQpBAMmz8BGBSWEeyziS4gQSZ37Tppf0
         euldqE5k6cMDx/llFekHGwuQmjcHt+5IVZZbaMha+KkmI6v3IebRsIQ5JtJmcdwMjAW6
         eQa3/2O0MEf5UidH59rTJdz8Ubj9HhMk7YiR/OjUaTTtTG6Dq93fZYFpCHZ8vVZfrIx6
         yMzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hrKEbBMgsE8JTGg8XVXnIk1GaeWuGUQgi5pPA+IiEQ4=;
        b=D1jfwQZmM0k2J1JWy5G5fNcggEOQKxHunYV1NSwx6DMl+ZvEKNpF8cN08l9rBYT2gl
         +hv7vqZQ/OPU6E9M6Qd8O/YyHlRWDw7l60RzgCU+Xf+q5rW1CzIgvbRgtJcfEIMEMRli
         7fIlVw0urNxKvSzZhDw6CrIVovkhcorzicbwPo8M7mFTlj0k/wYSYztZ/DKBg1AhXE40
         4blq5C6IabtUWE0IrtLzypHuLTQhkgojFQQIDrjPzcI7Kyr/nO41mxH+s7vCqleuPELn
         98Ej6NwoVDa0L4dpeGmZbpxEwx7d6MBoXek1RanPx/hbiq3pEVSozWHhd+fYEQ1TUHIl
         RfLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ak7Lim4r;
       spf=pass (google.com: domain of 3yqqvyaokczy0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3yQQvYAoKCZY0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id r2si313826ilb.3.2021.02.18.16.22.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Feb 2021 16:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yqqvyaokczy0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id o90so2267941qtd.9
        for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 16:22:33 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:2d89:512e:587f:6e72])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e13:: with SMTP id
 p19mr7008653qve.12.1613694153272; Thu, 18 Feb 2021 16:22:33 -0800 (PST)
Date: Fri, 19 Feb 2021 01:22:24 +0100
In-Reply-To: <c8e93571c18b3528aac5eb33ade213bf133d10ad.1613692950.git.andreyknvl@google.com>
Message-Id: <a0570dc1e3a8f39a55aa343a1fc08cd5c2d4cad6.1613692950.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c8e93571c18b3528aac5eb33ade213bf133d10ad.1613692950.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.617.g56c4b15f3c-goog
Subject: [PATCH v2 2/2] mm, kasan: don't poison boot memory with tag-based modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ak7Lim4r;       spf=pass
 (google.com: domain of 3yqqvyaokczy0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3yQQvYAoKCZY0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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

During boot, all non-reserved memblock memory is exposed to page_alloc
via memblock_free_pages->__free_pages_core(). This results in
kasan_free_pages() being called, which poisons that memory.

Poisoning all that memory lengthens boot time. The most noticeable effect
is observed with the HW_TAGS mode. A boot-time impact may potentially also
affect systems with large amount of RAM.

This patch changes the tag-based modes to not poison the memory during
the memblock->page_alloc transition.

An exception is made for KASAN_GENERIC. Since it marks all new memory as
accessible, not poisoning the memory released from memblock will lead to
KASAN missing invalid boot-time accesses to that memory.

With KASAN_SW_TAGS, as it uses the invalid 0xFE tag as the default tag
for all memory, it won't miss bad boot-time accesses even if the poisoning
of memblock memory is removed.

With KASAN_HW_TAGS, the default memory tags values are unspecified.
Therefore, if memblock poisoning is removed, this KASAN mode will miss
the mentioned type of boot-time bugs with a 1/16 probability. This is
taken as an acceptable trafe-off.

Internally, the poisoning is removed as follows. __free_pages_core() is
used when exposing fresh memory during system boot and when onlining
memory during hotplug. This patch adds a new FPI_SKIP_KASAN_POISON flag
and passes it to __free_pages_ok() through free_pages_prepare() from
__free_pages_core(). If FPI_SKIP_KASAN_POISON is set, kasan_free_pages()
is not called.

All memory allocated normally when the boot is over keeps getting
poisoned as usual.

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---

Changes v1->v2:
- Only drop memblock poisoning for tag-based KASAN modes.

---
 mm/page_alloc.c | 45 ++++++++++++++++++++++++++++++++++-----------
 1 file changed, 34 insertions(+), 11 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0b55c9c95364..c89e7b107514 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -108,6 +108,17 @@ typedef int __bitwise fpi_t;
  */
 #define FPI_TO_TAIL		((__force fpi_t)BIT(1))
 
+/*
+ * Don't poison memory with KASAN (only for the tag-based modes).
+ * During boot, all non-reserved memblock memory is exposed to page_alloc.
+ * Poisoning all that memory lengthens boot time, especially on systems with
+ * large amount of RAM. This flag is used to skip that poisoning.
+ * This is only done for the tag-based KASAN modes, as those are able to
+ * detect memory corruptions with the memory tags assigned by default.
+ * All memory allocated normally after boot gets poisoned as usual.
+ */
+#define FPI_SKIP_KASAN_POISON	((__force fpi_t)BIT(2))
+
 /* prevent >1 _updater_ of zone percpu pageset ->high and ->batch fields */
 static DEFINE_MUTEX(pcp_batch_high_lock);
 #define MIN_PERCPU_PAGELIST_FRACTION	(8)
@@ -384,10 +395,15 @@ static DEFINE_STATIC_KEY_TRUE(deferred_pages);
  * on-demand allocation and then freed again before the deferred pages
  * initialization is done, but this is not likely to happen.
  */
-static inline void kasan_free_nondeferred_pages(struct page *page, int order)
+static inline void kasan_free_nondeferred_pages(struct page *page, int order,
+							fpi_t fpi_flags)
 {
-	if (!static_branch_unlikely(&deferred_pages))
-		kasan_free_pages(page, order);
+	if (static_branch_unlikely(&deferred_pages))
+		return;
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+			(fpi_flags & FPI_SKIP_KASAN_POISON))
+		return;
+	kasan_free_pages(page, order);
 }
 
 /* Returns true if the struct page for the pfn is uninitialised */
@@ -438,7 +454,14 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
 	return false;
 }
 #else
-#define kasan_free_nondeferred_pages(p, o)	kasan_free_pages(p, o)
+static inline void kasan_free_nondeferred_pages(struct page *page, int order,
+							fpi_t fpi_flags)
+{
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+			(fpi_flags & FPI_SKIP_KASAN_POISON))
+		return;
+	kasan_free_pages(page, order);
+}
 
 static inline bool early_page_uninitialised(unsigned long pfn)
 {
@@ -1216,7 +1239,7 @@ static void kernel_init_free_pages(struct page *page, int numpages)
 }
 
 static __always_inline bool free_pages_prepare(struct page *page,
-					unsigned int order, bool check_free)
+			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
 
@@ -1290,7 +1313,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	debug_pagealloc_unmap_pages(page, 1 << order);
 
-	kasan_free_nondeferred_pages(page, order);
+	kasan_free_nondeferred_pages(page, order, fpi_flags);
 
 	return true;
 }
@@ -1303,7 +1326,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
  */
 static bool free_pcp_prepare(struct page *page)
 {
-	return free_pages_prepare(page, 0, true);
+	return free_pages_prepare(page, 0, true, FPI_NONE);
 }
 
 static bool bulkfree_pcp_prepare(struct page *page)
@@ -1323,9 +1346,9 @@ static bool bulkfree_pcp_prepare(struct page *page)
 static bool free_pcp_prepare(struct page *page)
 {
 	if (debug_pagealloc_enabled_static())
-		return free_pages_prepare(page, 0, true);
+		return free_pages_prepare(page, 0, true, FPI_NONE);
 	else
-		return free_pages_prepare(page, 0, false);
+		return free_pages_prepare(page, 0, false, FPI_NONE);
 }
 
 static bool bulkfree_pcp_prepare(struct page *page)
@@ -1533,7 +1556,7 @@ static void __free_pages_ok(struct page *page, unsigned int order,
 	int migratetype;
 	unsigned long pfn = page_to_pfn(page);
 
-	if (!free_pages_prepare(page, order, true))
+	if (!free_pages_prepare(page, order, true, fpi_flags))
 		return;
 
 	migratetype = get_pfnblock_migratetype(page, pfn);
@@ -1570,7 +1593,7 @@ void __free_pages_core(struct page *page, unsigned int order)
 	 * Bypass PCP and place fresh pages right to the tail, primarily
 	 * relevant for memory onlining.
 	 */
-	__free_pages_ok(page, order, FPI_TO_TAIL);
+	__free_pages_ok(page, order, FPI_TO_TAIL | FPI_SKIP_KASAN_POISON);
 }
 
 #ifdef CONFIG_NEED_MULTIPLE_NODES
-- 
2.30.0.617.g56c4b15f3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0570dc1e3a8f39a55aa343a1fc08cd5c2d4cad6.1613692950.git.andreyknvl%40google.com.
