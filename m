Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3MOROBAMGQELJO2UAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 57C9832F713
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:06:06 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id s18sf2560240pfe.10
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:06:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989165; cv=pass;
        d=google.com; s=arc-20160816;
        b=iIF+nTXoELA+xKJlaHw2M0oj9RyZblNO0ApjMowOWqCJ7kAqGFVGW2hNPkAS+Js/yq
         nT9n6OBvSW0+lrE7CnBGiSF3raSiDFIR/jHvSNnp/TO7khPGgR1cPXxz1n17f6gGOSAe
         n8NDNFy/G8KSx4nEUL51GAR+OV3MZiDeEtZBayo+pQzVt9swtnmbd7MlJTwFI1jTAw+k
         5dxMv7hTRto5ETpVFmIWoNyhD++YqQ0lqGGeUyEM3LFK2KdDhiJx+YXKSgQjwtmqjC8G
         YGCXk/8pY0wzxF1nvXyqPw8uUYzddyp78NpEH+iRHM+WMithMe1rPOJG6MInAqiYl0YM
         8uIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=14+mqfNny5GEk0bgEWNz8sgaCWVhe3H4889tJ1z/P8U=;
        b=gwcVfaEqYNg0q2svZRjpFrWzofa2aaZlMgnRajYbi5gxId7wXCtWqTKp6Ywdvi+fu4
         JwMUgsU6QanWJbtB3xbdZYLSx3yBDKJAXo/twoxYN0JwT8VxYY6zQPRXmbgh1aXfriGt
         /iPUqmcVBRAB7uexIDyCojKlWH2Qjsr0zei4yOdlukOAPk9MmdsMUv/laa9jP5MmqhoR
         ESF2pYVfU+Hwxfo6j9Gpha3JaEbLtCx3QS8TrbeI6E4mP5Tg4mdfVUZ/YbBtSg20Ivxc
         hiy5muNiaaV4kzc4PZRh15kbeWtJ9uoTr0nUxoyy01ryzJzh5BGjyyDzgfWOGPNo7yP5
         oQPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nXH2trZD;
       spf=pass (google.com: domain of 3a8dcyaokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3a8dCYAoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=14+mqfNny5GEk0bgEWNz8sgaCWVhe3H4889tJ1z/P8U=;
        b=NHFMFMXVzsqKk4mZXgf7dTugQYy2b2fe3cvHU8khaFbDtFFyMsmyPqD4J2TRyTLqxq
         sarSSDQLgY7pUOUdYomv2qrFfGgL6q7FS1uZjd2ByEHVsW41BubrPjLN9bpoMpjcS5zI
         X97Qpu2p0KjG043RcKqXGIEQIjHaZk6VVPnbhnTRo/h0Zdw/xUsVZXc6cDi6J0pBK9wS
         wJ1tlMRFVm36Y8cEdmdaA7/0bMek45QtcFmQH1vtE6+G12FmE00Gt/1HqnHDz98iW0AG
         lC7QDvoAc1IkHvgcArah454NyZXLlPLXbLgaS9HT3VDGMtenq+zobArnXc6t3aw5XQRI
         EApA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=14+mqfNny5GEk0bgEWNz8sgaCWVhe3H4889tJ1z/P8U=;
        b=mAZOp+EwSiuGZV/qWFjn8lSTm/cv6lpH30MQxUpZ8mhUnpzZRMocWuUnTL5CGFKJsd
         9xiiHeOYpqFXXke5nolkI5mB+q6ff3k8tw3f5SZzXiKDxWgBg0mRbrT6Tx5x2DMMSNcj
         8XwN3Hi4T8ubiradkV0W1WAxU7FbOoXmT2a/wMsjnmqyHqMRvvojSRffyLmbcQTeSsVs
         +KPB+qSicIPLSf15hDOfMMQy+Y8fbbhJn1rB2dFucktEBk/aiunnyaDToyOooGt/qwHq
         GcdrSbq7EdOlJS+xeJJu002lptGph9GlArJkJi75U0pfgIkWo8s0bPHSM9QVQM8LoTY6
         +pWw==
X-Gm-Message-State: AOAM530nxaxt5uwAN3Wy0a/YwPWl0t0GHY0BM1WLZ/z1rmYz+uUhB2iJ
	LZ+kbMadEXKWLjBE0fDUdXM=
X-Google-Smtp-Source: ABdhPJxtqkapnL9qxJ+uqV3vaKpcLkU6ztalWNUtYIjzz+Q1ntd7jfEyQJQkrwRIRZPn3BwK5zSGzw==
X-Received: by 2002:a63:e902:: with SMTP id i2mr2961433pgh.45.1614989165117;
        Fri, 05 Mar 2021 16:06:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1382:: with SMTP id i2ls6226997pja.1.canary-gmail;
 Fri, 05 Mar 2021 16:06:04 -0800 (PST)
X-Received: by 2002:a17:90a:1990:: with SMTP id 16mr12307273pji.26.1614989164516;
        Fri, 05 Mar 2021 16:06:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989164; cv=none;
        d=google.com; s=arc-20160816;
        b=Xsey3kvk6Jx2Hyr3KW5Te35bNWkPrezIE604zbOrt1mzRw83gZ+l/xhpRatmHN7yc4
         M/5JIylR92yRRbBL/3cy3/IsIytaKmmDO8UqR2LRHws7gm04FqFEQ3x3bBrzFf4nUjIK
         sLsXsXr8XsirXPZS+CVvMMCx0gVY+uDVXeTI+rK1vryXLUSRDe/H55g9mclcwC5ny2Jm
         HTYyg8ZTKHZ5XQoRMqC3dAS1hz46br2SxgTuA5GTRhAkilEboZAEbQq1E9J718gncYWn
         svyIGRTtAtZTe/3bzZgyNWl6naxR5g1yFhxls0gu6Oy6akcr4LelESX9q8YmiZofJBzB
         bNmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yJop2QuXemsmY+rS7D33vVlqYl2tBY2jpSe363QSuIM=;
        b=EIf/RFFU43MJa/4sCw6vTnVFU5fw+mOxcwFvC+CmoNuUv0a9Ut2kUJVulQ1Z+uSSLl
         kzbv/JoUxM/mxpxVfqnL5f1w0yr+DOndmajHk0hxJzYWmMaXNT4RRzWW9j4d6gKchnhf
         kZ0gSPW1+v43KPBl5rQ3l3hqGq+vXAIaDgqAYTU8VkIDyep6bVbNGKm1/b7CKH/RFkxB
         TfipCoOlHaCIKtLeVHaxgoIPWxAorHpMbtqQ0RsRyPAWAWNXXADHS/Mmwb8N3vt1wFrK
         T549/3pktgbg5kXEj7BniETlkdyrK0rxK009Atoi5/Ed5aV3xUdDDcdGkEEnRkmAIyWI
         OMLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nXH2trZD;
       spf=pass (google.com: domain of 3a8dcyaokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3a8dCYAoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id k21si323549pfa.5.2021.03.05.16.06.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:06:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3a8dcyaokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id c1so3166463qke.8
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:06:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c60b:: with SMTP id
 v11mr11124307qvi.44.1614989163659; Fri, 05 Mar 2021 16:06:03 -0800 (PST)
Date: Sat,  6 Mar 2021 01:05:58 +0100
In-Reply-To: <b6cd96a70f8faf58a1013ae063357d84db8d38d6.1614989145.git.andreyknvl@google.com>
Message-Id: <cbe2a3195ea0875c0abe44a18a3a7802b2ba4b58.1614989145.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <b6cd96a70f8faf58a1013ae063357d84db8d38d6.1614989145.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3 2/2] mm, kasan: don't poison boot memory with tag-based modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nXH2trZD;       spf=pass
 (google.com: domain of 3a8dcyaokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3a8dCYAoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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

Changes v2->v3:
- Rebased onto v3 of "kasan, mm: fix crash with HW_TAGS and
  DEBUG_PAGEALLOC".

---
 mm/page_alloc.c | 45 ++++++++++++++++++++++++++++++++++-----------
 1 file changed, 34 insertions(+), 11 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c89ee1ba7034..0efb07b5907c 100644
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
 
@@ -1285,7 +1308,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	kasan_free_nondeferred_pages(page, order);
+	kasan_free_nondeferred_pages(page, order, fpi_flags);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
@@ -1307,7 +1330,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
  */
 static bool free_pcp_prepare(struct page *page)
 {
-	return free_pages_prepare(page, 0, true);
+	return free_pages_prepare(page, 0, true, FPI_NONE);
 }
 
 static bool bulkfree_pcp_prepare(struct page *page)
@@ -1327,9 +1350,9 @@ static bool bulkfree_pcp_prepare(struct page *page)
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
@@ -1537,7 +1560,7 @@ static void __free_pages_ok(struct page *page, unsigned int order,
 	int migratetype;
 	unsigned long pfn = page_to_pfn(page);
 
-	if (!free_pages_prepare(page, order, true))
+	if (!free_pages_prepare(page, order, true, fpi_flags))
 		return;
 
 	migratetype = get_pfnblock_migratetype(page, pfn);
@@ -1574,7 +1597,7 @@ void __free_pages_core(struct page *page, unsigned int order)
 	 * Bypass PCP and place fresh pages right to the tail, primarily
 	 * relevant for memory onlining.
 	 */
-	__free_pages_ok(page, order, FPI_TO_TAIL);
+	__free_pages_ok(page, order, FPI_TO_TAIL | FPI_SKIP_KASAN_POISON);
 }
 
 #ifdef CONFIG_NEED_MULTIPLE_NODES
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cbe2a3195ea0875c0abe44a18a3a7802b2ba4b58.1614989145.git.andreyknvl%40google.com.
