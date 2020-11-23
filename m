Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVNQ6D6QKGQE4PDMAWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 425402C1573
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:19 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id b19sf4036542pgm.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162518; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pqp8pYyQBiSlMJtocS8VwA3wRhGQgks2uiVmRKqsTgaFkTtR6KL/Fpp7txRb7WO74N
         SMlFjNY0aYTH9IxVMjdvUUrj2uNgcRTnZO68gNfgK48LM+qMxW3DffME5In0Q/lggbL5
         USJDJzL2REnzDQunNlby8zFv9B38TnUYl4ltbBhwj5Iq0io7/T8/iLp24kphNvcwK4NP
         1ORBMZLfSHspI0E38pVBExFq8RSO1a8lmUqYEFAYad3yMltqG51u0JSw0j5uK74d67LG
         Ez8U6777x7is4vWVFRkz2oeGdlLv6hyHwWyUyCLBQ5ukTBN2Op7uihzPQKBLJrUKLkQ0
         14EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=9KPrnIO5mSRkydd7/UkEtyBw5ajbM8Z3wiTNpgRIDmo=;
        b=UqvTIN81jwM39DAV/hHjRN63t8LRrvjBKc+mAoIM8gxIYDQrBwIqnHlZu766dZCLKW
         Ns6SeqwbyWqzANajiwRgiLWpcI4O6JAY0X4MST+7JEIcA1J3eXN1tA2JHGZz/mV0Ypv8
         13rOX5zIvNK0pizbVfF74XlnKkHxQsA2k2YNJTU8G/y72oRjeFqOE/Z+cviKhlJa1Yj5
         nnk7V9ScrqZo4cBHcWCyAvALrKS4upIRxTyceVat28ANBYQNlm7FgyWRGIeTUz0B0vyh
         +xqmAa3Q0Grb1sFB9Pq/sHPvdVJWBRf/UogUHOin/OJ6TuDs/OAZ8n6FWsaANfttnTYh
         0Pig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xdpxb1Vf;
       spf=pass (google.com: domain of 3vri8xwokcxoylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VRi8XwoKCXoYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9KPrnIO5mSRkydd7/UkEtyBw5ajbM8Z3wiTNpgRIDmo=;
        b=b8kaqMPmZHMkT+AUYhABEi3Yd/Hb6x1o8scA8qXB/sBgaB2BuqNQIBE5lK7h0ROfvT
         yfy8eE996YoPzfql2kp8Ltk9gBmWHN4sNp+izSo8QEZo6aAtVsHPwuf8Q/xneyV10E7D
         9HR8alCjPmGCAD128Cd+eAQOaP+qSZVVU6Sn3xcuDnydrS1VYSmAluvmAlc5DbGpQU36
         2dPi2gLP9dbxhcofZU5rBcvrdH0iVjtdq4hbfvFYLG1cU87+SoeiNc3zJO+z7YjEZkFp
         sUm8LVJ5L4nWd9iOuSZYrgSqK6TkR5gvlSTa+P2oL5xIskRseZxOBbhjw2ph2lV4PX8L
         wWLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9KPrnIO5mSRkydd7/UkEtyBw5ajbM8Z3wiTNpgRIDmo=;
        b=JVNeQBQjpyJnhSnuVaQPEHdURJxFBopC2db+l5bar31C3wpcPQ1sD0iqA5xY8+kjGl
         5rQtvO3kMz27JjlWjSV2D6NyBkhwn83NLj1r/a1zSyaU+v3gUtEI3WhzRtiW7nDHGkkZ
         YLsYG0TWUCYB1tBC4e/meZM730MIFWUlOTIue/1HmveWYIe2qRlnG2/t8JanUFgaQSwa
         qAa0ZgiHx2+GVy5YZTKj/yg1Z8BH0p69B9SlCpoTjlHIRvUU6153QF1Xu9IyAyvZC3dt
         xn6fbvjhEuwkNIJ+uXuMB9zg6sMh2/OGBFDbni2NTGAxuvFte4URybE3+Fd5j7Ya0isD
         ko3w==
X-Gm-Message-State: AOAM533kgBn0vO0pn8AITUfqASlrW9iEfY8EUFWevuQ8ZdTB+podubWw
	c0c5ghkrNLzdrjG7WNPtaAY=
X-Google-Smtp-Source: ABdhPJyCqzUr0VWklNq2KkMD1JTlJ3Fkj/Od8xHnBCGiBQYsyBuz4E+YGdOuvdJXKBoIO2dKRhdbYQ==
X-Received: by 2002:a17:90a:5c85:: with SMTP id r5mr648049pji.199.1606162518044;
        Mon, 23 Nov 2020 12:15:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf08:: with SMTP id h8ls212308pju.3.gmail; Mon, 23
 Nov 2020 12:15:17 -0800 (PST)
X-Received: by 2002:a17:90b:1894:: with SMTP id mn20mr685647pjb.89.1606162517503;
        Mon, 23 Nov 2020 12:15:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162517; cv=none;
        d=google.com; s=arc-20160816;
        b=SicfUsZKiGnA0yRb1vRqW5q4cAh1Q5a1TbXNelCVx6QqStUY81L75KKwxTWREovj5u
         CFBu2ziD7CaoWS91hBcqfL7se2gdSWac6EOMdp+XIs1mUHAFv3SMnk0cINbMpww3B1pj
         zJy1VuyGlb4BGcb3c1YkJmtOcYSNn5UnGDX6tIwkUQ9KgAp4c8OU31UV+DydeMUPP8Gf
         +HCEoND9FlCU+J/dwm0UzqA9suc07PHeDaBLh9TJB8lFs1Ht/CeAq98Xwqtuw11Tmizn
         1Wf24T/SNwQwzX+UdP5o67AsT1Ctb5NhM6zoAG7k23AUXWo6cyJ4B8svzMfAV6eAbF8C
         fiXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=S3Qrn/dExjiymjsgYUNfOEnR/LmRZMAIXzYoVslXjjw=;
        b=CpbdHCCggR+DHKc8rqdXGQVy9EFwzyRJ+BOvBeh7kY3rZKEL09E4aubZU6MBJjX1CN
         zahnua5j4x3DIlOsQwBN8JIZpBFNX0euNN6XUBZSNzR0Tgz9scKv9eyb9D2p0Ubl60GF
         ONeJ9I3TqIVbJ3nSIou1bHDl7V7sKTNWHRiMxX60xJSNTiIJww/Efc6o1XTu3MffDE3V
         CGVgWUlYaEvtF7WNKNt60vigJBNSqgq9SRfeM7aUx3mS6FSkkoarlusoL/gdvBn28WOL
         puESzQGpFE0nfEJrvlbKSa3gVOm7mqaXjyUzgObNGQOXx3nCXMpi33aIF+ns3GQSyunW
         BhBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xdpxb1Vf;
       spf=pass (google.com: domain of 3vri8xwokcxoylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VRi8XwoKCXoYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id b26si765827pfd.5.2020.11.23.12.15.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vri8xwokcxoylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id v8so13697709qvq.12
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:17 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:470d:: with SMTP id
 k13mr1306441qvz.40.1606162517097; Mon, 23 Nov 2020 12:15:17 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:40 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <7007955b69eb31b5376a7dc1e0f4ac49138504f2.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 10/19] kasan: inline (un)poison_range and check_invalid_free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Xdpxb1Vf;       spf=pass
 (google.com: domain of 3vri8xwokcxoylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VRi8XwoKCXoYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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

Using (un)poison_range() or check_invalid_free() currently results in
function calls. Move their definitions to mm/kasan/kasan.h and turn them
into static inline functions for hardware tag-based mode to avoid
unneeded function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ia9d8191024a12d1374675b3d27197f10193f50bb
---
 mm/kasan/hw_tags.c | 30 ------------------------------
 mm/kasan/kasan.h   | 45 ++++++++++++++++++++++++++++++++++++++++-----
 2 files changed, 40 insertions(+), 35 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 3cdd87d189f6..863fed4edd3f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -10,7 +10,6 @@
 
 #include <linux/kasan.h>
 #include <linux/kernel.h>
-#include <linux/kfence.h>
 #include <linux/memory.h>
 #include <linux/mm.h>
 #include <linux/string.h>
@@ -31,35 +30,6 @@ void __init kasan_init_hw_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void poison_range(const void *address, size_t size, u8 value)
-{
-	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(address))
-		return;
-
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), value);
-}
-
-void unpoison_range(const void *address, size_t size)
-{
-	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(address))
-		return;
-
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
-}
-
-bool check_invalid_free(void *addr)
-{
-	u8 ptr_tag = get_tag(addr);
-	u8 mem_tag = hw_get_mem_tag(addr);
-
-	return (mem_tag == KASAN_TAG_INVALID) ||
-		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
-}
-
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 7876a2547b7d..8aa83b7ad79e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -3,6 +3,7 @@
 #define __MM_KASAN_KASAN_H
 
 #include <linux/kasan.h>
+#include <linux/kfence.h>
 #include <linux/stackdepot.h>
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
@@ -154,9 +155,6 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
 
-void poison_range(const void *address, size_t size, u8 value);
-void unpoison_range(const void *address, size_t size);
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
@@ -196,8 +194,6 @@ void print_tags(u8 addr_tag, const void *addr);
 static inline void print_tags(u8 addr_tag, const void *addr) { }
 #endif
 
-bool check_invalid_free(void *addr);
-
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 void metadata_fetch_row(char *buffer, void *row);
@@ -278,6 +274,45 @@ static inline u8 random_tag(void) { return hw_get_random_tag(); }
 static inline u8 random_tag(void) { return 0; }
 #endif
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+static inline void poison_range(const void *address, size_t size, u8 value)
+{
+	/* Skip KFENCE memory if called explicitly outside of sl*b. */
+	if (is_kfence_address(address))
+		return;
+
+	hw_set_mem_tag_range(kasan_reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), value);
+}
+
+static inline void unpoison_range(const void *address, size_t size)
+{
+	/* Skip KFENCE memory if called explicitly outside of sl*b. */
+	if (is_kfence_address(address))
+		return;
+
+	hw_set_mem_tag_range(kasan_reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+}
+
+static inline bool check_invalid_free(void *addr)
+{
+	u8 ptr_tag = get_tag(addr);
+	u8 mem_tag = hw_get_mem_tag(addr);
+
+	return (mem_tag == KASAN_TAG_INVALID) ||
+		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
+void poison_range(const void *address, size_t size, u8 value);
+void unpoison_range(const void *address, size_t size);
+bool check_invalid_free(void *addr);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7007955b69eb31b5376a7dc1e0f4ac49138504f2.1606162397.git.andreyknvl%40google.com.
