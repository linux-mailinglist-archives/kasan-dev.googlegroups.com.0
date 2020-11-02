Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQG4QD6QKGQEGGUJIWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6823D2A2F0B
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:21 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id c21sf2142724lfd.14
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333121; cv=pass;
        d=google.com; s=arc-20160816;
        b=P6HVmBLI0sXUK//q4YGinz910vYtMW3vARwoLBKq5W/7XybyU4hMMyc/9GG+9kDkGS
         BmrsjQnHP50102Ud/wbWpC2yJFXc5C/QcEpuHZIJttaftTVWcyaXWKWkQRwaUwRC9ZYt
         ZKBw5SLAXw8FsuvAgwRdgmsUa9TSjO42sDgI8EGSWZ9F2Rnsy+L0ymS7IagAh6LbJMj2
         AGyw4LXw7qMm7vRpJdZhCAbJ9IQBYlfSmT9VJ9kibDvmoOUSBR5PxFHnTGUSZaXakYyv
         HFDkjpQPeuSdZl99qnddnbLWRJ25oBTiGMo9+tIspR9AjvFPRtpiOPHSwlKB7BvA9qSe
         XroA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=XTPX7R94uzv3E+79ndC6SfMeqW5shnyqOZuaNCUN2L8=;
        b=wYH8wd3agRQDbghPqz4wpVvUJ4XA030oRGPflfSdldW+iIRvJktifftOPfX+sqsb9V
         2luZ7oVTsIJ2n8QWFLgZFnUWjQlrYVshMc7tALKfOsGNcqvitNbBB4lS0VyrxgXo+s+2
         j8WiY62bJks66tZBDrQpNqKFuXWuyEoRTY9PExgHKiVCS1uk6+i9uT/JRZQN4ry1Vszz
         W7OYG3f0deAPNdy1ZMX0PBgp1Pb3v6Xd+iqjUsH3StuxMge9HAwYp6Fq39aY8KdWaC3G
         JWUP4LpM1jAMrQhg94PGi40dZhoslvuCoTyfcWyFkoKfnP3BhkAy6Tsam242VlYJHpK+
         lQgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BSLt9OKa;
       spf=pass (google.com: domain of 3py6gxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Py6gXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XTPX7R94uzv3E+79ndC6SfMeqW5shnyqOZuaNCUN2L8=;
        b=hFH66daADSAwvr83KQJciEOsB8LeNRjiQ9gObCcf1EKhMhoCvhYmn9eI4HdzkUkSPr
         2heAOruo8MiQnhqXQkUxs64OnSOH1AJ3UUxhe9Es1OHww8BMfvk5I72+S4ov1AuV7vO7
         /uKazl9w+kaJWek4aJxD74fGK5qtK5KaZ+P/LaGSa6+wnt6jAs0p9KQVoxXBUXDPFrzg
         rQo5VO1YX22dxqiIbS5fjF/+9NPPA7j4i5xdA7juMIq/jFfe6p4Q6RbsHWc1Lr5Rp2Dd
         AoQ4oWLJ551/lqlyRStPoBp4QC6TNyU003i1LAWBk6k1ZvWIrhLyzYCP4yVHHz7I/mH/
         p6Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XTPX7R94uzv3E+79ndC6SfMeqW5shnyqOZuaNCUN2L8=;
        b=PAYVobg9F2Ef5m5llkfw1StoxNQFiNbfHgmNaF05dx5d5sx6SJosvDQbvrlUX3aH2H
         dg/xUog+boTwjJU9PhFNImdXGs5GKOz6+tpIcT1Tuf7Dt05mssvQih3/Wt5ruRA/dnRr
         +58XY7Po4w6xCrEAKHdte677yorcpgSTueKL4/srLBsIQGyHgCcwIywYlKK00syhYnk8
         5Gxt+SCzF/Fop3ud6lO66zsFcu4ZdxKzHBssyNSK0+fmcaN1q/CM0ZpL3X/OJEziID5G
         ATli4MCVft8+3MrJNXVMUAD5Uby2sL1eBcIxSXmGD0ndAdc5rBK2LWgvp88zBZSfAK0o
         DOfQ==
X-Gm-Message-State: AOAM531tI4gAQbelSTB7lABMLxuvkbx5xyMtfJ3pjUO+aKsDsSekmXiz
	JIBb4U+4s+NnVL8LCSyIDPg=
X-Google-Smtp-Source: ABdhPJyJhsJyuwuIizjmlMBMebbLgr94jDLrjsu4LgRLLyFUEd66anKxywuZIgud/81te+gApfqA6g==
X-Received: by 2002:ac2:5ecc:: with SMTP id d12mr6355470lfq.487.1604333120976;
        Mon, 02 Nov 2020 08:05:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b6d4:: with SMTP id m20ls2486532ljo.1.gmail; Mon, 02 Nov
 2020 08:05:19 -0800 (PST)
X-Received: by 2002:a2e:8ecc:: with SMTP id e12mr7129090ljl.98.1604333119923;
        Mon, 02 Nov 2020 08:05:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333119; cv=none;
        d=google.com; s=arc-20160816;
        b=avtfYnhtcLleiT4bH3XlDhqER1Ak1bq+WAKudiD/nesOhWeJzmHNATOLdi4U/6dd6K
         v9BOJ61KUetSBBzRatMuzUp9nAwSKVUBqMBp7Xgp7aOXej2MPKwhLo71yK3Viw4fqckf
         Va0VmZZB0IpSggplrmX6MH8Is0SqhagajWhRZYuRJiD6mXKg14TGbvrepOsafG/GwZci
         VsGhUcX5Lndcz+jrqmFoe9va/Yu9nDW7J3Fxq+krncpyix4XvFeg6k3cT6zHh7UTxyno
         BuMxhx/fzeg87iqxzk3YTNz8m7dToic+5g17dmkVUElaHykGd4OZ3vRGoEDHpDTn6+5t
         D/Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JrbTjwkrdKqcTf3OBQQXqXKZQLwLc5XAsTu4uoIDNkU=;
        b=pocSpwurGsmb53SrfS7sSPgcPU5eDpSEL4yYLHdUObmekMZX4fbBaTmcdwV9CZOuKr
         o6V2EQttwbe+GaN6Xs/ID1grwTbO0u5oW4aotFHF2BERRxWc9eErddhIu20RYUu1RWrj
         C0zRGhJNwHThj2vSDVdY6HTt5rzOIUobVpyx8KTX4EoorKKpj46wNJAulLipSfuUgZQm
         MDKkRhAhgzAYPql/FgR+2TZM3bJTk8M5sE8YVT/eXn5qh4PM4ux6RGj2jSUOOfzV6asG
         rGPC7TVr9JruTo43ZViFaWDy/wx7jSsl7omcojaLUsdtBIwxEv2804qJyyRyl2K6z1Cn
         N3yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BSLt9OKa;
       spf=pass (google.com: domain of 3py6gxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Py6gXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id x19si591839ljh.2.2020.11.02.08.05.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3py6gxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t11so6620673wrv.10
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:19 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6a85:: with SMTP id
 s5mr21657731wru.90.1604333119324; Mon, 02 Nov 2020 08:05:19 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:02 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <499c0824a10e32c7dbb29c2f28e9a76c771c0da0.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 22/41] kasan: hide invalid free check implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BSLt9OKa;       spf=pass
 (google.com: domain of 3py6gxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Py6gXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

For software KASAN modes the check is based on the value in the shadow
memory. Hardware tag-based KASAN won't be using shadow, so hide the
implementation of the check in check_invalid_free().

Also simplify the code for software tag-based mode.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5fae9531c9fc948eb4d4e0c589744032fc5a0789
---
 mm/kasan/common.c  | 19 +------------------
 mm/kasan/generic.c |  7 +++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/sw_tags.c |  9 +++++++++
 4 files changed, 19 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 123abfb760d4..543e6bf2168f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -272,25 +272,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
-{
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		return shadow_byte < 0 ||
-			shadow_byte >= KASAN_GRANULE_SIZE;
-
-	/* else CONFIG_KASAN_SW_TAGS: */
-	if ((u8)shadow_byte == KASAN_TAG_INVALID)
-		return true;
-	if ((tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte))
-		return true;
-
-	return false;
-}
-
 static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
-	s8 shadow_byte;
 	u8 tag;
 	void *tagged_object;
 	unsigned long rounded_up_size;
@@ -309,8 +293,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
-	if (shadow_invalid(tag, shadow_byte)) {
+	if (check_invalid_free(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index ec4417156943..e1af3b6c53b8 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -187,6 +187,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return check_memory_region_inline(addr, size, write, ret_ip);
 }
 
+bool check_invalid_free(void *addr)
+{
+	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
+
+	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
+}
+
 void kasan_cache_shrink(struct kmem_cache *cache)
 {
 	quarantine_remove_cache(cache);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d8f54efb2899..04df1481a033 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -164,6 +164,8 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+bool check_invalid_free(void *addr);
+
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 4bdd7dbd6647..b2638c2cd58a 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -121,6 +121,15 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return true;
 }
 
+bool check_invalid_free(void *addr)
+{
+	u8 tag = get_tag(addr);
+	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
+
+	return (shadow_byte == KASAN_TAG_INVALID) ||
+		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
+}
+
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
 	void __hwasan_load##size##_noabort(unsigned long addr)		\
 	{								\
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/499c0824a10e32c7dbb29c2f28e9a76c771c0da0.1604333009.git.andreyknvl%40google.com.
