Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMUCRX6QKGQEOEVP22I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A872B2A7378
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:58 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id s13sf153218lfo.6
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534578; cv=pass;
        d=google.com; s=arc-20160816;
        b=m+9eL/1fTLkPPM1UJNeOp1WoqNNDWwJwfMj7dPrpC1Pz5yTTfvP4qx0dYZQ2Oy1P2U
         50wI4pu9Pv5ZGqBZUZwvOcj6/FBh1TE529S64lwejhM+VZEoyl174pWMoDegL0oW+as6
         tzQnfoWuEd3I1vQMXI4t0b6rWAJ47aqcIb6e2J3F6tY2ZZcHdIqLkR5qOaHTcB5E26p9
         wW3KHYLjvRiagmRzqS8NHKoQciRO6tiMjeIt+tFnekSC6/VhrEK/oQsZ9Au04jhU6Wqi
         kkfNPNeOPM9xc0xls+j6/y1hcp2GncEw5k/kWLYMX7vKK7pIvBf3bB6XeHKuNVm/I9Pm
         a99w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=o8tnjIUFjN/085DOIEPreR5Ui5EiKvz2Ww7fIPYCRg4=;
        b=RRJO8Zktu9xbi4Y/csTBfU3TN1BimTjLy/4ssCVWkUzCVvKkLaMhlogrB2iQXGg1w6
         Uzr3pQPvzf7mOXnoHpSSPDlNGTn0iE/gFXZJeUOHd+tVBU4kaA0FkcNwmvsddRwY8N78
         9e2dncWijtB5WIrQIjwmJbCmdlbqDHIaciZKNBk3HJNWXi06PmTb746RLS07ak5mGPVp
         rGfWB0bIitSD1fdBV68ypr2DDMhMum4ftbiZBB1LjsLAacfDvlRuZeHej51bIshafhae
         14CN6lQlSLXsJwlTeHGVnmp3iIIB+9/5+Z00UUBvAYEgVssfDLQ8Rdd0vn+yhhtDUFY0
         2AOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DWEvy7mM;
       spf=pass (google.com: domain of 3megjxwokcumfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MEGjXwoKCUMfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o8tnjIUFjN/085DOIEPreR5Ui5EiKvz2Ww7fIPYCRg4=;
        b=luRQlHacrJWFrJL+5RqWFsr1i8QWkyrziu7q12f0QtIqWH/SaGEpDjckM/j2dgfLmQ
         qv4QXdhPuHqhwNclOw+H4kP2YnYAVB4pm4aAiWvpv9qKG9hKi4Q3tTmved+lab5SITS7
         hbwrzUO/Dt4KxVHXOUsB2pe4R69QxamE8lCa5Y8vVR5icNlDw03+Qlink2QjMCEIgpC0
         ntYcMP0HIh431H+/rnSiFGvyslzcIN7vU5P/jxqdCYK2NUPPjegc1VIN2K/0E/l+Pvm6
         NfPUVkXinsQDwqXbd6SN0B5CTKc5O+oNpe7jsfnWGtrSSbBnPTSDpDPYnQ9X3LPXc/+G
         tMAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o8tnjIUFjN/085DOIEPreR5Ui5EiKvz2Ww7fIPYCRg4=;
        b=nL3fD42rDKjpeAkySwsgw/lrSXK3VaWnUBuTVcCSYqGr6ZDDsHcTkCtG4AjSbarsJZ
         oR3/YpHqNpoQOkPDu2XKUQeBxf9bDtqyyCrH+79jEb+IlgzMtiB5lQtQZ9hPT2xw8YNf
         Kz6gyKZzSxYmHN8D/GHRiKkk1e/xyECydw5zywUs6uO28tWLAmNAxr1y9kVMqeMkvDYl
         FeKlLoWDQl3XLGUmH63cWoy46H5uBqGfr41rPkwbwm/Jk7AZOgHyqNmsfy9loa7eZY9e
         A5TbYo4lkTPhtdeBclHzP6D5pTt3or4QKXVShy0ox2Po+3QSTQ62CP8inJ22tukNeTmf
         DYaA==
X-Gm-Message-State: AOAM53377oK1FEbtaQbinFBNtg/IwceOEEA4AzCtmyYfNKQc1ZB1+e2J
	lSZzK1sqFyNwFjlXRv0GlRU=
X-Google-Smtp-Source: ABdhPJyP20UJqFIX/Mv1OBBtqVN8/rIeN0g2AAQ2tuctRQVHA+ArZjs34BINNJwsKb428oGZD4/oXA==
X-Received: by 2002:a19:c187:: with SMTP id r129mr67071lff.533.1604534578279;
        Wed, 04 Nov 2020 16:02:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls2301838lff.1.gmail; Wed, 04 Nov
 2020 16:02:57 -0800 (PST)
X-Received: by 2002:a19:913:: with SMTP id 19mr53421lfj.147.1604534577418;
        Wed, 04 Nov 2020 16:02:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534577; cv=none;
        d=google.com; s=arc-20160816;
        b=hUzy7Qetl3+yteXm5kK2D/2Br94R1ubfiEcg4KlB0FSCapKSaozMlQ1Zo7mA1j/XJg
         BFTOC/YvKnY2JjeIWBk2pQsLI4KDVxqqPHui9ZbbO0E/q8vIHnUk7gHuOmK6fTBBPBkv
         Qu6Oppy018yJMQwb36inttHHuSKc/Cucw6ru/3HgZiD9y+ryNGWOeV5vr6ERCuOM4IlJ
         yI2heQVBV9NqaA6/EbE7E6QhEmOWJIDoKoiwIpZvlF7zFD6CpdK2+k+jPn1nJgyihWKc
         V3qWDAoTS9/eExsr6kYZaI6xiB9ko8tvHDk1jtzNMN1q1rl0b5Gw9sh1CyI36Ux8B7Wn
         cCdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TVZ5KfDqV4sczuDDUV9gNsUWnBSctv8RhcIj1oMqFVo=;
        b=xC8M8Le4+9wah6WFVlxZjjt/5SFAXe6tRtctyFpYCx4ThB6gMoAYlGnUk6GcPu/AVY
         ta8SIYi6WPo82Zx4vFCxnWgMe+yB7fR8cOZVSgxNCincOpCqe1AdY8kHsq4URiBkvChj
         cfX9jQIjuQXuJzs+wzQtBqn4c0EpycZ2n9iDEPbwFWmHwM/WdcaSudQPkxsvU6JC4DL1
         NEfiTJAb/tjv7MovziOWWmRJjkLiHZ6/cpXBDl5gl9ux2XOg4xxhAXbYs5TgMPf9/6Gm
         K35FHMZXPgK5lIKGDDiMBFyG1Adw8YaUJwwqepWksbcXSPSro2b1e81yoL/Y3OGpvR11
         BIXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DWEvy7mM;
       spf=pass (google.com: domain of 3megjxwokcumfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MEGjXwoKCUMfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z23si108033ljm.6.2020.11.04.16.02.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3megjxwokcumfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id q15so96956wrw.8
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:57 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4d05:: with SMTP id
 o5mr23559wmh.94.1604534576841; Wed, 04 Nov 2020 16:02:56 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:19 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <7a831f5b5876f468545d637775d5440d49d31400.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 09/20] kasan: inline kasan_poison_memory and check_invalid_free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DWEvy7mM;       spf=pass
 (google.com: domain of 3megjxwokcumfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MEGjXwoKCUMfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

Using kasan_poison_memory() or check_invalid_free() currently results in
function calls. Move their definitions to mm/kasan/kasan.h and turn them
into static inline functions for hardware tag-based mode to avoid
unneeded function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/Ia9d8191024a12d1374675b3d27197f10193f50bb
---
 mm/kasan/hw_tags.c | 15 ---------------
 mm/kasan/kasan.h   | 28 ++++++++++++++++++++++++----
 2 files changed, 24 insertions(+), 19 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index d5824530fd15..9d7b1f1a2553 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -26,27 +26,12 @@ void kasan_init_hw_tags(void)
 		pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void kasan_poison_memory(const void *address, size_t size, u8 value)
-{
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), value);
-}
-
 void kasan_unpoison_memory(const void *address, size_t size)
 {
 	hw_set_mem_tag_range(kasan_reset_tag(address),
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
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
index d7a03eab5814..73364acf6ec8 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,8 +153,6 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
 
-void kasan_poison_memory(const void *address, size_t size, u8 value);
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
@@ -194,8 +192,6 @@ void print_tags(u8 addr_tag, const void *addr);
 static inline void print_tags(u8 addr_tag, const void *addr) { }
 #endif
 
-bool check_invalid_free(void *addr);
-
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 void metadata_fetch_row(char *buffer, void *row);
@@ -275,6 +271,30 @@ static inline u8 random_tag(void)
 }
 #endif
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+static inline void kasan_poison_memory(const void *address, size_t size, u8 value)
+{
+	hw_set_mem_tag_range(kasan_reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), value);
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
+void kasan_poison_memory(const void *address, size_t size, u8 value);
+bool check_invalid_free(void *addr);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7a831f5b5876f468545d637775d5440d49d31400.1604534322.git.andreyknvl%40google.com.
