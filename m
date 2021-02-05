Return-Path: <kasan-dev+bncBDX4HWEMTEBRBV4D62AAMGQEK4TD3RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF545310EC9
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:19 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id q8sf5865841ljj.13
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546519; cv=pass;
        d=google.com; s=arc-20160816;
        b=RqvG9jFOzfiBDi34iW4fdwcREWNyM1WWe14KWdVy2SLbP4Z1odWZybZ7Wq57nooQ7s
         s3+0H0OCoKskceBhXoRElu+0K4p9NZyaZ0qOKQcWvdEENDhSDq26X/JCeE5/tkRu4SeD
         TQYlk5p690l7NZtCixtld0yzzevfVOJJhl8KZwCbopFq16wPJC9RWk4nZw+yiuubWOZK
         dCnUrKyHmxt8fctq3/7zEE/k4bEvMGHd9vwwJuw6vZzmErzhopyONcpvwD6mQJavBy53
         X8p8U6wel/OoGWm8jkdvBvWrvOcNkLipYpNcvefOo1qDBVgaaBZYrLdKPtct6cZVe+l0
         aQpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3VcX5pmWE/gyehaDBIGKGRwbcrS+vcB9OqqtP5267RY=;
        b=sJg4VJEED2JzZnH2Am6sFpX02VEeLzGtJgJe5MR+xr8xy73VkkvIqmF7XErMd8GCB6
         sSurkT2AqMzHtZbVfLWszrIPjcScNeU4G1QySny96RvM53AiU6WvJzjrL6QaiDqmhjDj
         LPDfjLLDYdzVh+wDojr4fbejTsPaaLWIFdBNwTDfF9WBdFQDexA2BZT/zzb3zDXqZ3Zp
         XTMa/f55o3GA+niYm979zhlddb0W07Nj1ob2Kuk4uIZLm/ewPtTs2aqbDoff7nYTQ/hf
         B27CaEb1CB2exRKLdFPIholIAwRHRKs4PP3PaIIaVc/vt+hoofzjTYPcG6UWfBxgdTSd
         2I5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rhZcOisX;
       spf=pass (google.com: domain of 31yedyaokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=31YEdYAoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3VcX5pmWE/gyehaDBIGKGRwbcrS+vcB9OqqtP5267RY=;
        b=Ee+BNfTHA6uKVeTOLkbcM0h+/pT+BNFuzuKhwUxto//x8XBQfKF7+6Vy17jNGPXEXL
         fiQzk+GnsqpaLPLdqFZleGPz0pejqeEaWW5TQuoYXYD/egDUth9XWtXrBhzkIXpILsIk
         E3d2Fz5227fQrUTZvDib9agEScWXI8O08J091kA/8wc3Qt16TB3dw6pPMJyXkG1F6AAa
         QAOFpOuLBpT3hqzqVM0OwklmbnCHO3AsGACrpT/uKl7cYnUzJRBJTbW5coQfLxGxZImc
         osOaOLj3N80I3eG2Q7kdVTgfr7tbBk0LbxguekKnHY01CFQKXbV5u9ad7YwIR9JOnork
         dZlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3VcX5pmWE/gyehaDBIGKGRwbcrS+vcB9OqqtP5267RY=;
        b=mBPNVXaWQxqW44czunaOSsWiuaBebpxOGjF4HvAr7WZKnab6xulbOU4xrIvRCOY7f9
         qp3aXVqbICM3LPZuhWDlwBkgDS4B0esdTJd/B+Dfky65/Yl0cSLO4g6JrYoWp7W5mCf6
         0WOHLhZk1J4hHAJrATS+HL5rsBpoD0W0x1LxIPSirHDkQwE8mjzGEW+czfejNrZVaP3E
         r96R8mJQMVHTcLv6dh6LXYIbLNQsnBleF9D8f08oKJOD6p4qS0PyOaYiPQrA780MURwL
         epVQqcCknbRaBlBDdtPu2kg8hSHPlg3kSIbKK7BILVPSRqU/zAlyOSAASi6qBx9KbWKr
         ztsg==
X-Gm-Message-State: AOAM532yKXPXfMqbyK+aLtbUayGKuSY855JNm055KexIXG8+4KENpatE
	JJbUsDzQgeaE3b9susbyEjw=
X-Google-Smtp-Source: ABdhPJygmEeYB8nWj08wzq9d9ts7mjReXAIDQ3c2Gnp8k6bn0LY9Mfk92lFjbeSzVQS4E0Il0Q9RdQ==
X-Received: by 2002:a19:ed16:: with SMTP id y22mr2982077lfy.406.1612546519382;
        Fri, 05 Feb 2021 09:35:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1314:: with SMTP id u20ls1819217lja.9.gmail; Fri,
 05 Feb 2021 09:35:18 -0800 (PST)
X-Received: by 2002:a2e:7114:: with SMTP id m20mr3356903ljc.296.1612546517876;
        Fri, 05 Feb 2021 09:35:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546517; cv=none;
        d=google.com; s=arc-20160816;
        b=D2CEkyw26XRkUgJlRdAL4RYMMCDXzu/VLWZvXTylQeUg7DFIcy+F41lWHCsy7jinbv
         UK2vlPpfa7Sd+rXiEZDxZMDBkhjwHG8zFMtlrrkzsmxqTpEnJFQvU0ltRjc0E2mMbGeu
         h8MdwlMCZaQuTirF5KUou9TmKJgbdr6nvf8xV9yq1zT+sZZWZ2iROTE49yLlxllknBuu
         E0VwOIC/TZCeEdGUrSnL6IM5R0PYttB39NqXAdBsxmmIkdRCVHyWc6+93VDQhGbAm8IY
         n4UuCpDU06Tjx6TZ1G7UagwKfzsKvHaAXMJ98wSxCXPFC5Zdoy8wHemJDqVlbKxBt0fE
         B2Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=r9X5DpdR9qKQzOGqj5YPMHvNzUxwchyNv1XRoONrpMQ=;
        b=zsX0xeyChq9pEhbHJt9g2INpFW0OfyjzDGR187Abf4HYqURJ3pUkqsE4L+sSrDsGKi
         UtzJXlq7fR3m/JCgoAlHFIXJqsKIfInVQxaib5DVNXkSdeGH3pbyd7f3NXkI258FaEph
         QgH40L2CfBIVBSo2DnvlwBIWIUomtmKTICGHR/DIA6kpQw3w3XzJQaKm2EsL5dCUqqZG
         7rBniQhN+n9UP341uR8snoM18Y74EiNZJu9ORpIaEoqhYYnicUHXtyi7mBSxzdNPbkyb
         OV9WtereGbvzvd21vzmkxS2/Q1HVJL5+hBPOrlRXqhvQnoTHvT8uPbHUCB/V0Y6mAAo4
         tleA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rhZcOisX;
       spf=pass (google.com: domain of 31yedyaokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=31YEdYAoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f18si559455ljj.1.2021.02.05.09.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 31yedyaokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j8so5708415wrx.17
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:17 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:adf:f149:: with SMTP id
 y9mr6216013wro.144.1612546517387; Fri, 05 Feb 2021 09:35:17 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:45 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <2c94a2af0657f2b95b9337232339ff5ffa643ab5.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 11/13] kasan: inline HW_TAGS helper functions
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rhZcOisX;       spf=pass
 (google.com: domain of 31yedyaokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=31YEdYAoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
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

Mark all static functions in common.c and kasan.h that are used for
hardware tag-based KASAN as inline to avoid unnecessary function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 13 +++++++------
 1 file changed, 7 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7ffb1e6de2ef..7b53291dafa1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -279,7 +279,8 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
  *    based on objects indexes, so that objects that are next to each other
  *    get different tags.
  */
-static u8 assign_tag(struct kmem_cache *cache, const void *object, bool init)
+static inline u8 assign_tag(struct kmem_cache *cache,
+					const void *object, bool init)
 {
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0xff;
@@ -321,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
-			      unsigned long ip, bool quarantine)
+static inline bool ____kasan_slab_free(struct kmem_cache *cache,
+				void *object, unsigned long ip, bool quarantine)
 {
 	u8 tag;
 	void *tagged_object;
@@ -366,7 +367,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
-static bool ____kasan_kfree_large(void *ptr, unsigned long ip)
+static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip);
@@ -461,8 +462,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	return tagged_object;
 }
 
-static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
-					size_t size, gfp_t flags)
+static inline void *____kasan_kmalloc(struct kmem_cache *cache,
+				const void *object, size_t size, gfp_t flags)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2c94a2af0657f2b95b9337232339ff5ffa643ab5.1612546384.git.andreyknvl%40google.com.
