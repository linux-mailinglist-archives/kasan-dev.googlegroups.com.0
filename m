Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT5N6D6QKGQEOCSNXDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 18E522C1544
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:49 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id a3sf1673562oop.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162128; cv=pass;
        d=google.com; s=arc-20160816;
        b=R3stW0hE9EdREXze2ktrAhJqm/U7lZTkkllXbfvg17iKw+Nrltlzr/JxbklpDTFi9K
         jix40iFN4rSehnETm6NYflxtdGLPBUTRGA4C9U3HmCB5yCTCvV3cWRCKYYqW2Nsar1Sm
         w4ktZweHCCi+XkE1IgwFnQPiDFw/vRqM+ZnU85TT2RoaHsD4bT/a0gnF54dNtLlyCGNr
         aqcmHiYLYXL5jeRnq/72Dbf9E+0froinuNqo2vSb93KgjX7Y5PquWcz/gRpzgraq9mAk
         5bd5DpPdgteTPmX/IqjzsUIyCpW0/z+EJlQ1ml1azlqv/DZXCsDnRfLJYrfqaii4b9zo
         t3CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=JZO/0hOlDvdZ4hqrHSuWanfA9NtcYVE4zl4MsdF3Vsg=;
        b=bzkgUEqdARQkakOtoM0fUmMw8VX+gWPelmfMmNSnA/59l5/sfPi9iK4b3QPMo4L85C
         W1ceAzF3Bkm8Y44mXSDBZnKyMw5Xz3HAPNOpQxhQEqaSdOfzuq63aan+4k4Hde8Jumx2
         37pK0y+Mrq5uoJmsxSLhZKpdkCzR1TFwxDxUsaYNQGu2L5dttyR9B8UDYt5KBJjeqZzF
         UDUhtmUxX0XvhjTZpggKxI9w87yBGdbtujB6FpFydulw+hZQ6xG2evZe3j6vt1wIEDmu
         g2Jlsq2xcDRsTp1EWdw0Cx6hmqxuuHfkkxJd4S+2jGGyw/utncbeOJQeDyG2LkSdlNyY
         oiAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lgtA4NzR;
       spf=pass (google.com: domain of 3zha8xwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3zha8XwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JZO/0hOlDvdZ4hqrHSuWanfA9NtcYVE4zl4MsdF3Vsg=;
        b=Tw1rdJPQ1lCjE9gBdSlSccrJCnMuWHcsDVV1qzpOX83XRDOA+LZ8pidDqhuLu+aZhJ
         Iz40f0nVarrn46TN70m2QV1KsLnaAiPDDHm9GjBJfcJlic3dNKR66sw3hIN9RjL2+ZMS
         TG5LKde3w5gN8nmaAxQLYbCCDNzeTzkedM4Z/RfeWBYnVDmdY4om0o5absrQWGxHcfPX
         P7e0ibcYG6p5M0e4WWgBLYhtuFc7tDsPaKdHa8AlmJMpH0RyCQZm9bjctgIfFhBkQP33
         fU5YXRZbC1Zyi1LBJTLVPGEfdr1kECO7oToenPb8TEtdmB1lye8Hm7A8A5jX/oz5utxq
         b3wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JZO/0hOlDvdZ4hqrHSuWanfA9NtcYVE4zl4MsdF3Vsg=;
        b=WDLPHhdBjtGUk483Gs/1g/F9N4eHDa7hm/eNzonUr9kq/avBbK1ud92RFexMDod39k
         k78cxkFXMnifT5fnN3s5yDZuco2zS/m5w0WKr0asEY6rLmw7f7CC03xZPZr5B2Mnq4Lc
         uUIeBTTFjx3Tc//8mQncHQPPatSQcHbbrwMHEeq/R964kAc6W3AA3fbiypgMii3mKYkR
         OTSubrWiPiJbnbpQtTYlq9qXWF2I7CZdlwQ/fDMfLI1QcCsQXxJCs5AmfipitexrrV0R
         q7xw4MT/oGXRjaI+8V+6v7zoZ2nut3WTXwKZZSMohjnY3o7Fm3b0la0m3AEAqNZOX1JU
         yBPQ==
X-Gm-Message-State: AOAM530/5M8ZUOokaRF3o0RRR586uGyUjTwfgxP1qQM8dfLyClphDRSZ
	65Vm+RT+yy971x9PZdWRFTk=
X-Google-Smtp-Source: ABdhPJxWJWAgAhh99MitocF3/mpLJwC3rrqtw3JAO7W0vXiwTppHK1qIKN+7ATnh4gt/M8LE/GEriA==
X-Received: by 2002:a9d:4d83:: with SMTP id u3mr787464otk.283.1606162127922;
        Mon, 23 Nov 2020 12:08:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:dd84:: with SMTP id u126ls3678731oig.6.gmail; Mon, 23
 Nov 2020 12:08:47 -0800 (PST)
X-Received: by 2002:a05:6808:3d6:: with SMTP id o22mr402812oie.145.1606162127531;
        Mon, 23 Nov 2020 12:08:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162127; cv=none;
        d=google.com; s=arc-20160816;
        b=E3rDRpO1li+uXD9QtikvYtUk7jfm2j9rPxDVZDJbKgvAsrZj9AIfY516O87XfKteBL
         CwB7bE7iZ06xgDnBWTU2w5pzpneiuVBikUtp50wHbcsyPELXZRpjXBz/758Wb0Oty2hJ
         +nxhUV61aifsPdhG9s3CVTE3U29bQFLmqu/hKnhVG3jSjGPNSREMgt0YAEk8M7TFgzn6
         khQ1ArsQx5DPi54YJDi4puMLE9EO3rIUETb+JuNoSh5/B8uOwVQB0bKBdN9tHNYiGNUi
         kSYZOj3BKSaMBGdmEMeN0X5ElYDz7j20yghy2jy/MCmdyXLINtJC9EkT86gQWq2XatJJ
         oJoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VsAI4kIskvc7OgbGXOlaJf5U20hpa/63jMpnaocWLWM=;
        b=EoDizk88NxyXQEd19JpBEW7bnLI7NJTVVLDPfqUIKnF7HXhbsGF5yvNsdIOFX9ZWLF
         AJVGmlbr9oEQBlI92ipAGBp0JqiAKeG1OyuQSkngc5xDSGjwXoJNM7oCU6yqcEsd4hwU
         Gv9iq3hUxPz31Yj9Vhv6NpfXbWfpRpMy25Lhby98LF+Fq+xCQnWbauX61CgQ1/yTTKdj
         F/sTr29f7dQCPquZJskLE7vXsvb2jrABVaUqsBli3K7AXx4asJqoaSmHpZesS/eBnd6e
         fSClJaVwsx3loBf3amtSgxku6f3Dj7dxyhuTVYYng33GGM+He64nZ6A6ZdNwBJfYD7HJ
         3yMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lgtA4NzR;
       spf=pass (google.com: domain of 3zha8xwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3zha8XwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id i23si888339oto.5.2020.11.23.12.08.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zha8xwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id b9so6446279qvj.6
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:47 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:eac4:: with SMTP id
 y4mr1106877qvp.19.1606162126939; Mon, 23 Nov 2020 12:08:46 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:36 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <d01534a4b977f97d87515dc590e6348e1406de81.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 12/42] kasan: hide invalid free check implementation
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
 header.i=@google.com header.s=20161025 header.b=lgtA4NzR;       spf=pass
 (google.com: domain of 3zha8xwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3zha8XwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I5fae9531c9fc948eb4d4e0c589744032fc5a0789
---
 mm/kasan/common.c  | 19 +------------------
 mm/kasan/generic.c |  7 +++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/sw_tags.c |  9 +++++++++
 4 files changed, 19 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b3ebee6fcfca..ae55570b4d32 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -278,25 +278,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
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
@@ -318,8 +302,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
-	if (shadow_invalid(tag, shadow_byte)) {
+	if (check_invalid_free(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 754217c258a8..67642acafe92 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -188,6 +188,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
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
index eec88bf28c64..e5b5f60bc963 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -166,6 +166,8 @@ void unpoison_range(const void *address, size_t size);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+bool check_invalid_free(void *addr);
+
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index c0b3f327812b..64540109c461 100644
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d01534a4b977f97d87515dc590e6348e1406de81.1606161801.git.andreyknvl%40google.com.
