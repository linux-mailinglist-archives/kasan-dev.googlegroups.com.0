Return-Path: <kasan-dev+bncBDX4HWEMTEBRB54ASP6AKGQELQOGBNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 51B9228C301
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:45 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id j17sf13134907pgj.10
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535544; cv=pass;
        d=google.com; s=arc-20160816;
        b=NvSNSuSqj7eaL9qGHv9jC804Q2S6pmhpoNoMJf9/O4RcoS2mHs45vUhKZm1hbzX3Mw
         2LW22wlE9WjL9iiRosYs8+YQjrkweOu/mLQup/dLM2Tv86tjgOH5gmjQw+QfKz9hstCV
         43Dhzfyu4BE061E9Ft66oFbjBC2Dcoj0tDVcA0+y0VJCqkybCu6ZUDxysxWKCz4PwK2w
         LZv6IuV3prFD6EeAQGLYwmd9OLr05xGVWVc+lL4u5uah5I7Ae+4JgzXMFZWCSGmznjNR
         JPWyaviGHLwEKEv3PXIs06SvoxN2V5Z44YuugCrXmbSEG7AgzrKV1oFouuEtzI69uUbO
         1G7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=TGt8B2niKS7lyhwARW1b3tTsn1iL/nnYP2LOOBOESLc=;
        b=qmjwB+toDVArfgCpMYJ5zvTQJTeCAAgmzGaMEDWCh1jMw1F1jYoScBX/lBrTrhsOIr
         XWIJ62fsZX4F72+tNDbR0JcgtITgS6hMh/oMyVahAlarwnUxJFUJjHL8BLp34rg0si9j
         NAF84Tk8hLOsMC5QYnpeSzn7HLXrp4qCpdUthg3mwcf3WvcKUf+8grge0QSId6BZ9/AT
         E+j+NZ830wi8yhAxqi5VwjJEoOue5Z1oqxRAPPQYRPE3LElROGgPv57YxGKtq6bvx7XB
         Nwc1P8m4PEjJUexXCyLbBurxXDVYx+i3X8tzhqG/spQ5P+dhaUZSKNv0HpBfKrBB9C7W
         C41w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qb8mGGA5;
       spf=pass (google.com: domain of 3dscexwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dsCEXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TGt8B2niKS7lyhwARW1b3tTsn1iL/nnYP2LOOBOESLc=;
        b=NG9nwON3jyFPdGhoKsmzTxhHY4UA4Ph9u7T/Q5iBaRVPdhTi0J9xNlpv5dK1moPZHn
         XVYVlACoTl0w0qWI5g34ap4XmIeNiBMdpp/dwowDjBUah4kq9Y0VG9kIhSkUrj7saExT
         Ugm5Az6d1B8fNH4zyk23Iqufx8gIACzb96e6LjDgcfiJHuLDWaw3gepXjgF6xd32BESS
         vQNlP4YG7MauvAdu43J1SP7Ig11XELgT0i/w2W7Tgz8fBOLSaIzwE4842E1BRY6RZTSt
         7hPWg/bqCBNwTpi6DanrnaHdWqWqjO4Tq678pSEMu9RZ8JkHbCzruXotHhCxTRjl8xgr
         WvUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TGt8B2niKS7lyhwARW1b3tTsn1iL/nnYP2LOOBOESLc=;
        b=lMB4qW3CBGEAv7O/GtXHZlAhX8sjSBZLzYccYo3vozLIsGxAEXB/0I3IVhYLWziTrt
         alM6zDiYb4NFt09Xdhi0aKl2XhtlI67McFZTjcFF6rk8cvcb17lbssduEPyEnq6UnKLR
         qh2ikJefCRKaR5Va9nVbqGRWo0cA4n1otN6DMZ5oYqcy/63/ksnndof5Qj/EkNxeG8hH
         gcdxUkKjQl89AfIolg0g9M2MLD0L2d4rgWjqXQ86xKsAlB2oN+tgswRR6OvFyzr7VJB1
         NOuE7qYuwXKmjimwKY4gKmMM5vM6F/mSi4WEK4AWs7L2caiN5rbzAAbyNloWZPhpGc2v
         UwnA==
X-Gm-Message-State: AOAM531xxlhNEI6aDUyKvRP1gZomZVdumbYBk83PaDOrH7QdmxtlaTKx
	Q83j1lcCPqFW8ydvxnR+Y+0=
X-Google-Smtp-Source: ABdhPJwMB9gjnC7aeFVv7EPdcpK27+p8nQrPsLi6oQied/JZ32reCPk+sbn8UuQruYsGWbdEEfm72w==
X-Received: by 2002:a63:65c5:: with SMTP id z188mr5624460pgb.139.1602535544009;
        Mon, 12 Oct 2020 13:45:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a06:: with SMTP id v6ls1175164plp.11.gmail; Mon, 12
 Oct 2020 13:45:43 -0700 (PDT)
X-Received: by 2002:a17:90b:3d5:: with SMTP id go21mr22357716pjb.149.1602535543432;
        Mon, 12 Oct 2020 13:45:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535543; cv=none;
        d=google.com; s=arc-20160816;
        b=pBJk3E21KREmx5VUqIAfdZDibxtOrefZ9LZXt7GMG195g/fu7syUyi/NmMvnuem7Lq
         pjoI+9RMdRsxAI+NhoBDfEfEiAotEmQqwqLELPF9fRv5Ci4WQWo4RNO+UWhRZYlKHYE2
         sBIs6UO9PEcFkmKuEDGsdymghsrlAbyeS2Lqze+qTNh/ccq2wNHgsp/E9VZA9hmr3RpN
         +yP48br9D3EiSH6OQvd1143C3E5BeMctccjMisoidwnyOy2dFdAyzN3CoRQKGVPE2nhE
         E21ZI64rU9TiNxFD0rN+vgqQyZTDzEXlem+PeihpZM+OlpRM3JQ5oogT1ATjZ5xV0n1U
         5uPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=w5C2W2DY9SAvZH/qaocnCGPCQ8ZMERi9GQeckWB8bok=;
        b=jQUBkWLvHDT/3w4/wlyDc8cdc49Jd5d65ng4lB+FBD7ZfKfZMfVCnVavaKzBrB8p+4
         5PKUGdJheMWJGgySHZo/Rul6WHoUCfsaGEm45czD6ndIvZO1S5O+5fHFTqfq2kNvoyC+
         +tFrRMOyeE6Mez+5TYi9XLh0KnLLazq9lDQ37oCt5N56X9p9pm23f0VRt8r68EjlViAY
         9gMv9AqYZ5XLvhRCgyZdxHk27tYi83qN+YLUMaoB+k/zaMScKq/I7kbfJTCBXdS7k6T+
         XRZ2hnVDof9XMJP2hIkhsIoThwnm8hAHvb4SItSwdMVV6gpJtclLzJS+GrGjggApt0iw
         jjvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qb8mGGA5;
       spf=pass (google.com: domain of 3dscexwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dsCEXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id k65si1279464pfd.1.2020.10.12.13.45.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dscexwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s8so11434516qvv.18
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:43 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:146e:: with SMTP id
 c14mr26719107qvy.22.1602535542528; Mon, 12 Oct 2020 13:45:42 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:27 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <1d1755d107694267933ccf22045f9d4480a00593.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 21/40] kasan: hide invalid free check implementation
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
 header.i=@google.com header.s=20161025 header.b=Qb8mGGA5;       spf=pass
 (google.com: domain of 3dscexwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dsCEXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
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
index a2e71818d464..325bfd82bce4 100644
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d1755d107694267933ccf22045f9d4480a00593.1602535397.git.andreyknvl%40google.com.
