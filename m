Return-Path: <kasan-dev+bncBDX4HWEMTEBRB75T4GAAMGQEBF3CIWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B0EF30B0A1
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:44:00 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id s7sf20928269ybj.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:44:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208639; cv=pass;
        d=google.com; s=arc-20160816;
        b=nsOUhJkLa3pR8LWxESimcn7Q2Yd5BBnyCoO5Wz/AuxaMo+4vt24AzpYrvWKCjb0ake
         Z15BO/+6kc+mo5i4PNgG1wQ+wB794Ah6LGN9AABpVxTWZi6M0JJhVYt3UdZY798qCCHC
         0ok6PMgP70H4zVggqGOwK3OAV2QdjcqrpMusvHWNhu3S1sTOfOFCbrLgMOhRu9q1eN/0
         fdNMDjaBum1EB0WkCS+5TMhUbbfWk2gXjlK/62YpvWpoih7MDpV0EOiN5CD9vgtAtvXg
         n3W3qRwJIsvsglCKY0J8L6FNQ4UzicN2jIyk7qL4xusrdsQ+YxYbiCoYyLtnnHcgRERm
         LKmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=mYc2c1jhyfqiEeM/ihRWpxQ58oR+MR7DIUzOSYUhjqc=;
        b=qDud7EplnlHP3cLgKlM84q7+2T767tdOM82jVNVUZT/Q0ElolH2lD7ebQKq7teOf9V
         ZUzmFJXvL8mQcMIzECutUp4HDEP13jDZYem5nEkuJ0cmOvu4nFHkwGOFW+MK4d8Dbtkm
         y4w/v9wOO7HeptcMBicf5DpnVEG43RLcBbggo363TPap6JBaH0UUkauUjm30t+ZOPW+x
         XSuHk/gYdOaI7YEvrWQSYMX3v78J8dMdT1srrx/GN2i1KgKOdlDfZcFykdc/7C+Caugz
         4PZEBLwBMjAy32aAyOGVOptoD/6LQX6wtY8hLEMIOA5n9mB5NeVYkbHLmuJaOH8kTDog
         MOfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="NM/EWWXf";
       spf=pass (google.com: domain of 3_lkyyaokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_lkYYAoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mYc2c1jhyfqiEeM/ihRWpxQ58oR+MR7DIUzOSYUhjqc=;
        b=lgdYMImmSxk/MrJPPd97Xakz3BauUmGg1Ahtn6jA4gLoxgL16F1/uz9MYAVePkpfWS
         xQepf+CR7lWU3PYbId5WmtTXPlvpY/z9q1xRBVn28FGuNGP2Jk3uXL9f7V8BZJDQBKEA
         6ED34PQ4u5CQGkDvkd4TC5wgR3ly4+NDHc9+YDsW8U3UeRqMwlmrftn8er++zELzQksw
         j8g8rI3QW6PqqPZPquwuIO8t+pUcMZbUyUMVfxhDI5Q4Uc46cHX77M9oHGBvbTqF2O1k
         ZzbMQounqEyGQ3uQSEngw7O96/u+zMFXHqBtWvcziwyojAoFucykh/vP3ohYSDHM5lsI
         FGdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mYc2c1jhyfqiEeM/ihRWpxQ58oR+MR7DIUzOSYUhjqc=;
        b=iLy97SCIvi/US0qEs62yMmIRwh2Oej2L6xJrKTOo/2lW20DwVw6f17Ln0e7d14vWAD
         +1geyXuWDi4emeIib/SqSeXgAP1c4gsiPUp2zA7p8r7SWauAMzqtZlamMXPUEoGFECfZ
         DYwvDhc0R16inY2xKCfgF1/XIF1mFX5fih3p6zdfyyzl02Lsp5eMmtoUkRvJNn7XX1fB
         e1fY32LgrTQKzUg1iHDVmfZE4pfLqOAT224YbNA7+ssCe5Z84iXdeMRzi91bSjfjkdwz
         kXVkFGpnOJdo/M2DYjbbVg2qqeiTPIWc6V4krJ5ZDcjkYDddEUhIUSZ2Tz1iMxugPU3M
         WjHw==
X-Gm-Message-State: AOAM532Vo965kq91vwo1Kof0M5X9uFzETF6Sway1IwVBwJCMfGYE9Uf9
	z5TbXqbJYeSaGBpmWc55izc=
X-Google-Smtp-Source: ABdhPJzZBcYhuU+xIr0HY3rA6jXW7FBgWWSAcHjOTBuisrvbKFTm+s5hehyt+GFuuP8H2fSqJUEeWA==
X-Received: by 2002:a25:71d6:: with SMTP id m205mr15855029ybc.136.1612208639440;
        Mon, 01 Feb 2021 11:43:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7346:: with SMTP id o67ls2226159ybc.0.gmail; Mon, 01 Feb
 2021 11:43:59 -0800 (PST)
X-Received: by 2002:a25:84c5:: with SMTP id x5mr26962991ybm.296.1612208639107;
        Mon, 01 Feb 2021 11:43:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208639; cv=none;
        d=google.com; s=arc-20160816;
        b=1I1V9iDEDdNqLPPVOKk7GX5pKYcFYa8RK0hImYMPMZESM1h25pEHMIyE8Ahs3+q9Ex
         kJTxurMlPKpYuKCqtpXToXLaCCA4yke/eNLqGqhEs7pcN06ykm3O+VbIZvnYKa6qh6hv
         1jQ3m9ZJPHQrmPHFDavva6Q3r2cUf2V8W3tpN8Icb7BWpBm+9Ln+SStbQCSaonEkY2lO
         vgSyuHlOHCOT1M6H3Ij2su8oGLE3jSgWHP5QMwg+BPf6hqXuMdFyTc1FhRr2EKV2LvBX
         9U1Dm38ZOEa9OWPWu245yU0PQc62/7l+ljOyNvNsxHb+gHhJCCoGHMuLY6dpudAyujzn
         1bNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=wTS7rGEWy/lmgEwVXVBE+5vzcvue/e9GmeYKwLI3/GI=;
        b=csGXctUf5Iv2/1l7LInHiFwxg3IJop/i94iodnMaRL2w4i3XB7gVnD7Iqpmq+6uJke
         tkwiU9WJGETySwO8kiB40mV0R/2XNn62tq+jRfcsW4ljSu7x6BD1rtlBVvHcnR/HKSYU
         Bh8pVexsaX3rvQn1NyUWWz+Xuv4U3bbl3fw5u7T81VzzjBwf172KO4pEx99t9fSqVkeo
         vLFLzG3RJq2ENE94/8UMtR6b0IDwrFOYmAOo3Rc8uEk5ZB8MjgeLL03q25WSZR1e20SU
         v6ToL/Uy+YiHwxURrMjFSYQBltUdJBF/BLHkrJnsdhdx7MxwLiR9rZHhYOCwEo4afosC
         krXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="NM/EWWXf";
       spf=pass (google.com: domain of 3_lkyyaokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_lkYYAoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id i194si334093yba.2.2021.02.01.11.43.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_lkyyaokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id u66so14168130qkd.13
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1110:: with SMTP id
 e16mr16696575qvs.62.1612208638752; Mon, 01 Feb 2021 11:43:58 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:32 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <431c6cfa0ac8fb2b33d7ab561a64aa84c844d1a0.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 08/12] kasan, mm: optimize krealloc poisoning
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="NM/EWWXf";       spf=pass
 (google.com: domain of 3_lkyyaokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_lkYYAoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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

Currently, krealloc() always calls ksize(), which unpoisons the whole
object including the redzone. This is inefficient, as kasan_krealloc()
repoisons the redzone for objects that fit into the same buffer.

This patch changes krealloc() instrumentation to use uninstrumented
__ksize() that doesn't unpoison the memory. Instead, kasan_kreallos()
is changed to unpoison the memory excluding the redzone.

For objects that don't fit into the old allocation, this patch disables
KASAN accessibility checks when copying memory into a new object instead
of unpoisoning it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 12 ++++++++++--
 mm/slab_common.c  | 20 ++++++++++++++------
 2 files changed, 24 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 9c64a00bbf9c..a51d6ea580b0 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -476,7 +476,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 
 	/*
 	 * The object has already been unpoisoned by kasan_slab_alloc() for
-	 * kmalloc() or by ksize() for krealloc().
+	 * kmalloc() or by kasan_krealloc() for krealloc().
 	 */
 
 	/*
@@ -526,7 +526,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 
 	/*
 	 * The object has already been unpoisoned by kasan_alloc_pages() for
-	 * alloc_pages() or by ksize() for krealloc().
+	 * alloc_pages() or by kasan_krealloc() for krealloc().
 	 */
 
 	/*
@@ -554,8 +554,16 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
 
+	/*
+	 * Unpoison the object's data.
+	 * Part of it might already have been unpoisoned, but it's unknown
+	 * how big that part is.
+	 */
+	kasan_unpoison(object, size);
+
 	page = virt_to_head_page(object);
 
+	/* Piggy-back on kmalloc() instrumentation to poison the redzone. */
 	if (unlikely(!PageSlab(page)))
 		return __kasan_kmalloc_large(object, size, flags);
 	else
diff --git a/mm/slab_common.c b/mm/slab_common.c
index dad70239b54c..821f657d38b5 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1140,19 +1140,27 @@ static __always_inline void *__do_krealloc(const void *p, size_t new_size,
 	void *ret;
 	size_t ks;
 
-	if (likely(!ZERO_OR_NULL_PTR(p)) && !kasan_check_byte(p))
-		return NULL;
-
-	ks = ksize(p);
+	/* Don't use instrumented ksize to allow precise KASAN poisoning. */
+	if (likely(!ZERO_OR_NULL_PTR(p))) {
+		if (!kasan_check_byte(p))
+			return NULL;
+		ks = __ksize(p);
+	} else
+		ks = 0;
 
+	/* If the object still fits, repoison it precisely. */
 	if (ks >= new_size) {
 		p = kasan_krealloc((void *)p, new_size, flags);
 		return (void *)p;
 	}
 
 	ret = kmalloc_track_caller(new_size, flags);
-	if (ret && p)
-		memcpy(ret, p, ks);
+	if (ret && p) {
+		/* Disable KASAN checks as the object's redzone is accessed. */
+		kasan_disable_current();
+		memcpy(ret, kasan_reset_tag(p), ks);
+		kasan_enable_current();
+	}
 
 	return ret;
 }
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/431c6cfa0ac8fb2b33d7ab561a64aa84c844d1a0.1612208222.git.andreyknvl%40google.com.
