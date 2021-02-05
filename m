Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTUD62AAMGQEQB7K3AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 20ACC310EC6
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:12 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 36sf3908723oto.19
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546511; cv=pass;
        d=google.com; s=arc-20160816;
        b=qwNjwTaOohCaZrhm3Q4qEtAAxbCUv4saFOTDse400gTXuXhho2jPzEOIqqIWD/W8zS
         o5iyo/Fzg8nY1hUw675va2Ta6/SDIQJPE6g2qLvPnsydMS8sJGEi/hufHAYDBqxSTda9
         lQHEzMxV1IWBPzFJV078QLyLyCgxQdsy9Q3PlX2YlSB6nG8IAwOQGAkW3nhWLNNr1yv7
         /rRVe+OiWXNAlatUXMsnJIHHVvMvrDbP9O81HhiLJu16oRdmVYL6n6NxaCTZLV7xMRHQ
         u3kGlFWtDcea0DstqQ3VFIgAaVZcPuiZnK5llWGGpyj8gSG0owbf+B3hljeD3c/iiD4V
         Vvjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=m4TSvetdkr80nkBnat9bDMqiT+j7cUevS7/+vzq/7EE=;
        b=fXcFrEClx+GFqGUZ3sY8zyGJLBYZJoaPK6KZR4OofOqCeHH2fyEuaPi69kfLaYDzzI
         TjQfy3T+ZeHALAexDsNdip3O2B193yHCJA1oYAv6Tz11X4U4SuNTSgsWtGY5QWcy891c
         GjwiH+x9S/L2oYqBx05qpfFKHolVNu9JL5gx8YUybzCnJ5WCkJx1XJiY3drFttzTvcst
         ditN2BCJL7qLwjlHy6HHAIVBszTRDf/jeGb7w1LRug0gcaB26oCHjua2w15urs016L0h
         3EXX8ebAIGWKlyAptsk67EAjqhoeZ7EkILHhbzcoxXj2sjruULFqWxL4btttM/azQ4Sv
         ZVoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RwM46b1O;
       spf=pass (google.com: domain of 3zoedyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3zoEdYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=m4TSvetdkr80nkBnat9bDMqiT+j7cUevS7/+vzq/7EE=;
        b=MX2MptwtFSs8FFGsTMMKoZEv73qI0NNU0cVve4SyPZwvFgT/Mz+s3oQoMN+bPNqVh9
         7uZcvSF0tpogCoh29L39io+NdrZmdNY8Z94QyniPuG41e7nDmTYl5Wwb6NUwxIrbKocT
         gEQOYhuxRllrN5RfCYnQhrAlYb7//50JUddqjpujIWrhK3IQ9cFdo445+X2CNAHwq6bx
         htrsTGksZ5Cm4csp01xwhI89h8y6x+DBEr2IsAJB7EIUmtl0AJo3OyvNjsG2+oJvdKG6
         XV+znstfnXmy4Lxry71QcCtbSFPXdqbYpiKUQXfgNfUTXEusYLUbQ5hRIyXUJ9smzV8n
         uc6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m4TSvetdkr80nkBnat9bDMqiT+j7cUevS7/+vzq/7EE=;
        b=aTcW0aomSYin0nrl8luWb1vc8+z/A6/Nd9HcwpydpJVyt7qyUWBKbXfBLqtdpbnH6o
         GRkYCN5HPh51dmiQgqPT56Nb/bLzTQ+OjZicjpGAxERLp7e5ePEPCV4vOvQb/Jsh+RX4
         A5PPX1TTGIUsLiNJFHkJHx12csX86RciiId0uX51CG0zaQXHb+1TW+MGBolBNpUVaxsF
         1gOxv3hpk8wGH9ihOvTgw/BkPXXg2JTQUleZ0+MxdOz91OkO38n+4EvnjIrBXIEH2XAY
         J7mcIqNpmWG/b/PZp16luPvjuPV4QPg4ZRrP4XF79Z9nNgQg+kXoKV1q3p1C2FrxqGIa
         p1EA==
X-Gm-Message-State: AOAM531V2k2oKHZprpJiw1BZRp87SRbKOV0F2bVlOJHL+isL/Ddl50uQ
	NmgBfM6hg3zqWUU27p8YZ3U=
X-Google-Smtp-Source: ABdhPJzMwW3YXRyTVKwq+th3dPG1V/alfbBauUDesMpzeVYN5XO3zUSyNrUW4S/BohzDOQNsK1VNWA==
X-Received: by 2002:aca:b906:: with SMTP id j6mr3648214oif.159.1612546510956;
        Fri, 05 Feb 2021 09:35:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:7249:: with SMTP id p70ls1122232oic.5.gmail; Fri, 05 Feb
 2021 09:35:10 -0800 (PST)
X-Received: by 2002:a05:6808:2d2:: with SMTP id a18mr3767526oid.139.1612546510575;
        Fri, 05 Feb 2021 09:35:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546510; cv=none;
        d=google.com; s=arc-20160816;
        b=T0yniYld/EYJVjRLcKWh/AKjubNFp9+ZZJzd+TIyA4FB2A74pJsz65QeYryidWVCnu
         jE9zT3Xz1ROlnAEXKfeL+wlIHKSLpoLTLcmON3dq8g0XrwS9Jqrav9MWtSJTSIlx4hVE
         FQgrhIBWKwAkfOhm22cwUErJVp/sxoXPkFAtXk3FQ/fdDVMjG0nrXyP5/O/XqBGsNVdz
         69dPBarcG8uYJV5EciBV++A76AHtMYKPl301JZZTyGP2zLYeaAR4M4vlSe2J9HO80mGE
         m+Ws4e09NUkJL00/t0qLA0rtqZ0MZOD9AYHYQmh3SqcdGgCpKek8ww2JXfm6efdrZCBM
         lyaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ISHwxx5EnSKzUDUjZ1ysUZFyHBfF802klWxWhYA/428=;
        b=ksZtCfqwri8kiZ42WcxlLFgeobS8BbpFS14+x8AuPqv3dpd3uFCnIxlTKWD20+pyxj
         TfmKt+48PJJDzc/nQKhYVCXilyurJ+OtQ/izrHC/dJOY4WirEaJMdzEK3ZWNCzJsXePw
         /9Ro2wVVBi8Fi0PQT3u9jHgoH609gadiTUr89M18P8ai+SyTR71xPOBMHcu3m2W0xttB
         59p0yERcCPrkhIKa2xmdLbZO7nnmjeAC5hfypnectpcDa34SV+hAqqCBIeJ4zHfLYdA6
         k/53C5ILKCE7KEfZSi498b9Oip8N6ZMMTo8xtKaw8xc2WAU2I5vkHanpRV+ffeM+KVFK
         xWWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RwM46b1O;
       spf=pass (google.com: domain of 3zoedyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3zoEdYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id g62si484363oif.2.2021.02.05.09.35.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zoedyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id f7so5784969qtd.9
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:10 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c687:: with SMTP id
 d7mr5237396qvj.17.1612546510164; Fri, 05 Feb 2021 09:35:10 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:42 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <9bef90327c9cb109d736c40115684fd32f49e6b0.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 08/13] kasan, mm: optimize krealloc poisoning
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
 header.i=@google.com header.s=20161025 header.b=RwM46b1O;       spf=pass
 (google.com: domain of 3zoedyaokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3zoEdYAoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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
index 7ea643f7e69c..a8a67dca5e55 100644
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
index dad70239b54c..60a2f49df6ce 100644
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
+		ks = kfence_ksize(p) ?: __ksize(p);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9bef90327c9cb109d736c40115684fd32f49e6b0.1612546384.git.andreyknvl%40google.com.
