Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2VHQ6AAMGQEINU6IQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E1DD2F82A7
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:42:03 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id l11sf6015248plt.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:42:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610732522; cv=pass;
        d=google.com; s=arc-20160816;
        b=qxpTte4STHNe/eAkGubK+eit2hPZR8YnNQiVqhWx/0IgnCZdN/VsqvvN1BZ6aRYSqQ
         JhAELDNayjY/nljOQq4tBcgG9Jg+9wlgmibP3IxDxNp1Uqa9VQykZQ83J3pv9ShIR3rm
         wk4rum0CiphMjMQP2Tq7Rx/7mKw+kYoJNCd5AyrIEldtXLNi1YBdM147pNU1jzoQfx5b
         AoT5nzddp7vzkHNytoLRDbiHfBMD+E4T3U1Zpr+CVKbV88iGV9KaMCrrpMtPPwmoi1G4
         Oqio4pOHY0K3FRGl5k48r/fZLK8QqiJMC2AHYsybxUp5ysa3B27ppI8/kv9sWQPP8Hu9
         Be0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=BGsnaEM4aWEGNeqzC+O3QDKerrm8XQ0iyp+VEeRv//Q=;
        b=mPqURt9rarFBBDa74WPWCw20APJHRXmmmHMLd6hFzhfGRpeuOiqpDtbWlQzotVlooY
         vBVZcO459lk3ETyJsObwrr3wUNgIzARGYGk13Bc5BOZA9un+rqCbD6RNfIeUgtSGwabC
         ePZWgpX1ocDpNlOkNukWcN9c3Vl+BvcANdVrEEvwBZIrif7MI29nl0WSEuHXOm6r1bHe
         GxrHHwUaadsWLd2xSBvW6uLkV+LORXv6CJLKoEBVhWjI+f3rEigzfKHTE6hiJi+Mnb0e
         vEPXvsuWnrkb9sFidg3NGLikxgucKQFplqGEP5r+bIxmzvvqRSo9QmCwOa8KnPfmvI9O
         7b/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YxIbv2JZ;
       spf=pass (google.com: domain of 36nmbyaokcz07kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=36NMBYAoKCZ07KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BGsnaEM4aWEGNeqzC+O3QDKerrm8XQ0iyp+VEeRv//Q=;
        b=Ds1koPZHpBH2sHgfVJvRzoz/rJlJXwL4+s6jsWtjfYQ4NpMKXz8dTMMLJbRzEgB0sC
         RwhVM01R6jJk5FW5bPFv1bX0nVP8KnrHctebYApEoKOiW16tTnXnaYPgA0sKimlUGf4F
         kTG7RennZEkxp8/u6SzTq9Z8pmRPv+qPhDStTHDHwKTjfguKRXjoEVbEFBH5uPFLWx23
         7OZMShMGRbMNgeP97vDK6ywqbcR9608vzsIuT8B9tgCIUNKvgNYAeIBgv5EO0hksJk07
         nued+9YcqRbBv+NcnBlpATJLWKw+ZmxNz7OHUj5uq+t1Nexz5Q6qdCgJNMDVgqLHUDBK
         uZjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BGsnaEM4aWEGNeqzC+O3QDKerrm8XQ0iyp+VEeRv//Q=;
        b=A8/MmnCrL6zSLF+GhlvxC+xYukmQdqBgDm15mjXXHJHfPRuBlgMVNPHfcohnSTrxtO
         /dkX7ayBYYGidyZc+pfMYsTGRD8jA2roGqkJtpGYHuGn36XTzxbSOLJ/5C2bxZilY9a7
         Jv1DwYIc13Tk1YYkR8BCG6HlHzsotxcrLpPY8u/5glXFvK3GaGmQjHL8H7WOjM7q4Jfv
         HVsDSVjslcrTqcZ8BrqjulcCHerpfgN8Ez55WbipkE4QglRMsmWk4QYfrp4m08LMfB5w
         GmkIOqX68d7JJfp82iosfi10OYBu+l/pIyHyxu33RJrw+vxZgwOpHneSAS/HP+Vh468o
         U2Rg==
X-Gm-Message-State: AOAM533Cyc0zUR+/9ytK8dR7Kfgy/jQQxQ7XbWsRcLHym9OWLn8bf9Po
	KGj2qNEunuWUuhDQJAvAhrg=
X-Google-Smtp-Source: ABdhPJzw0Yk1UFvTPoRq6meZlzg1rX0t0AQVmreTANX+7si71GBZi6MbzEQCwti3kxErGTnpYV0JUQ==
X-Received: by 2002:a17:902:9896:b029:dc:3306:8aa7 with SMTP id s22-20020a1709029896b02900dc33068aa7mr13829916plp.6.1610732522206;
        Fri, 15 Jan 2021 09:42:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7409:: with SMTP id a9ls4994935pjg.2.canary-gmail;
 Fri, 15 Jan 2021 09:42:01 -0800 (PST)
X-Received: by 2002:a17:902:9686:b029:dc:3372:6e14 with SMTP id n6-20020a1709029686b02900dc33726e14mr13603738plp.24.1610732521537;
        Fri, 15 Jan 2021 09:42:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610732521; cv=none;
        d=google.com; s=arc-20160816;
        b=Rlg+Tyc93BjBpFxZtmQBfei4AzUOJiOIGgXKotinLFkFjB8ubcJcv8bpepf6vq7fxL
         r/sFxL2IMvaA0y4E58uZHYnDkVCKuwU9leL+w9UDq3ITv7Ag1J9WFJ51bvt2CY39jRG3
         4gvSrnLyKUM6Mq9Z/tNLtg7YPYhbrZ/tYD2IZUXuOnwTkvgQ6EvnjqsqXDf8xERS1Uv5
         EO9NqiHJe6vuM4dGmmp4Fe+9Nqoj8C+i/pE6secxAk7lgEr8xQa3uyeRtx74PFsuvMJX
         VelW/UsApXXfsiZ6Fq1dSJbVHiZAciKOsE8DvoN5nc0BuOrUcGrevTjbwQJyEm5wErDW
         6xSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=K3THHtce7/ygl6Gpfs3Di2sEUO2VBikWbOhVCkSY9ac=;
        b=qwMt4jI+PLT+HMh6RbImvcL52bLV0Q6EBZYPACojn7w0onukR+8w+vUDnMv06sQdAo
         3hR8yWC5eFy9kya/I9Ul3M5xnsFjjHS+cy3dT5mIk76zClqb+YwLi9Yhw/RrX4xpXBLA
         8CsPvDSlH23JmnxogmgJpR5pZLrpBL+qoAQxeMCr73ZZ5XGElh28dt9ob4DN1c3eNLiR
         m59iVWGzG+XtNRiab/WeSqdJBvXrU6ntMdjqZIIT/LJ2+Q90hd+SOtiaOOvux8mPaRLr
         mAhTmZbwtZEFsXrG13kb+DUBgFbFSXVhDD3R7EvNp+uLEumBdkjSSs1jGyDpFbmdPVV1
         4hPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YxIbv2JZ;
       spf=pass (google.com: domain of 36nmbyaokcz07kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=36NMBYAoKCZ07KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id jz6si410610pjb.1.2021.01.15.09.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:42:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 36nmbyaokcz07kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id h7so7946763qtn.21
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:42:01 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c583:: with SMTP id
 a3mr12947974qvj.15.1610732520689; Fri, 15 Jan 2021 09:42:00 -0800 (PST)
Date: Fri, 15 Jan 2021 18:41:52 +0100
In-Reply-To: <cover.1610731872.git.andreyknvl@google.com>
Message-Id: <093428b5d2ca8b507f4a79f92f9929b35f7fada7.1610731872.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610731872.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 1/2] kasan, mm: fix conflicts with init_on_alloc/free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vlastimil Babka <vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YxIbv2JZ;       spf=pass
 (google.com: domain of 36nmbyaokcz07kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=36NMBYAoKCZ07KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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

A few places where SLUB accesses object's data or metadata were missed in
a previous patch. This leads to false positives with hardware tag-based
KASAN when bulk allocations are used with init_on_alloc/free.

Fix the false-positives by resetting pointer tags during these accesses.

(The kasan_reset_tag call is removed from slab_alloc_node, as it's added
 into maybe_wipe_obj_freeptr.)

Link: https://linux-review.googlesource.com/id/I50dd32838a666e173fe06c3c5c766f2c36aae901
Fixes: aa1ef4d7b3f67 ("kasan, mm: reset tags when accessing metadata")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/slub.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index dc5b42e700b8..75fb097d990d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2791,7 +2791,8 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
 						   void *obj)
 {
 	if (unlikely(slab_want_init_on_free(s)) && obj)
-		memset((void *)((char *)obj + s->offset), 0, sizeof(void *));
+		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
+			0, sizeof(void *));
 }
 
 /*
@@ -2883,7 +2884,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 		stat(s, ALLOC_FASTPATH);
 	}
 
-	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
+	maybe_wipe_obj_freeptr(s, object);
 
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
 		memset(kasan_reset_tag(object), 0, s->object_size);
@@ -3329,7 +3330,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 		int j;
 
 		for (j = 0; j < i; j++)
-			memset(p[j], 0, s->object_size);
+			memset(kasan_reset_tag(p[j]), 0, s->object_size);
 	}
 
 	/* memcg and kmem_cache debug support */
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/093428b5d2ca8b507f4a79f92f9929b35f7fada7.1610731872.git.andreyknvl%40google.com.
