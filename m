Return-Path: <kasan-dev+bncBAABBMHO26LAMGQEFH3AT7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id C2C6D578EE9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:13:36 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id d26-20020ac244da000000b0048a48e661dfsf1059936lfm.12
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:13:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189616; cv=pass;
        d=google.com; s=arc-20160816;
        b=V67EMaIayNLZKX61sfBndC0XsHhIT2i71j/Mr80h7nmPbPtiikEjJ8yIXprwNl+wEz
         q8N7KIa84fDzERnBBoWPJes8UWn30EdIDz9RYOtfLtd9KtpJe6lE+csluZCmFydaiQSf
         UXJMKJ63fSNFEMQNNHNImIc0zGpp1nnyhfuxPUFs99ACml0D+lrNb0lbu1lO3pS7uutP
         SRB2Iu+AGsgrnWWCoxPxIGJr5tUCIbpb85KD4WxhRy0qwLrCKePNfq+15HakOFEL65h2
         XBeJhwAtZQXcdeIcKVvHns8aZtvIra79klC+5w8v5c+kbWTPaVenonLpaqL6g2jfmn5Y
         DPeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hh5Fd0HYYp+nhv91lVz7UhAaWbECvlIhGiOXNJn8xWg=;
        b=LDYdpYGq8w+lPw9zP9ACBxAxjpKDlmxN2S2lXM6LBOkQ8t++6TOFrt16Ag/yKX2/es
         PlrqihuCJvdiH9r1kttdSa5HVHBv7sEugrXNBU9FKnBoyF2mGjM4Y4TFUJ+YX+G5NSOj
         qTgpfVDD2H3cBS3lwYJvJSxaMhW9HdUura7XOzEDJNUnEkkSH9s9rQFv602m0X0bhqVi
         b+bQotuUkGaW8nwRJyV0hRC8BOAMEGRNd8JfLW72k3QaBvBkP5S3nEP8gMR517bb2Bdc
         HHKWxgL4ofkiqQYBdiGxiuRm1YoNttIKvb/06vvRug/lLn7lLawwfGZjKv0I3csfW+8o
         o6tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=l78plOGG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hh5Fd0HYYp+nhv91lVz7UhAaWbECvlIhGiOXNJn8xWg=;
        b=p5N5z1+Y+Yui9Xi3fULgr+wHplNX3KBqIlqlnt1nZU9ThUQnfEgwexgdm6RM/XslBv
         OlV5BGXH9DdH5FAWYWjsVIJY+YLeEO8gag5b4oh2Figv8B90F40474X6dcjQDWMMtH+K
         w+8uMXsSV48lvciX2ccGPVAfpRiwhhVNxE3k8SglzZSzDwmDrOaK674lKOulnz1ZBT8P
         riMkQD0HVPzIF90qYnPdDHpDE+Zp4mh0ZJY8CMKSnFnrEneej5dDCQnPfxcB+WNL5cnK
         8o5rU+ZfZQsMvCEsjrM4Q/M+zF87yMiABO1I3XgcBTX9B3Gitl36T/vkv9tQkYzmneAi
         lyaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hh5Fd0HYYp+nhv91lVz7UhAaWbECvlIhGiOXNJn8xWg=;
        b=cXYkvh3j6AT+BTydh5Bo878tr3gM59N4V1oc8CZA0uQRy4Tg85VHmjCt2yixPhDXCy
         Dhxx+MOM/wmobrhhl67pklfFWWghYgvSuAZMf5dPbuHQlSlUIqQfR24jkkPwOrwoTqHu
         zmInetfz/PIrk3/AZkUTYMi2JA7lVUNLsQhRLGl7Ia5uOgJAieO0pf+tEiJKZI6mohG+
         4HNAkAkh9CHMG2JTVVsgpvhXjmkNq6edNCluabEanTSh3dK8G74k1bQs4b+CrmoAjFEb
         qpjCBlfbkfq/hORSfUWpuqlG5CnvAgRHgyzMCEmL/pwoB50C96Fw7kAGew/I7lGkrN89
         z/1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9x2l4SgVtGXoqtMvNyUl3ztO/X+i7ypeL9qC9VLa2gdkuwcGJV
	ib4jtlwsCXNxkNZ9egAN7IM=
X-Google-Smtp-Source: AGRyM1uWep56MV18ZCjURwhqlc8KrzzBSTrCzddopcr1/9JDmbXZUekiimS7OjPoerPqgc3nFGe9sQ==
X-Received: by 2002:a05:6512:3984:b0:489:e65c:4627 with SMTP id j4-20020a056512398400b00489e65c4627mr16589146lfu.72.1658189616291;
        Mon, 18 Jul 2022 17:13:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:910e:0:b0:25d:5c90:1749 with SMTP id m14-20020a2e910e000000b0025d5c901749ls3206922ljg.7.gmail;
 Mon, 18 Jul 2022 17:13:35 -0700 (PDT)
X-Received: by 2002:a2e:9917:0:b0:25d:a469:75da with SMTP id v23-20020a2e9917000000b0025da46975damr7860762lji.55.1658189615502;
        Mon, 18 Jul 2022 17:13:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189615; cv=none;
        d=google.com; s=arc-20160816;
        b=Gz6g7Bs3/wOPZSQIeJDK4LZZD+MmBihmXvNNdOg2z+QthfMVVl3FbQu7ghfR1Pij5k
         DTX0FBHh/hQTlxbsZgLD0ZrC+B0/8rpnz77r3RvHdE0F8Qd8OwzzERguLxP3xrBPSpH/
         oXoE+iCDdb3fYFTeC+IAB/eQu42FV7zgJyLpffa6gqF7qx/Dlf7yemPUN6h/7ojCmLi2
         OPief26P0MPMtsGQr0x/Wll+JY+eUFiwmA8Ith4Rd4qw2Du8cb0gy4Q6Gar+XIRb6l6j
         yT9bz/Atdbzm6ZMILhSse2Oqycxj5bSiBgFaoaN+86LbQLVWGQHRQnlQc+DAxihr/NqW
         HmnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6+gehTqFh9JAtZFAnb2OrzE2PLFsl5pe0e/6PyzNuaE=;
        b=vqQtVhIlX7gRy0JHZ8MP89mBorTIOLXO2PVRLME2rtrJ38oYx0P7CJoafLh9N8fnpA
         872HSrhPgLIrzTLgGKWBihmRRLt7JyQgVXvC6xRqaSKnpgT60mp8DxH6/+YDcv1Kh16h
         mz+GgSLcy49HUspSNpBsHFs/ajEfMQ0ad6e8sgsnAqewUf9JlUgPFoiYVnMEr6usOMJX
         aDLqOIN4jWuXRmKL9zlAvV4RPLBzYTbbYusOOBU2VG8jGT5QRR9QBi0RAX+pMBALltPA
         cGc+T7cCkjqvjSfGFb+Dha5H3GOIT+tnNNh+F/0HAKlyqVjOtcEJyVI5SAVklctlGd1M
         ec/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=l78plOGG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id o5-20020a05651205c500b0048858e79d43si384038lfo.10.2022.07.18.17.13.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:13:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 19/33] kasan: pass tagged pointers to kasan_save_alloc/free_info
Date: Tue, 19 Jul 2022 02:09:59 +0200
Message-Id: <46aa2a55f0bcf04a2617222936d15119581f6dd7.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=l78plOGG;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Pass tagged pointers to kasan_save_alloc/free_info().

This is a preparatory patch to simplify other changes in the series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Drop unused variable tag from ____kasan_slab_free().
---
 mm/kasan/common.c  | 6 ++----
 mm/kasan/generic.c | 3 +--
 mm/kasan/kasan.h   | 2 +-
 mm/kasan/tags.c    | 3 +--
 4 files changed, 5 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 89aa97af876e..3dc57a199893 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -192,13 +192,11 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 				unsigned long ip, bool quarantine, bool init)
 {
-	u8 tag;
 	void *tagged_object;
 
 	if (!kasan_arch_is_ready())
 		return false;
 
-	tag = get_tag(object);
 	tagged_object = object;
 	object = kasan_reset_tag(object);
 
@@ -227,7 +225,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return false;
 
 	if (kasan_stack_collection_enabled())
-		kasan_save_free_info(cache, object, tag);
+		kasan_save_free_info(cache, tagged_object);
 
 	return kasan_quarantine_put(cache, object);
 }
@@ -316,7 +314,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
-		kasan_save_alloc_info(cache, (void *)object, flags);
+		kasan_save_alloc_info(cache, tagged_object, flags);
 
 	return tagged_object;
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index f6bef347de87..aff39af3c532 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -500,8 +500,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
-void kasan_save_free_info(struct kmem_cache *cache,
-				void *object, u8 tag)
+void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 	struct kasan_free_meta *free_meta;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cae60e4d8842..cca49ab029f1 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -309,7 +309,7 @@ static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
-void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
+void kasan_save_free_info(struct kmem_cache *cache, void *object);
 struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
 						void *object);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 4f24669085e9..fd11d10a4ffc 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -21,8 +21,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 }
 
-void kasan_save_free_info(struct kmem_cache *cache,
-				void *object, u8 tag)
+void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/46aa2a55f0bcf04a2617222936d15119581f6dd7.1658189199.git.andreyknvl%40google.com.
