Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXH3WEQMGQEOULL4HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 45B6C402A85
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 16:14:15 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id v2-20020a2e2f02000000b001dc7ee2a7b8sf4859836ljv.20
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 07:14:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631024054; cv=pass;
        d=google.com; s=arc-20160816;
        b=fnxzyQkCqnHrKlcLGRr/qMjuj6VCwSbV/zzRSjUFBhCm3Bn8/1JB1AUlbGOsFRvMPC
         4MNU1qHW+BQL60c+ikG2lI5q+Y5vcjFJE9M3SROC4JzBzNPwuntcDuDyNIr1GR9f0Et+
         7qaYELBqwSsyozV0JD7+0gBKGp4mNf5twAsVSbs6JsyTE6p+GTFDnYbClZka9EftRk9k
         ptiSEsptB2QVjopcXE2Owli5D+c5lBTUwgXWZVFA62UO/uQj8vA7131AVjM4BgOfr95J
         B/64El/HM0BFB7bqF2XC6Q47N/dRyP5gOBUNW6nI9LUCFZYtBiVk1BIm2dy+EwNHyApi
         G74g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=vYbVzU/roz5Hd6APmzQkhHkwR8bAuaG2fmiRPN20EKM=;
        b=OcJvdEYpWzsuMk+ULp4k+7VQLiENEjsoU/uBZy4MeJaVUrGcg8n9m1vNfR9TYOEiI3
         lrn2UfSeM18J4j6XnAW5NDpTzNrjTxpvMhCvB1lRznsuUmv7fN/Q3CpBXaeqxe66S3q3
         NY7LIbKEcUikHZ+VTHCM83PcTOboLlLutJ2Phuu5i2KRthhQ2JI55G+XgBpXbD6vrxhl
         n//wh9pWFQaosFOG0esbgijCCxSVynUEoEjtSCD0vgG3w4qZlwp1g8b2y/JdDh6XaVoL
         u9XQVfo9dOf0vraUGLZGGZ9PRpikgZRzKL6F79KJM1KZHRRgBdy1l6b6a1hxgmJkwPye
         0jlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PwTMtZh9;
       spf=pass (google.com: domain of 3txm3yqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tXM3YQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vYbVzU/roz5Hd6APmzQkhHkwR8bAuaG2fmiRPN20EKM=;
        b=o//8ih/div+3JO9M7cBrnQf/TfwV4upVzRQWxwASa4H0VxHRn5NBKqdYdE/fodDhjI
         XcoMHmZnJ60fiGUQv07aaoLadxcyO4OyF1FhahLeIt9gbc6dYXN9hCLIVR/AC71L+MtM
         AOId45MAXCB+rpP1/W78utSr6WSi+v36Okxoe7dUCi32D9bCRKM+fnPv5Ijly0O+1Aqn
         d1Tw8IRT9ttrAaCnvni0ke1kBFYFSC1FyTFl1aCpYu3IlgfJVI3Nl8CNY/WcCOF/YgVH
         Nu4Ks3CdiWY5cuRjCXVhiBpNrTYSeW6R8wb4KvjWC4DsNQBGwTcBOoLZ2nidF9zh7ss+
         wgfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vYbVzU/roz5Hd6APmzQkhHkwR8bAuaG2fmiRPN20EKM=;
        b=pXy3JNyZMLEpGJb1MFKCfe2oGVOo7jrYWRSx8bXJj2secFZYZdQdOi3/8wIc/bVlUT
         2eBHvA/NTANtl3n4X6Gb9JS5C6TLJBbO9WYLWJpsqLpHEolgf69cr2/10ak0gnd+l4bG
         //RuJbCs8vx986tyUkN9XLSboDN6QLSGk0XB7F6xifAOqey4dytF3kB+8L5HWlpiXy2N
         h/ZpDmF2JYBSw5Fesy2Pythtf00sCWauC9PeLvHdAFuWRo+/MVeckY+dTkPYG8Nkpvut
         eoEwyFmPxoqsbjAuuv+QIJMIGsBih+fyPdbTsdgKjJS3WUaeduRQM24zprtDOD/BdcyA
         iZvw==
X-Gm-Message-State: AOAM531h489ZtHtdeUyMT5hWh9ah1TjhXpnu7JTziGZ9wbyg6mY48zM6
	mqQegGdJr70Y/UQNiIuZhkU=
X-Google-Smtp-Source: ABdhPJxtFMORfI5b89IP6JsuPtEykWr42ibXc10PSovXbIWqZSCSjrQewShAxzr856uUz+dVLbygQA==
X-Received: by 2002:ac2:4d10:: with SMTP id r16mr12546962lfi.308.1631024054824;
        Tue, 07 Sep 2021 07:14:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8945:: with SMTP id b5ls1754410ljk.8.gmail; Tue, 07 Sep
 2021 07:14:13 -0700 (PDT)
X-Received: by 2002:a2e:bf18:: with SMTP id c24mr15153906ljr.408.1631024053755;
        Tue, 07 Sep 2021 07:14:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631024053; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8UguTXtP6Hvdia/HC8zMVDNST7dQuTMuNPm4CqwTtaGTHEmjOKu2HbVz6PvuRXuem
         UkfPzgwXZeOFohUAmUTR8N4fA6c2diVAppfGH7SUL4ECPm0UynSDy9J38hP4540fqjZy
         FTplrUvBg+n74okbFdm97ALnufx3SSd+G7iTY+AhbVT2oVOrYWWDgRGzGw/eEpzJ5Gge
         Mp14wYBjcBtZYlhp5ADseTLQ0/gkKxNTPn77Vaf+WPU36urffCit+HlUnJVCmib7IETL
         LZ0Dp7ILzNecKUzHqE7iWOU1FSnnV+rlWQVg3esyrm3+Nr7Hux4sHr88nP+d6gU4X76r
         apIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=xcObahmn+nrr83zfh05tWVTdAkOdXoaYlFTrwb+vDxw=;
        b=pbsb58yXOzEMQgTq0SMEXRlwOqB4O3dVwh4SFzdUDdeMosyd7i8UD3QUJpgw2zNLNj
         gT5hsLKRf6Jq0nw3sH8eeGShksVgiaoj37p2QVogB4wF/vUYNQjkb+6hz/tMIiy7rhoF
         gklRIqkxa9ysHK+pxIg2RIp+mFlacjMj9BsnG+E+rLwAksMz4ycfoTsvfwjLnv9/A8Bw
         y9ywPxp6z5YdA4dHEmqAtEth9Aumuh+ZvLBB70jBltuuYWvbDi40Dkt/p5FZNLB8mCC+
         VIyN7yW7kukHrNOEzBpudBBOnShX7kc5RVxJx37BtXIagzGiH8YLiMIgAOnsay69I3cP
         K+TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PwTMtZh9;
       spf=pass (google.com: domain of 3txm3yqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tXM3YQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id bp17si407967lfb.0.2021.09.07.07.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 07:14:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3txm3yqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id x125-20020a1c3183000000b002e73f079eefso1270253wmx.0
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 07:14:13 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6800:c1ea:4271:5898])
 (user=elver job=sendgmr) by 2002:a05:600c:2193:: with SMTP id
 e19mr4229864wme.40.1631024053139; Tue, 07 Sep 2021 07:14:13 -0700 (PDT)
Date: Tue,  7 Sep 2021 16:13:06 +0200
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
Message-Id: <20210907141307.1437816-6-elver@google.com>
Mime-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.153.gba50c8fa24-goog
Subject: [PATCH 5/6] kasan: generic: introduce kasan_record_aux_stack_noalloc()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PwTMtZh9;       spf=pass
 (google.com: domain of 3txm3yqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tXM3YQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Introduce a variant of kasan_record_aux_stack() that does not do any
memory allocation through stackdepot. This will permit using it in
contexts that cannot allocate any memory.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kasan.h |  2 ++
 mm/kasan/generic.c    | 14 ++++++++++++--
 2 files changed, 14 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index dd874a1ee862..736d7b458996 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -370,12 +370,14 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
+void kasan_record_aux_stack_noalloc(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
+static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 2a8e59e6326d..84a038b07c6f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,7 +328,7 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
-void kasan_record_aux_stack(void *addr)
+static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
 	struct page *page = kasan_addr_to_page(addr);
 	struct kmem_cache *cache;
@@ -345,7 +345,17 @@ void kasan_record_aux_stack(void *addr)
 		return;
 
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, true);
+	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, can_alloc);
+}
+
+void kasan_record_aux_stack(void *addr)
+{
+	return __kasan_record_aux_stack(addr, true);
+}
+
+void kasan_record_aux_stack_noalloc(void *addr)
+{
+	return __kasan_record_aux_stack(addr, false);
 }
 
 void kasan_set_free_info(struct kmem_cache *cache,
-- 
2.33.0.153.gba50c8fa24-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210907141307.1437816-6-elver%40google.com.
