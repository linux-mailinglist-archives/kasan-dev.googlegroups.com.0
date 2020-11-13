Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQMNXT6QKGQENA26RQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CE50C2B2845
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:50 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 204sf4566631oid.21
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306049; cv=pass;
        d=google.com; s=arc-20160816;
        b=KlUnLCHoJg4gr3aWETEMD/b2lZhGbq8hpMcycN7PtOGha+mFrlWjCAf6ekH+HOhW+U
         fjNQF7u9h+u3oNN/lONDdJQsHFz+TXMTTYF/ppr+D6/N9mH3pTmIH1ZYgXnabBvaPErL
         Amyz/qvn4Dfx4Sx2zsvCI67mtGDJeMaP1etjUUA7D0WtE8XS3FB9tPJX8HLk2uvdeSDs
         BPzEuw0lALVDcQeRTVDEYX5Rmyw57yFb8u8MTbfb/8bPQ6VtiSCsgUJnx8HeHOYFAAR7
         qN21sXnCQy2J5Qp23y7dZxM0Qk/8OGd4ucMV0H+jRnjpGcfItlbrUnaQmvgk96LaDYqy
         5MDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3BCkc4NzIqAfJCvH1CsNu1f4zoBZLNT85rj9lOfGOYE=;
        b=UfHDyaigHylPIThJb7Oq735/EOHlNUi8VxC0bS6jF2r5+nJX5W4DBX2XhP8u3vpdBO
         38xj13gagRHRbb6vy7O4VF06Kg015C8Q17DqMvVWQqfHq9y6FBmQVb/H0u5JRjSAF7WO
         IRlj0Pw6qH2ufaOwp+QN6xGUwhBGE+rAdWLT3bCYIsL0ETcdR5A9mOSSKOZ2XnG4jIcz
         IiHirvam+XmCGva5+UcJptGHsclAyfoG2UdbfnLil73KD13EAQgsklu650j7oZe0ge6C
         UFFar1mYdpLAv7fhLCy9/qYQOmmA8+w63NonSKNTUlHftMlfWvXF6nLuLMpyIQtT/EuF
         aBUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=feWIg6qU;
       spf=pass (google.com: domain of 3waavxwokcy0r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3wAavXwoKCY0r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3BCkc4NzIqAfJCvH1CsNu1f4zoBZLNT85rj9lOfGOYE=;
        b=Gv1vjZf+Pd5MFomCZYOEq9RvgJVLyVn39ulA41PXrWg4/4A8OmVgARZ8PbbAl32pNm
         kbiN7OCRe8zLDTG1mPxEw6nw1oBvvWXGjmaLsig4FOql+++6PQw3M1RgeQXwJjCYGf3b
         KV0xibdZ+DyMgn560ss+6hzx6RvmIpQALHJMmDdmvN9tdXfQYFBnhgwFeqJq272PQZui
         d70rgglcLC0jhT5O3hPU6musDW+BHWCDmyoVa9gA1IRzrRrPchuunSmRBNAOiXhR0axf
         WT1tBqSubBJmKKQpn+wp9dsGGgXGKEX4fF/JNNLx3Cx6/BqF47k5BKb0qSQ+4OT/M1OO
         a3tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3BCkc4NzIqAfJCvH1CsNu1f4zoBZLNT85rj9lOfGOYE=;
        b=RpbJzORiA+ETedqIonuO9T0ISD1MqnCLaOj+oK5H+ypu8e73XzNNB0R/+Qlr8pNCud
         1e2jdM/9Wr3R19vZJQZqb74Am36f5guh0kY711lGumvSh1ZHY0F/Jh8D55OAK0Tr2U/a
         OIgXP5rxByBRXQseCeuMXiDAM9QscTe/FBH/+CnWxnRfNA/CmHyXT6JrPBAoTWz5E/Nx
         Op/hL1keXAsf+Kex5as3KECMBl7y++lBfxb+eCDl82N36NnTlAhCvNZj7XG8gpu7Etds
         2JGTj4M+KxXvU061KAxWzvsoQcYtSfoY0IbXOCBmiFkdGHWolvsvAPXxBF8dCf02Ahm+
         KryQ==
X-Gm-Message-State: AOAM531F0HapGDfGswhlMdt3A2S8KkJlb0gXWOrEN0J7MBb+HaqSDqPE
	QpnoSMMnv3hvK7j2B3PM/dM=
X-Google-Smtp-Source: ABdhPJzqAoIO+SNgB70WEz7Sv3nCladgxfqwzesslPkR+IIPjhf1ny5zEz9oXw5YJ2KD9Mp9M3yF/w==
X-Received: by 2002:a4a:e80b:: with SMTP id b11mr3176483oob.1.1605306049825;
        Fri, 13 Nov 2020 14:20:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d658:: with SMTP id y24ls474894oos.7.gmail; Fri, 13 Nov
 2020 14:20:49 -0800 (PST)
X-Received: by 2002:a4a:b04f:: with SMTP id g15mr3205101oon.37.1605306049464;
        Fri, 13 Nov 2020 14:20:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306049; cv=none;
        d=google.com; s=arc-20160816;
        b=UCLOqWUFlPr4VfiBIGhnMlUtz76Vs42uCNmZYRD3Cv1hQ/TYc4N0QrH+J3GapuFVU+
         bnloVwG3gJMHn09oSpj0GOdz9tZDL+tm2tVh4GNheijwFflMvQVTeK93h6hQC6ms0Zx1
         uEVz0j9QTSm7tsKBoeNFJESw++Z/tj5oxWFF7Rjt+jeGetipHsf3YiqkCEv3Jk+3es5k
         2UlAMZIMVacZn27GYHv3sXRnNVn+biyXuTIxSGumqqCSPQy4Vah++vCmpWl8iixMp1SP
         vAKKsoy3CNWZY5q0rdBsZJA2Y6El0b/Ij09+zvWizn28m/L66hQgIRlK9SDqn3og2e8Z
         1pEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=WUG0j444ZBT4A3BTzNH/LM6507YxULafwrr/Sriwg0c=;
        b=gc0WDyPphO3Ile2XXR9rCWCNrFllxUsQu1EscoQDwFc1eIN/UOzYrSmO9AguJd1QGj
         uteWC3E70GUBgzPJrbkV0jOUaJ93poGGX2GZbaBaesf6KmcqeavaLJ1pXvTxV9CQkr1c
         7o5qOVK79hwYCJpU2d6gsyz9XOE9k1mOfn0yIMS+4efu+AxPAxoMKC501ApFTqEy5Rkd
         B1fLuKKT/F/8wai1issjR4dEPUTtRKdx9LXNUACDZwy/5vQqJCxDZSFZr/aGF1mKG9l7
         rHaJFlrzfLY6wcLYVEbRM5V2EqiQZONJMwSgxSNjcpS690YOQr+BdVOS7nS6RDAe7Gd7
         cqSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=feWIg6qU;
       spf=pass (google.com: domain of 3waavxwokcy0r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3wAavXwoKCY0r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id h8si765545oih.2.2020.11.13.14.20.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3waavxwokcy0r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id i20so6666784qtr.0
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:49 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:d43:: with SMTP id
 3mr4767045qvr.38.1605306048874; Fri, 13 Nov 2020 14:20:48 -0800 (PST)
Date: Fri, 13 Nov 2020 23:20:04 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <38ed98141f58eb53eb23100caac212b1c1f3bc9f.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 14/19] kasan: don't round_up too much
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
 header.i=@google.com header.s=20161025 header.b=feWIg6qU;       spf=pass
 (google.com: domain of 3waavxwokcy0r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3wAavXwoKCY0r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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

For hardware tag-based mode kasan_poison_memory() already rounds up the
size. Do the same for software modes and remove round_up() from the common
code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ib397128fac6eba874008662b4964d65352db4aa4
---
 mm/kasan/common.c | 8 ++------
 mm/kasan/shadow.c | 1 +
 2 files changed, 3 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1205faac90bd..1a88e4005181 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -214,9 +214,7 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 
 void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	poison_range(object,
-			round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_REDZONE);
+	poison_range(object, cache->object_size, KASAN_KMALLOC_REDZONE);
 }
 
 /*
@@ -289,7 +287,6 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 {
 	u8 tag;
 	void *tagged_object;
-	unsigned long rounded_up_size;
 
 	tag = get_tag(object);
 	tagged_object = object;
@@ -313,8 +310,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
-	poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	poison_range(object, cache->object_size, KASAN_KMALLOC_FREE);
 
 	if (!kasan_stack_collection_enabled())
 		return false;
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 37153bd1c126..e9efe88f7679 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -83,6 +83,7 @@ void poison_range(const void *address, size_t size, u8 value)
 	 * addresses to this function.
 	 */
 	address = kasan_reset_tag(address);
+	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/38ed98141f58eb53eb23100caac212b1c1f3bc9f.1605305978.git.andreyknvl%40google.com.
