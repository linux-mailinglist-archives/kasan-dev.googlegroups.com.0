Return-Path: <kasan-dev+bncBAABBSUV7KVAMGQE5C2O2JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C9857F5452
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 00:12:12 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-542e6564e2bsf7281a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 15:12:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700694731; cv=pass;
        d=google.com; s=arc-20160816;
        b=wD2UGsZR2hBWYNwCkdtDD7i3twX7Nzk57XY8vGgoCwocyvRBY33LIandpwYY8D2Khx
         2bmMXa9poOYbH7mRQWrDsUJk044hntXFjFRoWbpMow0B+h5E0jVh6lMi99JgK6Sn3Wop
         k76UUp5S33TvtfqszEZcBnzIVrr1xINTZmaiE+mTSzWTEs6kD8McM+mmtVhWz6iZniSL
         kNnX7E5SzilZ1LUq84bktiKiY0Dt2OqDfq2d+lAS5RN6LweRi0Lb9SEGAsEyqjlJR4do
         cn5VNJTB8FIBHuH2eSAOuI44ya7v25NDmPL8GrLcB+Iu2yZclTI+tN2svHJ0XJtdXUgm
         e8aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=76r00sDILIN/kvSvpYl3lHyOcx5pl/0OjtMrL5tdNoE=;
        fh=fOg1Tf0zNjDt2cuVJIoiwDMJeeeK+fpyehPH3RFMkTQ=;
        b=w0h6j9u/11bKYQzREq8+ahb3DqrBpdfXSbJDhjzXmE2W+nQyjZ5mWuCmUrxaoMGzHO
         Vra6DfvVYSzeUK1FfO8OE0LildqmhMlH7CpgVe6T3RGgKoKSIhJF2+BiD90uVEqa6Yk4
         KmBKgXwbHlhJGVdDA9MvXvyya+Z7qe+GOcos+a1IEJfxC/SMLVhUQzUrKMsvz22c9Y33
         2pTM938geRKhXznWtP0na+qgoac5mtm8Vg2PWyFOb/QI3BPi6Y5oI92Eg5iNadOd3Xel
         ZTVS0wtZj/Q+DvlLP5zhxePlP1j1tzEX7aoz2vTLeCiM7+S8ksRulXinJJSqbKehtJmQ
         cHxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EbjD+Kjt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700694731; x=1701299531; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=76r00sDILIN/kvSvpYl3lHyOcx5pl/0OjtMrL5tdNoE=;
        b=Suc46wHk9Uj79i+b8OPi5vX/YyVq9SeynCEtUZPkEVgrPOrT3Y4ijvkNBiMM0VqfRY
         XFkNK6XU0DfQ4XDUJMukOwrRr8kN9Ou7D/eoRFA1hK6ZiGJHLafiL/Ycmvr8kD3uE47M
         owIllA3S97APZm7SI8AqTDQzE9tPwQHmr3IPXIvS9bB0+LwOJaIoovo8XXEZiZvsh2+8
         FSMoQlK77jzdSKVAW9Zp3vdBIJjI84H4zqHmG68xRMinut7beBIf0Yn9To+Oxrr0lHct
         a+KGuxgpTa89SCsJzh3yD/4yMBjEIREZ6m5FSxkCPLxZCLk6VUqEpinDt7L53U5mZn2p
         bvOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700694731; x=1701299531;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=76r00sDILIN/kvSvpYl3lHyOcx5pl/0OjtMrL5tdNoE=;
        b=DSR2cm7lCLK1vW6sD+VFgikB/Fa9GC/8UynbzdmlfWN3AdkP7NClSYSPD5Q3T31VmA
         ddtxsGc+LNfhMfvQguzJQ9QwNvKxMlgYprkHjj+M3SlCA7/ES0sz+XCuyQ/5LLEb9nnD
         cBy7QCK+iKmKRtHcBu1VLZ1lvhENNqbyeI5/l9XY329S1XYbuuIhfv8fRqLQVgH1p/hl
         T9Pnu2MwASk5BrvJH0KgZVo8anXJBQyo1M+lSEXgr+1xxX00OeGE8/zjRWRQkNcxQoG1
         QMVtrig2fqyl7bVwHm7Hpgt9sfK+SfUnw5aMqBMrULT6zittc3RAhW3uw+gTn3A4bq84
         AAxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz8q4uh8U9W4UIpLWdA2P8qjLNKCduK/UOqonwDARCFG6WgZCdL
	PfjRpTbfpLMSRGBwHlPSyrk=
X-Google-Smtp-Source: AGHT+IGrFseAX7oAgpS3gNLiLOMeotMzM5AHwZ20FBChlxFZ0EOu8ENY/0JALM0ybk8smUme8JQ6Hg==
X-Received: by 2002:a05:6402:541b:b0:544:e2b8:ba6a with SMTP id ev27-20020a056402541b00b00544e2b8ba6amr215095edb.3.1700694731168;
        Wed, 22 Nov 2023 15:12:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c95:b0:2c5:356:6429 with SMTP id
 bz21-20020a05651c0c9500b002c503566429ls158935ljb.0.-pod-prod-01-eu; Wed, 22
 Nov 2023 15:12:09 -0800 (PST)
X-Received: by 2002:ac2:52af:0:b0:50a:a7e2:f2b8 with SMTP id r15-20020ac252af000000b0050aa7e2f2b8mr2600808lfm.62.1700694729352;
        Wed, 22 Nov 2023 15:12:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700694729; cv=none;
        d=google.com; s=arc-20160816;
        b=XCghgR4rqarkUE1fuZl5PtsoqSA2nBRGwB0IWXU+YzDp27ociucBZ6hIwIJtbYQdrh
         IKd3fm+zz2A15JTvf3T+5AFyE6tfD5eIHmfb7WjZsMmf+tgcoY32XtIEkl1cSVPOkwFj
         YvkZjsbY1LvWxwDZTbaidCEkx+0xADwXyN8Rv8GSXwmnw7IeOhnQx9ks5Ss9CAuGiXpJ
         SAvwpOgFhyt/V/lou094XQtEV0CeDSNmVmx3r7bKMHsXRG778tbvaCvzT7ETvwxRQMya
         7h3InpGImztdf+KC7YSbE4836Vws8OdYOagaVgqNxO6XDVM/eSEFvtCIFJ6BGJOlB47Q
         Erqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=uNmdlwYGwAMCb5jza2UGKjePd3PtCVqVMGoJzVDye+g=;
        fh=fOg1Tf0zNjDt2cuVJIoiwDMJeeeK+fpyehPH3RFMkTQ=;
        b=aAKkB4Q+W1P63IFsOZ3NsNaPM9vwPLbaFZWUIssLBa3tsvi+3OOTggLGhkPdJ6AxKL
         MSJoDzAXiCzw1gxepbvRuGkQ7oZ4cc0SdfQwQKw0RfQmpV35zLssm1suoRDscNWVmyIr
         lEKuyhb1eg4Ob6CUschAEXrrCVQ6qqdXYwtRPNlkmsgH5WuC62Ihqf2FHXZxU5pmIpB5
         Xh9PPzuIioXoy27bybAJ9l5icGvK7h0PbcpXudsWyrOC1j8gv6YGtoUQzuz3Ff2zv3Rv
         cJrVJEfVLpsvWnN42jnG8HIi8EGA71OL4LwVQuny20xJoJ/fUL2Jtg4H5H5lndBqUO53
         rx2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EbjD+Kjt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [91.218.175.171])
        by gmr-mx.google.com with ESMTPS id k33-20020a0565123da100b004ffa201cad8si241lfv.9.2023.11.22.15.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Nov 2023 15:12:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.171 as permitted sender) client-ip=91.218.175.171;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Feng Tang <feng.tang@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] slub, kasan: improve interaction of KASAN and slub_debug poisoning
Date: Thu, 23 Nov 2023 00:12:02 +0100
Message-Id: <20231122231202.121277-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=EbjD+Kjt;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.171
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

When both KASAN and slub_debug are enabled, when a free object is being
prepared in setup_object, slub_debug poisons the object data before KASAN
initializes its per-object metadata.

Right now, in setup_object, KASAN only initializes the alloc metadata,
which is always stored outside of the object. slub_debug is aware of
this and it skips poisoning and checking that memory area.

However, with the following patch in this series, KASAN also starts
initializing its free medata in setup_object. As this metadata might be
stored within the object, this initialization might overwrite the
slub_debug poisoning. This leads to slub_debug reports.

Thus, skip checking slub_debug poisoning of the object data area that
overlaps with the in-object KASAN free metadata.

Also make slub_debug poisoning of tail kmalloc redzones more precise when
KASAN is enabled: slub_debug can still poison and check the tail kmalloc
allocation area that comes after the KASAN free metadata.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Andrew, please put this patch right before "kasan: use stack_depot_put
for Generic mode".
---
 mm/slub.c | 41 ++++++++++++++++++++++++++---------------
 1 file changed, 26 insertions(+), 15 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 63d281dfacdb..782bd8a6bd34 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -870,20 +870,20 @@ static inline void set_orig_size(struct kmem_cache *s,
 				void *object, unsigned int orig_size)
 {
 	void *p = kasan_reset_tag(object);
+	unsigned int kasan_meta_size;
 
 	if (!slub_debug_orig_size(s))
 		return;
 
-#ifdef CONFIG_KASAN_GENERIC
 	/*
-	 * KASAN could save its free meta data in object's data area at
-	 * offset 0, if the size is larger than 'orig_size', it will
-	 * overlap the data redzone in [orig_size+1, object_size], and
-	 * the check should be skipped.
+	 * KASAN can save its free meta data inside of the object at offset 0.
+	 * If this meta data size is larger than 'orig_size', it will overlap
+	 * the data redzone in [orig_size+1, object_size]. Thus, we adjust
+	 * 'orig_size' to be as at least as big as KASAN's meta data.
 	 */
-	if (kasan_metadata_size(s, true) > orig_size)
-		orig_size = s->object_size;
-#endif
+	kasan_meta_size = kasan_metadata_size(s, true);
+	if (kasan_meta_size > orig_size)
+		orig_size = kasan_meta_size;
 
 	p += get_info_end(s);
 	p += sizeof(struct track) * 2;
@@ -1192,7 +1192,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 {
 	u8 *p = object;
 	u8 *endobject = object + s->object_size;
-	unsigned int orig_size;
+	unsigned int orig_size, kasan_meta_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
 		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
@@ -1222,12 +1222,23 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 	}
 
 	if (s->flags & SLAB_POISON) {
-		if (val != SLUB_RED_ACTIVE && (s->flags & __OBJECT_POISON) &&
-			(!check_bytes_and_report(s, slab, p, "Poison", p,
-					POISON_FREE, s->object_size - 1) ||
-			 !check_bytes_and_report(s, slab, p, "End Poison",
-				p + s->object_size - 1, POISON_END, 1)))
-			return 0;
+		if (val != SLUB_RED_ACTIVE && (s->flags & __OBJECT_POISON)) {
+			/*
+			 * KASAN can save its free meta data inside of the
+			 * object at offset 0. Thus, skip checking the part of
+			 * the redzone that overlaps with the meta data.
+			 */
+			kasan_meta_size = kasan_metadata_size(s, true);
+			if (kasan_meta_size < s->object_size - 1 &&
+			    !check_bytes_and_report(s, slab, p, "Poison",
+					p + kasan_meta_size, POISON_FREE,
+					s->object_size - kasan_meta_size - 1))
+				return 0;
+			if (kasan_meta_size < s->object_size &&
+			    !check_bytes_and_report(s, slab, p, "End Poison",
+					p + s->object_size - 1, POISON_END, 1))
+				return 0;
+		}
 		/*
 		 * check_pad_bytes cleans up on its own.
 		 */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231122231202.121277-1-andrey.konovalov%40linux.dev.
