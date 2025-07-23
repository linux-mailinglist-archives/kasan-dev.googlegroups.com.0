Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBU7RQPCAMGQEGFFYLVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 02E02B0F64C
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 16:59:33 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-32b3700af0fsf35293301fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 07:59:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753282772; cv=pass;
        d=google.com; s=arc-20240605;
        b=ieiaA/YeIuEmTpUvGSkULbKn2tsOrzVOEZZluwruShj4lvmF5FbNLNDM1Cmfc4u/fE
         UHAGIKrZ02GXwIGXy/Oy/1BU8p+Z+en0u0xbi0WNqVVOD0zBRAN1KQwIz4bhsEWjQlkB
         0im2wI8HNkvRuODUEgMMNFxw2PEYb1MHpPxIgcyO4xSw3mbDPJcIR7yTFzjYlzPGvAAT
         2p/jBBDlH3Hmz+flKzrs/YO+17cU4HmttRL0gjCKaP5P2jaSoHINaG+hxfWnBxuh7J1N
         gAI4WsajkLrFSvpS7m2HUfFCdQqxpnM+PbFqF+5J1Ly83d9BGX8hXuzDq6zNUT5O9dym
         mo/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=VrX0AmUhel3THeon1dT42vfdS2ak8mSIGnq/LlDZa8A=;
        fh=t8Ju9ix9UlUbOAo9QTgqi3jnshG5M6O46qHtNVwkkX4=;
        b=UEiNxs3KR0w/qNRrlJ7q8EUPTvfva+s9vxFbUQYZ1gNTujLrj6/9ANFnMbMqPIp4pD
         xaYVHBZzbWVw0b9KFAPmwKVNGUPSFNdaco3dsJR5Wmwkw6+IjBg7WQV1uwP91Dy01JVP
         3jTYxZhak12QPpiDFjZNnvI1XnPsyrhpVULRAzFx0pCltzMJ/AsHwge/ylAxdyiumgOn
         AnFpckKrRHMVUe7G6Ce317rK5IZ+rdPP5J8uDBvZx1BYoXjksJdkpOsfzOv5U27LZYoF
         c5ueTwSZ6hIF0dftUMSllLkBIJRw07Y9skZYD54XrnmtTFfDvyBlY7EaPh5BCeMzjn6U
         LQtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WynYgD+E;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753282772; x=1753887572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VrX0AmUhel3THeon1dT42vfdS2ak8mSIGnq/LlDZa8A=;
        b=g6THmtNRGat+Kq15kY6e8BPFasXUu4rVcVbaNScgzwUThnoi0TUNwdsZaGY6GBLewa
         lvYZQKLcrLjgZoTSJPgvOE4RlYprTFxPou+elqx+CG2vXfviAhKlA1jEbOzl93uPmxNZ
         yhWG+VB/sGxenEUoZe429fFYctRHdP303ugJg4URIKxNdo9qoBpSVDYvks7VPDYz28J9
         JL+W1dd2DoWUr3/DiypkBpQaeFh8y7A5Ml30v4y21UMxjymusrJPayV8WsZGWrajBIkw
         5qv9Yt4Cp/TMdc+6EyaXT/xMmg+CWMne4vdscDOSZGBj2faK2e3TUTqWQJXwTHPZd425
         nfEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753282772; x=1753887572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=VrX0AmUhel3THeon1dT42vfdS2ak8mSIGnq/LlDZa8A=;
        b=JwZBhUAxfMaAXjiSWM9Mae6ubqqAw8bR0oiLbQUp6a8ux6NR6Rf8n58dkemAytdM8i
         IIc+tcQZRGQZGmbe53KeDhpe1gJqmuYL2aVZiSGH89WQqXyhsc6hk5r03hgbbWrvVGXn
         0iaLf27ucfGLvdOzIZJnF7SEhDUunrV2ET5tpzacq+o9LPwX55NuMf60qio192KrFk5B
         8mrQHkowRiK8NcuLJQ0bLbrh+iYZQGgpx3DSN/RxPudDpezPpIhQSX1MBQU2te2WN2uF
         gIE8G4au54cJBLivB69mOUcJP9hjHYJ2oB/Mtv32NJUdgb1KTbhboq+Qj+Zj4/+7TRB2
         /geQ==
X-Forwarded-Encrypted: i=2; AJvYcCWpw1ozalc9YIs/3RLbcqvH1FsPWDFH6gOfFOKpZEYyVERw8K9qOA/VU+rGcBQssVO7IZvotQ==@lfdr.de
X-Gm-Message-State: AOJu0YzM4x3q5uq9YYHPZzu6DWQZRtpfpJn+iyx9gYWLlmPYcrifSHSf
	LFCMU1F434107tNecKuj2Z+AEoTQ9YwVAjLHrvnB3Fo8MR2pPfhGdyKj
X-Google-Smtp-Source: AGHT+IHtdsN5fszQTpNDPgvPYB8pcGkJMcMtY4xy7wl8kXJlkGI4xe7yKyleAbey/FgMe0eKovVmHw==
X-Received: by 2002:a2e:86cf:0:b0:32c:bc69:e91d with SMTP id 38308e7fff4ca-330dfdffcabmr8352371fa.39.1753282771658;
        Wed, 23 Jul 2025 07:59:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe48iJn2DY7L6KnxwwKQK1l0fEc4TW9Rj8uGgAm7pUIkw==
Received: by 2002:a2e:ae01:0:b0:32a:6004:f724 with SMTP id 38308e7fff4ca-33097e02cbfls14035801fa.0.-pod-prod-08-eu;
 Wed, 23 Jul 2025 07:59:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKOAUN8vCgQmCFN92wAXJGQgRiqPE6I7q9UOoc+UpsNvd+B8C1gafcLXqyryr1aI/JinT9mJlzG58=@googlegroups.com
X-Received: by 2002:a05:6512:e8a:b0:553:3892:5ead with SMTP id 2adb3069b0e04-55a5133b40emr965526e87.2.1753282768725;
        Wed, 23 Jul 2025 07:59:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753282768; cv=none;
        d=google.com; s=arc-20240605;
        b=gDWbHc3m/fMQJWg+Hpjq4OSGf3+NNtJh5yvZHW+WFbbP0ddCDB8gWffnGeROiKpHuX
         ppg4CiWSUdRpTVwV5/E8TZn1optNE87swGtFCKwf7BwnfJlM0b+GpD9BrCM8O6gB5Nig
         Mr/vvfEkL58jfMBa32Rmx5cNvvC8B/kfBLq7cv9XZ4uac2Yhu1K/aetxeDpu6XyrcEef
         Kw+UNyT4lal8WOstlQCa3UiVhoerVCNYq4HIhvL99cPsX5Kqex7iPaaqpN0hiF5tEYdJ
         evfbORCuqvy60g4Ogp3ZuUMxTL8LCaOTZMa+IUQL6Kd9xs4OCNoNiXogexTsMAfQn12E
         Ig2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=mrUzeAqJAgSJcs0yfhfK8Cv47SEHn3fw+SKS6td8SA0=;
        fh=dpjObDQTtiWUUDLcUr0pZIJC/qYKErD7590uCKDTUSU=;
        b=Yg/rw55UWUO0/cK+pSG5/hi70zG5fNunyRfxwoTWKGf87MnDw6VSEwInbZHVAplWj4
         VIMeoB+04jHiHTxt1VVrA4V0tWEQVO8y+clM8AFBu9DseV9urW8UmSH5asWr17nG1D/g
         weMol14U2++eoomJWyeUS1Zxm8SrMk8S7cXhAiKeM5D3eJwm7yRjIAyjatrIMsCyPu/F
         Awzgt4gMyKuN1tkXnf4w1wbSbg0Shj1ENQy9TeItg5SUjQDKcdJ0GUhon10s1zw+yZU4
         kBKo+cOB1vF3SSZsUBG5BoBiRCXv3V9gE/I9Rpqvq2zd0rlEvChCVxKal6Ef7WlULP8V
         Pg4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WynYgD+E;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55a31a12f16si347546e87.0.2025.07.23.07.59.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jul 2025 07:59:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-456007cfcd7so83645e9.1
        for <kasan-dev@googlegroups.com>; Wed, 23 Jul 2025 07:59:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWrAxjd0y8mApT2bmE8BHu3/Iske7bCnpM9vtogopB7axn4QkmjAYMY5pK9MFZRYKEYYRMTXymlXKQ=@googlegroups.com
X-Gm-Gg: ASbGncvkjIpKJQCgOQfKPCiCrLrLOfjTCLoLiKLgxnL2pMLgyq1A24q+eJDXCh3Fz6/
	Jzw7Ifgjldafb92UPe42dDyvcT8WjYzDV8I5Ud6hZsQkSirHYut2XZnt5u8Fejf7h9JsJNmM8om
	slDEDRq7V9x+YjhxPpEXy3uX5GWly5w4L6j4xTR2Na9FPXCNjnKKGMYfovEC0Eu752m50tY30YW
	XqALMDwEClzisTuDgCFJAUQFcyraQVy/anwN1YkLC5VlN8NbwfKWKD9VgMPXGMFEnNQ/Fr971zw
	nIuP2QKcGMoOM6IL0GjhLBM1Ku5nnuNZBDZhcyk6w9m4wdhR2tAmu1YJZUMDCDiVSkoRKp1jqiJ
	X7JZJeyvDz9vhnl731fZb
X-Received: by 2002:a05:600c:c04b:10b0:442:feea:622d with SMTP id 5b1f17b1804b1-4586947515fmr1001615e9.1.1753282767736;
        Wed, 23 Jul 2025 07:59:27 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:8af4:48b6:182f:2434])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3b61ca487fdsm16553683f8f.48.2025.07.23.07.59.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jul 2025 07:59:26 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Jul 2025 16:59:19 +0200
Subject: [PATCH] kasan: skip quarantine if object is still accessible under
 RCU
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c@google.com>
X-B4-Tracking: v=1; b=H4sIAMb4gGgC/x3MQQqDQAxA0atI1g1M0xbRq5QuMjbVIMQ2URHEu
 3dw+Rb/7xDiKgFttYPLqqGTFVwvFXQDWy+o72KgRI9U0w1HDjacI3u3oE2/hZ1tVhMUSnXOTZO
 E7lD6r8tHt/P9fB3HH18ZYKdrAAAA
X-Change-ID: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1753282763; l=3240;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=adPHI4t4JoxREbQY3IlmOrd4nE1YbruoXqCJg1mANYY=;
 b=Z83uOcvUi20dyNI/jDIxgSTZANRZyssbbsESb040Fl+CVwwSVB63M3K9wCM+YfaV/mMVv1/Uq
 PqVrnmlmqnlDPPlzwpQFvrT3yOjtJkds8+j17a6WtMFj7gTR0flqjSV
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WynYgD+E;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Currently, enabling KASAN masks bugs where a lockless lookup path gets a
pointer to a SLAB_TYPESAFE_BY_RCU object that might concurrently be
recycled and is insufficiently careful about handling recycled objects:
KASAN puts freed objects in SLAB_TYPESAFE_BY_RCU slabs onto its quarantine
queues, even when it can't actually detect UAF in these objects, and the
quarantine prevents fast recycling.

When I introduced CONFIG_SLUB_RCU_DEBUG, my intention was that enabling
CONFIG_SLUB_RCU_DEBUG should cause KASAN to mark such objects as freed
after an RCU grace period and put them on the quarantine, while disabling
CONFIG_SLUB_RCU_DEBUG should allow such objects to be reused immediately;
but that hasn't actually been working.

I discovered such a UAF bug involving SLAB_TYPESAFE_BY_RCU yesterday; I
could only trigger this bug in a KASAN build by disabling
CONFIG_SLUB_RCU_DEBUG and applying this patch.

Signed-off-by: Jann Horn <jannh@google.com>
---
 mm/kasan/common.c | 25 ++++++++++++++++++-------
 1 file changed, 18 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ed4873e18c75..9142964ab9c9 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -230,16 +230,12 @@ static bool check_slab_allocation(struct kmem_cache *cache, void *object,
 }
 
 static inline void poison_slab_object(struct kmem_cache *cache, void *object,
-				      bool init, bool still_accessible)
+				      bool init)
 {
 	void *tagged_object = object;
 
 	object = kasan_reset_tag(object);
 
-	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(still_accessible))
-		return;
-
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
@@ -261,7 +257,22 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 
-	poison_slab_object(cache, object, init, still_accessible);
+	/*
+	 * If this point is reached with an object that must still be
+	 * accessible under RCU, we can't poison it; in that case, also skip the
+	 * quarantine. This should mostly only happen when CONFIG_SLUB_RCU_DEBUG
+	 * has been disabled manually.
+	 *
+	 * Putting the object on the quarantine wouldn't help catch UAFs (since
+	 * we can't poison it here), and it would mask bugs caused by
+	 * SLAB_TYPESAFE_BY_RCU users not being careful enough about object
+	 * reuse; so overall, putting the object into the quarantine here would
+	 * be counterproductive.
+	 */
+	if (still_accessible)
+		return false;
+
+	poison_slab_object(cache, object, init);
 
 	/*
 	 * If the object is put into quarantine, do not let slab put the object
@@ -519,7 +530,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 	if (check_slab_allocation(slab->slab_cache, ptr, ip))
 		return false;
 
-	poison_slab_object(slab->slab_cache, ptr, false, false);
+	poison_slab_object(slab->slab_cache, ptr, false);
 	return true;
 }
 

---
base-commit: 89be9a83ccf1f88522317ce02f854f30d6115c41
change-id: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24

-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c%40google.com.
