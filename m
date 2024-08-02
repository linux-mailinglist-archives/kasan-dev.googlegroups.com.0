Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBUMEWW2QMGQEEPNAXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5144C94646B
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 22:32:19 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-52f0258afecsf10495762e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 13:32:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722630739; cv=pass;
        d=google.com; s=arc-20160816;
        b=M0wz4T2GnXYYUyi3gxKkuH8FXlJ+BGGbuGwtte0v8NoaZMe7eH5G+OHdTQMpgg2gvF
         Vq1VEyQuuS9LmzudiUMY2Ho6erTGd6ZevcTo6tTEFVAYpdKb+/RnBjk4yKYPtHIZeltl
         Mp3O0gCdHbHsSspjvtbEsGfaojS0nDtONlmZiigELA0D+yLiWAxY76Toq+L1RC92sacD
         wPTPlJtoQxPFImlGu7ZgB6ihkhiQT7y/faUhU+edKPESXfGI0NH5HTtQu8+EBa4cgNPR
         qtHfaq6Zpuz7t3nd2EiYvDF7wr5BOcUgPqP6Hu6krEEYuNq/x8bWR3n7peCSV03bwOlj
         E34g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=mz4szNPUpdhySPUAcJmit+cI3UmgtPPiUAJc7z12eVU=;
        fh=PZlk1HiV9gVmk5aoHHpFmjYpfJFzL8EXEeW/xDLOx+I=;
        b=KOJD4TxzeayAJCVIFGbO600to/jURkUw9O8C5p2QMEUWWAStGfXkiQApFDxcgBO4Ul
         yBHFxQHJQizKilSXPnFJDcHICIN0DInZjozH5yYoV0MZ/subzuVWoiImPPPubp4jN4Tg
         2G9LEjrlW8GYjDsTS9NC98n66q+OvlHyyIBMDdo0lMADypWYkP4Is/M+UoHUt+BjijA5
         bP+bZdhTUEud3BE/bmdF5QVOj23Gbd1uZk6DV1xJz4LTFo4LPgoccKZkzta9XnH7/c2O
         uspUzilXnjuupBkphr6xFJ6ResVuFpf83ujoRMT6MgZCMLNQU8Oav8m5Wm04r5IabFTX
         MKKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=diWpz7P7;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722630738; x=1723235538; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mz4szNPUpdhySPUAcJmit+cI3UmgtPPiUAJc7z12eVU=;
        b=OTXhzGMi4czRBIQBEWLJhOttY1gxtZGwfV3XU1NsIjGI5nu6ZamakCIjelvZmYVvS4
         l73yHa0+KLee8DFszj1OiEMeFo5NjtMMU3XVrbCK5bvJ/VCJfgognItk4G6jcpYOLj6D
         WSW7Hj2oLwIXpwLnsOVyApoS1Y/prqyBVs2RBmIZcp1L8SI2Hw6coBK2w0R31I6nhXmc
         2P+4YKQ6GvK3kmoNMmUM54tVBiRlRL8O7IRzanjRduHphttCjlC4CEBq6XJLmpGhKtol
         BYc4knA5rHyDqMkolw3ZXSj4L9hiaKFmgR+USdxRvGRL1Jc8f5WP42bnW8Q0ezOHg2Jd
         FBaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722630738; x=1723235538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mz4szNPUpdhySPUAcJmit+cI3UmgtPPiUAJc7z12eVU=;
        b=LBsr++tZ/JruvCh3oynzfdXIg8/IdIJwyaMQEy/gdIJm5jN226uv8CHlvzNe3xm5H1
         26pz3iaV0MHWCk7py4U+wrDHvGzVOXvZS8+eU1apdlasFAcFuMpcLl0j70OeFPM6CPYH
         CMH9UekjocrcLAyrlP2r7OTX9HNZNLaFashrPolkX6TrG8ZD/yWT1IJ6mzGIqj2LO/yi
         crKRh51IsgDguZQL33ipYbpgWKQmFx7RbKJWDU9vR+/EK6jCHiV/RWtNoPJnHz9anric
         uOyKwTMjr8DwjhuMQpk22LmMnfHLumkiyl3vViTn3hSHJvSQCV/0EetRtvKCrfba8Qu2
         hc0Q==
X-Forwarded-Encrypted: i=2; AJvYcCWk3G7/IfGrvGebi/trL0eeBDLyhFd8Vq/ldMa+2fpfo/0/cQiEXKSlbXM0Px5XnIMkddxPwtaUHg/mOGWmSyzduS6EZ/C1/g==
X-Gm-Message-State: AOJu0YxP4oaHvJlGXQ0NmX1Hj3sViLjbOF7cUOTGYW7r9wg58bZYHFR4
	fIyD4MFY6s4XVRHosX2C3cOsPLVYHdyqKb3FFzABp9SHQSaK0Smv
X-Google-Smtp-Source: AGHT+IElwftUq7ChSwXM7845fcaLLO9bOSmu/3eXe3476jslIRM4ZwUYQeJOtEliturmU5jOtneGBQ==
X-Received: by 2002:a05:6512:ac3:b0:52e:9f17:8418 with SMTP id 2adb3069b0e04-530bb363280mr2794609e87.12.1722630738156;
        Fri, 02 Aug 2024 13:32:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:282c:b0:52e:9bbf:bef3 with SMTP id
 2adb3069b0e04-530c3082964ls123949e87.0.-pod-prod-04-eu; Fri, 02 Aug 2024
 13:32:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1EWNgD5QvBRH0+7GhyMoPsCt2leUpDPNlCViq6HJ9oPK/qfcC4lFD6kSjS4R8oMUJEmuOT2AU6bkEkqcoTbySFCocJg9nBwuCbA==
X-Received: by 2002:a05:6512:b21:b0:52c:d76a:867f with SMTP id 2adb3069b0e04-530bb3041acmr2730417e87.0.1722630736014;
        Fri, 02 Aug 2024 13:32:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722630735; cv=none;
        d=google.com; s=arc-20160816;
        b=ZajJD+s53pNMEYNPwp0HPoJgA5u0MscdfCkyhbFoUSkHWnoSfTdP8HnswH30+M9kQ0
         4Uuvqk0QIB/o1vfHWhdbVToXWaDgKhN8+w2LaVu6HSmxBxgoeAkli4pQWEcDiAScewfz
         ga+k+Cej3YaZAll216uQ1Vo7NnSRaT1+vVyj7YS0p4dVMy/B4l6ExfpLWTEYI3Z+LHWt
         0y3eUxUIeRvqs2rxk9oucoflOcfXiX62oWBs+elpFw02z6jOVGp7S0OpytzAHrx1yd+f
         tDFqHXrFY66xN5lKmZ+PIUnoEBZx+qvAbqV8Pieq/a+8bYeB1V505aNlekmAj7koyjqQ
         /MRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=gS9NPze8LdlLVayadYCCoL3LPpgBZRi8njeMti2tyuw=;
        fh=bFu1EdE7uCTk2SpNWOgj58Tp+Fz6rir8Sz0eZU8dBXU=;
        b=clIxDL3qz1bZlz//rpfoZF7t3A89s9FIrQ9HobeW7ZLWGn2XM1UnkmsRyxUpWrdbAJ
         E9V38/hOM184XN1VJu/kFiH016amYHwise+Q1zbKmbgHzQkQbomQxRWb3kEqJaYYH/bA
         zOwK3Bzhrm4qS06w8avC7PMkbgAJMA8yjAQR3JKM6gsdEvdf0XhMOZDVcM1sxx4Qyc7B
         rMPMzlgdcxW4DQuMsDQlRCQTdBxDUxHfbm4saFe8XCC/6Tdj05/rKXOGLa8oYkovv+Qk
         U8uRo8htV9EodrS48z2rt3tBSQ1cPErPeld660CJuu5Fh6ilsGvutz8NGMijPq1nmAC0
         hdZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=diWpz7P7;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-530bba2732bsi107730e87.8.2024.08.02.13.32.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 13:32:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5a869e3e9dfso60249a12.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 13:32:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX120wL1aIdnAsr1qA52IA4H/n6pyGBb10Kn4zZzgZ5N6SYdg4gLe+E/PfcH+M4ydbxX7e8sH7BV/MR02HtlFq6rndQR/C34l8Fkg==
X-Received: by 2002:a05:6402:2816:b0:58b:b1a0:4a2d with SMTP id 4fb4d7f45d1cf-5b9bebbc4ebmr17989a12.1.1722630734696;
        Fri, 02 Aug 2024 13:32:14 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:9337:bd1:a20d:682d])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-36bbd059841sm2716966f8f.89.2024.08.02.13.32.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Aug 2024 13:32:14 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 02 Aug 2024 22:31:54 +0200
Subject: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
In-Reply-To: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>, 
 syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1722630727; l=18156;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=J5IOz20kzk9KYQulLnVcj2lXMR6PVa1DwOVNOSWymvw=;
 b=0H92uCvLY0kw+qDQ7+oe+cgncSTtQqSeKfiDV9+uYaF7HUyE68U4lSJXaRet66PD8xXt5I7yU
 yVLZhZrHfR2B8lzQaC2fP/BEDYIh055KR/gBWnizqJ6XwYyTWWsnA13
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=diWpz7P7;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as
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

Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
slabs because use-after-free is allowed within the RCU grace period by
design.

Add a SLUB debugging feature which RCU-delays every individual
kmem_cache_free() before either actually freeing the object or handing it
off to KASAN, and change KASAN to poison freed objects as normal when this
option is enabled.

For now I've configured Kconfig.debug to default-enable this feature in the
KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAGS
mode because I'm not sure if it might have unwanted performance degradation
effects there.

Note that this is mostly useful with KASAN in the quarantine-based GENERIC
mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
(A possible future extension of this work would be to also let SLUB call
the ->ctor() on every allocation instead of only when the slab page is
allocated; then tag-based modes would be able to assign new tags on every
reallocation.)

Tested-by: syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h | 17 +++++++----
 mm/Kconfig.debug      | 30 +++++++++++++++++++
 mm/kasan/common.c     | 11 +++----
 mm/kasan/kasan_test.c | 46 ++++++++++++++++++++++++++++++
 mm/slab_common.c      | 12 ++++++++
 mm/slub.c             | 79 +++++++++++++++++++++++++++++++++++++++++++++------
 6 files changed, 176 insertions(+), 19 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1570c7191176..00a3bf7c0d8f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -193,40 +193,44 @@ static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
 {
 	if (kasan_enabled())
 		return __kasan_slab_pre_free(s, object, _RET_IP_);
 	return false;
 }
 
-bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
+bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init,
+		       bool still_accessible);
 /**
  * kasan_slab_free - Poison, initialize, and quarantine a slab object.
  * @object: Object to be freed.
  * @init: Whether to initialize the object.
+ * @still_accessible: Whether the object contents are still accessible.
  *
  * This function informs that a slab object has been freed and is not
- * supposed to be accessed anymore, except for objects in
- * SLAB_TYPESAFE_BY_RCU caches.
+ * supposed to be accessed anymore, except when @still_accessible is set
+ * (indicating that the object is in a SLAB_TYPESAFE_BY_RCU cache and an RCU
+ * grace period might not have passed yet).
  *
  * For KASAN modes that have integrated memory initialization
  * (kasan_has_integrated_init() == true), this function also initializes
  * the object's memory. For other modes, the @init argument is ignored.
  *
  * This function might also take ownership of the object to quarantine it.
  * When this happens, KASAN will defer freeing the object to a later
  * stage and handle it internally until then. The return value indicates
  * whether KASAN took ownership of the object.
  *
  * This function is intended only for use by the slab allocator.
  *
  * @Return true if KASAN took ownership of the object; false otherwise.
  */
 static __always_inline bool kasan_slab_free(struct kmem_cache *s,
-						void *object, bool init)
+						void *object, bool init,
+						bool still_accessible)
 {
 	if (kasan_enabled())
-		return __kasan_slab_free(s, object, init);
+		return __kasan_slab_free(s, object, init, still_accessible);
 	return false;
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr)
 {
@@ -416,13 +420,14 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 
 static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
 {
 	return false;
 }
 
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
+				   bool init, bool still_accessible)
 {
 	return false;
 }
 static inline void kasan_kfree_large(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags, bool init)
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index afc72fde0f03..8e440214aac8 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -67,12 +67,42 @@ config SLUB_DEBUG_ON
 	  equivalent to specifying the "slab_debug" parameter on boot.
 	  There is no support for more fine grained debug control like
 	  possible with slab_debug=xxx. SLUB debugging may be switched
 	  off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
 	  "slab_debug=-".
 
+config SLUB_RCU_DEBUG
+	bool "Enable UAF detection in TYPESAFE_BY_RCU caches (for KASAN)"
+	depends on SLUB_DEBUG
+	depends on KASAN # not a real dependency; currently useless without KASAN
+	default KASAN_GENERIC || KASAN_SW_TAGS
+	help
+	  Make SLAB_TYPESAFE_BY_RCU caches behave approximately as if the cache
+	  was not marked as SLAB_TYPESAFE_BY_RCU and every caller used
+	  kfree_rcu() instead.
+
+	  This is intended for use in combination with KASAN, to enable KASAN to
+	  detect use-after-free accesses in such caches.
+	  (KFENCE is able to do that independent of this flag.)
+
+	  This might degrade performance.
+	  Unfortunately this also prevents a very specific bug pattern from
+	  triggering (insufficient checks against an object being recycled
+	  within the RCU grace period); so this option can be turned off even on
+	  KASAN builds, in case you want to test for such a bug.
+
+	  If you're using this for testing bugs / fuzzing and care about
+	  catching all the bugs WAY more than performance, you might want to
+	  also turn on CONFIG_RCU_STRICT_GRACE_PERIOD.
+
+	  WARNING:
+	  This is designed as a debugging feature, not a security feature.
+	  Objects are sometimes recycled without RCU delay under memory pressure.
+
+	  If unsure, say N.
+
 config PAGE_OWNER
 	bool "Track page owner"
 	depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
 	select DEBUG_FS
 	select STACKTRACE
 	select STACKDEPOT
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f26bbc087b3b..ed4873e18c75 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -227,43 +227,44 @@ static bool check_slab_allocation(struct kmem_cache *cache, void *object,
 	}
 
 	return false;
 }
 
 static inline void poison_slab_object(struct kmem_cache *cache, void *object,
-				      bool init)
+				      bool init, bool still_accessible)
 {
 	void *tagged_object = object;
 
 	object = kasan_reset_tag(object);
 
 	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+	if (unlikely(still_accessible))
 		return;
 
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
 	if (kasan_stack_collection_enabled())
 		kasan_save_free_info(cache, tagged_object);
 }
 
 bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 				unsigned long ip)
 {
 	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 	return check_slab_allocation(cache, object, ip);
 }
 
-bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
+		       bool still_accessible)
 {
 	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 
-	poison_slab_object(cache, object, init);
+	poison_slab_object(cache, object, init, still_accessible);
 
 	/*
 	 * If the object is put into quarantine, do not let slab put the object
 	 * onto the freelist for now. The object's metadata is kept until the
 	 * object gets evicted from quarantine.
 	 */
@@ -515,13 +516,13 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 
 	slab = folio_slab(folio);
 
 	if (check_slab_allocation(slab->slab_cache, ptr, ip))
 		return false;
 
-	poison_slab_object(slab->slab_cache, ptr, false);
+	poison_slab_object(slab->slab_cache, ptr, false, false);
 	return true;
 }
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 {
 	struct slab *slab;
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 7b32be2a3cf0..567d33b493e2 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -993,12 +993,57 @@ static void kmem_cache_invalid_free(struct kunit *test)
 	 */
 	kmem_cache_free(cache, p);
 
 	kmem_cache_destroy(cache);
 }
 
+static void kmem_cache_rcu_uaf(struct kunit *test)
+{
+	char *p;
+	size_t size = 200;
+	struct kmem_cache *cache;
+
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB_RCU_DEBUG);
+
+	cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
+				  NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+	*p = 1;
+
+	rcu_read_lock();
+
+	/* Free the object - this will internally schedule an RCU callback. */
+	kmem_cache_free(cache, p);
+
+	/*
+	 * We should still be allowed to access the object at this point because
+	 * the cache is SLAB_TYPESAFE_BY_RCU and we've been in an RCU read-side
+	 * critical section since before the kmem_cache_free().
+	 */
+	READ_ONCE(*p);
+
+	rcu_read_unlock();
+
+	/*
+	 * Wait for the RCU callback to execute; after this, the object should
+	 * have actually been freed from KASAN's perspective.
+	 */
+	rcu_barrier();
+
+	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
+
+	kmem_cache_destroy(cache);
+}
+
 static void empty_cache_ctor(void *object) { }
 
 static void kmem_cache_double_destroy(struct kunit *test)
 {
 	struct kmem_cache *cache;
 
@@ -1934,12 +1979,13 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(workqueue_uaf),
 	KUNIT_CASE(kfree_via_page),
 	KUNIT_CASE(kfree_via_phys),
 	KUNIT_CASE(kmem_cache_oob),
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
+	KUNIT_CASE(kmem_cache_rcu_uaf),
 	KUNIT_CASE(kmem_cache_double_destroy),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),
 	KUNIT_CASE(mempool_kmalloc_oob_right),
 	KUNIT_CASE(mempool_kmalloc_large_oob_right),
 	KUNIT_CASE(mempool_slab_oob_right),
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 40b582a014b8..df09066d56fe 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -539,12 +539,24 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 		kmem_cache_release(s);
 	}
 }
 
 static int shutdown_cache(struct kmem_cache *s)
 {
+	if (IS_ENABLED(CONFIG_SLUB_RCU_DEBUG) &&
+	    (s->flags & SLAB_TYPESAFE_BY_RCU)) {
+		/*
+		 * Under CONFIG_SLUB_RCU_DEBUG, when objects in a
+		 * SLAB_TYPESAFE_BY_RCU slab are freed, SLUB will internally
+		 * defer their freeing with call_rcu().
+		 * Wait for such call_rcu() invocations here before actually
+		 * destroying the cache.
+		 */
+		rcu_barrier();
+	}
+
 	/* free asan quarantined objects */
 	kasan_cache_shutdown(s);
 
 	if (__kmem_cache_shutdown(s) != 0)
 		return -EBUSY;
 
diff --git a/mm/slub.c b/mm/slub.c
index 0c98b6a2124f..a89f2006d46e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2197,45 +2197,81 @@ static inline bool memcg_slab_post_alloc_hook(struct kmem_cache *s,
 static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 					void **p, int objects)
 {
 }
 #endif /* CONFIG_MEMCG */
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+static void slab_free_after_rcu_debug(struct rcu_head *rcu_head);
+
+struct rcu_delayed_free {
+	struct rcu_head head;
+	void *object;
+};
+#endif
+
 /*
  * Hooks for other subsystems that check memory allocations. In a typical
  * production configuration these hooks all should produce no code at all.
  *
  * Returns true if freeing of the object can proceed, false if its reuse
- * was delayed by KASAN quarantine, or it was returned to KFENCE.
+ * was delayed by CONFIG_SLUB_RCU_DEBUG or KASAN quarantine, or it was returned
+ * to KFENCE.
  */
 static __always_inline
-bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
+bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
+		    bool after_rcu_delay)
 {
+	/* Are the object contents still accessible? */
+	bool still_accessible = (s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay;
+
 	kmemleak_free_recursive(x, s->flags);
 	kmsan_slab_free(s, x);
 
 	debug_check_no_locks_freed(x, s->object_size);
 
 	if (!(s->flags & SLAB_DEBUG_OBJECTS))
 		debug_check_no_obj_freed(x, s->object_size);
 
 	/* Use KCSAN to help debug racy use-after-free. */
-	if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
+	if (!still_accessible)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
 	if (kfence_free(x))
 		return false;
 
 	/*
 	 * Give KASAN a chance to notice an invalid free operation before we
 	 * modify the object.
 	 */
 	if (kasan_slab_pre_free(s, x))
 		return false;
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if (still_accessible) {
+		struct rcu_delayed_free *delayed_free;
+
+		delayed_free = kmalloc(sizeof(*delayed_free), GFP_NOWAIT);
+		if (delayed_free) {
+			/*
+			 * Let KASAN track our call stack as a "related work
+			 * creation", just like if the object had been freed
+			 * normally via kfree_rcu().
+			 * We have to do this manually because the rcu_head is
+			 * not located inside the object.
+			 */
+			kasan_record_aux_stack_noalloc(x);
+
+			delayed_free->object = x;
+			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
+			return false;
+		}
+	}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_free and initialization memset's must be
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * The initialization memset's clear the object and the metadata,
@@ -2253,42 +2289,42 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 			memset(kasan_reset_tag(x), 0, s->object_size);
 		rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
 		memset((char *)kasan_reset_tag(x) + inuse, 0,
 		       s->size - inuse - rsize);
 	}
 	/* KASAN might put x into memory quarantine, delaying its reuse. */
-	return !kasan_slab_free(s, x, init);
+	return !kasan_slab_free(s, x, init, still_accessible);
 }
 
 static __fastpath_inline
 bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
 			     int *cnt)
 {
 
 	void *object;
 	void *next = *head;
 	void *old_tail = *tail;
 	bool init;
 
 	if (is_kfence_address(next)) {
-		slab_free_hook(s, next, false);
+		slab_free_hook(s, next, false, false);
 		return false;
 	}
 
 	/* Head and tail of the reconstructed freelist */
 	*head = NULL;
 	*tail = NULL;
 
 	init = slab_want_init_on_free(s);
 
 	do {
 		object = next;
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (likely(slab_free_hook(s, object, init))) {
+		if (likely(slab_free_hook(s, object, init, false))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
 			if (!*tail)
 				*tail = object;
 		} else {
@@ -4474,40 +4510,67 @@ static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, &object, 1);
 	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, slab, object, object, 1, addr);
 }
 
 #ifdef CONFIG_MEMCG
 /* Do not inline the rare memcg charging failed path into the allocation path */
 static noinline
 void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
 {
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
 }
 #endif
 
 static __fastpath_inline
 void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 		    void *tail, void **p, int cnt, unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, p, cnt);
 	alloc_tagging_slab_free_hook(s, slab, p, cnt);
 	/*
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
 	 */
 	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
 		do_slab_free(s, slab, head, tail, cnt, addr);
 }
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
+{
+	struct rcu_delayed_free *delayed_free =
+			container_of(rcu_head, struct rcu_delayed_free, head);
+	void *object = delayed_free->object;
+	struct slab *slab = virt_to_slab(object);
+	struct kmem_cache *s;
+
+	if (WARN_ON(is_kfence_address(object)))
+		return;
+
+	/* find the object and the cache again */
+	if (WARN_ON(!slab))
+		return;
+	s = slab->slab_cache;
+	if (WARN_ON(!(s->flags & SLAB_TYPESAFE_BY_RCU)))
+		return;
+
+	/* resume freeing */
+	if (!slab_free_hook(s, object, slab_want_init_on_free(s), true))
+		return;
+	do_slab_free(s, slab, object, object, 1, _THIS_IP_);
+	kfree(delayed_free);
+}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
 	do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
 }
 #endif

-- 
2.46.0.rc2.264.g509ed76dc8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240802-kasan-tsbrcu-v6-2-60d86ea78416%40google.com.
