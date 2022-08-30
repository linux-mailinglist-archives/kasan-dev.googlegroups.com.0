Return-Path: <kasan-dev+bncBC7OD3FKWUERBBUMXKMAMGQEMD4H53I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id E9E975A6F8F
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:59 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id z10-20020a05622a124a00b003445680ff47sf9736210qtx.8
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896199; cv=pass;
        d=google.com; s=arc-20160816;
        b=oDkK2U4BP1NqiXsM6MrAKQlPobve9945WN3IiyLyD2H9UdXB44KnEjiVm/ShF6YHN8
         onbUE8JFrmQJGAkr6Xa4B1m/OGPcpIT1jzmk32EdPjSCT4WGP+zeBqaileUf1cA/KKew
         k3uvG/9i0N7kp2tzWa5Avb2Pcx7AnB3KcT3/WOyGdO7luWiOfUKnHAxruaEXNwmVhB6Q
         EF4+HdVMMw2eOS0T+GGL0uXQ73n4GA6VFTqJ/JftXN9tUK7WKOoAgSS4ajn0sOyv4CQC
         CcFLo6rTnONTrwCFH+kzSmoCXL6q3q3giJw2P2aG9/trsUL/uNlVNhemcqTIqpiEquqB
         9M6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nHwWfFyQHVcXL6WcwMKUA0OczeRkwbhtMQjUfOfPX5U=;
        b=hg15Lgs5sfAekzlxad8SbgZHLbpHcdm3wLwgNNVEzU6Pf3DEHZYEu+kWdlUSajwe5Z
         oePvxzYy6l2H98ADjH10jkX2CP37dzRC6XxAwI4agPVgq5hQWtuvdVjtK9HhqtCBBAAu
         Stft/Kv+5848THl6mECtu69uZcnbgwtROswwtuY1gE3UD/6CRL9yDXXsQ78jOZTw9+Fi
         UBak4udfAliQ+c9eTxuZpYR3a1fYZSX4ojMAGDz6Gdb57QL7U7Zmy5W3lV9VHkk4hBj3
         RK+9+hFN3X8GdVo14YUqzCGWcBeo2kc9Oizo5cJf5mEwsF/NdIqsBPONGZ6MQu+2JjLI
         DpYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="b1R/0Nze";
       spf=pass (google.com: domain of 3boyoywykcwsbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3BoYOYwYKCWsbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=nHwWfFyQHVcXL6WcwMKUA0OczeRkwbhtMQjUfOfPX5U=;
        b=FVOAZIbswVZfGPfbf22yZI6cmgb6aLXMjpmE/RjJVY3Z7pGNj7y7RtSoZzUeVJkK/Q
         D/xpImh3AakEXJXHWaIyEPt2zBbZgxzBQb5vAGMy1S2Pqntv7eRakAyYuwv5GSupz7nj
         ba7Q+f4DA2AlS2Lz5QiUjbk0zQoqkfzv9U+AZGRRz1pdJUlaGLFE9qhOqEDKQCmafVtW
         D3jjn2fnF1/6DdtzCm+y32XXE+J40yoO3VSW14uJkw31ssepWC7kZaJqdReoIjnDMih/
         DEac+MC6Lb8vmJK23F7N9mtZtVdc9lMnbeBX3SPNye/gc87UO2HiZqqncUVLgtqRFD1J
         PO5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=nHwWfFyQHVcXL6WcwMKUA0OczeRkwbhtMQjUfOfPX5U=;
        b=LWsGw75PybvlJtJjWsiDGoK9XosXk2vIPLsznF1V18Z+TteIn7tNDTMR4F6YtZUznq
         AwslyKUaZiWhZXX+As3C/fTLl4lq8EmDB6FNjTKh6GbOB0mDg6eHY2sJ3EVPK58MtEAp
         Mn2oB7kfebj3mbjFEctesheDx2+5mRrEN1n4lYflACsl40Tl8smSMaFOZ0aGdvRj57Pw
         O80tZhL17Z/vUvM+VHyFQUGb5MrU6snSXwSshWpMoVy79B8VHvdGTcEcfkLbtm4KBQ4k
         zQS1KvDQgBAgSzllZXWUJDwcGmCJuXtEwbGG8euue+k4Yu1r6hqFFgyClZo7YnCmPi29
         hCyQ==
X-Gm-Message-State: ACgBeo0QZ2hoB4NGUl+yS5nSF367UpPJWcHM8u09rFrfHGwaKtkp2LVY
	kzWzONtEll6PcVg7msVOxqg=
X-Google-Smtp-Source: AA6agR7qARx6Zd+zAWNWQi4YaIM1ehqcqlpHKogbDjo6h25CO5xoHsT0opCtTFlSS1e/vf16hee+tA==
X-Received: by 2002:a37:8903:0:b0:6bb:e6e8:a6c6 with SMTP id l3-20020a378903000000b006bbe6e8a6c6mr13458002qkd.316.1661896198918;
        Tue, 30 Aug 2022 14:49:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:578e:0:b0:342:fb4f:7470 with SMTP id v14-20020ac8578e000000b00342fb4f7470ls7260199qta.4.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:49:58 -0700 (PDT)
X-Received: by 2002:a05:622a:506:b0:344:6fcf:78c7 with SMTP id l6-20020a05622a050600b003446fcf78c7mr16097782qtx.296.1661896198436;
        Tue, 30 Aug 2022 14:49:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896198; cv=none;
        d=google.com; s=arc-20160816;
        b=kjDyNJ1a+mKmGaW9/17Ps5GvgRuE+voPk6Uhc9MAXbhNPnaUyY2MPCKxs5pO5FALW/
         WFO2kYJ/brNWTksqDgLDyKdP5Z6gRAZrhRDks+ObcwFcyxkysJmqkBgPTuzv2jLyluQX
         34PRxY9wTb1yFZoixFMhv/UQK4u25wxV+x793JWtVZKtb8HsT7xwGr1VFCRks1HJlQSR
         R+bWYlgOGSwC2zQzWw2XXi0Ed3q9QFDI7y3derrsPbEvFKlu75QwEeFGpzSiw+5k1jFH
         Xrr0OPtjpoUIr0EXHRU/NjxOohWlJCXs+Ft9Q6HHji7chHC7Iukg7Fsoxlt8YLueiaY4
         O0mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lEzLHp5EUALGBDR080eL/ZTXye/B6ScLofp8WoGZutw=;
        b=PQjfNJTnIeg4R7N7p3CDZoLwoUKD4WavJtt/N3/HjJxMx+75kreZ/hW7pZ0Qx3+lL6
         VIY3FGTTGowR0OiKuWRxcbcg0w7PL4D8uP4+SZRyIa8dhqywfWiM3y+jNGbQFTI3kTwZ
         kfws+YR92J0llawIEod5i6/x2MS9DzeliHDxpuLNRI2oYKirXdAC2vNk030s7I6OiT4c
         787dnJnhngsk/eeef7mhCuvViwtR0/TufxEEecNDCsuBfljO9FzbEis+/YlTlmMocG7s
         JcZeo68Xu4lr9hW/HKmPQXny4XGR7OHch8O6nuVkfCrPi+M22sQemA8EvlzI7Pkl5ad1
         1Zkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="b1R/0Nze";
       spf=pass (google.com: domain of 3boyoywykcwsbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3BoYOYwYKCWsbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id d21-20020ac84e35000000b00341a027f09fsi592982qtw.4.2022.08.30.14.49.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3boyoywykcwsbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-31f5960500bso188562817b3.14
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:58 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a05:6902:89:b0:695:7ed0:d8cb with SMTP id
 h9-20020a056902008900b006957ed0d8cbmr13360099ybs.77.1661896198026; Tue, 30
 Aug 2022 14:49:58 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:02 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-14-surenb@google.com>
Subject: [RFC PATCH 13/30] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="b1R/0Nze";       spf=pass
 (google.com: domain of 3boyoywykcwsbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3BoYOYwYKCWsbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

Slab extension objects can't be allocated before slab infrastructure is
initialized. Some caches, like kmem_cache and kmem_cache_node, are created
before slab infrastructure is initialized. Objects from these caches can't
have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
caches and avoid creating extensions for objects allocated from these
slabs.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/slab.h | 7 +++++++
 mm/slab.c            | 2 +-
 mm/slub.c            | 5 +++--
 3 files changed, 11 insertions(+), 3 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 0fefdf528e0d..55ae3ea864a4 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -124,6 +124,13 @@
 #define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0x00020000U)
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
+#ifdef CONFIG_SLAB_OBJ_EXT
+/* Slab created using create_boot_cache */
+#define SLAB_NO_OBJ_EXT         ((slab_flags_t __force)0x20000000U)
+#else
+#define SLAB_NO_OBJ_EXT         0
+#endif
+
 /*
  * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
  *
diff --git a/mm/slab.c b/mm/slab.c
index 10e96137b44f..ba97aeef7ec1 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -1233,7 +1233,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 		offsetof(struct kmem_cache, node) +
 				  nr_node_ids * sizeof(struct kmem_cache_node *),
-				  SLAB_HWCACHE_ALIGN, 0, 0);
+				  SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 	list_add(&kmem_cache->list, &slab_caches);
 	slab_state = PARTIAL;
 
diff --git a/mm/slub.c b/mm/slub.c
index 862dbd9af4f5..80199d5ac7c9 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4825,7 +4825,8 @@ void __init kmem_cache_init(void)
 		node_set(node, slab_nodes);
 
 	create_boot_cache(kmem_cache_node, "kmem_cache_node",
-		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);
+			sizeof(struct kmem_cache_node),
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	register_hotmemory_notifier(&slab_memory_callback_nb);
 
@@ -4835,7 +4836,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 			offsetof(struct kmem_cache, node) +
 				nr_node_ids * sizeof(struct kmem_cache_node *),
-		       SLAB_HWCACHE_ALIGN, 0, 0);
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	kmem_cache = bootstrap(&boot_kmem_cache);
 	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-14-surenb%40google.com.
