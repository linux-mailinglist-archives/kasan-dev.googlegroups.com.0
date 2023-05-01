Return-Path: <kasan-dev+bncBC7OD3FKWUERBBG6X6RAMGQEIHPWZOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 511BA6F33C3
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:33 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id a1e0cc1a2514c-77aad9af412sf25927309241.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960132; cv=pass;
        d=google.com; s=arc-20160816;
        b=kQIRHN6ZopGJnC1p8bRz5zZzuc3fahoK9dAUlXiiUk0QCwTaMRSRk/VgYzZfa3A50o
         psXa1H/Tt52IpN7yzJnDiLqaTgtQJHTLEvc3Qg2z7bIAZWYxHhpdudw50ytJ6nBxxiWh
         7urkeuZzO1spTpyPHJOKLfAVJnAIjB8Wf76YxsD8THgkBnAhU3LyUtXXlW2A+ozWhIkk
         uYcIdLxn49qb7XN7YGbcxG4YSyRPxcOEardF+w1pNC5vj7P+wPgekxlTISsqANFt2h0M
         eMzJuSJSmVpxX0Kqh3hLg5AhJGlok4PJWiSEizhEmCiYto40PNv0gsk34iU0ToJ2p1nM
         PXXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MV0J/WhCO8gJPHsZqsd8SA8VzTGxPLbendb1UhUKkx0=;
        b=LFaqyDlpOPTCSWXDlMHmHvu+MR2sOwJoHIkNgY/E7EKPdYMakDEkjR2P+uipfot7Wr
         MBsWOtHG5cmf/2wJnvaF3uT1Ey7++2v2lODBEihXQONHWz67z2HVg9hay7L/5858OqWl
         0PV8zgC8nsteolA6+Vh5HsRtKBdjdkzUUsErn3fRCd+Fy5HsgDD1EXcuBA4WL58qvqF9
         yCnOxbUmeuhPtm8vLPytelJY4D6VHiWQ7jNhhBX5sx0BPh+PZbEHWZ8/2n+0+NwlP9tO
         OLwj8rCzIi9zBGAZqDsfzqBviEYTN9GC66aQLdraXcj2PbnHDQOaRmEZS5Y/l1Kyd806
         t0NQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=MVmPTJvn;
       spf=pass (google.com: domain of 3a-9pzaykcuo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3A-9PZAYKCUo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960132; x=1685552132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MV0J/WhCO8gJPHsZqsd8SA8VzTGxPLbendb1UhUKkx0=;
        b=FhiQkO+jpdu42gZpZEvVrTuhX7urGA+CjMvDAFHZuz0TPP4jP+c+2Z4Eclh4ZvNUn/
         Y/ITlZlgjfTxTKLfeI2VB2tX0zUdiF14ITMJxBUx2RrieTEn4JBWenVNob3VQ8gIJwCS
         ttOM/LbIMaD+rDrtRLoGEI58I4mKex9HCDjQmKlspjjJ7fKOnNnFB8UFh+uSMN/X0q3A
         yQI5PQsiLSWtx9GGO5qq5ReRBCoIY8Fwcj6GqSwgXxCEB5R9fmYcEDGZIfQelVPL/UJn
         C4u5eqXkkxJTzAaLqgfzzYxIwhsX2M3vXMJXXlJVIlR5He/F3HnZYSJl60271H8l7hp3
         S6Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960132; x=1685552132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MV0J/WhCO8gJPHsZqsd8SA8VzTGxPLbendb1UhUKkx0=;
        b=AxswO4xClXv3nnngqkwLEHr13JswdnZlHLXdQwtykNgFwvcxPCYbTlp/wLHarMuGMW
         LboTufgc/mb73rvev43hCPUI6A9vH9bxBFnzSAlyo9xl5kO40Drb0qTPiArBnwWtiDUQ
         mwJybcKvaBEfBjsdx4oDL+B6mfAobHwKA1ocNeyl8vLe3v6+MytJiq/vj34JszAMGwXL
         oLNzH4csoXt3B9+EbxrHw0iB26pQvDEat0vm+nGsvRTYVkouavmGRnPJl+QmGambw+o2
         /vNuOFht6sU9j5Q7nyh+0ZETj5CYg9acCe1MAZD/hwTARzf7pySbJjoH7MkR9Us+9zTl
         SW2g==
X-Gm-Message-State: AC+VfDz3nNpIhEMAx/tVYRK9jmODOXq3wdQNeb/NHfmuxRfbA2ggngXx
	5w6o/eFerbQA5GF+dvrDBQM=
X-Google-Smtp-Source: ACHHUZ6wS1FAKjigi1tlvuj8LmnZm9WfuD5kR7NOfrnlQQrt2C8WIc6A/ovcnxKjrDyr/IqbWHXCrQ==
X-Received: by 2002:ab0:4add:0:b0:73f:f15b:d9e3 with SMTP id t29-20020ab04add000000b0073ff15bd9e3mr9072348uae.0.1682960132239;
        Mon, 01 May 2023 09:55:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:1609:b0:42e:5ac3:7f3e with SMTP id
 cu9-20020a056102160900b0042e5ac37f3els2756341vsb.2.-pod-prod-gmail; Mon, 01
 May 2023 09:55:31 -0700 (PDT)
X-Received: by 2002:a67:f2c2:0:b0:430:138f:ec2f with SMTP id a2-20020a67f2c2000000b00430138fec2fmr5092980vsn.4.1682960131592;
        Mon, 01 May 2023 09:55:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960131; cv=none;
        d=google.com; s=arc-20160816;
        b=hHZx9bC7Fu5fj5bLkBs1kfax0Bid/af715MbMDvqCEIoJyzB2U8QxpZ5mXkISZMyBr
         f2XoDwxM918GiyvprZLtGNB2LDBisiIPXUrALhz8gvGIwYAD02hVF3IgBF//8zinIdGd
         9P/mHSc2BkkwtjpQlG6NpkxGJkcngQlwaVmi+Jc54rwVreWmreTztZmOdPtOu8cyCjVU
         vDRBPpcN1iVjon5Vg2whR72mmZY6tKKrOunMtpKY4w1IgvGkCuNSFKLNwg9bsJoi1yFY
         4/DCt1agrseAZ6m0+TBzt1I0y66A+SQGJoKFwP/enf6pbs0S9+19fsCkIt0Tda8uDiHl
         uEdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gDL+lQo0P3G6fblFMKJonaRbqsrkB9ljveMgEFO8c80=;
        b=Prc9pa6rUkyUo9yPbqNQvle1KeTkgOnqoGPKbJ1VyxFqxrNwy8m3WfScvRPwWhFU0k
         z0bU6krrNUGTXEitRKFGr6oUrCR9fJsGV0g8bTdG8uuZCaMf5E4CAZoSWWChEcHt1vDL
         tmcz9C9Z5clggX1HTvu7mKUwP6cKzCI34T/emVMyKoHvXph1DakfsRzIZblu7Ul9Apy5
         nqon7lfTJkW71pwk3EPKTjRwqGzOpYzBzlRUOOm5nBrqgp+GvQqhCDHffM9ZPbYftI4o
         qPgIYcZTDTJ7C3eEOCF3WT+3n96ArIa2tQ7F2D6L1X9h8wGf1WpaHYg2/PGX54Md9WGG
         KLFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=MVmPTJvn;
       spf=pass (google.com: domain of 3a-9pzaykcuo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3A-9PZAYKCUo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id az40-20020a05613003a800b0077d31fab956si112449uab.1.2023.05.01.09.55.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3a-9pzaykcuo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a77926afbso5336043276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:31 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:6b05:0:b0:b8b:f5fb:5986 with SMTP id
 g5-20020a256b05000000b00b8bf5fb5986mr8475612ybc.10.1682960131180; Mon, 01 May
 2023 09:55:31 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:20 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-11-surenb@google.com>
Subject: [PATCH 10/40] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=MVmPTJvn;       spf=pass
 (google.com: domain of 3a-9pzaykcuo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3A-9PZAYKCUo463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
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
index 6b3e155b70bf..99a146f3cedf 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -147,6 +147,13 @@
 #endif
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
index bb57f7fdbae1..ccc76f7455e9 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -1232,7 +1232,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 		offsetof(struct kmem_cache, node) +
 				  nr_node_ids * sizeof(struct kmem_cache_node *),
-				  SLAB_HWCACHE_ALIGN, 0, 0);
+				  SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 	list_add(&kmem_cache->list, &slab_caches);
 	slab_state = PARTIAL;
 
diff --git a/mm/slub.c b/mm/slub.c
index c87628cd8a9a..507b71372ee4 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5020,7 +5020,8 @@ void __init kmem_cache_init(void)
 		node_set(node, slab_nodes);
 
 	create_boot_cache(kmem_cache_node, "kmem_cache_node",
-		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);
+			sizeof(struct kmem_cache_node),
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
 
@@ -5030,7 +5031,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 			offsetof(struct kmem_cache, node) +
 				nr_node_ids * sizeof(struct kmem_cache_node *),
-		       SLAB_HWCACHE_ALIGN, 0, 0);
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	kmem_cache = bootstrap(&boot_kmem_cache);
 	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-11-surenb%40google.com.
