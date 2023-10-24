Return-Path: <kasan-dev+bncBC7OD3FKWUERBVUV36UQMGQEAZHYR5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 051887D5231
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:04 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-d9ab79816a9sf5377223276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155223; cv=pass;
        d=google.com; s=arc-20160816;
        b=gjGZiRHWs22SwoXOIPLJO2VQYwjzvYPqveDBVopozl+r/a/uL0cTwIR5zzO0dh148W
         6nzWKemabW+Svu2OigjbNQeqOJNnhY/RojtTWaZRpmNrza+r5iuVhoA2+xQsiESBTtJL
         s49y6m1vTNVUUtgVHX7nypl3lXKldjJb6i2HIeKqssiCcsSt0Cdh0PVF6mUeZ1mklvsm
         ewBFcUwKlV97fENX8JHPaDO+eSACT7oj4u5TnV3PhsE8tui4YfJZjikZxJNFRp0twH7W
         hbZMw0RTkdA4Q4daunK4TANHgGgIbhRvAbOj7FqTS5eF9XBeftfYjJElLl/EvWygDlIh
         IKgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=DwjXNLoJFI8gTYUe47ZBBXf8S1BTc9rD4aY5Zt1m4PI=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=U9fU1s1QyEpghVNBi7KbOdVY0CA/ouUx+zAiWZnkXyK4gmtGeiG7oMiesyJZC/7ChD
         9oHT/XO4vi7YAGYLteh6QTB2/7Yq0g95zvEIbu8u0BgKpB1hu+zYhAPa20eG9+yg/vWs
         xk2n8A1CynVHL8lFV/jLi7KKnTWHWil6JA81RZhfkrKYfv+zIWewBPWWeEqn22IcMpIq
         RUjJnbCCnheksSZ3lUzU+LlGb3u4hSYWX8ktCmn5YBb4y0jvWu6Ma3yFCXFNy92ShYMx
         K+BWZ/pTENa9FGUmI0jN2Yg5dWKaBPJz5qa0UD28KHN08SI4aZErpe42jpmhG9mSWeM7
         6Qfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XdUPuYBp;
       spf=pass (google.com: domain of 31co3zqykcxoqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=31co3ZQYKCXoqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155223; x=1698760023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DwjXNLoJFI8gTYUe47ZBBXf8S1BTc9rD4aY5Zt1m4PI=;
        b=ujcxb5KeohZ4O1/TAviAhXId36WDs4NGcWHv3XWBh59F8LhtJNcBQwkBvx+858Ciz4
         CuWVdIoUOU1KJFFcmKmCwCdo7IAOlG9qaKKXj2EvzD8+q4SJ6NebE3m9NCWhL/LyZyZ4
         M6MQ7ASIN8cqcveijlG1/8L+UjrZbRMOWdde6k+VhNevDt8AZUPiHcAjKHJ8BYA9lp7Z
         ZQM5FFGt4fmdUToY/GRRs3YhPNq8/an8h7bHvsxmwte/NAgryjwyVbXRrp6/1Gh0iOnm
         uLdzoTqGTvLdfqsvuDcULIUAditmGlno6vZwRzDlKbG21DWvf9uhrJ/jcLiHmyP+paoh
         ewAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155223; x=1698760023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DwjXNLoJFI8gTYUe47ZBBXf8S1BTc9rD4aY5Zt1m4PI=;
        b=opx/k3YZgb97xvBphrb14F9ffccG5n3vT+ANJUx5S4IzoHalrcuHP1u9fV9czdcRqF
         OS0TNONfwABSJRM4MMhqmVa9+SDAOn9UHlQil91+P8VjWAd5vaJSAziw2rPyass6O/dd
         6YxmISOGsnLdtsTqpcv0SOgnJb1HbwLEBUuyikyfSQdwz/GW8ks0qg+oOpwpAPeUAXJ4
         ZQRYIU2acp2yL7mlDm8hjyrTziBQpa8Tna92TjpPrXmHIL5SNW8GNpnqRZ/vbsGXnOBs
         VppYI+gmkvZGazCszmprosUzVhBeVY4X93nOujfWYP3aBGmHKLGg/VujNL0JZfVpU17J
         1Ibg==
X-Gm-Message-State: AOJu0YzyShI4AiOjkibtHsPhyirYcoTfrH33vl0iOyW4yq5P9gEXhFbA
	85gHnB5f8M7+sPpQxcn+jPc=
X-Google-Smtp-Source: AGHT+IGNelIm/r31h6cKCdKBDJjn40qjrSArzHPAf+b40Ne90CzMUX97xVxgQmRRPAhRDYYEBa7INA==
X-Received: by 2002:a05:6902:566:b0:d9a:e398:5b25 with SMTP id a6-20020a056902056600b00d9ae3985b25mr10047440ybt.47.1698155222874;
        Tue, 24 Oct 2023 06:47:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d8c2:0:b0:d85:e5d1:b8c6 with SMTP id p185-20020a25d8c2000000b00d85e5d1b8c6ls525123ybg.2.-pod-prod-08-us;
 Tue, 24 Oct 2023 06:47:02 -0700 (PDT)
X-Received: by 2002:a25:385:0:b0:da0:47d8:4659 with SMTP id 127-20020a250385000000b00da047d84659mr1509924ybd.52.1698155221896;
        Tue, 24 Oct 2023 06:47:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155221; cv=none;
        d=google.com; s=arc-20160816;
        b=nN5Kn99I66Ix75hBYOFBUlOWw9IlLpAuz1aekjgvlsYBaW7sPEFzEbF6tOESlNdayC
         AxDGfJF27WGsG0NQngnOVerRJ4paEjmsdHXm3tsu9BurzjGc1hlK1yMUuv8s8Qvfzd8W
         UlKDeN8BAhMiKhkmI35CoS20GlfAhdwGuE8SAl0+7LD7pHFnQgEl+hYVBrDdeF/sTwfz
         89rYJJJ/gY7Y7agMg3dO6i8w2sdIRATAfe9cdCoC128mfPv7z946Y4/3p6dk6Bkcp/II
         0/2nyGJ8z2o1wqdU9eZ1O+cPWjQywKYBduTWAfbdFSo/A+D66YuCi9y4co7ADbikt3ul
         PB8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BlkdsRQXiDN3rg6CmmMqMbDupjvE+Qo4H/i7Q99VP7E=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=SBnV9lT+c3T98x1c9qjr4V+bnb74P6L/jhFJciF100Ow/OwpTiqEiBuWfFGtGYY2ZB
         NH1ucmDl9pAlw4QvRmWqvPU95VmB0AY2FZOif3qcrswaVF+3FUOZ20XJXYQCIIlNwMJ0
         nK8V9rDNThX5bgHyi7fk72Jyn1xqhOiIj/gwzdWtDdJPIWvx69DgeQWjvtWVz2HCk+CG
         nC/POioUdGVsCEYlUEV2Cc2vq19jlf+hTt9OYNPofavtC5kFWJ9CSIEMmlQPwfgZmqBJ
         1QWH1OrVCVJnak7bNTC5panC9FjhTsGg4JfeVTnBK9a2jhF5NeDx76nQLXgeR0V0TbtP
         6M6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XdUPuYBp;
       spf=pass (google.com: domain of 31co3zqykcxoqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=31co3ZQYKCXoqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id q9-20020a258209000000b00d9a58369b95si238177ybk.1.2023.10.24.06.47.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31co3zqykcxoqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5a7fb3f311bso59159297b3.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:01 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a0d:d50f:0:b0:5a7:be3f:159f with SMTP id
 x15-20020a0dd50f000000b005a7be3f159fmr287305ywd.5.1698155221495; Tue, 24 Oct
 2023 06:47:01 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:06 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-10-surenb@google.com>
Subject: [PATCH v2 09/39] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
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
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XdUPuYBp;       spf=pass
 (google.com: domain of 31co3zqykcxoqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=31co3ZQYKCXoqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
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
index 8228d1276a2f..11ef3d364b2b 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -164,6 +164,13 @@
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
index 9ad3d0f2d1a5..cefcb7499b6c 100644
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
index f7940048138c..d16643492320 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5043,7 +5043,8 @@ void __init kmem_cache_init(void)
 		node_set(node, slab_nodes);
 
 	create_boot_cache(kmem_cache_node, "kmem_cache_node",
-		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);
+			sizeof(struct kmem_cache_node),
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
 
@@ -5053,7 +5054,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 			offsetof(struct kmem_cache, node) +
 				nr_node_ids * sizeof(struct kmem_cache_node *),
-		       SLAB_HWCACHE_ALIGN, 0, 0);
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	kmem_cache = bootstrap(&boot_kmem_cache);
 	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-10-surenb%40google.com.
