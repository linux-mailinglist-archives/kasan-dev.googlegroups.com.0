Return-Path: <kasan-dev+bncBC7OD3FKWUERBSGE6GXQMGQEFRYWCTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EFD7885DA4
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:30 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dc6dbdcfd39sf2285604276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039049; cv=pass;
        d=google.com; s=arc-20160816;
        b=b0zWGQqxP3ONaOU9hTKHpG+iPXiq/oi1ERa4fXgg3vCkvTVXyOXKrwaX29T4pmk16y
         E+G2gJRM127bgeosCDltkN/zirfwx/2lmfIOGSYXg2JPJDg0aMumMbbzrLqOZO/G6lbG
         faO6mb16DIYs7K6f6W2K0LIkgg7O+yJDPvtM6ZbBjHhqGM7ZI0UiKX1DoOZ8DmvHMEkr
         YC+ZluwEERtxO1hQizkdn0Kb2xrPhhBj4uQo2fiAkVjD7bCNfhlXVESkmf6wohtrzkOC
         KAouNOdn7dFzMODrNucxWuqnVzHu6j9Qk/J4I+vdHMMRxminswFoqWRJeQszrUAXasEG
         +0uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fD2VUPg1KgQAwk6S3SeG3oYmEiKIs2GOedO153oAP5I=;
        fh=tiWt5mkzI3u0UOu6RVN0uEDK1fO0Y2Ie/luhJM7Wp5E=;
        b=nesiKjXZ0h8sUpKADifFFQ8AvXOeHl7GTH04T8ouQjMTEMLNUENzw+NDCdD3JFHJj3
         VrzDBoQfQJi3zSFaDLwtx5TaPnz7YTyX9SXm4yb+UorNiSPVDSk9czh6Z5wVb4e7AU7s
         1fNYQnD3U3Dcfk+Z2UA1W159vR6gBHa8bVJ/biQNzxD3MTdcMGAKcVOg/0QB74x5N3eG
         RQAPWeVoaS08dxATt0IyaKjbjdBArTfKS8OYr0oOWwdUEFABac5kmuYF0oXbgzLmq/S3
         L7WfFfV/POYE4F07sqeqQROjbv+YtM8gLNWuK1xtgnwANW0dkq1TwCaLVMtqxtoAHQ23
         T7UQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=26a1xZp2;
       spf=pass (google.com: domain of 3r2l8zqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R2L8ZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039049; x=1711643849; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fD2VUPg1KgQAwk6S3SeG3oYmEiKIs2GOedO153oAP5I=;
        b=WVZ8mWqmpV0G4aVEl7T7Z/ABUTEzx4VFpgzWJLccY0z7NaCw40Pts2TAz/NNi1FUQ1
         v7ntxAp5JdErRDKgAxci3VIucMDHw0GG7ZnGAq2T8KpaDP7mxtJpJH0Qopfu/cX5DSvn
         iA3x/0mgPFSCr6bI8o/SyaQbOm2NycautnfwtvcqlH5Xzf+rpgLEH96agpH5TBwIdaZx
         /OH84P5WCg+Ds9GRsMTQjkbwVtmUorh3/SSIdRJgFE3yguvLer2zueHFqakR5CXZY0BN
         FfVtCp0k7gIX2A4efAY+BoDW0VQttNwr48zvKHYIl/oZep3CThgt7m/F8186sqYXTB4B
         to1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039049; x=1711643849;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fD2VUPg1KgQAwk6S3SeG3oYmEiKIs2GOedO153oAP5I=;
        b=NWWJJbt7l8H3ieBZQ7EIdUAs6T6Z1hsWEgp30i9fQaZtVBS9yAFOf05sqlZMPitLg2
         kGggFPM/papXuUdTlSJI9yX3hpTFu19lLZwsA7IEanYnt9hg+TolANX4S40afeCJI0xc
         Etb1JR+uYt+3KSTElkAALjUikAlHneAwfK7DT8KhkyvA4KsaA1VXpue3YTXf8UKfABka
         ZUf2Oh2aoI2WEN93+97UiIowbe7UryG0gcnS+qJ06oCeKxZLrfWY223EjnjNGRIazGz8
         vTdYAJbFEO89VYH/HrRTDjK0Fd0aeDCQvki4NFW903oVj1X8b9u6tocqYEigK5/qwhlL
         vo0A==
X-Forwarded-Encrypted: i=2; AJvYcCVFQ3xtAeI4DNo7s5/cse/of8w/nFVPgLnsDZyWr2wCyHZFz3GUbe++MpU9LYxuASSQEj7KnPGyDyk8FzKE5IfZ+wZ5ShyrkA==
X-Gm-Message-State: AOJu0YyBwPzF80rFdr/aj1Qco9LODO7e8TrU7BOzQ2JoC5FPRq4VxFXu
	zWd4gi/Vx1x6NpCAJSr4Vg+9jMtTyRcaOOx19WT7w4kBnWCZ5//w
X-Google-Smtp-Source: AGHT+IHBzuFIXk1Ap99RaII2IuA0L2dnNoKCslVui/CBqkke2GLVMOUo+YGuMdhESGyzHCAnY6+Aew==
X-Received: by 2002:a25:ae97:0:b0:dd1:2f58:292b with SMTP id b23-20020a25ae97000000b00dd12f58292bmr2336354ybj.9.1711039048810;
        Thu, 21 Mar 2024 09:37:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:33c4:0:b0:dcd:a08f:c83a with SMTP id z187-20020a2533c4000000b00dcda08fc83als387938ybz.2.-pod-prod-05-us;
 Thu, 21 Mar 2024 09:37:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsLBPtKdwU3MenrjZ0eb2RnpLdmVrPUUj6yKdtHAZQn5Q8VoHavNkXahGrlYmCov4hLcCecKKaCJRQlsggicpIEvlcYpiUHt2noQ==
X-Received: by 2002:a0d:e482:0:b0:60c:bc77:9ba0 with SMTP id n124-20020a0de482000000b0060cbc779ba0mr2474515ywe.40.1711039047677;
        Thu, 21 Mar 2024 09:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039047; cv=none;
        d=google.com; s=arc-20160816;
        b=Bs+zN7alX9s5MupClWGvQh6dKeGJj3jqFzsu6hjnnSsCEVDg5fJ0MbbOAyjSdrdCUn
         x8rDYLs75QTv3yW9Gf7v2CdX3ZzWlAa6ysLeyQYSpXbelmW+UwFyV2Fk7kQFszx1DpXc
         Ky15+GWRWwdwXcWN3Dbzi/Z7En0qCkDPcnWNF4k9T+kBupDeTcF+ULzkvTKQklxJDf+Y
         ohFVpec2NkbRFo+X/f4krX+cBaPUGrenif8/af18x0Rt6Y1jS3BjO6CO27x3IPFZazp5
         1ahEXNhLYU0tOOpYv6MzooZ5AF+AfKY4bRyTOYqM6ZBnPmv4nJsyfljAURcOu3OldDHS
         vabQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=SHSiwfbVG9SSjDRWdVOT6ZUhatpmkb8bIc+SfDPMGsQ=;
        fh=3J8kwJ2Ttn3NsIL+Ts1satbVpZscIxFAvdzSRBeK/BI=;
        b=uS49qcUmUf+7ABlhbAQ6tURM1b3FTSTvW7TcgJtoOKMUtVg1gf0Q9otwZng+dfbQug
         x+na7w28cBoGVBH1A4VDxnd1pohp3wbJWwt4gW1url7Jg0lrADXcTrb9wf5m9vbgAe2B
         bJddNpWO9j7lmSwxTEqLBTM6oyMqz28rZHis/WnuuMku+xerIeJi3vuZcdfoT5QQnRST
         gksbgoUwvRMOerff33Mc/WAiCFcjdnuryC3ISDhrUWnG3A1XoFYu+xWUWJGX+mCqvQcs
         jH91SnFPGnQjEjy/Dsv8R8tP0vAOEb7T4KvXVumyBqJf8NB6hCP139fi1O9Frz3LElei
         tKrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=26a1xZp2;
       spf=pass (google.com: domain of 3r2l8zqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R2L8ZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id g185-20020a0dddc2000000b0060a1b30a432si834ywe.1.2024.03.21.09.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r2l8zqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60cd041665bso21140037b3.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWV0NwEfq1V29d1CJXPaanrPnB0UtlxfmBY6uZXZQKGVR/gRVRHIVIKj16k5V79RL+JPCh3NtQmFOs32ZpOLcJ1De3A/hIE9WjaFQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:690c:d0b:b0:610:e0de:1387 with SMTP id
 cn11-20020a05690c0d0b00b00610e0de1387mr2235869ywb.2.1711039047349; Thu, 21
 Mar 2024 09:37:27 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:30 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-9-surenb@google.com>
Subject: [PATCH v6 08/37] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=26a1xZp2;       spf=pass
 (google.com: domain of 3r2l8zqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R2L8ZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 10 ++++++++++
 mm/slub.c            |  5 +++--
 2 files changed, 13 insertions(+), 2 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index e53cbfa18325..68ff754b85a4 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -56,6 +56,9 @@ enum _slab_flag_bits {
 #endif
 	_SLAB_OBJECT_POISON,
 	_SLAB_CMPXCHG_DOUBLE,
+#ifdef CONFIG_SLAB_OBJ_EXT
+	_SLAB_NO_OBJ_EXT,
+#endif
 	_SLAB_FLAGS_LAST_BIT
 };
 
@@ -202,6 +205,13 @@ enum _slab_flag_bits {
 #endif
 #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
 
+/* Slab created using create_boot_cache */
+#ifdef CONFIG_SLAB_OBJ_EXT
+#define SLAB_NO_OBJ_EXT		__SLAB_FLAG_BIT(_SLAB_NO_OBJ_EXT)
+#else
+#define SLAB_NO_OBJ_EXT		__SLAB_FLAG_UNUSED
+#endif
+
 /*
  * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
  *
diff --git a/mm/slub.c b/mm/slub.c
index 2cb53642a091..666dcc3b8a26 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5693,7 +5693,8 @@ void __init kmem_cache_init(void)
 		node_set(node, slab_nodes);
 
 	create_boot_cache(kmem_cache_node, "kmem_cache_node",
-		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);
+			sizeof(struct kmem_cache_node),
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
 
@@ -5703,7 +5704,7 @@ void __init kmem_cache_init(void)
 	create_boot_cache(kmem_cache, "kmem_cache",
 			offsetof(struct kmem_cache, node) +
 				nr_node_ids * sizeof(struct kmem_cache_node *),
-		       SLAB_HWCACHE_ALIGN, 0, 0);
+			SLAB_HWCACHE_ALIGN | SLAB_NO_OBJ_EXT, 0, 0);
 
 	kmem_cache = bootstrap(&boot_kmem_cache);
 	kmem_cache_node = bootstrap(&boot_kmem_cache_node);
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-9-surenb%40google.com.
