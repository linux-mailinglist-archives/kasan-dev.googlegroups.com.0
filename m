Return-Path: <kasan-dev+bncBC7OD3FKWUERBWUV36UQMGQE55FCN5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 684417D5238
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:08 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-357ce7283d3sf1050505ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155227; cv=pass;
        d=google.com; s=arc-20160816;
        b=0IOpBvRAVJ7L4IoONovdgNVcaMBJnAvwoLTXca1VZuV37XS0mMIKGcb6ixzltDO1Bj
         jKyq/YVsWH3TX9IgMrjOhZziJ7ozyhuSA627WsOqq3JGvAW+A8ag4BZFc6hzOnk28dqs
         jTmtxGVNJTfNypcGCb5C3xdpnvWyFL+M0UXHKjkys4VzuxPU0/ApenA8LGk8Zvu/mpNZ
         BW0rQG+PCFqKCVqH9LRIPn2nNJ8L9QgkHKmjEa4hHdy9IWnx1kgIXKp/A1sE2/U4B4EK
         9Z+rZMs1vH1/Ey1ZbTkrTrBhqnOkUZ1om7ROq6Cq8LblYsfLh7/cRV2qqpBIYYz7Y30S
         zMUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PUuCBs/eSMvvP+bSo31t51sLZC5gxERUBjuq9+SMTPk=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=nyOi5vpCvD1cVu/rDU/wvPISTcFEUGKio8FNyOq9Tr330PoBMWOgO9KbCQquRL5jFA
         qD53/TKcawxA+ZC8wzz9PPnjdXQJR1VQFtiPI/e4eIHfRMTdrX/8eZ4gljKRm1k2NWac
         Vx8lwuZTUq+C3Ed+HUcKL2nzo4QpUJSh7d36T+SOS3aGgfZPgAV+p/nnwA3nQ2yW6kod
         5cM9nRF4RMPRRwyN27WRQRak9cen7zkuayDLpM83FS9f0KBt71+c3+ScYQ9Jz51EsgzT
         M2zBFEb0Dh+8mEnk0WuU67LqVckCMTuuAhIlmZY7cfg1HTVcbb3JxSfnHNnUqDkB10+W
         /6Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KjDbYtUB;
       spf=pass (google.com: domain of 32co3zqykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32co3ZQYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155227; x=1698760027; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PUuCBs/eSMvvP+bSo31t51sLZC5gxERUBjuq9+SMTPk=;
        b=dU63T7ElQw0VLEaR5lS0FszrdKvleyi2keH2z+xA2nr4mCD1kRMdmCUKujV5WCO1/d
         2a7JL77oo4FeRiNzBPDNuSC48TTD4cLS5u+7uKMm8ohNKmRvU6rgKLhNY2pdR7OPtv/V
         WC9Nf9tD6yEwJtLnT3A2r7kFAQSY7XnVD5o7cvlE6K4JYWb417mwJpmN4mT/dLCQrHqm
         Hl2iPc/bdNcs8MiEa/nayC07ZDF5w25h5RvQrLg86BSFN21EeGqVSHypYjdaN5F2z+j8
         5lz4i3JQ2ai1AerrxNM2iYv1W40Oo8Q2+dtS/VJhsZfi10ulRmOYIg1IwXhZj5pNwIH+
         n5/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155227; x=1698760027;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PUuCBs/eSMvvP+bSo31t51sLZC5gxERUBjuq9+SMTPk=;
        b=kj3vAsHh8aD7XxNG+dTAO3W8gRNHrKHty+8WthFSfi6bO7/jGGO7rs+45UD+EYrLal
         Ktc9znIhkF2dOKhCFtI8BaN1neH2ezje7T6p0UcAXdqhTBDSNH7mi6NqMcLB91HWOht2
         Endx5X6EL+Wwfvdr/tn17ODB7y/Iw7qvo4rNCGpCDOsr7eYwvgrktWlvqcAk4RtwPhd0
         +N+xT6NwW4rklkkXBQPgyGV6mh0y0hU9MmYjgcX15s1J6PHLEUCqJKCLfAPacBpXiXpj
         E3G/dR30rhlO29FpgXDEPBevU1VGS0l4OTAqxO8KxANiUDByOBQDprKSBp6AqcQnUEUK
         jDuw==
X-Gm-Message-State: AOJu0YyREFERrKfmm8wtx3zM2BvuGl27us+5tzqr/MjbOzBnWkNmUxZg
	RwjbS0GfBsKSIFuAQxG+4Oo=
X-Google-Smtp-Source: AGHT+IFt2jOmCdmtM0tiYDE80KxVkADDKhzIabE4hsksGOxmuC2XxNcKBi5FCFG7514nGexRak5vmw==
X-Received: by 2002:a92:8e42:0:b0:357:cdca:d0b1 with SMTP id k2-20020a928e42000000b00357cdcad0b1mr243434ilh.8.1698155227037;
        Tue, 24 Oct 2023 06:47:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:52d5:0:b0:581:e081:95d7 with SMTP id d204-20020a4a52d5000000b00581e08195d7ls4095255oob.0.-pod-prod-00-us;
 Tue, 24 Oct 2023 06:47:06 -0700 (PDT)
X-Received: by 2002:a05:6830:3153:b0:6c9:436:b36e with SMTP id c19-20020a056830315300b006c90436b36emr7411264ots.11.1698155226399;
        Tue, 24 Oct 2023 06:47:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155226; cv=none;
        d=google.com; s=arc-20160816;
        b=CegIWkGKwuzfzMgUkh/3pINOEvdlGS45PMghMOSZYwop299vMcqbZrUzwa5RrRdTVY
         1+iFCDWC+VmoLN0aA/k1nMuQFPzBeanagWgap0KsEiTIWjI9bewnI5ExC5PF3L/rsVxf
         +iX76It7shZ9IckUkLDKl81salSDkw/jwBRd1/FU/HgeqpeS1EOOdgQDwPFe3fslrcoz
         2LYVVhAJYsDbOXOhlL96ZBJ1VRfOrk7Ri5OkdX2gNghr1atQZRsy21weBBYonzBX+511
         NGcmSNf1687osb2xtwa/ctBx02Us3egWvCHZ7Q79XbuE1x1mCamwXXdy+ke7JNULRaXH
         NdvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Qg2lup2zwYWRtm8BAuIZWN5zY45A/qiqWGd2wrDGPpE=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=aZyErndZIWL0LC8zNxvdolkWA+kUXdw/MvBHI32tDraDb8oeYiOk+AnkB2sB6muTD+
         5BhgHO9uFEgkz2EEnmreTEKANwoBjZapFgBllMzbjCqfNMAU7cNEu5rqd7+MTe12rCNl
         RYRqBXTWPcgN+UtMqIBkE/YiTlo6yKvVe4zBOtPrMl7llgbhEMm8RxIzY2+p2mbv2SZR
         k7ujm3px7VV8hE8bc0HQbl0Euucg3jccmhBiqyRJE/Uy6h+a7nbg//KE+SyNujMBs6kf
         fFWemrmiXPTpYWALnTvAZeWYO8v1R+SOKXbgSiHsBXuARD0P/GWDvoCHpLjeOcBJrqhY
         CnOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KjDbYtUB;
       spf=pass (google.com: domain of 32co3zqykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32co3ZQYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id n24-20020a9d4d18000000b006c64ecd75f8si869711otf.5.2023.10.24.06.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32co3zqykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5a7d1816bccso59392017b3.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:06 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a0d:dd02:0:b0:579:f832:74b with SMTP id
 g2-20020a0ddd02000000b00579f832074bmr286214ywe.10.1698155225916; Tue, 24 Oct
 2023 06:47:05 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:08 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-12-surenb@google.com>
Subject: [PATCH v2 11/39] slab: objext: introduce objext_flags as extension to page_memcg_data_flags
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
 header.i=@google.com header.s=20230601 header.b=KjDbYtUB;       spf=pass
 (google.com: domain of 32co3zqykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32co3ZQYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
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

Introduce objext_flags to store additional objext flags unrelated to memcg.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/memcontrol.h | 29 ++++++++++++++++++++++-------
 mm/slab.h                  |  4 +---
 2 files changed, 23 insertions(+), 10 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 4b17ebb7e723..f3ede28b6fa6 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -354,7 +354,22 @@ enum page_memcg_data_flags {
 	__NR_MEMCG_DATA_FLAGS  = (1UL << 2),
 };
 
-#define MEMCG_DATA_FLAGS_MASK (__NR_MEMCG_DATA_FLAGS - 1)
+#define __FIRST_OBJEXT_FLAG	__NR_MEMCG_DATA_FLAGS
+
+#else /* CONFIG_MEMCG */
+
+#define __FIRST_OBJEXT_FLAG	(1UL << 0)
+
+#endif /* CONFIG_MEMCG */
+
+enum objext_flags {
+	/* the next bit after the last actual flag */
+	__NR_OBJEXTS_FLAGS  = __FIRST_OBJEXT_FLAG,
+};
+
+#define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
+
+#ifdef CONFIG_MEMCG
 
 static inline bool folio_memcg_kmem(struct folio *folio);
 
@@ -388,7 +403,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -409,7 +424,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
 
-	return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct obj_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -466,11 +481,11 @@ static inline struct mem_cgroup *folio_memcg_rcu(struct folio *folio)
 	if (memcg_data & MEMCG_DATA_KMEM) {
 		struct obj_cgroup *objcg;
 
-		objcg = (void *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+		objcg = (void *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 		return obj_cgroup_memcg(objcg);
 	}
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -509,11 +524,11 @@ static inline struct mem_cgroup *folio_memcg_check(struct folio *folio)
 	if (memcg_data & MEMCG_DATA_KMEM) {
 		struct obj_cgroup *objcg;
 
-		objcg = (void *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+		objcg = (void *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 		return obj_cgroup_memcg(objcg);
 	}
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 static inline struct mem_cgroup *page_memcg_check(struct page *page)
diff --git a/mm/slab.h b/mm/slab.h
index 187acc593397..60417fd262ea 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -448,10 +448,8 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 							slab_page(slab));
 	VM_BUG_ON_PAGE(obj_exts & MEMCG_DATA_KMEM, slab_page(slab));
 
-	return (struct slabobj_ext *)(obj_exts & ~MEMCG_DATA_FLAGS_MASK);
-#else
-	return (struct slabobj_ext *)obj_exts;
 #endif
+	return (struct slabobj_ext *)(obj_exts & ~OBJEXTS_FLAGS_MASK);
 }
 
 int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-12-surenb%40google.com.
