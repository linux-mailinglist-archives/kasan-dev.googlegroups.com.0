Return-Path: <kasan-dev+bncBC7OD3FKWUERBMO6X6RAMGQEXW7MJGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D1D16F33F0
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:18 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-3ef65714d24sf35611441cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960177; cv=pass;
        d=google.com; s=arc-20160816;
        b=fq0Qx3xzirbqmMClYlg6On3LGmPlxhRFJ8sOLks+KtfrkA47CN3lI8YI9tEJ2KD3zT
         9EEV9N1XzPymgkmNpGl92o0rFGgReaB6V1obhR8HcMVbDlZuaqc7wjy6/R6Ht1J2mGmn
         SjqUf3l6O7bh3HjPdz0QNbSG6ssM5NWeqiowm1e72xZARCcMGgGZxlaf/CzWaZkhjysu
         4lkkStswjNAKQCeGTF+Myk8AeKLccNh4NylJlA8x/jsyW8VhZiRTLat20DVKtMLgtY7Q
         0YfAx7R0czkpeOlS0k3kwck631tBc4UgdeGJh4PanckSAMSRJmnglsalalrDeXdzixph
         gDLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZRJA3elpzKLe1+YplwnVD+ytzKOE5csqrNtmFsblV9Y=;
        b=mEX9Q2KLhFpUDn3avRMwCZKltCivTGOweSHtNQMhl51Jk7M+cMaBVlhLXG5nRjYDZz
         SyqR0NZJM0VOJ2/txZYkqcWMc7vCS9RLYKJM6a9rLVRjcvgTp/yS8DU4iCeeYTeCZfll
         cPXnn5HWcDqY5hU6oyxs5RE0tnQtJRlDI0GB+wIDKlafxTvCk/GFe3hdyF+ysmwxlKpw
         uIqaoV39oYpJGavMpWWETD5yZbzTgtxn8m1PW5HgxydPdUtbAHbGPpIk1cjIRvtDDhkw
         /ujqkQIbtticAwzGUDitf2VUSPnwZQPO9xUpGJF5beMJFJWKCDQ2mxuhVPiVDTv78/9d
         vWBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=yzTHI1C2;
       spf=pass (google.com: domain of 3mo9pzaykcxcnpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3MO9PZAYKCXcnpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960177; x=1685552177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZRJA3elpzKLe1+YplwnVD+ytzKOE5csqrNtmFsblV9Y=;
        b=L30cBP6IQWDaSL6CFr3aUkd9p3pMc+AojIagWrc1HygBczE9nQkDYVqOWENbtYvnxG
         ZRgD+AWXiAyyLj+P2KvEbZ36tKUnrv+BncgAZD9OuUWT98XGC0B6taQ+bZNX03NeMhqK
         upiJ1Sr903iChv5eR2vWXskKE8jboOJoCyfZ4jnpr+sRjeDgeCQMQJdVcvBixiIw36d7
         L0j2XoM/4K4pPZ685IxSVt1gKG00nuBvbNJBUbAFfMk7xwhUtZICKOYZp5Y+LY5WT6K3
         qumdNdZfwG90PXqkrRGKVZB9mb6tOJiSsXk+QzYyj67jgqIoc4P7nm0JKzReUYL6UNO9
         dbtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960177; x=1685552177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZRJA3elpzKLe1+YplwnVD+ytzKOE5csqrNtmFsblV9Y=;
        b=R2sz7ZiDSbAqK7EL/sqUb7yITAzjRP8bHUoGvTjaDftYJqilGHjYL6MGyf/rK7FsF7
         aLiLWhthwOOLD77/qbKABfEjos/m1m45bXB1UcCwB2HlplANfG3c1wYWejw+dl/0CwOe
         7bkjLlZqMZ7+fUkTtMxxKI4XMHi1KPh4hx34Zx/1mGlKrsX4mBxyycyHpFAFmGDMkXSc
         s1XV3yISHHG9SDC9LKz+7yDpVIEsAIkLmONBhT12ukKiFrVaa/OI+sUMxRNBW4ywt3Pr
         yDPop/jN7BYPMmzwDoHjvl08nvP64SCDoiowxnMPB9XYVgnxc3BpPDmPSp5IH4HpACuq
         eEnw==
X-Gm-Message-State: AC+VfDzRGxMaoD68n6L5sHO++bVEmFpt5PlZvqJ/7SZ2yz92mk6lKeSR
	QqSqb5FLGOvoGkj9dbx+5GQ=
X-Google-Smtp-Source: ACHHUZ4XaDlb+gBxqCeOvCjd6LiGj0l22KHsEgr1LmRQESRCUv61qVWC1INDrkpqy3FeBz5T9WnpQw==
X-Received: by 2002:a05:622a:1ba0:b0:3f0:ab4f:3bf8 with SMTP id bp32-20020a05622a1ba000b003f0ab4f3bf8mr5237694qtb.9.1682960177311;
        Mon, 01 May 2023 09:56:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5786:b0:5a2:29c1:b542 with SMTP id
 lv6-20020a056214578600b005a229c1b542ls7404600qvb.10.-pod-prod-gmail; Mon, 01
 May 2023 09:56:16 -0700 (PDT)
X-Received: by 2002:ad4:5de1:0:b0:5ef:60c3:57af with SMTP id jn1-20020ad45de1000000b005ef60c357afmr933665qvb.4.1682960176858;
        Mon, 01 May 2023 09:56:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960176; cv=none;
        d=google.com; s=arc-20160816;
        b=wEpoGhm3WGuov6Z0Be3GIHW98BfJQIBSng9Y5HEv49rrqRt1+HDyfvLA+tBwq0rytr
         pF3QIcbhtLqwI4hnMBg1KLhyxjaASTiB5Ov+Oot2FZ3RQtb3J00iXfzjqpjr9URuWtgz
         lGvR5pexVvphdmdg79THt/vmyhFX0nOhpuwmPWajxFjYeqffTJpfOCaYtIK/rE3Algb+
         vL8RQ1PSQVzWTcnahkBFrg957ZiyZdw3cXxAwOOMIyZRHILbbsQROxI/cirgW1eGPWU1
         7FCrTx50QaUPjyIPivWBiYp8g8r/zU/ilNV6kBwCIwrWzHI1PBlJyqFzKN9dXHQLbPUu
         MQlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=utmd4o6Wxf9dKKkm5+p28Q6keQxRmEnIpppKzQNbjdk=;
        b=BTP/9gc91yGXelm+RaqFNr4nqVihiuSGidtVPUkPI3m4ZS0O0u3gVDD8xzfSTCUzPQ
         NIQ1gmJf/cjgdakdk/6+cfQoeoStL0Rcmr1STtxjdWb2VC3UoIlh/NP4j8RiYKm7tL66
         XiYk9MzoJPQvQWIaR9i9EhWSTbrpAx/yqz3AWUPGXvHb6kVMFS6cB+vHpJpgz3zwEJRd
         B0IgLSM9TWOQcirSo0MiRS/1s4Lc3/aGJIAC/CwDaIXl5wg87A863dwEgbEgApheqBSX
         vSsSqrT7dRLt1hIMXKrch8vPMfV8vXBP4+FqSG5hbYUPG5wovNM0+Zhf+aSkLyBHCV64
         JiCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=yzTHI1C2;
       spf=pass (google.com: domain of 3mo9pzaykcxcnpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3MO9PZAYKCXcnpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id op25-20020a056214459900b005ef42464657si1584259qvb.3.2023.05.01.09.56.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mo9pzaykcxcnpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a8075bd7cso4837604276.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:16 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a05:6902:100e:b0:b8b:f584:6b73 with SMTP id
 w14-20020a056902100e00b00b8bf5846b73mr5602392ybt.10.1682960176468; Mon, 01
 May 2023 09:56:16 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:40 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-31-surenb@google.com>
Subject: [PATCH 30/40] mm: percpu: Add codetag reference into pcpuobj_ext
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
 header.i=@google.com header.s=20221208 header.b=yzTHI1C2;       spf=pass
 (google.com: domain of 3mo9pzaykcxcnpmziwbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3MO9PZAYKCXcnpmZiWbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--surenb.bounces.google.com;
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

From: Kent Overstreet <kent.overstreet@linux.dev>

To store codetag for every per-cpu allocation, a codetag reference is
embedded into pcpuobj_ext when CONFIG_MEM_ALLOC_PROFILING=y. Hooks to
use the newly introduced codetag are added.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/percpu-internal.h | 11 +++++++++--
 mm/percpu.c          | 26 ++++++++++++++++++++++++++
 2 files changed, 35 insertions(+), 2 deletions(-)

diff --git a/mm/percpu-internal.h b/mm/percpu-internal.h
index 2433e7b24172..c5d1d6723a66 100644
--- a/mm/percpu-internal.h
+++ b/mm/percpu-internal.h
@@ -36,9 +36,12 @@ struct pcpuobj_ext {
 #ifdef CONFIG_MEMCG_KMEM
 	struct obj_cgroup	*cgroup;
 #endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	union codetag_ref	tag;
+#endif
 };
 
-#ifdef CONFIG_MEMCG_KMEM
+#if defined(CONFIG_MEMCG_KMEM) || defined(CONFIG_MEM_ALLOC_PROFILING)
 #define NEED_PCPUOBJ_EXT
 #endif
 
@@ -79,7 +82,11 @@ struct pcpu_chunk {
 
 static inline bool need_pcpuobj_ext(void)
 {
-	return !mem_cgroup_kmem_disabled();
+	if (IS_ENABLED(CONFIG_MEM_ALLOC_PROFILING))
+		return true;
+	if (!mem_cgroup_kmem_disabled())
+		return true;
+	return false;
 }
 
 extern spinlock_t pcpu_lock;
diff --git a/mm/percpu.c b/mm/percpu.c
index 95b26a6b718d..4e2592f2e58f 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1701,6 +1701,32 @@ static void pcpu_memcg_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+static void pcpu_alloc_tag_alloc_hook(struct pcpu_chunk *chunk, int off,
+				      size_t size)
+{
+	if (mem_alloc_profiling_enabled() && likely(chunk->obj_exts)) {
+		alloc_tag_add(&chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].tag,
+			      current->alloc_tag, size);
+	}
+}
+
+static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
+{
+	if (mem_alloc_profiling_enabled() && likely(chunk->obj_exts))
+		alloc_tag_sub_noalloc(&chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].tag, size);
+}
+#else
+static void pcpu_alloc_tag_alloc_hook(struct pcpu_chunk *chunk, int off,
+				      size_t size)
+{
+}
+
+static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
+{
+}
+#endif
+
 /**
  * pcpu_alloc - the percpu allocator
  * @size: size of area to allocate in bytes
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-31-surenb%40google.com.
