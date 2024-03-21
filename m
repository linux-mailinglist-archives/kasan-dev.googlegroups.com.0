Return-Path: <kasan-dev+bncBC7OD3FKWUERB56E6GXQMGQEAE7ZUWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A30A885DCB
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:17 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1dee0dd9193sf20965ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039096; cv=pass;
        d=google.com; s=arc-20160816;
        b=XUkdwvHW6PSaI/7zgKRz1Kn4oCYBUh5QdyKlAC/nreWIdilewM+RxIv+DDEYc64+Ao
         uTg25fUDio+9IFVru0ZNBD3N0qZFwbcYd6BR2O7e0ecgcWa+6jQDk3Heb/scgU/avzR0
         Q4oft/dih6jMxyikELvFssgEmH3vEaitddt9Ij2psE33Upv1Z3L2a+4ub66heKg0mJ/Z
         ZKQkwmZo9gNWDJWpKfuH8aVlFegCX5bysSYvp1uHEQKLxiwgivbL6Z1cBicQmY4yecEX
         FY8LR5VDLm21wpF5c2OI8kJkrVO0mE9PtZcy+/KryPc8WjKu69hyltfhrG4+f1Dh//v+
         UdHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=OmK1+bPS/urZyYV+TmxjBoCkVS/JZE/F/7ElDIOr5Gs=;
        fh=d95aKaFRdhSQyEGkivbcX9e+vQthmm/VGvHaN6CNOJ8=;
        b=VaL45ljCqXUuA+PnK+xYnmO9dyJh+mXebcVdG7O4F7KWBzdBBTUVL8Jq2Qc9pcZ99V
         y3HBIaU0QtCgHEAPd+9TAcNmjh5DF+K3emdj3u+0dM795SdlhV7u8VX+/JuxrZXQs3fC
         1RiF8UM+nFMWoB3HApo5nKwOKDg7By9vZKMKXV5uoPcf1VWVyP8FF8Si2feZ4ZcjRSeA
         TWKk8iih5wXMGbxHWlRbw25uMxvyNpjuVqjOCpQz/O3RX7A6UgoGizVXE87UkA4mgraX
         mEF8zQB6mtjFK2bLG+VhxpzIAKg6tE3Zg6UYeDqGc2OZkO9yqiaUiGYcRh/MJ7xkkkvA
         PWUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4S7m2fbd;
       spf=pass (google.com: domain of 3dgl8zqykcwertqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3dGL8ZQYKCWERTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039096; x=1711643896; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=OmK1+bPS/urZyYV+TmxjBoCkVS/JZE/F/7ElDIOr5Gs=;
        b=N/2ikNtUNT5cQ4VEZMn5hNsUEA6bTk8mmU3B+0p/tqrvP7SMENNz4gqx114umfUa3U
         exuUQ6pLVWFVF7OCanV2QqKaZkeduWom9gDvnV9h6xfcE89pPSIAK+CkuFIioFtg+jAY
         mBp7tRent3gQ5itdgt0hRAgpMn5tyHtOWh20+RUmOS6Oz3SFZeb3ol25fj1o42YDqjol
         1kkoTCIo8eTfEiUNf8sa93XNicNa0BbxGLFwMFhlc3GIUSF3h6KiFRtfUNrvgXDzZOlb
         +b6qLQUxyp3cKkb7mHCvPNBj5Y1a7R9ri9HiCfbY8GDzkn4AFQGwjNMlw2AwLTA5s0Jf
         JOnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039096; x=1711643896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OmK1+bPS/urZyYV+TmxjBoCkVS/JZE/F/7ElDIOr5Gs=;
        b=j2MopkmmjNhNrvlkxRYjMvbhXjB+vAdIiyhnM1SWUZrIMU5+Z+ExmFJ3u6syORi4Q2
         /PiqW6iH1bYNCEBUpEExEWJdlq1GaQRMGrhk2/0otDHV3GynlV9c7Sm+bV1ZqWhlKRqQ
         X3fXmfdr7LvC0Fcttdg6ppCrffT/83ReKr1tYlVAMXUTE33nmp68o23u/7uXyIyehj/+
         EM/2DLmreqVamBhLPMJnLsYTEfJKcZhRKM+urtIU8rZZ5JOC97lie0qoN81rVHm6LxAy
         Ms2hDiHTCcDLIFOga2cMfhHQ7i1Ac+62k9k+hpx2iDyUq3NFAD9a0BlXs+UW2F/i7tn9
         m5EA==
X-Forwarded-Encrypted: i=2; AJvYcCWyQydx7XZc8QUmBCbMxfMnTRmMM2ydQV1sYKz4Np+NnDAsQKEPQOKtMUu283BowQ8qzo9ilLUzHayJAihXconnB7iHYqYbOQ==
X-Gm-Message-State: AOJu0Yxca8cCclTqKHj5eUr22ejmeLLZz9D+fgITw3lIDC4Hi8cXn9mE
	/8FNlXKN8v6pFeEicPHdjzNxP74Y8NiYnrq7jOCUtUepBfuQO62E
X-Google-Smtp-Source: AGHT+IHggdyiVilhTNmqlgWc6JRZ/fivQJA2bNBzd70LKFNKU1aFAWJeYjXaocf4ExR05t2A1JV7tA==
X-Received: by 2002:a17:902:da87:b0:1dd:9819:5379 with SMTP id j7-20020a170902da8700b001dd98195379mr236629plx.9.1711039095996;
        Thu, 21 Mar 2024 09:38:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a90:b0:29c:5a19:1c32 with SMTP id
 x16-20020a17090a8a9000b0029c5a191c32ls770063pjn.1.-pod-prod-06-us; Thu, 21
 Mar 2024 09:38:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWdittLpyhulK75YDneEFCekL+RQUNU7YdTuTkZqI6eGZTgMhpmFKv5pHaCA1zeZxD9+u63o/XtEbmRBvyPbjx/BXnOtLY6r4XSKw==
X-Received: by 2002:a05:6a20:244d:b0:1a3:3dcb:aedc with SMTP id t13-20020a056a20244d00b001a33dcbaedcmr27304pzc.32.1711039094080;
        Thu, 21 Mar 2024 09:38:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039094; cv=none;
        d=google.com; s=arc-20160816;
        b=xA/UiCGuoJ2pd5jSMki1hyVeMcKgM8lLkG6gS/bOQcK6bk7Ape6oOUpXnKiqb7q3ED
         DNbIIzzzvOQO4+9hXpYnv6LrLvO3S5lU2w7Kmn+vftqGczwkInagtwn/3DztKIDP8b2R
         W8VKugLftzdM4uIRyIbWhEHjU4PTt6lOOBk4jD2m2o6K5Hqb8hlZh89BL8iHsFrvYM6G
         qbT7Rsa+rcWnUS7Jg75g/1ydUvbVEhhW966NklsBN17k00aXw0UNQlfQSKVXIAXJ4sdG
         6iC0oUHFEm9UgeTrtfCYWZADR3slBE1KpmTXyueFDwtd4NGQI6BWgfnBfYufQ79kRetf
         R+bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TkCDMNHfK5xLLlYY223eXbm7c73NL7RFva1BQ3rh7WM=;
        fh=ZvPrKfiI39nyL7R6phyvpCF5Wzt4/TNb2y7EE/i8xok=;
        b=oB8YN4pbJ8ngWQf5S19gVZ5qU2Go9DoxQeueM1UUg+xiiLl1cP8c/+cj390MllhXcU
         d5M4qgWDvCVBLN91sarsZmFGm/Z5HROawEAME2Lr8DzK7WDgMWOkah4gqgSsjdELaXEZ
         eUwJM/WPvO5/3gruclAzlorQ8ja9GRlQapATxjtm6d7er++UaYMUtc4RocX33TWBbrWW
         jrD0WjdJiSHwMsxhMrXFjT2e/PDFJ1pDSDVoIi06vORlFelwkZwl6n7oSr2DgUoV5vHn
         eWwiCOHJ/9TECY+ya3pUEzDINP8x+kMyi1Yc/WVaXGp8lMCXbzQ/RNj8BcAoROiDkLYX
         DrFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4S7m2fbd;
       spf=pass (google.com: domain of 3dgl8zqykcwertqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3dGL8ZQYKCWERTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id a4-20020a17090ad80400b0029bbd2c38d1si523361pjv.0.2024.03.21.09.38.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dgl8zqykcwertqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60cd62fa20fso23647117b3.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6y8RUiSbLA7kbapPZDdIMK3HE+xzVpZAw8gT/6GL+zhi7Vz1bJNhmRbElSCqZM5ZMkMhfTTvl7f00X6ts3JM2CHcr6zU4sm0HwA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:1a48:b0:dcc:8be2:7cb0 with SMTP id
 cy8-20020a0569021a4800b00dcc8be27cb0mr1175240ybb.0.1711039092976; Thu, 21 Mar
 2024 09:38:12 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:51 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-30-surenb@google.com>
Subject: [PATCH v6 29/37] mm: percpu: enable per-cpu allocation tagging
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
 header.i=@google.com header.s=20230601 header.b=4S7m2fbd;       spf=pass
 (google.com: domain of 3dgl8zqykcwertqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3dGL8ZQYKCWERTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
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

Redefine __alloc_percpu, __alloc_percpu_gfp and __alloc_reserved_percpu
to record allocations and deallocations done by these functions.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/percpu.h | 23 ++++++++++-----
 mm/percpu.c            | 64 +++++-------------------------------------
 2 files changed, 23 insertions(+), 64 deletions(-)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 62b5eb45bd89..e54921c79c9a 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -2,6 +2,7 @@
 #ifndef __LINUX_PERCPU_H
 #define __LINUX_PERCPU_H
 
+#include <linux/alloc_tag.h>
 #include <linux/mmdebug.h>
 #include <linux/preempt.h>
 #include <linux/smp.h>
@@ -9,6 +10,7 @@
 #include <linux/pfn.h>
 #include <linux/init.h>
 #include <linux/cleanup.h>
+#include <linux/sched.h>
 
 #include <asm/percpu.h>
 
@@ -125,7 +127,6 @@ extern int __init pcpu_page_first_chunk(size_t reserved_size,
 				pcpu_fc_cpu_to_node_fn_t cpu_to_nd_fn);
 #endif
 
-extern void __percpu *__alloc_reserved_percpu(size_t size, size_t align) __alloc_size(1);
 extern bool __is_kernel_percpu_address(unsigned long addr, unsigned long *can_addr);
 extern bool is_kernel_percpu_address(unsigned long addr);
 
@@ -133,14 +134,16 @@ extern bool is_kernel_percpu_address(unsigned long addr);
 extern void __init setup_per_cpu_areas(void);
 #endif
 
-extern void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp) __alloc_size(1);
-extern void __percpu *__alloc_percpu(size_t size, size_t align) __alloc_size(1);
-extern void free_percpu(void __percpu *__pdata);
+extern void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
+				   gfp_t gfp) __alloc_size(1);
 extern size_t pcpu_alloc_size(void __percpu *__pdata);
 
-DEFINE_FREE(free_percpu, void __percpu *, free_percpu(_T))
-
-extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
+#define __alloc_percpu_gfp(_size, _align, _gfp)				\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, false, _gfp))
+#define __alloc_percpu(_size, _align)					\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, false, GFP_KERNEL))
+#define __alloc_reserved_percpu(_size, _align)				\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, true, GFP_KERNEL))
 
 #define alloc_percpu_gfp(type, gfp)					\
 	(typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type),	\
@@ -149,6 +152,12 @@ extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
 	(typeof(type) __percpu *)__alloc_percpu(sizeof(type),		\
 						__alignof__(type))
 
+extern void free_percpu(void __percpu *__pdata);
+
+DEFINE_FREE(free_percpu, void __percpu *, free_percpu(_T))
+
+extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
+
 extern unsigned long pcpu_nr_pages(void);
 
 #endif /* __LINUX_PERCPU_H */
diff --git a/mm/percpu.c b/mm/percpu.c
index 90e9e4004ac9..dd7eeb370134 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1726,7 +1726,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
 #endif
 
 /**
- * pcpu_alloc - the percpu allocator
+ * pcpu_alloc_noprof - the percpu allocator
  * @size: size of area to allocate in bytes
  * @align: alignment of area (max PAGE_SIZE)
  * @reserved: allocate from the reserved chunk if available
@@ -1740,7 +1740,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
  * RETURNS:
  * Percpu pointer to the allocated area on success, NULL on failure.
  */
-static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
+void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
 				 gfp_t gfp)
 {
 	gfp_t pcpu_gfp;
@@ -1907,6 +1907,8 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	pcpu_memcg_post_alloc_hook(objcg, chunk, off, size);
 
+	pcpu_alloc_tag_alloc_hook(chunk, off, size);
+
 	return ptr;
 
 fail_unlock:
@@ -1935,61 +1937,7 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	return NULL;
 }
-
-/**
- * __alloc_percpu_gfp - allocate dynamic percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- * @gfp: allocation flags
- *
- * Allocate zero-filled percpu area of @size bytes aligned at @align.  If
- * @gfp doesn't contain %GFP_KERNEL, the allocation doesn't block and can
- * be called from any context but is a lot more likely to fail. If @gfp
- * has __GFP_NOWARN then no warning will be triggered on invalid or failed
- * allocation requests.
- *
- * RETURNS:
- * Percpu pointer to the allocated area on success, NULL on failure.
- */
-void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
-{
-	return pcpu_alloc(size, align, false, gfp);
-}
-EXPORT_SYMBOL_GPL(__alloc_percpu_gfp);
-
-/**
- * __alloc_percpu - allocate dynamic percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- *
- * Equivalent to __alloc_percpu_gfp(size, align, %GFP_KERNEL).
- */
-void __percpu *__alloc_percpu(size_t size, size_t align)
-{
-	return pcpu_alloc(size, align, false, GFP_KERNEL);
-}
-EXPORT_SYMBOL_GPL(__alloc_percpu);
-
-/**
- * __alloc_reserved_percpu - allocate reserved percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- *
- * Allocate zero-filled percpu area of @size bytes aligned at @align
- * from reserved percpu area if arch has set it up; otherwise,
- * allocation is served from the same dynamic area.  Might sleep.
- * Might trigger writeouts.
- *
- * CONTEXT:
- * Does GFP_KERNEL allocation.
- *
- * RETURNS:
- * Percpu pointer to the allocated area on success, NULL on failure.
- */
-void __percpu *__alloc_reserved_percpu(size_t size, size_t align)
-{
-	return pcpu_alloc(size, align, true, GFP_KERNEL);
-}
+EXPORT_SYMBOL_GPL(pcpu_alloc_noprof);
 
 /**
  * pcpu_balance_free - manage the amount of free chunks
@@ -2328,6 +2276,8 @@ void free_percpu(void __percpu *ptr)
 	spin_lock_irqsave(&pcpu_lock, flags);
 	size = pcpu_free_area(chunk, off);
 
+	pcpu_alloc_tag_free_hook(chunk, off, size);
+
 	pcpu_memcg_free_hook(chunk, off, size);
 
 	/*
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-30-surenb%40google.com.
