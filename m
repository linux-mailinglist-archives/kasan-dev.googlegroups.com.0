Return-Path: <kasan-dev+bncBC7OD3FKWUERBUVAVKXAMGQEEKK2H4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A214851FEB
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:35 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-6047a047f4csf97755197b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774034; cv=pass;
        d=google.com; s=arc-20160816;
        b=FhcPECYsVRy+CWAcbDxEnl9pEakpzuU0yfgOPeVD/JST5yFNiZcfx8FCbVcZPdnvZT
         NxZiKWT1ltYzNHq4BwUru6//HzezkSpFTFY01JznU1if++/GQ4g0LMuPG0TyXHDvrbq1
         sa+rczNpUbK8p+08C6cHzfl8AoJQEOMMzPGeEyH1fZ+/dbxwr11lcBt4CWRtVm2saieF
         DRNix9OiqRrSlSD4MyQWJYaC74Mrp7Lm3D5O4yEK8s2qGPwhzXjB3u3v+r8GbHrwH6is
         u86hkzF/Z8SCNiU361B+5UvoZ1IiqO8Ko29g3+hLPbT8DDkW2JRj9mC6Eg/QIfoLWO1N
         PCKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=WPlP8g8qcbecQEJzaw9eSpiShk+mlAV+uf803l0zagM=;
        fh=S27FY4Zt6f4ACnRQYYodtNO6+zWVJWVZrjxKRop2D2Q=;
        b=p971/FKIK3cBJ5Zgs89shWIbb0LH4r6G0UFhl6DU2qmERRgL1nh0C3d8Tr1z5+S4wP
         c9v27xB3KDXoY3J3kn4KbloHKd1ZV6xfVTojKEwcyJ5kKdiWcjJz9VYYh9Joxz0ra9rF
         9HIKcYv7c7RCrYIs/XVlL5mxQiiWQyEe0hgxV+v4/sZzhKjY9xJ4zUWWR3cooGTffGx9
         PMIStnSAzt2bF2CnlKxC1aZtF1IXurisaa3zQGkZL01vN8it+xIwkBhV02PIRfI4BdzT
         n3bYJ/r3Zyl4LWXv8i7XTdLyh3JAcezvk6pK+cGoBSlVQwiKz0bu93v9aMEQSy3yEHkj
         hySQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PBA8r5X9;
       spf=pass (google.com: domain of 3ujdkzqykcc8dfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3UJDKZQYKCc8DFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774034; x=1708378834; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WPlP8g8qcbecQEJzaw9eSpiShk+mlAV+uf803l0zagM=;
        b=BvqDkcBQVNTVqZE6SGlyBVQm6eb4DRzcU5HlQ1X2rztxfG8gwYue9nZDI3W5PFDiib
         BkFLLn4OD6Peb5x8JCJdS2hLL8fYungx9CK7tJaiYMGIwGyCAk8QBZzd1oO3wWQgHvx8
         W5zW/VW/kIfpiRbWQQQcxGuMJgrqD2Zsjjv27SrZo9JMTvxPMLg3oCj/1im6p2znMG/l
         Xekg9k6Zlc+HBCCluLt5hcjeObe2kW57dWdIuR9+S4JoNlxwIReJ6y9YN2I42SXTz5VY
         ktf8T2bTgBo+/FeWgvxb2P9UbBzgvY9+PiQvSlyedzCD3v2Of3ZXU4FTj2vSYOloYXQo
         D/6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774034; x=1708378834;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WPlP8g8qcbecQEJzaw9eSpiShk+mlAV+uf803l0zagM=;
        b=pjQG/5Tg9+dhngAY5WojxDj0QSQ7pn6zSU2KvXzeXnnavQ9Jk5MNBDWmR3I1OHBwzT
         D0yYefR1GUT7YAWPBxHGR36HlCrThHElLtH+YBgS2KWme3TkGtorBq2AAGU6EX6Tc4sp
         o0/+bTZDjcuLTkQ9RLWWEJxJZetWZkxcsywmCSQf0zY7jWI5OZ24OAvW/cXyH65Zkgiz
         ilx/l1qHxVMQoSprQhCLZvFprmjl8upYxp3Pl7Z4c1kgkZaepxaEat/mFn7+dzF9aslz
         xDVvIQeMKP5ocFBY5Y/fFHW04kDOM7BJHreLbKaJV9VMoohGrERXZeDW0bEu6VBvj65H
         7goQ==
X-Forwarded-Encrypted: i=2; AJvYcCVaa4aY2PAUBa5CbWHWfCLoWVBoEAxvWtXpcvV7/BTJ2cQ1RI4YjR6dQvuS/m7fkfQzBeIOoen8I437ugnkkdg95nEGyIelag==
X-Gm-Message-State: AOJu0YxA2+00qZyW29Y0iOI1cKqzTXu9Jgrd9JkiealtNhWvL54LcT4U
	5XGDtYwAabmIm8xwdzE6Cw1w+WuCHaThmy5nU1gtstWwgYM5rzm6MAs=
X-Google-Smtp-Source: AGHT+IFwMluiKwT8biu0OE5L4ZfAjWzWBrEV7u1YvvN9fMgYIGhUxKbG7FsHsNj4F+dI0fUv3EYZog==
X-Received: by 2002:a25:ce14:0:b0:dcc:7c0f:2222 with SMTP id x20-20020a25ce14000000b00dcc7c0f2222mr10304ybe.22.1707774034215;
        Mon, 12 Feb 2024 13:40:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6883:0:b0:dcb:f35a:afeb with SMTP id d125-20020a256883000000b00dcbf35aafebls543210ybc.2.-pod-prod-06-us;
 Mon, 12 Feb 2024 13:40:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVThZYq8tSrNG9WoEf7GR2fzH03bVAkmYNQkX3kshzjpAPmR1lQsQXBT05P+ZwJAHQILYRNsbzFV7v/WJ3IwZqt1s3TTGLkGYQG3w==
X-Received: by 2002:a25:b227:0:b0:dc2:3ec3:95d4 with SMTP id i39-20020a25b227000000b00dc23ec395d4mr6501112ybj.47.1707774033460;
        Mon, 12 Feb 2024 13:40:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774033; cv=none;
        d=google.com; s=arc-20160816;
        b=KZnuRyWh0t+I3FjgO3SN7nXq2rE7Ey7xInL2kvi1PArK46L7XRrFIvfuF6HdN1TETT
         RMPmJ8OmiY8qxK03QbUC8IqX3LMarGTyMRPAIlyNOwJnZ161nDQz8d/4XPqWC4sg61gz
         ZPfusk5WqKdo2GWNYA84WbHV3Vdboq0OyT7o5u7NMbbHisbnjbFs+YIq1g6Tes/Fl6S7
         bAO4y3C1F86K0uhlC7MAK+fxHaQovq4zM9Vr34iN52A6gn167qcEpON7s+Wz/udOqGvT
         BLNnqPRmzjdbY8zBzK5VwXgHgkStvh/RuljBvGJT05QjtU9yZHTANkG6pzJox7aNJH9d
         Apuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=z8tkEzFiQHW4+OeWkbnef4rwrjbu90Cr9IgJj7MTk7I=;
        fh=GLdxpO0tOpbf51WTtMAj7MNv677rSd86E+bFsH3S7iE=;
        b=OKbm/+Ze+gQ9sTx4SStM/AK3QxNk2CKeZvdc/wcFaD1LpEcUAO/8fAHwCpjGtzjcJV
         3/CkPeqgC/5awt41RECz/pS4oSDQaoz3wf7TreNO4z22MLP2DPXSgiog3ZpXODInvTmX
         IzL++CpE6CeNXTSQpGBlvWQlTKi+deV9rJqBs3aE3QXwMt7heSOfC0DbWf78zHSZDoOV
         vIWzx/wy9lzYNRxLHDiXoKfs27ixMo7r14nFueh2L9Jhx5cib8VbVl6VliUl6ucgOofl
         LL7WKH/gQvuccgwCpSOjuZ01MdYS+UScJmHBCHaqTmYlxnHT3NQ/IYRaSRvN9897KScB
         myzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PBA8r5X9;
       spf=pass (google.com: domain of 3ujdkzqykcc8dfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3UJDKZQYKCc8DFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCW2QB+zsU+5uqPnPmJR3JwXo60M+FKxARS7eiXWp76M76QAvzewzu7QezOjQHKq5wFTcx/zFAOmXA4vOYQVnqY+Ztuqa/dC/ZuIdA==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 9-20020a0562140d4900b0068d0f6d6b86si152508qvr.3.2024.02.12.13.40.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ujdkzqykcc8dfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5ffee6fcdc1so59582727b3.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVxW/bXTKahrZUnsHC5ubMD4igCwJvJlAkpKVxq+523F7h6WUaC81Amt1MyoUfwkS4EXQCnwApHVwpvaDL1O0Ws6e9aNutpv1reDQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a81:a010:0:b0:607:7dee:a7fa with SMTP id
 x16-20020a81a010000000b006077deea7famr162033ywg.2.1707774032997; Mon, 12 Feb
 2024 13:40:32 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:14 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-29-surenb@google.com>
Subject: [PATCH v3 28/35] mm: percpu: enable per-cpu allocation tagging
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=PBA8r5X9;       spf=pass
 (google.com: domain of 3ujdkzqykcc8dfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3UJDKZQYKCc8DFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
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
 include/linux/alloc_tag.h | 15 +++++++++
 include/linux/percpu.h    | 23 +++++++++-----
 mm/percpu.c               | 64 +++++----------------------------------
 3 files changed, 38 insertions(+), 64 deletions(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 6fa8a94d8bc1..3fe51e67e231 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -140,4 +140,19 @@ static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 	_res;								\
 })
 
+/*
+ * workaround for a sparse bug: it complains about res_type_to_err() when
+ * typeof(_do_alloc) is a __percpu pointer, but gcc won't let us add a separate
+ * __percpu case to res_type_to_err():
+ */
+#define alloc_hooks_pcpu(_do_alloc)					\
+({									\
+	typeof(_do_alloc) _res;						\
+	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
+									\
+	_res = _do_alloc;						\
+	alloc_tag_restore(&_alloc_tag, _old);				\
+	_res;								\
+})
+
 #endif /* _LINUX_ALLOC_TAG_H */
diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 62b5eb45bd89..eb4eb264136f 100644
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
+	alloc_hooks_pcpu(pcpu_alloc_noprof(_size, _align, false, _gfp))
+#define __alloc_percpu(_size, _align)					\
+	alloc_hooks_pcpu(pcpu_alloc_noprof(_size, _align, false, GFP_KERNEL))
+#define __alloc_reserved_percpu(_size, _align)				\
+	alloc_hooks_pcpu(pcpu_alloc_noprof(_size, _align, true, GFP_KERNEL))
 
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
index 578531ea1f43..2badcc5e0e71 100644
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-29-surenb%40google.com.
