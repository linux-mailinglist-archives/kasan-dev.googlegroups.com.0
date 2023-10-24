Return-Path: <kasan-dev+bncBC7OD3FKWUERBCEW36UQMGQEUZMWXTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 39E947D5273
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:53 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-357429e8ac0sf54570545ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155272; cv=pass;
        d=google.com; s=arc-20160816;
        b=oL/LtHyGOmrwKi8hrkG3knlPmYwgzPaZhlDJgsCTfQohRByf/M0HyhsfMU3NmJ7nHH
         iHeRVkckTDI+mkUoKSyQr+DcvTHSzJ85ahjhryv0U/qQS3hZTA81yaORGjWgz+WjLXR7
         V20RylksY+ELDJxqYVK+OlQFZxf5m9fUda41/or6/EXY3kPOUeFV6A165YonWzxUzY0p
         +xBi/3NyUZIyj6YT031cMgqOwTnJ+DaE+ZYhSMnML9e1L7C9Nk5lTrL+Kn889Tfatwjt
         9Dmb/fb2EIQz4y7UsosdvyEXhzyvzij0fYGoMKOe59CM6f4gA6bbfRZGUyKV3wwYEFfE
         pCjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=t2pZIzOy0vxkJq+/u16So4H/g8922ThTWSV3eiVxzfY=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=zde9EmepR3O9YUYCz7r8TfpNWlP+4ayhGTn357ykuXfG0mHMsoa4p5mPoFh+1o3M5v
         E4fMEBEyMDQ/xI+ge//bYzSS+TtPNJDjUr4qK0lJwRanVl7q6GuAbsFQxI/8bXVeMsGT
         dRXAOWETL6cNb4JnQZDk+p//XFRrH3MxO8PiX1d8oITgATNFc2QtHsnnY+e8SkSlcnHs
         UGDbmnG3LTE7cZRqCc8taLJnlY7D4RDHbMNmxxN7ij043O9TRIstao0mz68tNEeEcIbY
         kgNnzAMh90F11KWFZh7fNkxoYkR2FVCm2M90Okrsm+4KuzadTHlSo7xr0OsIxmpvZ8U6
         YCzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xiON1T2k;
       spf=pass (google.com: domain of 3bss3zqykcasdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Bss3ZQYKCasdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155272; x=1698760072; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=t2pZIzOy0vxkJq+/u16So4H/g8922ThTWSV3eiVxzfY=;
        b=kIVKM75socMbyhbNy3xI2RvxbhBvN+8+XSheXlpzLDOO8OSnNeBIDShH/qiOp0of0K
         M8d/Qi2rWYH1i6LVuPOFZZPdh6WOxEgwvPRA9OMW13QLTvw09cgv3WO98HvWJdGuRh+d
         WK5rDw75t8AhWOw44g/KvMNR+KNoWIbcFTiRbq1sMZEpJXTPVsgd1Kppwof4eWgyHyNA
         VO8XI1X10COeqAIJXpCD/BGTJIXc/+fK9N8ZWXfE7SbJ/4K/rGB+Ulk+HHeFfd/pop9z
         ssBKGL2Mnb/w2rVQFXhgICJJKZ+5Ih8LKe2IPQ6dROaaNUaIoqvWsOa1ETmyPYFJwpjd
         U7VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155272; x=1698760072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=t2pZIzOy0vxkJq+/u16So4H/g8922ThTWSV3eiVxzfY=;
        b=ISl8AUU7QjLIfllgnMwMiV/9ho7sW6ptzVH9jtJ2IyCerdUu0yeJpD//T8kdLWVIr0
         IEkJjdPD2lnt3JnEzob3ylx3rsQMYgLYdX7ldcteZ8URry2Ic7+pvQenjJJac48oO5lX
         W+XiwnL6d2TcnTfrQHWzdpP8bzDUIiDovz3cM4SZQ5ubNiOEFj3//gsGpobrDMa3kuaO
         kxRq88+eoidumrvi2T/ltA7qLiSD3H9UCLtBeJvatBI2k7UgBVix5jOi3I0mITATq9Nx
         WQcsd8H6wgjovkHDkW6wIEuFAVHGY1aaG1OET5M/KqEE4ZB/7zLL85qn2f8NUOny3Hp9
         V6xw==
X-Gm-Message-State: AOJu0YwzdeJUUVo/YDW/tU7359DmCDKzP5ujuj/WmcpSXqDBjjE7LGqs
	qXMIBV52ICnCdf1ADF73ERQ=
X-Google-Smtp-Source: AGHT+IGMnEMB+CSF6uZHeHEUW27g/CnuJh+9tTjjEDOBLeKrTka/0OeC/S1MfR0SMsdCgRSEyY58pQ==
X-Received: by 2002:a92:d443:0:b0:357:49f1:96a9 with SMTP id r3-20020a92d443000000b0035749f196a9mr11821144ilm.26.1698155272089;
        Tue, 24 Oct 2023 06:47:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ce43:0:b0:357:3d9d:209e with SMTP id a3-20020a92ce43000000b003573d9d209els175514ilr.2.-pod-prod-06-us;
 Tue, 24 Oct 2023 06:47:51 -0700 (PDT)
X-Received: by 2002:a92:d785:0:b0:357:ca98:3db2 with SMTP id d5-20020a92d785000000b00357ca983db2mr9838102iln.21.1698155271488;
        Tue, 24 Oct 2023 06:47:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155271; cv=none;
        d=google.com; s=arc-20160816;
        b=Y8Ofjf52cpgQcZK2g8ljs50+9A8+NuhFJlWj+GAZmcWdITM3vGbLlkMNCncGDqhYXu
         K2i8qfC5bz/pXInTq6Z6yBXT8UBD2MORw+K0A2Vq3nA5f9378LHjpjUmqU3d3uUJRQ4N
         whPnA1Doq2QbJmV89u1FCEvxlwMwun1QRGnbIpvXutL4Eay4iFxXzW7ornXgE0fgOkKF
         0BUKTnWRcoaFf9B8Kz1vqYTOIJh9Z+X/tkYJiHBMxgFGQJ0q6oBn8iK8aA8XkT74+ve+
         tDX7GiV4pMixHpYQczf7CzO9uAC+3cJFg4y2Hy8dgytz70E3aYJm5d7Oln6pq920kDwU
         iYtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=05OHaXyGuLuiu55tV7A0+NfbyrdoqwRt+v2k2i2/xoM=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=eIz43dto+JYZ75qiPaA1sFoflLs/5Xhr61IquBkODzfC8xhP8ovqrODUjMLQgMEj4J
         n+hSZ6VEqe3pCzOxniRTBcsbdGFqnpTCIh4l8TzoQvZ5+M/AIdkoa6EqdpLwUHdlR9ej
         VuI1x9D4l+re3eNz51zpnnqvMq0ryoPodyla4AhxTXxEo/foGtVJTs4Il2eova5l/wc1
         XssDfioFvIUm7yqRGKk/78oRTQBr2rUYLA5i82qkEpdQdGOcUjEmz+7pBJadINKfSYX0
         pFcHVy/PbQnNfTfeUIFWsgccj95M1rgPT6TUnE4gVdeBddvpA5yKOEzG0Ejb9IDui3EC
         nvxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xiON1T2k;
       spf=pass (google.com: domain of 3bss3zqykcasdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Bss3ZQYKCasdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id o5-20020a92d385000000b00350fd9a47f9si84525ilo.5.2023.10.24.06.47.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bss3zqykcasdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d9cad450d5fso5175387276.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:51 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:5008:0:b0:da0:2b01:7215 with SMTP id
 e8-20020a255008000000b00da02b017215mr55853ybb.10.1698155270752; Tue, 24 Oct
 2023 06:47:50 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:28 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-32-surenb@google.com>
Subject: [PATCH v2 31/39] mm: percpu: enable per-cpu allocation tagging
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
 header.i=@google.com header.s=20230601 header.b=xiON1T2k;       spf=pass
 (google.com: domain of 3bss3zqykcasdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Bss3ZQYKCasdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
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
index 68fac2e7cbe6..338c1ef9c93d 100644
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
 
@@ -121,7 +123,6 @@ extern int __init pcpu_page_first_chunk(size_t reserved_size,
 				pcpu_fc_cpu_to_node_fn_t cpu_to_nd_fn);
 #endif
 
-extern void __percpu *__alloc_reserved_percpu(size_t size, size_t align) __alloc_size(1);
 extern bool __is_kernel_percpu_address(unsigned long addr, unsigned long *can_addr);
 extern bool is_kernel_percpu_address(unsigned long addr);
 
@@ -129,13 +130,15 @@ extern bool is_kernel_percpu_address(unsigned long addr);
 extern void __init setup_per_cpu_areas(void);
 #endif
 
-extern void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp) __alloc_size(1);
-extern void __percpu *__alloc_percpu(size_t size, size_t align) __alloc_size(1);
-extern void free_percpu(void __percpu *__pdata);
+extern void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
+				   gfp_t gfp) __alloc_size(1);
 
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
@@ -144,6 +147,12 @@ extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
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
index 002ee5d38fd5..328a5b3c943b 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1728,7 +1728,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
 #endif
 
 /**
- * pcpu_alloc - the percpu allocator
+ * pcpu_alloc_noprof - the percpu allocator
  * @size: size of area to allocate in bytes
  * @align: alignment of area (max PAGE_SIZE)
  * @reserved: allocate from the reserved chunk if available
@@ -1742,7 +1742,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
  * RETURNS:
  * Percpu pointer to the allocated area on success, NULL on failure.
  */
-static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
+void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
 				 gfp_t gfp)
 {
 	gfp_t pcpu_gfp;
@@ -1909,6 +1909,8 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	pcpu_memcg_post_alloc_hook(objcg, chunk, off, size);
 
+	pcpu_alloc_tag_alloc_hook(chunk, off, size);
+
 	return ptr;
 
 fail_unlock:
@@ -1937,61 +1939,7 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
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
@@ -2301,6 +2249,8 @@ void free_percpu(void __percpu *ptr)
 
 	size = pcpu_free_area(chunk, off);
 
+	pcpu_alloc_tag_free_hook(chunk, off, size);
+
 	pcpu_memcg_free_hook(chunk, off, size);
 
 	/*
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-32-surenb%40google.com.
