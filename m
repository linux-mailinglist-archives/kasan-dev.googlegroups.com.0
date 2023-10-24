Return-Path: <kasan-dev+bncBC7OD3FKWUERBDEW36UQMGQEXKVNFYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 69F2F7D5279
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:57 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-357ce7283d3sf1051365ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155276; cv=pass;
        d=google.com; s=arc-20160816;
        b=vNnUFWTd8ifhqTzXop+m6fSgjGhW+RN2WyafEi0m9vzYKBpjslX9L3YM2HYETASq1K
         lv4RTbYV39Nq1p2cWI66Bo9i0ajFZGZ0+kj70fY273q898mjISeHDzbxEnhCf9LWSv/O
         HWHIls6Sd6wM/9zy/9wFvHqrzysMvxw0TQFycyHexvU/OVcnYFvhjXW+6sY/B4U+lsDE
         g7VwXPy1cVIKFTWALf/PgcfCXh/965kqQ/eJO+/kw98/v2NtZY8CPn4PTekupke0PJV8
         ysPj+6AyJJCAUlSQJsbZQgvljhV4O/OdLge0JQIDHuCIOlsGKPtzAJP0deLSYWCw3REO
         6UFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/Qd0tt+kO1iMay5g6h3IR5cqnHAqGGE8miryIsuzqag=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=VSYZQBUccUR+gFyLoMkVeM+MqVrUa2wyLKHekJfONE2GNetdNt7TegDn0N8wjH3yq8
         RhIaq9qi1g1x7SgEqS5scMS8tOostYik8dwfTvIs5t6/TPm1zYpzmk3xttbscFFXD91w
         xdJeCtRA2tDxytVkIdntO9TplTBTQ6yVT+HWCdp9Nc1djSel16ovwg9dWmGo+e/LKP8w
         FKP84mbfl6H762OKhcG69J67MyOplz3VCYXqTHv7wYVnO2M8awsD5KCwRL7mpnlcu6HZ
         kxoAPeGDViNKcXblq+DFkTzr69CcjnP7ILVg0kyPjsnf3sUIpek9he5qlnUg3owacE/L
         CdxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YbCIdwIe;
       spf=pass (google.com: domain of 3c8s3zqykcbaikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3C8s3ZQYKCbAikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155276; x=1698760076; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/Qd0tt+kO1iMay5g6h3IR5cqnHAqGGE8miryIsuzqag=;
        b=F8UmHdn9pgHMZ21r93kX5nvW50y3/Odc+KPtSfbtscv57SKjPmNbb5rJXcmfh4OiXu
         R7O96PITYdV2qP9DUVHULPYrgzEjjrIttI+usrFlGfdbZvqp/tBnG+1Ttg5Wo/a7YDUi
         9NWDESsD7NxbiEqgoFHeZFaADNpi/iO5uJAlCsVUFmyNOUxXt+OFH/HSkDtR+nQMWT1Z
         HZXYYorKyzWm1mG7Lp0LqiY3rPLtFBDkRj57BjfS8A+gCHGuHAP1zrhMr43GXWrKl3La
         bLwwMK532YNXdtF1mWxl0U1OZhYeADs4eI+aeK7eLN1gglLEvdHj2zULZ/YgGYDeDFdY
         4hJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155276; x=1698760076;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/Qd0tt+kO1iMay5g6h3IR5cqnHAqGGE8miryIsuzqag=;
        b=L3b79foHKIae7fskeEXoPJXp6CPwWdItsZgEICrHBd08z0mKz3uwUxuqtVWW3xv51/
         sRCm/FhJEG6n6J4GsOI2hK/bZxysPCvCOOKxp0eIAoa51hKmHyoF4+tiJEaaT47SB5Px
         pEvtLgryADq5ee4CLKyrJ+vZcevQodtmv/JNa5jcQaLohRYoSsmfM37DTRfX+GbP2vVy
         lem96zXJjkSQVxOQDN3CFpPJt/ugf4cszfF4W7Ym4rRk8f+/2h+odqJaFSrAnaU218o7
         cjl9OfWPdm54BJfUYAQa1XQp+BQUosLmYAm43w1BvTHQDrz5iaz9Ng0RtjIXiac9XPqx
         kIMA==
X-Gm-Message-State: AOJu0YzjteVArIhG12OYD5RjwV0SgdXZud1+bgfSQ2jdATdbDQEu3NZ8
	Ki7Ui5uMmJWZdGqSX9Q+Rpo=
X-Google-Smtp-Source: AGHT+IFXWpOu0AAPpKsQ5yi1741h6FhfqNNpFYdStr8dHWQYESCdJJHUlak6kNuWgjvxab83/3x0ZQ==
X-Received: by 2002:a05:6e02:c05:b0:346:48bd:da43 with SMTP id d5-20020a056e020c0500b0034648bdda43mr258198ile.4.1698155276288;
        Tue, 24 Oct 2023 06:47:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c56d:0:b0:357:b2f8:daf7 with SMTP id b13-20020a92c56d000000b00357b2f8daf7ls2184717ilj.1.-pod-prod-07-us;
 Tue, 24 Oct 2023 06:47:55 -0700 (PDT)
X-Received: by 2002:a05:6e02:1bca:b0:352:5fcb:1401 with SMTP id x10-20020a056e021bca00b003525fcb1401mr15937403ilv.8.1698155275424;
        Tue, 24 Oct 2023 06:47:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155275; cv=none;
        d=google.com; s=arc-20160816;
        b=eFWZIpB0g0oRQDJyml6n0v3jUxB/u5OWWi076ctKR9HTa0aYl4gZo+xenULXinIFpH
         +6OEjKzkqnUlCKsTkf8ttQLltlIwZa2lJHk/p+I22KOsozmIhvEqjcCz/m84r36ejmHw
         mi0ZGpzsnS2vhMhHKo9RfGeddzK4zrJe41LVtmI/urH+ErXsGhCU5hryoIiPRC5XQRv+
         KFU3voTnskunDqz2pdUWeFqOo9PK49cn4XKQvekkiadU52mQwa21WQNADRT5x6LgxdzY
         zO/0Tf3DIb21yg7nPEfqE8kq2uv1IWQfrDcoM9zAYo3ElbDnUWVIuBB11GJ7a+ppRw90
         tYwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=JDn4KyOu1aP1bbjJv2+LYLA0L02aMbiW0UOS3mV2n4g=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=T4lIefIoc2iGO5YKhnyIaCCfR7lKvR5jKNERPR7a69g+mEsZ2EbJ/2vJDpnBN8e7ob
         /vAXlBBPgav6Kid5wGhFTHnK8RKgBJjgloRuaHBBH4HK07asRTGxsbWLYB5MZ65M7zsP
         I0JCQ9QDWr9qcdkgEkGaTdNKx8vpJeTsXkTvATUVgP9e5SCWS4or6MrQvmMix3UtKhVk
         LeKAtiULQqjRXeiWE7W8vdybWLRUKINtSXbnayQbNoElz3g7lCgxqXcK1W+L+n7rEO1N
         FtD+I+kbz+K0pnfmi6PZhZO3DCkRmGifjFYMi9DnS64H2JbvQFjMOu9PQhk+8HW8S+1c
         N9Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YbCIdwIe;
       spf=pass (google.com: domain of 3c8s3zqykcbaikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3C8s3ZQYKCbAikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id cn5-20020a056e02388500b0035250544598si846486ilb.1.2023.10.24.06.47.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3c8s3zqykcbaikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d9a3a38b96cso5081352276.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:55 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a05:6902:4ad:b0:da0:46e5:a7ef with SMTP id
 r13-20020a05690204ad00b00da046e5a7efmr24271ybs.3.1698155275005; Tue, 24 Oct
 2023 06:47:55 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:30 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-34-surenb@google.com>
Subject: [PATCH v2 33/39] mm: vmalloc: Enable memory allocation profiling
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
 header.i=@google.com header.s=20230601 header.b=YbCIdwIe;       spf=pass
 (google.com: domain of 3c8s3zqykcbaikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3C8s3ZQYKCbAikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
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

This wrapps all external vmalloc allocation functions with the
alloc_hooks() wrapper, and switches internal allocations to _noprof
variants where appropriate, for the new memory allocation profiling
feature.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 drivers/staging/media/atomisp/pci/hmm/hmm.c |  2 +-
 include/linux/vmalloc.h                     | 60 ++++++++++----
 kernel/kallsyms_selftest.c                  |  2 +-
 mm/util.c                                   | 24 +++---
 mm/vmalloc.c                                | 88 ++++++++++-----------
 5 files changed, 103 insertions(+), 73 deletions(-)

diff --git a/drivers/staging/media/atomisp/pci/hmm/hmm.c b/drivers/staging/media/atomisp/pci/hmm/hmm.c
index bb12644fd033..3e2899ad8517 100644
--- a/drivers/staging/media/atomisp/pci/hmm/hmm.c
+++ b/drivers/staging/media/atomisp/pci/hmm/hmm.c
@@ -205,7 +205,7 @@ static ia_css_ptr __hmm_alloc(size_t bytes, enum hmm_bo_type type,
 	}
 
 	dev_dbg(atomisp_dev, "pages: 0x%08x (%zu bytes), type: %d, vmalloc %p\n",
-		bo->start, bytes, type, vmalloc);
+		bo->start, bytes, type, vmalloc_noprof);
 
 	return bo->start;
 
diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index c720be70c8dd..106d78e75606 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -2,6 +2,8 @@
 #ifndef _LINUX_VMALLOC_H
 #define _LINUX_VMALLOC_H
 
+#include <linux/alloc_tag.h>
+#include <linux/sched.h>
 #include <linux/spinlock.h>
 #include <linux/init.h>
 #include <linux/list.h>
@@ -137,26 +139,54 @@ extern unsigned long vmalloc_nr_pages(void);
 static inline unsigned long vmalloc_nr_pages(void) { return 0; }
 #endif
 
-extern void *vmalloc(unsigned long size) __alloc_size(1);
-extern void *vzalloc(unsigned long size) __alloc_size(1);
-extern void *vmalloc_user(unsigned long size) __alloc_size(1);
-extern void *vmalloc_node(unsigned long size, int node) __alloc_size(1);
-extern void *vzalloc_node(unsigned long size, int node) __alloc_size(1);
-extern void *vmalloc_32(unsigned long size) __alloc_size(1);
-extern void *vmalloc_32_user(unsigned long size) __alloc_size(1);
-extern void *__vmalloc(unsigned long size, gfp_t gfp_mask) __alloc_size(1);
-extern void *__vmalloc_node_range(unsigned long size, unsigned long align,
+extern void *vmalloc_noprof(unsigned long size) __alloc_size(1);
+#define vmalloc(...)		alloc_hooks(vmalloc_noprof(__VA_ARGS__))
+
+extern void *vzalloc_noprof(unsigned long size) __alloc_size(1);
+#define vzalloc(...)		alloc_hooks(vzalloc_noprof(__VA_ARGS__))
+
+extern void *vmalloc_user_noprof(unsigned long size) __alloc_size(1);
+#define vmalloc_user(...)	alloc_hooks(vmalloc_user_noprof(__VA_ARGS__))
+
+extern void *vmalloc_node_noprof(unsigned long size, int node) __alloc_size(1);
+#define vmalloc_node(...)	alloc_hooks(vmalloc_node_noprof(__VA_ARGS__))
+
+extern void *vzalloc_node_noprof(unsigned long size, int node) __alloc_size(1);
+#define vzalloc_node(...)	alloc_hooks(vzalloc_node_noprof(__VA_ARGS__))
+
+extern void *vmalloc_32_noprof(unsigned long size) __alloc_size(1);
+#define vmalloc_32(...)		alloc_hooks(vmalloc_32_noprof(__VA_ARGS__))
+
+extern void *vmalloc_32_user_noprof(unsigned long size) __alloc_size(1);
+#define vmalloc_32_user(...)	alloc_hooks(vmalloc_32_user_noprof(__VA_ARGS__))
+
+extern void *__vmalloc_noprof(unsigned long size, gfp_t gfp_mask) __alloc_size(1);
+#define __vmalloc(...)		alloc_hooks(__vmalloc_noprof(__VA_ARGS__))
+
+extern void *__vmalloc_node_range_noprof(unsigned long size, unsigned long align,
 			unsigned long start, unsigned long end, gfp_t gfp_mask,
 			pgprot_t prot, unsigned long vm_flags, int node,
 			const void *caller) __alloc_size(1);
-void *__vmalloc_node(unsigned long size, unsigned long align, gfp_t gfp_mask,
+#define __vmalloc_node_range(...)	alloc_hooks(__vmalloc_node_range_noprof(__VA_ARGS__))
+
+void *__vmalloc_node_noprof(unsigned long size, unsigned long align, gfp_t gfp_mask,
 		int node, const void *caller) __alloc_size(1);
-void *vmalloc_huge(unsigned long size, gfp_t gfp_mask) __alloc_size(1);
+#define __vmalloc_node(...)	alloc_hooks(__vmalloc_node_noprof(__VA_ARGS__))
+
+void *vmalloc_huge_noprof(unsigned long size, gfp_t gfp_mask) __alloc_size(1);
+#define vmalloc_huge(...)	alloc_hooks(vmalloc_huge_noprof(__VA_ARGS__))
+
+extern void *__vmalloc_array_noprof(size_t n, size_t size, gfp_t flags) __alloc_size(1, 2);
+#define __vmalloc_array(...)	alloc_hooks(__vmalloc_array_noprof(__VA_ARGS__))
+
+extern void *vmalloc_array_noprof(size_t n, size_t size) __alloc_size(1, 2);
+#define vmalloc_array(...)	alloc_hooks(vmalloc_array_noprof(__VA_ARGS__))
+
+extern void *__vcalloc_noprof(size_t n, size_t size, gfp_t flags) __alloc_size(1, 2);
+#define __vcalloc(...)		alloc_hooks(__vcalloc_noprof(__VA_ARGS__))
 
-extern void *__vmalloc_array(size_t n, size_t size, gfp_t flags) __alloc_size(1, 2);
-extern void *vmalloc_array(size_t n, size_t size) __alloc_size(1, 2);
-extern void *__vcalloc(size_t n, size_t size, gfp_t flags) __alloc_size(1, 2);
-extern void *vcalloc(size_t n, size_t size) __alloc_size(1, 2);
+extern void *vcalloc_noprof(size_t n, size_t size) __alloc_size(1, 2);
+#define vcalloc(...)		alloc_hooks(vcalloc_noprof(__VA_ARGS__))
 
 extern void vfree(const void *addr);
 extern void vfree_atomic(const void *addr);
diff --git a/kernel/kallsyms_selftest.c b/kernel/kallsyms_selftest.c
index b4cac76ea5e9..3ea9be364e32 100644
--- a/kernel/kallsyms_selftest.c
+++ b/kernel/kallsyms_selftest.c
@@ -82,7 +82,7 @@ static struct test_item test_items[] = {
 	ITEM_FUNC(kallsyms_test_func_static),
 	ITEM_FUNC(kallsyms_test_func),
 	ITEM_FUNC(kallsyms_test_func_weak),
-	ITEM_FUNC(vmalloc),
+	ITEM_FUNC(vmalloc_noprof),
 	ITEM_FUNC(vfree),
 #ifdef CONFIG_KALLSYMS_ALL
 	ITEM_DATA(kallsyms_test_var_bss_static),
diff --git a/mm/util.c b/mm/util.c
index 27ed6a5ac31a..7e6043ece040 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -629,7 +629,7 @@ void *kvmalloc_node_noprof(size_t size, gfp_t flags, int node)
 	 * about the resulting pointer, and cannot play
 	 * protection games.
 	 */
-	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
+	return __vmalloc_node_range_noprof(size, 1, VMALLOC_START, VMALLOC_END,
 			flags, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
 			node, __builtin_return_address(0));
 }
@@ -688,12 +688,12 @@ void *kvrealloc_noprof(const void *p, size_t oldsize, size_t newsize, gfp_t flag
 EXPORT_SYMBOL(kvrealloc_noprof);
 
 /**
- * __vmalloc_array - allocate memory for a virtually contiguous array.
+ * __vmalloc_array_noprof - allocate memory for a virtually contiguous array.
  * @n: number of elements.
  * @size: element size.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-void *__vmalloc_array(size_t n, size_t size, gfp_t flags)
+void *__vmalloc_array_noprof(size_t n, size_t size, gfp_t flags)
 {
 	size_t bytes;
 
@@ -701,18 +701,18 @@ void *__vmalloc_array(size_t n, size_t size, gfp_t flags)
 		return NULL;
 	return __vmalloc(bytes, flags);
 }
-EXPORT_SYMBOL(__vmalloc_array);
+EXPORT_SYMBOL(__vmalloc_array_noprof);
 
 /**
- * vmalloc_array - allocate memory for a virtually contiguous array.
+ * vmalloc_array_noprof - allocate memory for a virtually contiguous array.
  * @n: number of elements.
  * @size: element size.
  */
-void *vmalloc_array(size_t n, size_t size)
+void *vmalloc_array_noprof(size_t n, size_t size)
 {
 	return __vmalloc_array(n, size, GFP_KERNEL);
 }
-EXPORT_SYMBOL(vmalloc_array);
+EXPORT_SYMBOL(vmalloc_array_noprof);
 
 /**
  * __vcalloc - allocate and zero memory for a virtually contiguous array.
@@ -720,22 +720,22 @@ EXPORT_SYMBOL(vmalloc_array);
  * @size: element size.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-void *__vcalloc(size_t n, size_t size, gfp_t flags)
+void *__vcalloc_noprof(size_t n, size_t size, gfp_t flags)
 {
 	return __vmalloc_array(n, size, flags | __GFP_ZERO);
 }
-EXPORT_SYMBOL(__vcalloc);
+EXPORT_SYMBOL(__vcalloc_noprof);
 
 /**
- * vcalloc - allocate and zero memory for a virtually contiguous array.
+ * vcalloc_noprof - allocate and zero memory for a virtually contiguous array.
  * @n: number of elements.
  * @size: element size.
  */
-void *vcalloc(size_t n, size_t size)
+void *vcalloc_noprof(size_t n, size_t size)
 {
 	return __vmalloc_array(n, size, GFP_KERNEL | __GFP_ZERO);
 }
-EXPORT_SYMBOL(vcalloc);
+EXPORT_SYMBOL(vcalloc_noprof);
 
 struct anon_vma *folio_anon_vma(struct folio *folio)
 {
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index a3fedb3ee0db..62fd33094bfd 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3025,12 +3025,12 @@ vm_area_alloc_pages(gfp_t gfp, int nid,
 			 * but mempolicy wants to alloc memory by interleaving.
 			 */
 			if (IS_ENABLED(CONFIG_NUMA) && nid == NUMA_NO_NODE)
-				nr = alloc_pages_bulk_array_mempolicy(bulk_gfp,
+				nr = alloc_pages_bulk_array_mempolicy_noprof(bulk_gfp,
 							nr_pages_request,
 							pages + nr_allocated);
 
 			else
-				nr = alloc_pages_bulk_array_node(bulk_gfp, nid,
+				nr = alloc_pages_bulk_array_node_noprof(bulk_gfp, nid,
 							nr_pages_request,
 							pages + nr_allocated);
 
@@ -3060,9 +3060,9 @@ vm_area_alloc_pages(gfp_t gfp, int nid,
 			break;
 
 		if (nid == NUMA_NO_NODE)
-			page = alloc_pages(alloc_gfp, order);
+			page = alloc_pages_noprof(alloc_gfp, order);
 		else
-			page = alloc_pages_node(nid, alloc_gfp, order);
+			page = alloc_pages_node_noprof(nid, alloc_gfp, order);
 		if (unlikely(!page)) {
 			if (!nofail)
 				break;
@@ -3119,10 +3119,10 @@ static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
 
 	/* Please note that the recursion is strictly bounded. */
 	if (array_size > PAGE_SIZE) {
-		area->pages = __vmalloc_node(array_size, 1, nested_gfp, node,
+		area->pages = __vmalloc_node_noprof(array_size, 1, nested_gfp, node,
 					area->caller);
 	} else {
-		area->pages = kmalloc_node(array_size, nested_gfp, node);
+		area->pages = kmalloc_node_noprof(array_size, nested_gfp, node);
 	}
 
 	if (!area->pages) {
@@ -3205,7 +3205,7 @@ static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
 }
 
 /**
- * __vmalloc_node_range - allocate virtually contiguous memory
+ * __vmalloc_node_range_noprof - allocate virtually contiguous memory
  * @size:		  allocation size
  * @align:		  desired alignment
  * @start:		  vm area range start
@@ -3232,7 +3232,7 @@ static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
  *
  * Return: the address of the area or %NULL on failure
  */
-void *__vmalloc_node_range(unsigned long size, unsigned long align,
+void *__vmalloc_node_range_noprof(unsigned long size, unsigned long align,
 			unsigned long start, unsigned long end, gfp_t gfp_mask,
 			pgprot_t prot, unsigned long vm_flags, int node,
 			const void *caller)
@@ -3361,7 +3361,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 }
 
 /**
- * __vmalloc_node - allocate virtually contiguous memory
+ * __vmalloc_node_noprof - allocate virtually contiguous memory
  * @size:	    allocation size
  * @align:	    desired alignment
  * @gfp_mask:	    flags for the page level allocator
@@ -3379,10 +3379,10 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *__vmalloc_node(unsigned long size, unsigned long align,
+void *__vmalloc_node_noprof(unsigned long size, unsigned long align,
 			    gfp_t gfp_mask, int node, const void *caller)
 {
-	return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
+	return __vmalloc_node_range_noprof(size, align, VMALLOC_START, VMALLOC_END,
 				gfp_mask, PAGE_KERNEL, 0, node, caller);
 }
 /*
@@ -3391,15 +3391,15 @@ void *__vmalloc_node(unsigned long size, unsigned long align,
  * than that.
  */
 #ifdef CONFIG_TEST_VMALLOC_MODULE
-EXPORT_SYMBOL_GPL(__vmalloc_node);
+EXPORT_SYMBOL_GPL(__vmalloc_node_noprof);
 #endif
 
-void *__vmalloc(unsigned long size, gfp_t gfp_mask)
+void *__vmalloc_noprof(unsigned long size, gfp_t gfp_mask)
 {
-	return __vmalloc_node(size, 1, gfp_mask, NUMA_NO_NODE,
+	return __vmalloc_node_noprof(size, 1, gfp_mask, NUMA_NO_NODE,
 				__builtin_return_address(0));
 }
-EXPORT_SYMBOL(__vmalloc);
+EXPORT_SYMBOL(__vmalloc_noprof);
 
 /**
  * vmalloc - allocate virtually contiguous memory
@@ -3413,12 +3413,12 @@ EXPORT_SYMBOL(__vmalloc);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc(unsigned long size)
+void *vmalloc_noprof(unsigned long size)
 {
-	return __vmalloc_node(size, 1, GFP_KERNEL, NUMA_NO_NODE,
+	return __vmalloc_node_noprof(size, 1, GFP_KERNEL, NUMA_NO_NODE,
 				__builtin_return_address(0));
 }
-EXPORT_SYMBOL(vmalloc);
+EXPORT_SYMBOL(vmalloc_noprof);
 
 /**
  * vmalloc_huge - allocate virtually contiguous memory, allow huge pages
@@ -3432,16 +3432,16 @@ EXPORT_SYMBOL(vmalloc);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc_huge(unsigned long size, gfp_t gfp_mask)
+void *vmalloc_huge_noprof(unsigned long size, gfp_t gfp_mask)
 {
-	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
+	return __vmalloc_node_range_noprof(size, 1, VMALLOC_START, VMALLOC_END,
 				    gfp_mask, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
 				    NUMA_NO_NODE, __builtin_return_address(0));
 }
-EXPORT_SYMBOL_GPL(vmalloc_huge);
+EXPORT_SYMBOL_GPL(vmalloc_huge_noprof);
 
 /**
- * vzalloc - allocate virtually contiguous memory with zero fill
+ * vzalloc_noprof - allocate virtually contiguous memory with zero fill
  * @size:    allocation size
  *
  * Allocate enough pages to cover @size from the page level
@@ -3453,12 +3453,12 @@ EXPORT_SYMBOL_GPL(vmalloc_huge);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vzalloc(unsigned long size)
+void *vzalloc_noprof(unsigned long size)
 {
-	return __vmalloc_node(size, 1, GFP_KERNEL | __GFP_ZERO, NUMA_NO_NODE,
+	return __vmalloc_node_noprof(size, 1, GFP_KERNEL | __GFP_ZERO, NUMA_NO_NODE,
 				__builtin_return_address(0));
 }
-EXPORT_SYMBOL(vzalloc);
+EXPORT_SYMBOL(vzalloc_noprof);
 
 /**
  * vmalloc_user - allocate zeroed virtually contiguous memory for userspace
@@ -3469,17 +3469,17 @@ EXPORT_SYMBOL(vzalloc);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc_user(unsigned long size)
+void *vmalloc_user_noprof(unsigned long size)
 {
-	return __vmalloc_node_range(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
+	return __vmalloc_node_range_noprof(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
 				    GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL,
 				    VM_USERMAP, NUMA_NO_NODE,
 				    __builtin_return_address(0));
 }
-EXPORT_SYMBOL(vmalloc_user);
+EXPORT_SYMBOL(vmalloc_user_noprof);
 
 /**
- * vmalloc_node - allocate memory on a specific node
+ * vmalloc_node_noprof - allocate memory on a specific node
  * @size:	  allocation size
  * @node:	  numa node
  *
@@ -3491,15 +3491,15 @@ EXPORT_SYMBOL(vmalloc_user);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc_node(unsigned long size, int node)
+void *vmalloc_node_noprof(unsigned long size, int node)
 {
-	return __vmalloc_node(size, 1, GFP_KERNEL, node,
+	return __vmalloc_node_noprof(size, 1, GFP_KERNEL, node,
 			__builtin_return_address(0));
 }
-EXPORT_SYMBOL(vmalloc_node);
+EXPORT_SYMBOL(vmalloc_node_noprof);
 
 /**
- * vzalloc_node - allocate memory on a specific node with zero fill
+ * vzalloc_node_noprof - allocate memory on a specific node with zero fill
  * @size:	allocation size
  * @node:	numa node
  *
@@ -3509,12 +3509,12 @@ EXPORT_SYMBOL(vmalloc_node);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vzalloc_node(unsigned long size, int node)
+void *vzalloc_node_noprof(unsigned long size, int node)
 {
-	return __vmalloc_node(size, 1, GFP_KERNEL | __GFP_ZERO, node,
+	return __vmalloc_node_noprof(size, 1, GFP_KERNEL | __GFP_ZERO, node,
 				__builtin_return_address(0));
 }
-EXPORT_SYMBOL(vzalloc_node);
+EXPORT_SYMBOL(vzalloc_node_noprof);
 
 #if defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA32)
 #define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
@@ -3529,7 +3529,7 @@ EXPORT_SYMBOL(vzalloc_node);
 #endif
 
 /**
- * vmalloc_32 - allocate virtually contiguous memory (32bit addressable)
+ * vmalloc_32_noprof - allocate virtually contiguous memory (32bit addressable)
  * @size:	allocation size
  *
  * Allocate enough 32bit PA addressable pages to cover @size from the
@@ -3537,15 +3537,15 @@ EXPORT_SYMBOL(vzalloc_node);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc_32(unsigned long size)
+void *vmalloc_32_noprof(unsigned long size)
 {
-	return __vmalloc_node(size, 1, GFP_VMALLOC32, NUMA_NO_NODE,
+	return __vmalloc_node_noprof(size, 1, GFP_VMALLOC32, NUMA_NO_NODE,
 			__builtin_return_address(0));
 }
-EXPORT_SYMBOL(vmalloc_32);
+EXPORT_SYMBOL(vmalloc_32_noprof);
 
 /**
- * vmalloc_32_user - allocate zeroed virtually contiguous 32bit memory
+ * vmalloc_32_user_noprof - allocate zeroed virtually contiguous 32bit memory
  * @size:	     allocation size
  *
  * The resulting memory area is 32bit addressable and zeroed so it can be
@@ -3553,14 +3553,14 @@ EXPORT_SYMBOL(vmalloc_32);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc_32_user(unsigned long size)
+void *vmalloc_32_user_noprof(unsigned long size)
 {
-	return __vmalloc_node_range(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
+	return __vmalloc_node_range_noprof(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
 				    GFP_VMALLOC32 | __GFP_ZERO, PAGE_KERNEL,
 				    VM_USERMAP, NUMA_NO_NODE,
 				    __builtin_return_address(0));
 }
-EXPORT_SYMBOL(vmalloc_32_user);
+EXPORT_SYMBOL(vmalloc_32_user_noprof);
 
 /*
  * Atomically zero bytes in the iterator.
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-34-surenb%40google.com.
