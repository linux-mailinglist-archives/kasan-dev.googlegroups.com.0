Return-Path: <kasan-dev+bncBC7OD3FKWUERBFG6X6RAMGQEIW4V2NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AAB66F33DA
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:49 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-1881256ac23sf674719fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960148; cv=pass;
        d=google.com; s=arc-20160816;
        b=FBEio/82fngLyTiSEnRD/cpGPpJo8Mx6TPxfrk1HQuJ0Gr2tfHZDS0ZYKEgnGKpiCs
         IXToABXpdbJJO7tNLpQG3u6SrpAkp98Xon8zJrcJr4OUyR7ZJPfuuufEMmt8duel3exw
         kttTNzVUFyZ0LO1hRK77v+PXjkfa6Uuo9f/66IVhYI0CwZ7siRt4RvSZqCHsqVlcJ4XJ
         PJFX2qr4ktzm2G9vvo7gnV5AKf3Hk9163zmp6IWiGYV2JxMqUJV/TQjQNRe2MgiOduwa
         l0WUWxR6scnn0/LL1irNKkIqL5PPTDAUo6MWBgw7h7HIJ9iSkIb7S1Jz/NgCiTNuh6VP
         LlFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=C3cG/sNotplnn5T6606BQ2bvQ3tBa3kzSAR6nZwwb0Y=;
        b=kClXdccHdUpeoQgQV2J5eh8sNDKaP7mDEAhvakCMml8ItDizrpGKIjjBkl6jbJLuTz
         Kpd09WEqw/G4Wgn3WQbIDHwEET99ynAfX1RWcsF0ss6M61wHVP777iVAaQtih+HPpsvl
         HHhb1i2uUk4XLrXQ46scSt+ehMzJ3IIKjrcQ53pgQaXdFH2H5vh6r30k29vQ/OCM7E3i
         NoWyTvfJvu2Ru1UPHZOV3sfC1UQzn15u0+nL4FYxUSLfaD91qjTvHV91/PRoeQqMcs0f
         RDoGZmTHUaLrasXQI8T3oO6chaISZz7lbeP9TpdSzYDWr/S62tga4QKKzgSJjPjPBgWs
         41BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=EtKwNJp9;
       spf=pass (google.com: domain of 3e-9pzaykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E-9PZAYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960148; x=1685552148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=C3cG/sNotplnn5T6606BQ2bvQ3tBa3kzSAR6nZwwb0Y=;
        b=jdfXnpDh7ut4VBMN+jiuK9kUzrr1qPQLX1zCVJMTtsE7HRDzPDaIh7oo9TyeMYvJww
         BwcdrXEk+K879KHAWMDJLtOhLWpMa6WC3W/B77/Io+kwYYKoEoz0MUXWZVtHkuVnNpDd
         HQlkiF8BQRnmtnus6xbOokEWm9VkOfuyyazE5Bcx931XGIJpb5q0qBYcX9pToP9XJ8pp
         N4YLdU+lWRzrDPI5iUcZPXTnjVUrgQ08E7SfElPqMoEbK7taJJkXKLM7rS8AgA+4h0bG
         /h5n+zDgPI3ESCXsZcMq1p52HMd0anhM2JyoeXXFEVoRZyr6SqD3eDut+nrOdpkFxGR1
         9hOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960148; x=1685552148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=C3cG/sNotplnn5T6606BQ2bvQ3tBa3kzSAR6nZwwb0Y=;
        b=glvnmlO3QnKTBhYB3zHA8holshr9etzBqrqQ65stEPqnUjVGPCbkXIhVhuDu6fblSP
         e5NOHjObhX8BImbP4u/ROumO5j9foBLDO5wbxTW2dghSqsU6kXNMDkQguQMzIwgpjNJi
         TIfWz6rE095wTf4HGXcb9WiI9XqH0QFyx+BjuIMOyB9EoJWDfwuvA6rIRIcjAlXYnG/j
         WHAjUQYsYPsOVqIsS1opFtxmjhFikp+cwKbVyCOa+O/pv4pPOY4uVyiivu31daIz9kRm
         05IZRM+gGC0XOMsZQIAe4fpigqzvPiliJQhavWkMzXBTYjjy0IcwIBBE7StkDK7NcbWO
         USSw==
X-Gm-Message-State: AC+VfDwLLXNWkMxEPc9ZvGOSrsRFlBWeIozdd0QgL0PuOnRcBZfMdbFT
	RIqSBUAF3v0j+SjXwpXHi6I=
X-Google-Smtp-Source: ACHHUZ7azrKwhibDA2pGRtc/CiONGQS7FwCrfVoWpZO9PFUustKlxXk4PZ9aaYedSlHqqpWAG8yOcg==
X-Received: by 2002:a05:6870:5151:b0:180:5c28:aa68 with SMTP id z17-20020a056870515100b001805c28aa68mr5500634oak.7.1682960148111;
        Mon, 01 May 2023 09:55:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8e0c:b0:18e:7c56:c70f with SMTP id
 lw12-20020a0568708e0c00b0018e7c56c70fls3328116oab.5.-pod-prod-gmail; Mon, 01
 May 2023 09:55:47 -0700 (PDT)
X-Received: by 2002:a05:6871:690:b0:192:7088:8d49 with SMTP id l16-20020a056871069000b0019270888d49mr981245oao.25.1682960147612;
        Mon, 01 May 2023 09:55:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960147; cv=none;
        d=google.com; s=arc-20160816;
        b=CxM01Fb5VKo19ZURre+nWbDTYOL7FVj3VOfQadA18byaiQ52oGD+8aWPj6BB1WFdOZ
         SbRaFwqndeXe6+IT/Q1NIIVGaZzB2lQsliVrGgFpuO9aLnaRV+6TDD/wGwUFA++qHBnQ
         c8Wrjt7hEaRd93NAHA2ehCS6sGv2MoujTZh8agYb6pof/1AqP50sEZE0BaJqwQ/A0bNV
         IYvuHOexfqsJson0/BvRC4CFKBqNay55DyP2IxlTukQlVKD/t7G06+Zh3ZzdZ0Da/EdB
         IBzLCJX1Vz/ZVD0tJgW30xtHS8n3psc65WG1PeI0Glli9CoDVVL6R/QfDmiCJjkuVu+H
         YfDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=n4nztol7rM1gH9OZw6qc/mLZ9u/ayJFp51XDo0Zgdb0=;
        b=LyYxKLd+LYiRLcGKpSMh4h9o/6WQa5PDqzuVMJU4FUmxqSMakIjJiqKOwaxAIp/2ZA
         0ox7nfltptKrJhk2sb7S8DwZJ4AdezCjBey/TTQ3w6XZ6aUUfp8AKEoOlqZ867DMdZTM
         c2aANpFm9Y7gcLpY92zWB/rEIDyTxR/jJpvyjmx796DufHSJvP+bS3qWKuoR+riV9WED
         HbM6NIFAl66ipFADhvbFRd5u6veiiuUloWwZ22ed0KfAO76hbKO8TX/1Qmuu8rqFseYO
         NkrzctyMZoGD5HpqABfap15MdTyULFIoj6R507LzOKMI0c2GlXzr1K2e8FcFm6dJsDcG
         01CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=EtKwNJp9;
       spf=pass (google.com: domain of 3e-9pzaykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E-9PZAYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id gy16-20020a056870289000b0018b18eedb62si1829139oab.1.2023.05.01.09.55.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e-9pzaykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a7e65b34aso4867747276.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:47 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:bb0b:0:b0:b9a:6508:1b5f with SMTP id
 z11-20020a25bb0b000000b00b9a65081b5fmr5519617ybg.11.1682960147095; Mon, 01
 May 2023 09:55:47 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:27 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-18-surenb@google.com>
Subject: [PATCH 17/40] lib: add allocation tagging support for memory
 allocation profiling
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
 header.i=@google.com header.s=20221208 header.b=EtKwNJp9;       spf=pass
 (google.com: domain of 3e-9pzaykcvokmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E-9PZAYKCVoKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
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

Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easily
instrument memory allocators. It also registers an "alloc_tags" codetag
type with "allocations" defbugfs interface to output allocation tag
information.
CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
allocation profiling instrumentation.

Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 .../admin-guide/kernel-parameters.txt         |   2 +
 include/asm-generic/codetag.lds.h             |  14 ++
 include/asm-generic/vmlinux.lds.h             |   3 +
 include/linux/alloc_tag.h                     | 105 +++++++++++
 include/linux/sched.h                         |  24 +++
 lib/Kconfig.debug                             |  19 ++
 lib/Makefile                                  |   2 +
 lib/alloc_tag.c                               | 177 ++++++++++++++++++
 scripts/module.lds.S                          |   7 +
 9 files changed, 353 insertions(+)
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 lib/alloc_tag.c

diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
index 9e5bab29685f..2fd8e56b7af8 100644
--- a/Documentation/admin-guide/kernel-parameters.txt
+++ b/Documentation/admin-guide/kernel-parameters.txt
@@ -3770,6 +3770,8 @@
 
 	nomce		[X86-32] Disable Machine Check Exception
 
+	nomem_profiling	Disable memory allocation profiling.
+
 	nomfgpt		[X86-32] Disable Multi-Function General Purpose
 			Timer usage (for AMD Geode machines).
 
diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
new file mode 100644
index 000000000000..64f536b80380
--- /dev/null
+++ b/include/asm-generic/codetag.lds.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+#ifndef __ASM_GENERIC_CODETAG_LDS_H
+#define __ASM_GENERIC_CODETAG_LDS_H
+
+#define SECTION_WITH_BOUNDARIES(_name)	\
+	. = ALIGN(8);			\
+	__start_##_name = .;		\
+	KEEP(*(_name))			\
+	__stop_##_name = .;
+
+#define CODETAG_SECTIONS()		\
+	SECTION_WITH_BOUNDARIES(alloc_tags)
+
+#endif /* __ASM_GENERIC_CODETAG_LDS_H */
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index d1f57e4868ed..985ff045c2a2 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -50,6 +50,8 @@
  *               [__nosave_begin, __nosave_end] for the nosave data
  */
 
+#include <asm-generic/codetag.lds.h>
+
 #ifndef LOAD_OFFSET
 #define LOAD_OFFSET 0
 #endif
@@ -374,6 +376,7 @@
 	. = ALIGN(8);							\
 	BOUNDED_SECTION_BY(__dyndbg_classes, ___dyndbg_classes)		\
 	BOUNDED_SECTION_BY(__dyndbg, ___dyndbg)				\
+	CODETAG_SECTIONS()						\
 	LIKELY_PROFILE()		       				\
 	BRANCH_PROFILE()						\
 	TRACE_PRINTKS()							\
diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
new file mode 100644
index 000000000000..d913f8d9a7d8
--- /dev/null
+++ b/include/linux/alloc_tag.h
@@ -0,0 +1,105 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * allocation tagging
+ */
+#ifndef _LINUX_ALLOC_TAG_H
+#define _LINUX_ALLOC_TAG_H
+
+#include <linux/bug.h>
+#include <linux/codetag.h>
+#include <linux/container_of.h>
+#include <linux/lazy-percpu-counter.h>
+#include <linux/static_key.h>
+
+/*
+ * An instance of this structure is created in a special ELF section at every
+ * allocation callsite. At runtime, the special section is treated as
+ * an array of these. Embedded codetag utilizes codetag framework.
+ */
+struct alloc_tag {
+	struct codetag			ct;
+	struct lazy_percpu_counter	bytes_allocated;
+} __aligned(8);
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+
+static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
+{
+	return container_of(ct, struct alloc_tag, ct);
+}
+
+#define DEFINE_ALLOC_TAG(_alloc_tag, _old)				\
+	static struct alloc_tag _alloc_tag __used __aligned(8)		\
+	__section("alloc_tags") = { .ct = CODE_TAG_INIT };		\
+	struct alloc_tag * __maybe_unused _old = alloc_tag_save(&_alloc_tag)
+
+extern struct static_key_true mem_alloc_profiling_key;
+
+static inline bool mem_alloc_profiling_enabled(void)
+{
+	return static_branch_likely(&mem_alloc_profiling_key);
+}
+
+static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes,
+				   bool may_allocate)
+{
+	struct alloc_tag *tag;
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	/* The switch should be checked before this */
+	BUG_ON(!mem_alloc_profiling_enabled());
+
+	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
+#endif
+	if (!ref || !ref->ct)
+		return;
+
+	tag = ct_to_alloc_tag(ref->ct);
+
+	if (may_allocate)
+		lazy_percpu_counter_add(&tag->bytes_allocated, -bytes);
+	else
+		lazy_percpu_counter_add_noupgrade(&tag->bytes_allocated, -bytes);
+	ref->ct = NULL;
+}
+
+static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
+{
+	__alloc_tag_sub(ref, bytes, true);
+}
+
+static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes)
+{
+	__alloc_tag_sub(ref, bytes, false);
+}
+
+static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
+{
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	/* The switch should be checked before this */
+	BUG_ON(!mem_alloc_profiling_enabled());
+
+	WARN_ONCE(ref && ref->ct,
+		  "alloc_tag was not cleared (got tag for %s:%u)\n",\
+		  ref->ct->filename, ref->ct->lineno);
+
+	WARN_ONCE(!tag, "current->alloc_tag not set");
+#endif
+	if (!ref || !tag)
+		return;
+
+	ref->ct = &tag->ct;
+	lazy_percpu_counter_add(&tag->bytes_allocated, bytes);
+}
+
+#else
+
+#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
+static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
+static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
+static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
+				 size_t bytes) {}
+
+#endif
+
+#endif /* _LINUX_ALLOC_TAG_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 35e7efdea2d9..33708bf8f191 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -763,6 +763,10 @@ struct task_struct {
 	unsigned int			flags;
 	unsigned int			ptrace;
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	struct alloc_tag		*alloc_tag;
+#endif
+
 #ifdef CONFIG_SMP
 	int				on_cpu;
 	struct __call_single_node	wake_entry;
@@ -802,6 +806,7 @@ struct task_struct {
 	struct task_group		*sched_task_group;
 #endif
 
+
 #ifdef CONFIG_UCLAMP_TASK
 	/*
 	 * Clamp values requested for a scheduling entity.
@@ -2444,4 +2449,23 @@ static inline void sched_core_fork(struct task_struct *p) { }
 
 extern void sched_set_stop_task(int cpu, struct task_struct *stop);
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
+{
+	swap(current->alloc_tag, tag);
+	return tag;
+}
+
+static inline void alloc_tag_restore(struct alloc_tag *tag, struct alloc_tag *old)
+{
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	WARN(current->alloc_tag != tag, "current->alloc_tag was changed:\n");
+#endif
+	current->alloc_tag = old;
+}
+#else
+static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag) { return NULL; }
+#define alloc_tag_restore(_tag, _old)
+#endif
+
 #endif
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 5078da7d3ffb..da0a91ea6042 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -961,6 +961,25 @@ config CODE_TAGGING
 	bool
 	select KALLSYMS
 
+config MEM_ALLOC_PROFILING
+	bool "Enable memory allocation profiling"
+	default n
+	depends on DEBUG_FS
+	select CODE_TAGGING
+	select LAZY_PERCPU_COUNTER
+	help
+	  Track allocation source code and record total allocation size
+	  initiated at that code location. The mechanism can be used to track
+	  memory leaks with a low performance impact.
+
+config MEM_ALLOC_PROFILING_DEBUG
+	bool "Memory allocation profiler debugging"
+	default n
+	depends on MEM_ALLOC_PROFILING
+	help
+	  Adds warnings with helpful error messages for memory allocation
+	  profiling.
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 source "lib/Kconfig.kmsan"
diff --git a/lib/Makefile b/lib/Makefile
index 28d70ecf2976..8d09ccb4d30c 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -229,6 +229,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
 obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 
 obj-$(CONFIG_CODE_TAGGING) += codetag.o
+obj-$(CONFIG_MEM_ALLOC_PROFILING) += alloc_tag.o
+
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
 obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
new file mode 100644
index 000000000000..3c4cfeb79862
--- /dev/null
+++ b/lib/alloc_tag.c
@@ -0,0 +1,177 @@
+// SPDX-License-Identifier: GPL-2.0-only
+#include <linux/alloc_tag.h>
+#include <linux/debugfs.h>
+#include <linux/fs.h>
+#include <linux/gfp.h>
+#include <linux/module.h>
+#include <linux/seq_buf.h>
+#include <linux/uaccess.h>
+
+DEFINE_STATIC_KEY_TRUE(mem_alloc_profiling_key);
+
+/*
+ * Won't need to be exported once page allocation accounting is moved to the
+ * correct place:
+ */
+EXPORT_SYMBOL(mem_alloc_profiling_key);
+
+static int __init mem_alloc_profiling_disable(char *s)
+{
+	static_branch_disable(&mem_alloc_profiling_key);
+	return 1;
+}
+__setup("nomem_profiling", mem_alloc_profiling_disable);
+
+struct alloc_tag_file_iterator {
+	struct codetag_iterator ct_iter;
+	struct seq_buf		buf;
+	char			rawbuf[4096];
+};
+
+struct user_buf {
+	char __user		*buf;	/* destination user buffer */
+	size_t			size;	/* size of requested read */
+	ssize_t			ret;	/* bytes read so far */
+};
+
+static int flush_ubuf(struct user_buf *dst, struct seq_buf *src)
+{
+	if (src->len) {
+		size_t bytes = min_t(size_t, src->len, dst->size);
+		int err = copy_to_user(dst->buf, src->buffer, bytes);
+
+		if (err)
+			return err;
+
+		dst->ret	+= bytes;
+		dst->buf	+= bytes;
+		dst->size	-= bytes;
+		src->len	-= bytes;
+		memmove(src->buffer, src->buffer + bytes, src->len);
+	}
+
+	return 0;
+}
+
+static int allocations_file_open(struct inode *inode, struct file *file)
+{
+	struct codetag_type *cttype = inode->i_private;
+	struct alloc_tag_file_iterator *iter;
+
+	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
+	if (!iter)
+		return -ENOMEM;
+
+	codetag_lock_module_list(cttype, true);
+	iter->ct_iter = codetag_get_ct_iter(cttype);
+	codetag_lock_module_list(cttype, false);
+	seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
+	file->private_data = iter;
+
+	return 0;
+}
+
+static int allocations_file_release(struct inode *inode, struct file *file)
+{
+	struct alloc_tag_file_iterator *iter = file->private_data;
+
+	kfree(iter);
+	return 0;
+}
+
+static void alloc_tag_to_text(struct seq_buf *out, struct codetag *ct)
+{
+	struct alloc_tag *tag = ct_to_alloc_tag(ct);
+	char buf[10];
+
+	string_get_size(lazy_percpu_counter_read(&tag->bytes_allocated), 1,
+			STRING_UNITS_2, buf, sizeof(buf));
+
+	seq_buf_printf(out, "%8s ", buf);
+	codetag_to_text(out, ct);
+	seq_buf_putc(out, '\n');
+}
+
+static ssize_t allocations_file_read(struct file *file, char __user *ubuf,
+				     size_t size, loff_t *ppos)
+{
+	struct alloc_tag_file_iterator *iter = file->private_data;
+	struct user_buf	buf = { .buf = ubuf, .size = size };
+	struct codetag *ct;
+	int err = 0;
+
+	codetag_lock_module_list(iter->ct_iter.cttype, true);
+	while (1) {
+		err = flush_ubuf(&buf, &iter->buf);
+		if (err || !buf.size)
+			break;
+
+		ct = codetag_next_ct(&iter->ct_iter);
+		if (!ct)
+			break;
+
+		alloc_tag_to_text(&iter->buf, ct);
+	}
+	codetag_lock_module_list(iter->ct_iter.cttype, false);
+
+	return err ? : buf.ret;
+}
+
+static const struct file_operations allocations_file_ops = {
+	.owner	= THIS_MODULE,
+	.open	= allocations_file_open,
+	.release = allocations_file_release,
+	.read	= allocations_file_read,
+};
+
+static int __init dbgfs_init(struct codetag_type *cttype)
+{
+	struct dentry *file;
+
+	file = debugfs_create_file("allocations", 0444, NULL, cttype,
+				   &allocations_file_ops);
+
+	return IS_ERR(file) ? PTR_ERR(file) : 0;
+}
+
+static bool alloc_tag_module_unload(struct codetag_type *cttype, struct codetag_module *cmod)
+{
+	struct codetag_iterator iter = codetag_get_ct_iter(cttype);
+	bool module_unused = true;
+	struct alloc_tag *tag;
+	struct codetag *ct;
+	size_t bytes;
+
+	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
+		if (iter.cmod != cmod)
+			continue;
+
+		tag = ct_to_alloc_tag(ct);
+		bytes = lazy_percpu_counter_read(&tag->bytes_allocated);
+
+		if (!WARN(bytes, "%s:%u module %s func:%s has %zu allocated at module unload",
+			  ct->filename, ct->lineno, ct->modname, ct->function, bytes))
+			lazy_percpu_counter_exit(&tag->bytes_allocated);
+		else
+			module_unused = false;
+	}
+
+	return module_unused;
+}
+
+static int __init alloc_tag_init(void)
+{
+	struct codetag_type *cttype;
+	const struct codetag_type_desc desc = {
+		.section	= "alloc_tags",
+		.tag_size	= sizeof(struct alloc_tag),
+		.module_unload	= alloc_tag_module_unload,
+	};
+
+	cttype = codetag_register_type(&desc);
+	if (IS_ERR_OR_NULL(cttype))
+		return PTR_ERR(cttype);
+
+	return dbgfs_init(cttype);
+}
+module_init(alloc_tag_init);
diff --git a/scripts/module.lds.S b/scripts/module.lds.S
index bf5bcf2836d8..45c67a0994f3 100644
--- a/scripts/module.lds.S
+++ b/scripts/module.lds.S
@@ -9,6 +9,8 @@
 #define DISCARD_EH_FRAME	*(.eh_frame)
 #endif
 
+#include <asm-generic/codetag.lds.h>
+
 SECTIONS {
 	/DISCARD/ : {
 		*(.discard)
@@ -47,12 +49,17 @@ SECTIONS {
 	.data : {
 		*(.data .data.[0-9a-zA-Z_]*)
 		*(.data..L*)
+		CODETAG_SECTIONS()
 	}
 
 	.rodata : {
 		*(.rodata .rodata.[0-9a-zA-Z_]*)
 		*(.rodata..L*)
 	}
+#else
+	.data : {
+		CODETAG_SECTIONS()
+	}
 #endif
 }
 
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-18-surenb%40google.com.
