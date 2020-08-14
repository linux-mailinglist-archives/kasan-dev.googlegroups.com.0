Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRMT3P4QKGQEDSJZQVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C14244DDB
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:38 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id e12sf3602903wra.13
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426118; cv=pass;
        d=google.com; s=arc-20160816;
        b=D8OFaaODDAjvZdh7I3GQJZKNPgHKW3aXcuzYY8dMnLoII5/FQz0ZlAohhTBcEQadBI
         SbL2k3qJn2rJi+ptMmZJX6rtm9PJ2F4qdfO5yQMoFNn26HkYd+v42y/H/ObV4CToj3PV
         741OppiQTbt0NdZUt3dT+6v8UM8PbZj0Lgu+NgzENv8mNb2DBE6XPxuJwjBwDpwQzXE9
         VV7pJXlLcCigyvwequIsUXseeQDpxKezv3aK5ckKpGbyg7kbJIubUtn8EuqMmbUMzJcB
         bc+wse9hzKCXf+lVRJ2TMngbIyhHTVL0OVwCezVVOH83Tev4JapLq8xJFKbSfiCqS2rp
         YRhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=105mhFOZX+aCNKtdQpvwJGQlUTyoZd/7o6YgGUBJFwg=;
        b=t6eHYPUWKMDI+5OLuLzVblweXw9rwxtATbiEIAJG1uMTM2yKfApcZhVX+ra6pCRrPk
         qbYxKfhCEIRE8o/D2lPWNqq67z/Fq5WDn+H/T+Ybsy0FixQqHEpfyPJfHtodTs3SpQM6
         Z9G3k73kN1KZkAT4MrsMhqmgG6OW/+d4/b0su6AUQuxLAIlBbv68ZS2ok32b+SAY7ODE
         qhp+1gXbNLEZWszFN4sIkb9ouG0qxccn74TFSOHScu6pJJsHukyfJwFYSYMPne4kcCsb
         hL59rectT3d/8iKmidrP5q0JsxD1II67dwIi7FJezIXQjeJOLN9QaEgC4Kfhd1xN6Zp1
         tFzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="TwBLRF/r";
       spf=pass (google.com: domain of 3xck2xwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xck2XwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=105mhFOZX+aCNKtdQpvwJGQlUTyoZd/7o6YgGUBJFwg=;
        b=jcGZ/7NCLMJlgCYJmGWQbLv4sg99dXk2PhBRyG/GNSln391c8K2DTIkJvv25ILsOzM
         SOa6tA9s8OU47FRMoh1zLOVfWcJXdc/3dn2lc2Fk1neyZGCoqcIWBw4PBuI0LeZwci/r
         EbAAaeMWpuq+2ZvQYRthmQ+t5zqghvSAjD7An9xzc3OEs23B3NGp7zSm5h5k4mzri1sa
         pgRz//wpOn5Ve5HALaquB9nNwYC6OTUzlChnObbYLkLlKGNGEHocwAqeHFbVpTIF/mlo
         XUxX1NXsM0dFDq0Z3+atVt8rF5NTFcXmZ9vR6WP+o5tg2onpIlbSnhgptmfZk7CizXCF
         n7qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=105mhFOZX+aCNKtdQpvwJGQlUTyoZd/7o6YgGUBJFwg=;
        b=RNe34eooDqQSW8Z6o267OISwmurbMM2ZDcit3yiiep6s+lwI2xp/L3D+2Wl1oFJAfe
         rsGfw4/w1YrSdA5bok/xQEPWlvoj7OJ7M93NZLzZ4Pj3jGhQ6iHG16XpsQNpR7QuE0B/
         bvn7kUpdMaC0j0xSHiA/LzqxEkdqnYWWqj/jsCUNTiewSwkE8CRdkG+0aP2zu8mhSBv5
         +lH32sPgBrI3T29JgLhTpgoDmp/bMlrnQ7kTjPEq0BVoxhf83BQBCRBI8PoNsJRs+/Ne
         B9yU3yZXXXOKbPDHTXX6Z7iZY+1zrj48qSZXaY2NPFIfaOUHGbKo1XYrmAYHWVjo5I3M
         PXeg==
X-Gm-Message-State: AOAM530yHcBMONnkt7Wh45PHqP29Sd/l7es06zHXKeVCAzLqk8yGogCN
	69cTEvVENKxQiMfz5lGOnSA=
X-Google-Smtp-Source: ABdhPJzHDiMfFqYScEiMoveCXQVRbBTlTpaGDpG4I9DauvJZctLp5qA+BiOrcnj5kk9R8lyihegUWw==
X-Received: by 2002:adf:edc3:: with SMTP id v3mr3587803wro.193.1597426117886;
        Fri, 14 Aug 2020 10:28:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:b787:: with SMTP id h129ls4468354wmf.3.canary-gmail;
 Fri, 14 Aug 2020 10:28:37 -0700 (PDT)
X-Received: by 2002:a7b:c056:: with SMTP id u22mr3448793wmc.188.1597426117387;
        Fri, 14 Aug 2020 10:28:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426117; cv=none;
        d=google.com; s=arc-20160816;
        b=F/aKQaw8TmFuZVRafFlhWE0W0ZcGZp8lY8rDh2g8pSLypYKXK0vJ5oTJjqbyddv37U
         dgjIqo6lCoYet+b9O30HawgHJ13WxZRMIIXXHflbHBpZn4xbVtkH6WL316jeFuWyqazi
         1rhZQ/dXVc/MUObwdzbJVst8lGXFLai1F7b3IQ5Oyw9dZnn+bbgMYKgBdqJGPFdibANU
         79imKO0JTPSSimoD/9CFhtpw34DQhRZLqgcP8s99YkaBcn2ToKGV2ULEy7r6bJNb0nTT
         2El5wMGckqTXYzIBZuPju3SCPIaGkSCqoMaosnkkvH52iil0l9ZdDgQJ8r19NHAZ6d0+
         K3WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=zw6ofl64XJvLyRlNnYu73LFjRJ5KYIbvH8mlto9sbqM=;
        b=mdk6YcPqZ8In2zQsS1xkb6Kpv7jZjKZaWHK95SMv5czam/YdEbO/Utw6h1RgHpuTq2
         BAMc49SRgGS41cfySFtifBEdB2Qxm7lySFsceeMsN5meI0lvo/OWiI93Qu678eWVlkEy
         HK0jA5mr/iI9kRnr2eFsRB6cUym/m+tJFvEiFNnulEFdDUAwhRARZP1AV1kudK2j4z64
         GoGNr/t8Hmf1FWwjHqq2UOfugm3J/RJxZE8Ld6Q5fQUwqIZTMqhZHyBsWfvuwwTMhWyT
         1wJktXHA02iagsVWPpv6pEVqrFYY7lULp1n/bHKKMUqPL73QvWNxKQ8JdQcUVa/qr1AD
         O9wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="TwBLRF/r";
       spf=pass (google.com: domain of 3xck2xwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xck2XwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f134si833086wme.4.2020.08.14.10.28.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xck2xwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id b13so3605472wrq.19
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:37 -0700 (PDT)
X-Received: by 2002:adf:97d3:: with SMTP id t19mr3454793wrb.138.1597426117123;
 Fri, 14 Aug 2020 10:28:37 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:13 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <4e86d422f930831666137e06a71dff4a7a16a5cd.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 31/35] kasan, arm64: implement HW_TAGS runtime
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="TwBLRF/r";       spf=pass
 (google.com: domain of 3xck2xwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xck2XwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Provide implementation of KASAN functions required for the hardware
tag-based mode. Those include core functions for memory and pointer
tagging (mte.c) and bug reporting (report_mte.c). Also adapt common
KASAN code to support the new mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/memory.h   |  4 +-
 arch/arm64/kernel/setup.c         |  1 -
 include/linux/kasan.h             |  6 +--
 include/linux/mm.h                |  2 +-
 include/linux/page-flags-layout.h |  2 +-
 mm/kasan/Makefile                 |  5 ++
 mm/kasan/common.c                 | 14 +++---
 mm/kasan/kasan.h                  | 17 +++++--
 mm/kasan/mte.c                    | 76 +++++++++++++++++++++++++++++++
 mm/kasan/report_mte.c             | 47 +++++++++++++++++++
 mm/kasan/shadow.c                 |  2 +-
 11 files changed, 158 insertions(+), 18 deletions(-)
 create mode 100644 mm/kasan/mte.c
 create mode 100644 mm/kasan/report_mte.c

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 8881849929e3..433341acf3f3 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -214,7 +214,7 @@ static inline unsigned long kaslr_offset(void)
 	(__force __typeof__(addr))__addr;				\
 })
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 #define __tag_shifted(tag)	((u64)(tag) << 56)
 #define __tag_reset(addr)	__untagged_addr(addr)
 #define __tag_get(addr)		(__u8)((u64)(addr) >> 56)
@@ -222,7 +222,7 @@ static inline unsigned long kaslr_offset(void)
 #define __tag_shifted(tag)	0UL
 #define __tag_reset(addr)	(addr)
 #define __tag_get(addr)		0
-#endif /* CONFIG_KASAN_SW_TAGS */
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline const void *__tag_set(const void *addr, u8 tag)
 {
diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index 575da075a2b9..4bee6e70eef4 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -352,7 +352,6 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
 	smp_init_cpus();
 	smp_build_mpidr_hash();
 
-	/* Init percpu seeds for random tags after cpus are set up. */
 	kasan_init_tags();
 
 #ifdef CONFIG_ARM64_SW_TTBR0_PAN
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 875bbcedd994..613c9d38eee5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -184,7 +184,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 void kasan_init_tags(void);
 
@@ -193,7 +193,7 @@ void *kasan_reset_tag(const void *addr);
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
-#else /* CONFIG_KASAN_SW_TAGS */
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void kasan_init_tags(void) { }
 
@@ -202,7 +202,7 @@ static inline void *kasan_reset_tag(const void *addr)
 	return (void *)addr;
 }
 
-#endif /* CONFIG_KASAN_SW_TAGS */
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
 
 #ifdef CONFIG_KASAN_VMALLOC
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 65cbbfaa739b..94581f82c1b3 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1395,7 +1395,7 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
 }
 #endif /* CONFIG_NUMA_BALANCING */
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 static inline u8 page_kasan_tag(const struct page *page)
 {
 	return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
index 71283739ffd2..75945732a58b 100644
--- a/include/linux/page-flags-layout.h
+++ b/include/linux/page-flags-layout.h
@@ -77,7 +77,7 @@
 #define LAST_CPUPID_SHIFT 0
 #endif
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 #define KASAN_TAG_WIDTH 8
 #else
 #define KASAN_TAG_WIDTH 0
diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 007c824f6f43..182095c6af28 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -10,9 +10,11 @@ CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report_mte.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_mte.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
@@ -27,10 +29,13 @@ CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report_mte.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_mte.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
 obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_tags.o shadow.o tags.o
+obj-$(CONFIG_KASAN_HW_TAGS) += mte.o report_mte.o
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 41c7f1105eaa..412a23d1546b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -118,7 +118,7 @@ void kasan_free_pages(struct page *page, unsigned int order)
  */
 static inline unsigned int optimal_redzone(unsigned int object_size)
 {
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0;
 
 	return
@@ -183,14 +183,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
 struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 					const void *object)
 {
-	return (void *)object + cache->kasan_info.alloc_meta_offset;
+	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
 }
 
 struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 				      const void *object)
 {
 	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
-	return (void *)object + cache->kasan_info.free_meta_offset;
+	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
 void kasan_poison_slab(struct page *page)
@@ -272,7 +272,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	alloc_info = get_alloc_info(cache, object);
 	__memset(alloc_info, 0, sizeof(*alloc_info));
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
+			IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		object = set_tag(object,
 				assign_tag(cache, object, true, false));
 
@@ -342,10 +343,11 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
+			IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
 
-	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
+	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	kasan_unpoison_memory(set_tag(object, tag), size);
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4d8e229f8e01..bc56cf8b9c48 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -152,6 +152,10 @@ struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 					const void *object);
 
+void kasan_poison_memory(const void *address, size_t size, u8 value);
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
 	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
@@ -163,8 +167,6 @@ static inline bool addr_has_metadata(const void *addr)
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
 
-void kasan_poison_memory(const void *address, size_t size, u8 value);
-
 /**
  * check_memory_region - Check memory region, and report if invalid access.
  * @addr: the accessed address
@@ -176,6 +178,15 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline bool addr_has_metadata(const void *addr)
+{
+	return true;
+}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
 bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
@@ -212,7 +223,7 @@ static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 void print_tags(u8 addr_tag, const void *addr);
 
diff --git a/mm/kasan/mte.c b/mm/kasan/mte.c
new file mode 100644
index 000000000000..43b7d74161e5
--- /dev/null
+++ b/mm/kasan/mte.c
@@ -0,0 +1,76 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains hardware tag-based (MTE-based) KASAN code.
+ *
+ * Copyright (c) 2020 Google, Inc.
+ * Author: Andrey Konovalov <andreyknvl@google.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ *
+ */
+
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memory.h>
+#include <linux/mm.h>
+#include <linux/string.h>
+#include <linux/types.h>
+
+#include "kasan.h"
+
+void kasan_init_tags(void)
+{
+	mte_init_tags(KASAN_TAG_MAX);
+}
+
+void *kasan_reset_tag(const void *addr)
+{
+	return reset_tag(addr);
+}
+
+void kasan_poison_memory(const void *address, size_t size, u8 value)
+{
+	mte_set_mem_tag_range(reset_tag(address), size, value);
+}
+
+void kasan_unpoison_memory(const void *address, size_t size)
+{
+	mte_set_mem_tag_range(reset_tag(address), size, get_tag(address));
+}
+
+u8 random_tag(void)
+{
+	return mte_get_random_tag();
+}
+
+bool check_invalid_free(void *addr)
+{
+	u8 ptr_tag = get_tag(addr);
+	u8 mem_tag = mte_get_mem_tag(addr);
+
+	if (mem_tag == KASAN_TAG_INVALID)
+		return true;
+	if (ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag)
+		return true;
+	return false;
+}
+
+void kasan_set_free_info(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = get_alloc_info(cache, object);
+	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = get_alloc_info(cache, object);
+	return &alloc_meta->free_track[0];
+}
diff --git a/mm/kasan/report_mte.c b/mm/kasan/report_mte.c
new file mode 100644
index 000000000000..dbbf3aaa8798
--- /dev/null
+++ b/mm/kasan/report_mte.c
@@ -0,0 +1,47 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains Hardware Tag-Based (MTE-based) KASAN code.
+ *
+ * Copyright (c) 2020 Google, Inc.
+ * Author: Andrey Konovalov <andreyknvl@google.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ *
+ */
+
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memory.h>
+#include <linux/mm.h>
+#include <linux/string.h>
+#include <linux/types.h>
+
+#include "kasan.h"
+
+const char *get_bug_type(struct kasan_access_info *info)
+{
+	return "invalid-access";
+}
+
+void *find_first_bad_addr(void *addr, size_t size)
+{
+	return reset_tag(addr);
+}
+
+void metadata_fetch_row(char *buffer, void *row)
+{
+	int i;
+
+	for (i = 0; i < META_BYTES_PER_ROW; i++)
+		buffer[i] = mte_get_mem_tag(row + i * KASAN_GRANULE_SIZE);
+}
+
+void print_tags(u8 addr_tag, const void *addr)
+{
+	u8 memory_tag = mte_get_mem_tag((void *)addr);
+
+	pr_err("Pointer tag: [%02x], memory tag: [%02x]\n",
+		addr_tag, memory_tag);
+}
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 4888084ecdfc..ca69726adf8f 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -111,7 +111,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
 
 		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 			*shadow = tag;
-		else
+		else /* CONFIG_KASAN_GENERIC */
 			*shadow = size & KASAN_GRANULE_MASK;
 	}
 }
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e86d422f930831666137e06a71dff4a7a16a5cd.1597425745.git.andreyknvl%40google.com.
