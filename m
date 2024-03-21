Return-Path: <kasan-dev+bncBC7OD3FKWUERBAGF6GXQMGQEYM4KWII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D8B5885DD1
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:26 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3667e9288b3sf11486645ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039105; cv=pass;
        d=google.com; s=arc-20160816;
        b=a2gLqXjPe1hxE1lyTssdRMUjBkGHykzQA7SpOceKn/GRF3AlOqR52WJvUnUHCGcf9S
         9+p6YfScvyFu1vSta3NgcPvgkiMosjDiL+PqnzWZBXE0KG8VoEx7Q5Ra7APaOwLZ3HL7
         Y5dG7ZpkD/dXvmK+NSwuXJvwqSC57IwT2rXgICS8tC4K2pfMYmnDT624WaaBKBZoPr2B
         rmGEgYG2UKG/ag8YTnAFALnweZhxm1pixojRsFpSOiJARMPcG8z7S5QnZq0JXGuLFLyu
         VoNJu9THuSsUsdn5jqhe/8dtFkJgsMSD/EhuME4mlpGDmj5A0yZWOV1dIoLr0HFzAQcH
         7wLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=EDMzV4MVVzM34mPJj9YtqkscznGLpjYF1pmv2xpilCI=;
        fh=uLEqJk9ygUsuzJTwqaKCJAl/gsGElkYqGqy4Lumsp5Y=;
        b=drGpV7YAfGAB6Oicj//X6TT0pqCWhYwYc0yzRxq/yVUDXxyVjcycuF8x/qjWv5JsEa
         OlSKQFwqORoDbWgy/dmCvjRKEMCOiuz9JjMK2B9s9mzR/9314oIYRHtiFUAscNBqJULU
         44uNXZ4iE3eU0l/rLSi7G5IRW1FCvBbrMZIkcCqw/enxE8d/3d0HKStRi5JrQist/z79
         aHfAt64FAjIfq1dfWUI6k3S/DtikcW2HPONUDZEMHpjhcK2fEqRlggVXo4ZKzKwxxWZR
         tHbC//ofsPt8U/ob7oaWbFAFScKC0ZuZJmKDyPYmt657PTO4GUh3oJLArkn9dZje8JAt
         XxAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=np9LxLgE;
       spf=pass (google.com: domain of 3f2l8zqykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3f2L8ZQYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039105; x=1711643905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EDMzV4MVVzM34mPJj9YtqkscznGLpjYF1pmv2xpilCI=;
        b=vUowB/yq0F/2roAcHE4p29r8WEn4wZ+jfas038sktX+kre9bm+B6ApCJ6sNjcLQBhp
         GtYhBYz3SuUcsBnTochwMVnyTVf+orrrmVYkHgQ3AyRiSxt+jtwGomPuaAL7lvSMglJD
         Ofg5/od78p+akBF7qaJH5Lbf/3lGkzU8QFnRz24u0OlqWfHqvG560AxaDWz3v5WhB38K
         REpVUZZMBC0f1bttsrNnCvXmY4Ol7kNx0BfRK2xUGZfe2dR1k2YHvZGxIcqmrIjiq+EH
         OPygMDwTN167PLzC7WVmy7U4oAbJa4uZlKWD0HTvc5WwoWZjbdduK55RSOpvV9ehkACj
         z5Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039105; x=1711643905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EDMzV4MVVzM34mPJj9YtqkscznGLpjYF1pmv2xpilCI=;
        b=hfduupo/RWbfbR1vl9pzKfnnsTeC6uMZYz53yve2eJgFeVNzKXJCodCRAgR16Yzebm
         b5nbONY3/156JrK8+qYjSUl1z87hkUWhkDthfvARjEoYGRHEpOMothP5yrp0ZFRmkvzU
         QJsrJMCSVrO1pF5a+pJRUK4/UCZ1VVmtKO11l1rRn9LgaTf/wBgA6kF4abAVfWiastQC
         JNFYDP8gFKHSVWb6hBSX8D4U4IrROhlvxUhiY6pmqoOIPsfQF2tRBLOuLmm9GeH5aTVq
         j3MtAt9uSVZ57wgiT3NfNkh2By8h3SCS48eFnfvfA/PrK1BgufqYCK5OROeq/IdRZXcZ
         tlmg==
X-Forwarded-Encrypted: i=2; AJvYcCVO1tznnjDQxcnQ98VUzK+gp4tjTH1JenMI9Cww6ZgLshwYr27ZLtaNNcZdWDh+UkedakbfNPWub3mo6U1pURxBEZ7tW5sIPQ==
X-Gm-Message-State: AOJu0YzHK/jtKkj8Oz/nNGkVzDHxNIhrEQcjag5htB1EgLQj1AFX6ph+
	ASGOqTU1PxwjCmNwyBEhC+r8ixlSWcrigdjhWKawbqFL6zkcxHBF
X-Google-Smtp-Source: AGHT+IEp2NzDMUMsjCST5JMeLiolsRYE4Efb4PvOdS5Obpn44QS9/7+IX1Dx223XcO25lAsiKe2XgQ==
X-Received: by 2002:a92:ce09:0:b0:366:bbb9:d624 with SMTP id b9-20020a92ce09000000b00366bbb9d624mr48379ilo.3.1711039104886;
        Thu, 21 Mar 2024 09:38:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3882:b0:366:978d:b04e with SMTP id
 cn2-20020a056e02388200b00366978db04els798490ilb.1.-pod-prod-03-us; Thu, 21
 Mar 2024 09:38:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZ7XnNQXwZMVa7s1J3SzJj9guL0mOSEGFVa24oGDDmO3CLByKxA8yWNsknStKvtHj7wY20Ggvzyozpbwl0Hy92eUFV4bs+fFgzNg==
X-Received: by 2002:a6b:cac1:0:b0:7cc:3a5:a1c5 with SMTP id a184-20020a6bcac1000000b007cc03a5a1c5mr2908442iog.5.1711039104126;
        Thu, 21 Mar 2024 09:38:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039104; cv=none;
        d=google.com; s=arc-20160816;
        b=xtdzp0RSAev6wCZtKcDTYkRLJAQq9HeV8thqa7S/LQk3owXInkR8LrowcsUsRt2Of8
         rWm+mmFsv/cqiMukIml0++ziZoG0PdjPH1RfhRHk9cbMLgSW4ezrEk09ziiW4vf31bvo
         fHa1k0kSBnfRJXyP8pR4xXYkViDI6GJAB5Io/W8alTCGzP20sIMSm2UqW9fuTAyqHEZc
         KLJHDJx96zdzaNRsv2+ptooLKh9Cjz4JNQ6bO7kJ0WoRSnBsvp4X8cstzf5obyf69sVx
         KbWb2BvSvXjKWYDnbSCI3dIXvF3E/b4gBSjG52WB+Xy9b/coaRFIq860drMwnk9IAsWk
         IMvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fkzGAdcAIO9V5Ziif/kwje70ys4aQ86/VyfgELZXTD4=;
        fh=JoKN1gGYP7Qoc/iACJe55Moyb2vyctHHrcc3drevUTY=;
        b=ffv+MOLSYHmJDYy39mtkZjy5whPd6/z+yT6TX0ep7c6FRwqC84nhQystecksDlka1V
         w9QuXtZ4wiUqSVXBBVIzomFTPc8u1zGY+DPaX3X1GhQ2j/eTjnCfOD/hMRP6yJCUnFxm
         pkPwUyHWOjew74fc99fw1BECuQ3wFEFKJQQwd+EKZQkK9NS6aYaKdOreqfG1cL/mLNc0
         izLNXruPip5anIDx0XPATiVJLSR7RxzYU9c9X8WlVaTUpyVdw3jhaLroTaGZxJCHOIFY
         Ii8R8dp66q6evzNSnDAoX+tme5O6vCoiH222NWAcQU5vt77O940dBYxzIvnQNBchLGMb
         GmDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=np9LxLgE;
       spf=pass (google.com: domain of 3f2l8zqykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3f2L8ZQYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id n17-20020a056638265100b004791bba666esi852753jat.6.2024.03.21.09.38.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f2l8zqykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dd0ae66422fso2414076276.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrtFNSfIbkXRuW3FnM5gEdN2q5EXWZv33+4WrZ0HNdeNKU8CiCaNSWa/e+rRZYnHSS/33SvWVSJ3Acrg5Q1j4pUBpD5G1B2kqEew==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a25:dbd2:0:b0:dc6:b7c2:176e with SMTP id
 g201-20020a25dbd2000000b00dc6b7c2176emr610053ybf.4.1711039103623; Thu, 21 Mar
 2024 09:38:23 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:56 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-35-surenb@google.com>
Subject: [PATCH v6 34/37] codetag: debug: mark codetags for reserved pages as empty
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
 header.i=@google.com header.s=20230601 header.b=np9LxLgE;       spf=pass
 (google.com: domain of 3f2l8zqykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3f2L8ZQYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
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

To avoid debug warnings while freeing reserved pages which were not
allocated with usual allocators, mark their codetags as empty before
freeing.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 include/linux/alloc_tag.h   |  1 +
 include/linux/mm.h          |  9 +++++++++
 include/linux/pgalloc_tag.h |  2 ++
 mm/mm_init.c                | 12 +++++++++++-
 4 files changed, 23 insertions(+), 1 deletion(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index c30e6c944353..100ddf66eb8e 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -46,6 +46,7 @@ static inline void set_codetag_empty(union codetag_ref *ref)
 #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
 static inline bool is_codetag_empty(union codetag_ref *ref) { return false; }
+static inline void set_codetag_empty(union codetag_ref *ref) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 8147b1302413..2615aa69c823 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -5,6 +5,7 @@
 #include <linux/errno.h>
 #include <linux/mmdebug.h>
 #include <linux/gfp.h>
+#include <linux/pgalloc_tag.h>
 #include <linux/bug.h>
 #include <linux/list.h>
 #include <linux/mmzone.h>
@@ -3132,6 +3133,14 @@ extern void reserve_bootmem_region(phys_addr_t start,
 /* Free the reserved page into the buddy system, so it gets managed. */
 static inline void free_reserved_page(struct page *page)
 {
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		if (ref) {
+			set_codetag_empty(ref);
+			put_page_tag_ref(ref);
+		}
+	}
 	ClearPageReserved(page);
 	init_page_count(page);
 	__free_page(page);
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index 50d212330bbb..62d8dad74b37 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -120,6 +120,8 @@ static inline void pgalloc_tag_sub_pages(struct alloc_tag *tag, unsigned int nr)
 
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
+static inline union codetag_ref *get_page_tag_ref(struct page *page) { return NULL; }
+static inline void put_page_tag_ref(union codetag_ref *ref) {}
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int nr) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int nr) {}
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 3e48afcd0faa..c7d6376a180c 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2510,7 +2510,6 @@ void *__init alloc_large_system_hash(const char *tablename,
 void __init memblock_free_pages(struct page *page, unsigned long pfn,
 							unsigned int order)
 {
-
 	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
 		int nid = early_pfn_to_nid(pfn);
 
@@ -2522,6 +2521,17 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
 		/* KMSAN will take care of these pages. */
 		return;
 	}
+
+	/* pages were reserved and not allocated */
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		if (ref) {
+			set_codetag_empty(ref);
+			put_page_tag_ref(ref);
+		}
+	}
+
 	__free_pages_core(page, order);
 }
 
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-35-surenb%40google.com.
