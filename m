Return-Path: <kasan-dev+bncBC7OD3FKWUERBH66X6RAMGQE5OPEOSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BF996F33DF
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:00 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-61a9903f6e5sf8965976d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960159; cv=pass;
        d=google.com; s=arc-20160816;
        b=WUTJEB4b/IpZA7MEFhUKgYXZjvKo9lNY2+2P399SSjMWqhJEMVKa0TQQ9SMtiUME0p
         wJd66i+Ps0LlyREv9ZbFCqfG7tj1QG8hG6Kgp44F6L+nByi4TjfebsxJ/+0dUgHR4dr3
         4gov9WNPw0PbG0a+qfbgekSfA8EXk6AxcL6L9+E9uEm8vaqSwiOzyinCJtCBNMhPkssE
         c8arWpMBQ64qiZ50+KnJHhwXa142D2pxzUtQ1D+1rHlHFnS8cnqoDKhJszO8/lzxxq2X
         QUE8PRg3NBcU2G+TCqBFcbR+ACKJdKCXUK6p/Riyfpn29kG+tNi8FvIYNUARKGh8BYhn
         DP2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=FNMlVUMz7LBB3y9vokcB1Ek9UHxH9A0drnC0glnhv+g=;
        b=xOY8GK4kZVgGehotkoXL1HohlKwIrcXMvRwdDkyQAyMy04hc6kcvm4F885Y9DR695i
         RP6lselxLfh1fjsSY004J/+JIhVwmMSPXmu/M54sLtpeQ7bshfG5brSVXjAOEVmiHP/a
         qqNgkN2jmCZvjTjOTqmw5mjqYa33TT/BDA5OKCJLkvCu8mA1gmGdmG1Zgz9zcCZa6Ico
         8Yr58kta8JHd3tLtbofqCFZoMpKoG2KyDY5/CK77pRbnoNYum38XBwXlLwazMZsIf9Kv
         XlW0tHaOogp14w8lMpZVptC9VzZ5Cbda8rjZUlyTHLRSIdH7dQbNrTf8MARdBgzu3MTU
         ZzHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="7gQ7i/dA";
       spf=pass (google.com: domain of 3hu9pzaykcwuvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Hu9PZAYKCWUVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960159; x=1685552159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FNMlVUMz7LBB3y9vokcB1Ek9UHxH9A0drnC0glnhv+g=;
        b=fLNQ17WnKhr1qIVCYyrz/64YTUWz3wbHg+fElCuSuwIw/WFUA1nV01O9/XE/A6YGrc
         kCGNYh9EOKLad0yTKKC2Z9/WzMWtPUFL7/2D1tmUCWqKdiWTlNy7g61oMCXloGOiSYuV
         jWYhfvmICw0i0qTYlT/yfR8nzUBmM8HvrxKhsCpt3IKPyLueN/9v/sqzGYw4xx7CPUqT
         4t76deEUCWByo2R/WDAejqmTmEwVINJthnDzMZjTaILTCiqmthlv7NGauU849Z7DdzAq
         wJfUsAi768c4fuQHAARQCEEuPhStMW5HiqJTDKomy+u3Of3ki24VIg0EU5HuArk/Fk84
         uwFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960159; x=1685552159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FNMlVUMz7LBB3y9vokcB1Ek9UHxH9A0drnC0glnhv+g=;
        b=G0xMePngxRNBY+FTJlK7yoKCIz9d0i1jVxCvRZSaJnlwkUj/6nD9DlZw8z7kUWoiji
         tXeYllTvtqoLQEDeSplbAn6ss8EMtuD3nz9Tap2pu/Wsl/OAVW/Fjyv6wH2APpa3kuhR
         Hf2uZAUrEHGW2E8f+PlGf1CyLFu/2l1CXySzZpZhZkVOEOjy9fzt+RUzJslLuFpNfHkL
         oqmdSr0Lge+vuEp9QwquE+K/E+c26Qc/3tuYGY/ftQn6NN+gGDW4P3MhpWNwasYEZ5Ac
         jbZHEyCdwipmWnuHNmImotDUUt4dLp6GKHq0dhAeqnB2Lf+d7cORDwnH6Z6N/+ajRiWa
         ucLA==
X-Gm-Message-State: AC+VfDwUo7SHobkiH+ORJol+/TucaAszOpc1uj1oQr9yug3I/WTln+Iq
	04ccTTqlQ5Pk7SrXvEfnLb0=
X-Google-Smtp-Source: ACHHUZ60st29rKDE+q19pdDET/jLP16SgT7lWqqVIB8Am8IS6XPWgq4lGesp08YmphwmWQ7UdsVCRQ==
X-Received: by 2002:ad4:57ad:0:b0:5ef:512f:ffe1 with SMTP id g13-20020ad457ad000000b005ef512fffe1mr94156qvx.1.1682960159378;
        Mon, 01 May 2023 09:55:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ff21:0:b0:56b:f6be:9a8b with SMTP id x1-20020a0cff21000000b0056bf6be9a8bls7428513qvt.2.-pod-prod-gmail;
 Mon, 01 May 2023 09:55:58 -0700 (PDT)
X-Received: by 2002:a05:6214:21aa:b0:619:90cd:4a99 with SMTP id t10-20020a05621421aa00b0061990cd4a99mr719951qvc.3.1682960158894;
        Mon, 01 May 2023 09:55:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960158; cv=none;
        d=google.com; s=arc-20160816;
        b=j6KqJHL3Cuz+FBQT8WLTxkFI2jvHGOm6+PbnFc+PlROjQX5FrueE+4Eq/q3XDp2riM
         aJY2EBhz6T+TsDQLDt2w15tSQ/WWT6byXNiYSqdrRDo28illuKZ4MBQxs+JCS69f7TpO
         rWvHbzls9J5jC2ahXL4rQVDjpjy4zU4rJ4fsDp1dKISaY4kDkHFC7LTZBW44TlyeA5Wq
         3R/GECqSelRKK8MT3e1R7I2U3R6SRfvrnNpZtvHfjAFZevDylN2R5w6Ee2jGZGIIoz1V
         EGYqc18SKmLRb6ni9EG8UDZ3vjkHWReUAi/Ktt6x47mygZSnU3aNpFuZ6DkyDMN5hFmU
         sdVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+1Ptlsu3HrvWcynZoOK0ZqIIaOTUmOtwKZY5J1VaLvs=;
        b=UOmFxEEMIxOCaB+Es0/imqxwPSSGdf6gqeMBy+3RP8AnpHsDfCFvD1BnqomSHzlnIi
         EXWIAFjqIXUw5LMKo8D8qvyMXxXulEH2SaVKuAX53/geh2MexmKDklWwy2HP36NPWZ9a
         rIowMqRHt2I/5F0eB2CGvsZA9mubvUqP282196kdTAzgPZ72YAJq5nN0z9acIaMcSy7u
         wl3/JCp4mSOcI0NIHrfZ4/7i/8aigObcW5LrCqeBXxvugWdwS03LfPJn6rmduhvW9Ezi
         niyEWnzTfbiU2uQVxYQWQK/W6jGPPUQotn9FdwEfLsam+bGBRpQsvIytCdEgx6rH5ZPL
         dORQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="7gQ7i/dA";
       spf=pass (google.com: domain of 3hu9pzaykcwuvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Hu9PZAYKCWUVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id oo9-20020a056214450900b00619eb7752desi321515qvb.0.2023.05.01.09.55.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hu9pzaykcwuvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b96ee51ee20so3263414276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:58 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a05:6902:1028:b0:b8c:607:7669 with SMTP id
 x8-20020a056902102800b00b8c06077669mr8930549ybt.5.1682960158430; Mon, 01 May
 2023 09:55:58 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:32 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-23-surenb@google.com>
Subject: [PATCH 22/40] mm: create new codetag references during page splitting
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
 header.i=@google.com header.s=20221208 header.b="7gQ7i/dA";       spf=pass
 (google.com: domain of 3hu9pzaykcwuvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Hu9PZAYKCWUVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
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

When a high-order page is split into smaller ones, each newly split
page should get its codetag. The original codetag is reused for these
pages but it's recorded as 0-byte allocation because original codetag
already accounts for the original high-order allocated page.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/pgalloc_tag.h | 30 ++++++++++++++++++++++++++++++
 mm/huge_memory.c            |  2 ++
 mm/page_alloc.c             |  2 ++
 3 files changed, 34 insertions(+)

diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index 567327c1c46f..0cbba13869b5 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -52,11 +52,41 @@ static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
 	}
 }
 
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
+{
+	int i;
+	struct page_ext *page_ext;
+	union codetag_ref *ref;
+	struct alloc_tag *tag;
+
+	if (!mem_alloc_profiling_enabled())
+		return;
+
+	page_ext = page_ext_get(page);
+	if (unlikely(!page_ext))
+		return;
+
+	ref = codetag_ref_from_page_ext(page_ext);
+	if (!ref->ct)
+		goto out;
+
+	tag = ct_to_alloc_tag(ref->ct);
+	page_ext = page_ext_next(page_ext);
+	for (i = 1; i < nr; i++) {
+		/* New reference with 0 bytes accounted */
+		alloc_tag_add(codetag_ref_from_page_ext(page_ext), tag, 0);
+		page_ext = page_ext_next(page_ext);
+	}
+out:
+	page_ext_put(page_ext);
+}
+
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
 static inline union codetag_ref *get_page_tag_ref(struct page *page) { return NULL; }
 static inline void put_page_tag_ref(union codetag_ref *ref) {}
 #define pgalloc_tag_dec(__page, __size)		do {} while (0)
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
diff --git a/mm/huge_memory.c b/mm/huge_memory.c
index 624671aaa60d..221cce0052a2 100644
--- a/mm/huge_memory.c
+++ b/mm/huge_memory.c
@@ -37,6 +37,7 @@
 #include <linux/page_owner.h>
 #include <linux/sched/sysctl.h>
 #include <linux/memory-tiers.h>
+#include <linux/pgalloc_tag.h>
 
 #include <asm/tlb.h>
 #include <asm/pgalloc.h>
@@ -2557,6 +2558,7 @@ static void __split_huge_page(struct page *page, struct list_head *list,
 	/* Caller disabled irqs, so they are still disabled here */
 
 	split_page_owner(head, nr);
+	pgalloc_tag_split(head, nr);
 
 	/* See comment in __split_huge_page_tail() */
 	if (PageAnon(head)) {
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index edd35500f7f6..8cf5a835af7f 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2796,6 +2796,7 @@ void split_page(struct page *page, unsigned int order)
 	for (i = 1; i < (1 << order); i++)
 		set_page_refcounted(page + i);
 	split_page_owner(page, 1 << order);
+	pgalloc_tag_split(page, 1 << order);
 	split_page_memcg(page, 1 << order);
 }
 EXPORT_SYMBOL_GPL(split_page);
@@ -5012,6 +5013,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 		struct page *last = page + nr;
 
 		split_page_owner(page, 1 << order);
+		pgalloc_tag_split(page, 1 << order);
 		split_page_memcg(page, 1 << order);
 		while (page < --last)
 			set_page_refcounted(last);
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-23-surenb%40google.com.
