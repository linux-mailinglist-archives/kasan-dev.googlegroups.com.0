Return-Path: <kasan-dev+bncBC7OD3FKWUERBPNAVKXAMGQECRWFAVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B46C851FDA
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:14 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6e0df6d6530sf4222232a34.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774013; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZS1UgXfcEs7c9CQxtbdM9FBhLa/anpUpzZbLZGe6q2pKcLZ3Twb1rER4/iihdza+PW
         0+h1m1LpxavvAiTEwa5w3HZ6oAeHTlrjli8cfIvWcgPypZcvXPdjGz/Ni1pldR+dv//h
         IOGnTU/Mrx5/Nj/JdTt6hGmW2or9ui1hxygpBx8n7HMz9mvOgbgHw6zopzw/HEx8kGjn
         gqRJUggkhv05kiYLA8NYh/Fdou8o90uYvHwhltNqTMrJevpdRfsB8ajvg0RuwSF69N+R
         9C8rOrYBJeDCKyT5a3mIGfCoES8t3TRrVQE2HuGsFaeqylzZBn8e/x+FUIV+sSOGcHwd
         uPcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=lKdFebrs2z90U8ww1SFzjkOtnFOPwBGkg1Gp3wVDXkU=;
        fh=c/ppR1pVrod9VBSD5n9rWgwzUiyf1zUrh0FYX7Q1pJo=;
        b=uX4vw3blqE6YGgouFruBIwpi9BLLtgepspfho+INSY9H/w6UVSkZJ4kbw9O9oPc/KD
         65ttUppUd3irtohmQhMTeizVmFDOeW19av2LPLVyiAmGqrKZb4tUeNjK95Y7Hpf34IZV
         kOL80Ct3Xz+dowJjg8KSjO729rWykTyA+7+aIcJF9+l2ac9PnJ2MKx+ZHXTrx/O+lHwp
         nKxGt1pk2d1UxygaJEOFjb1im5gR0oo4LkiZbSwTPuD6auA3e3mFH5kjSFJU5oTaj2zx
         2NRL2j4irSGnFXcJHiT/ylNWhOahL1tOBDkaYezPSXF71lkJ4eQT8EXZeDDpRYTzySl9
         bp7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="cF5/XFT8";
       spf=pass (google.com: domain of 3pjdkzqykcbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3PJDKZQYKCbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774013; x=1708378813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lKdFebrs2z90U8ww1SFzjkOtnFOPwBGkg1Gp3wVDXkU=;
        b=AhmglOcmOlU2BOJWd5JQbYRdhZoF6LDBQlstaep2lDBrzf4mnEiYrSjVzwnrcGOf7W
         KO1F27zObx1T28IEsJQeUrWF1DHiIoCQeWiA09Jc1bZDc6ikZ6CwUXRhtDIdqLpAtZtR
         +xVjLwookz6bzWLp2pQPHKQVJFU6En04pdj2QiNLtf7jyOST7rluxiHwkGTxhkFfd03Z
         YWCeBQRxHcxOHetKiL+sUq0NsIDlozrpRBjoUlUSgFyO2niMaMt0B2wDFQIcEKioZSm6
         6FRhH6FFv315CBwn2ksmd4fy++sE7lJ8VW29MeZ0hTrHmtvZSo6GLx4KVRgQFhuho/Zj
         3j6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774013; x=1708378813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lKdFebrs2z90U8ww1SFzjkOtnFOPwBGkg1Gp3wVDXkU=;
        b=HNXPPgJT6BOA2L7eRXXPUgTUIo/w4vqqzsq06+XV5AbnNolvf0lJsythmqXnPo6Z0x
         Lw4w2ygQ+PEZ40FudqVpPlJO+O7hbbE8Jx2NwM+oNaEb527+hFu0IDJ0iNQ/twG1740u
         QVj4NivcgM3Sch8AmjzMnr9HLI63d0vENEoGM2n9KvYQpGd+L5HyKPxg3chjloj31dkl
         LXjZAxEcLWdu9BX+vsNHlDku6maOCTwGanoWtVm8Zz5nifo2jRQCSzvFtu4YsCXTJvRz
         63IEBMOsI+4XvyBrtl8Hb9wx/KxrThveE3pTYm9vQ7J/f72t/dPLweoC13qlinjxQ3Qp
         tN2A==
X-Forwarded-Encrypted: i=2; AJvYcCXTXnLmp+rMNbR8INGTP2vlNa+zc+wUSMUnyaLW/sS4YLTKbnkvrakBmBKJtot/gIp1iYRK2d4ANbsGPyrVgEJ7OnFZXhI0eg==
X-Gm-Message-State: AOJu0YwWEas04RE/cU4SUpdDb/T4u+nUud5mOAZD/gQZkHePEeTR2yEv
	grDO8bDJfigr5/FwFhqlythfIkbeGZvqZcG7KJGsmQOkUiy23T6H
X-Google-Smtp-Source: AGHT+IG+cSsclJ/rcanpJvWyMBfy6Bptxxg8BpiIa08NOcDXVkwWT7xRGjp1mXoSjURUwNBCgAUsuw==
X-Received: by 2002:a9d:76c5:0:b0:6e2:c2ce:6278 with SMTP id p5-20020a9d76c5000000b006e2c2ce6278mr7765552otl.11.1707774013389;
        Mon, 12 Feb 2024 13:40:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:400e:b0:68c:bb4e:b92c with SMTP id
 kd14-20020a056214400e00b0068cbb4eb92cls865588qvb.0.-pod-prod-08-us; Mon, 12
 Feb 2024 13:40:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVoJMb2hCKoUoRP0Ui/WsOOt5dbxKuGbB2YizGEjQN4YjNiYQHjjjCQWK0xfuIYUaveApoiphwX+1ryvWdOaMRhvAYb4Qe3BXFG7w==
X-Received: by 2002:a1f:e082:0:b0:4c0:309b:2755 with SMTP id x124-20020a1fe082000000b004c0309b2755mr3366543vkg.3.1707774012578;
        Mon, 12 Feb 2024 13:40:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774012; cv=none;
        d=google.com; s=arc-20160816;
        b=nLRlUEYtWtQD03NDLZTgYvlHo35jwseBZUFQs1VLzIkvE+B//x0sta91u97SU4gvyT
         OPYpkCNQ/JmS5uY3U9JyCGckNivc9K4xsC78dtVDlvQFoJi926BDlmurZdshm7QvCNlr
         gXjKuMozi1SXLpr0qlXDrEC0kCx/lNOi8HLl6UQXQ6SHnTpBw6Vm2EFWnSG5H10EMLbG
         BbbgeAe4EQI9YFICG7lFWjMm32a8s7dwhJB0+ns9zX8PSDJ3nm1jQUM/JLdzY8REL6/s
         ne2eFAWJqnQeX4hC3a9ssLcTToQfCz95HKf7Yq+iofYAAIia6w1wEe00XCXaYLdjoil3
         FaaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZrBz9DyywfwO606ZQMwpTbc2aylPEGoXqCQTswmuPUY=;
        fh=kS4xtbUcURf9KIx6P/bNs4+p35GKb5dHBJ3PcAwdGAw=;
        b=DLTGnebTQCL/g7HEaOCpC3X9xGNtmZlCKAWaIzVhV5n9edf1HjTmOUQ5kxA73fH3pi
         E00gE2QZJ3Ucfy+8qy6oFqZCZoGdYrflkIU/pl40yw2UHt4YYzYGFhdg9z3M249R7+vm
         eSAcsz/lsGmTtqEhjphhE+Cp3/ILXizESJib7VhyxU/ox69+oGK0CiqAyX38Cg8xnvPt
         t1s+6Bm+3gOOYvvD2IRrGeKuwGNHOw2j+lK8HPrV87LSzo0LeDwriVSftgaKG5OoloaU
         MGeOZibwFIsZEC8PmJCPh1OLEP+OqXOPwyORB13r6OImJWBLrbd/8QefJTbZcQiVI8yP
         v6mg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="cF5/XFT8";
       spf=pass (google.com: domain of 3pjdkzqykcbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3PJDKZQYKCbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXUAovfRiaLlkl++nf6Gj96nCOKi/dSBEF4i432614+ykjZELeygOsWmZw4uJiYw4JvoYGJGWotjHk4zvqkdMK9aBkNpnTenNnaFg==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id cl25-20020a056122251900b004c027d19fd3si665120vkb.5.2024.02.12.13.40.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pjdkzqykcbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc6b5d1899eso6231712276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXl3E8mz0y3P9B9cqeAv9sTbhxtUj5JNTU4WSLLQFES5n4X44jPldARYhNlZWDF2mpFWp+KQ6hpGgrBV/PMjXSQuch0FFd09xTIeQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a25:ad02:0:b0:dcc:2267:796e with SMTP id
 y2-20020a25ad02000000b00dcc2267796emr133364ybi.2.1707774012029; Mon, 12 Feb
 2024 13:40:12 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:04 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-19-surenb@google.com>
Subject: [PATCH v3 18/35] mm: create new codetag references during page splitting
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
 header.i=@google.com header.s=20230601 header.b="cF5/XFT8";       spf=pass
 (google.com: domain of 3pjdkzqykcbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3PJDKZQYKCbstvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com;
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
index a060c26eb449..0174aff5e871 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -62,11 +62,41 @@ static inline void pgalloc_tag_sub(struct page *page, unsigned int order)
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
 
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
diff --git a/mm/huge_memory.c b/mm/huge_memory.c
index 94c958f7ebb5..86daae671319 100644
--- a/mm/huge_memory.c
+++ b/mm/huge_memory.c
@@ -38,6 +38,7 @@
 #include <linux/sched/sysctl.h>
 #include <linux/memory-tiers.h>
 #include <linux/compat.h>
+#include <linux/pgalloc_tag.h>
 
 #include <asm/tlb.h>
 #include <asm/pgalloc.h>
@@ -2899,6 +2900,7 @@ static void __split_huge_page(struct page *page, struct list_head *list,
 	/* Caller disabled irqs, so they are still disabled here */
 
 	split_page_owner(head, nr);
+	pgalloc_tag_split(head, nr);
 
 	/* See comment in __split_huge_page_tail() */
 	if (PageAnon(head)) {
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 58c0e8b948a4..4bc5b4720fee 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2621,6 +2621,7 @@ void split_page(struct page *page, unsigned int order)
 	for (i = 1; i < (1 << order); i++)
 		set_page_refcounted(page + i);
 	split_page_owner(page, 1 << order);
+	pgalloc_tag_split(page, 1 << order);
 	split_page_memcg(page, 1 << order);
 }
 EXPORT_SYMBOL_GPL(split_page);
@@ -4806,6 +4807,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 		struct page *last = page + nr;
 
 		split_page_owner(page, 1 << order);
+		pgalloc_tag_split(page, 1 << order);
 		split_page_memcg(page, 1 << order);
 		while (page < --last)
 			set_page_refcounted(last);
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-19-surenb%40google.com.
