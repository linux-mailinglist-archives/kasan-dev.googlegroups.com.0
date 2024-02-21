Return-Path: <kasan-dev+bncBC7OD3FKWUERBE5E3GXAMGQEKDAZQ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id CF44385E79E
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:42:12 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1dc0e27ea7dsf147665ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:42:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544531; cv=pass;
        d=google.com; s=arc-20160816;
        b=0quiqenvOsrM8FZuoR3F0BbuVxAoGwH29KDaE+yPh2E/hlAVi82HtpDdmhRha+fJMD
         H8G73uatP/I5SdszBxG3/A2l7MDebg7iZHzNrsopwMc1hNk091+Pn+xn4I8PxrjnxjUH
         cXXzkZ1+NlxJ9pRAz3RFoJ8/0VCQsiEG5cCYIqKxkeZbXCvWBFbZttGxJpQqHZ5T/8Wi
         bm12k3T05sjNAzYm3E1ZBMakU5izGck09CBcFqmhS8NwqEduBxvlMzEeF7SCswduNMSV
         gFIFsJqyrpTaZW1DZyQgs/ycRuI9WkCkMJzRT9joqtkM9HXrZoai1TAZ1TOtoHgKDR8J
         E7hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=wWcL1QbO5PT8XW0kSOL5JXX6UNTVmBSW6LwoW9iT+X4=;
        fh=sWZyLxC4VWiklSWmwUsJWgOIJ8bgMcLzMPZY4Bg2h0s=;
        b=LSDCB/MzZs1YVBKBKNErAHsH/HS+qQrSgbsGhrrruaXzjWr1Wbs4T7iStb6iErgFUp
         4PRgzoo+0DOR7VSRouwE0fW1QQ0hGoCWYSwfo6P4jMSb3iegPheD7w7Vf+P3wVb0ES65
         6VRWQMmH9QD/MDcA3u19asQTEmJ0HG01vx6tQkg5mNEYjltryoJ3pih8zna4MHfUqsef
         IB9w4cXQabYK/QRlXOov1DOR0Rz68gUSnpjowam96Lu6FZ2iQMZY3rjf3fR3oBzBh4wl
         bNXjPq+CTYFBZH34scVC4riv3ERXFyncjWm6vVJzy2qhkbMFOivL+FIqhhOehilhpWJL
         zEDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ASHYzf6b;
       spf=pass (google.com: domain of 3evlwzqykcuqy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EVLWZQYKCUQy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544531; x=1709149331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wWcL1QbO5PT8XW0kSOL5JXX6UNTVmBSW6LwoW9iT+X4=;
        b=jVuNqXp56O8VqzKZnM9G6ayGNSdkr5IL/+NqNzkafOynE0XOnOJfIoO8NEjPiyfdXS
         8mmE+RxNq5BvHcrDM4b3WqL0JZjmtpoVntpk5Xhnegh2UiBFCD+BWQOXlxmmM4RTxu/1
         pVYS7uqkz0w0gP7HdEgxmAtZKwYdHAmBpvc5zj0nlbIkgwx3KhxwWXrvnv3iHVDx8mQd
         nFh64unxeEB5rl9Y9JP86O/cNmcueFQPxLMhPp0Z/Ce5IsfxWrYSoSfyMKxBCtMF+YgZ
         r3qQGER75LC9LCJLuS3Ae/P5BGlLel8+qgap7NWPhSnWfJ4/iEWKjRsh+cxsUE+caSug
         ZHsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544531; x=1709149331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wWcL1QbO5PT8XW0kSOL5JXX6UNTVmBSW6LwoW9iT+X4=;
        b=i6lfhmWBJatvDMeQAO/TUkq+0EDEddqSDiKYaXs3JLDQsGPSe3gSK8uTdDklbXDNyG
         XxS/f6xEMZHB7nRyKCsRcfeLAtrkB+JGb/euydSPEnWZ9hLZ/xQhshPuzdk2Az2dzFQg
         jff7vGFB6rJ5GjGO3tesRCsmkCsQChjzsizrOrQyBge43968WAnVTWoXyf1OLEDX07Wy
         pA79jTrLiL3SHJpchJv7ZJjRCm79sanncJVOaPb6qIujZjRb9X+OldBD9dWPfSERYgVO
         4JavkJcD3oswjL4zLaMfPkrICVbEF9NcrR2kaj0/mVX/g36ZOq3u+B233RN19wxIeD/v
         VBcQ==
X-Forwarded-Encrypted: i=2; AJvYcCUYUWMY+0ratVnoM6Ag1MVJdeE/k4srdkBUxx3qQ4RqKkfL48XSIeOmqaf51q/bhNpTlh3x9JJPEdijuMt2RcYTqQKCzR9m0A==
X-Gm-Message-State: AOJu0Yw/mJdibXMCwDAJOHtKI7sa/hnduqEnAu7U4llReK/yLNFQ4Hrf
	9ik8XX1KhXneORhqXKR/8pWpCVL4O9kW33ioht7W+7EWleW9wzCV
X-Google-Smtp-Source: AGHT+IEM/sETEvjo9r3+KVAQkSPKt3dft4+rnuh//zic0A3V4fulE2QjFaP6TBnt7V3v/Q/aD2nq8g==
X-Received: by 2002:a17:902:e992:b0:1db:e241:90c9 with SMTP id f18-20020a170902e99200b001dbe24190c9mr313274plb.16.1708544531352;
        Wed, 21 Feb 2024 11:42:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5885:0:b0:59a:98a2:b1f4 with SMTP id f127-20020a4a5885000000b0059a98a2b1f4ls1531940oob.1.-pod-prod-02-us;
 Wed, 21 Feb 2024 11:42:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUKeMLjmObdu7cM4SLYVbPv/bJG84xOAScKVcAlwtLTPs8wpQwZDAYXE3f6nzSrWDilFZNKkNM0GN3GqdrhFAAhuL6QDlX6yEDZCg==
X-Received: by 2002:a4a:900a:0:b0:59c:b9ad:4ba3 with SMTP id i10-20020a4a900a000000b0059cb9ad4ba3mr18111351oog.3.1708544530308;
        Wed, 21 Feb 2024 11:42:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544530; cv=none;
        d=google.com; s=arc-20160816;
        b=ad5cwLiB3SP3K8C4n6xynWCX2Ssld7psOEG/465iP7HMvmREDtlwxjYIs6FFo2k5mF
         Mjv/A8j8AZ+q1ADquCbe7rGFkVO3YhGQgR1bfUO3BE3jY9j8MUzwahU2wwcgi4eDcBux
         ViGu+CCCFhdjbX3B39RZynYEzMyu6roLJiR6RKTiBWnxymWRZQTulXpAzfsJOQ3c1tYf
         aUXuuTUvgtW+8revaA/CUhC3Rs5/NVL2wgreTj2dggTyLqYEFBjWxklCJOFGqV/tSddK
         IWSZxKyTDAKb+EIaUkRR4s7C6zE9kk27nozyRFOkyokIBZSFDusWXo4u6DZP/RfwKT1y
         1r/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=CzDIuQ0nYms/65bHZ69fKMNRRXjNNeWyOZfzFtq6j+Q=;
        fh=pp4rZ3QMw8xOegbIM2cJ5LXySoN0+f8x/+fRkKwp7wg=;
        b=VrcrCVWlbId7Y847sj3nOA5fHfTn5vBt6GS8CgJANXM5AQGmgv+MTzXMAo061DyE7F
         x257KYa8a1/e9jTluX3A6QGKIs9UmlSkfjY1TuD/3rL9+kx0qoaGQwADS0K4UJGkZ+VW
         q+qTbm/r1dsSowtQOGJrgxz7lkAyUDfB2XSX5EtwQwU5Wkl2tn7EM7PcO/gSjmKMb6aj
         vczavaOJHVgyyUN8M0A7p+vFW/8wwnRgrbLF1qqnPXBljyNuCn2NelhdNFyuLrcOKMRX
         yLZAu/HcOqtiXqfD1UPramrBpD+JRzTKWAHobAY9O6Ml6n5tUj4hYgLUAKg6F2HTjcsH
         EvJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ASHYzf6b;
       spf=pass (google.com: domain of 3evlwzqykcuqy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EVLWZQYKCUQy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id h6-20020a9d7986000000b006e2df32b368si649473otm.1.2024.02.21.11.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:42:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3evlwzqykcuqy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5f38d676cecso1906997b3.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:42:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVawDboZp79GYN9MnNQFUxD+gcF4s6HxMfdpTHTrwMMJxE1MCGu61CMcI7u90hSvuxpUMv+e87YxxGHRxzXzCwzmY0ZAyZhj52DOg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a81:b287:0:b0:608:6b9:bf09 with SMTP id
 q129-20020a81b287000000b0060806b9bf09mr97625ywh.1.1708544529717; Wed, 21 Feb
 2024 11:42:09 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:46 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-34-surenb@google.com>
Subject: [PATCH v4 33/36] codetag: debug: mark codetags for reserved pages as empty
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
 header.i=@google.com header.s=20230601 header.b=ASHYzf6b;       spf=pass
 (google.com: domain of 3evlwzqykcuqy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EVLWZQYKCUQy0xkthmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--surenb.bounces.google.com;
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
index 4a3fc865d878..64aa9557341e 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -46,6 +46,7 @@ static inline void set_codetag_empty(union codetag_ref *ref)
 #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
 static inline bool is_codetag_empty(union codetag_ref *ref) { return false; }
+static inline void set_codetag_empty(union codetag_ref *ref) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index f5a97dec5169..b9a4e2cb3ac1 100644
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
@@ -3112,6 +3113,14 @@ extern void reserve_bootmem_region(phys_addr_t start,
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
index 9e6ad8e0e4aa..7a41ed612423 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -98,6 +98,8 @@ static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
 
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
+static inline union codetag_ref *get_page_tag_ref(struct page *page) { return NULL; }
+static inline void put_page_tag_ref(union codetag_ref *ref) {}
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
diff --git a/mm/mm_init.c b/mm/mm_init.c
index e9ea2919d02d..6b5410a5112c 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2566,7 +2566,6 @@ void __init set_dma_reserve(unsigned long new_dma_reserve)
 void __init memblock_free_pages(struct page *page, unsigned long pfn,
 							unsigned int order)
 {
-
 	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
 		int nid = early_pfn_to_nid(pfn);
 
@@ -2578,6 +2577,17 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-34-surenb%40google.com.
