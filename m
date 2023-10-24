Return-Path: <kasan-dev+bncBC7OD3FKWUERBFMW36UQMGQEHHW7PSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B7217D5283
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:48:06 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-5a7a6fd18absf57847807b3.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:48:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155285; cv=pass;
        d=google.com; s=arc-20160816;
        b=iyLEnthVHXa90t+gC/5i05v8wvThztScSJDwf0cztStMvVtB+E5oXaEsG5iPljja5J
         AjMKL4ZS6nMFS+d2Q5EtIzw2K7itHsTbQaU375OtzAfBAIKfU/MOhMe77fMW53df9jF3
         xe2BCvG7kcoeKJavHs9atm98b2CmQAegHIFy0ZrmDOhkP9mIqlrdDYzsvE7Tb6H5jwDh
         qctBwR5BhCMELtbwv0MMLZUVoWCn5bthQQ4DdNT05DJZBcSKyF16JhXABr3SzO5JFXb0
         h48A3lLGAzScNPgFvu3FHLStKFF8AfUcFVKp+pHw3YGcnt/K5l6shEbytNsTX35mbIKo
         yIyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=yG4/kKQuphc/JalH8ihalkBgXYMaD7L81EE3KaIgJVs=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=lfdk/VvgWDXHHfgdbBAU47gKMGnAieHQTPqfbtNuNMryk4EO6ZsHvXgS6b4kIx0Gx4
         uI9fWBIsGX6u+12YAMvRK1rcoPSAGARIAXCrxSauUX84Q7lonUemPHng9+jmYRl7PRSu
         L1bf04hjyj5L6iLZpDqiCW7mMjdmXtvU0sXsbjmMGWNqMZwOoA/Hon37gROOoCrN7W5g
         P7rIp+MHoPbzwIpgCdIPDpHkA7YxWAiKb982HDoY0X0IRAc0lP5M/g7Cmg4BdrQSUI3b
         4VEBfhX0RKQaXE0y85RTWLpOTRduYtKbe8BhnvrYZG54aPTolyq1BgbPCW2dgqCl9fg7
         hd8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=agTMziIH;
       spf=pass (google.com: domain of 3e8s3zqykcbgqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3E8s3ZQYKCbgqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155285; x=1698760085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yG4/kKQuphc/JalH8ihalkBgXYMaD7L81EE3KaIgJVs=;
        b=mUvLdZRc9yNO8X6JRxEKTb6dFLfuw+DsSR5cdp1+h3BmZl7UqwDGvdII7L07fs9xMc
         JvxjZtGHA92avMO73H8z6aZOari23naMlu9I1ClbnYHuspO+OfZJtva4m4xHYU03a8YX
         g6p2P1FgRWrLZHLHxkEEMssypk+3Dm5j7+Jj2i4nMtGRdYh/uSC8pavmKq0lRl25hfUO
         nEwCq1qiht1kFIFomtyJGfibGYlmnEm+I/Lo2+bi6WMZXtm7paiTrio7boufhD378I2c
         cOQ9n5nq4KWPnI0sk+e3aSrj3wc1Zbz409zjJnU2Q0MjDV+QYHGHTUt28BLV9I9aIWxd
         n4bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155285; x=1698760085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yG4/kKQuphc/JalH8ihalkBgXYMaD7L81EE3KaIgJVs=;
        b=vr5bmIUCwnea2ZMU9FwbQ7XQOMSxHP8Opr4sT4Yw044wsbd6vVJHhPvRHSv9riO+Wo
         6TOZCjTPw+D/r340ecS7N0KH63VRY5ngv2Ly9noTRaT62A5mpY72gqXhn88+2C83LoPW
         oRO0O56RXxXv+EspqXa1FpZFm5ojikXAtOBf8kbv0eNaP/V4KFPACRLGurd62cJHoi+2
         mxJcoSGdp1ieZrXlOTDIT9kP2RlrIRS0rKRBGlPRlvo0ArV2AtMXB1TDIROtXaTcIOKo
         vkKHpfgR39eY2ySpgN53T0ViIMWNwQ5KWbX4CsMRkJ+3zBFV4WwShqtTX6DicNW10EpJ
         lGsA==
X-Gm-Message-State: AOJu0YxqN4yN1XVyMfSjx36Cs4NjQ+tvPUAx601NVUMkCryMHTt8BPq4
	BQAd7WqTI2gb7C+yOWDX/jc=
X-Google-Smtp-Source: AGHT+IFK888NGfOsjChum6q09gX1b/x73IBNUTt0W8VLAnZVzb9SRrnk8aYKEzZsyJ1raFNB+djOdw==
X-Received: by 2002:a25:b31e:0:b0:d81:bb7e:f47f with SMTP id l30-20020a25b31e000000b00d81bb7ef47fmr13073947ybj.44.1698155285147;
        Tue, 24 Oct 2023 06:48:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7755:0:b0:d86:29c:2155 with SMTP id s82-20020a257755000000b00d86029c2155ls1564502ybc.2.-pod-prod-01-us;
 Tue, 24 Oct 2023 06:48:04 -0700 (PDT)
X-Received: by 2002:a0d:e8cc:0:b0:5a7:ba09:52c7 with SMTP id r195-20020a0de8cc000000b005a7ba0952c7mr14766470ywe.11.1698155284430;
        Tue, 24 Oct 2023 06:48:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155284; cv=none;
        d=google.com; s=arc-20160816;
        b=FhQXzPy3UF/GhXDJ+ZbDg2Yv7PY7rDXJheAdCMZ/wwG1SezUbWgorrNRayvfS3xcI9
         ZqXZSQ7rK9D9ngUHbKYgltwc77c2gtEzJfx8ffIkO2eR+M16V6VFuxuaXWrzda97OQ/K
         PKo7AAAZ+baiBkbtUH3kFGIX12QT2RG3D1Xw5giYtqqnJ/K8Vy/8t3Fw+mmAaG+m2lqt
         2nE+3p1s0E8TvOgCLtvElA3ZskMlZz0/ovh0DgMlYgQokzvgYmq5aQiP3aH9n7VGROnI
         2ItndVANYk3AoXRF6+96H/k7+xkPn1q9eF+0oIy51dwjcciMi3UJATEOA2Ij7hQQuRHm
         4fqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nhDAtTQGKDGtY2/txJr7AfaYGvHf9XTIsotRfIG2XI4=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=pVp/vwgciaD4P9Vfh95/ARxcNxbVl3XlXTbVJa4b+NqyNfdB4qzx9DfAUXODUOf/le
         jDJdi2HgjsXCECUEWon3UiIl+TPKjQE/mheZytM4yhJMVOIPNf8upxL8sWD4aRzYhWxw
         m1/QBFQilc9PxvkxX97rVX7RT+r4BiE0lnFK/98MdVC8TOPUlZxHLCoN10tNkzcPFaOq
         IW84IEQIF3Dz9G+VvtGKumztUL2ovK3jjiKGgbMR70vcu5FwEAJoyTbAc6SQKWo++EtB
         gxIWifu37XCv/XGOKndfu6KEb9s8/D5B6WUVOXlGgUXKDwN8ysiwFWuEFfJDnzlsczaS
         BgcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=agTMziIH;
       spf=pass (google.com: domain of 3e8s3zqykcbgqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3E8s3ZQYKCbgqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id p15-20020a81f00f000000b005a7e4fb91b7si14325ywm.4.2023.10.24.06.48.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:48:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e8s3zqykcbgqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5a90d6ab944so49814557b3.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:48:04 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:8541:0:b0:d89:b072:d06f with SMTP id
 f1-20020a258541000000b00d89b072d06fmr231639ybn.7.1698155283973; Tue, 24 Oct
 2023 06:48:03 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:34 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-38-surenb@google.com>
Subject: [PATCH v2 37/39] codetag: debug: mark codetags for reserved pages as empty
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
 header.i=@google.com header.s=20230601 header.b=agTMziIH;       spf=pass
 (google.com: domain of 3e8s3zqykcbgqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3E8s3ZQYKCbgqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
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
Maybe we can annotate reserved pages correctly and avoid this?

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/alloc_tag.h   | 2 ++
 include/linux/mm.h          | 8 ++++++++
 include/linux/pgalloc_tag.h | 2 ++
 3 files changed, 12 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 1f3207097b03..102caf62c2a9 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -95,6 +95,7 @@ static inline void set_codetag_empty(union codetag_ref *ref)
 #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
 static inline bool is_codetag_empty(union codetag_ref *ref) { return false; }
+static inline void set_codetag_empty(union codetag_ref *ref) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
@@ -155,6 +156,7 @@ static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
 static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
 static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 				 size_t bytes) {}
+static inline void set_codetag_empty(union codetag_ref *ref) {}
 
 #endif
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index bf5d0b1b16f4..310129414833 100644
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
@@ -3077,6 +3078,13 @@ extern void reserve_bootmem_region(phys_addr_t start,
 /* Free the reserved page into the buddy system, so it gets managed. */
 static inline void free_reserved_page(struct page *page)
 {
+	union codetag_ref *ref;
+
+	ref = get_page_tag_ref(page);
+	if (ref) {
+		set_codetag_empty(ref);
+		put_page_tag_ref(ref);
+	}
 	ClearPageReserved(page);
 	init_page_count(page);
 	__free_page(page);
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index 0174aff5e871..ae9b0f359264 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -93,6 +93,8 @@ static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
 
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
+static inline union codetag_ref *get_page_tag_ref(struct page *page) { return NULL; }
+static inline void put_page_tag_ref(union codetag_ref *ref) {}
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-38-surenb%40google.com.
