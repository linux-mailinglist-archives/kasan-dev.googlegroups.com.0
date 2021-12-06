Return-Path: <kasan-dev+bncBAABBF4JXKGQMGQE33I5B5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id A889346AAC1
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:59 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id p12-20020a05600c1d8c00b0033a22e48203sf469455wms.6
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827159; cv=pass;
        d=google.com; s=arc-20160816;
        b=wilwcfaUYaYFT4hDczgyNyRVVsf8543bdKBMPSIvHtGZzjLDsh6TBbHt4AL2d6yimV
         rv2qw+vwYvQQR1Vcs5slhQk8/b9XzmXLgT2b+5kMWPEQfdE8fJmtxKEoFtD7mSJ4w1I4
         tLC0rnzCDKcPlyqPR4Zo4IOd5sDZ/rogtdH+Yb5OuvvpM/qJjgujQpc8YX7bqFZx5a19
         KBsViWo7MKAXjVnERB7W7GLSZ4L2GVl8d4u7eqbzxKJyGCsmxrifmeHn5L1fjyaEo8qi
         NGO3IpZLDJXTKTdX4fXP1YqNCfXDXZw8SD6QSKyrwrBBahUAjcO2kUUln76OBhDfKo9q
         bH3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0UeMKzxDQKopno53KMg4WP5LNDmj6J35dw0orPvQnHI=;
        b=orElulo4ptqqWV0Bxh510iAi1kJndObuqnaLK0u0dHMAqhachbEjfsQn97Xj1tX6Xu
         fuJxqrn9lGXF9sFv+8h6w1GGsNzocXM9VzVmW4n6BaYpu3bLor9sUjYhgtbwmBvQtQVc
         kK8xruOPc7g9V+4kcysUwEjsGoTbfzIPl75BVDgJRSfKBPRqLNSn4Tx/S9/1rHiEpOAF
         OwCFD/f4Nb6J8cIvuHeNBbs8LSX4dv6uiI7vAIDOa4aMh8sFXLkfsOR5k9R2jqnuYyk1
         ruWYq03pS70mk/Ujwf+zJcYO/5+436MBYrnh0gfHlofstmngXRmW6F32ClIJOCcQbova
         Syvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="W/pnZKDT";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0UeMKzxDQKopno53KMg4WP5LNDmj6J35dw0orPvQnHI=;
        b=JJgeqzyNStGDePjIykvlZ+aMzM4kD6AwrZsm0oj8Z10w8eiQe+cdsl/40hnINTUrZR
         tzvjpbTYQywf7zx2HfiEabcQmM1fZhxP5dAVhlwUsmZO5cUoy5BGlWOuoJcpo0IB+Ipp
         agctp4RqDRxTEfoB252FAIR2eUJplssiWKgr5fs8fIv7P5nym1K/LlAtdPkVKMJohPyr
         BYD+EsmvRpwJqaj7fVTbsiyo1J7M/aQS524qrPqKeMuQ0rnPCDPHlfI+sawGPfVhnvCP
         y2EDRimsT9QJ09+4W4vhcc8rqUa78G0lRWAaUrVokDvgXNE60e73pV/iwABvZkdc7d/9
         SLmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0UeMKzxDQKopno53KMg4WP5LNDmj6J35dw0orPvQnHI=;
        b=ztQKvQGiW3YdgFM64e1dhjjwACFr5IYLZDJLpsX2LrfPJzY1SivWH+5N+l4/bU9V+M
         GkpGzhKz5QxbTShQX9MvfdIhDc956Xc+SxL+ouLboJN7daXxvJZFfkKjw2svEJEtFoLw
         1pUAYeAqQ7sLG0xz8R/DGLppQV79ogK6ws9I0NzdzpSgEyA3TERV6sWinjaDkK8rsRJ6
         3Fl5V3n/kNqtuihi34rnno0P/T4+2WyUHuP0TbMZYKFDReqew4mTYL2r40S4XI/Fyuje
         NB2ArhiXMht6ePGZS1KysoOfJLro3VOhYfqnPL74WkOuutMoPPCUcnf4bybWf8CuTTHi
         3IKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ScyQlhpwbxiXpfJRXJKfvOlTKGeyjQdOtPWQ/pt3ZVBIVyUPH
	8x0IkKcTqIG9v/3NQBxPSp8=
X-Google-Smtp-Source: ABdhPJzZ7UGsMi8mxwYepYsv6QGlHLV8LSUtH78z3LZIKkrU7knJrpNcrm7h1FobKHVUqydSQxgFbA==
X-Received: by 2002:a05:600c:3c85:: with SMTP id bg5mr1543137wmb.58.1638827159492;
        Mon, 06 Dec 2021 13:45:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls1150860wrp.3.gmail; Mon, 06 Dec
 2021 13:45:58 -0800 (PST)
X-Received: by 2002:a5d:6acc:: with SMTP id u12mr45366125wrw.628.1638827158944;
        Mon, 06 Dec 2021 13:45:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827158; cv=none;
        d=google.com; s=arc-20160816;
        b=tmyFZbL4/dfXxJlJ5IsNZfBRqd1xE502n+WB6a1WazGga2XLqMCBx2TbSTF8PizNzs
         oe/b10sdALacSxukIE2Lf8rebV14NSpbZj7djET+MkoZslZqzLxEKbi91Zq0FxYba0A1
         crUvbe/+vKIE+B1ZpCoL6v7xCQRcsv+vQ78swhTWa5Pb52VV9iRFmgOFRvHAIFwJB11g
         d6ECAetzb3KfattyYsYQLIvXAcNW4m8ztkt6LqwLL8gdyr61OHtqMLdx271Ya9bcls8v
         4qvN8aN5jhcGMretF5XwaBvhwx5XwFhNfUYFqEuTW4dXsz7Egc+PrJ4MC3P6HaszRBlj
         qRdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JTNahgB9b8xFEkRfhyeNPJ7ITVoB0ROvdRGcm8t3Kk0=;
        b=r7ZD/1IzZr06P0XnxWpb0zpQpqCcWoB7cQ7ZnXnU3//62I/UfCe0I/OFjEdnXZ/uU6
         CxGg/mNBL/o4DibzdDMpE72PlokA9UrT3fj/Vbs7FA8r6yQPATaWhyU1lna9qkvFCx7a
         Yt9VDU3I8fM/SG9QU0nDLVes3jPU4TctsNMoZ9DgFTuVehFH1jgF9GmpFdL/2nIXO1AW
         EcD+CN77Cekkl10eHVuKutWrUuqrstCqlshd5EV9rpa8zL+VrrHKcWs2xo+CFOhUjNkD
         6PrRGi9U+geOteXAUFsO52CcxcH/6kCQky4N0uX473js9YMCVcC4j4S9eetDweWCfj/r
         WWYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="W/pnZKDT";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id c2si104679wmq.2.2021.12.06.13.45.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 19/34] kasan: reorder vmalloc hooks
Date: Mon,  6 Dec 2021 22:43:56 +0100
Message-Id: <290884a271e5adc79ef0121868558c1e19db1b70.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="W/pnZKDT";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Group functions that [de]populate shadow memory for vmalloc.
Group functions that [un]poison memory for vmalloc.

This patch does no functional changes but prepares KASAN code for
adding vmalloc support to HW_TAGS KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 20 +++++++++-----------
 mm/kasan/shadow.c     | 43 ++++++++++++++++++++++---------------------
 2 files changed, 31 insertions(+), 32 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4eec58e6ef82..af2dd67d2c0e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -417,34 +417,32 @@ static inline void kasan_init_hw_tags(void) { }
 
 #ifdef CONFIG_KASAN_VMALLOC
 
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+void kasan_unpoison_vmalloc(const void *start, unsigned long size);
+void kasan_poison_vmalloc(const void *start, unsigned long size);
 
 #else /* CONFIG_KASAN_VMALLOC */
 
+static inline void kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size) { }
 static inline int kasan_populate_vmalloc(unsigned long start,
 					unsigned long size)
 {
 	return 0;
 }
-
-static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
-{ }
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) {}
+					 unsigned long free_region_end) { }
 
-static inline void kasan_populate_early_vm_area_shadow(void *start,
-						       unsigned long size)
+static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{ }
+static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
 #endif /* CONFIG_KASAN_VMALLOC */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 585c2bf1073b..49a3660e111a 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -345,27 +345,6 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	return 0;
 }
 
-/*
- * Poison the shadow for a vmalloc region. Called as part of the
- * freeing process at the time the region is freed.
- */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	size = round_up(size, KASAN_GRANULE_SIZE);
-	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
-}
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	kasan_unpoison(start, size, false);
-}
-
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 					void *unused)
 {
@@ -496,6 +475,28 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
+
+void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	kasan_unpoison(start, size, false);
+}
+
+/*
+ * Poison the shadow for a vmalloc region. Called as part of the
+ * freeing process at the time the region is freed.
+ */
+void kasan_poison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	size = round_up(size, KASAN_GRANULE_SIZE);
+	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 int kasan_alloc_module_shadow(void *addr, size_t size)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/290884a271e5adc79ef0121868558c1e19db1b70.1638825394.git.andreyknvl%40google.com.
