Return-Path: <kasan-dev+bncBDK7LR5URMGRBUEWU3CQMGQEQI2ZD2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C8E23B327F3
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Aug 2025 11:35:14 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55f3ebcce78sf25617e87.1
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Aug 2025 02:35:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755941714; cv=pass;
        d=google.com; s=arc-20240605;
        b=NHd+rC/VOkUwXvy/+eIz5YZOddDSDFgNGoOnuiJ2ZRaiDBuD3/FNmTd8O7zVAxpyki
         4RNaMC51ed/mNElx0+1x5+EKUtUnMzrIO3woJRi1uHCtFSD8qpJca/3KOhvkzcN+eqqx
         ja3TtTRsLdJCfpq9wHrBltMVntL1AidrtRANgH5PvAgWw4mMnnGzYsYKiVHYlHnczMXb
         4oibECmXDhWPSlg+UUHN/NBbFkTXeSAb3VryZsEYkP1gd59JdSRH46UuSVlBukAcr9bH
         WZuxSuubRrqs9Wg3tvuGKsuVMtCzxSelGHWpJ6D9/g53RGYuyGWmjuwLSNT3wDCXLyej
         oxmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=e19Ck6tg44sbOTKQ5FsOGipZm8f5RiMV6K4q5+/v2r0=;
        fh=phGM1W6QbfDa2n2z0p85m3LxuRisABo0JkrvWoxjmM8=;
        b=lFRfy1t5gyTaL1TqxiLbECGklzfqvCXP2foggnvFlxWuEKWoIZtOn3vCgYBYnWSvhC
         KUnzgFeyHS3p+F2oEw0cGp0UHZWSyb8EuPQfHkllmtEqqdpiz736fftMJvgLUr8ezQru
         7+hWDZx7FH4ip+U71LwPXIGhD/rINnE5zdaN50mV8o+I5mmBEOxYTw15Is+0QxGKDo8V
         XYVNNZrOLKgppZexp+GKPFjdwpvqeDGANpdyW9p8E/2bozzY7gSPVVMU6i4NyEajX/73
         3LxcCUiX5w6lFfKYEQAoYE7hvwzRU2Jc5ATNFWDanWjYV0iJRShjGZP6YfoJBFxbc3Tb
         bm5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iJGSoecj;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755941714; x=1756546514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e19Ck6tg44sbOTKQ5FsOGipZm8f5RiMV6K4q5+/v2r0=;
        b=SD3lCnROkXdo8YT5YyoTDl515Ed9ZiArCVFUyltl/o2fJRMg1RN/0ilDHVbtlcv90J
         QoHlS8RAwZ/amJAupTSUxP9mSdipgtSbYwOM4RhNFeZTF2cMifBtAlczu9JVXPvYmjyL
         oF4rZBgHaX0IDVm75MB7ejxEA/aKvlAQ9QL0GV8S9FtSvMdHKf6LWrGiiYGsjv+SdwcQ
         2Gu4cyKbY/j+IZ8J9Qt/xiYU6AF1O9P6mIso6dqS74eGxH2Ftq//CZ3UWtiRxrnmd6qH
         vMJPk7rLktzIGTvHPbWinb+eiUMhxWtIrLCCqApYQp9CNSvFAFTMr0r37JEg2RShlOVr
         +EpA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755941714; x=1756546514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=e19Ck6tg44sbOTKQ5FsOGipZm8f5RiMV6K4q5+/v2r0=;
        b=lFfidh/XsYFxUd2PbxJYQ7nBXGdFDnNTQEv1tuwDim6XukH6nfktW3CwvEraSQ27qv
         9X7Uk6Nm/eyRy1HuadLMcoC0DPDBc8gwdTOI2VjN+MXliD+n1G9CDDSF0SD11GQNR81N
         bGJd1bqy5Xfmy0mCEU5yqoNjkM1okScgqIFggPra0qWqf1GmENu8gEbQv4LXlLe1PxV1
         aBwT0lAPruQUeJctvpk7YQOr5jSkfby1UxSO5ZhB87h3oc76hQQacBr3anjlMWCYg6Q+
         rjC765ThA7sPyQU7wndxFjw9tGpRf4IH93SloiGfLHnn6+BpRZBytEsqtg+6yfM2iFF5
         zMDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755941714; x=1756546514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e19Ck6tg44sbOTKQ5FsOGipZm8f5RiMV6K4q5+/v2r0=;
        b=ttrmhnVMPnkCXjApXmRQUzALZxa0rpIN6XYU4WLJdjZ6cIm13xb12ebQWcVJxSqHbw
         SxcJ8UANNPH/WSvA7Jdg4X9U/lPZQRYsi3hRKbHtlTs7lBA2YlmOJyrCiX4qCdSIP18B
         pw3m84SugcWudLAfNnM6A+by0X0D7UjIjWOy7XzQpQm6VxCtEDtEwlR2WsU4Zr7trmHo
         BeOxNY59bvgz9fk5wH6LcgrPOnGXXtANeC0+KghO9SJKZSucD41yMZaU9Wt9qK6ZyBlx
         pQysxIuo55wJ+7jXyrtfVDAXxvco17AKdf3k14SB1eTYcy/YSJ3KbYhfm3lOM98eDNf4
         JbmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX4/PA/xTWkb1lwycTfYJ7eq0mdIm6xLq4bbDGa2wyoafP7Gpmr2fQO/bZAqlhCwRipLF57YQ==@lfdr.de
X-Gm-Message-State: AOJu0YxRXY9V/gOsMwFp9VGGg5yPM4QBZQLLacRf//kXIfMar30ndUaO
	2gBQFmReHgLe+AfBujqTTzi434SCNvkS6DtEZd37uG37ihhlmWa0f6Ts
X-Google-Smtp-Source: AGHT+IHFUtq6nCN53+H2LGim7feE/cQ3N5SDCo89NnwDYybDSXaU0GKUHRN0dldd5fywfC+SVV7NNQ==
X-Received: by 2002:a05:651c:2113:b0:333:ac42:8d7b with SMTP id 38308e7fff4ca-33650fc86acmr17861291fa.23.1755941713396;
        Sat, 23 Aug 2025 02:35:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdopv6R3xhSenSsAk5Nb6NsOBXNXSnuQ1Nf2jH3lrclaw==
Received: by 2002:a05:651c:31c:b0:333:924b:baa3 with SMTP id
 38308e7fff4ca-33546b0ce46ls6026231fa.2.-pod-prod-06-eu; Sat, 23 Aug 2025
 02:35:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZnEU5uY+STlzzUg059VaAA/cQ3Dhp9abxj7MWMqYDBTBQKASjGb/FNFAdn0ujqwMWvgXd64pZKxs=@googlegroups.com
X-Received: by 2002:a2e:a581:0:b0:332:4381:246b with SMTP id 38308e7fff4ca-336510432f7mr16363081fa.40.1755941710462;
        Sat, 23 Aug 2025 02:35:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755941710; cv=none;
        d=google.com; s=arc-20240605;
        b=hmn9Ny4dC7uJ3rY+UGu01E9Ifi52BRrvoySO1IVtGtzKCQx9cI+0U0zU1tBms/0rzQ
         t7qcKvSQ7uTrcsOOMJ62/569d+O4SAJ7jsRiz7XF0W+sPmCtN5kh9ZWJdYE+knYmOwG+
         YZ8WVnJM5PiVoV0V9LX2I5bBR1mhkIQco/hvHhYxQsz3pttXpIjWL9DnUDsW1f4J6hVa
         TPlS5LFg10wA7a5ueXXDQgIKlR+0lYZ9leXo1tYWtOW6PZS8MAElNTT16Ot7abtC7Ik3
         G7igmCUNsj3NGF3IZKks5rfCV/pKhgL1OK4/Ov/aDwBYqMgirZN2umBeXIGko9ABsZcR
         o46g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=A92qUKVVscD1iUAIIcRKA9oYRSCgvP30+tdPO7B2xVE=;
        fh=LsW5d2HxraAhBZ2MZXN5gpKvnl9dsk4x+8ZrkRPtVhw=;
        b=BcnX7qI7V7N5+tjboFrOLgzqbUZWhfzB7TIVWWEBbMCRezrZPAu7NJ81vVpb9MfxmJ
         1Ugh3meOPD+trbQrT3MCv1XursdvNVjLuXeL1ncGGmh3i8Jl0YgCEgMjuEQlmH444vfX
         n1acAtHEY9lySKxH+hEGPeFmJfzd3gYObz0c4+CixV8sH+xTB66vl2Fsv0pxmeqpBN7K
         s4ltZ5BeV7vn9DrzTJoE6u/mNqRe+uemMKxq9PWvVui44fS0/FMOjLfSZKzi60xVc+q3
         ttxvp69BaIE2B9O1DQarcQiX1tOIWX+8xuncPtx326bmMHG2fPI41ztqQmixhLZjT1ey
         rQsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iJGSoecj;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3365e5d1fd2si316441fa.8.2025.08.23.02.35.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 Aug 2025 02:35:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id 2adb3069b0e04-55f39c0a22dso525741e87.1
        for <kasan-dev@googlegroups.com>; Sat, 23 Aug 2025 02:35:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXswdgelBrbxWkBhYdQBIwWhbYvukmh//Oxf0CQbJ4UowAOdagkPQtaeoyWIenVCIsoA66P/wj1h/k=@googlegroups.com
X-Gm-Gg: ASbGnctBgRVE0FhqBm6IuP9VF+pEPpEETLV0YIfjuWhi9jA8/I/88HA/+tSbYtmyEfV
	M1YjQ8BJ6u6vChEqLlN5tWVQB+pgfCA8abOXMlTI3dq/uCdp9JK7GoRgoZdm19GwfD2sW/mBkeO
	ehOAEHmhP1Fm+Izptgv6Qxi22kJHdwM7I/IhRlyDSF83qIprbc033Ju4ckov0bYNabZebi1d/us
	VYBY3tFQvgO8trtv4IOiYf+pFJYyUQK4u1HWa0DRNQDJAxbyDfK4iRmRJZh0mQHyGsfyl2NSe1m
	RsE8wAXAL0trAOOEgCBvdmVjTBXiKrVgkyhduPIye3Ke0qW/erz9tD1bN0FZOktO
X-Received: by 2002:a05:6512:4048:20b0:55f:34e8:b1b8 with SMTP id 2adb3069b0e04-55f34e8ca2fmr503948e87.55.1755941709652;
        Sat, 23 Aug 2025 02:35:09 -0700 (PDT)
Received: from pc636 ([2001:9b1:d5a0:a500::800])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55f35c9a0bbsm402584e87.121.2025.08.23.02.35.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Aug 2025 02:35:09 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Sat, 23 Aug 2025 11:35:07 +0200
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Michal Hocko <mhocko@kernel.org>,
	Baoquan He <bhe@redhat.com>, LKML <linux-kernel@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 0/8] __vmalloc() and no-block support
Message-ID: <aKmLS0sLG5-ILTGR@pc636>
References: <20250807075810.358714-1-urezki@gmail.com>
 <aJSHbFviIiB2oN5G@elver.google.com>
 <aJW520nQ78NrhXWX@pc636>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJW520nQ78NrhXWX@pc636>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iJGSoecj;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hello, Alexander!

I am working on making vmalloc to support extra non-blocking flags.
Currently i see one more place that i need to address:

kmsan_vmap_pages_range_noflush() function which uses hard-coded GFP_KERNEL
flags for allocation of two arrays for its internal use only.

I have a question to you, can we just get rid of those two allocations?
It is the easiest way, if possible. Otherwise i can add "gfp_t gfp_mask"
extra parameter and pass there a corresponding gfp_mask flag. See below:

<snip>
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 2b1432cc16d5..e4b34e7a3b11 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -133,6 +133,7 @@ void kmsan_kfree_large(const void *ptr);
  * @prot:      page protection flags used for vmap.
  * @pages:     array of pages.
  * @page_shift:        page_shift passed to vmap_range_noflush().
+ * @gfp_mask:  gfp_mask to use internally.
  *
  * KMSAN maps shadow and origin pages of @pages into contiguous ranges in
  * vmalloc metadata address range. Returns 0 on success, callers must check
@@ -142,7 +143,8 @@ int __must_check kmsan_vmap_pages_range_noflush(unsigned long start,
                                                unsigned long end,
                                                pgprot_t prot,
                                                struct page **pages,
-                                               unsigned int page_shift);
+                                               unsigned int page_shift,
+                                               gfp_t gfp_mask);

 /**
  * kmsan_vunmap_kernel_range_noflush() - Notify KMSAN about a vunmap.
@@ -348,7 +350,7 @@ static inline void kmsan_kfree_large(const void *ptr)

 static inline int __must_check kmsan_vmap_pages_range_noflush(
        unsigned long start, unsigned long end, pgprot_t prot,
-       struct page **pages, unsigned int page_shift)
+       struct page **pages, unsigned int page_shift, gfp_t gfp_mask)
 {
        return 0;
 }
diff --git a/mm/internal.h b/mm/internal.h
index 45b725c3dc03..6a13b8ee1e6c 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -1359,7 +1359,7 @@ size_t splice_folio_into_pipe(struct pipe_inode_info *pipe,
 #ifdef CONFIG_MMU
 void __init vmalloc_init(void);
 int __must_check vmap_pages_range_noflush(unsigned long addr, unsigned long end,
-                pgprot_t prot, struct page **pages, unsigned int page_shift);
+               pgprot_t prot, struct page **pages, unsigned int page_shift, gfp_t gfp_mask);
 unsigned int get_vm_area_page_order(struct vm_struct *vm);
 #else
 static inline void vmalloc_init(void)
@@ -1368,7 +1368,7 @@ static inline void vmalloc_init(void)

 static inline
 int __must_check vmap_pages_range_noflush(unsigned long addr, unsigned long end,
-                pgprot_t prot, struct page **pages, unsigned int page_shift)
+               pgprot_t prot, struct page **pages, unsigned int page_shift, gfp_t gfp_mask)
 {
        return -EINVAL;
 }
diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index b14ce3417e65..5b74d6dbf0b8 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -233,5 +233,6 @@ void __init kmsan_init_runtime(void)
        kmsan_memblock_discard();
        pr_info("Starting KernelMemorySanitizer\n");
        pr_info("ATTENTION: KMSAN is a debugging tool! Do not use it on production machines!\n");
-       kmsan_enabled = true;
+       /* kmsan_enabled = true; */
+       kmsan_enabled = false;
 }
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 54f3c3c962f0..3cd733663100 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -215,7 +215,7 @@ void kmsan_free_page(struct page *page, unsigned int order)

 int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
                                   pgprot_t prot, struct page **pages,
-                                  unsigned int page_shift)
+                                  unsigned int page_shift, gfp_t gfp_mask)
 {
        unsigned long shadow_start, origin_start, shadow_end, origin_end;
        struct page **s_pages, **o_pages;
@@ -230,8 +230,8 @@ int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
                return 0;

        nr = (end - start) / PAGE_SIZE;
-       s_pages = kcalloc(nr, sizeof(*s_pages), GFP_KERNEL);
-       o_pages = kcalloc(nr, sizeof(*o_pages), GFP_KERNEL);
+       s_pages = kcalloc(nr, sizeof(*s_pages), gfp_mask);
+       o_pages = kcalloc(nr, sizeof(*o_pages), gfp_mask);
        if (!s_pages || !o_pages) {
                err = -ENOMEM;
                goto ret;
diff --git a/mm/percpu-vm.c b/mm/percpu-vm.c
index cd69caf6aa8d..4f5937090590 100644
--- a/mm/percpu-vm.c
+++ b/mm/percpu-vm.c
@@ -194,7 +194,7 @@ static int __pcpu_map_pages(unsigned long addr, struct page **pages,
                            int nr_pages)
 {
        return vmap_pages_range_noflush(addr, addr + (nr_pages << PAGE_SHIFT),
-                                       PAGE_KERNEL, pages, PAGE_SHIFT);
+                       PAGE_KERNEL, pages, PAGE_SHIFT, GFP_KERNEL);
 }

 /**
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index ee197f5b8cf0..9be01dcca690 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -671,16 +671,28 @@ int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
 }

 int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
-               pgprot_t prot, struct page **pages, unsigned int page_shift)
+               pgprot_t prot, struct page **pages, unsigned int page_shift,
+               gfp_t gfp_mask)
 {
        int ret = kmsan_vmap_pages_range_noflush(addr, end, prot, pages,
-                                                page_shift);
+                                               page_shift, gfp_mask);

        if (ret)
                return ret;
        return __vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
 }

+static int __vmap_pages_range(unsigned long addr, unsigned long end,
+               pgprot_t prot, struct page **pages, unsigned int page_shift,
+               gfp_t gfp_mask)
+{
+       int err;
+
+       err = vmap_pages_range_noflush(addr, end, prot, pages, page_shift, gfp_mask);
+       flush_cache_vmap(addr, end);
+       return err;
+}
+
 /**
  * vmap_pages_range - map pages to a kernel virtual address
  * @addr: start of the VM area to map
@@ -696,11 +708,7 @@ int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
 int vmap_pages_range(unsigned long addr, unsigned long end,
                pgprot_t prot, struct page **pages, unsigned int page_shift)
 {
-       int err;
-
-       err = vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
-       flush_cache_vmap(addr, end);
-       return err;
+       return __vmap_pages_range(addr, end, prot, pages, page_shift, GFP_KERNEL);
 }

 static int check_sparse_vm_area(struct vm_struct *area, unsigned long start,
@@ -3804,8 +3812,8 @@ static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
                flags = memalloc_noio_save();

        do {
-               ret = vmap_pages_range(addr, addr + size, prot, area->pages,
-                       page_shift);
+               ret = __vmap_pages_range(addr, addr + size, prot, area->pages,
+                               page_shift, gfp_mask);
                if (nofail && (ret < 0))
                        schedule_timeout_uninterruptible(1);
        } while (nofail && (ret < 0));
<snip>

Thanks!

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKmLS0sLG5-ILTGR%40pc636.
