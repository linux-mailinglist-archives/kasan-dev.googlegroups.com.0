Return-Path: <kasan-dev+bncBCSL7B6LWYHBBZOUQSYQMGQENHEO5IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 30B7B8A9C56
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Apr 2024 16:12:55 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-418591f78a2sf920335e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Apr 2024 07:12:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713449574; cv=pass;
        d=google.com; s=arc-20160816;
        b=UrcLE49gV5iWVKtA78gKH3V2Wx+RfZLjYaEFOI/jsjP7dssyLdnuHqBxHUILHOLgia
         TtDHIYMWm4xTpQ7m1YHRD7MFS67lyqcrjqNraYlxH57BNPF5GUBPNFBWnk2KF8K2TC0E
         wUOtxpNH79qysMDElT9SNotRBoj2dHI9OPB9MMOy7btCZugocSFhT2JSTryXrjiCEwMj
         BTqjvKh1AV0HrF3cgefOP0Uhf2u/Ap9YNB/gRFiGmbCdB2G0sxkZrj8z2fTXgoW+h3Yz
         UDSDEpROVQhLWbWsFLxRcsB9RMctAx8NyfVSpA2sOlV1M6ZlJDJ3CT27gQlXj2mZZhLj
         lfoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=6k8eTKdmr9vabJ28CaeMSgpKuNsr5SxjRwJRsO45TWA=;
        fh=TjJ4ZiCitpNPxMeeTETYH9gR79yiKIrxJqkZK36r06Y=;
        b=z66uCO+VpPe0ozY6AiBJWHgHQhY2J/pwI0SM6WRv9EvQNv2Z4eXxj8BQLY+fawZYxH
         /rpjmG5UspnwY1s6vO6krS1jZE8YAHs5Bfcap69Ys3SDloq0lQjhLZzu3I5BvnYbvET8
         hPwp7VNdXGQ0wR98SwkFb/JL+/38I96TPiTSKz80/UKAWx4IP/PkSjU7PXlvJ5wx1iTC
         g+uXN+p/ko49k6pMtThqssOoVCdtclmhy+PTpm+l5DQO5QaOBlvjKn09bKsU95I1kM/p
         mG9Askz9w2ncEmtfCau7YsxyWhHvbw1o1FKAl6lvjMRyPSJwUSBlLtRP/3971Wz/HLCS
         1seg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LrIyTJMp;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713449574; x=1714054374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6k8eTKdmr9vabJ28CaeMSgpKuNsr5SxjRwJRsO45TWA=;
        b=Bjq0w61nwz3bN9b05M17LqPOyvcJ4yRgAK1scjejGFITA/8UAX1ej1x/rjjEuXhUDY
         xMURTFCbhUgeoU9CPZ6/UjQyMQowmtnAKtAs+Di/Hz0ZtEHm39bEqJaUudmvml953F6P
         x0AztBEmp5QFaPYzXSN3D3c21ZIoZqbScYytdBjQt+G3Pwmb5smBfuEjEGDAyxyGp6PQ
         IFRrFuQgv8VmCefpL19FuVlNDtmZa6/4gSkm/RKweTfN6Zv45JSzrqkquDMgIJZTwPgq
         je7NaGtH6lCOhdWGzDTPgZAZAWVK97ZUWGWxKKG2ONp8nNc/uL76eUNNy7ngAQK+oj0/
         n6cQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1713449574; x=1714054374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=6k8eTKdmr9vabJ28CaeMSgpKuNsr5SxjRwJRsO45TWA=;
        b=QqxPQldG3OuUY/Kq9qU4pBVB9wiPXcIeMsMQxnOd8ncxe66CODVArRF1Xnp9/sUE5V
         u948wVmuEMxmR6TtVZABpYqVTebjpffMYQUBNUSdiZRVvTYuhborOEFpuCF/uCaegx+x
         /cyrGYXbwzRWYLx8N1Ll9Qh1kqCpFlBU4uveIf87p4LK2TMZgwdAkO6iY6ZwXzal0YJJ
         /2j/5EryEv3NQ5ZbTokTzx6qTMocErYycuQti1xj9lyXxsFF4bArZn3HW9EIu4ot2wba
         gUFI5E5YvAW6MWpaTP/H/q8YIptlE0i9K8fLwgvz5lK97CHlxv/Kgwv2tZJ9fOctHocu
         9z5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713449574; x=1714054374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6k8eTKdmr9vabJ28CaeMSgpKuNsr5SxjRwJRsO45TWA=;
        b=KVsHsghWxRoyEpJ++d7BvB43VkfsWagtHXnjRYZUL0c63CbS+X42OrFBtvE5mY/6Kc
         IxP4NAKLPtCU5VfWg17g6aCRi+GM9HxFBjKb7jUdpaQikvYoS7ndfmhM7BkBJanQVIzG
         rUGRSXRP/MVffojbicSbltqSQ0gKbtydRUon8OrynYfcJTB9XdyMfvZFWsZ+StFpdfRl
         p5ZmAZjs249zt8tpCQjdZ+X0Cln53GAl6/M91cRJGrdhhnKRCgEV7FHBNlDAxEto+szs
         hBKLJA+vPpmAATn7G0Y4lcfVBk+NioAFH7Gnwpz4uSL6nZIOza4tC5/NaPUXRRFNkflu
         1KOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6660qnWqR6lyh1Wz2Cu0Jag2Q2quhPV3K+K+nr4439fmdIfRJ3fZYDpkquj1JKqSEnyHJoE9Ql+pZyq02YViEMC6w9IB+aQ==
X-Gm-Message-State: AOJu0YyAJuHk1ruxFdcBg3jf/6v/LJkcRcGCr7mVHsyHOoid0dGstvfH
	5wdsvtmT6Dg76YxAEyuobdDgTH5jePYxrVvuUsaOA+e8328Iqu93
X-Google-Smtp-Source: AGHT+IHr0Lkyuof8KrBvQg2BFHCw91IX9YMZGV7MyDsKs5qTf7ZDGFe4/PBxnhlWj3EQFabaPHefnw==
X-Received: by 2002:a05:600c:524f:b0:418:b854:a80 with SMTP id fc15-20020a05600c524f00b00418b8540a80mr230798wmb.0.1713449573775;
        Thu, 18 Apr 2024 07:12:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5250:b0:416:7e7e:98bd with SMTP id
 fc16-20020a05600c525000b004167e7e98bdls3387336wmb.1.-pod-prod-02-eu; Thu, 18
 Apr 2024 07:12:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMM/4fMvGHJpJw8oD6Y63HPlNrdwa1hDFDox08B6bEE9fSBqzu9Ti6cvL7XtUKL0S6zxOOGkB+MwOfUkAKptaFka4XgD3ImEOb/A==
X-Received: by 2002:a05:600c:4747:b0:418:c1a3:8521 with SMTP id w7-20020a05600c474700b00418c1a38521mr2076958wmo.26.1713449571539;
        Thu, 18 Apr 2024 07:12:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713449571; cv=none;
        d=google.com; s=arc-20160816;
        b=g68e6upysfNHJJfPJ8JIBIjdp1chTNIGcg70DOkHiDbRUOR5lFkbtxqERNZbXxcN0W
         iqaxFwyxpHuPi3xFbl6D99IEpY/Sks06pWuKlVD35bkscYNaJqQyDs7la0or3omKdZ2l
         3rerpgkn9DxCaYLtb7BMB844FSEJy+yHI+rJBCX15d7Gp9Lmr5s6FebyQRGWTKmXUkh1
         PA1qVTMSDXwX+n6aygV9Cb/VylOYnrOsa9BeKvBfFz0BV232BIItTmqNzZpBl0L/ZnMG
         d0Eq0HKljMqMoaoSPfM7WEavcOF/gkx1C19A6IRppNFJVYHZuI4Y8itnd2tXlgKbQvYO
         loFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+sf2v7BoXI0tVMGsUD8eOGlIIA/lRJLZkvnPM+Dzrr4=;
        fh=GLAiYAk9OFVMphuPZ5XfL0nWBwSCsLk0sOzHnERz10o=;
        b=Vj68eEY/CkM2c2X4DjUqQyv401VLG35SXmFc7ca5bcyjOQwgXSsD+U0NyG10hx3S+b
         cXoaYd3uyr1pDt8XQpHJr1+XagSHQoFg2/JL2gWWS6E2yV96EoNJE5Hm2nlePEgFmz+p
         zMiBcDGhCbOcZ+RNBQTCU2b4sL9Dcio3EUTHYGKNppgCn6q2J55OUk/f2M34tkISVtxT
         YcKEulmKpZEMrJvDAwP0WFs+V0OunhMTswHeZ8QRWCquqx08M9+MignGh42D58FAqEp7
         8wzIiHhgSD0wtREd1zy/RKIbOUDANI58tnufaT+T1kWj5E0C3qvtfXyB+ivVxBx+z7Hb
         3NWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LrIyTJMp;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id v13-20020a05600c470d00b004180c6a26b3si410456wmo.1.2024.04.18.07.12.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Apr 2024 07:12:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-2da0b3f7ad2so13804941fa.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Apr 2024 07:12:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcacOPX3JT5zt1GV839WwJbR6rjzlgV+pJBUHANQMZd5aPd4cJ5HeJEEUmJ3nULM/E9fn6fIm0GEX/qC28zrPWYNnG2ikdfIiTIw==
X-Received: by 2002:a2e:b6d0:0:b0:2dc:b467:cb35 with SMTP id m16-20020a2eb6d0000000b002dcb467cb35mr176685ljo.32.1713449570796;
        Thu, 18 Apr 2024 07:12:50 -0700 (PDT)
Received: from dellarbn.yandex.net ([109.245.231.121])
        by smtp.gmail.com with ESMTPSA id u15-20020a2e854f000000b002db706ec5f7sm206637ljj.98.2024.04.18.07.12.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Apr 2024 07:12:50 -0700 (PDT)
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Xiubo Li <xiubli@redhat.com>,
	Damien Le Moal <damien.lemoal@opensource.wdc.com>,
	Christoph Hellwig <hch@infradead.org>,
	Dave Chinner <david@fromorbit.com>,
	kasan-dev@googlegroups.com,
	linux-xfs@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Subject: [PATCH] stackdepot: respect __GFP_NOLOCKDEP allocation flag
Date: Thu, 18 Apr 2024 16:11:33 +0200
Message-ID: <20240418141133.22950-1-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.43.2
In-Reply-To: <a0caa289-ca02-48eb-9bf2-d86fd47b71f4@redhat.com>
References: <a0caa289-ca02-48eb-9bf2-d86fd47b71f4@redhat.com>
MIME-Version: 1.0
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LrIyTJMp;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

If stack_depot_save_flags() allocates memory it always drops
__GFP_NOLOCKDEP flag. So when KASAN tries to track __GFP_NOLOCKDEP
allocation we may end up with lockdep splat like bellow:

======================================================
 WARNING: possible circular locking dependency detected
 6.9.0-rc3+ #49 Not tainted
 ------------------------------------------------------
 kswapd0/149 is trying to acquire lock:
 ffff88811346a920
(&xfs_nondir_ilock_class){++++}-{4:4}, at: xfs_reclaim_inode+0x3ac/0x590
[xfs]

 but task is already holding lock:
 ffffffff8bb33100 (fs_reclaim){+.+.}-{0:0}, at:
balance_pgdat+0x5d9/0xad0

 which lock already depends on the new lock.

 the existing dependency chain (in reverse order) is:
 -> #1 (fs_reclaim){+.+.}-{0:0}:
        __lock_acquire+0x7da/0x1030
        lock_acquire+0x15d/0x400
        fs_reclaim_acquire+0xb5/0x100
 prepare_alloc_pages.constprop.0+0xc5/0x230
        __alloc_pages+0x12a/0x3f0
        alloc_pages_mpol+0x175/0x340
        stack_depot_save_flags+0x4c5/0x510
        kasan_save_stack+0x30/0x40
        kasan_save_track+0x10/0x30
        __kasan_slab_alloc+0x83/0x90
        kmem_cache_alloc+0x15e/0x4a0
        __alloc_object+0x35/0x370
        __create_object+0x22/0x90
 __kmalloc_node_track_caller+0x477/0x5b0
        krealloc+0x5f/0x110
        xfs_iext_insert_raw+0x4b2/0x6e0 [xfs]
        xfs_iext_insert+0x2e/0x130 [xfs]
        xfs_iread_bmbt_block+0x1a9/0x4d0 [xfs]
        xfs_btree_visit_block+0xfb/0x290 [xfs]
        xfs_btree_visit_blocks+0x215/0x2c0 [xfs]
        xfs_iread_extents+0x1a2/0x2e0 [xfs]
 xfs_buffered_write_iomap_begin+0x376/0x10a0 [xfs]
        iomap_iter+0x1d1/0x2d0
 iomap_file_buffered_write+0x120/0x1a0
        xfs_file_buffered_write+0x128/0x4b0 [xfs]
        vfs_write+0x675/0x890
        ksys_write+0xc3/0x160
        do_syscall_64+0x94/0x170
 entry_SYSCALL_64_after_hwframe+0x71/0x79

Always preserve __GFP_NOLOCKDEP to fix this.

Fixes: cd11016e5f52 ("mm, kasan: stackdepot implementation. Enable stackdepot for SLAB")
Reported-by: Xiubo Li <xiubli@redhat.com>
Closes: https://lore.kernel.org/all/a0caa289-ca02-48eb-9bf2-d86fd47b71f4@redhat.com/
Reported-by: Damien Le Moal <damien.lemoal@opensource.wdc.com>
Closes: https://lore.kernel.org/all/f9ff999a-e170-b66b-7caf-293f2b147ac2@opensource.wdc.com/
Suggested-by: Dave Chinner <david@fromorbit.com>
Cc: Christoph Hellwig <hch@infradead.org>
Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
 lib/stackdepot.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 68c97387aa54..cd8f23455285 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -627,10 +627,10 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
-		 * contexts and I/O.
+		 * contexts, I/O, nolockdep.
 		 */
 		alloc_flags &= ~GFP_ZONEMASK;
-		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
+		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL | __GFP_NOLOCKDEP);
 		alloc_flags |= __GFP_NOWARN;
 		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
 		if (page)
-- 
2.43.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240418141133.22950-1-ryabinin.a.a%40gmail.com.
