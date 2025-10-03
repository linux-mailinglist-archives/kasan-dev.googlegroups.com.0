Return-Path: <kasan-dev+bncBDG6PF6SSYDRBX7I7XDAMGQEKBXGKKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 03E0BBB6050
	for <lists+kasan-dev@lfdr.de>; Fri, 03 Oct 2025 09:00:05 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-362de25dbc4sf10946371fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Oct 2025 00:00:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759474784; cv=pass;
        d=google.com; s=arc-20240605;
        b=DguDBbWN8P4T26ENpeYhT7pMdHO55Vd5e/zwou1nG9/DvKOoy7DzFEmAHFCig36EDB
         KvHZti2bIlrDuhKsYoBbS423lfjGFMdRcg2eOS/4GutQvPVvrLOaY/t9zEHBXZhaKNjI
         nufdXEFeYaFp8kq5n5DsLu8ke9y+MtW1oMO1l1Lc3jch4uHvTXfVMcLMmotYoeWI+s/n
         0K2IBNBDSRh6oSNRDHwJQORVYgJ66GESxXu6KAa8uSGHWGDOE+OyQXHj1pXXKBFOXVj6
         RGdl2X8R84hTLS/7jvlg4V63XvsuG4xNzuqsCoQ9QGTD8fMgsWKwt9JJTxykAjhhGEO4
         e1YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=Tr0yfWpO0dkZvbcQy3DIoIiHvI6+KIL+M73o5QosCEY=;
        fh=JpYQQG/eYcZBJfB/4MPyGCslZVkkd6X7ODX9E7Iutdw=;
        b=NigWyGPGyeW7ev+ZVTq67+Qxz9LwjUucMPuePtd5n6xoU16x8ebbrZzMLPPLvMFvZv
         YvWwe7b/6QTBYXfMnAdEWqc9RZ4EVD+sbyejxTemsaCXeqcS4dHTrfCbxHoJBBE4d2qk
         y8pMK/D50+rI61/XU9oWGMgWQ5qGt8OYMYEA27f8F2RxoUuTlt/NufVc1vjVlURhtvo3
         FleG5CtpGfSwnymCDeddFxpsMVb5EF9FaO9FYzBdOrOM7YZcYSPTMmp7lAf4fUlsWJ7u
         57Wprfr597OlyQPmf9ZP8G0XRk04sYIeOxt/LtTQFXKvvJZ39U1RxWXTT2uq0ulv8Au9
         ct0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=rNU5cVhm;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759474784; x=1760079584; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Tr0yfWpO0dkZvbcQy3DIoIiHvI6+KIL+M73o5QosCEY=;
        b=OJWUzPaSZM0keKkSCqxssEW9TeVJjDbTEUMgkRugHM48a7ioarob7ItqkyE7z+3WY1
         H5YGpi7H0NEjATwJcHkJQBEnOnO9E++o0E5OhUYgWPiKZnvFr0sStvf7JSfbhNIZziJp
         LEWtDwp34SETS0Iuah3UYMCSzcnOhviKxquNBbmSVPoMJUUyxXsShGIOimURXcqfZNb5
         Fg23wOhIBsyot3PMK6U+S6ofkJ/iRp57/931xYUdj9xRZDfgLf6dF0oMWPtbu1Rh9I/9
         SdyNvtDc/YexM/JtB/q0JUKhq1Bn/3Iaf2Wg6VOQP7vglVSUx6LMvZ6Qfd5xqiSlA17r
         saBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759474784; x=1760079584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Tr0yfWpO0dkZvbcQy3DIoIiHvI6+KIL+M73o5QosCEY=;
        b=wQ25wXE+o2TzoZ6eGejkbjlMvFEzJMED4pfVIpjiX8xI+bLf0wbt1GypIVA/RSVq+o
         R24zHLDotHuMOFmWCZO6aEVeDcWc68ZqnU0dRvXVYULYSwnXAkxd4aMiG8Zegdh7++9c
         eS18/GwdTFRcIrt96PtY1ZS9t9shQRrgQhrt5zYgHdmcB4ud31/bFFi86vjTd47P239K
         ijpYN7XvQ09sQBt4GFKNcVqfFw95LfzQToKIJbZscvwHUhxlNNeeFCSkPJoqlm8rp1Rb
         +neZBlYrLqYaodLBEtJGBNhS7hupLt8SwoKSzfx9zQVRK+lgo1bZyYHn/ogZLHRNPeaP
         GHwQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQvs+h2CvXdeqA483R+Ll4FdwGFeDMzfIzg4E4BDDhm9jFzggn271pM/ejwu21w6DhQy3ryg==@lfdr.de
X-Gm-Message-State: AOJu0Yz4/CeZWywEhm5RG/aGX+JRKLwq8xBNo7EPXx6WkbZypBgs7GId
	rWDdINYktbD1IC/jBcQBrCG7Dq5U97p5/L0Lq5bspVgOshlP9ZPQhUUU
X-Google-Smtp-Source: AGHT+IEoYX7JDW+ecy1rM0+oLDnVXCBhU/UXDyH3Ns3MgIin+AhuYEj3jJeVK5pKp3B031Tt20221w==
X-Received: by 2002:a05:651c:1612:b0:372:932b:f5dd with SMTP id 38308e7fff4ca-374c38372b3mr5600271fa.20.1759474783974;
        Thu, 02 Oct 2025 23:59:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7KG2DRgy/x6588mUAQ8GyIxjXyU55HYiMutIvhakZvvQ=="
Received: by 2002:a05:651c:23d6:20b0:36b:ab9d:42ef with SMTP id
 38308e7fff4ca-373b85e0c67ls2547901fa.2.-pod-prod-05-eu; Thu, 02 Oct 2025
 23:59:41 -0700 (PDT)
X-Received: by 2002:a2e:bc21:0:b0:36e:6d54:b56d with SMTP id 38308e7fff4ca-374c36ff205mr5290861fa.12.1759474780848;
        Thu, 02 Oct 2025 23:59:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759474780; cv=none;
        d=google.com; s=arc-20240605;
        b=bPCuAYYEpprKHxuJ68lEUo+FlXr6d4STz9583QtMQbt7tEaIpYzGHsESPW7gCzCH0N
         tXA1sSHmzWO3k2KBDbMitnl7YEqrfDCTvsj5lqcfM/O/12zljpgG0GTeWcuXtnJCohzr
         bsy8aWdeeNQ7Cd3KSb2WsJo6TZRy5mF1k5EOO1uCqnQQVUTJnmqAk0IoqxVrsBNLPQVY
         03DgKw5lsHQ/GK0w0FRhhtC5CFk9GfOznKQRlsUFvWlppA/5LxpR08vpc+3XUHRGNJ70
         d8Vpweqv1KZrt6KKgmnNH737jmBEq44VBHGfnIeP9K9OF2yqZDegIs+WCGXJT0uqHH8u
         WDcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=WB9sbfpLecnMxMoiDerCoUS7521vhN66oFyAsMbTO/0=;
        fh=+f3FJC+LJz1xU0x5VHD/dtdGYZL2qc+FIGklMAXMR8Q=;
        b=FpYhD2YXYroXKTzmsmGDqf4xt3zKVnShqS2x8AIhSIutJkngBBlx2vVi43HX0NBx3F
         j8x5tdMIqK8QlMCz9S6BzhNgXGtHKSyhYYPIgo9fXc2WKS7L8RC6cvSmKiinrLMeLhev
         adabPYFw9qWOFrH3WxGOQYglK4NjeF3jaYs7SKv74w0hxgWMEPavofp55YK6k76QxJjT
         6hD5SGCH/dEKnuBtRT55sMqlcbo+4pK7LFtyJOOl5kekhrpNlaV3hUkE09w7rAixhaVB
         MsX3j8P3VrCvENy/13An9J8bRgHY8icLOh2/B85GgJaNs3ZRBZzbQhG2e3yfxj5Pj5zr
         6CHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=rNU5cVhm;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-373ba426631si886011fa.8.2025.10.02.23.59.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Oct 2025 23:59:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p1.samsung.com (unknown [182.198.249.206])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20251003065939euoutp02a5c93e7327fca8d506816727b9084aa9~q6P1jdEtb2855028550euoutp023
	for <kasan-dev@googlegroups.com>; Fri,  3 Oct 2025 06:59:39 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20251003065939euoutp02a5c93e7327fca8d506816727b9084aa9~q6P1jdEtb2855028550euoutp023
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20251003065939eucas1p2a570a631290b2053af4bfee78ca93977~q6P1Z1Cy11393413934eucas1p25;
	Fri,  3 Oct 2025 06:59:39 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20251003065937eusmtip1440172238527b922b950b45020a53526~q6P0IH4u62724027240eusmtip1D;
	Fri,  3 Oct 2025 06:59:37 +0000 (GMT)
Message-ID: <c921d3d4-3f15-4b46-bd6c-2f48b2747e60@samsung.com>
Date: Fri, 3 Oct 2025 08:59:37 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH] kmsan: fix kmsan_handle_dma() to avoid false positives
To: Shigeru Yoshida <syoshida@redhat.com>, glider@google.com,
	elver@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	jgg@ziepe.ca, leon@kernel.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <20251002051024.3096061-1-syoshida@redhat.com>
X-CMS-MailID: 20251003065939eucas1p2a570a631290b2053af4bfee78ca93977
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20251002051101eucas1p250c65f775d8e64053ee7e009142c89c7
X-EPHeader: CA
X-CMS-RootMailID: 20251002051101eucas1p250c65f775d8e64053ee7e009142c89c7
References: <CGME20251002051101eucas1p250c65f775d8e64053ee7e009142c89c7@eucas1p2.samsung.com>
	<20251002051024.3096061-1-syoshida@redhat.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=rNU5cVhm;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as
 permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

On 02.10.2025 07:10, Shigeru Yoshida wrote:
> KMSAN reports an uninitialized value issue in dma_map_phys()[1].  This
> is a false positive caused by the way the virtual address is handled
> in kmsan_handle_dma().  Fix it by translating the physical address to
> a virtual address using phys_to_virt().
>
> [1]
> BUG: KMSAN: uninit-value in dma_map_phys+0xdc5/0x1060
>   dma_map_phys+0xdc5/0x1060
>   dma_map_page_attrs+0xcf/0x130
>   e1000_xmit_frame+0x3c51/0x78f0
>   dev_hard_start_xmit+0x22f/0xa30
>   sch_direct_xmit+0x3b2/0xcf0
>   __dev_queue_xmit+0x3588/0x5e60
>   neigh_resolve_output+0x9c5/0xaf0
>   ip6_finish_output2+0x24e0/0x2d30
>   ip6_finish_output+0x903/0x10d0
>   ip6_output+0x331/0x600
>   mld_sendpack+0xb4a/0x1770
>   mld_ifc_work+0x1328/0x19b0
>   process_scheduled_works+0xb91/0x1d80
>   worker_thread+0xedf/0x1590
>   kthread+0xd5c/0xf00
>   ret_from_fork+0x1f5/0x4c0
>   ret_from_fork_asm+0x1a/0x30
>
> Uninit was created at:
>   __kmalloc_cache_noprof+0x8f5/0x16b0
>   syslog_print+0x9a/0xef0
>   do_syslog+0x849/0xfe0
>   __x64_sys_syslog+0x97/0x100
>   x64_sys_call+0x3cf8/0x3e30
>   do_syscall_64+0xd9/0xfa0
>   entry_SYSCALL_64_after_hwframe+0x77/0x7f
>
> Bytes 0-89 of 90 are uninitialized
> Memory access of size 90 starts at ffff8880367ed000
>
> CPU: 1 UID: 0 PID: 1552 Comm: kworker/1:2 Not tainted 6.17.0-next-20250929 #26 PREEMPT(none)
> Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.17.0-5.fc42 04/01/2014
> Workqueue: mld mld_ifc_work
>
> Fixes: 6eb1e769b2c1 ("kmsan: convert kmsan_handle_dma to use physical addresses")
> Signed-off-by: Shigeru Yoshida <syoshida@redhat.com>

Applied to dma-mapping-for-next (for v6.18-rc1) branch. Thanks!

> ---
> The hash in the "Fixes" tag comes from the linux-next tree
> (next-20250929), as it has not yet been included in the mainline tree.
> ---
>   mm/kmsan/hooks.c | 3 +--
>   1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 90bee565b9bc..2cee59d89c80 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -339,13 +339,12 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
>   void kmsan_handle_dma(phys_addr_t phys, size_t size,
>   		      enum dma_data_direction dir)
>   {
> -	struct page *page = phys_to_page(phys);
>   	u64 page_offset, to_go;
>   	void *addr;
>   
>   	if (PhysHighMem(phys))
>   		return;
> -	addr = page_to_virt(page);
> +	addr = phys_to_virt(phys);
>   	/*
>   	 * The kernel may occasionally give us adjacent DMA pages not belonging
>   	 * to the same allocation. Process them separately to avoid triggering

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c921d3d4-3f15-4b46-bd6c-2f48b2747e60%40samsung.com.
