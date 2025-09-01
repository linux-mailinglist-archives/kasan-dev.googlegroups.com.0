Return-Path: <kasan-dev+bncBC32535MUICBBFHN23CQMGQELM5JZ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D262B3E85F
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:07:02 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-61bfe5cccadsf1044407eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:07:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739221; cv=pass;
        d=google.com; s=arc-20240605;
        b=eqLx0gddvuyG2xSnLJRPtVguKPHjQ1dtUeDuMIupzfIZinGzO6PCPgd3y86lZHVKvl
         yoCnSLhBC9rI/Kd+Kxy4t0YCU8IS+RN7GTloVoHwP/xNzg/wUSEyBQwSk2Xg2D4BTgxO
         Jo5T4N/YQjKgMwDriKJgtbryxleRDpddj22/ZV/FwcrjS8lwNYMk+l16ZPnm5gWr3yY6
         znm1qFnogNvOOzmkxFTrKLl9NkL13EC/IrumGW6tDZTuQfCt/FOFRoheFNp+k/GTUAlT
         qmoIObOpG0KJ6MhnbMDvdx3ZatOUEhkbNqfFjgH6vFIIalr5Tr/ekSSdyGi9vE1vVlSq
         qv4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=oDu2BzMcYVN7NS2rlFBrdYUf63EnVlrzd9OhGXkJS8E=;
        fh=h45x8/Y9gZ1BuKV68yZM0CPKcmpfMbtV8uWRATmUUko=;
        b=Vj8LVB0P0gqCLbZpDVInKC3I8M/lbTpnTfQjRvS5zAOXgNPwJy8GdVfHQHPOjvJ0xf
         4DDTktIDsF/RMPtU2I954EdV/bQh7vKefITPrtrJq2wnwVefZ6L3L1rmn9jeS95jFam9
         6xN7N9yIhtI47aJBvdxUkze2zxcQevxMySGil1F/MYXgS7jiKA9+AXIRXiVFhvE4TXlP
         ICneYAKLUNAui1IyqWa5G3NICuL73L4jEJEM2oD15bJj8WN9ZyOX4PWjXP85vBww6rvr
         EbVn3tscr4zTMrfo/cROBaS3/A4LIFCmFejEPqEad+/Xv4IG2dvWGJ1oD4nnAqSJtO6e
         JhmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PhEB0gdJ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739221; x=1757344021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oDu2BzMcYVN7NS2rlFBrdYUf63EnVlrzd9OhGXkJS8E=;
        b=YiiURljUzxrqgxNU5e2rUHJqLsGHFprUyE1I+Knf/1TQLxIhZvarVrG2FbPYZiWp0H
         OnkGihDLTmxnuIUjT/s6wo5yZx6+hQfcLEYJJ6JKh1xuxp60Q5RCI92lem7Ui9PLnQ4+
         3JvgvQVXJD01lAYO5ekJGriSk9wgCFl7SExOx06AOY74LZKWFapErS1PsTcCKjqEtEU7
         V4ekuIH+TqKGIb9vImrTNUQdR0GinpNMjZAy6HvE6BVdh5I0lZZ0XHvdEb+W4YAOKY3t
         IwtXL+beN33BYTHpCF2hQ0IpUEghcBZRNeR7DiAh426CJC88eWhs9s4fu+kh4375ooWe
         EK9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739221; x=1757344021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oDu2BzMcYVN7NS2rlFBrdYUf63EnVlrzd9OhGXkJS8E=;
        b=HT4FNLJZrWnGbqxbR6sDFsdUUufz+Kuz0VYNN/MpRqiBn6TokhBztfzsiSHc5XO6ct
         mdS6UDYsHLmuIFuPh8bzeGjINiK7FDG4kJpoQCOoCbS5x+4D81/NV0BJ8qU2y2hRkwyn
         pbtp3Jb1uEwwsV82QJyGN/+yAp576QtW7ttgTY9J6Yzknc6q3yr2gL/IQzXRQ4iZTmxI
         TvXUQpMVxmZ9TTmqkwz19yS2JIaaudBHOWIMDTkMThzf651Fm5eCODyZHC4WBITFM8Dx
         963E0OxyJl3Z+LRjbIq1nx6H9hFJwvPPuwFhOJwpFibxrqTzb4jL7GY6gW8eoNKiQUd5
         pR0Q==
X-Forwarded-Encrypted: i=2; AJvYcCXVFsM+8y0MBU1k9keluTap+Jrqyox0b6QoqTUwXG4qiWkJ0tT/LmdaZ14HVNEnqY9mArk0sA==@lfdr.de
X-Gm-Message-State: AOJu0YxjinJBB//mzovneg1YCtXDlrtKwn16j06z8HXSZW344z5nS0B+
	DtlG4WkGQc1CBKAg6kktGeHnUYBy4eT9YWLtTWMihwn5NBa5xQqZYF1F
X-Google-Smtp-Source: AGHT+IG+HKJBOHszdQhmZvWkLBE+Oqgp6kaxD14Gmy3bgA2At0MwThLawwch1drsTKcFuut5khCNyg==
X-Received: by 2002:a05:6820:1691:b0:61e:107c:9940 with SMTP id 006d021491bc7-61e3379c23emr4111771eaf.6.1756739220891;
        Mon, 01 Sep 2025 08:07:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdZy85cxqnRVdapi9Kr++jlnYT6aIzN+hGjGGi8LP5BSg==
Received: by 2002:a05:6820:270d:b0:61c:1311:37ab with SMTP id
 006d021491bc7-61e13901a90ls1666167eaf.1.-pod-prod-04-us; Mon, 01 Sep 2025
 08:06:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVByD2Y/Pzm32FH42YO3DhtFmWDX562HEbDXHWWHUZ81axW8Y+vf2cwBol3ecoDkcsE7eoy4/yrGNk=@googlegroups.com
X-Received: by 2002:a05:6830:914:b0:742:fa50:10f2 with SMTP id 46e09a7af769-74569ddfef4mr3570212a34.13.1756739217894;
        Mon, 01 Sep 2025 08:06:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739217; cv=none;
        d=google.com; s=arc-20240605;
        b=XCRW+ExCmCipV7OiQ35fjp/C8d/feCiHKMPLjdJqfT5+7yQv2fxuk2dQP3vtuMPqIw
         7ARfElX7wPznt6HNXTJS06KbwaRKy4GhWakTLveSDyTX+tzkVDrhcAV8Re5KiS9pKnf6
         1kbXeQG+ID9jPOHwkMozZmjrdoTNhTD6QLcbl2jpN7p1oznDiOCZ5f+SV0WaMn873zTP
         RQHiXVH/O+XNal7s/WQyXu0Th2pLZ5Zlo4Nprpeb5VaEJbU4XlAkMQzxkKGzeSrR//oU
         S0X++IK+72J4tvk9p6baYFosbf/n7mkEnYO1ynSGbmNkcJCFMqUDc70Qzlz24BYSlKA/
         tNLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VuRYozOj4jxmWMcjtZVJC7s6FW6AbDAZr6KxBuADLqo=;
        fh=ctvfN477Kd/IFKwsFHl81/Edl10DgBGNAfmxor2gLUY=;
        b=EUg9ttMmpfz5oYvcqvvF3fG4mqJZyNmr6PopywZvP8k/m+8WuVMAohsffg26YhAisc
         sI4/EsDMxL1WAyKhibEWzVDnmCjzWo7+hdTBUO2at1H6JnGikjPsmaoJEDvfAke+rGKx
         m+rh79aZHNhy4LtbBlLXzDPpynyG1eHkTshO/Sf8wTlBQm+VQOEHgV7p6oqm482UZbCW
         6c8Qt5InuuYlv0jEAb7oONdOKG84n5yKRk/ZpOlLW1+qz+Tu9xO4+JWyc9bi/E4QEHMS
         bgzlAligL8vQ7ScLCk9+wl2ikhDIcApS7LJ1KI1ve3IYWw8ILd9bCx985/klm1IhtIQ9
         u+Ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PhEB0gdJ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745741df57csi204704a34.0.2025.09.01.08.06.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:06:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-307-0sc7uRoVMaCioWHY8YjrVg-1; Mon,
 01 Sep 2025 11:06:54 -0400
X-MC-Unique: 0sc7uRoVMaCioWHY8YjrVg-1
X-Mimecast-MFC-AGG-ID: 0sc7uRoVMaCioWHY8YjrVg_1756739207
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id BE64D19560AE;
	Mon,  1 Sep 2025 15:06:46 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 69EDB1800447;
	Mon,  1 Sep 2025 15:06:33 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org
Subject: [PATCH v2 08/37] mm/hugetlb: check for unreasonable folio sizes when registering hstate
Date: Mon,  1 Sep 2025 17:03:29 +0200
Message-ID: <20250901150359.867252-9-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=PhEB0gdJ;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

Let's check that no hstate that corresponds to an unreasonable folio size
is registered by an architecture. If we were to succeed registering, we
could later try allocating an unsupported gigantic folio size.

Further, let's add a BUILD_BUG_ON() for checking that HUGETLB_PAGE_ORDER
is sane at build time. As HUGETLB_PAGE_ORDER is dynamic on powerpc, we have
to use a BUILD_BUG_ON_INVALID() to make it compile.

No existing kernel configuration should be able to trigger this check:
either SPARSEMEM without SPARSEMEM_VMEMMAP cannot be configured or
gigantic folios will not exceed a memory section (the case on sparse).

Reviewed-by: Zi Yan <ziy@nvidia.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/hugetlb.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 1e777cc51ad04..d3542e92a712e 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
 
 	BUILD_BUG_ON(sizeof_field(struct page, private) * BITS_PER_BYTE <
 			__NR_HPAGEFLAGS);
+	BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOLIO_ORDER);
 
 	if (!hugepages_supported()) {
 		if (hugetlb_max_hstate || default_hstate_max_huge_pages)
@@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int order)
 	}
 	BUG_ON(hugetlb_max_hstate >= HUGE_MAX_HSTATE);
 	BUG_ON(order < order_base_2(__NR_USED_SUBPAGE));
+	WARN_ON(order > MAX_FOLIO_ORDER);
 	h = &hstates[hugetlb_max_hstate++];
 	__mutex_init(&h->resize_lock, "resize mutex", &h->resize_key);
 	h->order = order;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-9-david%40redhat.com.
