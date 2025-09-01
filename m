Return-Path: <kasan-dev+bncBC32535MUICBBBHN23CQMGQECJNPGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3990CB3E856
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:06:46 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-71d60183b47sf51404507b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:06:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739204; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y/36WmcNbKlYBuakWtiRcCWqqowGmUGVvxeZHnhMkehWFtpitsy3HX0ZyJkyroRDba
         O+tAgGIbtPaVXY4u1gdeTtiKNRZhzFEKD1OpblTkPm0C98p7WPaBCVRT6dcM4Ihf3ndp
         DDuijbpTl0yPS9vK3gVE3UVK3BB837dUtjoB7doUOehmhn8H9pzP+1zY5ZF5T3518+my
         UUFO8edNa3zsmCWWRkmI5FFPg9W3BjDB9M8z6cF5DaaoafLtJr8jO3N9+1HsTc/wEUGB
         0jF9heVpbza1ElbZzPKIwQwqpgeqJ2UPM8pQwczcH89LYrtlaCIstc4z4U0Eb71uRz92
         jn/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=1S2xpHYfJuo66LNEUUxE6U8btv3Qd9DcDCuGW1LqGis=;
        fh=K+7bfyt+jjkiOcqyNFJNTEN+AVE7GaOELNl5XN5LXyI=;
        b=RYplisNR1BoPV3k33CQ7fLk7ZKHr+5Z6sJy3xh9ml+ZrdroJ0LpCXZZXiRgu+qsl2i
         AqTp+kYqmQB6J/XKYKlO53JNKiwVXVNehVEN7jNuSO2XC5cG3CfbsP0Svbm02Q1xccLs
         zhkqp1HXn/ClViVlZZVekYb0ySJkRNG6hwzsKJ5GZjoc4mQdbAcj8C7Lhs2+QBHP5XZn
         O3Gb9Z9QgNeMlnv7XFF8OAzgMqbrgyZodbL01zxndQOjICeABR9zIWluCyKM/Phohcqw
         5LaRrZ7DjE0Aw4fjxx6KM7YEypNbylqmfIFWGWzCefk0J2yZaStmXD1TwywG32n3Xoj8
         B5DQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DuuVaSIA;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739204; x=1757344004; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1S2xpHYfJuo66LNEUUxE6U8btv3Qd9DcDCuGW1LqGis=;
        b=a7HXEbRNqPnF/X6S3jDfm0TAHpDni5EXmr3JJvEhjizGPRRKJc2qk7CIdPun8Az4Yu
         j8PL/Fq32bT6IhA15c4UmB90W89DhF6pmNXZ4HZZgx4nZJERvUySQvNTYeQDtFLgZi91
         CUi9oUbnxHjXdngijEn1r5K6n/XpFYp1tR1SPBxey2p7mS3+uuMwDyUPJfmTFGZDjZiD
         dk53pSoqMF6b7ELn7yLgFUHAJMu5KyNjpd4eI84VsnSWpUVfHk4T+MkoNRok6MGPbT98
         bevF5CdN72C/3auOu4fYBJQLuSBHW5jQ23ylwE/urhW9F0oe2PwZeYkf4GZpeZ6nAIAy
         0DQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739204; x=1757344004;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1S2xpHYfJuo66LNEUUxE6U8btv3Qd9DcDCuGW1LqGis=;
        b=giqh1lt20YgrhWgGJtxhsdIc1JxDOMUKpWICjnrISNjWDv0em1z5B+IAFTG93Rsci9
         NVz9mxJADrFTs5T+YauXfooIo0yGRWl/wHIzLp9TsY1udjzXQmuY4ZhTSslxZzDzUnub
         nSuqdDqm8nkL6BbuiHchWh63PTGjvp8oR3cdpsf6iraay54nnos2AwZMzSXoezaZSiKY
         9NqUs8AY/tRPQsvaoufe3rZBqFtyailetO3pGyPTv03Yt4YHBi4G38sWQFESCeZD+5bl
         cAJkSESZ/8My1UMfsV9U3tbdf/Coza1vT/uyp2DtKQtchMG2XmQ/93xs7MA+MFJY6D3K
         SeEQ==
X-Forwarded-Encrypted: i=2; AJvYcCViGKfucyxJPsQC31OvjRnUvLN95olJrFiDF6y6lbJKETONgNs3Jnu/oKPf2hz0TbE2IpUKdg==@lfdr.de
X-Gm-Message-State: AOJu0YyLzqCFHfOYCpyWA3uraHabMKORlLcw2RzvrrnJXJZUyoWHkKBy
	d2Vt5nbVRl7VIGatLVSbYC+H87z7gtNpSXadBng1hnqJxj/xCMCfz8WX
X-Google-Smtp-Source: AGHT+IGYONEIo0RjTN/3hZtvTlF+0JCp7KC6a1+9M8iUQdWg/PI117i0C4cHoZPPHsUg7pWPql5Ydg==
X-Received: by 2002:a05:6902:2b0e:b0:e98:a1cd:eeb4 with SMTP id 3f1490d57ef6-e98a581c988mr8576793276.29.1756739204461;
        Mon, 01 Sep 2025 08:06:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc+dmvJdXB2/82G1FF8KCh6vDgd1c+yU7KRd9/Va9lRcw==
Received: by 2002:a25:2d0a:0:b0:e9b:b7c1:80c4 with SMTP id 3f1490d57ef6-e9bb7c18642ls148726276.1.-pod-prod-07-us;
 Mon, 01 Sep 2025 08:06:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5y+UfJ1QWirYFTinjXGeyHwcvG8Jj5G2dU8owUCQG8hgpfgQM2mYPwVxW0KN+yp4tLCV2etd5W9k=@googlegroups.com
X-Received: by 2002:a05:690c:9688:b0:721:67c7:936e with SMTP id 00721157ae682-7227658a1e4mr92565887b3.50.1756739202959;
        Mon, 01 Sep 2025 08:06:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739202; cv=none;
        d=google.com; s=arc-20240605;
        b=VWlidXk0/Q/zwx25IHVZ3QzETGCkrTqzXFka65UjXoyOHmtD2dgJBtjIzJJqqlwbbk
         xszFolgGQZoWbV6se2GHNG40GiXfnSpvTum5gJIC1yFD+PBBrVoBTaVZ8ek1YUzDMHeO
         yw9L7OEtjnaAR8UX+Iw72QRpLfwJKJnrEtFoUHUw2Vd7I7a1GXCqOLrHvujcrE7BcxNp
         R0UXguPMx6e1DTK/axO2OUgK3a/G6BcUN/eu0J0YRicbdf8rcUIdQ+TTHLVzXXIjyyLk
         6nfA/l3TOF6aIiYs5hDVb6xhEQADW1k26ICsWBAisjw6jrHVdGu56G/iDxz9nYvsbf5L
         jvZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dzO5XeQXA+92El5MTIOjMpy0CzhO3womFwma0oFqoHc=;
        fh=NXcAEgKnZ6RguEDlIQQYbgS8z22YROO4NGcR7i2b7w4=;
        b=RNevcXGMcmSFcNjCkYK3gOjSg2jkBI63Cc79DN5Zmj10E4GOTNVtBIX3htyr9H/d2z
         eU4F6kYZ0hjbFA7KSA33i8VUPO+TlYy0Ht4b5+xF6em3QG8LtIFPXY4hZ+KLpNLUr3u6
         4aciPG0i/QnHo0Vs76SVyFxMPbRHXa0aJjgXxnia9pZyLy/Gj9B552/wTuGP6rS9TYCS
         Pf8GktFHxMKE/PyMLKVwO0trIQfnIr92cNrJ6Rfru5xzreCIMTwwW+vokZcZqzF8RlUU
         b49FguQ3SW9bLVHkwmXtcyF2a/YQd9krgXbdZeg9wVxVRrr1nSVbYnD5UJodI/FZ81Ra
         sy4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DuuVaSIA;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7227d34fbdbsi2258397b3.0.2025.09.01.08.06.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:06:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-473-jaRusggRNe6QfB0GmQhKbw-1; Mon,
 01 Sep 2025 11:06:38 -0400
X-MC-Unique: jaRusggRNe6QfB0GmQhKbw-1
X-Mimecast-MFC-AGG-ID: jaRusggRNe6QfB0GmQhKbw_1756739193
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E34BB19560AA;
	Mon,  1 Sep 2025 15:06:32 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A8FF618003FC;
	Mon,  1 Sep 2025 15:06:17 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	SeongJae Park <sj@kernel.org>,
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
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v2 07/37] mm/memremap: reject unreasonable folio/compound page sizes in memremap_pages()
Date: Mon,  1 Sep 2025 17:03:28 +0200
Message-ID: <20250901150359.867252-8-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DuuVaSIA;
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

Let's reject unreasonable folio sizes early, where we can still fail.
We'll add sanity checks to prepare_compound_head/prepare_compound_page
next.

Is there a way to configure a system such that unreasonable folio sizes
would be possible? It would already be rather questionable.

If so, we'd probably want to bail out earlier, where we can avoid a
WARN and just report a proper error message that indicates where
something went wrong such that we messed up.

Acked-by: SeongJae Park <sj@kernel.org>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/memremap.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/memremap.c b/mm/memremap.c
index b0ce0d8254bd8..a2d4bb88f64b6 100644
--- a/mm/memremap.c
+++ b/mm/memremap.c
@@ -275,6 +275,9 @@ void *memremap_pages(struct dev_pagemap *pgmap, int nid)
 
 	if (WARN_ONCE(!nr_range, "nr_range must be specified\n"))
 		return ERR_PTR(-EINVAL);
+	if (WARN_ONCE(pgmap->vmemmap_shift > MAX_FOLIO_ORDER,
+		      "requested folio size unsupported\n"))
+		return ERR_PTR(-EINVAL);
 
 	switch (pgmap->type) {
 	case MEMORY_DEVICE_PRIVATE:
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-8-david%40redhat.com.
