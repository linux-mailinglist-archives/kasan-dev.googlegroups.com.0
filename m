Return-Path: <kasan-dev+bncBC32535MUICBB3MBX3CQMGQEEL4QWRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C5C2B38C32
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:04:31 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b49da0156bdsf446411a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332269; cv=pass;
        d=google.com; s=arc-20240605;
        b=IOqoKifV1lN6Yo0+ZC714pMPXGQGkSz5/PzVQWRgrujW8DafjnWz2HhLMYPIm1sDSN
         yHsypAyrLL/NVWAq7MCEOXsOj/iFJOuHZ7yYnac58Obaa6iThhAKI3uweqTFt4swud5j
         EprcdzXFq/6GB0jSs0c3o/i6s5zYdmYyycbih4gWBXg+5+eZizqPo0lMvK0+YmYWS0ea
         6AkgkAtBlk71utCWW5+PhbQJsGkNQ1icz/RdkRAIpeDyMPESKJM93GBNsbhzldGU6sKA
         FgVkAn9kNfVvb4xoZWux85f592pinKlFddj3GNUcCVR7tesv7jphTfph+UVKNwAAaSzs
         G4vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=KVQDFR7vZypwSUv8eYpiGTjhIWlsjl1hbRSlXiRxzdc=;
        fh=a4rHWoAbT0ZOlGznPrCJx1RBWdD18VqPF7djP1RDErw=;
        b=WLiT7gzlvZhvGDj6e6Iousv+lwKxHWm4im4chLyFfg0A7ikZPaekukcqNZLKYQi+aq
         GQFbIqKUaanmNnC4Zh+BmczYWuUWRDLODO9+TUVyhZiAEGBirhNi9caJdtNG8tAun4Q9
         gmvFokT9X9BKYGgcYzlFKO2drqpNMCCPc+6ujO1L3D5MIS5eQIxEBpe+DMoZ9cmyE6OC
         dj7CmwLyQXKJX0js0oTc/moPWeNNcF/bW3om/EoyjgxVk/0IUZRr5jdIzfKiEPspZklM
         oEDVZ/lhn12L8daiue0xzUre0hIgnnSJ9EVe+odtpWNiJRiR5xMWjR3oAslGXzf7NTHd
         uzjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UnMe9JRW;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332269; x=1756937069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KVQDFR7vZypwSUv8eYpiGTjhIWlsjl1hbRSlXiRxzdc=;
        b=BibIfp880KyZmsQ8jJHUsKkNpiGJdMi1lz6ty6kSa4zt9VFlNumJIW0/290jgflYxg
         WO7pIAm6TvHlja+2cs7K4gLMCF0Be4iLfho52WMqAdbfErU5bjaj8cDaTEkhdPwOuV9Z
         nRurjzPyfmEgced1AbydUiykCbpZAdu1eK77Sbwzdy2PzuL/t81otfVuZH7x7TjbWKSg
         h80yvu7QDTxTqBSKu/8C5qdTaJOi93AB1IFmmHh44odZ5KnAxAnUswjjeokARNXhCb8N
         gfq3omSc9wxMsM5k0q5Rt2jxZ2hB+n9v79RcnGa1+nZ8bsNYtZXO/ABfcflhb2+809vY
         h4FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332269; x=1756937069;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KVQDFR7vZypwSUv8eYpiGTjhIWlsjl1hbRSlXiRxzdc=;
        b=PtkNd2AvnUbl0/VqG2V4v/L5H2+N716FD0kUgUbbhXPYC8MTz+DvaNKHUiVypOpPkT
         fX0+guvj8RG0N3I/ra9f/NVSG9IwTx3qNJGL6I77R9dGoex13gLGiJEwgxqnJWkm/qiN
         x7+7+vzLGll9cdRk2QPqsJIzY5cqyeVx/BbZ7iqIIkCx8X//NASeSCOAoGPKRkTgpvgc
         HLjwJa6YVGPFtGM5jn7oOY2uIQ5Irec71qSci3n8yVu4uFNr0Ez5dBNXzRbMvzKeb8Dy
         SLMTrdifA3Nhv4UiOMKBriZF4fVTfTh3ARFm9AdHbxzQj7GxyAEtAFDlpDcLMCZmgsMo
         4USw==
X-Forwarded-Encrypted: i=2; AJvYcCVT19giQBtE/Yhz69fvWzRx2zdQTriz0ma3cDMbr1GPh9URIYkKptb8icIHjD0cZ5mvciT1eg==@lfdr.de
X-Gm-Message-State: AOJu0YzzYs2epSgJbjiCEHryWWG1Wg2AwDIzX89bPXtGaED1pLKuwWE5
	qOXhbgfxhDaRpBlSGkv9F56M1zP8k5k2qTG8NpwkwsYhQLJkaM3DBZiN
X-Google-Smtp-Source: AGHT+IEX1Nsge0j9IvoNx+4sXpMtiHeKYRihLXigNjo0ny5ga3gtS811VHNEeuxFqXDToZSaoiXagw==
X-Received: by 2002:a05:6a20:939f:b0:240:c3d:2449 with SMTP id adf61e73a8af0-24340d1c795mr30847139637.42.1756332269435;
        Wed, 27 Aug 2025 15:04:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdX21XxvIEa29lnu1txjjvYQa7Kzn9WwrFAF3X3rsUddw==
Received: by 2002:a05:6a00:3685:b0:730:8472:3054 with SMTP id
 d2e1a72fcca58-772181d2e99ls146866b3a.1.-pod-prod-03-us; Wed, 27 Aug 2025
 15:04:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/i5zI/Prf2gmK5Zl10eTNF+u57YrrFUiOpKZ84Kq5mLdySpnwpT1U4JIk3qZBkcQDRILmpI9hLoY=@googlegroups.com
X-Received: by 2002:a05:6a20:72a0:b0:243:15b9:7660 with SMTP id adf61e73a8af0-24340d6e2ddmr33928955637.58.1756332268020;
        Wed, 27 Aug 2025 15:04:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332268; cv=none;
        d=google.com; s=arc-20240605;
        b=fvzyr7MveSxLiVYoqzfHHFJUYAOO1Pcr5idGNGawkDkwZNc+tgkDCwnGOKWH6rCm7R
         Byq6TcILIDBkzNqibG91/1kteArQoKm1yu1m0o31S9oRVIp9Vwuud51GVoYCgWHwjNl2
         yVXvZ2QaZTFJhPg63dBmX+BAqpoy5grlyzkB0FT/IkzCnoe56g8/YzxhiTnML6ck9VEC
         KnLEjZkyXQqS0upbEoUx1G/tC4x56v1jaksc/hsSNfNQtYDQYGQV4ONeL1ahz+9v2jGc
         uDsYULDQ58X/rAs+vw/uAZTdPNSRyH+CtfW47j2anXKLmCRkmrNDQtPj7ot/KwT+RzJA
         3VWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L6FCsZfzSN7fAFSGFsxI24ix2lgnSyrxfbvzUHWhoBg=;
        fh=n/mJ//t0/mP6hTKUffRVS5Ay+9Y17DBg7Nbi5vCzL+Y=;
        b=fraixD9tusngMqfCDlh2QJxOZ1jA5YJhPnQKpFnI0mkI8AtnxuvwzQAgxG8yo1ISoj
         FDKSSSd5kmezL6kVjgNjCPiIr3khWi84/2k9XaYkcSgX7W5HGAD4oDIUqzSWkpUjoz54
         zx7S6NEPsRQZieL6BhSBk8WA2zrO0p8HpeX3Mx9dmyrtwJ+spXSf8C3PQaaC9kGkWJ89
         cytvBgooOyhEIJune+vlpx6kCt/3hg9LcFWfoO3z5/qpmJFv1cO/JEdWGPXxBWxVkYTh
         NFzslSiM/pMenwDurZwYSxu0t+5ZmyQYUoOejHE+BP934hoMF0+pfwuRcBwclWIZi9Xl
         E8VQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UnMe9JRW;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7713e9379f0si462085b3a.1.2025.08.27.15.04.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:04:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-687-DyeoCm-sNhqCtBzBrbRJIA-1; Wed,
 27 Aug 2025 18:04:25 -0400
X-MC-Unique: DyeoCm-sNhqCtBzBrbRJIA-1
X-Mimecast-MFC-AGG-ID: DyeoCm-sNhqCtBzBrbRJIA_1756332260
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 15140195609F;
	Wed, 27 Aug 2025 22:04:20 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A03B330001A1;
	Wed, 27 Aug 2025 22:04:03 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	SeongJae Park <sj@kernel.org>,
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
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v1 07/36] mm/memremap: reject unreasonable folio/compound page sizes in memremap_pages()
Date: Thu, 28 Aug 2025 00:01:11 +0200
Message-ID: <20250827220141.262669-8-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UnMe9JRW;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-8-david%40redhat.com.
