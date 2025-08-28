Return-Path: <kasan-dev+bncBD56ZXUYQUBRBE4EYPCQMGQEL3YJKRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AC7DB3AC0F
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 22:54:44 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70de169afa2sf33425966d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 13:54:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756414483; cv=pass;
        d=google.com; s=arc-20240605;
        b=TV3k6c6Iah+3qGBor8NmDF5t7opVUJgmRDaMDv3SgCcdBbnKcsmo3QQ1Z7S7019+Wl
         tcCzSS6+7UNY7yPYEIjIWTMdLvj5L12L1yGhZexIcBv/361zXJf7ULR6/5NkMuaXLdeV
         0wPLdHD3PvvJXxLUezrqPUayJ1gtSu+Yd7eDyTuICxwDQ65Ddse9gxIr4JnJJr9oQ74H
         lWKtlm//puX+00o7VaHZsuEjS4lpuTXKqEeh4orVcY6ZaYWSA8fN2dRgluDJoXO/Sjzo
         zMZc9YHt12cKOmGAcj3ZJz91tHdxjTnDAC+XeEXgPpGK/rWubbV2KI69acoIv642SL5B
         LLIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rrjTUU2NotvcrTygqQ7noRI8EYpGQJsjKbfQT6W3BoE=;
        fh=baG50ZsqDJALdsxgz8J8htsSIaCenxhboK8UU47Y2zs=;
        b=d3C4HbXx4jSoAqoWPUzGWZMbe87FX23z+13IBzlHvmSGP3YDs6RE6IiYq6ikk6oagZ
         WQBH5xYGFIc55Yqve/CvhiD3dILQg4BTq4ImoTez6L8HIn02mKve+Wd49iQMkQ6Wg2Yh
         ZAmXcxR2FxMGzk+DX0eXtLb9wleeWv0LJKu0nZ0IdBMSvAqHzLZIfdl+88ZEcqZl90bN
         UrP5Rvwj4CHjipT+FxbbI4BVOBryjMPXT/fasXZBQwaDhR7yJwgPz+m0S0LwKw2E3jDE
         mSjqbyyRlPKiVoPR2IND52OcZL9HDqCN3U3L3kl0y2Ti2KYme5fCt0b5FIcoDnchIuRc
         AG2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sCjN9TPm;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756414483; x=1757019283; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=rrjTUU2NotvcrTygqQ7noRI8EYpGQJsjKbfQT6W3BoE=;
        b=GPmTf6/TLU84mxU9or23Nego016PBe4MKqGArH2Jms1PI/q1j2KaX5tQvigxA3/b/E
         hUrSlwbheobb/8YWz7mW9uf43DQDAWJWNOTshqnmc37pQBJO2N1u/LSRZhlWBIHpXd8b
         ZUdbGRNh0YMLrQ0JXX7ZF1M6J/MgP9vXs2nW+RRDgrew6ertS8quwF06Sthaz2X9MmRs
         AVSra0ydzHzmFRakiC7FnPqjAVHNqmzoAJ3qj6ytx0ijvvFYKst1WXFX6AL4Fe5KFxSP
         7MQ+GkEuEY74vRWVNqM/xhfhm93soHg1wx61tGnH3fUg/8oiAnx+o1r9A9PH0i2qWESg
         5aDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756414483; x=1757019283;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rrjTUU2NotvcrTygqQ7noRI8EYpGQJsjKbfQT6W3BoE=;
        b=cQGNu5MRodbe2QeU7JYDbWruwKbIJ9zMXs8TdjFeDfdz++ECYSOvvg3uIYcpTh91Im
         3mmSHpKjGYV/UV7ZaMDwrNVp8n72OixGxks444RYnc1nGZn2SUDxCAS9uRF0V0PwAZpo
         VAjjd1hJiDtb08XRQkYY7LWHm58nSx00Gt7qBqmpbopX0FIqNo4ZhxY6MoVZVf2DDZ2+
         1ZLgFQ20MSog+Och2XZjttJVLbeP16nREH+cMxCD+zL9SD3mkMQy6lfWrusTUAO19nBe
         ULqGQ516GbFJSE7C1bfEn2HKbpdDZObdP35JL3QFwKXj+vJPWcgL/2OnvppJ/Aff0KET
         oz5A==
X-Forwarded-Encrypted: i=2; AJvYcCVSMR3QdDwuen7Ko1d99tTk6KXGyYSAoJ8au67bc75k3SR362Y41xa/Gb8/XMvRGaiDFVaenA==@lfdr.de
X-Gm-Message-State: AOJu0YwY8FD403yUkYqKMB9FO4JBlyRAlyIPj1qbuNlWBEii0EAUe5zN
	x3LLZMHKf0PID/brmbTwY4lTCda2dH0+M3mA5d3qHESpWhnrwh0Yvqqi
X-Google-Smtp-Source: AGHT+IEDvmOKeliM7Gf9Pk7G6g0uyCTQmQ55U4cm7I1rTBBVQOTtjwyCsWJyRDiVuw/MIgsgoH26ag==
X-Received: by 2002:a05:6214:27c2:b0:70d:96d0:83cf with SMTP id 6a1803df08f44-70d97351b3emr319288576d6.63.1756414483346;
        Thu, 28 Aug 2025 13:54:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe0vJPR4aGZljn4x8p7hgIrYhxsK5YIk6xxwwXFrxketw==
Received: by 2002:a05:6214:19e6:b0:70b:acc1:ba52 with SMTP id
 6a1803df08f44-70df041b4b3ls21811196d6.2.-pod-prod-02-us; Thu, 28 Aug 2025
 13:54:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNxjUy5WREJZZ/O1HU5hGitiPjzW28Uf4HS08uAho3NL8J0zzmxQoAlAjx3QhAJlvqzmgrWDOvbSY=@googlegroups.com
X-Received: by 2002:a05:6214:21cd:b0:709:f305:705d with SMTP id 6a1803df08f44-70d9722c613mr302891556d6.19.1756414482389;
        Thu, 28 Aug 2025 13:54:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756414482; cv=none;
        d=google.com; s=arc-20240605;
        b=IEdVYrPNe99cRJHIDhInchBh1eBEGpwVcaD9Y2hRGSE3ShP6jDA+imnT9D3IwuKtnC
         8h9rnHaNzFacmZjVqyTl405fOQnyx6jBe9IZEocT0y7oigD8SQdJxnDyvXdagW/qwlq8
         Oihb21hihkf2DbCZu3Bks/N1rnJYW8TrlfuX2gaPW+SuYfyQysP/KTirg83+USpJoazf
         L7Y7cOYtClxLEVNfCFzkR4JPDjH+GmcBCPxCYaPTM33UgG/AnYcmxTXEZkM8Y2ibm8b2
         no1YkKgNFRdWeeJ+XnatrDhDL/xkr2Zk0EVT2TR3rj3MxofT3Jd4L1wzuapvsYCjh9AP
         RoNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ywvGPIy8PHl9G1ugzrJfF+cpNToiG/QPV9W1oXZBkHA=;
        fh=kGmHQt+14enYEes1OrQ0DO+++3SaqzFzOlO8vwACg9o=;
        b=ipOODpYP0y9wSHt6B7MWVOLYGIE6dgltBPwzzhk9EyfJnbKpfA9uL/VUG+4C5Xb8BV
         dUXkFHS7yhr+SIgBqLmvaBukAOxV7V/9OjO5HEc/hMqF3yVhHrK1gDCdxGwQp34JYidy
         JiOUXsIGyp9Q5Rhba94JuX6qLA8RfQCTMnBIEocng7hXPJ1PDYmfZHuBa+5pONt7vfcH
         71wY+p/u5tZ7sZRCDe7n5hecHnLcF43oKN1rYyzCJOatBrCxOLNiN7dmRKAnlCTVITeQ
         SAI+ZlulRM3sQeSj89k89PJ5hFSSY2XgOr9X/fasdOBOdE/iTixTD7VwOs8ovm0LxlLT
         Ql9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sCjN9TPm;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e62491debsi136876d6.6.2025.08.28.13.54.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 13:54:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CBC0C60139;
	Thu, 28 Aug 2025 20:54:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DF632C4CEEB;
	Thu, 28 Aug 2025 20:54:39 +0000 (UTC)
Date: Thu, 28 Aug 2025 14:54:35 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <aLDCC4rXcIKF8sRg@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
 <aLBzeMNT3WOrjprC@kbusch-mbp>
 <20250828165427.GB10073@unreal>
 <aLCOqIaoaKUEOdeh@kbusch-mbp>
 <20250828184115.GE7333@nvidia.com>
 <aLCpqI-VQ7KeB6DL@kbusch-mbp>
 <20250828191820.GH7333@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250828191820.GH7333@nvidia.com>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sCjN9TPm;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Thu, Aug 28, 2025 at 04:18:20PM -0300, Jason Gunthorpe wrote:
> On Thu, Aug 28, 2025 at 01:10:32PM -0600, Keith Busch wrote:
> > 
> > Data and metadata are mapped as separate operations. They're just
> > different parts of one blk-mq request.
> 
> In that case the new bit leon proposes should only be used for the
> unmap of the data pages and the metadata unmap should always be
> unmapped as CPU?

The common path uses host allocated memory to attach integrity metadata,
but that isn't the only path. A user can attach their own metadata with
nvme passthrough or the recent io_uring application metadata, and that
could have been allocated from anywhere.

In truth though, I hadn't tried p2p metadata before today, and it looks
like bio_integrity_map_user() is missing the P2P extraction flags to
make that work. Just added this patch below, now I can set p2p or host
memory independently for data and integrity payloads:

---
diff --git a/block/bio-integrity.c b/block/bio-integrity.c
index 6b077ca937f6b..cf45603e378d5 100644
--- a/block/bio-integrity.c
+++ b/block/bio-integrity.c
@@ -265,6 +265,7 @@ int bio_integrity_map_user(struct bio *bio, struct iov_iter *iter)
 	unsigned int align = blk_lim_dma_alignment_and_pad(&q->limits);
 	struct page *stack_pages[UIO_FASTIOV], **pages = stack_pages;
 	struct bio_vec stack_vec[UIO_FASTIOV], *bvec = stack_vec;
+	iov_iter_extraction_t extraction_flags = 0;
 	size_t offset, bytes = iter->count;
 	unsigned int nr_bvecs;
 	int ret, nr_vecs;
@@ -286,7 +287,12 @@ int bio_integrity_map_user(struct bio *bio, struct iov_iter *iter)
 	}
 
 	copy = !iov_iter_is_aligned(iter, align, align);
-	ret = iov_iter_extract_pages(iter, &pages, bytes, nr_vecs, 0, &offset);
+
+	if (blk_queue_pci_p2pdma(q))
+		extraction_flags |= ITER_ALLOW_P2PDMA;
+
+	ret = iov_iter_extract_pages(iter, &pages, bytes, nr_vecs,
+					extraction_flags, &offset);
 	if (unlikely(ret < 0))
 		goto free_bvec;
 
--

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLDCC4rXcIKF8sRg%40kbusch-mbp.
