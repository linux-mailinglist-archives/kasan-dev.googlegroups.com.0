Return-Path: <kasan-dev+bncBC32535MUICBB5EDX3CQMGQEMQGQX5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 727CAB38CC0
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:08:54 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e931c30dc0esf678776276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:08:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332533; cv=pass;
        d=google.com; s=arc-20240605;
        b=RpVvCBs7k8IM9KBuPIWK9ozqF3Znm0qCPIvzqLIKQUK3emtOFMfkksTCAXAYJIkHqG
         6m/e7Tt/5qvexJhF/aHI1OtMsQRWZkRTs0/7hZths4NofltaY84JG2+WIGMvSGgnxYPN
         s0yUxkNgEVFJE0jpel3maChKkTAsRC5yuIHRTk0wwwaEFhXlpfNSdjgJTnYkfWJzOvu7
         h1gzo8h16Z/x01ziQbqdPkRoKlWWSzRHvyLDCcxK5sSTJ621utZDQUVw38iOw8/xVfLY
         fqfQfA96V6SA1NN0DNY3yxo+phHzM3PDk6LbKtnpR6uCR/zyXS8Wd3qcL5OBbeAnKWNy
         cW6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ugJFlXBScn/JUlWCH5GWo64dHoHKfQKm2LN433BMRcY=;
        fh=gIex4AGv5shAKRUb03KaIdOVOI1L5qTGrbgwMNebSLY=;
        b=X21JUHqywIsW+GBd6T+FMXzMYn7av1Ys5WP0ibuLWkFmbxfZ+/ivSrgB3K3Lm/J8Cp
         IxqSppimDC2o81c0hkVziZsealFBpaxUFKZbp43WkfSVJL5uw7YCG7cBJSYi7VwTzF6+
         jhkU2YTY2lq1yoknJ6I0XLShnx26I6zZ5IKssKdX4TU/B+dXzTDpgQ9av9fOnxJHAAmx
         tKxMPnzevX95VYA/F/ZzMd4nRgcifx4YUC3KjFG/L8O2QkFnBKOVKwExbHEvTh6yu0Ot
         md2vG6CK+McD9hndLaY7fN7rFfTpWt45azrSazovV88WaIpPeJv4gi1r/rw+Jb7Z13A1
         0tSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DAkphgBT;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332533; x=1756937333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ugJFlXBScn/JUlWCH5GWo64dHoHKfQKm2LN433BMRcY=;
        b=L8bx43cjLOiOrkszT57qgP/fl19P8KbAjMNc/tLXjTtLLdZ12eiab/z2A32HJQG3iy
         IJEIuz8Lh6XwM4nFFRKHv3NXt57ayisQn8vJCOJ8BmJiq+DEdsdG3NgGLGzvXeNr5m5U
         WehxPbT3Ax/2Pm6YgRrbftn9a4zhMdPcvtnKWD7atFAlXeBxYsMOENscms7yyrBlBmkO
         c+po6WwpPm2pxSQsGWCmslauTXrA2JxGkBCHzPDE5kV3YnxmcudJPxzlfqcwrTD99Xza
         Xoji1YC0bdd2OboSFW7iaM+6xjt78xHg6VJkBt8h6UoHL+IQfM1ZW2Ll1v2hUimYUDc8
         vtMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332533; x=1756937333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ugJFlXBScn/JUlWCH5GWo64dHoHKfQKm2LN433BMRcY=;
        b=ENOIYeEPKYzfRCX0EX2PBQmy5uyJo+quNoi8q45UjiyShbiVLjS/yEMsPjRBh5Usl5
         mfGP2POeihkYuO2L19b1o3ep4Ch3kjdXd27Tqc339J0s8mE5VYBRzKB9DB702PXmO4MM
         ZXrjajDA7HS8/Cz2vRMu7IMO9DAcnWs5u95EH2tSSjhK/nwymylGYzp1E4JDpMtGilPh
         K3ZBSvVRnuhMNShLtVD3qcG2a0PW34lZCozRluM52C5LsvnworLgmUfIbInM1mO6mFWu
         3b45X3tNFGkjALuoZNZQzj1wNYqfFbDsLFXoqJMiysfMUBT83SLycFqEdFdAwH5kIzaA
         PdMg==
X-Forwarded-Encrypted: i=2; AJvYcCUeSdTXDB1e5ynuOtxf+HB+FcAbOY9TpMAtKh/zaZMb1H18DjI3MPRL2zU5jTTmz15tzagX8w==@lfdr.de
X-Gm-Message-State: AOJu0YyEh1tD9VdRQo9nowMcxro+jnNpYbVU69BJZztaRhuXIUGjzD40
	+7hVRRohohLUfb0UAfr4LeHUH7/fGU/zOMJEZpWDasZDOQsOE5x4WwVH
X-Google-Smtp-Source: AGHT+IGhLNasgwV2IHcPfimbPlV8ZfQgAq5Zjq+faWxQOpKJhiyBl/1ufSjY45V3v/ejwsYRrNQJjg==
X-Received: by 2002:a25:29c3:0:b0:e93:455b:d47b with SMTP id 3f1490d57ef6-e96e4792dc6mr6116394276.21.1756332532974;
        Wed, 27 Aug 2025 15:08:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf5z1Z/79uTqEc3oC1rkq7/58m8CGDZlKh6S1Cy2Elknw==
Received: by 2002:a05:6902:348a:b0:e93:4930:85e9 with SMTP id
 3f1490d57ef6-e9700f56d21ls84934276.2.-pod-prod-00-us; Wed, 27 Aug 2025
 15:08:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8f46IhVl6tnpGkB8uW/iVnDB/idBJO8ErRjlvBBxlJTjJG9xAL5qukRtGQDTR4hHuRB8ru9cEMnU=@googlegroups.com
X-Received: by 2002:a05:6902:540e:b0:e95:34cf:9b57 with SMTP id 3f1490d57ef6-e96e4793315mr8350711276.0.1756332532014;
        Wed, 27 Aug 2025 15:08:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332532; cv=none;
        d=google.com; s=arc-20240605;
        b=cczoKe68aObIgKU3CGE6AowdKm1XJnoAYpl0GCqRpBZrstrYBC0LYB5ksLb7mmSEpc
         WiCNUaEzH6yvDdwY10R5vN7+WeSjIKBL+CEZ7SAXLP4AlR9b8RufUgJbR2ySdElyB2D6
         afuzK3GOlpoJmT+RIUvEWUELY4MdU5zFww9Aw6c42NL5H9gZXzqVRXVGAXP6NqgzKxDO
         x0GXs3QzV5U7Jwz+TW2FX9QNazafUbZew3CcnsS1ypmIJA9d/I/JWAUW+4sw6NDC1nJu
         GOT01Gao2BxI32gvTDlTQbdlXPlkg9LLSzBOT+zagYTPbZG4EEkKxGTg6JwGSPs5Asg/
         ndxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1yoxwOMbQb1SEP5yy8swTlBLejpoyGQxYs/+m6JyaCE=;
        fh=shR0mXZN9t9LwaDOMs6Oim5HWzqSHckIEhVvNFWn96g=;
        b=UOeQSgKGBMDSoSIezmqgg+R1yndpoGaImwvtSrijW0EoM5xVcjZ8vzr5tvgpywk4gv
         tEK2vHpOp8keHUr4PLi0tXxKNbT3Ma2Ic9CqtezAStsL9/Ng0LweMq63C1aMkubo14T7
         jsNoGK+fslHqqHmSqUWyJJDebXoR8De0iDUsjXsBOgEUGJyIed1j37R2WAAHjqBdufVf
         4CgncOtBPQnckjwxliyvLuA3PtRZamPL+J9GDlAMRKT64NyRvggLs8H3BnSK/qgGxR0J
         mmzpY8GtL8AX1s/FvDs1MsoCmehIYhjOLM1sC03o/ofKIS25zqi6ZpXx4QMnjASQTdHL
         i03Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DAkphgBT;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e96e5b238e8si189589276.2.2025.08.27.15.08.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:08:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-607-cc5kuIasMpO-FgCR0RSeGg-1; Wed,
 27 Aug 2025 18:08:47 -0400
X-MC-Unique: cc5kuIasMpO-FgCR0RSeGg-1
X-Mimecast-MFC-AGG-ID: cc5kuIasMpO-FgCR0RSeGg_1756332521
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 151E518002C2;
	Wed, 27 Aug 2025 22:08:41 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 3FB8130001A1;
	Wed, 27 Aug 2025 22:08:23 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
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
Subject: [PATCH v1 23/36] scatterlist: disallow non-contigous page ranges in a single SG entry
Date: Thu, 28 Aug 2025 00:01:27 +0200
Message-ID: <20250827220141.262669-24-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DAkphgBT;
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

The expectation is that there is currently no user that would pass in
non-contigous page ranges: no allocator, not even VMA, will hand these
out.

The only problematic part would be if someone would provide a range
obtained directly from memblock, or manually merge problematic ranges.
If we find such cases, we should fix them to create separate
SG entries.

Let's check in sg_set_page() that this is really the case. No need to
check in sg_set_folio(), as pages in a folio are guaranteed to be
contiguous. As sg_set_page() gets inlined into modules, we have to
export the page_range_contiguous() helper -- use EXPORT_SYMBOL, there is
nothing special about this helper such that we would want to enforce
GPL-only modules.

We can now drop the nth_page() usage in sg_page_iter_page().

Acked-by: Marek Szyprowski <m.szyprowski@samsung.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/scatterlist.h | 3 ++-
 mm/util.c                   | 1 +
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/include/linux/scatterlist.h b/include/linux/scatterlist.h
index 6f8a4965f9b98..29f6ceb98d74b 100644
--- a/include/linux/scatterlist.h
+++ b/include/linux/scatterlist.h
@@ -158,6 +158,7 @@ static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
 static inline void sg_set_page(struct scatterlist *sg, struct page *page,
 			       unsigned int len, unsigned int offset)
 {
+	VM_WARN_ON_ONCE(!page_range_contiguous(page, ALIGN(len + offset, PAGE_SIZE) / PAGE_SIZE));
 	sg_assign_page(sg, page);
 	sg->offset = offset;
 	sg->length = len;
@@ -600,7 +601,7 @@ void __sg_page_iter_start(struct sg_page_iter *piter,
  */
 static inline struct page *sg_page_iter_page(struct sg_page_iter *piter)
 {
-	return nth_page(sg_page(piter->sg), piter->sg_pgoffset);
+	return sg_page(piter->sg) + piter->sg_pgoffset;
 }
 
 /**
diff --git a/mm/util.c b/mm/util.c
index 0bf349b19b652..e8b9da6b13230 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1312,5 +1312,6 @@ bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
 			return false;
 	return true;
 }
+EXPORT_SYMBOL(page_range_contiguous);
 #endif
 #endif /* CONFIG_MMU */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-24-david%40redhat.com.
