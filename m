Return-Path: <kasan-dev+bncBC32535MUICBBYUCX3CQMGQEPBC3XHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DDBECB38C6D
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:06:27 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70d93f57a7bsf8996886d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:06:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332386; cv=pass;
        d=google.com; s=arc-20240605;
        b=HBtU6Bbw1LeVYx3m7AwNseBJu5pxnLw8vuAz1MrIfeExRKw/C9AIQ55Dq3e2fT6bGz
         zHAde2YQh2GO84v6qEA1VV9FQtr9Rl1/MgA/iyhbve8P72UPu+DW9SHqrkSnjCgTdDpT
         gboprBVMWj/hbRQcQLRKzcF89VEb06/U2QutzcRz7p6dwDuBYFD9RSLdiyrxfAIZG+AI
         Ju8WmuT/z1szXa+CgZa6mhk6BTaZ6XHsWn0m1vDG3jg0ObLxrDBjhTD9oed95/FujUKZ
         CcURVO8nqXeVjtMzASICgrrYsOLT3HK84xQ5tN1L7KNEwMMuNKM9rBJwjcZD3pL5BBj/
         /GVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xisGo/LOAuAQLsyh3UuH6HIOrjeVuwJnfulFpNGXshQ=;
        fh=jZ2F+ILRxKInlQYohcd8mosbpYZTrq5Bn5DXYbfIrh0=;
        b=djQ5JnkUp4CcKMtP0dpVFv9IZVSixlbTlK/J2xduSyoJqbWklFrDCXqvJPvXH+moiw
         FTPMUmwHcnNwzXa7mTDD6PrkzD/G4HE3Cw/WcuaKwPAvjcPV9JJhFkgnpp9WQUh86arI
         Pk7FZOolC/li+ayi72e/63ZAHIy/tQbQO8WvkIzrD0395PlUlRq+sKe3JLtNLcdszhDK
         MKQNQOJW4TySmslvLr3BavB+w2pHsgVyWtky+Y9HtQdqJeHH8mY1oRDbSo+0iuzX2pim
         1LkbgPu12PIoUM4mzE+cx2u7gTXxtHc2maKpwLiKpnBlU62Gvk2pI/rqgXFZ11XZ5lfx
         Gp0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PoXHJwEz;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332386; x=1756937186; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xisGo/LOAuAQLsyh3UuH6HIOrjeVuwJnfulFpNGXshQ=;
        b=vP3iO8nK7Sv6fqH5is8rNVlEDHbhrVopviY7bdGx4fTlibRBBLOD6/SWWha7npGQcB
         ig/PjtNLYXSISFhojxKw0VP4WT+nXx6er/R6ICjnyLscvgc/moXKCS52TijNazG+KS8M
         ryElavxu0deDgKQO2pfrvCIHcWTJe4/JkmT5poalRwL/VJ59tiffgAQPP55gCyG3jki1
         R5FjDpe7fLeOyF0JT4kefvohiZiL0h5IdYQ8N055uSjTNBTycz4l6LTFPIjppDGH3mHv
         XMraqNQHCt38Kz/NlWNM3eg1dO8fTSGK3C/N2FzSMG+r92MGJ9ebiYm08JPrlilrPDfK
         Glbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332386; x=1756937186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xisGo/LOAuAQLsyh3UuH6HIOrjeVuwJnfulFpNGXshQ=;
        b=SMs6EKcyIb248H6IpbdUCopgxi6apE3Eo8XULaaU6WhAlM7e7MN43QU5DhHb1uiyLW
         W4oUzSwzhUOg89YCdxJwPvjgJ5e+hbUKLQq8RiKm24lPhPjkSdilNexzKuQQaZI12EeQ
         +ay49NY/3lfCcTd8TdD//dDIEVclNcJ1y5O5+phGKfGsA+dYrvHc4Qh1gyjId8wjE3vd
         kvMkW+U0YrPtDya9qkqoVT9ACEy1jc57d6K54uOdmwBD4kuYSIR6xeyHTWb5KGSIbDzg
         E2HgP8R/X2wDsSysssgQPSFFsk0H2DNeGY5XMdNIw1VsKNdeaXRbWLxmjqIlbeWAuxsk
         MQOQ==
X-Forwarded-Encrypted: i=2; AJvYcCUycxTxPxV2836sxoUrWC//c8ixrqLNVegT1ZEgAi9+f41CfqwOH42TGN/91wHAlUM6B48FvA==@lfdr.de
X-Gm-Message-State: AOJu0Yx1zDzdljGADRNXxZl34x5he4TBfWW0qKPLGQ45+X2o2g3D9869
	dCL2NaiOVQgGa2teedDcNKOKPgMsOHmd+1nkK3lIxh0Ju8cQE6yZH3iI
X-Google-Smtp-Source: AGHT+IFO5nqDXrsCfgwX8zFBw4QKxxddJZnkOAC7xxzUgeTfiJAhdlEKd4zpe4LC7MHkcgvvCrktBw==
X-Received: by 2002:a05:6214:c62:b0:70d:edda:f4f8 with SMTP id 6a1803df08f44-70deddafc48mr17189526d6.7.1756332386397;
        Wed, 27 Aug 2025 15:06:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7reYmypzD74M9EFjzdFnWgOKMGLK5aK/8buSeJ5Crfg==
Received: by 2002:a05:6214:c43:b0:707:56ac:be5f with SMTP id
 6a1803df08f44-70df00ae722ls2424546d6.0.-pod-prod-05-us; Wed, 27 Aug 2025
 15:06:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYx2YP4/Hhye4Xxa0cu4KtUecF1SA4GG6pMwaTkBrU12b/ad7bqcbUz6MFcxED6VupV6JRHk0AsP4=@googlegroups.com
X-Received: by 2002:a05:6122:1e14:b0:544:6ede:a9d with SMTP id 71dfb90a1353d-5446ede0af0mr1364839e0c.13.1756332385651;
        Wed, 27 Aug 2025 15:06:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332385; cv=none;
        d=google.com; s=arc-20240605;
        b=Zg/2abYETkzDj7XIAs5mkBkPADLjLI1FQe7ZaD7QjHjXhGC8oDmLU0Ko+MfCzNbWNA
         TJoJ2iu4FOZtCwP8aQEj/z3B2Bzvdb7imhn+E+4rsSMGGvrliXfYCfI5+y83aOkvp5NY
         rUSxEOxFXuiBUGqhEWH+SND9jQPQvNvy/gkJGOZKBBI0LWvtrYMyCSvxY7cgTMqsWqA/
         dNIKwPE7UpKxHeuA2AIEXTVHpqL3ZfiPwCnYwWnWmB3MVJdgERn95eeep/P04SYnH6o/
         gZBCLPsvin2zKcKnAthK+X6p2x3O8AG+wZ5p86gP5gX/6claoFwXi8AoWKyTDRhDL3+q
         +xbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TaqjYk7qiFpFT4dP16wKMuC8fiQfbkUwRRgQVKGzHC8=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=R2GaMhNxbZGb33Ihdz2iy/2GX58zBU8VhvXopJvbahDcGDc02FIndkJap3ruEMzW/1
         NfyG2fQyUChB10KZUgxNGgEhgp9lfsW8p6gR98YZUZgeJjzkHYRqBBK9HDUvZYFEsXLr
         yEKA/jFW6vtkjmxPwi9QvxYMnuiSk/MEl9PXPRR1MvqkRvfFzFJeLcM8bo1WL4N86ixc
         a6F2o0EK31D2EpFYuxnbaveSNFZ/vnWu/GeeyNP3bqdN4y5WKiT+PYADg55vRFLa+oKQ
         kzBvLcwyur7pomYvp92cX0TsSPFll88byPfAnx6eLEyMgpkt2gXUtJ/4N2IruqL4lnk8
         +gcw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PoXHJwEz;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5442b1d7933si163243e0c.0.2025.08.27.15.06.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:06:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-154-990HNXa9P7CWji11STEtIQ-1; Wed,
 27 Aug 2025 18:06:21 -0400
X-MC-Unique: 990HNXa9P7CWji11STEtIQ-1
X-Mimecast-MFC-AGG-ID: 990HNXa9P7CWji11STEtIQ_1756332373
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 36F19180028E;
	Wed, 27 Aug 2025 22:06:13 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id B193D30001A1;
	Wed, 27 Aug 2025 22:05:57 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
Subject: [PATCH v1 14/36] mm/mm/percpu-km: drop nth_page() usage within single allocation
Date: Thu, 28 Aug 2025 00:01:18 +0200
Message-ID: <20250827220141.262669-15-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=PoXHJwEz;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

We're allocating a higher-order page from the buddy. For these pages
(that are guaranteed to not exceed a single memory section) there is no
need to use nth_page().

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/percpu-km.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/percpu-km.c b/mm/percpu-km.c
index fe31aa19db81a..4efa74a495cb6 100644
--- a/mm/percpu-km.c
+++ b/mm/percpu-km.c
@@ -69,7 +69,7 @@ static struct pcpu_chunk *pcpu_create_chunk(gfp_t gfp)
 	}
 
 	for (i = 0; i < nr_pages; i++)
-		pcpu_set_page_chunk(nth_page(pages, i), chunk);
+		pcpu_set_page_chunk(pages + i, chunk);
 
 	chunk->data = pages;
 	chunk->base_addr = page_address(pages);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-15-david%40redhat.com.
