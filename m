Return-Path: <kasan-dev+bncBC32535MUICBBFXQ23CQMGQEW2OJSUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 97D32B3E902
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:13:28 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-24a8dcb3bddsf22676225ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:13:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739607; cv=pass;
        d=google.com; s=arc-20240605;
        b=S9dwms49Xxg5+oIEwx28JLVjK6dTvS0Z8uSdMOPRrJSa8kPB11PcLYC9XbrgBEH/dB
         zDvaoBJx4zQ9C3BI1QW+AkTmpga6cUWz4LVPCkw4NMSPrIAxhwCsF4VriOTxfsjik2MH
         biaIyOHykS2y/3fNmLFlPQB/+m7FJiyE/CEHzyPXkf03lhGKgKWja1Cogjsgw93RHitE
         83LdcsbGGCrf5Tiblcw4HENLnXqcIoCLDOJF+gjRs4cx1nuxLo7cm34xrq0Erh98msr0
         0jQ7DoYbKuYA7dahU1/k35fVItbo7cmBNM+ipmkghQDSnd53xK4SlfIsjSCOec0EUTb3
         0Ulw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=wL2VcmnyuMBNntcA7tD1Q+Kha+n2ym822AYZWDCXtVo=;
        fh=OLDpdR49xIB6K7QSzCQ2/2uxN9elJSGwbfWIOsmo1ME=;
        b=g0HTqgmnSpxhbxLHB5O2Iitg1i1hzEui1R00q8h4Kci+TxWHvGIaIBsJPJSu+iKMy1
         Issf37G6NjWR1LOBKHgQlsbqhgd8oyOTeW9E/NqQct0Kx/k//1u3y7SVMwzQL/BtLVC/
         Z74XQaE+zQ9B50UCJ2Q4yJwk4/LlQE9zr0dgLp1LYYrlL7pNJKFf618DPovuaq2JHtDk
         OSFRTNdCnfkE5llwPiXyRki+3AGnIQUCl5BJ41dQvLi37AjYzNveUuA4h4QIoHIB29AN
         +4vfXfmI5bIpJfJ+frXAivN9rzZnhMWsWHM0UazxYyR2g7HncBmwuCbTA77Djm+Jg72p
         Wr1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Xjlj/klo";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739607; x=1757344407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wL2VcmnyuMBNntcA7tD1Q+Kha+n2ym822AYZWDCXtVo=;
        b=pJ2+ItspsRr9ioBkslKv2SoO67SwBjBvfrRlI5JFE+uXzHqptyRJ0hnzmkvlAMJQ08
         QC4uRzddYvh0QOaNwLTkQOOClL8M0+ArVCifo3wJMObUie4LuWnOsFI8yUwv6EK17zmm
         HL1gi+rmoRUYhH0i3H60SSVzVGhp7b7PgmHiiNi5exmX0EXZbfE0E3WSDZ3QUIhBHzdR
         A5ixbFHHvD3nTNrhH+xaPgFmUReQOO2Fb5mYLi2jXd2u6HGF+25TEQ5Yl8cHENwWEk5X
         O5EJQlQF5bTxf8PpWHIKGaO18i4a6CrfLxKSd2VcofT8AoyNGML0cLUj4V3sz8H7+d7P
         T81g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739607; x=1757344407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wL2VcmnyuMBNntcA7tD1Q+Kha+n2ym822AYZWDCXtVo=;
        b=Tl6+1wA2vLvBS2SdoFZ7j3P7TNAI0fOUR1UN2vi/UnE2ztrUn0J9ExAhzYtI3vu2gi
         BQjHC/gUTO946c8k6npj8gp7ohIfon7n3FNXWnsHEJsiyyXCsb5KzTkcVeF+1NRFqJjR
         rkj6zcE493lsuaN09SQF4HEVAgdakc8N3/ZdQMdsCs9gWwgqJjFvJ8c0ItpEV2bCqJxn
         6HrpXsKjelSVadFfr3psAWBfBvWjoOJDNVPhVbFcNzOFCVF2VACLatR6hV1LEzUfTRHk
         17NJOqQ8POyk9Di9NrP2ZSLsrmz7/IwMukWAHOcWNGD6Es0PIY9SZMScr+rABa45+9oV
         KZ8Q==
X-Forwarded-Encrypted: i=2; AJvYcCWezzZxiY/Phgn+B3o66B/AAFA3JA3xoEhmLx80WtduvakF+PVoeGEI9HBIjjR34qtaGpv0Zg==@lfdr.de
X-Gm-Message-State: AOJu0Yw+rK8mmL+zFpeumqY2ytWCQsqdVNRPgXUq2ORJWvjI1fk8jhie
	R75NWtX4zXyBqirqC4N7R/82u4oM/sJwhZJc+5Tno/OGVP30KFVJFw56
X-Google-Smtp-Source: AGHT+IFTB/RhwrkrMuwAVMTvq1C8kzlWXv/gntwR/vnqKRoCXCcCVyfGraxWYVChKwQ3ADlfRa5jUQ==
X-Received: by 2002:a17:903:38d0:b0:244:99aa:5488 with SMTP id d9443c01a7336-24944aa1ed5mr96800755ad.30.1756739606895;
        Mon, 01 Sep 2025 08:13:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdV7vUQIUCr9FhOGyM/UFy3jT9anP7LaYRo8eYdV4JFHA==
Received: by 2002:a17:903:a08:b0:246:5a45:dcdf with SMTP id
 d9443c01a7336-248d4b225a5ls29507885ad.0.-pod-prod-07-us; Mon, 01 Sep 2025
 08:13:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2H9t5q/y9Nf96MK9cs/z6k2u4CPeewBpyo51QbSh24jCPP8mwsRTSCNqPTrEcxyWubMam5tPkgkQ=@googlegroups.com
X-Received: by 2002:a17:902:e80d:b0:249:308:353 with SMTP id d9443c01a7336-24944ad2e89mr105568495ad.41.1756739605509;
        Mon, 01 Sep 2025 08:13:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739605; cv=none;
        d=google.com; s=arc-20240605;
        b=WwF6lwxEBFxifxVvbvLYz+KFkj0RWw5g6ndb06DDZIMlPzF0k4t8eXNcgrFr+cXHpo
         cfeHuphntednFrVidkbDX3ep4ymeEDFDTOLxfv0SETTiQEqJP3Z0+bwVq/6dm9Da45mH
         d+/JjOYLSJg0fEmkDeorvDKzsS3PoLCu+ZQXvV9wqWD1gAFryIkmilRaoJ+MpoEwSpIg
         m6y1sFfSgbmyyd+lTIsq1f/R/YaI6573WBlyaeiRbPhKyRoVUlO1uKJr4u831APF6sja
         Z1Jfc2fHq+qqgxTzNIiazAfZMH7QEJcEmEER1JZdJFfhS/Tp9qIeTyj/ajvNyPN+qvA1
         9Wag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vm1zVGjW+sGlJ+HurCNe9nDe0XN3JBuCy2WCKHoB7cQ=;
        fh=WMY5iOGRw0p/EzISBuyANyxsmtdgJtDuGjKOE/rBy2Q=;
        b=N5KOVzWdn8XGmDZ3KyaCD29FmkhaudcfAAA8gOlvn2PgaMOMeR2mYM40TDYGlC+a2/
         tWj7K4RnvfUL/eqn/UfmLzsHmgOXO6qFGK3Bvh6Pj4juR+W++UuevwPzkQkS3zGmtHaR
         b5+CmiQRIO1NmLQKL9c5JdMF29hQrPjPYY9J4PXMVZZwIZmYOKqcaqaJr/2pTD0tENDS
         V2T1v4zI+4xXu9uXi+WycPRPjoWXqgpwgu1B6ig1xoy7R81OTdYRMiiyO8UOpUNJpNgF
         D56H9SyaKEguE176Un+/57qxxcNBNi1mKesVdUj2MbLrt4OtVzdFxGuo9nHJlTv74NNM
         pZ+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Xjlj/klo";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2490371b344si4054655ad.2.2025.09.01.08.13.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:13:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-595-l0sCqX0_O9e7dNlURLW9hw-1; Mon,
 01 Sep 2025 11:13:20 -0400
X-MC-Unique: l0sCqX0_O9e7dNlURLW9hw-1
X-Mimecast-MFC-AGG-ID: l0sCqX0_O9e7dNlURLW9hw_1756739595
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 054DC195C27B;
	Mon,  1 Sep 2025 15:13:15 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 1D2821800447;
	Mon,  1 Sep 2025 15:12:59 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	"David S. Miller" <davem@davemloft.net>,
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
Subject: [PATCH v2 33/37] crypto: remove nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:54 +0200
Message-ID: <20250901150359.867252-34-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="Xjlj/klo";
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Acked-by: Herbert Xu <herbert@gondor.apana.org.au>
Cc: "David S. Miller" <davem@davemloft.net>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 crypto/ahash.c               | 4 ++--
 crypto/scompress.c           | 8 ++++----
 include/crypto/scatterwalk.h | 4 ++--
 3 files changed, 8 insertions(+), 8 deletions(-)

diff --git a/crypto/ahash.c b/crypto/ahash.c
index a227793d2c5b5..dfb4f5476428f 100644
--- a/crypto/ahash.c
+++ b/crypto/ahash.c
@@ -88,7 +88,7 @@ static int hash_walk_new_entry(struct crypto_hash_walk *walk)
 
 	sg = walk->sg;
 	walk->offset = sg->offset;
-	walk->pg = nth_page(sg_page(walk->sg), (walk->offset >> PAGE_SHIFT));
+	walk->pg = sg_page(walk->sg) + (walk->offset >> PAGE_SHIFT);
 	walk->offset = offset_in_page(walk->offset);
 	walk->entrylen = sg->length;
 
@@ -226,7 +226,7 @@ int shash_ahash_digest(struct ahash_request *req, struct shash_desc *desc)
 	if (!IS_ENABLED(CONFIG_HIGHMEM))
 		return crypto_shash_digest(desc, data, nbytes, req->result);
 
-	page = nth_page(page, offset >> PAGE_SHIFT);
+	page += offset >> PAGE_SHIFT;
 	offset = offset_in_page(offset);
 
 	if (nbytes > (unsigned int)PAGE_SIZE - offset)
diff --git a/crypto/scompress.c b/crypto/scompress.c
index c651e7f2197a9..1a7ed8ae65b07 100644
--- a/crypto/scompress.c
+++ b/crypto/scompress.c
@@ -198,7 +198,7 @@ static int scomp_acomp_comp_decomp(struct acomp_req *req, int dir)
 		} else
 			return -ENOSYS;
 
-		dpage = nth_page(dpage, doff / PAGE_SIZE);
+		dpage += doff / PAGE_SIZE;
 		doff = offset_in_page(doff);
 
 		n = (dlen - 1) / PAGE_SIZE;
@@ -220,12 +220,12 @@ static int scomp_acomp_comp_decomp(struct acomp_req *req, int dir)
 			} else
 				break;
 
-			spage = nth_page(spage, soff / PAGE_SIZE);
+			spage = spage + soff / PAGE_SIZE;
 			soff = offset_in_page(soff);
 
 			n = (slen - 1) / PAGE_SIZE;
 			n += (offset_in_page(slen - 1) + soff) / PAGE_SIZE;
-			if (PageHighMem(nth_page(spage, n)) &&
+			if (PageHighMem(spage + n) &&
 			    size_add(soff, slen) > PAGE_SIZE)
 				break;
 			src = kmap_local_page(spage) + soff;
@@ -270,7 +270,7 @@ static int scomp_acomp_comp_decomp(struct acomp_req *req, int dir)
 			if (dlen <= PAGE_SIZE)
 				break;
 			dlen -= PAGE_SIZE;
-			dpage = nth_page(dpage, 1);
+			dpage++;
 		}
 	}
 
diff --git a/include/crypto/scatterwalk.h b/include/crypto/scatterwalk.h
index 15ab743f68c8f..83d14376ff2bc 100644
--- a/include/crypto/scatterwalk.h
+++ b/include/crypto/scatterwalk.h
@@ -159,7 +159,7 @@ static inline void scatterwalk_map(struct scatter_walk *walk)
 	if (IS_ENABLED(CONFIG_HIGHMEM)) {
 		struct page *page;
 
-		page = nth_page(base_page, offset >> PAGE_SHIFT);
+		page = base_page + (offset >> PAGE_SHIFT);
 		offset = offset_in_page(offset);
 		addr = kmap_local_page(page) + offset;
 	} else {
@@ -259,7 +259,7 @@ static inline void scatterwalk_done_dst(struct scatter_walk *walk,
 		end += (offset_in_page(offset) + offset_in_page(nbytes) +
 			PAGE_SIZE - 1) >> PAGE_SHIFT;
 		for (i = start; i < end; i++)
-			flush_dcache_page(nth_page(base_page, i));
+			flush_dcache_page(base_page + i);
 	}
 	scatterwalk_advance(walk, nbytes);
 }
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-34-david%40redhat.com.
