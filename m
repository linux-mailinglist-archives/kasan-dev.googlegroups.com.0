Return-Path: <kasan-dev+bncBC32535MUICBBEUFX3CQMGQEGIXX4SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id CD1E1B38D10
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:11:32 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2487543a4f9sf5984455ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:11:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332691; cv=pass;
        d=google.com; s=arc-20240605;
        b=L/3N+mGgZKIgTKSQkN9MIDL4aerzo1eIE5KKCAZJKUvPWgIGcq0l1UJbjqUzvEtEWM
         2/nvOFVeme46wFR1sK1EFsEqSqggzViLbOeQ1i8SuSLP2KeRrUpX31pO3ZaLtEzT+of2
         cQygfkXfRoKLkiM0XLaC9ODi5ytG945wB/Qr/Qxp4abUyanIbCk2qasYYF8wmmIq1nBR
         9LbaUtwXqAEgzwfFn+sAWIRpGdNDIj20x1p0reNmZde7JPsUEDTwdRss2YgipyVjlRZr
         hZ5fa9c41cGqIqIzpVJ4zsGORCmfiADNYm4TtNi7m4DIj/EsWPCPdcMxKnlrmRypbK7A
         Myag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xuha2NtuxkvbA2dRYeC4duoIXC4RBv9ywMRwzi7AZGE=;
        fh=of/hh4rgMBF79dbBBywjKdS39jZwRWOSTZHFF/fzEn0=;
        b=OyEoIs58IJbVMIAHRso2SeuXnuo0OEEtC+X8W8sBqWiy7rOU9qaFPvLb1ViqthRAyr
         ZSVAJ+dulBTgSmFEZ20GJWrt73w2Kghld3vPjZOi1wvYae8T4GVRjhAdQCR4xu1BLMk9
         cvKhtGPS1PYETpHwDITcBS5Tq+/CJBnXTTao4gsKf19cpjRooYYJbFGAbIn7YR3zyYYG
         SEt4dWALmG9xPL6ebUZaw9vBivNTpgTnucrZDx4bQ8bfPrvAhSt7sqzMWkCiyJHz7NNY
         rnET2/gigP26AkMUcjqA4mj58UR2iGUSX5zp8eX+DK14NdtVOktha91Q/RYfrDbpt/3M
         DXBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fcF7mI6Q;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332691; x=1756937491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xuha2NtuxkvbA2dRYeC4duoIXC4RBv9ywMRwzi7AZGE=;
        b=AgAbtY5GpxJW9TOZVD+TOvPk4kO4PcefPAxdNM+gSWKLnz80KLdNcBoZd2Z/3YTgh/
         PRFNWLNfy1LcnN/dN2Vl//gOc+Vw7x6OTuYpKlXwQJW5NKguWBGZXIT5cze91pxc2uFW
         U9ewyJdV0tGQ+wOrpbk7lh3VOTdsK0QZDAiCJB17H6hr0eD0POKao8rsGCSQRwmUX+fB
         uM0s24bfic/K8ImtLJ0KObICeLLiIHyfQtdprhyU3DIpj/7dEorEFKQTWHxox9FrmtNZ
         AIsNUH+29ogrnOSPH6UeZZ7ac5FXn/MlrDwqZ1j/b8niG4eZ2qBRsVWm7g848Rjzvu6j
         FoEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332691; x=1756937491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xuha2NtuxkvbA2dRYeC4duoIXC4RBv9ywMRwzi7AZGE=;
        b=jhS9x7Kb02rM+Xe6dx+IegCc+FnOiA5yb9O05xe/WC3jkXTITzFU6s1IMHk1tKHkEr
         NqEsrLFQasaGKvn6JMQun83YiXGZ5Ytk4ju/XgQ4B8WQHLyL+9ITRltNaapO3Ytrq+qt
         mNyVzuJbyinrjFsqcfzdzHgD6bt0h5dc6+nCyqmz1vtFVQlGWOkjICUYEHCz9pHv06e5
         k7SNfTA6QpnCSrKniTqPXuyHalqb0H+7xqWf1IKh/12Sgbvw5lLmPz7jEHoi3UKnXNP2
         PsZGNw4cuHNGHxX1YE8eejPdZEb3D1sxPdck+Wq4SSG4EazfBBgZFzenqJE6TKcMmmyv
         s8QQ==
X-Forwarded-Encrypted: i=2; AJvYcCUkV5IFVOC7/7QuEqjZFoA4aXgzuqmCA6WufSWqSMAkWiIC6pvo0oJBVYiqtanxK9lSpxeebQ==@lfdr.de
X-Gm-Message-State: AOJu0YzuE/Uhi/qyZCAmfVA199kxFBCrJdhgOJ3PZ4gCaZxpVXSI+kxJ
	VrqihmwQpW9mSw3ih6CHSnv8jiD+OqMUgdf/oGEd4p9FIqXHq+g79nK0
X-Google-Smtp-Source: AGHT+IHV5liObyTV1umdFAFiuh6ay4ocIuy73w21N9GF4oN4HGPqgnF7XXDEEQpoxaFrDQqOXSnQ0g==
X-Received: by 2002:a17:902:da89:b0:248:cd4d:a72b with SMTP id d9443c01a7336-248cd4da80cmr15993145ad.20.1756332691174;
        Wed, 27 Aug 2025 15:11:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe0Dh676Zras1Ls1t9WCjLAuN9YAl5ugPP7Vkt3ZztxOQ==
Received: by 2002:a17:903:288d:b0:242:434e:6d22 with SMTP id
 d9443c01a7336-248d4e7916dls979215ad.1.-pod-prod-08-us; Wed, 27 Aug 2025
 15:11:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjLKlxPHo84uQiaAf1Ceo+6IxcATZMq4YSAfQ3wb22srdYZg3aIeSxOP3plzT+M/P3i4vwrmNmttA=@googlegroups.com
X-Received: by 2002:a17:903:1a88:b0:240:671c:6341 with SMTP id d9443c01a7336-2462ee9bb60mr332599195ad.26.1756332689617;
        Wed, 27 Aug 2025 15:11:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332689; cv=none;
        d=google.com; s=arc-20240605;
        b=b54xFli2/nZavgJh5kgY3PvgPQswC1z46SbaZjjOIiLqVghNzpNYEmVLTmp1qiRA84
         VPre525nJ17uMv3KJEZXxyFCgWH6T3cDKo1Ts/fsOP1Cg+yqVGIHpeIbLWl87k/ccFAz
         4TxREeeYVBpWg3A/ytHURYM+1MiHGAJ09y5D2fIuCsW+HrBf9f0vbjqALr7EXDGkyhx6
         Bs0EjIJW9phUlumGVXz4v/+aYqSQeDeiT+JKkKH3Hy+Gv8vS2eHH/DlcPjLIHvyeWJod
         QHEFzpCpMHFdQxwGgHQmpXJlI8Zso8ZfgD9hh0Wr88qzOFiK8K9CbjTP1XNvStxS/wdS
         dvvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BOaasCb4pmSrDWTZ4dnyfdi01+ddZ5bW0CVKvkbWo5U=;
        fh=8GrIHAPfsqqvxmyvObaAGW9u5qGAGC++M00phaaWAcI=;
        b=Bd1pX7XjzvrIFhsi79Bvedn+2aqb+ZKchLrYwqPvdiepu2GgJ9hBVTsIpOdN0BJhwK
         3qNb++Vh40gMzMQDjMm6/1qEQUezFcBvDgdYCT4q2dzaVwqiID5Xw5aMqDSuG1Ueval8
         oBXkD6X9DRl6YMDZjy1xKfPjWozlAX+btcfgvzfLfzb0LJXNLdUZ3fhDLtSA8o6RdOmk
         3mCp72teqWcHi+T6xORFj8K/GxTqnToAygc/ZYtZ8x93e9JtHJvgK5dhmqkB45I8zq8T
         UR7AbkyKq6bMxC1fkPpCwxRtY8RXFqYnrCpVJyNvy08jBFxH8KnYIKaI/nt9OtdXdFJZ
         ao3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fcF7mI6Q;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2466884ab84si5435365ad.3.2025.08.27.15.11.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:11:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-526-Y03DoB7kMGejm_4jhOvFCg-1; Wed,
 27 Aug 2025 18:11:23 -0400
X-MC-Unique: Y03DoB7kMGejm_4jhOvFCg-1
X-Mimecast-MFC-AGG-ID: Y03DoB7kMGejm_4jhOvFCg_1756332676
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 1F89C195419F;
	Wed, 27 Aug 2025 22:11:16 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 61BFE30001A5;
	Wed, 27 Aug 2025 22:10:59 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
Subject: [PATCH v1 32/36] crypto: remove nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:36 +0200
Message-ID: <20250827220141.262669-33-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fcF7mI6Q;
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

Cc: Herbert Xu <herbert@gondor.apana.org.au>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-33-david%40redhat.com.
