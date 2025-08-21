Return-Path: <kasan-dev+bncBC32535MUICBBSPZTXCQMGQEZQS3KWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B9C9FB303CB
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:42 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-244581ce388sf30617795ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806921; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zp2kO4FaFChMN3SOdttInqZy5p0rAVdcvba7M4+xO5JaynqbrxInl+kqcdZMALmOLU
         fPA5NpWoT07tHxP6WVANzhm+h3vql7Mf2Uf4w1Q5kQNkanZvsCLflAswqajcbk42FQBF
         T2YSjMmTmczNF6rGP3ujIBY8VGSXzsQV/qR7yI1jTgGsyD+bqxnV0LLjLJTB6c36Bx6Y
         ymJzWw2DsPZJ52f5th4UKcX2JKHSwSP3K4Uodu0DH9fBnC5tV86fOUffSiyKu4zKJYmt
         kzfqTyFhbO4wwr1A+uBb24LbtuiXCumkyLSXRzBxbnlRBjaPaM64bu9G7cdkLiGRcZqb
         XYFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=9Bs2ehWjR7FwJmasrXFTtJGny5exb9jOnxYnulhSiPo=;
        fh=2KmPkY2F6qxnjXhUvCMaolNp6s1K6puodLsHM/ENHvY=;
        b=iqZOqVCR3/LkGspmwkxE3d+K+RMqZgF56Q5gVkEA1bZyBsO6/y+Ztp8A18gUuxr6fx
         f6VJE0fcXfu0l363Mxaf3pNlIJG+mx9GFSqkvpO8nlm476FNqIUiZDK4hGBgS35B4Tqo
         MTSjP0NeTzox1IXxHgZRScSYDuX5kYde2ATCmYdohf48/U8kswnjP4C3SkRJ+X11QCv9
         I6rl2rQ4PdED7nRhES75Xw2go9c05SwPVnqwKHfWroPSirHo3oA4FwMmJWY5DBxuxLKV
         gDoDeweHHOIsTnoxabmI8rDFpPvkKxOZluos4pglYBsC9tb6B8ho5KUIX8vw0qR1GTFD
         xKPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=F0U4HEso;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806921; x=1756411721; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9Bs2ehWjR7FwJmasrXFTtJGny5exb9jOnxYnulhSiPo=;
        b=niTg+Sondbm4uv7QU6BJfkgJDqenYc3MkG6qZxAn99hKiGd/AX0cNgvhqFI5k1k0JX
         7da+PGE6INmBDIPZuM9rQ0GDDUPotchJgiWMWFLqlLAmdz8sKnYRptD5pGcezDm40Hjy
         kyixSSP9LA/J9xyzVGMuSSrWsFHz8+5oBC8/GHmk7apbd853JugEfpXpqPVNhJh7JdCJ
         ukzXclqnEG04uam4IZSSQGxXsGZMfCIPL4bS3H4RsvxU8zx08fn3V3hyt3f/E1qchD3J
         3ba7HIAud3rAyzVjeN4CpYjeGtlELxdwiKspK/jSr78yVx23V8Ml/tA1GhWOxyVnDHWk
         PBOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806921; x=1756411721;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9Bs2ehWjR7FwJmasrXFTtJGny5exb9jOnxYnulhSiPo=;
        b=ZnmcN9g8LpWy8KL/3DJjm+9TaSqlSNd8ioeGPWRGi+P95idVWPfmMouu2HcZbbz7K8
         zqaqIMpb/i91f6uLdMeTSASkxxzKFq29o5sg121dnSWxAUflxElt433P/tLerA2qbN/B
         XFXxOM1zG8oxVFMELQs9WxNQ3RoHd4JWjPSJF1TKTZbSX4n9qREiUkweAogbgr5kGYIK
         uP6UyGu9E9f6O/sFWc2DeUxNcXh0H0ViTM0Gdaz8AboMo1+3iFD0+DojRzT7SPhB65Yz
         g7K82XXMj9nLWbRPsMcOh5PeSj2cEKj9/HCFTzGzUp82UNrYAJN+si3oHQks7CUW4yzP
         vN0Q==
X-Forwarded-Encrypted: i=2; AJvYcCWR6Db33CnQDwchsaj1+e0C9Wr6NYMmvfZqvxzm3so+GLtDL0q2W5HcQYCnJabI1+CGw+Vaug==@lfdr.de
X-Gm-Message-State: AOJu0Yzjaune9HLS7eJiTCA70jwH8wIYPnnYd7fcC81fUloO+r/iWrSU
	4g50J4CWUiSyeKCUvmaF2gwhDEzEwnnJ+NFkMkJ8nQOhFuXi2/2c7AO1
X-Google-Smtp-Source: AGHT+IFWyAJPoPB/Ppt390Sjnmtc7kpu33ADu2zH6qJsAndlbCKc3WlDsc4pMsXvUPfoU6Cv8TUvYQ==
X-Received: by 2002:a17:903:943:b0:242:fbc6:6a83 with SMTP id d9443c01a7336-2462eb56b82mr8480625ad.0.1755806921294;
        Thu, 21 Aug 2025 13:08:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdqfd+32BwP8BZMC6GqqNGYvq3A7LhYAEXq16LIRsE3NQ==
Received: by 2002:a17:902:f68f:b0:234:b735:dc95 with SMTP id
 d9443c01a7336-245fcba2b69ls19602535ad.2.-pod-prod-08-us; Thu, 21 Aug 2025
 13:08:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9q970uNPfZrMsc6tobimdN1YitA+iaEwoAOVc6q9wcJLylgRE7iMaTq/gcv1RA1E0WIS4FBwOTpM=@googlegroups.com
X-Received: by 2002:a17:902:e84a:b0:240:50c9:7f26 with SMTP id d9443c01a7336-2462ee38fc5mr7028415ad.13.1755806919815;
        Thu, 21 Aug 2025 13:08:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806919; cv=none;
        d=google.com; s=arc-20240605;
        b=bnPP/v4sUzZ5TR7fAKO1frUWWnlqxGLK4Z5zZeQOq6s0ghmydWZDTO2O/FK4rHrdbB
         YVyTJMVGf9t8HpGtXrS6h76bnvxkdoqfLPmvLNmHzP2uOwQWhB6PpoR+uqz/p/F8LtPm
         Cc1+l5ceGNdkMZg51vzt1ZXPfQwjRdW3vEuYJPhDSVXnGj1PkEV1XlP5WmOAj0dzMc/i
         mJouC3FdM0RyNz5lLie4oMfrKODOCPHTqWj30oLN4H1i7y/YPeyXEXyWbUFv+TPszv6o
         m5UUe/nPjANGOH6r3CXUz+Ptz4jvYQhwuH4w6hXwBlDDJEmpXrTGrfKBFLVHn22dqQDh
         iuOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3CqHI+s+zbpAzQhGC/xWDVPQsQNUZt86Ikrf9EwImgM=;
        fh=Vld/9pLXgay0OAuY0E6RMA/wGip76F6pOkUF6FtUW5Y=;
        b=WemkwXqIjoIdng/Ci/IddH4snbXGiPbZw5A1zm3sB1iKn37EnPuZz/hk6uAwdoMRSj
         nR4BcqKZRYb/sCe7IYpi4n752uS/Nm5J38o4OSQ/K1NgkPF0Xcz6Sry67O1JMsczy5+c
         XZpnG1wySxG2l6lQ+Lnwa4Nn7lMRnauX16XW7U1RSmpdZBmS4Gm+pRHgfB3D22TeO9fH
         8Uo/FDpHEP7Ek+n6SejLAqYBpcqYdFhL2SXMAnPMNH/um7nGmX3AAzQq/lsmWhzIqB/C
         zAU1hm3JzDWNwUemPB7QZAKuGFO2/VdnK4jxwMHXlo+jS+ZvoJvS6guWLWieFZ+OeZWE
         9j3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=F0U4HEso;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3251390caa0si35122a91.3.2025.08.21.13.08.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-372-LtMonkyVNlWUzR37uABW1A-1; Thu, 21 Aug 2025 16:08:36 -0400
X-MC-Unique: LtMonkyVNlWUzR37uABW1A-1
X-Mimecast-MFC-AGG-ID: LtMonkyVNlWUzR37uABW1A_1755806915
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45a1b0b2b5cso10143355e9.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUZYVhVlkwYLLX810t4X8Yds6hPhkXpZzSl5yGswMTbNZSvukKZJvXkwGxa5FcYghwcLWid10rsNss=@googlegroups.com
X-Gm-Gg: ASbGnctylH8MoQ16DOTPqrE4Vv/rc7imTre+9MGTbD80vED9G+FaCI0aI+qnuo7QJlx
	/GiX+oxi16BBNwxnN1MGFsJhu61zATcI3LvD0OemlpOSfYvwSW2FrzX7Wo6RK2y3i6Gs9Sa/nNO
	sa7rSUIp1STA3LvGgrYeQf+IOtNtiungoyxRm8JKXJXUvuqoFdwbHOVQsfpIAE6+QM8o0Q7pxQA
	QvvWKPUfJEtpFt7je0oJu7dMN+QtvL3eIJYh509TzLKh5PCZJK3NogpXgaZwukdrszaGw5Adqye
	JAsbwKyEUxMy5W9D5yTvFN4VpQXdR1+oPWwGC34SAPyRmh8XQWN4WBUrepprKdg5AdLN5arCgUw
	aiL2Z7Kj5benYgC3H4GnsFg==
X-Received: by 2002:a05:600c:1e85:b0:456:1006:5418 with SMTP id 5b1f17b1804b1-45b5179f0d8mr2710905e9.13.1755806915055;
        Thu, 21 Aug 2025 13:08:35 -0700 (PDT)
X-Received: by 2002:a05:600c:1e85:b0:456:1006:5418 with SMTP id 5b1f17b1804b1-45b5179f0d8mr2710565e9.13.1755806914568;
        Thu, 21 Aug 2025 13:08:34 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c074d43b9asm12707153f8f.24.2025.08.21.13.08.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:34 -0700 (PDT)
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
Subject: [PATCH RFC 31/35] crypto: remove nth_page() usage within SG entry
Date: Thu, 21 Aug 2025 22:06:57 +0200
Message-ID: <20250821200701.1329277-32-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: eyBjBjAUadwmB2rLkwdndlIj1JZ05oq1tLFRAnJBxlk_1755806915
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=F0U4HEso;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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
index a227793d2c5b5..a9f757224a223 100644
--- a/crypto/ahash.c
+++ b/crypto/ahash.c
@@ -88,7 +88,7 @@ static int hash_walk_new_entry(struct crypto_hash_walk *walk)
 
 	sg = walk->sg;
 	walk->offset = sg->offset;
-	walk->pg = nth_page(sg_page(walk->sg), (walk->offset >> PAGE_SHIFT));
+	walk->pg = sg_page(walk->sg) + walk->offset / PAGE_SIZE;
 	walk->offset = offset_in_page(walk->offset);
 	walk->entrylen = sg->length;
 
@@ -226,7 +226,7 @@ int shash_ahash_digest(struct ahash_request *req, struct shash_desc *desc)
 	if (!IS_ENABLED(CONFIG_HIGHMEM))
 		return crypto_shash_digest(desc, data, nbytes, req->result);
 
-	page = nth_page(page, offset >> PAGE_SHIFT);
+	page += offset / PAGE_SIZE;
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
index 15ab743f68c8f..cdf8497d19d27 100644
--- a/include/crypto/scatterwalk.h
+++ b/include/crypto/scatterwalk.h
@@ -159,7 +159,7 @@ static inline void scatterwalk_map(struct scatter_walk *walk)
 	if (IS_ENABLED(CONFIG_HIGHMEM)) {
 		struct page *page;
 
-		page = nth_page(base_page, offset >> PAGE_SHIFT);
+		page = base_page + offset / PAGE_SIZE;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-32-david%40redhat.com.
