Return-Path: <kasan-dev+bncBC32535MUICBBCPQ23CQMGQEZ5GIQMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id B30AFB3E8FE
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:13:14 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-7238c540fdcsf9379657b3.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:13:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739593; cv=pass;
        d=google.com; s=arc-20240605;
        b=GUQwlLtjTpcgLnfcI0Zfx2Lh4hf8wBNtvOdiEMsRkmKtCQLuuip9dkyyn3FuGn7tCN
         CS2hfwgOxgLbRGTN/vRamQejZClZC+KQKep8ioJXljKrhHtm667NtKIFbEYE6d0azFT4
         cAdQ/QrZnoQD3bIDiSUuKkKWacA/Yrt5wbwrnslMWyzOU5a/2CKqfptQ+Z8hFf7YDt2B
         T9E11gtRrrBJKsroaTmnc4+GwOJY1irBIOiiPrKsNXEIFByy4k0g7vG5vicQzB95uzcE
         nZ/v+RwawMcA0VGYgQzLTicflDK+6UH20Ka90kf1gvQWiS5uraFCPbADzl5477EnBn30
         HipQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=H9F69E5W9/4HFOLs6H0OApC7ZLRIw3OJinwomg6y2qs=;
        fh=qu6rbDfytH8prbDSCe5pGfaNsVzN1GquTvpLAcFxozg=;
        b=Cr60jOasBDLklUZ2IXf5HbmwU1vMRyI3mSVREJ9M18+5aNBv2ParNQGxyyt13Xt2ga
         viFstlqFgeYM0zygB1/CZxE+gdVpO0QsCmeUkNioxmifzpNY8n+T4mbhHu48dCGiA1mo
         hZqWJhsiU92i3QLbZbjEvEs1uN8IQczrzoaa5ixaqm91L4x4RnOjHgDBZYU0LWOKSpKl
         DW+T1tgNJi46YU9LwLFzKc69cVhOhCRHN5wD2OLcq58aLjFeJB9jwNFOGFTyZ13xP6sa
         hdVpSImNJZEZAijTJAn7mw4zY9iowWy4GTFxvNUht00uIGwSrjXwbN8GKfVnPL95mGPI
         UgkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=htukmBTE;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739593; x=1757344393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=H9F69E5W9/4HFOLs6H0OApC7ZLRIw3OJinwomg6y2qs=;
        b=tEYo2xiEvg6tneCCJyayPCk3+D+2AHeaoUo1C7Nj5fSPqJxGCbXF95kRAz74pz8SXq
         VkcDokB1LLBzxdqeWL3gX9dN6D77ON7mjmdwY03qsuw6ysk4NI0NNfd4gqoHbMLKBzDH
         U0zAXN9l8W7Vp7oFHUZ+Dj1UvbxS9qt9FliOyKXZDMfP5ufm0jMw22XdXUQXqH3SCKdu
         ZLOlSFmuyNXnYeKpGlXm1t/1SS72vVxetaP4ChvaGrlVD2qjY3qKDVWAavRaFGTc+itj
         K4xGlaazimw/w3i66XMA37Er374rmpeBp32sos/KnXNJOn9+BVvMx4P2ktxX7389ZnQg
         0+wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739593; x=1757344393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H9F69E5W9/4HFOLs6H0OApC7ZLRIw3OJinwomg6y2qs=;
        b=e4lqPW2eV9VPXZniIYnA0uvKywKkLR0m2Fv88TzuCqwUuFccjQ62fdHZ5Qf54Xt1uS
         6IPqCDTHzAmGzYsaese94IGTBAcasAZOSkP32Ax4aLPXVfB/9FpL/BnxNAvfEwG8y6R0
         3RfpC0c1BGV0NseRnmlVTDsFYkgL+wiEJ9etrQt1736xEl4o/rlUNhCZhJAWl77nsH0v
         kMnfK8rY2Y5KJL7AzNNGjt3lelYH/009e3WXGUpay/asgnRBkTpUSbow03gRROil1thJ
         o3B+qvWOfNsH3QDUGYvcu0kh9ASNUwOS1vRJh8cBclnaAeczRKAfMUshJxVx/7DgFWjY
         w7pg==
X-Forwarded-Encrypted: i=2; AJvYcCUAuTsaNxQ57wQbjVLOGAAMJL3voweSewcjg/2hby9xuBFCbbsKGd4D8oNMKkyKHRJD1RCihA==@lfdr.de
X-Gm-Message-State: AOJu0YwdGBoZ1Czw1SYbaJyvW9Yb0YDCyR1htKcq0w3dh0XB0poh8zcf
	UC6i4NbKtOH2YY4n1PAbExWNZXdMnLGcGfuIBAnPhrIzJ15pk11iFkUS
X-Google-Smtp-Source: AGHT+IFh/sdQuH+2Wx4ihWmKxqPMoGuGe3XhUGNzV5ZYbB2+f75pGnnEaHDCZM+EBedvXuIx2v57iQ==
X-Received: by 2002:a05:6902:2490:b0:e96:efc6:8392 with SMTP id 3f1490d57ef6-e98a5851c2amr8792613276.43.1756739593523;
        Mon, 01 Sep 2025 08:13:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdK7ldDOjUN8Q3JgxxswZmqIO8HbXej7Lp//N+naVx5fQ==
Received: by 2002:a05:6902:320e:b0:e94:eb75:8ac with SMTP id
 3f1490d57ef6-e9700ed3c5els4641240276.2.-pod-prod-03-us; Mon, 01 Sep 2025
 08:13:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWAwKgGMNdv12PQJ7Nm1LRJtiVyxseXbL0r50ONAACbKsGPdhxx4KLb4ET16OZpC2BbPMwFYDKGbs=@googlegroups.com
X-Received: by 2002:a05:6902:2492:b0:e98:9926:e5dd with SMTP id 3f1490d57ef6-e98a5869e00mr7713571276.48.1756739591048;
        Mon, 01 Sep 2025 08:13:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739591; cv=none;
        d=google.com; s=arc-20240605;
        b=HWenC8g4euRdpeRFP4h6Lpero3ZGwubNaMJX/Ia5Gt4KoxPZaPeYn0KCpB55mybx8x
         OAZG7ItevFOhFjZR3rIZF309qXvPr7JpjxWldMbISg5HTOGxRxzeDccKnnYV3Qpr3y3K
         NmdY0yrWD2u4VEMxCwJQd/eSstTLoVUzrMBNi76yGll2TLk8q3gNytIm43NZMpC9lsuJ
         whiPeLW0Jkt45IJSb/+DeBAAhSgWDhFpbbVZSdHTsrE0vcnTYxLZs9cWAh88VFl7aYG6
         RnHaP8KJp8rjOMLPRhXafWporBrfxqePuxoMH9rMlG4Uear4+thFuGWD5oDUMOts92as
         pQhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K7jUgCzLPy6D8wIKPj616StOUbYwsKVjaRrDFqVFeZE=;
        fh=GpVF9jyYgHZ7UchHD8ZOnA6YZzjqBJoYvktc1KKPakQ=;
        b=fOV5TzjoRnM+tB/F7F906DHC7a8gdt1Wso6W3j4UXKhN7+7qMHTtP8eJVS1iuXedzA
         yUmguQatfAOrhwSiOCg0eFjI5Q9L5JEMo1OS3J6XVWSxqxmBFjVprBT9ymukk0PljqSg
         Pzn6wPfvtp49MTYmhsNKEsPSG84gCv/+q58wr3Q5jpWFHQf06UC/U3/tM1STWfdcHzEc
         /mmPA+FQF2H0saC9hw2iiFjWjRz1CGUPxj8zVMg713GHpsStolXE15/C1LAq+Tfgcd8K
         ULYf+FBiwfLMpjc3hfNOlFq7jb7SccxGCXdAfxKN3CGfsKwqR04B6DcOnOAyOvev93xz
         nUsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=htukmBTE;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e98ac525de2si215707276.2.2025.09.01.08.13.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:13:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-436-_lGL3iH5PteCAFK281ZRWQ-1; Mon,
 01 Sep 2025 11:13:05 -0400
X-MC-Unique: _lGL3iH5PteCAFK281ZRWQ-1
X-Mimecast-MFC-AGG-ID: _lGL3iH5PteCAFK281ZRWQ_1756739580
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 995741800359;
	Mon,  1 Sep 2025 15:12:59 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 3D39D180044F;
	Mon,  1 Sep 2025 15:12:42 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Alex Williamson <alex.williamson@redhat.com>,
	Brett Creeley <brett.creeley@amd.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Yishai Hadas <yishaih@nvidia.com>,
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
	Kevin Tian <kevin.tian@intel.com>,
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
Subject: [PATCH v2 32/37] vfio/pci: drop nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:53 +0200
Message-ID: <20250901150359.867252-33-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=htukmBTE;
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

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Alex Williamson <alex.williamson@redhat.com>
Reviewed-by: Brett Creeley <brett.creeley@amd.com>
Cc: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Yishai Hadas <yishaih@nvidia.com>
Cc: Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>
Cc: Kevin Tian <kevin.tian@intel.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/vfio/pci/pds/lm.c         | 3 +--
 drivers/vfio/pci/virtio/migrate.c | 3 +--
 2 files changed, 2 insertions(+), 4 deletions(-)

diff --git a/drivers/vfio/pci/pds/lm.c b/drivers/vfio/pci/pds/lm.c
index f2673d395236a..4d70c833fa32e 100644
--- a/drivers/vfio/pci/pds/lm.c
+++ b/drivers/vfio/pci/pds/lm.c
@@ -151,8 +151,7 @@ static struct page *pds_vfio_get_file_page(struct pds_vfio_lm_file *lm_file,
 			lm_file->last_offset_sg = sg;
 			lm_file->sg_last_entry += i;
 			lm_file->last_offset = cur_offset;
-			return nth_page(sg_page(sg),
-					(offset - cur_offset) / PAGE_SIZE);
+			return sg_page(sg) + (offset - cur_offset) / PAGE_SIZE;
 		}
 		cur_offset += sg->length;
 	}
diff --git a/drivers/vfio/pci/virtio/migrate.c b/drivers/vfio/pci/virtio/migrate.c
index ba92bb4e9af94..7dd0ac866461d 100644
--- a/drivers/vfio/pci/virtio/migrate.c
+++ b/drivers/vfio/pci/virtio/migrate.c
@@ -53,8 +53,7 @@ virtiovf_get_migration_page(struct virtiovf_data_buffer *buf,
 			buf->last_offset_sg = sg;
 			buf->sg_last_entry += i;
 			buf->last_offset = cur_offset;
-			return nth_page(sg_page(sg),
-					(offset - cur_offset) / PAGE_SIZE);
+			return sg_page(sg) + (offset - cur_offset) / PAGE_SIZE;
 		}
 		cur_offset += sg->length;
 	}
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-33-david%40redhat.com.
