Return-Path: <kasan-dev+bncBC32535MUICBB7UEX3CQMGQEKDIFYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id C9AEAB38D05
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:11:11 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70d903d0cbasf8508156d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:11:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332670; cv=pass;
        d=google.com; s=arc-20240605;
        b=NSUdYJauivAm4GAM88qNYP5G80aLH8NMjkQa0AY+cOVsWojxwaw6aXP5ueusDnh1N1
         no0Ik04DfLUAMAJ2EI1H8a2qBVLX9wPCR+O+mFG+V+Nqn3VVZoe3Bd4xz32dVuOEERk7
         3nnq//f9eOVRd/fCPdmLHaBJHMuHOdbt/aFpJY7f2PK1bOgH/Y+YIVpimr8RgfUjmH4e
         k0yaO71iudo1lqlgRAKmhNf0+dp8yPCSsgueCWYWnWFG/47kA3K8kZYOMqxIJ/WcTWjn
         eS2A2bjRI09ELLlv+QLYBuMECxZzg+BawHFc9e5UOoki6OZCyoI2Ly5KfsUuNfZBPaxK
         jhcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YfWLdS8Ndak+Yld41fbyuG7gkWPinMIgA0EpePZc3t8=;
        fh=kdErdApKU8AZh60pDNCJsjAnvy/mMAHh4KWx8h4iCvU=;
        b=O9pV8931wzIWHz7TdikCDwjCww7PfCo7LxPWw7XN0qu35pQlGQwwjuQItSkveVZpJm
         HkrtlycrdCEJttqvikezLIzC7hZM6sQpKK4dYieb//PmjuP3XevpmwFd191mhsabCBgn
         G6gKsMpe+0vSQVXNalAKxqlJRKPJLa+gc/meTCJNaYZZBfdmFMJH+Tij/XpsgQ/P/BQQ
         ATMHXpCMn7+JGIvbErjS6afPYwXyk8sacnkgOd6jQPHUDxuFZofvCe41PFqFe1JbudhC
         2STA2yayss1IjBTN858YH0fTM/KFTUVpqEdbZcsqZ+ClhHQmq1By4R6Iqx4Q6IYOgnSL
         ATsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gq3rBFb0;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332670; x=1756937470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YfWLdS8Ndak+Yld41fbyuG7gkWPinMIgA0EpePZc3t8=;
        b=e3ICb9DuhqweYgl949SfFJnR0bP3dcwHEWGtbWonAeiojmZ9jhcXQGM3cTrzhOiJRq
         j1yqJV/CGPFLIn8ZiG8whwlxh6sawuxhAEU+Ar+V6co4IkR03/kvxLokSkEro3UJWMBv
         ++73XtLXhKoy/o1KGzBGb2WCyZW9jpQhWAqADx2yUkzLp6UiyobjvTbcfQ+fFSokuKuL
         C4dZqNjnpLoblClByJIb1Uaxt5pcf6+P7nZ7IBHiDja/ORefpS8QhCrcS7NcL3/1ywDP
         dplQZLYsk26D7ETmf8zRAC/3hoPy/VHx+kMScKOWIB2qHVFRXT7IUg+0UWYAev5jYq1n
         dHaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332670; x=1756937470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YfWLdS8Ndak+Yld41fbyuG7gkWPinMIgA0EpePZc3t8=;
        b=oHsbVrYTIRYoFyUrZb+rPEINK7+QEOyA/BI2bvOYu+7XqM9eTSahiSMq/XOgMhej0H
         ItWFv7NhYPa6URbyDG9riA95JVGGXF38twCwYTRIHx2qzWHDH0WV7/cQZuibp/cQm9u7
         59yHrzjTLwKgUqQkOq/inJ1D5+K2O+J7vEMM68sgfq7C94EhbWDXrnjNQgxa9zBciqdn
         hHT/PYVzG7z18F6w5AkQH1oegcbKGL6Q6lqVTMp/VghfW1kUmf/SA8rs3hepTObmdRzP
         gPzo3SDPUubso72VtaTpPcCl6UsYvhAKi7VCHWF3h3QUHVWsSCpqLzGpdmd47byQAQ2J
         nJdA==
X-Forwarded-Encrypted: i=2; AJvYcCVAOWJqoQwBr5RIJEunTcerQU41ZBUK79AtJoTs809ufICsU9aC6+F6qeNmeLHkYwZkFf32qg==@lfdr.de
X-Gm-Message-State: AOJu0Yy+aVcIk6qJc5LyGqkk/83kSAv5WpGNXUHJKM4OnvB6ug/dBlhV
	stFUkbeof33ikorqD/vdRcTrh9l73rAIBXoXdBCe8rynFz48sEeCdWAH
X-Google-Smtp-Source: AGHT+IEd171jwSuMmfWC8Uh0CtjlMwN456yiRIZX9FwjZNzVEPmGiImk88XUuIzylIFEYIrLnJF7ag==
X-Received: by 2002:a05:6214:ccd:b0:70d:c70a:f17d with SMTP id 6a1803df08f44-70dd59c020emr78224126d6.12.1756332670527;
        Wed, 27 Aug 2025 15:11:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfTyKawVcaQpJ9hO9RsFG/ruTl3VxcnDIXz2AUoa/8QkA==
Received: by 2002:a05:6214:19ed:b0:709:642d:1566 with SMTP id
 6a1803df08f44-70defe4325als3141646d6.2.-pod-prod-00-us-canary; Wed, 27 Aug
 2025 15:11:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWK+VlDvfc3+qo0yOXGs2fQ/ChMyShUkWOcxR8nJQCOQG+nImHjWtLoJO+BUFKFr/SkyISY63D1IBI=@googlegroups.com
X-Received: by 2002:a05:6122:2017:b0:53b:fb9:6fd3 with SMTP id 71dfb90a1353d-5438f39df3amr2910116e0c.7.1756332669719;
        Wed, 27 Aug 2025 15:11:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332669; cv=none;
        d=google.com; s=arc-20240605;
        b=I7XywnwRyHZ2R181hv3vmEQFdYVky9YtayWTboBD9H3AnuZuMOpeGNtm12vijB3ICV
         6U7XSYFkjlkpDoww6ugdQdeKdmHUgZDNbCFAJSMnV2pTd/d6umGSZMAxoMUEgeoWofBq
         sevuTPNGyt0R120AD4gfToz6cpup4X6CoAt48jXraxBPjqpe1GswpkstB5XX+PzlashP
         4/raOnv3/0foBb3GzcKYy70RmfYHG/rYK74C4yNP0qWC/au/j4+E0tod8IRbEMtxGN3X
         5jBTQFCNYTPq5cIWmyu6b/QagQlATYjX7VJHTVaCYKYINATl889IMqcozoDqI9DBB1RU
         /4iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uIthYg0x+2djveHghlw2Jb9wmVGYKVQz7R4ULrPQfiU=;
        fh=Pz5ufWiw9oMOOPwK34AhyGMzZkppHz4BJ0VQCzXplt4=;
        b=ZLwEj7fA37Ep5Fywcf/QVnryNQEugbVpCjYNgQxg9NugbMSoQgZluV/mKoUcbXnOx+
         00PnNJWFTvp7pkd5kQaFLWTltn958a003Surc6/cEK+zN5oXJJ68Yo+hX2WOim1IxD2u
         FcYui56pgaR2h0ci+YgtcO9U9ATNJmrgwK/JQGVSCeqiyT1qfuiuE//kQ7IbztMV1C1P
         HUazSZCmyq0iPI38BUSCKUyowCe72wtVpRxayMsr/2sYjITmxKlsiPRJN3uDuzeiGJRZ
         7sru5Iqx2yC6zcshMS3/qXRWEce7DCfQRSLWug/Rd7/1Nb1uRWsvKotlalsQN+W08Vj5
         uH1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gq3rBFb0;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5442fa6d282si137828e0c.3.2025.08.27.15.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:11:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-116-ssFK63pfMnq5S88UlMY_DQ-1; Wed,
 27 Aug 2025 18:11:04 -0400
X-MC-Unique: ssFK63pfMnq5S88UlMY_DQ-1
X-Mimecast-MFC-AGG-ID: ssFK63pfMnq5S88UlMY_DQ_1756332659
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id C780E180035B;
	Wed, 27 Aug 2025 22:10:58 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 10AB430001A1;
	Wed, 27 Aug 2025 22:10:40 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Brett Creeley <brett.creeley@amd.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Yishai Hadas <yishaih@nvidia.com>,
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
	Kevin Tian <kevin.tian@intel.com>,
	Alex Williamson <alex.williamson@redhat.com>,
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
Subject: [PATCH v1 31/36] vfio/pci: drop nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:35 +0200
Message-ID: <20250827220141.262669-32-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gq3rBFb0;
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

Cc: Brett Creeley <brett.creeley@amd.com>
Cc: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Yishai Hadas <yishaih@nvidia.com>
Cc: Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>
Cc: Kevin Tian <kevin.tian@intel.com>
Cc: Alex Williamson <alex.williamson@redhat.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-32-david%40redhat.com.
