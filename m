Return-Path: <kasan-dev+bncBC32535MUICBBRHZTXCQMGQENA4G5EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 38E34B303C4
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:38 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70a8b32a6e3sf29601766d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806917; cv=pass;
        d=google.com; s=arc-20240605;
        b=h3mf3nTcqbSo4Vi9dqDvhlCeVg54SIncfcM3vkDPDHg7kRrdDZdIqqvbasHF6NYz3p
         O+7My1czsUvvZNv/aUzUzJxPm/5CGYb8kGG/T2YtAlWsrlldve12BY8UChKmmPM56EU/
         tiESjmrMhJTTEtHRLiC+44/+D4TSwBQgJ5imZJkUCA+8TMBYanoOX4CtAaOxYboKBuTf
         QkSGghsaZIhsQ1QiVowefxdosyXGQFWj5Sfif20iryoJs6g5JfjIE6zetaDqR7XZ20Mv
         +QD8opAHrSa6kz9okAFVHgu9RS9fLh8XtCZeB2YbOMzKobTBsNw89vEB+CCzSgjsBq8c
         h3aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=bT2Sgk+Ukor0rh+Cd6pR5QdotfsA3eOQeM5VQ/QDuGU=;
        fh=Sk7CpeL4XRzNPGvKXElrncSRkGw6ksZFtKl3V71B298=;
        b=YmWC65uUqHV344DNi2UDhBb3mTIhzW+GVK6L+ExAnBhwyB9pXkDJmP6JfLUeR/cU/o
         ahxi51GDwZQ7o35CDs9eiVIhDAY+YkKVKmFWGq51Ps9lIjlMc97OoL/YgPuTzXd+MSYZ
         bQDtt+cHxtzYimAN6WV86cimvpFVM3JnkDkSMviHmJnxPlyjFmJGXBRcV/bcBzm0ab/m
         hQZXNU8p/I/Le2V4bo2dR8yYKWp5Cy1im3NzX37sJ4XwV0+HICNm5eawkrfaVhavq3C/
         Ky01/sizBGVzt7oqpCHwR9R9VIyMovGTu25RjVVw2mxMaOPdjwJgwQ/q8y2xvtGUebW0
         sOng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=B3sr6LQt;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806917; x=1756411717; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bT2Sgk+Ukor0rh+Cd6pR5QdotfsA3eOQeM5VQ/QDuGU=;
        b=aDI/pVKsX8SI1Nun16nyGytBd3igeDOx9LsSZTyhTsouZeueihNEbNg36L8fz/zgyp
         OXE6RvDhku/9c2hRPIu9UT61jryd+3pjr2L0f8qpw2eCzygxCu5IswEXFY5Q0mJm3FbL
         3kai5T7gV2F7Ai7oCKLvvSvIEIJ97He0v11CDpS7QWciEXOb/12L/LhZ2GvczYrz4dQz
         k11e0jL7MqoMHn1mq4bbVyZuH2WnKOtGPIeLlgCbV98tgMYjDjw+i1fEWuL4arJfKHoX
         NuBLz4lcO+OEi9dmwGx/ISxSM0p05D3lzrAvucuc512tpRgLbxGMMEB2Qsig9s+1RNGM
         LN/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806917; x=1756411717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bT2Sgk+Ukor0rh+Cd6pR5QdotfsA3eOQeM5VQ/QDuGU=;
        b=umGARV+uhX6we2xWWkqa4xLk7SEzmug+sIMEjmwc8Dob5QBnLgZEWqv1zWuzRuRAEY
         CiUeulNUiuymlwzYfYwBzuG9fH9IBLOf9AiYhguo6Xz7NBuWzyvQuWwnXlDlFcN5T9GA
         5PEYBaa9INHrXGKlWbMh+9a2JzWdUnWXjnzNoL9dSDQY9E3GuTRP540At/scJTSLRyGS
         w9kj1TeFJlQx3zGJM4QMHuX4+DwvACFRsdG++cgUuaqjOxof74x/6lou1mWAbYj7OVex
         PodkUGKxmy2ajzu5r5ESFAia2UzKHMXLrUdol16UoYw7ZO2eLM4KZ8eY6RZFGBLEeqPl
         5Mqg==
X-Forwarded-Encrypted: i=2; AJvYcCXNqXKSyEpHa6uCAeG+iHnb8kNPgbNKOvJI/JFnTjQgZir6MiA5/ZsY1lORFmaH7CaNNdRYZw==@lfdr.de
X-Gm-Message-State: AOJu0YzlvbmgsvvAfw39Eq0+ejmHjQuWgriVOdKDRfnQs538KZ+HuAEs
	1b+nDf64JkJ2SobuyEKZuOrYcjYAabyG04prYeqw6R5GgrbXSFqyNpRx
X-Google-Smtp-Source: AGHT+IHaiUG9Hk3jLcZbzUsnuSk2k3kjptSb4SaAOIPsO/o6KGbvcZ74s3h0B/WtcrWuT1hqyiaegQ==
X-Received: by 2002:a05:6214:5191:b0:707:7090:5400 with SMTP id 6a1803df08f44-70d970fc554mr9286626d6.17.1755806917003;
        Thu, 21 Aug 2025 13:08:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd1OagdPCBPvQS5EHbZjGB0/8NKPnI1TV4LQ+Koyz78JQ==
Received: by 2002:a05:6214:f0b:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70d9522245als7927576d6.1.-pod-prod-01-us; Thu, 21 Aug 2025
 13:08:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgZAcntDQjMg4WzNyq4Nm7qgeep8/2yRSgqBUqXN77DDWQY/4lZqpw48yKgje9r+uLxVHV9IEvoaw=@googlegroups.com
X-Received: by 2002:a05:620a:1993:b0:7e8:2ad2:6f44 with SMTP id af79cd13be357-7ea10f86e5fmr84137385a.1.1755806916090;
        Thu, 21 Aug 2025 13:08:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806916; cv=none;
        d=google.com; s=arc-20240605;
        b=gerkqbI7sLuhpGPJ4AWOKYghgHHCAYc8i0z+ZHYeLPYdtdU1WM1tdxbq2ywqz+nifC
         GBkWtUsDGto33om7GEt5Rd8S5o0TUJ5TMR0MnrBC1JHV0yK5QsBq11w0AFXNRt8/hsWJ
         k3vjwwa3P2vBq1g/AhNVtfL09BrtxN9PN3eaO3cCzZ3s7X4k00oUDu8Q6tzQRb/769An
         mZ4e6N1k1Sa+7zLVhPH9DFqJffTgHb//TEW/bWq2vmfY9iPdUp7YUoSWlcKkxq067BM1
         FQiP/NRchf4KwjjyMelMnnZWSAOpxQAuX4aPppAGYFhXkcGIrYFd/sEjmGTZMz8hXIPW
         HuHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uIthYg0x+2djveHghlw2Jb9wmVGYKVQz7R4ULrPQfiU=;
        fh=pGWL/NfiCpV9OQM5zuf++5EEwUOEctzFcTX4XCKJpVE=;
        b=VM60sQU7c1DkYmdibx4FjFAuPsntRTLWz8043nowhl1MJmpJzE0FnfLMIS/Bousnf4
         NxKplxBJcDmtKyTiaAvDB3T80DOdEZCmalzkcvc9fQDPaUzaBT8y4q8Xlcu8lXTf5fu8
         ruNZJO6HVlLqML8VXkER0M7eYeiixk7llygr8eRgaO7QvPeQPbjoEu0/jBC5B57oTf44
         549ltWsEEtFv2JnXzWb78OwUSj05qGvi4GSoIegbmjMZGVt8bOTyxUlSKVbVfQI6s1pF
         KI35+NTKLSeKSFhRPHJMnFVpGyRm55TPUGlsJDNuAwr1i1KFyyZcPEdaO608T6D3VOwF
         36dg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=B3sr6LQt;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e0e7865si68141185a.1.2025.08.21.13.08.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-1-0nHvqg9SMxO1PemT9UdchQ-1; Thu, 21 Aug 2025 16:08:33 -0400
X-MC-Unique: 0nHvqg9SMxO1PemT9UdchQ-1
X-Mimecast-MFC-AGG-ID: 0nHvqg9SMxO1PemT9UdchQ_1755806912
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b05a59cso9779525e9.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVuVz3YKFrQsg6ahFN9Ucu7YQJLQS560T+SknQxPVHwWraGqnMHXRwowCfT1KuZ5xSGhSF7z8RI0jY=@googlegroups.com
X-Gm-Gg: ASbGncv2mrY8OnDsrnaXMLIBVia0r2GKgbwbcZJhOotRVfbkZt6cyaftXmsFn8Ee0gv
	Eix3B98bzikO9u6GhAQzr8QDrWWG+tPP3wrYHvOa1XCgQsEVjxcf+LRacRsuX1cFyPa/WXlTvDq
	hUdwnz/r9IRTonLmlZYNhwhcEv4Z4qW4NWSmMReQUtgfrvmADZlc8UMG/pIZMDdNaa85ZwVBIkQ
	RMvUSyhwzcNLMC2qwZLzBQRWWKcaR+V56W3jQ8OSCr2xetjaqmBkLcntPJLHToBkvpH9CcM/15r
	zwiCwHlZEjJYWJsY2pvgCsYWE4uILwzWeDXLynJR74woOFCMjY8oH6SjvusDa5D9xwGvqxQDuZ9
	cOJTAOS7YSUhZU7diseB19w==
X-Received: by 2002:a05:6000:40de:b0:3a5:783f:528a with SMTP id ffacd0b85a97d-3c5dcefee22mr195287f8f.59.1755806912324;
        Thu, 21 Aug 2025 13:08:32 -0700 (PDT)
X-Received: by 2002:a05:6000:40de:b0:3a5:783f:528a with SMTP id ffacd0b85a97d-3c5dcefee22mr195231f8f.59.1755806911819;
        Thu, 21 Aug 2025 13:08:31 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50f16eb1sm7598185e9.3.2025.08.21.13.08.29
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:31 -0700 (PDT)
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
Subject: [PATCH RFC 30/35] vfio/pci: drop nth_page() usage within SG entry
Date: Thu, 21 Aug 2025 22:06:56 +0200
Message-ID: <20250821200701.1329277-31-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: giT-rW0zPd5GyHtjzpkDugMm7MOqkISyWBPoHxugtBw_1755806912
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=B3sr6LQt;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-31-david%40redhat.com.
