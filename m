Return-Path: <kasan-dev+bncBC32535MUICBBH7ZTXCQMGQELY5OVRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id E542DB30391
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:09 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2461907278dsf8269765ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806880; cv=pass;
        d=google.com; s=arc-20240605;
        b=VJWx0eCGWD2ZmmdmTbKFEDE23BtvE9oamX3mZDIZtCOjBxmdZfB6NUjpqDSOyOpy98
         nUr7upwFY2QIKm5b2aRp3TDlPloubBHcWVSC1f8wHf39jT+lZ7Vtjgiy3crXQj+04Ywf
         hmMA/MwbMI/sHkYQWwv9kHtk90XqpTdgsHUV2Vi7bN5z3qAu9c3tGNnA5VxtduIhR99p
         Gq07+M2ywM9EYatXgV3Ybl3aCjI0TVAbOoOPULkudkku15RmctK+G5r5VFpkZ0Oo9A6w
         3Dx5e2Zguw4WtY17+rc6gJR+mV2avSMwBIEnnsWHyxcdsf7+Pc4cTHoGt8Mkvg3aMSJ4
         LMUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=0JRL5OlG5FiJFBRITyWoTVB4UbsrRdrCJpQf7SxI0cs=;
        fh=tJVMVgZlor4SXeG5ny4YH2KFntN5sonbHCuue8wEAMk=;
        b=docVeHWwsKKvyKacx2exABrTfVyOJXl19OFxUD9FL93QaKYClO6lq/nPTDhVVIiQzs
         C8vKdnPtcuD1PFs6nww+XjBvETB7mnYSCofKCaozAN55VKuWnHwa3C3AuP0Pe9Qe0VY2
         lmVCyl2hGVgj4IlHV6436O261SRvylI+MXXzMGztKFa06VBaUu18R1nJg+WyTOimblQO
         JbHnrnIqhv+Y2SX+GTDcL8jcHqKmf7R64g5PXl4m8QH/nhyAVEpDdSA75r4s+ZkyFkhQ
         00d97HwnQuXFMxTl01afY5dCndKnpYaqr6D0HUmHTmd/4VKOKAnnoY2LedQmZWnu6Tbb
         DLjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=c3iWzq7g;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806880; x=1756411680; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0JRL5OlG5FiJFBRITyWoTVB4UbsrRdrCJpQf7SxI0cs=;
        b=nEVn2eZ/pY+fOzqSIf8KyvmEG9/O5zwIXyxBw5Z+iwa8FDxcNPWfyKODuY516GBTM6
         u4UGkME0N5AQqv8LPOGWQIu8BuRxskJk+pL6FwIsfLeQa0Iu0APXSze4jGIE6yEYvubb
         EpT128irm+kAoTpMAD5H+knucSh0cwYMD+BqC9sRV85xPLkM8L97d/SbB/arXHs+MoBL
         p6wx35mjFLZ7Evsmjuc0dehS8D/PZZvHGSRtDNIsoC513bYheCkGj7NpVnxjI+Ocp7SY
         1TB9uQf5ULFg4kECbqKDSO8USulta/PHG+aY4mK2UDaUHKTIp8GIEwT74IbbmJQpc3O7
         NR0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806880; x=1756411680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0JRL5OlG5FiJFBRITyWoTVB4UbsrRdrCJpQf7SxI0cs=;
        b=bHwLZjzPyaMYebZ8LD7IJgX1cGIFurznf7HZGo0R+R9ey7Czy33V1rz6KxJDqyD486
         T4bbdFEwMUb72sM5/q0z60aRn50/FPfAkaxecvUHLi8bIDjzVOQVgvntWSvGNu2btTMy
         jXnPnvh6VaPgpRpGSONMHygr9I7KoFvS0ObyHEkSDxYUfi7gAGp5EgtlGzAiFJ6MGu1M
         ZFUnVnZy9/VTeDhd0u1VnRZmJZnmXEOpRyFZmdcnSoz3VW9LYx5KLG7QDJtH4tZxoHEL
         Rxo+f9ToaidnM60WtD1AZu7/e6xoHIZeQTp3zeGoh0RiWfQYCyH/F/opOEAPI1ILfpJ6
         fLsw==
X-Forwarded-Encrypted: i=2; AJvYcCV+ORlBtJLkv85VMVaEl60zpW2y2Pd0Qg/H9y+IauGZyj7DSMAYKDe0Ho+cCS4n+yc9htIDvQ==@lfdr.de
X-Gm-Message-State: AOJu0YyjYtr04Wgg8dcTWDTwM1PCwvfN9Q6SKLT+wpTyzWZEAKC+wO2Q
	M0QnTCurMyEMoat7VNJh6dIjbyo/hSaZg0MlGF/eBn0BJ2J0UL471B7O
X-Google-Smtp-Source: AGHT+IGuydKei2aavIKUM2igTjx2akBqp0kCWoPIj/Jr1gSHZt652R+unFgbEuJ0hI3ksw0+1bq7nQ==
X-Received: by 2002:a17:902:d2d1:b0:240:48f4:40f7 with SMTP id d9443c01a7336-2462ef423e2mr7137345ad.39.1755806880115;
        Thu, 21 Aug 2025 13:08:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZegO3Ig20JlJW9Mom/gcuyb4TmMM4IErAxTI4KdQscDBg==
Received: by 2002:a17:902:e8c2:b0:244:6c39:335e with SMTP id
 d9443c01a7336-245fcc255c9ls10566575ad.1.-pod-prod-05-us; Thu, 21 Aug 2025
 13:07:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6Ia25CKAKMADJjW/7g0E/PQrI28/8axH1ma8XieTQ/eGFxI7RqzSjt4aQAG7Ct1nKLl6doeiijVc=@googlegroups.com
X-Received: by 2002:a17:902:fd45:b0:244:214f:13a0 with SMTP id d9443c01a7336-2462efae428mr4598305ad.52.1755806878604;
        Thu, 21 Aug 2025 13:07:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806878; cv=none;
        d=google.com; s=arc-20240605;
        b=Fno8WJQhx51zJyyXUVpCGGAAssBBrrQE+qMHUYDn5j/4ajGmQBS8ml8ArWqrCzOzeP
         +l6DtSZ7jNJABeA9jr2oKlWcIferBW3vQXZzMRRRoP4YSiYbwvR165yB7Lx3zMTzAd/9
         l48mSnb+wQP3EILMk8QyL3rUPHbTEblFmYtiDiob7B2ZdZ+zLAWaSjBY2JMv6l1S1tog
         jRuitZpagWx79oQizg886YDeMbq4B2KsPilMlXiRyfK5xtd0P1/qldeF/ZHXD0Y5roLB
         q4abPxE9i5hcnr8103OhsSkGqJruY1FV7J25j1VsIsW1ecRinE5zjpSDdomMVMjWgEV+
         Na/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TaqjYk7qiFpFT4dP16wKMuC8fiQfbkUwRRgQVKGzHC8=;
        fh=yWLO5hybFmi0IthcNvwQ0yX08B2I+juIoDHG6c03UQQ=;
        b=kjmAFu/xmbBK92vDOUF8N6mrtO/IoB6X4ig/KoN1y5SEoOMbMrrV19/aNFJE9I7bSH
         Tvg/swGODvb0OQ5ln+PpZ3K3ZZHQjMoii7Eo3VPIE5KHP/0wkXT3qN/KQJf9wws9FOD1
         p5r1CjzMPI2StMQPNBdKAr9b717RaD97zyloBfRtxp/ePMP0vqcYXF2cYtbIXC9WtsIW
         BZnhRnFJjFm0HqNskOG2lWaptSievboHPjcd8su8UCuiykepaLeiJzumbW1UYytuoWWu
         Vs11PO8kJRlJ3Q0VRCQar6uXpEd5sz2siBQpJh00R8ni9+zOf1IzjEZ76wHg3o2465CP
         78Fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=c3iWzq7g;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-245ed44d7bdsi2262175ad.8.2025.08.21.13.07.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-649-INoRMURyNuWH0O3aMvjEAA-1; Thu, 21 Aug 2025 16:07:47 -0400
X-MC-Unique: INoRMURyNuWH0O3aMvjEAA-1
X-Mimecast-MFC-AGG-ID: INoRMURyNuWH0O3aMvjEAA_1755806866
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45a1b0071c1so6420355e9.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOUdI8bSIlZKNLE5tCVAvsazQylLRIYO8OapuATswda5a7qa8vWw8/Didqme3upk5V1bjcKe3fvh8=@googlegroups.com
X-Gm-Gg: ASbGnctITmC16QEsNUS5myr0tCx1OZiJmaSfxZ3kIVXTL6FbQ9Srr3TtyQ0Gff48kAn
	WK0SvcJsgwcnVduxRmki4dXjrHbcmW8pgbSQvkl6rd4eO9A+/JGIlpCLOm/oDkfaNw94bxbjMi5
	cu1CkKGcQ6z3Q9fnBRw8TZkP988A9jpkrHFhKrFfE8cE4q5gJQhaY6aZU1qUx9TXm0Eb38DYNW6
	tCCsENIPSaa9HUYEvr2/w2urxwoxrZioEhXOIDqAUcIqE1OJZgJl707VNeqYXOZAOeXoV/AI5tR
	jNdFXJB6O4iQ2VeWi9qdGv8WU5zbuHsu06h3JGKp0bWhInFran7V2aqB3lHqcWG0mM8oGMUxKV2
	rnWzsVMDOvaY2RsnWWcERrQ==
X-Received: by 2002:a05:600c:1392:b0:453:5a04:b60e with SMTP id 5b1f17b1804b1-45b517d4e23mr2819295e9.26.1755806866180;
        Thu, 21 Aug 2025 13:07:46 -0700 (PDT)
X-Received: by 2002:a05:600c:1392:b0:453:5a04:b60e with SMTP id 5b1f17b1804b1-45b517d4e23mr2819075e9.26.1755806865726;
        Thu, 21 Aug 2025 13:07:45 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50dd0380sm8632985e9.10.2025.08.21.13.07.43
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:45 -0700 (PDT)
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
Subject: [PATCH RFC 14/35] mm/mm/percpu-km: drop nth_page() usage within single allocation
Date: Thu, 21 Aug 2025 22:06:40 +0200
Message-ID: <20250821200701.1329277-15-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: XDNR85X1sqOqNIiQd7m3Hc8lwFPWwqw6sVeJPFwlZLQ_1755806866
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=c3iWzq7g;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-15-david%40redhat.com.
