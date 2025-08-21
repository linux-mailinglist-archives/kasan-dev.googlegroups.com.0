Return-Path: <kasan-dev+bncBC32535MUICBBFXZTXCQMGQEJTCN3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E102B30387
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:09 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e56ffe6c5csf12228515ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806871; cv=pass;
        d=google.com; s=arc-20240605;
        b=kw3Udedg9l0rfZ+EhhGwImF9CJRCi8Ani7h3gZCOKUkqNJtucFUiHgfeQVbaUTl14/
         iaWrzdZap5gCSG5gLgndm6aXzFDnMLf1ji8wjoVs0uKuxiFCD7IusqL0/h/w/MQtkR7L
         dPVh3/OG1Ta3YDMFAv73E3+boi7a4/ZTWHKqmTZI+esyc0VMvTLbqp3N7m5oMlUhfGez
         QoBIcXAhFfn1lNrQsI3VaE1+vwn6xojcnAWSeb8RD0mYE8J3Fnn5v6RRmbi/WmPOCw+x
         nF0//A9Wn3sKhab2idn3qkm1YAdUeifrkRAaobzXa4CjbatmUdMTACztDxNr2aWbmM4n
         7GEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=gYs8tYiunJVN81YISUHCUZEBq6+br9vcR6tP+kS0yCA=;
        fh=+JaKRC+COw17szqyc2tE20f5k+Ik26zE+LRaxRFZRuk=;
        b=Jb9HGJ3/Q3ZCNKb/45HlR1H7igoXGL0+bxMtivbiMyRp/ijFmBlhdyaFnJ8QkNPr9C
         mW8cg4uWxnVuxTkeVzG3HZnlgkvtL4Pq33nMv9mcqUqhFKpToWL5qM09UVh2VoR3AuuR
         jF/jJdeBEJy6I8BvK9o9WP6Fe7Et1nxzsy+RFRZMvh64zL6PN2oPUgHtue/9dvOvpzyT
         oP1N+dRULZIKsaszUPth3x6dPFYA11+73uIDcLWyxAYj/g4Ut0/ywzLXShd+TfO+t+Zk
         HAXBTBaTPGizzX+SXn/l/WvU+bS/bPFVKvedCVLMDZ5Kn7XWlyp6s9UF/tXqIORx+/DC
         Iyvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OILxWTwK;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806871; x=1756411671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gYs8tYiunJVN81YISUHCUZEBq6+br9vcR6tP+kS0yCA=;
        b=nChsdj+Z+/nqx8nofnMMq5EQMcoOvKm6rm/uHbwIrtO1drq6T4T9WNf2qUdK6HHngT
         AoxV7k97OtNHXVnOSbj2zrbx2qO7ohNu7LRFeCE9dJMIyfbMLafxj6vie7L53L0KcGHf
         +RUNJisy/tEviKHN48o3vi5VGShbX8J/OjuPP61nmYWLf3hpD0vwTZ+ow2YLoUWkg9A7
         PnxWz1tbqPZwZZx3MQCzW5As9w2niBrRld0SHfbliJeqXqXnTUGwlc2McK2d5kraPBoR
         O0MtPRnD1TgJ8PwVMF+eZBuKb5sk45p8JYwjbdr8p9FFAc8uejqM3ytsiuu8OQPse5v6
         gW9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806871; x=1756411671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gYs8tYiunJVN81YISUHCUZEBq6+br9vcR6tP+kS0yCA=;
        b=NcKASf6yoEAqrrGyKL7bqDnZHv5tKeO0wcjzfV2nIU+SIV07LC14rCeoF0cwk6Jsph
         ntqM9tF0Iwx87rSa0WGwHf7r/c9vuIFzn243oZ0anx1y9NYUyOII5CZSW5lVYQYNG+Q0
         N65Jtw+voKa2Kd3w5X+/gHKIZX8UXizWHjBenhyZHJ9tNa+T7dV/fgaXyVj1TUJAhg8V
         vOR+8YDGD3nZViSS8q7kkCQ6D911Wl5vXXxXzVBWTmsN6d3HRNBVU9OeNr1nfB9uuS1M
         b+3CEvBMYWnmBb0ZyaBVfw2JVekuiYzSYqwxv5BLABYnTzmk1PdYYdY7Zq9dDglrENvY
         XGgg==
X-Forwarded-Encrypted: i=2; AJvYcCWP+EKlwgMnA2YsM7sX9l7ZbhW0k1RhNIkgPCVxpzWBF8XCRFzlqHw2kOJZwpKktrz4QytmCw==@lfdr.de
X-Gm-Message-State: AOJu0Ywi+XYiEJmmdwE7bfhgbr5NUYzLP3oG7aFw74S2+7onePjguz7C
	z7UgYV1C7Twt6BeGldwF2CRqJMThnUHLMAj7bov9fltrmMe4Z5K3gmuy
X-Google-Smtp-Source: AGHT+IGcgb02UTr/0kwG0rwSONUWntuOHdfpu/4vtC8aC3JE+iKy1LO+EoOlVaSbTrnC7NIlW1FVLg==
X-Received: by 2002:a05:6e02:2301:b0:3e6:7bb7:f41c with SMTP id e9e14a558f8ab-3e921f3c589mr12401735ab.20.1755806870933;
        Thu, 21 Aug 2025 13:07:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcaH9a1nXlNrC0W7NNBEsAUd48xCGLDceYIWsjdKTGuSg==
Received: by 2002:a05:6e02:450e:b0:3e6:64cb:4f25 with SMTP id
 e9e14a558f8ab-3e6835fd3b5ls11725135ab.0.-pod-prod-03-us; Thu, 21 Aug 2025
 13:07:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnoTsnPBzAamtczHMXMBP5+wrylfP0EM5wsj+DWCSQnT/ogDxeYpIq9h8b7eqzoUnQKnHNXpl/ZJE=@googlegroups.com
X-Received: by 2002:a05:6e02:2591:b0:3e2:9ab4:3ebf with SMTP id e9e14a558f8ab-3e921e3b277mr13023905ab.19.1755806869848;
        Thu, 21 Aug 2025 13:07:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806869; cv=none;
        d=google.com; s=arc-20240605;
        b=j6FX2ICaKff8DkN+iMmzy+Odz6WlnwhnaL+V8x9iolnxrFHfjW2EDcbqGI1rLzhu7W
         fnA+SfWdldonaBl344aYX2f4NbA3eoK9VB2I6T7+g6PTRzMzyV0P5GY+UWGxUrdVF6nY
         48gbccxEKESTQkqxV6yr6RkyM9a90/CSGleXoxwU6yWDKwlUsAfVNklOfqVBskLlXeAv
         iowDCRvL6elbMfWoyf6vBHTvdZKJhartsjz/oF0jQbEYgxYK41MPSizANixs+CoHqZuR
         K+PH9GSNhS/aIpLnMJ1/o16kS8s+Gw4dVEhK2cQcbTiKXrWUHoLon6/OWHRXvjSgDbLd
         LPqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=G9hzYOZv6YXUN4v1wicJ53nqMhopJDezqYU76J2buLg=;
        fh=ZKFH5a+wgr1ZC0h488PmoDsqUzqw+xpKTtCoJbkFHyg=;
        b=bqr0aI8r2zhH1n6+0kX9gKOecRI9XWJuM3S/6qEt2JxBYsb4ovGRVt9UF2VCK7ojde
         S8P8jdH2BaUORSvDdhf8TvnuhhzocalPWncukNKex+zq7mLFHvgM4L1W9qLugGkIiylG
         7zIaSQO2ZDjep3QA6s+JGweJoqkAhK/r5XNn6O+T2lDO+a+62ASbPkuzbUekm3UAY38X
         gWIXR6yMLhdcCn50aaK02bXkkcM1aHSeBCJnQejsoFSNvR3qSrgHiPI+jPqC6NaJYLYc
         R5ycj0LVRPlSsQqePdZfIQ6+z12hb5ihfBlsTE8d2/FRiRs0Aez3KFcs7k/O3kYCaGHN
         +NwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OILxWTwK;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e67e5752c7si2097685ab.4.2025.08.21.13.07.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-502-y2easFTkO0K24OkggApi3A-1; Thu, 21 Aug 2025 16:07:31 -0400
X-MC-Unique: y2easFTkO0K24OkggApi3A-1
X-Mimecast-MFC-AGG-ID: y2easFTkO0K24OkggApi3A_1755806850
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b0b6466so9581885e9.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWOt1EnhmvEJtWmEnYs8yPCSzSDSwVrtaj7PaxlFnLhcar52Jt2Za7upZAfp1PvtKRlnRpvGx+VCaY=@googlegroups.com
X-Gm-Gg: ASbGncuREKZb2x66G2MMhdc1Hyam0cH15upd5isK8Z3u/tPKxnGRLmruH3ui9GOHNhL
	swHMDP66T4QsTD5V0duoxXFfDsNjjhNjMbM9bqFndt+97X3Cliw0QhqMqeyhbMx2wgnU1i+0xBX
	1+EVHDFS/CGxZnS8vpNOsTwRrbtEeYHAKS0cvQYbgcJRzbqKB3JFfHbxbBmSfIdSUBDagvn+lZz
	pTY53crWW+KA1wSlti6+pYf4fs+Ljq36B7FGTO5Ky96iszhk0eXkQF2vL5LtyZ8pgsSNB+W9WqY
	fVf6shYCtMh8MnjwUdYyAf048ezAjppUdUuciYQTlC7Enkrmtx3QjUZQcdfEkVIyXw04opxSjv6
	36YLTM11/pshz3k+OC2om2w==
X-Received: by 2002:a05:600c:1548:b0:459:dfde:3329 with SMTP id 5b1f17b1804b1-45b517ddbe2mr2955835e9.31.1755806850016;
        Thu, 21 Aug 2025 13:07:30 -0700 (PDT)
X-Received: by 2002:a05:600c:1548:b0:459:dfde:3329 with SMTP id 5b1f17b1804b1-45b517ddbe2mr2955545e9.31.1755806849496;
        Thu, 21 Aug 2025 13:07:29 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c3a8980ed5sm7242256f8f.16.2025.08.21.13.07.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:29 -0700 (PDT)
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
Subject: [PATCH RFC 08/35] mm/hugetlb: check for unreasonable folio sizes when registering hstate
Date: Thu, 21 Aug 2025 22:06:34 +0200
Message-ID: <20250821200701.1329277-9-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: imUNMgYDqHTooeBfDqccfc7d8-Galq6desSb9WRlZJU_1755806850
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=OILxWTwK;
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

Let's check that no hstate that corresponds to an unreasonable folio size
is registered by an architecture. If we were to succeed registering, we
could later try allocating an unsupported gigantic folio size.

Further, let's add a BUILD_BUG_ON() for checking that HUGETLB_PAGE_ORDER
is sane at build time. As HUGETLB_PAGE_ORDER is dynamic on powerpc, we have
to use a BUILD_BUG_ON_INVALID() to make it compile.

No existing kernel configuration should be able to trigger this check:
either SPARSEMEM without SPARSEMEM_VMEMMAP cannot be configured or
gigantic folios will not exceed a memory section (the case on sparse).

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/hugetlb.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 514fab5a20ef8..d12a9d5146af4 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
 
 	BUILD_BUG_ON(sizeof_field(struct page, private) * BITS_PER_BYTE <
 			__NR_HPAGEFLAGS);
+	BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOLIO_ORDER);
 
 	if (!hugepages_supported()) {
 		if (hugetlb_max_hstate || default_hstate_max_huge_pages)
@@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int order)
 	}
 	BUG_ON(hugetlb_max_hstate >= HUGE_MAX_HSTATE);
 	BUG_ON(order < order_base_2(__NR_USED_SUBPAGE));
+	WARN_ON(order > MAX_FOLIO_ORDER);
 	h = &hstates[hugetlb_max_hstate++];
 	__mutex_init(&h->resize_lock, "resize mutex", &h->resize_key);
 	h->order = order;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-9-david%40redhat.com.
