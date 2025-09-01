Return-Path: <kasan-dev+bncBC32535MUICBBHHN23CQMGQE33LWPXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 555B1B3E864
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:07:10 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70d7c7e972esf92876996d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:07:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739229; cv=pass;
        d=google.com; s=arc-20240605;
        b=k3z5q1LqlcBs5/LUYaY92bwR7YtajNbOWgs8kgSvlY9+M9rLtUoUy/rhBByiWym5Km
         q9yungxQku8nCLMERC1ETYqTL1Kq4k80DFiqizAaWGX3UgCKl+DlrxUsm1uiE9ca1ivc
         Y7q2KB+vwdDueLRaluAM5jJVSA7GDMuotRp6CLvsHux1ULzBYMAe7hukzyPf1m/ke+rc
         rn/tYZaZB2GapWxijMKyVHK0NlRB4hOf2CXx/+c1cuzqvtbvv5JIrNYSApYw8MKi20B1
         3sy1LxAVUSUKUsRU4epUXHYZ2Xe8chn1udXNW+vzc2cId/oLPXIzFupUN1Q832e9o4AR
         GkyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=AJ7UrSTiMPvUuw5Z0ng1rYyFM7eZKQgCCqlC7c4dWfE=;
        fh=Z1Cc6j/DIzhAlAc+g8wKX6hks8IL6wyxmxfqlejdedM=;
        b=MJR3GlSe8ASNM6oRtSQa5FvaR/tgNZoGLb6P/enjWfHENdmFeiSGItN0NPB9GeC/SR
         0aMmiy09g/doQKeFzQFXaZL2t0uH4NYW6E84trLGqFtXiWERpBAWaT29JhZJ7tzmCP37
         b9E0fKjGRt1SEYhV+DBT05hOG+U5s482KKFO22gPC1Yfk6YEsgeSycPEJhXtI7MBi4iZ
         mirQHEqSqfM+onSwnS1emVomacFz2U0NTcqBC0/F/bmWHQPWsKyTmNBffknq2uoDNvLv
         Rm8VOiZ69IjNU+/4ELikw9a5iM1Wip886RPxVKAztxGV0dPoKQ880FXx4/pGxQpAYCaM
         0rmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=B0U54YfN;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739229; x=1757344029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AJ7UrSTiMPvUuw5Z0ng1rYyFM7eZKQgCCqlC7c4dWfE=;
        b=QjD5II7zt7gjjzUOqao5Bql9rVGwfBXR+naaq8/LXP+m8KY9wby5MxLrpFuG06hX1I
         qVG/+v2OTXJuBv8ndTpc8r3jolVnTG1KfEIiXbcmcRCsfb3UzH5wdfJC5JyfNr6FdWlH
         Sgbk7JbI6khKr5s+qOimO25s5mbMFDqEVeI5GbXZikw5WztYzsOvw0PzDnPI1zMWco55
         CSQPiU5UxpI56roPlNy6Pn/EDB4pkA4MSuROyzMCRM1G8zlTM30HyiykU0I/AI83aSod
         Sl28bq5opUcTg8CL3Z+NEcqcBLaACFjayaGwrcMBnuGWb4WDC+dfOqtHrHigkgyQ9JJA
         Ez0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739229; x=1757344029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AJ7UrSTiMPvUuw5Z0ng1rYyFM7eZKQgCCqlC7c4dWfE=;
        b=F3ZYcSHd2TwmKszc0iuGRexEsC83fMqced197kh8/QaPL/bw+LCwLO+1QnoizoZU0P
         HarQLnTWgwkyB9rJXAFr0ZRBmiTUBMGG0d60M3friGJZhV0SAuNUXqnCVuZ7dxqAfp4v
         jFRROLfWn4mlbtznqsJxdWTj+sXY5zGDiPnGOCyxeKZ4h9pYM6++hkw2z/prgq4weQMT
         N20XZBAnesgs5/OsC23gfx39uarcfh9Pxu6uhZwAOZ9tQM+vYOX/+Kdz3QPpgubcVkyg
         CF2fi8nqVyIElH0mfPLdPTnoM4XC++ued8TNaIPJnaaS1EHT1ddLOY9QqfAtf8PwptWp
         /JYA==
X-Forwarded-Encrypted: i=2; AJvYcCVii9tEEWokhKXq7/OUDoZobQs9Ky4mpJUJQ4wIX9dXjtUjKQNc7EnnVn6P3oIr+S0MxUiVfw==@lfdr.de
X-Gm-Message-State: AOJu0YxMJChYFmtooxR1g7d5TLtr8fW3JkAJsq36vZe8p/KQYhD5wuOB
	NGFRX/77PQQiDWKD52DmPtroILAMTmSWM9oGXkkWDyovh5uUanByFeWp
X-Google-Smtp-Source: AGHT+IHAVymIRx6KfcZUeY0ULvSLj05XxRbWcMpWdvDcpWWU9eLS0drVgzSNJx6BPazNk2ghHQDB3Q==
X-Received: by 2002:a05:6214:40e:b0:709:6582:86d8 with SMTP id 6a1803df08f44-70fac789c6amr95647106d6.21.1756739228759;
        Mon, 01 Sep 2025 08:07:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd9Qj3WjdDeLcRkndAbVwuln89MiFMgmY5K1hw2w0+NWg==
Received: by 2002:a05:6214:daf:b0:70d:9fb7:756b with SMTP id
 6a1803df08f44-70df03db7eals66536596d6.2.-pod-prod-03-us; Mon, 01 Sep 2025
 08:07:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4KKO6m+xcUGxgqDgBssUj0L/fd7pzTZs0Cgap5GkSq0UfT2j6Z31fYmqfgdViKPF4OcAqiI8mHKw=@googlegroups.com
X-Received: by 2002:a05:6214:6113:b0:712:e30b:ef27 with SMTP id 6a1803df08f44-712e30bf209mr61543126d6.13.1756739227711;
        Mon, 01 Sep 2025 08:07:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739227; cv=none;
        d=google.com; s=arc-20240605;
        b=bXxTSiDH6Fc79Xa193LRHD2Zvtva7poVET3mQRuDM14Hs5JjAsrwrwNRpDrD9E06Aa
         xEvjoM1PKihe9FaeCqg0hj4iD2I5X55ntizfopHDQUgBlcbygTiCL5ZZWhdE/MaFoYq3
         S7f5R/KsZrhDdqhoBQ5334L9Xf8qLpDNwKK6yXorzuvY7A/jrvAqu7+oU2SUm9TujtDG
         44cunGPlDJRtgYHwJzK7g11FLUAp7xGYDn3t6frG7S8Z/rSUmyhba70dox9rnIiOfvmk
         cU3XuMUst0653jkwVWASWGd4oU4nbwGJPqaMu4PiukPUJb5IgFWanVgCYIaFtZ35bO5C
         GywA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R4lKJy8SBWSrsm7Vh+zb8hrnJCJALrpbQ5NruWVxUgs=;
        fh=ao0q64WF1kU97kUZOWvWUWJ+YNDVsUUaOpXSF7SJDBo=;
        b=HWjYV9/etKzZuYTLg6iTKWrOCY8qI2cPjXBKHUSHBJ/3Ctey2gU2MVlzs28uDAJ88n
         L2NsZD9N/m6xm54kiDnN05U56IaHvXjpQHEGFyaOu2R8+mn45ZT8aezxLpB2WIncuPtQ
         SqhM64TaiquCB5jsI8H+rscPjqCUQYI7nZhYyG0Mouo3Teo4YbcHeF+XKO26dHO+gmaU
         ElF2uVA8FR1GMrL2RMBe8dBDQalw/GbwDh+IEwaWftiD9oHh87AKiIi2JwkN6cuPg1JG
         32phBPCkIB4N9RnbD7AX1m3TUqiTDtJkOFq3nrRhDqz6FPbEvh/jFLCOuuW8MGN8LJkD
         wa9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=B0U54YfN;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70fb279f749si2222546d6.8.2025.09.01.08.07.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:07:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-488-6C4RCufwPEqzyZW8T0eORg-1; Mon,
 01 Sep 2025 11:07:06 -0400
X-MC-Unique: 6C4RCufwPEqzyZW8T0eORg-1
X-Mimecast-MFC-AGG-ID: 6C4RCufwPEqzyZW8T0eORg_1756739221
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 331CF195C27E;
	Mon,  1 Sep 2025 15:07:01 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 3B7921800447;
	Mon,  1 Sep 2025 15:06:47 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Wei Yang <richard.weiyang@gmail.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
Subject: [PATCH v2 09/37] mm/mm_init: make memmap_init_compound() look more like prep_compound_page()
Date: Mon,  1 Sep 2025 17:03:30 +0200
Message-ID: <20250901150359.867252-10-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=B0U54YfN;
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

Grepping for "prep_compound_page" leaves on clueless how devdax gets its
compound pages initialized.

Let's add a comment that might help finding this open-coded
prep_compound_page() initialization more easily.

Further, let's be less smart about the ordering of initialization and just
perform the prep_compound_head() call after all tail pages were
initialized: just like prep_compound_page() does.

No need for a comment to describe the initialization order: again,
just like prep_compound_page().

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Reviewed-by: Wei Yang <richard.weiyang@gmail.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Acked-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/mm_init.c | 15 +++++++--------
 1 file changed, 7 insertions(+), 8 deletions(-)

diff --git a/mm/mm_init.c b/mm/mm_init.c
index 5c21b3af216b2..df614556741a4 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -1091,6 +1091,12 @@ static void __ref memmap_init_compound(struct page *head,
 	unsigned long pfn, end_pfn = head_pfn + nr_pages;
 	unsigned int order = pgmap->vmemmap_shift;
 
+	/*
+	 * We have to initialize the pages, including setting up page links.
+	 * prep_compound_page() does not take care of that, so instead we
+	 * open-code prep_compound_page() so we can take care of initializing
+	 * the pages in the same go.
+	 */
 	__SetPageHead(head);
 	for (pfn = head_pfn + 1; pfn < end_pfn; pfn++) {
 		struct page *page = pfn_to_page(pfn);
@@ -1098,15 +1104,8 @@ static void __ref memmap_init_compound(struct page *head,
 		__init_zone_device_page(page, pfn, zone_idx, nid, pgmap);
 		prep_compound_tail(head, pfn - head_pfn);
 		set_page_count(page, 0);
-
-		/*
-		 * The first tail page stores important compound page info.
-		 * Call prep_compound_head() after the first tail page has
-		 * been initialized, to not have the data overwritten.
-		 */
-		if (pfn == head_pfn + 1)
-			prep_compound_head(head, order);
 	}
+	prep_compound_head(head, order);
 }
 
 void __ref memmap_init_zone_device(struct zone *zone,
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-10-david%40redhat.com.
