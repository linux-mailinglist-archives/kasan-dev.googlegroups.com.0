Return-Path: <kasan-dev+bncBC32535MUICBBW4EX3CQMGQENFKWTQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 073A8B38CF4
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:10:37 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-244581c62fasf3256825ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:10:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332635; cv=pass;
        d=google.com; s=arc-20240605;
        b=FVhKlxHHaUEl9iCGRGHzdE0exLqd3JZiDV+UQrS8wF8ES7KOlsHKJEuMJ9mCtYJQ2P
         1/KAbanY0jY3V9AldJopQuMQUFYLK9Ux0kKDeNH5rzZXOmEZ5GbrjaAJHj+YD8nRGE/E
         8vL6XckR2XPFKF66yvFZy/oKsI5tMYu6EAqWtmVjWRrNR0LlvlXyFlgqk6hwYyMjJ8jK
         rlRxusrYl9P5iQEYVMSXvNabDWHNdApHbsh8RiIZqKp6NusrUppAAELP3obSXPWB+wle
         2Lv3p076w2ECJx1T0EzaURmmsEoRMglGfcTeRitHrsRPFLdeXDv2Z8/Qn8LZiyvbsFnq
         hskg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=6RUz2DdffAtVyUjpF6cjR8PYS0Z1Tdr/sRWrES9zKJs=;
        fh=O8FwmU2ihqYyxIkz5x1ivq0zglerR7+nXyNjoO3BgqM=;
        b=Shc6U1JAPCXHsfj2RIDIulg58ctBTvaQgZb1RMkN7aywe2HtEYpKLH2aro3NBUZYSz
         WN607HS9GWLS6bAs2q6SxZZBqzHqOmIU8NqeehcFqMnwVLEcgr22EkoqI1cIdP0/mqty
         5M3VbapDrU91dnoB2bL3+uPGVnKqfDWVwN0w2k05i21OBlWQFjU91DetUwST1wFlI241
         kPRCbSXqthKJIVwaGP2iA0hla0bVve4GLxxWoqiF1FzmC8gxTZ34x8CX607yJoHedXUM
         L2faVIUkapfRVU65ER4mFn6epteeJd08UpHuMfr/jLTyBlIvM6cHHJXwH4bweugiVx1z
         6xRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YcpE9LNV;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332635; x=1756937435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6RUz2DdffAtVyUjpF6cjR8PYS0Z1Tdr/sRWrES9zKJs=;
        b=aql0w2PkIVcyT4sLDfBbcWp8pGwv8KxRJBS2FZxv/yQc+DyWDrK+wdzrxNnSMwfpaL
         axJn2InkOWCcXfO9tfGt1chBIP+pLWKNF64QAcY4RcjqNTAWQcVVnvtE814b0RfJd7tH
         Wed9AkK3Zn1wYSl2kGRPu3nfenxBKRiHQ/y5nN3vc3nR8XINDmoxIig9q2jDUS/7evMX
         pLq2wZrqIArszcfD9+WTWxQoBBWfpkSTDCVOAGt66mlDTttn2n3AFXeNSAS7gZHDQgSr
         oixNHr1f9Gj6CbvOcgG1KbYBHXtXgb1RB9mZTXbEaCxZXPyLrMHYIl2PSsU0sAMmlPTh
         DVDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332635; x=1756937435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6RUz2DdffAtVyUjpF6cjR8PYS0Z1Tdr/sRWrES9zKJs=;
        b=D0nW9JDfmaTyDLbzNwP7irlUI/9HWiu7XarzJH09IjpnEk4xSFzMF/5Rhpkehrms+0
         SPGRCS+ITNhGR3HQZCmT3tZfnPytVnDBXwsluC7ZSwX9Ks4qIMbkaMWp52doKhQhRKq8
         0bnJqTtWpkBfvmJ07cO8YoSZG9APqHXFHZxeQXQbztFP6K3h430r67qTV2LyjyiBCnKa
         niyNxAGOXEikI0yILeHdFWhWjYr27rRNeA47pxucpbjwjHXGOIvIznkUt9u4ha3ifg8e
         4rLtbNLIc0p26PLwJYDGngMrEKb1pTPuWEePSf6oeROH2+7TvjprKvYxjwvQMsjs6NYL
         RRVw==
X-Forwarded-Encrypted: i=2; AJvYcCVPr4Nyzz0wOogpxpEt4N8kNCRn/GjG9pwgBcXV3+TI+IX+OMEMrNgbYJoFpax32gSgyGpKpw==@lfdr.de
X-Gm-Message-State: AOJu0Ywyn6Wg7zbK6trjgi2ryuYDGieKfNKNvWJchQt+JRIIOZphmApd
	Wo0kjEDrz4a81gTqOkjBOBHUT09ndkk7xBM7dWj3XshOOJ3V+6fAfLZH
X-Google-Smtp-Source: AGHT+IEphygfU5YPWclHL9VeKw1D4/B1XsSKRc5jgecP5LGB9a+r78AG03kvQ8u611r1Zsdub01uIQ==
X-Received: by 2002:a17:902:e78b:b0:248:98a6:fb55 with SMTP id d9443c01a7336-24898a6fc9dmr52853035ad.16.1756332635384;
        Wed, 27 Aug 2025 15:10:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZflvdq7e57iPEfXUWAH/EYi2XANTdMgD80/iezNzmNiyQ==
Received: by 2002:a17:903:1894:b0:248:c926:8445 with SMTP id
 d9443c01a7336-248d4acdfa0ls1085745ad.0.-pod-prod-02-us; Wed, 27 Aug 2025
 15:10:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWG0sNIEPOjDPYWaZOYbj+353JpU1A7qEeEaRLUcSGXl02jU3mEUQ9uvFZZWnk2C6YZNcV5JZNoieM=@googlegroups.com
X-Received: by 2002:a17:902:d486:b0:246:b46b:1b09 with SMTP id d9443c01a7336-246b46b2296mr187367905ad.30.1756332634098;
        Wed, 27 Aug 2025 15:10:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332634; cv=none;
        d=google.com; s=arc-20240605;
        b=Y/fzea+FLJu/4OqmRPijKGFS+LoW6Oq/edr9lzdxGn2QgJH9HfILArd3VH+dvJ6WcN
         IiwJ7yMH+oxTLZwCGnU8FqgYofPQDEFdpZSFCKehlqOMAMqI6JaGsR52TCj70wwo++pl
         7acJ7nszg2F1tepdnyFrocY/FI2FZNdaRub/xSjVEk+IKYTaUxrH9AErZP/N1CBz6OyA
         B9mVWK1WUyqhzc3ABViM8a2yNPAyGJCFjzIVHAf+fwmWUlbJ7ghq+Q8pYVfK0ljtsWkD
         p3kabS7nhu4OTM7OjVDtbBcHhZ2E8US8QRk84x7/QkZUF0KEa5sP1sk2/gBimdtnmpf8
         br6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KMi10d6QgZutAbGzL3nSBlY7ky4aRhvMewcb8M9EfzA=;
        fh=PA8gQiSfD8x1QCP5VzKamiq/jEz+EN3lXnisMMv5yn0=;
        b=Y5KjmpLDcAlvxubaQa98GULlA5+v4z6U1gdPG7H/eg84wn/23zyEsWM4Gb0GOfMqoN
         oXVTwVdWcDHl0IXSh6ka/231tPV+4T24VZBuaQi68nSam9DfvhMjB+lUdyNfl2lWR0hu
         c4lq3Kan5R+Hn1g0lxmMjn/5sZTGFuTeh3IH5aM161bHNGyBoCNrhLI6U9UYtDmhns50
         yeGXyTDxFCWjWAj6dTmz02ftbh2A+F368bdJxzMS4EFbAl5llYPLrV8JQTecNs3ZYzjH
         WHn829T/RmqzJMQ0l0aLfceHtjzb/XrAxbB4+M1iue+W6yhCsdthHCehwkcgQviQ8lQm
         3LEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YcpE9LNV;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2466885e39fsi5608915ad.5.2025.08.27.15.10.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:10:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-126-Kk9fYkzwMM6MQxKq-D-h2g-1; Wed,
 27 Aug 2025 18:10:29 -0400
X-MC-Unique: Kk9fYkzwMM6MQxKq-D-h2g-1
X-Mimecast-MFC-AGG-ID: Kk9fYkzwMM6MQxKq-D-h2g_1756332624
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0FA831956087;
	Wed, 27 Aug 2025 22:10:24 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id DC4FD30001A1;
	Wed, 27 Aug 2025 22:10:07 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Bart Van Assche <bvanassche@acm.org>,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
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
Subject: [PATCH v1 29/36] scsi: scsi_lib: drop nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:33 +0200
Message-ID: <20250827220141.262669-30-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=YcpE9LNV;
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

Reviewed-by: Bart Van Assche <bvanassche@acm.org>
Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>
Cc: "Martin K. Petersen" <martin.petersen@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/scsi/scsi_lib.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/drivers/scsi/scsi_lib.c b/drivers/scsi/scsi_lib.c
index 0c65ecfedfbd6..d7e42293b8645 100644
--- a/drivers/scsi/scsi_lib.c
+++ b/drivers/scsi/scsi_lib.c
@@ -3148,8 +3148,7 @@ void *scsi_kmap_atomic_sg(struct scatterlist *sgl, int sg_count,
 	/* Offset starting from the beginning of first page in this sg-entry */
 	*offset = *offset - len_complete + sg->offset;
 
-	/* Assumption: contiguous pages can be accessed as "page + i" */
-	page = nth_page(sg_page(sg), (*offset >> PAGE_SHIFT));
+	page = sg_page(sg) + (*offset >> PAGE_SHIFT);
 	*offset &= ~PAGE_MASK;
 
 	/* Bytes in this sg-entry from *offset to the end of the page */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-30-david%40redhat.com.
