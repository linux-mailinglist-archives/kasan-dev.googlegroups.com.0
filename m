Return-Path: <kasan-dev+bncBC32535MUICBBYXP23CQMGQET7QLY5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5887BB3E8EB
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:12:36 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-8870219dce3sf412527539f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:12:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739555; cv=pass;
        d=google.com; s=arc-20240605;
        b=lf3N/fVogjFcSPDoD42zYqxClPGtDaV7c3wL721GfaJhvGeojFdA1BzbXcJjnsvskb
         Ijf0cRE3f2AqntHnTW/ajgUYH9TsEF8Bm/0U/CUdXIP6BItG1XD2KmP242llxcrxtU7T
         tgCvsQIebRUch/5LUxwLOGeTpZ4Ubjcgwt+vbDiqnZNc1aSdIdAx727u5YJy8BUV6WuP
         8fYk4JsVxdaSPm5T8wVGYQ4Edci82/ChpJDwmic3OGFYWcKMPwpPiq7os5bJEIfOp1wX
         6d3KVyVbZp4ulI2glzC59AykHcUmC1upGXQh0jnmYj+lqKiYZ4fN0Ju1dHgENtIGaPzr
         SOrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kylklYnvpJAEpn1ykrFnpWvCBhqKXaYMtrdGLqCMUrw=;
        fh=ffj1RGKflhokwblYaB0jEp5dF3Jn8tapPaMpMccm1Ec=;
        b=OSwZVXyivb/K5XcvB2FEhlPs6Po/tP20ezMSf2UyNEV3IqqiOIxSuuB1GhqBWBTX1c
         ojuBLSWDxT4S17unPDxieiKg9m3v3mTYa8I3MEcDI6sPbHouEghMzRPfn7D7VNGtZr47
         UQ/5WnRZartmvpB3XQVNqBaVHN9b2sS1TfIEFlVUN2dRbrxVDIxxSZGuq2cGsdCTU9zL
         O+KtUZSMojgxtoXh7pnHsxldn5PwPFOhLRK8Bv8HaEla3eH2d48QHrik1xTeAmh/+N+w
         Sb6hVBrgr7h3HW7P38CTB1ixeejDTHoZplQ+OsoD0uDvWHoKInCAHUbbD8SGYQh2Q/Ob
         745Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SxLze3GO;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739555; x=1757344355; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kylklYnvpJAEpn1ykrFnpWvCBhqKXaYMtrdGLqCMUrw=;
        b=bP3tqWKXu/ESR1BnJyG3mQIUvfPfbGo6ik4Qv+NblCMfJxB2EUg5CY3/lX99FjllFF
         +yOsyVpXkCkgODhtJ+huQi6BbLur76eyKLsyuKGWhJSQAK4Tfg/NNyEvUoFX/3pmrzDx
         uA2mh22L0890YEBo1hKIY9z5x+vlI0CEOGdmSSswA5OgBq8rM0RLNpzDjRMKjDFds5k1
         DYpVJxTzhDTQ5WrQC7MbAs0ziKxknsji+5k5bRXdxMAZ9uy6WZ/KGyd10OJbvO2wzaGN
         QFi6mpm6OSkYHaGvIQfJR6OH33dv+M5X2ttxE6xNTFNpJjojx1cHGrvHh5xJL38Yv8DP
         Y3uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739555; x=1757344355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kylklYnvpJAEpn1ykrFnpWvCBhqKXaYMtrdGLqCMUrw=;
        b=Y4H7Z6Opl95GkVTThk/iUgIrBi6rDYZJvyiKc3IKbuma4bq1stetASX8ffHr5ijgKS
         NSlXSHMunk2nmDjVqdNmJq1cpu1Q3IyZB5bE/IPk3XYkTfXaUfMbQ29g/6F+4IxYREo0
         8kpQs4EC0oHulycr65+Eh2mLJtKsmrkQltv/T/S3PElfO3Q8hkV2p1j4VDUsz+kZjWUP
         tz/i8Q6xyg/bb6dDh7SPirkrcbXkGoq1AkoT7WuRhJQQQZShIUm9cNlMegFX2FNVvXt3
         DwZtrb2FbQtQnye2LUOrsnawtc/VUXgZWmq2S0A2pChZkdcRQZNU9iWnW9Jq1FMgXERz
         BDIA==
X-Forwarded-Encrypted: i=2; AJvYcCVfee1+5ZG0mACCiz0zKNtlaN3eAwlCPXCcjCccwoYW1lwOrXIcmgKage7q969nE/8YMFN5DQ==@lfdr.de
X-Gm-Message-State: AOJu0YyOyO0K/cxs5piC07m5Tc7nN/aw9HskT9zQAOD6d+/I7L0knVmI
	lAx/U4YroLllAm2EFzwCt39gABG4LGaZ6Kyb9MvYnR8SA1oAdqZ+LX0j
X-Google-Smtp-Source: AGHT+IFhFnjW9nXSNswR8DV3nl2/+5OIRZBNNacsH2WqA7DfbfXdEH0KjGDxava2mrGJ/JsagcihoQ==
X-Received: by 2002:a05:6e02:2503:b0:3f3:3b81:e857 with SMTP id e9e14a558f8ab-3f4024c7e84mr141149745ab.23.1756739554750;
        Mon, 01 Sep 2025 08:12:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfTixQlVkAoB7tHuGCpbT3QDIsgr1+ymeMTIL/eKxXARA==
Received: by 2002:a05:6e02:178b:b0:3e3:e743:1e41 with SMTP id
 e9e14a558f8ab-3f13b55828bls34817555ab.1.-pod-prod-04-us; Mon, 01 Sep 2025
 08:12:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWS0aTZ1PBYluVoaKhpH1RlK632lM99PsjmtQ6sFAAjk4kD17EuyYb+j4X8wmfdHFRu68IHvU6RvTg=@googlegroups.com
X-Received: by 2002:a05:6e02:3c8a:b0:3f0:ac23:ea89 with SMTP id e9e14a558f8ab-3f402f9daefmr175625385ab.29.1756739553746;
        Mon, 01 Sep 2025 08:12:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739553; cv=none;
        d=google.com; s=arc-20240605;
        b=jKDn4g0Xtj8cAzgm+1PoYZOVHz0x6Jonpepe3N5GWN/XVWIhQ8Woe3bIi/hk2WgCoN
         ta/kRxbN7uv4qaiP2m/XH9jxTWeyVtOrHs0IoehOu/6MQkPA8wEkuwQ7Mjrx3N4C9ORa
         1/UJGQS2+AEyeSbQMPWyUZzcE9PNf8jd6eRwEg36rilL4SkhvNG592Go7yE0BVcoFPDz
         HcGLnWZ6gy2+WDPhxRxGQPTS+qu2YuIFbzvxY+pbt554v8w6xwsbd54xLILbVs4NzCGl
         aKdfuvrpxrjO3hxm4tPoQNt0Rd1/LAo052VNhICWIcij9WixK40eG9UurH33K0ZR3ajv
         NE6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xdu9xaWJPy4xxrd5+T58pW5GTA8RumIRC51tNRceaXw=;
        fh=KVKCnFHLO5wS+HINkTISmknrhIAkJHIUmMVx9+zh3RQ=;
        b=T70C1KHjtzP8dw2LgvbX+YDlaMpAJYWWjY67fHDxuE7Rsjpc84hh8T4kcyIG8innAu
         gX1WIA6xJ6VJ3bY6yPONr+/wS4v8fHBX0J3tMXMNAdFc5IxbeZde1FacwbADoaiB2q28
         +JilX+Tb/zSC+03WBexTaDhtanM60sdkY6YNAAU4jCXiQScZJ9ABrREynIJroFqQnsfP
         jPJ9JZxIXBBlfKPs6W5S6JkxNK/huhTXu/HXWsn50fAZZwdyKAabqE4bcnTb7vHXS7uh
         qNhoBKaHDwZh+us/ZcpDHBITQHywWTvMhR772/WQemMIfUp/6yak4tWYPAeFqN+9H8sA
         dkXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SxLze3GO;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f65621fe47si91685ab.4.2025.09.01.08.12.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:12:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-631-7XKs2uOQNGSb4vphMHuW0w-1; Mon,
 01 Sep 2025 11:12:29 -0400
X-MC-Unique: 7XKs2uOQNGSb4vphMHuW0w-1
X-Mimecast-MFC-AGG-ID: 7XKs2uOQNGSb4vphMHuW0w_1756739544
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 49ACB19560A2;
	Mon,  1 Sep 2025 15:12:24 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 4FFED1800447;
	Mon,  1 Sep 2025 15:12:05 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
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
Subject: [PATCH v2 30/37] scsi: scsi_lib: drop nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:51 +0200
Message-ID: <20250901150359.867252-31-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SxLze3GO;
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

Reviewed-by: Bart Van Assche <bvanassche@acm.org>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Martin K. Petersen <martin.petersen@oracle.com>
Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-31-david%40redhat.com.
