Return-Path: <kasan-dev+bncBC32535MUICBBKMEX3CQMGQESYVWHOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 52639B38CDD
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:09:47 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-61de2471a7fsf320145eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:09:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332586; cv=pass;
        d=google.com; s=arc-20240605;
        b=HNld4CSXrLOpIvRNznOCUAmLlxd1VpIEAmb8xa7crnGg6TFD6f45GgKStAOI0/fRin
         AH+ksI+gBrjg5xM9ZQSly+SJXX7LrPzkVkOqgFb+ziAXlWE5XLUE2zVb146ECcaBnQHx
         I6vv2CZ7iJX7nLGIzTQyos6Y/WT+KoiIL+ErbAt22fZDPr0oUZvqaqHAE/XmFvB1qQOS
         Cs21drCNmVncdI2wbYElHhyCbKV17y5VKL6Ivf9Cj09IedvwNhYq6uu1prf8HfF3EJBZ
         xpPU3+/URta88zHg9q9CISLtcxD89f14KskZnTF417Uq7J8lMxzT1ODzcQr/RWFmHovN
         O+lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YnEBBAXBu1u3cQMTLCW0iUogZvVi06NE73MdWpOm+8o=;
        fh=hmQYCE1vQ5G2y6O3pS3OKpv1AR/gvxTSqlcUmRR2yR8=;
        b=OAReVg3e1/WGQ0kLhRsJI8P5YdtDIALL6IMt5ObrOtwkBvj/eOauWqQvOqhtVLtm88
         cVXK5N43u0ybWKvilPhARNZOUQACDrzUCE/TIaAqc4T/ABPpjpzFT6EFBzVPGnQJq6mB
         yF67kzsVaWuga0aC+52CBNv2hcnhx24SsDyxT7iAVZGoTSve/seFQWAWoKxUkqtEqico
         qhDfqwSRmw5KWMlaOgycCg1FmtaMJlBEBsCtUZrP9mUUE8z5rDUlSDImYVvRfw1kpFtz
         HwNTM5Gsn7RtZFKw1598RUEkdcaWzT25388drU+45KSiK11WAkmFvxj6KV+Kroy0etVG
         /9Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LPYliZZb;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332586; x=1756937386; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YnEBBAXBu1u3cQMTLCW0iUogZvVi06NE73MdWpOm+8o=;
        b=ONPDl6lN6VJ0uyPqv9VCcw2+HSIbDiKWCgRmLzdtu4QUPyyI1kxB5oaixmlsgVHOi2
         6eucZ/2seWbP1J1czPjs/Y5EG3tl5foSQ5NxdMZO4qiT9C/+sq34hflePny9F21pNFD6
         nWnIXkH81hctNfxmQrNxrnMIWZJe5C578f/+WKkiOUwLF/imMlSYUxaNH8rCpcHkNk4h
         JREPUUw2/mCr9X2E1e3atV28aRbtbYuLiwAT8RjBJnT8s+ILBa4s/3SyzHCjz82mUXnw
         8hsKDSVdruDxQwRF2fAmOjV7N8Fjn5ZsrQeb0CX4uALPACoQeLdgtlJd/h8gCyr736zG
         JEEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332586; x=1756937386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YnEBBAXBu1u3cQMTLCW0iUogZvVi06NE73MdWpOm+8o=;
        b=OZZuHqjK5bSSXlavYM6GomF9VaLXNOnDeJEt3Mzqpt77iGVeRXXu7EgR1AOvLWp8rv
         HvQnl2H2cWhJKw2HgXYltrxDnRAfJAyX3CzpZbsgzledMZFNtgsjIZVHK9tDJTXmbPQx
         LQgaLl0RHimH3ecc7mRJU9NHQb/QdyClVux68uLtuSlaDiDhmCL0AKR3nDwFVFtA+U/O
         PiN49yVTNm5v8Jkz+MyBBJE3AWc+jmR67yBRzpgvi3+D6GaV+fEe7K3CeY7TMUfvV0LQ
         58ubXwnxTv+6UtMiqjitivoKJavDZ0KCyEjhRlPfyNoEMgWMIoppmyrwdoCc2RcUOA48
         bVLg==
X-Forwarded-Encrypted: i=2; AJvYcCVtZgqH5iJOdVacuxr1LHV9GP1FugMOmG5LYWeDh7NuHGSgD0x9FzLJc+MO4WFw15p8pql/fw==@lfdr.de
X-Gm-Message-State: AOJu0Yxear/g2PFYJ5PoCehZ/U6XemKR2qsHVOxvqQKMcNnUR68WhckW
	+qFJgw5hixn2WNqPYNz+03T2EAHIPIc/2Ye8dMSKL16J1oiIHupXcjpJ
X-Google-Smtp-Source: AGHT+IERdkVCHjs7jP43H20k4ViPgR0MyBqS/t9hQQL9/oxw4YgQGqOwffNSbm0lsLAgjRoBNx4mzQ==
X-Received: by 2002:a05:6820:2226:b0:61b:924a:b796 with SMTP id 006d021491bc7-61db9bb427fmr10332799eaf.6.1756332585648;
        Wed, 27 Aug 2025 15:09:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdeixOsGik1rZg79IGFbesSLOz37AbDItPLwqR3yKOpEg==
Received: by 2002:a05:6820:d8f:b0:61b:943a:28d with SMTP id
 006d021491bc7-61e124ea9eals32434eaf.0.-pod-prod-03-us; Wed, 27 Aug 2025
 15:09:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVp3YT61k8bwoQ83zMVuiuJHFwC4jjBXJL7/g/XUX2Mk/pFefFnv8UJIZztSkAhxe1BkqXu1RRv/Ew=@googlegroups.com
X-Received: by 2002:a05:6830:3c83:b0:745:2d05:713b with SMTP id 46e09a7af769-7452d057aa8mr5645629a34.10.1756332584711;
        Wed, 27 Aug 2025 15:09:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332584; cv=none;
        d=google.com; s=arc-20240605;
        b=WLasZ+SecGR5J7vGlQNjvR3zmwoh+AxNXj/S4CeZaxS9qsOlEVmYI8/DSM62upXcRb
         pYTuGFav8RzIOylijRARxh3iHLiWxQGq9d4AUziD5R4+0Id0GkFnuHyT+OkgsNZFhL47
         rdfd6oTwfsUyfMjwNDZuJ8sqyejbSUuFcXfsBEYyXu+rBHI9RWp6FzfFSHz6x+jnOuuu
         mrCmjbtbenP3i1hYSOrE852PpRd0dzS4NgRyLFmKQ2Wb08EKq8tzALhDzeDKKGJqodVn
         96nyHbX61nVpk197Pwvy60Q0qvGIMQt6eLbi2PogpwYDOQNQ4PbtOjJm5UIkAP9aSWun
         bvZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8SUmSf66LiCJvVJzeEx0UA2HTOESqflB/UZ9jC2+86E=;
        fh=kwQeefftB7j9Uk4cNGb0Fa04HMqO3NJhkl6Z01LSZLY=;
        b=T5i8VYOvWuH/qXJYZfLhznRmVb8odSp2/GkvKIxwmfCN+t1IuJJReGebiUzdq3t0rR
         wzhmjIuIz4QpVEjbogKaId2P5DhEvN+RsPAI93suQf1mOJjYIqjM9Y8BYPyz3UEybpro
         uYBysTnatQlCGqguDIvBENvovc0OlndJrKSgDI0n6rILY3cPUL/JrAsOPb2JyCYhVPY4
         LKPE63mZx6K4Vj9FjxjGeof10VDtb7lIOTv9iz9C99ILTnkvhYtM7Itnn2rzNZTLiqRc
         x8wdUYlenz8Y6mOKImGJag08bCTcsMmtTKO5eQq+M4WKr7M+nTKw1d8wU1aZ2nLC0NW/
         GCCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LPYliZZb;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e32ae13si693201a34.3.2025.08.27.15.09.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:09:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-638-wuVJZl_PPm-kz40j0XhWgA-1; Wed,
 27 Aug 2025 18:09:38 -0400
X-MC-Unique: wuVJZl_PPm-kz40j0XhWgA-1
X-Mimecast-MFC-AGG-ID: wuVJZl_PPm-kz40j0XhWgA_1756332573
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 006A91956095;
	Wed, 27 Aug 2025 22:09:33 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id C1B9F30001A1;
	Wed, 27 Aug 2025 22:09:16 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Maxim Levitsky <maximlevitsky@gmail.com>,
	Alex Dubov <oakad@yahoo.com>,
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
Subject: [PATCH v1 26/36] mspro_block: drop nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:30 +0200
Message-ID: <20250827220141.262669-27-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=LPYliZZb;
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

Acked-by: Ulf Hansson <ulf.hansson@linaro.org>
Cc: Maxim Levitsky <maximlevitsky@gmail.com>
Cc: Alex Dubov <oakad@yahoo.com>
Cc: Ulf Hansson <ulf.hansson@linaro.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/memstick/core/mspro_block.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/drivers/memstick/core/mspro_block.c b/drivers/memstick/core/mspro_block.c
index c9853d887d282..d3f160dc0da4c 100644
--- a/drivers/memstick/core/mspro_block.c
+++ b/drivers/memstick/core/mspro_block.c
@@ -560,8 +560,7 @@ static int h_mspro_block_transfer_data(struct memstick_dev *card,
 		t_offset += msb->current_page * msb->page_size;
 
 		sg_set_page(&t_sg,
-			    nth_page(sg_page(&(msb->req_sg[msb->current_seg])),
-				     t_offset >> PAGE_SHIFT),
+			    sg_page(&(msb->req_sg[msb->current_seg])) + (t_offset >> PAGE_SHIFT),
 			    msb->page_size, offset_in_page(t_offset));
 
 		memstick_init_req_sg(*mrq, msb->data_dir == READ
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-27-david%40redhat.com.
