Return-Path: <kasan-dev+bncBC32535MUICBBL7P23CQMGQE6XG2LTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EDBAB3E8D7
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:11:45 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-30cce9b093bsf5643473fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:11:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739504; cv=pass;
        d=google.com; s=arc-20240605;
        b=BQzAA9XOi52S1NHaDSIVRR2wkzSwrvFFzZ/UijR714/j4ekng6yUCrxE1WW69lHVjP
         5tMcPW8u/kgp96ojl6ZDitDKx4PkQp+27dso5/MiqhbJuhZ6l75mLbT+07GA4muWVKHF
         cUDQLlok/vgw41JMFiIcbKb38dIaiI/Ayk7iaF8tx+hHvBbhfnX1VwkI8GrY9WLTpJZF
         Prd45oYpdYPZMMc03BOS9iNoU5bP4nwUl3V1AVPc1EstvsjbkBiAOluxRTTai+mTN3gO
         1hJD+7Okm6w8HQYKTLpBh/rKfcbR/zZ+Sdks5NyJldmQhOvjwhZEwC+6Xartl09jKL2t
         dpuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=v+0korH7JwBgG24po2xo5nyhekcSMLgea3TvQBkAQLU=;
        fh=54A8RyJSVAaUrVqkNGQM9wy+crvLDzHyvsz1ivdAQKk=;
        b=PAid+Ms34k6so9LOf19EHACB7h/q5BoItnpVqtTvU+KZqyXv6AS7ERrLpfLVLffX7M
         Hrm0yND0iqHdJs5h4J7AhZFTIXRHnpFiSXi5mPOaZkhbYSsrN1+GmNlEvwdTdXemStAP
         L2InpzNRxkREebbwUYUTCSa+neyDvTOWDr3vh0LAWOijgTY3UuFzJ2uCjd+64f+gh3rQ
         3Rrem86yBG6Gki5haSLJsyU7tX67k6z6/JZeSGUSSeGA+diYb+OybsOqXYrIojCfa4f8
         S7mFH+7+P28vIuvIq6qR3Vjg0mTcc8ACxWsQ6TxYTkx1mk48/dWzQzmgv9KIIrqlfHfd
         VQ+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=O88midU0;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739504; x=1757344304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=v+0korH7JwBgG24po2xo5nyhekcSMLgea3TvQBkAQLU=;
        b=MPOGiYMEFjgSgiu1Par53FanCl7D1iovQgeNzy80kycwwdb8vB8GTIWhnolte12EBa
         bTxLUg6ueI38wNFYx0IBl/USB6xXp9/LeIPlcAM5jRja/5rm4p3bEHkCjVF2YhpyHggV
         yzW02fKu7MRKj/eY6RkXTiedaRY6+1jfNfS3i49ZUA/xXzPOoCUdxxLjd+dFd/T1Snqs
         N5Q46krXogi1BCH5o+iOvyuYEWh1U3Nfj8oJiFCYZENhm+t6GKXwWUo0Jop+82GtGnn8
         N9BfBcchJXkRbB37G9vHtIBtAkmvoCnLTwyV4XMLhncNVA1SPudwZa6w4Lxsgl2RaxWa
         pmwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739504; x=1757344304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v+0korH7JwBgG24po2xo5nyhekcSMLgea3TvQBkAQLU=;
        b=Q5KkUPrCQW4teobGFKO4PTNQB8QuIvMZHY8udgOMnseol1zZodaZvPh/u31mHOpmoo
         KzWpSjOU71UQ1dkD4tdbo3FsyVbnv017cqmC5uhZ9C4QPB6Ht57LJZLD+ieGIYTI/IGV
         2ETn0Q6wjcMKLQiGz7nkO5JcPVyniBTNxdn6DFLjHzr1Sr2ZPU7gJbA4VtA//CK22dJF
         +MrP5eI2zYbyTnVDuBv/i4vfqcQW58qAyKulnnKXZVzTUjHn07n/dUbO+4fdpZ/vRpFr
         VE9j2ShB59nJZpLn+6ZMJkuWJvWU6NM8knK+p6TbRmGTkFddXc0oDMrzaoCR2QqWC5YZ
         i5hQ==
X-Forwarded-Encrypted: i=2; AJvYcCUaH5TkRnUzOWgAjtdRjD7G2tBMlUpnuO2UAgac4zsdBeS5h9LfCqyiR8qd6nSGsn+9YE9CTg==@lfdr.de
X-Gm-Message-State: AOJu0YyrjMxmO5SCa3hFphCs9CVqNrselpNYAmOJG6YNhF7wP2bJmiDM
	tOBD9vhSDXaXVSogMa59aHig2HTeyNI2Txa8SvNCjvMRuOa0Rz2ZMRyu
X-Google-Smtp-Source: AGHT+IH0rYi95sEbDnd1Q12R2QyIrX5cWElC6mqj9DS+uyppQ1FKvl82eLjSQtW8JKeRiFAHh5hCsA==
X-Received: by 2002:a05:6870:1582:b0:30b:85a0:eb66 with SMTP id 586e51a60fabf-319630c7ab2mr3389092fac.12.1756739503845;
        Mon, 01 Sep 2025 08:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7u8JZOY2prmdxNsnVok6moCyTbB9JQhr9IrmIqpuk9g==
Received: by 2002:a05:6871:4201:b0:2c2:2ed7:fb78 with SMTP id
 586e51a60fabf-31595d5fd70ls1179162fac.0.-pod-prod-01-us; Mon, 01 Sep 2025
 08:11:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXeAnrbHpLCFWDFuMeJHFQJxLTqjJKVEx5X4+TvUVbfKEUxJH3L/vsEVm5JTIs4iP1rcPRq+AYI0k=@googlegroups.com
X-Received: by 2002:a05:687c:2186:b0:315:29a5:fc3b with SMTP id 586e51a60fabf-319630c80f6mr3847904fac.15.1756739502729;
        Mon, 01 Sep 2025 08:11:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739502; cv=none;
        d=google.com; s=arc-20240605;
        b=IdaWEQhzVfAniqScvyOigxIk+c4oyr870xOR0A/fMqVRuKe+a8O6xPpYx2rr4QC0Kd
         nwz/JxCxsn1nyBsg5FQ/3grdJ7pCw9ox5vLzOAEy5IcIsMmsdBEeqrsDMr1hLCA8x9T1
         IWCPJdqhbtZyrbWbCRvhy8+pcOmjHOZaOBI2otNRS+JXTaSAwvOJvF+urGSBpfJ7OcNJ
         7TqRzvjFKRXMG5u7aibTtGBCAQRnHyETzgAH+KofOITyVvByT6prBy9VA4cfOGPN9oKM
         bq8prj57fcwP3tq6X1s/0bxklMrVNllhcJcHSbe1YpFqBA7HbzGytOHkB7jIdum1a+/d
         04Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=p1jCKThuxMeVarNn2yntb5yTQBw7NhKRXi1yCoCreSs=;
        fh=fvedQo4vQjbZYpEFV+wFhJA/YMCG75fdLIq77JRWiy4=;
        b=evccQ2vaNWla2qTC59Pym+T1atRSa3No15hJUiaARuFv0J7nBwO0eDSbxe+9gnRO8X
         1TASUapdq/VCMKSiI4uL5WvuGes4b3DOFIZ/4oCY+havSl/dtY/Hr/qqfh+01Q3eVJH+
         ab1vtR0PEbOGxTGvooFSiWNPZ1hA17/J8jTQM07v5zOAWCi/IaZHUT2VcvUM3LEKIs+E
         0urUSTsMo9ajMCuSCsgbwyVNEHS3w92Dc7WIpV/dP423QJFx9xJCKKEJ5AUgXl2IhUHy
         lwZ9IFrwqmYRmi3JOomI4Yb4ppyv4o+MhdIHfDRomePW/92odV/KUadriJylpmFo7wWj
         iF8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=O88midU0;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3196d170149si184894fac.2.2025.09.01.08.11.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:11:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-687-20oygJbWN0mott4utV957w-1; Mon,
 01 Sep 2025 11:11:38 -0400
X-MC-Unique: 20oygJbWN0mott4utV957w-1
X-Mimecast-MFC-AGG-ID: 20oygJbWN0mott4utV957w_1756739493
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id C115419560B8;
	Mon,  1 Sep 2025 15:11:32 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id F28721800280;
	Mon,  1 Sep 2025 15:11:16 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v2 27/37] mspro_block: drop nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:48 +0200
Message-ID: <20250901150359.867252-28-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=O88midU0;
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

Acked-by: Ulf Hansson <ulf.hansson@linaro.org>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Maxim Levitsky <maximlevitsky@gmail.com>
Cc: Alex Dubov <oakad@yahoo.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-28-david%40redhat.com.
