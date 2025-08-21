Return-Path: <kasan-dev+bncBC32535MUICBBM7ZTXCQMGQEEK34TTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 92487B303AD
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:20 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70a88dd0193sf34344246d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806899; cv=pass;
        d=google.com; s=arc-20240605;
        b=VLELBpvJSoKZvuB/4IXS9ThBQEjoQ9gTChwTx2tu9i0ta0U5bjF+8IWows9+DnY5zg
         GZKMGnLlK1DJ9ma2tWBNEApTmr73UMNr7X91A1zfg5QU9EHAyVQolsSx+JItvxkBffV7
         pCzIcmKfy3DDC89sep6Oufa43yLzypqhPfV+8BfLUFpTYp0uyHXmiJdM56axJO45lHkD
         iQBSs2yAKScLvjth+u1l8gGJ4xzOYt4jjNDxz2zAiKsG6aOshWK4wETEuxf+v757tRwQ
         s8/lxueHpOHciGE6WxdgjOD5s3MnMFwhdWPpEDUY3DQQkpqBOB4OkYicASW0UMCRWgzu
         TS2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kSOap+a3fRx3W8YBUEN7uohtpzmVBOX1MaZ2yPNxSmk=;
        fh=jeVRxVhsi03jVqnaKXSzaO8t+EowFT1lzsEyWSgtc1E=;
        b=S/bmpRp+suateh49YDglAca8DpquBRXkInT+4KdFBHgv0XazLvlUvd138ODvRRhF5W
         6CYV8gBrKJD49OFX8Fhx0pxlnzOgAe7DstfGG4mFK/bXyjiMmUnFhODKTkHYh7HrdQeK
         dyc38EMBBP6XXE+34Qh9Sc+mvoI+Bwtg9S3mqq34n8OfTIdprzF9uMz4svqBWVtyV/w6
         pmx/hgxSjobiuRcTGZAyWJ2ohjPZSrjCgFWTetJaatSJprTq1X144aU8kFTCXkFeRNXD
         u1KOvuLGfvJrTvCOVpA/pdjSCoZZ4Gvzb1p+1fNy05xOOqhwgX+7ovvxccT58/sqhkCd
         eMPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RpPHIlIz;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806899; x=1756411699; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kSOap+a3fRx3W8YBUEN7uohtpzmVBOX1MaZ2yPNxSmk=;
        b=khJCtyHcOtD3ojCGgHkK4hyOTIfg0DjFBEe8aa2y7NwlOB0JKMEHT4428EKkNIrETr
         LHRJwxgre73zWXSKu8CyddZxU/IF+Oq0QuB+hfz3jMRE+Fd+z5k026hkUoEXrXEYZfyQ
         /UFRzAD+i59Q8onHATWjxLeTtIR+f62aRUDorqN6NZKz2JiiExutaWw/xWGwgFPVPmWw
         S3riU5kKoFcA0L0NZQS9mi7WYZueYDjTd6sptHg+JiseDqzZ7dKdLPKjyoFJ2/DV8Wc3
         78+5I0lI8jukxeDI09l6ImZKp0yGVYfyK/lLAd0G6gZyyY3j5xMWKxc+qWTRmXXXBDO3
         k6sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806899; x=1756411699;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kSOap+a3fRx3W8YBUEN7uohtpzmVBOX1MaZ2yPNxSmk=;
        b=Shvkog1txu1uwKkJZ2CQZ9r9KgwnQo73WjYHrGloxtkc8kapBWQBxmJXooEXigyV8v
         4KPqNFa9hWwQ/CYfRE5bA4sb/V1Rke15W9fHzyVJwMUC10DYaovQvQoO344loIcxOxiw
         51iTe/hTisdn8Nuxy34e9mfQLBsrUftNeCoZUlGWHOyLAp6Q94wU5qxUS/H+5/xLgztB
         tFJ1CNqzgx5dK8jPRKi2QlQxxxz1bWWbJN9BeuoUgZrsWrMOskLAQ033XbzrxxeK+Bkr
         h8F6G3QSvlud7b8H2d0LpArD49vpBTTfc9fDJ4OFZqT0blOfTiN9ZFOOeYG2ByhPVhrZ
         2c8w==
X-Forwarded-Encrypted: i=2; AJvYcCXXFke6UEGFrqxPsKoxvwpris+DNycOr2Fidkr1sL7ip3G1hrjHKj8L8bdYa0bvf6Ks0QB41A==@lfdr.de
X-Gm-Message-State: AOJu0YzGETPAKyxBBGJx5tnaRfqFdO5AKO4crTMS9kMKUjJ5PrDNTcrs
	0DYtr5nuep7PD4K+nbVjREhXkH5YYZqAtTTZVLOcqdKAoACQm9rqVdJU
X-Google-Smtp-Source: AGHT+IGCMbhxbWsRD0biP+3KY4AjMQnsrfJ9oYE/RvHfAPx4Gqdb2P9O7LAAOflpw/3DiF5gfIZQyA==
X-Received: by 2002:a05:6214:262c:b0:707:6665:eb67 with SMTP id 6a1803df08f44-70d970d80acmr8772406d6.27.1755806899339;
        Thu, 21 Aug 2025 13:08:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcTCbG+eJl15Yl7/ITZ7nqNYO/2Uhn20YUYZg7sAAZ9Ug==
Received: by 2002:a05:6214:d07:b0:707:2629:964c with SMTP id
 6a1803df08f44-70d8591d5c9ls20226736d6.0.-pod-prod-03-us; Thu, 21 Aug 2025
 13:08:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDY3ov1YUSOBua9nQ3WJC1v8Jas8OIwtjWoKLao6ex+GZ/+bZk6ZQSFbi8CgtaMrfSHZ0RAZoMld8=@googlegroups.com
X-Received: by 2002:a05:6122:1e0a:b0:538:dbd2:2ece with SMTP id 71dfb90a1353d-53c8a3c14efmr241836e0c.11.1755806898376;
        Thu, 21 Aug 2025 13:08:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806898; cv=none;
        d=google.com; s=arc-20240605;
        b=iRUJ7/lQqSDINvLIRfRhQ17m5Os+dClVxiYyHN1pyHWrYgoCcZSJzdEP+qEq0X1xWL
         WBNWckr+Tv8h+5nnMXU6KxBkbLU8uoNdcaMQvO+CMBHh2F3MVaoziIuc/uY/xdJBqxpf
         z7mHgfDjP4hzxmeedFjR3O0AZsOAwTELS89fcm4apbwnbn0Wb8328C3uEIvUbsQwaoy9
         LJqLx7GX8J49CejSYWIBIlktZ35+6wGZn+7ya1JpQB69d3RW5Iipg17CnpcLJ1liwwPx
         x9d+ywT6felidHeUpi23dOtZqCNk1evWDAG+v0Jgzi8w5FxZt2ePXAUAgsG4fxDf3iI/
         erfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qEz5al18caSg7WeU7/xaDhHrA43/vq8xaUIrOF+uMyw=;
        fh=mJNFLro5DPGUb9LdwforydOCGT0kz22bOVOi1trveVA=;
        b=ALMeQ2QkgbACIUi/LuKFk+l/ZJbOkMoukVelt+KyV1gX+92JRS+sZdzqtjnkQBVFeH
         x4tTcXbyWcxT1VWbwNiy0D2HMpIglFnRWr4FScHgr++H85ibE8rUxYK/VWBcr8KvSF9s
         5foe1tE7ObIQ9XVZ8OHNcAiVSXqXxG6fBLfxp/HI6H64JC79b2RtJnhXzXOCbCu7MGDI
         vvB2VRIRGK08XZtPp3tnikIVFhcQbFdmbkNXl7TuxC+u+X/90h4bjVD+jbxydN9OF5B9
         xEWw4IR3A8NgMt2RjcRpCs1g2iU79whdh59Wyeg265ZL1VQIPRp4OFKtJkoB1pk5Y7Wv
         FvXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RpPHIlIz;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53b2bf2af08si711557e0c.3.2025.08.21.13.08.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-583-DS-oU5UzPJ2Gq7Ndn0kfpQ-1; Thu, 21 Aug 2025 16:08:15 -0400
X-MC-Unique: DS-oU5UzPJ2Gq7Ndn0kfpQ-1
X-Mimecast-MFC-AGG-ID: DS-oU5UzPJ2Gq7Ndn0kfpQ_1755806895
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3b9e743736dso787492f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV79cfl7AyOrQw49+bpyC5IRKaXF/5VUkYi4uunOZlJzMs8oWrBB6Vl3y0lik6g+E+7UJ7If/Gq3ts=@googlegroups.com
X-Gm-Gg: ASbGnctsxx9Kp2QpX0ohHutCQWpgjjN+PzUuJ3+oqcD5m90N0mDZmWvZy94UQvdH1n4
	aictPBHeH4qCahts1gUX4lVGWnqjcpW8xeHLGjpAyM2/wNlNO9/2q+HYdBTUYXszJ/pIGjVhZ4j
	tXLXSxc1vUWTnTyBuboV7DcrzdXtPxjeITADtTP6x8jbmpwOea6j0wIRMbx9YRk23plTlWfkUz3
	hxRSyIta5yQhZU2pQtHbG+470EO4ePghw1Fc+etgZ/wJFwqiGsobAFWuBJeiGUjmWUVS7iHrrQo
	eIn1qsDL4fS2awmNL862sL+myCzlDLK3rKyZ+DLwdvoreJF1pJ3/rytWpijVuucnuXRSHrXxJVB
	cEMOliJ634yPoSJkVxxrS1A==
X-Received: by 2002:a05:6000:18ad:b0:3b7:9c79:32bb with SMTP id ffacd0b85a97d-3c5dcdf9bd9mr215844f8f.44.1755806894493;
        Thu, 21 Aug 2025 13:08:14 -0700 (PDT)
X-Received: by 2002:a05:6000:18ad:b0:3b7:9c79:32bb with SMTP id ffacd0b85a97d-3c5dcdf9bd9mr215789f8f.44.1755806894010;
        Thu, 21 Aug 2025 13:08:14 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c074e38d65sm12982954f8f.27.2025.08.21.13.08.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:13 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Damien Le Moal <dlemoal@kernel.org>,
	Niklas Cassel <cassel@kernel.org>,
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
Subject: [PATCH RFC 24/35] ata: libata-eh: drop nth_page() usage within SG entry
Date: Thu, 21 Aug 2025 22:06:50 +0200
Message-ID: <20250821200701.1329277-25-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: GjiiE8w7CLHWMM_glGarY1m1lNPARZev4BZOP_AWuQw_1755806895
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RpPHIlIz;
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

Cc: Damien Le Moal <dlemoal@kernel.org>
Cc: Niklas Cassel <cassel@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/ata/libata-sff.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/drivers/ata/libata-sff.c b/drivers/ata/libata-sff.c
index 7fc407255eb46..9f5d0f9f6d686 100644
--- a/drivers/ata/libata-sff.c
+++ b/drivers/ata/libata-sff.c
@@ -614,7 +614,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
 	offset = qc->cursg->offset + qc->cursg_ofs;
 
 	/* get the current page and offset */
-	page = nth_page(page, (offset >> PAGE_SHIFT));
+	page += offset / PAGE_SHIFT;
 	offset %= PAGE_SIZE;
 
 	/* don't overrun current sg */
@@ -631,7 +631,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
 		unsigned int split_len = PAGE_SIZE - offset;
 
 		ata_pio_xfer(qc, page, offset, split_len);
-		ata_pio_xfer(qc, nth_page(page, 1), 0, count - split_len);
+		ata_pio_xfer(qc, page + 1, 0, count - split_len);
 	} else {
 		ata_pio_xfer(qc, page, offset, count);
 	}
@@ -751,7 +751,7 @@ static int __atapi_pio_bytes(struct ata_queued_cmd *qc, unsigned int bytes)
 	offset = sg->offset + qc->cursg_ofs;
 
 	/* get the current page and offset */
-	page = nth_page(page, (offset >> PAGE_SHIFT));
+	page += offset / PAGE_SIZE;
 	offset %= PAGE_SIZE;
 
 	/* don't overrun current sg */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-25-david%40redhat.com.
