Return-Path: <kasan-dev+bncBC32535MUICBBQXO23CQMGQE2ZULUNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id C5E23B3E8B0
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:09:55 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70dfd87a763sf46112366d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:09:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739395; cv=pass;
        d=google.com; s=arc-20240605;
        b=DvfpmusKMO7E145v+rQewYUR7MYQxPU/ukSeoWWhwXixCyWf8VKc9HV+woCi9XNkYA
         up8D08UZz41I1LmatJNzkFpxel2pQOCXk+sG7Zu5WC3RCVb6KXvh9Cwx+0TscWi+ovcY
         AnVeHlCmfIuuKl3fzjAqt7L6Q+sLOypW1D8g4EahWGtP0ihhjYmkp51WNFZRmbKTLH2W
         ga46a+rWMjp7EzvwcSPLitacKuyu3u0LZbHE6d+nbWMSwv3thuS+8BkHI3/TdOlij7zY
         tWjsqM/axn/IRNaG3aqQQqHnpN26Bhpidx0jrcFjUaQ4SxBsHMbD/GDSjX0pGzp/1mmQ
         Si2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=OQB4FCtlWxhQNfXpe68Lx1ZTbKffH/JqSvvUAkjcQpw=;
        fh=WBoskE/2xPywbsvBqW82YdAgbawuV5IwUEDA6zoOAfw=;
        b=KrA91Q2kBRQXy544lhLj4WUthZ/t2/ARoeMhYud3u3vMQts/QY96ONl5+Re/pBR1VC
         UQKstz+4HjM246LHCBbzZ2DQTywYxJ0Q8BP7A3qs1Sk+2nk1SJwmYeMy2HB46wU4ZlhO
         NA3AV11cvmb8Y59+L26ZpjZy95mn5QAjrOcj42Ej+v0yH2bpr66PjwzEJQzVS37bl4fP
         PHslWyr9Vmj2QaRxEUkjM1s0g95kG8SIo5KvEzY8A04U2s7La4fCbabTw5uuejwcTpfW
         S9iA4q7Pf1vIi/iyiLP3kPKxzKawNU/UJgixj8WTIYSyWsOWxY5Eq1D1VNCvvWYx+v38
         aIWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PRx8rG0j;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739395; x=1757344195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=OQB4FCtlWxhQNfXpe68Lx1ZTbKffH/JqSvvUAkjcQpw=;
        b=BOZrxW6F9zcgp0tpy3X9jZPdeNSqYZnInVr78iMZzaPwKi1OKKDNbC5+n/9z4mqWI7
         bowgZi8rteYs6wIiw+wp1ZYX/k7wV+ztvFeyX+4ne2kMPL5OtYQFGDy5Rol5jRemZk2m
         j3PmGrMr2taF/B44YpNWYM7Lp4GY5FLjn9hRr+9wuoLR/6cqAdNBW0XhcN/8A9Fde0YG
         mD4X29hrGZvXbUTWPYU0jkS3jHRwiYX031uD/+xIgNpCpbZ1IsVjdV5eOMdjwwVpplAx
         tZtAZOWW2xaFv1xVWJm81+aWx45CldrX0Hci+J8CkFIqVv2K2XEAmOKFdMjSzENxbK3N
         PBsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739395; x=1757344195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OQB4FCtlWxhQNfXpe68Lx1ZTbKffH/JqSvvUAkjcQpw=;
        b=Hg6wZIGz82GqaoQoCO5eUT+9Chj5RVpih1g9ckZtPRHKSakiJLrcDJp8GXyXWHqEoF
         OkyUyPhrkOqkWGU+FAWgp0ox72nNhCq1yNGrcSSeQmXXtAD9a/cUUw03IsnPeoLUa1Qz
         AcOVjsFwf+ZSfyVlPj4PyeYtBqIk1CjhT7wvG89U+Lfg9nIVjChX30a57AS22E42Fw6w
         4XJmoUIFS8m80Gszd30Ar1UaVMaH20aNbLb5Ck+CATlNcaSAmmjg/xpa3m0Q9sLGt/X7
         oFzK8iyopwZaz6+QYh6Q3QcGmbk74u3f5zwc3DS02cD98KmNBaIYnuFRaGl6ER2hFEj7
         76xw==
X-Forwarded-Encrypted: i=2; AJvYcCXswFl+DFzI2eLN5ObHX29I9i1u6IU9nCrCDA7wfol4gBcx0bBSWv5AnU7K3qOmiIgYCYoJXw==@lfdr.de
X-Gm-Message-State: AOJu0Yxz8OtSoYzrPBBBVvTpOFJ5v1ZZgJzmS68UgiuQ04fMMIvdDWcf
	5guz1STrbY+FOpJngUSDj2eYnEuxC6pqzl3uSOQvuW1xOoaNF2naTMgP
X-Google-Smtp-Source: AGHT+IGMm0Uten0uJ22wakfzrj3N/jzApwQxbmPPXYQ4/QlcLRLGjzRV/9YqfyhLdmMMPC5ImR16lA==
X-Received: by 2002:a05:6214:4017:b0:707:3cb1:3fac with SMTP id 6a1803df08f44-70fac740196mr82584396d6.15.1756739394718;
        Mon, 01 Sep 2025 08:09:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd8wKjYXUFb7xTrOt7qd2pcGYjyHjSQFAsrhhrT0bV2yQ==
Received: by 2002:ad4:5743:0:b0:70b:acc1:ba4f with SMTP id 6a1803df08f44-70df04c37b8ls70711436d6.1.-pod-prod-08-us;
 Mon, 01 Sep 2025 08:09:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKW98NAUdaGrQx5YYak1DqKwtWVq0BpXF0ShoIzsYSsZRDT05pxA714Zl9nXbTkPWVM6hyplcg1/s=@googlegroups.com
X-Received: by 2002:a05:620a:3909:b0:7ee:683a:6b35 with SMTP id af79cd13be357-7ff27b22913mr965685685a.31.1756739391927;
        Mon, 01 Sep 2025 08:09:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739391; cv=none;
        d=google.com; s=arc-20240605;
        b=Jhtmje+EZCuLBIsDix5xbkqKPOQl+LedilMYrxG/rH0USYVEJXx7cNW284L/BLi3PO
         5siTsdJFWMaYFooD1cXZwIR1biFp2BzOoxsAD5W003yzbepeqa+HVMcbj1tsKGX2rxKE
         LG7UuRqHeomqSkfNNvVjRDXpoNjGR17uVceGgNCjL2e4USVnaBcKlrz2F94ji7mcYy5A
         BUbnKkRS1LkIp6OxDkdohcUTDnMd7Ya+rC/Yw1YVg43HM+mCVpI6Y8Qig4++i8xtDvZn
         uzkQiDN/4xcIVYIQBSAy3jYOKXJ4vtdrki9XRrERJWoqzWK4UekLTabuy+drHAwWJ+Ef
         GE9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0kDSZHtV88oad9zCDDBj5yf1ZyH7AU8+3y2ZSBVzpUw=;
        fh=GuBe6BazrCMh+ha4dGF2+G1Zbg7JSX1Fjemh/GfuP68=;
        b=YKUrgGg4r1lV7Z97sOqrynsyTqVlT/wE41aWisY5lSFVrP+nlBOZiwkjK9innZE+sX
         xrubCgJQueHTgFdX8r+dY+TSlmDT3pnly9MYCPPN83MrNuXSx1UxqwELEUPCNXsTaaX3
         Y+8xRp23HLMISjsW3fomYg61p8IjatDu5Z+aQSEwaVvmTDW8MUMq9ffMxMtyXVBCPFCJ
         AH1ouumeybrPGykYWZb5ZXoEQjMp/c3Uq19K+LXqHwx3glhMYOg80BZ8NPYir2SkWZ3B
         KHB2JYyqAwYfyn+QBvL14SOIDH3m/vP5KEW9aA6Ajo7xik+RWaqr+Y16WZuJ9oj4ApA/
         2Pug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PRx8rG0j;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fc108a914csi40789585a.5.2025.09.01.08.09.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:09:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-35-RS9bIdDPOQKXbvnr4BPRbg-1; Mon,
 01 Sep 2025 11:09:48 -0400
X-MC-Unique: RS9bIdDPOQKXbvnr4BPRbg-1
X-Mimecast-MFC-AGG-ID: RS9bIdDPOQKXbvnr4BPRbg_1756739383
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 3EB7719560B2;
	Mon,  1 Sep 2025 15:09:43 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 54B441800447;
	Mon,  1 Sep 2025 15:09:28 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Pavel Begunkov <asml.silence@gmail.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Jens Axboe <axboe@kernel.dk>,
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
Subject: [PATCH v2 20/37] io_uring/zcrx: remove nth_page() usage within folio
Date: Mon,  1 Sep 2025 17:03:41 +0200
Message-ID: <20250901150359.867252-21-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=PRx8rG0j;
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

Within a folio/compound page, nth_page() is no longer required.
Given that we call folio_test_partial_kmap()+kmap_local_page(), the code
would already be problematic if the pages would span multiple folios.

So let's just assume that all src pages belong to a single
folio/compound page and can be iterated ordinarily. The dst page is
currently always a single page, so we're not actually iterating
anything.

Reviewed-by: Pavel Begunkov <asml.silence@gmail.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Pavel Begunkov <asml.silence@gmail.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 io_uring/zcrx.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/io_uring/zcrx.c b/io_uring/zcrx.c
index e5ff49f3425e0..18c12f4b56b6c 100644
--- a/io_uring/zcrx.c
+++ b/io_uring/zcrx.c
@@ -975,9 +975,9 @@ static ssize_t io_copy_page(struct io_copy_cache *cc, struct page *src_page,
 
 		if (folio_test_partial_kmap(page_folio(dst_page)) ||
 		    folio_test_partial_kmap(page_folio(src_page))) {
-			dst_page = nth_page(dst_page, dst_offset / PAGE_SIZE);
+			dst_page += dst_offset / PAGE_SIZE;
 			dst_offset = offset_in_page(dst_offset);
-			src_page = nth_page(src_page, src_offset / PAGE_SIZE);
+			src_page += src_offset / PAGE_SIZE;
 			src_offset = offset_in_page(src_offset);
 			n = min(PAGE_SIZE - src_offset, PAGE_SIZE - dst_offset);
 			n = min(n, len);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-21-david%40redhat.com.
