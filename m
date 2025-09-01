Return-Path: <kasan-dev+bncBC32535MUICBBEHP23CQMGQEUUFGUGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 557E5B3E8C7
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:11:14 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-45b7c01a6d3sf24784215e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:11:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739474; cv=pass;
        d=google.com; s=arc-20240605;
        b=FpMj2k6nDTqRcLt9USNN4gurzF4lVyMCUSGAyfy2OohT8JIhbXP8NInx90S7s4+P9Q
         EANFMhu+SP3LqmGh4l4HOWc+bv08Z1es2bzE3dqXbUCRFEZIIHht8T7wooC3l/zyvrxe
         YS7CYMnwwcIgtqdYaBfYFKYHD0QEJMmBYQnBI0+CFr7MroytsU1rCVCHsswqjFooIgQm
         JiOmLyhmIOM9YQa3I0OtUbDy5lxbBwczv5Oak23YbNRWv4VqqMhm24MJWsMlHmPYOnFR
         HHzNYLdf47n9LDj3xzuaNJCsybeirjctH2hMeVjcj8s1D4GMO9/NNL2cSZKGnUV14BpG
         x62w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ly0u6lmEHu+YifZFqAFdLGr1P2k/0zSbJyAXnRXydP8=;
        fh=JmNNVcxZMPEw1mEdFa9lLqqCmYPJYFGaqPbvtMNi/gM=;
        b=Yd8wPZwEPwblIKKwwtWh3BBRCi19g+fMJM5naDuBdfkVv+pT5+6kIjJcoL6h+bfJwE
         SW1s4s/MJE+PZmRkHr/6/bBGnF/zNSJqF683Z6AbCPmFRJpTuv9RhIQYE1Uz9Ps4PJOo
         KAW264ldryLuhbMSq3/v8fCiOfZHbK7LBLQKdsUDUrRISOqW68QHOQubW872vh8E0U36
         lFOBOvvXx0rTNl6tBGOUG8gHaKtrPnXbm8GnlrXKQ81IdZXgbMy6CStfoemYxScWXmBK
         tTY3chkDxAR+p9jJUnDtLU7V0Q7mW9NXA5RgO9tVnv2pz9CsE0kbvEWJCQsWSPc5dnaN
         h4YQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QvHyoiwb;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739474; x=1757344274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ly0u6lmEHu+YifZFqAFdLGr1P2k/0zSbJyAXnRXydP8=;
        b=HORRTGpemasW5AyDnLR4BRJ92xgH7X0PNpetHqLpqvg+Itw2UB/xyxd6cmqklWYlsr
         8xYgXGu3zw7qfP+S4LXX9gW6Dne22ILHhXE/3oREZWImpLYkC6+vi9tZLaOdxgxkMMen
         QOK3WtHqE+RskZXd+Rxf03ZEHmILrJNFJiygy0LQfmCXcXHxj6qPznjUdROP6riFKZq5
         2oZPDkNDV3PUtXejxEjUMpMZbmZEYwXN0mDjE9S8Rr14friJAl620Dsqe75FTPRP5hbt
         29sDPT4vIT31G6aQraTb4K9RXRR0Q/QeN4GlqyHSR0Bb8rYrLdBiIiQPslrO7Bc42H/s
         hD2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739474; x=1757344274;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ly0u6lmEHu+YifZFqAFdLGr1P2k/0zSbJyAXnRXydP8=;
        b=K8FBAZ6xe/VGD3fcqgLNX1Eef8lNT03nKYhWGzaxn4kZ6HrUYF6eb5ui7zWgqahYZe
         B4BnJGACmVsPf3rCe/VXMOnRWuaPpP5FGSyw/3R74plHonx2sMW5N14THc+TrwnS2cBR
         GuvDiiTpm2XYtB0+W00SVr6G0VisvxJB9cgNi5R6e1D9YPGIJnT3VoOpkzg9RnGIJZ7Q
         v8NHTR1yBr9vTcluEHApICGX8vD3Uw4VkWwyJevJSSsiFUZtTBDQGlSj501WhnPw842a
         /hj90d8j17ve3KqQSgoGC88GClsMfjhMXcm2fF2y6WxzGj/BdelllnpfhQEy43RIf3Eh
         qaqA==
X-Forwarded-Encrypted: i=2; AJvYcCUdOrMd5hIqqacACm1rn7vFh6aza8hEPS1HcfOpHnLP8/ndCT5Z3q+jTsB9aC2SpVDd21SB6w==@lfdr.de
X-Gm-Message-State: AOJu0YzI7o7dSt4y9M1R3S7SXX98iWF4GUIsqQAyj900O+wR//Tvt6m+
	s02f088IgnnDQP1G3wJ4AY58OkzdejBqkU6zKXc76+O+BUh0ib6uYxXs
X-Google-Smtp-Source: AGHT+IGo4Jf95Q7GfLws3qjJzZrlLGPYaoSkKURKUSQTY5Us5xqLdIxyqMsUuBhdNPaZ4FycrDu5dA==
X-Received: by 2002:a05:600c:4454:b0:459:dfde:3324 with SMTP id 5b1f17b1804b1-45b855b34f8mr63005225e9.29.1756739473515;
        Mon, 01 Sep 2025 08:11:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZezHbKyhobUmO3LC6kG08i6JFBEM9FEWUAdUuIAk9lJpQ==
Received: by 2002:a05:600c:3b9c:b0:459:def4:3d79 with SMTP id
 5b1f17b1804b1-45b78ccf4b1ls30359905e9.2.-pod-prod-02-eu; Mon, 01 Sep 2025
 08:11:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUigmsH+nzkSRPJyp6vLt7tB2PNG0flqXSeV73v7vnF0yHZ5kyj9/XhKMmzMpLQGNoeOEc1d4/KLXg=@googlegroups.com
X-Received: by 2002:a05:600c:3b29:b0:45b:6269:d257 with SMTP id 5b1f17b1804b1-45b855c428fmr70188865e9.35.1756739470736;
        Mon, 01 Sep 2025 08:11:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739470; cv=none;
        d=google.com; s=arc-20240605;
        b=GKS8JwGad+YhbqwUby5Zwpk2obTmnakNxOeyKS9i6eXHOQ3F196bvIFrCXWtzBg3g6
         N+tMMng1vFYnLWGk3RBwGAaRHCf19ulsYUYkgDYMEcxUunASZVOeMsHxBpXvv+Wzl+wm
         c1M8jtZtwHzGzxZC3ClPoXbdvCWiwAe/qQmvOqciXHEs1Ed0RiL3QGQXFsl7jhmrMn8F
         ysfMhwP+tTm3I4fGe6QaeomvyyxEuRNIA/csYcdUXOEZECb3JWPHsTrWY+7XcwzuuE3m
         uE61g6wz9irIW5SxwEYVLJV42I2CCXWkJ9735HLrQE6HTyz653VMNn4jxv14s6390f6f
         XxVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XXIrQPK2KTSHTm5n0r+eAcK1OeXNu/U6cGKCJgmF5aw=;
        fh=7oIf4gaXsVNPdB1NMK1Rj2Nw3nB3sepib2VzAYnchPY=;
        b=IHmMmai7SLlyWQUhIZpVaH1yJ3T4a4gMQA+zTgwe6RHsGFNKbSZQkMB9Fa+7GhCwGl
         0OEwNVkDkb3KaqeNGM3029sEQ6j4WI6Jgub01RDNWlzqw+7wsN5EJroJpkLMCRckgguU
         sCe6wpfQxFiboL4iNk4qRvStD2hGQOdTTeBRZXskwzvgT72t70RT4CtLgqK0DFb9yJ3b
         xa22fU8t7gFgscebHisOhFvSZw2KDYl3souLcfwZd1SfunAG4jjxJZIO7uUBpEteGz+H
         Fl3sSX8muKjb6Mi3n7nqqOCgXn6ls/lPkeq7P9U2WpHPf0tscRlP3ROkV3VgEGd3WaWs
         yncw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QvHyoiwb;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b8b916d49si1016635e9.0.2025.09.01.08.11.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:11:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-80-VJeTZUpaN-Gpu0-I1j8nww-1; Mon,
 01 Sep 2025 11:11:05 -0400
X-MC-Unique: VJeTZUpaN-Gpu0-I1j8nww-1
X-Mimecast-MFC-AGG-ID: VJeTZUpaN-Gpu0-I1j8nww_1756739460
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 389871955F27;
	Mon,  1 Sep 2025 15:11:00 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 0AAD418003FC;
	Mon,  1 Sep 2025 15:10:44 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Damien Le Moal <dlemoal@kernel.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v2 25/37] ata: libata-sff: drop nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:46 +0200
Message-ID: <20250901150359.867252-26-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QvHyoiwb;
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

Acked-by: Damien Le Moal <dlemoal@kernel.org>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Niklas Cassel <cassel@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/ata/libata-sff.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/drivers/ata/libata-sff.c b/drivers/ata/libata-sff.c
index 7fc407255eb46..1e2a2c33cdc80 100644
--- a/drivers/ata/libata-sff.c
+++ b/drivers/ata/libata-sff.c
@@ -614,7 +614,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
 	offset = qc->cursg->offset + qc->cursg_ofs;
 
 	/* get the current page and offset */
-	page = nth_page(page, (offset >> PAGE_SHIFT));
+	page += offset >> PAGE_SHIFT;
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
+	page += offset >> PAGE_SHIFT;
 	offset %= PAGE_SIZE;
 
 	/* don't overrun current sg */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-26-david%40redhat.com.
