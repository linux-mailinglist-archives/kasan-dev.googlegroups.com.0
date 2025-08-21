Return-Path: <kasan-dev+bncBC32535MUICBBUHZTXCQMGQEYKGAVDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id D43B1B303D5
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:49 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-324f2f16924sf1062847a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806928; cv=pass;
        d=google.com; s=arc-20240605;
        b=R7TYz/xGhJy/l0lzunuh7iqCph815cdpzatVFESjMGjx0mplx3Q4CvtgJe5JFXnatB
         OnVgVLac0cczpmvnO1xAPW3XrjVJP5A8COv/p28Ii61FYkOgf06hA1clfzl8HHQ8Yx0U
         JEqYI6J32q0U0GTSzBkLDWRRUuOXTENbMU71n/hIXQdp/T2vgZTwKfoTPiRVVWaMqp/n
         TunJ+8bTaPd/udoGM0RY7rnh1XrYjwX/R4gIJEMh3Puu/n17hUjubzVaVQTENJBJmB0p
         SrowbgJxto1/Z1Ogxcdv2lrTYdyKH3tUuaqdJK5UH1A0v5MUTwyCyqfW8O/9BXyfjZ+F
         212Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=M1dShEy4xH+8Y2jczowam68N0R4lNe3A69dSDhd5FjA=;
        fh=QTqerBgPAvNobwHGo7Jb0Ffcfz64fUV7cFvRdRwGixg=;
        b=Hlv7VDLSkZPmumM+Bc0l6ymXvp8iP/Pewz82umSE5Ut2SFm37CRdb7P8L7X9Cw9Mhn
         v6VNuW6qsczx9ByOlbCNC8Glr2vzlszIY4qrg1xEG13/88Mfe5zgUrvzbr/vnj3vmFvm
         05w0tOA/AvOotv8DacH8nYLW8IY+vEOEahtVx1HgTixBTc8lMqIEJDSrcgguKeUeNc0+
         zYQk81ctiGLS7Ik3uEWMFVc2gUiXIDgNT7E6F/SH4kXl6qV3nsYV7XSqe+cq9aHXgWPS
         TEBjvKFiroxPRaTgPZ7njwG2Dn6As096q1mNTmA+3zwLCASLonVcDGc5tgC2aslDUHG1
         HarQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UonbbPAB;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806928; x=1756411728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=M1dShEy4xH+8Y2jczowam68N0R4lNe3A69dSDhd5FjA=;
        b=YHZ7L1RfPfqFXsi67IUZ36K6BPo8/ULxiQDrVPqJP4B/WHxfrRTYuWInGDPHFtc3Fx
         GTm1Ea8VkOGfLv389LXkJl2yDMZ9oEbfa5tjVRO1bxLYu9sIptO8Hu9RPrlL4Q0MKGzb
         H2DMPEqCsaA8a+7iWQI5RG6iw0PPDaS157P5B5TxA00kd3jYcXI7Kb4jHHxKvTdtq9M1
         UbVbZoitYxzMeFqsjOFJKc37zm+0p6EfEkcJAf1OZb1VeVkfbs9XUA80NLiJ6XxBiGo4
         6R6CH9FJlIdl8Kx9ff36I//mxrF9xY3M9JVbeZ/SDYp/TgDwpKite0zlrYAfBz7Hdqk/
         JZKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806928; x=1756411728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M1dShEy4xH+8Y2jczowam68N0R4lNe3A69dSDhd5FjA=;
        b=pwFNgTpOYZKYt+e8pTdtwFKXoRroQtkMHcYKazO04Beqj9iyVp8+skHagPa8rIdStk
         OtMiQu3dEnxcc0eTGE/l1BernLjx4yYf2UNGfItjKbX6XwaRLtDGC3cfeF2R4Erw+4nX
         CvipD2kKKkZkgYS0WW5zSBzmKb6qNFGgNsdWyCPWEllrdqJepIZl6ipziEvcCW9Q6FGo
         l8VjKU/UZGQBFDrVWPiT0oijsy636mURo2/I12T5kC0W7UlPqQkyJJE6yEnsZnM3ERJ8
         4KkNzSWiLlBqywGiUPkk1lumg2pNA3saOQbzI6zjIuQXAr0fqTxnzz08QtPRF0qvBIoE
         Z/gA==
X-Forwarded-Encrypted: i=2; AJvYcCVlQsJnjqyhQeoYA5zWBAW6qgEV4K/tVSrQ6lDsuqsFjnpey2+2Z1yWO3z8TjQiH7eOqV/ebg==@lfdr.de
X-Gm-Message-State: AOJu0Yxa/qQb8DYFhL0Cb5x4xGOy82QovFIJMnnB8DVpBrY9q1kFFEDP
	XVy5cJGAYSS4goEASa1UpgIcVa2PKQWa8lIPpzDkBK2RPiIOG7EtKqTz
X-Google-Smtp-Source: AGHT+IGnaWW1xofusX++LL27WvpGDfRLOryq5ECEltfMqcs1GWBhQxyWooNza0r+yfkSf/kEEtZisQ==
X-Received: by 2002:a17:90b:1c06:b0:321:9366:5865 with SMTP id 98e67ed59e1d1-32518b8232fmr903522a91.33.1755806928295;
        Thu, 21 Aug 2025 13:08:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcr7HK5WBgNBSz6Ylqe1lt9c9UUDnx6Tj9sbGltCbyRPQ==
Received: by 2002:a17:90b:5785:b0:31e:ff9d:533e with SMTP id
 98e67ed59e1d1-324eb81ae89ls1712660a91.2.-pod-prod-07-us; Thu, 21 Aug 2025
 13:08:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlInNYYWrginjpT2sVNnMqWKr5Waozk49D8ddnvs1ON/9oaIySLEFcja+bdodWuviAG497ya94XWI=@googlegroups.com
X-Received: by 2002:a17:90b:2ccf:b0:312:959:dc42 with SMTP id 98e67ed59e1d1-32515ef6f25mr681458a91.11.1755806926727;
        Thu, 21 Aug 2025 13:08:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806926; cv=none;
        d=google.com; s=arc-20240605;
        b=akxYvDU3gxjFxH08pQ4Yp5Kp6loyB9euUfGXLFVKl2m9cxeyVLXAKK6nwag6E6S9Gl
         ku5w/RkPZIynejPYEPRMIfy5qmkB9+MDMJEgrvFkRUutLE2iQ5+QKWO6A+4VCFdYIZyX
         3KX+3xVr37g73ZR1hj1Do9eJRhH7dGW0wwgkU1j7YqWeRS3SazXJYxmry4UVuFCvPyyf
         29iOV5H7ToFSt8PDeFVrDCnrkzvUc1uihoq4cvpzJ3YGbGcpqvia9ixW+MsWnlInzykR
         PaePJkhYMfk2oo8dw4dRjGoQjc9ZOrzFhxu7WwdAaZhHGG86gtVYQw3RcjjC4C0yD3L2
         Z2WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z7iPpUiW3LrFM0W3XrB+Z82uodwKTsefoCzXwhLbLUo=;
        fh=SRAbeR9tqlo1aBd1Nb6P3eJeuNxsVwwncdfSbwoU7OY=;
        b=Yhce/mIbjxh07VJymF6+epJUA0pUn4UfPYhZ9x/agWL0iKw8/LbVBP24idwHA171ta
         EbgY9zaYk5WUFeET7hjzQ6alHtPFymVFnpWUlkaRGS9CE6cR+DMzEqV0VvysbypNSHYy
         18Jfb8X+L6k+2tN7kA9lN7aRNweL97nefENOwV6y7wwoxp3McybytbyTzPycK7CtLJkV
         FC8EO2t3dLlANlcgFOaFOPvj6HVMUms66OcoJTHeK7/sUWCwCo+3804nplFlbamrWMr0
         huyqh+FLXgSCEwKrUB5ShqM0afcy3m/EbXzzpX8ZaIt1JQVAaPBzJC7Wxr2DVj8QQaT7
         tvMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UonbbPAB;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-324f80d032fsi71668a91.1.2025.08.21.13.08.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-594-FMBd6oH6NAmTeSG-8XWqjw-1; Thu, 21 Aug 2025 16:08:44 -0400
X-MC-Unique: FMBd6oH6NAmTeSG-8XWqjw-1
X-Mimecast-MFC-AGG-ID: FMBd6oH6NAmTeSG-8XWqjw_1755806923
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3b9edf80ddcso517662f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU1SRMite4uariZ/N+ilNy6MaAewULMqTlyGiB4Ghn2utk2J7YqZ4HASAJ+xlIxFpiqWxzzxk7jVTU=@googlegroups.com
X-Gm-Gg: ASbGncupD/UC71LsV4bMIhDS2a29Q53+wm/xWIqA6qYP5vMVFCRQ4Ze83BCMnB1MH5J
	XlyZ3igGhtSnKebzSPY1Lb5I8seVCvtmz81CwLpxpMzdJYOUeFytJvc+Smj921+KjzS5AQ4V7Vj
	DWteJL7NlaInx1ngsA684PzlbW64MqvwE1T1bqXRKNmcVRUStc+JcuvyXRkQEhu5rxlS3aX7HsF
	2g0UO1CZ2F9p2IFm0Bkk78aMVyNTRcxWXHNeL3pOwEwHw6Otb2GZ6KGRn/T9KVH5hbarjAkqjQ0
	RVhVXYeHxyvvQL3n1qEjRJ7toeAqLdG1sKJfM9NkMF9bbfueInkMfMfwmIui6TncDjvvMF0jr41
	152YjxhhrPoCb4A5aPzqtWA==
X-Received: by 2002:a5d:64ed:0:b0:3b5:dafc:1525 with SMTP id ffacd0b85a97d-3c5dc7313famr204670f8f.33.1755806922947;
        Thu, 21 Aug 2025 13:08:42 -0700 (PDT)
X-Received: by 2002:a5d:64ed:0:b0:3b5:dafc:1525 with SMTP id ffacd0b85a97d-3c5dc7313famr204645f8f.33.1755806922505;
        Thu, 21 Aug 2025 13:08:42 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50e3a587sm10028205e9.18.2025.08.21.13.08.40
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:42 -0700 (PDT)
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
Subject: [PATCH RFC 34/35] block: update comment of "struct bio_vec" regarding nth_page()
Date: Thu, 21 Aug 2025 22:07:00 +0200
Message-ID: <20250821200701.1329277-35-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: I5Zr94yn_j1AuZ5JX5RK96_sFM4AhpW7vSs1yPRRNqM_1755806923
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UonbbPAB;
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

Ever since commit 858c708d9efb ("block: move the bi_size update out of
__bio_try_merge_page"), page_is_mergeable() no longer exists, and the
logic in bvec_try_merge_page() is now a simple page pointer
comparison.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/bvec.h | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/include/linux/bvec.h b/include/linux/bvec.h
index 0a80e1f9aa201..3fc0efa0825b1 100644
--- a/include/linux/bvec.h
+++ b/include/linux/bvec.h
@@ -22,11 +22,8 @@ struct page;
  * @bv_len:    Number of bytes in the address range.
  * @bv_offset: Start of the address range relative to the start of @bv_page.
  *
- * The following holds for a bvec if n * PAGE_SIZE < bv_offset + bv_len:
- *
- *   nth_page(@bv_page, n) == @bv_page + n
- *
- * This holds because page_is_mergeable() checks the above property.
+ * All pages within a bio_vec starting from @bv_page are contiguous and
+ * can simply be iterated (see bvec_advance()).
  */
 struct bio_vec {
 	struct page	*bv_page;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-35-david%40redhat.com.
