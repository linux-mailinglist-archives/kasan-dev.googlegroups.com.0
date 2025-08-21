Return-Path: <kasan-dev+bncBC32535MUICBBTXZTXCQMGQEO7LOFBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id CB75EB303D4
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:47 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3e56ffe6c5csf12234885ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806926; cv=pass;
        d=google.com; s=arc-20240605;
        b=TlQWGfzoQ9KcjF3u9SVfkTMP+z0lw6XJQy7N7wKcfvVLb3eLDu8NeKwNxF8aZboxuO
         OyWlHrsArOvdyDV5s6mBtijDK3kygVL5U+XTmvP69vSYUjpW2jaxha0HUwn3DCyFExcQ
         m/6Uu8UXKSUv9/AE/JJpv5imXnnfBGFmP3WI4XQ3QjZ6TTDWuLo72x5loxkr6kslY3wO
         Ra1SV/Orl9VlKeE2DXWINuJmTxvynE1Y7mhKf4PiRIOyN5nbKmZVD0NoAvAdi466Q6wg
         MgWhfgkSPAKeDIIYlYoS7ZgdEgyJ3Yv37+bxxQHeskQBYUoizSbvd+Oe3jfakkPN7jO8
         3E5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=0mcD+rEWLB5vS6WqBHLjyswAAPM4L2FL7e2EaVrNd3s=;
        fh=LEDDLJVezBnibkt/YTAmFn/lGYMXPmPcqvcYtroglnA=;
        b=JPpEulIye5S/lyUlm5dcRxph40BSDy33tjdcmFV3rOPGtexJY1PvQJBdN5FT2y2KZo
         FnJWhq3bjGlTFv4KMPpzPtqKyoM+5C/1UvvpzydN05t+kCHyHNMUiwz3sqUU/xq6ESRW
         fPyxWwsLL3Oij46QYKUnNszPm7t2Zuu8Bt9h6c0CqhH2RAoebhs6WLsc5KO+FNSG0/sR
         WSJvPTsKxDHOoL79NDIoLSsyP5zgJ0vKfWyZdCx4Ps71mCoJlMXKYSGxCvTG4LlPKbd2
         4AAYBWLEq9zD1Bp4HBOyEkVKbRaiTMN6Inprq/C393VsjvUfi0qCuApVIuXduyhlfWqt
         WLFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Sbqter2n;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806926; x=1756411726; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0mcD+rEWLB5vS6WqBHLjyswAAPM4L2FL7e2EaVrNd3s=;
        b=Hi97HYzCzRFkIvzmm9NYmPyZgmEWtHxoFGRRczuf6D/lrXzjgvNiudT3fNfUgkXeGS
         6CtB3FvFHo/sVjgPnj6da5HlTi3hTLbSIWTlHhcsKnPWWKZLAfIWszjjYMajriPWLbxF
         c1Ukr3S58rDLMXl8cGP/CTty2sWT8oGd1UTOQLDafCW8104BgJrR/W9F7tReoVZHD937
         N45wBuFHbObR3Xm3z0vIISN4l+0JXm52J5dWsfLL/IC4CxDMKm/tjFJ1L4hJE/gCDx0r
         6ZFX64FoI0k4ayLyC2rC3eM0gFHjjYcBUE9WLbqlPAf4ckQbqlxuXoIPZWDFOMoxbh2N
         7+Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806926; x=1756411726;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0mcD+rEWLB5vS6WqBHLjyswAAPM4L2FL7e2EaVrNd3s=;
        b=UALaK0AC6e9bnFjTH8XqH1m7edy1SXRNVuLoy4p1nUKKQSuZQpoeoZcX2U9XkAk0gB
         I5pRR8W3+KAgr0+refXsLX8GA/P/iCTiI1FI/mrvI+HQqT3/R8M4wYLCzruYtqDTXcQe
         ezfxV0zaAAbz4md3Bae/ZRzsHwDEb5tQb+h3mBvfvk1jpCYmFoQRMRi3ov/HEEDUgbXN
         2H4A8uLYhFWTRDCFFjH1hjYfaGTaW5oAu/RpT3jk2txTW4wW9/oGBZ2n7DVk+QE2uJhH
         r90ioSndrwz8w+UUBDvwZXwwyiG59P7ZW48TBb/EUkCh2pVHVYR5nsCxi7Y9Q9F1RW13
         CrsQ==
X-Forwarded-Encrypted: i=2; AJvYcCUb88qLZR8nKHCV99N3yhQLCQXrOfkF00PjNl0rWXJESQ8osDvDGE4HJGDKobW9/iPOgO17lg==@lfdr.de
X-Gm-Message-State: AOJu0Ywc7tNrH3cudG0oVqRfI+dhpps7LIyL/C/8WlLK2dAPgaPAoXm0
	p4+abj+ZjzdZnNL2eg3fAbkMkfId9t2IfGWSPdupnvMUwMBpGBVMwY4K
X-Google-Smtp-Source: AGHT+IHGeDm6Z9H2PGaIwBAvtSDqwJ7nMu/nmdxtEZ9/7BcACENAvT7lm0OOrFjmXZ9iQ3RKHgQ+ZQ==
X-Received: by 2002:a05:6e02:1a82:b0:3e5:5937:e54d with SMTP id e9e14a558f8ab-3e921770911mr12501025ab.15.1755806926427;
        Thu, 21 Aug 2025 13:08:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdQMiaJU+VEDbS1Lg434Ee9xuy5lFQogXwhmqoaTyd5qg==
Received: by 2002:a05:6e02:5e88:b0:3e5:8140:1e59 with SMTP id
 e9e14a558f8ab-3e683709608ls7614405ab.1.-pod-prod-03-us; Thu, 21 Aug 2025
 13:08:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUY+WlaDp+N7Ima7hLFHC1BHcBEw/pBET0wNDor37JwQae+fordadjDWnWQP3yT5BcHOBXmP9LNGAY=@googlegroups.com
X-Received: by 2002:a05:6e02:1706:b0:3e5:4631:5477 with SMTP id e9e14a558f8ab-3e921770755mr10623285ab.11.1755806925432;
        Thu, 21 Aug 2025 13:08:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806925; cv=none;
        d=google.com; s=arc-20240605;
        b=jA3dVG1IAZ13sRYmNGn+J9/A8c5bdYLC72RL/ZzmYGjBM+YJdB4rypF6jxk1H7mQqj
         ZFgfHFklgdSK2VQZjyMBHqPPabsyZNKos+iYvM+dkVNFljva8KEjVK8+LYDyZ+e4wpI1
         cp/CmPcKgZWb0hLs0Kh8Vmfi4LGTvKsxL6qYlxQnRjvYbUA+4ZWJahMLGDhnve7cEqJc
         HFoirvjk62dqSFusLazupqmJHtblnDt93iSmd7kCZUHEtZWfkeQ1msXrOJ8tPQ2/LzlA
         qnu0hWX9Gj69WW2Rftz1iCqDw47xvWYhdVI/0wxs7qy8QuzB2jSHy06Tao2ISnyZnaxy
         VKCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OnKBChYNBt6k7pWFZ1VK2zlCQ3hhOdGhc0x5VCAB6rA=;
        fh=MZHr4Vwk5uxArRumlcyOnF4g9q+ggtGjN4343nTwHcw=;
        b=TEbO/R5Quz3MTZ/mmSv1q7Jk65UgQu/FE8JVrkEwAMSAbLJ5ElfShPPWGDC2/2FYG1
         w3W/xF4R3JDT3JEqpfZ2z0XGVrRWCwjyCGyd1MXJk8Yll+qxa1qi5XeoanEU4aamCcmZ
         d2ZieSycPgDKhflpfGlwpQHYRVhwGH8Ad53iFk4tZH5XBDYPthYKk1JyPz+M//3eUUNw
         zOU6jfTxDrwbea4AHvRxzuWBexXfsfM/VVsE/Vohhb307+vMotpjiZF1wgQWXO6Xonva
         +7U0MIlgzt1dJ8ItBlNrOjZ1gho1dzfAkmmhl6kqOaR7ZTJMmWHSDZMRzZFtteDqYiqF
         elGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Sbqter2n;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e66ba5ef4asi6747775ab.5.2025.08.21.13.08.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-518-CfAeWXG_OmisDxPVHCOBqw-1; Thu, 21 Aug 2025 16:08:41 -0400
X-MC-Unique: CfAeWXG_OmisDxPVHCOBqw-1
X-Mimecast-MFC-AGG-ID: CfAeWXG_OmisDxPVHCOBqw_1755806920
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3b9e418aab7so509934f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWaZWMslvflBtrqay5Gk90aMsaTEb4e2CG0Zxvao2P/x+euNw7VkUYk+BQvVrRUl0TCFdHem/N2UVI=@googlegroups.com
X-Gm-Gg: ASbGncst0tmH6lPyUnHPMgahZWJOXYXcRVI5YJ0js9nr+BwlR0/v45tD/SCJY4vHlIY
	JZtAsohzYzumzV0dHblYY+v48Nl31ju8BU69R4paiPBai+iqNucOpt6KWXZpKmShEqqpo4NYaio
	aN7N5hg1N5BbuN80FUa4qxmEyLTzjhsd9fYw376HzZ8ZZ+je5wxJEfSB/LtGK2U1XwtCkFwOaBN
	Geal42ayZe3NwU3F8uBdP5MaTjkL6r0WEBOjZHn1shgjlb6uTOXuNOJM8khooo162Cd+QmpS+cV
	UvywmQurMuE+96dB0Bb4YmDhSs0WpyYO1udTQD7/3X82EXJyZFLIcjE2PhjcmoTOHb7ruRvvBSM
	Hm8zDSKZ8nBxWiFwOBUwvDw==
X-Received: by 2002:a05:6000:2405:b0:3a4:e841:b236 with SMTP id ffacd0b85a97d-3c5dc735246mr192369f8f.33.1755806920388;
        Thu, 21 Aug 2025 13:08:40 -0700 (PDT)
X-Received: by 2002:a05:6000:2405:b0:3a4:e841:b236 with SMTP id ffacd0b85a97d-3c5dc735246mr192328f8f.33.1755806919917;
        Thu, 21 Aug 2025 13:08:39 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c0771c166bsm12920369f8f.33.2025.08.21.13.08.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:39 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
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
Subject: [PATCH RFC 33/35] kfence: drop nth_page() usage
Date: Thu, 21 Aug 2025 22:06:59 +0200
Message-ID: <20250821200701.1329277-34-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 0YwObe6KIFjvkSjD8kQ6EhIQ1tDeGeJunwTVDRZsbdM_1755806920
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Sbqter2n;
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

We want to get rid of nth_page(), and kfence init code is the last user.

Unfortunately, we might actually walk a PFN range where the pages are
not contiguous, because we might be allocating an area from memblock
that could span memory sections in problematic kernel configs (SPARSEMEM
without SPARSEMEM_VMEMMAP).

We could check whether the page range is contiguous
using page_range_contiguous() and failing kfence init, or making kfence
incompatible these problemtic kernel configs.

Let's keep it simple and simply use pfn_to_page() by iterating PFNs.

Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/kfence/core.c | 17 ++++++++++-------
 1 file changed, 10 insertions(+), 7 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 0ed3be100963a..793507c77f9e8 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -594,15 +594,15 @@ static void rcu_guarded_free(struct rcu_head *h)
  */
 static unsigned long kfence_init_pool(void)
 {
-	unsigned long addr;
-	struct page *pages;
+	unsigned long addr, pfn, start_pfn, end_pfn;
 	int i;
 
 	if (!arch_kfence_init_pool())
 		return (unsigned long)__kfence_pool;
 
 	addr = (unsigned long)__kfence_pool;
-	pages = virt_to_page(__kfence_pool);
+	start_pfn = PHYS_PFN(virt_to_phys(__kfence_pool));
+	end_pfn = start_pfn + KFENCE_POOL_SIZE / PAGE_SIZE;
 
 	/*
 	 * Set up object pages: they must have PGTY_slab set to avoid freeing
@@ -612,12 +612,13 @@ static unsigned long kfence_init_pool(void)
 	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
 	 * enters __slab_free() slow-path.
 	 */
-	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab = page_slab(nth_page(pages, i));
+	for (pfn = start_pfn; pfn != end_pfn; pfn++) {
+		struct slab *slab;
 
 		if (!i || (i % 2))
 			continue;
 
+		slab = page_slab(pfn_to_page(pfn));
 		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
 		slab->obj_exts = (unsigned long)&kfence_metadata_init[i / 2 - 1].obj_exts |
@@ -664,11 +665,13 @@ static unsigned long kfence_init_pool(void)
 	return 0;
 
 reset_slab:
-	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab = page_slab(nth_page(pages, i));
+	for (pfn = start_pfn; pfn != end_pfn; pfn++) {
+		struct slab *slab;
 
 		if (!i || (i % 2))
 			continue;
+
+		slab = page_slab(pfn_to_page(pfn));
 #ifdef CONFIG_MEMCG
 		slab->obj_exts = 0;
 #endif
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-34-david%40redhat.com.
