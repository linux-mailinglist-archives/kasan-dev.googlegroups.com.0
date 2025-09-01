Return-Path: <kasan-dev+bncBC32535MUICBBJXO23CQMGQEJLFE2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id C4795B3E8A9
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:09:28 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3234811cab3sf5580457a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:09:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739367; cv=pass;
        d=google.com; s=arc-20240605;
        b=K+oSP6/72QDQIGLjlQo9l0W9KhJ+izzIpcSUYGYEWhakk1BN0ijKmvHOfnsv6VtI1t
         NP8mPgHCSwBKZgxN2qI3f+je9LYE9tl1De9eM443SKqJEXKhjkkYOeogUBVneAxkHzLi
         qt5mXQ4NVDF2SlTuksB7vxh4Snk8fLVDU1w3uALmDlprf26UoCRhRZlZ3Ln1Gc3K6vE5
         GijGadBc8XrFkKP3t60aCrLQmG/ut70VHUL9/zcq/jk9RkdXE4iH9rhrMzppvk+nK/EB
         8DcgzZAzjQbAVQ+vF4R68VG/pWtfUAipXchjqtg0KouMYMwEYxsctXGiGOZZvbc9AIje
         ASdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ll419VNshmbcElgdfA+34XJHKB63LcQHq04kwrM1Kdc=;
        fh=jLM0lYMAzH8kpCdhWwi8WNlYY3tHMP6bgnY0g/UDigk=;
        b=fvmL2/RE/34j44vM/gi3nsQj7ywrC/9xQKT/6IhAOirHBnQRfBE5e6jYhqLKuKe9jM
         Q4KeB8ccNTRTFniTK3Xn4oKJQBT38w+CeuXNf6fehP1MzB4l5x42j4To2gsreZkDENJe
         UjE46cE4shQVJF8aKWGUl6W6ClaJ7VlA1MosVsTKiF803gXxezg00rkiNQ3ThvkDFZWq
         T+7pvMl7XprTjKi07IWlsSmq09+SeMcW7NLZOjz03xyBjt3hdLutF1eBZfCpwcEkAG45
         4yPIro7jzwal1EQOWP+aO5K5WdGLp4djKcoeO7tFV/blJNnvhigsz3AcE/tVpJ9wYjYy
         99gw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QDkdbQ6g;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739367; x=1757344167; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ll419VNshmbcElgdfA+34XJHKB63LcQHq04kwrM1Kdc=;
        b=a3C4nYeKyXTthQnZph/MC1XxX4fz/8UDm5lCEQ7R4FCyTTjLoifx6QwwG+uHRdnYUf
         oBNmGfFg/KgGFQa36Q4/DnGEzs6RoPNFpm2SfRo3sznIrAM9LuzrTY1m4Ma64Lq5AZqw
         xEz2u3yGnsZoNrplyILk/KsNCC1hjvo4VNzSyzz6kbNDr0s0p2vDfhJ7LEVYZcV0lPv0
         LFlYkfxyONc0YWY4Bzo8jhwOOgH/3GpvYjclc8udftGh6V4CVtjmObdO8N12AQxJPjvI
         o2E8G3xRRImTXIGVfmeLM4wlCJQpl9ko8DBn10FHQWl1Xb1ltbEdyO/wcgErkjsdiDoW
         qxzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739367; x=1757344167;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ll419VNshmbcElgdfA+34XJHKB63LcQHq04kwrM1Kdc=;
        b=e9DDWgeV9iin6HU+iSbwzCqwga4uuNBOI2V1Fr0Hu0KSDfVb/8B4mPPR/SSABcCHw+
         da70kGr6R92Lnehq0HCKZi7bmE5FtbltgRy/AiwUBry3moIVnw0Wjv89T9V4+S5LOBAz
         U5F1lKVNyBJcQEZNCwciHvPX032NdSdZUag/WaDN+cI8LPF+Sxo2vc/qNTqygQ2yhRmS
         SHBUzQWU9AYO+FFoOt2f8I7ncBusDSdvt0i/op7p9UuDKKNtq2iqEpj699u6cIHKQGED
         60bRgYHtEQAhmn2Ex2izESau7RkmaBglGNKevp5NQRWfbYjSlXBVEU5KWQHUebgfiQko
         GD7g==
X-Forwarded-Encrypted: i=2; AJvYcCXkhZ1zjDWKPmIcnn8Mzf9wQxIv609AOb+EgaH5LmcnfhyuCPBZwV0AjW2ONGJscKxLZ/rx4g==@lfdr.de
X-Gm-Message-State: AOJu0Yy40npYDUzBhm1N9M9Cc3N6QHy9MvQTebKDHKBc0XSzG880mb5A
	NoI4GBmYhjw+Qu+jp2aWdLishy5oZrBrdlP2P4+3WrTNu8TKXaH2d8m7
X-Google-Smtp-Source: AGHT+IElk4NFLjN2PjpPqIHlHkfXMev6B+OvLc+JgHlT9J66gNjwqVFww5RmjIKiDXHXDOORhUldVQ==
X-Received: by 2002:a17:90b:1d81:b0:325:65ef:5961 with SMTP id 98e67ed59e1d1-328156e1203mr10532274a91.33.1756739366996;
        Mon, 01 Sep 2025 08:09:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcnR/JDBPy3toAYv02UnrHOeCpcFZrwenC8NadtCurFeQ==
Received: by 2002:a17:90a:c4:b0:31e:f3b4:707e with SMTP id 98e67ed59e1d1-327aa888dbfls3246120a91.0.-pod-prod-02-us;
 Mon, 01 Sep 2025 08:09:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdhWBls1iKHU6F2gV/v9lRIHzag/f0wrtxTv3K0nhh4ra0kcrHjuaug5L3QMy/2rHU/0TrsY2fGWE=@googlegroups.com
X-Received: by 2002:a17:90b:2ec7:b0:327:f20b:90b5 with SMTP id 98e67ed59e1d1-32815412230mr11460254a91.4.1756739364844;
        Mon, 01 Sep 2025 08:09:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739364; cv=none;
        d=google.com; s=arc-20240605;
        b=Bxs0IaePj7qAXsWNW65fxDHtLUQgD/OW20a8etVZGolf9e82FV3HUZ63r4FoOfVuMl
         Sdm2sZibQ6atF+BsYz/hgdPUapz94dTZ2L9MnJNMRwTrXUmpZbhSk1kDCqARO32n1GMF
         UVeA4KuoWwY8nkEKs71iu3OH9YHhhOQkAv/0B8PCQVc3JPQzH5HCmBv5xZHjWxPBwx/q
         cKP0NWNTnIYNfCyM5SCqDEPncD8aby84DN5fwZq4o3zXTNlTalgypSvlfa3qa4j62cM7
         KfTdwzZiezWxjZHXtRxSyeZvLbOM6r2mQ26VVo8F3VIF4YVDaXqM9HksYlY3bE/v+hmB
         iWIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o5i9udlRk4QSJedS+fkFLitKqPgB2ec3GW66dESbqjw=;
        fh=a+0inipWR+gxi2bF8fgHCUkmRRcEkdXajxBfbsdM2UE=;
        b=eryNhKvWAg9FVvZ50rtAbBbqLYdBvn1OrVITbPMCRDck/Ip7XtX9TjIang/7rPjQGy
         vyCJUatO1lR0SOZjFgtsTwTgpaOuSXeQWvGoL1K+KaZXJ94Qm118wZbAJZsV+QlrPhxT
         XtIJtbV6EWD2OKBQgO74Akd32MSD7V5Neb87osr2xLet7GFImxqcHFNHU0JNUXzmm+xo
         6hT1pzAC3AtqJoB1sda2YX4P59E2JynLLim4+fUOsS0HaL4009HcXUU1YjO7CPRwgMnx
         7jUrQ/x9T+HJUFjLfhqcTV8JIE3MXhUwEp9vJuDahiLSPBbDBtAcGu9vjS1Y4BLNdFOq
         3XYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QDkdbQ6g;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3275cf6bf9asi329573a91.1.2025.09.01.08.09.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:09:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-453-Qi9ByX3gP66LGgSG-c-ffA-1; Mon,
 01 Sep 2025 11:09:18 -0400
X-MC-Unique: Qi9ByX3gP66LGgSG-c-ffA-1
X-Mimecast-MFC-AGG-ID: Qi9ByX3gP66LGgSG-c-ffA_1756739353
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 06857195609D;
	Mon,  1 Sep 2025 15:09:13 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id BDAE918003FC;
	Mon,  1 Sep 2025 15:08:59 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v2 18/37] mm/gup: drop nth_page() usage within folio when recording subpages
Date: Mon,  1 Sep 2025 17:03:39 +0200
Message-ID: <20250901150359.867252-19-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QDkdbQ6g;
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

nth_page() is no longer required when iterating over pages within a
single folio, so let's just drop it when recording subpages.

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/gup.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/gup.c b/mm/gup.c
index 8157197a19f77..c10cd969c1a3b 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -488,12 +488,11 @@ static int record_subpages(struct page *page, unsigned long sz,
 			   unsigned long addr, unsigned long end,
 			   struct page **pages)
 {
-	struct page *start_page;
 	int nr;
 
-	start_page = nth_page(page, (addr & (sz - 1)) >> PAGE_SHIFT);
+	page += (addr & (sz - 1)) >> PAGE_SHIFT;
 	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
-		pages[nr] = nth_page(start_page, nr);
+		pages[nr] = page++;
 
 	return nr;
 }
@@ -1512,7 +1511,7 @@ static long __get_user_pages(struct mm_struct *mm,
 			}
 
 			for (j = 0; j < page_increm; j++) {
-				subpage = nth_page(page, j);
+				subpage = page + j;
 				pages[i + j] = subpage;
 				flush_anon_page(vma, subpage, start + j * PAGE_SIZE);
 				flush_dcache_page(subpage);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-19-david%40redhat.com.
