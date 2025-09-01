Return-Path: <kasan-dev+bncBC32535MUICBBJ7Q23CQMGQEWHHTCTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 13B00B3E90E
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:13:45 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-45b83ae1717sf22182495e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:13:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739624; cv=pass;
        d=google.com; s=arc-20240605;
        b=PdxREjr+iMzGT6YMU/Ofs9sfS4WFhQf5bz5Q8kFP/WGxzq2nO7DVpFz7XMo+8odfi8
         dAzRUtpfYunEhmhIurABAZONuh84XHs+8g2X1PLu9eE4vVnzGscezgX6a5oiMHAWzqGk
         spQxmD7ADzlkX9J/AvxNyZkwSfmWRidjwHlO6x3/0XKgAc6ROXpgm3i4kgEgOiyiaGdV
         9R8i7Zar1JYhE55ipfqW95wCuP5bOowMy+3amSAQ+MCH6TPje3JRD7pSBEKI3wBBvuAb
         Tu+/0xK8/XuKvVAS13OKtE6k1I/PJL5J7FbifySSak11+5WTRF2yZ5JGazw6h8Af370F
         5AnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=pJUyaXd1YWZ4qkkDNl8qRK7AOD+xKjWJhuvFnjImFuw=;
        fh=z/yQ/AO5TWAIjS58utWJ36gNmmJX6m8Q2BNk2S3c8fY=;
        b=IHDT+b4ZvToAHvrtO4ytVBRCbSUqM8A8Df21NnNBPOV1GL9dR76wrq4/rOzRTtsHxo
         XSHJwx76RwMF+Ze9e0cEt7MAgbnUYABChXrjDswAY/rNt7bztbBvsJxqufHS+AKHSvPx
         8Vurotwm1zDntVA/FNMIbyl9AO6yox3EymLBkrwfqwTfUZLtbVlXC70IVf6b1m1dV9ZO
         hfOyYjQHDyEU12NGclr2Iy36eT1NVJTMrLaHtr5QSzfwf6AWVDAW8quWpyFSgJ9E/wRz
         FamaxJVXIDRpCYp6CmR2EqRMv8M8iAcmNWs6WNZ0Ez3LGS3epdMzoljzIawDKpp0N5YW
         MKwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NURZkgBf;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739624; x=1757344424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pJUyaXd1YWZ4qkkDNl8qRK7AOD+xKjWJhuvFnjImFuw=;
        b=FMdES6ztZJHXSvtcfYtN3YzixXIFUN5NbztXrUgRgn3SSTqXYdkpeHFQmoDKxarMVz
         /Eh0CvB1alekWDB83qzIhNDDNTfffpmFrww3cq25yeC6U4eEXSsWBQa67/Xg2KvcPSM5
         4mJsWfJdK/ImzdcNOEW1I1b0tsqfJPVnI0KwRPKeGLuibYvE8NatSgd39XmXinZyr/sU
         hxx/72wvbldABMEOE2i4FzsISxyPCbY/Jov/jIIvLDxk1KVBwKl21u6vWmcd4+YcXnDO
         pPlNSwj1XwzT+jdPwc60GqRQFoEmtYK992irDrCz8+hMkiRT/JDIInq5MXcc0hGYLAa1
         nqbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739624; x=1757344424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pJUyaXd1YWZ4qkkDNl8qRK7AOD+xKjWJhuvFnjImFuw=;
        b=ptJe0Iw8PBE8BhAURQBXEqWfdM6IjoSjolV4tgiVDzC9NyNg70DAisOofbcPJ/2fEH
         X009WdN1xy6SUGxiHvBe3f/XWcd40gVi+WfEXN4c06Vn7R+D5/qOlyesxefBHzcTK/nH
         WuS2+Am9w9P5GGBPdE3x0b3jjx91Fidmp6pCKgXHPyZnBDoZI0w9Ry9PXLS07gCxrm2p
         /CAF1o8itignwwyab7NmmUh6J5lgW6I72q2ns7/U8Hxaun/VxnHXqpfo7QcRnbUy+TWg
         MFKnID8dr4Dizxj4GHmYNIHRYUy6RSHGEPF7b/L+fqvY2/7lxmVPRjFx665o8M11LiiW
         c4nw==
X-Forwarded-Encrypted: i=2; AJvYcCUe5Mjty9ZAohhOsj+72OIfBvO9p2sG9IYsboVX2lHW5erRip0RfSzJkyHUlPYi8vptt8jN1g==@lfdr.de
X-Gm-Message-State: AOJu0YxzdLGDwQ+N8zudwrjMkpnbDbN8GD/KL9wsivcymk5Llz+ywbZe
	wbNB4DJ5zg/ibVMwR71V1Edu304kazNTDiuCwgNt5CO1plj8yYCkwedI
X-Google-Smtp-Source: AGHT+IHDzQBeP+Pq9XpOKKU2V3ezise28CPuPoRy6HIuMbz/4yP9Li5r+WuwCGSxGrzy36tGZsutgA==
X-Received: by 2002:a05:600c:1e89:b0:45b:88ed:9558 with SMTP id 5b1f17b1804b1-45b88ed9bc3mr57821945e9.30.1756739624357;
        Mon, 01 Sep 2025 08:13:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZesYpQp/3u7C7K+I5aIe3znHqUFR0rx1Ojq2pS/1avmVw==
Received: by 2002:a05:600c:4d96:b0:459:e761:bc87 with SMTP id
 5b1f17b1804b1-45b78794905ls18683485e9.0.-pod-prod-02-eu; Mon, 01 Sep 2025
 08:13:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJqUvJOTmBhPxox/JYx+e/9JjZeBlCPw06ZSeYZQzWRFYMg9CzOygH6euLOEVzXkL2vlI5g6CLVxY=@googlegroups.com
X-Received: by 2002:a05:6000:1acd:b0:3cb:46fc:8eaa with SMTP id ffacd0b85a97d-3d1de5b087dmr6895314f8f.31.1756739621085;
        Mon, 01 Sep 2025 08:13:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739621; cv=none;
        d=google.com; s=arc-20240605;
        b=ZWR6h5nR0ILeEcUL+gN2p2Z86DOKtnQw9p+QFbuBII2Jj+xbn1nmz/1az6lBTzmSDq
         KD+shwMB2e9ztkiqoxrNoTk0IDZtOE/J6zmpDCCV4/DfG4E23vKT7POlmcwjK1PmQgqF
         +btrc9mUurOudu9HIgu3k6VcBKnDV/ie6Zvxqmc63mmvxhaBX8426hVWTzxzM8ZLBMYR
         cjfFw+mtz2VHnbvJ6ocGYkNK1Zde5MJ73U5h/AMAOYScSPvAJUrUHTfdUfxhDQuMMRfp
         /42ARztweSC4QHViIALl539+zAJd4n3/x4RBcLFQgx68igHhE5pb737D39dpyiraOTUU
         HJmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kPHmZzTajGoiIu4Pb16cc/zxagZSiNHTxiRnREwqsAY=;
        fh=a+0inipWR+gxi2bF8fgHCUkmRRcEkdXajxBfbsdM2UE=;
        b=A6vEZZGQtUMa5dg/ixHZJCVPj9ggDysul9Nh7hQtenREvjtOzl+L4hy4jMOh3MQYMK
         w7kTckN7xhWd8/ZlM5E67pRmF9P8tlsF3LYie0Cq9taAgUpBT6rd1regQcE5v4WBiSJC
         rgUoPP9tJifnN2qPfPiM3SI4MBdpEEIIyJiZQ/wEcIURLvXfbG1CCU45MULj5RqE4PgF
         Y/bBNQxRY6kcG0sHeckEoz9o66B48PQfeLVt44LoyHSV469EuBT+xgoNhXx8OxeCeW+P
         kH5jB0rWyXgz8UlGF3iS9X5OIPLIaV9FX3LXCjKqbQM9lwM8bZSFuI9IL82A9pPk+B+L
         K7Xw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NURZkgBf;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b7e7f1697si1839005e9.1.2025.09.01.08.13.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:13:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-626-GrEIet-nN5GvzvRvynVS6A-1; Mon,
 01 Sep 2025 11:13:35 -0400
X-MC-Unique: GrEIet-nN5GvzvRvynVS6A-1
X-Mimecast-MFC-AGG-ID: GrEIet-nN5GvzvRvynVS6A_1756739610
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5BC2F18004A7;
	Mon,  1 Sep 2025 15:13:30 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8D7A81800447;
	Mon,  1 Sep 2025 15:13:15 +0000 (UTC)
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
Subject: [PATCH v2 34/37] mm/gup: drop nth_page() usage in unpin_user_page_range_dirty_lock()
Date: Mon,  1 Sep 2025 17:03:55 +0200
Message-ID: <20250901150359.867252-35-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NURZkgBf;
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

There is the concern that unpin_user_page_range_dirty_lock() might do
some weird merging of PFN ranges -- either now or in the future -- such
that PFN range is contiguous but the page range might not be.

Let's sanity-check for that and drop the nth_page() usage.

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/gup.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/mm/gup.c b/mm/gup.c
index f0f4d1a68e094..010fe56f6e132 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -237,7 +237,7 @@ void folio_add_pin(struct folio *folio)
 static inline struct folio *gup_folio_range_next(struct page *start,
 		unsigned long npages, unsigned long i, unsigned int *ntails)
 {
-	struct page *next = nth_page(start, i);
+	struct page *next = start + i;
 	struct folio *folio = page_folio(next);
 	unsigned int nr = 1;
 
@@ -342,6 +342,10 @@ EXPORT_SYMBOL(unpin_user_pages_dirty_lock);
  * "gup-pinned page range" refers to a range of pages that has had one of the
  * pin_user_pages() variants called on that page.
  *
+ * The page range must be truly physically contiguous: the page range
+ * corresponds to a contiguous PFN range and all pages can be iterated
+ * naturally.
+ *
  * For the page ranges defined by [page .. page+npages], make that range (or
  * its head pages, if a compound page) dirty, if @make_dirty is true, and if the
  * page range was previously listed as clean.
@@ -359,6 +363,8 @@ void unpin_user_page_range_dirty_lock(struct page *page, unsigned long npages,
 	struct folio *folio;
 	unsigned int nr;
 
+	VM_WARN_ON_ONCE(!page_range_contiguous(page, npages));
+
 	for (i = 0; i < npages; i += nr) {
 		folio = gup_folio_range_next(page, npages, i, &nr);
 		if (make_dirty && !folio_test_dirty(folio)) {
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-35-david%40redhat.com.
