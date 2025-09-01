Return-Path: <kasan-dev+bncBC32535MUICBBFPO23CQMGQE5DARG3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id A945DB3E89D
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:09:10 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-88724fdcd7dsf148311639f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:09:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739349; cv=pass;
        d=google.com; s=arc-20240605;
        b=bHmkrRmZo88szyyF9Z7sIiMHuvem+iIeALEGGc+H4eOePeYPoTLR50TJQ/Di9/onxG
         wDMnfx+Aj+eRGbYpuPz1qHo99RoUc/ToGpu1YZPc4gWyfdiN0+726jdAvL94pxck1Yv7
         gGMgFIsZ751SaRiFHsmZ7iwAVxC+UtczD6jZcsth7Ry291dYcn8aelRTvyQFnYQB5ZoI
         M5OXKu2S8j6uYaIbEdbh3EmWoog8G5QJcy5Qh+tXbSn786PmSn7Z4S2CfkZgyTy+DIZK
         bSZIhqZGBNlJUUUrHxBenjqrU3i9oAqFBRpzDGoLsUHHn5swdsgiZW88SYLWk7k8htqD
         JoDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=J5Ij8zxlmWs05HLjVbe6BBNDxHT1ijQWKqcaDIzk7m4=;
        fh=EvK63XAecFymfkD8v8qLU3qgA9y9NLZlDD4kpCLmiUc=;
        b=KUkmIhJcso0I8lnKkvGSG96MML++a2Yf6w/EYfLk187HBnZbWmSF+xS7R6c3fipi3B
         OOvDzchudOH77gpA20L73cHvlmljv9WRJc3N0GbECn2ZvhanJBSJV93JdsvS1VDft36n
         NHYyJPLDgH6TverZhLbp03CNh7LuEJJ0aPEumJIOKmpgKiDnQqKjNYGPox/xRyqHqHfg
         4Wk1kXNgDoBqJK6IgO6C93MapZbsnoy0m1JKKB6BLqZTGUWDZMFypWmx15ATekmmGDsU
         Iu37eznZRPkFX8jCoshY2tfgCnGOLHskUh5RJw7v2ZR1mv/tCo77Qd+fMkHipiYZuWm/
         o8Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QyWNQ46S;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739349; x=1757344149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=J5Ij8zxlmWs05HLjVbe6BBNDxHT1ijQWKqcaDIzk7m4=;
        b=C2Pd2/HdX+uyRHn4EfGDqs31ZJRGYhfyegvYhaAwj1vIeGgLOUDEXIadCgTxYyxy8h
         448s9qz3birnDmxDH/vH7xED/GUduYFiKHALsC6CTSWmDoSLlnb2SUzm6Oc511EHNNQR
         JJTwkq1YKNvWXfMRmPF24BaWjOXyfgP0B5aB1/7FHVzdKd45bGYUPzyGw6SU4P35n5Pl
         HiTbPfqPtgPMmrZfl4oA2GddfYRcJl5qDKr1baDxPOt7S6OffjBDuAaTxl/LlgbCu3Al
         GPZxv2j9LU6Q7Sq7BZsAXjlAo0nKuRnW9Q24qx7fVQYaWe7I1t0AmsEXrwQ0gF5C9LHl
         Z1rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739349; x=1757344149;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J5Ij8zxlmWs05HLjVbe6BBNDxHT1ijQWKqcaDIzk7m4=;
        b=mz4jWYHYaq1nOVvYKt5KaJz+KhXpGtDB5opPfyaKtUPElVO6lrq1MSWfvzzIlA/ZsX
         UPxLZiY0UMRB7NNd2Zw6EvTHKTr4s9WAL831I+eGWL7IhEL2p3LsemAZuMzx9RO48fWc
         Mu9/5HoOaTzZWt4a4Z13l89ypF25Q2s8chzZ4k9dJEsIf8W8jZ/Ln+mJbA0dS/9yxUuX
         qFVxe0y/AkR9avCZjGzrUZ00IZ9VH2jtGmDJFcGsuq/Ritu+9hEMVlTAwZ7ApENXyXfI
         ci6G+rhWnanYtULVhsYWka30j3iNBlisGKyKjFObvzlHEyNAB/CUNcHyWvzS27p+nxEg
         SBfg==
X-Forwarded-Encrypted: i=2; AJvYcCXItEk/VBb37iShH1Eb0LHH8KY+StGvjE5VyJtAhKmtXMPSvmT2fyhQ7kTdwzqanzpilFeyZw==@lfdr.de
X-Gm-Message-State: AOJu0YxO1+rlLJwhVdGCKTOhglTeE05lIq6WwMKZOhpLyQYI1VtsbMci
	pxZGn+GWJYKPWCmP9QBsxLHqc6iPfrXz3DsY+cW9dGe80/NfrfmeBTwY
X-Google-Smtp-Source: AGHT+IEL6Fv7z70L7YKReKiokCch8zsc2EJeVwgpoqE/6FY2hyCwsZ5z9ivkQOy3kiuupSt69cZG0Q==
X-Received: by 2002:a05:6e02:19c7:b0:3ee:1aca:3162 with SMTP id e9e14a558f8ab-3f4021bfd90mr144361095ab.26.1756739349209;
        Mon, 01 Sep 2025 08:09:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeTcOeSPufoDJiWm9RW8Danl6IP9AVMV3r3PHoPN16X7w==
Received: by 2002:a05:6e02:3f0e:b0:3dd:bec6:f17d with SMTP id
 e9e14a558f8ab-3f13b276ae8ls38656505ab.2.-pod-prod-06-us; Mon, 01 Sep 2025
 08:09:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPUYLLlSebu/F5sNnaYcSbX/9gIvSScwnSDgkm39gcv3/PUnrcZz+z+Ba0OgIBlrPYSklELu26DYs=@googlegroups.com
X-Received: by 2002:a92:c246:0:b0:3eb:cca5:5586 with SMTP id e9e14a558f8ab-3f401aee276mr164618855ab.17.1756739348233;
        Mon, 01 Sep 2025 08:09:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739348; cv=none;
        d=google.com; s=arc-20240605;
        b=D/Q1Zh/69fO/zZa6FH1r5rAjJonTpAQdzTrfi3u9Urll6vlDVPbMXeQbtoaGXSBIqh
         uAGSWtq9RGSBNRw5OJWrczAUepqOcwNShnscfQVYXIGUNpUweJgHJe57DpkzjfuSaN6i
         XLMbUYwanmM8AePeuofuBWvjeZPRumMq2kvoLXTXKPyxXFb00q2Bw00U/K6+SSCKlVFs
         9WdU75NaPTaW2quVyavvdkOx3k9Do8xBp6JexvWxn7zwp54u6aDvkTV3ThVHWMN6f802
         CBsmPCtKiwXtpZE1cEa3/kpPJO1zGXH43eIIiAIAWNJHePdeyMCCuYXeuNZz7mg90yQH
         Vw4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=28W0TjP7quFSAyZF0qsh8B2KkVopKfPNU5v7Cs/5Ym0=;
        fh=/E6tkKVOuzBmayN7VWrhfRPnEmOY6l2P9TuUpRLnJco=;
        b=gHCR6NZ3EpNVKIWOFb1CORZ+GjKR9DKLq1VvJCuiMwVwcOT8tKgdRo9MNoybUtyGqD
         c0s9HX+6CRm4kt243ItnMVmd70IAxDaYkF6/XMMNbUpBGGACRzy7VwJIkdPaHkFjenvg
         2tnbs9mmkH4N4EUpm1e6W5hPYuLYWlCIJ3gQsTENpQJvLxnYGVkxGOJ1ppLQWbHjyvKi
         Do1IRNnc9Ujk0u360TfgcSIzDF+dvHiMTbkAWZP5BjDlrABps5HQKXu/QM7Mnt97GpTl
         OXquF7AIQKy2Zu5YkTl3GEH3NxxoC/ATF9pyNms6J6Hm+I+5PaIdL0aLaTuv63yvSDfB
         TekA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QyWNQ46S;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f3e0411afbsi3060415ab.5.2025.09.01.08.09.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:09:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-367-Xnh8yLGcPFel-NQdQHGKhw-1; Mon,
 01 Sep 2025 11:09:04 -0400
X-MC-Unique: Xnh8yLGcPFel-NQdQHGKhw-1
X-Mimecast-MFC-AGG-ID: Xnh8yLGcPFel-NQdQHGKhw_1756739339
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 2E757195608B;
	Mon,  1 Sep 2025 15:08:59 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 4EC2D1800447;
	Mon,  1 Sep 2025 15:08:44 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
Subject: [PATCH v2 17/37] mm/pagewalk: drop nth_page() usage within folio in folio_walk_start()
Date: Mon,  1 Sep 2025 17:03:38 +0200
Message-ID: <20250901150359.867252-18-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QyWNQ46S;
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

It's no longer required to use nth_page() within a folio, so let's just
drop the nth_page() in folio_walk_start().

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/pagewalk.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/pagewalk.c b/mm/pagewalk.c
index c6753d370ff4e..9e4225e5fcf5c 100644
--- a/mm/pagewalk.c
+++ b/mm/pagewalk.c
@@ -1004,7 +1004,7 @@ struct folio *folio_walk_start(struct folio_walk *fw,
 found:
 	if (expose_page)
 		/* Note: Offset from the mapped page, not the folio start. */
-		fw->page = nth_page(page, (addr & (entry_size - 1)) >> PAGE_SHIFT);
+		fw->page = page + ((addr & (entry_size - 1)) >> PAGE_SHIFT);
 	else
 		fw->page = NULL;
 	fw->ptl = ptl;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-18-david%40redhat.com.
