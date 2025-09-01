Return-Path: <kasan-dev+bncBC32535MUICBB57N23CQMGQEE7NZTAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F63BB3E895
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:08:59 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-248eec89618sf43807875ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:08:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739320; cv=pass;
        d=google.com; s=arc-20240605;
        b=TBrwedmjdHdDzfcvUzBu1TwctqQ3QyeXwtrsjiNjj8nt5vvkcj8Rn9gcD/0m/NnNI0
         Ufyd93HvhqF7ungKHAP8tzSohBvT/T+3cmR54gVeTVS5970AaWs5I6fISOnwVROzUvNh
         avPKLb8LcifCsthUsJ5dV9Fk5G1ZKmhO7e48+IBhYoNghpgh1hlrgHP1iJ0QCJcC7p8C
         vrQEV3rcNc92jpyX4eawvD5gZEO6f92B1jYOIT3alyD7fV2npVo6TNrkcf4UPN7+dyNa
         dsenJv0Ib6xK0W/mFHdVqkZFlpcl2Pww9yN/NaYPvS2cK2N7KQxqFPc71a6JFy7oqRoQ
         ErAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=X19LKt0AGBp2qcOCEZQTlKvK5B1WSMURVilDZB8ierY=;
        fh=FVmQum0sdZquQzq5rgh8XncJeZG3eLaZSxq1V6yLQPs=;
        b=FTzTZEKNw0SYCcyeAXE43A5CQTIcDGOH21cEfVdy8Y9hO+uh75rHB0X18rEgMXEwXc
         jQLgJP9aDud60i7wfpR4e07nel0sNQY/GsrZJbQf025YXAYpa93495KwyoN9bDPs4eAE
         lBGuikd+HO2zeYoAcOBEmrpLf21duhnj6CiTRtuMeCBqGlA77P7TdTROiGvPmGX5S0TC
         Ku1pZslv3kY7Hx53JH7FaQsQmZpFRO6FIRg72iByunyIfE5ma2QyrLGS5HG5yX/oxIev
         0gr3taDjVHRTMA8SKpbZG+qzlg5kWHbghgMQ9c9bY77+MZZ6lcOj4i1+FcrD917YCqzT
         fWbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Yrs0RB9f;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739320; x=1757344120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=X19LKt0AGBp2qcOCEZQTlKvK5B1WSMURVilDZB8ierY=;
        b=Wxv33isuRw+lPB71m8JQVFW10AcXvILwY7kMdwTWRyvUCA8k658pSemrAYd/UnRmXt
         GgsE5EU/jVi/BihFg1m/i6t8bMoxF+ZLoT0H801ZT/2cxqhj+E9Hh5B9IfVygwiHAbEJ
         8skWKGb6sT0eUpOyIEpOP1gEH6Nqq8Fpx/HMZfAHxVhmb0k+QkifFlD1ci3r5ih2CTNJ
         QYWimtl6NzIIZwBdamlVHJnqF0cwSKdbP0b9dsv+RxwCi2xE2XWgjDkbHxemIFsfzXqO
         lIXbViQEzZR7gXUs8bd+8FUGhYiPZuQ7WeSx/C0aAs21bcHuJ8CLxj1AbubNeMfKjyrc
         5gNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739320; x=1757344120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X19LKt0AGBp2qcOCEZQTlKvK5B1WSMURVilDZB8ierY=;
        b=l+IHCOapMhgrTO/oIvK8zrGbnH7Pds3Fw6s+RgYnaADR96m8p7CTrSxL5gzjBepCzu
         kD4zawOQQbFNq35Ma8nk1HyHp429e50NbVcu2DXNuHsWk7TYu/f0IMdi4t11IEPfgA2m
         QCCbJKKgePQCY1mZ6MlQEvKOi0m6qn7B7Nx7PWZx1vz5kSXW+V842U2s/8eqAmvgFi08
         T39N3VgbxzGQQvTYQyyUKbZeipRvRgzvYERq11BfjX1uzNAwcMj63jRmcQJTGVM+0VWb
         h4A6daqXtYKruG6gSrisePEel//AwA0HH+cj9ovXje6gAovQPBSqbbuic1l1LL/JVuvw
         /Pkw==
X-Forwarded-Encrypted: i=2; AJvYcCVuIHO524w7prtFZIYLv5NNyoQGRUsvf08oq+P+ib86LNfcrk7PRoKX2F0qq6VDldmfeKgM1w==@lfdr.de
X-Gm-Message-State: AOJu0Yw5qv/uhHGyiZ5MRA6fHOEwC4LD3kmmR1tjAH4xvdCcJtZGJKHo
	c2DQtelvq9kxcVH2vbO37sryZNdDsl3lcmmwhRzmai4rc7XbZRchBkI8
X-Google-Smtp-Source: AGHT+IH+U1V7+JqobJ43hsciNQQTJRXVXswDryp1k/jd7qwYCXDQI1bNiStHiZm9mw4eQsNt15Rw1w==
X-Received: by 2002:a17:903:2383:b0:242:9bc5:31a0 with SMTP id d9443c01a7336-24944b15ef5mr109491925ad.56.1756739320028;
        Mon, 01 Sep 2025 08:08:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc2rLVSHfCGE9rpBbmvUYU4Xbfw9LXRXCcuOunBQ4egMA==
Received: by 2002:a17:903:1a0f:b0:248:b6dc:9f18 with SMTP id
 d9443c01a7336-248d4df57cfls49849585ad.1.-pod-prod-04-us; Mon, 01 Sep 2025
 08:08:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2qkxllJoUFIOJLJqKXHKt/+LTwhpuodt5CjIGshQa9oNvbV3K9Ty7hsjiLWGsTAKjvzTbLEQGAeU=@googlegroups.com
X-Received: by 2002:a17:902:f60a:b0:240:2efe:c384 with SMTP id d9443c01a7336-249448db132mr99236515ad.19.1756739318224;
        Mon, 01 Sep 2025 08:08:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739318; cv=none;
        d=google.com; s=arc-20240605;
        b=bjgzWwmPilaN4LNJs+YS+W7KoQS4Mc45EWv7f7+u/rdmEDfLXPmJ0o91Bmwxwbz5kP
         4vm33woLVx923Dt444DbUUfb4I7Oq8dU6fz7R3WLtp05FxP3C5vaP4gBsUZDJZc4T9dx
         +k+qtarzdl/rrlVco4dPXmsienIPLHmCboFlxzfyNkfbm7MAoJjAZkyqPP7LJmCkw3WQ
         LYrKOWAj8eymAWefBHBVvWJwRlPU+DmUWQ+nEdpuZsthFCK+O14NQoOTTnATHSE1M2mT
         xKs24LBQVotvM9bh1n9DmVJjdMcC0DMu+WJL72aLrzq5WQWL5y3hE4yUG/c5OuMTAQaZ
         QnyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q7z1hEbmTMnNJugBbqE6gV6TDdcPzbGR+eC0MU5uXl8=;
        fh=Le5UCAyHFARpvd5xG7qbGRmMIMGH6cdg0dbHcRTfhZI=;
        b=dbDx0UzMMKICS8fkkL81zVvIRcbei9LVs1Ev3HlVN7+r5sd8Tac7hR76ZAqGYZyD1O
         gL6c8eI+OC2x3nT7s6TnGVqNpvA+Hgy0Rf01cYyVxgMnDIaeXV0uWdI9vq3kzbiv5duZ
         W6NnYwViEipl6SaGmA9m6gFb8+q/eG3/3ueWPaUWqXByf4MfxQ27T5ymEuyBtjcHAiVY
         ANdbjZ/SfjZtKLGUQldDtYB5hhVRL7KabJmRDz+cEpAAjg8sa+gBdCCa24xwMoLFBOcA
         IVVtAN7AGW2NCR6wwWRvQ9E4GWPUh5ef8gVkF6+5FH4qYKSYVS7J1vqcIynpekOZWFKj
         Qjvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Yrs0RB9f;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24905da342dsi2938445ad.5.2025.09.01.08.08.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:08:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-495-YP3xofrJN8yNNz_Gl_acQw-1; Mon,
 01 Sep 2025 11:08:34 -0400
X-MC-Unique: YP3xofrJN8yNNz_Gl_acQw-1
X-Mimecast-MFC-AGG-ID: YP3xofrJN8yNNz_Gl_acQw_1756739309
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 44870180028C;
	Mon,  1 Sep 2025 15:08:29 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id B085118003FC;
	Mon,  1 Sep 2025 15:08:14 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
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
	x86@kernel.org
Subject: [PATCH v2 15/37] fs: hugetlbfs: remove nth_page() usage within folio in adjust_range_hwpoison()
Date: Mon,  1 Sep 2025 17:03:36 +0200
Message-ID: <20250901150359.867252-16-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Yrs0RB9f;
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

The nth_page() is not really required anymore, so let's remove it.

Reviewed-by: Zi Yan <ziy@nvidia.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 fs/hugetlbfs/inode.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
index 34d496a2b7de6..c5a46d10afaa0 100644
--- a/fs/hugetlbfs/inode.c
+++ b/fs/hugetlbfs/inode.c
@@ -217,7 +217,7 @@ static size_t adjust_range_hwpoison(struct folio *folio, size_t offset,
 			break;
 		offset += n;
 		if (offset == PAGE_SIZE) {
-			page = nth_page(page, 1);
+			page++;
 			offset = 0;
 		}
 	}
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-16-david%40redhat.com.
