Return-Path: <kasan-dev+bncBD2ZJZWL7ICRBO73WSUAMGQE3SQGGXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AB117AA9BC
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 09:09:49 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5039413f4f9sf2192055e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 00:09:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695366588; cv=pass;
        d=google.com; s=arc-20160816;
        b=PM2vHHGBZNqbgceSXXeSc85NC+oSVnOKNHhjR7Ilv0FKBNC+zMDoAOe/XXzE5Qb1R/
         84ITTtmJgc7EqapAr/jq6uUztKj9Ysb6zHXEweTJUMexBqmXrGZKiYyTWIIE3WtzrG9M
         VhyONshKyWVR+B1bbsgDnwUByEVBuFZgbmNDSUlSqfCP7rp5Bzlx9J/w6jlfZ++mw7zU
         LkJDa5p9kWMJey0SgY/zt7RaKNOD5Th80MX4ps2NVMh5rLCJ8lamOEcWPdWLC+K7HmIg
         ajgjR+h/Ju6F1zccoF1jqe+p8yCDRBYOYD9AXhb3XRyFz50qbXxHVBrfz9j1OHdo8Y2E
         BE7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=uPqwlh9pCVd8xM7SnJ5pEHu8Co6Y+DK/nrIMZmJuI+g=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=0VisOYAdka5wB/V3vP+I4jDGC6jQE0P98aF/Z7oLWSgtg8DicGONpV1pUM5pJgZOno
         YPZZ52b1fPx7NDF1ectoO9sd3ydC5uXzDoKyKmx17+8lvZ2EZY1q30tcbfZs//fvmLVN
         PexevFf5cNfN6DpCqEnhlQ94bF1WHxAcp+QejbbJmTTqtgykhmNEfoMEP3dw02rL0Ztn
         YJroDUCUINc2r/qeT56h5M+cphqFZILbrepmbB6WrEkhp9ka5yNKIIWKVkkbPASo6mlH
         XSg81qWpTCMAdrWpWWOv5g/Anlcwcb2EBEo8mLY2LAj+/2ZECobwgn1ZtLK6cJwVUh/u
         712g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=j0GTHFYy;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e3 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695366588; x=1695971388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uPqwlh9pCVd8xM7SnJ5pEHu8Co6Y+DK/nrIMZmJuI+g=;
        b=g9sUE7OJAEUwwaPFVtv4SR/xMf2YccQXmWnqAG87hxsa/vYfUGOTDEkUbhtzZ0NZr2
         vjTKPJSANjPkGK0eRXI1eweG/xrSEb7eeJ3q+46tdvpvgXcvw0uN9i1P5mFS2F80PrWV
         GIDASdp1fBQnls2t9QXwXAik5D6jl+KnRufEHNTwCmV16u5iFiyXfsaQ83IlrDgMchRb
         BDu/1ePkU1kelkb+955KZlXD294nDavdkRGxZMc/YkDA5pSPkheMqE3huWUm5XfOG/Pq
         0xA8H2QL54IOZV0DhOYzlEQ8ObMVPZ9BVlb8El1rotUUdu3ptKIEZGNnq1myaNf8M7AN
         uk2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695366588; x=1695971388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uPqwlh9pCVd8xM7SnJ5pEHu8Co6Y+DK/nrIMZmJuI+g=;
        b=xCS2y6336W8F7r/1nfaqLhllX9IbyHCgnqJVC3+t5ApeK3gtfBqNgMv2Gs9dJZypZz
         BZyVoQllZByzIbv+aIb9g+aWi92zK9HRQMhJor/Bp5T7rTw1eWmv+f0gFi3ER5PRV/Kq
         inRqc/9SMEc05M/WTNIbMQwC4xxo7oLfQyKWzQFACnFB9REDce8S5hVNmO5/+eiNCTGR
         pR5ZbwUM0WpZwNmKY6NaOzK96KvSzb0Kx0o8FsT9YuSKCPvr2AYuYGUjfxy9XsiQ+uQ8
         ehG4kggv9ElLkjdQlkNLXxpC/mH7LAhmhiB/GQ4gmRwueAXjY1uN1qKeh1VZMtxv9s3S
         bhCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YysulB9MIyhTwj/H8KdGxD57pnJtbA5sXFFzKVaPGwYY2fZzBO6
	Qyjdb2CuvwiIbkdSI/lmxk0=
X-Google-Smtp-Source: AGHT+IEsuhIHKy2fhzetj1RvFwQAiHh46un2WpsB2yp4tJxmA+rNG+yFDlBF2VNyycPJ/o5jH/c51w==
X-Received: by 2002:a05:6512:2397:b0:503:56e:ae4 with SMTP id c23-20020a056512239700b00503056e0ae4mr9548312lfv.38.1695366587272;
        Fri, 22 Sep 2023 00:09:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7204:0:b0:405:2359:570a with SMTP id n4-20020a1c7204000000b004052359570als85004wmc.1.-pod-prod-01-eu;
 Fri, 22 Sep 2023 00:09:45 -0700 (PDT)
X-Received: by 2002:a05:600c:2d82:b0:405:3d27:70e8 with SMTP id i2-20020a05600c2d8200b004053d2770e8mr1088030wmg.36.1695366585437;
        Fri, 22 Sep 2023 00:09:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695366585; cv=none;
        d=google.com; s=arc-20160816;
        b=zKPfFCDJmA45SU84w7kGtWHoGgjFG0SSTiEbED000jwFjIV1c9Ia+j7sGoESrBBugg
         c4c8o7FSiuZqW7MrPkCDRoJ+6zbRKv8SNWctg3sQ0IPebvZsBkKFXEcSWL45xN3R43XC
         ECt0SZfmNkok4qJS8D8YGS4EQCC0MNIyqQ8TNef8InHEphJ1UfteFvmFtopkQ680RNUo
         SqvuCpGM/TYAYFriObpolayOE5kqh1Ulz0cuVits+LX+YCL8vYNxsO4WVOEwUPh1IfMM
         SIaG40cm9Uv69QYKu2pdXhPhGxjfOAjZ/cgM9rmnGicWziBFBqHJGhsFgEAxK+rW5mxa
         8V9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=STMVv9/CmiXKMmwvCbzFA6MyMoHyyxo+IXJElKifvKA=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=r/Ld68ShOFflE84Oecjs1YW+xGlboISbUcnelt++8EHZB+9grcBVmU0ynclZywcW8W
         jRFnc+nHwHtbMs/5utZvkilJ0VUuSZJdp2lXNJD2r3Oy9Zx7YmhUc8c6cYmpOBaT/tTs
         D26Cg5PXYYSNg3CCeBfR51VDJ+RVZ4VfIK4dJqk+5S7KLKqsSBSR9H5+lKSQQYjyiAQn
         T2twQWfzgwFjQLVscPL+KaBAuJIM68xwIT6d8Oq2+h7ZyiQzux6SVWidJ9FEfOYrfMuo
         hEQAcD9Eb6m/ibwEHnyJpHVJQTEXyQlbvyv7wkJQq3/DRUDtMkyO4DoC2L9tay8yoYRX
         aVxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=j0GTHFYy;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e3 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-227.mta0.migadu.com (out-227.mta0.migadu.com. [2001:41d0:1004:224b::e3])
        by gmr-mx.google.com with ESMTPS id he5-20020a05600c540500b0040476a42269si281263wmb.2.2023.09.22.00.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Sep 2023 00:09:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e3 as permitted sender) client-ip=2001:41d0:1004:224b::e3;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Yajun Deng <yajun.deng@linux.dev>
To: akpm@linux-foundation.org,
	mike.kravetz@oracle.com,
	muchun.song@linux.dev,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	rppt@kernel.org,
	david@redhat.com,
	osalvador@suse.de
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Yajun Deng <yajun.deng@linux.dev>
Subject: [PATCH 0/4] mm: Don't set and reset page count in MEMINIT_EARLY
Date: Fri, 22 Sep 2023 15:09:19 +0800
Message-Id: <20230922070923.355656-1-yajun.deng@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: yajun.deng@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=j0GTHFYy;       spf=pass
 (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e3
 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

__init_single_page would set page count and __free_pages_core would
reset it. A lot of pages don't need to do this when in MEMINIT_EARLY
context. It's unnecessary and time-consuming.

The first two patches are in preparation for the next two, they didn't
change anything.
The third patch only set page count for the reserved region, not all
of the region.
The fourth patch removes the set paget count in deferred_init_pages.

Yajun Deng (4):
  mm: pass set_count and set_reserved to __init_single_page
  mm: Introduce MEMINIT_LATE context
  mm: Set page count and mark page reserved in reserve_bootmem_region
  mm: don't set page count in deferred_init_pages

 include/linux/mmzone.h |  1 +
 mm/hugetlb.c           |  2 +-
 mm/internal.h          | 10 +++++---
 mm/kmsan/init.c        |  2 +-
 mm/memblock.c          |  4 +--
 mm/memory_hotplug.c    |  2 +-
 mm/mm_init.c           | 57 +++++++++++++++++++++++++-----------------
 mm/page_alloc.c        | 22 +++++++++-------
 8 files changed, 59 insertions(+), 41 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230922070923.355656-1-yajun.deng%40linux.dev.
