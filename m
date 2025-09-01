Return-Path: <kasan-dev+bncBC32535MUICBBZXM23CQMGQEBSMHF2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id F379EB3E84E
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:06:16 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b49da7c3ff6sf2594446a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:06:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739175; cv=pass;
        d=google.com; s=arc-20240605;
        b=JPhN/cIPUFZkokbsuAmi5Ma9e9NqTh9CYb2YDjLG1e2Ej+tsd9ybAoxMegUpFcngO4
         xMfJiwy5UttgNGjjAYS2+tnOWsn0Hfiya3NG4R/fQbK6MWir4bHkZB6vk29SZfb5Ib72
         631+/xhB5n8D6jflfI4oGMdX5ZQE99w7nAfNB52a+0kr1usVpUqDf4Q12rfBiLcZOxAS
         B8TzrBrQI6ptiFtxRkc2Iy+EF8YZarz81U5ie+XUU+vvjsD0+Lmcz2hjLbaHAwBN9hg1
         TywOG73tQ8qfmhZj5eYgN+/J6+fZ/jHHvRCimhveYl0jKrL2Cgrkd98c630aD/CM4mqv
         2Xvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=v6bezJpzs3TyTjIslIKgTE5KRM9yAZaDpuer13pMRSc=;
        fh=pK+sx/blf6Uf5Uz0eK92xH5K9WaIaU5F45LWf3R0FaQ=;
        b=GEve37IJjxlS47F8gGKQ7xQ2U1kXz9c+pHd94caBY1m0kvOUdKwmFqk3zlvbZk05sT
         e97qPhm/IJdqixGlwF3M4p0yYjpAEkJtmjCAR0VvKKEqx7w6gzHKE7IpOP71gqrvrjY6
         8ABp78lMzA5imm4P1YO5AOsvRjqO7EHjuMyUNKn8kRsPO6QN/pFlxMUpgL+dU5pXQJ4x
         1Yb7lStWCzkMeGyT2eLZQp+55N4eY63O6RzcoRwuur4sHMnaylh+DA1VzG2U7erXE7M5
         ndPo+QfNK23++JcDKiNLOrTFLNFv9iCuyNRCQXlId/ut9tOqdl8AwPYDB6NT4kjqcrip
         F7Iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QNcx8jan;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739175; x=1757343975; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=v6bezJpzs3TyTjIslIKgTE5KRM9yAZaDpuer13pMRSc=;
        b=rgeWKuziAT2SqH4wbib6i1bYU31aajt1H2aipRXGBHfYFP9VZ0BhpiMAOUNA/oPZrs
         aBsE2ZoGQFQGTjr7uTKApA7cdjfdJiK1/mxHHJG7F6UOP0UBbL7vFWlvl1i/FcWW3T8x
         YnrSP4iuADCV+YwcyqXm/XFa1Hyt11ZPKFDv7XXtVprespjJokQ8H0BnnjXEtLdO+e2S
         zJJYWsbtmgbQZsnzrdpDjL0q8i9VOMypCJ3Y6fLOfHrXh9RHzcHPPJFsMrcqWuox/mbW
         i1r/n9j4vOaHPuZsSeFrddvxCze9fkfhdEp6aZL/cCu4ffAtP6cfbJ1SMd5Xw9mxje2e
         G20g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739175; x=1757343975;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v6bezJpzs3TyTjIslIKgTE5KRM9yAZaDpuer13pMRSc=;
        b=YVhQjLazzotD2LxLkRQ18O/ZZ1AIc1zBVk71rRkoFSnCyeivhF4m2nVSMApzUUFaxv
         c+p7xG+tHj6CYxj8YXsihZJGmdsTMh5G+JrgxGO6IXDtv7LRcRlKWOmmnCQYGTzR2Cx/
         2kLAwKjHieYrP8MPsKJmmdEOtAKRzVwr7cH1BLYs2eLPcb1GEgTSmLHTpDQFXFLSJTxF
         dcx2XZafGckclwkAqLcKtyuXEK2CB/7GQRcq+oZHvF2OmJSyEJ4F+xbhaySZEqlpVRKw
         0zOHOG7aVpzulPp1kv2c0y4IZeA8ZO8SBE/iJEyieXGELKq17Vf77SzcVfgZ1xlZE+w7
         qbVg==
X-Forwarded-Encrypted: i=2; AJvYcCWYLrjbseAsW5TYKAB+wWNJqI8p0A54cVTB9bXJP3LjMWA4cbNQaeTbkuMnRD7eihY4EE6IFQ==@lfdr.de
X-Gm-Message-State: AOJu0YwuXwrPFZ/ytIli41ccTV+oBy/ZUGSS31GT6vx3u995OyBum1lu
	YMLZKd/tO8HjX/c9RvUvD4VfLL1Pf91RbEWmKmqucUsdn2tIrYOMJXMx
X-Google-Smtp-Source: AGHT+IH92scDos4sYR50o2q4cH6uHEC/YSFDsd1tAwpAbDcXOsmL1cCWdxCe0t1jgirtHMgvHWjH8Q==
X-Received: by 2002:a05:6a20:4321:b0:243:b8c8:a247 with SMTP id adf61e73a8af0-243d6dd8d9dmr11884724637.2.1756739175093;
        Mon, 01 Sep 2025 08:06:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZexVfj/79vTkgJCSjQlKbAcRo563z5jhPIdyfz06MZ9uw==
Received: by 2002:a05:6a00:2b9:b0:772:27f9:fd39 with SMTP id
 d2e1a72fcca58-77227fa0a1els3746667b3a.2.-pod-prod-02-us; Mon, 01 Sep 2025
 08:06:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMDScttq0ot5/96hMac3byKyRdm2AZMx0Jj4VklSz+4PzltgJ4zL3GpvQlnmc6ahUP4xbCQsJQloo=@googlegroups.com
X-Received: by 2002:a05:6a20:3d86:b0:243:a189:f1f8 with SMTP id adf61e73a8af0-243d6ddb3bdmr12304587637.8.1756739172155;
        Mon, 01 Sep 2025 08:06:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739172; cv=none;
        d=google.com; s=arc-20240605;
        b=O4OFWKjotZiafc16660bQbhAYPgAJW0Pc/fi7++g5A1Odyx8FNpDZvSLBrRFLxoaDV
         bnA35tu4EWpQIisJfWsW3ixubOic5d8NcUzeCytWzSttbvKI9guLRiWBWlNC3GlT7HLn
         D+z16poB4Wcg0233cTnHxYtcaT+e+Jfok58ru1fCR+yIFMTiiuwnUrPnINZ4rVpFl/Jt
         1E57lWYSmneQ81gUwWkxiVQgFA6jeRY2xe2IkwiLtDlU9E20XZVVMMT78NT0FFVJsgp1
         A/BDgLt1XIRcj97qyphUGbBJcMv5j1JHm0pZ4wCnKvpJmBz8KY1FWkrqf8xfnpnlsaJp
         hOug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cLXaFnsvcEZ3Dj9TJuBmn3z/jlqr9HdUmmd8IA3Df2I=;
        fh=bGeIh8wYPpLnZcVtWmq+vRRGqY2Ry+3P/s8NJCQAGn0=;
        b=Fn0FhJTXOFBRzCc3E50EJbvDAcUCO8ZFBp32ahep7c+Yrqj5vm6bBcDZINSr6j4Qru
         45T4l31NqChEbTIPPsradZhcDtlObeusGDvEoCBxM5uk49rYwiZbKniS2yqUTq8X2WnG
         QkJ1NJdRlYcAuEy678GyloY/cvmDP6bzaPU6rtM5l7nCf5UCoMOjrBU1Qxh8o5jSWcaD
         5sLLT0NEbMH0hqee3LelAYEu2muMKW2HDU+VKDWPLZzc9KEU6+COa3o4v+ecQ8TGrmcN
         aVprZjyBbQSpnsvHcO8ue2FgWg5yVgpgVJvSgTAkppSpcBH4bWdE4TZQ4MsJPPcr8Jxh
         Eq6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QNcx8jan;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4e61004f72si264133a12.5.2025.09.01.08.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:06:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-643-vn9FlFaVPyW1oPG7gsT7bA-1; Mon,
 01 Sep 2025 11:06:06 -0400
X-MC-Unique: vn9FlFaVPyW1oPG7gsT7bA-1
X-Mimecast-MFC-AGG-ID: vn9FlFaVPyW1oPG7gsT7bA_1756739161
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 9823C19560B2;
	Mon,  1 Sep 2025 15:06:01 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id F13EE18003FC;
	Mon,  1 Sep 2025 15:05:45 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Shuah Khan <shuah@kernel.org>,
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
Subject: [PATCH v2 05/37] wireguard: selftests: remove CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel config
Date: Mon,  1 Sep 2025 17:03:26 +0200
Message-ID: <20250901150359.867252-6-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QNcx8jan;
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

It's no longer user-selectable (and the default was already "y"), so
let's just drop it.

It was never really relevant to the wireguard selftests either way.

Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Shuah Khan <shuah@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 tools/testing/selftests/wireguard/qemu/kernel.config | 1 -
 1 file changed, 1 deletion(-)

diff --git a/tools/testing/selftests/wireguard/qemu/kernel.config b/tools/testing/selftests/wireguard/qemu/kernel.config
index 0a5381717e9f4..1149289f4b30f 100644
--- a/tools/testing/selftests/wireguard/qemu/kernel.config
+++ b/tools/testing/selftests/wireguard/qemu/kernel.config
@@ -48,7 +48,6 @@ CONFIG_JUMP_LABEL=y
 CONFIG_FUTEX=y
 CONFIG_SHMEM=y
 CONFIG_SLUB=y
-CONFIG_SPARSEMEM_VMEMMAP=y
 CONFIG_SMP=y
 CONFIG_SCHED_SMT=y
 CONFIG_SCHED_MC=y
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-6-david%40redhat.com.
