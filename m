Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4UG7SKQMGQE2R7DPQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E4476563510
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:46 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id e10-20020a19674a000000b0047f8d95f43csf1203842lfj.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685426; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wur6rcEwUrJ6U0uE4ChNe0AJehBDBycFcgtPrLeXLbU2CO5ucpW6zYepiOiDbbOVvH
         HJxWxOdQk6qiHM84fJKB1VrkiUWvjto1eQnjv2ELcw1Xn5GT3GPKGx2jPj1hVSLLGls/
         cxzRwTrCogUBMNUV59/78I3GZKsjMW86T89hpwSszp4dGHQv09GJXBOi7wavU3fTrMNl
         mdVyZxwUbuNWnudVqX2oSooeiNobg6+L/SLi56m9kiwwRV27QpvuUCHjJXaa/6gbqXty
         P81sjG/QjqQqKMDGz2TotaaMLi81vRyNJTjLH5igxCLBAlqeIdFHT9+rg0mgFt/FQAMc
         aq7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=bZmBxLHc4LHzrbYMO8LejyJ+S1aiHsQSYIMp3ms4QKM=;
        b=BvMt+OklUhSZKLKbZI/GbfsK7ezXD6UdwhPlee7UJcPgpQmQgN6hx8KES0YTPNWuho
         EufBVaNQAMimd8SNMt99PMZHVnTX9djbx/i+4DVKbR1Eb6fST+mxnEEF/XmfMARjOtEc
         t/pKOvJ2k3x4/gRYJ30GbDN5jtwGl4FsX2XqCdbbzACqVJH/J/0et+Cf347YDh4NYcqV
         WMOUKk1JRW2Y4hKVkHtKveENyjOf+/h7LMLMOpkbBWDDlG3bZ6tKuRqdowZwJTbtfs0C
         YpQzUjWSdkQ0KJhgKZl4FUFL+osi3+w+FADNDCYKsP2Gq4NVpH2ngWsCiTn3CEouhjTJ
         b+/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rHudIZCM;
       spf=pass (google.com: domain of 3bwo_ygykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3bwO_YgYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bZmBxLHc4LHzrbYMO8LejyJ+S1aiHsQSYIMp3ms4QKM=;
        b=pCtAptftfQ8b9VLdpc+uImN75yCHMhsZNt6ez23rR+j795v3K8FGTFDC2RG1seKwjV
         aj4yIBuebQq1ksJDozwRxY0Iyt5YM0Yp+BZv+KdFz2Yg3STWRt/51Wza1R3F+pOFZ9wy
         NvBMdKJoOMV0BvD1NTVXAiTIXS/8akx7HFsUYd/94GVWlB8ozBuryvbMx9YpdvEwbRgG
         FdPFfxIt2xHqWzbdr1GyQYcQ0Jp8hdrKXEgfguYz8vZajPJPGCDnteW+NvVQcMAYMClf
         jNBJpoOtF3oHrrld/TNYQ0STJlF0RIgctqcaiaAOtOiOl31nypcS2I53Vz/s2LhVU89Y
         cyAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bZmBxLHc4LHzrbYMO8LejyJ+S1aiHsQSYIMp3ms4QKM=;
        b=bnd4JPp10ug5j7S2dMcsmGLTNgelFvQmBFlJonD8pVQ7FWyUARUPyxqrLWr8bXygnN
         HUVxe3EIsEU7OmIpAv8byBMJ9pPEc1gDlQkTZDyF9cmINNjdZ0xI3zyUhALaQV/7MSMS
         oUqqbPnx9lf1zV+o/hcFy/lhyCp33JVSOnt7opvqhC1ZccOiTwtjcy1U3MmR7MavVM0l
         8BmQeOskoMnBe36/AkLOwO7aAqXCCWXHhyvPOSmU8xyGPFI7HoU7sasAWabbPOM72z2q
         UHeCCdOc05DbQJUnlAzkWIVKTnLrOZ3ETAUHhXFoQ7jhiCHD8j28BkFMnm+8zEyhF1U5
         eQgA==
X-Gm-Message-State: AJIora8/9aNNJ1GDiAndHggkHg/KXf1L/NQP6F+LRIhTs07UquFffqmG
	JrQKszc2kN00JUIMNK1E764=
X-Google-Smtp-Source: AGRyM1tw+21IvFl3HCqmqidsHqmM/dVJG8/7kkHlfnxfVVFBTFKevDyhlSZhz8PF59TKuclfqoOAVQ==
X-Received: by 2002:a05:6512:348f:b0:47f:8b25:e9f9 with SMTP id v15-20020a056512348f00b0047f8b25e9f9mr9442095lfr.512.1656685426442;
        Fri, 01 Jul 2022 07:23:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls86357lfn.2.gmail;
 Fri, 01 Jul 2022 07:23:44 -0700 (PDT)
X-Received: by 2002:a05:6512:4012:b0:47f:641d:45a4 with SMTP id br18-20020a056512401200b0047f641d45a4mr8839499lfb.425.1656685423978;
        Fri, 01 Jul 2022 07:23:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685423; cv=none;
        d=google.com; s=arc-20160816;
        b=q+5KGuet+h6O731T7wYbsyuMOKTs4g/kMbwjzYt+YpYCDGeCArqBmth4AQfwQrfj3m
         PtnxeY9fDQV7tYaa5ACbpCKm9dzIK1egqAXeWundgWBW0rIygvpWSxX+S0UWCT9VHikC
         y1FkJVusHQAlMVBL3eu7GjCymf+7TvrhY7P4HLdYYZVgwWVdGFB4Q73tVpcMEG9E6CGd
         OamPdADkCd1P4ek3EduGoXpeYLKGeRy8CTWpKorFsr/4C9m26+qYWzaqZ7jmwop+68FI
         TGD+hS1C9L7V/gzesjEqtbC/cNbAgdQoH8uvKfSwTFqUCZ1RZOVbaGHoDpuPUIVouHIH
         Y/rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=AkHvx6ZxtZ0IjsJvZfH9AmZNAyLy9uG4lwf6iPpek9Y=;
        b=yhC6eBzM3KH8baaALJVsJJFA4vRZXy6oANUcm8S2UThVEeKhHcJGUY4Uq6fA/4Fv5z
         jrdLSBTfofIM1Pt2jmLSZlwZHdGoMJhqloPtkoT3K3G3WEiAp9541hLC7lIuR1NVev1L
         NX6HSFf3V1E3dDIZFxZTyZdZPHH3ZV1wWo+WRlOaEsx22qt9F+6Z+YDrR+lglQVoRRr8
         uW2ARnRRVLvSNfzGbD/WJ7YhWrWQx0OshvAfHjSXRbv5oTHwKji50obs4Sm//Q0E1KLV
         rR7YbRilvI4ZdGNkZ0nwJUUsBxYM7sXz4pp6gWFIGmCF+7Wr38LisxcfMDVUc6M8yEDX
         Fknw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rHudIZCM;
       spf=pass (google.com: domain of 3bwo_ygykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3bwO_YgYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id o9-20020ac25e29000000b0047f8e0add59si1067088lfg.10.2022.07.01.07.23.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bwo_ygykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id w22-20020a05640234d600b00435ba41dbaaso1882181edc.12
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:43 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a50:fe83:0:b0:437:9c60:12f3 with SMTP id
 d3-20020a50fe83000000b004379c6012f3mr19071968edt.120.1656685423650; Fri, 01
 Jul 2022 07:23:43 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:35 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-11-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rHudIZCM;       spf=pass
 (google.com: domain of 3bwo_ygykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3bwO_YgYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN adds extra metadata fields to struct page, so it does not fit into
64 bytes anymore.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I353796acc6a850bfd7bb342aa1b63e616fc614f1
---
 drivers/nvdimm/nd.h       | 2 +-
 drivers/nvdimm/pfn_devs.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
index ec5219680092d..85ca5b4da3cf3 100644
--- a/drivers/nvdimm/nd.h
+++ b/drivers/nvdimm/nd.h
@@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
 		struct nd_namespace_common *ndns);
 #if IS_ENABLED(CONFIG_ND_CLAIM)
 /* max struct page size independent of kernel config */
-#define MAX_STRUCT_PAGE_SIZE 64
+#define MAX_STRUCT_PAGE_SIZE 128
 int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap);
 #else
 static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
index 0e92ab4b32833..61af072ac98f9 100644
--- a/drivers/nvdimm/pfn_devs.c
+++ b/drivers/nvdimm/pfn_devs.c
@@ -787,7 +787,7 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
 		 * when populating the vmemmap. This *should* be equal to
 		 * PMD_SIZE for most architectures.
 		 *
-		 * Also make sure size of struct page is less than 64. We
+		 * Also make sure size of struct page is less than 128. We
 		 * want to make sure we use large enough size here so that
 		 * we don't have a dynamic reserve space depending on
 		 * struct page size. But we also want to make sure we notice
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-11-glider%40google.com.
