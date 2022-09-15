Return-Path: <kasan-dev+bncBCCMH5WKTMGRBI76RSMQMGQEEEMNUEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 73E635B9E07
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:08 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id q10-20020a19f20a000000b0048d029a71d3sf5645596lfh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254308; cv=pass;
        d=google.com; s=arc-20160816;
        b=bx5D4ktrMjZnMo4gsR5Ic8wQAIweLpXw4Ytv7FaF4mSIHHCGhoRyTkx+HzLnfGYm1W
         7Qkxj/hMinboRUUEq/FWzahMLRnHyLQl/ECR/bdgIrhok9xpshO/QmvrNC7ZNpGL5dWa
         BGL/frr9tvh6lzQhjcFbfz2ihNEHYcObs2/xEDax/n6AXelpIduO2WeoyPaTWSQG5SS7
         4ywS08PL3DKWesA5Ztob8a68GQGKj7z/WJllIq4fXGFJRIuMDwoJLFMMtv7iRyx9quWf
         lmFbKONN+QxFy5tyHghQ65k/oKdcl72yVYyXv/y/FRwvUwDp8ETl8U1lWxtHM205+mMb
         Lqiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=sAG/bLonw60j4jWLU0fYGCVCYakpc5Rx3fG5cN96kXg=;
        b=aoUG73g20iRCGySzQ4bqjd+4p8g7y0HqV6y8AWwlDSsyzm0yBMagfI+VSnPyDYZAsn
         vJGDpByUYCkkGjZwtPeGzA6RsBIng9idCATftL87RkrO4aumHxFm7bQfZyYqgoVinId+
         TF9de1uCyiUgT8ThG4PBoAKP4MF/77sYCtu3Juwq2cABiTPAtndkmPynOVXikgctZYY7
         Okey8ho2JEstK5QLV/RAh5Ud7m3Ou5TNVsgj6v0heAQCp6QIj++DqAKra62up8AjiCzJ
         oN7Gj5A9JZDWbiv2uOkeaENZqLApr5izlh5VAWjKOkcMIVZVYy5zTp5DMx1gOUObvVt2
         p37w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gEgjEUXt;
       spf=pass (google.com: domain of 3it8jywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3IT8jYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=sAG/bLonw60j4jWLU0fYGCVCYakpc5Rx3fG5cN96kXg=;
        b=p7cTK2aTZJZSodp5HvPHzwOGoY6Hvplasvwr0wyOYRIbYmN5tcBlV06cCK5gUk22xL
         MGIMMPjkdCOLpvuTwiYDLB4hVR6XJ6IuqKQd6eEPl9p3fNgLiuoW3jyHzSxZgvka5SPQ
         p8PEVwf12cQRf6EmZ4sXsljtNapaVXOiT7kqzr2WRCfJxnGsx/jh2xZJhGwFpx7upi1w
         8Lxn3ncLwItxIbv0RRkBqdsEQtAqfPjuhNGw0Eectq5d2h8qtLvsMWbM8VAqz+8ZNwhB
         LqfOfycbBNN8eRu/x2JauDIrm34/LeLuJVq5Oh8PyZ4GJjU4VU8FfrinXk1MdBIh4jvf
         tNtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=sAG/bLonw60j4jWLU0fYGCVCYakpc5Rx3fG5cN96kXg=;
        b=ueaL7EwjdBwtnzWzOJA8wRQ1jToZnygjp0UyZboOiOmftcjwQ3UymMNjBAsyh9rlOt
         KGK2R1IG6PXKiJeCH+2pAwfDuPDf5WH4d4zho5f04fGn+tg9DdKrWs0DKzBba0+Emjo+
         YgvQx6G70bpXXQ6uYpgF9ucpc2+sYW3Enb3q26lLKntmP1eSTSS19rHEhq7/bbInpsiD
         j3znj31XBHXs5q/W/4rmwcn/T7w+dK/xvPtIVFCIYZWf8WOVsS/cg9aLTaIus30OVCnY
         aBpOa5E8B/2bKDLS/u8C8plscInTOBp264YJfylIR+r5oe7vWZA4XZwAYqG+3nGLGofd
         72cQ==
X-Gm-Message-State: ACrzQf0124LnBq1JW+nfxFHn7JOseap3Bamzcll6VhjBVZo3yhVZmZS9
	1QQbwUt9XYSgXa4LbQtOBew=
X-Google-Smtp-Source: AMsMyM4HljroR5uByY+P0UiHR8fYOai/aEYUWoB1r8DlhbY2gKusVwD2gSRgOrz42oY/THtRSKpcYQ==
X-Received: by 2002:a05:6512:b0a:b0:492:dacb:33da with SMTP id w10-20020a0565120b0a00b00492dacb33damr112681lfu.668.1663254307872;
        Thu, 15 Sep 2022 08:05:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:36c9:b0:49b:8c05:71a5 with SMTP id
 e9-20020a05651236c900b0049b8c0571a5ls1226570lfs.0.-pod-prod-gmail; Thu, 15
 Sep 2022 08:05:06 -0700 (PDT)
X-Received: by 2002:a05:6512:3e4:b0:497:a649:6627 with SMTP id n4-20020a05651203e400b00497a6496627mr131595lfq.326.1663254306519;
        Thu, 15 Sep 2022 08:05:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254306; cv=none;
        d=google.com; s=arc-20160816;
        b=acIjlWIKuoLEbuUcp3AuRoRL1YGhOJP59pyYhwgDVMk4bk81hfwllDj8NcG7xJdYmU
         boRMrhFIIDXrCO7fYQa0UhKQC9GJ7mYFQQK2j+GSOcKAHWhVPbxCjrNsBszF8Mgm12oK
         DxyMo+ZtVntL5/+vOI0uN5czFeQT35li61cqbDWlmc24xP96wViHvnP7kmboU0kS29YC
         R8jm0N/1ZlEWBKz29jyNZoh8pcZAroJYaHxd+yZhJZ/9U1dXm9tYT1Y4RREWpqV4NHgi
         OCUNyJGM+CG2MHBXpn0zaAJtnkiU8vXDVenFKT8OGcm65q/vuHxJrmIibyXcatsBpkXW
         43tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=vmKBMF2McNFVJqtG6TmpI3MAJxV0RMGeKyj0ZsE0Fyg=;
        b=sscZg1ClZWWgi9FoTd8st+DD4/uYiBHldKFpPqIax3neCxPNO8XyVB4tFerZT6wnzc
         w1YRJGIQ518O8+EcAFlrD/gpU0MQa/jD2sxtke6ewR99MydPfcETexVDbEmwnTKlE0af
         dTMCoEw7g/s7qh3L4WVgY/PB7zdGFU5Pqk0AVTWWlfXGhBGs3CAIKQgLz2bYM6fcLXPK
         zNd7BbRrLkDT+YBQUk1YtkHJR2+V6oN8wol4DtjLbW6cTXu+C55v+TPfnrslTdXypSv9
         2fyydQWbBO7KhNgNRZfPkB/t9XIpXB0cUnbSpsifOi1S2XxWuNT5a2kauqDh3LOtMD/p
         EVug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gEgjEUXt;
       spf=pass (google.com: domain of 3it8jywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3IT8jYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id p22-20020a2eba16000000b00261e5b01fe0si489097lja.6.2022.09.15.08.05.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3it8jywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id sb32-20020a1709076da000b0077faea20701so4744614ejc.10
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:06 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:5112:b0:451:cb1d:c46f with SMTP id
 m18-20020a056402511200b00451cb1dc46fmr254990edd.35.1663254305960; Thu, 15 Sep
 2022 08:05:05 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:44 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-11-glider@google.com>
Subject: [PATCH v7 10/43] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gEgjEUXt;       spf=pass
 (google.com: domain of 3it8jywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3IT8jYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
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

This change leads to increased memory consumption of the nvdimm driver,
regardless of whether the kernel is built with KMSAN or not.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-11-glider%40google.com.
