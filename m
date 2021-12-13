Return-Path: <kasan-dev+bncBAABB3MB36GQMGQEPDVCPSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 09ED64736DC
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:50 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id j25-20020a05600c1c1900b00332372c252dsf7051484wms.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432429; cv=pass;
        d=google.com; s=arc-20160816;
        b=GJjKac++iiRAOkVpHjTPt24/2oH72iqdY8B7TXk6ZtDqWDu9HAMhx30+Hq2iAjO0OZ
         dF52+ULjnt4BcEcx9TegU5iQSRmMDaU7egczgk467ZMi395aNh8lummIFFPK2hGvqkAi
         2eRFGkvaxC7tu7djNhvtTmbkSEuJJv2bweFY+vt3HLt2WKMVAta9OCgOGhV2zkB/KyDd
         awijc/eHC8UXnm/5bX52urh4lKeHXkb1aSaW8NVtBwnmkxEp8RH3DYfx6eZsvEaBNKa0
         LMe24+P8+N5tpAAkWxfkOLs2Opdgw7ADQHb/hx5YTICbiPSagOKNjNGj1fHVopqMw8HJ
         diRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oq5bHaLCavGnRG0YeWEYZpwrmmaCUYC7DGTMPg2nw4g=;
        b=P+bh4AOddbd/7BAwEu5a1HvDPYGgjNz/WWf1RRc9KsrZHyk0bmZs9cKTvPZEVo2oig
         7hu11TBuFOlLXePYsw20jmOfXZasIMKFKEJdFAnOhqzPdvwXE2J/gOCvE80Z0XK0M9jv
         8AenuhRfA/y93Ufyco1y2pCmEi69bLzqmAuXf7GuUHgZyaDoGMaccdUWd1bOYcXQNpI2
         K+CE+SBFmp3Cd0onvKdbupz6JqzBRHE1nfsaoHrnG5WMWl/Wf1wSzSSEAmRYpnlT+/oi
         9gD8NALN81UqTnF3OPCynWJen9lEQdTttGVX7r7+uLTNIMVzIZdA1r5MkQqDbOmlTXiB
         stUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SQk271af;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oq5bHaLCavGnRG0YeWEYZpwrmmaCUYC7DGTMPg2nw4g=;
        b=V7Lbra87iaRrKpdWdsw6gziQ9yottQPDraThrY0lffk5ctmA2xBu0uqJdiGj8JHHXc
         8UPmLuSoGmjwyU3HUTLhTSqYmX1c+qk6ZACfXduUMLloyaw3awYO73a4mLwiKgqCXERP
         GFDs7MQkHsaOS2xckzcCbP1OJGKPe/K9lWOHPrupuuD9hXoQt3eKSLUzbTMPrcnLWeWj
         HSMuN+YTXaM8ANIGrPkEK54Zxeo3vXL7DW1Rq/6yHJAsq/geap8RZtqxrKu9H7ohOWMJ
         6Rf799j5i2p0VcFeA98PlkOJJGvBCQz35Mc0Eq9JpFjsX74OhzooQU/Che8d84ykQfwP
         DGDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oq5bHaLCavGnRG0YeWEYZpwrmmaCUYC7DGTMPg2nw4g=;
        b=znea0EhC0sfsP3dRiFnCF56yTd48aAUeBM3asJbYHULeQCBSJx4ZoNDkihSqCpqlJ5
         npA6k7uKiqb73XuAZxQ1imKYmzc2chab4oYav+oEeKuEB74g5wZ1taUU9PkiAR/jsara
         lI+hjY8WjukB4Njy+gPwb6BDnGg0vTUYNTrX2jA/L2PALOFiWUoBr+mPhjO7j1Clhhfk
         bHTwlcL6c+octjjb8kEoHnphFdHWTn7ntampKyrJHUP2F7NZ1bWpLKhbb64fjy9qixxm
         jRpG9v8tI3fFePPvAadgSL6KV6b9KWrGaewp1SYe6cwqlPHRfrGhUGbR/AmVjmVE9mKN
         zQyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lNKxn3w4QrlRMNE5lJvuJOFiq5zAkGZqjG+iENkDGtwuyKdru
	yY0Eiaq3TxHsLXJmhiaXO04=
X-Google-Smtp-Source: ABdhPJyjVPNL94GKrEaag8QumOSnjRqISSkT8gcmVx5Sybfo56i0l/lzWwrNVNYOZA7DNnVbPdwniw==
X-Received: by 2002:adf:f189:: with SMTP id h9mr1207160wro.463.1639432429811;
        Mon, 13 Dec 2021 13:53:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:770f:: with SMTP id t15ls90414wmi.3.gmail; Mon, 13 Dec
 2021 13:53:49 -0800 (PST)
X-Received: by 2002:a05:600c:2297:: with SMTP id 23mr39703574wmf.73.1639432429056;
        Mon, 13 Dec 2021 13:53:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432429; cv=none;
        d=google.com; s=arc-20160816;
        b=MMFCAHknT7Erx0P/zJlx389rtCOyAdw5e5RvgnuxN8EO6nUxaDMqkvJ5drnnZs7h47
         gfjMiXA73GOo4S5j8Ri23Tk1uF5RW7+wFrnARHw58Kjz1oQ+tR43w3te6iuRFSLSaiTX
         rv4mHA5MmNV2pwJN0BNUrvls3P51gLHviIKMYGonINt46MnKCcjPLPaoH3SZQWqgjpPE
         R17VIPLuoU/4FCXE4rxl+9lHKIAM/D106sQcWnEbcMfhUtaV6cHDBfRtbM03yAIOnfKa
         NUZRH+uYZVfSkJu5mCmJo7G7abJ1E7Ul9mnalbFziuFxCmSIvICNNVYHNvqhxpzfgLRP
         4s/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cJ0jlRH/hquQ8J9ZVRCu3YYtyS2ZzdopP10ccd9wkaM=;
        b=id6uouPWj/imnn2kU7Q1TxF0aYZ3gMSRDIXwssWjUUR0qGtu4XN2x4hHpFn91fhkh2
         QzwORZspn/P0JwYzC9z4qsz2XFUcBbnI+VmtwPZ9dWj7/R/XraZFGxhcIL7IvaWsKhcJ
         3PM0J68qYR1xldKJeqe+Fz5N6Hd+Krnsb7QD4Y+9swmHX/jBnObGXbFeqR6Aul1otZfz
         InUXnfIY6mfwoGcrxQ/3OJr2MJvvoqJ1Em9a8pZhPf+Z1xexXLE6CmfyCcJ2nta9Cn2O
         eDZ2OiA6Yv5/6kzGxhtaE3fRcN9cEuK32Rm6tz086zt+Ilu/6eqPWCw2jzMGQPoxBZ7J
         RbjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SQk271af;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id r5si530523wrw.8.2021.12.13.13.53.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 16/38] kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
Date: Mon, 13 Dec 2021 22:53:06 +0100
Message-Id: <1d56452cf3603ef28cacf13ec92a9e6c3522ae43.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SQk271af;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
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

From: Andrey Konovalov <andreyknvl@google.com>

In preparation for adding vmalloc support to SW_TAGS KASAN,
provide a KASAN_VMALLOC_INVALID definition for it.

HW_TAGS KASAN won't be using this value, as it falls back onto
page_alloc for poisoning freed vmalloc() memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 952cd6f9ca46..020f3e57a03f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -71,18 +71,19 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
 #define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
 #define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
+#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 #else
 #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
 #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
 #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
+#define KASAN_VMALLOC_INVALID   KASAN_TAG_INVALID /* only for SW_TAGS */
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
 
 #define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
-#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 
 /*
  * Stack redzone shadow values
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d56452cf3603ef28cacf13ec92a9e6c3522ae43.1639432170.git.andreyknvl%40google.com.
