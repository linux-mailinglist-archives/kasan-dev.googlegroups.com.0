Return-Path: <kasan-dev+bncBAABBF6UXOHQMGQEI24DH7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id D16C64987A9
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:04:07 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id n7-20020a1c7207000000b0034ec3d8ce0asf273978wmc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:04:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047447; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uo5nmE8aCWOooYs1nZ6/Wbn4Zkr+/xJENM7MAwcZZ9z0S7XGyp0oINivmyPrMOBlUH
         uuJp7BRWvasq3kNjl/9s4sTdPgx/pgQxHpIrG47ZrmmfHvZEm2AGoX0BnNOkWfgdILiA
         p7ykRMx1GEptJ3dFuLwQfPJaK+hwB9S+xmJAMbzg7r0WVtCv5Uq15Jmxp9Vw84jXFijm
         o22gcoirtpDUHSqE566qQZnObUTHTUZpCwpJ3XiNaEp7W3QN+qlIF39sjS6DTx3Ai9Ea
         FLv2HcUX2RjHNKjAu5Xfx12oaQ3tgaPTm07jn0j5WN3JQGUMmyE5nOwlQnymXM3F3qKO
         KoAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=M/s5FjmtDd6VFDxE2XIvFHOkwV+mMRcv6pXBY2ZGd6o=;
        b=YiRUIPW9awFPQCPCz2Ik1Mg9ZRKggAIYJiK1X0+N/heq90ywU2UzI3Dmia8crelJhZ
         aNJkL69ECVBneEbpqqRUd7qlh2D+9YM7xtyDxPbOG2eGjSHEuYVE/dLyVOTVkndLsyud
         nXsEkkS8NXpxNwKDLPn1i+zBdlyShcxlzFMKUQgvKx1zcucyqfoEV0NfszA+/eiltX1Z
         JOhWaVKKjWSLGFyA9RuhNpII3mhIC7FhqX9FDQHuLti7vxan8cVLSwAljff72MhQqbxW
         LHiX67Ld3KnOqRPH0c7zcyIxHODXLljshQSEhvTPcgvU0MIY2EcfK+k7aflaHAjqHrZI
         1fKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OU7GvARn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M/s5FjmtDd6VFDxE2XIvFHOkwV+mMRcv6pXBY2ZGd6o=;
        b=Vex988bQx1T+DUD5WU95xVrkk/PvAl2/QrnkFDXmUfSJI4Splh0nPHwZcwq3tozfyE
         YR7k2wQp4oNSNZrbRSf7GUdvjBgcLwKv1llsH8chT4tds+HYzIK0iCYShKP7v9n/kCwP
         zt7i9QJt80cVGEbd28YCKfH5WvnTIPduDLdPlAyDwteL6VU1SUGRbnSPxBnvC0srgR1E
         ny1TWt3K6+qmSkmxfc8ZK8BYFNxM/lyAnnt29arAFukGGJSrCmPEMoHZCNEc5IQ/JD93
         A6PiAe42v1U0gSC/0mPftI7irC+NW6H/ccULfECpg2jCPPm+y/englpnfaSStKAap0ez
         foPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M/s5FjmtDd6VFDxE2XIvFHOkwV+mMRcv6pXBY2ZGd6o=;
        b=umG49jYsyAYrkYJL1R4cj9m4++nXIi45O4ZneV7vUQC4CG9GrHGsd8Z8xbamvikExN
         TScU6UyEXtClrxDnK8buErscZkyrkDmtgUIhUWTc0+omvXOsFaFIU+1YidI9Pr8/MKhh
         UqSkSrUCCyRCyAZbxix12rJTx2W5B4NdqHhQVeRQghTETi1yELSAVRfqxfSmMnUhGhJi
         8ZytPLFSvVHmhfJd5IdYgGoRzKuWe0/qLzRwQ9Ywu0lCtPwRjn18HRZIy9+U0bSAdezz
         us5/4BKwGxi2r+5xNIEgf31EB8zf5MzvoRml7qC0p+QJagyH+WP4FJ58rZaGn2kXTlbK
         RCrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KWceBUmfgxMJW1VvTz//ECwEv/1t5ainHe3G5h2bBlyCSbHMz
	v2JHcr1zlypxvN2IvnWI6Os=
X-Google-Smtp-Source: ABdhPJw9TVG991bA7+mI7OYTJ/MTLl4GfVfdJItnb24AOIdQDI1ztjnUpVMj4tXGNVnwT8U8FsVIPQ==
X-Received: by 2002:a05:600c:3391:: with SMTP id o17mr2791460wmp.156.1643047447551;
        Mon, 24 Jan 2022 10:04:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e390:: with SMTP id e16ls291494wrm.0.gmail; Mon, 24 Jan
 2022 10:04:07 -0800 (PST)
X-Received: by 2002:adf:dcc3:: with SMTP id x3mr15493617wrm.417.1643047446982;
        Mon, 24 Jan 2022 10:04:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047446; cv=none;
        d=google.com; s=arc-20160816;
        b=oSxexXOGtlcGJYrOdU6c0Hx31YOioGTEpXs2bc3qjk6bMioxyvG59aI3Os6zjcPS94
         /s7tw28R2zPJi+2WsBCLJTVBg6QpKbTe7guPxOCLq1gy8+Dk39i0bfJ+NO8QnYG+T2iJ
         +XDAqZCt1un5WiM63uRAcFPB3UNuoSTgDIHeqW9NyWmdS33Oj+UOKNmJqeqVwzTk47sM
         O49NxKtt0sWRLO8ZEpl94TAcHLidy6DIN9oqHFL+x4iLN2fExhF9hZNrKkMSFiFoErgX
         kctCQI2+jTADZb5NHnc3iiCpfoQm807b8iFd4OV+gU1rDi9M6KwRLGMvMI+bZoijL0q9
         m5Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Kp+2Q3QLxWnCUmTGCUqJeVTafIKYNKQMJyZMylxx2h8=;
        b=znrhsbWoOuXMs92wRveh+Dbk0e93OY6uqUwyEx4PrSNaCs/57F21fQU6zeEQK0cvF2
         ghqzqstEUqwoBGNf76v6/LcsTwsxepScE+vxatZWsRBTU75Sv9h9wGAuqmGWIDr0JnRD
         tuBqebXQbQKmyrHLMv53sf9KhX0OLICLhT9wySvS87/a77m3fQiOnrHNrOrqfozzR/JK
         W6nLRgMclAY78mCFZIvrlNoqIOPE7vjdg/XveocjCajc4cEm2fiSdbxNfvAXG9AqQcZ4
         57rfIaR/rm7SrV/fbsGnbFN+WuCiCwmZCBMuqp8tDcUf5t8hBHF/TNSlKrRGg/M09uf+
         Nt7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OU7GvARn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id m4si516922wru.6.2022.01.24.10.04.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:04:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v6 16/39] kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
Date: Mon, 24 Jan 2022 19:02:24 +0100
Message-Id: <1daaaafeb148a7ae8285265edc97d7ca07b6a07d.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=OU7GvARn;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1daaaafeb148a7ae8285265edc97d7ca07b6a07d.1643047180.git.andreyknvl%40google.com.
