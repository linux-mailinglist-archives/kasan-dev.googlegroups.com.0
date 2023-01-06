Return-Path: <kasan-dev+bncBAABBNN64KOQMGQEEXV5VKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id CA5B6660971
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 23:22:47 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d2-20020a170902cec200b001899479b1d8sf2029664plg.22
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Jan 2023 14:22:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673043766; cv=pass;
        d=google.com; s=arc-20160816;
        b=JerkUzd7nYJasQEPd85njPlTy0DLOJI3jCFGl2HywF1PU+unYvx2SCtsQtLDpJODRe
         Thl26vDy9x+8OWr4nq6dzqBlomseqdxjfq30u9+o/irPTdqlSVkoHZ6cOENQajvB9FuG
         8PlpXreDcgGzDXWr2zkDSKINiIshS1i1zJHW2u+zVWwZxiDQryCYRSSK9Krbvc7eBce1
         1yhp3GfL3mtFLISuzjJRH1poqczNO9J0hn26ysnkoWPFsfqfj2NY5MXDFOiHuTK5TA36
         EI08ONjvTyZQGVV26uR00Pglw+NrT/p9zjYYVnsDurtBEnZMj0bD2gvDcOG8/COcRNTd
         LmgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=dqAlFRIvveZ9tOGQqWEI5joyLqLjD8HYzUgNjUDHylw=;
        b=Ljx5nrdU+IWU7c8r3Ehdi8lLcCUiz9blEorXB01/zFA0lrPrjDIEzHfE5pCuxqUak1
         ifgHjdIPquLE3O5VHYb+V7RbFja9qRk6nae19sDtGAl5IzM73fOCgMfoKWljLC3wXp+V
         2SnvmJZn2tHlAX+TR6hmAGN7SlOy1NODuaLXYN4+7Z+6awAWWLzrsIPBdQZAxKXBEJ4X
         ULnuUSeN9WA8YyXINNYoV60Rs7lhiUcun7VekVo+QU61x5vS30LfYlpUx7ajIINoY/j4
         RPV9b9BCQVwCGJT59Rut/WlQD9ZQPTh4s0pLW6UFt2cjOeINAqiiGFjkXkgL3jSggqWg
         oBTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=OYQCLSIc;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=ASqI4DHB;
       spf=pass (google.com: domain of 01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.51 as permitted sender) smtp.mailfrom=01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=dqAlFRIvveZ9tOGQqWEI5joyLqLjD8HYzUgNjUDHylw=;
        b=a38aPJpAxZ8ppByYJVr8ocFXIvYuACj+j0atkyZUoot3GgQfpfdjtcYF0kZC8kP78+
         7WDddJNRKzTmOUwp+SaOeXCuhFj01z4qWNDHKNAHELiich8rowFZQ6XkrecQNE9QIT6A
         eXR8Zfi7BJEX69jAnMZJ2XSvTX/s8WvQ3I+yB7UYCOpB4B3qAvfWFCva8onIXkywTv5z
         dh+LKto84Gd8LmDeRKRkfqKS1ErrsBIrFEcCAKma2F2ZlS+KVKq3jyTX8h2Xm62wfQVr
         dF2q/Xa5xDp41gNjN7IrPE2wUH7hR9EeBrz4r066AEkCb9SwcQzTOJ5VqDrK/JeWintI
         fxDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dqAlFRIvveZ9tOGQqWEI5joyLqLjD8HYzUgNjUDHylw=;
        b=vrvRyzqn75FXBraDcM93pygopTQcMxln1wjvlIogknFaEZJNdTSlFhbemeLxWiH0YG
         pTk0w062mKaVenBh/TT2IVgAj1aWBh/8SOYwjsKr1GrtasL4G0NAD2SR9YnYENnlCEMA
         c27w4njHkXNX2EIzYa49cfi3xTVe2DxpMpwnx2K38Pcz5NG/b/CZOepVw2IE18Gf9S8U
         6EPhzae9vhyALaNjlmT8H5lPoIFABB7U9aa5XXBR9MBclR+JMcvnrqiNNaFT8S/o/ftH
         Xlrve9XUcce/fxpUAX8fYBTyF5/hKRUlTa5UhQhnbcXWtl87zUAx0/q7YAtUgAezj1ra
         QWwg==
X-Gm-Message-State: AFqh2krzzl0SoVnjvONa5iZJZ0kHWiQ4Rsmv68LjhgDrtFFeiTGUH3oj
	heJIvyFE185EM6fdm4QNEB4=
X-Google-Smtp-Source: AMrXdXtoGZ2j/JZ5+wCURg0c7rsRDi+rO4McwKFF8rmO4oq4U+kTJapPWQp7t7cbpyMbj+WZ6Y56yQ==
X-Received: by 2002:a17:902:cecb:b0:190:f88e:255 with SMTP id d11-20020a170902cecb00b00190f88e0255mr4362129plg.114.1673043766022;
        Fri, 06 Jan 2023 14:22:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a13:b0:1fa:bc38:b125 with SMTP id
 w19-20020a17090a8a1300b001fabc38b125ls3650330pjn.1.-pod-preprod-gmail; Fri,
 06 Jan 2023 14:22:45 -0800 (PST)
X-Received: by 2002:a17:90b:4a8c:b0:225:a8f2:fa38 with SMTP id lp12-20020a17090b4a8c00b00225a8f2fa38mr55760757pjb.21.1673043765435;
        Fri, 06 Jan 2023 14:22:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673043765; cv=none;
        d=google.com; s=arc-20160816;
        b=ji3UG3umg1392TfyewPE3DxuZgiTJdWtL/u9yehWrgRMOGBxtDwnb/qsu4lfA0y0lY
         52Acb27ygAe/1fLgf88vN92guk6iLgCliLyj+244Lvwpx5YchZRG0ptut94j7PLHmyK4
         643ScW+b3oX/xYQT3oEt6Lg6J5ypfOGqU1dh8jejUfP0kCmwBcmO4F0HQqN8CxWjJPNQ
         LCyI0e+Xi5bqVDq8d4s15GtHZX4O6P0X2ZJanLZZrAiJQ+rO1VQ8EpU/aHUe1nYYF5G9
         DaZr8O3wzPh8lBSrf3/ISa72HQ1zyh0jbcAJz0fSB+C2LuZMASiQ8mLkbXuyTsH3wpRs
         ff+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=Uhia4t3YP+RwBA+Ks0Blx3+ryYIr65e+4gAG6zciDF8=;
        b=hGouqXsx9D8OKEnlDeg9mr1FBYhJY0FcTw8hBrTqlxXCTMGKyG+fdhrVlScVtx1XMk
         PgH9fy0iVn7bCTwyJPO8535Y1ZMbW4Y4PP7uPPypr4kFgvwY1NWjQqhlUQADb5GNPcNg
         XcSBqq0gHHO4kY8e725ym15XCFkkv/joG4+j/RS6DE8jcWA8+zg+rGPzt/Eledwqgn5O
         BEuKyPqpakEmcZZ0hoKI7VHro/lz0O+CsclQQNwwjIfTKRWc8BYWcJbmfB9dZLWNQnIS
         R0Mixj2kpdQcqASiFSgbCxpaeGlLgK9yk4zWqUMadqa717YKGrqCZ6fBcGnDgumn49G6
         UImw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=OYQCLSIc;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=ASqI4DHB;
       spf=pass (google.com: domain of 01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.51 as permitted sender) smtp.mailfrom=01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
Received: from a27-51.smtp-out.us-west-2.amazonses.com (a27-51.smtp-out.us-west-2.amazonses.com. [54.240.27.51])
        by gmr-mx.google.com with ESMTPS id t23-20020a17090ae51700b0022673858f16si525299pjy.1.2023.01.06.14.22.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Jan 2023 14:22:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.51 as permitted sender) client-ip=54.240.27.51;
From: "'Aaron Thompson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mike Rapoport <rppt@kernel.org>,
	linux-mm@kvack.org
Cc: "H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andy@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	Darren Hart <dvhart@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	platform-driver-x86@vger.kernel.org,
	x86@kernel.org,
	Aaron Thompson <dev@aaront.org>
Subject: [PATCH v3 1/1] mm: Always release pages to the buddy allocator in memblock_free_late().
Date: Fri, 6 Jan 2023 22:22:44 +0000
Message-ID: <01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@us-west-2.amazonses.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20230106222222.1024-1-dev@aaront.org>
References: <20230106222222.1024-1-dev@aaront.org>
MIME-Version: 1.0
Feedback-ID: 1.us-west-2.OwdjDcIoZWY+bZWuVZYzryiuW455iyNkDEZFeL97Dng=:AmazonSES
X-SES-Outgoing: 2023.01.06-54.240.27.51
X-Original-Sender: dev@aaront.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h
 header.b=OYQCLSIc;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=ASqI4DHB;       spf=pass
 (google.com: domain of 01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@ses-us-west-2.bounces.aaront.org
 designates 54.240.27.51 as permitted sender) smtp.mailfrom=01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
X-Original-From: Aaron Thompson <dev@aaront.org>
Reply-To: Aaron Thompson <dev@aaront.org>
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

If CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, memblock_free_pages()
only releases pages to the buddy allocator if they are not in the
deferred range. This is correct for free pages (as defined by
for_each_free_mem_pfn_range_in_zone()) because free pages in the
deferred range will be initialized and released as part of the deferred
init process. memblock_free_pages() is called by memblock_free_late(),
which is used to free reserved ranges after memblock_free_all() has
run. All pages in reserved ranges have been initialized at that point,
and accordingly, those pages are not touched by the deferred init
process. This means that currently, if the pages that
memblock_free_late() intends to release are in the deferred range, they
will never be released to the buddy allocator. They will forever be
reserved.

In addition, memblock_free_pages() calls kmsan_memblock_free_pages(),
which is also correct for free pages but is not correct for reserved
pages. KMSAN metadata for reserved pages is initialized by
kmsan_init_shadow(), which runs shortly before memblock_free_all().

For both of these reasons, memblock_free_pages() should only be called
for free pages, and memblock_free_late() should call __free_pages_core()
directly instead.

One case where this issue can occur in the wild is EFI boot on
x86_64. The x86 EFI code reserves all EFI boot services memory ranges
via memblock_reserve() and frees them later via memblock_free_late()
(efi_reserve_boot_services() and efi_free_boot_services(),
respectively). If any of those ranges happens to fall within the
deferred init range, the pages will not be released and that memory will
be unavailable.

For example, on an Amazon EC2 t3.micro VM (1 GB) booting via EFI:

v6.2-rc2:
  # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
  Node 0, zone      DMA
          spanned  4095
          present  3999
          managed  3840
  Node 0, zone    DMA32
          spanned  246652
          present  245868
          managed  178867

v6.2-rc2 + patch:
  # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
  Node 0, zone      DMA
          spanned  4095
          present  3999
          managed  3840
  Node 0, zone    DMA32
          spanned  246652
          present  245868
          managed  222816   # +43,949 pages

Fixes: 3a80a7fa7989 ("mm: meminit: initialise a subset of struct pages if CONFIG_DEFERRED_STRUCT_PAGE_INIT is set")
Signed-off-by: Aaron Thompson <dev@aaront.org>
---
 mm/memblock.c                     | 8 +++++++-
 tools/testing/memblock/internal.h | 4 ++++
 2 files changed, 11 insertions(+), 1 deletion(-)

diff --git a/mm/memblock.c b/mm/memblock.c
index 511d4783dcf1..fc3d8fbd2060 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1640,7 +1640,13 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
 	end = PFN_DOWN(base + size);
 
 	for (; cursor < end; cursor++) {
-		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
+		/*
+		 * Reserved pages are always initialized by the end of
+		 * memblock_free_all() (by memmap_init() and, if deferred
+		 * initialization is enabled, memmap_init_reserved_pages()), so
+		 * these pages can be released directly to the buddy allocator.
+		 */
+		__free_pages_core(pfn_to_page(cursor), 0);
 		totalram_pages_inc();
 	}
 }
diff --git a/tools/testing/memblock/internal.h b/tools/testing/memblock/internal.h
index fdb7f5db7308..85973e55489e 100644
--- a/tools/testing/memblock/internal.h
+++ b/tools/testing/memblock/internal.h
@@ -15,6 +15,10 @@ bool mirrored_kernelcore = false;
 
 struct page {};
 
+void __free_pages_core(struct page *page, unsigned int order)
+{
+}
+
 void memblock_free_pages(struct page *page, unsigned long pfn,
 			 unsigned int order)
 {
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000%40us-west-2.amazonses.com.
