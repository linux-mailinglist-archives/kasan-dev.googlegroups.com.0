Return-Path: <kasan-dev+bncBAABBXM63GOQMGQETUVYKQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 99CAA65E489
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 05:17:35 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id t15-20020a17090a4e4f00b00225a7107898sf393810pjl.9
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 20:17:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672892254; cv=pass;
        d=google.com; s=arc-20160816;
        b=RJMvFjCtMbqDRDGKuwnsrG4syL7zGyoxy30/JvomcTQh8274F3z0EH3Vu6B7Zf5Iyz
         M7WdPVU7jTkt9bE86QOUiOWj7L5aGaZs2wb8Sur+w5suwpWnbYymEDJ8OEWPejt2Ieik
         Zu3ALWjcxrzCuZrW9aPG5gesesrYoh/ovLdGDFpbsAaQofDeWrAtG6k3HUw69ZyFP58x
         bVHsAMrqEXT1FAgbyf2l2MmR11cBbyVL0/hRsMOaUMSHMcG4wA8wjBH0AZOGslXeLdvr
         sJ5rGWriKLXHn2J51BWSlpAJXkAFmds6oQmBT8A5w0XsQwYmMtxH4rjkqBG+8WBIu/wX
         cuJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=Iib/4DNFAhh8qQVbAz83Nr2AE8mSvKL51nAKl9Fae3A=;
        b=zS4EXZH44YxaXHU27ZkGxuiFnEwN7FyvZ9rXmflC+jg+ZMwlfRposRbFXBMuO/BtQy
         SK3LbQrC7+5qA+pLG0Ov6VRCDfdQAgOH/kOgNvEaoxkzcYCfXDcTRVWCshILBNwDngQ8
         4/2PURQCynULkO7lhTCmJ6zUePy3edSM8zRutvS3WIg3W5KyMSEsN9+AIuI/zNo5cavA
         5C5z69D/WJm8TJJMDWDrmyLEB4NYsZySPUOlVlR5YeOfS3RytV/eU7aypBVgFWTi4nO7
         1ck9LFAzkPkr5ERP/6VJosjxiosS7D/qaWbBtEtjI4HM2sqFG1lhOQCg/SOdt3dygS7a
         /WpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=zp2ap7btoiiow65hultmctjebh3tse7g header.b=AiYjSxo4;
       dkim=pass header.i=@amazonses.com header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw header.b=b9UFfezr;
       spf=pass (google.com: domain of 010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@ses-us-east-1.bounces.aaront.org designates 54.240.48.117 as permitted sender) smtp.mailfrom=010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@ses-us-east-1.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Iib/4DNFAhh8qQVbAz83Nr2AE8mSvKL51nAKl9Fae3A=;
        b=kB71pAfaAKvh5hvqW5N0A7cqzHRmMA4gFhwI0ff15093AXBJB4hH+i0enP+hm0hfvB
         dBsnrxT5drclblQfTcHWfeq3IfQJVB/TT1ZxHm5iIeBgV+ScIiNfFnyfz7GvMn7s5e1n
         s+ZucjPDrfdySjTsZ+h71cAIeGr7LDG2hfotxI08LmqUs8HY9IQUa69hryU/Co+j55gd
         WZprkijoc0h9i61pyuZ5kj9RMSrEloyT/IKKCqc9YH+ImnVv/IcGWm5C0IAPNb8k7P/H
         BZKF8GZ8f/bhy780d0o/buzrHPZvFamnyQoWTXikoWlsnMhQGEQATJ3WRAKI6JkoF/nY
         lE6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Iib/4DNFAhh8qQVbAz83Nr2AE8mSvKL51nAKl9Fae3A=;
        b=i7Nx4LMbt6K6ndoHKa+SM3WxvPHTctUBq56P3N6kmcjTRyxsZXNsJCtA0Rvamy573P
         62ekRZs5mo+Ue26CZ5gTe6yDOlS0zN7jwhEnoSQ1Ms8RcTYtYoYb0EBVIZOKgBhO6rK8
         FYRlmc4aZwI0ErKoL2Lt6lro4Cd0uYMkHuWM15W/n32zStcVVAxHTpXdWgmWqe2f6wZM
         Ai1Ahb7WHYhHzy5itkXAdMLxhyj1G5LRXIjigTen8OF9NGh+9vCRTaiMJ2ytsvsUpnDP
         Fyporar6xq0gOo9Flu/DyXOAP8NkIRxyEjaDVVcibq2WdYpjW+9/jxd+BZ++gnQjwkJT
         pbCQ==
X-Gm-Message-State: AFqh2kpcMx2MuFdWaoiQhd6MkbsfKTDTtbJA0OZBw2MKFbRBLWv0lM5r
	PPBQzxZ+GnhtYI9persNzmU=
X-Google-Smtp-Source: AMrXdXuCLHc5wNfEOv6/LgLriJ/3CTJHeC7OK5h/tSeEoVfa0MHsmz9eCjBbLl/Bu+QSZqq1as6Ceg==
X-Received: by 2002:a05:6a00:bdb:b0:582:b099:8431 with SMTP id x27-20020a056a000bdb00b00582b0998431mr712469pfu.49.1672892253743;
        Wed, 04 Jan 2023 20:17:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f394:b0:192:62df:a3e7 with SMTP id
 f20-20020a170902f39400b0019262dfa3e7ls31973472ple.9.-pod-prod-gmail; Wed, 04
 Jan 2023 20:17:33 -0800 (PST)
X-Received: by 2002:a17:90a:ee86:b0:226:b627:6779 with SMTP id i6-20020a17090aee8600b00226b6276779mr4735439pjz.5.1672892253175;
        Wed, 04 Jan 2023 20:17:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672892253; cv=none;
        d=google.com; s=arc-20160816;
        b=MsgmVGNWPc+ptwS7BJ7gdGxDQDx/AoG9MMpxbG3Z0bei729p1aAZmhJ9Eod5pm3wHz
         ovEyEuFCYurv7nYOzZi2rkdOqfz6h8KqkK6kRvVLNCQpVla0Ly8jj4VaowIFt9HJR91u
         YuuL8P/KAEmI168rSSpj+GH+SOfNugyj2HACHVdJzNwSVwwDgOFQUkMLcgWnyXEsku1j
         0hK4Toiz5iPLlUKV6k/pLmUSIe0q9Jre/PrIK9fIMBynm/mlgQ1e4kkLfJQcZQWojBcp
         L9smRLCJXVHczdw9VhwfLgL3Zn+7DGy1LLS8/uAE1fqYyHnSAuPax9uB2Bb52UdIXMCv
         hRdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=yakfCQe+8Ykoijus7tecq8mv0JnqLNzwgKukFStPbcw=;
        b=g0u7/FAMnfRCGHS/i2SgvJ147WJtLYGoDWyICwYNj/AqclU0qOJMUTBVgqGXHnFYlf
         Z6WBm+psFqu92rEIzHaX2XGjhrc9pyUt01kEbb4mauBd0K8ypXuVjn+cDpugeY58Vrwc
         2Wued9mQf5FnyW4LuUfdNqKMayHz6zwGQnsAW4Bj87ZRthKWogaX8WJqJ5FESjxDNVtO
         IMdCNXCj9RO2+eR6DQtFyMm+HrnIZaC35i+Yw1MukE//Uyhii5hKY/v1oHhYruU7JFm6
         AmL9JhjiJmNv+Mf8LMzPAmb11cMQqItoPLTydlM0Rkm/Xl1jmXElxHhDPJxsKFt/x5ED
         ICKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=zp2ap7btoiiow65hultmctjebh3tse7g header.b=AiYjSxo4;
       dkim=pass header.i=@amazonses.com header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw header.b=b9UFfezr;
       spf=pass (google.com: domain of 010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@ses-us-east-1.bounces.aaront.org designates 54.240.48.117 as permitted sender) smtp.mailfrom=010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@ses-us-east-1.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
Received: from a48-117.smtp-out.amazonses.com (a48-117.smtp-out.amazonses.com. [54.240.48.117])
        by gmr-mx.google.com with ESMTPS id kx17-20020a17090b229100b00225c983fb3dsi52398pjb.0.2023.01.04.20.17.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Jan 2023 20:17:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@ses-us-east-1.bounces.aaront.org designates 54.240.48.117 as permitted sender) client-ip=54.240.48.117;
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
Subject: [PATCH v2 1/1] mm: Always release pages to the buddy allocator in memblock_free_late().
Date: Thu, 5 Jan 2023 04:17:31 +0000
Message-ID: <010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@email.amazonses.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20230105041650.1485-1-dev@aaront.org>
References: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
 <20230105041650.1485-1-dev@aaront.org>
MIME-Version: 1.0
Feedback-ID: 1.us-east-1.8/56jQl+KfkRukJqWjlnf+MtEL0x/NchId1fC0q616g=:AmazonSES
X-SES-Outgoing: 2023.01.05-54.240.48.117
X-Original-Sender: dev@aaront.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@aaront.org header.s=zp2ap7btoiiow65hultmctjebh3tse7g
 header.b=AiYjSxo4;       dkim=pass header.i=@amazonses.com
 header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw header.b=b9UFfezr;       spf=pass
 (google.com: domain of 010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@ses-us-east-1.bounces.aaront.org
 designates 54.240.48.117 as permitted sender) smtp.mailfrom=010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@ses-us-east-1.bounces.aaront.org;
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
respectively). If any of those ranges happen to fall within the deferred
init range, the pages will not be released and that memory will be
unavailable.

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
          managed  222816

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000%40email.amazonses.com.
