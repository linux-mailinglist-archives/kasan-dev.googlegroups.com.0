Return-Path: <kasan-dev+bncBAABBKO42SOQMGQEVNQGUAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 06D5465CDC6
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 08:43:39 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id f11-20020a0cf7cb000000b005319ce47af9sf8928275qvo.15
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jan 2023 23:43:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672818218; cv=pass;
        d=google.com; s=arc-20160816;
        b=QY8Pa186BtiuuFv0o7rpZwsN7b/cY3PfQXserBSWKRDaDGkBglJ9QG3j204HBfE3qC
         JhGiVqXGfszdn/4Tv5WenRuDsuQrG5rmG95H+evpibei+qkimGyX7tJI0pFKpzeB8dnm
         1dtO+eYGWSPNoGLAGd8pWCGRxoM+7mXaqesYOsShHWDK5BingUuMkfJyB9PuTZ5+Eh+4
         1H9B2Gn6B4BQgTow4FK/zce8/IlDtT4uzFK7fUwiDWSfN2mJqFwGv6Ma9aK2S5kf+G3d
         +Fxs2W4WPo1ypqKdwpUdF8QWhkDAIhl4ejNa+maAETQKqJz2vZtcJVD7VtmJcJoxzeSb
         d7LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=niZoxa2nbGbhcNdo8ZFGuHiWVPvtpDs1zH7WPfQms7o=;
        b=Fdq9MjAZnBkzS0EavSlGcOSlzXEkDdAG9ttJo5aePs5SNo3PZEnJy08myS1K62Didv
         Y4G67qLviF5bcjsZJ7XvE1u4tYTPJ0VcpOaaQXHx4fb8cia6YtJkcXrXpvxfBFMQuSnL
         sKc1TQVXcAhh/DUwR8WZ0hnRoZyJuMCXOXHEaja4qp1sUTi8zeFI9NDMfMlerXED0n8w
         7y/2ssynXR6SGS9/4CqsnrKOzsUg2tHjUY7CwmzglzJsSpFYdfpS2KlKex47hakK3RX4
         vpl0QLo+g2TWAV9qm81yc504ThnRfYZjYUHOqDQmX9c5ZFtHjcRjpvkQOIgjhmqcuX8/
         nMmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=UE067h7L;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=MPGVIN0A;
       spf=pass (google.com: domain of 010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.19 as permitted sender) smtp.mailfrom=010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=niZoxa2nbGbhcNdo8ZFGuHiWVPvtpDs1zH7WPfQms7o=;
        b=DbF0UJrF78acLrdxSs5ELyaYN62dc6zEZD9QEnGgiMwHFVXzu1wRpjK0t24pH8703S
         K6K5WN8oj2W3ffup2aGm/4iz2EFOM2e+2QxXWt7lXDW/zEqkhiPZGSK9jPpWLzcMl0oN
         SjQlt/An3jX3N1arKsm6sBxxsurb61tZcFzt8xDjcZN1LCWSfckNxB20+59BgRbnOW7s
         cWfEn/LIUPqLlZrk0Mw/e997nCAqKI0mL/LUCeEsFsFlXUXuVA2a3Prci39vWxoUC4Ci
         JjAWxkShLCTiDK55ZuwNE3yrIFy4ztrUrJxgtyOm/tGiM8wnwl0CvSkbsAmmMGEqSDbs
         0UBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=niZoxa2nbGbhcNdo8ZFGuHiWVPvtpDs1zH7WPfQms7o=;
        b=MI9vBOaUUl7RhQC/8noDRVUYnGFIX2LtnJIZUUKlWgMioXxp1mi+529uyMuRsd/zG4
         YQh8ULsyZcAav6mBJDBRB5Xqa++NQny2UavvQJ4AEgIF0nNee+s9j4AQ9Ci15eEZcjzX
         8yTYPQNz73XTJe61qykJqOkgbAqrs5yj7yEPt+m3xcT8sUgxhD6ZE94MLv6YlrSPNXGE
         IwdyzeoqoTWooboIvVWLvk4dheJpSk4HHlGRfSZysnouqdiEH7o63NpZ3JE7Wl6SQul+
         Hd30NNEN+OrfTd0F4xjy4cRUqy+Qd7VESg7cK4qcOaIaLg8Zdpwr5qbFqXjdcQXGHQmj
         18Ew==
X-Gm-Message-State: AFqh2koyGZFe3gGUfe9VsXJNA59uLteaoNnJTephfmFstEu6DmqYOte4
	/FiFliKMWxeVxz1Px+l/7GE=
X-Google-Smtp-Source: AMrXdXtpqHRdqdC40jLZN0EWRXTKDYgNsaMDzBpmkFJCui6udWSM6x9f6/p7TSni3AQe7LwR0NV1kQ==
X-Received: by 2002:a0c:ef11:0:b0:532:ae7:697c with SMTP id t17-20020a0cef11000000b005320ae7697cmr27812qvr.87.1672818218012;
        Tue, 03 Jan 2023 23:43:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2445:b0:35d:5bc0:6460 with SMTP id
 bl5-20020a05622a244500b0035d5bc06460ls23922820qtb.1.-pod-prod-gmail; Tue, 03
 Jan 2023 23:43:37 -0800 (PST)
X-Received: by 2002:ac8:480b:0:b0:3a5:361f:9819 with SMTP id g11-20020ac8480b000000b003a5361f9819mr67979395qtq.18.1672818217641;
        Tue, 03 Jan 2023 23:43:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672818217; cv=none;
        d=google.com; s=arc-20160816;
        b=ORQoZSdGW+aCFnprCcwuBcbreWdvOazj6Jk6ZmuoYPuquM/ssrw9TOYBJfGpLuaA9Q
         T9tXl2nuX/+EX1CiIOGWmCoF/w8IBJNbCiUV7x/8se8OnCK6iW92HSu4U+RiI1pZUdfs
         GobxwOdgrUfdUwEsnec8wGDPQdgmSSwxvbgvNsqRHV8tbPbilUP+MsJalYxLHJ4vMJak
         3NwLEXvtq81uWkVOS032oSI3Jk0KFpMR4JAxEqNvGqfYwjCej3CGzTetWarinXbgObaw
         oGD62ofqfcROfaG86jMpf+7rn9mWqWPs6NrYf3DpnHKixXkIJHzVKJYDEwrDkbFAndPM
         uRjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=nm7ZBamrjIPVpTrWsj0mVH/CoTNVR1jvbpOznxgOoCQ=;
        b=ZfmM9lTLrWPN8S68WXjh1KiH0BlGAxBXEPYnSMxFsmmaL9U/Dc8fl5xCrppnmQdcMx
         hp2d3VHD89udg78VaAud8bcrjbgjFKv3AwFq7Q4rdF7lbr35z9MDSPGaSra17CHKrQ+h
         MCLxTE6QtrDue86ieGNYeBqpa1dv72+snBrvv7Md72LlzfA68/rB/W/m5ZRNBqg3kUHf
         It7XOwjx1LACaV6KIH+ccrni2qnUYOBiD2QfLBoXqJz25DFgSzfVksm/E1K4bBc8+Upx
         egGimxVO02I4xaTU1Klns9d7vR+hK/fPdJODNDZ0YD5Em2SWBSOYwivj9T3Hr5FCGTsu
         0q5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=UE067h7L;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=MPGVIN0A;
       spf=pass (google.com: domain of 010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.19 as permitted sender) smtp.mailfrom=010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
Received: from a27-19.smtp-out.us-west-2.amazonses.com (a27-19.smtp-out.us-west-2.amazonses.com. [54.240.27.19])
        by gmr-mx.google.com with ESMTPS id i11-20020a05620a144b00b006fe3de3ed80si1949247qkl.4.2023.01.03.23.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Jan 2023 23:43:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.19 as permitted sender) client-ip=54.240.27.19;
From: "'Aaron Thompson' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org,
	Mike Rapoport <rppt@kernel.org>
Cc: "H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andy@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	Darren Hart <dvhart@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
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
Subject: [PATCH 1/1] mm: Always release pages to the buddy allocator in memblock_free_late().
Date: Wed, 4 Jan 2023 07:43:36 +0000
Message-ID: <010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@us-west-2.amazonses.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20230104074215.2621-1-dev@aaront.org>
References: <20230104074215.2621-1-dev@aaront.org>
MIME-Version: 1.0
Feedback-ID: 1.us-west-2.OwdjDcIoZWY+bZWuVZYzryiuW455iyNkDEZFeL97Dng=:AmazonSES
X-SES-Outgoing: 2023.01.04-54.240.27.19
X-Original-Sender: dev@aaront.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h
 header.b=UE067h7L;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=MPGVIN0A;       spf=pass
 (google.com: domain of 010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@ses-us-west-2.bounces.aaront.org
 designates 54.240.27.19 as permitted sender) smtp.mailfrom=010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@ses-us-west-2.bounces.aaront.org;
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
run. memblock_free_all() initializes all pages in reserved ranges, and
accordingly, those pages are not touched by the deferred init
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

Fixes: 3a80a7fa7989 ("mm: meminit: initialise a subset of struct pages if CONFIG_DEFERRED_STRUCT_PAGE_INIT is set")
Signed-off-by: Aaron Thompson <dev@aaront.org>
---
 mm/memblock.c                     | 2 +-
 tools/testing/memblock/internal.h | 4 ++++
 2 files changed, 5 insertions(+), 1 deletion(-)

diff --git a/mm/memblock.c b/mm/memblock.c
index 511d4783dcf1..56a5b6086c50 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1640,7 +1640,7 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
 	end = PFN_DOWN(base + size);
 
 	for (; cursor < end; cursor++) {
-		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000%40us-west-2.amazonses.com.
