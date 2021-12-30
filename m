Return-Path: <kasan-dev+bncBAABBMEJXCHAMGQE6GB62SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CBEC481F78
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:12:49 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id d6-20020adfa346000000b001a262748c6fsf6497393wrb.12
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:12:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891569; cv=pass;
        d=google.com; s=arc-20160816;
        b=eYZC9dRlo+pQ7NJsDBW4G83s11K8STVazF4RPNOQLXC+llAQP+ZG0HlYUfNAXItX6b
         rCjtm8rHAXgpo3bxyEiVW1GCCbY0/EsF6WDTvHXSK77CiEcyC2P3bQ+KTRLYkYCjvI7c
         +ED9mcwMf7CR6fOzIKSNDX8AQpQGIid3PqvwnK0QlUYHoa91VX4GBGH4Qnprpakpqc3F
         09qYz/YT7YkeeUj+owQfiCtYHT/75ragr/9L942aOzUMqxtmSmICKWd+RPDbyDwld/VF
         2g/ATDhVuVUSjwi+dEE7D8P9poD+bPPCasGIHnC4lbSv53zSoVWKi2X4NWmaRnLfcdLG
         GYzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BITN27BC2EzEMLS9PGwo9K0C2FLaZTLDnOkVA+W/y/Q=;
        b=YhQwX14lDVs3SiKqiNCL5jCvQg61XDMQDRfrbfisQcijT+3ZWXWH8QcflkoxR0mT4I
         12YEkGCuY/M2ZdZIsHEiiXZmlOD/OrzGnhpyH6NwxXHFy+uSG6jL1FzyEw/TvMIxCqwl
         kM9He/l+qcY2SstQ59cmfvu+LO7uru4+/QkCRzL6Ls/CRZMjKxhc66hXzLwkh66duXbs
         M9B1D2M/Ev08ILSYslsjpJ4KfG0zcchwLCW2I0R+26iTT+cHM9p5sX8qEOwjtNbAGpGC
         MlIssUavlswxCr/1c0o9XQybHl4oxyTGj6bjYP9iwqDwpmSec8Ytu/2n3NGS5ZBtP/Ij
         8hVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F2kuBLZ2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BITN27BC2EzEMLS9PGwo9K0C2FLaZTLDnOkVA+W/y/Q=;
        b=Tt8kpf5vcKr2YIrDxQ3bZtNN/Fxa0l3NWpXWX3/i3RfDkKYANiGghmPOvI7aXVPE8e
         +Tpf3uU37gKuz0SecHosXmjkUzh6kBQhKXot3U3ByGVZv6PeL6/61Bll8eMO6thKk6Ex
         LcCnYhfMrMLxrmSgpMffEj+Bt+JSiDWuO+5//HZHmJqhPPwrMVngmRSlDqU0qo5hkM6C
         4RL4jwOfiPqVLJv/w0ifRez4MxG26NwCqHPtuXL+Iei2N2KmSZ4nxU3i7YWwgbsqP93x
         D4vOEo8ZihpM2OLtu4HfEMjU2Fjg/kttamRRDBkIGHO+Kb882tMt+lDu/op6WGQHt+68
         Au5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BITN27BC2EzEMLS9PGwo9K0C2FLaZTLDnOkVA+W/y/Q=;
        b=ktp3i5vViw/KC1oXLBzCxtL3m8yrVUQlaebj+eU6jf7aG7m/ZWdZpn1A1mSxSOOGnD
         GbS6kV52wddcBraS23ThrXue8wD8Kk4sphQLSfjP98A332pQwttV8Xa9z8sV29xg3lbI
         EeJYEXG1X9WedecSoUy8HJC8+UDLbGprP+sX9L9UhBMCp38kgn9WqRv/fBCqV29YzQFh
         lWQkwOZFMTYl6QqGcwsQkZ/AGzgN50v/4g3iShuLyVoYYh1aOMMZhNGejMalkjXdnMt/
         vR3CrFjdkR2eWQigMr/XuJBC27bboErAsVtUdm1iscnuBAzecRssuKliW4L7rZCtSvsZ
         uOuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532g5UMRewNi/8H1gLMcPlBQY482CrEC1JtXz1ttTytlCySviZFm
	j4uEl02QLcvA/0qpTbfb5ec=
X-Google-Smtp-Source: ABdhPJxjQpsBaLWRmglaJVH6KlHhYbMyzocZDv+Ac+dHnbYzt+f7xFOqmJarVfHjy1jftJB5nyFe7g==
X-Received: by 2002:adf:cd07:: with SMTP id w7mr26384293wrm.137.1640891569033;
        Thu, 30 Dec 2021 11:12:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5082:: with SMTP id a2ls297937wrt.1.gmail; Thu, 30 Dec
 2021 11:12:48 -0800 (PST)
X-Received: by 2002:a05:6000:144d:: with SMTP id v13mr27120818wrx.393.1640891568343;
        Thu, 30 Dec 2021 11:12:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891568; cv=none;
        d=google.com; s=arc-20160816;
        b=D9NTrZ7mHsBiFNqpIVf/Vb1GC9mxMudHhVXtXkBtF20+kIDLYYlwiju4KrXipNCpjk
         CMDwFyQM23Z32BUYl7s8W11aD3uYsQjsp6ms7omx9NGFPRy5zcrPNIAcTVAOTre4B341
         Kn1V2Ewf6+tKVs5ofS1Vvp6eSgjaniG16w696JW9XY9rsxKGxDFLvoXHRmDIzDBYrDJB
         +E4TwO2nWcVkT45RdXNgV7hG6trB0nQ0qquOZoYh21hPCCbrzngn9OAgdcv+efzBpHxf
         zMw5h+zmFx1Y4Eg24CHuanU2t2o5WF09zMejyNv7IQaniYLEpZqhOYXTHbeczkd1jG36
         c/zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UPKTOfGemEkoQbDp819rZg49kcfBuqLexV6afOkLkJE=;
        b=HV2bN0jHtqX6k21aLieLbLs1MpuHizkk51AcPxlD5Yh8GsuUPJx6jbWPx2iPqSY7t+
         IJxXSlgvDs1cMEKoHkwyn1OdKdkP2CcbN1QRvX7OzfENYAE0EqUElmDCXE2gOxm6hd0s
         cIUoe3HoHFad1vnE78MKFuSxWQrQKWp1THC3L16AFRzn7aqaZt4uaMGPgmPsirRbPKUk
         Hb6SmSSQyCSYIgP6KkqJ9JdLk3G0IFALJJ6kOR9VVA8fCcyoUaRfBA3TIFE1TqXAtAqR
         a+gFo5yM/LDjm7iAe43qrGC6NSCvRxZnGu0X7PiOPuzN410L6pnCNRPiOQFCee5jb+Ia
         PscQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F2kuBLZ2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id e3si560856wrv.5.2021.12.30.11.12.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:12:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v5 02/39] kasan, page_alloc: move tag_clear_highpage out of kernel_init_free_pages
Date: Thu, 30 Dec 2021 20:12:04 +0100
Message-Id: <3d8f0ec4b71fd639db321781e0862584978162b6.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=F2kuBLZ2;       spf=pass
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

Currently, kernel_init_free_pages() serves two purposes: it either only
zeroes memory or zeroes both memory and memory tags via a different
code path. As this function has only two callers, each using only one
code path, this behaviour is confusing.

Pull the code that zeroes both memory and tags out of
kernel_init_free_pages().

As a result of this change, the code in free_pages_prepare() starts to
look complicated, but this is improved in the few following patches.
Those improvements are not integrated into this patch to make diffs
easier to read.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 24 +++++++++++++-----------
 1 file changed, 13 insertions(+), 11 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 8ecc715a3614..106c427ff8b8 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1282,16 +1282,10 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 	       PageSkipKASanPoison(page);
 }
 
-static void kernel_init_free_pages(struct page *page, int numpages, bool zero_tags)
+static void kernel_init_free_pages(struct page *page, int numpages)
 {
 	int i;
 
-	if (zero_tags) {
-		for (i = 0; i < numpages; i++)
-			tag_clear_highpage(page + i);
-		return;
-	}
-
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
 	for (i = 0; i < numpages; i++) {
@@ -1387,7 +1381,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 		bool init = want_init_on_free();
 
 		if (init)
-			kernel_init_free_pages(page, 1 << order, false);
+			kernel_init_free_pages(page, 1 << order);
 		if (!skip_kasan_poison)
 			kasan_poison_pages(page, order, init);
 	}
@@ -2430,9 +2424,17 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
 
 		kasan_unpoison_pages(page, order, init);
-		if (init)
-			kernel_init_free_pages(page, 1 << order,
-					       gfp_flags & __GFP_ZEROTAGS);
+
+		if (init) {
+			if (gfp_flags & __GFP_ZEROTAGS) {
+				int i;
+
+				for (i = 0; i < 1 << order; i++)
+					tag_clear_highpage(page + i);
+			} else {
+				kernel_init_free_pages(page, 1 << order);
+			}
+		}
 	}
 
 	set_page_owner(page, order, gfp_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3d8f0ec4b71fd639db321781e0862584978162b6.1640891329.git.andreyknvl%40google.com.
