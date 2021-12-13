Return-Path: <kasan-dev+bncBAABBW4B36GQMGQENQIK26Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5486E4736D5
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:32 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id v1-20020aa7cd41000000b003e80973378asf15150306edw.14
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432412; cv=pass;
        d=google.com; s=arc-20160816;
        b=JL5jBaRW8gIfVVcMYecHTYHZvxupAZEdBIVK9sQspJOCeip89VgvlJdHihliICYUQR
         OcLtwXQA2aAAGjgOd2RDbcfMOE4IQ9cD5XzYHoZ7ZPLAbJAUPE6Kf3RutmGC/NB0Wfip
         HakdQnunc1UJ19pvVUT5XEY4M4RJg3gLMpeG5sHnP68zvvA/imMU8GBAZLFu+oYLy8sE
         msHXaBCdcv488GnVDUptRwrAlLOuthkmXwuvVA0hHNUVeKvBV45k43esYysMliZlrT1f
         nXngOnxAepcZMLvnWEivpV5f3mhDWBtFXB3mPXZkfU/GzoXZ9gGsMOzS/q1DGl9drjRb
         GT7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jB31YNdSfMV3wTul6ZgjBqKGMLlfMfc//WPKBI4+XCo=;
        b=clt5QaUkafDXc/Yy/NeywK9ihfq4WMRKaFoTLQ7z5c9IJFHe7bhzWJC9WzmKfQ/sLO
         XczmNGAzOS4fV5f+xQMy5rUT72FOWanM4lI5ZV99n7BvS+RPPypNcqLYLa8n66mKM0AN
         MdsgSNSXfFJcrTI5vpEG9fYX0BeArhR1gStuJ/jKAgewn8KuEc5JfonfL01uYZ0WgM3a
         NCMU534q4QPkVLXVAwbJI+W8y/wf+Dmzzo2Ko5/+aRK2htOZS8kmkiK2I2UWR9/FHenJ
         ubQrr8YlRmD2GMA8cfEMSg/NtD8x5cC9TWYmb7yIZCgCl6soJKZpH0vc/LuI+WVdn4FX
         4qlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=s8HCaE0I;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jB31YNdSfMV3wTul6ZgjBqKGMLlfMfc//WPKBI4+XCo=;
        b=M3dl3oGRYtm9qahMwQnShMB6SpXtg92zv7+g+/BeF3ym+fotaZ+GtJ+Q/8WYU9u+fN
         0qhXpHfy2b1XMsPw4jPKG5gMRL7lQeLEhaIIKC4UYkdKXgK2pQiQzZMMK7fxRS5qJ/43
         dXgE7gWMOcXDwm5LD+9ruPB8g9bHO4aSB0gWWOGtyuH3P6Y6fw6noa1QYRtze8329s+R
         kv/vnt5PQ+4cAX61vKAOr17ehnBKxwCTAHqKz4/wlZ2AS21luR6NaixbEKt4rzN7yLz+
         /OS9GenJDGo3JIwXtBlM+5cundXCX6KuL7eFSbL5DiqSQQaHG6owDFAosMKvsZ742RRg
         l85w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jB31YNdSfMV3wTul6ZgjBqKGMLlfMfc//WPKBI4+XCo=;
        b=MeUuZPESGcr73VGB4VOxUckm2QiDkuY5kP+L5LVjNBd0jXlaFEaa3XTHLk2LT5lofK
         buUi0xy1ppjOQzkSXjvRd1FvpqYgceUucGOmLRD+ZXY5YMP2JdBJVg/DL6Us2b4nf3FU
         xvRBRIoRLwihjF6TrwAJAoZJKirI3FQF4B7AMCeg+08ZR2u4erFWWPrpzYEHBSNq3d7t
         h/H8hoKQMXhLs6bwMRhbxhBbU8wHFgS8IQ6rmMgjc1gSWFIUL7+TkChlxk8NuBVQ/kA/
         Jxq5vGupclRuV8P+/0xDYlh0zbvH9zo/EEKZT6bsjAJ8H8XwiqA4UPsCyxJ2W0Kq9UIY
         1rVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YLU3yhFZn4T6qrAtVTb0LE7TwB1aMCD+43GJmjDxruAy+0+kC
	O9wycQp7hRa6ykDeSO4uJ4Q=
X-Google-Smtp-Source: ABdhPJwtWrQYN53IuA69J6NjTRZ/zaFEihhwZuyBkj4+VasF/Lo4Q2k/I/bVWacS41vgnLmSrljneg==
X-Received: by 2002:a17:907:9056:: with SMTP id az22mr1038377ejc.107.1639432412069;
        Mon, 13 Dec 2021 13:53:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3e9d:: with SMTP id hs29ls1784236ejc.2.gmail; Mon,
 13 Dec 2021 13:53:31 -0800 (PST)
X-Received: by 2002:a17:907:7b9e:: with SMTP id ne30mr1187438ejc.24.1639432411442;
        Mon, 13 Dec 2021 13:53:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432411; cv=none;
        d=google.com; s=arc-20160816;
        b=tXVr84FYOrVl4EmK6EdXf8iXWcFvRMK8Q6VVNYRcIXx71MZSwpiPni1+YCqCSvHevd
         2jO+Ag1ldH2jttbOAJOcL3LoYluBRZ0nS2ODnKSuVuxXKIr44mgbojFTRdJEShB0zr4g
         smeO75f26bQYcCZ4MoPaXLObSjIl2oO2siMz2a6uh26YiGBp4rzhleoQXJPLgM6TU0Bm
         kWvn4U/xlBYAzg6l2kJnSebcYwcEvVzcgL3pXe16Fgmszf0NptiGeSeczxEyWk5YauhK
         48c/tBBDzGCHH5yQ2ACHg1LD1JmxDmBlkX8p9PQcjdPnL68jJxoiMpTABwT2qjiaaHj9
         +cpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U0xyJR8h0NzK4f0d23y72W+ijwLL48MO0qPoTx5MTdw=;
        b=kiwPoPRMsvG7X+HnRTpEobakL383uni3RTpv4WTUsVMmtjSxy6UZAWRFHIo0/UY8qy
         v0VOpiMz/iWlk6sioEIvoYutYtFL/KIPvfW15E7q8znQUnM87uiy+WgcmGYydw9orlEx
         zQBi7wl1gYVGk7qqAiG/Jfyg+LC7vVkQfN0N64Uu/DcOrxAoKlIkYgSo8VeEL/ScSyhK
         HcJwWnPfVJotKpGGVf9i1K1SwEZH5FfMmiV5x/s4Emi0X/giDNqv2PkRn36/ffFAiKRr
         9W91ILsmyzCUtKJYIn0F0IbfyJvXbZuUIxVUUiJdd0bQs2QTFIqVdTG0xaIwgu9w4uDP
         8W4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=s8HCaE0I;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id w5si520118ede.3.2021.12.13.13.53.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v3 11/38] kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
Date: Mon, 13 Dec 2021 22:53:01 +0100
Message-Id: <585c27bfa692331cd75de7c9dc713a318d3db466.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=s8HCaE0I;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move tag_clear_highpage() loops out of the kasan_has_integrated_init()
clause as a code simplification.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 32 ++++++++++++++++----------------
 1 file changed, 16 insertions(+), 16 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index a2e32a8abd7f..2d1e63a01ed8 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2418,30 +2418,30 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	 * KASAN unpoisoning and memory initializion code must be
 	 * kept together to avoid discrepancies in behavior.
 	 */
+
+	/*
+	 * If memory tags should be zeroed (which happens only when memory
+	 * should be initialized as well).
+	 */
+	if (init_tags) {
+		int i;
+
+		/* Initialize both memory and tags. */
+		for (i = 0; i != 1 << order; ++i)
+			tag_clear_highpage(page + i);
+
+		/* Note that memory is already initialized by the loop above. */
+		init = false;
+	}
 	if (kasan_has_integrated_init()) {
 		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
 			SetPageSkipKASanPoison(page);
 
-		if (init_tags) {
-			int i;
-
-			for (i = 0; i != 1 << order; ++i)
-				tag_clear_highpage(page + i);
-		} else {
+		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
-		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
 
-		if (init_tags) {
-			int i;
-
-			for (i = 0; i < 1 << order; i++)
-				tag_clear_highpage(page + i);
-
-			init = false;
-		}
-
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/585c27bfa692331cd75de7c9dc713a318d3db466.1639432170.git.andreyknvl%40google.com.
