Return-Path: <kasan-dev+bncBAABBFWUXOHQMGQESR4G5XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D7984987A7
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:04:07 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id o3-20020a1ca503000000b0035056b042desf302196wme.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:04:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047447; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hmwsocznoz67yZMbIJGeKhT/95A+deOGVErHE3IiRMCT0LfTGMgz0libnS7GKcJxaz
         +Vn11jPxt63GXcTZA42Nig5HICI7VFO/s41zStk13/Y6ErnHPoPwY04QSHIDOos0jcih
         4aPUOVKYRaNtI3d5BpI28Ecpl817e+IQZAlAoP/NE8lUDBJizw9T1RnRiloFhdHRHzB3
         AR43mcmlP+hYh9uy9T/la15sQfACq4ElPcfEdLLCU8pKnzRZcgiXsmyWzMklVHhPd4PF
         Z+gFPvWnNDtYuaKDV81hhmbSmn+uTi0oaTAIO5bpUMIMU0pWCCzWoDqgKU9N7mKN66iC
         K2Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=C0bRyKDcW1qJZS3fLzZWCpyHW/vibVmyG7NmWKPScAA=;
        b=QZW9NYGQcLSStjRn5ZIhnEJpGe/cEwWJeL6PC1mje3U3pHn0dLpg06XZMOUw959D+A
         u9Ovkv76VgHj0+/0IhhGW4sU0HjRrk/+Zb3eTKRnrFXkyX7YAqrrrN3avL8msrosBXZY
         CbPnlEMQ+KLmPPPJk7MFuntFe9SUnGSuQ3xvjhc1MFKeuSDzTzW4q1v/D4bSSWjupbQ3
         F5VSyenmFkZaU0Gr0LPHYEPdVC2tJFtdl0Mhvnwwx5u8PLPI63tC4xfMaAqwununWP5Q
         gJX+2jrepMe/7ENuKl/djV4WiCmUJHIkoz9u2YPNWrYlq4SevQFfRAH8znar1YKBSxSM
         05gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fFDtB2KD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C0bRyKDcW1qJZS3fLzZWCpyHW/vibVmyG7NmWKPScAA=;
        b=SNJJhI5xHXV1cWhJDW1XhZ9O2jIPm3sY9FzD+WVFZJwUwibV5OfN7MDl/swKSBdFpl
         5oSWPCdFK7/BVbMJ65+gxDYbREa7hq+JncbB0/FRd8NTRPjXq/yPZnw2jij5Nifkw4pD
         0WnBdb40OXduzGSixOrTvYXQ6bGdPGFOEl1Mx825Q0pN3YEWYSRzz+Q51/ma6FKZBeFz
         g0PdSbM6iF1XpygSMTxGpzBwi7fSkdVWb5FQwT3ejboHB4ofICkbRxRpmO8g9XmEZhO9
         KjJDD2ZAHLPqkvVJ76zvyyROpNZlMIz7dvP/Eq/OxjChgwAktxGOlqXpMme5jpGQdmRh
         imeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C0bRyKDcW1qJZS3fLzZWCpyHW/vibVmyG7NmWKPScAA=;
        b=Fry3VzvUpKYQncW+WL+VhxZl+dSEbag48SEtjQByr4o2PUJ9dMAzmmT1uhHnddrNel
         XjEPvkCcEMjEwnw1ljwp45Ln33UwjaseRxWEyq4M6hYal+VTMKmWJ8482VlnG5mkEEQE
         RMSbp0T0OUo7lZjDMU2rX6rO+mT0gKUEaP14XPUHzC7IEdQDf7rXfO4gNc3kDa6QkPB5
         6UUiCbZsq+ELMUXAEPT0QEC61AkL2EXY4JOy345zwdld4tGewX04pQbGCJVafkpCqbh3
         m9mtS9+W6CmGqJS3nF1QQRZzEoOJygEOXDEVPf+ZGKyY7ML5WrqjrV3QiGB18VIyGwE1
         q2Dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lV37EXRF0DRI4WVjoEQS5FrUhHyYUOEnKun0ANeQ3SV92gSDr
	oEMA6fjP8cIgLe9xwxBaJlc=
X-Google-Smtp-Source: ABdhPJzr+KCUX6AdW5MmvQYveSATQ//331xoXCSLQVU3Kpqy/qE3Lif96REr8alXnu5Yxq+HpS3Xwg==
X-Received: by 2002:adf:f48a:: with SMTP id l10mr14985115wro.220.1643047446971;
        Mon, 24 Jan 2022 10:04:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f04:: with SMTP id l4ls38347wmq.1.canary-gmail;
 Mon, 24 Jan 2022 10:04:06 -0800 (PST)
X-Received: by 2002:a05:600c:4e8e:: with SMTP id f14mr2859427wmq.175.1643047446245;
        Mon, 24 Jan 2022 10:04:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047446; cv=none;
        d=google.com; s=arc-20160816;
        b=J9+tfLvM0UfC6lvD89Vt/hy7EonwLyNfFODIjHY4yrQXjw+r+YPZIPI1Gzug3Tqj4M
         R9EfYOn9Ynu9SwFDOPtxrzuEsaYlkFL9CEEV1ewPT+qFKTIDpKVl/eWDNktfCKh0KMu8
         aVLp/13+KdRFdEV+MXZ2+Z6Pjp2g+MdQgIgpmLSP6UiljwXnqQadHNenGPJ8MZ+XpeV3
         thJSwQTTmCwwfaAEKxCseL9fX+DrSaMaKOodX3CYxzvuSTWHFEUlk301+sfK07JfAeJ6
         B8gvgBjbPSB4Lfm6kEkY6V9sVF8dsgvzolM/f9Ksgd9A4znAVFdlKHtDye3zgL7w9aHe
         SuZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=28nrHGgMyGK55v/Rjfsypuf+W8Mz9cvlkAPr7bWxb48=;
        b=uWOxbu8FCS+vHPWsyvA9yr0laPkut5vA5LfT583Bbq2oUfQ9PysZNSPNt70RmgKaIU
         qQdtSUwxL1ijI7ExWyO+g4g6b6mwIX9xRSDzYbN0SbRInSlENTDXmNR2eNG35exod7YQ
         4BaIWa8nrOsWRwtYLaLqkA7E8So7YYbtk9RnT5toaV0c4VViTAFugtk9YLCBAbC/oml4
         BTdy9Mkwb0ijS32ESADBFi195s9Y839XBMrTC607AQ6CaN58HQe1GMAuP8mKcXQjjT8W
         v+lQ8VP5W3rNZENJoY1B3sH96/ZROijM1XpcWqO1TBgndWVTvyStfngDCSRhaxpxuGy3
         Odcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fFDtB2KD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id p4si1404wmg.1.2022.01.24.10.04.06
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
Subject: [PATCH v6 15/39] kasan: clean up metadata byte definitions
Date: Mon, 24 Jan 2022 19:02:23 +0100
Message-Id: <ac11d6e9e007c95e472e8fdd22efb6074ef3c6d8.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fFDtB2KD;       spf=pass
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

Most of the metadata byte values are only used for Generic KASAN.

Remove KASAN_KMALLOC_FREETRACK definition for !CONFIG_KASAN_GENERIC
case, and put it along with other metadata values for the Generic
mode under a corresponding ifdef.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/kasan/kasan.h | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c17fa8d26ffe..952cd6f9ca46 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -71,15 +71,16 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
 #define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
 #define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
-#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #else
 #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
 #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
 #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
-#define KASAN_KMALLOC_FREETRACK KASAN_TAG_INVALID
 #endif
 
+#ifdef CONFIG_KASAN_GENERIC
+
+#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
 #define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 
@@ -110,6 +111,8 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_ABI_VERSION 1
 #endif
 
+#endif /* CONFIG_KASAN_GENERIC */
+
 /* Metadata layout customization. */
 #define META_BYTES_PER_BLOCK 1
 #define META_BLOCKS_PER_ROW 16
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ac11d6e9e007c95e472e8fdd22efb6074ef3c6d8.1643047180.git.andreyknvl%40google.com.
