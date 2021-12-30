Return-Path: <kasan-dev+bncBAABBUEJXCHAMGQEP64D7CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 18BF7481F8D
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:21 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id j26-20020adfb31a000000b001a2356afd4fsf6508943wrd.21
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891600; cv=pass;
        d=google.com; s=arc-20160816;
        b=GnX51vqrYuCT9/PYmXFsK7YzKfAZzqmnX5a664Kd2r2DvyHDRyJD5S6c6ix8majMtw
         E4rvy148R8HFOEem9Xkheyf0YPTwJMkEbnoD56wgliMUM3LLBMncfDG3MYslZDsK5fdV
         GMBOk1xOvod0BkuK18x+y7ul6hnm2czKG0ggdYezhIu9IWqSog2af2AktJVsn+w08oHe
         npIbTDwoPEjEWP+/sBWrMOpx9rFx5Z7hGAwMawRL2vqQT3fGvBR17FqdkA90OKyaRTbM
         Ri063DYRqz+rLjlxnsN0qH3NXnigSDU26YXeKsoOzTjgX+0nePbjzVO0bO64Wm/KoCHN
         AIsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AqXxf2un+NGMkniyFwlgYQYNIufIkUUBdBQKUdYk334=;
        b=HdtfAliA/DuRAM+QUTxCFGahhq8UoqbMtz/VhsjCPI34KULP6+VzY1lBCsbq1VWs+x
         eeS1iXIvgrQ71FXs1RgGZJNAh3p/Km98eRU3YuIQWyIfxUmcW5wN6IJXIgV1U62KGMol
         qSN4l0omJ+ruPhB7xvaeWi/PD+6zDPe+3bPxBp86EwY+N50MU5MZwdnikw3pNlxO4VIF
         IuBrmPjh7YM0Ik14i9MvuRznmYQmgV1bxwS2ZayJ5BmnT+cjL5mjWVVeuvhZ3g4H3Bkc
         pho3F4R4hbi+mzRpGU9gVrfY5S7Bzp1RzPbuQ0Eij7b8En6PIp9g3pRQpsXihXH/2z9V
         NbSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B8CmrXMF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AqXxf2un+NGMkniyFwlgYQYNIufIkUUBdBQKUdYk334=;
        b=tz2xK4raij68BctmR0KHgqEHTwKckGgE/dCEuk/6iAMRIorr2VdEGK5qLAL4W9xpev
         Lalnb8UoPtYYs94X98B/r0ULemP1mu5dz8NHnLUCZeRRHv2MHv7t3hS+9P8IVUTn4NSv
         IDgUnlESEQRrMb0W3mQkUDeWEwp/+W+hV7ndkXQZ3Xc+BRZJiRb1NCxnf1fJtqnFpNwb
         LcrelKuPjqp0rvVexgoW56g+tmPh5EsWl4MPZKaGp7nhtTtJSuIzPBpIcYx7dI90a2x1
         NU6/HmZljNZxHqDr5T5LC8cniHkdMuXPCI7jzRyY5HyN1y8nGoEjTw9K+Qb283O8kY99
         gW4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AqXxf2un+NGMkniyFwlgYQYNIufIkUUBdBQKUdYk334=;
        b=aLTcTnGGJnNPJ/3oCC7Q8pyrfVWS2pV6wfnd/MiyyWZYX4Guoqjjtzv457jxx99uq9
         IrIxCtyn3VsDVewsO5+/buUEyfWnzXLXoH4X2PIB6UIl4bz2aTl15AfVPha2zF/2Ps16
         VhkKwXwK1Es6wne2NOTemUrWsYiKmZjPfHM+7p3Xf6+TWrx7wA/1qsBKKwXMIVd9DS4U
         AJqUyMtYffcnQHN1dHoIjTnpmnLzp+gL9t/N9Xxdq2HbMSy7cSs1NmS49o7YqRyOo2HH
         RMSz2XvARoVxPlclm3O/DWq+lkyW/aeWUobXrJkZkfj/qcJCkV+EbaEjCLE/VD9NV0YA
         STFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530H4keyfiLinZXB6yLKWoI4BLRnUuUu7gkl7By46fUYYvz0tdae
	hMqYHAOkMhydyIKZzEdE2Cg=
X-Google-Smtp-Source: ABdhPJzrIy/QQonLa5MS2EIn/3fbd2Y7aocIHKIeA50DcW0H6/S/b3AeOebXuVRylaZACCxvZN2H6A==
X-Received: by 2002:a1c:f209:: with SMTP id s9mr3112177wmc.94.1640891600823;
        Thu, 30 Dec 2021 11:13:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c27:: with SMTP id j39ls322423wms.2.gmail; Thu, 30
 Dec 2021 11:13:20 -0800 (PST)
X-Received: by 2002:a1c:f209:: with SMTP id s9mr3112138wmc.94.1640891600124;
        Thu, 30 Dec 2021 11:13:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891600; cv=none;
        d=google.com; s=arc-20160816;
        b=OGZ08zk4l70D1L+Q6TRTC4GXEOKqlSdyCkvTdi2mYwWXC7uZGkKiWRD4ocDlxiH04P
         IYpJn05K+eDoOzrX4kJoWR1xRjESsUvHd9dElLfxWqfuauvEQX+hHxW0ZBtQDEceTijL
         BSTQVw6qwZ/7FTpxQLr3qTanW+1Zn5EYiWatDchKyXju4IygpApJZlbadz+R8sSsaQHP
         GtbdF4YOIOnmv0tIpMfyM6+IcPh5Rhffk+FlmOygeZW49QN0dCBhLPTL528SBcNu5AAW
         jcKr9cKqh+G4NCjRfKmtRRQgXnx3C/3HU/hZDhxzCsPS31Ntd8iHiTPwukaTs0MN/nXh
         vf+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=28nrHGgMyGK55v/Rjfsypuf+W8Mz9cvlkAPr7bWxb48=;
        b=oyHJrru2iU/I+wRHuCr+FBndv+QW1X2rhyTz04C+hlYR4gnVFFMewRzJY0U883/xts
         MY5HVzM038XKP4ktEtGUwYsER7NGYmVvmVBGHYJg8BuH+ZA0gYpb1C1cjskKlfKUgO/Q
         nQF7E7VcuK2HiLrBNn7yRzUgaacTdFK2wlQD42xskioNf/4ttlSxaDwM63toYuvD807B
         nNnjE8fTSxT23CrGifX+FQQtyWPqrUDM7Tvwy8gcFjmJETscpVIfF2SMbXYEokOTk+to
         pCr442bEJlmlawzwmW+Lyesi7MN8LjRVWCMTN8kb+njlU2qZ/pTvv+Y3PYVUbjHbI6xS
         sgkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B8CmrXMF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id z16si1268169wmp.1.2021.12.30.11.13.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v5 15/39] kasan: clean up metadata byte definitions
Date: Thu, 30 Dec 2021 20:12:17 +0100
Message-Id: <9549503f54d610083da80559cda1587afb35ee2b.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=B8CmrXMF;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9549503f54d610083da80559cda1587afb35ee2b.1640891329.git.andreyknvl%40google.com.
