Return-Path: <kasan-dev+bncBAABB7EIXKGQMGQE3UBU22A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 55FE246AABA
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:33 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 201-20020a1c04d2000000b003335bf8075fsf6742137wme.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827133; cv=pass;
        d=google.com; s=arc-20160816;
        b=HeSrqPAdcakUrnQruao6WNdu0e8vH+vx19MoVEVxHaeGbvIEyrF1YhoE/FE5472PcO
         DerDtkSmsi1X8gdbFbAQ4tURO/AWdlulz9NrFE0XBqdutkkVU1194Fl7KuVG/z6rb92L
         XGAjcCg6HsAkV3XbWoZHoDZv1ov7vb0sf+ZwOSJE0JXHPK01rZkQW4+EtxEpMGwLTRC+
         sQ/zvpQd2JaOUP/W3BAG1rEHQ84YFONMv7JyVyWCsMp0/IcBFK8kEucFvwlwZJTtNclg
         o5dXnPqUAOGesQOHpyTDArwVtQzbVmPGo0e4ZPbItZZlrwxHzA0JOYkAP+y50f5lqxLa
         ST8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kU3D/HOgMgh+JibM2fMgZsZJJLQqchIMzHpZ/Rb0E/g=;
        b=cGzDwuDlV4NRhOp5t2exSgAoE6PCRca/2vEfaRIQnxCZpCKtPqDQfFJGq+qobHjLcW
         r4UlMxu13sabhbLn3Bfu4oVRIYnX8n0PygPloBBIEDEm2ExaKW34X5fexcFUS2qKXzy7
         9cCZbN3uHbPMBs3jTmb6054unyoXF1I5VwuN6w3HCsJRp0PqyfQU/zzhq6fqvsrbtyxL
         AuQEa1kJhMA5NIjHoFrZH2BJpNmzoRZMfASeDZrJm+wBGTCDA1jP6ZUM6kGSSkyXaCu/
         b41q9my+n20tfB7KEXxP+JWUv+QUdC5hhBo5ZLA9SSV78x4OH0DGNcG+xC3cDikFtklq
         NABA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LcblNL2D;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kU3D/HOgMgh+JibM2fMgZsZJJLQqchIMzHpZ/Rb0E/g=;
        b=YgQjW/aNxB3JIzYnf/6QiOQgoOWfCwRZf4GSfnLxiUbvm4f7xbktkEJzaQad6TIAC7
         q+uD5U0xv/B9VzV7c3Gb2sJUcwRbCcRc//VqgMW13cTdN94EpZmroXztxWNhV7g84AGd
         ghUIMOt79f972Iai/IQWMIrvAd1V/EpSzTDCw65ugOv7IP54k+Zq8mvi8RNGzl4pebvU
         uMhxHIiakh06xaF6kUP1jH2T7yHCtDHHykK8oQiToRMi/z5oj0rqBWq9Iwbwq3YGmaVf
         6wsmUU+y0lVnS6VNJecCg4iLRjoUlt9D061hz6PQavPQCvUez20TqCGgdVxiLPpz3Q6j
         5msA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kU3D/HOgMgh+JibM2fMgZsZJJLQqchIMzHpZ/Rb0E/g=;
        b=HZhqRua8Nw5oJ6cQovD5CKNBoyVsx0oXjQszkwHXXA5gz0/vclHqNdqb7JzAe3+bS9
         4bJ/hrLIjAcujmR1I1ecLVtkd1RJRuqyxMCjKAGj5ggeqoFP1XBTZtFM94dXLuWjLmgk
         CLVZ5Iv3wYO8f4wUf+A+xK+Z7xuWalUk3xK5hWOPGwKfriniFUEZLEnrxF79vU3OxAXf
         UciIyFqqvDSrrZQ5poeOM/9Iv1QBHz5IIW6TlLNMnTNGnmv8cDLWOQaY4Ei1k+1VQZks
         8mN13xintWGMGTUirI50p/7CDXoYTuAn4UZX8/wyeL0TL66N3N86F7uElFWtdaO93Msj
         qdyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ABRxYXdgdi/D0UQxYkjFU5Zs3ZV0diPKZxFxIas1Gh/L80a9N
	dZg0ujQg8rzn2j+WZJshjrw=
X-Google-Smtp-Source: ABdhPJwup7Ve5QlUy4CaPMzfob5E4krCKP7lXvlzUVQWevW893LNaF91K7ThdlkKSszit9jTtje+7g==
X-Received: by 2002:a05:600c:5125:: with SMTP id o37mr1483655wms.81.1638827133137;
        Mon, 06 Dec 2021 13:45:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls224528wmc.2.canary-gmail; Mon,
 06 Dec 2021 13:45:32 -0800 (PST)
X-Received: by 2002:a05:600c:3227:: with SMTP id r39mr1614684wmp.120.1638827132443;
        Mon, 06 Dec 2021 13:45:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827132; cv=none;
        d=google.com; s=arc-20160816;
        b=mvQszN8sRCMISNpS2MuTAqLChaawUF2R4viJAXsIic02WtVOi18xOsqMdt3EpDoacw
         fI9NNN5kbKRYQuT5Lw8ZEuOft0xxCRbgOthWh65hu7V9yKSunItKF0S1GWY5fn8xts5p
         53RmU55+gh8DNQRuMAl6zNepykqMVKD2cxM/zekUE1EHeaJDUbBcLtnDXVc54NHKFxFi
         Lhi7EUAfZDXgWMT9PYBKVFTe3qNb5TH51Y2K2T+TzX5hHhiY4rLrqiD7+Ul1M5lShR4D
         wNNm9GsZqAA4e1/gQFsXHI0xIdFpXJHErqRJptChBwCrdMAmLif6qkIWF3ll58+phs2q
         YnyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pxjwWPacm+/5s9n0kHhZDBwjPwmcQ9h5CfpbBNedfPY=;
        b=PpSET2ZcCGPwdVjRnhHmNO1qlaTbGjJDHRFQJS4Hed/zDIYdpHzSerSBqzvl6RF3Ay
         oiGXthZfXZYok6V7TiT7j1cMIzIsKRnxiy8jOE7yN3yr7IvaE1SKDzb2w4pqVchUze4t
         aDczrdeef2YbhIf/WCDiCrFsSFCphRR8lCCPRww9KukhBeHZo3yZhwCbQGH5ioFnmBM3
         P7bPUIx3B7DO/CFWj9SWGt+DsJ5tNW8Deg2PBlp7NPjW2jjV5QHKxzj9ldZzZA18ylJF
         74aHi21WmM/y7KekXTIJBYDIcCZgi3uhue0+shDMagnskbCJdln450OQVd3IJSrM/nzV
         /e+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LcblNL2D;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id z64si69404wmc.0.2021.12.06.13.45.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 15/34] kasan: clean up metadata byte definitions
Date: Mon,  6 Dec 2021 22:43:52 +0100
Message-Id: <e18630b9702870589763987ad53977987139bc63.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LcblNL2D;       spf=pass
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
---
 mm/kasan/kasan.h | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index aebd8df86a1f..a50450160638 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e18630b9702870589763987ad53977987139bc63.1638825394.git.andreyknvl%40google.com.
