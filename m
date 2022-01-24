Return-Path: <kasan-dev+bncBAABBUWTXOHQMGQEMDZSZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id AD32F498791
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:02:58 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id w23-20020a50d797000000b00406d33c039dsf6035590edi.11
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:02:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047378; cv=pass;
        d=google.com; s=arc-20160816;
        b=FB7V3sL018NKsfZS0m3wH9yUIpHz0kUgttiRJft1u8YQ9nuNfRs/BYaUubZKyllVUA
         5nlN1FSXXax7PNSkJusXutcudRJYOof4Xwa4G3L1Jnvku0OS92PeiOD79wCfoCorLnIN
         YyXNpnunUh8TQ2oso62229aj6n0m+PFwM4XCGZu+88EkiNuPXZvxhkgh2cgK11LiAW8J
         iI9rocg8NPXFyqW10G5tLG2xT8hKZYlwIjvmGh6zWn7BJgp69yhNqSymeLkdYGP0mHLd
         VRDIv+Ujjbc7EjssOulrBjBLswBgefq4Zu+nJ7vNQztTrHOO/Kh22F2CLevO3HlppnFM
         1jNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xmtAT7xQre4MekEOj9kWkTYgGJQWHmbZi+QjFLh1tuQ=;
        b=hSuNLy1NIKj4u1cawAyWW8P4quzp3CtAOdHVkrzAC+rCj88TdpFa0Vxn9D+5viB9w6
         /H5TueKBDFjX9ztrtmvUyAOIYVCg9TG9dSfpG//nFVA7mDfsyACcRlUUHq1D6//fLnc3
         6SDT7AK0J8y1Yovn9vhSvq+JSCuFWuvSbJM/WfJAcPoRriZVWSYBy7RPnzM/m5HXvnH/
         MdAP4Dj1w1IHq0eGwioSQbUyT5nTqZVcV7sh1DMuQkhE6aWS0xoLUT1+wbszw/j7gD3u
         Z7rIB+SElKddlXYFuE4nAEaZbjmDIROOAiTdbpmSU35vGkuTYiDnqD2/rb+wger+Is4h
         q+6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jk1sGMKw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xmtAT7xQre4MekEOj9kWkTYgGJQWHmbZi+QjFLh1tuQ=;
        b=jBSXN3uMEUX2EYdN2wBlJUjSVmNR7qKeInKfh6CFJIkyJ28p30xTpUa9mgt8m132Fz
         CbLSCococ9o9aNc4dZRBoELvYfFtNxpJ9mg0XSyuTUmEeu/qrd+JlsLd0dVLk+UP1EVm
         VGx4Wys3niMu7xkwBRYD/TMHZxEnMhVmd7HUXDjPUd1lyTetZWRudRIHbkP0O+p1Ptv5
         UC3qtXtpqZCsl40TbLkR1h7MoJbe+3NUp1GAAl7La3xkfoE1Z2LOxjtsVxmss7d6gI0M
         x3eTodc12xkhgHjnJ+GTFwugUHQOHJ8btNXHYb4guu3GTyxEEw1Hu/RlevZlSq29gxxh
         o+dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xmtAT7xQre4MekEOj9kWkTYgGJQWHmbZi+QjFLh1tuQ=;
        b=bhQd12UOk3bSnFixndX6h548x0wW5XhaPa6F2WLH6Us/fekaEKUUlNQ2Mb+I9sWvzi
         uFJUtm9ZmfckKfw/hVgHunETUOtTumZhj4iBt51ZtWgPPTRCI1MD6QHAyzAYGRZr2AaM
         qHs81aop+vMceT4QcnZ+6MbylZZaIWdC9TxbB/txkNRBvAeRmd3fMXAkVAj16KVZxcYb
         RHEHHMcht7nTnj2TXSbFaw0GJ2T2ktcQ2/e/l28iVf17gxZ1cQJa3kxJO91ewRceCtX3
         m1MmBNIwpKMozhh0+8UoVuRPqP0BquZ5fA0upKN0YUMJRP0dz5FOnnht7drzZvcXHw1L
         F5NA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dbi43hMYekuAeZXNJ2wSFjD6gkKaZkW4TBUk6utR4ccVOSI5x
	Zl6ZPEMiLy3Q1fcsgTXdPNA=
X-Google-Smtp-Source: ABdhPJwJ5Uv4XuJqxsd3bYsK4bQMVdPtbnoGGuoO2c72gzPZW7zxTla7dEE9m7WyjuWFb7EKEfw6Cg==
X-Received: by 2002:a17:906:7044:: with SMTP id r4mr13109061ejj.351.1643047378393;
        Mon, 24 Jan 2022 10:02:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:370d:: with SMTP id ek13ls5745688edb.1.gmail; Mon,
 24 Jan 2022 10:02:57 -0800 (PST)
X-Received: by 2002:aa7:d554:: with SMTP id u20mr17269796edr.322.1643047377622;
        Mon, 24 Jan 2022 10:02:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047377; cv=none;
        d=google.com; s=arc-20160816;
        b=IA+YhS7s0glISN7t+nCpcAJWsdTeuacpOJeskNn0EXhJO+HozwvtXIc3E1qN8VyRqH
         lvrdHm+Vtu97gY7xyvKPuHVNb19T7CZ44w6T471iMJvJ5EIqBJoQM5ARxu2x/xSY/dtB
         oRnuMWuaRUzlu7No1NI0B79pMjGsSgioi2tkWhfIh3jpacYY+xFtbOAuPGGt/6xakMyq
         tb/lTWBCvrysw+VZvRWVmtEPtNQHOqkG76M9XFoW2kPy5resZIykkeEq+B9Eu3Mq61U+
         bL7RqcTzf6c0W/J/C1hHOX3fYiztaid6CAsw+NM+LkS0BcL1OjBWO0d4EvYvjAVovpAO
         L/Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lu+d0FvmlGAoYbgcSnAcHnve/JGZrRKgqG6H2fXAm3E=;
        b=I19ID/dLHBjZhnmOrsrXYSsBp20VXNRjbKdr9dNb8WRqCj96TDsxwfduxn3P4bGfUq
         EHa6icVwjBQZf1a8886JkmLzaNuKOXOgyEej0eMNWgk/QxdiYyN+/l5CWJuWMb83pZBr
         xOfv3iLZzkKR2fULSSFbduriLEg9uD8Vdtca4YSOy1wXuod++utliqMkWLuU+4+lV69P
         lUnFH4R6bmua+n1iqFFK5vezKss6+jED4GDqM/40zjltiGQWnN9ADw9igTud8rcjkV8q
         pzhZ4Ls6T/lcjGphP1T9ERkraVct2ndIJ4RV1Qa5enI4vnn1Vv91U1omz4HeL6wWCW3a
         2JJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jk1sGMKw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id l16si674502edb.1.2022.01.24.10.02.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:02:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH v6 05/39] kasan, page_alloc: init memory of skipped pages on free
Date: Mon, 24 Jan 2022 19:02:13 +0100
Message-Id: <1d97df75955e52727a3dc1c4e33b3b50506fc3fd.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jk1sGMKw;       spf=pass
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

Since commit 7a3b83537188 ("kasan: use separate (un)poison implementation
for integrated init"), when all init, kasan_has_integrated_init(), and
skip_kasan_poison are true, free_pages_prepare() doesn't initialize
the page. This is wrong.

Fix it by remembering whether kasan_poison_pages() performed
initialization, and call kernel_init_free_pages() if it didn't.

Reordering kasan_poison_pages() and kernel_init_free_pages() is OK,
since kernel_init_free_pages() can handle poisoned memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Drop Fixes tag, as the patch won't cleanly apply to older kernels
  anyway. The commit is mentioned in the patch description.

Changes v1->v2:
- Reorder kasan_poison_pages() and free_pages_prepare() in this patch
  instead of doing it in the previous one.
---
 mm/page_alloc.c | 11 ++++++++---
 1 file changed, 8 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 60bc838a4d85..f994fd68e3b1 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1375,11 +1375,16 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (init && !kasan_has_integrated_init())
-		kernel_init_free_pages(page, 1 << order);
-	if (!skip_kasan_poison)
+	if (!skip_kasan_poison) {
 		kasan_poison_pages(page, order, init);
 
+		/* Memory is already initialized if KASAN did it internally. */
+		if (kasan_has_integrated_init())
+			init = false;
+	}
+	if (init)
+		kernel_init_free_pages(page, 1 << order);
+
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
 	 * does this.  So nothing which can access the page's contents should
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d97df75955e52727a3dc1c4e33b3b50506fc3fd.1643047180.git.andreyknvl%40google.com.
