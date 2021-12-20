Return-Path: <kasan-dev+bncBAABBLPZQOHAMGQEQPLXMOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3ADFE47B573
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:10 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id bi14-20020a05600c3d8e00b00345787d3177sf573400wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037550; cv=pass;
        d=google.com; s=arc-20160816;
        b=gLg+lO7LLXBUGkHWRaKNkvIKpC7Yqphwzhq3lps9GDtor5f5xiWCZNm17XxfWGicDh
         apJYeH7VtUIoUP43d+7+CVdAlY2SoAd5Imirp3+6Eg6lMGfwO4qicgOXcKE4UWM7MYBN
         9xUs+vwNlt6jwekpm4sG0mS6+gbEpTx8nkpvEBzX8hfNzBbFGWnsv46g4+N0D+vKVZeq
         kOGmFILFmjKoquv9FqgabaZUattpSZjWN+sLEn5q10zfSSG7LQIOj5V/eB8m1FUhKlm/
         h8P/GY5WHyusWXq4Cea2QSnr7aG1RJj1vPjUzOoLEohO5c/EcqaKEwKb2Tu0j3BPqTBJ
         p8Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qPaXdl390ptj+vc7cA+DZBJb1CEiK/sPeTvwwNzTHJc=;
        b=XUGaQItO96raSh4NfgyAMwHGzSvvJtaVKxi7eFmFCyj+0H5t1hLR9qXfv1690TGVHI
         rIQqtzogPiSyEqv1O4eOacSgV7GPwXeVExSVm+k1OLeP774VtpotJLZbnhkr8gUsF1SZ
         LavDvNxHY0/G8Q7f9ztTmXmfvvSdbYV7iqjd8cRtjHUxD64GnqR1C1u4ASJ/JFGBmZgF
         DIyndTF3I61xPJwljYn6f68TplqOZbvrb6KUwclC29a4ve85lqBGMs4h88mEeSctHA4y
         a1d9j32ypTgmyHWBdPwVhLAixJI7dUKOhUuGKUFHtNa172576Y+vRo6FfvOEzdgGQgBO
         GuXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gDJSglEc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qPaXdl390ptj+vc7cA+DZBJb1CEiK/sPeTvwwNzTHJc=;
        b=MeveWjWIaXsS+ioj/IJPrhz/Gk7mh7PaQd/DIr/5pInGqNSkam/nRBvV3k3FnmwiwG
         A49lfXLcSQOLZOSVd55fMbL1jyjo319pbSyNh7A0kIak75ewQ/LkLtoSlRZGx3lyHcMw
         t5Wkc9pXfkAzaMoHpohD97i45h4eA+24puNA29QHyrc3V4HwNhNlfH/Ak/xofBcGMxg2
         4ohYIaPDCr9JjyA/ydJcfjUu7ncXKmjv6bwTUtpPUl8j1G4ke0BTrONxfBYkmide2pm0
         j8DdQISCEwo44bNbKrwPHpsE0KdCVelorWC9goUeh1Ib4mESTYXaSHrdCfZdbLboOCHx
         puHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qPaXdl390ptj+vc7cA+DZBJb1CEiK/sPeTvwwNzTHJc=;
        b=ay6O1UU+NWzSH0Lg0Ku/FfcYw/gf4Hv4T1sBLUe/QGpCMk+j5BELa8vOoqGrpbzcOU
         lxj1i+y+YNrcljfqe2vSxjDSq+hQk5mCKlx7A31kgQ4CT9a0ktjkPfKUl4cr+bo8pigo
         NMgwkHe4FcOdX3+rhhnhKcMTSpUiCb8K+aDsALuepMNjxz6B1AJCyOCJtIHVKwNTCMc1
         Kx6vmqy5twi/6lIO+A1asL32T1qPYu+R5yNNVadMcXIKNQ0Ij0trbRLxSHdO5zJ/3qAE
         2mKx829ooUlK6wUC/Wqfq3dVMob+IJnNI2vHZTNZ393/qmwg3yKxcdTLPwwAQjREStyl
         SHfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qMVE9vPEM4tvz24RKAHabfLxrbHyApZP4j4JFb7hNKP4Qr30L
	eT0sZVossj8I/cADswrVbPc=
X-Google-Smtp-Source: ABdhPJz0qBxvPMrVTrGGsWciOLMCS8aA7YXfZNJAALifN1eII293b4b8WwFlKItxf47GpWOl/rIeZQ==
X-Received: by 2002:a05:6000:1867:: with SMTP id d7mr97368wri.21.1640037549973;
        Mon, 20 Dec 2021 13:59:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5111:: with SMTP id o17ls237881wms.1.canary-gmail;
 Mon, 20 Dec 2021 13:59:09 -0800 (PST)
X-Received: by 2002:a1c:c917:: with SMTP id f23mr67237wmb.10.1640037549263;
        Mon, 20 Dec 2021 13:59:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037549; cv=none;
        d=google.com; s=arc-20160816;
        b=a4BQhxASi44KjoOmrYSGNo3deOGT7Bs6wnHCUaS5YnG3J5Uk/mrTFOmOAc4+BGW1m5
         n5J/2DEZqSDbz5bkZZLLSBUqeKErJk4rmRXYbxQqrBFNh1tyU87p78nsWMryH8qSPxdU
         sDUQEEGsDDNmvU7HXgior/QtkpFVDTvDEJFJqJYnPNkmKHwJDeWAf2/sVrr/aXiAkeIq
         AGFavYWqjjexb95Bli8g1UJbr9HWCLxnlIpqG+G0t+FlT+c+bScvMtfGSIYl2QzczfWS
         UAg6MpXo8ooskAA1IC9KIRolWd/DjpQ21z2/qBolYi51j25LpYAqKp/S5fbNPSdan7U0
         EOEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gEwxHYhSfawbBtJvbiR6+iX2264JYoaXaLcYxmnXGuo=;
        b=xE3klId/l2I0v9tIamK0zCn1lgGuOZeyBua8DCym+zNRr1r/v9X/kdlLqUTvdRiTuF
         OrDr59roTZRBAi4uLWaDgqS62Q1q8U5AWyv1n69m5pPBDjOikEG636LTiFfMsDb4Q9DM
         IKdzyt+o1sXzfIO3i9/G0S/n2tRAC/LmW5b+WpoBjSR+tU1k46kaQxW7Xh5zh3rIa4Tf
         GzP7TgUYkmYFgLCSDGOP9eUr2As0C50NA/1jbbY2j02qWWnIX0KqZsGnYo3ExkYPvLt/
         SrpFE3bD7ULRH1XlKmI02ptcu5Yvzhc67tZgtkshmS2fAtDa+XSNCnMhR7NYT4r1SpAp
         LS8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gDJSglEc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id ay11si53598wmb.0.2021.12.20.13.59.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v4 05/39] kasan, page_alloc: init memory of skipped pages on free
Date: Mon, 20 Dec 2021 22:58:20 +0100
Message-Id: <2511bbfddce7e48245a4d9fc08f162ddf1597e66.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=gDJSglEc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index db8cecdd0aaa..114d6b010331 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1374,11 +1374,16 @@ static __always_inline bool free_pages_prepare(struct page *page,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2511bbfddce7e48245a4d9fc08f162ddf1597e66.1640036051.git.andreyknvl%40google.com.
