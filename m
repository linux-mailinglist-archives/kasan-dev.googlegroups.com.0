Return-Path: <kasan-dev+bncBAABBFWUXOHQMGQESR4G5XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 71A384987A8
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:04:07 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id j11-20020ac2550b000000b00436c45fe232sf3078865lfk.12
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:04:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047447; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzyVvr4h04AsE0ndrpheGwQaT+oc8JZHvzyylrBN2TtMYsj4M0eBK14DxmL4cDVhxa
         SnxyXGoXESY3OW048kTS8Kr0fRFwZPIQ3z1ITvWs39clkkpoQw+L4TW837rxXv67HWFB
         G7Iyzs73x8BIeawN/IghGbMkUM/L4oyDj2COxpgiNwPBOHQzFiR9rZcwcuHdKELP5cT+
         +BVK1pHZeZBaBsgQiWFd3BG1cZ6fpFLhPJogZbUQ6cdxOBysRKx0E+rw8ke8JGsa8x5W
         harGr1YicsFZ27YhBHcDDR9FpSMvFbJSyX1BRkK71ibPPcolOZw1E2HIuldeWP99e7UE
         O/YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nFigIAf/l36lyUpYtyZhx0+bfK7ChWJ9g2c546HnO10=;
        b=E1W7KC0i68l3D2xXJl2a8V3ZOuvMkzavSKtspvT1BXW3s45TAzdcRlGajDqXUIWv+p
         o9X5RR/Uj1O3cbuv9Xni3PF5GThcj1QO/eMRZbWlXyb+/BQ+sfY5IdajkCicHh4mBiGW
         jiYYiVXPIFHkFA69zn7o6IXfjhgciLryynC6G0Ml9AHyiujKCemqc9q80nzQ2EQ55vmt
         ZVLNKLS0j2/L7ulFkhV3156FOMBjqFNe8t8bekNtT3BM67Dl5laBaj+iLS6yo1UhHudh
         nqdawEV6QUiVxcJ2s3AR3U5OcSXZtyH4HhAmT02HsCKhqzy0Uf6C/Ii6OGvdTmxdJw6U
         T7/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hKYMToa+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nFigIAf/l36lyUpYtyZhx0+bfK7ChWJ9g2c546HnO10=;
        b=edTAGCEynLocD7Y5vSJLa9mpVxhDNj7kJ6qcEGO4gBRXimRiuPOiWt1WAebHwKRP+V
         yalMnyAayACRcA+1RSdtrHv1A28I3oNp4px8M6bKDBhfHAqMYWbX7x+KbYuVj/AW/rui
         3ZlFzpBnr0VEZ3dRv2gwDc3CpL8Nx8JEsvOoKa1GgOZXW4aMLRv9gS3k8HqbYrK9snfk
         2T/kRYVfrtWsFtYPlivtQhn4aANjo61vhXb33qMKutfSYDPj9obr+41ceTQm8DuZcjyt
         +hJTwrKBqfeZ61u/bKMGajKntT4ppseWE7lVOOCFLufsUbLYFryk2sR2kLgfV1pyeI0n
         jZVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nFigIAf/l36lyUpYtyZhx0+bfK7ChWJ9g2c546HnO10=;
        b=wBzkEeb/TpVIhrslQfEJ3hnoROuypyXIbno6PrFvQOV3T97qt47JV55VffEZcio51X
         vF54z3gZcCCK6aTolrEWGbrc4VwL1BEXO6rGgcBt0kDUP5ws9zt2jR1O3gYrFghnxdAn
         F/5ao1Rt1eBMj8eGx1mP0CZkUgj4VQHRtioEENHeUIBVBuwo0aF6uUGv1StLg2ucO5WH
         eT86el22k7+MrBH/dysC8KHQINMti2+btVul7ez+nDkwLm+WJpsZckd3qs9K22rt3qeX
         BDHkeXkr7hmgPDsFwqfIgJlY7OO6i6zdbrU6hzcfv523anzF6OELWUzotwe+EODSs0oC
         yz0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532G+xDqetWI1VVghgEseLNS/QgJ3kzpI+AVbyx35Y8GrqBym13O
	lHmP/eUaJqhM4MrsEKMNrK8=
X-Google-Smtp-Source: ABdhPJwziObLurVubSlWqmHWKS0nhdUHZic8OwtyWhFEIdMvty/XufRfmEVEjdqozhST9SDLhkTQYQ==
X-Received: by 2002:a05:6512:3e24:: with SMTP id i36mr9362694lfv.225.1643047447026;
        Mon, 24 Jan 2022 10:04:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b90:: with SMTP id g16ls570806lfv.3.gmail; Mon, 24
 Jan 2022 10:04:05 -0800 (PST)
X-Received: by 2002:a05:6512:2307:: with SMTP id o7mr5349139lfu.127.1643047445733;
        Mon, 24 Jan 2022 10:04:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047445; cv=none;
        d=google.com; s=arc-20160816;
        b=EhBDfkaEsL3W2eRtynjo8nfa2SgycCv+jcafkV5TeRmLvseO93tXOOGxlR/W72TpDL
         KcLGkhxkTltvB0hpwAJsq4J5Y/d1SnhwfC9AOn5HVp4jE9mpth27om24GK24bVYYxMck
         Ro8SKvi1rhfXmgJMJptxkc6k6FlPbJpvClypphGbR3eDgQJkoSgttO/RinVG6xTSqclD
         kwPL8CmG/VVOJ4NOtBRvumf3EbGkWEXTZwRv92ZTG4kNdBmHXeovKBOk7x+vaI3hvb1M
         /N4HGacNefcFKrxabDLJq+tbyNt06fJvpCnCtfpc5WVyoeMFFsdKU5hT02I9HMRZhnWN
         T7OA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oezMiLyxVhF2aG84EFC26Sv8fZTyXG8nFAITNGxgkbE=;
        b=Acg05Hlr5wxBd7wjdJ6KVhfjC/iQiyGvBHMztnWiTPlT2NRudc7JjETUVcGHLBd8Ri
         LyZ+YoyLhRYoibTLCa1wX52sOSf03JYxjltl4WEVHlzDZtGuF263p/KdP61CI4ceTbVp
         oileOUda/hD3TSXqkIThWllMPA7Lx2oB/eWnhHjhlIC/PonVyl9f++ZYIu77Qk0jZOgV
         NbRwaScB7jIorWtxVYvpnDGcaDyr3j0dDK71xC0m3KclibcCdpmhLiswlh61V5WtpnfO
         NtJI26m2lzBtj0/mCf9NTusK/XpisHBqtnsPtsUkYH82moXo4rchGF/dOvsWCBa1Jao4
         1HBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hKYMToa+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id br32si71623lfb.11.2022.01.24.10.04.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:04:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH v6 14/39] kasan, page_alloc: rework kasan_unpoison_pages call site
Date: Mon, 24 Jan 2022 19:02:22 +0100
Message-Id: <0ecebd0d7ccd79150e3620ea4185a32d3dfe912f.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hKYMToa+;       spf=pass
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

Rework the checks around kasan_unpoison_pages() call in
post_alloc_hook().

The logical condition for calling this function is:

- If a software KASAN mode is enabled, we need to mark shadow memory.
- Otherwise, HW_TAGS KASAN is enabled, and it only makes sense to
  set tags if they haven't already been cleared by tag_clear_highpage(),
  which is indicated by init_tags.

This patch concludes the changes for post_alloc_hook().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- Make the confition checks more explicit.
- Update patch description.
---
 mm/page_alloc.c | 19 ++++++++++++-------
 1 file changed, 12 insertions(+), 7 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2784bd478942..3af38e323391 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2434,15 +2434,20 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	if (kasan_has_integrated_init()) {
-		if (!init_tags) {
-			kasan_unpoison_pages(page, order, init);
+	/*
+	 * If either a software KASAN mode is enabled, or,
+	 * in the case of hardware tag-based KASAN,
+	 * if memory tags have not been cleared via tag_clear_highpage().
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	    IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
+	    kasan_hw_tags_enabled() && !init_tags) {
+		/* Mark shadow memory or set memory tags. */
+		kasan_unpoison_pages(page, order, init);
 
-			/* Note that memory is already initialized by KASAN. */
+		/* Note that memory is already initialized by KASAN. */
+		if (kasan_has_integrated_init())
 			init = false;
-		}
-	} else {
-		kasan_unpoison_pages(page, order, init);
 	}
 	/* If memory is still not initialized, do it now. */
 	if (init)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ecebd0d7ccd79150e3620ea4185a32d3dfe912f.1643047180.git.andreyknvl%40google.com.
