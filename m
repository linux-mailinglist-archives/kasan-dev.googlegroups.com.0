Return-Path: <kasan-dev+bncBAABBOGK3GMAMGQEXNKZBTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B8B95ADAA4
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:08:09 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id e1-20020a2e9841000000b002602ebb584fsf3224402ljj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412089; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z24/le4YNtYNL1XTfiukPUf4IpDGlqSIzllTdMZl/ua4pXW2+AocEGqQ/UKOZZ2kXN
         lq93CcwwEkXiPxF0BgsCZsLEnwT6vyPuCKBdPvqR7Lrqs9rjuNuN7tXjAYUj5FC25UNc
         YK4aN00Ix5Fjncg+2UhdzKfOyrPwcsa0rPI6ut8HY5Zj2fyVYP/1FYpWA0zWz1WTV5uJ
         CQIRbXT8rf+9FdPChKuUIa0oKbmwv0IziD6wwCf1LLsXacReLXQzWNuPd0GIAAeKYduN
         LhPJqwzXnn1F3R+oKvDjBaG5zxmbwh5Btgk1lRNMnWHVOmPevPc3AMLXza0JZiY41cnJ
         kRTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bjQAV6/I20hoWy8f/F71h0sD4R8U5iuYCJUlypXxrLs=;
        b=YGFpSFrE/ghjnN8v3bgsLqe/zsUwt4g0Na+mNnCOyq2Sa0WL0yUHZpdxnWzghlCEPx
         kRf+SQ3NlR5q90+zQ8fJx8p5W6UGRrHrqaLd4BujKxMlwejDLM+ko+A+22GdCTBpxZLW
         ngjwtsndioyMFijisCVWbWwhzoTjtt729vijygzpTO5/cNtQcb48GPOc9K0qLcNAm4Zf
         EfOj1s13imT2HeHKv2E495c4X3seOij7Mcd+xPD4rTYJ6d5AWHXao4AIDPmDTBQ9iRE6
         8X3kTWt8Ja3/1vQeQzTp5M5id84/mjBqiFDpUPbzdQjU+0MSodGiLWBs0YjuwlnQcJRW
         WdJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mUENtsfi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=bjQAV6/I20hoWy8f/F71h0sD4R8U5iuYCJUlypXxrLs=;
        b=Zg4wV7SP4joIiGXmtx6iXt91iJDTAdnSAwLpw+o9T13IgYPoa8HOsMN1uuqlhYRzh3
         YIyzOTWWBy9yIMoV6Sv4Ba0lbS48hZk6a15OmvFvEeogOwY0h44EJim9OJTv7SsODoYE
         A9DImbXL69LtBnDzX+MTLx/Xwzj6EKub3DFmdpCsJLK8FxNfM/7dIItvicnTiOWV1KpQ
         +QBEDjcZgZPkJXpS/WoI96DaYUtH5M9/OgTMjfUF3o8apPOBRGj3hllZoM+Yam4OQeBL
         eiTxVg28VH//AIizuzrtBsXEQuW/qthyWIg/vMxKz3jUFfic5NGCbQfQUgjcsLNQcXFX
         mjOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=bjQAV6/I20hoWy8f/F71h0sD4R8U5iuYCJUlypXxrLs=;
        b=aCbg8uiVrmrjEKBbrf1L9ixeR3gCB81l5PuFew9rGtiS/5/kigw61tmILyWkohWfPm
         BTtP2As32TVLd8D4Lr3np6P3Biyz/4kZuHdG89AQWP9P/F75sx5p0IoJNGY0IY/XhP0Z
         TuHF/U872a+Aay3zzAbGnns3Z31VNYS6rCabZUi+EthcxhQTjzaHXf49rsORk3BJqSx2
         Mi4BRyXDVuSe73+TgkrJIAr1iaJ781IAW1ogtN6P6zjEuXJcapzfCSjR7teen8dRkNDv
         4j0NWDLdzeQAnYtZ2msH47i2JabXLBA061tdupB1jKx2nht3DRaHIeHHoY8PCMXIS+iP
         g4dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0K9olfgP6nDYDciQvs2jUMS5/WjqjdSqI6VUXMBtfOahm4i8T6
	6x+R3NPAIJ1PLwFtnW7nSPY=
X-Google-Smtp-Source: AA6agR4tGae7PO8M3oz79tsoZ+QuLRgeoMM34QTwgi9hKstiON5HfqtMptLYuC0g/2Qf3qNjUi8WdQ==
X-Received: by 2002:a2e:94c7:0:b0:265:6126:6562 with SMTP id r7-20020a2e94c7000000b0026561266562mr10619038ljh.150.1662412088973;
        Mon, 05 Sep 2022 14:08:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:150f:b0:25f:dcd4:53b4 with SMTP id
 e15-20020a05651c150f00b0025fdcd453b4ls1717924ljf.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:08:08 -0700 (PDT)
X-Received: by 2002:a2e:a9a0:0:b0:268:5e62:acfb with SMTP id x32-20020a2ea9a0000000b002685e62acfbmr8751801ljq.326.1662412088254;
        Mon, 05 Sep 2022 14:08:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412088; cv=none;
        d=google.com; s=arc-20160816;
        b=PcpWo5+Q58FWldZk2RAoPS/GPLCd6bL8WqCCCdXjkCwNUiGVSFoKjoRtdRWN1AwC7I
         hvClGqboFVRmeAF+0uYhDtydCYcoD3O3gOueSBc/BBCza853VfwEuxc3VreFpA9QmeSK
         zUusLkb/ikRPsSly7s3uqy8YJ8B5fpf4+LSKm0ptDRWMXzo5o+LSso648lkf1ksh4m9h
         lPOCgbjZluvtn7llEk0TV1cZe1OEQnjGBZAyD1epqBmJGBWPtcWOb2DdoMINKY5QnnnW
         V69NfJgTGq5gsr5Locxq6XU7JMNEbVM+hSTVXgh5gL30QU41IoC3UK/AHiKjvQPt1Q2C
         5+fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QPTLEFKVNhHBs5rA/ZsHhl+NYzDo7/AO4Izo15rUT6s=;
        b=Y1yO2/kXyc/YvphRPko2E0wede+RuAbpJhcXhKPAOWJafdyA/emq+F9lLTGPSy9a+R
         eHlVroIObtCgJCUoqeCrMoDPI2SmbYNQ4ZC4XNrP7Oc7Wwt/jWkX68oxLnhPX7QQuzeV
         eRFUQnJ9LHh2U/oiqGlr1efdUDMaUgv2dx4fIHFFDWVs0igb5W0ZqI+H2vf3Cx3+HAav
         Tu7AjvlN/YkZ/kTVy2NNW3trPRX07ACellaoSvC+XaeKCUJpnxZxJTO7H+Cip4YYDvqa
         Y1sKEyAgIvyQ20AisXSuxWKYhReL8ZSu/y1P47jTYGYKOYNuBKzFtioeSser2L4/coue
         GVAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mUENtsfi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id o20-20020ac24e94000000b0048b1833caeasi433619lfr.3.2022.09.05.14.08.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:08:08 -0700 (PDT)
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
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 17/34] kasan: only define metadata structs for Generic mode
Date: Mon,  5 Sep 2022 23:05:32 +0200
Message-Id: <8d2aabff8c227c444a3f62edf87d5630beb77640.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mUENtsfi;       spf=pass
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

Hide the definitions of kasan_alloc_meta and kasan_free_meta under
an ifdef CONFIG_KASAN_GENERIC check, as these structures are now only
used when the Generic mode is enabled.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 6da35370ba37..cae60e4d8842 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -193,14 +193,12 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
+#ifdef CONFIG_KASAN_GENERIC
+
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
-	/* Generic mode stores free track in kasan_free_meta. */
-#ifdef CONFIG_KASAN_GENERIC
+	/* Free track is stored in kasan_free_meta. */
 	depot_stack_handle_t aux_stack[2];
-#else
-	struct kasan_track free_track;
-#endif
 };
 
 struct qlist_node {
@@ -219,12 +217,12 @@ struct qlist_node {
  * After that, slab allocator stores the freelist pointer in the object.
  */
 struct kasan_free_meta {
-#ifdef CONFIG_KASAN_GENERIC
 	struct qlist_node quarantine_link;
 	struct kasan_track free_track;
-#endif
 };
 
+#endif /* CONFIG_KASAN_GENERIC */
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 /* Used in KUnit-compatible KASAN tests. */
 struct kunit_kasan_status {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d2aabff8c227c444a3f62edf87d5630beb77640.1662411799.git.andreyknvl%40google.com.
