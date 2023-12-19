Return-Path: <kasan-dev+bncBAABBAMSRCWAMGQEMKN6HYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 011D6819227
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 22:20:02 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-40c514f9243sf33260465e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 13:20:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703020801; cv=pass;
        d=google.com; s=arc-20160816;
        b=V81IuxJ0gjR3G6kn9OML5OLh8o9hmGsUCL516Lnyn3Uox+gmNikrmp8lIG5OLBZVoS
         V4C6RiEnA8Fs0fmMhJiITqDKQP9tDRr1zr/LfHnrFPRkxsXY34fFzdTDlxWl9VkNijCu
         u5nmeKp2/Fgjy0LdCTUb3lvRYXhL2AzhYHC76iizUsfSL75yLSn2knOF8UHyntP9KbhG
         clRgoymOl4KSGxRvlGTYKRWPQ8UYnKMy/EpZEEUKOoGCYzpwYaUXaC8dL8IX2uZryPL4
         GQL3V/uQ/H9BAj9g1KtLg40Chtzw2wM9JG0jlBAO7V8ZFF8lHSrdOB4s1vrtA2KRQwT8
         yANQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=39D5pofGt0Y2GmbJ8P/lb2Mpk+qHSg5QXT14L5KY1SY=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=tl9BSoewaldHbz19znlXptjkFLt8ndOGcdM35I9vQotym1WqJHgxyLkhlS4xwwt1vl
         qiyGyo1EjS3SpE8KzGiJvF5F6LC+AUzSD57WhNuAis8U64a4XGUpLCvuPJ8ireCqitNJ
         VST3uGJYIh206fE5KUBGJye8FFxe1GSs4vAdZWHSkkmCySypGJV8en2EDV6o82uYSZ+P
         66JynLFGnDsxjkK06cHYReUZJdLWcKAUFZaPmN47FeTO3ZV9bxGUE0QtK+5icVl/KB0g
         cuqXvb/raiQMSWzSUxuaZln9WiXWd8HYeNpg50dXA9F2wRRyQoEkxqzvopvcKNsBnEd3
         h18g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vWTr3qhn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703020801; x=1703625601; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=39D5pofGt0Y2GmbJ8P/lb2Mpk+qHSg5QXT14L5KY1SY=;
        b=pA20dfxJaG9fdJxZr0gbY8c1zGVTknP5ov0O6XhRq0elJSBFTVG13rmxTitBPrHyLB
         6R7nMc0FTfJawqaFgY8wA+Rxgyh6UUzGCVP+zL9C8BJ2fZGTzAFaTALXWK0Y05zGAeMC
         OE3XckuH3BjxOYwA19/itLVNUa9IZjwCW4t9q1eqwMs43sl5jh2o/YsfZhqZgCr6eOOJ
         WJFShwSxZ7w+NuzrflwsGdD1PVsTnJ3BMNJbIqw8wpBtMpbR71d1e9Yc4z4nxU+l40p8
         T2sXBQSkvDih3WBJ4A7u/eiLYbvXyvF9Y+aOBafHx09mZblMPHzcBfxsBybMgzmHDh9w
         XBUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703020801; x=1703625601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=39D5pofGt0Y2GmbJ8P/lb2Mpk+qHSg5QXT14L5KY1SY=;
        b=DlxhOhSvVjaR/9nj7UwBH/RPvVaerycUSx5SQkJY0veqraKK4BmH1wEpRw3sBNyOZO
         9Wv+CmqImwLQ9yTkq8+vdqzud6pPzW05XY2RbH0TJc6A6kN+zGyFiBOC9gdAMtoqqMiZ
         YrGQ7TyoQOsDPEXKYJ+PI2vp8BDom325W6mE4gdSTVe2iWNIho+JzL3hVgR5pFC5hVoM
         WI/lT3W+/nVf/bsmUSyDb4Xwpijo9dvnl3qpIN1VD8raJGL/FSyQbc5sdM6gGO0Nq8wt
         rMuRT35XDq8QBF6D0FzAuWNdWBBpdxIz5H1Otg30evYDjrCm6OVuOEiHn+9rloDsqb38
         msgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyh3Balq8f1FAB2y6+VgH3V2pGUw4xSFBFLNFoxOEmspTxlvQ6k
	yeKv3G48yrbJIMecl19Pn/4=
X-Google-Smtp-Source: AGHT+IFg/fM2M8AGEChXmDSUw2QA+iPUYJ7rrhZjcDZpRt0zFqPFJhSDaVNKcUTVYESx5SVEZHTzkA==
X-Received: by 2002:a05:600c:3ca2:b0:40c:50d5:f7a6 with SMTP id bg34-20020a05600c3ca200b0040c50d5f7a6mr8893807wmb.121.1703020801526;
        Tue, 19 Dec 2023 13:20:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6a90:b0:40d:3158:40dd with SMTP id
 jl16-20020a05600c6a9000b0040d315840ddls103008wmb.0.-pod-prod-09-eu; Tue, 19
 Dec 2023 13:20:00 -0800 (PST)
X-Received: by 2002:adf:f046:0:b0:336:5965:40c0 with SMTP id t6-20020adff046000000b00336596540c0mr3847124wro.15.1703020799790;
        Tue, 19 Dec 2023 13:19:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703020799; cv=none;
        d=google.com; s=arc-20160816;
        b=pD1rrauRTtGQMW5ijUO2DVdcxjD61DvNU6L4eLOCoQLlds79G4ENF6QB2/M0JfGQ64
         Lhe+wkzRq1e/5bSa4JWiWvP758qv5PHuZxH/fx02I58aDGg4LCEAYGqAQ1hXJjnlC4t4
         0l0PEUOOX84F6iM5/sGZ1B8gwy8Z6UyHniImh8+UkmZu32u+mjJFznofNL3+mMQliPgD
         F4UNGb5DNMjfnzkwqa4S0KrXTG33q0b5gEiGdt9xhGvCP72CVDPaMi6FnlsxkaIzIjcI
         Tz5VNaRR0DG+H1zZXYM/BbeTYBAXeAypJ23J6vnANcQRdaBFO34W7wb0YAKmIzO/TJee
         eUew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nCFM+nFcyoFd/gCQWZCb7EKvVZ+qSBSDeoPEA8Jfh0A=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=NZHKtSlvbsd5YlfYB9Wg8C5vGlJgYDlux4aBKrXCBJNC71J+UIzSvy1Xm0pi4UH2lP
         /1monFT/fPQ4peZ4whWal61wUyKQ55mvEVbtOcoVlxS8sw9xMcT/iyLmeMPdxN+61aGn
         xzVooMy2BiwnQCQwL/pAJWbj4lXG2l6WwBkQh/QAz80Z6Z1sET/jlpi3b+Lsp2gZsZkI
         inB1acKBm1dI3TWHGkzs9/36sVe27/GW2zUP5+mctDxsIXnw5Jw+4Fo4mBuvIvnHu/Y3
         iuAZVxcyzXEd+k9/wHTzPATJIrRm5p81RPCfPPMPW4sRn4CF8njnE0S9dA7wlCdUsCC7
         bmJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vWTr3qhn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta1.migadu.com (out-183.mta1.migadu.com. [2001:41d0:203:375::b7])
        by gmr-mx.google.com with ESMTPS id c18-20020adfe712000000b0033666fb6212si259426wrm.8.2023.12.19.13.19.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 13:19:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) client-ip=2001:41d0:203:375::b7;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 mm 4/4] lib/stackdepot: fix comment in include/linux/stackdepot.h
Date: Tue, 19 Dec 2023 22:19:53 +0100
Message-Id: <0ebe712d91f8d302a8947d3c9e9123bc2b1b8440.1703020707.git.andreyknvl@google.com>
In-Reply-To: <cover.1703020707.git.andreyknvl@google.com>
References: <cover.1703020707.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vWTr3qhn;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

As stack traces can now be evicted from the stack depot, remove the
comment saying that they are never removed.

Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h | 2 --
 1 file changed, 2 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index a6796f178913..adcbb8f23600 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -11,8 +11,6 @@
  * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
  * stack traces often repeat, using stack depot allows to save about 100x space.
  *
- * Stack traces are never removed from the stack depot.
- *
  * Author: Alexander Potapenko <glider@google.com>
  * Copyright (C) 2016 Google, Inc.
  *
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ebe712d91f8d302a8947d3c9e9123bc2b1b8440.1703020707.git.andreyknvl%40google.com.
