Return-Path: <kasan-dev+bncBAABBKUAWOIQMGQEN2VEJRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id CE78C4D6FCD
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Mar 2022 16:45:46 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id ga31-20020a1709070c1f00b006cec400422fsf6415450ejc.22
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Mar 2022 07:45:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1647099946; cv=pass;
        d=google.com; s=arc-20160816;
        b=atPWPIirdt7rt1U1Y1EmoL+22zzxyLC7z+UF8xkz+xO1KpLOra1rDZr4LminF1R/fB
         hzHov9UVnNEoHU7RdyRfqmf33YJQ8kvxOlcJOFysdByTp9TnwSAR6oVllD2ijTQXD0N8
         gWDWg9fTqqKDMxQtzE5v+hHKXtAEqcVT6dNM3/LkqYxYVQKkDnbade1dty4ka5tL+7UX
         uzqeEPod2kopXhW6xEQkLMgPig1hY1H3KQR6P3mWoH2pM3p5Z8YoSAbDRuAqE7aBmO2Z
         0oEnwYoIk8e0mIQAU22M7E1wJGQLkT2wsvJJmfCo5MtJH3AX8+OolIc4Abt032ARBEY4
         oGCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=n7s4uUpgjhNh/TrsVUHl0kGmlWSSvLj6hR2RXLMSB98=;
        b=RXcyZF/J/n9VCtc4N8DBCxAGyn2VI7sDemHYvyK/h7nSSmMDLkVdKbVynsOmZlYENf
         z/dR/HAvgoysMVv+jtqPhUzQdu9HbNQEcTVOj8/WwyPvppO9NOQc23b9e3C1fGPbsyFw
         Qq7gFvxMKmtoICuWFHfzeAfOe4oR//XCMTZ4QyzXoT+n57umOXW+TL+/J/Hj+J0bcXtB
         406wlo40Uo/WLwh7u3bf3STE05SnYNlZzV9oz1/cckgPE0j4afqFNgL/SXvj6Rh5Sm0c
         H0gZMKroVzErhBBlTcZYwRBFdsVyjBNVo5VTNoa9AibfrwiXWa/VMcJ0J3/56szVU8/b
         JBag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=migH5osF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n7s4uUpgjhNh/TrsVUHl0kGmlWSSvLj6hR2RXLMSB98=;
        b=txfdYhUj2Ql7wN2Rle2WWi8aos0EEK0ACWftoHDBe99EbQeAw6sxfws9UHvic+8AUE
         BdqxyJ6BIqH1FKRaDrF4m5q8Q3nM9QeK7NryueS/9MD/FrhYTEU0oTJQ42s4tVpCBoAF
         gp9YHNcvys6ZnzWlNfpke0I/hHXguHQOlsPIsIuOhv6o0nqHCGyH/bxIcxrbTGPTxrn6
         BBXSnt66jIuvNxHYLaflkNsBx8dDlKKGvshkWeTCfrtWOkfjBV2xAnaXdtUgCW6mgASY
         1rhMa5Ne98JapP1ijaF3G3zExxtvQgQ6UpdQ1pVOq+x8WqhD0B0jDifPNc+vS3+4yyev
         1vRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=n7s4uUpgjhNh/TrsVUHl0kGmlWSSvLj6hR2RXLMSB98=;
        b=BWeH+tlhriJmV5q+/8eiCJk1hCtrkkUiOQxW1Rkp0/hiqrZauP8RwF0grd1vIGbpx4
         XjQC40DwtsWxo4vFNKX5h4RtIuDPyhkeki7p7bGYSiWZatgZn4bwcEH9UYH+/4zhcKxs
         TDmez8PN5anBVoHWHftIj2rKraAfpLpeuUMMzvDwg5VGje/4YkiOMf4duF2TZIHewLpN
         8YUqcCiqYc6IqiLvCKfbBk9LvU2EQj4xlqxZPrduUOw3ODf7j/98Kxc7Vrw5vdaU6cRv
         1BMYDKw9k25wNDUSht5yQEa7kiUJGztgG0WuFJwLEjpjl5XGfiavlDQ9wOXheu83OCjX
         AUag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532wh3XSnIinsw7DPokkawr029gttLey05CnvL4nhk8s89pm5cZD
	yjI+rsTQ4XiuWxBqfgXQ8+M=
X-Google-Smtp-Source: ABdhPJwO6F0XABw0e5h2RnpklEJQe1UMuD1yBByVs+JTYnR9TZ5Bk19Hh1AR3/AqQl4AFSgmB53rRQ==
X-Received: by 2002:a17:907:7da9:b0:6da:866a:3c59 with SMTP id oz41-20020a1709077da900b006da866a3c59mr12848299ejc.13.1647099946488;
        Sat, 12 Mar 2022 07:45:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4c96:b0:6da:fcca:a047 with SMTP id
 q22-20020a1709064c9600b006dafccaa047ls2148832eju.10.gmail; Sat, 12 Mar 2022
 07:45:45 -0800 (PST)
X-Received: by 2002:a17:906:1603:b0:6ce:362:c938 with SMTP id m3-20020a170906160300b006ce0362c938mr12525419ejd.253.1647099945647;
        Sat, 12 Mar 2022 07:45:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1647099945; cv=none;
        d=google.com; s=arc-20160816;
        b=xdJDPMJC/XSo6GJKGWbCf2b1T5fAJ99EsfuBTWOWnLDTrgBo9VQD12yFF1kKnVgzyV
         agGDvMpSkFxWhX29CKnNTb+hL4/HhIn6xOWOgnqw5v+dOfutyh7M6K39s0UZkT0GzLjI
         gNV3rk1CyegHyGwPPZl6UnxnjjHArZM82FD+NZ0yFtvbFhYCozm94vBf5CBjmd0p8n+k
         1pHbXEX+5mtJNKn/EA24+p/K7JNZFuHtG5Tod2KJwESCqgb5uWFA5mBZHswEL7ZAHtHT
         dXdIf2RV000HhJzUcJOqemNj2HQTgK760U9+evJ6j8xPRPmmQsBzgJ4AUDxjdMXm7Ugn
         DQ4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YtbCAnJ5abXcprPbTV1RAyWaH18oFJblxeHW3cll9LQ=;
        b=SLNEJOQksPeGT7wlXuIeGSkNldoQkTDd+5Ct+Fj6HSMRDI3KTMcZLCFmbsTTvsjqzd
         n69G79cIWB+VcM7WF40Egu56wJsTVSAIFdtYIRPHTJDznmZ7EAGA++YM6zGahbyIUX+i
         QSVZGgFo4Sh1Tdrcg9kCvvemTqF7atp/yR1v9iyU1o8H0Lsm/oPO6FvL+Tgl7gfpX/AB
         Lf5zGX7XJhkPn8n9VQPDaqSuLwGhy8l4qHdoBqCVBASX+yW1Zv2Kat6mlWGJJeu8DDY7
         xTYBTxtmWzqxPLhukgbACp0gtUBWge064Jq9R5oWsNOWEVbccIMEKakeBmPbu+Cfptje
         tUgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=migH5osF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id s7-20020a05640217c700b00415edbdf697si713404edy.5.2022.03.12.07.45.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 12 Mar 2022 07:45:45 -0800 (PST)
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
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] fix for "kasan: print basic stack frame info for SW_TAGS"
Date: Sat, 12 Mar 2022 16:45:43 +0100
Message-Id: <d7598f11a34ed96e508f7640fa038662ed2305ec.1647099922.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=migH5osF;       spf=pass
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

Using object_is_on_stack() requires linux/sched/task_stack.h.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report_sw_tags.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 68724ba3d814..7a26397297ed 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -16,6 +16,7 @@
 #include <linux/mm.h>
 #include <linux/printk.h>
 #include <linux/sched.h>
+#include <linux/sched/task_stack.h>
 #include <linux/slab.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d7598f11a34ed96e508f7640fa038662ed2305ec.1647099922.git.andreyknvl%40google.com.
