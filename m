Return-Path: <kasan-dev+bncBAABBMVQQKJAMGQE6TFAOLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id A3D974E8910
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 19:00:34 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id f2-20020a50d542000000b00418ed3d95d8sf7741893edj.11
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 10:00:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648400434; cv=pass;
        d=google.com; s=arc-20160816;
        b=vxL5sEW2JKu5fhv3JR+9bJ5VdiFvt+lyM+Uy0GBjziu+u6XWenlhMtaWTZ83mrg/jo
         Upl2JPIWxx5eHm3HO8D3fQKXTkhuKSGnqYLqZvR2Lb0ttrrBCeUrpQfO2b+80pOqsyeJ
         lzzBc6Ph8236S11OA4LLSaUPssl6tQ+tOFJA8JMulJsxXu1sibTub//OwDOi0WGmQ9hL
         d6tbPB9uJpDOhiSYk+bP4Q5EzFJ5t8ABigNFLvjfjO87tCGfQAMzvYTDUUsSNSlKTgYS
         KsGXYX2k8rVJHMP47UifIC3XLdXp59FHEZMW/1G3SoFMJYRcCsTEQR6egxeNQvDzvmDa
         lqIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=A75zxtrPjPGnV0S3hv3cZ2d/XX+AjEQ2r9bvUa+sBzU=;
        b=kExN2rhPjpFYdhn1uy+YxkTHPT2bPXejrgZ6s6J3lgvSDd9x4uqiinhD7ZH4zeJJOY
         AaxkDNjPWSUARsYCjyuOjbn+Zaw2i0eniVapZWkmcNwGxi9ugFR51wYqhEbjRYi04ByR
         6RgaZaXigCLr5ve8WYbj2h5EOf3exAQDGfD9JJGBbX5dfesksJlv8I0QPSW6f1kLen4X
         rpwblykyKyjFjxl6Y5RguJps/sfC9h/imYK+RKFfdMSsWQ+qs/m4otZHZTtpg3nxmbBt
         xjD1wrdjBAFhcFMjw4BeJ+1jWxLDjKYfq7+V8irpwPjt2Hw+Hmw8XTMOnCmLOkLk6rvu
         PF3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iphgMXGF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A75zxtrPjPGnV0S3hv3cZ2d/XX+AjEQ2r9bvUa+sBzU=;
        b=tKDn+hXd0bDdPvFBnl4t3HUI88dWIWWaJgp8YkW0Fx5Yr/bsnROjsjsnppVm84UOid
         8rQ1llBgHGp/5dsyO58gLX3KleCEcQqgvZ6i8GTlm/HR+ghs9luufkfLF5OehcnFP57F
         25CgPR8kmyfFFwz26UGDadw+Zx20LxUSKU75Pdd11HNCUKvGHG2b+7XQsmh4UZRKPtlv
         cNAOQHOJvGOE4BijWroC2VxZ07BTEjfRqorXRODTJ9irsZjvwEpsDNj97DVnQT3Pn6Lx
         QOMDt3TRk6jV7bgtIi/+dQVBJ96wqyQrl/mB7yvv77zHiT1GoPCVeiK5rNktnAMsVb2s
         4y3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=A75zxtrPjPGnV0S3hv3cZ2d/XX+AjEQ2r9bvUa+sBzU=;
        b=r4Tbrj1z4c1blglvbFqUEVvq7QDoKtFREcI25FG2jv3iiClXI6N9KeSVfdavZ7CLDh
         fHxCIvTfgVa3NNkvPZMkvwahKAKGWDxZRvwcnQl+deDAqrM11hIcFUJi4apqLMP552/v
         4BseUCIj6PwqRpWmphYIymh+4Aga2HYvPwTEenSeDeA5SmuDDseijDzTn+/azrY22Yzj
         q5NvXAM/D9E3n7eT1dbLuLqQupbQii/s11vOKrRH4l1C/Py827BAnxAGPEMX9lMSXqNC
         eNdwjJdwax6ktpbGC50opGnOPbYcByNhYZiaVBDQ5AkvaDoqJjPJb30NiDbt0Nd218f0
         pxEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530AHkK+oz8SF2gpDYh8YAaykYpeOvbE5XJ8EH+jGU6kQJa2oA6W
	talGdDxGeLx/r3f6zOMUCyI=
X-Google-Smtp-Source: ABdhPJzW1slXihAgmJaO2a+pVC1SPCNIHwOVjSsTxiV+6pNPqqGMjSJBctlE7n/hVcDZqaV40RYtDQ==
X-Received: by 2002:a17:907:3f13:b0:6e1:143:59dd with SMTP id hq19-20020a1709073f1300b006e1014359ddmr3172593ejc.341.1648400434304;
        Sun, 27 Mar 2022 10:00:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3ea6:b0:6e0:7fa:9d11 with SMTP id
 hs38-20020a1709073ea600b006e007fa9d11ls1919303ejc.5.gmail; Sun, 27 Mar 2022
 10:00:33 -0700 (PDT)
X-Received: by 2002:a17:907:c018:b0:6df:fb9b:e6f8 with SMTP id ss24-20020a170907c01800b006dffb9be6f8mr22386841ejc.495.1648400433540;
        Sun, 27 Mar 2022 10:00:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648400433; cv=none;
        d=google.com; s=arc-20160816;
        b=QPM3QPF1+vwE+3f0OprVD55YH/kQdAOSS1q0jt2M2ZmiOcT5Xg2tGPmOBPHS/j0Fsu
         oipxkkzq8cK7RLNHJaJu3iNY4jqDlfSYXkA71v8zEOFbNta+U1HDShUaFAIXPcgDu+xb
         CoWzlbJrTseI5njlBBY0p1p+9oL7k44MNKbg5PxrmHC84h5ebzkbTvXrhnmfr1OYz50t
         /4zN9U8mjq/QrnZfhPIFyt4Rs+p2nGRLFyNR5EW0uimYakuywE2p6XzzrgM1zwQclJZb
         Vg79qxldMq42FBCX8H807mKmURdsMVorNnCu8u0P9xVyrNhj1gjWWqOYcmnzsSe8KtqE
         pQZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=mNdfGwODQpy307VgfLm6WxBMSo9tvm6XjaGTK6OBfVE=;
        b=ON51+HAACSBSWEXWr2yeZS2Niihw40GT7zldSD4jitXbkIiJH+nqodVoDCyrFcH1Ye
         6p7apCEr6KXk5qgG9Q5OeCktDhD6ZJErEOSMdjf17Rc6i+0cQzHkhChgveNQJPHBON/q
         PMo4BbVbPLX3SQNXJNBXvZSsnB0tW6vo3DnX0nuTYEAP95OL0x8SMsmlW4t5KbSGFT4Q
         +3zVXf8NPSwnr6zY49ILADfugnLjlY9KBcy57CIrQEDdni96aJIQikAS93UgMuUw/Y7V
         0Hl5EEAIJR5D4xBH0dQbUBkOEuf0O62Ad4SZzBFR4iq/eMMIZRjuKV4PdB3zD5ax2d7d
         pg0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iphgMXGF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id g3-20020a056402090300b004197c1cec99si559565edz.4.2022.03.27.10.00.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 27 Mar 2022 10:00:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
	Vlastimil Babka <vbabka@suse.cz>,
	Matthew Wilcox <willy@infradead.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] mm, kasan: fix __GFP_BITS_SHIFT definition breaking LOCKDEP
Date: Sun, 27 Mar 2022 19:00:23 +0200
Message-Id: <462ff52742a1fcc95a69778685737f723ee4dfb3.1648400273.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iphgMXGF;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

KASAN changes that added new GFP flags mistakenly updated __GFP_BITS_SHIFT
as the total number of GFP bits instead of as a shift used to define
__GFP_BITS_MASK.

This broke LOCKDEP, as __GFP_BITS_MASK now gets the 25th bit enabled
instead of the 28th for __GFP_NOLOCKDEP.

Update __GFP_BITS_SHIFT to always count KASAN GFP bits.

In the future, we could handle all combinations of KASAN and LOCKDEP to
occupy as few bits as possible. For now, we have enough GFP bits to be
inefficient in this quick fix.

Fixes: 9353ffa6e9e9 ("kasan, page_alloc: allow skipping memory init for HW_TAGS")
Fixes: 53ae233c30a6 ("kasan, page_alloc: allow skipping unpoisoning for HW_TAGS")
Fixes: f49d9c5bb15c ("kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS")
Reported-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 0fa17fb85de5..761f8f1885c7 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -264,9 +264,7 @@ struct vm_area_struct;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (24 +						\
-			  3 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
-			  IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/462ff52742a1fcc95a69778685737f723ee4dfb3.1648400273.git.andreyknvl%40google.com.
