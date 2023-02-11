Return-Path: <kasan-dev+bncBAABBYPRT2PQMGQEXQ7L2UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DE52693216
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Feb 2023 16:48:50 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id g14-20020a056402090e00b0046790cd9082sf5218148edz.21
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Feb 2023 07:48:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676130530; cv=pass;
        d=google.com; s=arc-20160816;
        b=nwDwDmW5caGEbdQ8LUUaeEK0aT2jx+O17XgY2mURiqEy2AyWiK9oAX18BUDEYMgCQO
         rDUOezneEfIF1G1z9p2QGg6kvHq5JGny7acoBV2dsPBVnbjxdEltZu/C+LcV4+cm7kh7
         9cUsp/eOjx3rEMQLr9Frn6emntq0pCdxWwBdQo+O9Fe5uIgBPZ+a9NuxTMhZO20+gfWW
         5M4RX1ejtUPZMKVQveN+rQk0eCsyAW5rPScayTcqVHzqYqwo2CgvGkb2E/vHxIj0kAfm
         Ljf3DguV7Z9bgebLl87Rj3LGjtBRzBG8vNZrloc7jAy8dXYx668vdwBVkyr0CoGbVGmB
         B0Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4XZIk+YFc+5yJkFcEQQv06VczIN1TpBrJz4w3EIF0j4=;
        b=BYq/iLtbo5JNg55E2vRz2Nel2gqtCyi+Mufcby6RrHDAF6QWAEI72Wn9SF2AYyReMb
         WvdYhGEFYU72m10BTEoWSv37sYdIcw51pZ8JL6+LMOnl4Jt9iKaicnv/cGxndSXwvZe2
         a2w4j6kCtXIzyJldJxNl5ZFAID6ozaaWTh01QxwtQ8bve1qQU4+d75xMiGVl2c4KikA+
         FFbfcNG0CU4KCYi0zOKhFJlf5YMccQIW4yivCe1d9H7L32x8TShrW/3IMqZPeY7LclwX
         SXsJwDdsjbLnvL2dQOra8UguPCAp/gT2Hfb9HrJof0uKW/efP0CfpxQuPo/4GZX9Im+s
         elnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="cC/ddxCb";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4XZIk+YFc+5yJkFcEQQv06VczIN1TpBrJz4w3EIF0j4=;
        b=pXKb/6TGQOOCKuEYSDVAuX5ME9Tz1htPrnpSvM3e+GYbLTRimEE2ElhO8LGeQGZHAX
         Ud1GZPdCYTlROSPsmagQcs+ag5jj7h3LfVvem6iJ/X5Z0tsBStb5toIWYI4JI17UkvyC
         YmZ8QUKNIUwVlTarsbzzOl+9OJ6QJ7HUhANkD+Xk1EZL/fPwKczcOGabmvpWe6CNIzhv
         Yb6kgU+OU10gzRu0kDHrPiuByKS4m5wfUuTlEFFUUbL1skAhgpQZztNOxmfhsHzNVKqW
         qDHRRmjwRKloE3W6GMJCsmW+PzczL2zL+R6rVAw7WGKnB+AzAym5PiHVBQpc+03C3Uxi
         xTKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4XZIk+YFc+5yJkFcEQQv06VczIN1TpBrJz4w3EIF0j4=;
        b=HQ9iOQl7KbUbQ1GW7IQbqRShOCXiRqw/YwQ+7+zJf4TNFubiBswIafwrta1HGRIXFg
         zM7WFHziTAAVd/RJPtk3rDaXNpyckz2DQLXMhui3TNRZ0fyrcx7hwrnP2DEselWUVF48
         LW99/mMFWkmOhlqmUMH/YEiwadF8QfuPZ7Uqqx+7xZ2DEzt/R96x/bAzre4pXhrtN91h
         MoySMWAq/IXWxbZ1h2AihuAGQB8iD7X0IWrQwto4P0eUhjc+jxAiAx1SRAUIxXFHR0h5
         7qIU+Mxg6Nw/+5WQag09QaOnnY0Os2eBh1QIQBOiZ/31U7x+zrDhQRXnzdwruwf4bXka
         wMjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUYUU4hg9LoBa80aPXwuVvXOs1+pd24ITlUFL/n/dpl5rLsChwj
	Eo/v786bMG1Hy2a2M/oqQ5E=
X-Google-Smtp-Source: AK7set+GfT32LIhhFfsYmcmdzQh47Zd6HeI1HSMwUoCepKBb3PrORNiEUq2KqQrkWw3hL+P0w79w5w==
X-Received: by 2002:a17:906:7147:b0:878:72e3:d7ad with SMTP id z7-20020a170906714700b0087872e3d7admr2412364ejj.12.1676130529828;
        Sat, 11 Feb 2023 07:48:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:358e:b0:4ac:b2c8:698d with SMTP id
 y14-20020a056402358e00b004acb2c8698dls2932764edc.0.-pod-prod-gmail; Sat, 11
 Feb 2023 07:48:48 -0800 (PST)
X-Received: by 2002:a50:d081:0:b0:4ac:bdae:9822 with SMTP id v1-20020a50d081000000b004acbdae9822mr781439edd.12.1676130528868;
        Sat, 11 Feb 2023 07:48:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676130528; cv=none;
        d=google.com; s=arc-20160816;
        b=b/WhEmhEIlzUuTky5+G4sRM6hc1YbyI0OvPUWlIP8AneeHs9iuFhILUC5pJd0EMOyD
         exfvfb90ciJmlFssNO0jlINYSu0JNmdV+OxHYDcYy17oxThUcZB2UH60j8Eb8vEWk67W
         /5VuM5DPbVqexNSbhDN2c6NcJmqu7GY5GJNIR61i00TMrCSYFr/xXtogg1PX1BzCy3WS
         MVz6rQrRgkuGRJ/ejQdpsM2w43RlHizHeMV0zGxCDheJ+WS1NYpZfYXwpfvFa8mBiosH
         m94TcHvJdw5MgndNySY2GQTGcnzVNN0WYJ9/z1+GxzGtR/ArtnvgLRfY+bFdljNu80Lr
         HPEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ePdADAGgNuPhLaxQ+Eg7zNcrIY+/1S9vDM4BoYe1IWA=;
        b=cKZG0BLazBrnlDC23Yb1C3fVbCpNKRLgv00P4TL9B+n9GENF0BhHgd3L4TngX1K/tH
         7+6vFF73TblJlyaHLrabojqYVHVgHEvEluyWvq/EZ8+Gee0G/hJYRI4vwrIPrHLQNhf2
         /smZfV76GbfXM7TYOYfNtPT0VZmCnwf+9gAruGOoecGa+6AA1hqUGCsUHyaHY8j0dgoQ
         ymFToK1X8NvfgujOo1soJ+6BebuFiq+ZfxCl7KruyZyrBkeaAMcOkl0KIWEaPzf5Sglt
         xdNScirrde3EWuXGNxP3pAEZIkxGh2cly9a3yHebFWowfQSM2do0Cib6d6rIU5jv5dAT
         oHtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="cC/ddxCb";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-191.mta1.migadu.com (out-191.mta1.migadu.com. [2001:41d0:203:375::bf])
        by gmr-mx.google.com with ESMTPS id m26-20020aa7d35a000000b004acb6374876si89458edr.1.2023.02.11.07.48.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 11 Feb 2023 07:48:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bf as permitted sender) client-ip=2001:41d0:203:375::bf;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] lib/stackdepot: fix for "annotate racy pool_index accesses"
Date: Sat, 11 Feb 2023 16:48:42 +0100
Message-Id: <95cf53f0da2c112aa2cc54456cbcd6975c3ff343.1676129911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="cC/ddxCb";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::bf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Change the remaning reference to pool_index in stack_depot_fetch to
pool_index_cached.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This change can be squashed into "lib/stackdepot: annotate racy pool_index
accesses".
---
 lib/stackdepot.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index ec772e78af39..036da8e295d1 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -470,7 +470,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 
 	if (parts.pool_index > pool_index_cached) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-			parts.pool_index, pool_index, handle);
+			parts.pool_index, pool_index_cached, handle);
 		return 0;
 	}
 	pool = stack_pools[parts.pool_index];
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/95cf53f0da2c112aa2cc54456cbcd6975c3ff343.1676129911.git.andreyknvl%40google.com.
