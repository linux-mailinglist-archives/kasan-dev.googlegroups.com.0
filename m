Return-Path: <kasan-dev+bncBAABB55Y52VAMGQEGLT5O5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id F00717F1B8E
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:50:47 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-547bb01fec2sf3661135a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:50:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502647; cv=pass;
        d=google.com; s=arc-20160816;
        b=kFT6bHUxhQv6lJiAozgiJRNoflM3XE5Exz+9FHnl78AbHgvy4PLS5t9S7qGBmhtc7Q
         Ho2Y7hEg2EJt3t4YK+R95thdFZKpz7EVreg2b9QYgrHab1CisExQImgtXH7O4tZwGxuP
         tehpy37IMK0k+hYzjSImzmfBc7cdlWEUZ5eeXJBXRu/bR+KgCsZbuDPn/GP3tcVdX7X1
         +NyMvbFq9Dr5A+rUeaBTxGQmi44lqI/kE05F2l3Lk/ip6dOdIihCwJ+gAeYje0JZQBZM
         YXHOBDZj2UNXNP9Zs0wsbMNLseOMs/9v2IG+GT13kP3+hSl1f3vvrXkRkFOIFMrXlyB9
         aK8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/1lVY31CvovkUvXF9TW5fQmbCdWvxgJ/xoHYCCaX7lg=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=KUDfgxYhM4Ge4pTXINyGmBHTguLe37q7do1hKN3rsm1yqc6AyCZNoQoYP2nd1/Aeb2
         Ff0qDpxrj93UqpmDX/qvfvYRsttiEKFnjTkbbZkquqImLTENAiVYvl+QuEazNXzaAiA/
         QESHcRscrVtKe6lBofUDn2+SWb/chWnS0+5iHgDC62arswnZeisooMM1wlW6V05/H5J7
         S1ziCikmiHcm9bsZrUBfRNI4SxOctxcVrM9o9ryHFZO3dgxmOFIONn8KfNIUcyDbf3aq
         t+jWqSsptwRl7WIjPma4ClZ0xnGLu9ogFON0KnGYqUvoW7AsySXZE8i/Wz0OjxmJj3sR
         fnsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WmK6Qhek;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502647; x=1701107447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/1lVY31CvovkUvXF9TW5fQmbCdWvxgJ/xoHYCCaX7lg=;
        b=TGTuSG33dWQ8h5V/vIhuCUS2rIuUpwi21ut9FHgh+vyMhmxO8GNc9LfW7R9YFEigUh
         OG4Ke11paBPJY+0F12zoSaYgBayoQuRZj8Klc9zLQ9c1MWJT+zPETxnkexetrIPnLICu
         I+h3skccx2bTlehSMt+xOBAhCuWAk1wE8wnBnOpc8ejME3Z5ndA/FsZYR/RGGkqtRHO8
         z+m7/dwsM1p0kFPM/L158nMOL9r0jqHplVX99GjHa9Ttn5WJn13fgRQ34DvRWBZZsTK4
         T5yvKAIdsBvMn8WxKlnK1fHCxfqK6P/AeQWNcR/EKAsnkVfef9gd+ekz7CjNUWLhaOba
         xTBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502647; x=1701107447;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/1lVY31CvovkUvXF9TW5fQmbCdWvxgJ/xoHYCCaX7lg=;
        b=xFr1bpZi+B+JxLgfKD4iTlQkNrLOdEN2EIALP9xDEeO1lJCTP9k3fIf4qA3DJKTltV
         97u9xXG5tYSDF3gXoj5SfOoO5Ac92iX9LqSSz8kk7UP8MUaidy5lyHCLTASco/WShhIO
         ZHz2kM03F7uo6W7Tm2H0rfFdjlEIM3/upnPqf11Kf6+9sjUimP3FOlFnnPGMdbnt26eg
         HB9i0TiJGteXA+k08hOYw+ddbAiS4ftZ0e84vmWWTS7yD82IVA4WLhGJ32shvxZFYr3T
         9tdYu/3q7kLR3aHOWsMDrLHa3KBbDY9SOyMQa0cvdaDsL85NsUhHiChBimg1BV17InUx
         3wjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyLRDsr9SHAYE7qqIvVSMbjT4K7hsvrHUBcwzp+ZJphJQG+vvR5
	5kjYvfWX3hns2BrqNIgUTgY=
X-Google-Smtp-Source: AGHT+IFSvj/pnxtbOgykovbechLvMGAsY9wR0+esOoy6zOrnLBwMqZMS9kuEaQMCaMPjOdGWUDxHzA==
X-Received: by 2002:a05:6402:797:b0:543:8391:a19a with SMTP id d23-20020a056402079700b005438391a19amr74969edy.40.1700502647424;
        Mon, 20 Nov 2023 09:50:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5487:b0:544:a163:413f with SMTP id
 fg7-20020a056402548700b00544a163413fls296969edb.2.-pod-prod-08-eu; Mon, 20
 Nov 2023 09:50:46 -0800 (PST)
X-Received: by 2002:aa7:c994:0:b0:543:c50c:cacc with SMTP id c20-20020aa7c994000000b00543c50ccaccmr73733edt.41.1700502645651;
        Mon, 20 Nov 2023 09:50:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502645; cv=none;
        d=google.com; s=arc-20160816;
        b=hPAXgAay1YYND7B41VIR/uZxfzp4NYm4b2Rcty5InVEvGw/zByfdWF6SVSt1cTrDAs
         ylNRTm5CVqHYlJCGSDa908ibTrDzV/OnOdQFJrk9c0/vbTLPzxDlnlEgkYwXLadfp811
         /Vb7xuJIHxrgqRoB9AihABGKLtG7weRq1RZhAKkHFAY5Np+wanuFnZvmgFyra5cNsJw2
         klIsuWUigZvqHGV3wTcFJiBdNcFAefrkX8eAOLu+FhK9vKESdD40bPyGsn8i3aFk6xP2
         s4K9vBMcVTkRieVZITQtpyGX+u1u5blgn/SrRslmF7o7PvP0B5vKM+Tbm66m8TPIJw1s
         OXgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mWJyEm6VyaOWhREL8AAhhvtbKxcDTX0iHOdq2I7biaE=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=Z3kgq+zcnVbh75OcqTdILZoRsbCoF5moxLNT1mIo3CM+h3VCn8MPZfOH5c4F2kqFYI
         ym2EIaSccv/GEEz8zUJ8To27JJcX2M2WDvyflWgEei84H1NjassYIDBrwbljDHk5mu0u
         UWoGtvuM+XWMfhRwhFb0rJVUGlh2Nv9V5qcJaoWP/FW/q2+nveiqQ4wfoLapAaAiRKu0
         HXm1Yh/pjf1M+nLrttINEoo6FMPLPNBz4g2jl3r1d5Ku3QJuXexTiiLhfG3e3PiAVYtq
         dUR6CZZ5mb9ehcXvmEM/bGN0eH16s49p1Jkk2+P6qyCj4cj5nYPKC5KhqEL0I9GDyJZI
         OB9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WmK6Qhek;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [95.215.58.175])
        by gmr-mx.google.com with ESMTPS id h21-20020a0564020e9500b0053e90546ff6si329863eda.1.2023.11.20.09.50.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:50:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) client-ip=95.215.58.175;
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
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 22/22] lib/stackdepot: adjust DEPOT_POOLS_CAP for KMSAN
Date: Mon, 20 Nov 2023 18:47:20 +0100
Message-Id: <301a115cf7ce8ddb42ef6de9151c2bb76ba728fc.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=WmK6Qhek;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as
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

KMSAN is frequently used in fuzzing scenarios and thus saves a lot of
stack traces. As KMSAN does not support evicting stack traces from the
stack depot, the stack depot capacity might be reached quickly with large
stack records.

Adjust the maximum number of stack depot pools for this case.

The average size of a stack trace saved into the stack depot is ~16
frames. Thus, adjust the maximum pools number accordingly to keep the
maximum number of stack traces that can be saved into the stack depot
similar to the one that was allowed before the stack trace eviction
changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index c1b31160f4b4..870cce2f4cbd 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -41,7 +41,17 @@
 #define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
 #define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
 			       STACK_DEPOT_EXTRA_BITS)
+#if IS_ENABLED(CONFIG_KMSAN) && CONFIG_STACKDEPOT_MAX_FRAMES >= 32
+/*
+ * KMSAN is frequently used in fuzzing scenarios and thus saves a lot of stack
+ * traces. As KMSAN does not support evicting stack traces from the stack
+ * depot, the stack depot capacity might be reached quickly with large stack
+ * records. Adjust the maximum number of stack depot pools for this case.
+ */
+#define DEPOT_POOLS_CAP (8192 * (CONFIG_STACKDEPOT_MAX_FRAMES / 16))
+#else
 #define DEPOT_POOLS_CAP 8192
+#endif
 #define DEPOT_MAX_POOLS \
 	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
 	 (1LL << (DEPOT_POOL_INDEX_BITS)) : DEPOT_POOLS_CAP)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/301a115cf7ce8ddb42ef6de9151c2bb76ba728fc.1700502145.git.andreyknvl%40google.com.
