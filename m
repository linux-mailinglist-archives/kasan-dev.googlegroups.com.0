Return-Path: <kasan-dev+bncBAABBCFF2SIAMGQE5K53NVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id DDD1A4BFF13
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 17:42:48 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id v13-20020ac2592d000000b004435f5315dbsf2899647lfi.21
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 08:42:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645548168; cv=pass;
        d=google.com; s=arc-20160816;
        b=TnEdOj+RxTMQBZnHzMy4AhhygTOdbB5ooWkeDvJ6i5i1tfHGpPR9NtFeigbw3U3yXN
         XfEYCYKYRFF0LFKCklQJFAMVm5pb8mwyOULr6ir18D4+BPQlUDtNsy8lD6fvazyWcuOX
         3wqPH0YwrtHw35UyOvmf2M7eB8ENixIbg5oXoylboQaSzmxfPn5B36HvL8OxTloDWHLq
         FQk/C7tshhmuxQgJXoD5O4RVooZYi3e6ySLJqPu7hLgYxefwnAdQYOkrUI3tWHMi9KGa
         9DAkvh/SnP1OtEOoA0rozMiR9uu1/qchd6JT8kp8VubXkkBjoEdka4cTuHpuN15Th9eg
         AduA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=zgY7o5xTdbyDbrHfBQDS+6crt53NBxVODn2LiiOmhTs=;
        b=kJapWrtkmFZ0W9DrXXj2pUxwKOQwj/25Lh+/P2pZ7Y4Ga3KE4SajND34ArTtkDncaV
         ZMBoSickPJOghZJ0rSYVXx0twhAi1U1jSl1Hk7HF2tQq3iaLT2/0XaOwW4CHuivFwg9a
         cFbCkjH8TufPag2pKvo6f87w2lqSUfsi28UXxLaCGvMsPqbTzxWosJIPtS0rZ3Tpuhy7
         EKEOPxPXDYN+QwI8CmwbUnpqtNUUg+cvnL6Zrg/iFeXfbqO1RsRpq64LnrB4e2thSJZT
         eDXfa1WBWgCKhBkFMvct45iyuc7/w4cZF5msBvIcH+0ijt0uthfYbF63FhdYLYltCadD
         SYjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L0rb8ZSb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zgY7o5xTdbyDbrHfBQDS+6crt53NBxVODn2LiiOmhTs=;
        b=Kc/2fG2OM0HiG7t8LC7yrNuIgnA282PSimwzHsET5QtaADRsFOKCignxmay2AELJzx
         XX+3BhhO2UoxMqvCNDj0EHiha2jcRqfmIdwbXwuhC8Lr9K0prtI/zxneyB2xxaH8q4Ks
         014NzydRIrj9U91gf7jjB07OH8tp20A32mmWZ7MVQCpEIa0c67DbXVZe9Uq25HQAS512
         gDEiEv6b260NgeNcf47+rlpG5oOCNkE0VsYsXXnKAkr0l8ADARlsIht/s54UONpntvHQ
         xCkJvIz2kWe0+es6RAe7ZZli8ZPfhuINs1CkHsYSBKhMdJpWQkjatj5BB7hgoS1lnevJ
         zQ9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zgY7o5xTdbyDbrHfBQDS+6crt53NBxVODn2LiiOmhTs=;
        b=hN5YEBQ5bM6dudP+EW5kNQ+yi3IR48Mrl1sH08nvYjyjiH8hF5BdpbwPhfrYJ9ElZC
         OVg5KZhCp/L2vNuBBKsToSK1fS12TLkHYbi+2Ze92nKzk7atvkoFKPWJOulelG8ex5T0
         EAScMpf1N3gsS64yrWNQ2F5ddnrwtP2R378NbkZ9xtt8ZrNUZjsi0TRfGqYFvcteo8xK
         uWqNvaY8fZoMzraKCUUm9MKAyUu+ArUEEZkFRv794I1KYRcsoa0VasNgeZfmJZGffjqd
         rAqSTqWi4+KAFQYyluo6TDsg7BO9WLWYVlJA4ms4wwqj8gTIVFcny8TfQEPtA67m35o3
         XFaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zl3y+wMmgBmWDMK0PRvRBb4UArFSKvoeG14JxWzrGQPaTeD2H
	XGPzwfIggAvufarNDCX2sgo=
X-Google-Smtp-Source: ABdhPJwuYNblEpkSp4giL6tKMuOlTVbrWHqVYXTtm0h8WeV4FRrigkitXphKeqKW89HDY5Bfb8hXdA==
X-Received: by 2002:a2e:7a15:0:b0:244:c138:7379 with SMTP id v21-20020a2e7a15000000b00244c1387379mr18464314ljc.312.1645548168253;
        Tue, 22 Feb 2022 08:42:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b8e:b0:443:9610:6a0c with SMTP id
 g14-20020a0565123b8e00b0044396106a0cls3027085lfv.1.gmail; Tue, 22 Feb 2022
 08:42:47 -0800 (PST)
X-Received: by 2002:a05:6512:39d5:b0:439:750e:4541 with SMTP id k21-20020a05651239d500b00439750e4541mr16958514lfu.497.1645548167463;
        Tue, 22 Feb 2022 08:42:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645548167; cv=none;
        d=google.com; s=arc-20160816;
        b=w9YdqjaeNu28mRG9RnvBuNm4xraHrbk/sLhd2wcyWiR+k6VTTWd9TzpvaEBCIo6xKq
         WFz5nwn9wm8fcqL/Nio+GGsCbX3megwJmHWQ5+QGE03G/wk43SWIGL67D+Gc7BrWBfy3
         W7YPSwndpk6QVH34dz7hlbWgp1gFd6GHlQ3DM9wd3k1jHgGMX7y/b0xymbxtUt7TM0Ix
         kF/DCIQf9ELxnAlXo6OtB7iujcjAwf0+FEsWXZxlIJEmRs8nIWCU1HgIhcLS7QqNzWau
         BEV21xKdxbwWvk++d0eTVc15BrEMLrKZ3goSsXjBnkbMZruJMW8oSdeEegH84YyAvznh
         IqOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZEtbE1Y1jeIgzgzA2TFDElC+yLbMe5ouicxIZ65PMO0=;
        b=hPgnAJmWCOSOOkQSMLprQexAEpxQ98CONI7ghm9gbD40VfZ7vropZ+xowmgPYs35Dz
         Zw7aXn0z06jVuFA4SxxHeqT2lWmGsJYLLhhhTGVXofGV/Y3ZX/wWJnsqFUFTvNql2wtf
         63+N32qQrg5Hp9TWtni1/fnqcpU3UELnSwD+xFOQBmNYoBYnT4Qc34xvEsJhzrlCaBjh
         j8ki8O64PM9KKXZraVimebjbYMsMRv8OWWiE9qSPDWQ4Tt0AUmXHNPuQNYKWca80v61/
         Sh8FJ2DLX8IGkBmqDqMPpUkfNLx3flISlkUT6yFVjTEe7gM5UVE0+l7WFLxpZLZGhm5b
         YVDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L0rb8ZSb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id b40si260410ljf.7.2022.02.22.08.42.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 22 Feb 2022 08:42:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] kasan: print virtual mapping info in reports
Date: Tue, 22 Feb 2022 17:42:44 +0100
Message-Id: <6ebb11210ae21253198e264d4bb0752c1fad67d7.1645548053.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L0rb8ZSb;       spf=pass
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

Print virtual mapping range and its creator in reports affecting virtual
mappings.

Also get physical page pointer for such mappings, so page information
gets printed as well.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Note: no need to merge this patch into any of the KASAN vmalloc patches
that are already in mm, better to keep it separate.

Changes v1->v2:
- Add find_vm_area() return value NULL check as suggested by Mark Rutland.
---
 mm/kasan/report.c | 15 ++++++++++++++-
 1 file changed, 14 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 137c2c0b09db..f64352008bb8 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -260,8 +260,21 @@ static void print_address_description(void *addr, u8 tag)
 		pr_err(" %pS\n", addr);
 	}
 
+	if (is_vmalloc_addr(addr)) {
+		struct vm_struct *va = find_vm_area(addr);
+
+		if (va) {
+			pr_err("The buggy address belongs to the virtual mapping at\n"
+			       " [%px, %px) created by:\n"
+			       " %pS\n",
+			       va->addr, va->addr + va->size, va->caller);
+
+			page = vmalloc_to_page(page);
+		}
+	}
+
 	if (page) {
-		pr_err("The buggy address belongs to the page:\n");
+		pr_err("The buggy address belongs to the physical page:\n");
 		dump_page(page, "kasan: bad access detected");
 	}
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ebb11210ae21253198e264d4bb0752c1fad67d7.1645548053.git.andreyknvl%40google.com.
