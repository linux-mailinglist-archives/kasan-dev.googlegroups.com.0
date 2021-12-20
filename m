Return-Path: <kasan-dev+bncBAABB5PZQOHAMGQEPT4JMLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id F05C747B589
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:21 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id v190-20020a1cacc7000000b003456d598510sf225018wme.6
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037621; cv=pass;
        d=google.com; s=arc-20160816;
        b=KENkS1L0dkkX2y3gcXnrrSLuO9XVtL6IrZCI/orTKq0IRAY566gLlfYsWJCATQKgEm
         vsKbItDKDihaf1rGD1IOPxh3jgwbnPn8e+YVyNq7ma+x7WvIbQ+GYcg5ssM5k7YRei6M
         sQ0KsGthzITXXh+0Xu6KuQN5zph/8FsWc+StEFzLR4WNvCztRZ7IT+nBz90oP9p6NQBv
         z+sqydf6/2fB7gS4kCPsFHPUGvAcuLH2Cn4O0474Nb8+rlB/jZPd++7zexCZobVk7cbb
         ve/zxg2b/9XYVRV95h8VPYjFn545uD6D7AdRsVJossebrbFwN478JQkmQJDE58sJwC18
         UTVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ix9i8ExQSsO0ltEpbnEdiBEwp3KUfPzNjmNjsIewOCI=;
        b=WJG8zXGJ4WwL9c+Byr9gapjqHoymskiv5ogJWrOmjylmOySW5dnSWfgUfAq50A1ycp
         ra0DRTZlGEGIDeQX09eAdtqaejuvl8Cs+cEpgvqA+OxzrO/n++pc6kM5/EQYzaZuPJNy
         i7K+ucEJO0U3Njm8WViC9yz3M6OLfZNKaBSkjGLeqNE01K6hLrP8exLiUIgSjYtrur1O
         ZNqxOA3WcVBd1kXbdusUNSvPWSzbo4IRzL7XQG/5So65+N3hpeF4jWZYE2FZDZLvg7jq
         54yhJX0N+wJkxKjZodPgVIxdV7GagRhpme57RlEFRC4tVSkOtZuJhsH12G7AF6l1EhfS
         ByjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UuQikHdq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ix9i8ExQSsO0ltEpbnEdiBEwp3KUfPzNjmNjsIewOCI=;
        b=FgG+47qsUpOoVaLKu+v3u+YJCT8l7VxxH5gs96FceVNPdwDG9PtBkzmnjKgFHvGFxk
         YXePJwG9gU7SyV3UMAHXfqM23ck2OeVcAkiwdfp8oTB1TSVY4Mdl59+eleEZIeFVuJ2J
         dmqAgVZi/ap7JijJ7WvAF6FZZVSbwRBesmMwW2TFzPobKmdbt5xiEB9gh2qoCogUHEgq
         9GNkk9QfKKyn5h8RcZJC37aGNZS6JdzIt41z3dS582MYwgkqmhtvOubCl9VEd0HGfVwn
         CswK5q8xlbZjrGUjy5PWx//a27zho+xat6vbpixWgpZ8FwWLrYkspGTqnQp3I5NWEbY2
         nTgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ix9i8ExQSsO0ltEpbnEdiBEwp3KUfPzNjmNjsIewOCI=;
        b=qMI9IewxTQxSMPI22/XdXOung5rHLtPOihF5oT4WjXcT4jaZoXtZLV70KMc2Z2PhD5
         Ado0WRsIKlC5AS2PRupqt8a/CUM6vJIGayAmg5wojwrON6Ks8cAJMhzoYHZMtvcWwqyI
         SbXSV8GqOM/vJuNBcLEyrfQdFrTZnyQRq3Oi6CjpZnONviY0lToHfFSmJCTiD7qha4sz
         hqD7J4Rvftut5PjJhOa/Tlm9f+i6rf0RHCveee1/kFe/1F0jTp4/Ev+VA59y/8X4hSkT
         1L7xxtK1PkhmCENmabwiNQeHekg7uIGZYerP2k3cuadk8An1LnoMFMfTNUXv143uQOBe
         o4Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oLkYqVB0nkmQONHFRzus/qOHp7ukggsEa9Q8y06RY0ahjeVUG
	K50KXRBmJ9hlP8McYaSXSFs=
X-Google-Smtp-Source: ABdhPJzz9w+FnsAvinb82QSp3ZJnp8rX/sHinikTnV+EPwTbkb3x6BRXL0MrQcA/NmEWgK0ToPJUBw==
X-Received: by 2002:a7b:c30e:: with SMTP id k14mr50216wmj.156.1640037621759;
        Mon, 20 Dec 2021 14:00:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:522c:: with SMTP id i12ls6379742wra.0.gmail; Mon, 20 Dec
 2021 14:00:21 -0800 (PST)
X-Received: by 2002:adf:c751:: with SMTP id b17mr104812wrh.560.1640037621122;
        Mon, 20 Dec 2021 14:00:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037621; cv=none;
        d=google.com; s=arc-20160816;
        b=hRJfLj7XQ+6UQGF3BKaqrRFH6qXjw6Lif55p2Y7JvTO/wKInkGnFfXOuYzzYQ+P6xo
         bylk62VQYyMv1mZ34vID0+OJPeULVuhJfX/ImHuEcBytIxPRuuv3qTnO0HPUm+9iYN8e
         92GrlpLm83P/11U6BJCab50wacD+XXGhEElsiERmF5Bdfm//pEA5BJLWlMkguoddn0Bt
         cYWidfP5+uTb2v9SbtHHHJSdVQvGAitTM1B462nYHsu2+2/xd9UQUWMeLwVO6CZ4LKYs
         7anmiC6ZRcn7jxxbpZELWB7nGcD7xz+Fmk6Mevecgcyy0NUo0ed9eyk7MquoJW4fTBiR
         MoyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ETGtFPT9DSWIB4bf6pEH+UDYDV7ngicpRFQCLs3jhbs=;
        b=B+t2Pa3nzBAOjE1WRUx56weqn0JYfEfa0eZQWZKxteRDBb+Z6QkNJJsLT7+29p9iuH
         cSeVW7gc1LckYB0j+LYQ42MKfee5F9ptdOvVByLZpXXIpq3vis9pSpVPMLIBL/8ykinq
         lzcJ3TzmfkvPsuPEXRIcJPlsDmkbmnSBHkW/EIE6tpKdifo6WR6Vwb5Xwmf4kTer/B6u
         PfQwFBeznNPwlnlIXFVf9+9oh7IwfE7VQoYvLk3TScvE/BR8BnA+qRNS1Ze8YM3j9qJj
         9ZUG2WsE1DhipOXn0TlUdfaXQtQnVQrXhaQtgvAlZlWF14e1krWQ+r0tkGlXy78qHjGc
         IMfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UuQikHdq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id f15si289220wry.1.2021.12.20.14.00.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 18/39] kasan, vmalloc: drop outdated VM_KASAN comment
Date: Mon, 20 Dec 2021 22:59:33 +0100
Message-Id: <de7bc412ed4d04bb98a4c04dfd8873f35ad18db1.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UuQikHdq;       spf=pass
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

The comment about VM_KASAN in include/linux/vmalloc.c is outdated.
VM_KASAN is currently only used to mark vm_areas allocated for
kernel modules when CONFIG_KASAN_VMALLOC is disabled.

Drop the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/vmalloc.h | 11 -----------
 1 file changed, 11 deletions(-)

diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index cde400a9fd87..34ac66a656d4 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -35,17 +35,6 @@ struct notifier_block;		/* in notifier.h */
 #define VM_DEFER_KMEMLEAK	0
 #endif
 
-/*
- * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMALLOC.
- *
- * If IS_ENABLED(CONFIG_KASAN_VMALLOC), VM_KASAN is set on a vm_struct after
- * shadow memory has been mapped. It's used to handle allocation errors so that
- * we don't try to poison shadow on free if it was never allocated.
- *
- * Otherwise, VM_KASAN is set for kasan_module_alloc() allocations and used to
- * determine which allocations need the module shadow freed.
- */
-
 /* bits [20..32] reserved for arch specific ioremap internals */
 
 /*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/de7bc412ed4d04bb98a4c04dfd8873f35ad18db1.1640036051.git.andreyknvl%40google.com.
