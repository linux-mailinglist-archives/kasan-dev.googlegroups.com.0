Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3OCUCJQMGQE4IMRJAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C3B4C5103DB
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:29 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id m124-20020a1c2682000000b00393fcd2722dsf316932wmm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991469; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZqzjqHUqBl/RP8J/0lqR7wU3P/LDrlFY4ma7UAbcNNXSqKHb7NJccQqCJdBWV441P3
         g+J/XHUFtDzrP9iMFmKgFAMbLUqoTdjjlrsq/tF4xmhetkhcXASVkJy9DWQqu3t2rndB
         esYsuDLHZE6xMsschwDaRQYZjP0v6ge4vcwcah74yUt30YsLORTqgVasJLQ1EFJfbRCc
         FFEUISKZOIQYwncvPm+KQColqUEwLKY9wEOLMJ7QmZA1Lh0h1Ww2muUzTtxlRw4EN5YU
         AMGWlUO4wMBLKcWU3MSHs7CJcNsosf3tb3lN1y1xXi76g8fE9LZmXxSWhyu0v+7BQmtr
         7NRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Tsglho87xTIT2+vnCpueAeon3K49m2H+qbR32t6D1SA=;
        b=VQS3UPiinWIaxT7oB4+Aes5uHhqOy/ojDriWPKw08uZRdmgZThKnM/DcWBX8eBosnr
         HS4lvQXhRse52bjiQUuvzXv7isUhr7mYvNsVzDPNeC/WHFmN+NY2WteItoteKRXzkZyd
         Rmao0gWANYTGc/kmv3oqjMtsDW5hMDzGqyLphV+m8tDJUAswH6cRJoy+C6LtbRk6kfvw
         WLkzV988nwEDHQgtoaLGdeR6mvO4P3RwiYEJ8O2aSB29xqJHPjy42ZGAwomnX96wXYDd
         flg2Vjit+u9/L60BMvGUWRYtkrWokTF5agqBpF6XWqQJtebmMv2N83F+aDZ5dsGEzOHn
         3zjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LZKEFbB8;
       spf=pass (google.com: domain of 3bcfoygykcwknspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3bCFoYgYKCWkNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tsglho87xTIT2+vnCpueAeon3K49m2H+qbR32t6D1SA=;
        b=rwRmo4vf9AlF4YkMuHSGsLLCAWKabJx1JUXSwF7h/QsTD+uga9JhhQsgIiAhR6wgJK
         cObx/TGkqN7tnU7/ZEt5jpNvgm/6+xZFLWc9EYX2QNCvmVRo62TeSzZddptNM6/oJATu
         I7DANqThP717UyckxJyROZoW8l7HlJ3PWR9bWXN7Et54wGv00BcS2qinT0bPudW73mzI
         j5RN0mhCMO7pAiaBtEpBVIVRlwotsZ00/TgPI8t8JVjdPd6kO/4gIHxANojnwdfJ/RIF
         z1xU3dN0Sq4PQ4ZDC9oJA19ohru5TJW/O9AwlDRgLSCt3Ez8Gd7dxK/JsBcCw8IC9j1J
         stRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tsglho87xTIT2+vnCpueAeon3K49m2H+qbR32t6D1SA=;
        b=mKAOiJc2JbUGU3xbRatDImgMD6UL4XAVR11q/pzFyNzx2CM4wUZNM5rc0S8RM3/JSs
         MOE10r4t29DX1dvRSnJc0aJq1BMN3V31MZrXTruRbRHJ2w+c7eE1rfS5nauo4g3IMEcP
         kfvAwLyvL5Oix50MQ7omw2l5oFvTa3cKQudmX2IuiLlo+c+nPN+buKFfw28mX/vQ7phK
         L7iZD9uPsULQvbP9nOKtlJTj21tBvsuqJBHol9QJ4FTkyJfKm0FD1Ay1mT0FnBVHuriM
         2BLYLWDmbrcA0XXs/mlul2JlJMJmokkM1soLQX3KvPKDu59x0SuIafmVGXsi0RWcbwYC
         Wbdw==
X-Gm-Message-State: AOAM533y/1z083DCaC5qwRGwvH7K98UIqh3A6wwaQzO0bjItyuxzgT2h
	fi/b1QMcCPvdPXkwIuXUS2w=
X-Google-Smtp-Source: ABdhPJyLRyxdidirGrFY8OxEbi4QmQD4PNbNpXokdmASjacSvW6Jn/5UnJp3cRfQ9U7JM5dp/ZMD6g==
X-Received: by 2002:adf:db05:0:b0:20a:dbf1:fdf8 with SMTP id s5-20020adfdb05000000b0020adbf1fdf8mr8454375wri.404.1650991469546;
        Tue, 26 Apr 2022 09:44:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3590:b0:393:e880:6531 with SMTP id
 p16-20020a05600c359000b00393e8806531ls3797471wmq.1.canary-gmail; Tue, 26 Apr
 2022 09:44:28 -0700 (PDT)
X-Received: by 2002:a05:600c:34c7:b0:392:8d86:b148 with SMTP id d7-20020a05600c34c700b003928d86b148mr33091576wmq.117.1650991468577;
        Tue, 26 Apr 2022 09:44:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991468; cv=none;
        d=google.com; s=arc-20160816;
        b=h02OEpGpR9uMtQXkgkmLMGRVY+TnZsuAsdrT/ePILwpipBUoH4TJ//WJVf51xUKnnC
         lD5/ge91yO698Lgm7G5jyuSKUm1bA+0P+Jx1hGD1gU4NSRF0gN4yPFsCrvtQ8+tbzjwf
         1EgJpGIPOjnA43chEGiV88+Mb+buO11AdAn/LHE2f2NincMv2pwGFnwS3KPdIr5vxPM2
         MRpx95sEkS4pXiKnvoBQe1EcWOEbq2FOkd+ZObzVZ17VOpNyxbY+JwntHeKq3b3TJfN+
         Os/OpeM+64n14sbpI4URhLv+h3I++v3xysiPfoi/m4NWiJZGyqhcNuWRBj41ix8d08Bq
         P0hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nOhCPOtwmNXODLijzTSO8M7zxl8h4T8Tb26PN26Qq0M=;
        b=kWo21G9Uzs6rdm0IVcTo0t96JhOQY3KFyIhSv4Tf3i4c/oCJmb4hgAMoO4cum75F5X
         ScjMv1QzmFjI9nm5Dq/EeRIE4HmXP8xcOCWFOVKHC5oXwjD1r/7rqr+udV/YKO1kA0+i
         M2CyoDcZbaU3TNloZjEWfZqp39PaDvDTkZ1TI0z83yvfw02Y35hLE4l34o/h9l/M4kMd
         CRwxfj+rcVj9DKOKOPlZnCxpqLjDisgoZ9qUI2wwGZt3J/3fABFgczdpp+aRp2uXhAn4
         KVeC7kxPtvHLv3Mqkzh0GsMcNwocEi2pTIWAtsyqG+UieStoO9rUKp7piVUtYYBvDpCa
         f9cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LZKEFbB8;
       spf=pass (google.com: domain of 3bcfoygykcwknspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3bCFoYgYKCWkNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id x20-20020a05600c21d400b0038c73e87e1asi203183wmj.0.2022.04.26.09.44.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bcfoygykcwknspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id cf16-20020a0564020b9000b00425d543c75dso4623172edb.11
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:28 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a17:907:7815:b0:6ce:5242:1280 with SMTP id
 la21-20020a170907781500b006ce52421280mr22103960ejc.217.1650991468011; Tue, 26
 Apr 2022 09:44:28 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:32 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-4-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 03/46] kasan: common: adapt to the new prototype of __stack_depot_save()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LZKEFbB8;       spf=pass
 (google.com: domain of 3bcfoygykcwknspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3bCFoYgYKCWkNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Pass extra_bits=0, as KASAN does not intend to store additional
information in the stack handle. No functional change.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I932d8f4f11a41b7483e0d57078744cc94697607a
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d9079ec11f313..5d244746ac4fe 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -36,7 +36,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 	unsigned int nr_entries;
 
 	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
-	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
+	return __stack_depot_save(entries, nr_entries, 0, flags, can_alloc);
 }
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-4-glider%40google.com.
