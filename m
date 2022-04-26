Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXGDUCJQMGQEG2ECZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E03B510429
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:21 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id h12-20020a05651211cc00b00471af04ec12sf7843565lfr.15
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991581; cv=pass;
        d=google.com; s=arc-20160816;
        b=PJky7/VlIAuLMUGN9nGVD6kzJMQlYkb1CwUdNgzddGGcX9FNyJ/Ei6PISUoDCMmkKt
         fphkMWj552IJb9WuNn4GXWjnJs5+dntbKUEoeaUPVY3J0EzZreYCldTX54R4KKVIZfR5
         b2/sF3ylTKH+oCAiZRsk7aotSbyAiJEBuxT8+6TEHiveyYjn0ZRELx5+b3/psc9GLGVP
         44xTlknWukI2i3NdaMwXqYWdL3t3yPqt3nFYLzXxKhx0KeF1a0xaDmo9lUzAZxgZZCjU
         rfDiiDeg/CA3z3DUHJDWuyKAFF5L7tL+eTP1w38WEL6jTMtASaoRtATbTqVc6V5uJWai
         xH/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=HC3g+1smRWJ6WyMpm/6T3CrYhKtNSkMhKhZQxZiS7S0=;
        b=oHIU6MbwSU2+MzYQCNH0ymATricsHbrvohwFHjvDfQvHpsDgkUK4cCLFQV+fVlyB0D
         B36obf6GTtmWfGkVMpRsMj4R5Xop2g55QhuTkyxcu6xzgPamusduISaJe1BjKKos9RWo
         PuvYM/1wzt/+k7y/BCXvYUWNxpnaz4KCOA8LFONKuIfojJTEI01+jd3pNSGHEgRx+G8Z
         8pBFTg1O87Wa2zM1lkyzHiqPjWe99VAwQq/LmA6LdTwMHX4Q2FUhn7T86KRBitrk9L4p
         YYCEOEx5nsvq3oCzi9s4yd0nRxr/DVcZxV8bh/WZiuTzx8F1/PewL9WQoPsNPJ1P4Ps7
         3KIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tfexPWSj;
       spf=pass (google.com: domain of 32yfoygykcdgafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32yFoYgYKCdgAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HC3g+1smRWJ6WyMpm/6T3CrYhKtNSkMhKhZQxZiS7S0=;
        b=LL738g9Iv5ojLUciVDbQgoPIZMK2AOXM/9Ao+LJA9IUfiXchBi1yK+2Gou5hvC8HAY
         7TARNwzTBhtf+O5RTyqS7/hbcnFC/8/LCegXTpchxE/mAiODKK15DApMmXkwuOkpy/rI
         6amQIOiHTdyLAL9prWFlxAzqWkIG5Z1YL9SEKMScyt50Mzau9ae8mrxXF8W9R8+yd6dM
         SaZgiVLxDGGO/uZqdNOy9WrHrWvbp24GxpHJlkQ1twraBk319S3fAEYNxM/rV1idItbK
         dbzMtn6j6y0Sv2oZBi/gfaOXLe0t56+sF2QYX04QVjBa1hDUOauoQtjFIpi/PYSn3pB3
         VOaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HC3g+1smRWJ6WyMpm/6T3CrYhKtNSkMhKhZQxZiS7S0=;
        b=cZFWU628+gC/HWsbusAib9df0wweuKKw8wxVqDdv8c/slaOUUAEcoUJD3jTzD8Ilvi
         H9+gvGAaHw8+7Xcp+vtI+SOEML7L2NCodskU/WKGMoNSKeBByTZO0ebmIL4Hv7sJmtQD
         gD/NXEEgPpZsWFw0YW1qzVFWAuGH1xEnJfzPDxl8Gf3Eh+owbxVIQcq53OJ1Yt/uCoeJ
         hqHoYnAZz/Z5M5iJSQ9HdNld9BpUBQMKCL6GfId32NkFc4P5gnTsoIH9abxOkAXlq1dp
         It5yPr/1yi2f8yIgkc5F5AJW3pf04hXvkpVMnV1Idg/NPa+af+pBMTW80JAdw5NnJoQq
         DVcg==
X-Gm-Message-State: AOAM533ITDdxMzgHH3gVoktBhlriRVEwCCkZFwCK/bcW9aSAXXXRmp5T
	5TGu7HS82NL0rsohJi//RZU=
X-Google-Smtp-Source: ABdhPJxw56OgbK7yLSYsddC71w3PJpzsl1rFqfmwCrX5zOGfNkEgbvCvyEDJyn1KL2yiKoXfFsTKLQ==
X-Received: by 2002:a2e:8501:0:b0:249:17a0:ebf8 with SMTP id j1-20020a2e8501000000b0024917a0ebf8mr15162978lji.125.1650991581009;
        Tue, 26 Apr 2022 09:46:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a54f:0:b0:24f:18c1:d26c with SMTP id e15-20020a2ea54f000000b0024f18c1d26cls757597ljn.5.gmail;
 Tue, 26 Apr 2022 09:46:20 -0700 (PDT)
X-Received: by 2002:a2e:9bd4:0:b0:24f:2300:c33a with SMTP id w20-20020a2e9bd4000000b0024f2300c33amr1865836ljj.353.1650991580006;
        Tue, 26 Apr 2022 09:46:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991580; cv=none;
        d=google.com; s=arc-20160816;
        b=1EjOcAkf8tFf3/Vf/907fv7RHDE/VPHNmE28J6fAzjILuFYGFG9tffA7HQF4LLvr5y
         nvNl2TttFwVhk67UGwTuOgAO2dFqWfMcaMSmwACe4ptdnt7Rb688sv7XEFeGt1ormtGd
         DFNA/mkY6uWj8gl9cClFFWEcNH7sVi3/YsUU9xR1QKKh2LLRS0260QzAuoryzU9PjN91
         tUka7nu0XDUiD4gaLHY3+i42HBgFoygZIf1QQHdsYFAFoua39tiWJflb/I2vBNOBDFS4
         mSLxQmobKTRsuuGE62Wt4HSklfxoB3/0rrH5YWQXse/SQexUw2qfdmI2EhRx6Sm1qhDh
         +0Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=XPVyte1DHdZzGVqIYLZisC9WWn/NV5PTOOmKGsNYVqI=;
        b=bF7t7D6mo7HDi7nW4Eidflb40TdEUHWOsfPGUIJMEcakIPvgSnTfG+wEEk70HcAKNM
         qZJdv72cF9fxt4/bmBBvtoNreAsGLDo1d+tGm65yREfCQW661PBvzh6x/R6VLdpOJAuh
         HG9uKUcRLGJ2GZ45I9pVK2UJP6HQ/JbzgJyHpALw9rmBfkAbwBR520Am0gRla2WludMq
         sVcaN8b45V2y7lvBQoUucPu0YZv1jYmvUE7RDv4USqYBMamaHvkw5X7tWt5d1ppU9p5W
         DueWnR7pdrq+jUhbVK3geY62nnSZ9MkWhbQtquj237gikWHqjRY1HEaVnSd0WZm3BcCz
         dwCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tfexPWSj;
       spf=pass (google.com: domain of 32yfoygykcdgafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32yFoYgYKCdgAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id e9-20020a2e8189000000b0024eee872899si542818ljg.0.2022.04.26.09.46.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:46:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32yfoygykcdgafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id cm1-20020a0564020c8100b0041d6b9cf07eso10590245edb.14
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:46:19 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a17:906:478b:b0:6db:8b6e:d5de with SMTP id
 cw11-20020a170906478b00b006db8b6ed5demr22938586ejc.161.1650991579678; Tue, 26
 Apr 2022 09:46:19 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:15 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-47-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 46/46] x86: kmsan: enable KMSAN builds for x86
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
 header.i=@google.com header.s=20210112 header.b=tfexPWSj;       spf=pass
 (google.com: domain of 32yfoygykcdgafc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32yFoYgYKCdgAFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
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

Make KMSAN usable by adding the necessary Kconfig bits.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I1d295ce8159ce15faa496d20089d953a919c125e
---
 arch/x86/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 3209073f96415..592f5ca2017c2 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -168,6 +168,7 @@ config X86
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
 	select HAVE_ARCH_KFENCE
+	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-47-glider%40google.com.
