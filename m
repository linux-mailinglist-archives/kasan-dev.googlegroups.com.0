Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTODUCJQMGQEW3NNSGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E277510416
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:06 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id b33-20020a0565120ba100b004720174b354sf3180109lfv.19
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991566; cv=pass;
        d=google.com; s=arc-20160816;
        b=lVbuKQVvMUA60S0ukRQrHjIR6YT5UIPOz+Eq53bd+p33l0BcgOYQXlFgcGomjqoF3g
         7r8W0U9DNdD1b6uMpCbDqMfE7xLRpzepUmMk8E1Px1UXdvlHyNXtQFVJUd3lHSUR2yVp
         d7H1Yt3ivuSOhsGWNxwm1eJXIxuL5C/g0DSFfY/8SutNiqc3M5u5SMvk6nBazI1QENrz
         pdZ5hW6X0cwk4dDeAhiJILiq/s7a0X+bYjgKaJSjx5Wd3hf8RMbqm57uq+oSaJJonCSF
         KlBLxP3/dmdPtm+qASr1gAbWQX3dxMVVDhSqItZ53i9lS5ThMYaOKFdm8vMyj+y+eRAj
         qDKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SMMFQSneQzDX+agWaH0UyPOG3leYF1iv3RwMmwbvNOI=;
        b=YGsxBzDg8Uv4oorebELbf5G30SqSoP4EUKnJAYSTbBBS9w0pdRwURkb7jbsriufdN7
         KLHibZqQFg9XS8WF/FI2f3RwaW1Kql7Oz9gDHs3yoOU3wExHAXZYTXp5qSE+7BIoz9ny
         HycjZf+MWsr769e7gtwNhExGPHU5GoBSCUfHpwIdBE/4lRrevEn5mfA24yg1uDw1ENYL
         JVD1RyVsbBvO7E4nQwboDUq0I9z6MNKfbgKmem/PDllmdw8eWrqjUCtP8+D1BiWvLYof
         ulUyBhKFwHVkiay8K+ycyQi0SAnrAXrdHOVnt7g0UjNAfmAroZZbzZgxVVeHqoDMrGBd
         +waQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Dp8fDgew;
       spf=pass (google.com: domain of 3zcfoygykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3zCFoYgYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SMMFQSneQzDX+agWaH0UyPOG3leYF1iv3RwMmwbvNOI=;
        b=B0SelUwGZbBnz2RAH0Sd2Z7eoj646GY+hSX3QvPTC5rrPST+quxx7YAQVDL8MKPqe2
         MrCQqdKwCQh+0QVLMdBRNQ4TT5sf353OhFTWxxAFTXi5+eztNDvSExoqocheSMM/3gKJ
         EiKEIvTas+wXoagk0nePP+cBiQIlHiB9q3gzp+WePHsnfZf9JZAANPiE+EK/oWzMLZT2
         xPHbWU7S9D+cDXe2Mk4CS3Qyjaohybb3xNqd2ejm7fbMadONYxjopHvRojUSUkDMxkSB
         zHzlg2o2/OelQZGoAS40vdFGc99pviV2bu1LEr4m1omIe1gY6LA1DmQ65E82/lWYd4iQ
         xswA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SMMFQSneQzDX+agWaH0UyPOG3leYF1iv3RwMmwbvNOI=;
        b=U25jo6uOI8xkhUYNcoM9c90TLYgnkeDXvQX+MpiPcn/uFvqZFD8Wg5+AQMTAikeYHQ
         e/CnXmqm2kEXDqDsCAMg+WWWQUYng1gnOylcj/Rsh7WtF1FRrmMdACDD/+4nv7OW67HY
         s4Vq27jpMtHiRGBANXVvadYvL5gKOnfWgmuEo6q7Lh4sKH63ANzD04mks+cdaZIX4C5c
         wyDhZCuiCiwhFkbwPfelWGq2qaOowMUzGgqZVA3jkxAj80meKi93J6VUPGxgryOiXrYm
         iRYbg1eDudxWvaIR1eynbvHddwhaBxa/GT6qL1JW3DfkUjjWARkz2G9qvqVjotkfyMW7
         etEQ==
X-Gm-Message-State: AOAM533Z5nxUzGmCB6z1sBrm5PIAgsXckYvn3EovZKvjw5iVp6kjFIdm
	CxWdQVftMn7yAz8pUZxvhkk=
X-Google-Smtp-Source: ABdhPJzPEewVtd9Ypffsv4HMyz4zfqG21/NWVjPRG/qc+As0LOEhWDbn78TbA11s8F6aldTRvXbXQA==
X-Received: by 2002:a05:651c:b2c:b0:24d:c72b:ebb4 with SMTP id b44-20020a05651c0b2c00b0024dc72bebb4mr14365814ljr.190.1650991566123;
        Tue, 26 Apr 2022 09:46:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:892:b0:249:a5b7:d97e with SMTP id
 d18-20020a05651c089200b00249a5b7d97els2127181ljq.10.gmail; Tue, 26 Apr 2022
 09:46:05 -0700 (PDT)
X-Received: by 2002:a2e:9901:0:b0:24d:d567:d846 with SMTP id v1-20020a2e9901000000b0024dd567d846mr14769963lji.496.1650991564989;
        Tue, 26 Apr 2022 09:46:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991564; cv=none;
        d=google.com; s=arc-20160816;
        b=xZSC/5v0LI1UCoV+0orPP8hQmDgGi73dQtamn/Rn/0gqzx8r1x66m53zWa8Ip7XoIe
         4cYHRifbh18APhlOqtpUDI3O8kj2XjtBwqDn3VWn+IarFpBdQ3M6U9DiF9bYTxYb/X5G
         Tn13obUwEFHgDH+oxkLEeC0t9/E2Z4zOYANef7kEo9uh5JQcGhkSO0K0thjuq+mTV72X
         BDULxt5saanzupnxDDQhRHd41AKhzZdPMeRZqVF0F6PTo98ruEDK5KJ5iDEOOzoppdDz
         EiFc7wJ+nNU1/n3AGAZiFbLF43MH9VSZSxpOfxUhuS+sSU2URzxzrGSwDodQLcD/x8t0
         9AYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=xs3mnLw1SF/DZ/Tq7NTZzrdEtEEoGjj1tkhOxGSNVPQ=;
        b=gbJu84VdHM18S2oygfKFM6nVNsJhUV+CefwWJj6VYldxk/EFpuH01rL3ezy3XKoNB9
         uexz0jXQ5AQfaxI65RULdfVjVgJ7ala1xKtCmZ7VzM7y5GWje/t03t0Df+1AVa/2fs/j
         1mH430ENV+uy4uU1Gx6CNyR2NXPpsEqNF6RJphNL2q0EGJ0ScvFKVbViZIDZXBrEgee8
         JE9c0BbJse5inBsdw+FckM9EIlu2owDtoaHTmHQtJBzJU4ExqHEMGTCS1ubxtYlwvhkh
         QJd7+qWKFG7xVPBJKmVf34Ev200h35n7/N/9zdyLSuG7izMqlrU6RAUZ0UKCR81hIwZf
         hjQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Dp8fDgew;
       spf=pass (google.com: domain of 3zcfoygykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3zCFoYgYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id e9-20020a2e8189000000b0024eee872899si542818ljg.0.2022.04.26.09.46.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:46:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zcfoygykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id cm1-20020a0564020c8100b0041d6b9cf07eso10590245edb.14
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:46:04 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:aa7:c70f:0:b0:425:f70d:b34 with SMTP id
 i15-20020aa7c70f000000b00425f70d0b34mr7131646edq.306.1650991564200; Tue, 26
 Apr 2022 09:46:04 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:09 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-41-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 40/46] x86: kmsan: handle open-coded assembly in lib/iomem.c
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
 header.i=@google.com header.s=20210112 header.b=Dp8fDgew;       spf=pass
 (google.com: domain of 3zcfoygykcckv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3zCFoYgYKCckv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
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

KMSAN cannot intercept memory accesses within asm() statements.
That's why we add kmsan_unpoison_memory() and kmsan_check_memory() to
hint it how to handle memory copied from/to I/O memory.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Icb16bf17269087e475debf07a7fe7d4bebc3df23
---
 arch/x86/lib/iomem.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/x86/lib/iomem.c b/arch/x86/lib/iomem.c
index 3e2f33fc33de2..e0411a3774d49 100644
--- a/arch/x86/lib/iomem.c
+++ b/arch/x86/lib/iomem.c
@@ -1,6 +1,7 @@
 #include <linux/string.h>
 #include <linux/module.h>
 #include <linux/io.h>
+#include <linux/kmsan-checks.h>
 
 #define movs(type,to,from) \
 	asm volatile("movs" type:"=&D" (to), "=&S" (from):"0" (to), "1" (from):"memory")
@@ -37,6 +38,8 @@ static void string_memcpy_fromio(void *to, const volatile void __iomem *from, si
 		n-=2;
 	}
 	rep_movs(to, (const void *)from, n);
+	/* KMSAN must treat values read from devices as initialized. */
+	kmsan_unpoison_memory(to, n);
 }
 
 static void string_memcpy_toio(volatile void __iomem *to, const void *from, size_t n)
@@ -44,6 +47,8 @@ static void string_memcpy_toio(volatile void __iomem *to, const void *from, size
 	if (unlikely(!n))
 		return;
 
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(from, n);
 	/* Align any unaligned destination IO */
 	if (unlikely(1 & (unsigned long)to)) {
 		movs("b", to, from);
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-41-glider%40google.com.
