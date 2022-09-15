Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCP6RSMQMGQEYR36HAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id CA3215B9DF8
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:04:41 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id v128-20020a1cac86000000b003b33fab37e8sf9724511wme.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:04:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254281; cv=pass;
        d=google.com; s=arc-20160816;
        b=QzS8h7vLUotcOc7vv+pP/3/tUGrhg1OW8SJId8m+c06pXuRhh62z2LCPWs9Ip00hxy
         fnT2BIRZB4fpIz94GLU+Qnml10bBd8hywQQzB7eFNjdVGHNRnAxmB8AGE+vUNuPaFKFR
         TDHxnSsiBZmEJOVcoltUhRV6g5zaNhLD8WI3T4YilGyScK/bAKle2VwnqeW82fYzXJ5D
         2rk4DCIxlNNjfJQ1xcZkI7CGs3+puBcfq5xcM1pdxbSZ9nCrIuR6NtfiMbcf9yc/wmRj
         0ooNU/Oy4GsAyEirqqrLHhI6HFq+T1cxPmx89gCuNCajjdJV3c859REHelkb6n3nnH/x
         iL5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=4r9IATFx0y20ey7wGUClIiWp/wopzchMrLJ6FbaOT+0=;
        b=uj3ttXci+7w+eQPMfwtK5+vdKPhoA7AGetGVqP7Yi01eFXgmg6CILobrsaMlfxpiJf
         xJ7rr71sxEhcWqhiQW+DAxPS7PYufHrwAeyVQPbugHBXAAEwIKdVXeTD4JfX+xwE+CKB
         YzT8oBB0f6yPXfJCqlZ8D3Fxs4hnOxC4fn126xm6p+ND0D8ZUIFgkKxvHMuBgeQtbB35
         q96qsbhAdGd6P/9YMK3Emiu7/H1bGduFxMW0rpMkZIrhPWxIfWI3F7y54QBAAUAPEy0P
         6aUUZN+hqc1o6tJxOFCX11kebmicJSV9rvQNTQMd4DeJGbkEJLtrZqPtOTd/b1yhJRgz
         bS5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Z7D99KP/";
       spf=pass (google.com: domain of 3cd8jywykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3CD8jYwYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=4r9IATFx0y20ey7wGUClIiWp/wopzchMrLJ6FbaOT+0=;
        b=ej/BO9cSWOkcX1jbAKTKDkOBaar+axHA+he4+Uc5d/1z3ANEPzDvED1sc6XWXEYDKm
         WNOPnPgW4/WYKqV7pBhWcaGwM3jErZaZ3rfXIczwywTz5wgt1UqUuBekxas/g/QLE8nI
         ZejekN/+cI1DeDMgFJalguHEWk4IKAM1nD9uMmaPklgufYeq9c7JVZgEDq/IFvlSDpDV
         t3/OBoMRWbKiYB48+tgHOJCVfCOILfYaFk7R84qnvtPqH8eY6L4IkVV1rtV0aLK3R4dm
         rqmWi6jaNACEgusO58jjSzq5EUopzatDNinDJSXKWQQ+z39Pxqe6T+ZXChNS5ktAMGxG
         q7qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=4r9IATFx0y20ey7wGUClIiWp/wopzchMrLJ6FbaOT+0=;
        b=pj0OpNuu/cGBtPCHFRqUot2WM1weZkxGqjhrERXWDokrtL8/S/AxHnTlt6rHhExyae
         7Q4S4+GVsw1RzOWzideTb3k2l9WTYVKwQb2XfKIXSDXRqrlFrGrZwJi4Tfzpf2WVI3Z7
         2g+ipI72n5xBQgflR2SLNcgPJPcTLzGvIHu9AVBQ46s1N0ZWjxVtyZ/AyRzJE81iTLss
         DzILfy+XRM/U4aaDiDfWiMnOVN4NgF7urrCr61U0mpHrcJ3IJRc54efNsonzAh0QdpOI
         0RKNfIZL/FDmf+fhYP02hBMH7ZEadoFOSTnyA8+yiOI0dd9qfDq0dZtamw+Brf3detje
         ItzA==
X-Gm-Message-State: ACrzQf0+kn42ATKyCRS7nZ4WyBVIBTqJk+knbYlFI+WmZZLC9e9RvTDL
	NEfGzxGBrQftEF2T+0Lv0mo=
X-Google-Smtp-Source: AMsMyM6B5HOdZXC0JtSZQ+iarv4kN6C5g/2kJ7RJEe/ksW2M6ANnJKSjj8Jq8FkjJVr4VhnDAKjF6Q==
X-Received: by 2002:a05:6000:11d0:b0:228:8d5d:f2e9 with SMTP id i16-20020a05600011d000b002288d5df2e9mr56189wrx.207.1663254281648;
        Thu, 15 Sep 2022 08:04:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:256:b0:228:a25b:134a with SMTP id
 m22-20020a056000025600b00228a25b134als3194788wrz.0.-pod-prod-gmail; Thu, 15
 Sep 2022 08:04:40 -0700 (PDT)
X-Received: by 2002:a05:6000:1882:b0:22a:a8cb:30b4 with SMTP id a2-20020a056000188200b0022aa8cb30b4mr47351wri.511.1663254280528;
        Thu, 15 Sep 2022 08:04:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254280; cv=none;
        d=google.com; s=arc-20160816;
        b=oVfoODQOgJK58UFtdI/msDyaJOcYEuLdENvcKd+C0HbrSwKiFAjhwY2yDkZX2Cr/c7
         J4eqkB/E3ku4MmhaTM76AANb2W8OWyyJn7K8B8RvC9vtkKllAclEWq6uBGe4v5H98cE6
         7RCgp9oHUWx2Dtwq6Lo8I1eIVuC5/vjvd7tfEEdC/P494fTy+hC32S1/63V1AsqjHAH/
         ZSyGCV+pUUOo5aiJYpZu8bm6XSZG6zrSXx4ynVcLwj2Z4rY5Y62s+AjlQrpNey/JoyXu
         woi4RG2opMBYp398hmx8f3NNgRaDlRGopMSPRG9q9kWALVCTui3SC9b5WTWuDHiHpUuQ
         IKDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=H32LKJ4QtRE8PW83scu/rnCN+O5l16ld3Egd+3MOYzM=;
        b=B7CFPclb8R3oaXQ19EE7sScR7zpgGtuiwsN5vet8pMGF7ShvbMnTLWYlnusJR/DmKM
         StIaPVidKc/ED9+s/ZIdIoE6xaq6f0isV0G2/gddOOO3HPsiKi4q/4xfLCjAi47ZA/8i
         sOqqeKrfe6/VTkPEac4Gzfquw1tL+KJYhqM7DzAWboLr5Ulm75CQYNk66m5mtabQPVy5
         4nHyWm7slR6zL7vJMqUxKowbR/QOEnScgTmcNRr+Dk9pYAMxuJtmLS6wF9ISgQDl94uJ
         2OPvKwsOb8kXhOvahMmyqVNglQamQ0MxHgklbWTC8JM2SFlGBVO840YCiDtBr8K7ihuG
         8qYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Z7D99KP/";
       spf=pass (google.com: domain of 3cd8jywykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3CD8jYwYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003a5ce2af2c7si77098wmi.1.2022.09.15.08.04.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:04:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cd8jywykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id f18-20020a056402355200b0045115517911so12952765edd.14
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:04:40 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:5406:b0:452:1560:f9d4 with SMTP id
 ev6-20020a056402540600b004521560f9d4mr246547edb.333.1663254280120; Thu, 15
 Sep 2022 08:04:40 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:35 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-2-glider@google.com>
Subject: [PATCH v7 01/43] x86: add missing include to sparsemem.h
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="Z7D99KP/";       spf=pass
 (google.com: domain of 3cd8jywykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3CD8jYwYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
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

From: Dmitry Vyukov <dvyukov@google.com>

Including sparsemem.h from other files (e.g. transitively via
asm/pgtable_64_types.h) results in compilation errors due to unknown
types:

sparsemem.h:34:32: error: unknown type name 'phys_addr_t'
extern int phys_to_target_node(phys_addr_t start);
                               ^
sparsemem.h:36:39: error: unknown type name 'u64'
extern int memory_add_physaddr_to_nid(u64 start);
                                      ^

Fix these errors by including linux/types.h from sparsemem.h
This is required for the upcoming KMSAN patches.

Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Ifae221ce85d870d8f8d17173bd44d5cf9be2950f
---
 arch/x86/include/asm/sparsemem.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/include/asm/sparsemem.h b/arch/x86/include/asm/sparsemem.h
index 6a9ccc1b2be5d..64df897c0ee30 100644
--- a/arch/x86/include/asm/sparsemem.h
+++ b/arch/x86/include/asm/sparsemem.h
@@ -2,6 +2,8 @@
 #ifndef _ASM_X86_SPARSEMEM_H
 #define _ASM_X86_SPARSEMEM_H
 
+#include <linux/types.h>
+
 #ifdef CONFIG_SPARSEMEM
 /*
  * generic non-linear memory support:
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-2-glider%40google.com.
