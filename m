Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHOV26MAMGQEMLR32TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id A18205AD250
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:07 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id h21-20020a2e9ed5000000b0025d516572f4sf2815039ljk.12
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380702; cv=pass;
        d=google.com; s=arc-20160816;
        b=BGxd6ZbFjSIeUHBX/6Yp7zOTxiXnVbJQk5KYxFkeGS6HaSNFz8W4+XWNyvnTkcdIIk
         R7JrjVqU9xqqKE3XLaTkfRMZFOrpo7vSN7W4QUpxtPToArxzOK4m5663xNNBoPu3WwLb
         hJyGDCuDqsVMw1a1qCkUfI62uArcLt1pB+87gxqoW50hYVQEzvzmkhZzo7g6aPz31+cs
         Z51cYqZ+9vgpI/F+JKCpOrr71ivfjmTU4Px6kISHFGwu3X0/G/I6wn5lGlBR5sAivMIT
         uU75bl3EP03raVu6Dt6tJaeArlWbm2Aa+KCgc/b3vNADfaJy+Wh9Qkld7bOK+6Ay4UT+
         /t1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=pLlxS48tbbssxpnkGsDqxmbziay64h34Xg7Mw95BUx4=;
        b=P4sW1PgQ0o7lgST+hJDEkoDeh0RUbr2QlXbC1M5cNgnuY5/2sddDQINlwhHaiIhxAz
         d3SKJQT/TaEjqS7Uji4c430sszxnT/PgFad5EjbG4pJ3c/F7a6HXg5tsm9CRYeHoFF6h
         jC7L/cxlDaxnW1e3W0SA53aECkXvLzf7iuBUcTCUAvCdTjukXx6ggQuoumv00rZy/BwF
         xxTwFZhSwjSfihXXegOBmzVIQnmVmuy0wimD9X5OTHZtq6vKVmwycMjFmghF0jnhauQS
         23c7Y9rdh+I07wSb+GwB7MWnyhEP1jhQ95DJwiwoN/d9onppTJttKidymwX0r1lrXGQ9
         fN7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aLfolEGF;
       spf=pass (google.com: domain of 3m-ovywykceyotqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3m-oVYwYKCeYOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=pLlxS48tbbssxpnkGsDqxmbziay64h34Xg7Mw95BUx4=;
        b=BGTpxqpL1AFPJa53VepQ4UwihFFlikwtZHM9SoIs0Sp5qp5940nZZXShckbMOHwQmx
         zPPBvQwKdPAsFjQEYEpTxmndp2yR7SA/34SsLiCkwHp5mdz8h/BIc9PXMwPEEhZXv1ia
         3u7MuBrTUQF4Put0e2JyELK2zsBddq2AC4ieP+K1EtyOJHOduyYIIRzkvRpCIt4BnGFN
         zj8I/Nu/u7wqkPnUwVpGXALPDqm0/rLTkaSHUv1O/hfDggx5YN55RD4id0//N/o1OhYl
         0U2kXQaW+pQ7ae9Hu1SFPUdIuYZwGj5iQTDszvpFyo6kw83tYWaIbh+UsvmNS6bOm08F
         kL8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=pLlxS48tbbssxpnkGsDqxmbziay64h34Xg7Mw95BUx4=;
        b=eFtZ1XQzH2ltTVS5lz0xw25DWnakvS3ZjectA/RhAhAFKrWRkUGI+REiXxZqHxHIa0
         vUQ1N2kp/8xm6jsf6eGyEqzpyr1JiqSRpdmmDKWn1ZC/e7WvoD0Z+qBCOqkaWKkmccxc
         Bbmc3U0E/Wbu1E4+IeCR2lFBFV+4rcDwaH+ShSIKo4VkP0SU88APXdbKT69zEe/GB4/r
         IrBo1E9mQSZCeQCA1jlGoE/41PJPD9ul9LgdJM/WWRecalHHui81AE5NIPPYJ6XSnrw3
         ztvUkHbwdEVRtVVkxOSRhciBrHqQD3TdYqRcpT6HVNM/qdqvGKlJKN0rqopHKCY4/aj1
         jpFw==
X-Gm-Message-State: ACgBeo1sCif24GXzWxKjVGL3ZNCMyHeKXY2IVh//qSJmOVG10SsauDjE
	FlBpMOz3cdJ9e7Yx0GY/So8=
X-Google-Smtp-Source: AA6agR7RvuoD5m1Grzo/YWZuNidjVGY3tfO/QCL0njgx6AcLVOgvuwR/G5m/z8HffHDgq4nict/Rag==
X-Received: by 2002:a05:6512:2293:b0:48c:f602:475d with SMTP id f19-20020a056512229300b0048cf602475dmr18672151lfu.232.1662380701728;
        Mon, 05 Sep 2022 05:25:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls4740488lfr.2.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:00 -0700 (PDT)
X-Received: by 2002:ac2:4c4f:0:b0:48b:1358:67e3 with SMTP id o15-20020ac24c4f000000b0048b135867e3mr15550494lfk.441.1662380700296;
        Mon, 05 Sep 2022 05:25:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380700; cv=none;
        d=google.com; s=arc-20160816;
        b=NdvYrXFyrM5cMOFSnocJQ0G0UjpOvVSuZPhX2o0yv9acMPigGTS/N9T5Om/Z9I7NA4
         VJcDAObynRljhMufe5iJs96jORQ9TEwIUt4z0y4zY+/3h6zIZPmWSBEUlLssx+YRimX7
         lgBCyGu8z1iJ8OpdRpdAkfGu12mdPnkRCsPtiU9PvXBNDphMUHGyAuw5TMsmLhz0GS9E
         4NUj4PSxVDL0w/jLCUkn4vZEh/VQ8R6P5Pn9TVt/VjUkNyAl4+LYvvtBBQizqzd3hwbx
         a4CQik+S0vZzVm1m/epiZsE6F6ZZK2wPDlORmfpO9fzGGheSViQ9mTBR0HsQUiR65HNm
         cgPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=H32LKJ4QtRE8PW83scu/rnCN+O5l16ld3Egd+3MOYzM=;
        b=mRq9hwultoVDEUY82dNrl/yfCD2p91rg55hWPajNNffaq0xRBgmu03UF93DNT0zuY+
         Uu13qa6eB3Qo1Fn5toJOn5YjMOncSK40hcKC4dXiw9kgJTe7GXX0Txglpxjg/PSsPbmG
         JrG+EEwpjhsqqz+Orfvot/tO6TGwZZMFNMZOxWQxhqjvnyFme46LGtmR7CfNSGwLFxER
         pz8qf/MDmHInd0x90xh+IEZLUc95Kqju4WlhnND/ltFWesJxzVXGKF8BShlcyP3jEL7r
         y4+ddhTlGWkWYFisKiaxUoZpWdsDuStUWq/zt++JZ7sv3qfqm/BIGshQaqUzFHNNMCAT
         O0IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aLfolEGF;
       spf=pass (google.com: domain of 3m-ovywykceyotqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3m-oVYwYKCeYOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id w13-20020a05651c118d00b00263ee782b8fsi312084ljo.1.2022.09.05.05.25.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m-ovywykceyotqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qf22-20020a1709077f1600b00741638c5f3cso2290129ejc.23
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:00 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:aa7:c556:0:b0:44e:9c95:a9a4 with SMTP id
 s22-20020aa7c556000000b0044e9c95a9a4mr2284696edr.301.1662380699688; Mon, 05
 Sep 2022 05:24:59 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:09 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-2-glider@google.com>
Subject: [PATCH v6 01/44] x86: add missing include to sparsemem.h
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aLfolEGF;       spf=pass
 (google.com: domain of 3m-ovywykceyotqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3m-oVYwYKCeYOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-2-glider%40google.com.
