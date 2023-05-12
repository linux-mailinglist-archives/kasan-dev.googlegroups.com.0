Return-Path: <kasan-dev+bncBDLKPY4HVQKBBWNX7GRAMGQERGDGC5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E1154700BCD
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 17:31:38 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id a640c23a62f3a-966329c872bsf852796766b.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 08:31:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683905498; cv=pass;
        d=google.com; s=arc-20160816;
        b=qQkxJwlrh0dXql0XDBJ8/CYr2PPKegPKn2kgswEmKVC+SHAIovFltUfNmHNZNnT9iO
         mJFBVtZzbQaNEG2VSVt2RA1K57+eD9G22Ql1orYCqNNicu/V/ljaWujd+jpgKzf/HnAa
         ey3oD9G4Jvt37HMHegY2ZmmN5b/3QFEQLGJHQ8gbKWO5clKA2j8SUZ0aEZF9qY/5wu6h
         cOrbLVaoiqsULiVqCv4ItnK52mtoWQtc1cqXBAM3Puz5O8Ibfh21gNHDVQp5E5HTuGVQ
         VmYnp2UMdXE8sZnJDkc02iOTHJ4PxIA0jpJr2uMx5kED60+QtuW/r3s4xfr5pyI1AogQ
         Tw+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=WGsybpmrqzA9/Oagi8Ypr+cM19nSGGq07ayYmZZWasM=;
        b=EgIstc13GuFiDKePNKDMcWHOGg5OsopOYgU39OLeH/izBCgIYsXilnyiCT7rcj8Lc4
         WsZECk12NxnbZVffBaJjQmxPOw/lk9LaWww97gUlf9AJgvyVNYoQu2Ni/K8m6Ap/E/Uv
         N2k86nZ/+sXFciMlMZQA4INbRnOw8GLTht/clcYqIBXHcl9pTGWGhcNLcsDOi5CLRSr9
         Xh4KaQNQ6B4GGIXajriEjbV92hcLvgIXpxG+dnrhBXokUTh8JNH6Z1edDnqpp/bCg8Nz
         0oqpHgXZ3OXNzpz2f+V4EhE963033bzuBYSMLhOqINOQiv3y4gV++cHkjVTllcRNXHs1
         2EZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683905498; x=1686497498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WGsybpmrqzA9/Oagi8Ypr+cM19nSGGq07ayYmZZWasM=;
        b=mz9Hk40Gb/QXvCzqGP+OtIu63yEp32gB/gFr03DAO86zzDpQIaadIstEXLIOOcWgQc
         tvOejzpNlymoPqPrKYMbOn4430ngUvi8i46+QT4lOHoipl+BMYFUIvhXUA2xlODPkF7G
         rEEpvDkYWDDXJOoWuS9nw4sD01SeYpZn7m5PnScU+txqtsJbAuaEWiXUs2+791wEWapX
         s2hTcPlwyazk7kV55qN0DXoNOTO9ZfI1IASBOGQ5y08e+sPmIFNRgzobLkYNcrL3mTyA
         G8ohbHmcrZ3PsqivcOzJRhQ92lVaVkf3gLDdFmciMykm7jZLbKll2Wm+khI4f5BRj8rs
         L0uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683905498; x=1686497498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WGsybpmrqzA9/Oagi8Ypr+cM19nSGGq07ayYmZZWasM=;
        b=WQvQYs3Gw+T4kSSLTd1ps6bxtIeKdctXVBV2VAkmBM2k5aCeko6qXI3RO9arkLYy6b
         +Tp6m4yQsjkISOikBGiOEx5+pFAjekDn/uC+6nv1uUKGvpKhr8zwsspsp123Zw3W8ZhT
         1IMeLQgXRJFOrO1SyjBTDOYcoz5Id8S0SnsFW0CkPEeSUSPQIOOEZ9B7yJUBkaeTy7PM
         uFzeHNJQipqH3Q//KshtKCEwZRoU4XglYzeclUeQzH/HOuhoZIFXxpZ653GhbWK3RLTe
         1F1O/ggESM23omuOS9ZX730aLGZSKs7UAPy9P8P+pb1KoTXghofyB/WRnV8YWgivpS/v
         SbjA==
X-Gm-Message-State: AC+VfDyexZ1+yhpP23wd2hS13kT9ippyFkUH1iZczNslqXI29E7Y2TgA
	kND3UZY71a1GOVxB3ZS/ndc=
X-Google-Smtp-Source: ACHHUZ6k4LkXH0F7CPEsTKDgh3Kt7Il1NMLBnqr80I8jCUclnLFzlIC1OFyP5uI9wQ1TT7UgQHm2oQ==
X-Received: by 2002:a17:907:2717:b0:966:3b1a:ddaf with SMTP id w23-20020a170907271700b009663b1addafmr6934857ejk.9.1683905498126;
        Fri, 12 May 2023 08:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d0c6:0:b0:50b:c3b9:c10a with SMTP id u6-20020aa7d0c6000000b0050bc3b9c10als3195191edo.0.-pod-prod-05-eu;
 Fri, 12 May 2023 08:31:36 -0700 (PDT)
X-Received: by 2002:a17:906:58d2:b0:956:fdb6:bc77 with SMTP id e18-20020a17090658d200b00956fdb6bc77mr27127014ejs.30.1683905496859;
        Fri, 12 May 2023 08:31:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683905496; cv=none;
        d=google.com; s=arc-20160816;
        b=vPBnfN8H8SKF8teyYqA9iV6OPY+lF1fJ2iBmRpsUClITHP/iJwzKig5fw1mLuTAqsl
         pmAoLjOQ7pTg1LefVAgMVOLAS533YQo6rc9R8rUvvgaknvC7zDF8ALwFRw7PHPu4sd6P
         tJMaR5q6fF30yeH2xuPa9Sgeq1F/r/zX2wZohFaYi3BAWZzS1IC3ze870blLHaeGip/d
         36I/jEkZHbiQQe/7+DgE4xxRbS8FQ9XFe/mLs+EtPcHMcihpuR42Kd5hp/thvVXbvSZ9
         jB1y62jD7gZi8CgX09+byaH/KrsU03TGihnKTbfif3BoFRwFxHUyaW0bfdKTu1zIGDR3
         3vKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ure60A3nCQljnfAbDqscbgLTZZd20W6Po918uKKIFRI=;
        b=S+yBFCEynbKFecDkQVqeA1v7Z81VUTo/+0M/hF8IYsUgbVPmKC3kh7EBcwM4To1DLl
         qFuHR3TFKarmgt8qYauj/FwteblKnxw6fSWL76L65VwOAa4SipuOeixfImCpwambNGft
         IHMM9KoxaGyRdUEBrCqe2m0BbM5ogv2JsUBsbMD2yFhwH1InuZFthJhPGufu36aTZVRE
         zj8QRwRvD5WJAFN/cs/FLbLQSPrd7DFrYDp8cDZ0pWe9xp7nW3o/ieSgpRPjSLubfcKY
         l7ZISxpFR2SxpJojDovEJNmeeWhYAgnRUcKTIawr9Vy6Es0cVkY2XVDJ1k73BrmfYpLQ
         gbgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id ci17-20020a170906c35100b00965600719e4si1047754ejb.1.2023.05.12.08.31.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 May 2023 08:31:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4QHt603JMnz9shK;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id j9QjvUkD4Q3Y; Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4QHt602W6Gz9shF;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 45CC78B78F;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id Z2fdMt-ivM6f; Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (unknown [172.25.230.108])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1E0918B78D;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (localhost [127.0.0.1])
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.16.1) with ESMTPS id 34CFVXpr027572
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Fri, 12 May 2023 17:31:33 +0200
Received: (from chleroy@localhost)
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.17.1/Submit) id 34CFVX5x027571;
	Fri, 12 May 2023 17:31:33 +0200
X-Authentication-Warning: PO20335.IDSI0.si.c-s.fr: chleroy set sender to christophe.leroy@csgroup.eu using -f
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        "Paul E. McKenney" <paulmck@kernel.org>,
        Michael Ellerman <mpe@ellerman.id.au>,
        Nicholas Piggin <npiggin@gmail.com>, Chris Zankel <chris@zankel.net>,
        Max Filippov <jcmvbkbc@gmail.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
        linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
        kasan-dev@googlegroups.com, Rohan McLure <rmclure@linux.ibm.com>
Subject: [PATCH 2/3] powerpc/{32,book3e}: kcsan: Extend KCSAN Support
Date: Fri, 12 May 2023 17:31:18 +0200
Message-Id: <1a1138966780c3709f55bde8a0eb80209fa4395d.1683892665.git.christophe.leroy@csgroup.eu>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <cover.1683892665.git.christophe.leroy@csgroup.eu>
References: <cover.1683892665.git.christophe.leroy@csgroup.eu>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=ed25519-sha256; t=1683905477; l=1060; i=christophe.leroy@csgroup.eu; s=20211009; h=from:subject:message-id; bh=iOCU0/N1NN4MtsKG9zsIEYw/8lfD2axoPdIAx+GkS9s=; b=EvwnTux8lT+dm20oToq/tU/Rfl9rPrCQsCd+7Xfyh3L4PK/7Fnj7WP99M0uv4LLpVBQsXTB3J vQdb6V2ffTQAranodLUKWDjk6Etl/Ke/s1FjpE5TBcsF0e/gUU0DzU4
X-Developer-Key: i=christophe.leroy@csgroup.eu; a=ed25519; pk=HIzTzUj91asvincQGOFx6+ZF5AoUuP9GdOtQChs7Mm0=
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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

From: Rohan McLure <rmclure@linux.ibm.com>

Enable HAVE_ARCH_KCSAN on all powerpc platforms, permitting use of the
kernel concurrency sanitiser through the CONFIG_KCSAN_* kconfig options.

Boots and passes selftests on 32-bit and 64-bit platforms. See
documentation in Documentation/dev-tools/kcsan.rst for more information.

Signed-off-by: Rohan McLure <rmclure@linux.ibm.com>
Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
 arch/powerpc/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 539d1f03ff42..2f6af3cb75d6 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -211,7 +211,7 @@ config PPC
 	select HAVE_ARCH_KASAN			if PPC_RADIX_MMU
 	select HAVE_ARCH_KASAN			if PPC_BOOK3E_64
 	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN
-	select HAVE_ARCH_KCSAN            	if PPC_BOOK3S_64
+	select HAVE_ARCH_KCSAN
 	select HAVE_ARCH_KFENCE			if ARCH_SUPPORTS_DEBUG_PAGEALLOC
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_WITHIN_STACK_FRAMES
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1a1138966780c3709f55bde8a0eb80209fa4395d.1683892665.git.christophe.leroy%40csgroup.eu.
