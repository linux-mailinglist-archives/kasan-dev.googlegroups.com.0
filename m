Return-Path: <kasan-dev+bncBDLKPY4HVQKBBWVX7GRAMGQE362XRUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 902D7700BCE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 17:31:39 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-3f4231d7893sf41548715e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 08:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683905499; cv=pass;
        d=google.com; s=arc-20160816;
        b=uMdWxyEJ7Cxxpywlypn6VTF0hMAVa+gnkCkTXYQmrXH0xiz6JQhgrmmR4i4+gX7lFR
         wdh3v6EODDHXE3fHKCunMfUeiyaRtteKj6Fd0k08TDPOUZR+hlZ02QFRGmiODJOgzj5u
         0nMhLSYiM1+8ZAFSTJvdTrlidJyst1h8Li/EkAUHTIGGLTMr76HY13QVC1tRJI0dpJ3b
         kd3+c4gwDa5rnlGg2tEqHPEoWmYEj/xee0r1BaWl40nn9DuKEX8ReLUDo60k5dGz+7HS
         wKtE8kkdrdQA9B5BDndImii0kHRxKnmvrKbEcmX2LMPlkHRMM3KHgY4DalNiZqsxbIQB
         DF2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=IqetJ6tXdJAsaEXBwVAf81wwsp6P0YUFYDmAaW1MZsI=;
        b=PcHq6mYBIPduO16RcHltEB0Hm7gEgLxASlysDmdZ+isN0AARurAeHxCm/5RZK0QEA6
         ynPcsGk6wRyra/AN0aLmwz2IRZGm9W+wLYvhfAD3wc3wo4jEaAJ9wrFH9Aqcyh9oBXBu
         7rf6PtOJEGMFTveR1OHVC6ibBRInG1i6zioIctRvoay8M7+DjuOvXDBaEt5Njh60ARJT
         /khfttrqv5LUZxqUwO/6NKbIBRjUt46WXz5UC2kxTqbp6g3iNhxoBBTmeVqwFtUM9xj5
         bHmezCRxB8W9JcrGrb8L0c30GSswkqMkak80S/yhC2ABwHSkO6iEKSyAln+ayJ+lusA1
         KKfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683905499; x=1686497499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IqetJ6tXdJAsaEXBwVAf81wwsp6P0YUFYDmAaW1MZsI=;
        b=N2RJ5smpOJUKTyGl12Myo8D6YprMktJzUC4p+zjQR2Z8UtOEXg8n+dtEteiOik2Mwf
         zhVD4O4PI1lJzS0e8Z/3RCgZjZN4qGI269Mvqzzs4oTRI5T05NW94+Fcr5qPqpaxYALt
         TOxsKsQ5LXuYGnvo8+YCDDP33F6h4PWKGiErVFBJxwhnILC2vRe/hUeDJghcHVoa1sQg
         w5nPucqvX72kWEIlq7d9x6txBNKmV+MzvOfZWmDM0ORapDfunlmaXL3vXM1uoR6gZStA
         m47CTaUh24DEJn5jj11D7mOJUMGhGj8QOtDhCsKutWRw/rdATwdJXiqCM8HpWNEcCCJB
         VLrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683905499; x=1686497499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IqetJ6tXdJAsaEXBwVAf81wwsp6P0YUFYDmAaW1MZsI=;
        b=P8JaZTdgminAJRL0SJgX7gdor7QuxrYP6ZyJh8NRgmZcel6RwT4lr9KO0osNxfV3pG
         hxy77frmI2Y2QMkktOapHC52UxXNkI1H52X/XlUKkdAt8+3bzAtHCjWTwXEOEwaVPEyX
         bTaGdO3oq/XmTv4ZCawlHvdQn0bY//ncuFkoTw7K0k+hROSklgraZ8cCDAJs+l6wMeEC
         4PezIiBcUI8Wy8Yt8Rb6eoz+No/r3hF4nmgXOQnXwiaMJrmYzYhjgrT+t8tZyseTgCQ+
         0Si5AIwuJ70gp5VPFE2Ub6tgJxCcHg0Wv4gjeGhquGoeAX5dpDfMSnVrFZh1pf3MiVat
         QUFQ==
X-Gm-Message-State: AC+VfDw+ewN1D3oSmWz0/EzhhJU0roiKL2PKBFAf6x9Q6H96gmEtuy3K
	qUJA8o08n+g2cp6Z9d61E5DFKw==
X-Google-Smtp-Source: ACHHUZ7q7IDCTpBF6r3MX5p8oR0Hx5BfAawlOxhj2LhHsh73NbOOCHqg4lYGJeQZcTJf8OevqiosWg==
X-Received: by 2002:a1c:7c06:0:b0:3f4:253b:92ac with SMTP id x6-20020a1c7c06000000b003f4253b92acmr3160744wmc.0.1683905498623;
        Fri, 12 May 2023 08:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6f02:0:b0:306:35d:2f11 with SMTP id ay2-20020a5d6f02000000b00306035d2f11ls2173778wrb.2.-pod-prod-gmail;
 Fri, 12 May 2023 08:31:37 -0700 (PDT)
X-Received: by 2002:adf:f2c3:0:b0:305:fbfb:c7d7 with SMTP id d3-20020adff2c3000000b00305fbfbc7d7mr18890903wrp.44.1683905497477;
        Fri, 12 May 2023 08:31:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683905497; cv=none;
        d=google.com; s=arc-20160816;
        b=LFCSqN8YCNeLQd0UnkKyUKdnaIZ7b9RjOEvC82v1eXSL762X9s+71IqU8ICXev/aaC
         Ph6+CqhRTJ0jvx8c7XWK8b3rJp7N4aIweOa4wU3ZeIhqX9cnjlHherzkpuSTIJ5D3M2j
         mdjX8/3SGhht1WSv1F3qKCMCU/dD/aluXurNfO/4MNcWrVpXIbTP0zjroEIn1E4IrDHr
         MUAfQbcu5ZvKipnb5hRtdeK+7p4fiUjHdkr8CGDtoi0Ka1Wlzk3KtooPodQiubkq4sFP
         Y2rpRNF2bzcu+VIUxPTTW8718WFjO0KJHzupDmzobiDfB0H7zoeOA18+R9UQv/xWMKm7
         F0aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Vm+XIfzv3+ENXSaTDxVM07d6sThY+OG3pQni8ydc4uE=;
        b=aTj0bOGrg6Wb5CPWsXqxLjilqZe9pcunecFNSk8FC51euP+u24t+lQiU3OkjxNB+zx
         52T/YMiRvtZI413QlUgslEq5om9Qy3HFEz18ncQmyjvvcFS7EK/k+JvBipNbSX4aD9Bv
         cbSJJmX4BOA0qi9/kFTU45ogJiU6rlMK28x2YJMxhYESKvlbiEm1v3in7oF3w/pLxaSP
         MLriSlnpTC/yyNhw62gLTE8ELSW1UouwPzrcUxgJ8curFxhSKnTFcf7h0lP+Ki7APzKE
         o4lURRymmrjZsE4/aKpQJjFS7+9bqjVzb6ykIQaEahp9iiHcWm6M7auvHMvItHvzJQZP
         7rkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id o25-20020a05600c511900b003f4276a712bsi900663wms.1.2023.05.12.08.31.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 May 2023 08:31:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4QHt610zXXz9shF;
	Fri, 12 May 2023 17:31:37 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id 0NR9N_j0eNz5; Fri, 12 May 2023 17:31:37 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4QHt602kSNz9shH;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4D6608B78D;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id Rn7iRsKABlYE; Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (unknown [172.25.230.108])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 19C5E8B763;
	Fri, 12 May 2023 17:31:36 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (localhost [127.0.0.1])
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.16.1) with ESMTPS id 34CFVWbx027568
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Fri, 12 May 2023 17:31:32 +0200
Received: (from chleroy@localhost)
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.17.1/Submit) id 34CFVWm4027562;
	Fri, 12 May 2023 17:31:32 +0200
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
Subject: [PATCH 1/3] kcsan: Don't expect 64 bits atomic builtins from 32 bits architectures
Date: Fri, 12 May 2023 17:31:17 +0200
Message-Id: <d9c6afc28d0855240171a4e0ad9ffcdb9d07fceb.1683892665.git.christophe.leroy@csgroup.eu>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <cover.1683892665.git.christophe.leroy@csgroup.eu>
References: <cover.1683892665.git.christophe.leroy@csgroup.eu>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=ed25519-sha256; t=1683905477; l=2965; i=christophe.leroy@csgroup.eu; s=20211009; h=from:subject:message-id; bh=37bWyYVN3vTJ1QuCO1CebY5RYrI1juPiUTBYcAmWWDU=; b=SCEXIyl+QeSBTalTSYb28ctSf7iwi4YRcjupvXCplEUtY6ePrW7RQWBcP1Nm8YcUkmyttrNzR o3Vct24RL+QBsfrJvYlTzjmm8fCMHigBCa/8aSw7V1Ryl+JV4ARn3G0
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

Activating KCSAN on a 32 bits architecture leads to the following
link-time failure:

    LD      .tmp_vmlinux.kallsyms1
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_load':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_load_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_store':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_store_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_exchange':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_exchange_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_add':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_add_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_sub':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_sub_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_and':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_and_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_or':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_or_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_xor':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_xor_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_fetch_nand':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_nand_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_compare_exchange_strong':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_exchange_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_compare_exchange_weak':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_exchange_8'
  powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64_compare_exchange_val':
  kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_exchange_8'

32 bits architectures don't have 64 bits atomic builtins. Only
include DEFINE_TSAN_ATOMIC_OPS(64) on 64 bits architectures.

Fixes: 0f8ad5f2e934 ("kcsan: Add support for atomic builtins")
Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
 kernel/kcsan/core.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 5a60cc52adc0..8a7baf4e332e 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -1270,7 +1270,9 @@ static __always_inline void kcsan_atomic_builtin_memorder(int memorder)
 DEFINE_TSAN_ATOMIC_OPS(8);
 DEFINE_TSAN_ATOMIC_OPS(16);
 DEFINE_TSAN_ATOMIC_OPS(32);
+#ifdef CONFIG_64BIT
 DEFINE_TSAN_ATOMIC_OPS(64);
+#endif
 
 void __tsan_atomic_thread_fence(int memorder);
 void __tsan_atomic_thread_fence(int memorder)
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9c6afc28d0855240171a4e0ad9ffcdb9d07fceb.1683892665.git.christophe.leroy%40csgroup.eu.
