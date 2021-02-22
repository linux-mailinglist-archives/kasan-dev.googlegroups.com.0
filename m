Return-Path: <kasan-dev+bncBC447XVYUEMRBZOMZWAQMGQESJTJMBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B6A2A3211C1
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 09:08:05 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id s25sf12565959ljd.21
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 00:08:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613981285; cv=pass;
        d=google.com; s=arc-20160816;
        b=nXs1ncGQHg/IUBjCL5koIbw6tMemypIlZM3xsDy1ht+X9SEpXBv14jg3xyTMheKRDG
         NMQxt6yWU/N5NTUZVvlSmP5O/JFmlngGh4FfpeEvc5FXTM+eSjVyVZCbmtqb23KwzEVL
         gEJehxPVALeNn6Vtf76aBq+IMdmLJTdkiAojaM/mRmvnkW/y5RG8LStkBBb9rbYXo97N
         a7trll0U9ipy1q8zvux5VT/byCVqyZ1iepHOLw36pDqTJk/qiLvVEc/H63vSAWYhncpA
         RR5HEgaGOjmuMVu/QMhr3aqzq6XWPsoY39fPhEozaNw+an1DrX3s+SMOjKvpk7IRbu1K
         qmZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Gikf+erieniIfsjGH6NERTXUB2+cQLthuo+VYhf/gbo=;
        b=uqFJuyoiOZXG5KBZPRjwvpCp0sm3lySu+znpi9hN5f5lILPwk29hzx35z1T0chY6zl
         aN3xZMnhtX2+JJiqYyOPS6BFNvlZaNKen3kN/Z6K4X+g3aVIxLlYKTqN8y3inJpEYMrv
         LCtCnO/ViUOeTXGDofVeX+HzqN6nKkquZ+bsnv3r2YC+vaq8PXYqb4LLiTfakMXbcUjq
         AHqDjFYqoj5+hOPGhxMKLlPgTlb6zwP2bDDYvFCezgW2FCsBbSkL3DJcAYvqK5zwjhGn
         fy5AA62gXIx3pjfvOyVuIILcnXjkRmxIXZ7pvhP7zYn3gSQ5w6eUz0lsMDhc7JMZPSJX
         ISng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gikf+erieniIfsjGH6NERTXUB2+cQLthuo+VYhf/gbo=;
        b=Mler1+4bZnxh1Sip/Vpi6favr8ypccIYn99CL/JSwQdKZ+ISmLOgPBllPs3VJ4q7Ul
         RTkTOclpv+w6csr6tTdExcMfLFoS0xKHvJfgIKfArLJhudj41QcOAxCzts1bWaxR8mZc
         7xWyvjGyRPoolISuEZC0fJRjvkx3C6/1f2BVRpfao9mTJ5f4akg+raDHAksepXnP0AHU
         WI5kfgFMvZRcnwpEyGxSIY/Rq95TN1VaG6poiQeETtuiSqHDkJIfnYtKUZ3+JWQNCDu9
         5/djOVtwJo/HsB+5g2L2+OocWWKHxhvUyzTsuDwI42s0eQoRBC1uVlaLj74M9dsrouOh
         +/Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Gikf+erieniIfsjGH6NERTXUB2+cQLthuo+VYhf/gbo=;
        b=spDwf2igL35Q2SaJejTPAA142FvsdmARO1fwYOqIgRXA5Nr8Hx/efzHsWJu2NOl9mT
         ZenrXbOuViFgRG16tVZ6quFt4uqooiiA7j3r90Hk27940ZF8nCuh8KX0Wxl2qkC+gbV0
         JWDpQ7h8UIY4u50e2SQ45c3hc654RnoOs6txMY0o5oOv+s6BTk/PBVUanmKoOeY39biG
         Lb633SiRVuGP6jUBJz04Ymp8PBe/7L+9hlxnYWhW8tTn5x3qTDp4wtzXe6T8clITKjHX
         KCXIPDraJcbY0L9rwd9edQdDWgT6XQjuo+7F1/XbInjxLHNv3C9EJMYy9FqFLvXjODUz
         NkIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/K31JkeFdHylYiPDXVtL39e/qwSdj+OULOlny3QJKC136qrLc
	U8MLZxQZVZ7mIG2R34lKRuw=
X-Google-Smtp-Source: ABdhPJwWYoYFUCEW3bIWnZhyll4QXa0M/K06YR1W/oud04YFEQnGUck+ognqtktqZmUDDPLDe7xnbQ==
X-Received: by 2002:a05:6512:519:: with SMTP id o25mr12955027lfb.529.1613981285239;
        Mon, 22 Feb 2021 00:08:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls3721916lfu.3.gmail; Mon,
 22 Feb 2021 00:08:04 -0800 (PST)
X-Received: by 2002:ac2:4ad0:: with SMTP id m16mr10966198lfp.195.1613981284274;
        Mon, 22 Feb 2021 00:08:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613981284; cv=none;
        d=google.com; s=arc-20160816;
        b=LqCn2E2wwoXVDESz6mZM2bUsSh/zshE+EPRUnUhfz+C6gE5s3qtN33sBumoDkDG1ba
         VXfwOJoJw3SGEvXU2f7xOGKmd0LwktVB0ieXcNlJmT51bVac4HFD7WR4giB2Dw1sjy6H
         /ItwplvbjHPuuo5yAD7e3bzoI/uxMN9lwQf+ptooARG5aJipU/Y7zB30L8NkDhw6qSzD
         8N8+nu34i7c4DN69pVCVjD+Lf7BqaEWNZtK2fAcESfmA+J2XX5WrR0cSxHT/5CjOPQ93
         +I38NX9Mi+WObLwNSLNyTTwMNSGG2zCA3Myc99jwoox3Dlu7lTYAJKGneMI9lm9Q9tcz
         ZokQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=4ZF9vUY2CsLKz7kuuDFD0UWH9WYTZL44sQgQxJcGctA=;
        b=YqSR+vU0pSFtMRrrjFKm11c3pdJpZItkj0zqylh0QyIOAtN7lMywNX0EyW1AcS4cAs
         iQuWoqNF2m4sqjlzri3OZ+H04b6HgJdEk79H1/VYkxYd20Sz7admieJdibqOpnjDGpXH
         S24gt4sSn+vJ8+BllJbO5AGlhakAhRIbevk0MSgwNQlb6FbDr3rT3j8gDI72SQ46rn7I
         herVokL9qnWSSV3X9i400E3Kq1x4xlRLKjTez4Kn5oqOFIx2sTEl8OlVYiUEfzYcYx+J
         aDcRAZm4r8VU31c8fJx7q2rVEXApmKZNxWDkJzav09+Tu+qnviHxw6KkHnImZxgymeTA
         eM5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay6-d.mail.gandi.net (relay6-d.mail.gandi.net. [217.70.183.198])
        by gmr-mx.google.com with ESMTPS id g12si416885lfu.13.2021.02.22.00.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 22 Feb 2021 00:08:04 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.198;
X-Originating-IP: 81.185.166.122
Received: from localhost.localdomain (122.166.185.81.rev.sfr.net [81.185.166.122])
	(Authenticated sender: alex@ghiti.fr)
	by relay6-d.mail.gandi.net (Postfix) with ESMTPSA id 13306C0006;
	Mon, 22 Feb 2021 08:07:56 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrew Morton <akpm@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH] riscv: Pass virtual addresses to kasan_mem_to_shadow
Date: Mon, 22 Feb 2021 03:07:34 -0500
Message-Id: <20210222080734.31631-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.198 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

kasan_mem_to_shadow translates virtual addresses to kasan shadow
addresses whereas for_each_mem_range returns physical addresses: it is
then required to use __va on those addresses before passing them to
kasan_mem_to_shadow.

Fixes: b10d6bca8720 ("arch, drivers: replace for_each_membock() with for_each_mem_range()")
Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/mm/kasan_init.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 4b9149f963d3..6d3b88f2c566 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -148,8 +148,8 @@ void __init kasan_init(void)
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
 	for_each_mem_range(i, &_start, &_end) {
-		void *start = (void *)_start;
-		void *end = (void *)_end;
+		void *start = (void *)__va(_start);
+		void *end = (void *)__va(_end);
 
 		if (start >= end)
 			break;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210222080734.31631-1-alex%40ghiti.fr.
