Return-Path: <kasan-dev+bncBDAOJ6534YNBB7MQ4TBQMGQEI26X5OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 004E5B08F46
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:28:14 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-553d7f16558sf676287e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:28:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762494; cv=pass;
        d=google.com; s=arc-20240605;
        b=ER0j69wUva1nAX0ihu1igOPmGqlTGbfyKuVj+/ck++vtPuxn2sSL6/2t35A3C3za/e
         +bmrH0v5wVByPmRBQU7sb2GZejD3MffQYJ4bhMUUop2M31sunLC3+dTtQNvrZMG1mjLE
         bkXmksZl6pv00zi4qdmgQBBO++BDzR9YbAJCfapCHZWFEsPX99qpWlKph+qMGZsYrTEs
         bFagTgeMn00gFuUsEs6CTx0GYDmjJZbJuoMl+J53V1nDaY2wmLkj1UXuaK4E0+yAvmze
         wa+gc/S09NJX11f/JC8jmZcIALyOkg9fgPqeZNCOwSTJuf722ugyxSxxnhOo4kuR5fnL
         Qn4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=QRfaTw34zCGMElKBDPAE9kc6uvL9y7hlRK3KGKI62Z4=;
        fh=fctvQUGiIVDwVbxa7QGwbjZcdzAftgR7eWQRJnPZdaE=;
        b=Iyeb8Vuo6AP8JKL/oEqmU2zNU+RmIrxbWdskYIDOrx8OMCR9stB/qki9urIQvXj4O4
         1xK0lA9XniCOD3z/FzOo2id3bmCDiSoS+AXbaMyAC/ckBypZxEXuyYQiZ7mpe1PSsDUe
         rI7rPEur7zIfVavjldV1Au0XqEQGJ+lnE2G1uaUymHz+HCrigBrYouLAahUFTJWzBptD
         l2d4hXQXrx6r8vu5UBcWfXreoquz5q3oD23IWysTYwFm7t91TI+cBBSwiKasoZN5ybu6
         6gFDXbOJqq69AZiCz1OdBjdqZxwfvsVxhQ13NGZOKP/lBSxHJ3PxD+0JLZXcDuA6gm4u
         Tq/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RVs0cEcm;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762494; x=1753367294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QRfaTw34zCGMElKBDPAE9kc6uvL9y7hlRK3KGKI62Z4=;
        b=Zq73CKU4PhfABPcxA7/aDFFDt1QJXgVCbzcDDynKmy7Oz4HERwuBHJfCnhZSwQ3Xqy
         oeupptOH1My6wAuI8X1L9pUjFWOR+FKVXwvnYFu+aMEMOvinNBgzCV2x4Nc8k2K3EJlT
         7vlEgJkHvwGz4+6OHc5uSZwLn4Z3pVWAFzTfQ/HAp6ILYT3bi2Ememazf05fLpIg5BqY
         Y6HLpNOh4KiQ8EAKN6hqPBe3CkLhqG7IOVXxroRYV209k80CqZm8dRG3PJH4OSD5lfWD
         TvzrRWFeWGqj6/HTF2q+vU1XO4/RaCzh5Oa+Dvl+h2KQvTZ+W7no8sE8nTPY+5/V3KZa
         H00A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762494; x=1753367294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=QRfaTw34zCGMElKBDPAE9kc6uvL9y7hlRK3KGKI62Z4=;
        b=hELMq5YAmUPSsEPENZu/LAHl3WPCDxHm4BMRUIzNV23BilVioY7d6BpvPLRxSnPnMT
         cQsD51jzrTBYpTlnv/ZAfY/r2xBPKgk8v0F4xG21wscnRsnZPRfdsnafxslb/1JuBbzv
         VYalAAZTt5NIQxYJ67rfuLHLw6elO9477bY/OpYJBXEDgfyZcGXy1eNxnTH1mh3OajmN
         hPF7ASwRVXxwLcBSk5h6hO/khRqbeWjPSYQmobOgasnDugPS+w/Mv1zhDfK84bacWWkx
         kMsF34qLJeWXk/AXbxgcKHKskb8HLL6zuVE6+MrBrNdt8pCPKjmy+yMJkQE5HWu/ZHJ5
         /B9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762494; x=1753367294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QRfaTw34zCGMElKBDPAE9kc6uvL9y7hlRK3KGKI62Z4=;
        b=lw6c6zC1WR2I8mleNuTDy9ep+bYANplFiutDx8mVNMgqz8EMg9vqMxBxx7dcFkMB6V
         W4aMqAmO9Pc/3oY0G6fZb6AW/TYVvoI2XHUdeiYlVozAzEWSIZmg6mXV2uk0NHE1DQqq
         RGOgg5x9ix9yQ0zJepCuhEoO0ZJR9PLhcm91tF344nIetFXvrW89J/rPBubSZe+ZhxVr
         V6OnlGqnJiD1ohdHNLIYqSbBBJI4xyelz+mX4Pyk5b1TAi/LXk1Ez2y3Mx1XIBa2PfdM
         WjWKQD4PmbrNSKHUN2k0S4sCw9rB2f6t6L4WlXuceKCvkyZkUmmyyXTMrB3KuukaLfXI
         /vEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWch9PSGODRIs/COU/eXwy00NzystVnAZjCvlkP04r+QHmR6xNyDeBtMLGCeRVZlU5NxpN6dA==@lfdr.de
X-Gm-Message-State: AOJu0Yx0zENGMJFppbDb6P8DD2750oLYs0ABPrN/7qmmbr7zDGCVhySm
	fzl+3QorYS90QjVkAm7CK437ZhWFnEv8/dst/zIWh4qRnerFrbnTKxB2
X-Google-Smtp-Source: AGHT+IFskzfub3pkCYjcCNvHvCvVGZ34kVXa06GulA1IHO7YZG0ujoImMxR+aNFYm9o5jsXJOO2xNw==
X-Received: by 2002:ac2:57c5:0:b0:54b:117b:b54e with SMTP id 2adb3069b0e04-55a233e75bcmr2236543e87.57.1752762494170;
        Thu, 17 Jul 2025 07:28:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcQ7rg5vQUIlnGcVtYkKOpzGudgDfBcZ1DxIeqg9Sb7WQ==
Received: by 2002:a05:6512:4401:b0:553:66c0:cc33 with SMTP id
 2adb3069b0e04-55a28899dbels235445e87.1.-pod-prod-01-eu; Thu, 17 Jul 2025
 07:28:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXGMY2IUIKbpvQcwnXbJifAPvEw8nwH8Eu7DYn4KD6Kni2WW4VznErgMFSsICiD2kHol3sIG/kDgA=@googlegroups.com
X-Received: by 2002:a05:6512:485:b0:553:2ce8:a000 with SMTP id 2adb3069b0e04-55a233b2fc9mr1832035e87.41.1752762491151;
        Thu, 17 Jul 2025 07:28:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762491; cv=none;
        d=google.com; s=arc-20240605;
        b=L6Pr30sB6Uk82CQj0cPySdaGlVodqLdJd1FKaUslP4l0Mt0iux9paYuMrcWdGANqmP
         ZwGSqBJJF1nGFoqig7RyDbb+Yvd1MTTxDT5Z02IxfrDBvbIcZT+hOQTL4MvR6XMryCNg
         57kBo32KkOmaoAt62DHNO7zGN7tlbVTj8oKKVSJOaLxJRaTA5KclBAY1hLWIP6RGYzOA
         1pC+kC3NK/jHLaq3lezNrT51aEjIhtf6hgFDDb1jZE5kJvLqR+NnbRSGY4bmPpOW43pB
         72KRnRqiB29I3QomWm7tixF+Y8XGm3tNHPloiQuYi1NPhZVuxR1QFItGyQhfo2oNaRdE
         9/Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4lUgc2mQ1RFMODut/DxjH0e3nH7UxMqXiDg2xTFsSSw=;
        fh=aVMHiX4HXxabqsl9dgnR+JV0daugU+QPERBYX4pmYE0=;
        b=YKZGyob0Tb+iQkGjf0r/MpxUl0Fbz+2HR6WALoPjwHF80lVj7Odhq8MdTlA7nWJjt+
         JhgTj6f2HqqymSwZ1vCSxx92ghMxgYsG6qAHKY1p0XLUO4nuWyK2yjq1i+rjZSDDtH2N
         qlAhM/1biV04ozNzPWjv3iaGmCSdmz4CtBwgAfi4067UA7tRVSFSicBjSiMOyqkAVUt6
         KI71lKtT1wCJnv3qJVVaPlQtJQ/s9g/DD6FPyBdK+Xh5/zovmRIXMXp/6HPkOwizoiYo
         EvtuTxf//fmtEC00KNQNIvYMqSbwR0IG1X1gYvkrLJ2WDVmoYwJHsVTOTJtSU1KIL/xx
         JtVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RVs0cEcm;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5593c9bd011si294373e87.9.2025.07.17.07.28.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:28:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-558fa0b2c99so852433e87.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:28:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWJh8E+3nhwhQOOZlRmFzqSesRnZD01SMWT0xUlSEWT/f6AWNL06+KicccM+GZA+qyAbmr/y9BfpGA=@googlegroups.com
X-Gm-Gg: ASbGnctWZwjlvJqo6Ek9B4Oro4tSRLa0HXmwC6t+nKH7WfO1Fz4wOsZiMi1h83OCoI2
	AYas5hcIleafj7w91o8v9l31p73C5F0oPgRbOZ0sbXnx/gbYsiOxa8tXn0hcTKkm+3Mzw04k5bV
	D5Z9nm3vZo2h0W5XRj9ZPavjkAElKe+WWmeB37iqVBzU4K35Z9572UkTuNydEw8NfOxqoLcpf2u
	3qjHmNvyanMe8hSeuZNVXil+hUN0if6wTZfSAOZUku/OlTkMgAZdd6/106T8dr51qERkxRdFNeu
	/9bALbwsnPZW7KbXbXmvI/Qq27gSZnetzP8BM89lP5qGF7S2tgAIX9pM/lfry5pF9ImJsGJlUgx
	wH7IZDGdMj8yWuBA9S7dYL7txAT1LVEi+TN29x5opwP2S00y4OoHMLFY46zSmZBqk3OPc
X-Received: by 2002:a05:6512:618:20b0:553:23f9:bb37 with SMTP id 2adb3069b0e04-55a233b2fbemr1641277e87.40.1752762490421;
        Thu, 17 Jul 2025 07:28:10 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.28.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:28:09 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 09/12] kasan/x86: call kasan_init_generic in kasan_init
Date: Thu, 17 Jul 2025 19:27:29 +0500
Message-Id: <20250717142732.292822-10-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RVs0cEcm;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which handles Generic KASAN initialization
and prints the banner. Since x86 doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op, and kasan_enabled() will return
IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/x86/mm/kasan_init_64.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d21..998b6010d6d 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -451,5 +451,5 @@ void __init kasan_init(void)
 	__flush_tlb_all();
 
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-10-snovitoll%40gmail.com.
