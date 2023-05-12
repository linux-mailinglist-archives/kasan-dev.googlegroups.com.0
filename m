Return-Path: <kasan-dev+bncBDLKPY4HVQKBBUVX7GRAMGQEKHXQKNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 19636700BCB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 17:31:31 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-3f41dcf1e28sf26783875e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 08:31:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683905490; cv=pass;
        d=google.com; s=arc-20160816;
        b=mToU/qOpLPTY1VharQbIKq2jcTmWT03p5weOCgvMC4kdw6FsugUU0BeW0VtUuXQh+K
         yUzTP61lwHLbCSn7C2RVFLlKG4VsEY4x/gwE7UEVtXA91YL5PNmlg0MtkvwX6iC5cwc+
         4w/QNd3v4nq+Q6+rMpROyKlmonHvY2JSy+ABN/s61UNf/zsB0aQAmVicmpqBWvsvmNHV
         7BrCzQiwumOfEKsE75l06x26vGgEUk/pRZsjDov4IUehvers3wSyDZdfTaNNtaNBgVqx
         YGlmzLqwetLO9ssTbLXcZcTzRIU9H3agB3R27udqMFomb5csJni249C++d+MGE8WORuP
         yVYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=Sod8iGXsyX2+V2GxJUtZSQjqELSlKJ3d/TqAkESOpxo=;
        b=Ysc7GAna1r0RUckKiYuW1P/3VyJJPfk4u68S76kujPWvWBN2IWVnjHN7ZmUA4n2Qy3
         IViszWqRMR+X+EJKFhs5VXUMq86sCEnUkUykMtvQ6FC8WqEKRJ3lRJvXJAahv+ayUSAG
         lzGi+UUrLm0gjmB4AtgoX02+4Toh/Edx2uUtgaIIe8ZwzEiLXCpaQlDA3w3A1h7ZTJAe
         598aTHfu5wv970SUR6qeBDC90sY6dvGk4RiWNyK8SWwAvLQXRF72+EPb+LnPRi5aMVVE
         pYEAEZma6PyslD2mQAj4GvN9acmsgqAKorvrXHiN1kZAbxO/9VDPFYomk+pg36QoqYNa
         YR8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683905490; x=1686497490;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Sod8iGXsyX2+V2GxJUtZSQjqELSlKJ3d/TqAkESOpxo=;
        b=DP4LcOnN8bt3nshqd0+Kpp5Do6Nmls3cvh8jxdoG6slcSuSm//mzbg3FioDa/0/mDr
         OP69gWeSXsifle00HXhwoXuMWgFXLBm5wHA+3ushvYnakpml2/1wDbtFCjdNfdk44z9L
         gE8uYhPfu3QfO2gUljXPCG0Me6hTzrGiCgn0BQsLVpotcXrh8lwTCxyH1CZ6EiaS5U6C
         zgEYdNk1ThhgDfQ66NJSjZRhKN5brXb+T06BxMArciYg8wmb582XRinfwxDSYdHKTZSl
         ZnAkP2953pyueAlYKWsTUjAd1tCYgLE25UrLFoJqD8GAizjEuIQ9f5NoOQqu17c7drNp
         9vaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683905490; x=1686497490;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Sod8iGXsyX2+V2GxJUtZSQjqELSlKJ3d/TqAkESOpxo=;
        b=YqWSD9pd2I7zmuSUERHakeIuj5sk7xG/I57mxuvtEdsKYCc22DAJYc/Ujfl5YxDjEJ
         zAaNXg0Kt5R5sh5WyRMcd693dPz0MP5S5Gsl1eC7ebdm4S36wX5qafWXToCRaJPrJVp4
         IjMKBysbcf2JmQD0YUjFvZxPefxNwgh2hk9+ZmZ5DEgN6mw2cdSq2sce2tZNWxESau/5
         8clQZ8r7/Nn14KAm0tklLvBg/KnciRbbeD0B2l/o4BFTAKwGXF1yQdMNw8rBZ+YWlINe
         Mvjmgzj2kY3x1trTbVwkoPGz+Y8M22rfnfyoD5T118pR7UsSGvMcg1RZUJkdR4vlUdwW
         0Pbw==
X-Gm-Message-State: AC+VfDxQeAnVqJT9oUBZSvDWrNogkiNmaJHDuMpYpWlGtV9J3VBvcfOn
	RWoiAC9YIEbPWU0rWvpPdG4=
X-Google-Smtp-Source: ACHHUZ40P4EAYjIRtDxrSP5h3SjWtP4Y5CZqZe/JVtOVv3dlen8iyguQHFQNXEJPOwaQHf3ogPCG6g==
X-Received: by 2002:a05:600c:2158:b0:3f4:2148:e8de with SMTP id v24-20020a05600c215800b003f42148e8demr3722438wml.1.1683905490423;
        Fri, 12 May 2023 08:31:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4445:b0:3f1:68f0:7451 with SMTP id
 v5-20020a05600c444500b003f168f07451ls590823wmn.3.-pod-canary-gmail; Fri, 12
 May 2023 08:31:29 -0700 (PDT)
X-Received: by 2002:a7b:ce8e:0:b0:3f1:4971:5cd1 with SMTP id q14-20020a7bce8e000000b003f149715cd1mr17132044wmj.21.1683905489106;
        Fri, 12 May 2023 08:31:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683905489; cv=none;
        d=google.com; s=arc-20160816;
        b=U8fxdIV9oBNYdMQeQxAI+0Cm2mAN4yCrz5/OV64XXF8hnLs0Dpz3DT7PWcfE9UDaGT
         USuXXZ68Y4yAyJ2GK81SHILEj5/DBO+RU+lDWL7iVT84SnHe+w7tH+9jUHIfeAWyT9iV
         10dEiSWL4f216VsQhUznSi0TOyWKa1EBufq8FIdDYK+x6hy/fGyn74hv7vAUf2DdkZyd
         m8cXXDgXoG3gDB9NjQvBELrGFGxHpbzcnv2yGwbPzHjHbwGv5JsUbJtots8iYLTxF4CE
         OgYSEvVH6ESJHgQUPub8ICYzi/pE2vOiIKbrL7UkLlT8rwmCdNvUocoZXYsROIYQgICa
         1fIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=Gx/36Yvu5GjGusiKHOwQWEOxDSEHDV6oGp9a2923mO8=;
        b=FjeYKihuuWxfE37hfoixryjnNACY4tGZchAvmkW46AQRfPsIJZ+p/k+1av3SpdVHjv
         v/EfC5yWAX6TbSLHc+Vp64DIjPUHCNJewD5d1nf9dfXSGQ756rVc8rFIAHbXbVkyGtj9
         1OHE9BPvq8FejuB16GJnNeGydE+0XURNfoVrVgB3Fru6l4kBDG6tkkL2KwVGbtBi2RkD
         ybBj2FMngq6D8p8IRzHbqjCuX3CzzD4iwOt9EcqmhjPai4jNR4szny1CWoqVyVPwFFPh
         cme5Wi/JAyg5xFg8LQmmGdnKsQUWspf9cVNMKHPA/J8P1BI7V8SwYnya6Lz57755SBRt
         VyCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id k9-20020a05600c1c8900b003f16ecd5e6esi1001136wms.4.2023.05.12.08.31.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 May 2023 08:31:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4QHt5r4h20z9shD;
	Fri, 12 May 2023 17:31:28 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id rIDy-JiO_jv1; Fri, 12 May 2023 17:31:28 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4QHt5r3s9wz9sh9;
	Fri, 12 May 2023 17:31:28 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 732B18B78C;
	Fri, 12 May 2023 17:31:28 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id H1LpH-jMWSRN; Fri, 12 May 2023 17:31:28 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (unknown [172.25.230.108])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 5678D8B763;
	Fri, 12 May 2023 17:31:28 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (localhost [127.0.0.1])
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.16.1) with ESMTPS id 34CFVRlp027559
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Fri, 12 May 2023 17:31:27 +0200
Received: (from chleroy@localhost)
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.17.1/Submit) id 34CFVQ9N027555;
	Fri, 12 May 2023 17:31:26 +0200
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
Subject: [PATCH 0/3] Extend KCSAN to all powerpc
Date: Fri, 12 May 2023 17:31:16 +0200
Message-Id: <cover.1683892665.git.christophe.leroy@csgroup.eu>
X-Mailer: git-send-email 2.40.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=ed25519-sha256; t=1683905477; l=837; i=christophe.leroy@csgroup.eu; s=20211009; h=from:subject:message-id; bh=hPBnA5KflZMsLfBVOf1qnFl729hUS0enPhkbxf5HtTs=; b=+rCPMq09lu0PQQBWq0K3cX4hp8o3P5mr2OmgxPEWSSY2TZtz6UHhi0/tZZqKNtNMu8nfSrXT9 2/46XXMIUz7C1yYchavqsPeWJAztLAyhgUonNSsXnrmrAL0V9j9ZI1a
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

This series enables KCSAN on all powerpc.

To do this, a fix is required to KCSAN core.

Once that fix is done, the stubs can also be removed from xtensa.

It would be nice if patch 1 could go in v6.4 as a fix, then patches 2 and 3
could be handled separately in each architecture in next cycle.

Christophe Leroy (2):
  kcsan: Don't expect 64 bits atomic builtins from 32 bits architectures
  xtensa: Remove 64 bits atomic builtins stubs

Rohan McLure (1):
  powerpc/{32,book3e}: kcsan: Extend KCSAN Support

 arch/powerpc/Kconfig          |  2 +-
 arch/xtensa/lib/Makefile      |  2 --
 arch/xtensa/lib/kcsan-stubs.c | 54 -----------------------------------
 kernel/kcsan/core.c           |  2 ++
 4 files changed, 3 insertions(+), 57 deletions(-)
 delete mode 100644 arch/xtensa/lib/kcsan-stubs.c

-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1683892665.git.christophe.leroy%40csgroup.eu.
