Return-Path: <kasan-dev+bncBDQ27FVWWUFRBIUM5PXQKGQEDJ6B24Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id C5C44125897
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 01:36:51 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id 6sf2450782pfv.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 16:36:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576715810; cv=pass;
        d=google.com; s=arc-20160816;
        b=xE7y7XxQr5YIDkDe7/nqRl4yDxzEjb5G/WPWAgsDD1/N2Uxr1uXD5beWna+lSQ9/pe
         QLb99cJ8YgsltN7SzmNXK2LhmhmCZHuq7YXItZhb8u2bk+UiPd1AG6sEooVsWNCXiTa+
         RdRr9Bc0LdHwFz71u8QlZ2a5vH88PlbzTTYWs99lPUhYUQCbfani+B+AogPt0cVgryS+
         s84l4tBssS3sXUjNrMFVdo6nSOd9jDZjpKKerDZRzxnOscsUbTdEPn65tDxfTXXJT8K3
         AihA8AiHrs5wBJq1CCdYUVPtr2yoME+LDnBsexZ4MKDTKevrmvN9xOM7UzU90L0MyE8t
         1DoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5MxZWSI0zgH8OTaMcIGvUyMjm3GOgRTiiRcQOOIB5Ss=;
        b=iesZzVVGhTeQEHSFx9cYT8c7nBWT70vNhwfOrjJ4+7A7lEUqeTGtfXGfDu+gmwL9Dy
         X3xbX+d5XUiXtZDaDABL4XA0Duh5vOzwSagZzLRX2psDjiukA1H6fvz5rR5CYdDcVCbH
         OZFRrcUPxPqVj+yj8rFOW0NHvVt56wQ0vGuI5Lp1SA/7l2nfQHNannzIta2+ALPQ+tF8
         DfBEqq8Q/Mb25VEqtqXHgIsDW3nSEoqvWQ9/6uIicHSbqCM43M4gLl/E5PaFGYbA91XE
         rQ2q9gTTY8s7fxbdaKmyZQvw3m0hGP7bo6O7zDO+bfJoGXr9TsC0p+g7b7pcb/UmXVm4
         SNqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=k4Nwt35P;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5MxZWSI0zgH8OTaMcIGvUyMjm3GOgRTiiRcQOOIB5Ss=;
        b=l6FMFefZq4gX5fMNX4HBhc9/Badw341bC23nYBg7quNT1e17rKPUN5TmbEdsTTU/jz
         osj4QRWMZpWoUyTLWHMcAX7pQCsKcydrxLVHjpEJ6RiNgW2yb+n8zRWcWt5RzkYF6e+L
         IxwMSb18aSx+cN+qQ0n6fFaXinvpFM8zSlwipyOEbx7GeyI1APRBiRtckXzS1AxP3DLj
         5HXKHVr0xbLgQVMzoeTwZDFBvppHUnDBC0m4ptdZR4Qqx2Orj2q3lftnhYGjkcW9mnj5
         O2QWf2RHgW4UbigHNS+h/JCRhDSI9YPK0Dt4uSZJvmZ7SnWw3esc9nW7CM/SwOdgrMM0
         8Yvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5MxZWSI0zgH8OTaMcIGvUyMjm3GOgRTiiRcQOOIB5Ss=;
        b=WJKEIrZyX9axTtm6FmaeJZSHJ30nBy5KCNTKeWTWfsWGf5YpdoB4nCjCT4VwkMl9a6
         /9u5fUUbrrBGh5AFKBxcNm5tCE3zgpwt+2wiXDLkt/iK0bcQZoVvyXRkoSxixpzwut4M
         61IslQpDZJWFC1o/ULPD+oXH9/FqVR7Gyfbt1Jtb1gCsqVYOk6Bpv5SsGr/XYHsPRcRh
         UdM1NauyWjLWLxam7vA0UtTuducWMLEl0vMryWnkJzrJ/rAQN9/cXHubByJn3xKkR+UJ
         Q2/ioi3jlUTMVEMXmKjqgniPeFkMySGKGfIwUlr/TZycqcTHfhzdNKzhJAA3ovi0d3BV
         pVkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWtWNhL/DjrNW2yxiQOaucI9C6UGchwAQ4675Gt8LA2+wQhjK0Q
	8cuBtRTGstosxrIMrESTYGE=
X-Google-Smtp-Source: APXvYqw1U+H0i9+VNTLwDlc4CUc137DuZGjR3SqUCM/igZrpJIDI40Q73iQaJLl868FvU7xeIjyNYg==
X-Received: by 2002:a17:90a:20c4:: with SMTP id f62mr6388778pjg.70.1576715810522;
        Wed, 18 Dec 2019 16:36:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:68cc:: with SMTP id k12ls869797pgt.15.gmail; Wed, 18 Dec
 2019 16:36:50 -0800 (PST)
X-Received: by 2002:a63:4d4c:: with SMTP id n12mr6264996pgl.212.1576715810047;
        Wed, 18 Dec 2019 16:36:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576715810; cv=none;
        d=google.com; s=arc-20160816;
        b=Indr0C9e/Z0FVB1MEfPN5F5+hOiBX0oaz+Jbac/h3JV5HIZPrMRd+4kHakT0DzjtHJ
         +Ri0Pf3Ixk40SiFYLTk6D1multsxUck+mDT8SxXkz8Y/dkiO6B2hgVygFGr843eTNCkB
         hSpuKZhqFkYndjBdxKcOqec6tFxXYl1/jlQt6XEy9nHRObw+KKLTpynoMEDvjq3eDCqN
         Vmmp/cNFO2oxvBunTLj6gYPAvgtKtw6x82AM+pBE6s+KhyiRQa0OL2AF/lN3iFkiGgw/
         EIPMJamLjSXtByG9kRiAAF83qHrrhFFLOMWZgiaiu5z1ZqvylzRjHbJG+UwO+ITDlHgZ
         dEoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jwvqhmbLPpvanCf4CYPj6H756JJZayFM0Q320MsSZZo=;
        b=MWhXIkMHNjc3d/2RUURzV7mxiB3X8d6e+KMhNd0xfgjxvi/0aeoBjhXSopo4pEDpqJ
         aIeeWME0Vr+qxsJejEapTSTXheEM1KYJ8wmK92blGL56mkoxtbz9+Bj3BJxlHf9rb9M/
         p8Abqb2a69TMZepertRbhVTfgvoCgougdTtst2zHBYO9wdru0IucXWYAD4xTmdWHBfar
         sHl2sWR0xQ9ghk4PBvPYzoNebP9a3iK2E2wUjzN8ox1mJC4YSRiDfbiJ6nVylQK3Zexm
         109MQL5oDR2Ov3/Ih1ldTN/EWiSiHR/oB6S2gZyb5wKNa7B6IrR1ls6/7lA1JCUh142p
         sfng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=k4Nwt35P;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id 65si208860pfx.5.2019.12.18.16.36.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 16:36:50 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id q10so2159181pfs.6
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 16:36:50 -0800 (PST)
X-Received: by 2002:a63:211f:: with SMTP id h31mr5808165pgh.299.1576715809809;
        Wed, 18 Dec 2019 16:36:49 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b05d-cbfe-b2ee-de17.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b05d:cbfe:b2ee:de17])
        by smtp.gmail.com with ESMTPSA id k12sm4636303pgm.65.2019.12.18.16.36.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Dec 2019 16:36:49 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v4 3/4] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Thu, 19 Dec 2019 11:36:29 +1100
Message-Id: <20191219003630.31288-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191219003630.31288-1-dja@axtens.net>
References: <20191219003630.31288-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=k4Nwt35P;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

kasan is already implied by the directory name, we don't need to
repeat it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/mm/kasan/Makefile                       | 2 +-
 arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} | 0
 2 files changed, 1 insertion(+), 1 deletion(-)
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)

diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index 6577897673dd..36a4e1b10b2d 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -2,4 +2,4 @@
 
 KASAN_SANITIZE := n
 
-obj-$(CONFIG_PPC32)           += kasan_init_32.o
+obj-$(CONFIG_PPC32)           += init_32.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/init_32.c
similarity index 100%
rename from arch/powerpc/mm/kasan/kasan_init_32.c
rename to arch/powerpc/mm/kasan/init_32.c
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191219003630.31288-4-dja%40axtens.net.
