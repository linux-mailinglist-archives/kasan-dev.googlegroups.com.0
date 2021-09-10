Return-Path: <kasan-dev+bncBC5JXFXXVEGRBFWK5KEQMGQEGIUBCJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 339B94060E4
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:21:44 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id v65-20020a627a44000000b003f286b054cbsf161574pfc.11
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:21:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233302; cv=pass;
        d=google.com; s=arc-20160816;
        b=tuFej0swoWX5gAQPijZhXLiq9t/yumb0VIBrG+K1/quCM+cS9MYci2dqlZb0B8mgmN
         JQJgk/1UILtZBWHaCGNZzjs3A/Q0G0Bcxg39PdFVbEp51Mh4w8+K+THRdCknE6f6U6b2
         ZbwiMyQKD9LfisipZYguIJK9FBEtABYgjBNib4K+KfE3EOMPkEoqeV6ML7rGJdvWVzXg
         TFJfwKY1oaXWXCAJvLLusunIBreesCmeiF/VW0Fo1LtMDsG+Eor90t2G9oELW5/FUcvM
         Lf/S2GnKYlWxJKru4z3uyjETSUhFC/FuGKdUQI7NqEELnwGrvCEkx10uWgKaXC/J8GjN
         kqIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kgnT0+GiiSUi9JA2v+MrkbuFpR8f4KOfmd0xS7GYm2E=;
        b=Ultqlt+TnNLo6MFpOblv+qwQ2fCJJGNzLgzBLGxcn3lx4RIaOzpIhOTvJqvBc8I8LJ
         3IsFnLGNumsZF0wWzlsQUtQmtFC3yqLq4dM6H1nGx5Zc65yjNFsH10ysVBkSRiySpXSW
         OFrDfjN+LD8V5VNfCrEBmnlTkcxf6j+XL1BRBhv6X7PosmtytiUl64Bm7/bGFAWUKD6a
         2WVVg0VMeFbeNvarn9X3oRLO8Y7dcA1OmtaspO1eYR5+nHDTMw2TlmRMXkJZnkE6Ofrq
         n7C9GEYl5ZwEeP4G61tag1iojQcM7T8lHszwJTnNEkwHE2aU43VzRupaJSob/2T/tgxx
         nWTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YVDH9aWK;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kgnT0+GiiSUi9JA2v+MrkbuFpR8f4KOfmd0xS7GYm2E=;
        b=KIQ4kL9xGpl5OIf4fqCNrXWfD/PN7bp03R0TilU3GD0giGpaYOdt3tdDt8W95KXII0
         uDP99pWpXtCCS1cbcY/Sb3UA4V1MUHDXDs1Ur6JqczUsKQWHrFG2DgLJWYaZ+RiuvREE
         xKQvqQNrO3Pfod9PUagbsBjdhKtZ5WjrdkxcsqTl/cfmP8zPf6tg5eSDus8lBYxNuSkP
         JoYoSbLgrv8fHvrqQynnF0pWWX1yE+LaadCnO8m18Ny22FUEBp/B4+Yj46M/35pyWnY0
         Lk9Ned9qq1rUCT5s8Fl7oc+dv7ZmJQ95hGpeTRBZMZkW5xyyWUJNG3t4+zQkQtMdil8C
         j0lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kgnT0+GiiSUi9JA2v+MrkbuFpR8f4KOfmd0xS7GYm2E=;
        b=y6YCZK9JC8JKEcCYlqvC9P50p2nAnmyB9xSryZixgFLAVdByaWpZItRs+jP2HPbRhI
         T9oYBy951TwMtmwYOSq8ry19kLjgS+trqvHk5uwwyLZz3vrTOXjD5FmAl5JXpmDs/Ri/
         6SNZClbLTq9mpzJSSBueFmdcfIiwuj+nPVj2lcuKJFHqytjtBHbPlc/CkE84HsDhXDCU
         jFMQ9nZnByH7ZxnB5NYoW5yj2DH3EUGAsO95kl0vWKPh6sdS8ZjiSZlJZqzziSGOfJuv
         ph2d2xlQ/G/K0LmvezxNxqxB90ON8d3eCh7S/pfro0OI2TFQ1+nIDnN93Xg/WZZPwOBc
         CpQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530YUTWBX3/QtpTYEkgE+B58kCBL6whsjxVlCNTY56pecnfaB4G8
	943/Y0wbTbgxpK0v57N0c00=
X-Google-Smtp-Source: ABdhPJyj8rlvvUvBJ844W5b+bCjxw3Qi/RRDvastyj4YL1AXhDM8IgZTIUMmSjtnZg3F53IfB3af2A==
X-Received: by 2002:a62:7c0d:0:b0:3fe:60d2:bce2 with SMTP id x13-20020a627c0d000000b003fe60d2bce2mr5479494pfc.27.1631233302793;
        Thu, 09 Sep 2021 17:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c405:: with SMTP id k5ls2089213plk.5.gmail; Thu, 09
 Sep 2021 17:21:42 -0700 (PDT)
X-Received: by 2002:a17:902:aa88:b0:13a:95d:d059 with SMTP id d8-20020a170902aa8800b0013a095dd059mr5017858plr.65.1631233302156;
        Thu, 09 Sep 2021 17:21:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233302; cv=none;
        d=google.com; s=arc-20160816;
        b=BrpU3zB8JXYMsHePEQm01KB5q0obSmb4JdsP4hldv5ufXji6xQkdbibeugBF54UMRU
         RMN8b8V5/c1ULdtKeic+ATCPQxpoD1Zzik5uUXoblpPzu/RJD82kcG32D2536ub8ni8Y
         L18F5f19o6+lV3dO0XLtzhyqrb4rkD9ogvPOUJxy0UNfG9DXZBfjukkDiwUoPA3vBicl
         1mC/dEIjY/CRzTCszWqS7XHAwMZVeLsES4U/4rZxO7amlyQub/A9fJPODIlvb07UDl5V
         pkcy4NQpQmeALGzMSG0QJVYg+goufxMccGBHJ4Jua7JTEYSuOkA4STpQ6vZaTOgLS3DY
         7ThA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=k3L84Gxsg8jK/aqN9axvOl5wWF1RP8V7g/OrMDEMgG8=;
        b=Q//1HYgc3PL0Xpl46Zc7bw3lwJmH21NyyR4pJZxOLzZ0jmtIT2YxL4o+HQMzc/j6rb
         HWsWQDIYv+HB/DDGwmCaDKMWCYXlvylws9WCmstOSbpLHgZvGahBB4QQeJnt7tLgEa5k
         HlQlgsnFqhK9SzHTVLPft4gC2O4OL6aMVSExS8mqtonvSfNfGAC6wgFR7kkf6cD7iZf+
         hXd/5/RcdBe17J7sf5yNE9xh2RNqa8t6VtlKVOOr1hSfvra5PUyikFiqY3EO5EhhAKSt
         EUeknyKWmryvgZG6TMjS1eH20qExkXlQ3TrNcjyCwA6tzsVvdSMVOUlSd6ImiZr1LUDl
         O5PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YVDH9aWK;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a14si427544pjg.2.2021.09.09.17.21.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:21:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id BF08F60F24;
	Fri, 10 Sep 2021 00:21:40 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.10 53/53] kasan: test: avoid corrupting memory in kasan_rcu_uaf
Date: Thu,  9 Sep 2021 20:20:28 -0400
Message-Id: <20210910002028.175174-53-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910002028.175174-1-sashal@kernel.org>
References: <20210910002028.175174-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YVDH9aWK;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Andrey Konovalov <andreyknvl@gmail.com>

[ Upstream commit f16de0bcdb55bf18e2533ca625f3e4b4952f254c ]

kasan_rcu_uaf() writes to freed memory via kasan_rcu_reclaim(), which is
only safe with the GENERIC mode (as it uses quarantine).  For other modes,
this test corrupts kernel memory, which might result in a crash.

Turn the write into a read.

Link: https://lkml.kernel.org/r/b6f2c3bf712d2457c783fa59498225b66a634f62.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan_module.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index 2d68db6ae67b..1c6e06136f78 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -73,7 +73,7 @@ static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
 						struct kasan_rcu_info, rcu);
 
 	kfree(fp);
-	fp->i = 1;
+	((volatile struct kasan_rcu_info *)fp)->i;
 }
 
 static noinline void __init kasan_rcu_uaf(void)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910002028.175174-53-sashal%40kernel.org.
