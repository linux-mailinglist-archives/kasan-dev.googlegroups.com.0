Return-Path: <kasan-dev+bncBDQ27FVWWUFRBX73RP2QKGQENVSYSPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D82B31B789B
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 16:55:28 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id x16sf8027333pgi.0
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 07:55:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587740127; cv=pass;
        d=google.com; s=arc-20160816;
        b=deVTe2qMzGsC2GMcStiR6ROfaAJXqHKSuHuRwzP2IX0VgfFRGZSQtqAhB/L2xGzIJp
         BFBF8rUF01kAExWPqx3CNXrYrOgs/JXKufe828LYhEdLzu/hYK3P5ny83gGSoHLHCgw/
         kQDA+XM7itk4N0Kq/YA87nsAhP080i6fPFZ1+sEmr8GowH3ruU3takaMJ3fEIM8Is0p7
         aw+qTr2RcFwcKac8dHm/hNKYwST38pGkjF5K8Kn1xtg9mYP/InTJItdR7/yRxASQgxF6
         RgaVmZZnNJW8JcH5r+18txcnh58rqW1kH0amba5FRGv1/XHPCyBnJna66C20abyRjpeV
         Ewrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=b0yMyV6be3lvxugxLQ7l/DwS4X1gfawa44HPkZf6bW0=;
        b=TLs3zlMIodKe4hYcX044ZLU//uFlSY4mcg59eR6JU7fs+lXqRPFjY5nrjANu6oiDuD
         923AXGCjEvqubVS+iYl5hZw1+Xkj5B78kXWstsYASaOF7vJ0pcgpH+/DqJRxNgM1Ay6F
         IGYuTZKwXrW9TDPe6s2i2PrCRshQHtOPmWSeSBHvXxhcyxo9lmWK0N7g96rRe5JxxPHT
         KGqYl8e6U2QcGd2t21r21BxSy9TWXm2m8rZ/32NgGn+rrph0TDi7VQQAASdj18XHuqFF
         waqlfW4kJbodfgK5qcWf4UX2gje4sx3k31EWGx8FuNz6VjAkfcnkN/zvsZ1blcCFuu0O
         mP7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=o941UkGJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b0yMyV6be3lvxugxLQ7l/DwS4X1gfawa44HPkZf6bW0=;
        b=TKgnNAEV/HX78UtTpk7kqHAugb7O7I9oqtb0zPwzvXhM9LWwgCD/fQTAa9MRoMmnr2
         30Nw2BjUB8MWrs5dW/9jDkoHbVAx7yux+9dG8GeDeuD5hp9Q6aVzCYoTd1VaJFiABua/
         iAA0oG9z/nZp5k/rZgDrMnykPicpJ+A84FWAC/n/1WbaFzX1NABIAUCpSwN292PQ+AS/
         i4Yn49EdKdBUoLo/iweL3IHg9hMuhlJjuECxjzJIIdPpPk8u/OcTBJp1/IiV8SWlm6xb
         q9MiCz6wHYaDgn4J7SnpeX5tsHIRWLW+O1rWmQ8TrK0SEjSK2ycaKcVWR9MfIAChrjX7
         WCHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b0yMyV6be3lvxugxLQ7l/DwS4X1gfawa44HPkZf6bW0=;
        b=qz0OBLZ5571FZaeT9yTb9ya7EqEQA2THneg3BpeZcdEQq7Xhch5bNbG/AboF8x2qM/
         W5MIt5EHjXvwHnj7nczoEcxLcJUqzT4PMzbRYVy1WOaEAYIk3zK4m3sKXptQ930/SyN4
         hNRmW3p3qPsHKJJu1dTgStbqha5du5vRUFKfYpOBHFTQ6chp4oVwkUs7GqvvRfJukk3C
         LM0uA6sHwhfin3kJi/emTf0V1hUB0mRGKL+TyhsFxcpJ4Q4dzDZ0pbBdDW5cAO1GgEis
         Y+10/IQZc+BeQFMg1eTvJ1zMqZ+m1pYw+IZyrZwzd6tplFcDulhhu6UDBIRyYyAYDwh2
         iLdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZ26d9j7KnQ+AsGgDN0hJvayURLhawjJ0TjT2xW7DCmXIh+NGrU
	odc1RmWW0dQMA87WKChAR2g=
X-Google-Smtp-Source: APiQypJP+Rzoi7EVaOtaYzXgODfo+6MoTUfL3ZE6lfqNrm/maz9XUkNqgwxenzGqrzlJRroqxRGxSQ==
X-Received: by 2002:a17:90a:d3ca:: with SMTP id d10mr6853817pjw.24.1587740127347;
        Fri, 24 Apr 2020 07:55:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7c89:: with SMTP id x131ls6356603pfc.5.gmail; Fri, 24
 Apr 2020 07:55:27 -0700 (PDT)
X-Received: by 2002:aa7:8118:: with SMTP id b24mr10021200pfi.321.1587740126889;
        Fri, 24 Apr 2020 07:55:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587740126; cv=none;
        d=google.com; s=arc-20160816;
        b=ip2C+Q+8gLy43Y8332rsaVgfsTP3m1KczJ2lek/XrLvv3N6BQ2E2S/J93oNRK2Is1g
         wwiYYo4CYwduYWTJ5PwWo7jfA+JPHiV+BqznpI4i1WVu9E61bIt72DhOWHz37JIrU4bJ
         xQsxjf4dMz23UZnny1EQXEKOqQgHk7joywo9OT/9H1UfT9jAnNVUWhvzTZkDaE6uzYlF
         otidJ49dJTwdPpCSEpKkPe8KtB2x9SfxPwd6lur7DlB2xJ0IM7DivhS1T5gFHNIiXXGg
         EQkOgbSX0Z6mNPb4JqpFfDjKnl6v1OrNENqkcWmyMxXrHqddeXXtOifwv8D9FrRodklV
         VRJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=SjOuEDkqyCRoQlGb4r++HBQnM1FePx7k1uf7opXgrlY=;
        b=CPCYjuNqHY8yt7X8xn/j7+AkmcGylpnnGNOUPlUl0tAfkYM2YoC31o2ecs54bn1sqr
         +NTMg7bBLqtOhn+nTuj/BZOkqE9lMOe2SGa2YE4Qa3p79I9LanZMjHQKVaWowFFLGa7g
         8UXq7AkroXCwL0RVc+NDQQ05WYioSyGDzOO7liFz5nKIWkO4AS8qT9Q8SZf4vK4fu5WT
         V3+7NWZNoZ8fQ5ckrKfMt5v+O4VttdVH79TE/yk4bf9vxubBUEXMfdr4qG1YEkRcdvTH
         s2qC1CUsis3FcBqmZYekcv7zf4rj8ofW61+cDGs2Qd+KTq9i0Y8I8EvrocL1UG/9/HpW
         uTUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=o941UkGJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id t141si483767pfc.5.2020.04.24.07.55.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Apr 2020 07:55:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id s18so2065346pgl.12
        for <kasan-dev@googlegroups.com>; Fri, 24 Apr 2020 07:55:26 -0700 (PDT)
X-Received: by 2002:aa7:92cc:: with SMTP id k12mr7642619pfa.184.1587740126558;
        Fri, 24 Apr 2020 07:55:26 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-fd06-aa7b-7508-4b8b.static.ipv6.internode.on.net. [2001:44b8:1113:6700:fd06:aa7b:7508:4b8b])
        by smtp.gmail.com with ESMTPSA id 1sm5978738pff.151.2020.04.24.07.55.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Apr 2020 07:55:25 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Cc: dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v4 0/2] Fix some incompatibilites between KASAN and FORTIFY_SOURCE
Date: Sat, 25 Apr 2020 00:55:19 +1000
Message-Id: <20200424145521.8203-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=o941UkGJ;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
memchr, memcmp and strlen. I have observed this on x86 and powerpc.

When FORTIFY_SOURCE is on, a number of functions are replaced with
fortified versions, which attempt to check the sizes of the
operands. However, these functions often directly invoke __builtin_foo()
once they have performed the fortify check.

This breaks things in 2 ways:

 - the three function calls are technically dead code, and can be
   eliminated. When __builtin_ versions are used, the compiler can detect
   this.

 - Using __builtins may bypass KASAN checks if the compiler decides to
   inline it's own implementation as sequence of instructions, rather than
   emit a function call that goes out to a KASAN-instrumented
   implementation.

The patches address each reason in turn.

v4: Drop patch 3, it turns out I created that issue in patch 1!
    Include David's Tested-by.

v3: resend with Reviewed-bys, hopefully for inclusion in 5.8.

v2: - some cleanups, don't mess with arch code as I missed some wrinkles.
    - add stack array init (patch 3)

Daniel Axtens (2):
  kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
  string.h: fix incompatibility between FORTIFY_SOURCE and KASAN

 include/linux/string.h | 60 +++++++++++++++++++++++++++++++++---------
 lib/test_kasan.c       | 29 +++++++++++++-------
 2 files changed, 67 insertions(+), 22 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424145521.8203-1-dja%40axtens.net.
