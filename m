Return-Path: <kasan-dev+bncBAABB2N7RXFAMGQESBUQVUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 31483CCA069
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 02:59:08 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-34c48a76e75sf300327a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 17:59:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766023146; cv=pass;
        d=google.com; s=arc-20240605;
        b=c23aPs20PJw2QbHxF79i3FJsR3k0uTWkYpUqeZQxxI/x5ZrRnJMdXIzqVnOm4Ph+Xi
         LanMFDfiTBXgdtnuRX0GT2y4KOSuMA83QcHN6UeYGlOErGamePHQBTu7wAVI7jAMXH6Q
         yEuIm63PBhzF0defv9aodnvPgTQLSAnODQw3w3EjF+H5erN2xeA6fk5+5GgIJSpqVxxa
         8P4GSgq1dJjWP8ZQITYytvN+aj9OyZk6f3Fm6yL2BQaqroLDZghHa7J3bMPzJ7F0AcPU
         tz2xU9YUFwejUSBzDjj06RxvYMSpqT8lcK8OlvJ5BbvjD8SSv1tqOYPAetjJ4Hp9/uD2
         yORQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=igq1vH5GHr4/Tj6Cpw84NgVONjaeBNa6Huz4yE9uIw8=;
        fh=Cav2e1/yhQdXUjG1hvvDm0oX485fM6uyrCI8bg8GWIM=;
        b=fsmZV4h9JevXvRj9YKOvA4wFhN7HPEv9VUhPTVS3H3ghdft8dbWxev3X0YZ8lRs0vV
         C+1wpcs2X2+mGYWR8fsNmP8q8tSQatwIwIvwmyIVkN3KlYz5CfBE6bmtzm2qGFdu5R6E
         XIkCxowRJ2GApwiJ6QPNlFzZsddXj2qHGcA/UYWnUjanmULKyTOkShphOCKt1ROvcGOm
         GCEnDFcxo0Gy6PAK5SNtU5dtM/cmJ6IUR3fN6ufrGEPpGpKZWJs2z3P7/zXwHY+cOn2Z
         e8NpuQnLI7Ne2olAz1Q4gS3AS7pQvxT72gONzjREEDPcvqPn6NUjKZPMNFUnUWcQdbGQ
         rzcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766023146; x=1766627946; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=igq1vH5GHr4/Tj6Cpw84NgVONjaeBNa6Huz4yE9uIw8=;
        b=l6I0qn72rPPWTnr3cfxS++hLOjyW6j8JqZQ+0c9K29E6OQft5jkgXCzEtzRhIcjV3m
         rNKjzNYJczU2PILTYbMy3ZjgRvp2RallaZ11DQgPuIRQrHQQQgPKTzK4bQ08AKyEXgHZ
         ucvaDloqgiLrngY5BYR0YeZYNxTict0hQi+h1M4SOTHm9PmKEmIAade/+BQVxWExhvAB
         ZBYqnSxxAyQDzQwUmnfCyGuJWx6btUCXQxEXDXyP+DkIJcNQo1B/JbNTZhhHvik59SCq
         ZZyI4HWx8RCUPP+xjNmLjzvMm2Ze1nVHya7Aw8iAWG8zr83eUUcrNEcRvqskNGczUsON
         KROw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766023146; x=1766627946;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=igq1vH5GHr4/Tj6Cpw84NgVONjaeBNa6Huz4yE9uIw8=;
        b=Lu4J1adXvu2IPztCuy3MrHKj5yhn67QiAZZ74mnN72NJBJGrf5LWTGkAAVopXOwtwv
         y2bMuu2oU3BZCFw2HmGLXGvrb+JluLR5hqoh6rao27QmCkPdP400I4mdTVqpjp98wY/x
         /d87Hv/Erk1JdvQXPH2m7aoTS7P0OdBE2DL0ulIeFAhuizkkQanKcFLg5+2XimcEZSgw
         mLi4txG/Bzy08Ztmaemq17Yyg34zWwYe/DktHgxS6Ln0BfgjUCHBN9iBAIHYB30C3Wxj
         MlEHx4zx8OSE6+H3SMtXg2A1BpUaxYnWvRVfoTYa4hlGWZNL2xqQwmAgUjyPZ86yplrn
         WPSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWA0NfGQm/8GGNTW6JcqDV6BG9TaEnjLElIkIkhVMw1jKTS/rzWhzA+VUxzZW3sGo92IN7mug==@lfdr.de
X-Gm-Message-State: AOJu0YxrbTm9vd9DYYjHXJ/We8EXkRvS2etLBcQ4GHpo6LA8hk3YGxiN
	cWSZSrchoeNuXu6CfTNCH/PHIpZM41VtMtriJfcRGtkQAQHmh4sdIu4U
X-Google-Smtp-Source: AGHT+IHSkpTGSP48AER1dVpabdT49u43+Vf+/IxWtIMEyLHa0aPrAFmX5ryc16wLDnJw8rLmrh8GKA==
X-Received: by 2002:a17:90b:2d4b:b0:349:2936:7f4 with SMTP id 98e67ed59e1d1-34abd786b6amr16640631a91.32.1766023146262;
        Wed, 17 Dec 2025 17:59:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb+8EhriEQOPbp/+Op5Pd1lKoKRyZTx0cfvECZ1O5KtTA=="
Received: by 2002:a17:90a:7308:b0:349:869a:80f6 with SMTP id
 98e67ed59e1d1-34abcc97709ls4579405a91.2.-pod-prod-02-us; Wed, 17 Dec 2025
 17:59:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU8vzhLdgC5jBIoHKkOlhpIPEyLlo8mQpUsFXc7uGFOpQ2X9tzi7G+whAz3LS7bR2LJJSx043GQYjA=@googlegroups.com
X-Received: by 2002:a17:90b:180c:b0:340:ec6f:5ac5 with SMTP id 98e67ed59e1d1-34abd6c0312mr13979394a91.2.1766023145090;
        Wed, 17 Dec 2025 17:59:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766023145; cv=none;
        d=google.com; s=arc-20240605;
        b=h+TG6xoujaBGyRKG0iBFycMkPKtx569Q4sLf9yjnRCRK279HGd1OtWChfliNVs7FoZ
         yE+wgmehSiK3OJyvOLXpHXO2x/vIr39ewehTZhCNax7QMxkQhbImyp65trSQt+Tz9pBv
         EpjLZg82gLpfNlJbvFBr9KGncTOsj8CKYUCNOmfbbVMerIcohKJKtDBUcA4XCitng88A
         8t0WTBqtwpJJx9LEncD6QIcsRNtdI2ISVeidIqveyTkLkI+wZmlRJm1Tq2lFkbQupGPQ
         P66eHrf4xraMKVsvzVFmzTP9566SSlxuyeMp3Rzlw1s/oe7FwsaprarwuAiHb4I5ad/O
         T5JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=rm+M/uxyWs/iVekWljIjPDYeDjOBTK972JK/hYCgjwM=;
        fh=tXyokhajkC3Hwq5fulW7liM7gDFGcDjcIYOJPNGPN8w=;
        b=ckcULpZ2bVTF5AKROZDkhmDsPm6ADGbGhA12xKGlr4Po93bkx44HMi5q6FHZ+973UQ
         7GxEynKiR8IUHJca+KBjAsKH92NqIqwudITfu6P9H3UaBQ3OzhgVyHCj9U78Kxwtm3lb
         mpFmvnz1ZuapUSdtifXKYd4dFlv1tgt4F9svyosVMGx89GOqIDo1QrN3me0IRi9Z+ocJ
         9Omeffkv3xQQcrFZ1d1maeNBpRnHIHRBOzXkui58Lw4Hu4TFqb88q+b9v9LSJNN5fFrY
         ftkaab1dgL3A1q2OacXOsyOl7luJnWBBB6ZFJoSUa5TvWY5wRYCjdk7JDQXkMVBlspXb
         /1yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta21.hihonor.com (mta21.hihonor.com. [81.70.160.142])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34e70d9098esi12597a91.2.2025.12.17.17.59.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 17:59:05 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) client-ip=81.70.160.142;
Received: from w003.hihonor.com (unknown [10.68.17.88])
	by mta21.hihonor.com (SkyGuard) with ESMTPS id 4dWv0T0yGbzYnWDP;
	Thu, 18 Dec 2025 09:56:25 +0800 (CST)
Received: from w025.hihonor.com (10.68.28.69) by w003.hihonor.com
 (10.68.17.88) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 09:59:01 +0800
Received: from localhost.localdomain (10.144.17.252) by w025.hihonor.com
 (10.68.28.69) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 09:59:01 +0800
From: yuan linyu <yuanlinyu@honor.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui
	<kernel@xen0n.name>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<loongarch@lists.linux.dev>
CC: <linux-kernel@vger.kernel.org>, yuan linyu <yuanlinyu@honor.com>
Subject: [PATCH 0/3] kfence: allow change objects number
Date: Thu, 18 Dec 2025 09:58:46 +0800
Message-ID: <20251218015849.1414609-1-yuanlinyu@honor.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.144.17.252]
X-ClientProxiedBy: w012.hihonor.com (10.68.27.189) To w025.hihonor.com
 (10.68.28.69)
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

patch01 use common KFENCE_POOL_SIZE for LoongArch
patch02 always create kfence debugfs dir/file
patch03 allow change objects number

yuan linyu (3):
  LoongArch: kfence: avoid use CONFIG_KFENCE_NUM_OBJECTS
  kfence: allow create debugfs dir/file unconditionally
  kfence: allow change number of object by early parameter

 arch/loongarch/include/asm/pgtable.h |   3 +-
 include/linux/kfence.h               |   5 +-
 mm/kfence/core.c                     | 125 +++++++++++++++++++--------
 mm/kfence/kfence.h                   |   4 +-
 mm/kfence/kfence_test.c              |   2 +-
 5 files changed, 98 insertions(+), 41 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218015849.1414609-1-yuanlinyu%40honor.com.
