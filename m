Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBBEPYTCAMGQEI577K5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id B75E0B1A96C
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 21:18:29 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-6157ba67602sf4472173a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754335109; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZKRNv1h5yYgpQJiDP38KqPXQ3g7LsC8ZzGumdRL2o8rv5QeKOV+D7HsH4Xuub4FnWi
         P1xPVhBp5ypjWFSj0CeryUw2isfIzUXuOlM63Y+Bv+Dg2XKZ+/tSaK1XTrOmcZg8rsjS
         lhTpuvsnsiUStjwUtMleYBLgzy8bA2e5dxn9ytC7XPxjq6/7h/UvG6kghyvaQIaixkUm
         VgTdNAVI274YT1ITHkjPrXfbeVkXyds6Lht2LrJP58azOV7eacInmlG7p2ASaZVTGK+T
         gZOLv92FylxCpQdW0aGssxKprpNg2tBuK5d2bR5P8j7RA58QFYxzXKLl/vL1v+dQhHWe
         XdbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=56jZ2QINJn7O1Dqbd4QtnP4M75beynbzuXnUDlIubTo=;
        fh=s9NC+FXaWksFN/A+aoYwOEzXNAKv6iYQef0ee4DFZlc=;
        b=Uh0fAq/JCrne2tGsLIPWVVmKUDS32BsJicBut3tv8LK+Gbz+xiwnPQdtzz7bUd8Pi0
         zZ6NYALaTQebPsuc5GPiflCWHFUR77dd2rDxCIk73syPKTW5EiuBM3Hpn0BxK0fcMjHf
         4iHUq9v89roausTXRHWJJtZbzCnsY13I2r4ZF+Y+5OKWlbUayqlX5RaiDUg1SzIokOKT
         wi98rByRCYUvqWkXhn15lUIbY+FkPKByVP5biPffaQnkUghsxihHfWSP+RwPUH6OI5BT
         rGqiPjQC1LmSQCNZYc70bCNnVuuQZX9fxG2G31JsdM/5Q8uYCSNRKI0JrAPdDge9KpyL
         2b+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KOIQ4bK8;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754335109; x=1754939909; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=56jZ2QINJn7O1Dqbd4QtnP4M75beynbzuXnUDlIubTo=;
        b=qcqWP7/QcX1P9ZiEVztSGnxPunPAK3Fvgdx8VBLcLwBILpWCM/3qc6bL9qXpilnp/e
         mtJli4Bafk9wxvuvbaXMKZXSB/b5cd8raXRVGKALGPJACNngHm/jl6dTdaParsdxLfud
         617OoJeAzyAJQWoDeiZlTs3KZjBHaKazwYYy8BIwDMyNPxwt9ShEQfIdmIW2ARSO2Tt4
         zEfk0QIYyznq/LceodX3et0bobYg9ySuOMNtN4nOA1Y9dC1z41xUa01o27F08v6YucoD
         LfD7BWNwzTswS/rXDq/vFi+OFgHQ8YToRURC/xGo2PU1AFvw2Yo3aXULuGYgwZPw3/6v
         8+EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754335109; x=1754939909;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=56jZ2QINJn7O1Dqbd4QtnP4M75beynbzuXnUDlIubTo=;
        b=Ru0PqO4cVYuDi3u+uvazYqT85x2Z/3q/SBMDsArwIi+6hyQwsgpgKIM9wAqzl4CPCI
         5tb3gRObBlOMR3SiWrIalpq66FElknvBxbGDt7R4ucxK4OwgUsBHlW0rzcBTlpLbGzFp
         paKw61d2uxDL6ppRIdzTe1W18SLlOuBJmOe8UnQuZrG3scR3Ovi/WK7Q/Gz7eQcJpLoi
         1tBZFNAPbIGPqDLaUVtOBGixuRGBwZL7AYQ4aotM3xWEKWt5fiBgwgVXMGwFmwHUie5s
         4KquYlYNVpi0mOfrQdLtrXyMgGj/tBqJxEbI/YeVGuIARnA5SOhmNufxyM0QWjwD87/p
         99qw==
X-Forwarded-Encrypted: i=2; AJvYcCXWtIJmGD/MhfBnKLHF+93jDBFOaYuN0nww0AV9Zp1qIPkQDlH2bGrfeGYcjrZihao2LC0OsA==@lfdr.de
X-Gm-Message-State: AOJu0YwimtyAZxxyphicrPl8wKgErRVp91EONOakzmgTV6X6EB013O6O
	ycL9+5uVJ0ud9cQdnqgOrOzw6VlCqRdU5pKs3FCOIWxw/jn4EKPhznNh
X-Google-Smtp-Source: AGHT+IF8Nce7QaJIjDypm5lqdar6UAFnkvIzC6xQPeM2sd87a7PartXb02BksvX49xJWusZWPh6Jug==
X-Received: by 2002:a05:6402:254e:b0:615:aec5:b5bc with SMTP id 4fb4d7f45d1cf-615e6cd3968mr8993417a12.0.1754335108840;
        Mon, 04 Aug 2025 12:18:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe8cGk14zvN/5k92PBeWuVp732uKWjnoUk20XYZJEJ+Pw==
Received: by 2002:a05:6402:5206:b0:60c:44d6:282c with SMTP id
 4fb4d7f45d1cf-615a5dc1704ls4783661a12.1.-pod-prod-04-eu; Mon, 04 Aug 2025
 12:18:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhekGpcsY2bpLJbrxnboc0EJziZR2gRR3VyEgS/SkDLt04ovdQKFwybfRl/dFEILdu6kfop3XRu+E=@googlegroups.com
X-Received: by 2002:a17:906:b852:b0:af9:5993:65ed with SMTP id a640c23a62f3a-af9599370f2mr636565266b.6.1754335106030;
        Mon, 04 Aug 2025 12:18:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754335106; cv=none;
        d=google.com; s=arc-20240605;
        b=VaFxNEhS8pMQF4AFEGUnQiF3qTQoAqViSMk9cM+Evlr/usMGlOee0hLztfhd82IT9a
         Kv3nCzsVl4fS9TMkZcHcqfbMGfGKlOUnSZS183NbUQzZJNG1TmzY0jMtA82iPWdRLLiH
         GHiPQ6Yti3yDFATN/sI2jxOq0Azqco8xmVYRxa3gDm2NomZYPb8zyKjhEk4v8kZbn/y+
         IOSwtS0tiuE7kkBqKBPAqH05vrWywUj3TP9nehAoa4N2a2qmzfsXPkXXlxzcSF3vXmm0
         7Xyt4pXMxUeyiZ9pbervtpICxiVTTXHCpJY6pE6c4RVriW+yLaElP12RLUPJptDSZl9I
         oNkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=w6vpa7s/m259CJfR4wWBW3OSc7Z5L+y7nCDofPdwxAY=;
        fh=DFYa2zF/J/Pcn+lVhMUVcqZSLLT/+Pu4lzPmmO01Uow=;
        b=cS2ccpQKPzav5kYu6+LURz3NAF3ekrwTfHu5CjmxrBkslue59my/SQ7gktkb2t+PDy
         e86J+oeJH19mtmVERKWnPiCrpRAR2Fo6SVu/DKJ08cSeuly8cr5bVJ+XIpnaEoeQEcFi
         40mz/lO+DkClxc9NqnB/W42AZ+1zP5ccBBzxr+Jjzjl5xwFSbCG7VaM2Wp7ftWwlYPAF
         lf3VOjeXp7GEHAswk381DAju20HYRLRBHKxdsynpovBO99HLKzZvlwu6QuK84+8b9kXe
         r++NPRFU+HcpDS7ZHtK8t+CZGF7sgKZ3RAo101nvDTrtLapeSNnxKh7Wv8Rfg7QR+Xgx
         ztTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KOIQ4bK8;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af919eac6c6si25974366b.0.2025.08.04.12.18.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Aug 2025 12:18:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-459b3904fdeso65e9.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Aug 2025 12:18:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVkh4ucrjR1KhcbNFVFKfXxW4I/jEb8b8imiFaiJknHZ2aIH31judHs2c7Oz+IsUqnvxxyEVlbpTsg=@googlegroups.com
X-Gm-Gg: ASbGncuu+xEzQH1v/IkiMAaqg3TJEDsiE/oiHmv8AcV3t2xCY5WzD+T7HHHbRzuWmh7
	aB1JhOaTnVaQ2fR9DyWN2IpdOgI2CraLY6XG+zzmwklctmUstzhWevX4Rd97VhaDGmQ68flsCmz
	/Qj1pO4K7lTK5fnzRWg/TsCPlAs16KZ7Dj6BdvWE7ODEm5HwLnAxKsxYPsEg0nb2N93dhabpeX1
	ktZG6nyvEjLBHGryu+1v8zukb3EC9GmCIO9lUM41X5IDvnX76ubLVqGiCUZOdlBaSkNfhNpuoMO
	vQcYHoBQEwxwwGOD2sdvn8rssd0GfJOXR4ONkWB+0klr3q9NEUWVqyEHq0IolxGodi0h+xzyDFf
	ujWr13W8yTEJMujg/hnCl
X-Received: by 2002:a05:600c:8710:b0:453:5ffb:e007 with SMTP id 5b1f17b1804b1-459e13d17b5mr185195e9.4.1754335105309;
        Mon, 04 Aug 2025 12:18:25 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:2069:2f99:1a0c:3fdd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3b79c3abed3sm16384379f8f.10.2025.08.04.12.18.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 12:18:24 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH early RFC 0/4] running KASAN off of KCSAN's TSAN hooks
Date: Mon, 04 Aug 2025 21:17:04 +0200
Message-Id: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIADEHkWgC/x2MQQqAIBAAvyJ7TjBBiq5BD+gaHbbcaiksFKSI/
 p51mznM3BDIMwWoxA2eIgfeXZI8EzAu6GaSbJODVtqoQpdyxYBORka5jh+RQauM0WSHAVJ1eJr
 4/I8dEPrtEm1TQ/88L4RYtiRsAAAA
X-Change-ID: 20250728-kasan-via-kcsan-e5ad0552edbb
To: Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>, 
 Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1754335100; l=2607;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=PWEz9+NA3TL9Bqy+uoJY56JiWsNlBHfsy/4lEOXISf8=;
 b=nXtIxc/y9azUYFN45trrZkS2dtWwbDHscpVL5UvAgY+drSEtVoEfY3ljQ8HRkVq9Vawlwh1zo
 kPjnIzFnO5ADoel+f8BEEVlhBhu4mzDuxjpd3cFHJlcMHb3iIXrNMZ/
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KOIQ4bK8;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

This is an experimental series for running KASAN off of KCSAN's TSAN
hooks, to allow the two modes to coexist.

The first two patches are cleanups that I think are worth landing
independently of the rest of the series.

Patch 3 implements running KASAN off of KCSAN hooks; patch 4 is a little
tweak to KCSAN's integration with SLUB.

To be transparent: This is part of a larger project I'm tinkering on; I
figured I'd send this part early since it could reasonably be useful as
a standalone feature, but my real usecase involves plumbing the data
from KCSAN further into other stuff like KCOV, and my code for that
is still very much work in progress.
If you think this feature isn't worth merging by itself, I think that'd
also be reasonable; in that case I would appreciate a very short reply
on whether this is something you'd consider merging as part of a larger
feature, or if you strongly dislike what I'm doing here.

The reason why I decided to go with running KASAN off KCSAN
instrumentation, not the other way around, is that TSAN hooks provide
more information about memory ordering properties than ASAN hooks do.

An alternate approach might be to merge ASAN and TSAN in the compiler
into one combined memory access instrumentation feature; but I don't
think my weird usecase warrants significant compiler changes at this
point.

I have checked that the KASAN unit tests (other than the ones I
explicitly disabled in my patch, and also excluding the two that are
currently failing in mainline) pass with CONFIG_KASAN_KCSAN.

The current version of this series applies on top of Linux 6.16.

Signed-off-by: Jann Horn <jannh@google.com>
---
Jann Horn (4):
      kbuild: kasan,kcsan: refactor out enablement check
      kbuild: kasan: refactor open coded cflags for kasan test
      kasan: add support for running via KCSAN hooks
      mm/slub: Defer KCSAN hook on free to KASAN if available

 include/linux/kasan.h   | 14 ++++++++++++++
 kernel/kcsan/core.c     | 13 +++++++++++++
 lib/Kconfig.kasan       | 17 +++++++++++++++++
 lib/Kconfig.kcsan       |  2 +-
 mm/kasan/Makefile       | 12 ++----------
 mm/kasan/common.c       |  5 +++++
 mm/kasan/kasan.h        | 11 -----------
 mm/kasan/kasan_test_c.c |  4 ++++
 mm/kasan/shadow.c       |  3 ++-
 mm/slub.c               |  9 +++++++--
 scripts/Makefile.lib    | 20 +++++++++++---------
 11 files changed, 76 insertions(+), 34 deletions(-)
---
base-commit: 038d61fd642278bab63ee8ef722c50d10ab01e8f
change-id: 20250728-kasan-via-kcsan-e5ad0552edbb

-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250804-kasan-via-kcsan-v1-0-823a6d5b5f84%40google.com.
