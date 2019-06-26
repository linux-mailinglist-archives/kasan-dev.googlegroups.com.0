Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2UBZ3UAKGQEF42LRMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id C5AA656BD6
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 16:27:55 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id q14sf1882617pff.8
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 07:27:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561559274; cv=pass;
        d=google.com; s=arc-20160816;
        b=h7aAiZVAMi8QfumK+8rodukmjsNDCuSezclNkx9dC7hbiopDkLppt/4D167lyf3qR8
         Jsu9rkJoi/fLKM/F37S9RcBoCh8kGNI8/oaYrqvdPrsZ1ghu8gTmgMy01tRHDE/59tGG
         RSnr6FQgnX3J/byKJdnFPzcJAVbVUanKNeFvboq+qVJFXg0B1IsqSlD4CyCXVrKMSDIl
         S9z2BlobLv/qHCzXgMzHCYrJ2eMPxgA+cGhlY2/KyZR7Zy7D6yokoIzNYcrb+bM61hgz
         xLe86XNAXbYHaZ++bV7PDftJiXjVAZ6EWzZX2w2/lcaOcOn8upHNDoFokRrIo3Cpi1fV
         3GUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=q8XVT1H5R9IodbFYzF51e9Sr/uk/KH7CNW0epAI9FH4=;
        b=EYkF9Am9wY3nvqb7JMn+tNUYIZXXskdFUs2gX7QUrKFFWis48KjhY5bIzGBUfO4gNG
         vmARzZf02CDjyWg6WXUzWf0CzFcM3W6yxS6MlP02w+dXv2zWyyacSuL2Ngv8BfkyFpMR
         N1xOgI4IcRRs+hdhSSNk4GEQwPHmo5tOZYhkwR7zF4Yf5+lSHjZ2pLO0bq2PdbZ5np7u
         2MKBEMvct5hfyN5zRbotfjrPvAlU/RUeNJ+iD76oPG/9CCPSJVZkxe6ZtMKLcj+13HI9
         yxOz1mEOybLq70uCgPIO28tLTPNYKo135mp2vy53kORuYr9jLlt0q3mv6rjS3Rl0/x6v
         SYhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Obt/qbqC";
       spf=pass (google.com: domain of 36yatxqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=36YATXQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=q8XVT1H5R9IodbFYzF51e9Sr/uk/KH7CNW0epAI9FH4=;
        b=VIsfOfi0B/GipHnczTujwPtyrm1Xbb/73O2MrkNRhJrh/b7HFfh+F8WbocKpRX/7tR
         7tAAK8YGH2ifRTxaAOZScsi0w1B5hoiWMfihmE0KdQCrEJrJU2Zi8kQS2x8SpBHFD4ej
         aR83Dfdxm42kSr4UXuv6QtvEqtzWyL5HfGE+joHrNHqWm/7kOyx0D6Yn/BwrGo6Ovdbw
         r8WCZcbJ0rBg9EQXxmeZnrI0gRVJzk6i5C6IBdhlUbCk2uWSjTzPhcwzZn4CnEFa3PMv
         TEdghvQGV6LDvrwG4xjad/JA1TS4mjsDY4MSMfgPl6regxl2RgLg0wHoWoSfa4iHoTZA
         8yVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q8XVT1H5R9IodbFYzF51e9Sr/uk/KH7CNW0epAI9FH4=;
        b=RPt0WTz1wiJ1zYdO6fqAqN6dOj5/zp8e30BJTznGvSrg393kYFTF/fd8e09SSCI0Ql
         jymFAeiVsrFZIMpjglWxbJWEO+xRqpO00sxKXC4xt7Jk0LIPmtPNEeg9Z9gJwu/sortV
         Pp2ZCDUJb7ZFyMC9CN7BBe7RTkFMPLHQhLXHE5quK6WHW4vFy62eZscOFJZcciSrdeEk
         E27nM9wsMj+QYLL0e+FTtMtsNbQkjOitMACprg/b5ZTmhbfCDAUewdGoY7QKKWbw0iRr
         hN4sVXJgV/WUxX7TO7WfYt8XHkAgK3YGjwKdlfjhJ6Zf4zaUFU9uc8CxZYNvnJkMBIYi
         lD4A==
X-Gm-Message-State: APjAAAWWVz/6bZXCY7xzrk5LxEWQrWsrqJ/b6DToKprHnh2yfUUulbW9
	8hSBmWAz/QQH/fHvAuWmiUU=
X-Google-Smtp-Source: APXvYqw6v04i5ek3BtHtX0dtTolb4keuNcZnZQF4FZClNSbzbNKE0/RX38TTs/E1sZ4oUZXEjqxBtw==
X-Received: by 2002:a17:902:b20c:: with SMTP id t12mr5851252plr.285.1561559274396;
        Wed, 26 Jun 2019 07:27:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:1021:: with SMTP id b30ls772084pla.1.gmail; Wed, 26
 Jun 2019 07:27:54 -0700 (PDT)
X-Received: by 2002:a17:902:ac81:: with SMTP id h1mr5900907plr.171.1561559274036;
        Wed, 26 Jun 2019 07:27:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561559274; cv=none;
        d=google.com; s=arc-20160816;
        b=eyzTulg+FBTGFXu6fRkzor81jVQnnNREZCBSvKP/+QzcGbKyECRkOhu5MBupC7UzMY
         M8gCRTec+112anqDss1o4u7/8y1J0tq8j4UKdlPD7AHh14Up/KoKihoX4+2+XphaNp0N
         1Z0+qJkFXw/waErFqP2hFxYlk96i4XeYBpeBT524t8MNNvU6EW1udVOrQqXxb+0bpHot
         4n713NWD3W3RE/Jxllw+s6aDBd/5m+xK46CGkfhS4PNIXnv5f7lJetBu1uNW5kwjDvWQ
         7OOl6VfMNwwzlmabfVGSrMJ2+vZBzscKaWyblcm0PYeR3GlyuhC5//1sa5J3ij2H93WB
         Byhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=r4ItmzOajsz46SiEckz8j+X5GgZKewiKuJJu0la+VeE=;
        b=cFWdTP8SZ85+l4hi5QgOarsjzNTo1igNfQc1TqPqCCMv5UiHfRcH1m85bcj+uJiayF
         2vz6Nt8kxYzILv/dSFegjW/QPYq7jBo2NSMvknMDT3bYjNVhddZW+/2tqCQP6htDANqw
         XENYy427OIZEugfoLaYi/J2HByv3lU9ZREVfKwcS0Or1ONtWI7A6F9iInGknNJIKxh/t
         PZwnFLqdTDLwGCH5Kt4BkNy3dtzcHlxBkFHLXiUS8C/tE8oTipcrbR3ML93N6tf+oqoR
         HPsl+ZFFzFBIF2+E2intbMW0dnGkfYsvnR7Sz3XiShno4BzlJ3SolHfw+jMc+5SPLM/w
         +b/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Obt/qbqC";
       spf=pass (google.com: domain of 36yatxqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=36YATXQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id 7si852584pgb.2.2019.06.26.07.27.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 07:27:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36yatxqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id c4so2732137qkd.16
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 07:27:53 -0700 (PDT)
X-Received: by 2002:ac8:29c9:: with SMTP id 9mr4065369qtt.196.1561559273101;
 Wed, 26 Jun 2019 07:27:53 -0700 (PDT)
Date: Wed, 26 Jun 2019 16:20:09 +0200
Message-Id: <20190626142014.141844-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v3 0/5] mm/kasan: Add object validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Obt/qbqC";       spf=pass
 (google.com: domain of 36yatxqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=36YATXQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This version addresses formatting in kasan-checks.h and splits
introduction of __kasan_check and returning boolean into 2 patches.

Previous version:
http://lkml.kernel.org/r/20190626122018.171606-1-elver@google.com

Marco Elver (5):
  mm/kasan: Introduce __kasan_check_{read,write}
  mm/kasan: Change kasan_check_{read,write} to return boolean
  lib/test_kasan: Add test for double-kzfree detection
  mm/slab: Refactor common ksize KASAN logic into slab_common.c
  mm/kasan: Add object validation in ksize()

 include/linux/kasan-checks.h | 47 ++++++++++++++++++++++++++++++------
 include/linux/kasan.h        |  7 ++++--
 include/linux/slab.h         |  1 +
 lib/test_kasan.c             | 17 +++++++++++++
 mm/kasan/common.c            | 14 +++++------
 mm/kasan/generic.c           | 13 +++++-----
 mm/kasan/kasan.h             | 10 +++++++-
 mm/kasan/tags.c              | 12 +++++----
 mm/slab.c                    | 28 +++++----------------
 mm/slab_common.c             | 45 ++++++++++++++++++++++++++++++++++
 mm/slob.c                    |  4 +--
 mm/slub.c                    | 14 ++---------
 12 files changed, 147 insertions(+), 65 deletions(-)

-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626142014.141844-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
