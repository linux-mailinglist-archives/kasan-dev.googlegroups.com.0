Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJOHZXUAKGQEBQW2XSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id D16A656897
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 14:23:02 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id 184sf807491vku.17
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 05:23:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561551782; cv=pass;
        d=google.com; s=arc-20160816;
        b=P/9zGT3ocSlxOmK0G43/SbuOV7Anw71XOpYHVKqhf3grDxDVCt0QT3ccVzoHQIwrTL
         v6y70aZrVNoA/b527UL0HnhjNVOY51VOhP6AlHOQnKirED5VlGKnKCWZjSPtFCYmCtBv
         kxBTc82IJAYmsfpPO+2R81QawDOWVJGPtD6tjvz7SexgV+EoxlO9HNVr7JmYyEO5UsSt
         05YrlpAoF7XtL1FqXtL2EgVW88tuRUeAxXvgHYlkEHbXNeb01ckSMgBGvphQ/u1zgMz0
         Ix+6Ilcc8eV1YYMEp3AyWyfxKh02rDwAjrOr8msgApF/BLA2n3+wYb1sK2v7bVIIqMSl
         aFkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=2ZhLqt6oRC1ocF8TJb93nWQKobBprhDlQu7LracNjbU=;
        b=OntLEASsZuadyAW1Rco8LG3sZEFLOZ5GfdXj781fRem4SoHm4DaTSpPHaVdiMGRprq
         P/sAfdMpg8HgK/RSGkfQ+6+mYOGoUa8dwkrb7I43t8C9cTQBuf4Uw9SDUof7TqenQF2X
         sks1l4rqys25LuNAS4ALFYR5WbHMaKx9qSOpwq6qClWJ0dX1b0WSFFWEbUl40GE/arVd
         wmtCz+7AXUIGC1E2O7XgDHwy5/8PQC3zuHpsb25H8I4JodyIZNE1aTjQwUwtATu/Z6hf
         F5Q+jhIZW2xujJVgn/sv2bYBWgMLkov7SqkKJM13e4lTPbMmORvWYlOVqx9Yo8JEg3Tk
         jdtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FVvuA3zJ;
       spf=pass (google.com: domain of 3pwmtxqukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pWMTXQUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2ZhLqt6oRC1ocF8TJb93nWQKobBprhDlQu7LracNjbU=;
        b=pBwrevKLo5NZIYdJeeNCVY0zqTRUxsc/8uXskYjLQBRyLYW8qxdfaoC8HH8NhHoTuH
         0qZP95idULcv510rlsvpb+i6K0FtcijioBxQ9McgTqS3ll2wNJ36UQ9cEK5frn91i8h+
         JG0EQj3rzF9AG3h+W5uO8Cq4TPlYpYrH7yKdMjrWwukN3PxsF4PC9fDmAPtQO9S2yUi2
         xxY0qNxfHPOSeQtG3pGxGsSffy34n64GNbmeSi95u7ihOYSpIgTOx7//rVOTzCKs0cGw
         JsenddYBqFsqPOACMOeNurx/A8u/t9s8mQ7kVNezvdhWzV4292+nLm1RNWLAayNZ2S3T
         7hvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2ZhLqt6oRC1ocF8TJb93nWQKobBprhDlQu7LracNjbU=;
        b=sxIrz36oftnIUvfunXcDlXySNzci8QsUBz61t4E3jqDG1l0ncSUB1dtUWBnZ24VK1w
         bi7Ursh0XoZgB9kvv8dmAvkXWy2mW2/G+aThpb15b9jvrT7ceMVyozatmpL2btrxkWKU
         yu699c5D8l6AutsTACM+HV4NqNehZUrIx6N1jaB4Jf6+AnyNZuQCESxRRiu7PUadoUDM
         oRKPilM2xECSPGtGXJaY2VupOr0yHycrjMJkg6UagRnY2t9GuoXEQnXABcNH2FEoE9yI
         pfMil2FFnhs8RRlyIqPKils4rt8EQ2ycA1S3yEZ6uxeuUf4u3eIp7rEixorh/ZhlnsWL
         kCPw==
X-Gm-Message-State: APjAAAWO/kAk3QgWX9tGdMqZuxBbV6d4KrEwvfdPAJs4b3Uc1jVG94Cu
	rPj2eAInWDSg4fJ3cZFep7M=
X-Google-Smtp-Source: APXvYqwjx0w9BktAd4oGkWYl2BQAkfV0gFwENy7Pj1r1sPjIdTjPc81vnPCK2ZEFAM1DcwpRn8i3kg==
X-Received: by 2002:a67:bb03:: with SMTP id m3mr421734vsn.84.1561551781889;
        Wed, 26 Jun 2019 05:23:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8002:: with SMTP id b2ls166448vsd.13.gmail; Wed, 26 Jun
 2019 05:23:01 -0700 (PDT)
X-Received: by 2002:a67:d81:: with SMTP id 123mr2938730vsn.38.1561551781621;
        Wed, 26 Jun 2019 05:23:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561551781; cv=none;
        d=google.com; s=arc-20160816;
        b=bMfy53C3G1Nza2U35kE7GroSz43CaVmqQUjyfIX1QyqJNRsw6eIQJTI20VU8RX6Kvr
         PnRAC60nI/zEhe4p+/QJEu/yIMwf0comzG54poL59SP3RgHqKY0DrTG+TyiISLcOti6G
         2ARsdKgHUUMGwwS/tiw59qccA2qUHiiSL5dMLf9uMCDZJ/M88MkX1PB2YYJRwWH1rO+U
         oZYGJoMUoCkqcrmoutweBmQIbdHFhXbXJclrJuW/gmHpjHraxAUCx5fdAg0974WqyL81
         zLLB0nRwe2/G1bLypWFxQEPkVB6ME+AQruxN2nL+bRPSeao6WkxczavJ/OkLwUutj9HN
         CYcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=rHwJaORfU9mZJNEEo+jfWN6v6wx9eIm8a8mlUMvLB5Q=;
        b=G1adrAbNV+M3SsL0bIImMdanjqAAcNI+60Q4uF3gHFftZBX8Q8OH0xF0tbbw1T7fcI
         QbX4JmxzDuSaldowXQuv5bA28cPDDoLi8aFtWmDMTDCn9DigIDcpFOl6Ypn2+NL3aHLX
         DnWfBIsHqt1smV4za8/vKczCl8GL1uicEvAorh3BDK/uYov0qyAWVT2Zm7z5TIzfWOPG
         SgkA9E63j91NYAlAvZBTLupuyfBYFTKjBOt1w/Dz9p9v/apAQV2FKow+NOfqQoOAQmPg
         Ja5OmFt83PSgZkaq8DoEUYdRGD1Pd6W2sUqe7WSCuXpOlm+aVn7HjnHBUx7PGX/NFoLb
         oaMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FVvuA3zJ;
       spf=pass (google.com: domain of 3pwmtxqukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pWMTXQUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id g25si991171vsq.0.2019.06.26.05.23.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 05:23:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pwmtxqukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id k8so2604594qtb.12
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 05:23:01 -0700 (PDT)
X-Received: by 2002:ac8:197a:: with SMTP id g55mr3301594qtk.320.1561551781196;
 Wed, 26 Jun 2019 05:23:01 -0700 (PDT)
Date: Wed, 26 Jun 2019 14:20:15 +0200
Message-Id: <20190626122018.171606-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v2 0/4] mm/kasan: Add object validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com
Cc: linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FVvuA3zJ;       spf=pass
 (google.com: domain of 3pwmtxqukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pWMTXQUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

This patch series adds proper validation of an object in ksize() --
ksize() has been unconditionally unpoisoning the entire memory region
associated with an allocation. This can lead to various undetected bugs.

To correctly address this for all allocators, and a requirement that we
still need access to an unchecked ksize(), we introduce __ksize(), and
then refactor the common logic in ksize() to slab_common.c.

Furthermore, we introduce __kasan_check_{read,write}, which can be used
even if KASAN is disabled in a compilation unit (as is the case for
slab_common.c). See inline comment for why __kasan_check_read() is
chosen to check validity of an object inside ksize().

Previous version:
http://lkml.kernel.org/r/20190624110532.41065-1-elver@google.com

v2:
* Complete rewrite of patch, refactoring ksize() and relying on
  kasan_check_read for validation.

Marco Elver (4):
  mm/kasan: Introduce __kasan_check_{read,write}
  lib/test_kasan: Add test for double-kzfree detection
  mm/slab: Refactor common ksize KASAN logic into slab_common.c
  mm/kasan: Add object validation in ksize()

 include/linux/kasan-checks.h | 35 ++++++++++++++++++++++------
 include/linux/kasan.h        |  7 ++++--
 include/linux/slab.h         |  1 +
 lib/test_kasan.c             | 17 ++++++++++++++
 mm/kasan/common.c            | 14 +++++------
 mm/kasan/generic.c           | 13 ++++++-----
 mm/kasan/kasan.h             | 10 +++++++-
 mm/kasan/tags.c              | 12 ++++++----
 mm/slab.c                    | 28 +++++-----------------
 mm/slab_common.c             | 45 ++++++++++++++++++++++++++++++++++++
 mm/slob.c                    |  4 ++--
 mm/slub.c                    | 14 ++---------
 12 files changed, 135 insertions(+), 65 deletions(-)

-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626122018.171606-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
