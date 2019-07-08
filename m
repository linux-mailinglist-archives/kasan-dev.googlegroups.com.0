Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ7RRXUQKGQE24345SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id B0D15626D4
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 19:08:56 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id w137sf6813307vkd.21
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 10:08:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562605735; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z8RmlVmd3L9QiASVkiJuU4XOLi9q2tdEIOHREyfMq+KahxJYmrZvUbQBQX9Vb/fgU9
         ZZnvRapAAibFGUA0459US268Cm8/LB2pMB9AQiEwIyJdyVlKLDbcGR9WNrNG/dc+fJ1R
         kkSEnC7RhwERkGOf1vVTx+C4moz1kCddAbOuz/m/CKgVWz7/eeWrwrOy+AxDzFtOrZC1
         s0vmZzRqkptSyrDnwCLDBlxQQhfWoctSxI4ldPPPGt8nxa/rBEHBqs9Eo//KNwvJmH4o
         nZlDhUsiKbO7b45QxhjseEKmPeg1ZXrNlqvsP94MWkPJ3wfdmkM6wFllupi8TNvRjm9p
         mdJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=eeZhGMFJlZMOkitkAZoK6kt/3dOHbYbcGO23xJ//AZM=;
        b=VOFcftfVLcKKaH3mtB2QM9sWk25+ZACRRzIKRZuym2Vf+UxRnXY+t2EM83abVTvK71
         oqfMXFeUmzWWFscAbSap3WTmUwxwz7d1d1UG39P+bgrTpBKbddgm8EBZYwT65Djl7KeK
         SHHLT39oE8gckZK9eTmTZbYQCOp/BOeVj5hBuKB4jos7EJUNsbrpiY0opN/ncCQ78Nee
         qO8evHr7SY+pr7xL/XURhSYbcAdzz4vur/fsaxQefGt+MzrAUKV7wWXBc8vyH/F6uzJ+
         PM6/cYq/dEvEmEZ51ampT7fi+CCghbuC1vYGqsk9JS5Xgo1ySxqmbYlEkzLtXmcCLTv1
         J00g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="su70wQ6/";
       spf=pass (google.com: domain of 3pngjxqukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3pngjXQUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=eeZhGMFJlZMOkitkAZoK6kt/3dOHbYbcGO23xJ//AZM=;
        b=EqOBGpBM2+PkpBvGCRSMqOryOjlsvE69WqNCShWDJqsRvmjwMhT3u88/uiE+kJ2YK2
         Wyh5NzYKpT7JFj68eE7bxKwh5soVDpCDg9wSqCDuYxVwHerA1i4klVXURKpsrdX9ouYN
         Yu/74dqtDgHq3j2QWDcQ+Nhn44DVMvWqvJYa52KISq6BHG7B8pC+Ngt3EUX9j4C1FWGg
         64sZ+2LVBSNCH8yD+WhjM/UDkros6R38gXLbIxAnFu4EWt773/alZlSysICDe6p9Ckpe
         5vL8Whhsh3pOYEjOrBPwrEdvnFuPyKMY7QNpdX/gK+sawvIae6D7UVCem2W0QOtv7Dnk
         59Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eeZhGMFJlZMOkitkAZoK6kt/3dOHbYbcGO23xJ//AZM=;
        b=OKvmghuv01jQEmgp/A3PKHS2oTq4CfG+AXIE5mnUfc4dsHfFe6pr8VRQvja+wQ9gLD
         8CqJJVfcjQ8va5A8ottJ9o3dFG4VYF7TBws/Iv3xOjruVD1gs2J5SqB5VGlyYY7VO2zp
         LUHBW0NJ/oSrtRjWVnsHsKSu7Ry/Sc0bT/tCZMFkdLrKUFi54RxqR8SiWMJqNYiZP+2L
         gZzoWwODi2ftrM86A+MzcRYVtbisTHyAVzpnBpYTKVZhWKFwfZ+y8fFDYHmFmR3alJR3
         q7U3a3xqfrOfcEyXqtx/Lhsg3TMQtnTAKV9p2OyFHUednMj4eXlkmal0VCsg6QDe0o8/
         /hRA==
X-Gm-Message-State: APjAAAW7KA3GdZ3ye0324h1ElldlmtunnRNYQdrjUgj/lIbhMQSaWgIT
	SMWMAnnENi4mTC/MpoC6eXk=
X-Google-Smtp-Source: APXvYqyvgOkgZTS0ADC4q4UNZ6OJgH3l3fBIodR1Tv096PfsXHo/vwoiaoAilF6Ysl9kX6NYSb8lxw==
X-Received: by 2002:a67:ba12:: with SMTP id l18mr11202258vsn.29.1562605735520;
        Mon, 08 Jul 2019 10:08:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1006:: with SMTP id 6ls1389881vsq.1.gmail; Mon, 08 Jul
 2019 10:08:55 -0700 (PDT)
X-Received: by 2002:a67:1281:: with SMTP id 123mr10877880vss.10.1562605735240;
        Mon, 08 Jul 2019 10:08:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562605735; cv=none;
        d=google.com; s=arc-20160816;
        b=Sa8cK86cQAI7+7xY03HaTzoh3X59Z74dj5fCP6zxF0ofHEuyCOiBBVnMbZMbv4Hv0D
         yR5fqyncvAVQ0kwbnKDi7lDWfRYuDQ6ZhTOtfu6Lqa7/6HkoIrcTJS9MCIGdILfjIdYV
         Yxq32TK+HeNAsI0ByModkEo6Fo6ZYkk3Mvwzm9yu9/7IVj6FuAnl2ArTAEgfgS9vl/Nx
         J64daFuVeAoCdob3jmL0EVSr1UIRBHJUc2Z2KjDLtRzrm7SQP2Zz6PIWE2uE+fymLo5t
         EcCXO5XNQl13Pg9M3L8FAocHMQCaOyFP4UrOvJz6kSheBKkrFddlGVDYOFNPjlLxmBDv
         78yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=rkb+RBbpaLSwWUUB7g0A+rsu7yIfnRDIumBvHSjiI6g=;
        b=1DAsEKsH8h8zGDFaciUqYrloe3L9KkD6JaZzzOdqwwdmpbHe/YiqNNI/UXYw+eHSeu
         dKFcy6QvaioTG+ToubbuZ0TcGQCpaZiOV50wxeNkzswfC9PbqpLt4Kt0g91clWtS+pt2
         ASl8QY3R+Ct+2iuywzIiFvVhYxqfnzjDn0kG+BeUoOqhYLBusyz6sScJelgxN7pYVoJr
         hKcavU5iuY1zGEBs8Kk/NdWLgZkMfwY5vKD2f4Ch02SpVojCayGH74rFSnI3qikqxv5j
         T0Nxd5aWXt1vdWDAa+xLeAIjNRteZkr4qZV7t23x4Bag650EculPfZK1xCkcgP5n20Dh
         Vf1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="su70wQ6/";
       spf=pass (google.com: domain of 3pngjxqukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3pngjXQUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa49.google.com (mail-vk1-xa49.google.com. [2607:f8b0:4864:20::a49])
        by gmr-mx.google.com with ESMTPS id q12si386090uar.1.2019.07.08.10.08.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 10:08:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pngjxqukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) client-ip=2607:f8b0:4864:20::a49;
Received: by mail-vk1-xa49.google.com with SMTP id t7so6835091vka.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 10:08:55 -0700 (PDT)
X-Received: by 2002:ab0:7143:: with SMTP id k3mr10372932uao.91.1562605734773;
 Mon, 08 Jul 2019 10:08:54 -0700 (PDT)
Date: Mon,  8 Jul 2019 19:07:02 +0200
Message-Id: <20190708170706.174189-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v5 0/5] Add object validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Kees Cook <keescook@chromium.org>, Stephen Rothwell <sfr@canb.auug.org.au>, Qian Cai <cai@lca.pw>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	kbuild test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="su70wQ6/";       spf=pass
 (google.com: domain of 3pngjxqukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3pngjXQUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

This version fixes several build issues --
Reported-by: kbuild test robot <lkp@intel.com>

Previous version here:
http://lkml.kernel.org/r/20190627094445.216365-1-elver@google.com

Marco Elver (5):
  mm/kasan: Introduce __kasan_check_{read,write}
  mm/kasan: Change kasan_check_{read,write} to return boolean
  lib/test_kasan: Add test for double-kzfree detection
  mm/slab: Refactor common ksize KASAN logic into slab_common.c
  mm/kasan: Add object validation in ksize()

 include/linux/kasan-checks.h | 43 +++++++++++++++++++++++++++------
 include/linux/kasan.h        |  7 ++++--
 include/linux/slab.h         |  1 +
 lib/test_kasan.c             | 17 +++++++++++++
 mm/kasan/common.c            | 14 +++++------
 mm/kasan/generic.c           | 13 +++++-----
 mm/kasan/kasan.h             | 10 +++++++-
 mm/kasan/tags.c              | 12 ++++++----
 mm/slab.c                    | 28 +++++-----------------
 mm/slab_common.c             | 46 ++++++++++++++++++++++++++++++++++++
 mm/slob.c                    |  4 ++--
 mm/slub.c                    | 14 ++---------
 12 files changed, 144 insertions(+), 65 deletions(-)

-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190708170706.174189-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
