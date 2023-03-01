Return-Path: <kasan-dev+bncBD52JJ7JXILRB2537KPQMGQEYVQPX2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 592BB6A644C
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 01:35:57 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id x137-20020a62868f000000b0060017d68643sf2141828pfd.18
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 16:35:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677630955; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ga2JPOxNoV2z57hEFVh5jiUA9aZ1AJNYVFTZT8+Dzn/aEANReo/yBLU66zPXS8GYJ9
         agWGci1KjPPANLVok1aJ9GRfmBRhp7tebmiYPpyJCbEcKuM5YWdnsww7+DHvWocMThTO
         IdWjfdZ+R1ReholXqF3MIOfnzLO3pkch0ztsaitqU1KE0lQbVjtH53+szCb4wmeNR+aL
         2qoF/L19CRQmv/7ejfgcRton+scL8+MXL9/Bfp/yX+dthRSc/JeYreUXjO+48Fcn9uWb
         6fMSlaWUpojZrXJTX1dQAfCFt5FoUF1oSsjbW4mCJ0qBemdiwgi+uGgWfHypEh7t4KhG
         5KzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=MBe1mTDbW3JkAUdydoFPdUI+oriIO4APOResASdR8Ck=;
        b=FG8Raqb0tSgYEl8XL0Uxe4SwZOx4YkK0rdIsyoyT44hKF3q6NNEk0OxIuBLZHoPslZ
         noqe/RgxE004OwgwtMMJET/At142rZekwf8AmxYsbVjGp0OaiG/TUSzOpKXKoq6AGHdj
         3RN2mXg2G21thGVoIfz628syVnwVUca1QITqIJLnqBoL51BvqKJxsU2MtfonPkHUMVEJ
         7nL3DEe0XGxBpbw3jXxuz1AB8hHgEJvZ5wtUP/jVuVcK4S8nM43KaOfU0CEx+rV6rO/1
         UpwO9ASNm+fpvSq6zAdI20/drSRXXQKZRuslwANTnj4Yif11zw7dXdpL96KIyqrjoeqC
         dTKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pet2R1oT;
       spf=pass (google.com: domain of 36z3-ywmkcuyxkkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=36Z3-YwMKCUYxkkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MBe1mTDbW3JkAUdydoFPdUI+oriIO4APOResASdR8Ck=;
        b=XVpSIl0d7XqonkKWuezAvfd+zyVgNSnGvKZfVTpt073ztIH292GUQ45JSFUiuKa+JI
         jW85+2X/udunq6cirMYe+bTxknTmsb2r4qbuUB4hoMMJ16WqTbl6opTNuUWF2VFbhZeR
         /b/lqpN72bIllWu8Im61whDu3FMHjGC4Uwj1IZ5D9Fv4/8pKb3vAjikz+ksoYrhIYTq3
         wxkrCqKeVJu+1b1ejEGKT3R32+6mjk6ZzlOeGQkZSWZR3d6yOANf1ZheZTO9TMKwOIMd
         +4zpEGe2fkqajB40cT4OCK55BzSvO0TwIGRY99HxHMEVbLcfp6zCztLKiWu0st9yyEdI
         V71g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MBe1mTDbW3JkAUdydoFPdUI+oriIO4APOResASdR8Ck=;
        b=iwKULw8tIW4zS7ElVNOLLb9y/FyN19QLhMt6c2NbvjBDcmUfTPXxPMLL1bBc7/Zk0A
         ZO2wZBDI61G59dEVKWU6X5fLVk7x6h4mLzluiTkGIHCsZ/uUWF4PthxZIYkyXU3jAQmR
         x9WpxXh72uGSLsU5Z6BKrTUlQZNOTIDuryKF3k9CHR37kpiMWF192kGZ9TND1nhYh3pC
         Br9vRRg/OcJel+kfN1bg5BEYLg+eLp5gLCfY1vR0XtEOQUtAm/8WXhw+GV5XSlAfaejp
         XTxS5WeF/sm4m7Xap54wAPxXjpYcH3KwzWtJfyJit7WR7bc6igaS89jXNTi/3k3/4JM/
         MyyA==
X-Gm-Message-State: AO0yUKWxSox5N9Fn6tzEiWUkJnkijPmpWeMASObkM2xvlcd6diuLRBlq
	tukbdxHDKtZPM6GYmxAUF6M=
X-Google-Smtp-Source: AK7set/zu5QSKPQDmRn8egmWg79boOnPpqBga8pHhDaHRVe0LXQYBJNuOxW+5Gttn1Fhq3OPeTSJBg==
X-Received: by 2002:a17:903:2584:b0:199:49d7:cead with SMTP id jb4-20020a170903258400b0019949d7ceadmr1655442plb.11.1677630955398;
        Tue, 28 Feb 2023 16:35:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:33c7:b0:234:bff4:2e74 with SMTP id
 lk7-20020a17090b33c700b00234bff42e74ls1495234pjb.1.-pod-preprod-gmail; Tue,
 28 Feb 2023 16:35:54 -0800 (PST)
X-Received: by 2002:a17:90b:4a85:b0:234:9715:fe9a with SMTP id lp5-20020a17090b4a8500b002349715fe9amr4906491pjb.43.1677630954548;
        Tue, 28 Feb 2023 16:35:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677630954; cv=none;
        d=google.com; s=arc-20160816;
        b=GgmjujeLtoxz//DZ2KcLDaG0weyxmI+cGn3ASZJxOuelclgTSQPCBPhfqYWprHTYx/
         bVNe6ideW0RtAq7JzJHEdiQ98XGcYJ2DKVrw816ti7mWs0plEnZRQAJHLb8ATogUW29P
         q7HVRHTLoMicmV1lTE0uNKncJjW9hoh7hx5u3aBf7vRxm75WDkdGsUC64dmNoV2C9AZd
         W48pDET03dwGQ2psDQ12QkdTuwnwI8X8UmbvZMcIH9nP7eHrbGEvB153F/4hzEv/ZtIB
         0Ugdwfl9Kfjj8mv5NRteQ7dHXXCFg/skKa88o1hdZvkaj07DLVXSvYpU2G1kU0VKLNq3
         CCXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=341EiElQDDcMgbAyTPSBPMw9kz/Bxxf49gfw3+dBaX8=;
        b=jDxC4z32xwKHa1sWRRJkRxNs6k2nZZcUuCinN0IwmDGQhosD5qEDK6UfLYqJh0UeLu
         idzgE3N0AOrAS+5Ck4DRbk8pBprydrySEONvawvc966/AVhiRflJN3UDhQa4mDrFTKbu
         Ze6y57x4Rg6O3pD4o8q+JBm0r8XXpI+E1vEhzpjvgl4lfpsmNJApvLJ3w9UyrobburJS
         9yEWpNPgD/H8/O/DZ+KACP93+gdPBxnz8wRkZcwEvCvSM5pJYiPTlpSPTTi90bkZRQEb
         yR0LfxaLx5Uz+zqQVX8h7caeZbrR8LArjwINmYvNTHPYHM0MDaCkOZ/zZDQc7tr1xa5J
         6PGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pet2R1oT;
       spf=pass (google.com: domain of 36z3-ywmkcuyxkkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=36Z3-YwMKCUYxkkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id pf9-20020a17090b1d8900b00233ba2c16a0si830822pjb.2.2023.02.28.16.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 16:35:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 36z3-ywmkcuyxkkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-536af109f9aso249114317b3.13
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 16:35:54 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:cb8e:e6d0:b612:8d4c])
 (user=pcc job=sendgmr) by 2002:a05:6902:140c:b0:88a:f2f:d004 with SMTP id
 z12-20020a056902140c00b0088a0f2fd004mr4373352ybu.5.1677630953849; Tue, 28 Feb
 2023 16:35:53 -0800 (PST)
Date: Tue, 28 Feb 2023 16:35:43 -0800
Message-Id: <20230301003545.282859-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Subject: [PATCH v3 0/2] kasan: bugfix and cleanup
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pet2R1oT;       spf=pass
 (google.com: domain of 36z3-ywmkcuyxkkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=36Z3-YwMKCUYxkkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

Hi,

This patch series reverts a cleanup patch that turned out to introduce
a bug, and does some cleanup of its own by removing some flags that I
realized were redundant while investigating the bug.

Peter

Peter Collingbourne (2):
  Revert "kasan: drop skip_kasan_poison variable in free_pages_prepare"
  kasan: remove PG_skip_kasan_poison flag

 include/linux/gfp_types.h      | 30 ++++++------
 include/linux/page-flags.h     |  9 ----
 include/trace/events/mmflags.h | 12 +----
 mm/kasan/hw_tags.c             |  2 +-
 mm/page_alloc.c                | 84 +++++++++++++---------------------
 mm/vmalloc.c                   |  2 +-
 6 files changed, 49 insertions(+), 90 deletions(-)

-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301003545.282859-1-pcc%40google.com.
