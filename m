Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZXZUL3QKGQEO3MWTUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C22C1FB0DA
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 14:36:55 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id v78sf10496824oif.8
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 05:36:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592311014; cv=pass;
        d=google.com; s=arc-20160816;
        b=OXrpBZthGj7iMa/KkWWno5kq4do7V7L+o5nvr4VAuAEbzTYcOfGFNYFDPt25EoTNjd
         xjzoid/LsgWMnF8z9AyOwJmITEivnlgHoWzR5ufY7RiSg0amp59ZJFPl5upfx/gof89X
         R3lqTsFcQhMm8a7bwCOC/dYfCNbanBfRW4gVZlOqCYsuUFKCEmz1f+f84fL/VCHJES9A
         pj4f7ToL+czBY6dO47wltYXaIcIb90GtDUlJCqTBxcLQBrr7Hl1qfrRYjk0UmtsODItA
         NselJDZ1gjwopMG8omtSovHZ4rCYR3siwxf1cSGCBl7Zkr2q0S7nvjuchE/nZBsD+ZcV
         zfOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=C45Mzc0KQh4/X/9cF4LHnwj2y7Y7pM46ZwDJR0ytfFM=;
        b=oA9Th9e6XoGm2wxdDNPgaVhtQVcHySrk4RVkp/3u5buVGebbg40rY97SPv8ReeKH06
         kA2czY4/czABwZzL2uWMNFZ4Rmzj1d+LVSPR0L6YygNH7isvdk2jqnxC7MZDtmPBNgt6
         L57VjlUMcS2/hgM0wsZT7qbmNNjcYa9HB1ePLd/po6JnOKxKjX+DMMA0e6ONYUx4bzDz
         R69tMsjGPVZyOWfPvXZzjCClYiAJyHXOCbgpIeyA23DZNjii4wtY98kbkxdmOpl/DqS5
         2W5LCSoGZDnTRy05OhKWhzYkqbOfbgetaijWTo+KgKZ/pqOoLyjNY/aBdcODC5FPYqoS
         Vw9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rFcoOTAe;
       spf=pass (google.com: domain of 35bzoxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=35bzoXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=C45Mzc0KQh4/X/9cF4LHnwj2y7Y7pM46ZwDJR0ytfFM=;
        b=nsSy2CFCQaVCWloYLrvL/m7kBDJ0zvD0CqJ2UmbKUQH5vNw8HWFSdzyS/22uLiZXWo
         42IW8OICpEYCMAcRSFDCB4yERhVpqyzWjr+ZP8v1gfHEuJwOS0SGq0qZg0XUNxattsiC
         PoUqRYSsVb1TWHWs8bdkN/GibwAgNnc5LnGjUN90r4Gur2LLrkuTjdNW833ivLBEa4gn
         ULBS3Idzz/aRO8PJTj4nHyb36ok/YVhL0whtrH9RZD5eBq6J/fYqymGT4mOl0R6iv3IA
         SlalW8DfR10JCR6Xe14JyqBk9YndqXmfROdrTAjmR9qmeMYUoFyQZHAuaxgRiqOd0MJg
         y+Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C45Mzc0KQh4/X/9cF4LHnwj2y7Y7pM46ZwDJR0ytfFM=;
        b=IJ6T3iETOzbrkQRaejg5vp6UVil1aY4tgtO+MxV6+2Q12sZE4ygI6cfALfpikxjdcC
         YQRP6JRERpN7Au1XtM0AvhEhj/iQj8Gad307QQ0+KcdJHzRS4Dh2Y7vyMq+Ip8wPkfU9
         CwRz+s/d3iEw+zt4JlbXbysvbfhCp9hY1bjtakJlSZTCz9P3x6v3t3NH03scQHSn/d20
         shuOfubDZT3spfUtb30U+TvPcVPrFCpNzL0xMg5DGKqRpVJJ6LcWxDxknxiJgNbGaCmW
         y/aVvp65zEOa1jrIlz7XGFsGyc4F6nAiZCPxEW5kw8CrlZxC2gS4CXedzAgFz0KZ9YRY
         FLgQ==
X-Gm-Message-State: AOAM5333wiAFMp5Bp1Wxj7JjaIlb7CZptiyWs8Fn6eeaXde/Cni91UxR
	FLrfZ5bvV4C4+fVlEDBQWiQ=
X-Google-Smtp-Source: ABdhPJwUIgcTElQjpbQhBdFtmQRvxB4CQyeV+g/U8mmJxswaG4YpXCb2OK3VAb3f9jc/bifhv5Pebw==
X-Received: by 2002:aca:48d7:: with SMTP id v206mr3148805oia.97.1592311014105;
        Tue, 16 Jun 2020 05:36:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7051:: with SMTP id x17ls3795780otj.4.gmail; Tue, 16 Jun
 2020 05:36:53 -0700 (PDT)
X-Received: by 2002:a05:6830:18c8:: with SMTP id v8mr2259069ote.119.1592311013761;
        Tue, 16 Jun 2020 05:36:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592311013; cv=none;
        d=google.com; s=arc-20160816;
        b=L6wUGIjY4/KB3R3QPvMtXX1jQUzlwwIAcH1QNupyZJnKKBg63uNIr9ecsKnI0BT/mb
         lbW+M5nxsH/0TIq86asQgQFdFRg0ki+Wbffob3UTy4FBzjPfWdXzrmfNPzKVJAZk8GKa
         dDNTHy7S35a70lO/PrPCt523thzjv3h0sc3yromqIDow+ng2ibOqrwOxtFf6Yc6+VeDd
         uq15dQs8NSo/FaOFy7u2a4FHbnymJGTH/oE1Ly15sdtH5r6l/WxSBy42X1pDn3ThhSz6
         8unIJS4drkWoE7Wzhpet4NZRehbQXUa7WRhh3+N3G8QBJWrha8LStzYD34OtqL84CRIV
         ITTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=2PngY9rpSrc/JWo0nu1D3c8c8eSsxwN0TWotJmkVNDg=;
        b=gtNA9tvRZqecL6yyxu5xnmWF/oLmz+o7zEJ3AbT106oqY0VJvs9zFjZ6PKn+iCD7Ih
         pqnNAsQDbg74FnOon5siq96kWiAg82GAgRsdSMTDQlFUX+7e7Yz1nlGvrVZmLPQpojGL
         XuSSlCKdygmMRAU2ZT93QBRgr0hdXvBQP73RyGPbfUYmAstQbQtp6hWrymhrAPM97jTk
         ODYtcKjui2l8U7me3GNl4FYKQk8fN/s4hlBlt8a4KXwNJrP2tqc22Y4XZ8MZ8aSs50Ek
         YyZUVgh759wP9K50AJ5LTr+2L9E3o7ZY8+iJ27hX3l5CRtQu/HfBIw/kOkS6ERjlJRJp
         uD/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rFcoOTAe;
       spf=pass (google.com: domain of 35bzoxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=35bzoXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id a13si1047427otl.0.2020.06.16.05.36.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Jun 2020 05:36:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35bzoxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id a4so13642031qvl.18
        for <kasan-dev@googlegroups.com>; Tue, 16 Jun 2020 05:36:53 -0700 (PDT)
X-Received: by 2002:a05:6214:11a1:: with SMTP id u1mr2008197qvv.91.1592311013195;
 Tue, 16 Jun 2020 05:36:53 -0700 (PDT)
Date: Tue, 16 Jun 2020 14:36:21 +0200
Message-Id: <20200616123625.188905-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 0/4] kcsan: Minor cleanups
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rFcoOTAe;       spf=pass
 (google.com: domain of 35bzoxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=35bzoXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

Minor KCSAN cleanups, none of which should affect functionality.

Marco Elver (4):
  kcsan: Silence -Wmissing-prototypes warning with W=1
  kcsan: Rename test.c to selftest.c
  kcsan: Remove existing special atomic rules
  kcsan: Add jiffies test to test suite

 kernel/kcsan/Makefile               |  2 +-
 kernel/kcsan/atomic.h               |  6 ++----
 kernel/kcsan/core.c                 |  9 +++++++++
 kernel/kcsan/kcsan-test.c           | 23 +++++++++++++++++++++++
 kernel/kcsan/{test.c => selftest.c} |  0
 5 files changed, 35 insertions(+), 5 deletions(-)
 rename kernel/kcsan/{test.c => selftest.c} (100%)

-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616123625.188905-1-elver%40google.com.
