Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDXJVT3QKGQEBMEERTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 04C7F1FEEB0
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 11:32:00 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id j9sf1893739iog.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 02:31:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592472719; cv=pass;
        d=google.com; s=arc-20160816;
        b=LvyqyUgjUCCpBQ+wpJ4GLxL/Ep9SrSe5p5kbXNGxCJGNMYkjAeyHpFUgFkHGIF6urZ
         qxxMcbMclpDMyFsnHS7F7tH16JeqViy9pVpKWd+nZlB4a2viRcuhyKAr14n8IzpXDdnj
         E2sUPF22VLntht33NAhURHkojCkdkKFZmvOrEzQqunmzbNcsxc+b9DrEGg6/jcpbZE3u
         AuHueTidV/UqqAOsXS2BpcsyRtUT1aqKo/Etjo7v/xPkqOyWqshUZ447fEwhy2kvZ4SK
         OeaF+qdNRE0juyEXTekJSoGUsRTZx7ELY4Db9KGxAFJjJDZSYLYwPPAplqIsqPpGqo/U
         DagA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ennKrr+IwC2X3lGHfGCpDdpiAtmzUsSync4sALMZEnM=;
        b=iuyUpsXM4UYJ7K42sOyOBGHmvu4kzEodNd0P8PerIjGBK8c7IDU6benXdzK8E+Ww8F
         XU51zGgL6KEc0T0JJZ/5sSANeNI55oJVFEGWZiVkRFb2Z9y5m5M8gW8mFQ0PaSA6B0EB
         bDqNgxf8LSzo7TzhEHfqaWYHXiis/3pXVrDum6A+wwtKapPZB+Wev0/YAOjwhLVCAIU0
         WsLp8Hya778NnxJgD6ljstyliETZM/EJo47olJ9hZDs1M1NDWDPf+9uGXjeRW2zgy7vX
         LGplhRDXuZuoIb3LK6o/fQkdAnO9MWntBAMcvgn6FQOxEQ8zlHjWKgmfW/+4tv3wEM1o
         1AOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lrw5CS3S;
       spf=pass (google.com: domain of 3jjtrxgukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3jjTrXgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ennKrr+IwC2X3lGHfGCpDdpiAtmzUsSync4sALMZEnM=;
        b=nh2zFEwZYUYXaFFPa3WlL0a1Qh927IzzggRu5BJwRp2DWVH3Qbz9KxFdR9mIPn5M9g
         eaiRWFTleC8VYl1m1ib2UuFLwFFinT+MMZGSrfrSZfa8H0hzzFuH49wE1B4L9oXqBmNq
         EbdQioDc705mItwQDuVrKmPlVYtghdEkUP8yN1jql59Y3PE8yXAuNaIDUzoZwwuo+BaF
         O0rAmKTbEirdxaB4QBnPSVM48pn61a7Izb8qksMFjlTOMjQ8aWxisIyTbXcIFcPXUl7X
         n0pHe24sg7DVvs/rzpOjeIafy1Wi4bBXW4NT0euZNjxEhhmHaF48OY45szMn2sQPGCO+
         oXVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ennKrr+IwC2X3lGHfGCpDdpiAtmzUsSync4sALMZEnM=;
        b=mqfLUkm15W4fChc176WS4PCZG5V9AmdulrdSLY5mFxjCIcrSHL+avcWwIOJbw+cXmg
         sg0W4TfYwJpI1I+DvUILAW62tqRmAaeiXIV+1vNCEy2q0nLavySWQWYxfI4bpi+JkiEt
         70JiqKjMvg5SCPQsOGvi7foGLWz1bi07e9aBh0NLSCMgB8nRc4Cf7gg/J6m43buzhq1X
         UPQx2JxotsmLWLBZzLDx0BJPPpepWYB4/wARj3FDncgnJw33SkWM4YoN7CIhmb1KYak7
         hIJkHXdXTGgY5EgIQcv88mqrG+eTMxEg4bGxbCqiW2dzjbxwPPBZEJ2TetrrqrLT5wyd
         WV5Q==
X-Gm-Message-State: AOAM532D+VfkiE2yPeb2nMrS4mwHP6Yy+iBSBXgAKdZ/m+sTaZqCVuOd
	eiw/kwUzaJxq+blPfRIM4MQ=
X-Google-Smtp-Source: ABdhPJwi+9OC79FzR+Bvbhf/kfN1WGnelj5dNuIerMAPMKDU1KUlnB6WMThKmfDdiDZBVlshrX+snw==
X-Received: by 2002:a92:60d:: with SMTP id x13mr2933501ilg.156.1592472718877;
        Thu, 18 Jun 2020 02:31:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:ba8c:: with SMTP id g12ls659749jao.6.gmail; Thu, 18 Jun
 2020 02:31:58 -0700 (PDT)
X-Received: by 2002:a02:cc56:: with SMTP id i22mr3479361jaq.31.1592472718527;
        Thu, 18 Jun 2020 02:31:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592472718; cv=none;
        d=google.com; s=arc-20160816;
        b=Fdo/93tlop1IFTIYLYTp5TmzRF+tegTqOduXr9lmIW94n1Y7SBa4M6kCtISCeVrhwi
         6qftvr4mbHY38vZCW7p8lxfLODHMb1OmRZ/CYJ7DJHufHiiISF0vsR+PVYwF2KkRCdal
         CdVQ9v9kg47rvKPA0C91wiqQ6S1yX0arxk2nz+dYJIBZcqkoqbRH9QtZK9VHMKoElw5R
         pSotlpSu10GqlQQ3VqOvzkqfm8PkTJ8RH2dL2wwLpKKOoHU0OS3q3CixP9pO3HEDWcJF
         cVI79wGyOyRc6AAP2V6xWfeHapl2gXiHIl6/FQxGPYe8aEvWDWIhkzYG43wThH/8vu1b
         rlXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=L6v3WNe9vB4gYfOBJzsidmJB3J+19cEKm9MUweYc46U=;
        b=JPoiSJxbTgVIUpeEYojNKJk7z3ed7fVa3EtkuLlfewGxuvOA2vOGI66YaH0qPKFsgE
         ieFIzB72vPu1IT5thFnQeTq3xqr4HsoSGM3TZ+GjzHa/TqW3Wwye8DtPRXOfKhGyQ9Fc
         JQE6dMXoz/bLHJGwRqxkgj704s208iCsOKK5YsNHixXzX4NXOoL39dmmrbMMQhaNx+ji
         a7QHvyEiWNFiukNW4caFREBNrFYruU/ZsrDEG25d07KvaNRQ6vT3twMuwLvcfa1Jy4m6
         Jad7j6++xy3p1UZ5G/iFHpDnYpIPbAO6uhj1EBlaQta3BtNe8mp59vtdZblYznjEN+Qn
         qk3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lrw5CS3S;
       spf=pass (google.com: domain of 3jjtrxgukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3jjTrXgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id v16si89267ilj.1.2020.06.18.02.31.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jun 2020 02:31:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jjtrxgukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id s90so5796334ybi.6
        for <kasan-dev@googlegroups.com>; Thu, 18 Jun 2020 02:31:58 -0700 (PDT)
X-Received: by 2002:a25:84cc:: with SMTP id x12mr4787589ybm.454.1592472718011;
 Thu, 18 Jun 2020 02:31:58 -0700 (PDT)
Date: Thu, 18 Jun 2020 11:31:15 +0200
Message-Id: <20200618093118.247375-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 0/3] kcsan: Re-add GCC support, and compiler flags improvements
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, dvyukov@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Lrw5CS3S;       spf=pass
 (google.com: domain of 3jjtrxgukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3jjTrXgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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

Re-add GCC as a supported compiler and clean up compiler flags.

To use KCSAN with GCC before GCC 11 is released, the following will get
a stable GCC 10 and cherry-pick the patches required for KCSAN support:

	git clone git://gcc.gnu.org/git/gcc.git && cd gcc
	git checkout -b gcc-10-for-kcsan releases/gcc-10.1.0
	git cherry-pick \
	    4089df8ef4a63126b0774c39b6638845244c20d2 \
	    ab2789ec507a94f1a75a6534bca51c7b39037ce0 \
	    06712fc68dc9843d9af7c7ac10047f49d305ad76
	./configure --prefix <your-prefix> --enable-languages=c,c++
	make -j$(nproc) && make install

Marco Elver (3):
  kcsan: Re-add GCC as a supported compiler
  kcsan: Simplify compiler flags
  kcsan: Disable branch tracing in core runtime

 Documentation/dev-tools/kcsan.rst | 3 ++-
 kernel/kcsan/Makefile             | 4 ++--
 lib/Kconfig.kcsan                 | 3 ++-
 scripts/Makefile.kcsan            | 2 +-
 4 files changed, 7 insertions(+), 5 deletions(-)

-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200618093118.247375-1-elver%40google.com.
