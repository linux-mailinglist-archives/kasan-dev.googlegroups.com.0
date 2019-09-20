Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXV7SPWAKGQEGCOYYGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id C1F6DB9183
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 16:19:11 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 9sf3646369otc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 07:19:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568989150; cv=pass;
        d=google.com; s=arc-20160816;
        b=s1D1+ix71i6HUWuZClJHY1Ym2LBFtWD1o0qJpdzAvqVAx2irFB4YE9hhyGkfw6sMfD
         ABe5YWy171zBsDV051dUC1uK7CqMd6d1wtm3OrnvdQcMhZqhnzjDpAhz8mLFBTNeQfG8
         oSh/zTooiXb1DdC4j4FpW1pRlGpiSRIE1o7SiUjcm62PFUTMlsJNxNb3MQjBuG2sG3lH
         GcG3y3cN4onEMiJY0Rb7/Smip1EWoUL3/+uAMI0r5NPBx4gcLdIxtQ9WSx24+CNBn5XK
         s2a9q864o39CGejZJEdmex9KOQ/NUixXQxaEhZts6tTQY5YRb2ob5nCIGsqeLtpKAVsy
         5S3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:mime-version:dkim-signature;
        bh=3mhjWCrJWKQzD6t4M000nxn39Ovuy0s2ePlJjroGLX4=;
        b=ZZXEWJOnOlzAWx9q2fZpa15lZV3PpCUrXGhXpYVmuBn2TJ6o0A9jRP7xvJa8HTStrG
         cWICsCScc8HNRoeV5wBrYPBeHCA4/kd9XFho5Vet2jFk5qBchFx+ElfADcFMC2W5s3su
         BYzQQp3g0fVJ2YQiu3gfo6xFD9GVunPhNPQaWxdXNt8/C1ElMVYD+GPAO7jjHhFWiuGz
         sDeFhcGQPuZxpeMiZUsTgd5Vi91gyWh6H5cjoDVsRrcTm9i9bnOrYoMgwZiLhXfvCZHp
         TlAILkZOyGP+WxFZb93MEQvqBAX3FCKRaoKrLQewCUCd1XTEETGe4FHA+Qb3na4iyTtW
         eUFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dRC/bCyN";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3mhjWCrJWKQzD6t4M000nxn39Ovuy0s2ePlJjroGLX4=;
        b=HFyh7G5Ykxj4MvYWXs5p3rZL+I1N+qEobO2aGX94UO4Vi24NUdlDU4cDbSVreRofLR
         JJJFK7LUrjY8R/k+FqMvW+7Ck73cpkVdePXQi7cmugYhNfUFJnnSwm3VFV2FjHEJevhb
         IGfmmSzyVLTiH0m+8zw8gDUY+2750RMwjlglht9Cd3pb1JE+lCLaBOq7S75hzKlI9TiA
         idIirRNZ6tOYPDYvw22BG2/8/6jsjZ++kpxGuaSp7qhUJSd9KkoVggYDxITDrhv+IPE3
         DJfLcFP4L5ziykf3jsMKmg1D8us7uGrYjq/wz5EdVIoatzmGmHDIdXR2ARIBg6x1kpda
         RigA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3mhjWCrJWKQzD6t4M000nxn39Ovuy0s2ePlJjroGLX4=;
        b=gPRnTzwsDBfQo1oN7jy5JVlPgd3yzpAVNetU8LU3HmaqrH0VMw/o21we9ImPxoYWCt
         mDzCVjC4vlIga6Bj0xux0gv8XPpKSwE1Eg7d+VlMjHLhT6h4KnJ4fX4VbmtoaiAb4CtM
         ChN0txyMFNrau8q1SfFzqzVK6JqWlW4jDAq+EZBaTmIa4gEO0ySB3PvlcKRdFBtoXrjF
         kBA4Cipub/o23WCogFSUYDUb9y6ojo6VE0phl7kWT985bWtHwzxlQ7J/xmnhIZUE7CYV
         niBWNIt36DcJxxkK4kl9G7HmSJJeDv/3WhhTb/2GdW+Fzy1cNQM2zZtp//hB7E1bOglz
         e/Gw==
X-Gm-Message-State: APjAAAXKe9osM4IyLAGsvJaVZdCj7BmX1x7v2RGn2D54C/0X/w8XsUpu
	ZdU5j+L3cIN8Rf93LV/3ZAo=
X-Google-Smtp-Source: APXvYqwrhpgBXuazeZsRZL2qFmRk4t35GT/R04++YnJPjnSPQg+Y64t7GGJ0hJ/rj63p2/K/HpCQmA==
X-Received: by 2002:aca:7212:: with SMTP id p18mr2958475oic.165.1568989150412;
        Fri, 20 Sep 2019 07:19:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5a07:: with SMTP id v7ls1633253oth.7.gmail; Fri, 20 Sep
 2019 07:19:10 -0700 (PDT)
X-Received: by 2002:a9d:6190:: with SMTP id g16mr11573786otk.302.1568989150132;
        Fri, 20 Sep 2019 07:19:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568989150; cv=none;
        d=google.com; s=arc-20160816;
        b=GpUr3DPnr9indTojTDDD4eBBtkln8xwSFtq5Uauly/p1pOqi0WyUenoTuiXHUjteqK
         16ISE1JEs9a77pgAm+vUjDIdEEIeN/zBB2VMlgOADGSkAS9PbFxDvcsdhE7HXOd6nHLv
         m3GnE8XpM9+lEQr7+i3/Chtis6lPpDSEV6XlrTJfxB9KyvOgG9+h53zGldfIEtLXp+ym
         uHLVkiFOFVpTkYhNNc/xNV6Uy4q+kHZCTMtS8hMSP+5ph1SCQ0ud5AAMrgKg0Xf1plcP
         6Hixec7VdbYydnf/SYr2oVfHYsE0Se9aJH6hAklB8sqTZMS5x1MvRE7B8pfIoCQ+zUDZ
         LL0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=g3oaDqbgzggwPivHDVLZWW42Zmh9QYBbWFwvRIUuPVY=;
        b=TolhpDJPCTrdfYLVZzdjnPLK5vhj2hppeo8Hj6p1jdi919mcaSHEqZV5NZJAn/6lbk
         cDq/bBPn5ur5Lgixa8OSJWPMibQbUkv2FuQZxoCTGsdnUIASt3Tc0GK8a10tA3IA4Uus
         M3AMKb5Tvz6Kkw+sRKnqamBga+s6EPj5iCoPC22cESyWgT4v2gez5xt+nlr5/0JdiCIC
         3oEPTbIXnFpQUnJdhQGG/LJMSGjEQeRx4qqReBRucIDe0kUdAbagrLQpODLaLbwl1BeC
         wyHokr5FDxvqQwO2pEFEGwvpKdo874PufZDWGMpMfZSjSImaCLIep29qP0hiaBE1Pgly
         HV2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dRC/bCyN";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id k198si57822oib.4.2019.09.20.07.19.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Sep 2019 07:19:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id g13so6306699otp.8
        for <kasan-dev@googlegroups.com>; Fri, 20 Sep 2019 07:19:10 -0700 (PDT)
X-Received: by 2002:a9d:774b:: with SMTP id t11mr178617otl.2.1568989149028;
 Fri, 20 Sep 2019 07:19:09 -0700 (PDT)
MIME-Version: 1.0
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Sep 2019 16:18:57 +0200
Message-ID: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
Subject: Kernel Concurrency Sanitizer (KCSAN)
To: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, paulmck@linux.ibm.com, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, stern@rowland.harvard.edu, akiyks@gmail.com, 
	npiggin@gmail.com, boqun.feng@gmail.com, dlustig@nvidia.com, 
	j.alglave@ucl.ac.uk, luc.maranget@inria.fr
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="dRC/bCyN";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Hi all,

We would like to share a new data-race detector for the Linux kernel:
Kernel Concurrency Sanitizer (KCSAN) --
https://github.com/google/ktsan/wiki/KCSAN  (Details:
https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)

To those of you who we mentioned at LPC that we're working on a
watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
renamed it to KCSAN to avoid confusion with KTSAN).
[1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf

In the coming weeks we're planning to:
* Set up a syzkaller instance.
* Share the dashboard so that you can see the races that are found.
* Attempt to send fixes for some races upstream (if you find that the
kcsan-with-fixes branch contains an important fix, please feel free to
point it out and we'll prioritize that).

There are a few open questions:
* The big one: most of the reported races are due to unmarked
accesses; prioritization or pruning of races to focus initial efforts
to fix races might be required. Comments on how best to proceed are
welcome. We're aware that these are issues that have recently received
attention in the context of the LKMM
(https://lwn.net/Articles/793253/).
* How/when to upstream KCSAN?

Feel free to test and send feedback.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA%40mail.gmail.com.
