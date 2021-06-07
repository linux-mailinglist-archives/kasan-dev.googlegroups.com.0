Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIVP7CCQMGQE5H3MI5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 8882739DD15
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 14:57:07 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id jw3-20020a17090b4643b029016606f04954sf12547511pjb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 05:57:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623070626; cv=pass;
        d=google.com; s=arc-20160816;
        b=f5r6+cK9z4NWMu6JWhZHbDzyDhByIwTPBaUdbA00TNYpXgIhKZeH4QgGUFMnB0dlz2
         4jdBIv10awvmqYvTXQl8pzYbRUzDQX6yvHniemDcMEClor5L2MBBeLOVKf8gwyRIq+l3
         0nRDB0Y5jBzJ7oAD/s2KNNpSaj4vBC/Ox7r2qKhhcxD2+2S42XMfFHb6H8jMs/QauvyL
         0VInUCoRRYERvVgpAp/lbyz/3b9yFDLbRMJ0EryDpFgFqM56nZmISmZc6L0hA/EGDCu9
         gLnVakih6aed9M0PIAW9xfr3iVuCESHkw7gIyHP9ANMZwk4Q6BfwZNpFexmAfu64cl2w
         lC3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=9VpPHN0c4A2fLTWWcqdeSCsWGtulR/avHyx9gMMFRoA=;
        b=g5vcOdjPF1k3LWSeqMXNaymAxm7Zy863KKfOQfZCPDFevVYn3YXR0xCWXCrq46gw3h
         I90ZMxlm3yAlEZI4iTGspsSJU4PFLd5aNkpC78iHw07iuxZWqoKr8BacX/MefhFQ9cF5
         PuUbKv9Ny7hCtkk7E8MV+2hGG+y1Rqe3tf/TNsoMQ1LB7lDfPhVPFYDXY08o8Pk0dd4F
         X9ovUpW9ZUA9keNRPbxvZpWEk6HZaAP43HfayV7wYH/Hr/wP7dBoJuU24Nnoq1CdoMi9
         ru31W5Tj/zpp73hpo3x0WY4/k7srYIap/qCfOUAv1nEIx+ujfaFiz+/wnOMhx5DFug/W
         gChg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sRyyLxFt;
       spf=pass (google.com: domain of 3obe-yaukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3oBe-YAUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9VpPHN0c4A2fLTWWcqdeSCsWGtulR/avHyx9gMMFRoA=;
        b=DzJ6/Z3ytGCK+KNuWfiji7vjeEW08B4Vf5shBhIqgh1BX47zoiYhucF6Tm77DLtRBx
         Qw2UOgmuSLqu2pIWffn/XnjdZmB1+/3jNfryYwerYbVYmin/8eYjTJbKESS8F7mR9T2+
         J+qYhaKSeRJfsYunE3EeTbytaWWVbeHbcNSw5MEcs2jpmhz/J7fJa+B76sww9Us8udKY
         b9MiG1F4YrHeNAWB8NcAgnm6x0POQ/vxFbq5YujRcy1rna1HSsQGovdcrB4tgdXAnGmZ
         c6O4jxoRw+oJNxNczFNrX9K4d2EzF9R0SZkTI2AAPJwj9M3T+EmoiaFx+a/u6wpnRBg8
         3pDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9VpPHN0c4A2fLTWWcqdeSCsWGtulR/avHyx9gMMFRoA=;
        b=Ij5T0Ht1gR4MX31RWNEaBs9SdEx5O+bc5ZROHPQ26eC4bVeVg5UkrOBBsMYLFrEAKL
         XvZy9PmIo5fsPya0xKxECqaTXJEhwh+GYFFgS5sYS7oGfaLoMaEtI+DoXbXc5bTaSt15
         Tc87cdgZ+aSesnmDUeNNGJwYdJRbomzCu6MSANHOzplk9sIgm7WS7Wl5o5x9TjwqSPvG
         Xia7+7VRG8UAXgh7pe2L5bzCbNlsJBcJ7ELtSXKJt1F9YcO2Ct4c/stluhAf5LPkDN5N
         LIS1Q9xSg1GADcupFEDlcUy5yk/yvU9xVOnv7M2Nr6I/gJID2YSKtQ8mKG6Sgqb3MCSk
         Mdvg==
X-Gm-Message-State: AOAM533J48sqMWE4gyij9CSze5BTIpHVlpUZQQ96nDtc7vVsEQGC6CaM
	fAlerBUzPA2FFI1U4soW2/E=
X-Google-Smtp-Source: ABdhPJxPoZj4fDQ50jU0n+ZnpVtOX5sXtzugSrkHQjTJoL2VwJvdJI/uNGcaBYVlwJ9KRQqJfbETDg==
X-Received: by 2002:a17:902:c942:b029:10f:b651:4fa9 with SMTP id i2-20020a170902c942b029010fb6514fa9mr14988347pla.83.1623070626296;
        Mon, 07 Jun 2021 05:57:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e804:: with SMTP id u4ls7537761plg.9.gmail; Mon, 07
 Jun 2021 05:57:05 -0700 (PDT)
X-Received: by 2002:a17:90a:a512:: with SMTP id a18mr13076426pjq.215.1623070625612;
        Mon, 07 Jun 2021 05:57:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623070625; cv=none;
        d=google.com; s=arc-20160816;
        b=hutBak31vcTKdgImMEtVKfoTPykVEAV9DPlnXASdjhYwNoRgnQJArpNNKguw6ExSjJ
         rqIOmAFX4Q+lizesQelBKhkbJqZJ+q+b8jpg0Z8ZLgog63OnuAiigSVbnbN6QZdyrOGL
         q8ElKvDmT9jM8trDN5tH+GtC5oBlgFdoTGX+/tdFnJOlxx4amJMgq2AgzqvQd6JvvJax
         sedmbcw4kt6+hX3lk3SvcKFZZtUWufyGhFVOZNDylW6ESkAcT2gKlrOTXLHFgVg7CQ9L
         Rg/Pqg9a4Xt16vM5sCuLlUhyLtvF33gG5BWdHrbeBy9k3l6EZTV2+IvYauPDe6SM4aJ1
         n/Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=n+BHm+6M37s7n8g9zZY3JE9atHfS3eOCealK8Ja+AsE=;
        b=FnKr23y3FzFFadztj0Kg0vR8OJkfegkPZBYT04MqTOUPcrSuSpRJXSQI2WEoF/Bj5T
         5p/qaQFoPO79aWkz/JfGTwk0vF275xjD0G+EwOc+6224qrtiE4uoNvuS4rwiS2QmkOPf
         LeK/AR1SeWgHFnrw3lZZzcf/ZX1QFE/3kNKIn+oIf2yXE42WztYVJXE1aURnWkbmJn1m
         z9NCAAFRAfyLrhVgOgAjiw1o4pa6B4u8y997Hg4hOlMclLV9qbJuJDlNB7tMEzoY5Ahi
         iPpafTC89SWN1fxG3ty7UHlQMORAusUQOuAUmcjpJsjUxo7+hjVJOtqlONrdFMSOBr5c
         t7Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sRyyLxFt;
       spf=pass (google.com: domain of 3obe-yaukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3oBe-YAUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id n5si966212pgf.5.2021.06.07.05.57.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 05:57:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3obe-yaukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id s16-20020a0cdc100000b02902177eec9426so13120854qvk.4
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 05:57:05 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2587:50:741c:6fde])
 (user=elver job=sendgmr) by 2002:a0c:c587:: with SMTP id a7mr17495331qvj.59.1623070624677;
 Mon, 07 Jun 2021 05:57:04 -0700 (PDT)
Date: Mon,  7 Jun 2021 14:56:46 +0200
Message-Id: <20210607125653.1388091-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH 0/7] kcsan: Introduce CONFIG_KCSAN_PERMISSIVE
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: boqun.feng@gmail.com, mark.rutland@arm.com, will@kernel.org, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sRyyLxFt;       spf=pass
 (google.com: domain of 3obe-yaukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3oBe-YAUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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

While investigating a number of data races, we've encountered data-racy
accesses on flags variables to be very common. The typical pattern is a
reader masking all but one bit, and the writer setting/clearing only 1
bit (current->flags being a frequently encountered case; mm/sl[au]b.c
disables KCSAN for this reason currently).

Since these types of "trivial" data races are common (assuming they're
intentional and hard to miscompile!), having the option to filter them
(like we currently do for other types of data races) will avoid forcing
everyone to mark them, and deliberately left to preference at this time.

The primary motivation is to move closer towards more easily filtering
interesting data races (like [1], [2], [3]) on CI systems (e.g. syzbot),
without the churn to mark all such "trivial" data races.
[1] https://lkml.kernel.org/r/20210527092547.2656514-1-elver@google.com
[2] https://lkml.kernel.org/r/20210527104711.2671610-1-elver@google.com
[3] https://lkml.kernel.org/r/20210209112701.3341724-1-elver@google.com

Notably, the need for further built-in filtering has become clearer as
we notice some other CI systems (without active moderation) trying to
employ KCSAN, but usually have to turn it down quickly because their
reports are quickly met with negative feedback:
https://lkml.kernel.org/r/YHSPfiJ/h/f3ky5n@elver.google.com

The rules are implemented and guarded by a new option
CONFIG_KCSAN_PERMISSIVE. With it, we will ignore data races with only
1-bit value changes. Please see more details in in patch 7/7.

The rest of the patches are cleanups and improving configuration.

I ran some experiments to see what data races we're left with. With
CONFIG_KCSAN_PERMISSIVE=y paired with syzbot's current KCSAN config
(minimal kernel, most permissive KCSAN options), we're "just" about ~100
reports away to a pretty silent KCSAN kernel:

  https://github.com/google/ktsan/tree/kcsan-permissive-with-dataraces
  [ !!Disclaimer!! None of the commits are usable patches nor guaranteed
    to be correct -- they merely resolve a data race so it wouldn't be
    shown again and then moved on. Expect that simply marking is not
    enough for some! ]

Most of the data races look interesting enough, and only few already had
a comment nearby explaining what's happening.

All data races on current->flags, and most other flags are absent
(unlike before). Those that were reported all had value changes with >1
bit. A limitation is that few data races are still reported where the
reader is only interested in 1 bit but the writer changed more than 1
bit. A complete approach would require compiler changes in addition to
the changes in this series -- but since that would further reduce the
data races reported, the simpler and conservative approach is to stick
to the value-change based rules for now.

Marco Elver (7):
  kcsan: Improve some Kconfig comments
  kcsan: Remove CONFIG_KCSAN_DEBUG
  kcsan: Introduce CONFIG_KCSAN_STRICT
  kcsan: Reduce get_ctx() uses in kcsan_found_watchpoint()
  kcsan: Rework atomic.h into permissive.h
  kcsan: Print if strict or non-strict during init
  kcsan: permissive: Ignore data-racy 1-bit value changes

 Documentation/dev-tools/kcsan.rst | 12 ++++
 kernel/kcsan/atomic.h             | 23 --------
 kernel/kcsan/core.c               | 77 ++++++++++++++++---------
 kernel/kcsan/kcsan_test.c         | 32 +++++++++++
 kernel/kcsan/permissive.h         | 94 +++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan                 | 39 +++++++++----
 6 files changed, 215 insertions(+), 62 deletions(-)
 delete mode 100644 kernel/kcsan/atomic.h
 create mode 100644 kernel/kcsan/permissive.h

-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607125653.1388091-1-elver%40google.com.
