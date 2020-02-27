Return-Path: <kasan-dev+bncBCF5XGNWYQBRB7NT4DZAKGQE3XLTCGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id BC23A1728AC
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 20:35:26 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id l13sf727599ils.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 11:35:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582832125; cv=pass;
        d=google.com; s=arc-20160816;
        b=lqu0WZp4yVRqYl98/ixaDtPL/Qn2ha2CR3+CZaCZQKFy//7QQTiGJj98YXkBuJDkHT
         cv/SxovMZJRfGpcLJeIUXGg1NZu6xQwDb7zJb/NcJGg/QqbOP/V2HLnm6E4IOOtVrSpA
         9bInQHAdRCDevE3fVlfNIEbzp9952sg1RqGncXbtiO5L9h0Ithrorm4yW9AjFWFhrBSY
         eF7/LsnqK4MIrDCFBTWjVyq2ylBsRumFKp8afMMEK6ST/WMfLvu1Jhy9TJobottd5ZJ7
         NKy5TTC34sPQHJwgmzckugDWFg0VT1HP13bSBNE/SFNvliiVjv2YGZ6kKT10zksW+5KF
         LTug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NT2iTBxbLzMjfOOxueubtrMkTTN6HIIlDinTggB0Lhk=;
        b=oXSe414siF5NTSXO+3TTPGB0zWQdb3ZLJB/K5N04kKrDdsx0dLQfJzaxPn36BIsbSp
         v7LmsvRKSaePJRp/+WXOHykQln+CMak188dfzdBuYx3cQbSMS8kMzSMnt44lHEZNtQbu
         1c7wd4XoccAEhGI+oZ9IZrR5B8VVIgdadwELtO2Lccv4Mw6nC1BxTwbnekIDgqD2qXsR
         bYLBv6Cr4gny5PKcR/WxmULfxRnKWaSlZwgjYWLh4838oQ93Fu570e/KSJ7yhq2gHYsn
         iuOOUvq6Dh3WpivlzqKN7pfN30j2GL7qrBCHrLY+6lqHkIK8Gq9NjETfH2pbcwE48//j
         xnSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="GqYMFX/u";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NT2iTBxbLzMjfOOxueubtrMkTTN6HIIlDinTggB0Lhk=;
        b=gwQu8AbKu4fcmwloYzpnrtf9HkBWfGBKYKjbH/Uggnkjau6qDLROQk1cixEjrtEFUq
         UeYMLfHImjp/0U4iid/xAEZz/D6fKPyqOsIcj3L7Sv6dhUsaKzveXKah3MAvZLA/1GHF
         urm5cHVbHjthLo2UM1NlSg+6JAjmSuWurMyxjrQtwlMMJmgvC2f4R9QO9gHlnOK5MoGP
         v5W2evmBCewx4TgigG+yU4V+kIbr1qGJ8B/Yvt8ZV/gDY7klL/tkyA/wQ7qtF3y89beK
         XD2vc4ChKzzMeIzZjgrjWiKbo4m0h37Q/aX+PGUCRMRNDmoAw0Gt7i8ikKaKdyk3bqAM
         lokQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NT2iTBxbLzMjfOOxueubtrMkTTN6HIIlDinTggB0Lhk=;
        b=opPom+cT0eT/Oo+Sm3OhR/JMa0Xjyav8y+D5gjNurpxVY47jQ+YjHLwDRyS37Xm8ey
         9kFnHNLyYXzxSd3wcTDSPEH/JaVWbyqOXgmWPZ55DPoqvtHT+4Gb7gfg0kfFSYdk73Eo
         UKDnqsWQ99hYj+o4CwAb7KX2+RvRXxM1E9B9Qt9uKCcgxOfyrCwmF5F9ZWwnHBoAg/Vl
         xAxAt7NQGUTYl8/FD8i/TXcXOAVw83HNLglFkSyWXrBG0sIYvurYMH3Wo9MhwUOuQEvW
         h96DNbqpPZN0a8VNIRGyTG1Wophwdb5S4cjNRSe2z6IyeqOrXlXjaXbWeztWp4JGyQjq
         KnfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWJJ95GPWnHwVoaYMPOlULZ4+HlzqmfP3l9hy/8Hgtl7E+knYwf
	tPQzc2W1EU6Yab5CJwK9JyA=
X-Google-Smtp-Source: APXvYqxb+8xb3uvcPIgdcvCz4TDQtDkI6qd4vOTmj1o9iNou72AX5ELsaG6VUEvsxMI9QhFB6/UBsg==
X-Received: by 2002:a05:6638:5b1:: with SMTP id b17mr378088jar.66.1582832125751;
        Thu, 27 Feb 2020 11:35:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:1483:: with SMTP id 125ls131383iou.2.gmail; Thu, 27 Feb
 2020 11:35:25 -0800 (PST)
X-Received: by 2002:a05:6602:1242:: with SMTP id o2mr777702iou.0.1582832125418;
        Thu, 27 Feb 2020 11:35:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582832125; cv=none;
        d=google.com; s=arc-20160816;
        b=hEWe+s+Eg9KEArPnGea88ZGhqc+nq1oWp0xilpTKNfMfBuv7a/7IrvZVayv5m3MyRv
         166kbAoo7coQzHV5svZZ0xQiR+Z8FeOvZlSUzoW9VPgPO2xdcKbV7wfR7zOmvfobFx51
         3fHxNjE0r+xjEroYXqffSGx2hUPS3eC6XpZwmH4EX774l22pOJ0iv0mZPJbPUbOETJOV
         isWWzotZDnYe83GkuJxbsATLH/ymS9GjRCL0teJ8XnNglUsPO/FTHD1sdg7vPnY2l9Y2
         +b9iKNR51qovOP0cVxIXYudN6bcFFPu0RJt3SH2F905khPnZq5B1mzm898drC5yK25QE
         r51w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=AoE4OLd/IvDA6cmd9pXDgHl19RWwO6y4VAoz5pE6b4E=;
        b=sAhHQ6Wwe4x12n8pXmFcMYrwAMC+48LfN4zlowuhSRMrWmMpJ+bxVFfp6Naapq9etL
         dRvcvCkN8IVWCMRzTHtK8Ulmxu36oSPtW61WG9YL+VgTUq/A8aPZnzMXocG4A898BYbo
         FtXjV7nD1oh96uz/kpsiNGJ8bgIMAzXXBIHcfa41Pivl1kdbtR3KIV4XlBMNQHrn1i9o
         wNF4QRYKKhXeFLMRMjzvMxKQku+dDvRqJcDJ3QttHXs8CyBN1EWFT07VEQy1kaxSVsdY
         063KzeIv/ouLDdFftsO+Sy1KwY/cVdnGW0JsNwYPg2MaXktgpJGvFhSKDi3eGtBeKl7r
         /boQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="GqYMFX/u";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id d26si26684ioo.1.2020.02.27.11.35.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 11:35:25 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id a6so210826plm.3
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 11:35:25 -0800 (PST)
X-Received: by 2002:a17:90b:8ce:: with SMTP id ds14mr584791pjb.70.1582832124805;
        Thu, 27 Feb 2020 11:35:24 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id e17sm8348002pfm.12.2020.02.27.11.35.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 11:35:20 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v5 0/6] ubsan: Split out bounds checker
Date: Thu, 27 Feb 2020 11:35:10 -0800
Message-Id: <20200227193516.32566-1-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="GqYMFX/u";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
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

Argh, v4 missed uncommitted changes. v5 brown paper bag release! :)

This splits out the bounds checker so it can be individually used. This
is enabled in Android and hopefully for syzbot. Includes LKDTM tests for
behavioral corner-cases (beyond just the bounds checker), and adjusts
ubsan and kasan slightly for correct panic handling.

-Kees

v5:
 - _actually_ use hyphenated bug class names (andreyknvl)
v4: https://lore.kernel.org/lkml/20200227184921.30215-1-keescook@chromium.org
v3: https://lore.kernel.org/lkml/20200116012321.26254-1-keescook@chromium.org
v2: https://lore.kernel.org/lkml/20191121181519.28637-1-keescook@chromium.org
v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org


Kees Cook (6):
  ubsan: Add trap instrumentation option
  ubsan: Split "bounds" checker from other options
  lkdtm/bugs: Add arithmetic overflow and array bounds checks
  ubsan: Check panic_on_warn
  kasan: Unset panic_on_warn before calling panic()
  ubsan: Include bug type in report header

 drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/core.c  |  3 ++
 drivers/misc/lkdtm/lkdtm.h |  3 ++
 lib/Kconfig.ubsan          | 49 +++++++++++++++++++++----
 lib/Makefile               |  2 +
 lib/ubsan.c                | 47 +++++++++++++-----------
 mm/kasan/report.c          | 10 ++++-
 scripts/Makefile.ubsan     | 16 ++++++--
 8 files changed, 172 insertions(+), 33 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227193516.32566-1-keescook%40chromium.org.
