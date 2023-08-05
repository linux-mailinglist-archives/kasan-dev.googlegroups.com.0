Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBMUXXKTAMGQEVRDQFIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0219877111F
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Aug 2023 19:49:40 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-4fe3a1e0329sf3112232e87.3
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Aug 2023 10:49:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691257779; cv=pass;
        d=google.com; s=arc-20160816;
        b=fuWEGhArJQstNpH9H1rU5D+vHGh1rtPkAszjq6FMaLgzpBbC4it+wDNasUJv/yzBT+
         MMs79iVwumI6hEOAr7SNBPFt90u5KIIXBCiiFMKL494JRjeAGqnYYGNtdJ6nQOKdAPaG
         5xEWDeA8/ye3aVgwmOaQ7Gpq/e20P0K19aHh3GWGW0vR5j+2ySds4YoxcvoUKaeyx5MX
         gsJa8BufMATyccgocHCSlkM+QpFHo3TpPnOSduCRjp+supy7YiyHPgWIZhbXjS7mNIPY
         MiTRbAPy0u4RZ14JVZYLebwtFqqnFNx6k/JDJS9OaJNB+vux4keQTedIHJZEJ3fwXwWD
         yW/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=tQMocabo5Uva4ijKbjN3zcSPfTCS3yQabM80ygyqSY4=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=kpRIbhg1F6hlD640QXX453ejgQQAdwfcviXW7dxWe+Rrev8C1kr/KFg4yorXMxx05i
         dny7YuHDITMDpva1ydLxOl6mKxi6pxTuylG4NWnDyh9rMVXG5nWngeJrDBDTgol1EXHc
         3GhQEiiuN9jzgCBbWYURdf2fzeBN/4ZDVvq7KGFNvDaTpsrdiWtKtCorqm8S6sU/GE1l
         9jVo6GbULZf1+H8355zYX4dL3hcaWlI6P+o00/qIr/mzdA0twYZXtls+RWVqUkSd8WM8
         7CFmk9SJ1VKD+OOQJ6ZXCUOxjmJhMiOIoL/A5TAeFUyQDpyU0xco2RHKlliZrnFfy6ix
         MYKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GED2JNqX;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691257779; x=1691862579;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tQMocabo5Uva4ijKbjN3zcSPfTCS3yQabM80ygyqSY4=;
        b=Rn1aqQlGGCBqBBF5M6b82VxHgxnjnWhqvUXkEXuKmHmmGO3xcmvwhZxEPi2w9BozoZ
         vfQf4g90udH27e3UTLJzNNannZW+Y53uIdv93L92iz6meP/P0TxXJGJW/7n/NHw2qJDF
         UBO8ZbhWsCj11zr7oP850W/6P9ckFU4FdziKo9/54EYOjvBzy5dZDdodOHVHBHYjmkKf
         LhvDw7okpux9i2NC0vzhKyAMoBxhLt4O4zczMHRebBP+X9BSuwM9wplKwDpXRKzYSFFR
         i08xHatJ1P/BsCSpuuG5Y5ccV0LqoVmu8ufWSub9u703XazbF+zSnNzp+pE0N4HfBg58
         B/Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691257779; x=1691862579;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tQMocabo5Uva4ijKbjN3zcSPfTCS3yQabM80ygyqSY4=;
        b=P34NNFpFCksXBEy9ER9c2qxGHhYTJ8lMD2kJFBqul4qLdOxVC6zhz1VHt4Ev2nMKXH
         AjTXuLq3A4bWxmr1WFYysGhLOt3+qtMPHRzR8kMFgnt/JAGT/VfEyRnaJdieRrPZ3D7o
         h1O3y56+uYm7Cw2c7fM8pfgSmwk35mrdrlw2hIk6knEL9bYVa9dZf/Y63JMiFRZLgpFh
         oZuGuNUI7gBDG8asAFjfLj7RX6kQJaOhpQ4HJfGqEmwqnvVeK9Cfx+i8F8J2Fbk3b+AO
         uNYV9AGLu4acSClycYgRbE6ETfCX7MUWVVMMUGU3RKFxG3J8tOgZEZkmRrx+CB4uyIIM
         8Gow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyiW5p+K5NB9NBQwnET3kwkFtEIbSbllF7jKt+NbaGwAi/BywYO
	i8nmt7aUHNtSj9VNtIRo1U+e+g==
X-Google-Smtp-Source: AGHT+IFU+cMlMBp4sVLaGvGDS/DrSG4iCiEBGFzfhQjhXjbeaueFbE3Y9mJW9HwkmsJTPSeuvW4yJw==
X-Received: by 2002:a05:6512:6d2:b0:4fd:f7a8:a9f3 with SMTP id u18-20020a05651206d200b004fdf7a8a9f3mr4212197lff.38.1691257778979;
        Sat, 05 Aug 2023 10:49:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:561a:0:b0:4f9:5593:b2ce with SMTP id k26-20020a19561a000000b004f95593b2cels429309lfb.2.-pod-prod-01-eu;
 Sat, 05 Aug 2023 10:49:37 -0700 (PDT)
X-Received: by 2002:a19:9156:0:b0:4fb:79b5:5512 with SMTP id y22-20020a199156000000b004fb79b55512mr3368864lfj.66.1691257777310;
        Sat, 05 Aug 2023 10:49:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691257777; cv=none;
        d=google.com; s=arc-20160816;
        b=gmWItD8/0dCw3W+3UEZNlKhka4ttw/norVhJwc6VEPbht/R9w8zjxm7yzmh+zcjxaN
         q9EwWRKCN72YiklKhU0HUr/FhJATM/9u8T57Nv0RVqEH3FcVCCAJIiFeViaF3Ad/h2AF
         rpQsYeREPozoR1ti39FMWPRdx2FUXxNsmS/6ZSoqG3K1bdkjNm2x1TxDHWpjILnh+p1F
         vHZ56B0vEWcwYycyBlr+i9JZptjSLakD7tUgxlnTVgE/XHCO+VNVlClgUVi+nGNrZNWv
         10hkC2BWTNBFFAz4GW2Kbz/6yeaingVLAab3ubEs1dSDU1VNDPQtV+ZD4St//80mB2QG
         aAfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=M7sJ9gGeF49op4HZCyGN9WO14IstQT6js5K5KrYBSYM=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=yM9RGPuBNkdzerSxYtRkHPbP8pRZ375XDyrYVFzhEV/3ffROFPpnyL3zfrT+OVOy3Y
         85XIZLyIpgBD+4CewMpyZzDpiNfCr19BxglVpI7p2qQZJ2TyZg14L5r7x7UcXvhsYIaO
         EpoLuxhKZFfEhQRadd1m4TocN9x+gdronzJ0/pUyIGCwF93Yjqy6aSmCotqJDstbYLc3
         aHJ4Vwq8zVphJ4plS3blCjgTmzW/OWDzM/S16j/S44G14AQ6ayepd3qHu0GW8Nvf6fmY
         kKL2ogiObCot0hTAP5pX65kZzDm4Cfw+jEOJfl5UHbOMvbLTLoh+gtRU9Kcj2RemrOPb
         EDqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GED2JNqX;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id a7-20020ac25e67000000b004fba12b2dfasi289524lfr.2.2023.08.05.10.49.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 05 Aug 2023 10:49:37 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="401292520"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="401292520"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Aug 2023 10:49:31 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10793"; a="820494256"
X-IronPort-AV: E=Sophos;i="6.01,258,1684825200"; 
   d="scan'208";a="820494256"
Received: from black.fi.intel.com ([10.237.72.28])
  by FMSMGA003.fm.intel.com with ESMTP; 05 Aug 2023 10:49:29 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 87E94241; Sat,  5 Aug 2023 20:50:29 +0300 (EEST)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Petr Mladek <pmladek@suse.com>,
	Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH v2 0/3] lib/vsprintf: Rework header inclusions
Date: Sat,  5 Aug 2023 20:50:24 +0300
Message-Id: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=GED2JNqX;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=andriy.shevchenko@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

Some patches that reduce the mess with the header inclusions related to
vsprintf.c module. Each patch has its own description, and has no
dependencies to each other, except the collisions over modifications
of the same places. Hence the series.

Changelog v2:
- covered test_printf.c in patches 1 & 2
- do not remove likely implict inclusions (Rasmus)
- declare no_hash_pointers in sprintf.h (Marco, Steven, Rasmus)

Andy Shevchenko (3):
  lib/vsprintf: Sort headers alphabetically
  lib/vsprintf: Split out sprintf() and friends
  lib/vsprintf: Declare no_hash_pointers in sprintf.h

 include/linux/kernel.h  | 30 +-----------------------------
 include/linux/sprintf.h | 27 +++++++++++++++++++++++++++
 lib/test_printf.c       | 20 ++++++++------------
 lib/vsprintf.c          | 39 +++++++++++++++++++++------------------
 mm/kfence/report.c      |  3 +--
 5 files changed, 58 insertions(+), 61 deletions(-)
 create mode 100644 include/linux/sprintf.h

-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230805175027.50029-1-andriy.shevchenko%40linux.intel.com.
