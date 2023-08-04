Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBM7MWKTAMGQEMIEJCOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 373D776FBED
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 10:26:29 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-3fe45e71db3sf4178615e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 01:26:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691137588; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZXstAY9MHortHVkEks7+4YUhQlzHwruTOmP4ccnrjPZVropHPeSFzdQR+8QdM/QJMw
         irSgSNJUeRsCFtWiN4PGqLPRCBKdR5SCL1T4WwKx7xAJGp9TZAVZjYBCAxy6zsqk5Pku
         OE+0QxCUNKSiXrWVOW2h9GP42iO1SFdzoei3lnkeCLu3OS0Yjuzr812UAZEjAyOlhOzj
         Hw00J2jU74YBgGrIJ/ss7bLMNFKBvAw/Lqlm5JfSOnNcOe9tjy5XZ+C97nWWsExrv4yI
         D9u5sZc5Qd7kDnpjqCFqVK4JlUbOexYlB2d3vTki6VUzQL6a4+Hl29z5avj50UKfnAL8
         2ZNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WKfNb9d5sRgZXsh2Go1gcXTkIW4ncFdnafHk71S2zio=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=JMIV7aWeykm1uWR4uAhwcUIXsUX8yr+tNFsvaMbyk2KI/LiZ282pe3InalNH+chu9F
         gDHqYCQ7SdV1gQUYBMQH/ZaqflR/RXvJc5+p09BbTnwCfYluTVRlMhmm9TtZMe2UxrPO
         xPsewjSeAs/1PJpV5waF0ORLBwWtv1KAcGYYN8KV7mfbMoAz6RHraFDmtjP/uLOLMgO/
         Wb1nGMmzzB3lzxhObdIOZbKh0s8cK9z/ZZw0e4Q2nE74jHLcz/EMo88Pr1TMwbVr+chs
         Ov8O9QQ9uaMPdwsWkoFDeohFVsKIj8cKO0xYeG/9DRXXnzFZV92KRaX2hHM1vrLww6jV
         i/LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GQt7rfUS;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691137588; x=1691742388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WKfNb9d5sRgZXsh2Go1gcXTkIW4ncFdnafHk71S2zio=;
        b=lTjuq6gIsF+DDNQJ2X0QPBFBSUtCOqOepIoar1SkGmucG+92cUO0lWb2UOTEyUNQDm
         L6JtFesYiY99BilNq2sXFPiMhIvJqq7FIXlD52iVz21DmnO9I/oHoXkU7411v7gu9tBi
         AuEcV4vZpfmzpLCRzgf7j+x+PvZA5mtwugiUg6EO7VHnCevDId6m9lq0O24dGqwDLD+g
         7TzvNUqGKYHvdx4Xb1U2J3hPgVhA1rEp6v7EnWLqLMaCzFR+mwNd0UsK271X3ErfBhx8
         VwiJxORyQ4YcmJazDgnJvfxuolvN8C20bpkpbUNyUQTSvr/gelpMbvrFGBEwO6bMfb+l
         Edqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691137588; x=1691742388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WKfNb9d5sRgZXsh2Go1gcXTkIW4ncFdnafHk71S2zio=;
        b=NIi29jyS1iaU9fQYdJl4QDR8WvWUc6prPZjC99DPttckFmpUqpstsILx0Fajs9IHeq
         hfvObEZpd5aTK6eNN+PIDkPCwD9icjOftvaCeeAp1YFdRKk27HS66hkghkJLw1A+dQTd
         ItF3gyXvBT4/sAFgm3fRN/OhVqYreGZCWTAIQlfW6AYKSKbUHVFvIfjlvfKxeBM+dC4w
         PjPMh0zc0L+nNw5hcZ2d6gJEckguVhnD6Z9HL+Qft7SEOI04LBWYgbUPjEPzJV1ZCHcX
         ftGyjIBtRSw8nxJUCaHoj9X9usFqlG4gCXpWwRZtNUr0wVKMdVxOEae18U5iCmnEZrJA
         Yd9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzFEzl8a+74aSqR4XCUB0FoJrVhIpGg/Uzy6IK3z6iTiu6KwDbL
	pJLgAsgBOI2XsR0nyeXkr7E=
X-Google-Smtp-Source: AGHT+IEgMM8t9lWsgBMukjeNr1gxcezL5Lb7TC9E6ax6KJ1EcjVWX8fsPuZHVnFdfAZao7BOAbJ6Pg==
X-Received: by 2002:a7b:cd10:0:b0:3fe:1deb:79 with SMTP id f16-20020a7bcd10000000b003fe1deb0079mr966593wmj.26.1691137588067;
        Fri, 04 Aug 2023 01:26:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c25:b0:3fd:2f74:fa8 with SMTP id
 j37-20020a05600c1c2500b003fd2f740fa8ls1980462wms.2.-pod-prod-02-eu; Fri, 04
 Aug 2023 01:26:26 -0700 (PDT)
X-Received: by 2002:a1c:f715:0:b0:3fe:196f:b5f5 with SMTP id v21-20020a1cf715000000b003fe196fb5f5mr975360wmh.16.1691137586496;
        Fri, 04 Aug 2023 01:26:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691137586; cv=none;
        d=google.com; s=arc-20160816;
        b=RaBBCVxWYymmAHhXVFHzp9Jp+Tn5N2XBREbvWqV8byrgLa2X/h7VeiY1RJDLO1sd5X
         IWNHW4CXKqvOhXHw9nUYp7LYtG6lC3OrQ7jG82KUazPAqvyGVqPojVLYUTscYuYD/or4
         i1VoZ+AAT16fREi51cw1yJSpFOFCUAw3hyEU0SyKyfIpmHgt6D5IhpQRz6HJ3mVbzN5t
         CAYS7QG61+KpNFB/GsenycLXy1f1A/ASj9ipbsPigH1iqBJ+J1b6YGDX1iy1lVy+aIEi
         cUGo+DySkChuhoZmNm98JUjKvJ6znmce0EQheS1SrbYKb+FMp9OHhk+ti2Ev/KKLOXSD
         fORw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=qGsLNWMarAuuCP4hn3WhePhRn9hLu0OcSV+cI8+VfVg=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=qAFVHQ8QIVYCDF3P7gDaSd7ilHJuMtGUR3kYZp0HfRjyVv1iDOPCVipt36B5/CHV+U
         P3G5+a0RFDWrR2lzD+sse//IcAiwc2JI2IYSgx8EYejGu8zZp/xZkWFw4G/nTpQxhUVM
         nxJgcfOSyHbcRPs79OZs6IyJoptDic/HCWkLF3h0s9S6706RpfswULi65IgisIXd4JnZ
         6m9wzGY92ScUJP1mXudczLuv2EtkMfXCNVScr8H6zdxVhz1vB471My/FdbFBJ4z5PorB
         yDj84RH3Bn2zFQ455/zQQGUmaVtcTZhQ0g4++KpsmoaEa0M9iJq16diAQzGKu8gzPwoz
         hj7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GQt7rfUS;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id p27-20020a05600c1d9b00b003fbf22a6ddcsi146408wms.1.2023.08.04.01.26.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Aug 2023 01:26:26 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="370090202"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="370090202"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Aug 2023 01:26:24 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="733132236"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="733132236"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmsmga007.fm.intel.com with ESMTP; 04 Aug 2023 01:26:21 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 6BD6FBAB; Fri,  4 Aug 2023 11:26:32 +0300 (EEST)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH v1 0/4] lib/vsprintf: Rework header inclusions
Date: Fri,  4 Aug 2023 11:26:15 +0300
Message-Id: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=GQt7rfUS;       spf=none
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

Andy Shevchenko (4):
  lib/vsprintf: Declare no_hash_pointers in a local header
  lib/vsprintf: Sort headers alphabetically
  lib/vsprintf: Remove implied inclusions
  lib/vsprintf: Split out sprintf() and friends

 include/linux/kernel.h  | 30 +-----------------------------
 include/linux/sprintf.h | 24 ++++++++++++++++++++++++
 lib/test_printf.c       |  4 ++--
 lib/vsprintf.c          | 38 ++++++++++++++++++++------------------
 lib/vsprintf.h          |  7 +++++++
 mm/kfence/report.c      |  3 +--
 6 files changed, 55 insertions(+), 51 deletions(-)
 create mode 100644 include/linux/sprintf.h
 create mode 100644 lib/vsprintf.h

-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804082619.61833-1-andriy.shevchenko%40linux.intel.com.
