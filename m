Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBMNL5GTAMGQEMQCUVQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CA6B877BDDD
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 18:26:26 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-3fe657c1e68sf729675e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 09:26:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692030386; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jy39HqRyNqZXoQY74sGeCK762cGaNIuXHXkQRuAKcMmtjfDubONQ+I2XByCabzgS2h
         N/VGLC4t6S0fzZcVKt5WanklotP4W9sy5x0q/wu7qgUiBQPVn7UtvyZ3kW0rIu0owGx9
         cPH15L8cvbxO0cmUjNzelCijYq8rC8T+XnYALhGNSCHYd5fmOz63FTSR9YKiUx0ac66K
         NOKoVCQgqvMo236YfrnuhnLAqqqrM4Gm8iBHU1uq5rfdQwj2TA7E4L0+hf2mRsPmZukQ
         pt8Aqk9E1KrgtSvtOx9PGsnQO6KT4HP3DR7C1M1D981HglLZqCKNjPynp3w4Pr5WA7SJ
         qIig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JMyQfqzKq3arFCEbCB2w4Qsda+OJK0ZUCUL7g8BamV8=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=nz+94eo7LCQu/kW7UuNEgh7DP3uFgMuVTXjRZyqbyXw8Oa3w0KF/u0ZMVU7GR/mTiv
         v3oUJgqHShOwuYzQSOqeIDiV/P3pYYIA7VNeoc45GXC4lD3uc0Wcr8q+y9Ojo2IQCI/H
         bZog06DUssx8TtLvLUJWTzLdHFDDN2aT3d6g93DG6LUcpnIqvdVI4yp+r4OZn0K3OyfK
         KxH01nHZKlUXjYvf+cZqHdK1MNkmIfWQbavDeXP12Jjl85m/2VNSEQMJk8qdXLhXWev4
         FFUH9rS0NI4PMufIMchYuwqxaTLnc/PjjJ/y+z50jMGqXnpcBx38yBGDfEM41N3JTPAi
         VyRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZEAYzzlk;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692030386; x=1692635186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JMyQfqzKq3arFCEbCB2w4Qsda+OJK0ZUCUL7g8BamV8=;
        b=VhcXwoJW8OYty8zbqSOfS79+909z02v45wu4YE1YACmVkuWusNFXi4Dmg6iznJjT8g
         NEiQby6yWrfda1Q8VIYBdj2tl6q+9FRKDJkilgVi2GvB27cjgrJFG/oBDsfkYsNPp9e9
         DVHrGOgdvyRC6iShUGUp3JU5yNpTPyUxhCHwJnk0q9yMu1aQfcKQqlpjzZS8S3FMgdaf
         Ld1BQi8ZYdgqufkDbWUneRVQ9lh9DRXFDoNKW9I8O3s1GeWBoCxFcpY8aaQSWjfay4iu
         l+pCikTTxZL2a3QnKpzIVsr891twfBvGqsztmnExvVyZL0DEgU/Xjxcz2mBwozZuqJlY
         eFyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692030386; x=1692635186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JMyQfqzKq3arFCEbCB2w4Qsda+OJK0ZUCUL7g8BamV8=;
        b=OEGVgA7j2pT3dKYeAepibGRXP4AXln2gjevyFb+gKJqffC3wrQhsCAQPsALNa+1EL+
         GM/gqU3xgpl74C1uTGTgddjs7iFUJntO1uLAhqilKEcPUldzyrLyt2KD5P1zVIgV2hOm
         D7jCFIV0291qdnBaMPPY8TyVA4/ZDFSBbZWVflI4UwKH7M6lbBbooUBO9Cz1tREGhpPy
         FKlvVqBZ6qw8OiFCQ0FSSCrwzv2IjWRZX+HSae9yDiX3gKTVVbakWu1Mm73W5xH+lgXr
         SPJdUudFcJXUPDuY8xwTE39BXH0cItiX3fnm5Ue174yStUjVt773E2+R2/ZUSPtFJHT9
         h+ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxveUXmBSXfEhgi2G6BbP4DU4+k/zngRkzdnErTKB1NoeA1zWjy
	iMSqZv2i7hhWQe+P8ghx+R8=
X-Google-Smtp-Source: AGHT+IEyDXrjlUBrgqKr0+b51QtxtH266IKFowJeahNDrse7rWgMk2hE6ap5fanvDcNntwu4JWpBnw==
X-Received: by 2002:a05:600c:3ba2:b0:3f7:3e85:36a with SMTP id n34-20020a05600c3ba200b003f73e85036amr280261wms.7.1692030385486;
        Mon, 14 Aug 2023 09:26:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:52c8:0:b0:312:831e:d905 with SMTP id r8-20020a5d52c8000000b00312831ed905ls1344246wrv.2.-pod-prod-08-eu;
 Mon, 14 Aug 2023 09:26:24 -0700 (PDT)
X-Received: by 2002:adf:fcce:0:b0:316:fc63:dfed with SMTP id f14-20020adffcce000000b00316fc63dfedmr6724765wrs.39.1692030383870;
        Mon, 14 Aug 2023 09:26:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692030383; cv=none;
        d=google.com; s=arc-20160816;
        b=mm1UsR4IGPfCcsm4xIlsBFE8+eDCb4CniEqDrZPc4yiIpCroKbk5ByEpwAsOuRXVFL
         hK6LKLKOJ7JnMMJnbzS2e8MIoxq+cwUDdoJkZs+Mh5gli6V+nwVB3lfKPLJFcTgzZNtg
         gkmswj2SDWhDFSENfKeTOwHIC5Kc90af6uCF+dD0sbDzARnO+KfWVZ71mDxrezfLRWOF
         YcYLX946SpGb1qNYP+Hi7DCc9BQZl66T0r8Ypg7H3NbA91H3g8otyQdJzBtDgyzux2XR
         CFlFck4hTpSbn/BSuxlWshwzme7eAFqwWsd/x5RrZFiB4+j9zt+fwMJIv1NNJ9ThWyhT
         R41g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Hh6xyFX3lrWtHaAHe9l1sscLDUJokypxYBHgPvN98Gs=;
        fh=RoWWTRK1ZrXNP/VtEBcCDaK18unRqwp2i1mhxrenPO0=;
        b=EZvh4LpXauDdQUUpJVR1nFrI2gUnui2gIBmogDqI7fvQQiY6pweNiiu3msjgepUqY4
         pPWiSMSOIw93A18H8Jtlvwuh3agh7VJ221eLGBlv74ejhqhQLfApAofRASivciLarl53
         Vlq9CyJaC99KutKyD1FEtRzwIM9Hja/ky/1C14R2+1Uz9lvLNho2/xovJb9phEaaxQhv
         vBdSS/tt937vRtengGmqL2Rmc2FVY/z9x8sgCtiF7ArnT1ApH3Ng4udExgC52bsBxJSl
         LXP6aX4STBIzlsay7v/Dj72YzRvBX/cPUuDAxk6kyCAK2u0tzfn4ZCXpVL5dlJG5vepT
         LOOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZEAYzzlk;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id n7-20020a05600c3b8700b003fc3b03cceasi401487wms.1.2023.08.14.09.26.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Aug 2023 09:26:23 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="374852959"
X-IronPort-AV: E=Sophos;i="6.01,173,1684825200"; 
   d="scan'208";a="374852959"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Aug 2023 09:26:21 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10802"; a="762991299"
X-IronPort-AV: E=Sophos;i="6.01,173,1684825200"; 
   d="scan'208";a="762991299"
Received: from black.fi.intel.com ([10.237.72.28])
  by orsmga008.jf.intel.com with ESMTP; 14 Aug 2023 09:26:18 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id C15EB33B; Mon, 14 Aug 2023 19:33:47 +0300 (EEST)
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
Subject: [PATCH v3 0/2] lib/vsprintf: Rework header inclusions
Date: Mon, 14 Aug 2023 19:33:42 +0300
Message-Id: <20230814163344.17429-1-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ZEAYzzlk;       spf=none
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

Changelog v3:
- dropped sorting headers patch (Petr)
- added tag (Marco)

Changelog v2:
- covered test_printf.c in patches 1 & 2
- do not remove likely implict inclusions (Rasmus)
- declare no_hash_pointers in sprintf.h (Marco, Steven, Rasmus)

Andy Shevchenko (2):
  lib/vsprintf: Split out sprintf() and friends
  lib/vsprintf: Declare no_hash_pointers in sprintf.h

 include/linux/kernel.h  | 30 +-----------------------------
 include/linux/sprintf.h | 27 +++++++++++++++++++++++++++
 lib/test_printf.c       |  3 +--
 lib/vsprintf.c          |  1 +
 mm/kfence/report.c      |  3 +--
 5 files changed, 31 insertions(+), 33 deletions(-)
 create mode 100644 include/linux/sprintf.h

-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230814163344.17429-1-andriy.shevchenko%40linux.intel.com.
