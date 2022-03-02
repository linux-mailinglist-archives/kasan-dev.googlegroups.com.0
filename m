Return-Path: <kasan-dev+bncBAABBH5272IAMGQEB2VZR4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A42964CAA6B
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:36:48 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id bn10-20020a05651c178a00b00244baa268b6sf661124ljb.15
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:36:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239008; cv=pass;
        d=google.com; s=arc-20160816;
        b=XoajuEQHA4nqRLULbysSg+PejowNWhCLQwtYUcHYnN0z+yHa0/y84GO4B65TrXw536
         1Cyf7iAg8w1vwzwczu8UYFtfJ//Hv/Xkq2vud7n1R8GJJ5F69stB3muf5Cgko2X16eWz
         dlCYLzwRUPTBz5nhPzle4kEUu24CxS6CVj0tjy5XRUVVa1GLr6v2Hbt6432xfWluymxx
         8zRuQcPLXw6P1ZYcCuHTzRt/GnqiaWzk5mryO4YzYj+5OCPEhbOe+DD9RxaZmj+MhbFd
         2b0SDNurm5fBXVFFgydoSbn2pKD+V9KpBXOFmrL52Pe77Z7AQZviG/VKTgdDKHDK2T+S
         8igw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8nemTbn515qR6jLMrSwwLnzVICbfaGbeN7KzIxILQUU=;
        b=WwuVQZC7/HuKdwr5vynlYrQjCM+E1fa0w4Ng8VEt/nupuc7Jq1kkqkMAxEqnS1H9dG
         tgoM3mO8X3wLC0GFH+YvAheiydcgbI8tsC1J3tCvOuuzEk7mrwHQ3e4GvVP1i5wedksI
         CDb/DWWDOV993NKDaS1HQdS5ks8YFaxRYRUO5AvQxr9ibxD8t7nyK5XsIAHHg1WkMmQS
         ++wKb65qHWDb+P8eBBFJ8PlAsTS9eC4cBSW3GGukG2km5yzZkeaouWgXf18uv7DblN7r
         hLQhFKldjGejEvmohY2QGFmt2RgjYJpntcrxjSpmmlDJAjGdmshKeA2KQWdX7Ip5Bugn
         1SCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OCYrJ0Ds;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8nemTbn515qR6jLMrSwwLnzVICbfaGbeN7KzIxILQUU=;
        b=YnFiGLQBd5k5sM2C2Q0lQei5s9Dx9HxX4yr+0v3F2eWZjmBDEtVSj+Xl8o1G7TDHUG
         4hDsb0MOZYvPqFvX+c8MZBjcf+DEHHIXrUXf70/x+YttQt051tZA3A+nK9AIzlT3fTP0
         hbZceGXXB3m2fBay7huIvd1sbqVcVKW0hc4XrQ5iYZkX59AiVIFT81rsArTonNll+7EZ
         gSLDYQLRKaD1s9EIXQj3nm+Kft+g1cO/CDzif31macz2ochqifqrB8QpAd4zY1dn5L1j
         3+Hv25el15ecwKrkexjvCui8L1jzDbFMIw4fp4o/kYxJzRaTsBoVIccrtHqS3jJ/ig9r
         ZEJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8nemTbn515qR6jLMrSwwLnzVICbfaGbeN7KzIxILQUU=;
        b=VeQYrEgi9TA2xCwR9vcSJLx6gH406x9XzPttqciijQ8Z8bgathz69WI9uCdDEMeJTa
         qHEv8Ano/LQfXPLOCj5DP9sweQ/IITOlNsQmYdDe5Igu9O4dQGS0DEP3L2xQQjLFQmW8
         Eoc6znZvL2uD9ATqTR8RgOx9U8slcI4EJWLflOQm96RRUqQlC2NV1pu7nj+Hy8VQvTvM
         4X+ofCY0kFS+feDTIg+KbcC5OJKa32byOUyC64Ri2vBpoTVIa/DnZPW2EZbpMbSrAFxJ
         fzT/fbXe3FjpQhSp1o7T4pMklFRD59hU1/SFDDMB3GkTzsaSVLz2VpER2AOQPzDc3X9/
         ljKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531it23DRn0BYQOuSX+uidj2f8c8Ix7re5h6wqFwk8kBBGmg2x39
	WT0xqEDTa3mzB/XQiDCVZWQ=
X-Google-Smtp-Source: ABdhPJwcLg7EHUNkG01SgQYnhSfDl0PhENsvCClIBlkqZ32q4CdLY0VF3/qmPeoM526yTz6fq7EAMA==
X-Received: by 2002:a2e:b0c9:0:b0:246:3636:86a0 with SMTP id g9-20020a2eb0c9000000b00246363686a0mr21415607ljl.129.1646239008022;
        Wed, 02 Mar 2022 08:36:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2153:b0:443:9651:a9f4 with SMTP id
 s19-20020a056512215300b004439651a9f4ls484496lfr.3.gmail; Wed, 02 Mar 2022
 08:36:47 -0800 (PST)
X-Received: by 2002:a05:6512:2306:b0:43a:11eb:1c95 with SMTP id o6-20020a056512230600b0043a11eb1c95mr19275034lfu.63.1646239007169;
        Wed, 02 Mar 2022 08:36:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239007; cv=none;
        d=google.com; s=arc-20160816;
        b=ZRFtEXbiYHXF7jFbBhp1aFOTA4bAFj8dIbHzUnAVxk1YIEFCqdgfFIzOrEtrufBXWO
         3yAUx8blCDKsIxhq3vF1zm1nRcru/7vR3ry3dolFLUzagm0w17gKhojB5ee3EOsXeOt6
         z7iViAuaXpmnoASVpDSR4o/jPP/aDziZ8T4AWzJexFW7BMYifpp/SonjefFPiCVdpz8y
         yJbH6u7fXnZ62w37SeeGh+1ebvCGmHW5lTkoYgnqGMYiPpN/C8OX55ZBUzUgALDUwqrJ
         rK48E3vbenbZUZsdTD3FvzX9UgGy9nF/4iDRAPjdI2WLg3mp0RCDSWcOFMqeFatKFj6A
         o+Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=u21KV9s2q5sfOslEpw/sDzZbvsgVEVjrwLfohbEqpJg=;
        b=Vshuhxu9lvdQvGGfXQ29N9llG/41DuEVHCzVp8dXv+P6UpAFl5/Qy7jIMzsBrNrWjq
         nX0jxgFsgI5xjLqPRbOGGxqGrBWQBMq274K5/rtxdAK0iFpP3EUYN6tqkR/3qgBZsNll
         lZ8z9u+5ATj+fuyzME/x7OwPsQ3dQOnVkqw64ZJYqONEJNN9r6jHPZeuv+ir0xtNUIXt
         iFd8xgHrtk5co6JY6FCrz2tY6/fhSiyPq8Mbt0EhOxxRPNJaEc8HMvmzCTpk2sgsgc5a
         tvAZMIGe6dMoyp/R58L0iTCSOAks4d9wAK41708TgEa9w6UnPe0qQgKyh6I3cT/QAfBt
         Q6wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OCYrJ0Ds;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id s22-20020a056512315600b004433c2a6e0fsi709588lfi.10.2022.03.02.08.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:36:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 00/22] kasan: report clean-ups and improvements
Date: Wed,  2 Mar 2022 17:36:20 +0100
Message-Id: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=OCYrJ0Ds;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

A number of clean-up patches for KASAN reporting code.

Most are non-functional and only improve readability.

The patches go on top of mm.

Andrey Konovalov (22):
  kasan: drop addr check from describe_object_addr
  kasan: more line breaks in reports
  kasan: rearrange stack frame info in reports
  kasan: improve stack frame info in reports
  kasan: print basic stack frame info for SW_TAGS
  kasan: simplify async check in end_report
  kasan: simplify kasan_update_kunit_status and call sites
  kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT
  kasan: move update_kunit_status to start_report
  kasan: move disable_trace_on_warning to start_report
  kasan: split out print_report from __kasan_report
  kasan: simplify kasan_find_first_bad_addr call sites
  kasan: restructure kasan_report
  kasan: merge __kasan_report into kasan_report
  kasan: call print_report from kasan_report_invalid_free
  kasan: move and simplify kasan_report_async
  kasan: rename kasan_access_info to kasan_report_info
  kasan: add comment about UACCESS regions to kasan_report
  kasan: respect KASAN_BIT_REPORTED in all reporting routines
  kasan: reorder reporting functions
  kasan: move and hide kasan_save_enable/restore_multi_shot
  kasan: disable LOCKDEP when printing reports

 include/linux/kasan.h     |   4 -
 mm/kasan/kasan.h          |  44 ++++--
 mm/kasan/report.c         | 312 ++++++++++++++++++++++----------------
 mm/kasan/report_generic.c |  34 ++---
 mm/kasan/report_hw_tags.c |   1 +
 mm/kasan/report_sw_tags.c |  15 ++
 mm/kasan/report_tags.c    |   2 +-
 7 files changed, 241 insertions(+), 171 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1646237226.git.andreyknvl%40google.com.
