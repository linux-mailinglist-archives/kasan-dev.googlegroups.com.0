Return-Path: <kasan-dev+bncBD52JJ7JXILRBEWA62PQMGQETTYSD5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1453E6A5309
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 07:32:52 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id gf1-20020a17090ac7c100b002369bf87b7asf2557534pjb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 22:32:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677565970; cv=pass;
        d=google.com; s=arc-20160816;
        b=BFQMt7EIaU0v/gucZdAX99RkFbbC/0EmdE1BlolOYJLSgGFC/ZkAOl2Lpw7JgIsgeO
         70wtyIQ7pYKlAG/QSoZhtwvZyq1ADV2LMAJWEzMwNfK+nrFxAXYpPTJgR5yeLZy573Tb
         I7AcAjx2OgytrEsNhymixlfLa03xOWzESB5/EChuxb74tZqVt+V0PXY9MYR0WePzdLwH
         kAZJi4kpAT1HxVQcfWjDH66NyRkbpSgeRPGLBDLlLnB15a1NGHCaOsWT2LW+8FHEMgxk
         qTj4Lci31/wOnalAM6IwMn3jeOUgtAkIyJmeruIJ/N28WChiXYIvl8DDHJnsipEw3EMY
         1sDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=QSILx5MeeGbq32CtDsTmAfYtiPCTMvc0pJUDCK0GzJg=;
        b=vMD3W3X0Gnwd/DUHg8braUrocD9mzgNseITZZBycBBTQ/jiG/MMf23QPNzMsU3mW1W
         9FGFZmxctJWCXo4YHsTGyoPp1PwPv/RQq7/wU5GaE7aRTRuSvxm3x280p6bhJHV0XF8a
         U+aW/rNHcgQFv1/eVh5u22/LOa5T1E4jeHRBD5EtmuYWVNGKvxxeiB07qDs5dkvLfbnG
         i7alnQJ7Oe36Xe7fTDU72NZrYY2tXq9wZg3mYGgo9AqUETU1gkLTz3tVpolcU9xXK6E5
         uTHLA6aHm6pLQlYIvv/N/J2jJVL/rGMXHU3uU+CLC04mNOa9s1N16En1uAIvEi/sv1ow
         x5SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="DZWc15U/";
       spf=pass (google.com: domain of 3ekd9ywmkcw0annrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EKD9YwMKCW0aNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QSILx5MeeGbq32CtDsTmAfYtiPCTMvc0pJUDCK0GzJg=;
        b=d5ECP+ge15nAl//cZID0+BNifoFnEEYqD5aHoHSZ0rlfbgCw1lMpzPsIaQlbs56KCF
         b3lzS1bEA86fbuvQjKZFFaH36k68wPD0IVd0LjonpSLe5kasvWDDA21X4msiQhVLItc6
         VO82/IBVkUbBn1jYwaWgEA5z+FCmTl0nYUidOEchzMtLT0zNmpmfXDdKO7WP9C0jpjBq
         YOrSwdqJ+PjUeun2zkP63+NI/04vCO73Lp7lgc1yt+Nax7vuXfT8nwaSiULQKq23A99U
         5EYpuEzQotBMrXlUsM+BX0QvpzYtuzA7050FTvR5ui3JnjSVx4sOW84OMmRMSzxamg9T
         dFqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QSILx5MeeGbq32CtDsTmAfYtiPCTMvc0pJUDCK0GzJg=;
        b=yMVXMNCfcLVPgkEnPjFIMP6w1bd3rY+XE/hC5gXaOxqj/ZFI0RCjxghGMRZDpBywFX
         uiNDqPOogy5vxy/Vy0oPYdhXm1hjuk2+JRczTHIJLntpkda2iiKwoni+HiiAjnMd5Iy5
         Z3rEjbOoYHiegcZXrmAM58virS+FXknBO91kRDTDjd2/odyGCnljoY09D9enn9mTt/Z8
         +2ClZMZaJSe0eueC7rIjfl2fCdYS2oNsgY8fxUrC2n9aR4OMAcLIrkursv/wYrAip3ew
         t9BC2zhssUo9+fLwSBfNlfiMP/1P3dz69gGyyKh7bVh5EKXVMfoYjm8ETiw7TpqCO6ka
         tlUg==
X-Gm-Message-State: AO0yUKVi+4mMqlEKkes2NiMJBPBYY107OmBxw72zABQwICMjhtf5E1yQ
	d3rSA5og723lGHcmGJA78cI=
X-Google-Smtp-Source: AK7set/anTzmRa2T5iX6HYLN22SHMxmbcNnOt8t1Vvxz+nsVVS6uoX4dUf00wYHKXJgua5GgMpjAUQ==
X-Received: by 2002:a17:903:485:b0:19a:f22b:31d4 with SMTP id jj5-20020a170903048500b0019af22b31d4mr557029plb.7.1677565970195;
        Mon, 27 Feb 2023 22:32:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:dec4:0:b0:5e0:316a:2ce7 with SMTP id h187-20020a62dec4000000b005e0316a2ce7ls3828839pfg.6.-pod-prod-gmail;
 Mon, 27 Feb 2023 22:32:49 -0800 (PST)
X-Received: by 2002:aa7:8ec8:0:b0:5a9:d247:bc76 with SMTP id b8-20020aa78ec8000000b005a9d247bc76mr1467780pfr.20.1677565969482;
        Mon, 27 Feb 2023 22:32:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677565969; cv=none;
        d=google.com; s=arc-20160816;
        b=WZrS3CRQkrSoQytbQmKxsYc/fdeBy5AETaK9yCxsZvMCqSWwd6gS/VufQbWkrU9Rqg
         JExvg4B6xor44mMGok+ryyR2vQu0gwCEvJm5SJ3TtaaUrtQ++hBZ2FclPGbzuWTh6OPz
         kYadg456X6OenyEfcGeo6KAjMIb19kzPK6GRjB6edvq6gEjuTdSSKxU77KtvV0N4+k+m
         FHXQ7GZ0DrK4euN8G3a808aqOiGqioaF5h3NGeIsnfuM6mSgIUwwTMZomMqqAv9RYFfr
         BKu1FjYf9MwyWP/wKuDKOvVLDlBNqhMGy4U7F0DW4Ku50I5aeZSCJ40JjGAqda+OoXaC
         /+FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Gfch4ggdlRbaS+LPf7sPXWuMxYrtd7MRHAdgdZrCUsw=;
        b=S6wTcla7n+AmfFk8FDuIpnh8N4yQ+I/jSpaQcvimv6IoP7BRt5dH1SA5mLoTVMbGDP
         K066c68ZHnK6Uz+xo1P82qhHjbL5Pf4UEDNyuhsbLeEfKjBYlGI8BherHKiMNnks9VEq
         /lVb+DYRH8VLGmItQsCqBcrLa9VAKmVO1JJpnyZQe+WBoZk+mAZkSNYNW+7fcl9lpC8j
         1ewFh6j5RAtprn8aBcofQAzRFeTfZP8vftu3NNFos3XvHP0OwBSyo9OXvGmfmTSAOtAr
         SivYb6dmhntIoBI2jNFk+YuF/CwE4LQdEp2pPMDjklXu8F6/KEevoj/A/zfkI1giwPv6
         WwTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="DZWc15U/";
       spf=pass (google.com: domain of 3ekd9ywmkcw0annrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EKD9YwMKCW0aNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id p18-20020a62ab12000000b00593910fa1d3si472783pff.6.2023.02.27.22.32.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Feb 2023 22:32:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ekd9ywmkcw0annrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-536af109f9aso191965847b3.13
        for <kasan-dev@googlegroups.com>; Mon, 27 Feb 2023 22:32:49 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:cb8e:e6d0:b612:8d4c])
 (user=pcc job=sendgmr) by 2002:a05:6902:ca:b0:a3b:7dbc:a9f6 with SMTP id
 i10-20020a05690200ca00b00a3b7dbca9f6mr643522ybs.5.1677565968739; Mon, 27 Feb
 2023 22:32:48 -0800 (PST)
Date: Mon, 27 Feb 2023 22:32:38 -0800
Message-Id: <20230228063240.3613139-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Subject: [PATCH v2 0/2] kasan: bugfix and cleanup
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="DZWc15U/";       spf=pass
 (google.com: domain of 3ekd9ywmkcw0annrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EKD9YwMKCW0aNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
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

 include/linux/gfp_types.h      | 28 +++++-------
 include/linux/page-flags.h     |  9 ----
 include/trace/events/mmflags.h | 12 +----
 mm/kasan/hw_tags.c             |  2 +-
 mm/page_alloc.c                | 82 +++++++++++++---------------------
 mm/vmalloc.c                   |  2 +-
 6 files changed, 46 insertions(+), 89 deletions(-)

-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230228063240.3613139-1-pcc%40google.com.
