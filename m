Return-Path: <kasan-dev+bncBAABBL4BRKAAMGQERKARDQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 90B772F8BC2
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 06:59:13 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id o23sf7580999pji.9
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 21:59:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610776752; cv=pass;
        d=google.com; s=arc-20160816;
        b=BmbwMS4kYvOLuuZ/TWn6yW/Vw4SPHNJhBQPfVqPOJ+804at6SEgGlijTk0MGaajUyP
         jO6Ns0XRpYOdkxnoVUczFOWTwSYyquY4xtlipMo9O+tst4rH/a7tjRuu4gUMBVDqnO2b
         cNu0a9DKznji85hX9E2I0lblZgLNxod5+C6aROebBV6TKYRGUBy2m/tMLYzFnpcwCNTg
         5gFeWqdwZKgnurV3fIT11AjNp7XVTCsCBRF0V9wiekBMO4RYOvUsVIg7cTpr8jk0b8/E
         3WrV93hh7mTLEOL1qbRsrT5fXwwAbz3Z19m1qezdoO9gqgWk1vTcJ9FGGt19W9jbJrpF
         /CMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2fhMU645/xytkOClog6BdXVQp2A+5Ok1naDh3qxZRcE=;
        b=pMCRZT6esMnU/FjJZ7laOWNHEiyEWbF0V/2lBkTS9YCvVa66vgw8mesgYWIP1MV05Q
         YantjyMaF2YCCIFCTr/igIdoWg74ubOAf164Ei9sM+lfEqjBnGwbcZX4XrIuqKOp3KnI
         dJ+/kCeK4OBc0t8T+18uOe0e0sjmjFLThCw0hDN1PSYH9hMd9vJ/+ve76KntxiVx/K95
         QHIP0skIpFKSduKoAlr07M7oRMb8nZlp4zfzFlvatEXFMZFeFAAjZAz0n+1JqNBCqGFc
         DQ+MrRP1RLDk0kWsBsE2utswrXt6bVBVGCmIRNMMZz1nKAA02SwwK6mnLoI2SfeitEbw
         EKwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2fhMU645/xytkOClog6BdXVQp2A+5Ok1naDh3qxZRcE=;
        b=PkmMWg5+auakOboMBCTyr42hnZhJwp8yyB231MXiysvYIjd5bWowWVA4KhE1MWHWjw
         ifXHww3AeUE6azyVrW4XMVCWFY3nCb8FEQJdEkSQDzlWkjnizsLwYnt1U32+YEWpkyWj
         S0jqaqUggh25nwMa/UVucKj65BHQyFj0w79wMIanpgk2pAnrX1FS63NXZKKQlo2LIT/P
         tO5zVw8Rs8RMOd3VH7mC6Pm38ocRk7qbvh9jY6umtM8SBdzBR5ZO4iH+av/Rk3zKRNVB
         /AsSyhGQXfmfzHHizycNC/JMVpwUxN35cOPyxEEiOQHUOjnmYvxEs0qrI0yn0GbwS4OD
         LORw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2fhMU645/xytkOClog6BdXVQp2A+5Ok1naDh3qxZRcE=;
        b=gfKl4tnuiD+10c5IPh8sgO1OvOcpEhij1bmy9ekZ7kgwd4QXjl5fZAGstdTbY/nUC2
         gpXDC0Usbsr/SRTJOZxG9mGxbrLBWFS2HyFbx6df8bJIkiK9GRWLxcjw3lVIpxF7j1jR
         xYLDNTvzN5fEPpUbSLdiYDU4lghFvWX2s3qnMliyqZcgx497Vab/tJNOM4gK3k8QQgG7
         rfbWjPVduGohxXplPAJIbZMwdTQ5WjRXBngyLybdHG/Q+Clrkfoylg/K4MbH7pot7TRr
         mLwwjgbVJekaawR4E117LDNv/D8Y70rqYsWF3K/axc5vUVeXlV1jbqLAfkAAjLcTYp5P
         J2Yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533BjgRH21Vkrq38++5+HCXLm5sI52i4SzdzojSG2icCpTx6WrYd
	uFloGgNyf7KpCy/6ilGwV58=
X-Google-Smtp-Source: ABdhPJyDk8oR4uDka7bhTY8Lk5+1jEuT5gxYO5rJUq8ChVKi80KuVu4rDhpZi5DrrOOXdZpA+8IFuw==
X-Received: by 2002:a63:3ec9:: with SMTP id l192mr16268943pga.104.1610776752009;
        Fri, 15 Jan 2021 21:59:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d149:: with SMTP id c9ls4282069pgj.1.gmail; Fri, 15 Jan
 2021 21:59:11 -0800 (PST)
X-Received: by 2002:a63:d041:: with SMTP id s1mr16088970pgi.249.1610776751366;
        Fri, 15 Jan 2021 21:59:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610776751; cv=none;
        d=google.com; s=arc-20160816;
        b=OsIU5ajsYS7NYKVRyZKw9UL9O+42r+HOPwAgmkqS8IdSFb9jMzCO192Oj1NZ8WtsxI
         7HrLeSgVpxIMH1D7sI1guKt0FKygDr6/V7s4s30WuvFGm3jPxUacRTfEtEXPomQCYjHF
         RJhkN0KuDeERTVixlMIFySA1TdCJJzBerm5SYfw8zy5pMFMemmDHxYkd0bKla7ocMnql
         /nmyvJVV0Ln4uYYlPBFLJwhRpnw09mZFyXxDzFthqQ3aQ5TEZ39Ae2nUIE3hFyq1421b
         GZYeDZRc2NC3u/wME9lFi1G68uGYsZvntb9PaTWnB+oyg5fiXf4XTWpsP9bwBk6pW1ze
         vEqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=+f+zV0JBQGfzVRFskICfN08i8Otd577hmN8Hyp7sW8A=;
        b=q+I/PEcfwE1sYjRQGkSdTItjB5ggR+Nd8gyYORqEUqj5cFEwNIfOduFBkMCon4o0E8
         d+RR7YxyV4s8maZBOXhJML4m5r/bILRIglaD9QLCqPNRvckQ+bIgDpfveIILGI7i5Gd2
         2q7VQ1KIpXurqnFPtnOZ1H8QU8eWlNWXbF7/PUYvAu5OR9K6Gtepf9SUAEfsQHTtN1Vq
         xziD4w26S4V8LXGWF+eRN5ZF3H+h60NygXOyTl8tm3GrWs25E2MR5O5U+5zNksVEe2Lz
         VUZ8mI0gNqxDNWuo3KVsX7CJ6bRX0AJlFa76pCKtYOks3AZ2LV6QNm3kC6ss4h13b0f1
         fckA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (exmail.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id t9si416361pjv.2.2021.01.15.21.59.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 21:59:11 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 10G5thf2057676;
	Sat, 16 Jan 2021 13:55:43 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from atcfdc88.andestech.com (10.0.15.120) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.487.0; Sat, 16 Jan 2021
 13:58:37 +0800
From: Nylon Chen <nylon7@andestech.com>
To: <linux-kernel@vger.kernel.org>, <linux-riscv@lists.infradead.org>,
        <kasan-dev@googlegroups.com>
CC: <paul.walmsley@sifive.com>, <palmer@dabbelt.com>, <aou@eecs.berkeley.edu>,
        <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
        <nylon7717@gmail.com>, <alankao@andestech.com>, <nickhu@andestech.com>,
        "Nylon Chen" <nylon7@andestech.com>
Subject: [PATCH v2 0/1] kasan: support backing vmalloc space for riscv
Date: Sat, 16 Jan 2021 13:58:34 +0800
Message-ID: <20210116055836.22366-1-nylon7@andestech.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.120]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 10G5thf2057676
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

v1: https://lore.kernel.org/patchwork/cover/1364392/
v2:
    1) Fix checkpatch issues.
    2) Remove set_pmd and pmd_populate because it's not necessary.

Nylon Chen (1):
  riscv/kasan: add KASAN_VMALLOC support

 arch/riscv/Kconfig         |  1 +
 arch/riscv/mm/kasan_init.c | 57 +++++++++++++++++++++++++++++++++++++-
 2 files changed, 57 insertions(+), 1 deletion(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210116055836.22366-1-nylon7%40andestech.com.
