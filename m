Return-Path: <kasan-dev+bncBCRKFI7J2AJRBBMYU6GQMGQE65SE7AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id AEA924672E9
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 08:49:26 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id u14-20020a05622a198e00b002b2f35a6dcfsf2581166qtc.21
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 23:49:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638517765; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vw/KxLedsNguke4+B1c5nwA1dHHKM6uvPQZMJ8cf0YBcL3KoKByYLs0AkJcqraIOUZ
         0YA/O2W9A3X+Fh7UqvUlUVDGYxLy4j5ezQ8ljl9BaU8iq9lOLQp6fX9BYUp3bG17apwZ
         El26PtGPQtaG6U/yxbLMOXO4sSMRVHePgJdpecYjr2VXb5Zd+1ZZNbWDiC85PLOpn7Sg
         36WGxSrEm5jKJAzI7AxnrFF54mpY8sr67UtAu9pkw5sJEW9P8o4xsvh3l2sP1Ko7f/Kk
         iFp6W2vnoXeNcliSdQo2kp9vcLywdshn3Op5LA1maFcLjW87o/esh6Cbw7zN1/Oxr3rP
         2zFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=nofEUbtVrsbL8OlgYLBla3L1dtSlU8BhPk3PgZp8IAE=;
        b=W5F/VBQP24GbI44E5gZG94bX2r9WXWBcWvt0CDeg2KDBf7V+wAom5joMMcZzKIQpLK
         4COigHyq18aPRvTC4aqkZXaRogBacU/nx49sUttRDp/L4+pEGiEJTCs2REtJqp+WR8ra
         xVPHoxMgwfeL7USvQtalqTC4BPf95WC3xjX73L+Vs8RLGIXVj2bh0G9rN8Mgm+j+RHQ6
         SrXCf9IYb00v5YnBvJFLgm+tImIurZge9P6Ch3g3MKT4c1MgKXdV4wI+LMDO6IJgDIwo
         8DZC3YS5kwo3F2d2nGkW5nHDJwOhjXk1CNYkA7yzuoBu39sGLegrkzBVaQZmiNVGmdnZ
         3PNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=nofEUbtVrsbL8OlgYLBla3L1dtSlU8BhPk3PgZp8IAE=;
        b=AiJlCRE2QOC++zPwaE+2brEOaZApHCb7EktMJRBnNHJfZaGybVT2VYdSqdbEHAr+8H
         jeqIR2E84kqrSgBaoFeJUf83+zhbhxHG//H1wNvLKlNI6hT2wHPwZVkhtBSlxvpoDZDI
         2zOrwDfHgH4z1snAIZr08KBi/QaMc6mPHwZyP/4j+IkkJBLGecUL1IFBlvgJOYRyvXk3
         qtRXE38ktelUP1v9k3PQXTCRkUdKlazFyRU4fYDjEzlgULwyWQXjr3ZC4n+wYaTXRPyL
         1+tMEhh1YwPS42NH4E0rF3NEWg4uUtLs8YrcCDNHcVAiU0sRQ5zQ0wsUzz8McFSo4ish
         73uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nofEUbtVrsbL8OlgYLBla3L1dtSlU8BhPk3PgZp8IAE=;
        b=4ny9RGPt04oJf813HFOXNmbVUm/l4R3liWYnDu5T7GKKEAAHrePvyVaFT9eIxqoAyz
         v5eRkClghoMPn3SvyiAJo8Qx8JTt1a3kCXy18ckImzBWyT4FUXw0rM2KOHz/LoJKgDRb
         JtP4uFXksd2UjTqE5p6omdQ56NczxT/5eT5b05i9wcFaIwMtXXWWb02W3YspgXXeLiJ5
         aJEIgniZ75mzrPCLdkJMCNOwBe3GDGrWCbYM8ZwVV26cCHA8R7qNcHw+5A1t/bzGj97r
         /Pwv1qcTwFCxWh/wZ172L6onHnnhZA5oFxIKlAfN87AKFMhrXdkY66NdT7HD+rwrjE+6
         5qYg==
X-Gm-Message-State: AOAM531Imy0mWOuZsInRjXiIiuAIfsmbvS9D0Hr7Mhl8cShXK4d/xnc7
	wxoOvjhSYpnun3vTYylFqXY=
X-Google-Smtp-Source: ABdhPJymQhy2hTSyz8dSvaZaxjhxM/5ywGCYq0TpkcBlV4QZkr/Ef4oSHBrjWjT3pTkkga6RkALg5Q==
X-Received: by 2002:ac8:1e9e:: with SMTP id c30mr19047732qtm.238.1638517765735;
        Thu, 02 Dec 2021 23:49:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f3cb:: with SMTP id f11ls4256369qvm.4.gmail; Thu, 02 Dec
 2021 23:49:25 -0800 (PST)
X-Received: by 2002:a05:6214:8f2:: with SMTP id dr18mr18397723qvb.56.1638517765273;
        Thu, 02 Dec 2021 23:49:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638517765; cv=none;
        d=google.com; s=arc-20160816;
        b=qdSZgcA5ohjEnFe5eIf0lea5+IBTsoEVyeXE3WE6tIA48MwVuo98iRJ21MH3Ok5d2v
         fAg14Wfa9JcIp6UlJ21ZzQYOgsk9Fof05nVCYSNOToYlLNt0grKmwNF0E59Klb+VYiCN
         lBBDr+lEzrQn8l9LcczSmhd4dSE7jqMxCSrU+hKTNz09eLPRcG4m505BIuuO8GY3ORRi
         j1OfGg+aoxgQd/4ydG7U5A1B0sX5y2Oq5FrSAHiKBVTCp+T3jBQ8XHUmkNwI0aN5SNt/
         NvJFEjz3vQp+wfeAinyWXCkCEaONmpvW6Gk51F7YOfa67XyCTIwhjqpOKbF6W8r51Ul7
         i60w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=3eZL2ZrDIM7+61p6S+BBmS9F5ThVoV2VO1DOko0KY1g=;
        b=LeAVuyEjVZUiuWmQHAUGk8EMnIEVxBf81onEg+NlWY2XhzxsZatDRf9v1RYzY3eZD1
         zoYhZMyePpBJgahKeDc+km3nEXA4RMT+IZEbGhrKQmT4NU03qCKhG9tIudtJGijYvQm8
         v3bYpz7YYPla2mE/ZHfiPW6sUNNS7qs10GFIutTJQxN+iiNqs9XD1OKhn6joT9aC9S7c
         bg4AklsZXlNjgUD6AbDNdwVcoX1pdKbJWqe3bpv1iHhm6Z6JLLCxuEKRWt9F7+P0EnvF
         lzRAfbNkVwYHZVDpdIWyEb33vXtGlNEvfwca6oxHrbHyaqlZEjw+2p0euJLDpdHZhAoq
         Mz1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id s4si446902qtc.4.2021.12.02.23.49.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Dec 2021 23:49:25 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500024.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4J54hC3qf6zbj8w;
	Fri,  3 Dec 2021 15:48:43 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500024.china.huawei.com (7.185.36.203) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Fri, 3 Dec 2021 15:48:52 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Fri, 3 Dec 2021 15:48:51 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
CC: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Waiman Long
	<longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>, Thomas Gleixner
	<tglx@linutronix.de>, Mark Rutland <mark.rutland@arm.com>, "Paul E. McKenney"
	<paulmck@kernel.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH v2 0/2] locking: Fix racy reads of owner->on_cpu
Date: Fri, 3 Dec 2021 15:59:33 +0800
Message-ID: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

v2:
- adding owner_on_cpu() refactor, shared by mutex/rtmutex/rwsem

v1: https://lore.kernel.org/all/20211202101238.33546-1-elver@google.com/

Kefeng Wang (1):
  locking: Make owner_on_cpu() into <linux/sched.h>

Marco Elver (1):
  locking: Mark racy reads of owner->on_cpu

 include/linux/sched.h    |  9 +++++++++
 kernel/locking/mutex.c   | 11 ++---------
 kernel/locking/rtmutex.c |  5 ++---
 kernel/locking/rwsem.c   |  9 ---------
 4 files changed, 13 insertions(+), 21 deletions(-)

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211203075935.136808-1-wangkefeng.wang%40huawei.com.
