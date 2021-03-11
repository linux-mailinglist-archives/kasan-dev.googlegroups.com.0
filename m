Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIU3VKBAMGQENB5PTWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D487337FB4
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:39 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id g6sf7129050lfu.13
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498658; cv=pass;
        d=google.com; s=arc-20160816;
        b=BXTCG640TAs0XohWBS/MXevlTOqW94FPYMxEhwkWuiFZG/Gb/KC1E98Izlz5AcsFZ4
         cahXzRBcsPuhhhyuvrUlPPv3qvPcRA8HlaHhxImjq9ZnUma++TtAfnAL9almYj8af50v
         1guMj0yjvCkIChy0W9r1dSgnOjJMnlhOVHOCWa9lUZoCNY/ys20tHm49qO24weKvTh4J
         1EcmtFZrkj3YKKd8cMevJfzr0nc/AUdAR/C5Iw6uCSZ16LvTzGYFoC6mDsaSJXwiJ3wI
         DWt0jUTXyBrITA12Oj0x8ajIYlR+NmQ8oMmzQDJflb8QUDAo1oC57rLh9jGbPtkQhE54
         wl/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=65FQZ5+NuCvMOTNKaru4DYWFqmTw4AkXSejjEkXsXno=;
        b=pcJsbzeucMx4XqnFtS2Q27lFaev8rAy4hshwZxRCe1nYEca8TZiXi7nxV5Wr0ULeQV
         umkmKOviEnH10O8hDkwlEIKf03GElwH2WdwpKsnHO/ABGvXW9c3VzTGVBOwcCrp7hcNy
         pEPvP9Q3Pf823waLibfgBb6v4MowXM/RUkrQffxBjgmCknuzojT0CYrCFeYaOJKZ1tAp
         uKhqelfb8+wOIdn2bbibJZ3OqOcmnpznF4+HvgI/QO9HKyVwupBw4c3VlBrxBNtZJpko
         tPhOgrTkhNxxOVeA8DkMw8qBf2+6wIqPgtWm1xVS+WObcy6LAn+ZrbYTCTprYs2zPjhZ
         1H8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ACyAQPWm;
       spf=pass (google.com: domain of 3oy1kyaokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3oY1KYAoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=65FQZ5+NuCvMOTNKaru4DYWFqmTw4AkXSejjEkXsXno=;
        b=Tej1rgn46KLIx5PCRTvrFbbfQ5/ehDR64dMo28W9QNdwTGwziHtkpxZe1DUcMKqrEM
         Cb3sd+cP2SoRbgNc42hth/7W0BOi0lmUACQMsbD9yzh09ug67Oabb1VilyToqlznaXyh
         3Xs7999Pg3ITQm3RifgGtlzLnROJmrKoMggWLniq2TZko05woX7N2kinVSHORJaqeXzy
         Bl1PZQ2Moy65/9NBWoCP/fihvQT2pMK3rGIBqz9/CEgZgy7NCti9Xyb22uiCKFt8rD5z
         7aK/rlDzN+tcLZTxZg1gNNjZ0+rVMw0W3SmIsdflDndytllbSX/1gur7rqpTffXGNnc3
         S/1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=65FQZ5+NuCvMOTNKaru4DYWFqmTw4AkXSejjEkXsXno=;
        b=qvF+mVR1o0aVDtZJiMTxXJlHWbo6IiKc6xlOZ59OrjuqFyigOF+CBhUdq18PXCzEx+
         DrRPHKfW2/2LVoxKy9xNr1CczU/PYsxJF1L+Pg1AGHaG+tPYlW6prVO4ADnE1dhO23U+
         OCAH6mnclqZFG98Uod7x1kRRxWTmhGZKB0EGlKErghShumU7S5nL6v1r2lPj/CKuB4pl
         IG18/EqeC+C+NttdXN0hoozseDJl1FTsMP5WvQqi5OykEBaaifRK+CGEUTaUm/WUZnJ6
         2kn3D5n8d9eS5zsbNjA0K172Z3012Igm5/4k5ab2xGkPmC6Yb+9nnkttPeJd1byx8KZM
         02Tw==
X-Gm-Message-State: AOAM532BcDWOwgifoqGhDj54oI3p41DF1RItNtQDLE1M216Vlt4Qw5Ep
	HGpszdtQn9IRhTXLLVf7PSg=
X-Google-Smtp-Source: ABdhPJw+uwyA+gsE3fMhlRh3Dz5U8Ocg6AwnM/h477lgUlL1IYLRjG8D4HtRweLOZSHIBQwEIOnBnA==
X-Received: by 2002:a2e:b011:: with SMTP id y17mr521775ljk.390.1615498658772;
        Thu, 11 Mar 2021 13:37:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:391a:: with SMTP id g26ls1535599lja.4.gmail; Thu, 11 Mar
 2021 13:37:37 -0800 (PST)
X-Received: by 2002:a2e:91c2:: with SMTP id u2mr507115ljg.301.1615498657678;
        Thu, 11 Mar 2021 13:37:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498657; cv=none;
        d=google.com; s=arc-20160816;
        b=akFMC8fvctp4aDAGmiQ7E+bwufPaFvGxghS1uvKmGU5UjmpPevIWw04E9e2Z51as53
         G82a6mzTXSXKmKQgXo5FQJxXWh3c2iEqi63W71Cyfl/OYO7WOoKimsCytqm0DI5hjj3Q
         QnIx37XtdEp0cl0sbFh03SpyCYdzM7lKYgv0e2ho9Se1Op/DbyoeA8KF59KDWt2Y1y2P
         JoHEEbMYEa3mDhpPkz5S0P8T7XH1+eh8v9Q1BBZ2C+nxquqQznTpt+XPkbxcmJVBOZnV
         YXHk+/E6DgAk0m+cfMoJ6GOnHZdHAdGUUu3HG6zf1hpWFPJJDtK0wY48hVR7TCexRYwY
         Vfsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=5DZPocqARvJ2VhBFUP59zWFPA2pzWUkM0o/y8pYmFsA=;
        b=Y+f8UaN/eZzlg1gn2USAnf+ZWiLlJZ9pZkBQEnXi1niuTiCFuet4pQ9qmj5DKooOrQ
         EcEeBM9U+KzQAX5Cq3jm/6pewI+j2+eNBB7MOr/ccG7VS5cPJCNvzGzWvmoh/9/4W4H0
         TvT5kROrruFaktBeMhboiCuOFwflFGjG+yVw9oVtb1+ZNP5uq+BJ+/O0DLwylJxC09Lq
         cdQuVbVCoCsZChp4YmS5D9X5Uej83ZT7s8hCoSM5ZU5F0SG6xtInXyrQwFzNMRv6+6GP
         zXER/CO/vpVVlCPucy1O+yft9kzVb0vTXmLAb0/ykXh2UCtYndA/kdXYxiHCHGf/hggQ
         TdsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ACyAQPWm;
       spf=pass (google.com: domain of 3oy1kyaokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3oY1KYAoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id o10si179479lfg.12.2021.03.11.13.37.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oy1kyaokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id m9so10146041wrx.6
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:37 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a5d:58ce:: with SMTP id
 o14mr5622327wrf.4.1615498657160; Thu, 11 Mar 2021 13:37:37 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:17 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <afdec1e3271c9560bb0eb56bf36d6e3613830562.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 05/11] kasan: docs: update boot parameters section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ACyAQPWm;       spf=pass
 (google.com: domain of 3oy1kyaokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3oY1KYAoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Update the "Boot parameters" section in KASAN documentation:

- Mention panic_on_warn.
- Mention kasan_multi_shot and its interaction with panic_on_warn.
- Clarify kasan.fault=panic interaction with panic_on_warn.
- A readability clean-up.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 14 ++++++++++----
 1 file changed, 10 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 5fe43489e94e..2f939241349d 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -174,10 +174,16 @@ call_rcu() and workqueue queuing.
 Boot parameters
 ~~~~~~~~~~~~~~~
 
+KASAN is affected by the generic ``panic_on_warn`` command line parameter.
+When it is enabled, KASAN panics the kernel after printing a bug report.
+
+By default, KASAN prints a bug report only for the first invalid memory access.
+With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
+effectively disables ``panic_on_warn`` for KASAN reports.
+
 Hardware tag-based KASAN mode (see the section about various modes below) is
 intended for use in production as a security mitigation. Therefore, it supports
-boot parameters that allow to disable KASAN competely or otherwise control
-particular KASAN features.
+boot parameters that allow disabling KASAN or controlling its features.
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
@@ -185,8 +191,8 @@ particular KASAN features.
   traces collection (default: ``on``).
 
 - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
-  report or also panic the kernel (default: ``report``). Note, that tag
-  checking gets disabled after the first reported bug.
+  report or also panic the kernel (default: ``report``). The panic happens even
+  if ``kasan_multi_shot`` is enabled.
 
 Implementation details
 ----------------------
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/afdec1e3271c9560bb0eb56bf36d6e3613830562.1615498565.git.andreyknvl%40google.com.
