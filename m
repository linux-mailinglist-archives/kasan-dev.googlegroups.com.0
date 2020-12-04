Return-Path: <kasan-dev+bncBCT6537ZTEKRBMMKVL7AKGQELC2MASY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B9A892CF448
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 19:51:29 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 190sf1431427lff.4
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 10:51:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607107889; cv=pass;
        d=google.com; s=arc-20160816;
        b=IsXLDuhhjHicy9hV+Euf2p+5VJ0603ATeJcfRaBzH78GrLpPTDhKaRRi5psHwQGKxe
         w5ycHH4fSgXZ8/uVNo0F3sxaYBvfoRJJZx4VK17Z1IjAacXUidqPhqPe67NkH3CrFcsC
         f3HElAF2qehbCREekLo0Qqe76C2YnKFvEUwPZXIxG4LiCWGzWBWF87+noFIaidEzjj9z
         BrJLdUO+Vx2rURroHenmRLrzjRFeJwTLq4sqTfOe/fcy9SfEs05EnpRsFDfMOrdmqGBj
         Df0VeJvlw7J2ldVqSHaCWAEsNWwRH6eQ3zeCAbUaeLrEz/CDFZ0iAx1sHkiOP50JNCuZ
         +MXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=TfZUrGSq8qhzbXBEXx8vtYsDpW9eYqOZmXQ7kHiVJiI=;
        b=X84nLeWY7Bp5HrCBRNAi99GOZEpVt5O3cj352mYXe4wZ9rOcLXge5pZNj1L9mTZWXP
         530oGJTF0iO907BpTcn0bJOiVsxlfkoc0vE8eAZQmwKvcesxh4PNhhA0B16buVy68+/Y
         UNlvdogos1MyDKSwSLtjB2WcRAQ264aNVk8VYJyPwqqHnyHcF9Yo0g1RIs4+tzfBHz+x
         g3kYbnRbpUI5vxxW4yIz5IyypTByy1uwbav4+wYRwgRHkSdEjTEMtyAbBcufrpL8oR6o
         FHNFBbrfQgV/cNGeDDffk4QdqNgIFzVLxBVLIbdJ+s8JqBpUBtXtFfYdmD4Jv2sDn2M6
         sK0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ci93SS+C;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TfZUrGSq8qhzbXBEXx8vtYsDpW9eYqOZmXQ7kHiVJiI=;
        b=Z+KBrjsM3CXNmuhGzug4fZZB7o/MC4iF1CEkNynv/xMYGYsoLiIJa6rqq+PYcZ3B9e
         75m44NbWChp4wr+NxW/aJ5jNEPwqcHq2zlyvVHPiEXEY7UwSHDxFqcJagSFmo53ApFKE
         P+HunSHMWMNOFD/u9Ra6EeHqbU/seYQZADGjLbeKGyEEg22PKptbVZnvxQ/KDSbfme6j
         3o0q0bhK72FA0MUGv30E8iDM/q5iMFuHpyq1I59ovIl9m8uz89B11zRWJUwOI/yciJuT
         Nc0gaXsmtLH0BaFmL0P1719IKJdyraTRZM57of+tg7OZErRE2GMd8kQt9BZgDKcD7SVz
         pj/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TfZUrGSq8qhzbXBEXx8vtYsDpW9eYqOZmXQ7kHiVJiI=;
        b=Y+UTwv2lQjaTNcl8YA1sB9rnOJFo4Wc/76RTGBH14Wl4h/3K16KOVSOAQ4gT8Xl9/s
         PF7qJ8ygUvkv3VD9FYn/JJvAVU3l8MFr5dcdi9H2C1eyZP/7kNh5j1zoOwJBOVInP6tY
         m61Wa8uJiHdv9kwAQqfASF5APIstfJGaU2icgwL1WSfl9BBhkpURsnlRnsU7QYriJNZL
         fFIFF97OKnQvpbI2wrZcQbrQv2RxMrOg1hOKrMuFDk0BAoeSHubxg1kI3vlvOpVOyZR6
         33yY4Se2oeP4JUipgtU5ALiQt4IJ2HCQTOjY3eQWVAsPdtpTY0gUd3bdqgUAG1ZU86ic
         uyRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310uxjC1anmJmnjxUODqd8soNiIpLA5uwvoZx2sjIKM8XtbRZ6o
	Ldri4IuYZ7AM8LU+3AP5pY8=
X-Google-Smtp-Source: ABdhPJwKHbYWSadk5xmG8h+1HV8p3PlJt5ddwGL40tjEjs7O/sFGIJLRshKccwaLuWxJli/F9Q5dkg==
X-Received: by 2002:a05:6512:2039:: with SMTP id s25mr3972213lfs.558.1607107889325;
        Fri, 04 Dec 2020 10:51:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls3446326lfn.0.gmail; Fri, 04 Dec
 2020 10:51:28 -0800 (PST)
X-Received: by 2002:ac2:5c5d:: with SMTP id s29mr713631lfp.88.1607107888281;
        Fri, 04 Dec 2020 10:51:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607107888; cv=none;
        d=google.com; s=arc-20160816;
        b=p1PL5PNfrI1YrCdH9n3fQMGmpR2cEnzmj6VVhwaNVnv7QDQK194Vk5o4kgzXlj8o90
         cZzlaEma+XFaIpwH0YCjqU6f9qDg2m1Xw9F7csJdJiAddI81UEQHH7B7iFppO6JEuPJR
         OgNx/NLX/hPge2vLafvO+WHWCINNV+K2c9aoYKj5rDGiXSf8OkfLT609Esxd1UhDpR+4
         jbUU8wfw6DwE8EsS3FCOLAEdt7XrrYuc+TxhdvQ1jdYfZOEDaRZw0fB6Mu4r9tZ9ey/n
         f1p1CYOEFUu9m/Ycjy+1y7spj3sepyZ3UELw0vaK3uN/6tT/lILMSSwZm984loo/m5x/
         +MiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=i6PGv4ZUKAWV06uB1yhL9icgz9mN5bj5ndLK9GnWxk4=;
        b=IkQ+o9B/0N5FdoyRvMzCkcUnMRQL7TY/e1pRXSnrEx7a/64kGg1Zwn98XRjm3A7MZ8
         Vj0rZbbtETrghze9jSD01G37SJ0KhdK8g8yR9YNBDtkGwurHJJtnQUPUrykC1+wtlrzX
         5D3C7GCVcP3p9Cb+kwoolAPZgM/MMGree/sXUwfIepBwOF7Xtv5TZEkfjdXy6yb3OFJ6
         ZUYnLeoiaIWmlLU5G1DqOe7dcR95fd8BJTL2hMUjyjJiz6qMOwci5xhFVbEHSEwAwijQ
         B/0Joni2eqawfhoUyaqPT6Ko6e0foAvAkgmBTz45JbmBjYvPuZSwio4+ifW00g5cEIAe
         TQkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ci93SS+C;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ej1-x642.google.com (mail-ej1-x642.google.com. [2a00:1450:4864:20::642])
        by gmr-mx.google.com with ESMTPS id f28si179053ljp.3.2020.12.04.10.51.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 10:51:28 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::642 as permitted sender) client-ip=2a00:1450:4864:20::642;
Received: by mail-ej1-x642.google.com with SMTP id lt17so10184504ejb.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 10:51:28 -0800 (PST)
X-Received: by 2002:a17:906:2ec3:: with SMTP id s3mr8195458eji.133.1607107887772;
 Fri, 04 Dec 2020 10:51:27 -0800 (PST)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Sat, 5 Dec 2020 00:21:16 +0530
Message-ID: <CA+G9fYvGeHv-iPy2J3tdYGfr1A7ZuUrZystuQ9tDxV7vbP8iPg@mail.gmail.com>
Subject: BUG: KCSAN: data-race in dec_zone_page_state / write_cache_pages
To: linux-mm <linux-mm@kvack.org>, linux-block <linux-block@vger.kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	rcu@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	lkft-triage@lists.linaro.org
Cc: Andrew Morton <akpm@linux-foundation.org>, Jens Axboe <axboe@kernel.dk>, 
	Al Viro <viro@zeniv.linux.org.uk>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=ci93SS+C;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

LKFT started testing KCSAN enabled kernel from the linux next tree.
Here we have found BUG: KCSAN: data-race in dec_zone_page_state /
write_cache_pages

This report is from an x86_64 machine clang-11 linux next 20201201.
Since we are running for the first time we do not call this regression.

[   45.484972] BUG: KCSAN: data-race in dec_zone_page_state / write_cache_pages
[   45.492030]
[   45.493532] read-write (marked) to 0xffffd4e284455380 of 8 bytes by
task 269 on cpu 0:
[   45.501453]  write_cache_pages+0x270/0x6a0
[   45.505560]  generic_writepages+0x63/0xa0
[   45.509582]  blkdev_writepages+0xe/0x10
[   45.513429]  do_writepages+0x79/0x140
[   45.517096]  __writeback_single_inode+0x6d/0x390
[   45.521714]  writeback_sb_inodes+0x4fd/0xbe0
[   45.525986]  wb_writeback+0x42e/0x690
[   45.529652]  wb_do_writeback+0x4d2/0x530
[   45.533578]  wb_workfn+0xc8/0x4a0
[   45.536897]  process_one_work+0x4a6/0x830
[   45.540908]  worker_thread+0x5f7/0xaa0
[   45.544661]  kthread+0x20b/0x220
[   45.547893]  ret_from_fork+0x22/0x30
[   45.551471]
[   45.552963] read to 0xffffd4e284455380 of 8 bytes by task 499 on cpu 2:
[   45.559576]  dec_zone_page_state+0x1d/0x140
[   45.563764]  clear_page_dirty_for_io+0x2ab/0x3a0
[   45.568382]  write_cache_pages+0x388/0x6a0
[   45.572480]  generic_writepages+0x63/0xa0
[   45.576495]  blkdev_writepages+0xe/0x10
[   45.580334]  do_writepages+0x79/0x140
[   45.584000]  __filemap_fdatawrite_range+0x155/0x190
[   45.588880]  file_write_and_wait_range+0x51/0xa0
[   45.593498]  blkdev_fsync+0x45/0x70
[   45.596991]  __x64_sys_fsync+0xda/0x120
[   45.600830]  do_syscall_64+0x3b/0x50
[   45.604409]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
[   45.609460]
[   45.610950] Reported by Kernel Concurrency Sanitizer on:
[   45.616259] CPU: 2 PID: 499 Comm: mkfs.ext4 Not tainted
5.10.0-rc6-next-20201201 #2
[   45.623908] Hardware name: Supermicro SYS-5019S-ML/X11SSH-F, BIOS
2.2 05/23/2018

metadata:
    git_repo: https://gitlab.com/aroxell/lkft-linux-next
    target_arch: x86
    toolchain: clang-11
    git_describe: next-20201201
    download_url: https://builds.tuxbuild.com/1l8eiWgGMi6W4aDobjAAlOleFVl/

Full test log link,
https://lkft.validation.linaro.org/scheduler/job/2002643#L1866

-- 
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvGeHv-iPy2J3tdYGfr1A7ZuUrZystuQ9tDxV7vbP8iPg%40mail.gmail.com.
