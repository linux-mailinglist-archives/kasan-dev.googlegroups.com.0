Return-Path: <kasan-dev+bncBAABB4GTXOXQMGQEH62AUTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BE93877EF2
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 12:24:34 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-690dd4cf6fbsf1162176d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 04:24:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710156273; cv=pass;
        d=google.com; s=arc-20160816;
        b=qAmSSfF3X8IscYmJfCnUm8Jt+Am6AzI0SChL97oh1CyemkdYjQ0bGyRcswHzzqYM51
         4dIcwJa/werWItsCpVXXl2pujhi0LDYCdONI1skRuLDVLe/K8e+U6ttOhnnWsuKOIkg7
         w9b1Bvyn60XOrFN8NG8oP7NmohJSSytzLxyDGbQQ2YTd9NcvnDN3fdrOG6mkGCJ8TuZ3
         zwsblcQY8nogWc4Dr8lkRD5r8qw9cfXApMoRnkfJM0g2/VGRmbeMlP3KYoN8uoZQ8zD/
         mcQgQmwki7cDLp70rdtFIWrnd77be+l+wSM3dGUPyegP11geHSXj3Pz0q8YOEBncU24c
         8M/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=IIul1Pahoa7qmuoVu9OO5TVVhqOdGxMPj7ZX/Jj8s0A=;
        fh=Y3bAu+pbpTatmPZ60Dzmn8zfMnhnl7tXjGJPwtKorLo=;
        b=xpWMkz44RZr/5je9kBCVvaUEu+WC62lOHowrezLuRZlvW5+BkjbE5LDIpeoS/SSGyv
         GYAd1p4QUqaN+v7Zqc8s7Ty0bOZRuOGL0FjcsTJ+JX3hl1BaQrVTbBAvFDKaojrtOL6p
         8O7o55xxQBmHfYbdggyPtRSnZvNPYXehqcsl6429wC5rU94qMh0yVC481dlkAh2Zx3Qa
         Zc5lZr+ODAA+YG7TZLkRRIExzXrwnY8Veu1v2lbNmUklmQskYEU4WOCMzUPTt7Tzca8j
         tsPvWeGQ8h8s6ctaOrZ8auTlMgzP5o+9OX+GoZVROq6Llg91LbNwejdyBkWlo9JXbEYI
         bnEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710156273; x=1710761073; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IIul1Pahoa7qmuoVu9OO5TVVhqOdGxMPj7ZX/Jj8s0A=;
        b=YJwN1Dpfj2l6jcDbQp2AZ/EQjl3bSw8OWKS0ji/8Tl7AMq3VQPTbb9w4ndS0WvXJWo
         xZFNrM/q7nxy5FAkiR5Pw8qxQL7AwCFvZnx/tfsU/71HW2N5gFoBNC8ySWkn38ELtqM5
         vaXAwVS3gNItAtfXSXxvrK0M1FNF8mldR0ISxElf8tgQ23NflqjYm+Jr08fhfdzoTsw3
         /9KRj6idfmRqiHo42m79X/sG9i2duoDMtG43PND3wI4a6PGpjtk6xaoIHXyzyHxcQ54a
         tmpZKRGcDpH6Fby3L2DfwwxN9+sKWCzPlLKq/6q6CCknLdj3IzZAWA3Q7puU5SlK/oe3
         RaAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710156273; x=1710761073;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IIul1Pahoa7qmuoVu9OO5TVVhqOdGxMPj7ZX/Jj8s0A=;
        b=hEcdzTK/+8DczzhNyM8aYy6UpoaUMuTTPwNMiVyECAeFNgQhYebVLSSNOYm18ODi6T
         xrNGjP0x9zoF0BgI9VomLDn2AtIHh7jOIMmjpJYeP4huDTNa7csDdgnQJdjpNTYUIrQD
         vOgnHpb7wqM4Oju0dlEfi4vgWEvoA3qVDVzyPsSJExyVCExX+IkKhDiTdyadxrndXhkE
         wCT3p2dC/XZ1hYjf1UQqPlBkv16sDYkQD2RBLlbdHeXtP20o/695mSXkINHfIqfSk9pk
         vxgbFauzj5cjwR5BgpsbMTnu0rDSPzGbJyc9WuO9HIu841M0hS916HOVNsK8ezzs1vza
         p7VQ==
X-Forwarded-Encrypted: i=2; AJvYcCUUvr9ZgEH35FTztGB9dXzcul6RjyIGp9WYAZEPIG/5wZdXKPryGKVtWGV+xCDEfmilUwvQwYjD8HoZiaAqlJZ98KaetIVBtw==
X-Gm-Message-State: AOJu0Yz9IydoCA+g5Ue7vqgt5RjnkTjbZYQ+mcwJIqA93uB3BrYaVda9
	AveVKA92ZvPepYkqqJXIy3HtwdS++ersybucdY0UHwm2R6s77XeY
X-Google-Smtp-Source: AGHT+IFkat/6THYqtxPKMlv3quzmyBzvGRxUX12dRdM6v5BHODEYHfKY0OHJSk8Ye1hsBdPHV9D0+g==
X-Received: by 2002:ad4:5a53:0:b0:690:b459:1c5b with SMTP id ej19-20020ad45a53000000b00690b4591c5bmr6718491qvb.47.1710156273027;
        Mon, 11 Mar 2024 04:24:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:401a:b0:690:6d7:8276 with SMTP id
 kd26-20020a056214401a00b0069006d78276ls3240535qvb.2.-pod-prod-05-us; Mon, 11
 Mar 2024 04:24:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzgi5kpJRzC/txi9fy2EiyWHKrNYlTVbsYcnTX3y1fr5XYknldC2Yk0gPHPQiHvOZsFLrKrI6dX9nhl9SJnrAcU3hI6zEdgavTAA==
X-Received: by 2002:a0c:e38d:0:b0:690:8a01:eb2e with SMTP id a13-20020a0ce38d000000b006908a01eb2emr7727015qvl.54.1710156271520;
        Mon, 11 Mar 2024 04:24:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710156271; cv=none;
        d=google.com; s=arc-20160816;
        b=VfE0HVcXVQ94PaTskz/mgnwrLn/508dsqXyFEUC9TokxwUS1jOQmHiB7dvzjrF4yKQ
         SMQmmV87K6oxrGMbHzxUwKeJlIVIUX1hICuxMWWFSwWd9eh7FEs7NcxKmLxNxwAVMVx2
         WubgxjebmFM6z/UcP4OJCEWCwXoMndlR5X39feRMPTrgNW5H9uxQ4PisdNN24eMQDYyL
         Oc2qUCr3IIIExzPw5KWWLVNjtJ6JI1oT8v05zGptxsnunNyNlJVc8Y6BDVRdBd4aKZSR
         4u0/Fy3+9z/cCImlTQmYOyGpQw56YHVKgejI4JCShque4RqHDK51kIivmg3tpthW2LXM
         vECg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=AKJUPIi5ehiXACBaHP8MmBAHSQKfOjojtQyJv7fZX+c=;
        fh=XP3LCPTs5cj8PsdqeVmtUQlVN9yl18VhHBxzetGgYE8=;
        b=QQ8jGjRZLT6ipDm9ay5eNaTeftTt3bUqMsLrMtEIB1jEXb3yJUDd6ARou0GMC9mwXo
         tmBUl1ax5OBtkcWmDh3Bvvaw7H+cViDL4sfXxKDOMpQOYIcYmgAhu7PvqK8mq3da5k8i
         Iy1PzMfvEdmbG09V3xqM7fbHop/IWnsWrTkMzfPIb2VuS9Yii2hS/H5MHfWG4HQHC6tK
         /Qn1OMiK1KI1Ck8dBvYBdh70z7fBkd6GEFdonyHX1/x8Fdi6fvIjdBubjr8+emt5XP52
         vptLMk0b3mY6jTgLA4OKi/YpTEk/14datpgY0y/EgkpLoF0ofXdWLtS59BRJyFeOsxjV
         SROA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id f12-20020ad442cc000000b00690dad342a3si64711qvr.2.2024.03.11.04.24.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Mar 2024 04:24:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4TtZB80BlGz1Q9YQ;
	Mon, 11 Mar 2024 19:22:24 +0800 (CST)
Received: from kwepemd100011.china.huawei.com (unknown [7.221.188.204])
	by mail.maildlp.com (Postfix) with ESMTPS id 4CBB81400F4;
	Mon, 11 Mar 2024 19:24:28 +0800 (CST)
Received: from M910t.huawei.com (10.110.54.157) by
 kwepemd100011.china.huawei.com (7.221.188.204) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.28; Mon, 11 Mar 2024 19:24:26 +0800
From: "'Changbin Du' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ingo Molnar <mingo@redhat.com>, Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>
CC: Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt
	<rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman
	<mgorman@suse.de>, Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin
 Schneider <vschneid@redhat.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, Alexander Potapenko <glider@google.com>,
	<linux-kernel@vger.kernel.org>, Changbin Du <changbin.du@huawei.com>, Marco
 Elver <elver@google.com>
Subject: [PATCH] mm: kmsan: fix instrumentation recursion on preempt_count
Date: Mon, 11 Mar 2024 19:23:30 +0800
Message-ID: <20240311112330.372158-1-changbin.du@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.110.54.157]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 kwepemd100011.china.huawei.com (7.221.188.204)
X-Original-Sender: changbin.du@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of changbin.du@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=changbin.du@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Changbin Du <changbin.du@huawei.com>
Reply-To: Changbin Du <changbin.du@huawei.com>
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

This disables msan check for preempt_count_{add,sub} to fix a
instrumentation recursion issue on preempt_count:

  __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() ->
	preempt_disable() -> __msan_metadata_ptr_for_load_4()

With this fix, I was able to run kmsan kernel with:
  o CONFIG_DEBUG_KMEMLEAK=n
  o CONFIG_KFENCE=n
  o CONFIG_LOCKDEP=n

KMEMLEAK and KFENCE generate too many false positives in unwinding code.
LOCKDEP still introduces instrumenting recursions issue. But these are
other issues expected to be fixed.

Cc: Marco Elver <elver@google.com>
Signed-off-by: Changbin Du <changbin.du@huawei.com>
---
 kernel/sched/core.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 9116bcc90346..5b63bb98e60a 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -5848,7 +5848,7 @@ static inline void preempt_latency_start(int val)
 	}
 }
 
-void preempt_count_add(int val)
+void __no_kmsan_checks preempt_count_add(int val)
 {
 #ifdef CONFIG_DEBUG_PREEMPT
 	/*
@@ -5880,7 +5880,7 @@ static inline void preempt_latency_stop(int val)
 		trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
 }
 
-void preempt_count_sub(int val)
+void __no_kmsan_checks preempt_count_sub(int val)
 {
 #ifdef CONFIG_DEBUG_PREEMPT
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240311112330.372158-1-changbin.du%40huawei.com.
