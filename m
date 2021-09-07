Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOHH3WEQMGQEPBUE6PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 69EC4402A86
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 16:14:17 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id bq3-20020a056512150300b003ee49c29389sf140000lfb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 07:14:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631024057; cv=pass;
        d=google.com; s=arc-20160816;
        b=RpD086zOGpUB9ASuEclAK1Jr8RhbCfv9NxfCHDqcrW/xAhWMnAvzQvi459Pr0DGw3f
         +vcQ98FMoPXMIeEgyNkdpHDcGYQt4XBYP0oLurS4ZR1peLu7go4WlQ7cE9oD8gPUl64h
         t20Pen8zB2RIOdem3Js/1Npxh3fUxZ4nkFsOEJwnFVG1o/zexydbQ74H0h1eb6QQgyJ6
         SN0WiNLw/ZCZ2fXYWjdBZTTEG0Ejw56gptk5I6jiOaHr4aShCSlIGKTi+Y9pp6EwPfI9
         xzL5m/WsDiyFmpIAgctcaje5+3QyGf6RW/utogT8vGkHrsdevRLHWad/QElY36B0FFqw
         RY1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=EnK4wjzvUnFejL3gpOHr1SoyiymUV5rW0DDK6ZhI/Co=;
        b=u9uCQUvddS8yrnMf32qSCt4qlU93k+27rhBnFAIx+VW+T9lFzZHW9v33FzD19VPh/a
         uXDLWlEFs1d7NpKumyHcS/z2TneFyLcv4ww34cNeVySnX+XQMz0qGOBRKFFIRNWGi0Ae
         IXUMxCPDeZZ56OxJICFnPaYybVNKSkSab8w+DAqBzApbpnXb2hCefpytvg++xIMPZSeP
         2HrEaHylU1EIE0+PUNUHnoY/WTHXvF2z09DjhIGxe5vyDqJMD3TLevRy71vne+S4O2uW
         eUKvFEvhDR7LSSFn8aiWCL6OijXO70FIew+6W/VUYr0xXkTq9NOp34YiLsgw+r94lscq
         JJCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=edoUkiH2;
       spf=pass (google.com: domain of 3t3m3yqukcywu1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3t3M3YQUKCYwu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EnK4wjzvUnFejL3gpOHr1SoyiymUV5rW0DDK6ZhI/Co=;
        b=Cy2CSJDROaeunZKzcpuCBGoaJ8YiuxNeRBEs4lC0mmktaB8pzxolQnxRIEKhaYjzZB
         0IFsEhye/qudA7QdOLIHcxSwfDh7d+8ySI25wXWZ1a//6xx1XVKeN/vMlVgbj2h5vyIf
         9Fxij3iMpw/mz8fQIXgRPkRsKHtvOrTsmZrt1W+VRtrKCUUG9HYGqImI/eLiUghSCXk6
         7/Mj5pWvQl5xjbQMK+3STusajr9LOesdha8H8/baYbB0C7CVNcbm+6JO3mtcd0hQNbd9
         rstI65U27gFZdiEvWfl+gmNA191Qdlax8gOhXIM6D8HhIpZkGLVMgFNCstMQVavwmyQ2
         CyZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EnK4wjzvUnFejL3gpOHr1SoyiymUV5rW0DDK6ZhI/Co=;
        b=PwytSAr8NzQCYOCM8AB2tn4b33HTLQGgQlNN9xqJ8V/RqtkphFptwsngF/3SNrVA+W
         VPxjeR2UUjcBk7WdNG9bCFF0GOtPmo2JQz0YY0Ws2r9JQEQ4wHAmXI8aZ6MiZX8yXHCG
         pRc4zmD5DocHtasmqT9KjI6PhQYpymQ57vlol+pvgFua9DHUxnjx3eTRgydWe+V2AA9p
         TTB0tGEcgvSJdoomQfR2s11SApQHkz0lfbS0XCoXohf+/4evn3LM4oIVI1obXF9wnWKy
         ewimEhlER2f+v77tJCglrc42dqzTmx39aVOERdR6CdhRjy/7yup5GUje9yI4mrPu/FnX
         5QSA==
X-Gm-Message-State: AOAM531Dltn84IHuNeX1U+JOB0xGP7a4E/ZixN/8D0Amy+2dfE5Wto+Z
	2qYZZgiCL8//JZMWjT25IUo=
X-Google-Smtp-Source: ABdhPJxw/5LBSdwFNztTO71wxeLGtnYL6EMBN4fANeZdVllwq+kxe1splHLKbedYpcBzc8AU2vtj7Q==
X-Received: by 2002:ac2:5972:: with SMTP id h18mr12877147lfp.681.1631024057004;
        Tue, 07 Sep 2021 07:14:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8945:: with SMTP id b5ls1754442ljk.8.gmail; Tue, 07 Sep
 2021 07:14:16 -0700 (PDT)
X-Received: by 2002:a2e:9e04:: with SMTP id e4mr15641668ljk.431.1631024056043;
        Tue, 07 Sep 2021 07:14:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631024056; cv=none;
        d=google.com; s=arc-20160816;
        b=vOJUhEq/4q9bfFRyu/CTuW7eg5YbTiAMj3xtt5MIPuVdpDLHMLbI5K9dp8m0qsVBQM
         mKUsoE+nXnw+RVaFvOtvCeoCDPzC6v8KU0DufukcBSQZeADwxTp0H18o0MM1FHi6ejIA
         hMm1YWDrXNsYLd/0B9zFAYT4f9tWc0NiJQHOeNlpgGdUzQuI8RMX78GsSjvBCUdsiqsI
         5dVbx/TSvUn3iPSwUB8+LwtRiTO38x954F/K/As0fSqZd5/TAiEvrKdeTZNNIOtav+ob
         agfwnHAH0qEzqoyBe6fZSww1rqgN1nq/srExgSzk89k7ZXnP2YoQ1Fw6d0dwtcLlfJgF
         qlVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7ChlQWANvSBXBNUBCDuMgq5Cekd+HYTjR/ntyIg1Zyg=;
        b=DKaUhaxpv/Q6q5nsOa6fkughb1TH9PfJbKJYxUBebuvA3r2L5mgcpC2gF08XgjLVTN
         W3hpG5X4aJB/fz82cqTlURUOSNAKd6gq7jXYOjnucPSny3pSy18k2gUcaov2HKO+cYVo
         /lUhjmriGg3rM+0MZwvQsLz464Ged6XVcZfrI/pCHQvR2r/QtjyNH76kMpv5rgnyjEvJ
         Cfr0/WKT2Q2eX0gE1+gyY9THgkDB3T5SJ3pKlZb0VKJRI6FHcB/ExIn9sDPHBcXxvjjV
         aj/sWbwd9k9ZEKYYXdB6PLPXDV48LLfAcgCdjnXjlzrSbloZ7PQPChGkXWZp/a8CIvBq
         j3JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=edoUkiH2;
       spf=pass (google.com: domain of 3t3m3yqukcywu1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3t3M3YQUKCYwu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id b25si654297ljk.6.2021.09.07.07.14.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 07:14:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3t3m3yqukcywu1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id b8-20020a056402350800b003c5e3d4e2a7so5368899edd.2
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 07:14:16 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6800:c1ea:4271:5898])
 (user=elver job=sendgmr) by 2002:a05:6402:3107:: with SMTP id
 dc7mr18886580edb.341.1631024055406; Tue, 07 Sep 2021 07:14:15 -0700 (PDT)
Date: Tue,  7 Sep 2021 16:13:07 +0200
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
Message-Id: <20210907141307.1437816-7-elver@google.com>
Mime-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.153.gba50c8fa24-goog
Subject: [PATCH 6/6] workqueue, kasan: avoid alloc_pages() when recording stack
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=edoUkiH2;       spf=pass
 (google.com: domain of 3t3m3yqukcywu1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3t3M3YQUKCYwu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Shuah Khan reported:

 | When CONFIG_PROVE_RAW_LOCK_NESTING=y and CONFIG_KASAN are enabled,
 | kasan_record_aux_stack() runs into "BUG: Invalid wait context" when
 | it tries to allocate memory attempting to acquire spinlock in page
 | allocation code while holding workqueue pool raw_spinlock.
 |
 | There are several instances of this problem when block layer tries
 | to __queue_work(). Call trace from one of these instances is below:
 |
 |     kblockd_mod_delayed_work_on()
 |       mod_delayed_work_on()
 |         __queue_delayed_work()
 |           __queue_work() (rcu_read_lock, raw_spin_lock pool->lock held)
 |             insert_work()
 |               kasan_record_aux_stack()
 |                 kasan_save_stack()
 |                   stack_depot_save()
 |                     alloc_pages()
 |                       __alloc_pages()
 |                         get_page_from_freelist()
 |                           rm_queue()
 |                             rm_queue_pcplist()
 |                               local_lock_irqsave(&pagesets.lock, flags);
 |                               [ BUG: Invalid wait context triggered ]

The default kasan_record_aux_stack() calls stack_depot_save() with
GFP_NOWAIT, which in turn can then call alloc_pages(GFP_NOWAIT, ...).
In general, however, it is not even possible to use either GFP_ATOMIC
nor GFP_NOWAIT in certain non-preemptive contexts, including
raw_spin_locks (see gfp.h and ab00db216c9c7).

Fix it by instructing stackdepot to not expand stack storage via
alloc_pages() in case it runs out by using kasan_record_aux_stack_noalloc().

While there is an increased risk of failing to insert the stack trace,
this is typically unlikely, especially if the same insertion had already
succeeded previously (stack depot hit). For frequent calls from the same
location, it therefore becomes extremely unlikely that
kasan_record_aux_stack_noalloc() fails.

Link: https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org
Reported-by: Shuah Khan <skhan@linuxfoundation.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/workqueue.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 50142fc08902..0681774e6908 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -1329,7 +1329,7 @@ static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
 	struct worker_pool *pool = pwq->pool;
 
 	/* record the work call stack in order to print it in KASAN reports */
-	kasan_record_aux_stack(work);
+	kasan_record_aux_stack_noalloc(work);
 
 	/* we own @work, set data and link */
 	set_work_pwq(work, pwq, extra_flags);
-- 
2.33.0.153.gba50c8fa24-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210907141307.1437816-7-elver%40google.com.
