Return-Path: <kasan-dev+bncBC7OBJGL2MHBB47K7SEQMGQEWCB3TZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C9132408A1B
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 13:26:43 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id j13-20020ac253ad000000b003f3c093087fsf564117lfh.13
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 04:26:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631532403; cv=pass;
        d=google.com; s=arc-20160816;
        b=u7MXpJyYVbnZTgTVSc5SUWmtnYohhrdxWdOu8R5PSZdx227pzyn5kahffReuD1XCFQ
         mkLB07vX1FysP/E3WqydxphivxtEL8CyT8i/UIFIOvT3pLDPvUSTNm/LWoLRAYM/GMOe
         YBiQ9ZYQznQNPOAbSVOpSM3vMLdxjfKTfQOKdYUgdHEv2hQQhD4nuDwqG+/BxAniwfAl
         geDcpZKAx/Pc53drgRbx4DQAfh+pUx8xZ1j+qsldMQsVLync0tzMAwnfFia7LdMgKGt0
         ax7PG4KZbEqUmTrjhZEc79E7PnU07FzmMHrmH4D7VjvO0AQbHkgy03UvKRteuYtLb5Qu
         24Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=u3BCVC0jqdLAPseAKEUZidybRewQd2CVzOgjRHCl8Qw=;
        b=tuJqZscSZUQqGUjPF9LiVfJ7llr/5Iw1QIShEDEv5xOVNt7ugotGsljuDpDVZIkaWz
         JV4j43FIqaZB7nslsfakLYN6d+BfdCq1GndgcZJckl7vmPfBrV3PhIJSUWWkKO95i2Yp
         Bn0xqtFqFbV8mX43Us1wET3+tGFtc53ZaCe/gSxckVUpouHye5n10oSR27BPn5EXTx2i
         jlKhLrTSDNpSAJGuY+4Pzyg4v39etzlpiPHHdI/M2nCwEQ3t4M35yhekz/RblwYzyCjh
         mo8YYNWu9kVabujdurjuuegItceTuOpGrLACqjoD8YtT5E9saQKT8XOSqW0PPdm3PbrL
         PoUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=H9qgnMTa;
       spf=pass (google.com: domain of 3ctu_yqukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cTU_YQUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u3BCVC0jqdLAPseAKEUZidybRewQd2CVzOgjRHCl8Qw=;
        b=PI05cTBQhfOMJK/F2rr2O5sY3s8hzUW07CBDEaZru9oNoMvPcVcxCU9Nqu9ghx+o5y
         453hzsvQdXXlDAu+BSMlYKnjwSk3Xvmmt7AYIjCE8BLgv92d73XjXBg2XcA5RIAmJ6eW
         A+eZc5unUUM2Mvx1xTGVPUcdsjmzhUHt//XK1/unT18HZQtqPa5Ra2mFtyyDGNm3iBGH
         aW0JwO03CKNmbtOrKdmHBSF5TS+4srmeKs2wLIcfnW0BmLDTlc/fLluSEzKCL2D+4xtX
         UPp+OO7TMe8kEXhPh/7k4jHEsUVNJft5jS5RW7Obkdp6DCEqURGumyGpu76hBuzvn0KF
         2hIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u3BCVC0jqdLAPseAKEUZidybRewQd2CVzOgjRHCl8Qw=;
        b=hD2xnP9XZ7QPGT2qPsbPxbsPsLCY4kpLPZ+5mWGbzePwUVPmo2533vXlDR6OfmGep3
         1F0SJ/dCsIGxaIx1ZI4ZdJtR3fGez7lCa7aBAfnCU77yK/ss2sJ3ajM5b7PQI0EFXwt8
         so5C/A1aW5+e+b+FMGKMiiTs21xluvNbCE06DnT0mNXKj6DSc0SyKBamDmMLJkhXoESU
         p66XUxrxwWcNyiYGhtFR8KbE9wpe8ESRWNvsOzXqyLROUGwAe4pQIdycY7QGW2f1zmOP
         2gq3bfwIVFdU82K2MeBq08d90tOlKmcuZUnmLXdHvwVb+oORIBqclntpNhiSIAi7PfRr
         8riw==
X-Gm-Message-State: AOAM530IKVohRwo8KCJ9A30kQ7LzlnH/wQbo/tNEmC5l41516CVDu0dM
	xOIp1LSB5O9kmRXdlzVkaFk=
X-Google-Smtp-Source: ABdhPJyrkFTzFgdWYDT3dHY5VPop92PsWq2u2kSjlk90X7e7wlKeby2y/sGV2ohM7BMCFSc1tiHbPA==
X-Received: by 2002:a2e:9995:: with SMTP id w21mr9778053lji.163.1631532403389;
        Mon, 13 Sep 2021 04:26:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:597:: with SMTP id 145ls1073669ljf.7.gmail; Mon, 13 Sep
 2021 04:26:42 -0700 (PDT)
X-Received: by 2002:a05:651c:1124:: with SMTP id e4mr9976038ljo.261.1631532402284;
        Mon, 13 Sep 2021 04:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631532402; cv=none;
        d=google.com; s=arc-20160816;
        b=ihmgSkNSzcXLcM69X1y3K9rPya7XlKrk/+KgAQACyosob8qZfSgI+uWvc4WXOT94/7
         2Et+Un8FuPGGhCB2Oyi6QJcbIfkhgpyDISxa121SBtFqP9DizMWtZHJikDejNoF1WaR6
         U2oB/tWLqRxmeKlUbxNo+nDxVuQa+fZzoc99rprBmuY2W9SmTE8RVEY7KwtBjat/h83E
         zCbTkFFoKugte5Gyu+HhC9HV3rAdrvbRAnZFONNFAIMRbdMr4LGzOoXKnGC1leWyy9Hd
         OrPlSlxQm1TMnyLuhiQx6QUgMq+aF/G62vNlzYMgvfDCL/K3WLfm0ES4WT29qvXOukwu
         dOww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=uXbisNK0hzVjo0x7v5RilsBzlcwLLC23aSoidmJI5Q0=;
        b=RrHrUDrA2ubhPGpHctfA2dCwbL2InPDQvYN+GKJlIV9MHTmpJ6Bx1YwWDOCR0YaFhx
         2AyJn5mNWZJ7krDU5yy7VAjQkoUMLUbttVYT2+pVdtu5+IdwTFq2VXvBZg7SnxPAANIm
         7iKtFCbQwp/lw5S4wrfQj2rMvZqATsPKMAnENkXiD3V4T7LH/fknPVpt6qJeu5EBjptm
         EKNSQ4o9GJM7K7gMWz4uwjXCSw1k4V5N7PsUQWHJXieaFh4kvCPszT3KRVjjcUET5zgn
         t9LAzDGDzygeZfs4B4Qgr7L1kRlHVlWZNku5ghuMHpNlDEvFbvEUFCoTLEDQUWwhi4tD
         lzog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=H9qgnMTa;
       spf=pass (google.com: domain of 3ctu_yqukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cTU_YQUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f40si632023lfv.10.2021.09.13.04.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 04:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ctu_yqukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id q14-20020a5d574e000000b00157b0978ddeso2553210wrw.5
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 04:26:42 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1f19:d46:38c8:7e48])
 (user=elver job=sendgmr) by 2002:a05:600c:245:: with SMTP id
 5mr9896478wmj.53.1631532401563; Mon, 13 Sep 2021 04:26:41 -0700 (PDT)
Date: Mon, 13 Sep 2021 13:26:09 +0200
In-Reply-To: <20210913112609.2651084-1-elver@google.com>
Message-Id: <20210913112609.2651084-7-elver@google.com>
Mime-Version: 1.0
References: <20210913112609.2651084-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH v2 6/6] workqueue, kasan: avoid alloc_pages() when recording stack
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=H9qgnMTa;       spf=pass
 (google.com: domain of 3ctu_yqukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cTU_YQUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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
Tested-by: Shuah Khan <skhan@linuxfoundation.org>
Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/workqueue.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 33a6b4a2443d..9a042a449002 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -1350,7 +1350,7 @@ static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
 	struct worker_pool *pool = pwq->pool;
 
 	/* record the work call stack in order to print it in KASAN reports */
-	kasan_record_aux_stack(work);
+	kasan_record_aux_stack_noalloc(work);
 
 	/* we own @work, set data and link */
 	set_work_pwq(work, pwq, extra_flags);
-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913112609.2651084-7-elver%40google.com.
