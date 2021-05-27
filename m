Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNGLXWCQMGQE6OAX4AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id CDEBD392AB1
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 11:26:12 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id p11-20020adfc38b0000b0290111f48b8adfsf1504412wrf.7
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 02:26:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622107572; cv=pass;
        d=google.com; s=arc-20160816;
        b=II5GHb8AXBF7lXc2SBXx4WfeaOum9sYXmFu/dPQIcoN/zUgZ2SyujTrY6gMl3D5nGr
         bi8nT+TvHodp0RDI83pmip7pv+4qxQ2z/Mmo5yTsP/0XZSPnEb4t7ce02Ae5/KKzWGm3
         Mpce6RQaf8pEP9QTyFwWLzKGEw8NG4TRHQs8ugL2bnRv+O5gbP75V3Bujj4aGTF8twkr
         VTkweSO5qcEP5zfGI4keWPE76xtLUAVou5cMTN7D+HRvrSqCIf8Ba0vcJYzRJ9Z7KsK3
         IOeUqRzljpdFhXZW08tefVbQAWcpJTXgUlqRhZnCmqWgll31SsWiRUHNa+c2P2BpK/7k
         6MLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=EshadyUxM9ni0Q+GKHfqL2GGgvKpqYs2K2vxnlRniSU=;
        b=v48YP2KUv9Rw+dt/5eh7Rn1+T3LYjOJaeZ4z1saV4w2zTmJAJcknFsNPUD4DeIPsGG
         hfP9LhZ0TvZPhpczCjQ+JhU7ocRTv2mOQ9QrREeML/lETv+CMbzZpw+O7gVLXNnElImC
         /0yc8Z4qGth0X8Ik41MACCfvjZRczDwO0OXzcvRatCuPEYEdZYk3UJERbvi0eb4z+nKb
         811hb+xO5eIZYbJyl2iEEsQ+Q4cqKvrbq1jnKyLBGR/2G8Bilp1dj/yimmoSNRNoVtZp
         u+Eb5NejLB0AA0Ot1bXGUCOLzWnHEwUCkq7Vpur7qPsX12iCaDi8p06Z6yhXAxJXq0Ge
         Hqkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Q/vJeL9s";
       spf=pass (google.com: domain of 3smwvyaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3smWvYAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EshadyUxM9ni0Q+GKHfqL2GGgvKpqYs2K2vxnlRniSU=;
        b=FxYu++HUynpL5h7eTHTa+AGv6Wv0nz8Cv41r++mKJeYO5H11WnBzU6w3hxl8LbIbSu
         vizY5qQTGM0tkAqFbBYw4b4aCHA96cFg27vCGRBTNSPhODPWqSSlgOiGfwQ+e0KMoTPA
         Y9jwxxf2FSCNol4s/5vQ/j9oyXcCbE1PFsJqHqCJEWTsNzYcYF0Fu1Ao2E9pknE3uAd5
         b0mkTbIft2hQietmnU5/Lnpv5VB7dcSm5TKhWpEJ+5SBP1sDcELqW4kVStMr5iQUUkWi
         6ff9o54/kO/ouK3ANOALhmHx4AVgJDEOWuRrSf60qtoZyCWhdjh5PCuK16E7kYzzCcac
         4qmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EshadyUxM9ni0Q+GKHfqL2GGgvKpqYs2K2vxnlRniSU=;
        b=ObFfCWwCJLXtATLY7atoP6icRAqB3V8jT3nTWem9b6HZN1az92yI7aIr2ARYuSkpw0
         nBq5VsJsppmoxOlATCZZMrVfGt2IZsoM+Iix5Xj6E/796czTCB5ilSb9GIbS6Ga3J1cb
         RoHVv+MCY4++oflbrsuiPX/PCSks119JQEOyKSJq4Uy+RIvAULBYMoWgw/33UcvJ9x6X
         u/9OklbxeYHZLPTcMQL1rDKsNTJhAT8pWoF0fcBxT4v/uls/LUhPU+hShWr/wACnp9Km
         gZZeOtjhD+ZP+oJYpwc8gs3ls2G6nzfE3Qb6HPN32cAtunI5wTp09qLWnAH71YjKu0BU
         5Sxw==
X-Gm-Message-State: AOAM531zHb+Bv3RXF/DcKNn60QcWYu8/vJ4NKBdZsWefwRgQCsyEkwi6
	sgsc490wsWxZ+JFdaMDfljY=
X-Google-Smtp-Source: ABdhPJyLqaNITO8Kf0qkTx4xK7CByMcB5AKcqke8zlG7NXuRBpPjo98TvmO9Ft+XbzS6WXnKBF20Mg==
X-Received: by 2002:a05:6000:1147:: with SMTP id d7mr2340648wrx.302.1622107572596;
        Thu, 27 May 2021 02:26:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e87:: with SMTP id f7ls4921009wmq.1.canary-gmail;
 Thu, 27 May 2021 02:26:11 -0700 (PDT)
X-Received: by 2002:a1c:e90d:: with SMTP id q13mr2422963wmc.163.1622107571591;
        Thu, 27 May 2021 02:26:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622107571; cv=none;
        d=google.com; s=arc-20160816;
        b=bpLRpjqtLRkOIV5vf+J2ec439V/Vr3qGFxm0NClHV9bQTbPAJPeTiAh+WD/sgy6nXK
         eigkdA82ebKm5+TsQU+342PBzN4Lzp1UWcB2Ds+B6hLjTz37ai44JGQlOYPYr3msdfZ0
         sVIe9zPnVmyjgByk+XQgqPZ0T9d1o8JtgDlVUgOcP5tEBOeQe/8poOgBb40GyX5K9b0l
         OmR+M8fVMXmjt62+9uLk9S/5+koNYA2Ar8m6fh2whFjLClnuzYvf/fReMWmw9ceNhLRM
         oO9lZw6IcyXGuQ7JFd+iGo1YDeD7qDcB0+dx6UyMqU4D+V5Iswd0ptkcvJ4misFIZCu8
         55QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=tpMhr1a1ucqmSn8aEv/I+3Jaj5nsK3OJYJ5e/mt9yGY=;
        b=IgSzpw9jW8CkoVWVm4RnsbD9l29h54YocMxJqf9oLKZD4J4GFp7uPeQS6Ih6CVzSus
         egmRwapfxk3Iq8o77dAvtsxqprzzW1WKYAo9Za/CfSry7Up/ongl3uYDfDxCHr3zDczp
         koRSgSG8awjaZBM3BW+vxgGaFkVdTY703yCNOEls9qbgSX7R5fHrS9zy5Dk3TkzB/MeN
         OBRSertY2RLXvCEv3CoCpdviUQRr6o27Ce5ssfLUqeFEL7WlYqgdaql1cuGD0mfnETPt
         sv0xvQ1684VhPGjW103sxxZ2nQYt7B5CczhGTbY/2fYBED1PhpOAP+qrfJ/LLXCPS9dL
         Tupw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Q/vJeL9s";
       spf=pass (google.com: domain of 3smwvyaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3smWvYAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id o63si394380wme.3.2021.05.27.02.26.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 May 2021 02:26:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3smwvyaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id c15-20020a05640227cfb029038d710bf29cso2122552ede.16
        for <kasan-dev@googlegroups.com>; Thu, 27 May 2021 02:26:11 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:74ba:ff42:8494:7f35])
 (user=elver job=sendgmr) by 2002:a05:6402:1c97:: with SMTP id
 cy23mr3063078edb.213.1622107570950; Thu, 27 May 2021 02:26:10 -0700 (PDT)
Date: Thu, 27 May 2021 11:25:48 +0200
Message-Id: <20210527092547.2656514-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.818.g46aad6cb9e-goog
Subject: [PATCH] io_uring: fix data race to avoid potential NULL-deref
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, axboe@kernel.dk, asml.silence@gmail.com, 
	io-uring@vger.kernel.org, linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, dvyukov@google.com, 
	syzbot+bf2b3d0435b9b728946c@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Q/vJeL9s";       spf=pass
 (google.com: domain of 3smwvyaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3smWvYAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
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

Commit ba5ef6dc8a82 ("io_uring: fortify tctx/io_wq cleanup") introduced
setting tctx->io_wq to NULL a bit earlier. This has caused KCSAN to
detect a data race between accesses to tctx->io_wq:

  write to 0xffff88811d8df330 of 8 bytes by task 3709 on cpu 1:
   io_uring_clean_tctx                  fs/io_uring.c:9042 [inline]
   __io_uring_cancel                    fs/io_uring.c:9136
   io_uring_files_cancel                include/linux/io_uring.h:16 [inline]
   do_exit                              kernel/exit.c:781
   do_group_exit                        kernel/exit.c:923
   get_signal                           kernel/signal.c:2835
   arch_do_signal_or_restart            arch/x86/kernel/signal.c:789
   handle_signal_work                   kernel/entry/common.c:147 [inline]
   exit_to_user_mode_loop               kernel/entry/common.c:171 [inline]
   ...
  read to 0xffff88811d8df330 of 8 bytes by task 6412 on cpu 0:
   io_uring_try_cancel_iowq             fs/io_uring.c:8911 [inline]
   io_uring_try_cancel_requests         fs/io_uring.c:8933
   io_ring_exit_work                    fs/io_uring.c:8736
   process_one_work                     kernel/workqueue.c:2276
   ...

With the config used, KCSAN only reports data races with value changes:
this implies that in the case here we also know that tctx->io_wq was
non-NULL. Therefore, depending on interleaving, we may end up with:

              [CPU 0]                 |        [CPU 1]
  io_uring_try_cancel_iowq()          | io_uring_clean_tctx()
    if (!tctx->io_wq) // false        |   ...
    ...                               |   tctx->io_wq = NULL
    io_wq_cancel_cb(tctx->io_wq, ...) |   ...
      -> NULL-deref                   |

Note: It is likely that thus far we've gotten lucky and the compiler
optimizes the double-read into a single read into a register -- but this
is never guaranteed, and can easily change with a different config!

Fix the data race by restoring the previous behaviour, where both
setting io_wq to NULL and put of the wq are _serialized_ after
concurrent io_uring_try_cancel_iowq() via acquisition of the uring_lock
and removal of the node in io_uring_del_task_file().

Fixes: ba5ef6dc8a82 ("io_uring: fortify tctx/io_wq cleanup")
Suggested-by: Pavel Begunkov <asml.silence@gmail.com>
Reported-by: syzbot+bf2b3d0435b9b728946c@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
Cc: Jens Axboe <axboe@kernel.dk>
---
 fs/io_uring.c | 9 +++++++--
 1 file changed, 7 insertions(+), 2 deletions(-)

diff --git a/fs/io_uring.c b/fs/io_uring.c
index 5f82954004f6..08830b954fbf 100644
--- a/fs/io_uring.c
+++ b/fs/io_uring.c
@@ -9039,11 +9039,16 @@ static void io_uring_clean_tctx(struct io_uring_task *tctx)
 	struct io_tctx_node *node;
 	unsigned long index;
 
-	tctx->io_wq = NULL;
 	xa_for_each(&tctx->xa, index, node)
 		io_uring_del_task_file(index);
-	if (wq)
+	if (wq) {
+		/*
+		 * Must be after io_uring_del_task_file() (removes nodes under
+		 * uring_lock) to avoid race with io_uring_try_cancel_iowq().
+		 */
+		tctx->io_wq = NULL;
 		io_wq_put_and_exit(wq);
+	}
 }
 
 static s64 tctx_inflight(struct io_uring_task *tctx, bool tracked)
-- 
2.31.1.818.g46aad6cb9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210527092547.2656514-1-elver%40google.com.
