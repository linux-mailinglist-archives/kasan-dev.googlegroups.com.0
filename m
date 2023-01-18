Return-Path: <kasan-dev+bncBDTMJ55N44FBBO5NUCPAMGQEZDRXH3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2195F672238
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 16:56:44 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id e10-20020a2ea54a000000b0028bb7bdae44sf50221ljn.5
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 07:56:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674057403; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4+yGn9z+FIqEvKsD1APjYZINjwbI22kuSkPCymwRLSnTretkVkwbxxxbpfPSNOp68
         2eQijliaEsnhDu7Bcx8AuQAieyijVLkBujMLGJOmIcH5aTiPznhX5YheIO2F+JoSlr42
         zDZhuM2sLxoqQWuus55Q0MMPhmglyeneOBWmTOfAIN2iKKCD1OqZ490gN9zjiILTNFg1
         LsP6Kht5ZTG0gs1ZFxPnbCgvqEIfVzfwSonc2kQd6aGZc5ezDDYc4GiUhVAU5OPDDgf7
         IrqEPsx6Vz303SU/qpQ16KFevf9jUWCgpIrjS0w5RUaRkCersZXjjJZchWRNcmTzFUuU
         Tq4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=k+2fKxvvKsauVaEdclAwEU4VWy1GZkGRf1YPOjGHaz4=;
        b=QzQ/OpGsFNPXb1PyW2rUjiU3CT9QgGscu6wICzWb0aX7zAjKTnKxdij9uHpkqNZLpp
         bNYyKHtgLy0qaSmHQ8NoAUA6cjhi7QE8SZTtOsYKMX1hnJqpQtGttvYHm8jAwi/QTMWo
         75AuKOlpFoisRXevhbG2Y4uDdAyW1x7vlFNG4mKblqfSH0DgGJRNvojg7Bpujwx2kqOh
         fq9BCk/XV6/DIfZEbDi4nu4apGRCwXzEEI/L3uh+4UWlOx+epBXt9oKV3j0WBR+dc+Ax
         w1LRAjlqqCJCsUKqjRuNEautx93u85SFaPSbeTd95uDT1v/6M//KpbG6n4/VBax3oTXp
         7syw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.47 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k+2fKxvvKsauVaEdclAwEU4VWy1GZkGRf1YPOjGHaz4=;
        b=hpzay5wlN2x3ySQIId3r53ClzlPDaL9pPiP28FP1UY+bloG+LeH4MEZF59dz5SW1+s
         uKQVgRsnV/N9JY39mAiJ240rkQUK1au3gSzCc9OQMiFof4fTmCNoHyoPousF2ST/7C4N
         2wk/DyB3AkhrvjghVeBVjpO/2bO/Nl5h1Oo/REgXj/EQ8LMFcMypec5mkDW8+sw8nza5
         ysmRrj0YBb5Q8YWxuhCrSX+M7JkRnpnR3nFhYXpqkb9hEPYLYogvth6anwlSvwc+4ksm
         dnsJz9AJXYXOTHPdmSSPAXbEY3T74pVQu1xIHueFuX0uN4Wna1VUWg9fq1v9x3M2A3TG
         PkBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=k+2fKxvvKsauVaEdclAwEU4VWy1GZkGRf1YPOjGHaz4=;
        b=t4in9yzjFX2L6Gh9WH/ITV86auzFfDXnf03KbGpILqRFBwGhcZdSpHIFai/r+X4C+K
         t1cW9U3aGA/ecwmOmKBSlqU5/+ySQF581pjtrSL54Q/qIGkl6Tt1Mlam1mvU/i41eT+v
         5Cua6k0tCOrYV+O8E75UI+Dk3GlMem9ov67G+FYwQFk+NjspaM6pHdvGfnJUXMXR5N+0
         Zk8pFTtN0g33J/P8ekkWkHkZhlMUK/m0KtiIeTu5+dy+P4TroeF0AMyDfgV5JYpWTPio
         swViKNt9copzxFNfQYMOO+0U/8upbyR+5xFXJR79QeyIOJhrbPh1+f9skOHIeCANIgVM
         8Kcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koT3FMTLXAC+PnSt4HYWVxj2AKKOl8IYBAzwbWEeHYEKBOveEE4
	SDU685OPijed8PP/0ZMMwxs=
X-Google-Smtp-Source: AMrXdXuwblBYlEE7vsVJfBAnyqUHWdhHzAcyaG5FhBrzXmaoId45TXDyUtfUOhKwGgZcODCZY9+Bhg==
X-Received: by 2002:a2e:6818:0:b0:288:e35f:d87c with SMTP id c24-20020a2e6818000000b00288e35fd87cmr437768lja.500.1674057403449;
        Wed, 18 Jan 2023 07:56:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls5666766lfr.3.-pod-prod-gmail; Wed, 18
 Jan 2023 07:56:41 -0800 (PST)
X-Received: by 2002:a05:6512:e9f:b0:4d2:c74:bf67 with SMTP id bi31-20020a0565120e9f00b004d20c74bf67mr2713546lfb.45.1674057401533;
        Wed, 18 Jan 2023 07:56:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674057401; cv=none;
        d=google.com; s=arc-20160816;
        b=XMgcnNwBmjW4Rogk1tZyfSPp2ubuYFD6zK3A7UkXBHVRhERdEi4BbK9tmYteetZEy7
         UCgATA3zt9vglBBVSLipQ59kse9TpLp2ZFrB8XU/Vb5wZb4xkHqAgp/hGzi6SR0uVt0a
         pgtG8GTaUIP6lHGg3wq5CZS3WbKNjUk2hsxePzX0ojBMRPmsJlvyN3gTt+PCeDZF8Nzk
         LGw+leVg7vOJkD2aO/uijlpZHwSDLpSGoJ4aNjSDDDBGkpFaVEfVgQt8GU8AF4Bsgu+C
         wDQO3SwOKOcQ8xdcw8V8EuhHk1UwjwiavfVK6uVeMwsRWJtNS+WA13T7oAGwmzyEg5MV
         VNjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=kpirYHngnT4pnfeId8PwGYCJd6AYwIUHThaVH7Hubp4=;
        b=WGOzJONKQAZNgY8kn6MfAwxc2eeQNOnNMqQTcrfTxcixJKT5uW+bpHss8YPYurhDSA
         EH1uclYhrw9CdAjAHYQa1KsPmbTciE8r9rOt8IZaGqA0ggGECXiHpYDkjifaIcQ3iQTI
         S1QJwFUvkxaQueqPPpoU9YCtGetrx5DG0M1MJMQXXIRlVfq7qTIk6LuSkKwuzJtMoGjb
         dSaqpNbrOk5hq6MQlIMvJufKjnfxrFZDEnp3cOB0MZd9PHGc0wPChuzC5Nl9D/Np3c/r
         PZVbQVgwxZubDup6pjQkhnU04lMhAVUpB+3qS4bCc8FsAc2L0z17qSOACv02zG2S8qTx
         9HJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.47 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f47.google.com (mail-ej1-f47.google.com. [209.85.218.47])
        by gmr-mx.google.com with ESMTPS id m3-20020a056512114300b004d57ca1c967si393662lfg.0.2023.01.18.07.56.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jan 2023 07:56:41 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.47 as permitted sender) client-ip=209.85.218.47;
Received: by mail-ej1-f47.google.com with SMTP id bk15so26818552ejb.9
        for <kasan-dev@googlegroups.com>; Wed, 18 Jan 2023 07:56:41 -0800 (PST)
X-Received: by 2002:a17:907:c388:b0:86e:65c8:6fe3 with SMTP id tm8-20020a170907c38800b0086e65c86fe3mr8253919ejc.7.1674057401112;
        Wed, 18 Jan 2023 07:56:41 -0800 (PST)
Received: from localhost (fwdproxy-cln-120.fbsv.net. [2a03:2880:31ff:78::face:b00c])
        by smtp.gmail.com with ESMTPSA id gw21-20020a170906f15500b0086dc9e05685sm5621406ejb.222.2023.01.18.07.56.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Jan 2023 07:56:40 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
To: asml.silence@gmail.com,
	axboe@kernel.dk,
	io-uring@vger.kernel.org
Cc: kasan-dev@googlegroups.com,
	leitao@debian.org,
	leit@fb.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] io_uring: Enable KASAN for request cache
Date: Wed, 18 Jan 2023 07:56:30 -0800
Message-Id: <20230118155630.2762921-1-leitao@debian.org>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.47 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

Every io_uring request is represented by struct io_kiocb, which is
cached locally by io_uring (not SLAB/SLUB) in the list called
submit_state.freelist. This patch simply enabled KASAN for this free
list.

This list is initially created by KMEM_CACHE, but later, managed by
io_uring. This patch basically poisons the objects that are not used
(i.e., they are the free list), and unpoisons it when the object is
allocated/removed from the list.

Touching these poisoned objects while in the freelist will cause a KASAN
warning.

Suggested-by: Jens Axboe <axboe@kernel.dk>
Signed-off-by: Breno Leitao <leitao@debian.org>
---
 io_uring/io_uring.c |  3 ++-
 io_uring/io_uring.h | 11 ++++++++---
 2 files changed, 10 insertions(+), 4 deletions(-)

diff --git a/io_uring/io_uring.c b/io_uring/io_uring.c
index 2ac1cd8d23ea..8cc0f12034d1 100644
--- a/io_uring/io_uring.c
+++ b/io_uring/io_uring.c
@@ -151,7 +151,7 @@ static void io_move_task_work_from_local(struct io_ring_ctx *ctx);
 static void __io_submit_flush_completions(struct io_ring_ctx *ctx);
 static __cold void io_fallback_tw(struct io_uring_task *tctx);
 
-static struct kmem_cache *req_cachep;
+struct kmem_cache *req_cachep;
 
 struct sock *io_uring_get_socket(struct file *file)
 {
@@ -230,6 +230,7 @@ static inline void req_fail_link_node(struct io_kiocb *req, int res)
 static inline void io_req_add_to_cache(struct io_kiocb *req, struct io_ring_ctx *ctx)
 {
 	wq_stack_add_head(&req->comp_list, &ctx->submit_state.free_list);
+	kasan_poison_object_data(req_cachep, req);
 }
 
 static __cold void io_ring_ctx_ref_free(struct percpu_ref *ref)
diff --git a/io_uring/io_uring.h b/io_uring/io_uring.h
index ab4b2a1c3b7e..0ccf62a19b65 100644
--- a/io_uring/io_uring.h
+++ b/io_uring/io_uring.h
@@ -3,6 +3,7 @@
 
 #include <linux/errno.h>
 #include <linux/lockdep.h>
+#include <linux/kasan.h>
 #include <linux/io_uring_types.h>
 #include <uapi/linux/eventpoll.h>
 #include "io-wq.h"
@@ -379,12 +380,16 @@ static inline bool io_alloc_req_refill(struct io_ring_ctx *ctx)
 	return true;
 }
 
+extern struct kmem_cache *req_cachep;
+
 static inline struct io_kiocb *io_alloc_req(struct io_ring_ctx *ctx)
 {
-	struct io_wq_work_node *node;
+	struct io_kiocb *req;
 
-	node = wq_stack_extract(&ctx->submit_state.free_list);
-	return container_of(node, struct io_kiocb, comp_list);
+	req = container_of(ctx->submit_state.free_list.next, struct io_kiocb, comp_list);
+	kasan_unpoison_object_data(req_cachep, req);
+	wq_stack_extract(&ctx->submit_state.free_list);
+	return req;
 }
 
 static inline bool io_allowed_run_tw(struct io_ring_ctx *ctx)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230118155630.2762921-1-leitao%40debian.org.
