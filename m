Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ5ZXOBQMGQEBDECCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B9673580B8
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:36:52 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id u23sf1074259ioc.4
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:36:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878211; cv=pass;
        d=google.com; s=arc-20160816;
        b=fCP2kpHcs1aWgpPOPsMkKxWi6Y8m6cqFsOqU9SQ34ZNgM9Zm2rvOmkyQZG9iClztbt
         gGmB0BjwQaFGqJ2ayxY8zf/GMpeIKemNFtRddmNY/QlPjh/WATNItppAGm4BMFjaejKv
         UN6NQavSolbZn8+v1HRfoCrWyZtickE+jfGMELbfVWXIR3+6LunheTJajCeyQRZLUpwP
         wVgu3EGdXgXbhWJ3ePPkPJtU/5Ame1NBF2umfRrSFoyfIZgE4XMRVeEaOwpWfjeZRUlw
         ZOttIHuzzW17NG+HddraQHSZUxOPkpO9yMM1a8AzpCpmtPIv3CI9Liv/n6CmKhCh98gK
         mWeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4uhZUZEn/GInjduj8JqP+F7e/sWwxseYoJWzzSSVxCI=;
        b=E7l1Ub6xhij68wXKURhMbl3bmP1KMbkddrVHtioESVLW+3ugKgfHLfmxdtOXerOPpg
         Mqb3QL/pNuxJL2sRiieksnyuFyPXxRP+nshLLuW2tzzGzDXkRX7D04X6l505SBxUSFjF
         b60xx3fXFIOBUEAoJrkc/ZLPViX7+EsZuInnalAmlkf8bV9IqHqGkBfASE4VPm7XMSub
         4bOLcr6HDiPKMy1H7XfU2d65nBkY0CVITOUIMEf+IlxOr913trZy8bT6J28ELyBEVyPy
         RKEhlT/mhkHXThOrymgGNS85qlEbJa1bEjK7p2yg6ZGYt16TbGJf7LrJDYAySvlBEoKO
         MyEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VXjEJZGn;
       spf=pass (google.com: domain of 3wtxuyaukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3wtxuYAUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4uhZUZEn/GInjduj8JqP+F7e/sWwxseYoJWzzSSVxCI=;
        b=qtTJCybvS2KkkXcnz2rMWJuxEDgbLsp1Eef1gVDKxt0NGRMayllJMejRbEvpLu7Bc8
         pSMrofGvU4yFIOMoedirt9REzYhx0Qd716GCxsi6boFi2yWf+qfBJbBnmJ9XOgNaNLQ9
         vHRkP3fAQ89CmtfrM0yZ0MusbF3nsZiBM/VEI5cN4mZJUKiENgmigV1mBiojQY/GzBGI
         jJZedC6CSWUdituRgY9y6CLUA2PhTt4Zao+NmLrQw3P1AKGCvjifyRDUv914qKt+0pR5
         +YVEfo+OpYmqrxsUq6kn92DYW1srk6zDR7Z0rryRLb6LoLdJK8xmcOSdud9X+dx+yXef
         T0dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4uhZUZEn/GInjduj8JqP+F7e/sWwxseYoJWzzSSVxCI=;
        b=Vz2NeS8QYTNkR/ati8ipQkSjSdrpiTf4Mik9IQb7pIzOhxzP1QPJ43unLJPMflXbMG
         99jXHG9mNSL6KRPxtFjwuG4SXJLjST+9iKeeqGMvnynDzv4/lCJ/NPkWXrJs/fJIOhRW
         fTYG54F98QnqqHpIRGTuk4HrfSlhxoWBzZGfL/fsuUMTpDK0a1ruNFODPRxrdkU8+6E1
         LdEIks6NiH/MjuzJ1Cbu/bE21GsD4HK6klEhRJuq/mkX1ja8MRnlfqDefIPsqCc+JXm7
         x5IVmzP665McAHVZa0p8N7/tS7ddd8qsTZ2/u4hzroEfemTJ0/xSzmF3if3LZgZSlY7J
         UnIg==
X-Gm-Message-State: AOAM5306FgtJjZA8cvsHyJaP6dnqU1VdPZluLKPnLQ3j/zr9bDjK24tr
	1RbhsGwsIRHVjSzl9m5w9F4=
X-Google-Smtp-Source: ABdhPJyppThRtr0pIKKsVvvzMRtHl/EvNWeazW2xZNa8MrqIc6vjoxPQoDBWvZxNAxI2p8xRujHBSQ==
X-Received: by 2002:a05:6638:d0d:: with SMTP id q13mr8009818jaj.141.1617878211359;
        Thu, 08 Apr 2021 03:36:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:107:: with SMTP id s7ls832625iot.2.gmail; Thu, 08
 Apr 2021 03:36:51 -0700 (PDT)
X-Received: by 2002:a6b:7d4c:: with SMTP id d12mr6194494ioq.162.1617878211051;
        Thu, 08 Apr 2021 03:36:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878211; cv=none;
        d=google.com; s=arc-20160816;
        b=ztGORktltfukzTUXxwVJx9yW1DVnKba+X3dz1w4m8Xi/CV2JWo8/gytuFehkBFSP4m
         33AOu0nq49UVfWYcfdwTLXQ7KIlL1QUn3kir6n3SNLJNVfcCQkHXwop0p0Q9wdzwjwY+
         PTaiXYGoh+MHtWIh8OX3obrOlFzyEVzj1SnIWQf0znz3/e65eh3NQooODb84Zny1wYx9
         DWlbOvRfgYNdssdiGIbc4PPOxddsqs1aDchczsJehoJUkc74A/m4fljBnSnapvFZMHQC
         MJMtcoOD2MnvPZhodnGXdHJmzBxT/dS2KtcBLKqckRdIlEZ24dsGRv9hNf/Pz/jLtfdP
         uBVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=RsfSzYLxgdWoAhPhCR1Dg9aZ0g82F67d3GS+eLHn15c=;
        b=alHrdDEE/OIC7Gd1Uh4GkEVUdybzhUeWVSp+JhDmj+3s6sXBnj7LKq0MTshJ3WHUdO
         l2NKGFXe2arkJLz9gkrpQ84tr7FV2nl4w0cO7PUZENbY/aCR43ZB+BpSwhv5uTSyWJe1
         DbP2Ruc4C6dmNs82XUvClTIbQ2TmKxhc30143cBoxsWV9vmfwRv6xEyxvCfqdIrZrUTa
         Kpog8KACt7Tq7qvytX5P8jELlKnB71G10fQzrWxnYWPcFZufLD4OPVGCtjzBxoA2JWd/
         r6u6Y3eiyMVzcK1pcFc8RP+vtQSFfeP9+dZqlmgTau+wDUqTD9Gf30Ix0mW444m3L5aD
         wiRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VXjEJZGn;
       spf=pass (google.com: domain of 3wtxuyaukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3wtxuYAUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id y8si1743084iom.1.2021.04.08.03.36.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:36:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wtxuyaukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id l11so869405qtk.2
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:36:51 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:ad4:4f28:: with SMTP id fc8mr8186684qvb.10.1617878210503;
 Thu, 08 Apr 2021 03:36:50 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:35:57 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-3-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 02/10] perf: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, oleg@redhat.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VXjEJZGn;       spf=pass
 (google.com: domain of 3wtxuyaukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3wtxuYAUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

As with other ioctls (such as PERF_EVENT_IOC_{ENABLE,DISABLE}), fix up
handling of PERF_EVENT_IOC_MODIFY_ATTRIBUTES to also apply to children.

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/core.c | 22 +++++++++++++++++++++-
 1 file changed, 21 insertions(+), 1 deletion(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index e77294c7e654..a9a0a46909af 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3199,16 +3199,36 @@ static int perf_event_modify_breakpoint(struct perf_event *bp,
 static int perf_event_modify_attr(struct perf_event *event,
 				  struct perf_event_attr *attr)
 {
+	int (*func)(struct perf_event *, struct perf_event_attr *);
+	struct perf_event *child;
+	int err;
+
 	if (event->attr.type != attr->type)
 		return -EINVAL;
 
 	switch (event->attr.type) {
 	case PERF_TYPE_BREAKPOINT:
-		return perf_event_modify_breakpoint(event, attr);
+		func = perf_event_modify_breakpoint;
+		break;
 	default:
 		/* Place holder for future additions. */
 		return -EOPNOTSUPP;
 	}
+
+	WARN_ON_ONCE(event->ctx->parent_ctx);
+
+	mutex_lock(&event->child_mutex);
+	err = func(event, attr);
+	if (err)
+		goto out;
+	list_for_each_entry(child, &event->child_list, child_list) {
+		err = func(child, attr);
+		if (err)
+			goto out;
+	}
+out:
+	mutex_unlock(&event->child_mutex);
+	return err;
 }
 
 static void ctx_sched_out(struct perf_event_context *ctx,
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-3-elver%40google.com.
