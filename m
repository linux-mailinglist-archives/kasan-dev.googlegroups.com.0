Return-Path: <kasan-dev+bncBC6OLHHDVUOBBR5KST4QKGQEDDDFYRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 71FA12350E9
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Aug 2020 09:10:00 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id ba2sf23911923plb.0
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Aug 2020 00:10:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596265799; cv=pass;
        d=google.com; s=arc-20160816;
        b=HB+BzPD8upDuSCE35rfsfXaRMcCkAU/JJF5oMvuUDMfV6Wb6D2eIotfs2Fcn7wzM5o
         K4MKUtm8Gsjy8gBDuqt23nA57dfr+mHLhZKMMz8cV/vMYKaqDbij5rdMCdhSJCNx7GEG
         mYXa8lIigpmnbSu6/8h2KiYCsIioMb7Yyz1VjZrkob0D9+HjlaPjs6vdpMy8FDhPfKsY
         2ZihQx6pbuM4P5mZJqaMoUUcFoziFNIr8Jrxc/Eh0oWAxnvP9eYMy/FjDD8iNYMAHThm
         11mUcmU8rz6JeX38Al8oLhfqgB5yPl1phCKsC4R+i8uAKWoH7GcXB6E9a/5zr7+8kfZE
         RNGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xbOBzxEooDsIaS82ldks8RMLWU5mn0hj2PMUCkRUUxw=;
        b=hg0paIlI0MqUzkgT/Nk+QzHZaFf4Or+D5Z+cL4+INPNnFRWwflUSWjeMciVzDD089N
         N3j+WKYEjZpJLr/8DSaeHya790PpFS1muyQaKlXDR6VvW1JRTBAREHyjKta3PqBiB5IL
         0hy2VeRL+EbN60VQ6jXXdwsz+hGdlFEV7EODW7a9mTBSkBbz1oou6Rq+EZ1MNPXLEE0v
         hQ6cZK5AS2J64kChMdaSREPVLQSmsYF9182wbG8p1rpkHX/O5iQkf4R1EQKN7B7Yc3EZ
         U3JJOd+ARHABPPCe0t9b/DXPr7bkYr+BbLR8u8kcxUDuXyZhD/zZ2majIo8orqwWAgJ5
         n5FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cdRSBdXu;
       spf=pass (google.com: domain of 3rbulxwgkcqmgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RBUlXwgKCQMgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xbOBzxEooDsIaS82ldks8RMLWU5mn0hj2PMUCkRUUxw=;
        b=KWMB43FNy12mofg9WS2knNTNLKFefgCqyB3whtD6vpR6xOpo4XmpP6xu7sYP2cZ5fo
         9GEg86QSOc6VNXJwdASneFg3ESNrTywe/RB90xiu/EYA/Zwu9Bf363AU4YskRv10XPS4
         RV26ZAAaNpqPqVh1JDgcNkEjx7DViX8D5pb0gooDk3zSen4SwLlHs2bpLBLihQjFlFGy
         21jHDd0F/a2FczgimJJDargPCxJYEGIuU+Hr+pZM8hWR0BOOitkN3ygn6PEEHoG0Nlb9
         X7+NgMCqFxUl18bVVF2/HWAHJtIPfJkzOmHo/A8YEgcXfR3GPnc0n6mNYMbpnserOvwf
         i4Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xbOBzxEooDsIaS82ldks8RMLWU5mn0hj2PMUCkRUUxw=;
        b=nIxWpE13sur9sjcl1eGwH392oUygeWaqp+DDscz9pIyIzmQorPiqjAA/GpAIJsGB5k
         A5tElj8gOZPq23tuTcgggzoKk2wRw6IflGkKpAfKOJDhdZJ2E3ToFw9M4yVCCAdMskmA
         vq3a5WV85pgBfHkE7CVOcnsLDw/RBVvkKTDI4n5LfJM6Ng8qgZzcCPXGKgjqlcS0N5im
         nCda3+3/Ug6KahHOEIWANaimaVajcck/V4on5rR/ysA2V5s3whJdLDIvwVQf/g0I4yLF
         G8lMOKTo+Hw4guNOu3ktdD7LTit1PW+oxcrhBnCBdz0YBR4K8fQAjvWgvypvweFtvLBC
         VzbQ==
X-Gm-Message-State: AOAM532R5hLpssq2/zUy7Z0xfxMCeVA1H9BEZSNpu3IGLA9SSMhRqM22
	Aa2OD76LT1jH4oH//zdjlEY=
X-Google-Smtp-Source: ABdhPJy/EYekFnAXJr3MiJKQm6dBMA+n6rhCSy97SKyaGj00fPLhW9NcZsXasyAQurNUZns24q6nYA==
X-Received: by 2002:aa7:952d:: with SMTP id c13mr7433387pfp.198.1596265799139;
        Sat, 01 Aug 2020 00:09:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7616:: with SMTP id k22ls4625664pll.1.gmail; Sat, 01
 Aug 2020 00:09:57 -0700 (PDT)
X-Received: by 2002:a17:902:e78e:: with SMTP id cp14mr6706221plb.182.1596265797746;
        Sat, 01 Aug 2020 00:09:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596265797; cv=none;
        d=google.com; s=arc-20160816;
        b=wn8xHQ9B6SkNR3fdZIoy7s7W7FRk8urAK6CN/8mbo2S6KQfS1DExlGmsreruDD3GjO
         sFYU75S7duoeeDvZxYD4BP+V869zyt3fDqVX/5qPSiwgiiM24sFa1YQobvl0wgQAOXoM
         3h8p/s4n0gK77nA+2t6/zjQdhdgarlEQCgn2sLhotdDHKHq8qZxgu1zzkuQFZfQhvE3a
         cx//XMNOrEZWaPuSmIJWoQrzGU/fAgupd3QBTmWegviE+ZrW9x8K7s+L70pmwe2EqDqP
         1nSrTDJe90ZafaqCWfkWj+FJ5FlJs5E6IGQP/LhkGjRV3PoSCKwFA/rbuMVTMcHqY+EC
         RqWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1s/fGj49wZAcV85LY6dM4ghB8ELbpKuQm5SC6WcoZ6s=;
        b=o6NjPQ3rswljfmWOL3OS3gKH5h3uJgago9uVVnITkJdD/cLOKsQhPS5p5bW/nWgKga
         yfM7QrkojlK2I+q3BsCT8junkJH3Sd2BE1MbQbkRlEcpXGm+5OB+6Cb+cbHnksk8zmbP
         I4AbAOYtEOR9k+HbVvhEASlHpTHdLAF29IWZX463UA6IxtzFDUwuXjtSvYacoe5EjGlA
         6/Zz2n74y8qrEJmJKq6L1y7y2/QN2V1Qslj2VNqM5GoFhQewZZ0RzUYGVFXVyRcmvBSU
         OJP4HoyKrBaZMtkF61F6Qn8m/+eq9sQmOapeM9SgW3oChJ/gd9ZWeOB7MYF+CEd6QoGu
         obZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cdRSBdXu;
       spf=pass (google.com: domain of 3rbulxwgkcqmgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RBUlXwgKCQMgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id w2si492990plq.3.2020.08.01.00.09.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Aug 2020 00:09:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rbulxwgkcqmgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id b127so23637436ybh.21
        for <kasan-dev@googlegroups.com>; Sat, 01 Aug 2020 00:09:57 -0700 (PDT)
X-Received: by 2002:a25:9249:: with SMTP id e9mr12571927ybo.105.1596265796918;
 Sat, 01 Aug 2020 00:09:56 -0700 (PDT)
Date: Sat,  1 Aug 2020 00:09:20 -0700
In-Reply-To: <20200801070924.1786166-1-davidgow@google.com>
Message-Id: <20200801070924.1786166-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v10 1/5] Add KUnit Struct to Current Task
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cdRSBdXu;       spf=pass
 (google.com: domain of 3rbulxwgkcqmgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RBUlXwgKCQMgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 27882a08163f..f3f990b82bde 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1196,6 +1196,10 @@ struct task_struct {
 	struct kcsan_ctx		kcsan_ctx;
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200801070924.1786166-2-davidgow%40google.com.
