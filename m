Return-Path: <kasan-dev+bncBC6OLHHDVUOBBT6W2T2AKGQEVAO6CRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BF091A7195
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 05:17:36 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id y2sf3811508ilm.8
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 20:17:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586834255; cv=pass;
        d=google.com; s=arc-20160816;
        b=z0vEsZl+IV9E1SKEnMf7M06whqwqmuoDcvkjKX7cuufBeN+xNbUt/0liIg0iqtQhkM
         PhJhInLdc0OqZXacTE7StoqwwZ5M/IzKemi6Sq8JiMTzo6sMJni+NDtCfYIcZhf1waqM
         DbsS3EosMMhSK/aTmFM0k4vG65XYhYLkkshoTNr2ADUtGcV/Tt2/6PH2ZZshrlTVx2ae
         gITPW4aUpIawtggkcemviV8hzlS6Zs88MXdSqFXvhuEOn94AiYwC2VLoTtyZ7YTockna
         ZSq8RHLj0Vlb9ZFXRd/JSuHLVJ55HZBG3QyE9JpW863h0vsH0zkEw78sUrBhloFCr3f4
         /S2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=YUpwiG7khfuP/lllo3VoE9tifodrQEb9jjAPqPirwnY=;
        b=0xnh8E6dov/R+rAXquM3L0XI1W1nKPks/cv0LarbFt6rEl3tVL+Zif4ly9pieV+OtZ
         vaYRDAG4cQJGPIrj1cHQ8gPbRxteonY+Lazpxd/PNufneuZgdpF0Q93+4Z+NdD5ZXBfz
         IOxnRDsKR6X524W/e5vK1wZRKk27pjp7qpUpmw7EZPSiHMG69OsaBui+tZswyGgNGJOe
         q1f6aTe77YWyIMR9TKXtRieDQAFd7MbpthtdjyqIL4XirEfQ7wQjlHTJjZEMYs804wHP
         nf2zyIywo3PBiODP4BfI3rjYvyUAulSzW2Oxtem84UhDBcYNRiKyRC3Gee1hJF+uL0RJ
         kpzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tniFeoki;
       spf=pass (google.com: domain of 3tiuvxggkcfmyvqdybjrbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3TiuVXggKCfMYVqdYbjrbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YUpwiG7khfuP/lllo3VoE9tifodrQEb9jjAPqPirwnY=;
        b=kM4vUHBo64+vKIey8GNc9F4icyAUsuCMo/v900ueXC4mzLood6UxZFbjyynJzR3OTl
         MJ1mC0nvKkJimY2yICa5GrvfugwoUIf9Cjs0keiBH8Yf2YjCUb+B4i7jk6wu+oRWbMXN
         HWg8OINPbSwxr6xOkIH+LfVJJMJHL+eKA2pjON7HJxziwJ8JwiP6lqO7dOneiy8xH03/
         K6st9Q+HpI+TAUFVB58QVW9Tqbabg9thOhpi5Mqm7799Si6gIIgvAs9ydNZBFvqGpRmA
         zaV7RpgEbKYrRpjifDMWHrFtkiAnabWoAjtvxm/ML9mPFij42X9IDhBgzwpzNmAYIwVX
         jYlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YUpwiG7khfuP/lllo3VoE9tifodrQEb9jjAPqPirwnY=;
        b=W5phpDbbaudg/yzxChMXvyGbiNgHQklJOW3ZbOLVg9H50l/8hfF8tY31WVVZf9HsYa
         E9+MvIEKyl6ljCSbFrHuJPmLpDz6Xn3YIUKkLPXDO7BFr6YjUseS9xPcefTlmTcMysIH
         /QmRyup9amDEvV7XB3ktwD+EDAMYbYw3ov/qFn6XN7s4wbT27bu7N9JUgSsj2wTeFw+V
         dI4ueGhu+fYDC24+Vw0yjahklHFgjZqPiDKdD0jFU0uui8EzpXpjEkEw63k4+rs9STcz
         4sdAkJLK157PNOO2uy++VEcU+oyKfbEtxkJAxSv24XmXK64SSPkiogH5mb1FfKZc0KrH
         7GAw==
X-Gm-Message-State: AGi0PuaH/p0aibNCmksB/UIz4I7GerWQumsRhs+cetNhkrP9O9svFwKJ
	NSH+H1wjFViVSQ8XZdnwRYE=
X-Google-Smtp-Source: APiQypKi7QNZmmzbp8IfiDa7Mo1Kw9Fl8IMT9ZL9KyrtN2gNIGe5L7MgxE7XFPxFTXl1ZToYJ/MGBQ==
X-Received: by 2002:a05:6e02:f43:: with SMTP id y3mr21537869ilj.112.1586834255120;
        Mon, 13 Apr 2020 20:17:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8ac3:: with SMTP id e3ls643330iot.10.gmail; Mon, 13 Apr
 2020 20:17:34 -0700 (PDT)
X-Received: by 2002:a5d:905a:: with SMTP id v26mr19030305ioq.39.1586834254669;
        Mon, 13 Apr 2020 20:17:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586834254; cv=none;
        d=google.com; s=arc-20160816;
        b=A2pBjYSDs3wF/zAQjkAtDpklTpatqCtYAawB9P0HGW2hwiOH3CiyM6wgYas7qD2z1J
         +KkwbvtzSxHxKbv9sqwvjUL8Eyg2Ritr7mZgf+jMN6LVUJzth2eOnKdKvzHgkpEuJUVg
         6DNHnm0Ab423EZJ2QA0qHO+Sor3VieVNXlKZP8754EINQpQDJ8aUfCSKfCd14qxQo5YP
         rSDO8U8ObtbwnHbSofqfk1p68OTlgdM6mLhxJSXQB7+aEDkkInuRFSVmJOhoqz8UzkI2
         wFDOnUE8f+qZnXZZSZc9siUW5Kfo2ZQPp5cQoHwtCPm6VKkLCrbtSPG5tQEtOAymPj91
         7w0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=qmS4Dws1dS9Cf9mpNh1dkBLiz6hqHz5k1HrVTs3BHIU=;
        b=dyjssdPeJDACfwc2GSGbA7PRxjvzpyDpu2Hk0sKfcIC1N7ykBvlC/j8rg6rmvgUKEx
         MtAjQ5257gerZGWbrXjGSWMNq7nVXIv4ZZpsI1Yw0BGp4fKo3KcvVjMwC5UMnya7z5RI
         A3la6VNp0VCBKFQItky0VjxqC7n1yUDh2veQune0z3hRRh3qjIfnf8TFLbB/hsYFUjTm
         2qw4V9QCXT/IhIg8xli5f+Swnb840wHmmjHUKDdvEAficz9JbEBw/M0xOLrdbkPhkEzg
         /VzZpOKLI1bCegDnCnM0yTXvihRFkGbTdretZK4CZDJvWwCmxyhAqANW9718L8H/j20y
         hqTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tniFeoki;
       spf=pass (google.com: domain of 3tiuvxggkcfmyvqdybjrbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3TiuVXggKCfMYVqdYbjrbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1049.google.com (mail-pj1-x1049.google.com. [2607:f8b0:4864:20::1049])
        by gmr-mx.google.com with ESMTPS id g17si300722ioe.0.2020.04.13.20.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Apr 2020 20:17:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tiuvxggkcfmyvqdybjrbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) client-ip=2607:f8b0:4864:20::1049;
Received: by mail-pj1-x1049.google.com with SMTP id o103so12140243pjb.3
        for <kasan-dev@googlegroups.com>; Mon, 13 Apr 2020 20:17:34 -0700 (PDT)
X-Received: by 2002:a17:90a:ea05:: with SMTP id w5mr5197470pjy.143.1586834254059;
 Mon, 13 Apr 2020 20:17:34 -0700 (PDT)
Date: Mon, 13 Apr 2020 20:16:45 -0700
In-Reply-To: <20200414031647.124664-1-davidgow@google.com>
Message-Id: <20200414031647.124664-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200414031647.124664-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.0.110.g2183baf09c-goog
Subject: [PATCH v5 1/4] Add KUnit Struct to Current Task
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tniFeoki;       spf=pass
 (google.com: domain of 3tiuvxggkcfmyvqdybjrbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3TiuVXggKCfMYVqdYbjrbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--davidgow.bounces.google.com;
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
index 04278493bf15..7ca3e5068316 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1180,6 +1180,10 @@ struct task_struct {
 	unsigned int			kasan_depth;
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.26.0.110.g2183baf09c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200414031647.124664-2-davidgow%40google.com.
