Return-Path: <kasan-dev+bncBC6OLHHDVUOBBI4HRL2QKGQEDZX4RQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id DE0AC1B6DD5
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:13:56 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id d7sf6224946ooi.12
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 23:13:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587708836; cv=pass;
        d=google.com; s=arc-20160816;
        b=pgVlTJJiN05hCRAYht+q8Rl2NSrMx0cKfw5E9aR3ZybgNPlDqQ+MRQIBcE9H0ctLuJ
         ouLLwGHOC1LfqvJuYgokfGL1ufOQAy9odVymyVappvxwKMcohveVUWc858+IyafZ7WIo
         bSr7oAny13Ai1ArG8FzkSxNT8UryWhjCzSEYZWNQX8No2uBJwIoWfx9/nCW4dge6CS6B
         XjTgHx9IQWH0GtaUK80b+rZGpRxvZE+jYc/VCNU3At9xdEYE8R83xP7P3dV6Cdo7+Zvx
         5j9gOzOp8pCPDl1BjnC5U+MwzsZVTzvI2ybR6e7FtNX/M7bkfLKfTebI5Ac2JrJ7RIbh
         qgXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=vUqsKEOHp2VQ5mhDShVa13iXGlvrMjdY3iC5tbi/Qw0=;
        b=T/9cL53YL7+fxJqux8w95Flpj+AF1fCWIpQsTIqAYYYOfN3XgtXoovivSP5C2kRg2f
         kqeXXgDJDneuYJz4CBebQcGZpBgs+LtjmB3kcr9QVWU7pwvScVK9sGUAdwpFYWnM3EAi
         nICkxqvBE8Frn8Q5QOEm7NT69PxxaXFSS67TqW/WcCEfL/B/eTqcDb2ONqkpRyZRIhMN
         Iv75zGS8+t2UkhZU7Qa+FQSg3HtWISU61w4dIfQ1VOFIqbFTp/g9yNp8N2TWyTCdP+ed
         G7M/buc16Jlpwd3XOGxPWjzUNptCJTg5LYmqz+xBvIWQ5phWjQbiBpiVLU90W2I1t5sN
         xZQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BfemyIP0;
       spf=pass (google.com: domain of 3oooixggkcs8olgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3ooOiXggKCS8OLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vUqsKEOHp2VQ5mhDShVa13iXGlvrMjdY3iC5tbi/Qw0=;
        b=LYZqNT/p80Y6gdT9E29af2eftmaUKPL9+9A5v51cOZL/wOQeKHApNvlsh4vLHbYIPN
         b9B88c/jZ5U/ZeZmIFQosQTpPPfxa3x/nAb8zrP3uzsZLGpqi5PlYkIUACGLs4ylfimg
         QJtN5ozmPqDj4giamMgrNtR3UnlNxxIP1HYVEKpzGD1ARXZZDQ07Suk1zBpilmVIVyWS
         FZrOZyD2j3fT2yubAZItD4wqwMVTf760+z4/C6ue7dcjamK1+vHL5Ss7WU/cWGJuw25H
         yVK3TWZh9+quONLwBpgaoqNHZ1l6XeGrS0gXo9MBQTh4y66i9b9koAx9ZfWGeM5XYKOh
         gmUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vUqsKEOHp2VQ5mhDShVa13iXGlvrMjdY3iC5tbi/Qw0=;
        b=pwz9a+mac+lbvmkUdvKYPe0fIYf74pzp3sPkvMV1VvkGUsdEUF6K0C08KXdLL7G7JC
         S9SH5JmG2Z3vrDJJVG9zxmCPwTf/WEef5BasMo3pDkNHOBlvdoTeHKVXwwfv6Lp4tKBD
         f+ehrNqH/6LFWLxYKB6bljHrQ92zEQqJNeZK4TV1lwoMGFU8JEcL5L0BWHkGeDNEW3rS
         Pz+K9EAe/0RvR+EEBKT0013TCWBOvTIBEPHlrs1x4w4J53nWGsNIdLxMFWcGh6ClwdPW
         FpovTjFtHnsySZXxBrJi6r8g2TCM2b/QjAIfSwVcH1UKSNel06uD5kpAaoLaAi8zSfWl
         q46Q==
X-Gm-Message-State: AGi0Puap/OREqYE8efp0dpnXx+r/UeXdzrCFT2XwXgxbhHPmt2NMjb/q
	NmXx3IxY2XrloSMPqrJuf5g=
X-Google-Smtp-Source: APiQypI+CuVpbnqed0e1DeBKcnQLwv7BKn34rWbsFmFJmjJdWnlI2rkY0UJGRqjlcVmi7VTFfk3DGg==
X-Received: by 2002:a9d:2da7:: with SMTP id g36mr6305682otb.57.1587708835887;
        Thu, 23 Apr 2020 23:13:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:108e:: with SMTP id y14ls635992oto.9.gmail; Thu, 23
 Apr 2020 23:13:55 -0700 (PDT)
X-Received: by 2002:a05:6830:1e68:: with SMTP id m8mr6508535otr.340.1587708835474;
        Thu, 23 Apr 2020 23:13:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587708835; cv=none;
        d=google.com; s=arc-20160816;
        b=QS2kplzj7No1m+Dk+36sGrBscRbFDdPyyai3Ex9VrgYeQkCqLhIh7HhfoqM40ivDnz
         orMnh909FKgVR3FzRVXV2fQXpmFQNQ1iO5zzwjlDUxZZUmnk7a6RMACYvN20BxzXsLwT
         duYwOZjqCBk45PReRJlI3kxEB3gNZ4rdxez658Pn6mBz7JoYeidn9ckwFgJwTOtmkB0s
         iwUYndNfT5+3CPxA+ceY9POkx/6Hfo9hWPx84z6Lyp9WErgDKTSOvFmwy9twP3+RbKuU
         sts9TcE1RNeI2/AfucGu2jM3NBoXQjVACBdKr2HVcaG8ZEAJFJi0uNNecAOe1xD6dKgb
         v+cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=j69Gvq4vK6TM54rY0b5SnTVA9UkpfVZ6E3MyvEyHlqI=;
        b=csh1fViMfe86cRZ4L7a98O4/ADFeXMjrP8vT/J/vjhYmil2dbVxfPLsKY90ZZWIu/Z
         q3UlLqfGHpoEfEUQWFEZI+nWhTY/ImNyqGdN/0V/zP1c+H+oiy/ijyM5h1936uO2X7WM
         n/5yetJ3nB8dTJmjCurrLMWjTzd6zWRhhx5UZt6QFiMR7mAI9mBtGZJFcLW5PklDfudU
         fjjEI6pnWpocn6ZKFlGFuuq72YeLf291geb1crpAYeUxyjXFt5eO1ne0rFT6AkpI3kU1
         RrmPTagXL8rrDefbcwbx5DroOgpQ9Nb8hrGPcYUU+RkboRgpUwRjf9R+2zDzmrB9Eip7
         aI2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BfemyIP0;
       spf=pass (google.com: domain of 3oooixggkcs8olgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3ooOiXggKCS8OLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id w196si626929oif.4.2020.04.23.23.13.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 23:13:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oooixggkcs8olgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id h2so6830353pls.16
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 23:13:55 -0700 (PDT)
X-Received: by 2002:a65:58c4:: with SMTP id e4mr7831219pgu.61.1587708834690;
 Thu, 23 Apr 2020 23:13:54 -0700 (PDT)
Date: Thu, 23 Apr 2020 23:13:38 -0700
In-Reply-To: <20200424061342.212535-1-davidgow@google.com>
Message-Id: <20200424061342.212535-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200424061342.212535-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.2.303.gf8c07b1a785-goog
Subject: [PATCH v7 1/5] Add KUnit Struct to Current Task
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
 header.i=@google.com header.s=20161025 header.b=BfemyIP0;       spf=pass
 (google.com: domain of 3oooixggkcs8olgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3ooOiXggKCS8OLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
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
index 4418f5cb8324..e50c568a8dc7 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1188,6 +1188,10 @@ struct task_struct {
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
2.26.2.303.gf8c07b1a785-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424061342.212535-2-davidgow%40google.com.
