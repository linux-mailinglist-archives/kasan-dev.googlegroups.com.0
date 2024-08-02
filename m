Return-Path: <kasan-dev+bncBCS4VDMYRUNBBNGOWC2QMGQEH6PFH2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 1581894555E
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 02:24:23 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1fb44af00edsf4960025ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2024 17:24:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722558261; cv=pass;
        d=google.com; s=arc-20160816;
        b=OlYnriHShNw+UmguPu+7dlSAAl+OfmVOuETeTdad3EX4aeW1MF7WRbh0yHgas4+uHz
         1NSnWUtQqs8M0UMBWtYoKLabCnupICJtCBS3IZ0A00+iEYlXKQPQqyfflYn0/UGWPof5
         VCCkTvPYx43+k0d/wcabdKfzn53p8l4diMXUWwTr41yJMvar5f8Vmd5UjXupdWtyVvfA
         SeLzGAzF3BvuZHXjORpP5rAc8emXxAwyZfqNAV95OQXqUVKYW1Y/Sx2sKN0bdRF6pccs
         FUZKTxfFwOzFhH366w+n2rqgvmiaxUNnGu3ZhwH4w7OScfB+MYQFJuAm9TD1r9e9rqCi
         Jq7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MlbDWnHSG5iR/tYZ5g+K7KQ+sZig6CWRvVnPudhZ2uM=;
        fh=vv2L8BpfrgOLPpg27i3tjQ8V8KD6bugs9rW1Xhxqn88=;
        b=hOgVnX3xtWRIUJv/fOoqlh/yg0EGM3CnzIMPVljvzLB9lnXN42cgEiMq6mzyk75MJY
         pzCCr3tzsieXrMGDW0aTXca0UkIuZ9P/yRo6/OdXBDdA9Qy0v24viJUYSRpAk0lC9CA2
         ZClDmh0d4TWv3F3sMWJzSijXk3kdp1rI0W9pNc9DB7zv6lScSUamWbM4j2xa1HEOt6Yo
         S+e9SgFyResUmnSVdek1hpNaXDrwCt8QwSXjxGBBtaGthLGTGW1JuhfkGPAuwvrPXa2F
         x/7E/Dg9ebV6c0bmfcmhEb5Q5iqVJtq4U8oU0fL4rwwG+YWAr3yroznmUmIdUv+8PmSY
         SQgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iezjY47u;
       spf=pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722558261; x=1723163061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MlbDWnHSG5iR/tYZ5g+K7KQ+sZig6CWRvVnPudhZ2uM=;
        b=IN6OcbL9lVfkGBdBlX+qTS0x/5UJnCLnhJcaUKkx5tpDITyDFw2OfNfBZNTAJQq+Fl
         9Dpqy9DF4lt96Ju1CsLHbe9mZ6tIDbimKlVeSsLzj+9kif75p5hL8kKr8d4ZW2SmwGC1
         nrqehaFLDH7+KHAhvjEhSZm7JRQdL+8xpLDAT8MgdjFAPhoe/G/DEHrYUVla49kyr1NF
         ny/lY1C7sOEQBVu7cqCg2x8edgwCOFfYcmYJah3MPO6n4MhYwvDQquQWuzq9Znk5C/1u
         OoFIZYpbXwEjiV7OY98gibzH2KaOkZ8/zkjBw/rWi9IdZfDmBRB5sXDIgW5z7MajOlhI
         kvRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722558261; x=1723163061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MlbDWnHSG5iR/tYZ5g+K7KQ+sZig6CWRvVnPudhZ2uM=;
        b=L5N4gZ3k/lZyh8aODntF9b0QbfHHQcPelKZlxSbSvzEfBRKq39xdmJtjG/yB4kBXtL
         1znwyXtqFjk6ZjlCFUb3Pd3vH2LGKQjk8vUXl6OQwmNRTbOGCvFoEpmsNMqLpqhZJ9bL
         ZwUvvvtBld8JpV9jJrHsIehkAqGPJsug/Xzw+0TiyZANfxq39fsyW1AFYHiOQS6aZ/0m
         TZ2kJwPSN7voDDCIGuzvDnTGgOPTDhLlm/ygZY+MoRwCVfGQjfnmS/aQqBoH2Z/g7liM
         jCxXYBW7ApYJmtrBuGR4M7tsfQeXGomuzBF5w3aZSaTQ5Jl4K9rAV6EBr45tMzI+6JAL
         ENVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUvAFwMmXs5elZeoGo1UU9l5zeZcn55aQuXC6x92plbpo/h1AIsQuojWgjNCtsS5ddzE0/wZMJco+KbxiZhpCqxM2k8IkP4Vw==
X-Gm-Message-State: AOJu0Yz/r3JgOcwO7fNwty6/FN6Cv/AVRsMad5LTjTk/5DJsh7WriEd9
	KA+P3313AIJFuZSOtGzP6b0+nhJlCWfz8IPq5ui8kOJoSZRGu8rx
X-Google-Smtp-Source: AGHT+IFS1/42EnAodVoghOa7esGf1bmGtTwvSxaj+7NlXazg8pY5R0uMHa6GAys/ZNKyPIQCu+IXVQ==
X-Received: by 2002:a17:902:d2c8:b0:1f3:61f1:e340 with SMTP id d9443c01a7336-1ff5d0b3536mr458555ad.13.1722558261166;
        Thu, 01 Aug 2024 17:24:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:190b:b0:706:a89c:32b4 with SMTP id
 d2e1a72fcca58-70ea999b630ls6800437b3a.0.-pod-prod-06-us; Thu, 01 Aug 2024
 17:24:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNPEBvShaXXx79LigpQPdH5WARoGxFnRazhD332J7J3IPlcxu/318TSwk2a9YIHGlgOOunyUpivW2b5+JPFKIlKQvLXNCSTJm+PA==
X-Received: by 2002:a05:6a00:4b4f:b0:70d:323f:d0c6 with SMTP id d2e1a72fcca58-7106d02dcb2mr2435105b3a.24.1722558259695;
        Thu, 01 Aug 2024 17:24:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722558259; cv=none;
        d=google.com; s=arc-20160816;
        b=aV60uTz44It12IC3UNfAOK8HGUUnnMU0bINulxf7q4rb6jr5BxKYIeFRil8zvFfQyY
         Fgl1qD59Os4V+kRcozFrMCfnyPHtZcUYqPS5GrgSQ1tYd0gShp+/S52UF5MppxXUILI7
         gav6bKIT6JVbDzCc9TBye+gwdVLHQSiYukUs85JiAmz9kkgO9WpdnQ9IDgvlwA+y3y/X
         k4f8vpIeeCJxwP2igB8Lf7kELjNsFfBR5NKJvml7AIYdHJj3OVurS/cymRGF8FOO1RoB
         HJpNoyfpt7iWQAGnmlcWkRA0qeJUoifHukHy4eO9D1ai+OtaoIbDxTOUr/pvMlTLxYwx
         v2Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y9bHa5zih9Fy2K+eFY3pLce0vlvA2kzOZVzc7FCsfUU=;
        fh=4dY1hVQ62kE9zRtFb8LgyiYYnSp/AKP3UnMm22jDMN4=;
        b=fBAp+F9Wv0bqYElLUhfdmDpIoft3O85jE/ptv6DYqRUuK5Upe342YQbHjaFfqd98i1
         HLHKxQ77StzTTNIOAYLXu4DjCywLTRPnuGIyWNsFy8n2c9gExR26O/3ADhQ5EyX5H4Rj
         6G6OdN7okwF/Igbc2fQ6OAsZNPgkpvbuTt1UUfdw07g26c0KVPD4R+A/GRBTRvt60S+t
         O23RuX7WoHpN6xQTkjwKE/kxcyUhJFMdsG1CQbnLhj/u9w0qxHuOwlOItkVthGuODpM7
         UtY+OQx4Z/ZVfUdQAAw9BaXy7k4r3XyU4PMO1Vza/0B9qs3LDRmQ1TSCeL5ub5NGiVkM
         VFwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iezjY47u;
       spf=pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7106ec40f72si49227b3a.2.2024.08.01.17.24.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Aug 2024 17:24:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D84966298C;
	Fri,  2 Aug 2024 00:24:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 96184C32786;
	Fri,  2 Aug 2024 00:24:18 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 46AC4CE09F8; Thu,  1 Aug 2024 17:24:18 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@meta.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Thorsten Blum <thorsten.blum@toblux.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 1/1] kcsan: Use min() to fix Coccinelle warning
Date: Thu,  1 Aug 2024 17:24:16 -0700
Message-Id: <20240802002416.4133822-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <b5ce4d12-e970-4d84-8f89-fd314e42ed30@paulmck-laptop>
References: <b5ce4d12-e970-4d84-8f89-fd314e42ed30@paulmck-laptop>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iezjY47u;       spf=pass
 (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Thorsten Blum <thorsten.blum@toblux.com>

Fixes the following Coccinelle/coccicheck warning reported by
minmax.cocci:

	WARNING opportunity for min()

Use const size_t instead of int for the result of min().

Compile-tested with CONFIG_KCSAN=y.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/debugfs.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 1d1d1b0e42489..53b21ae30e00e 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -225,7 +225,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 {
 	char kbuf[KSYM_NAME_LEN];
 	char *arg;
-	int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
+	const size_t read_len = min(count, sizeof(kbuf) - 1);
 
 	if (copy_from_user(kbuf, buf, read_len))
 		return -EFAULT;
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240802002416.4133822-1-paulmck%40kernel.org.
