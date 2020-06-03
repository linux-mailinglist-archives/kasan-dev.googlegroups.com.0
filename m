Return-Path: <kasan-dev+bncBCV5TUXXRUIBBKUZ333AKGQEQU7AY5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 43E111ECEAD
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:36 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id b22sf1733042pfi.23
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184555; cv=pass;
        d=google.com; s=arc-20160816;
        b=CNRHLD+Z81d5lrlFFlKYKk4iJTjwT33EAR8qJpQfGVPQr83ycKe8pnSXX7KepU4RGt
         QEzdpkWLf/ADspNrTvW84O19a50Com+Z7JLxTM/bP3721n7C77/CZ6OxqBluC6gmvJq4
         4xsuBVnylLgLyy0VoJ9by6aSHj1by3vNh5u+I19dS/D5NOOxuMPLUeRLcm2hL6niIqnk
         hXa907O2VE3LVYQJgIbJasH3FFSehSfvAeE1ZwEk17FPFFh0vn6eTPeTVNhfTNYPB1eM
         3V+pcfcYPuXVfnrzp3nr2vXalKRNQMM3IMasHDaImD/xs7NYevINf6XPa6OwwfdCOQll
         Y34g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=iGMiKbLFILb190af4af9FXSo2d+hAYWhxSTd3FcQeOk=;
        b=LeNS9YIiB8p+2/M3bEyNfiERj8D5nm23SNJ7TitEmDSF9ObgNFXszEfEMeIqD/Sj9o
         c0sNJXhs+NOWW9zaoPMyRht69O+HrWbVC8C+mp6/9U43pH6lmqudOp23yq7awEMVdXL6
         sUIbnRG1Q9snmz+3xUMyqq+PzfEYbJKnSFsN6MD2JlPZiZ+vGY+0EStggxeHLWL6Syto
         3nFZWxXyY814kKpq29vtNOTmMYIqQ//CxJ6ap0aj0iIT9uF6Smz8pdIHjCPIwxoEJVJy
         AkH3OjaagJR26bOXOMccDFPWaGsWUl0525pniVwYBVsWRPDyxGwLUjvwLT9Z3C95VCvh
         CJaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=oBxMVUoK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iGMiKbLFILb190af4af9FXSo2d+hAYWhxSTd3FcQeOk=;
        b=P2sRy1n+wfEg9d7TpzbFCYFGHd4odGBFNFmwSZw1ioZLLNtHgt4d7e/Ryy62IURSxQ
         2927wwpSZK7sj9qu0XIJfJ0wCy0Okn6Z29L3/4wzphAp7qCMemy8JeHGbOekzDWBbD5/
         uy+PezFcjThOJ+1+6ubhe/xIJhZBFWuFGmMFAIInXmff0IdVgdQtujKHV3JIdyINMBeu
         AET6SccG+BVtPqPT610gC+LqEL+qx+TZL5Qp95nExFEiU9rj75Xqb2US+pXbqK7CrU19
         qfUpEHSZDx03uGpQ+BTiPcZG5TifOahNj0OVnCfAMZVVtleLsM+wFnKZqeXa2OHOZN3K
         /83A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iGMiKbLFILb190af4af9FXSo2d+hAYWhxSTd3FcQeOk=;
        b=dJ4gSYDI1ktizjWvPoK+QinK4t81z81ZaN77oaoqhsL8WR+J9C2K1T+S5RFM2S9vOQ
         wJtGAZeBp8BoCdov8TzQiI5A0lbd2w0gN1iB5MkPfVwJvA7A92VLjziMX6Qfx58eMJhc
         Q7GJ1+9tKJXeZaUOkZ5mHkrG7kTS77ITbdgf5izAMUIewIGL3RylaZjDfU+5X7zKxxO8
         7+LcZLAyoCWyspynkjCCx4BDfzTcDEroZGxk1tCu2ZHeQmjNB2LKj9qNJwhVlZBXiWFA
         rbZQ5squSILe3ofiMxpHErUo1NWvrYTbcdmTie9wWIU+89LzbEkjhDogZegdrH5xULZm
         DAzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zWAYZOiiz9Tls/LZNsA2CmShisYcPyyOZdXaNlHcVAz74gpZi
	AG2ENJJZ4JVFK62dQLU9B5k=
X-Google-Smtp-Source: ABdhPJxMqbjEJ0m70KgjxfG5u814+NCf+j9shUj9ZtK/Ww5pjPs+O0IXXeEUf0EgcHTwNf2OVSmJlA==
X-Received: by 2002:a17:902:61:: with SMTP id 88mr1736127pla.193.1591184554948;
        Wed, 03 Jun 2020 04:42:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:55c3:: with SMTP id j186ls711235pfb.6.gmail; Wed, 03 Jun
 2020 04:42:34 -0700 (PDT)
X-Received: by 2002:a63:6704:: with SMTP id b4mr29031644pgc.419.1591184554579;
        Wed, 03 Jun 2020 04:42:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184554; cv=none;
        d=google.com; s=arc-20160816;
        b=uH3MrRf0plzEhhw/ZSMpaEWB4xxRcNAjVCz5Pz4sasfG6AY54wtpgCmhnSygKcZRrX
         Jxhq5+8pOm8SGciOpUyz5rBM6A9lk1lmeCU8n3qoZgGZW2uBcOT3hIqrN0/t+nSZUc7+
         SH1CXX0IkMOqz1UWiT6+tDPYNm2sFZEeZauVvzsp11UwiCQ/GGyrHn2NTegi+BqeKXhr
         2RAKQU64DsqxOLXvC29IHtEStVoqeKH6g454TtT9aVAMPEQ0+F955e2oDaP3+WSD+JiR
         LgIGVTvjOVElQRvHj0udqh0q6BPtr7pizfROHefrJqsOLWqYoI49SgoP/MxHOGfnwtT+
         uUzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=yPkPZ4WAEN9GaKTtWJwMN7uBHheFrK3ZxdnYRFtfdVY=;
        b=dtk/t8xGO6hUThl22+vm74Kr9mm2xvbbAT2HQBT5oJ4bZHhiakaPaiYLd2fpy1x5ab
         QqLqGsQKRBpxWUedaUubWP9/FLWCv00DR9N3wg9/+tji4mqpfkIvPu8fQRWFXChyOSup
         vz5lrb3NDKZwZ+dqggzS6cT7NPn5hzGMnal5EyoKFRVwg6LgNfs8pkPF+3LZUE7YroHS
         Z3EDNFcrl4pmQ/Ybvo0MMYbQ9U/ZezkChiiDGVvMyOhxgPhuIseCeNkOrfsL14nGC4KM
         8/XZWWWuascdpQDeo7oj7WKK6BToTiEZ/VzNJjF5y8Pq/Eh9qx4NDZdIcnPrNk0X5aUS
         +jAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=oBxMVUoK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id kb2si172092pjb.1.2020.06.03.04.42.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:34 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRmr-0005oV-F1; Wed, 03 Jun 2020 11:42:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 080FC306E56;
	Wed,  3 Jun 2020 13:42:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id BB489209DB0D8; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114052.185201076@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:21 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 7/9] lockdep: __always_inline more for noinstr
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=oBxMVUoK;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

vmlinux.o: warning: objtool: debug_locks_off()+0xd: call to __debug_locks_off() leaves .noinstr.text section
vmlinux.o: warning: objtool: match_held_lock()+0x6a: call to look_up_lock_class.isra.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: lock_is_held_type()+0x90: call to lockdep_recursion_finish() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 include/linux/debug_locks.h |    2 +-
 kernel/locking/lockdep.c    |    4 ++--
 2 files changed, 3 insertions(+), 3 deletions(-)

--- a/include/linux/debug_locks.h
+++ b/include/linux/debug_locks.h
@@ -12,7 +12,7 @@ extern int debug_locks __read_mostly;
 extern int debug_locks_silent __read_mostly;
 
 
-static inline int __debug_locks_off(void)
+static __always_inline int __debug_locks_off(void)
 {
 	return xchg(&debug_locks, 0);
 }
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -393,7 +393,7 @@ void lockdep_init_task(struct task_struc
 	task->lockdep_recursion = 0;
 }
 
-static inline void lockdep_recursion_finish(void)
+static __always_inline void lockdep_recursion_finish(void)
 {
 	if (WARN_ON_ONCE(--current->lockdep_recursion))
 		current->lockdep_recursion = 0;
@@ -801,7 +801,7 @@ static int count_matching_names(struct l
 }
 
 /* used from NMI context -- must be lockless */
-static inline struct lock_class *
+static __always_inline struct lock_class *
 look_up_lock_class(const struct lockdep_map *lock, unsigned int subclass)
 {
 	struct lockdep_subclass_key *key;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114052.185201076%40infradead.org.
