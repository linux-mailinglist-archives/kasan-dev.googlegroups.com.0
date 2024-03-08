Return-Path: <kasan-dev+bncBAABBL5LVKXQMGQEJHH5SBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id C6B77875D33
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 05:36:00 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2995baae8b4sf1355221a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 20:36:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709872559; cv=pass;
        d=google.com; s=arc-20160816;
        b=klXNcPHgdmRKhrou2e/r6n17Tngr8PF4e9P+mzsNMDF0aCI6Ti0ujD1LX1+PLP1k9B
         ivRwWH3kfgGmhBf1Cv66budru1cUPxVVZKUcIEBIRTDpCaqDQ1pHqlpprh905L7kcSaS
         9COnw9bpUnS3TwQgskLn6RbjjKt5vHxhntIl8ZRVs1e6FdjAyHWQwmQSST2VdnphnvrA
         2/YfagQlO3QtqGKBG0xGSFDs3KMHBUJ+FXdeWrw/TQEUTynW6fxwkKEInWXQxMpafVCH
         bKkIzSGX1ELUbsVcgaHOHZor9YTsMU/NgDfA9CbvLz4/1urMdoQHVoociwIeLlHMVaD1
         +cRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:dkim-signature;
        bh=3++RpRzo5+5Sy8yqt3sChcdI35hndUuJ+VdkgGHDow4=;
        fh=eUw05u+8bT9tKppHlMVQ7lg3a7grwLZOf1U4MwIh7I0=;
        b=VxA5P1WHqAdMUyI/AIDPcV/FaB0iPpL1/49v19wZtc3SCvmnFPHK2qOwLGw1ZepZcl
         Y2y/ACGUxN6KgOb34Z1HpxnlD7c05OaWrCkjF9dVE3M1UoQTW2bTi4OgocROKXnVmS5I
         cVeU1S21U7v2TRjj2RQ9yBVoG7efPj8onPM/XypUY4tQSK4wH8FKboBvT9mt4jQ6mTXr
         RRKzj31Kllad3sPh/LcJZQDglJ25kgZ3E2ChIEPRlVgB1XhHdw5VnK7Rz4V/j7dUdbFO
         hDdlXtOIhYxE90Ya8vPaV+3pyZwVZPilA/o33+24EVxbuT4uJXosU9Z1X9HKIZbVkwfj
         EReQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709872559; x=1710477359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3++RpRzo5+5Sy8yqt3sChcdI35hndUuJ+VdkgGHDow4=;
        b=jxJwR+8keLZ1VzFeAmTI8ZzMLNhNv28N1jOMUag+UzVuUnTwz934NUPK48AAQpvgJX
         oHT6AxiakxBX67NMKDAaiZp8o8RrcKSdYu9R/sFTkmAnSsy/V6R3YmSpWoDKOvGSv4JS
         wXJ78HlHlhVr+LSD+5OYRhfCU7vANVkJDaXQpJKuRrpt/MHIx1XJWD1dEGDvO/O6LE+T
         gC/UFExRCG/9zYIPFu/Klb2xzo+4DYXS4AthkHBdW6H9VptPZ6ovtK/agu4Ab2k4joHk
         cgAWkb0gsxhaZMk1KUaZiftR4s1y2R8oEsHxAColGt8mnxT3YHBBGRI3DKcwFQYAsWj0
         1r1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709872559; x=1710477359;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3++RpRzo5+5Sy8yqt3sChcdI35hndUuJ+VdkgGHDow4=;
        b=eVA3ZkN2dMUWOCWbNp7ZtGQrKu8UiVK6jteHc8hX5IXMshj2zfibrnkLGCvMED2P9h
         UUfjtLKmNedr3emHXtGjdUxOe7OX7KfSWBm34DxDcRzYQZpPltbYrcKhjA5SleYKTvmL
         gcBHJ9rUGLo9EKTgmmbHe5q9UFns1/Ocp9bBh6ET7i0sy1RkJF8VreiSLpJ/ag5nDWPz
         DVdiQ/zdRwsigDk8qyd7LyWVGlEYz3YQcCqEsRcgmY3cGkRWgEn0mUZvG1vpb5w0KoIf
         fbH4W0UUZfPrjrSzxEcN2pckAffn2mYuTmjUzdI9Ubrt23Dckz7acWeegaOUIFBT6n8O
         le3g==
X-Forwarded-Encrypted: i=2; AJvYcCXwSYAcg4L4Qmeis+1dWR0lFlFCi7k4q9ihqw2ooE3N/vB/c+fnPIheWWE0s/YfTU3weoESbJQc7jl6k9HFic4Ape8rj1W0yg==
X-Gm-Message-State: AOJu0YxxQEcot90fyN3J5Q+qpKVYy/TIUS8JLJugwVG3gIrD6fAb501p
	qkNFXvrNTNgH0osI7oYPlZZty7q6YGDCxLNy/tEdiwIQVXXBKTpP
X-Google-Smtp-Source: AGHT+IFAvFxp7qKGKo7o3WGk84D3VruGLaQHrVTWJeDfM8BN9SSZfyTs76gwEe0BnvY+f0S+3MC4FA==
X-Received: by 2002:a17:90a:c694:b0:29b:53d7:f7a3 with SMTP id n20-20020a17090ac69400b0029b53d7f7a3mr12112855pjt.17.1709872559186;
        Thu, 07 Mar 2024 20:35:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fa8e:b0:29b:7165:53be with SMTP id
 cu14-20020a17090afa8e00b0029b716553bels870561pjb.2.-pod-prod-08-us; Thu, 07
 Mar 2024 20:35:58 -0800 (PST)
X-Received: by 2002:a17:90a:cc0e:b0:29b:b1d2:2441 with SMTP id b14-20020a17090acc0e00b0029bb1d22441mr722516pju.26.1709872558238;
        Thu, 07 Mar 2024 20:35:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709872558; cv=none;
        d=google.com; s=arc-20160816;
        b=aTcQty0VOC0plEO4as55ofZ4LSRlD3Nnv4pBSDTNGUUwRRKNI4uz+FqcyZF4Mw2py5
         0s6P7jqtep8o+etkgwqS/4F8Qdhy+WXDxw050TaYUXIsrI5w26ks/piFqd6gqmMwhGdD
         CGypMn6PgjPL+Bn49KKPOLDJx9rmO2DPYBhnluVaCywkqmevwF22Jm27SDNRbFqFctza
         9akmanMJuICoq0DpVV5vFrLwKeabnNwFDj+7EpY0Egf536jfigZ3DP4XePNcbcwW4xJ7
         hZvJwu9IoLKsRVkJKfqYUSVawe6amtYVmfDxsPyaGrMulli7cQ1v/TUCusWihiRU+7IH
         snJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date;
        bh=TMc1AB2wXHIxCNcaSfZTzVUgC/RwnpGpsAah6qB8Q0k=;
        fh=5XWoAW87GaxgJKWiKv9gz1SoLLeSV1Y3LFZNIE4DUts=;
        b=NhyiL2wBdO9cr7DMzocTHUAGzxDq+fMMRth88h0WI8j/wlK5ahlNd9ZujmCh3O2vgG
         r5v7w6SwYDk7gQf4HrhK4hElP0nWN8u9mGW+vPLhXPaRP5aSCYD8CSISpKwkmYRQdTYc
         flyGo01v9Ge+b8GENfzcJEtsX0nuCJkvHAT6fNvluUCz2KOe6COtDmsfYqGh1XuSHLHJ
         eUEx0Vb5Rbhyu2j0sIr6qOfQSHCjv2b1GU5KxIc+3H2htaST8627EFUHpFswurVk7W3o
         jKEF9mtPq/J3vvVBJ1KQT34xJK7TK17kCI/PFuBCh+jG5pyOYcdyPpDT3DEJOLisgLUp
         sbdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga05-in.huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id x1-20020a17090a970100b0029b10bca4ffsi293507pjo.0.2024.03.07.20.35.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Mar 2024 20:35:58 -0800 (PST)
Received-SPF: pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from mail.maildlp.com (unknown [172.19.88.234])
	by szxga05-in.huawei.com (SkyGuard) with ESMTP id 4TrYFn5DkPz1h1Zw;
	Fri,  8 Mar 2024 12:33:33 +0800 (CST)
Received: from kwepemd100005.china.huawei.com (unknown [7.221.188.91])
	by mail.maildlp.com (Postfix) with ESMTPS id 34A9E14011B;
	Fri,  8 Mar 2024 12:35:56 +0800 (CST)
Received: from kwepemd100011.china.huawei.com (7.221.188.204) by
 kwepemd100005.china.huawei.com (7.221.188.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.28; Fri, 8 Mar 2024 12:35:55 +0800
Received: from M910t (10.110.54.157) by kwepemd100011.china.huawei.com
 (7.221.188.204) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.28; Fri, 8 Mar
 2024 12:35:55 +0800
Date: Fri, 8 Mar 2024 12:34:48 +0800
From: "'Changbin Du' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <changbin.du@huawei.com>
Subject: [BUG] kmsan: instrumentation recursion problems
Message-ID: <20240308043448.masllzeqwht45d4j@M910t>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Originating-IP: [10.110.54.157]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemd100011.china.huawei.com (7.221.188.204)
X-Original-Sender: changbin.du@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of changbin.du@huawei.com designates 45.249.212.191 as
 permitted sender) smtp.mailfrom=changbin.du@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Changbin Du <changbin.du@huawei.com>
Reply-To: Changbin Du <changbin.du@huawei.com>
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

Hey, folks,
I found two instrumentation recursion issues on mainline kernel.

1. recur on preempt count.
__msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> preempt_disable() -> __msan_metadata_ptr_for_load_4()

2. recur in lockdep and rcu
__msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> pfn_valid() -> rcu_read_lock_sched() -> lock_acquire() -> rcu_is_watching() -> __msan_metadata_ptr_for_load_8()


Here is an unofficial fix, I don't know if it will generate false reports.

$ git show
commit 7f0120b621c1cbb667822b0f7eb89f3c25868509 (HEAD -> master)
Author: Changbin Du <changbin.du@huawei.com>
Date:   Fri Mar 8 20:21:48 2024 +0800

    kmsan: fix instrumentation recursions

    Signed-off-by: Changbin Du <changbin.du@huawei.com>

diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index 0db4093d17b8..ea925731fa40 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -7,6 +7,7 @@ obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o

 # Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
 KCSAN_SANITIZE_lockdep.o := n
+KMSAN_SANITIZE_lockdep.o := n

 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index b2bccfd37c38..8935cc866e2d 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -692,7 +692,7 @@ static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
  * Make notrace because it can be called by the internal functions of
  * ftrace, and making this notrace removes unnecessary recursion calls.
  */
-notrace bool rcu_is_watching(void)
+notrace __no_sanitize_memory bool rcu_is_watching(void)
 {
        bool ret;

diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 9116bcc90346..33aa4df8fd82 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -5848,7 +5848,7 @@ static inline void preempt_latency_start(int val)
        }
 }

-void preempt_count_add(int val)
+void __no_sanitize_memory preempt_count_add(int val)
 {
 #ifdef CONFIG_DEBUG_PREEMPT
        /*
@@ -5880,7 +5880,7 @@ static inline void preempt_latency_stop(int val)
                trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
 }

-void preempt_count_sub(int val)
+void __no_sanitize_memory preempt_count_sub(int val)
 {
 #ifdef CONFIG_DEBUG_PREEMPT


-- 
Cheers,
Changbin Du

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240308043448.masllzeqwht45d4j%40M910t.
