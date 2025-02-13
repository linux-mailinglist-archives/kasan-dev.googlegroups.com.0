Return-Path: <kasan-dev+bncBCPILY4NUAFBB4U7XG6QMGQEEH7GJMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DD82DA34EF0
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 21:02:59 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2b8eaa67315sf1083064fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 12:02:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739476978; cv=pass;
        d=google.com; s=arc-20240605;
        b=bGWJAF6rtyt/s7k+SRbIDIryCH9CMHHoAg0b4pxU5JeTBzv322BgtcFWgkBezU3lKV
         g70v4SdHTtKYPtpl3pbG/gS5rBdbOkPszS5IaUzK9MAMBWm6wYEplMqkR93kI6VOEFpO
         5vzYzFm01+1QyuNzlWmxE7jnIfB0bt2oQFLnpyNhUzMVXQAX2+LBVf1T8BibH0y/8j8b
         p/n9nqs4MStY9+HZGIL7MbXd5OKgt9Y5DCEQLst+4zJTPogC40slhCggzape4J30mQDw
         JSkQ68uAEtkBy2kR3N2jZAcPHTmhl0QylIXRmG180+G2dkTXzeu98fzJfo/UCItJDHwA
         attg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JrKRiWIQPNr26AZKNtgO+a2+w+DYqs2d7W8eDZtciPE=;
        fh=YyY7rXxYeA2nt+byySNe4hRkZvie8QuWX3Ae1DA8Quw=;
        b=H6AalPKmHSe2ctc+mKmdSh/aF0JdAZEEJy8JoQV42evBP6VtEfocaZhKy3Xx/o6vsk
         EF6G/b6C9aqMjsUsCjYypR7XErAxY4rpObODfLCwz6fzYOaYflY3VbB/ZJHvitisx8ot
         M/+LpxK87XpDLc3zaORIAS9Hkb5KIKAMT4U8dg22i8NnYRoPf6LGq6terOvUrw8cH/kS
         Ut3n9anf7Yk/fNwrcAqrY4n5O7S5ALVtwlSjOEPx7mGFoGCdEnEOwWtjqSw71ZyPaA3h
         tJhFcc515CUu3iwTqjW/orQk7f2axX4o9AijCsm8EwxzyyycHr3xR92Von0ZTDWsIezA
         xKCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RltJGkhT;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739476978; x=1740081778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JrKRiWIQPNr26AZKNtgO+a2+w+DYqs2d7W8eDZtciPE=;
        b=na1anL+9IrOteLqDGaBGctjHhTHppBGraifhJeK/p64eYWwdUMIv1ZSlT6Ja34USdJ
         VjQKlDA2BbtNphAFTsyHMx6fcjvnNTUHlGwQsQbTF9jgXSggnJRd2TPzv/IVKKSmc5HU
         jG8oDGH+7bD3TZ5d3I7k2bu9k3Rb945FKK8DZ2m9VnXqIPg5laPDfdB6vgFav+qEZDwm
         AgkAVKZVFsleRYx+UOO/Vum+TDsdL/Jiax0tet2zUHITN+eDU0yilKhmHoncfTfn/Ky5
         rKt3FDWpj3gZAt9e1ePu1t7m6PIwW1cdWbBOCDS2yvvttVE1jL04D8QPVVUr5c0aIMRx
         eFcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739476978; x=1740081778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JrKRiWIQPNr26AZKNtgO+a2+w+DYqs2d7W8eDZtciPE=;
        b=sVBKpN9JiZ58hb65O2LX+4H2GogFmtgZkEoJoAgMNThwUEU3Ktm2LM+eS7JBXb1XRD
         57J++qiyjIdc+poLS8vH8GMebFoR8ddCLYrUVNXGYq4nbJFtlH6r+z7tyuicdXjTbqbe
         E2OLVosQmILSlVgcgnJlBJCXbhwlSYm9sRKqhwtNaPVdI7df4N40kkDZC4MkxNXY9roO
         3GPF9qb/qdEvQLKwmsDRl9HAYMMXTkwFv8q9DCiiie9qG+Ta/OQEeCgt32X0s2yGnoGA
         BvvWB+y/lky+4xfZu5Riup4xAmrOuBzFPjtG1AWWB3wCOPKpALRdTlQEqBtNjDt8XXgY
         fzkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1Ucx2iKGIw0BNofRw6EGph8ZNcAtvtAfgmtKwb6OVAunCIt3hRwfN7zpqJVZeFPtfWs8HAg==@lfdr.de
X-Gm-Message-State: AOJu0YzcrKKQkETJbtcSwdQZw4ohvY0tM/aGVaqeVeacJi0xBS8s1JPh
	tqzJStsIjmgpiNDN4P7JkqJqy7p7HNt0BgaY6OsU8mov3L7moBri
X-Google-Smtp-Source: AGHT+IHJNLw6wwcCLKHPD4hnUx2b+1J5a4cvE7BY/mfZR/XCmHZXsgg3obaApWT15Uhb+iBzsb2OyQ==
X-Received: by 2002:a05:6870:ec94:b0:29e:29ac:5ade with SMTP id 586e51a60fabf-2b8daf9798fmr5465422fac.35.1739476978434;
        Thu, 13 Feb 2025 12:02:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGae97BBIjWnk9uPgiu6j+6sUzt4esLdkp0TaMcLHjF/w==
Received: by 2002:a05:6870:1b08:b0:2b8:803a:caa1 with SMTP id
 586e51a60fabf-2b8f7b54400ls897906fac.0.-pod-prod-01-us; Thu, 13 Feb 2025
 12:02:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW6F5IXX0+JuRI3lTmig3MU2+7K4myIdZPC6hsdkvu4TB2DZpN/QWGQTqVuFl6+WrVXdnO7qitgeu8=@googlegroups.com
X-Received: by 2002:a05:6870:b506:b0:29e:290f:7af4 with SMTP id 586e51a60fabf-2b8daf97972mr5325853fac.34.1739476977389;
        Thu, 13 Feb 2025 12:02:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739476977; cv=none;
        d=google.com; s=arc-20240605;
        b=ZVO2LSmXqV+Qe1d/lcjfdf5Iinj4nptJ+B4miOkF91C8AZRbyNi267WB81SD4kx2QF
         whKuDKOvKYNHoiql4TSookTI3BSy3HGSNpGCcs2geDLtrYt9spqLn+KPiIAHqztgOvXQ
         Fds4bzufs8eYg+lLgRB7t1eGPyKDoGgkD04/KJ4UyeVCmy4wxEc2Gsp1ySk0sue3IdiW
         iaP+CwCA/qxxVQr0E3EMCqZacDLi7aqy2tGaMfjJvApaVQS7wHLpNCjeP6RyNwADVbRc
         iGmrYQIW6kAFN9FOM5TSWR2Rg8HrmRSAvpU84AI57oS0ISiuF+Ze+nykQFH+ACehZ4cE
         iw/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oSXvIJINQIfUxBjAhkboBcPP4OyeZ0/nogoPQVNBBqQ=;
        fh=lQv1AjbPVKIvQPz9UUOSn+HIjjyR/F37iUMUXKbc//M=;
        b=GSW1BqTAMlUnQgz9KzZV6aXKIK10unhR07IxjxyFH7ZzvKypIzQVYUi87w7fAaygwk
         VK+tvuYFEs28OQN+HR6FMl57dWj9vmEjoFr1M0vLTTerxHVK2X65ozeE4WWrNukSK57u
         2Pncu19XCv2Yy+pqMhx64THrhl1NWPsmA43x//zGMePkmXuQu1f0Nc9owpLX/1P8MvAN
         yGBtPUNt/NkZWbaRDWZRjMFKEdvOMp4GjDA26tZ1YaMR+Pxam6tT71EkId9Htuw2JRtd
         ottaEBUJGlTUA0IBbowHzyxyqSAH3q5LmgMLr/xD/uqRmMzLH7iW6RqWVyIzue1k33v3
         Li6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RltJGkhT;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2b9548b5967si99952fac.2.2025.02.13.12.02.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Feb 2025 12:02:57 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-678-FV_rQcKIPGaILACE79EL4g-1; Thu,
 13 Feb 2025 15:02:53 -0500
X-MC-Unique: FV_rQcKIPGaILACE79EL4g-1
X-Mimecast-MFC-AGG-ID: FV_rQcKIPGaILACE79EL4g
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 14C1B180087F;
	Thu, 13 Feb 2025 20:02:51 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.88.174])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id B57FC1800358;
	Thu, 13 Feb 2025 20:02:48 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will.deacon@arm.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Waiman Long <longman@redhat.com>
Subject: [PATCH v4 4/4] locking/lockdep: Add kasan_check_byte() check in lock_acquire()
Date: Thu, 13 Feb 2025 15:02:28 -0500
Message-ID: <20250213200228.1993588-5-longman@redhat.com>
In-Reply-To: <20250213200228.1993588-1-longman@redhat.com>
References: <20250213200228.1993588-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RltJGkhT;
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

KASAN instrumentation of lockdep has been disabled as we don't need
KASAN to check the validity of lockdep internal data structures and
incur unnecessary performance overhead. However, the lockdep_map pointer
passed in externally may not be valid (e.g. use-after-free) and we run
the risk of using garbage data resulting in false lockdep reports. Add
kasan_check_byte() call in lock_acquire() for non kernel core data
object to catch invalid lockdep_map and abort lockdep processing if
input data isn't valid.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Waiman Long <longman@redhat.com>
---
 kernel/locking/lock_events_list.h |  1 +
 kernel/locking/lockdep.c          | 14 ++++++++++++++
 2 files changed, 15 insertions(+)

diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
index 9ef9850aeebe..bed59b2195c7 100644
--- a/kernel/locking/lock_events_list.h
+++ b/kernel/locking/lock_events_list.h
@@ -95,3 +95,4 @@ LOCK_EVENT(rtmutex_deadlock)	/* # of rt_mutex_handle_deadlock()'s	*/
 LOCK_EVENT(lockdep_acquire)
 LOCK_EVENT(lockdep_lock)
 LOCK_EVENT(lockdep_nocheck)
+LOCK_EVENT(lockdep_kasan_fail)
diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 8436f017c74d..98dd0455d4be 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -57,6 +57,7 @@
 #include <linux/lockdep.h>
 #include <linux/context_tracking.h>
 #include <linux/console.h>
+#include <linux/kasan.h>
 
 #include <asm/sections.h>
 
@@ -5830,6 +5831,19 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
 	if (!debug_locks)
 		return;
 
+	/*
+	 * As KASAN instrumentation is disabled and lock_acquire() is usually
+	 * the first lockdep call when a task tries to acquire a lock, add
+	 * kasan_check_byte() here to check for use-after-free of non kernel
+	 * core lockdep_map data to avoid referencing garbage data.
+	 */
+	if (unlikely(IS_ENABLED(CONFIG_KASAN) &&
+		     !is_kernel_core_data((unsigned long)lock) &&
+		     !kasan_check_byte(lock))) {
+		lockevent_inc(lockdep_kasan_fail);
+		return;
+	}
+
 	if (unlikely(!lockdep_enabled())) {
 		/* XXX allow trylock from NMI ?!? */
 		if (lockdep_nmi() && !trylock) {
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250213200228.1993588-5-longman%40redhat.com.
