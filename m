Return-Path: <kasan-dev+bncBCPILY4NUAFBBKN6X26QMGQETEABLII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 13F59A36682
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 20:53:15 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6e44150a32dsf62036586d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 11:53:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739562794; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZGHtk8UQ7KJUkEX5u0q/ugWFHT3zcxerh7exSdWWnscw2gzRWkR3PP6CCMg37o6f5A
         rTP84nW9PlrsGNS17vmRNUh+aFvxlsc0TSMdBNJNroxKOPPFFaQHRF1AxRjFw/+P1I4P
         hKtimLk0PfscgpxfHwlnwHTQTC2ktjRu7WZ5fTcrVer8p5Zn3zEkB2bLiEcyReOt9jSz
         OPnRF/WY4+3vzqRlP6gr29kL9Jjvai+fZHDYwoGFEo3esla97Doz+oMHyvR709N5KCPI
         48Ki6yZN75ZwmyukeQzCgCHVZHa9rVBAYCh2pkr0Y56OceDMj8oCKmvfAyEKeynr2U2J
         pIlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OlTB7pvElGkDWN1NNJhV6UDr6ccQ2jC5UIpasiTFKao=;
        fh=wPxGWRGlv2cpjWN7BzAWGUbeMFMqj+xSe1Si9no3Nrk=;
        b=WD94yV4KuDYRcgLXQsa620NiQomlY2Zy1hkWJ08VAs5xR2hazERWESfSpq/eX0nMVF
         /niPmnBlKYLjKDWvC27czfeAS7dCB3No/Tu/X+eoqaQb0rF7rbB+uqA7Fgtl97WNTgY2
         CgSkRoikbbYlKJ9LiGUWZdzMdILEzoUEhbf81i3NZt6bQwstYwf+XVFzmTjtM/LrkR5M
         xMnefW/dBssJeEH+nsQ83c4wD+aaqSeg8sbNwYbV34RqTN3fRJGYKyywqO0/hsjgijXw
         xpIIm8ThI7JYjAmE7jiE/o+eEH0Y+maCN0U+O/KQFMqmzdkek/N0Scdnx4zPKuRtE4BO
         ztAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NVme36Ea;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739562794; x=1740167594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OlTB7pvElGkDWN1NNJhV6UDr6ccQ2jC5UIpasiTFKao=;
        b=StV2bNKFR3TCpr1cQ7Jj0gj2oqF0qqkeYC+VXyxFHRuoEQo+WQoB5sqJER+h9B2cdp
         6GvDlSxQer9/pkamCj7gI7tgP9SNIrbO7OwnMyDEJR0z88AzxwlxNJn5rPr5qKoTLbG0
         rBMkgNo2yiBJoeSDFdnB/CalwCo0elkGbimU8+L53oxD4xMmxfIOQxMMzCHP/Je2HpPH
         wOvIG68dg6Ni7+PQqJLxUoMaKfpafyq5LKba9aNrEYjQHXZXhfPOJPtIWdQbYm9xuSvI
         QZpNU7cMcR4pFSrg61VBGUPd8GNdc62JxIsmhcdp6hvR2fhsxljrg8VEr2Nu0CpyeIEc
         KTRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739562794; x=1740167594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OlTB7pvElGkDWN1NNJhV6UDr6ccQ2jC5UIpasiTFKao=;
        b=hN1aHnERd+gMOzuU5TKwCupccf8TNfsHXUowD3A1rQnZ6ZFkUszaVq9y6SfWZv5G/L
         6LAT/D/IAR32k1J8KurNSH6w28paDbi3IsxxAwllc9uloxZ6TMZ0KAF2PY493jVMSQXx
         CWili0RwjLajUZsf3qXJtQMMu5KAOHzcLESp9vxY2xtONwf2Fl8qoLwjl6JgEXf9zK5n
         ID8CytTYEmWqwqO/JErKtftM/dPR5jZkI63C9UdaM1KE+Yx+fTtyuQIcPUBLDSQYywpD
         3hhC1xRqOLZ6Mk9spcdhf3HuzBBaVOITzmUEEWQMbx5habsH4UAJkaNQ0qXAFoYeK6+j
         B6CA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2oRGnOtIEv/RqxH0JJWAVG02fsmGPODlIfRE2OspTCRuIUxJ+6pySmOoCCv00QHrI1I4RwQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZHc2+EG1LMlZAm5ME+cp5qIeAOERrVnFrPeWmAW1rqpSnr9vN
	jGvfLfGzoM8GsWOGbEWC4KFPi7YLmnbeOuaUSho0y+WNrpXjUIqh
X-Google-Smtp-Source: AGHT+IH7lnZZ5VFw0rRCRCOk/QieKLRvZD7yZ/9A8oRCkZ6q3g4CrgyBxAyyckWq3lMO5wTiXVdeUA==
X-Received: by 2002:a05:6214:21c3:b0:6d8:9994:ac30 with SMTP id 6a1803df08f44-6e66cce7329mr9787326d6.26.1739562793810;
        Fri, 14 Feb 2025 11:53:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGoV23y/YvPuO3/9i/Nj8HU1hGrZTbT/VcrigRlUWB/SQ==
Received: by 2002:a05:6214:1808:b0:6df:8164:cdb0 with SMTP id
 6a1803df08f44-6e65c243524ls6975916d6.1.-pod-prod-06-us; Fri, 14 Feb 2025
 11:53:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWfaWne7zkHKS+j3aOYXtSDqca9QrhNJxSJD2QsjBytGpRzbl8HMbzNokiU9XwSsB9PbVGBgXpAShA=@googlegroups.com
X-Received: by 2002:a05:6102:cca:b0:4bd:3924:44c3 with SMTP id ada2fe7eead31-4bd3fc9d6a6mr858551137.6.1739562792938;
        Fri, 14 Feb 2025 11:53:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739562792; cv=none;
        d=google.com; s=arc-20240605;
        b=LJriURTb5hV6HNsEf1Fri2bGmskWUmIchGL+AIxxD3uEu0EDiikH020m0o2VEsF0wz
         1uQtDBStxEMWAx/WUuLu02g8wagZbszZDt3Dijgv4rBIsQDIWO4WlUQb9AHrQk1+raZj
         0eNTJ+W7/+5vDxDN+ZLSJSg8nWSzZbLjVXEvYjDX+cMxB4snLMZUhhHuM/tRIRO4IYcm
         XhjgKJ4ITajRBpP8lBPIU0zZvmkNgISFyAWTBpQA1ePU1VRy3xWfPkvEfU6HeI3tvxi6
         kAy13M4wkNiv9GfgYQPL+8ZcARK8EYW3+efrnHJRoTC2pigvwnRmKS/02bZhKKpJqUwp
         o3Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v0A/F0sxY6CPbFBG1cOgr1XQMfWgjq/GMhonm5xEbAY=;
        fh=lQv1AjbPVKIvQPz9UUOSn+HIjjyR/F37iUMUXKbc//M=;
        b=YOMy+UsVeAov0hvtfsN8xwJSlGPS09j57GydfBapeIbPWq6fEMIjCOWAa96KZ8TDbq
         oshK75hYkBLr3UxyRE+gWIyxd+SU1Z5SYY7rFPd+6sGLwlBDuDKUOZxQRXXKpxU4iEZz
         G2MTb45R3KV5zNbWGTXnFah7xHoyXFGEQZ0y5HfVqJaO+HUz2rUqs+JrsMRO0AAI4G7t
         SG7cn8/5CMTosvOw4AbuWa2c/D2kGTkudN5DxP4iRwPXOT1trF9PVQIAl2+1RlHCeXtv
         50lYSQl+DMW+jOdYVvc6IE6urJE4Miwf8iCYciZExtDSYElfd3CMMftWdEn9/86DY9yi
         uieQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NVme36Ea;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5207ab5b340si240012e0c.4.2025.02.14.11.53.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Feb 2025 11:53:12 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-138-hiKAVQYcPD6OURKxGKIcvA-1; Fri,
 14 Feb 2025 14:53:09 -0500
X-MC-Unique: hiKAVQYcPD6OURKxGKIcvA-1
X-Mimecast-MFC-AGG-ID: hiKAVQYcPD6OURKxGKIcvA_1739562787
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 072CE18D95DC;
	Fri, 14 Feb 2025 19:53:07 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.89.30])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 4749C1800874;
	Fri, 14 Feb 2025 19:53:03 +0000 (UTC)
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
Subject: [PATCH v4.1 4/4] locking/lockdep: Add kasan_check_byte() check in lock_acquire()
Date: Fri, 14 Feb 2025 14:52:42 -0500
Message-ID: <20250214195242.2480920-1-longman@redhat.com>
In-Reply-To: <20250213200228.1993588-1-longman@redhat.com>
References: <20250213200228.1993588-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NVme36Ea;
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
the risk of using garbage data resulting in false lockdep reports.

Add kasan_check_byte() call in lock_acquire() for non kernel core data
object to catch invalid lockdep_map and print out a KASAN report before
any lockdep splat, if any.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Waiman Long <longman@redhat.com>
---
 kernel/locking/lockdep.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 8436f017c74d..b15757e63626 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -57,6 +57,7 @@
 #include <linux/lockdep.h>
 #include <linux/context_tracking.h>
 #include <linux/console.h>
+#include <linux/kasan.h>
 
 #include <asm/sections.h>
 
@@ -5830,6 +5831,14 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
 	if (!debug_locks)
 		return;
 
+	/*
+	 * As KASAN instrumentation is disabled and lock_acquire() is usually
+	 * the first lockdep call when a task tries to acquire a lock, add
+	 * kasan_check_byte() here to check for use-after-free and other
+	 * memory errors.
+	 */
+	kasan_check_byte(lock);
+
 	if (unlikely(!lockdep_enabled())) {
 		/* XXX allow trylock from NMI ?!? */
 		if (lockdep_nmi() && !trylock) {
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250214195242.2480920-1-longman%40redhat.com.
