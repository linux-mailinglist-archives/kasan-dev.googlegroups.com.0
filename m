Return-Path: <kasan-dev+bncBCPILY4NUAFBB3U7XG6QMGQEQJMKJUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id A8DCCA34EEB
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 21:02:55 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e65d4d54b4sf24029896d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 12:02:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739476974; cv=pass;
        d=google.com; s=arc-20240605;
        b=R6svuLRjMiLPymnpBX7Ro4h4UpbNtY9fEOiG9JHx1sHP9CU5siwJPnLH21Xi8K1bac
         m0CvGYg/RaOsPpaOSovRfEKrjpPqFCZM4DygZXGvgcDqlYsw7teTAX0jnk4EHpeQgJ1y
         MGWRsagxybtrSC0a34v2ldhJrxw/ClHSaXZeNCDDJCcBPUYyZ9iOgx/ZXkHyGeutjdWK
         VlCja+6coCQXX5hkKbDbhKmzBEBuz88ovkUCoX+7TxhDB7wWeEJGuXlxeGeN3LELvBVq
         YhtgcweXjrDxoxqm48UnXL8JJJ9YX6MRLySEgJnP9nMum1SQeJAJYjoYcZ29KIznN3WC
         VGyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Jmjte/PhcTesFixcdTXnlMGffJjMbzOYDfYc2LUxV5k=;
        fh=+yV66tdkdUwpwbiSwmPpNWgOxcKClVlCLWrFnkBWq+Y=;
        b=LPLRYazu8LvDHGRZrD0gk5hoA2PPdPgaNPuKXYkFzGlBkjEX69ef6ZU00SlATIhiYL
         FMphrCtlC0wS8bywuaeFa9zlF4lg8XB8zxd2hBaMGSxBK+IjoJEOhWlrtTY3ZFxFgsIO
         2zMYmmuZI6aTMlkTZ6ZRHI7dvVcLpxqCQGh4Wtj1NRtFNoDFgBYEzpH5dL6CGxKNeBnG
         d/VzwVDjKxfCW2r71EpdUimcdXCWWq1tWFAdkaerhlP90PaD1KMW/S7OTfSPX0vHHeSC
         PV4BESMgAvcGVgCFvySNbej9TQP0/DA0lTS49n6rg0Og05tRM9Mv4tm+ts2y7d1UFiaT
         8x4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FOw992O8;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739476974; x=1740081774; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Jmjte/PhcTesFixcdTXnlMGffJjMbzOYDfYc2LUxV5k=;
        b=SEvuSrwlSlSF0EADtdY+O3fn0GRxqZg6ibDisID8YE2aY4QYkBbZZLIISts2vwE9pN
         hjp+KfrLuDTAYifTwjdw+faSzrqIb/h2rSGeHmqP84XaLkjXZxoqEGwrTqqMA3ML86zb
         OuuX17TgA1YN2pH40fv5r64VbPMGF8aKRPmSWwdpnyJvV+J1UPvgs1+q1NUEtEkcNZX5
         ATgVi1ORMdn0T7mJU4/Bvc6BguEVJlNfcH3hJZ2IGD8cjiZ8+ROZUfMWgu6SocgRguwA
         fjMs3UHHZPlgb6D8QetlvAujqoYDpZH0wOt7GsBnXdVY9jmys7r7t2w0t9cALxa0gE/9
         zIGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739476974; x=1740081774;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Jmjte/PhcTesFixcdTXnlMGffJjMbzOYDfYc2LUxV5k=;
        b=o9nEsPtaIJ88VZ/zqrT+uprZ+R24jtEfCfzoPEt4XYolOnaXM8jNeps/3O76ICm15a
         FSB51Vrs1bd0fWETRCVK4RdKfzFPoEeSxcPf6HjJBKYKSXVCveaLCsBFSVd4GFh9nx2H
         /VnA+ptspdwejgiBY7N0e9/EH66e8gvLZUAB/a2F1e+wpp9mn6Gvbagz0ToiTbiIr/LQ
         oeGBfFbMzRbiyXLr52T9TxMJO4Ye6Z5juZN454LiSEqPrRjeoiQ3RPEExQjx1rCyz3tH
         ajgO8PQuNRar4dQzyxjrj+3Sh04w5VTf2w/JmXzeRioXVhJ+vxYSH5mSUSZdqPXU6u0i
         iT9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJFQwYclacQOsjNcyR6W0whYZ8qrYpV35lrbKv9pcH4Z3m9Er1f4i6E2KuOqV5nSaz+gWVyA==@lfdr.de
X-Gm-Message-State: AOJu0Yzyz+iyeSh8mGxtjllA/Zc1PhkxA3euya5sjuX+kfPeBz+nfB17
	8DRisvdulIglD69/O3398cGXlYbKdNbqxEnGyo6OWCkRA5azzsMS
X-Google-Smtp-Source: AGHT+IEpdcY4NY+lZm2n0LlasGx0NS8doLTt19Efgkzg6ifzNSZBgwnFCDD5w0EFi8jqx4/D141tDQ==
X-Received: by 2002:a05:6214:c8d:b0:6d8:a258:68bb with SMTP id 6a1803df08f44-6e46ed8e6b7mr112923456d6.6.1739476974304;
        Thu, 13 Feb 2025 12:02:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEWQFZuWCPlOPbp1fp29zRJGa8TKqH0ea9Dt+/nTOdZog==
Received: by 2002:ad4:5894:0:b0:6e4:41b5:919e with SMTP id 6a1803df08f44-6e65c24795bls20255706d6.1.-pod-prod-07-us;
 Thu, 13 Feb 2025 12:02:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWutDBe/Xe3w6/DmkbC3439/n7BG69ZIfcK5IosQe6fN0PRxAX8VXG36+mbx6ySoIChwziZoiC/X94=@googlegroups.com
X-Received: by 2002:a05:6214:21ea:b0:6d4:1e43:f3a5 with SMTP id 6a1803df08f44-6e46ed9a5b5mr130249876d6.13.1739476972659;
        Thu, 13 Feb 2025 12:02:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739476972; cv=none;
        d=google.com; s=arc-20240605;
        b=ZpBasTBCrpBZwKXn4BwhHExa3d970+wNnPaZzk8UL96Ld/FHM9SgWjBbAhpgPJIZFh
         3LVMn44ozAtFLxAjegRRI7g+FUdOpGzseGwgbQizjHQobYqQLy3lLHgiTxU0ukyb45QM
         TH81pz95HJ9RiH7PElTIvpX+G3tdtP9mq/sV5e1ohNsjIGC65kk7GWdE4Zlh1s5vVA5d
         5/qEHQ9B6OidCIGe3hE4A6DkdVX7jJMT5u10BtA0jkIIF/GgW7X3q75G1S68LwtJr8ub
         wYoT+bb9/54Mne6aEZIzLJHm1axpanOuRsFrH4R4LobXKCAnZIzHR+RoAHYVSqsSPj7L
         DI8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oz+7MpT+Dx78HRfBDvJLdqx8byUVr6Veo3C9NU8MZLY=;
        fh=lQv1AjbPVKIvQPz9UUOSn+HIjjyR/F37iUMUXKbc//M=;
        b=h0zfG5c/htIAzzIryNJSFmO7LnkLCQb8+dByxIlTgbCxpNwJSKFI8u9Bpm2Y+yZmVq
         7VM43N9ezPHtSnyYb/mMHnhX0dQJmW1nxvRL6y+z/K7X3d+YzJZMyBAmdo93JGywo6sd
         qTDoWdqutxi5nBovpLdA8cIxTlE8gt+AEneJ9FNbq0Iuk6FW9+2PBtnTzl6T7JbwY8+I
         PRBUCWSmwTry+7ouQdPwDGoFpq7KPrxGmGQ7vV81I2tBNF03abHW/HRVq2/MPJs/txL4
         zJSXdWBSBHoMEwXRP2W04KaitM5uTM3AUkUw6EW5zlCd2IHkBpe0w62PqTakXbUZABU+
         tFCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FOw992O8;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6e65d7b19absi956106d6.6.2025.02.13.12.02.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Feb 2025 12:02:52 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-609--0t1wsnLOGKBHz3JatwlMA-1; Thu,
 13 Feb 2025 15:02:50 -0500
X-MC-Unique: -0t1wsnLOGKBHz3JatwlMA-1
X-Mimecast-MFC-AGG-ID: -0t1wsnLOGKBHz3JatwlMA
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6AB25180087D;
	Thu, 13 Feb 2025 20:02:48 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.88.174])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 00E791800358;
	Thu, 13 Feb 2025 20:02:45 +0000 (UTC)
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
Subject: [PATCH v4 3/4] locking/lockdep: Disable KASAN instrumentation of lockdep.c
Date: Thu, 13 Feb 2025 15:02:27 -0500
Message-ID: <20250213200228.1993588-4-longman@redhat.com>
In-Reply-To: <20250213200228.1993588-1-longman@redhat.com>
References: <20250213200228.1993588-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=FOw992O8;
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

Both KASAN and LOCKDEP are commonly enabled in building a debug kernel.
Each of them can significantly slow down the speed of a debug kernel.
Enabling KASAN instrumentation of the LOCKDEP code will further slow
thing down.

Since LOCKDEP is a high overhead debugging tool, it will never get
enabled in a production kernel. The LOCKDEP code is also pretty mature
and is unlikely to get major changes. There is also a possibility of
recursion similar to KCSAN.

To evaluate the performance impact of disabling KASAN instrumentation
of lockdep.c, the time to do a parallel build of the Linux defconfig
kernel was used as the benchmark. Two x86-64 systems (Skylake & Zen 2)
and an arm64 system were used as test beds. Two sets of non-RT and RT
kernels with similar configurations except mainly CONFIG_PREEMPT_RT
were used for evaulation.

For the Skylake system:

  Kernel			Run time	    Sys time
  ------			--------	    --------
  Non-debug kernel (baseline)	0m47.642s	      4m19.811s

  [CONFIG_KASAN_INLINE=y]
  Debug kernel			2m11.108s (x2.8)     38m20.467s (x8.9)
  Debug kernel (patched)	1m49.602s (x2.3)     31m28.501s (x7.3)
  Debug kernel
  (patched + mitigations=off) 	1m30.988s (x1.9)     26m41.993s (x6.2)

  RT kernel (baseline)		0m54.871s	      7m15.340s

  [CONFIG_KASAN_INLINE=n]
  RT debug kernel		6m07.151s (x6.7)    135m47.428s (x18.7)
  RT debug kernel (patched)	3m42.434s (x4.1)     74m51.636s (x10.3)
  RT debug kernel
  (patched + mitigations=off) 	2m40.383s (x2.9)     57m54.369s (x8.0)

  [CONFIG_KASAN_INLINE=y]
  RT debug kernel		3m22.155s (x3.7)     77m53.018s (x10.7)
  RT debug kernel (patched)	2m36.700s (x2.9)     54m31.195s (x7.5)
  RT debug kernel
  (patched + mitigations=off) 	2m06.110s (x2.3)     45m49.493s (x6.3)

For the Zen 2 system:

  Kernel			Run time	    Sys time
  ------			--------	    --------
  Non-debug kernel (baseline)	1m42.806s	     39m48.714s

  [CONFIG_KASAN_INLINE=y]
  Debug kernel			4m04.524s (x2.4)    125m35.904s (x3.2)
  Debug kernel (patched)	3m56.241s (x2.3)    127m22.378s (x3.2)
  Debug kernel
  (patched + mitigations=off) 	2m38.157s (x1.5)     92m35.680s (x2.3)

  RT kernel (baseline)		 1m51.500s	     14m56.322s

  [CONFIG_KASAN_INLINE=n]
  RT debug kernel		16m04.962s (x8.7)   244m36.463s (x16.4)
  RT debug kernel (patched)	 9m09.073s (x4.9)   129m28.439s (x8.7)
  RT debug kernel
  (patched + mitigations=off) 	 3m31.662s (x1.9)    51m01.391s (x3.4)

For the arm64 system:

  Kernel			Run time	    Sys time
  ------			--------	    --------
  Non-debug kernel (baseline)	1m56.844s	      8m47.150s
  Debug kernel			3m54.774s (x2.0)     92m30.098s (x10.5)
  Debug kernel (patched)	3m32.429s (x1.8)     77m40.779s (x8.8)

  RT kernel (baseline)		 4m01.641s	     18m16.777s

  [CONFIG_KASAN_INLINE=n]
  RT debug kernel		19m32.977s (x4.9)   304m23.965s (x16.7)
  RT debug kernel (patched)	16m28.354s (x4.1)   234m18.149s (x12.8)

Turning the mitigations off doesn't seems to have any noticeable impact
on the performance of the arm64 system. So the mitigation=off entries
aren't included.

For the x86 CPUs, cpu mitigations has a much bigger
impact on performance, especially the RT debug kernel with
CONFIG_KASAN_INLINE=n. The SRSO mitigation in Zen 2 has an especially
big impact on the debug kernel. It is also the majority of the slowdown
with mitigations on. It is because the patched ret instruction slows
down function returns. A lot of helper functions that are normally
compiled out or inlined may become real function calls in the debug
kernel.

With CONFIG_KASAN_INLINE=n, the KASAN instrumentation inserts a
lot of __asan_loadX*() and __kasan_check_read() function calls to memory
access portion of the code. The lockdep's __lock_acquire() function,
for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
added with KASAN instrumentation. Of course, the actual numbers may vary
depending on the compiler used and the exact version of the lockdep code.

With the Skylake test system, the parallel kernel build times reduction
of the RT debug kernel with this patch are:

 CONFIG_KASAN_INLINE=n: -37%
 CONFIG_KASAN_INLINE=y: -22%

The time reduction is less with CONFIG_KASAN_INLINE=y, but it is still
significant.

Setting CONFIG_KASAN_INLINE=y can result in a significant performance
improvement. The major drawback is a significant increase in the size
of kernel text. In the case of vmlinux, its text size increases from
45997948 to 67606807. That is a 47% size increase (about 21 Mbytes). The
size increase of other kernel modules should be similar.

With the newly added rtmutex and lockdep lock events, the relevant
event counts for the test runs with the Skylake system were:

  Event type		Debug kernel	RT debug kernel
  ----------		------------	---------------
  lockdep_acquire	1,968,663,277	5,425,313,953
  rtlock_slowlock	     -		  401,701,156
  rtmutex_slowlock	     -		      139,672

The __lock_acquire() calls in the RT debug kernel are x2.8 times of the
non-RT debug kernel with the same workload. Since the __lock_acquire()
function is a big hitter in term of performance slowdown, this makes
the RT debug kernel much slower than the non-RT one. The average lock
nesting depth is likely to be higher in the RT debug kernel too leading
to longer execution time in the __lock_acquire() function.

As the small advantage of enabling KASAN instrumentation to catch
potential memory access error in the lockdep debugging tool is probably
not worth the drawback of further slowing down a debug kernel, disable
KASAN instrumentation in the lockdep code to allow the debug kernels
to regain some performance back, especially for the RT debug kernels.

Signed-off-by: Waiman Long <longman@redhat.com>
---
 kernel/locking/Makefile | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index 0db4093d17b8..a114949eeed5 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -5,7 +5,8 @@ KCOV_INSTRUMENT		:= n
 
 obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
-# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
+# Avoid recursion lockdep -> sanitizer -> ... -> lockdep & improve performance.
+KASAN_SANITIZE_lockdep.o := n
 KCSAN_SANITIZE_lockdep.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250213200228.1993588-4-longman%40redhat.com.
