Return-Path: <kasan-dev+bncBD66N3MZ6ALRBH4K2WYAMGQEYJ4WBOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 71ABB89DA80
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Apr 2024 15:39:45 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-5f0382f688fsf3919603a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Apr 2024 06:39:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712669984; cv=pass;
        d=google.com; s=arc-20160816;
        b=MPkVlewZmiZtlTlp/yvbXQU2/bQvGDOKgv6fm+k+GjhmbIFmpBe8CmpvZ3ahJPtZgY
         Hgpn3tOnHdobhY9jHPKrhK82CgVK1AnDjtMMRsF+MN6YL5PwauqX8HNm2SLam7DCQBFp
         oH+HPDA1NUM+sOocQaLU47N6gQfyNeZB3+mSRoyPCpCvO1siSvxUjk2F02JuDhkNw4sW
         HRrRDk5VZ3ZvKbTqi37+pHLAxEPtYRUqHs35Zz2XclX/FRSCwa8LqrXXiQDz9h8wvjxN
         g/pQWSm2CahJCBLyNiFyfZJJBL1Ujlyiuj/izjlUqOtp//5ZME/X6DSPRWaT0XpibMzs
         Q6vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=l+d4kDVOPtUx7JMfZK2i/d9rUcjBPb92DayvDBXxTpQ=;
        fh=YNjtM/MElG99g/XolRYnBSWgW+LriRnza/Du3zQdk80=;
        b=KL8jUwU088YRoMexaNNHlPiZGf8URlUtwP6uxhCIUivnvyrTE9Q/1m/WsmCKfcNm02
         qMFyOHJaydpu0rvl6mKGlLJWZw8yihXn53BQJW468+N08juiRY5uk6QDnyElRo+zHB4h
         pSG687Y+tsqEDfQpqTYBvkumG/D/iNfnxy+OORQxXpzjrEtPzWnVUDp2GH9qoxxOap1i
         d/VWyUEK5LBZ+5WRO1Ol6OwsD7K8cFAw5wrQYjbwTcFlyM2vyASIzCHgdujxGBiWk+gc
         fFpWDc3wn4ydg9X2zrcc95WTI7wCrnU3mxohXzKC8rMULJq2OxNxq+TDWlaz92oTGtAT
         n3Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HO69Uw+u;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712669984; x=1713274784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=l+d4kDVOPtUx7JMfZK2i/d9rUcjBPb92DayvDBXxTpQ=;
        b=V+0BC3BPmA4yqQ1WTU4JzBMVTNcgGf6avvhOmuR18ghOgkdFOST/COmVQ57bdZ0LOU
         mbB4V6XpPddZOtDK+kHO7bPSAMm7S2tY3w9VedIvfd2Pg9Nb1PXJ0KFzYu04QAe3RlsD
         A3dP01TvcWSmWeFTsVU+K0V9m86N3TQX87nj1GCAwafWjOA2A712HgqElv9AzLh309bL
         aIF7eOPrphaMHUkYGTM6DajmkMScTHaK6c9fsIgoDOoWEbSsCkaPZ5urzkWTxqMb9Csj
         TBSGFHwSzHslEVCNR1agKE936WYry2hTugg5G5UeQv6iLbrkR6S1gxVcickfCJVdy2mn
         d0TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712669984; x=1713274784;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=l+d4kDVOPtUx7JMfZK2i/d9rUcjBPb92DayvDBXxTpQ=;
        b=HMWnkY92xtqBwVEACEDfA/3Q5gOqxNPYt9nCiG+FwEUUDVEiQfDzGuN1PEdrmuDp8Z
         P0EIixU1Ims5X6pQbaBSDPZc8DYztyDMaELKDpSdSwoWOIcFRUHo3R7Dw8T7to6c4SHi
         BNxDEatG9aO6lAGHlEyspDklQgIFkRMGuC4/lNC+Lk7CXeT97xwt7dvfacnvQaJKM7AZ
         9oD5I9NYa+TLh+bzF5DWIzPlRtChJrD2CAc/6gzC56p2c04wu/jhwcSMghHM8i0FTF2/
         CqRBqu4KsB4azKrONmp2g6LpTnnVWiO6Fqpygjgmuc/BqENptIxq6i8+TzKhypqBmcbq
         9N0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUtcjKsFR75MZGcjaVhNq9L+NeAzUBL9QUNJOAWdbW2mq3KZtdnX0EueOCZLEeTlDF0E/G8S4j7FSVKSCPp688WW2hO4gx8Yw==
X-Gm-Message-State: AOJu0YwSMeu89T849VtIneP1Dg1ffFH2zGDbYVye8RhvrasFeoZmcbrK
	Cj34LZt73cUkqtJbrFQ04T1PhuoYVpE0j/C7YQzcdaQ3SvhyaI3MBTg=
X-Google-Smtp-Source: AGHT+IFx6Xk8sKSMr0fbCLYLLZp1v+Kp7Ypqf89/aISGNCm+U2pLL0i3C9dcTX8mDBAun1J0IbgUzA==
X-Received: by 2002:a05:6a21:9999:b0:1a7:8127:c919 with SMTP id ve25-20020a056a21999900b001a78127c919mr4628427pzb.43.1712669983543;
        Tue, 09 Apr 2024 06:39:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:9285:b0:6ec:fe13:95c with SMTP id
 jw5-20020a056a00928500b006ecfe13095cls2699092pfb.0.-pod-prod-01-us; Tue, 09
 Apr 2024 06:39:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnYE/kYQn97J3ot47VFXP9P6dR25YDEu9fuTDwUU3Cy5q8tW9BkGU4W7bxRr3M+J1FG53S9YsKB1wDRlVQ/yHJgfPV179YgQdGVg==
X-Received: by 2002:a05:6a20:5b19:b0:1a7:336c:555c with SMTP id kl25-20020a056a205b1900b001a7336c555cmr8219110pzb.60.1712669982012;
        Tue, 09 Apr 2024 06:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712669981; cv=none;
        d=google.com; s=arc-20160816;
        b=jhFwR1YFKA8Y/dEwR8xo7+nHBLk75WReVAlkU5pD/hUG9dXLpqrYb4C6K16QB/RmPS
         QPqKR9ZKDXwsEVLK4bHftUdABluuLTZi4vimEszvRtbznjrBxRNz4UeiJRkjqJGQ2KDn
         Cd9cOaNCudxe0rERWeJOnMemmTlBQwalqN2UsRdOMFR/QREIGlBhDhWLmzXc1YJ52WSo
         G4KV+N2XKRLC9OkPBjpRWXUPW514mN9Xz7nOrQlN0Lpa1Acskxw2shSeK7aN+2P78wCk
         kNXpg+gRFYjHN732+awTppoFK1//C43y3lDhuorBqxUwlPcZXPGXEpVMZ0QTFKOkxmMd
         HyZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cHNENpIo5P3xNA2FT6uR/Fpf8icdmb0An+YCTlDYv/k=;
        fh=ct+SAC++KuMnHEs0TDY7BoMNklHQXTXWPHBS4yDpdlg=;
        b=thL5IdkXnYdX1fcgrAzYtlL2H7HWnq8oAmjMuIoXLGJ6Zye7YbhMzVQR2q3JcmMLZG
         +N3YdX7QtEmjo3xo0+ytlHOavrxteRJH9IsicjAXcsnPqbbGry/ZIe1a2cQIM0FeRaat
         lXHt5YHamIDIlO+DD2m6lTCJxyzCD33G/EnOdRPb8GanAyjBAPJW8koDF0LycrbUBp+Y
         6iNjv+U1nMGNLSKJO/WCLNfha/BUUYoqgkJ46pip/0g+8zsnY/ZhVvevBrxpP3u/FxB/
         QvXp3HZ+1ycFq136MU3bwwd+9z4qs2xPzAVaC8bYi8q8Bc/s+/8gkpnlCJyyU8FQ4JsK
         6WQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HO69Uw+u;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id k35-20020a17090a4ca600b002a499886dcbsi200503pjh.1.2024.04.09.06.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Apr 2024 06:39:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-653-I0pd653lOZ2bOgxz-s13DQ-1; Tue, 09 Apr 2024 09:39:37 -0400
X-MC-Unique: I0pd653lOZ2bOgxz-s13DQ-1
Received: from smtp.corp.redhat.com (int-mx10.intmail.prod.int.rdu2.redhat.com [10.11.54.10])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id CDDDF802A6F;
	Tue,  9 Apr 2024 13:39:36 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.56])
	by smtp.corp.redhat.com (Postfix) with SMTP id DFF89444300;
	Tue,  9 Apr 2024 13:39:33 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Tue,  9 Apr 2024 15:38:11 +0200 (CEST)
Date: Tue, 9 Apr 2024 15:38:03 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, John Stultz <jstultz@google.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: [PATCH v2] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
Message-ID: <20240409133802.GD29396@redhat.com>
References: <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
 <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com>
 <20240408184957.GD25058@redhat.com>
 <87il0r7b4k.ffs@tglx>
 <20240409111051.GB29396@redhat.com>
 <877ch67nhb.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <877ch67nhb.ffs@tglx>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.10
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HO69Uw+u;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

Thomas says:

	The signal distribution test has a tendency to hang for a long
	time as the signal delivery is not really evenly distributed. In
	fact it might never be distributed across all threads ever in
	the way it is written.

To me even the

	This primarily tests that the kernel does not favour any one.

comment doesn't look right. The kernel does favour a thread which hits
the timer interrupt when CLOCK_PROCESS_CPUTIME_ID expires.

The new version simply checks that the group leader sleeping in join()
never receives SIGALRM, cpu_timer_fire() should always send the signal
to the thread which burns cpu.

Without the commit bcb7ee79029d ("posix-timers: Prefer delivery of signals
to the current thread") the test-case fails immediately, the very 1st tick
wakes the leader up. Otherwise it quickly succeeds after 100 ticks.

As Thomas suggested, the new version doesn't report the failure on the
pre v6.3 kernels that do not have the commit bcb7ee79029d; this is a
feature that obviously fails on the older kernels. So the patch adds the
new simple ksft_ck_kernel_version() helper and uses ksft_test_result_skip()
if check_timer_distribution() fails on the older kernel.

Signed-off-by: Oleg Nesterov <oleg@redhat.com>
---
 tools/testing/selftests/kselftest.h           |  14 +++
 tools/testing/selftests/timers/posix_timers.c | 103 ++++++++----------
 2 files changed, 61 insertions(+), 56 deletions(-)

diff --git a/tools/testing/selftests/kselftest.h b/tools/testing/selftests/kselftest.h
index 541bf192e30e..6aab3309c6a3 100644
--- a/tools/testing/selftests/kselftest.h
+++ b/tools/testing/selftests/kselftest.h
@@ -51,6 +51,7 @@
 #include <stdarg.h>
 #include <string.h>
 #include <stdio.h>
+#include <sys/utsname.h>
 #endif
 
 #ifndef ARRAY_SIZE
@@ -388,4 +389,17 @@ static inline __printf(1, 2) int ksft_exit_skip(const char *msg, ...)
 	exit(KSFT_SKIP);
 }
 
+static inline int ksft_ck_kernel_version(unsigned int min_major,
+					 unsigned int min_minor)
+{
+	struct utsname info;
+	unsigned int major, minor;
+
+	uname(&info);
+	if (sscanf(info.release, "%u.%u.", &major, &minor) != 2)
+		ksft_exit_fail();
+
+	return major > min_major || (major == min_major && minor >= min_minor);
+}
+
 #endif /* __KSELFTEST_H */
diff --git a/tools/testing/selftests/timers/posix_timers.c b/tools/testing/selftests/timers/posix_timers.c
index d49dd3ffd0d9..64c41463b704 100644
--- a/tools/testing/selftests/timers/posix_timers.c
+++ b/tools/testing/selftests/timers/posix_timers.c
@@ -184,80 +184,71 @@ static int check_timer_create(int which)
 	return 0;
 }
 
-int remain;
-__thread int got_signal;
+static pthread_t ctd_thread;
+static volatile int ctd_count, ctd_failed;
 
-static void *distribution_thread(void *arg)
+static void ctd_sighandler(int sig)
 {
-	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
-	return NULL;
+	if (pthread_self() != ctd_thread)
+		ctd_failed = 1;
+	ctd_count--;
 }
 
-static void distribution_handler(int nr)
+static void *ctd_thread_func(void *arg)
 {
-	if (!__atomic_exchange_n(&got_signal, 1, __ATOMIC_RELAXED))
-		__atomic_fetch_sub(&remain, 1, __ATOMIC_RELAXED);
-}
-
-/*
- * Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID
- * timer signals. This primarily tests that the kernel does not favour any one.
- */
-static int check_timer_distribution(void)
-{
-	int err, i;
-	timer_t id;
-	const int nthreads = 10;
-	pthread_t threads[nthreads];
 	struct itimerspec val = {
 		.it_value.tv_sec = 0,
 		.it_value.tv_nsec = 1000 * 1000,
 		.it_interval.tv_sec = 0,
 		.it_interval.tv_nsec = 1000 * 1000,
 	};
+	timer_t id;
 
-	remain = nthreads + 1;  /* worker threads + this thread */
-	signal(SIGALRM, distribution_handler);
-	err = timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id);
-	if (err < 0) {
-		ksft_perror("Can't create timer");
-		return -1;
-	}
-	err = timer_settime(id, 0, &val, NULL);
-	if (err < 0) {
-		ksft_perror("Can't set timer");
-		return -1;
-	}
+	/* 1/10 seconds to ensure the leader sleeps */
+	usleep(10000);
 
-	for (i = 0; i < nthreads; i++) {
-		err = pthread_create(&threads[i], NULL, distribution_thread,
-				     NULL);
-		if (err) {
-			ksft_print_msg("Can't create thread: %s (%d)\n",
-				       strerror(errno), errno);
-			return -1;
-		}
-	}
+	ctd_count = 100;
+	if (timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id))
+		return "Can't create timer";
+	if (timer_settime(id, 0, &val, NULL))
+		return "Can't set timer";
 
-	/* Wait for all threads to receive the signal. */
-	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
+	while (ctd_count > 0 && !ctd_failed)
+		;
 
-	for (i = 0; i < nthreads; i++) {
-		err = pthread_join(threads[i], NULL);
-		if (err) {
-			ksft_print_msg("Can't join thread: %s (%d)\n",
-				       strerror(errno), errno);
-			return -1;
-		}
-	}
+	if (timer_delete(id))
+		return "Can't delete timer";
 
-	if (timer_delete(id)) {
-		ksft_perror("Can't delete timer");
-		return -1;
-	}
+	return NULL;
+}
+
+/*
+ * Test that only the running thread receives the timer signal.
+ */
+static int check_timer_distribution(void)
+{
+	const char *errmsg;
 
-	ksft_test_result_pass("check_timer_distribution\n");
+	signal(SIGALRM, ctd_sighandler);
+
+	errmsg = "Can't create thread";
+	if (pthread_create(&ctd_thread, NULL, ctd_thread_func, NULL))
+		goto err;
+
+	errmsg = "Can't join thread";
+	if (pthread_join(ctd_thread, (void **)&errmsg) || errmsg)
+		goto err;
+
+	if (!ctd_failed)
+		ksft_test_result_pass("check signal distribution\n");
+	else if (ksft_ck_kernel_version(6, 3))
+		ksft_test_result_fail("check signal distribution\n");
+	else
+		ksft_test_result_skip("check signal distribution (old kernel)\n");
 	return 0;
+err:
+	ksft_print_msg(errmsg);
+	return -1;
 }
 
 int main(int argc, char **argv)
-- 
2.25.1.362.g51ebf55


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240409133802.GD29396%40redhat.com.
