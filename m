Return-Path: <kasan-dev+bncBD66N3MZ6ALRBMOMYWYAMGQEMDTATYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 61CC989AB8C
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Apr 2024 17:11:47 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4343f23080fsf34706521cf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Apr 2024 08:11:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712416306; cv=pass;
        d=google.com; s=arc-20160816;
        b=MgI1NuxZJ45U8MC53xm1yHSc2JHD5lphQLn2jsVXr8xQl5/MvSCL6TAlzyBl7k7dCm
         KyQyR1J4i9tt/z6xHfDlsJ6AcQZMXPFdiHfwUHhvsgd75hF4Z6yN6HLG6AVDvj9RqKf7
         EQpI1UsrqQU0Wmrlh4ywylsoBQwH0Hy/m7wBKS1AOFPv83fsGw8lsoNbZuFvfgL10r3I
         I87afKp3q8EAz9GO2TQhwjb3xVUwkfN9mRZpPcUE75giFqtmXHd1jOqu4ZRXxYLE4jar
         0I4e+ELnrIsnfglkTVEzooEQqMvvsiKF8YCtebKOPrxlXjFBRo6x/DmpTVZwb3SG8Tct
         O6sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=sk8MOGLYY1uS6MMhih2pExTCfbfy9H1UcuB5+xrDPE4=;
        fh=CbxpHSxoLeEIqrJldc2vZ7MU4aTqrtJCaRoqX8ydFiw=;
        b=T5iWkiQvWlaVJYA+dMOh139CxoYtOejGIvt3NTaYZdA8//6REc7FZcbnaJIPMguiQh
         qimqtEAJHAoXkMvAIWgoUtAx3EKXcsvUolpkLQWkDDYwtjdZ+UPPuwVKrd7yWcciP0Ak
         vtOFbckYK45vnDc2v6apRb8kLlO47I13D1ScRVLJHOBV88lLzobgBWgw+WQ02rB94Wgi
         nWFp+/KMapQEJ49SE15B7wIhLLT0sGzl/l4nMR0SOVodZwTJb/iYNPtYmx6n8L8cqW5q
         ovbqlJu4ciOUVFm07dtYxt3QnwD55rwwqhYA9YbKj0o8vSL0b2J753LPEibF9iQjszw3
         z7EA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712416306; x=1713021106; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sk8MOGLYY1uS6MMhih2pExTCfbfy9H1UcuB5+xrDPE4=;
        b=CrsoxViQcY9FM9Ao5zZME84ae6tpwhPqBVyYwWjOaEgJ2/FvNGiiDNLUwA09GbD8i/
         ImCyUY3mAfscRSFa82GBnPdDR8pXwK+WNbsr86l4W1Z7QntjUFlN5T250XO+fEAt0TPH
         pYCBavdh4FggDgSBbsldCYtOt3UaHzlD0odkgJIsL+b99V5x7d6rZi7rNvVvB7CPc/dw
         cc/TE7eBjSs66k6CvVyOi58z9TQuwvn9Tbn/z3De/4qr0G7VPwVOD5w5Fm078otOCk8E
         FmxK8LACf7kZLxgkQhab7ZjL9bgtHFDWkboTUDDohJbxNFbxhi30agyQeQc0OoGOziz9
         HNiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712416306; x=1713021106;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=sk8MOGLYY1uS6MMhih2pExTCfbfy9H1UcuB5+xrDPE4=;
        b=gjOEfyHzfbnROLmXcTg4MOBxbhSInUIAIvKAZgMxMk/Icb8NUr4K6Gd1cs2d50/9b9
         o4yawt30OZu616LZb+dEP7ET5jwpO5AvWLeyIEixZP0d0gOV31TcMKWGdKfabXQIUuD1
         NOsvzdXwBFLpfRVIF7DjuqnmJHOK2YvRVkvnyrHLagDepIjqAEbwf7zcBi9/AEd2IWw1
         jTIRPFXfXnVk47Zmsq6s1pB22vMh2Ck6BRq4JMPxdH3NXW+EjdUYzwGghzZTvDX0l2gE
         6Ta2IxJspjNPvy1jZyNe3F9sbGbgEVtffrDAES05nz1iE+iF/H05qAMFJT9fPR0cvPWt
         RUhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGqPGXECI2zXY1+Fl9825aoeirbd/XtHu0WG8JItqYpK4tqnVD6V48qLte3v8jSubTaMzqRDCeVtQPPL8CDBQps8JeWVKCHw==
X-Gm-Message-State: AOJu0YxIHJs6uRswNWSYZH0ikk30Iu+3xFJuA2vFLet7hxJQS82wAo5L
	W5q+Bl3R7VAchOiMPtF5QTW1b3KGSJZnjDv7vJygCttUHeqOSMUL
X-Google-Smtp-Source: AGHT+IHrmclW1iaVr9WFnGG4LpqY+IivuG3Izm01VWJp84EU9WeDzIW3ndy7cSps2E7i2Ro2oxFNTg==
X-Received: by 2002:ac8:5992:0:b0:434:7b16:96bb with SMTP id e18-20020ac85992000000b004347b1696bbmr1119492qte.62.1712416305885;
        Sat, 06 Apr 2024 08:11:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5ac1:0:b0:431:7c7c:abae with SMTP id d1-20020ac85ac1000000b004317c7cabaels4139287qtd.0.-pod-prod-03-us;
 Sat, 06 Apr 2024 08:11:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxY3jCyrNIybRxgc/+NPeYDhH5agEg5NYI05K/hITu+oK6FwKiDCqDufg0IFL9ONHtfO7BPJtAosH1as0DHXH+0QTJ28nKN0Vu2g==
X-Received: by 2002:a05:620a:a9b:b0:78d:39e9:2f65 with SMTP id v27-20020a05620a0a9b00b0078d39e92f65mr5010018qkg.0.1712416304944;
        Sat, 06 Apr 2024 08:11:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712416304; cv=none;
        d=google.com; s=arc-20160816;
        b=mquarVhRujRqUI7m2DpJe2ORexClZei1pQPbXVtabG9ewlBfQUdIRIuLcySAGM0Zm2
         eARWWtwGWJpA5GxDtqj4sGxdtJ6NvcmmUuI1z/e6fjrxD+O7KM0f7qDf9y74P7L5oNhi
         eywTgfdbS8sQCn6ayqlWvQWD+QqVWCL8H6Mgdmyr0RnGL0Y5INnK8MsdNts6bHHkgLCO
         QFLTo5n2fP4T5EXHt6MWQZ4k06a5vJ0hqeAFuZXwZyC0hroG+14iH+qYkyo0gflD+/C8
         0m36PHaM5mFP8b2PeSj+RCQ9QUG/rqE8B1eZ17v8IvlFsZ0gGl5H3LROHYY2PyZKXkSA
         HMRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ig0EmkPspn25ineI/4jKY6oNuD+KZIpANNpTNpRld0A=;
        fh=QM13yX5cyx0gKVLH9qgXc292C0jk7N6nZCeRL8zZxhQ=;
        b=Cu4YXq4X90mbDD7e70bsoDzzbDjP+nLainYqhSJGT8Ug7z46zDgStRIbpNCutCcmgc
         kx4Yzt92D7upLYUb60BYiEjJ2PUnmun0K/Fi2Bx0GxQu92UpmDf64slR1HMD8WQ2sc/0
         DAUXOye5zTFqdSNn3U8EY7bGHNRIHNOe3tD6IgY3iVxV6XMlhJsfG/1ASP8H8f7WvT5Z
         LPgbx+NoTprskBU760X76i4gOSqiDHbF9K1Lhs5UiF7EDvImcX7mMNa1vQP/+mzyCYtL
         Sar78JPPM481qF6piOgEdiRIPvjan4sKfrIW35/OGfA5oe6tWP92MEaXFlB3Tz69Rzft
         44bg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id qy7-20020a05620a8bc700b0078d60d5611csi2779qkn.4.2024.04.06.08.11.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Apr 2024 08:11:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-505-8qpYagkzMxSV1T4VL2nekg-1; Sat,
 06 Apr 2024 11:11:40 -0400
X-MC-Unique: 8qpYagkzMxSV1T4VL2nekg-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id F348128AC1E7;
	Sat,  6 Apr 2024 15:11:39 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.226.136])
	by smtp.corp.redhat.com (Postfix) with SMTP id 0E9593C20;
	Sat,  6 Apr 2024 15:11:36 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Sat,  6 Apr 2024 17:10:15 +0200 (CEST)
Date: Sat, 6 Apr 2024 17:09:51 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
Message-ID: <20240406150950.GA3060@redhat.com>
References: <87sf02bgez.ffs@tglx>
 <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87le5t9f14.ffs@tglx>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted
 sender) smtp.mailfrom=oleg@redhat.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=redhat.com
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

Signed-off-by: Oleg Nesterov <oleg@redhat.com>
---
 tools/testing/selftests/timers/posix_timers.c | 102 ++++++++----------
 1 file changed, 46 insertions(+), 56 deletions(-)

diff --git a/tools/testing/selftests/timers/posix_timers.c b/tools/testing/selftests/timers/posix_timers.c
index d49dd3ffd0d9..2586a6552737 100644
--- a/tools/testing/selftests/timers/posix_timers.c
+++ b/tools/testing/selftests/timers/posix_timers.c
@@ -184,80 +184,70 @@ static int check_timer_create(int which)
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
+
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
+	if (ctd_failed)
+		ksft_test_result_skip("No signal distribution. Assuming old kernel\n");
+	else
+		ksft_test_result_pass("check signal distribution\n");
 
-	ksft_test_result_pass("check_timer_distribution\n");
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240406150950.GA3060%40redhat.com.
