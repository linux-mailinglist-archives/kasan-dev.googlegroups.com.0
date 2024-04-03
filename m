Return-Path: <kasan-dev+bncBDAMN6NI5EERBBUJW2YAMGQEUCFXIUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C45F897545
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 18:32:08 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-516ae78d9a7sf13092e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 09:32:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712161927; cv=pass;
        d=google.com; s=arc-20160816;
        b=tLwR7jw8wsTei15Of5ht4Gs3yUTE0mFq+Q0SYbfsUahzuvjynoLCW8ZhEIaFKEMiMw
         c1AMp40T6ysHXIQUn61Zh6ofWoAl6XnccCs69OgPm0O6G5LjZ0zWHvDm1aID6W+GA/so
         VCnSw8H/MgP7PGx+I756BDoB4lGO0/0qj6T06FL5OpyFeFHEHIerrReWiquSvEASpv7Z
         Iym6Uz0F9889PQ4nh/LAk0wvV/yK2MLERFCseh4RTXTnVqbvSFp8LMS+R7DcDJxPKhrR
         0sVR1+pCtw4lflDp7t7ZhtwVwkpVMaK39sSFO1nifmPtn4h4uEyS7HxfVFiZ71eTIiFw
         gbig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=wY0j6CmIMkSHcdNe/sGyaw0J+zNEcjLJkD95LQz881o=;
        fh=NO6qjSv8nlebqIQLrdVdQKas75FtwQtjM/YQC2ASlxA=;
        b=zUNMRyVGqkWDFDOwG3vzGoTcTXHvNxVlziYBuSWvu4LxBST2g2TtFvfcLbYPdWtzxm
         yMhVUEpkce10jTPz16Hq7dSFWZigUaFMCcLhvN7AZNz7654Vfx6ArCyqhHq/mYMSPw6M
         kualoiwTc9jmXwAyczMyvVFFkgLdWGG5GPgF2R6bbZUoVJ2IiV/XreSWiBY8zf3aUD2q
         U1OEQhF370+rNvArTpYn34ME4TCPwndhdGCHI2ag1PzG8vvYpf0Rhdspt3wBGwDd4xe7
         6sCJEFiK4xK3PYmX1zKKvFee8ih63HnUOMsHd6W2Gw6vJtavY2hI9CGYBhMq285HNhkT
         Kurg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Ouf7GHaC;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712161927; x=1712766727; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:in-reply-to:subject
         :cc:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wY0j6CmIMkSHcdNe/sGyaw0J+zNEcjLJkD95LQz881o=;
        b=XFg8yDVxmcO2RWO+oiC7dNCrK6p2y8jnr2BCuRItyMABoXqREjdEPDdhonOb1sM3Ov
         RQM599A1lbA2bH0o/Z/4te6fT6p9ivxGJw52GkQgh71egtKqWJQcrY5RBT+B6/nAK7jS
         YjARJUZnN5nQ/thCgNQRw7dCR7DwTbyVqn+Lp21SSx4z2s5hA+VKbW+/Fl7RU+KoZ1qu
         roHi5xbq1Jhh2bb43lKYWp3x6i+JT3DIedje1Wutbv89YfsboX8KWeZbJl6GdJUK+81o
         zN7HilkSqMZUDQeM16SVOUDzD/n5Z0S4NHI7n+HQHh5FRAfO2hb5WMzJz7A2SeetXn9Q
         XLcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712161927; x=1712766727;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:in-reply-to:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wY0j6CmIMkSHcdNe/sGyaw0J+zNEcjLJkD95LQz881o=;
        b=vEz75Izzch18v2K/z9QwMBk+E6lCeZ1omKdj77wTSfQ5OS/7c1oF/+52TDk3z2LPsQ
         bHSfjtP4lNJaxXHXkq1BuuYSEXqMsWzn/2mlBzgQOvHsChz0Z4imoS1+x6vTDppRm/vp
         I1l8w4TwDsceao8cJG8Tk9cia0CWtVv907y4KZwwon2hiJPDxzfNutuqwr/Mq3HQGFZM
         U1S/Qr3D6fFc0LiwypHCr91on9vrD5z3+LbXzlSwCJnxdFkxDiTrQsnMbBp1fQJwTd9b
         hSM4UDfu50Ao0dSNY0jhozKgIGjcjepd7sFrg0imtUdE0bz1JMFL5icP50spfLKb9IW/
         wG7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3K6P0Xvh8KRJ4vmwJrUxSkDGK4o0rsNndG+Bn2iLHGrOUvmnnjic/UbQVgyXJxcgNKEr4JbKX7axOdxJhoJJ69E8k7+DgGQ==
X-Gm-Message-State: AOJu0YxvWLPrWCWod4NKPqkPrr4f854axq/PpDFZb7ROmOM4JpN4060O
	kTv1jMo4mPIUCqqzoQzjcVyK/HGYlO7mGA0VGyVaXgIXD/uiI5Lk
X-Google-Smtp-Source: AGHT+IFrI91D7OGGx6n1PrCcecGSG7Y+FoE3Nr+L/ZXGPullSqOy5lA5WIE5azD3qHE/pOlFwLx4eQ==
X-Received: by 2002:ac2:5dda:0:b0:513:b30c:53c7 with SMTP id x26-20020ac25dda000000b00513b30c53c7mr17033lfq.10.1712161926751;
        Wed, 03 Apr 2024 09:32:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a08:0:b0:515:bf5a:b49 with SMTP id q8-20020ac25a08000000b00515bf5a0b49ls40676lfn.1.-pod-prod-04-eu;
 Wed, 03 Apr 2024 09:32:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXZonSpYCG2oLUn/By0D8GhbHUkW76NpOP9P0q6GqtanX+XlkX7XK76FoEmGdNjlt8ammInNf1Sn/v7JQwKgw7X/E3/9r4YEHQQw==
X-Received: by 2002:a05:651c:488:b0:2d8:2f0f:14c9 with SMTP id s8-20020a05651c048800b002d82f0f14c9mr40221ljc.33.1712161924450;
        Wed, 03 Apr 2024 09:32:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712161924; cv=none;
        d=google.com; s=arc-20160816;
        b=BRlxmrGgQGYvWLLDMXEVCW5AAT1VGzJfys17gv+pPDJnzIk7ZLi/s/p29yws4hSzvJ
         1PnRtW7ktpuqOqXF/eUKIr2V5dRfsvuN8lk9UcSf+c3leqiq3DtFIIigiJx38roxOTjm
         AlqiMi2lFo+eKG1mJLVmrPhLBbdz2c1iUk3u7ItpA7NKMSy9xhAuU6bniZgjfE5sg/EZ
         DKdQjK7lyfmplGFGzcs3GA0iRgWxQ7uQd3KhaWMVHk31/7/R7tyFHBcQrMf+857aEUf6
         NaXXAZuW5WZzyi5vTzUhRkThhYjYyGcXrtamG+UsdXuJKxEsZq9oF1njaKQzAZaSljUP
         WDuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=QL5+NDE0RM/D6PNrdYdHtXWw+c3iYIalpqMyMeR1Y8E=;
        fh=OuAojZ9XtyzR6STIF2qTI9iuNn5xasdqzotJ7hmY3kQ=;
        b=avwjQf8jL420WpBSb7xFS2mvGLKzJEB+bcxHcSbMHDqOBkq8KwojEK1tfIKTr6quOP
         Ba+3hgdtzuF0nH1DReQWzrWLNx1cq+NSweebL0ywIjRsRE8ZMaq8hdTr4/FAPJD0le3c
         vrUPcypDKvDsxyfNVV8dA4HfcFYLKoxrEfz7ZF1IZDIg/8/3mo0ITKSFdAUJiOT1QxVV
         axXyMXB+4nuydbMjt1qbYY0XZRKNTIzdceHU0Gipz4jyEJHWj3CqhdCa677+afPt35Mm
         Inp4k39uuNyfqbTpyYo6MaddvhhnLuSBFVLxXldM6c48sBc8IPEybqSpoPD+mT3Bo0w/
         Mngg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Ouf7GHaC;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id w11-20020a2e300b000000b002d83db42d33si56605ljw.6.2024.04.03.09.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 09:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Oleg Nesterov <oleg@redhat.com>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
In-Reply-To: <87sf02bgez.ffs@tglx>
Date: Wed, 03 Apr 2024 18:32:02 +0200
Message-ID: <87r0fmbe65.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Ouf7GHaC;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Wed, Apr 03 2024 at 17:43, Thomas Gleixner wrote:
> On Wed, Apr 03 2024 at 17:03, Oleg Nesterov wrote:
>>
>> Why distribution_thread() can't simply exit if got_signal != 0 ?
>>
>> See https://lore.kernel.org/all/20230128195641.GA14906@redhat.com/
>
> Indeed. It's too obvious :)

Revised simpler version below.

Thanks,

        tglx
---
Subject: selftests/timers/posix_timers: Make signal distribution test less fragile
From: Thomas Gleixner <tglx@linutronix.de>

The signal distribution test has a tendency to hang for a long time as the
signal delivery is not really evenly distributed. In fact it might never be
distributed across all threads ever in the way it is written.

Address this by:

   1) Adding a timeout which aborts the test

   2) Letting the test threads exit once they got a signal instead of
      running continuously. That ensures that the other threads will
      have a chance to expire the timer and get the signal.

   3) Adding a detection whether all signals arrvied at the main thread,
      which allows to run the test on older kernels and emit 'SKIP'.

While at it get rid of the pointless atomic operation on a the thread local
variable in the signal handler.

Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
---
 tools/testing/selftests/timers/posix_timers.c |   41 ++++++++++++++++----------
 1 file changed, 26 insertions(+), 15 deletions(-)

--- a/tools/testing/selftests/timers/posix_timers.c
+++ b/tools/testing/selftests/timers/posix_timers.c
@@ -184,18 +184,19 @@ static int check_timer_create(int which)
 	return 0;
 }
 
-int remain;
-__thread int got_signal;
+static int remain;
+static __thread int got_signal;
 
 static void *distribution_thread(void *arg)
 {
-	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
+	while (!done && !got_signal);
+
 	return NULL;
 }
 
 static void distribution_handler(int nr)
 {
-	if (!__atomic_exchange_n(&got_signal, 1, __ATOMIC_RELAXED))
+	if (++got_signal == 1)
 		__atomic_fetch_sub(&remain, 1, __ATOMIC_RELAXED);
 }
 
@@ -205,8 +206,6 @@ static void distribution_handler(int nr)
  */
 static int check_timer_distribution(void)
 {
-	int err, i;
-	timer_t id;
 	const int nthreads = 10;
 	pthread_t threads[nthreads];
 	struct itimerspec val = {
@@ -215,7 +214,11 @@ static int check_timer_distribution(void
 		.it_interval.tv_sec = 0,
 		.it_interval.tv_nsec = 1000 * 1000,
 	};
+	time_t start, now;
+	timer_t id;
+	int err, i;
 
+	done = 0;
 	remain = nthreads + 1;  /* worker threads + this thread */
 	signal(SIGALRM, distribution_handler);
 	err = timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id);
@@ -230,8 +233,7 @@ static int check_timer_distribution(void
 	}
 
 	for (i = 0; i < nthreads; i++) {
-		err = pthread_create(&threads[i], NULL, distribution_thread,
-				     NULL);
+		err = pthread_create(&threads[i], NULL, distribution_thread, NULL);
 		if (err) {
 			ksft_print_msg("Can't create thread: %s (%d)\n",
 				       strerror(errno), errno);
@@ -240,7 +242,18 @@ static int check_timer_distribution(void
 	}
 
 	/* Wait for all threads to receive the signal. */
-	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
+	now = start = time(NULL);
+	while (__atomic_load_n(&remain, __ATOMIC_RELAXED)) {
+		now = time(NULL);
+		if (now - start > 2)
+			break;
+	}
+	done = 1;
+
+	if (timer_delete(id)) {
+		ksft_perror("Can't delete timer\n");
+		return -1;
+	}
 
 	for (i = 0; i < nthreads; i++) {
 		err = pthread_join(threads[i], NULL);
@@ -251,12 +264,10 @@ static int check_timer_distribution(void
 		}
 	}
 
-	if (timer_delete(id)) {
-		ksft_perror("Can't delete timer");
-		return -1;
-	}
-
-	ksft_test_result_pass("check_timer_distribution\n");
+	if (__atomic_load_n(&remain, __ATOMIC_RELAXED) == nthreads)
+		ksft_test_result_skip("No signal distribution. Assuming old kernel\n");
+	else
+		ksft_test_result(now - start <= 2, "check signal distribution\n");
 	return 0;
 }
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87r0fmbe65.ffs%40tglx.
