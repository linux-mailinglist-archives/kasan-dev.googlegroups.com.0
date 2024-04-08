Return-Path: <kasan-dev+bncBDAMN6NI5EERB36Z2GYAMGQEROUER2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id A776589CE5E
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Apr 2024 00:17:20 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-3450bcc1482sf690396f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Apr 2024 15:17:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712614640; cv=pass;
        d=google.com; s=arc-20160816;
        b=TtLD+mH2PJzgZ+hWvaKVUweu8WL+rKTTLigquLDNxczLinCAekFnnQ8M1ISbZnJRm8
         FS4SZUMiN79ALxzgE7E9gtx2UL8+K3GVKdtGyjUTcUFNJsmxeUibGT/VKzZtE4DWbxcA
         eKusEELkfd1bZIQKT8g/L7n8cTIFqmzp4y7jYodMCfAKft4RcKivFOqwuqzZg8hcoj5O
         Kq74Ru0kybfCjRaengxllBhBrxKnnoTbtC7ZeCfcOouxWH15YfjFtINsvvEJP0dCE6LN
         ffT/mUxmLXRbFU4REbCZ9TAu1gwE9i6XCLFFBUqdkR8puNeFXqVdoPghgeqK5yfPKYYY
         Iw9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=5Gvj4sB+Tc2oWzAVQqg0n+iQTFqZwbtZUaN4euxSunc=;
        fh=lfwYc/dxDhbKGPkqBqX3lyDPd2U9JLnYR/6p6niV1ro=;
        b=0reOXbhXhjHhSvNRsDP6+UjND4HJ6/zacSGGzFknpAOiEC1xnfyX6EaPj82BkSqSYD
         QP3ZpSoRJuTbC9V8moXSEQMz2mK7H/u8xaN5RMTB8hJ0MYYrdrF/kCT0gjZh+hLtATPR
         /Hhuyb8sOKLYJsVpcfx5mtqJ3Lgi+kmGsNEUnN8K5TfDgYelmJnyUXev5/TLW4c9Y5Q5
         BISdHGv40IqdPuTwC7AebnWEtdtFkJ7F49sgQoobX5P8jM3dvqGQ0bcMWwwupTXaty00
         ibJiI5Adic++eyli4p5JPR1oVzzQo8e+vKkHSd5pXrzsIcQFo3K+VsFIlWxVabO7Xw0x
         ACSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=HQn0DlXC;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=2tsU0bRX;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712614640; x=1713219440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5Gvj4sB+Tc2oWzAVQqg0n+iQTFqZwbtZUaN4euxSunc=;
        b=rgcfvok0XJFrwdr7A2qL6Hb64rx8B8B9U8fepYDIAFm89hiWT5bllvkTLNHl39wr9F
         NAP7gzl9FChlfrOVZAu9NcLXEHGRXg2d8wJUliWgRp/BWZ7er/xpTyCvJ3pP899o4Wlc
         F5Sylze67Iwg7pX2Y7H+wTKqz++QCuTY+5TPDdey1As5FF9SCXFIbmd7W20D/VrB0p7G
         Y9OwIVUR0XF9f/WIge1G708s1omh7Lf36e4vJU1nAkvhZ3NzyN9hVl4LpAsf0op3F5kJ
         vORZYWn1LkLkxxzI1vKTtjJgiKuc53B4TDZsJogXxZ1dTq8mFDDz2rN5qtMvIldeXtv5
         LheQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712614640; x=1713219440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5Gvj4sB+Tc2oWzAVQqg0n+iQTFqZwbtZUaN4euxSunc=;
        b=NXeJs7JAKRAjFGCmoFOiGSUKANynVOoO3y45HbyxEaX9tNxHsfMyod65WD42v0WZGT
         dlN0aB8sbmfStPTlaMRY8orNU2PWFPke91o6PFRwv/oeaqnyIljRG+ogDRzRTrnR+5Wj
         95o9deqqvDFIHs6IE89wYOnmo8qaDwfKFdMO4Umm2dueLoACAXd8LZTVgL+8uJlK9YSc
         03pdJXb5eCmBVW9foXg8rvMzG7SkxH1Ggt5pJEP+WJyaJf4rY+rTjjX4PGswGa9G5aLN
         2C4BXS5rW7P/U7Yiv8d1VgwtkPl7FmUUFSOFAXKCoBTX+tGbTvjh/2EcZE6ybn2iQHeI
         GN5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVK7+CSBDbqcShxep2dBjEJfGZE9axO0PftkQYQ/FOJV7RcVa6kA080iHbfNREq1FZjSlly6U1rBMHDm/i6TnwMa9FMWSVrfw==
X-Gm-Message-State: AOJu0Yz1bSJGHduaDb3e4MXTwS0CWt3iqsu4fjEnuVeXHLaCM6MDAqLi
	571+nw8XinehiDHQER0r/RSfrsNaaE6Ykm3ZC8Qmw1rDxulu1NL4
X-Google-Smtp-Source: AGHT+IG9Yx7N4zs15oL8SAkDWQvmmjcwsNvCoYtjvpNwkrVEVcAfZaPj2TeG/zFUeJ3GvQPyymsIsw==
X-Received: by 2002:a05:600c:3b27:b0:416:7e7e:98fd with SMTP id m39-20020a05600c3b2700b004167e7e98fdmr2123820wms.3.1712614639546;
        Mon, 08 Apr 2024 15:17:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d13:b0:416:664d:e4c6 with SMTP id
 l19-20020a05600c1d1300b00416664de4c6ls823540wms.1.-pod-prod-06-eu; Mon, 08
 Apr 2024 15:17:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnJtrR4y4vDlbZvch1rExJDHMXgOME9w1yiQwjOpSYFxooz9oRO/sACmPWpNz7Vven6z4aViEZKHDI8AqwLK7DTxjhAfA4nAp+7Q==
X-Received: by 2002:a05:600c:1f0f:b0:416:536b:b6bb with SMTP id bd15-20020a05600c1f0f00b00416536bb6bbmr3826517wmb.23.1712614637293;
        Mon, 08 Apr 2024 15:17:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712614637; cv=none;
        d=google.com; s=arc-20160816;
        b=JREt6MPozWT54e1/nyQTZY6bXxDqpgOFGcXQle9A/HMroaEP4wRqgDmA80M6WU+8Fd
         JtIct11w+eOoJSFx/ERsIWjRnJfYi0KvDb+ptQW4BJqMtemguLuJi7IJTYajH388Hc0n
         pPGcv763mnlKYhpzDcqPCaXVe/k4jgFQJ7nkVQ74C0jehxXbSqW60D6/jmieGou0Pz7j
         FYJoegUSmHe2pHAaN5WQRUDcfFiZy6vGBQSGxBM25NlrnJZML3S0/BF6PIu/ya+qpUCU
         iH9QpRyUBF6tYM58DaIaNMrfzsWpJh4FNrzXUjzmIn69pxXKU7yKNviaoTixGEMNYdAW
         /QEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=Mmbn5DsA9ubK+0jZ4PQnylXNHi12qhjspWzNa9zKp8Q=;
        fh=4Nv/nEfyFs8DOpffvrTsm+4TdL3Ck8nKKOoUBFJ9uL8=;
        b=g/bktRiEUCWpbhm6ezlw/RvV2RC3OGrtqAIAE+YaEwb+G4G3ITcH9f0oDxIBfW2sSH
         3WNdfDeN4veXBS5ZH3RInQWkUPLTxm5b1C+n5st0yHvbp5W2vKjkC2a4PtxnMZO+v5AF
         zEqsmoEgjM+DpN/Q8PAPuQq8Zpx4QawBQO4UN66hKFCVkSxLkifKrAAA9+MVlv8dz9ZV
         YWNLY4RDRWyV8qXKq7MQDXHwWUyZN7FoIWOCjRaJkSaDcBokWECRYEL7AOwXyTmzfwgF
         ScbONFdyvnMV4tvrOBEsEQJllUUqn/H9T1tvXS+W1R/MysjYh7njUSl/QSotuXsYFZmV
         uF2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=HQn0DlXC;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=2tsU0bRX;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id g38-20020a05600c4ca600b00416414a841asi188466wmp.0.2024.04.08.15.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Apr 2024 15:17:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Oleg Nesterov <oleg@redhat.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, Edward Liaw
 <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
In-Reply-To: <20240408184957.GD25058@redhat.com>
References: <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx> <20240406150950.GA3060@redhat.com>
 <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com> <20240408184957.GD25058@redhat.com>
Date: Tue, 09 Apr 2024 00:17:15 +0200
Message-ID: <87il0r7b4k.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=HQn0DlXC;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=2tsU0bRX;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Mon, Apr 08 2024 at 20:49, Oleg Nesterov wrote:
> To me this test should simply do
>
> 	ksft_test_result(!ctd_failed, "check signal distribution\n");
> 	return 0;

Right.

> but I am not familiar with tools/testing/selftests/ and I am not sure
> I understand the last email from Thomas.

The discussion started about running new tests on older kernels. As this
is a feature and not a bug fix that obviously fails on older kernels.

So something like the uncompiled below should work.

Thanks,

        tglx
---
--- a/tools/testing/selftests/timers/posix_timers.c
+++ b/tools/testing/selftests/timers/posix_timers.c
@@ -184,80 +184,83 @@ static int check_timer_create(int which)
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
-}
-
-static void distribution_handler(int nr)
-{
-	if (!__atomic_exchange_n(&got_signal, 1, __ATOMIC_RELAXED))
-		__atomic_fetch_sub(&remain, 1, __ATOMIC_RELAXED);
+	if (pthread_self() != ctd_thread)
+		ctd_failed = 1;
+	ctd_count--;
 }
 
-/*
- * Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID
- * timer signals. This primarily tests that the kernel does not favour any one.
- */
-static int check_timer_distribution(void)
+static void *ctd_thread_func(void *arg)
 {
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
+	return NULL;
+}
+
+static bool check_kernel_version(unsigned int min_major, unsigned int min_minor)
+{
+	unsigned int major, minor;
+	struct utsname info;
+
+	uname(&info);
+	if (sscanf(info.release, "%u.%u.", &major, &minor) != 2)
+		ksft_exit_fail();
+	return major > min_major || (major == min_major && minor >= min_minor);
+}
+
+/*
+ * Test that only the running thread receives the timer signal.
+ */
+static int check_timer_distribution(void)
+{
+	const char *errmsg;
+
+	if (!check_kernel_version(6, 3)) {
+		ksft_test_result_skip("check signal distribution (old kernel)\n");
 		return 0;
 	}
 
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
+	ksft_test_result(!ctd_failed, "check signal distribution\n");
 	return 0;
+
+err:
+	ksft_print_msg(errmsg);
+	return -1;
 }
 
 int main(int argc, char **argv)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87il0r7b4k.ffs%40tglx.
