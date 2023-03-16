Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQMYZSQAMGQEZMOJD3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id AF1006BCF89
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 13:32:03 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id g12-20020aa7874c000000b0062519d49a5dsf1060460pfo.12
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 05:32:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678969922; cv=pass;
        d=google.com; s=arc-20160816;
        b=wg1peQt0f1BRxIb/OrWo1p0oG9FIy9xbqEEeUq14ao4TpCoFr41S4RCiUjmerK7v7I
         zs6JMSQxxYHsX2rtA0AKu4/9sXUVlKOseNXFjZubMAxkUbvhhqmDrcHKnnH56+kRcf8C
         yh/rGoGq1QsyEahaj2J0KyFI9FBoHH5J+otyRgBALiDB8eLfYVURq2lvFW1Cjy1NcrKE
         uXYK9oNkHgjdHns2yqdKT++u7qKSPYyRMBRGnidB5LH2Rpc9/Bi1c657lNn/REb+CrGy
         KtZ5G3pxfua83g278C6inVPFZTYlJpk5fFyGnIf4sVdrFPnGkJq2bzEag50noru2YlWR
         wdbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=aYOus/8xqSffdtyW2WT6xNu/UwpTcAbiqasq5Xo8NN8=;
        b=Qs8h4gwEuatBhYUzEDodUiY6aN5x+RamFJ7LDmYkpoPUaz07TZjNGPOxDgZmY+l3jM
         Q5jgXvrJtir6xZjtTtNj+8/sNHFnCxn8Zwwv4300efvqHpZfnNgCj6hSk+5N46c5Zqvj
         BgKBsmhAiR9PwRMfRUXIgoRAoiSmhetoewLbldqxzaT2zWA8m4tFoGXGdP4zNlycKP9h
         AlzB/XbrWgipXIvtzuLDVxgWFrBwTjzb9ZSmeLJBhmYBUdh3sXW9ren93nz1K3ggr2rb
         6TxLwl2p3SSNq7r4Kwb5m0gjbqN3fPIAWg2zRcpsgMstBA+dQbetm8PE5C+8AUg0ecyU
         H9vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AyWoKrQz;
       spf=pass (google.com: domain of 3qawtzaukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QAwTZAUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678969922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=aYOus/8xqSffdtyW2WT6xNu/UwpTcAbiqasq5Xo8NN8=;
        b=cFOOMKFLgtzm7UrZRp4sqi78CYV+3cZPqTDnqCtgImC7WpakYdvnMnKfq0H4awMV9/
         9r/otRkeps4kCi+De8gc+k5bcOidSrOK7Q7EjZ+/YK9XBmFl7571KwdWAcFM+adVtotY
         OawslYeb3Kyl3HGhF4hArMMzWPGCQVbLFjwd/HNVQrJTdzKst1j7J1KsBok7uxtaFC7n
         r9O9ga3AV2vCuP+P5nWHIUOgGBTjLNoSl1IK2EefzAfPsEyfqPPj1RoxvDhVh4HAOo8S
         qa9Af7+A78JVqW/EtID63hbZq5gBhG7E7qgLSjlg4Wo5Z5Zaq/nEUwjOJHi3ExhLML0M
         ungQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678969922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=aYOus/8xqSffdtyW2WT6xNu/UwpTcAbiqasq5Xo8NN8=;
        b=B1i3JZcjwnW6ozOlx7Lwz7txgUiBoGf/3Im+LNK9QKqmhF6BiqI4shiAEx6Ia5lCNe
         mUDXIAmbinZjTVF0g1SPyVZ1P5Ug0HhASkd/rzgoXaxWaWpoAw5L3y60ADgypSG2zqTE
         tzBAlGs4g2xygF/3pNWREoKC/JtrxIsCC/i+huQFiu0fOvtaDK1wDubuHDDP93aq+55K
         gH2z9elTiOPN2krSHuo7/IGwavREUgYH0t2jkVOnxhWip7hILnCWoRhjDQuflgE/IGZX
         nwlkXqQA5R5hGufboxoaoAvrRBsQliaa3cdHR+f4Lt9tmrnthqc3GV27D94k+JWTITcw
         tb0Q==
X-Gm-Message-State: AO0yUKUu8HOTAdfk1UvB4XSOzk4Ip7xY6gp4Nfq9SX1zkqLl4EEe+281
	IDrfNE/+ShVxkFO5TY+3XKo=
X-Google-Smtp-Source: AK7set9J2CQg/HLSury0jIwElsDh3YyOI8dUf9NOelKSbQDLdXTf6lIy2wneQDrbJ4KyUdYpzgoARA==
X-Received: by 2002:a17:902:e54c:b0:19a:5953:e85c with SMTP id n12-20020a170902e54c00b0019a5953e85cmr1386503plf.1.1678969921986;
        Thu, 16 Mar 2023 05:32:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bf42:b0:19f:2451:31b6 with SMTP id
 u2-20020a170902bf4200b0019f245131b6ls1972645pls.0.-pod-prod-gmail; Thu, 16
 Mar 2023 05:32:01 -0700 (PDT)
X-Received: by 2002:a17:902:d505:b0:19d:16e4:ac0f with SMTP id b5-20020a170902d50500b0019d16e4ac0fmr4108564plg.5.1678969921081;
        Thu, 16 Mar 2023 05:32:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678969921; cv=none;
        d=google.com; s=arc-20160816;
        b=TqafI3nzEz5nYZCArUqt6zIErV9dYD2MlXtw4ucETSrb1uJOR7daninbZ771+uzL8+
         cGuigz41Ln5W8+4KyBKzN2xVIDrvi8E7BZUna/pS38djEdiB9XGfO7FBcmCDiCCpr082
         h6gJ6gmvAM+WxyKP00AJ92tt0cz38JtJ4MHB2fPO3+rQFILvoJoTIdQZD6Nvx324kb7F
         RDtyw7kvHaEnuaHyVYQ5LsRRse2uk8UEkDDB+Ultz6rSJewT3Gnx+g71/qR2Sa7kF8FM
         LtgzuiOXOTw4602rgLXdye/dPRS/bzY+kgwFxQ29czW5VhdE/LzfjgZU0siqLwMMefFD
         HGpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Wgf7EduwhN6551MQujeSUTn74g+txYbPhrHuCm2tsLY=;
        b=Hg0PzK7k7OXyTLyWtJnUV8UTagabmw5nJPrZGr0G/XZ1Gv8rSXfn80CVDgsNehe22N
         Vdd/eri60QSavKhJQutgoIJleiBLd3JR7UgnoNOdyJuj1nDdUBZjVJfowQSA+iXGTxzT
         H8WsfcNoodVq1cPqC0MliKdKn4ytegaZl9J0J9g+ne0fGALIX/3UPe5s7RsggpZdOBM3
         QdfrZVKzf8EUDtPAo5tVksGEDbJTCKZW07BjXVmEKwVuyqsLkuu0KrbL9pJFISv7IH98
         n5xZIFOeDLG3tD0i3YNahRYyiSrTMtZVTWb9G9mvDK4h85frArcIs+NEBgwh8zqI1F7w
         Vg8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AyWoKrQz;
       spf=pass (google.com: domain of 3qawtzaukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QAwTZAUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id z3-20020a170902d54300b0019c35405665si310548plf.1.2023.03.16.05.32.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 05:32:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qawtzaukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 206-20020a2504d7000000b00b3511d10748so1661655ybe.20
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 05:32:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:f359:6b95:96e:1317])
 (user=elver job=sendgmr) by 2002:a81:e508:0:b0:544:5fc7:f01f with SMTP id
 s8-20020a81e508000000b005445fc7f01fmr2036499ywl.4.1678969920431; Thu, 16 Mar
 2023 05:32:00 -0700 (PDT)
Date: Thu, 16 Mar 2023 13:30:28 +0100
In-Reply-To: <20230316123028.2890338-1-elver@google.com>
Mime-Version: 1.0
References: <20230316123028.2890338-1-elver@google.com>
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Message-ID: <20230316123028.2890338-2-elver@google.com>
Subject: [PATCH v6 2/2] selftests/timers/posix_timers: Test delivery of
 signals across threads
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>
Cc: Oleg Nesterov <oleg@redhat.com>, "Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AyWoKrQz;       spf=pass
 (google.com: domain of 3qawtzaukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QAwTZAUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Dmitry Vyukov <dvyukov@google.com>

Test that POSIX timers using CLOCK_PROCESS_CPUTIME_ID eventually deliver
a signal to all running threads.  This effectively tests that the kernel
doesn't prefer any one thread (or subset of threads) for signal delivery.

Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v6:
- Update wording on what the test aims to test.
- Fix formatting per checkpatch.pl.
---
 tools/testing/selftests/timers/posix_timers.c | 77 +++++++++++++++++++
 1 file changed, 77 insertions(+)

diff --git a/tools/testing/selftests/timers/posix_timers.c b/tools/testing/selftests/timers/posix_timers.c
index 0ba500056e63..8a17c0e8d82b 100644
--- a/tools/testing/selftests/timers/posix_timers.c
+++ b/tools/testing/selftests/timers/posix_timers.c
@@ -188,6 +188,80 @@ static int check_timer_create(int which)
 	return 0;
 }
 
+int remain;
+__thread int got_signal;
+
+static void *distribution_thread(void *arg)
+{
+	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
+	return NULL;
+}
+
+static void distribution_handler(int nr)
+{
+	if (!__atomic_exchange_n(&got_signal, 1, __ATOMIC_RELAXED))
+		__atomic_fetch_sub(&remain, 1, __ATOMIC_RELAXED);
+}
+
+/*
+ * Test that all running threads _eventually_ receive CLOCK_PROCESS_CPUTIME_ID
+ * timer signals. This primarily tests that the kernel does not favour any one.
+ */
+static int check_timer_distribution(void)
+{
+	int err, i;
+	timer_t id;
+	const int nthreads = 10;
+	pthread_t threads[nthreads];
+	struct itimerspec val = {
+		.it_value.tv_sec = 0,
+		.it_value.tv_nsec = 1000 * 1000,
+		.it_interval.tv_sec = 0,
+		.it_interval.tv_nsec = 1000 * 1000,
+	};
+
+	printf("Check timer_create() per process signal distribution... ");
+	fflush(stdout);
+
+	remain = nthreads + 1;  /* worker threads + this thread */
+	signal(SIGALRM, distribution_handler);
+	err = timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id);
+	if (err < 0) {
+		perror("Can't create timer\n");
+		return -1;
+	}
+	err = timer_settime(id, 0, &val, NULL);
+	if (err < 0) {
+		perror("Can't set timer\n");
+		return -1;
+	}
+
+	for (i = 0; i < nthreads; i++) {
+		if (pthread_create(&threads[i], NULL, distribution_thread, NULL)) {
+			perror("Can't create thread\n");
+			return -1;
+		}
+	}
+
+	/* Wait for all threads to receive the signal. */
+	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
+
+	for (i = 0; i < nthreads; i++) {
+		if (pthread_join(threads[i], NULL)) {
+			perror("Can't join thread\n");
+			return -1;
+		}
+	}
+
+	if (timer_delete(id)) {
+		perror("Can't delete timer\n");
+		return -1;
+	}
+
+	printf("[OK]\n");
+	return 0;
+}
+
 int main(int argc, char **argv)
 {
 	printf("Testing posix timers. False negative may happen on CPU execution \n");
@@ -217,5 +291,8 @@ int main(int argc, char **argv)
 	if (check_timer_create(CLOCK_PROCESS_CPUTIME_ID) < 0)
 		return ksft_exit_fail();
 
+	if (check_timer_distribution() < 0)
+		return ksft_exit_fail();
+
 	return ksft_exit_pass();
 }
-- 
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230316123028.2890338-2-elver%40google.com.
