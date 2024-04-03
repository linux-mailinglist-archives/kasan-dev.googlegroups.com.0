Return-Path: <kasan-dev+bncBDAMN6NI5EERB344WWYAMGQEQ56FCSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E463B896F07
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 14:41:21 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-414aa7bd274sf32028195e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 05:41:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712148081; cv=pass;
        d=google.com; s=arc-20160816;
        b=cOUw2yEdvYAKjzg9DDtfbw6tv6Ejz8TiXsOUk/UaI3d9qzhlY7zOimtDqo0Kq/ggBF
         6L/kMKxlyXLuvM7H4Xu2xWRHNCZy5LTeb+6IHwUYSGiiU8iNAWVA67DeIPIvB8ueZUrw
         N8FTsAl9oqwIho5qb6QnniZMuYXGkhoIGiMxcqXo3Sbe+k0oga99gcuFult2rJ0Brb7W
         awBwr9+iwj5MMZm5RQaK5QD9gsVk07JaCwqbqleYy2SLXcDlJd7t044XgaMLIfk+QaxY
         Arre42aJaYp1+DiY42p9gx4qa6eEURYPf25fpcnAn0+VcU5irJvlIAzrVuI6cu9v7HPm
         NI3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=ApRV921zyxEDXnVVeu9g6UldErYgIZ9Og/esq4SvwFg=;
        fh=wFPVZZkdqGnegJGKkdjI7MG6RA8gxGlLg1ezhgWy5ac=;
        b=WLC5e5Ev5L2A6IALqTi8EQl4/oP7jdp98BrEv8aJ8sqF3SqahqDhA67cuseAOOZ9SD
         R6OCRUGrC2Ushg8AQe6Q5zEb+ace4xyibopM1rG/Eb4wJxDUsFuBvLKgKYgRfrXsPOgU
         egExyVpkRZUfQQ8N3qVIRclEFU1DYUlHJL9SuX0lJWtRjTkEVsY0mUuJxRi8imVU+bTq
         z/LiOjgC+zyo4jvnpFpxjxwohwEGxhDT3oyHdWDb6CxY4sRlLSP7vIxDjyuBZx/N015k
         mGq0oMnqrJxTIah5OQkV7z1yKhvZIvspRevVa091FmVczA/osDPHKyxiLJ8F01GEC5BD
         vkvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=TkFrhMgP;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712148081; x=1712752881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ApRV921zyxEDXnVVeu9g6UldErYgIZ9Og/esq4SvwFg=;
        b=rSDCZH+OPwBiBopWVwGsOvs9FNQ9whiVeb9PZMDDGrInLM5A9M2GDCAtvdfhCXheqK
         aV3zy+TULRfiyGlT+z1v9NuUTr5tcrDyRf6xflcNi45dYVGpBxwzrGM03GrBpyHRoarr
         +3SLCkHp23rwOUpDffsiHlThWqLaapPitTr+173Ir7HRilKW0AoxacI61/Gdo0qPpAdb
         VhRLUsbFmISGrzV00UOh5CZNIdr/F7DZvq5ka9b1k4D2usdbDtfo1BF+oQRjBXqoBkVD
         ZxZvhc9ElhzVUZJThQlbGupjVlN9h4Q7faW7V0hH1sIFJgNz/bYBm1/8uvr5/76xIXML
         pvSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712148081; x=1712752881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ApRV921zyxEDXnVVeu9g6UldErYgIZ9Og/esq4SvwFg=;
        b=OUqqcguf59Cf7bz3BVTD0SSn7h1Cv6XpFXY/PwVpwZuAeu5hQuvVUXs3YDqGJA18ZX
         9JGaYr54lD97NZOFrxYgx5/1vy0373nPnw+z5Rgjvz0ZQuuQNzIMYZ72pBfaOAV38UWF
         uY2ikKRFWCPRbkRc1pFdI/dcLEBV4k1/zJPZLtQiufBwPOWVXNyXrqgDcQlEqk1M0QqQ
         Xiv2UxdOjs+4uuKe9b5GRxW23PYple71YALFNOWw0KpDT7DTbakEkA3gvwVK0Scr577+
         uxJEl0xBJkyRVQz6h+yBfD8mQVsjqU73jNYS4WU57Qc9nZJy4hbR20TUUYuq3+4t4RoN
         Jxbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1ytswnabX5pSwUs1iJwXoONauibO9Og86ZZcq42+K7KUeig4I6bpdoDZbzt0F8V7uGtacm6yN0kVdWHJOI5LYioqDgNxwhQ==
X-Gm-Message-State: AOJu0YzMCx1q+HIVTkJGPBLHePt5GLOuKzMfcKopLMD2MxPpXmYEIXcy
	eqVFo+88neyuqucSVHdseIeIrvsNuJ/gVMITq8yyhkRfQdYL0KZz
X-Google-Smtp-Source: AGHT+IFaHaCDgbx4qCe85puB+Uf9bQwoXXo4avBKqDoL8iClmD9zxp+6fQU/+4iDa8o+9vc8TtXZpw==
X-Received: by 2002:a05:600c:1d29:b0:413:fc09:7b19 with SMTP id l41-20020a05600c1d2900b00413fc097b19mr8641696wms.40.1712148080160;
        Wed, 03 Apr 2024 05:41:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:19cf:b0:415:509c:891 with SMTP id
 u15-20020a05600c19cf00b00415509c0891ls2455933wmq.0.-pod-prod-06-eu; Wed, 03
 Apr 2024 05:41:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVpSHKfQiZqF3DuJ+SmYQU6uHDzwp9sX+t2gP9SzHIAG2M2Sb3Mj/d5pyXxQJPA/shjHEYrqLckGYZ1XSctTbaFN8frnVPAmprJOg==
X-Received: by 2002:a05:600c:46c9:b0:415:5343:cc6c with SMTP id q9-20020a05600c46c900b004155343cc6cmr9483871wmo.33.1712148078179;
        Wed, 03 Apr 2024 05:41:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712148078; cv=none;
        d=google.com; s=arc-20160816;
        b=Fuhc5A0P1fXqrEM+gAIG9xB6Hqvyolucms3jByPPhjzTCYIjn6y73XWetIROi/eACM
         3Sg466M9Dlawuw20yBP4U7k4rsw4LlYxCYaaG9AXLvW4+wUQ6U4D5mEVpYjI/BGUZcpg
         r3TnLG3ipwh+pw2f44AZZ4XHPqLAUTW0xrh+X59Xc98miIBuF6vuCKUBvRktuRYf8S/E
         EgdDEJ5O73TOuq8TLTeYNUXbFkGwORBZE/WhOcgT6zFymsNgSyAslkWptwgYrA1B0NN9
         xeeGnwx6RwRb6m/4McNfJghpO1sDUnfasDIMbtn1Ed7+aaXWxcVrwWZgv5Q2PMLpHh/3
         iEvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=j8VcjIqJYxqL7stv0uL/vZUNq6uNvM3BP6g5mSRVMO0=;
        fh=F66kdI58HNerbKlFxDOryXtsIEE6ptPDhsXn/JDVSUI=;
        b=iimVKW4zdAhDWJ0pThZJry6hl/9kayYRe7zRdcdftQ93JhaaojJg5Fu3mbFr/l0fHu
         gpfduTSwUcj1NzUwHivxWCYNUP11cU+BHRBF8iJyFN1LSyp1ceW0IJrR4z5RHEKR4XTI
         fNLUYIR5jzCiQZAkOuBCZfr6uTaxW5bmC8dMH0OKynuKkjWFfE+l1L2FI4MWsd1FsTvc
         UZcRLEFaxKPXbCWH4O4YcKXbyo4i6xRnqL9iGRQ8l7Eo6W8+LRB46e3v4cMsf4CsMjpy
         XSPaujMF9EFphl9exbnQxa/1BcqtaQH3AuEUYhmfYfN5ZoqtxtM1qcU0OabnmRB8vnfP
         izSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=TkFrhMgP;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id dx14-20020a05600c63ce00b004161ed6e07dsi167075wmb.1.2024.04.03.05.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 05:41:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: John Stultz <jstultz@google.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Ingo Molnar <mingo@kernel.org>, Oleg Nesterov <oleg@redhat.com>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
In-Reply-To: <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
References: <20230316123028.2890338-1-elver@google.com>
 <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx>
 <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
Date: Wed, 03 Apr 2024 14:41:17 +0200
Message-ID: <874jcid3f6.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=TkFrhMgP;       dkim=neutral
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

On Tue, Apr 02 2024 at 10:23, John Stultz wrote:
> On Tue, Apr 2, 2024 at 7:57=E2=80=AFAM Thomas Gleixner <tglx@linutronix.d=
e> wrote:
>> This test in particular exercises new functionality/behaviour, which
>> really has no business to be backported into stable just to make the
>> relevant test usable on older kernels.
>
> That's fair. I didn't have all the context around what motivated the
> change and the follow-on test, which is why I'm asking here.

It's a performance enhancement to avoid waking up idle threads for
signal delivery instead of just delivering it to the current running
thread which made the CPU timer fire. So it does not qualify for fix.

>> Why would testing with latest tests against an older kernel be valid per
>> se?
>
> So yeah, it definitely can get fuzzy trying to split hairs between
> when a change in behavior is a "new feature" or a "fix".
>
> Greg could probably articulate it better, but my understanding is the
> main point for running newer tests on older kernels is that newer
> tests will have more coverage of what is expected of the kernel. For
> features that older kernels don't support, ideally the tests will
> check for that functionality like userland applications would, and
> skip that portion of the test if it's unsupported. This way, we're
> able to find issues (important enough to warrant tests having been
> created) that have not yet been patched in the -stable trees.
>
> In this case, there is a behavioral change combined with a compliance
> test, which makes it look a bit more like a fix, rather than a feature
> (additionally the lack of a way for userland to probe for this new
> "feature" makes it seem fix-like).  But the intended result of this is
> just spurring this discussion to see if it makes sense to backport or
> not.  Disabling/ignoring the test (maybe after Thomas' fix to avoid it
> from hanging :) is a fine solution too, but not one I'd want folks to
> do until they've synced with maintainers and had full context.

I was staring at this test because it hangs even on upstream on a
regular base, at least in a VM. The timeout change I posted prevents the
hang, but still the posixtimer test will not have 0 fails.

The test if fragile as hell as there is absolutely no guarantee that the
signal target distribution is as expected. The expectation is based on a
statistical assumption which does not really hold.

So I came up with a modified variant of that, which can deduce pretty
reliably that the test runs on an older kernel.

Thanks,

        tglx
---
Subject: selftests/timers/posix_timers: Make signal distribution test less =
fragile
From: Thomas Gleixner <tglx@linutronix.de>
Date: Mon, 15 May 2023 00:40:10 +0200

The signal distribution test has a tendency to hang for a long time as the
signal delivery is not really evenly distributed. In fact it might never be
distributed across all threads ever in the way it is written.

Address this by:

   1) Adding a timeout which aborts the test

   2) Letting the test threads do a usleep() once they got a signal instead
      of running continuously. That ensures that the other threads will exp=
ire
      the timer and get the signal

   3) Adding a detection whether all signals arrvied at the main thread,
      which allows to run the test on older kernels.

While at it get rid of the pointless atomic operation on a the thread local
variable in the signal handler.

Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
---
 tools/testing/selftests/timers/posix_timers.c |   48 +++++++++++++++++----=
-----
 1 file changed, 32 insertions(+), 16 deletions(-)

--- a/tools/testing/selftests/timers/posix_timers.c
+++ b/tools/testing/selftests/timers/posix_timers.c
@@ -184,18 +184,22 @@ static int check_timer_create(int which)
 	return 0;
 }
=20
-int remain;
-__thread int got_signal;
+static int remain;
+static __thread int got_signal;
=20
 static void *distribution_thread(void *arg)
 {
-	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
-	return NULL;
+	while (__atomic_load_n(&remain, __ATOMIC_RELAXED) && !done) {
+		if (got_signal)
+			usleep(10);
+	}
+
+	return (void *)got_signal;
 }
=20
 static void distribution_handler(int nr)
 {
-	if (!__atomic_exchange_n(&got_signal, 1, __ATOMIC_RELAXED))
+	if (++got_signal =3D=3D 1)
 		__atomic_fetch_sub(&remain, 1, __ATOMIC_RELAXED);
 }
=20
@@ -205,8 +209,6 @@ static void distribution_handler(int nr)
  */
 static int check_timer_distribution(void)
 {
-	int err, i;
-	timer_t id;
 	const int nthreads =3D 10;
 	pthread_t threads[nthreads];
 	struct itimerspec val =3D {
@@ -215,7 +217,11 @@ static int check_timer_distribution(void
 		.it_interval.tv_sec =3D 0,
 		.it_interval.tv_nsec =3D 1000 * 1000,
 	};
+	int err, i, nsigs;
+	time_t start, now;
+	timer_t id;
=20
+	done =3D 0;
 	remain =3D nthreads + 1;  /* worker threads + this thread */
 	signal(SIGALRM, distribution_handler);
 	err =3D timer_create(CLOCK_PROCESS_CPUTIME_ID, NULL, &id);
@@ -231,7 +237,7 @@ static int check_timer_distribution(void
=20
 	for (i =3D 0; i < nthreads; i++) {
 		err =3D pthread_create(&threads[i], NULL, distribution_thread,
-				     NULL);
+				     thread_sigs + i);
 		if (err) {
 			ksft_print_msg("Can't create thread: %s (%d)\n",
 				       strerror(errno), errno);
@@ -240,23 +246,33 @@ static int check_timer_distribution(void
 	}
=20
 	/* Wait for all threads to receive the signal. */
-	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
+	now =3D start =3D time(NULL);
+	while (__atomic_load_n(&remain, __ATOMIC_RELAXED)) {
+		now =3D time(NULL);
+		if (now - start > 5)
+			break;
+	}
+	done =3D 1;
=20
-	for (i =3D 0; i < nthreads; i++) {
+	if (timer_delete(id)) {
+		ksft_perror("Can't delete timer\n");
+		return -1;
+	}
+
+	for (i =3D 0, nsigs =3D 0; i < nthreads; i++) {
 		err =3D pthread_join(threads[i], NULL);
 		if (err) {
 			ksft_print_msg("Can't join thread: %s (%d)\n",
 				       strerror(errno), errno);
 			return -1;
 		}
+		nsigs +=3D thread_sigs[i];
 	}
=20
-	if (timer_delete(id)) {
-		ksft_perror("Can't delete timer");
-		return -1;
-	}
-
-	ksft_test_result_pass("check_timer_distribution\n");
+	if (!nsigs)
+		ksft_test_result_skip("No signal distribution. Assuming old kernel\n");
+	else
+		ksft_test_result(now - start < 5, "check_timer_distribution\n");
 	return 0;
 }
=20


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/874jcid3f6.ffs%40tglx.
