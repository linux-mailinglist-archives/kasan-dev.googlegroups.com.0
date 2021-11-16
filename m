Return-Path: <kasan-dev+bncBDZ7JWMQ2EGBBTOSZ2GAMGQEGBFXFXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C13FE453269
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 13:51:26 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id g12-20020a0562141ccc00b003c0322ea7b6sf13133880qvd.19
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 04:51:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637067085; cv=pass;
        d=google.com; s=arc-20160816;
        b=j+R5p3B1Z1OUDvMzWaCxI6dNa8WUh1JGwHEG1xv8zjxr19eR2j6ggmPAa5w+1TQbP3
         72AU8UbKQadd8JeUNtfOnkq2JbTsVsErdeeQIesESmLhYn3VX4RkcAE/0rNtturBeyP9
         QPCx/IwTUbaodxVBcFI/6Ybp6GlE3EzSPJnWYfaxxf2v6qbEtF2PsIykeNQoD1L1u0pl
         40pyDi0X0LRoiT84tJ9Jyhjw3WkoLzIm1Y0KAi+CRpsUUVUp7CTaT4Ms3Ypx749w2rIO
         C8j1jUKuCyn7gAzbZwfXwwIRzPT4tSL3keuDoqxAZw2Jy+JfaH7UW3KBiZpaJV+4y4EQ
         KfLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=g7rhUMmo7M6zUEL3SUEIxws/WiNvmZtDVOnYSa1sGjA=;
        b=0rt2yH2Jymj8Z6e/MtTgxYjqsiwEv1nPUdoOj1ykLodnqlRZC5SdboZkQ0BmaObmPP
         M8EeyBLOEQjkH0tuCxPOOXq4rG2PUwndlviJFW+wbTVZnB2SsxQAxUa8LCaOAEA6O5lG
         hayaKHVTcWlSumaauKVJxbKADyYlp/23PbxyaskVqFZb+9/OAFeCYLgJJ+3vKUiFmMqa
         u+GsVxS/NW/g227lXjZXGSObUHwMqF+0N9rze7M4C89hVl3aea82gaxf+Rt0EfJckR4w
         vd00MmUpYLJvBLMVdUny/VBONi150X6jB7wL+TFiKeESRQ1YbDC/u0Dx1Zt7YKp5XRj7
         Fugg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="mK/jhGYp";
       spf=pass (google.com: domain of acme@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=acme@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g7rhUMmo7M6zUEL3SUEIxws/WiNvmZtDVOnYSa1sGjA=;
        b=q7kf+BHyAJ08GKjJxniWD/TC2W5be8Az4YASj9pAXcnksQSSPkFYfCtzfx3Lbcji86
         2zjNhme2cu7HVp4VZpZRry2cednko/nd72Jo9rECgAK14goQnJJ+DWat2LzYuJV6fzpY
         b+oG8Y62Y1y3bJi4bg7VoH0gPERFk9QHMXLNLe+O7MdyWPC9NieVE3svPM9Y8atd6JkG
         X3y5GL4WeCzlVv3cIyGSwXCMcXkS9wqoOEPqdjclEDHUH6f7+h/MnCtBaowWABhvzE5e
         lxhKkxUBXLxB/Fn28XVxstroziKqhssD2M1uccgsDMwGzAQjkZEQi9KxvAb8Dx5wxzqD
         qFig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g7rhUMmo7M6zUEL3SUEIxws/WiNvmZtDVOnYSa1sGjA=;
        b=VEFX2S/mdL5szvP6LqnVgMUpx3wFShPaju77lOcxbWSHPtX+ldLv4YsX/NhxUsG2B5
         FXkyK6Xd57s9pLVdimn1vpuyPDlV7+5SEPJ4nIULnxzUPemF8r7XzMa9e0Ct2qpfIR+R
         nxCy73n4jxb2pgIYlM+ltK52X6RKqNd0mDLeCMpqTgziYyg6riemYtg0CaP5LDKk8cwZ
         +X9gbRvalU1yVv+LLqHbhGDAGL14fx2+wTZnddzQ57Ysgm7Zs3LMl5q6/E89fHfPn5uv
         Bdz0HBYkE8/YKHKL9NBRBlKnibTpHwDbRBV9ybd8p2TGuM5bEitoqKvoH9EGr1+bisDP
         dGug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533L69mVnlZ7M89sVZCqy7y6JMEGix+P+sqONHaBfxRpJmGXRvkD
	YSTFfHW06frM02a3vg7C5u4=
X-Google-Smtp-Source: ABdhPJzy1kKg06Gr0mH1vNwcUATJxe8hQc6/LKKuJqEgjverl0S0q0LPN0mi38V3fenq6JsYNIENDQ==
X-Received: by 2002:ad4:4451:: with SMTP id l17mr45888515qvt.33.1637067085709;
        Tue, 16 Nov 2021 04:51:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:180f:: with SMTP id t15ls6361676qtc.2.gmail; Tue,
 16 Nov 2021 04:51:25 -0800 (PST)
X-Received: by 2002:ac8:5a51:: with SMTP id o17mr7308553qta.180.1637067085229;
        Tue, 16 Nov 2021 04:51:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637067085; cv=none;
        d=google.com; s=arc-20160816;
        b=YELzWfb9w9tbKKUrFt2idRNgw1InlXz2IHZXxRYbjGQlBhLinlr7gmqhUEmoQyquOI
         9ACEOguOOHoJIpsuMcNVt/Pq2e4I3xQRM/l/0c1t6c+csvSv7a5kPQTBa8cSwL1mGKhQ
         NyswEbt0yqilNpNZJ5VuYXPYv43iDJJ8WPEgW/XcHtVGyq4BlldKPfMZAmm5WjtwbEs3
         khHOQv6yZb7qEPUCa5j88wMsDy2xJXSopqZ/RSvWwSNkhU4UiJcIOJE2gGG32zCpVbZ2
         khHqZin+PRA/wVuSMQ9DOrp72s/clDIAqSG62f52+i9GwLWSltIILIOVtG+Vo2/nRIOh
         C+Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=zZd3HyKvDAg3GOxJbvtuearOLYXlDUpVFHDw6cyBDlE=;
        b=q11zYixMQdhijXfRhceGiNXrzeJHyIHJatSdcgLMWtbv6WFbfZfkAt9+I3/xGaoSBQ
         J4y5x04g41ac9ljmY47Wqs3gxfJylBF6o1osWN0D4gMntZsTeOuJQ31671+vTbLauOKr
         Czx0CKOFkupKiHVJTYtVd1PEn5nzb+JjZZiJIEHA8JDpuvtch2AvA8SsXp+X4DDhEX2t
         HyTsln0muKYjklvrpKAuz7In1EBtfGx0ms3cjtL32kYUrhxSiwIEXaJ84mLpMl2WVXd0
         c7cjPzHBs4JY/w5Qo6Bd8lCrt32dVPma1cI2a+t1NipPliJMte0ezzNSp1OEz7edAsmQ
         Ovbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="mK/jhGYp";
       spf=pass (google.com: domain of acme@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=acme@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b8si322062qtg.5.2021.11.16.04.51.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 04:51:25 -0800 (PST)
Received-SPF: pass (google.com: domain of acme@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E695361BF6;
	Tue, 16 Nov 2021 12:51:23 +0000 (UTC)
Received: by quaco.ghostprotocols.net (Postfix, from userid 1000)
	id 371D54088E; Tue, 16 Nov 2021 09:51:21 -0300 (-03)
Date: Tue, 16 Nov 2021 09:51:21 -0300
From: Arnaldo Carvalho de Melo <acme@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Fabian Hemmer <copy@copy.sh>, Ian Rogers <irogers@google.com>,
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] perf test: Add basic stress test for sigtrap handling
Message-ID: <YZOpSVOCXe0zWeRs@kernel.org>
References: <20211115112822.4077224-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20211115112822.4077224-1-elver@google.com>
X-Url: http://acmel.wordpress.com
X-Original-Sender: acme@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="mK/jhGYp";       spf=pass
 (google.com: domain of acme@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=acme@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Em Mon, Nov 15, 2021 at 12:28:23PM +0100, Marco Elver escreveu:
> Add basic stress test for sigtrap handling as a perf tool built-in test.
> This allows sanity checking the basic sigtrap functionality from within
> the perf tool.

Works as root:

[root@five ~]# perf test sigtrap
73: Sigtrap                                                         : Ok
[root@five ~]

Not for !root:

=E2=AC=A2[acme@toolbox perf]$ perf test sigtrap
73: Sigtrap                                                         : FAILE=
D!
=E2=AC=A2[acme@toolbox perf]$ perf test -v sigtrap
Couldn't bump rlimit(MEMLOCK), failures may take place when creating BPF ma=
ps, etc
73: Sigtrap                                                         :
--- start ---
test child forked, pid 3812428
FAILED sys_perf_event_open()
test child finished with -1
---- end ----
Sigtrap: FAILED!
=E2=AC=A2[acme@toolbox perf]$

I'll add the following patch on top of it, with it I get:

=E2=AC=A2[acme@toolbox perf]$ perf test sigtrap
73: Sigtrap                                                         : FAILE=
D!
=E2=AC=A2[acme@toolbox perf]$ perf test -v sigtrap
Couldn't bump rlimit(MEMLOCK), failures may take place when creating BPF ma=
ps, etc
73: Sigtrap                                                         :
--- start ---
test child forked, pid 3816772
FAILED sys_perf_event_open(): Permission denied
test child finished with -1
---- end ----
Sigtrap: FAILED!
=E2=AC=A2[acme@toolbox perf]$


diff --git a/tools/perf/tests/sigtrap.c b/tools/perf/tests/sigtrap.c
index febfa1609356c4c5..6344704619cd8a49 100644
--- a/tools/perf/tests/sigtrap.c
+++ b/tools/perf/tests/sigtrap.c
@@ -5,9 +5,11 @@
  * Copyright (C) 2021, Google LLC.
  */
=20
+#include <errno.h>
 #include <stdint.h>
 #include <stdlib.h>
 #include <linux/hw_breakpoint.h>
+#include <linux/string.h>
 #include <pthread.h>
 #include <signal.h>
 #include <sys/ioctl.h>
@@ -115,6 +117,7 @@ static int test__sigtrap(struct test_suite *test __mayb=
e_unused, int subtest __m
 	struct sigaction oldact;
 	pthread_t threads[NUM_THREADS];
 	pthread_barrier_t barrier;
+	char sbuf[STRERR_BUFSIZE];
 	int i, fd, ret =3D TEST_FAIL;
=20
 	pthread_barrier_init(&barrier, NULL, NUM_THREADS + 1);
@@ -123,19 +126,19 @@ static int test__sigtrap(struct test_suite *test __ma=
ybe_unused, int subtest __m
 	action.sa_sigaction =3D sigtrap_handler;
 	sigemptyset(&action.sa_mask);
 	if (sigaction(SIGTRAP, &action, &oldact)) {
-		pr_debug("FAILED sigaction()\n");
+		pr_debug("FAILED sigaction(): %s\n", str_error_r(errno, sbuf, sizeof(sbu=
f)));
 		goto out;
 	}
=20
 	fd =3D sys_perf_event_open(&attr, 0, -1, -1, perf_event_open_cloexec_flag=
());
 	if (fd < 0) {
-		pr_debug("FAILED sys_perf_event_open()\n");
+		pr_debug("FAILED sys_perf_event_open(): %s\n", str_error_r(errno, sbuf, =
sizeof(sbuf)));
 		goto out_restore_sigaction;
 	}
=20
 	for (i =3D 0; i < NUM_THREADS; i++) {
 		if (pthread_create(&threads[i], NULL, test_thread, &barrier)) {
-			pr_debug("FAILED pthread_create()");
+			pr_debug("FAILED pthread_create(): %s\n", str_error_r(errno, sbuf, size=
of(sbuf)));
 			goto out_close_perf_event;
 		}
 	}


=20
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  tools/perf/tests/Build          |   1 +
>  tools/perf/tests/builtin-test.c |   1 +
>  tools/perf/tests/sigtrap.c      | 154 ++++++++++++++++++++++++++++++++
>  tools/perf/tests/tests.h        |   1 +
>  4 files changed, 157 insertions(+)
>  create mode 100644 tools/perf/tests/sigtrap.c
>=20
> diff --git a/tools/perf/tests/Build b/tools/perf/tests/Build
> index 803ca426f8e6..af2b37ef7c70 100644
> --- a/tools/perf/tests/Build
> +++ b/tools/perf/tests/Build
> @@ -65,6 +65,7 @@ perf-y +=3D pe-file-parsing.o
>  perf-y +=3D expand-cgroup.o
>  perf-y +=3D perf-time-to-tsc.o
>  perf-y +=3D dlfilter-test.o
> +perf-y +=3D sigtrap.o
> =20
>  $(OUTPUT)tests/llvm-src-base.c: tests/bpf-script-example.c tests/Build
>  	$(call rule_mkdir)
> diff --git a/tools/perf/tests/builtin-test.c b/tools/perf/tests/builtin-t=
est.c
> index 8cb5a1c3489e..f1e6d2a3a578 100644
> --- a/tools/perf/tests/builtin-test.c
> +++ b/tools/perf/tests/builtin-test.c
> @@ -107,6 +107,7 @@ static struct test_suite *generic_tests[] =3D {
>  	&suite__expand_cgroup_events,
>  	&suite__perf_time_to_tsc,
>  	&suite__dlfilter,
> +	&suite__sigtrap,
>  	NULL,
>  };
> =20
> diff --git a/tools/perf/tests/sigtrap.c b/tools/perf/tests/sigtrap.c
> new file mode 100644
> index 000000000000..febfa1609356
> --- /dev/null
> +++ b/tools/perf/tests/sigtrap.c
> @@ -0,0 +1,154 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * Basic test for sigtrap support.
> + *
> + * Copyright (C) 2021, Google LLC.
> + */
> +
> +#include <stdint.h>
> +#include <stdlib.h>
> +#include <linux/hw_breakpoint.h>
> +#include <pthread.h>
> +#include <signal.h>
> +#include <sys/ioctl.h>
> +#include <sys/syscall.h>
> +#include <unistd.h>
> +
> +#include "cloexec.h"
> +#include "debug.h"
> +#include "event.h"
> +#include "tests.h"
> +#include "../perf-sys.h"
> +
> +#define NUM_THREADS 5
> +
> +static struct {
> +	int tids_want_signal;		/* Which threads still want a signal. */
> +	int signal_count;		/* Sanity check number of signals received. */
> +	volatile int iterate_on;	/* Variable to set breakpoint on. */
> +	siginfo_t first_siginfo;	/* First observed siginfo_t. */
> +} ctx;
> +
> +#define TEST_SIG_DATA (~(unsigned long)(&ctx.iterate_on))
> +
> +static struct perf_event_attr make_event_attr(void)
> +{
> +	struct perf_event_attr attr =3D {
> +		.type		=3D PERF_TYPE_BREAKPOINT,
> +		.size		=3D sizeof(attr),
> +		.sample_period	=3D 1,
> +		.disabled	=3D 1,
> +		.bp_addr	=3D (unsigned long)&ctx.iterate_on,
> +		.bp_type	=3D HW_BREAKPOINT_RW,
> +		.bp_len		=3D HW_BREAKPOINT_LEN_1,
> +		.inherit	=3D 1, /* Children inherit events ... */
> +		.inherit_thread =3D 1, /* ... but only cloned with CLONE_THREAD. */
> +		.remove_on_exec =3D 1, /* Required by sigtrap. */
> +		.sigtrap	=3D 1, /* Request synchronous SIGTRAP on event. */
> +		.sig_data	=3D TEST_SIG_DATA,
> +	};
> +	return attr;
> +}
> +
> +static void
> +sigtrap_handler(int signum __maybe_unused, siginfo_t *info, void *uconte=
xt __maybe_unused)
> +{
> +	if (!__atomic_fetch_add(&ctx.signal_count, 1, __ATOMIC_RELAXED))
> +		ctx.first_siginfo =3D *info;
> +	__atomic_fetch_sub(&ctx.tids_want_signal, syscall(SYS_gettid), __ATOMIC=
_RELAXED);
> +}
> +
> +static void *test_thread(void *arg)
> +{
> +	pthread_barrier_t *barrier =3D (pthread_barrier_t *)arg;
> +	pid_t tid =3D syscall(SYS_gettid);
> +	int i;
> +
> +	pthread_barrier_wait(barrier);
> +
> +	__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
> +	for (i =3D 0; i < ctx.iterate_on - 1; i++)
> +		__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
> +
> +	return NULL;
> +}
> +
> +static int run_test_threads(pthread_t *threads, pthread_barrier_t *barri=
er)
> +{
> +	int i;
> +
> +	pthread_barrier_wait(barrier);
> +	for (i =3D 0; i < NUM_THREADS; i++)
> +		TEST_ASSERT_EQUAL("pthread_join() failed", pthread_join(threads[i], NU=
LL), 0);
> +
> +	return TEST_OK;
> +}
> +
> +static int run_stress_test(int fd, pthread_t *threads, pthread_barrier_t=
 *barrier)
> +{
> +	int ret;
> +
> +	ctx.iterate_on =3D 3000;
> +
> +	TEST_ASSERT_EQUAL("misfired signal?", ctx.signal_count, 0);
> +	TEST_ASSERT_EQUAL("enable failed", ioctl(fd, PERF_EVENT_IOC_ENABLE, 0),=
 0);
> +	ret =3D run_test_threads(threads, barrier);
> +	TEST_ASSERT_EQUAL("disable failed", ioctl(fd, PERF_EVENT_IOC_DISABLE, 0=
), 0);
> +
> +	TEST_ASSERT_EQUAL("unexpected sigtraps", ctx.signal_count, NUM_THREADS =
* ctx.iterate_on);
> +	TEST_ASSERT_EQUAL("missing signals or incorrectly delivered", ctx.tids_=
want_signal, 0);
> +	TEST_ASSERT_VAL("unexpected si_addr", ctx.first_siginfo.si_addr =3D=3D =
&ctx.iterate_on);
> +#if 0 /* FIXME: enable when libc's signal.h has si_perf_{type,data} */
> +	TEST_ASSERT_EQUAL("unexpected si_perf_type", ctx.first_siginfo.si_perf_=
type,
> +			  PERF_TYPE_BREAKPOINT);
> +	TEST_ASSERT_EQUAL("unexpected si_perf_data", ctx.first_siginfo.si_perf_=
data,
> +			  TEST_SIG_DATA);
> +#endif
> +
> +	return ret;
> +}
> +
> +static int test__sigtrap(struct test_suite *test __maybe_unused, int sub=
test __maybe_unused)
> +{
> +	struct perf_event_attr attr =3D make_event_attr();
> +	struct sigaction action =3D {};
> +	struct sigaction oldact;
> +	pthread_t threads[NUM_THREADS];
> +	pthread_barrier_t barrier;
> +	int i, fd, ret =3D TEST_FAIL;
> +
> +	pthread_barrier_init(&barrier, NULL, NUM_THREADS + 1);
> +
> +	action.sa_flags =3D SA_SIGINFO | SA_NODEFER;
> +	action.sa_sigaction =3D sigtrap_handler;
> +	sigemptyset(&action.sa_mask);
> +	if (sigaction(SIGTRAP, &action, &oldact)) {
> +		pr_debug("FAILED sigaction()\n");
> +		goto out;
> +	}
> +
> +	fd =3D sys_perf_event_open(&attr, 0, -1, -1, perf_event_open_cloexec_fl=
ag());
> +	if (fd < 0) {
> +		pr_debug("FAILED sys_perf_event_open()\n");
> +		goto out_restore_sigaction;
> +	}
> +
> +	for (i =3D 0; i < NUM_THREADS; i++) {
> +		if (pthread_create(&threads[i], NULL, test_thread, &barrier)) {
> +			pr_debug("FAILED pthread_create()");
> +			goto out_close_perf_event;
> +		}
> +	}
> +
> +	ret =3D run_stress_test(fd, threads, &barrier);
> +
> +out_close_perf_event:
> +	close(fd);
> +out_restore_sigaction:
> +	sigaction(SIGTRAP, &oldact, NULL);
> +out:
> +	pthread_barrier_destroy(&barrier);
> +	return ret;
> +}
> +
> +DEFINE_SUITE("Sigtrap", sigtrap);
> diff --git a/tools/perf/tests/tests.h b/tools/perf/tests/tests.h
> index 8f65098110fc..5bbb8f6a48fc 100644
> --- a/tools/perf/tests/tests.h
> +++ b/tools/perf/tests/tests.h
> @@ -146,6 +146,7 @@ DECLARE_SUITE(pe_file_parsing);
>  DECLARE_SUITE(expand_cgroup_events);
>  DECLARE_SUITE(perf_time_to_tsc);
>  DECLARE_SUITE(dlfilter);
> +DECLARE_SUITE(sigtrap);
> =20
>  /*
>   * PowerPC and S390 do not support creation of instruction breakpoints u=
sing the
> --=20
> 2.34.0.rc1.387.gb447b232ab-goog

--=20

- Arnaldo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YZOpSVOCXe0zWeRs%40kernel.org.
