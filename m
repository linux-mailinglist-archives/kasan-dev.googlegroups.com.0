Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUVZXOBQMGQEZNHIFOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id BC46F3580C3
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:37:06 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id j18sf812151edv.6
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:37:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878226; cv=pass;
        d=google.com; s=arc-20160816;
        b=lGEe22UMo9zUW9/qtlzW/+jkCZr4gcpC4WDh9RmzhbPJn5l7zM91e1HU0+CN3oaQhN
         gVx2Kxheo9gZP/dXMV9y4OrT077ildpHwmaLX9QkBfucTDDeBGxuIuy3KwVt55WLaE/5
         m1g1zaKx41GOMje36zUhTVRZLrM+QiNTAbuwBCkoZJlSKiI7faUOZbbaKIoVKNoQsJR6
         X9HYK97aeXHhegPlxxlStzgvFFrymVr1hjPaLv7Q/MtLv/nsUPzgAkfaBHgdiVxvwL2I
         0d+Enw3SXrmpH0mL5cikjBebv7NUjr6hqrT0gCvy+YTGDXfur+YeBh931dBzWEdKOVXR
         MsWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=clXbhx2PwcY/IZrUaIla9Y1FGz2ihXp21HXQ39DtTyc=;
        b=eehniPy49ux2PFuAJH8dgrycjRgQXWVUFBJaBdBF0/anFwcLtGUUFvmIww8Gys83hF
         NmzPogcrZVPj/PgZw6UE/b3EgSwRq/yWRvtPeQky3hJ4X9CyAO1qKIvM2mFCS9jdKUWw
         2C6UvDtxSDNfK4ULAzSD1bfAMZRvNmewQuIQ2cZaIjcEJSGrIsxRd/bGfxgDmz/kVKKw
         ay0iBD7ZCFAii8fVAUhniGQq8Ww+8Lltt1P6tZLZObIYG/xxszAJmix7deBmsg+Ho2s5
         nv2UH673RgmlLVtggsIy+QUDY7FvXKh9yp0xc+Nd+3XYksWiAKaRk1ZESB3EGSg3t65P
         U19g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="O/PS32Yv";
       spf=pass (google.com: domain of 30dxuyaukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30dxuYAUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=clXbhx2PwcY/IZrUaIla9Y1FGz2ihXp21HXQ39DtTyc=;
        b=A3e1S/MZlwKIPmLsSL3qZipHzWBD+LjPWZX2YuNvqObEkgFQDE95ALEHygK7bV1QxB
         GzoyImzzeHUIDMHJhcRaeiDqMVELhi16rXIo6Y994EUTngEEMOeINfwfz6MGxLFq2jpj
         QxF1gw2OeO80L86aaiOm9zWce8tZ36BmWJGZw6D9jHTHQP0p48WUA6sX1NxZofhUO0Tv
         d7EIe4KCb6UPQjsokYRAQ4pvll/QNH3hFvBnxsjCkI/lApy7AlfrKGX4dxf7RgEueiBW
         fg5/vakqvsqdm8Ax8MqwmlVlFXqRcnhgdmSihWf7Yepm8FK4HmY5Gyo5AqFsKPgarmGx
         HEWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=clXbhx2PwcY/IZrUaIla9Y1FGz2ihXp21HXQ39DtTyc=;
        b=Nrq2pU3YvNBhBV17Ou0fwdFJP2hwCxcfukg9JdYySQy/7sP3f8wievoK8xWMT/Tvld
         KfiyvDH1p6AjKB4LB1mnkhGqC9QAXgFlpsrOmdzAIG8YrawcavfO9ZsZuilEPcrG9cxm
         mVhAdKXKCQg06bgItMBTL9RyzvGHmtD0OAG5vjX//sWMphaSv1zUY7hvKEjPpZr8lnEU
         HI6zbnsDllCnh06g3ngOG4wjOAI1bSB01CoPe04t8Dq0KlBvtUGbtbaFMige6EQMW0RX
         GKZQ2kLY37+CtrrkEm8Zlc40PGMzNkJ84zaewracNgX9qXLRZeMdBU3GbKzAslKpA5nP
         sF1g==
X-Gm-Message-State: AOAM5300/oshTFAbgOno4A1CatiaK2gsGHg9vgP8R3fkBjQgnldzwz5d
	I6ulJl/JeydOyL26/ytQTH8=
X-Google-Smtp-Source: ABdhPJw5OLgJ4FGgsBmOOVgAbCK/q/4qc650atk2A9TazjUkdGq8jcgxL8BwOQUoKhM8YekyNAl7Bg==
X-Received: by 2002:a17:907:3e93:: with SMTP id hs19mr9669095ejc.272.1617878226484;
        Thu, 08 Apr 2021 03:37:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:26c7:: with SMTP id u7ls1848019ejc.2.gmail; Thu, 08
 Apr 2021 03:37:05 -0700 (PDT)
X-Received: by 2002:a17:906:3544:: with SMTP id s4mr9523266eja.73.1617878225505;
        Thu, 08 Apr 2021 03:37:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878225; cv=none;
        d=google.com; s=arc-20160816;
        b=0KCLqUbtzna0E7sgmju6WagIxu1aUEQrtD/MFnFTRZ3VmZKmHDLQ5p7VH7vqYyS4yz
         OPe0f3h7rFnYO5nMXbWT62ZNBwgTe0qzhniwMblBWGmATe8pQjRnhby1DCVHjN/pDIH7
         GEd8Jii0zv5anyqiykHNvVllvmTst5Rvtu42PMo0zc8fn+vrjvKGNMwijdVsB6MNnDfG
         E6BjATYNhI85Iei15oOOLR+lNGyUgqcASYlvZ2C8c3X9qrYwgK9oGI83KZtgxh1imYM3
         LeFrMvJ9IseJ01HVoPHjvHyaMnpuxPsWXaE+1IwEyRpDbZ58u80qjjH3hH3JRdg3/Tb4
         KNqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=e9eNC+rfkR/Mvozr1enkH/S77j3eXQYf4mLuBW4j23Y=;
        b=AUtRqkfggFQKnoJGQMg5mCr7mfTxIvPR1JlOY6DTMPrydfqG1LhjhRjXctLCpvp1EV
         zv5V6TA5+AM/YvkOdNbKsB4udt6VlyAWa8BoGbLYX2/TfcvC0Qe4t5n/y5V4cyoQMuYZ
         IAHDmDdKRxQjz1mMBPfa6/YIjMmZy9SrCSNQZ40bTG5gksL6LhLo6Bl90wh7FVtiNEHo
         Oba2FzD++Pq1IYsEUThBzeMG8Ww4agZ4BvyvBndHfUivCkhwLUHT3Icvv1VThKjrqiTu
         oAHuGhAKoz2uF5BmVvXA5elT2SMI8BBVsyfmeslgZQivNsU/8MUKy+OPXL1QJpkYqVR9
         Y6sA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="O/PS32Yv";
       spf=pass (google.com: domain of 30dxuyaukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30dxuYAUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id c12si912343eds.0.2021.04.08.03.37.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:37:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30dxuyaukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id y14so780070wro.23
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:37:05 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a05:600c:31a2:: with SMTP id
 s34mr2521929wmp.171.1617878225115; Thu, 08 Apr 2021 03:37:05 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:36:03 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-9-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 08/10] selftests/perf_events: Add kselftest for remove_on_exec
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, oleg@redhat.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="O/PS32Yv";       spf=pass
 (google.com: domain of 30dxuyaukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30dxuYAUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

Add kselftest to test that remove_on_exec removes inherited events from
child tasks.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Fix for latest libc signal.h.

v2:
* Add patch to series.
---
 .../testing/selftests/perf_events/.gitignore  |   1 +
 tools/testing/selftests/perf_events/Makefile  |   2 +-
 .../selftests/perf_events/remove_on_exec.c    | 260 ++++++++++++++++++
 3 files changed, 262 insertions(+), 1 deletion(-)
 create mode 100644 tools/testing/selftests/perf_events/remove_on_exec.c

diff --git a/tools/testing/selftests/perf_events/.gitignore b/tools/testing/selftests/perf_events/.gitignore
index 4dc43e1bd79c..790c47001e77 100644
--- a/tools/testing/selftests/perf_events/.gitignore
+++ b/tools/testing/selftests/perf_events/.gitignore
@@ -1,2 +1,3 @@
 # SPDX-License-Identifier: GPL-2.0-only
 sigtrap_threads
+remove_on_exec
diff --git a/tools/testing/selftests/perf_events/Makefile b/tools/testing/selftests/perf_events/Makefile
index 973a2c39ca83..fcafa5f0d34c 100644
--- a/tools/testing/selftests/perf_events/Makefile
+++ b/tools/testing/selftests/perf_events/Makefile
@@ -2,5 +2,5 @@
 CFLAGS += -Wl,-no-as-needed -Wall -I../../../../usr/include
 LDFLAGS += -lpthread
 
-TEST_GEN_PROGS := sigtrap_threads
+TEST_GEN_PROGS := sigtrap_threads remove_on_exec
 include ../lib.mk
diff --git a/tools/testing/selftests/perf_events/remove_on_exec.c b/tools/testing/selftests/perf_events/remove_on_exec.c
new file mode 100644
index 000000000000..5814611a1dc7
--- /dev/null
+++ b/tools/testing/selftests/perf_events/remove_on_exec.c
@@ -0,0 +1,260 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Test for remove_on_exec.
+ *
+ * Copyright (C) 2021, Google LLC.
+ */
+
+#define _GNU_SOURCE
+
+/* We need the latest siginfo from the kernel repo. */
+#include <sys/types.h>
+#include <asm/siginfo.h>
+#define __have_siginfo_t 1
+#define __have_sigval_t 1
+#define __have_sigevent_t 1
+#define __siginfo_t_defined
+#define __sigval_t_defined
+#define __sigevent_t_defined
+#define _BITS_SIGINFO_CONSTS_H 1
+#define _BITS_SIGEVENT_CONSTS_H 1
+
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <linux/perf_event.h>
+#include <pthread.h>
+#include <signal.h>
+#include <sys/ioctl.h>
+#include <sys/syscall.h>
+#include <unistd.h>
+
+#include "../kselftest_harness.h"
+
+static volatile int signal_count;
+
+static struct perf_event_attr make_event_attr(void)
+{
+	struct perf_event_attr attr = {
+		.type		= PERF_TYPE_HARDWARE,
+		.size		= sizeof(attr),
+		.config		= PERF_COUNT_HW_INSTRUCTIONS,
+		.sample_period	= 1000,
+		.exclude_kernel = 1,
+		.exclude_hv	= 1,
+		.disabled	= 1,
+		.inherit	= 1,
+		/*
+		 * Children normally retain their inherited event on exec; with
+		 * remove_on_exec, we'll remove their event, but the parent and
+		 * any other non-exec'd children will keep their events.
+		 */
+		.remove_on_exec = 1,
+		.sigtrap	= 1,
+	};
+	return attr;
+}
+
+static void sigtrap_handler(int signum, siginfo_t *info, void *ucontext)
+{
+	if (info->si_code != TRAP_PERF) {
+		fprintf(stderr, "%s: unexpected si_code %d\n", __func__, info->si_code);
+		return;
+	}
+
+	signal_count++;
+}
+
+FIXTURE(remove_on_exec)
+{
+	struct sigaction oldact;
+	int fd;
+};
+
+FIXTURE_SETUP(remove_on_exec)
+{
+	struct perf_event_attr attr = make_event_attr();
+	struct sigaction action = {};
+
+	signal_count = 0;
+
+	/* Initialize sigtrap handler. */
+	action.sa_flags = SA_SIGINFO | SA_NODEFER;
+	action.sa_sigaction = sigtrap_handler;
+	sigemptyset(&action.sa_mask);
+	ASSERT_EQ(sigaction(SIGTRAP, &action, &self->oldact), 0);
+
+	/* Initialize perf event. */
+	self->fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
+	ASSERT_NE(self->fd, -1);
+}
+
+FIXTURE_TEARDOWN(remove_on_exec)
+{
+	close(self->fd);
+	sigaction(SIGTRAP, &self->oldact, NULL);
+}
+
+/* Verify event propagates to fork'd child. */
+TEST_F(remove_on_exec, fork_only)
+{
+	int status;
+	pid_t pid = fork();
+
+	if (pid == 0) {
+		ASSERT_EQ(signal_count, 0);
+		ASSERT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+		while (!signal_count);
+		_exit(42);
+	}
+
+	while (!signal_count); /* Child enables event. */
+	EXPECT_EQ(waitpid(pid, &status, 0), pid);
+	EXPECT_EQ(WEXITSTATUS(status), 42);
+}
+
+/*
+ * Verify that event does _not_ propagate to fork+exec'd child; event enabled
+ * after fork+exec.
+ */
+TEST_F(remove_on_exec, fork_exec_then_enable)
+{
+	pid_t pid_exec, pid_only_fork;
+	int pipefd[2];
+	int tmp;
+
+	/*
+	 * Non-exec child, to ensure exec does not affect inherited events of
+	 * other children.
+	 */
+	pid_only_fork = fork();
+	if (pid_only_fork == 0) {
+		/* Block until parent enables event. */
+		while (!signal_count);
+		_exit(42);
+	}
+
+	ASSERT_NE(pipe(pipefd), -1);
+	pid_exec = fork();
+	if (pid_exec == 0) {
+		ASSERT_NE(dup2(pipefd[1], STDOUT_FILENO), -1);
+		close(pipefd[0]);
+		execl("/proc/self/exe", "exec_child", NULL);
+		_exit((perror("exec failed"), 1));
+	}
+	close(pipefd[1]);
+
+	ASSERT_EQ(waitpid(pid_exec, &tmp, WNOHANG), 0); /* Child is running. */
+	/* Wait for exec'd child to start spinning. */
+	EXPECT_EQ(read(pipefd[0], &tmp, sizeof(int)), sizeof(int));
+	EXPECT_EQ(tmp, 42);
+	close(pipefd[0]);
+	/* Now we can enable the event, knowing the child is doing work. */
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	/* If the event propagated to the exec'd child, it will exit normally... */
+	usleep(100000); /* ... give time for event to trigger (in case of bug). */
+	EXPECT_EQ(waitpid(pid_exec, &tmp, WNOHANG), 0); /* Should still be running. */
+	EXPECT_EQ(kill(pid_exec, SIGKILL), 0);
+
+	/* Verify removal from child did not affect this task's event. */
+	tmp = signal_count;
+	while (signal_count == tmp); /* Should not hang! */
+	/* Nor should it have affected the first child. */
+	EXPECT_EQ(waitpid(pid_only_fork, &tmp, 0), pid_only_fork);
+	EXPECT_EQ(WEXITSTATUS(tmp), 42);
+}
+
+/*
+ * Verify that event does _not_ propagate to fork+exec'd child; event enabled
+ * before fork+exec.
+ */
+TEST_F(remove_on_exec, enable_then_fork_exec)
+{
+	pid_t pid_exec;
+	int tmp;
+
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+
+	pid_exec = fork();
+	if (pid_exec == 0) {
+		execl("/proc/self/exe", "exec_child", NULL);
+		_exit((perror("exec failed"), 1));
+	}
+
+	/*
+	 * The child may exit abnormally at any time if the event propagated and
+	 * a SIGTRAP is sent before the handler was set up.
+	 */
+	usleep(100000); /* ... give time for event to trigger (in case of bug). */
+	EXPECT_EQ(waitpid(pid_exec, &tmp, WNOHANG), 0); /* Should still be running. */
+	EXPECT_EQ(kill(pid_exec, SIGKILL), 0);
+
+	/* Verify removal from child did not affect this task's event. */
+	tmp = signal_count;
+	while (signal_count == tmp); /* Should not hang! */
+}
+
+TEST_F(remove_on_exec, exec_stress)
+{
+	pid_t pids[30];
+	int i, tmp;
+
+	for (i = 0; i < sizeof(pids) / sizeof(pids[0]); i++) {
+		pids[i] = fork();
+		if (pids[i] == 0) {
+			execl("/proc/self/exe", "exec_child", NULL);
+			_exit((perror("exec failed"), 1));
+		}
+
+		/* Some forked with event disabled, rest with enabled. */
+		if (i > 10)
+			EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	}
+
+	usleep(100000); /* ... give time for event to trigger (in case of bug). */
+
+	for (i = 0; i < sizeof(pids) / sizeof(pids[0]); i++) {
+		/* All children should still be running. */
+		EXPECT_EQ(waitpid(pids[i], &tmp, WNOHANG), 0);
+		EXPECT_EQ(kill(pids[i], SIGKILL), 0);
+	}
+
+	/* Verify event is still alive. */
+	tmp = signal_count;
+	while (signal_count == tmp);
+}
+
+/* For exec'd child. */
+static void exec_child(void)
+{
+	struct sigaction action = {};
+	const int val = 42;
+
+	/* Set up sigtrap handler in case we erroneously receive a trap. */
+	action.sa_flags = SA_SIGINFO | SA_NODEFER;
+	action.sa_sigaction = sigtrap_handler;
+	sigemptyset(&action.sa_mask);
+	if (sigaction(SIGTRAP, &action, NULL))
+		_exit((perror("sigaction failed"), 1));
+
+	/* Signal parent that we're starting to spin. */
+	if (write(STDOUT_FILENO, &val, sizeof(int)) == -1)
+		_exit((perror("write failed"), 1));
+
+	/* Should hang here until killed. */
+	while (!signal_count);
+}
+
+#define main test_main
+TEST_HARNESS_MAIN
+#undef main
+int main(int argc, char *argv[])
+{
+	if (!strcmp(argv[0], "exec_child")) {
+		exec_child();
+		return 1;
+	}
+
+	return test_main(argc, argv);
+}
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-9-elver%40google.com.
