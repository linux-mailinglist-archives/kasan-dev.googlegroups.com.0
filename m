Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBUGPVT2AKGQEY6I7JJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E3BF19F63F
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Apr 2020 15:00:07 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id t6sf14388448qtj.12
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Apr 2020 06:00:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586178001; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ltno8ixNqTPxHjqPQUIlPsBYJsplkqcmS0P8x11URcoksXyjx/jzi4pklU9fuVihJq
         vbQG6m6lyNLEeoUoHxKPzwSTc4Zk/i05aAaJOXWfxk4xYGk54Vl1L9gpkP4Hktcb786n
         FsK3sR3ZJcyrnsHb3XaewZd1A4wXMIxor5rUVdN61CErSpyDb/tyjbZ8VpbcWQ4VNYb5
         a3y/3OWm+M78OablEg/DZtnyQIcIxOpSyYhwgQ7Ie0uOOYk8n1Xciif/BFH2iDgNp99n
         xX3yQgBEzVX1Mv40FQ3stsye2gLMJW3sNELI0mRXvbmYHCO/SuxJ/Lod+XeISoPEUv1r
         upCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=0cFyDnCDclqmLb651r6FyxYiI0p0vruNqCjucmweLpI=;
        b=SXTX33eviH2oB4kMTJ96DChRPiYIGbIp5ptN/tDOyXmg+TyCGoCObA22ggahTEg7Mt
         KBndhmsgH8DbPa9jFBStEFW3pumb1Juj5SqD0jTMpdZyCgzlKCZm3HEHxEzbvA6cBL3o
         E6ga0AF+t/ipo9vxumy9iXO38aF4v8L/WpcbsK5uzABz6zwJnaM4pIVxz2Ue5sMLn2y7
         eXiYktAFJ2Qm4qHvSxLW21IpGEq8UqufZkElonUwW8hriHVUGZB+jbZ9M+1/MrWVXkJM
         bUmhrQT7dWtaZu8TJvwbed3H6ELXANf5p4cBdwIz2j1xuASLUYqq2eRNE0EexcNgOjwf
         zPOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=HtLdCzNF;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0cFyDnCDclqmLb651r6FyxYiI0p0vruNqCjucmweLpI=;
        b=SJF1JnHnUCE0Vs/wJ9tD5sjqkzmc5syKGVrOk/fPvGomTzFupe3p/uPLgUKYrINWUn
         VizKYwqMZZv62LQ0fx0CkiSWl5GLnqk6jpWb31EoVdcgwBtFXAwfIBcESa19D578N07u
         sXLosdvRNsUfEzQstipz9eo76ZFJrhrMCgLw578RS85G0aAoHRgg/3gRMlN3EfJ0KhtA
         59I94g3iBTp0tjYLMgE7/buAoUtOv0XFOrqz+tfvuktwPznAfp/hOZexkmbpQcwk0U5W
         z2M1LBJN2fKyt5kJ4p1LN47E9LrF2NFBDHjLAsrJe3TlVQa7PXewLbexgawvyicXarIT
         bHhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0cFyDnCDclqmLb651r6FyxYiI0p0vruNqCjucmweLpI=;
        b=AArq893weaNpX60WHHhqwydXNBm++cbTQ5NK6h+5nhOSxGvmPhDAH9V/+WdLxtjO15
         dxddeV+dmpx/croWh5xUbOZFb6xEz/D9K/5vx0FGQ3Th+2qor7ds87qwthbu8l5bFoAZ
         /NL+gc4/joNsJpxMDAR7rjsWceIr9g8DgtehLc4W1GoD17xbib4cevuJX9KplYdEU9bU
         coga7pDfl0NmcK3nXG93gayizdylE3ZGWb3+Nbf2NDAK7Gq+HMbM7FMZPK0QaFmFy2qa
         B43q7TIieI6P7UqntrzHWx7CvVBUZN6827UXSYsB4QtjseY/J9yADceamEzPubCQc4AP
         kCMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubZMSfUlGSn+AudM2Gnt2qLkZ/dOqtfCtjjpVVDe3eoJy+Dkjnw
	Y7qDssxsn7KS4sExAf5HnWY=
X-Google-Smtp-Source: APiQypLGWjr76HkRJ59zDAC+FjgRnMdy26h8aFjdIktRu9BE+i3oECPARdZGigkR0AGEyPESyEC79g==
X-Received: by 2002:a37:7d44:: with SMTP id y65mr14983850qkc.244.1586178000955;
        Mon, 06 Apr 2020 06:00:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2521:: with SMTP id v30ls8732994qtc.6.gmail; Mon, 06 Apr
 2020 06:00:00 -0700 (PDT)
X-Received: by 2002:aed:2be5:: with SMTP id e92mr7872108qtd.374.1586178000528;
        Mon, 06 Apr 2020 06:00:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586178000; cv=none;
        d=google.com; s=arc-20160816;
        b=isqZPS5ceJfo3YACarVGApiXbHtD0yiAkqekGP/HyQEblHR45fGqwo6S+JFTVpY/nT
         Vtq+y5IfHz/gMLBuoKiYLlQ7o6E7KVGYf8snellwJK9ubMdqgqXKHjL6dRtRkvY5RSs+
         ySYaSgyMWk4qfcrQP+HhEu/B0XGtExNjunLlmWboPcVxilcYmTm45rGVCOniWOOCE7PI
         73Zqf/C9dO93F8OGEDpTeai9v+3U+IVewazYPysHxlrRLOKCCL0GmjxxdJXfKk24IlzZ
         BPIp3P3ucop57yC0Of2GFBdmg5JiFCag6817OtDLEV2yxEGqrCzmywMJA7fIr9xHHA6G
         wKaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=e6p2CS4Lx8Kl1OnF8Wel1pTuwVY9nphUpk15OX9vN4A=;
        b=nXGmlMwtPfRV+TrC+ruYcYxYywkXF9MXoVdO82u81V8P8RjXyCuMUEOoUX/lsgVhYw
         nDiktxEsXKXKP9n+v0rvqAWtmNG+Zt0VCmmkhY32WMVNV06H9D+pUzk8v3RzlzeDf8EI
         nYm+BlCBeu0aY/iAmdRN7clkZpJKOeIA1hXMN3YEkou3wC8ljCxGztakWNqHVz6vQYuW
         oXK+x6NLftfwG3ft9Y5QXKvXlmyOZi51/gfDDRky21mB08KeJ8kOkAome/mK+KfC7CY+
         ZkyisrP2/yZZtqFsS5Q/KGXuHA+gdbLsRD++urs22T12yEWPE1IgzzpdepdA4oy0pAnQ
         /T3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=HtLdCzNF;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id b139si440698qkc.5.2020.04.06.06.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Apr 2020 06:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id a5so12625993qtw.10
        for <kasan-dev@googlegroups.com>; Mon, 06 Apr 2020 06:00:00 -0700 (PDT)
X-Received: by 2002:aed:2bc1:: with SMTP id e59mr4697971qtd.313.1586177999774;
        Mon, 06 Apr 2020 05:59:59 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id f1sm13584767qkl.72.2020.04.06.05.59.58
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Apr 2020 05:59:59 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20200221231027.230147-1-elver@google.com>
Date: Mon, 6 Apr 2020 08:59:58 -0400
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Marco Elver <elver@google.com>
Content-Transfer-Encoding: quoted-printable
Message-Id: <6A08FE59-AD3B-4209-AF57-D4CEF7E94B56@lca.pw>
References: <20200221231027.230147-1-elver@google.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=HtLdCzNF;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Feb 21, 2020, at 6:10 PM, Marco Elver <elver@google.com> wrote:
>=20
> Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> Currently information about the reporting task's held locks and IRQ
> trace events are shown, if they are enabled.

This patch is no longer in today=E2=80=99s linux-next. I suppose that it is=
 because Paul had sent
the initial pull request without this one that I had missed dearly.

Is there a way to get it back there?

>=20
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: Qian Cai <cai@lca.pw>
> ---
> v3:
> * Typos
> v2:
> * Rework obtaining 'current' for the "other thread" -- it now passes
>  'current' and ensures that we stall until the report was printed, so
>  that the lockdep information contained in 'current' is accurate. This
>  was non-trivial but testing so far leads me to conclude this now
>  reliably prints the held locks for the "other thread" (please test
>  more!).
> ---
> kernel/kcsan/core.c   |   4 +-
> kernel/kcsan/kcsan.h  |   3 ++
> kernel/kcsan/report.c | 103 +++++++++++++++++++++++++++++++++++++++++-
> lib/Kconfig.kcsan     |  13 ++++++
> 4 files changed, 120 insertions(+), 3 deletions(-)
>=20
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index e7387fec66795..065615df88eaa 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -18,8 +18,8 @@
> #include "kcsan.h"
>=20
> static bool kcsan_early_enable =3D IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
> -static unsigned int kcsan_udelay_task =3D CONFIG_KCSAN_UDELAY_TASK;
> -static unsigned int kcsan_udelay_interrupt =3D CONFIG_KCSAN_UDELAY_INTER=
RUPT;
> +unsigned int kcsan_udelay_task =3D CONFIG_KCSAN_UDELAY_TASK;
> +unsigned int kcsan_udelay_interrupt =3D CONFIG_KCSAN_UDELAY_INTERRUPT;
> static long kcsan_skip_watch =3D CONFIG_KCSAN_SKIP_WATCH;
> static bool kcsan_interrupt_watcher =3D IS_ENABLED(CONFIG_KCSAN_INTERRUPT=
_WATCHER);
>=20
> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> index 892de5120c1b6..e282f8b5749e9 100644
> --- a/kernel/kcsan/kcsan.h
> +++ b/kernel/kcsan/kcsan.h
> @@ -13,6 +13,9 @@
> /* The number of adjacent watchpoints to check. */
> #define KCSAN_CHECK_ADJACENT 1
>=20
> +extern unsigned int kcsan_udelay_task;
> +extern unsigned int kcsan_udelay_interrupt;
> +
> /*
>  * Globally enable and disable KCSAN.
>  */
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 11c791b886f3c..7bdb515e3662f 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -1,5 +1,7 @@
> // SPDX-License-Identifier: GPL-2.0
>=20
> +#include <linux/debug_locks.h>
> +#include <linux/delay.h>
> #include <linux/jiffies.h>
> #include <linux/kernel.h>
> #include <linux/lockdep.h>
> @@ -31,7 +33,26 @@ static struct {
> 	int			cpu_id;
> 	unsigned long		stack_entries[NUM_STACK_ENTRIES];
> 	int			num_stack_entries;
> -} other_info =3D { .ptr =3D NULL };
> +
> +	/*
> +	 * Optionally pass @current. Typically we do not need to pass @current
> +	 * via @other_info since just @task_pid is sufficient. Passing @current
> +	 * has additional overhead.
> +	 *
> +	 * To safely pass @current, we must either use get_task_struct/
> +	 * put_task_struct, or stall the thread that populated @other_info.
> +	 *
> +	 * We cannot rely on get_task_struct/put_task_struct in case
> +	 * release_report() races with a task being released, and would have to
> +	 * free it in release_report(). This may result in deadlock if we want
> +	 * to use KCSAN on the allocators.
> +	 *
> +	 * Since we also want to reliably print held locks for
> +	 * CONFIG_KCSAN_VERBOSE, the current implementation stalls the thread
> +	 * that populated @other_info until it has been consumed.
> +	 */
> +	struct task_struct	*task;
> +} other_info;
>=20
> /*
>  * Information about reported races; used to rate limit reporting.
> @@ -245,6 +266,16 @@ static int sym_strcmp(void *addr1, void *addr2)
> 	return strncmp(buf1, buf2, sizeof(buf1));
> }
>=20
> +static void print_verbose_info(struct task_struct *task)
> +{
> +	if (!task)
> +		return;
> +
> +	pr_err("\n");
> +	debug_show_held_locks(task);
> +	print_irqtrace_events(task);
> +}
> +
> /*
>  * Returns true if a report was generated, false otherwise.
>  */
> @@ -319,6 +350,9 @@ static bool print_report(const volatile void *ptr, si=
ze_t size, int access_type,
> 				  other_info.num_stack_entries - other_skipnr,
> 				  0);
>=20
> +		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +		    print_verbose_info(other_info.task);
> +
> 		pr_err("\n");
> 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> 		       get_access_type(access_type), ptr, size,
> @@ -340,6 +374,9 @@ static bool print_report(const volatile void *ptr, si=
ze_t size, int access_type,
> 	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> 			  0);
>=20
> +	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +		print_verbose_info(current);
> +
> 	/* Print report footer. */
> 	pr_err("\n");
> 	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> @@ -357,6 +394,67 @@ static void release_report(unsigned long *flags, enu=
m kcsan_report_type type)
> 	spin_unlock_irqrestore(&report_lock, *flags);
> }
>=20
> +/*
> + * Sets @other_info.task and awaits consumption of @other_info.
> + *
> + * Precondition: report_lock is held.
> + * Postcondition: report_lock is held.
> + */
> +static void
> +set_other_info_task_blocking(unsigned long *flags, const volatile void *=
ptr)
> +{
> +	/*
> +	 * We may be instrumenting a code-path where current->state is already
> +	 * something other than TASK_RUNNING.
> +	 */
> +	const bool is_running =3D current->state =3D=3D TASK_RUNNING;
> +	/*
> +	 * To avoid deadlock in case we are in an interrupt here and this is a
> +	 * race with a task on the same CPU (KCSAN_INTERRUPT_WATCHER), provide =
a
> +	 * timeout to ensure this works in all contexts.
> +	 *
> +	 * Await approximately the worst case delay of the reporting thread (if
> +	 * we are not interrupted).
> +	 */
> +	int timeout =3D max(kcsan_udelay_task, kcsan_udelay_interrupt);
> +
> +	other_info.task =3D current;
> +	do {
> +		if (is_running) {
> +			/*
> +			 * Let lockdep know the real task is sleeping, to print
> +			 * the held locks (recall we turned lockdep off, so
> +			 * locking/unlocking @report_lock won't be recorded).
> +			 */
> +			set_current_state(TASK_UNINTERRUPTIBLE);
> +		}
> +		spin_unlock_irqrestore(&report_lock, *flags);
> +		/*
> +		 * We cannot call schedule() since we also cannot reliably
> +		 * determine if sleeping here is permitted -- see in_atomic().
> +		 */
> +
> +		udelay(1);
> +		spin_lock_irqsave(&report_lock, *flags);
> +		if (timeout-- < 0) {
> +			/*
> +			 * Abort. Reset other_info.task to NULL, since it
> +			 * appears the other thread is still going to consume
> +			 * it. It will result in no verbose info printed for
> +			 * this task.
> +			 */
> +			other_info.task =3D NULL;
> +			break;
> +		}
> +		/*
> +		 * If @ptr nor @current matches, then our information has been
> +		 * consumed and we may continue. If not, retry.
> +		 */
> +	} while (other_info.ptr =3D=3D ptr && other_info.task =3D=3D current);
> +	if (is_running)
> +		set_current_state(TASK_RUNNING);
> +}
> +
> /*
>  * Depending on the report type either sets other_info and returns false,=
 or
>  * acquires the matching other_info and returns true. If other_info is no=
t
> @@ -388,6 +486,9 @@ static bool prepare_report(unsigned long *flags, cons=
t volatile void *ptr,
> 		other_info.cpu_id		=3D cpu_id;
> 		other_info.num_stack_entries	=3D stack_trace_save(other_info.stack_entr=
ies, NUM_STACK_ENTRIES, 1);
>=20
> +		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +			set_other_info_task_blocking(flags, ptr);
> +
> 		spin_unlock_irqrestore(&report_lock, *flags);
>=20
> 		/*
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 081ed2e1bf7b1..0f1447ff8f558 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -20,6 +20,19 @@ menuconfig KCSAN
>=20
> if KCSAN
>=20
> +config KCSAN_VERBOSE
> +	bool "Show verbose reports with more information about system state"
> +	depends on PROVE_LOCKING
> +	help
> +	  If enabled, reports show more information about the system state that
> +	  may help better analyze and debug races. This includes held locks and
> +	  IRQ trace events.
> +
> +	  While this option should generally be benign, we call into more
> +	  external functions on report generation; if a race report is
> +	  generated from any one of them, system stability may suffer due to
> +	  deadlocks or recursion.  If in doubt, say N.
> +
> config KCSAN_DEBUG
> 	bool "Debugging of KCSAN internals"
>=20
> --=20
> 2.25.0.265.gbab2e86ba0-goog
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6A08FE59-AD3B-4209-AF57-D4CEF7E94B56%40lca.pw.
