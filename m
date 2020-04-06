Return-Path: <kasan-dev+bncBAABBMHAVT2AKGQE5SCHZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id C54BA19F70D
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Apr 2020 15:35:45 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id r42sf14835123pjb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Apr 2020 06:35:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586180144; cv=pass;
        d=google.com; s=arc-20160816;
        b=ug4HwfKb8jU29fUGNtABYItJGZoWp3SHGr1BrJ0bEkd0luOGo+Jm9D7SZVCbf18PKW
         1wBB28NTqBhWLQf8+Fqeym5fSFlIjtIy3y2jWa9uzD9Dq1BhdErXw6m3Lx13pplwlMSY
         C5RBnS53SoQDlgmn5lgB2FKH1e+8oYZjFuXVUdMbaor4bPQv03onRr5nZv+kyMaGrBoE
         QZI3WnapqT9ex5w5IQ8RcfDkJnl0GKZqHslbDjalkPNT0O2R8N3vhxqHkFe2LYTGKUst
         r4a/buz3QpBg1RxBCIz4I7lUJI/Z1M7j48tTfWEvybMIW/Af6h3uIfaKkjnHDv+lvwKP
         fSNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WqWEWyNEka3LX5RVMoJJ86st2sYVcpGwmMT7DFKAMqk=;
        b=p/LffHiEXRwvOdSTxBYb6X7iHsSFHlwXonVZKXN2IsXNfG7E2kYa5NEY98Lh4YrcP9
         eMTyHZ77QuW40bpgE+hLnXvl0orS2+agR54N7n/hAQS7Vz1B4wD20UkIWwicDl+jm7gi
         +hzZjpw2/buU0LJZFFexkkDWMZ1O385ca2eiSbJJ9VRwujpwt0l9DDF1a7/9dMalCyLu
         PHdKskxcR8mp6aL5rXNFBkPBM9emE8jRdJ5LACWCCy4NWZ8QNZ78ossi+1GmDtmMd3+S
         Sq6oFIZZas/JxWVlZChYZ0L2YrGQ+VZV4ZzRFh406qVSb/dh3MZ2Q+dXWsbV3mhMTnbK
         C6GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=pz6Up9F+;
       spf=pass (google.com: domain of srs0=hppt=5w=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=HppT=5W=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WqWEWyNEka3LX5RVMoJJ86st2sYVcpGwmMT7DFKAMqk=;
        b=ASdYPX27xqeyK6gPF6Z1XvPWL+MfhHSFYDEktbTKT1f8OqQVaAcURyKxlMT8iMW762
         77v2K75z/yIsIHwJk/wyKl7DUb2YaiCVWmMNNTC6jR7RJAVI7F0+32K0HPgAjv3ca9jt
         W/fmn+USU8+QWbGHjm3i8YyzuPVrMnE6WGxZr8Nxr/Xh92drJCL9haIOCTY2/ZRWnwEe
         VnyUljAk4hbF3Pz0qMQk0T7JbczeDPf2GwdWGJ1DXwOLQ7rtl0pRaGVDOmqdWV74Qffb
         ti356bLj6uGjGJk7HhCNzUbv7LDA0S5R1gF9KNvptfHlTVV3Q25Yi6l+GW2VkHphpLV5
         fxLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WqWEWyNEka3LX5RVMoJJ86st2sYVcpGwmMT7DFKAMqk=;
        b=enpkBtB1/CJrkEZZWT6fKEXkZCidSxDcvm+wH9CUh2PGH/hrhI34/Fo/SS4lSxP2QP
         4xezxgaAVO1m3uDHNN+zYQAHZSudElXUNVkCNojOT3p+qJ7u5tg8zJE2e+8XE7xv/v/Y
         5QhHG3ZZCXsOHroDtnkSloRsVR3BMMrnfAwK6tSwEIJZyebJxYd0ofyIycJ4gnF417+g
         3cy9ARzBUnby779tSLmf5jnkHK9lJDyB2tDdDdkyxpDyez48P/SszBWX/BCcZRTPVmMs
         QeFZO9vHrLKSbQ+55oSptKpQk7dCqM1G8N21wTwBXIF9BxNDhuXy+DUweKZ6p7Il8BFA
         f+qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYCstcBc6m4R6PwTbirll25iNIBcgRZXrRQOrlZO2h7I+U3BX31
	MSGIGg4yrc/t3i4K4/sPSac=
X-Google-Smtp-Source: APiQypIahf7IquilOBRzdxAB4E3uPdFx0Q25w4EyT3eFeyHZ3V+nGZyFTZBVJJJ4ancQgfOB9i6FSA==
X-Received: by 2002:aa7:850f:: with SMTP id v15mr20702058pfn.119.1586180144073;
        Mon, 06 Apr 2020 06:35:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4c4:: with SMTP id 187ls10265826pge.5.gmail; Mon, 06 Apr
 2020 06:35:43 -0700 (PDT)
X-Received: by 2002:a63:1060:: with SMTP id 32mr22408935pgq.271.1586180143605;
        Mon, 06 Apr 2020 06:35:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586180143; cv=none;
        d=google.com; s=arc-20160816;
        b=l2HFC3SLnW5i8EepZO2F26NlzR5cnMblp8KiWymiOm2BqJ7yl9b9R7fMVV+pYeUlMX
         tvoW1kSzCCulZ9i3DUPhSC7/mh+HnxH2EH+MztvSIGOPvy122PSXM1rX0FCDoOK1tdo6
         xg7iNg+me5pyVjKatLaZoPLLpn99IAKrjVZGggQLyNJ4IquCQ9wmUVACSfxmA8i5FG4J
         +Wd1i6gwq0OBsaewO3KV+VQqei4sROXRsT9iH/rQnEsKMaQI1YwuIIohSZEIYBYzSGpr
         epnmOER796WminjDnLAqhPuvxYEHM39IzKCwNjEWTqg3mq4CyfzjQLWQEzBBXjsE2xU8
         KPww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=v/YIhMSwgyl9Zr65hTERwjVGq1muJ8Ux087ZEF7ndwk=;
        b=ZdmerAuuZPLIfKYoItf4SowAiuENKpeKgg4CRHdtQon/TvmVca2xR9gcC52GgbOIfP
         +UR4O0+D+tnJqiZuKNLJgFf7S7Atu/vxUjta6aEO8ryxkB9a6iaqHnE5y6hAN4lDcFmh
         ctDdq/56Fa4pJwA4jbcypis4WDy3ZmX0gsZhwFRJ0Ntmb+5ExbEHhnKYzMXdx5mU0POo
         WPjoRnomtEpZBshQGGzBLNglI7Q7hy6zykfcWb35woQRqQGv3Sua4d/siZRH6OlHn5wN
         VzWQiDSHCRvnLpZqjpbH7ydIOhfWUWeMTTlpG+QZPEulTq56gCjEVINOGFoBv6XKxAEc
         GtcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=pz6Up9F+;
       spf=pass (google.com: domain of srs0=hppt=5w=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=HppT=5W=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i10si15643pli.0.2020.04.06.06.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Apr 2020 06:35:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=hppt=5w=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4D73422B4E;
	Mon,  6 Apr 2020 13:35:43 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 250783522726; Mon,  6 Apr 2020 06:35:43 -0700 (PDT)
Date: Mon, 6 Apr 2020 06:35:43 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
Message-ID: <20200406133543.GB19865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200221231027.230147-1-elver@google.com>
 <6A08FE59-AD3B-4209-AF57-D4CEF7E94B56@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <6A08FE59-AD3B-4209-AF57-D4CEF7E94B56@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=pz6Up9F+;       spf=pass
 (google.com: domain of srs0=hppt=5w=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=HppT=5W=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Apr 06, 2020 at 08:59:58AM -0400, Qian Cai wrote:
>=20
>=20
> > On Feb 21, 2020, at 6:10 PM, Marco Elver <elver@google.com> wrote:
> >=20
> > Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> > Currently information about the reporting task's held locks and IRQ
> > trace events are shown, if they are enabled.
>=20
> This patch is no longer in today=E2=80=99s linux-next. I suppose that it =
is because Paul had sent
> the initial pull request without this one that I had missed dearly.
>=20
> Is there a way to get it back there?

It goes back in in seven days, after -rc1 is released.  The fact that
it was there last week was a mistake on my part, and I did eventually
get my hand slapped for it.  ;-)

In the meantime, if it would help, I could group the KCSAN commits
on top of those in -tip to allow you to get them with one "git pull"
command.

							Thanx, Paul

> > Signed-off-by: Marco Elver <elver@google.com>
> > Suggested-by: Qian Cai <cai@lca.pw>
> > ---
> > v3:
> > * Typos
> > v2:
> > * Rework obtaining 'current' for the "other thread" -- it now passes
> >  'current' and ensures that we stall until the report was printed, so
> >  that the lockdep information contained in 'current' is accurate. This
> >  was non-trivial but testing so far leads me to conclude this now
> >  reliably prints the held locks for the "other thread" (please test
> >  more!).
> > ---
> > kernel/kcsan/core.c   |   4 +-
> > kernel/kcsan/kcsan.h  |   3 ++
> > kernel/kcsan/report.c | 103 +++++++++++++++++++++++++++++++++++++++++-
> > lib/Kconfig.kcsan     |  13 ++++++
> > 4 files changed, 120 insertions(+), 3 deletions(-)
> >=20
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index e7387fec66795..065615df88eaa 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -18,8 +18,8 @@
> > #include "kcsan.h"
> >=20
> > static bool kcsan_early_enable =3D IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE=
);
> > -static unsigned int kcsan_udelay_task =3D CONFIG_KCSAN_UDELAY_TASK;
> > -static unsigned int kcsan_udelay_interrupt =3D CONFIG_KCSAN_UDELAY_INT=
ERRUPT;
> > +unsigned int kcsan_udelay_task =3D CONFIG_KCSAN_UDELAY_TASK;
> > +unsigned int kcsan_udelay_interrupt =3D CONFIG_KCSAN_UDELAY_INTERRUPT;
> > static long kcsan_skip_watch =3D CONFIG_KCSAN_SKIP_WATCH;
> > static bool kcsan_interrupt_watcher =3D IS_ENABLED(CONFIG_KCSAN_INTERRU=
PT_WATCHER);
> >=20
> > diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> > index 892de5120c1b6..e282f8b5749e9 100644
> > --- a/kernel/kcsan/kcsan.h
> > +++ b/kernel/kcsan/kcsan.h
> > @@ -13,6 +13,9 @@
> > /* The number of adjacent watchpoints to check. */
> > #define KCSAN_CHECK_ADJACENT 1
> >=20
> > +extern unsigned int kcsan_udelay_task;
> > +extern unsigned int kcsan_udelay_interrupt;
> > +
> > /*
> >  * Globally enable and disable KCSAN.
> >  */
> > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > index 11c791b886f3c..7bdb515e3662f 100644
> > --- a/kernel/kcsan/report.c
> > +++ b/kernel/kcsan/report.c
> > @@ -1,5 +1,7 @@
> > // SPDX-License-Identifier: GPL-2.0
> >=20
> > +#include <linux/debug_locks.h>
> > +#include <linux/delay.h>
> > #include <linux/jiffies.h>
> > #include <linux/kernel.h>
> > #include <linux/lockdep.h>
> > @@ -31,7 +33,26 @@ static struct {
> > 	int			cpu_id;
> > 	unsigned long		stack_entries[NUM_STACK_ENTRIES];
> > 	int			num_stack_entries;
> > -} other_info =3D { .ptr =3D NULL };
> > +
> > +	/*
> > +	 * Optionally pass @current. Typically we do not need to pass @curren=
t
> > +	 * via @other_info since just @task_pid is sufficient. Passing @curre=
nt
> > +	 * has additional overhead.
> > +	 *
> > +	 * To safely pass @current, we must either use get_task_struct/
> > +	 * put_task_struct, or stall the thread that populated @other_info.
> > +	 *
> > +	 * We cannot rely on get_task_struct/put_task_struct in case
> > +	 * release_report() races with a task being released, and would have =
to
> > +	 * free it in release_report(). This may result in deadlock if we wan=
t
> > +	 * to use KCSAN on the allocators.
> > +	 *
> > +	 * Since we also want to reliably print held locks for
> > +	 * CONFIG_KCSAN_VERBOSE, the current implementation stalls the thread
> > +	 * that populated @other_info until it has been consumed.
> > +	 */
> > +	struct task_struct	*task;
> > +} other_info;
> >=20
> > /*
> >  * Information about reported races; used to rate limit reporting.
> > @@ -245,6 +266,16 @@ static int sym_strcmp(void *addr1, void *addr2)
> > 	return strncmp(buf1, buf2, sizeof(buf1));
> > }
> >=20
> > +static void print_verbose_info(struct task_struct *task)
> > +{
> > +	if (!task)
> > +		return;
> > +
> > +	pr_err("\n");
> > +	debug_show_held_locks(task);
> > +	print_irqtrace_events(task);
> > +}
> > +
> > /*
> >  * Returns true if a report was generated, false otherwise.
> >  */
> > @@ -319,6 +350,9 @@ static bool print_report(const volatile void *ptr, =
size_t size, int access_type,
> > 				  other_info.num_stack_entries - other_skipnr,
> > 				  0);
> >=20
> > +		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > +		    print_verbose_info(other_info.task);
> > +
> > 		pr_err("\n");
> > 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> > 		       get_access_type(access_type), ptr, size,
> > @@ -340,6 +374,9 @@ static bool print_report(const volatile void *ptr, =
size_t size, int access_type,
> > 	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> > 			  0);
> >=20
> > +	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > +		print_verbose_info(current);
> > +
> > 	/* Print report footer. */
> > 	pr_err("\n");
> > 	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> > @@ -357,6 +394,67 @@ static void release_report(unsigned long *flags, e=
num kcsan_report_type type)
> > 	spin_unlock_irqrestore(&report_lock, *flags);
> > }
> >=20
> > +/*
> > + * Sets @other_info.task and awaits consumption of @other_info.
> > + *
> > + * Precondition: report_lock is held.
> > + * Postcondition: report_lock is held.
> > + */
> > +static void
> > +set_other_info_task_blocking(unsigned long *flags, const volatile void=
 *ptr)
> > +{
> > +	/*
> > +	 * We may be instrumenting a code-path where current->state is alread=
y
> > +	 * something other than TASK_RUNNING.
> > +	 */
> > +	const bool is_running =3D current->state =3D=3D TASK_RUNNING;
> > +	/*
> > +	 * To avoid deadlock in case we are in an interrupt here and this is =
a
> > +	 * race with a task on the same CPU (KCSAN_INTERRUPT_WATCHER), provid=
e a
> > +	 * timeout to ensure this works in all contexts.
> > +	 *
> > +	 * Await approximately the worst case delay of the reporting thread (=
if
> > +	 * we are not interrupted).
> > +	 */
> > +	int timeout =3D max(kcsan_udelay_task, kcsan_udelay_interrupt);
> > +
> > +	other_info.task =3D current;
> > +	do {
> > +		if (is_running) {
> > +			/*
> > +			 * Let lockdep know the real task is sleeping, to print
> > +			 * the held locks (recall we turned lockdep off, so
> > +			 * locking/unlocking @report_lock won't be recorded).
> > +			 */
> > +			set_current_state(TASK_UNINTERRUPTIBLE);
> > +		}
> > +		spin_unlock_irqrestore(&report_lock, *flags);
> > +		/*
> > +		 * We cannot call schedule() since we also cannot reliably
> > +		 * determine if sleeping here is permitted -- see in_atomic().
> > +		 */
> > +
> > +		udelay(1);
> > +		spin_lock_irqsave(&report_lock, *flags);
> > +		if (timeout-- < 0) {
> > +			/*
> > +			 * Abort. Reset other_info.task to NULL, since it
> > +			 * appears the other thread is still going to consume
> > +			 * it. It will result in no verbose info printed for
> > +			 * this task.
> > +			 */
> > +			other_info.task =3D NULL;
> > +			break;
> > +		}
> > +		/*
> > +		 * If @ptr nor @current matches, then our information has been
> > +		 * consumed and we may continue. If not, retry.
> > +		 */
> > +	} while (other_info.ptr =3D=3D ptr && other_info.task =3D=3D current)=
;
> > +	if (is_running)
> > +		set_current_state(TASK_RUNNING);
> > +}
> > +
> > /*
> >  * Depending on the report type either sets other_info and returns fals=
e, or
> >  * acquires the matching other_info and returns true. If other_info is =
not
> > @@ -388,6 +486,9 @@ static bool prepare_report(unsigned long *flags, co=
nst volatile void *ptr,
> > 		other_info.cpu_id		=3D cpu_id;
> > 		other_info.num_stack_entries	=3D stack_trace_save(other_info.stack_en=
tries, NUM_STACK_ENTRIES, 1);
> >=20
> > +		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > +			set_other_info_task_blocking(flags, ptr);
> > +
> > 		spin_unlock_irqrestore(&report_lock, *flags);
> >=20
> > 		/*
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index 081ed2e1bf7b1..0f1447ff8f558 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -20,6 +20,19 @@ menuconfig KCSAN
> >=20
> > if KCSAN
> >=20
> > +config KCSAN_VERBOSE
> > +	bool "Show verbose reports with more information about system state"
> > +	depends on PROVE_LOCKING
> > +	help
> > +	  If enabled, reports show more information about the system state th=
at
> > +	  may help better analyze and debug races. This includes held locks a=
nd
> > +	  IRQ trace events.
> > +
> > +	  While this option should generally be benign, we call into more
> > +	  external functions on report generation; if a race report is
> > +	  generated from any one of them, system stability may suffer due to
> > +	  deadlocks or recursion.  If in doubt, say N.
> > +
> > config KCSAN_DEBUG
> > 	bool "Debugging of KCSAN internals"
> >=20
> > --=20
> > 2.25.0.265.gbab2e86ba0-goog
> >=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200406133543.GB19865%40paulmck-ThinkPad-P72.
