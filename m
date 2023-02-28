Return-Path: <kasan-dev+bncBCMIZB7QWENRB44W66PQMGQESUI3HCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CA346A55F6
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 10:37:56 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id co14-20020a0564020c0e00b004aab4319cedsf12922719edb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 01:37:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677577076; cv=pass;
        d=google.com; s=arc-20160816;
        b=BK3vfD2sAK+KBVYdD3kng5W1JZg3glzIpWeVsCPD/XDx/YrAdbeC93s/A7W2jIi9Ol
         BJ2ncvtBHCTxLJjQADUTFTjPf4osmx6Aaj+TJ43qR1Rk3CIXJTsI6v7V8UsFHQHPe+Y2
         Zyq8hHFCQr2BZR0JyDrdOPaKzLNCV32aaK5FgH3S1PXOuBzfGH3x8w70vxHrl+YxoS5n
         V0h0hA2UHoX565G0fyRit6EsYEQ0jS0n9Zm6GKIki8bV/jXZM6WIiOZj8WM+J62n/N1e
         uiKenDqSv9FJzOVoEWvogkueSsbM07C8atZN9f9U+ih3gRku3sYmQK18WBc4b9oMt0PS
         uaMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dN1ZFWWuK1xXT8mDHH803JRsnPkCrkZwvE4uhWw7FSc=;
        b=zJUonB9Znz8IPtm5UEfp8vLf1dOyQy3vaOg5MdWCAACx5IIl38mp96yuHjpaHSsDDu
         CAx1Uj5xJfTmT71Sov5fEMiAn/2ueikKqJaNEpXkXrx8K8CYiBfo+szpYm/YayJLDHCS
         kOxVfRyfBKfAB0blk6YZ1HvYzuTIvnwGJZldjH0F9lpPxruVKdZb+ADI5fG1F1+M7VRq
         lAnHyNtGtI4Tuge5CM/+OLbXMT2LjyIDr4iIzcqU/iWcUrTOCoQjTIgtRV9nk5sCmnw+
         qxs136byHtdnDaviU3ElRCDr8VKFXN6daFM9tdIMir5GaCs5TCxW3qx5Xg2K8tOYpAml
         gOWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JxTwuIbc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dN1ZFWWuK1xXT8mDHH803JRsnPkCrkZwvE4uhWw7FSc=;
        b=XIRWCjrhVIS2Tqu/15tw/113qUf4CedNBEjxp6DT+PfQf1bxNB551uhXAbGJBdRGch
         uksi2/kpeBXLyrgCK/H8Y0zVQ/PlMCghQsoR6HLkq9zpbt1llVwgOmoFFJpPV6sLJcfu
         KDFu8u5AZfdWtrqShmpE5OStZqRKicfWvihc6ne33FLmnxFjq5MItq1U0rH86OG+wTXM
         cHMhI7RYcG2tjWVqRw31SZKqx8hTA+pV90jsGGMDfVwQluYoPs/sdIxRJ0lPnxh1frnD
         lE4LhNY8zlRxW8vsxvk1MOZNRbz9RG+rGGBeY1IUzfC5OcnCfyZIqTba8sL+JekMv/N5
         clNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dN1ZFWWuK1xXT8mDHH803JRsnPkCrkZwvE4uhWw7FSc=;
        b=2+M2LoqygDpk26sc9m/+W7Q1gaRAZa82DSCnWGmOpbNLsyp1cG+0vKZex9506Zx9FQ
         LxlssxzyqX+JircQKfQOvxsWHLBY41jiKHAciqapOQlAYdpZFeR1oA1T2AcYaiJTwvB9
         tNjdJTsoZWK1dUSMbe+0lUPwarCi0s1s/TRshNmMXs3OFAyMB+525qNv4Jb3DfZDF/26
         iBD5jF8mTSQW7l7C0/iXwS0roHe8nUU5bTSR/cYXJX1e/dFTelcUIjF++jTfMdHvQnOu
         78y6mxCTdbm/m7ScsKIARUotmtGn3NGTp1weZDwD31/gYI8du1kL39KroH3VzWE+0uOo
         3wWw==
X-Gm-Message-State: AO0yUKUbhWwagB2YTrcwsCjC/k2+IKulvCNjmbJoEUCvVLEDtmnIe51q
	Pn2RqhaO/v7FEwzL2yoFzqs=
X-Google-Smtp-Source: AK7set+HZvyL3hMmdsSCY8q4NprOImBfeJz2PVD0UG4Wi5GDPYKMx69MAxlK52CV93VtjngSuPDxxg==
X-Received: by 2002:a50:d743:0:b0:4af:515d:5691 with SMTP id i3-20020a50d743000000b004af515d5691mr1425718edj.7.1677577075689;
        Tue, 28 Feb 2023 01:37:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:51cc:b0:4ad:7c6c:4f6d with SMTP id
 r12-20020a05640251cc00b004ad7c6c4f6dls416333edd.1.-pod-prod-gmail; Tue, 28
 Feb 2023 01:37:54 -0800 (PST)
X-Received: by 2002:a05:6402:110a:b0:4ac:d2b4:ec2c with SMTP id u10-20020a056402110a00b004acd2b4ec2cmr2402625edv.29.1677577074384;
        Tue, 28 Feb 2023 01:37:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677577074; cv=none;
        d=google.com; s=arc-20160816;
        b=CoRls3ARTCBq9fWxzXhO3VIgu0A0XQaUSIYU9oJwIoqFcyeQUIJ8SRnf1SDbQARAGm
         0zOpqRfTSZQrQJbAKQdsbbaxlK7ncD0gqfMYRWVI2GhMsanl7DDt/a1yEt0K9gswi8vn
         wC+zY2nmCGoXYK1YNQR35eRVhD4BGhCQu60BQxuUA+aMqVehsQ209NzWrwbbvKBqJn32
         6QAq5suKUe9JW4wf8Cq/OPJDp3yDw38FFt+BPykYikHDG351bspGEAsliYfZSZyQ3Wi+
         0911CbiwZaV0JZS+7eSFTW8q8gc8OJ24LmZ7dx5mFjE47SYlncCAcszVN5k7UKmjK1ap
         nbaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pLx88XxeINaxlh9c88no1ufEASvBrkn7OcCaxFAtYeg=;
        b=FBaXIUoLo019wob2wlSI0gqt1nDpBhGSGFWQhj1x40ahFE+MeJLz9060MY/qTmNqiF
         e1iwKTikWZmy8HqBJ4pi5wPRPCNU5CTXf1xZce+DTSuCnCJW6EYXxphQkiCkZKPOHRWx
         cQcYDPkBxT/bXlcD+kc4Ia0JF31gE8RV/NrKIaom8Mq1MyOiBegAD6JULLaZFf+FLJ99
         Enzhqk7hVfEH9xR8XVHxoDynur21eIrMabpTwafiIbwcDQ5zj8OFA2FUbYN9UHXeT/Bp
         rB00+s5R0ktsSUpge/7DxnHr9+uTtiEHg6LAVnHaIlVb+ZQM+s01pz4MwZzZM6M3hIvO
         swPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JxTwuIbc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id m6-20020a056402430600b004aee5c48387si296313edc.3.2023.02.28.01.37.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 01:37:54 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id h9so9504071ljq.2
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 01:37:54 -0800 (PST)
X-Received: by 2002:a05:651c:1242:b0:295:b83b:ab11 with SMTP id
 h2-20020a05651c124200b00295b83bab11mr576748ljh.4.1677577073761; Tue, 28 Feb
 2023 01:37:53 -0800 (PST)
MIME-Version: 1.0
References: <0b5efd70e31bba7912cf9a6c951f0e76a8df27df.1677517724.git.andreyknvl@google.com>
In-Reply-To: <0b5efd70e31bba7912cf9a6c951f0e76a8df27df.1677517724.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Feb 2023 10:37:40 +0100
Message-ID: <CACT4Y+Z4GvK-XCbrLp8cuH-xHYsCdh1f0948ZgkU2D0apfGG5w@mail.gmail.com>
Subject: Re: [PATCH] kcov: improve documentation
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JxTwuIbc;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 27 Feb 2023 at 18:17, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Improve KCOV documentation:
>
> - Use KCOV instead of kcov, as the former is more widely-used.
>
> - Mention Clang in compiler requirements.
>
> - Use ``annotations`` for inline code.
>
> - Rework remote coverage collection documentation for better clarity.
>
> - Various smaller changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  Documentation/dev-tools/kcov.rst | 169 +++++++++++++++++++------------
>  1 file changed, 102 insertions(+), 67 deletions(-)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index d83c9ab49427..a113a03a475f 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -1,42 +1,50 @@
> -kcov: code coverage for fuzzing
> +KCOV: code coverage for fuzzing
>  ===============================
>
> -kcov exposes kernel code coverage information in a form suitable for coverage-
> -guided fuzzing (randomized testing). Coverage data of a running kernel is
> -exported via the "kcov" debugfs file. Coverage collection is enabled on a task
> -basis, and thus it can capture precise coverage of a single system call.
> +KCOV collects and exposes kernel code coverage information in a form suitable
> +for coverage-guided fuzzing. Coverage data of a running kernel is exported via
> +the ``kcov`` debugfs file. Coverage collection is enabled on a task basis, and
> +thus KCOV can capture precise coverage of a single system call.
>
> -Note that kcov does not aim to collect as much coverage as possible. It aims
> -to collect more or less stable coverage that is function of syscall inputs.
> -To achieve this goal it does not collect coverage in soft/hard interrupts
> -and instrumentation of some inherently non-deterministic parts of kernel is
> -disabled (e.g. scheduler, locking).
> +Note that KCOV does not aim to collect as much coverage as possible. It aims
> +to collect more or less stable coverage that is a function of syscall inputs.
> +To achieve this goal, it does not collect coverage in soft/hard interrupts
> +(unless remove coverage collection is enabled, see below) and from some
> +inherently non-deterministic parts of the kernel (e.g. scheduler, locking).
>
> -kcov is also able to collect comparison operands from the instrumented code
> -(this feature currently requires that the kernel is compiled with clang).
> +Besides collecting code coverage, KCOV can also collect comparison operands.
> +See the "Comparison operands collection" section for details.
> +
> +Besides collecting coverage data from syscall handlers, KCOV can also collect
> +coverage for annotated parts of the kernel executing in background kernel
> +tasks or soft interrupts. See the "Remote coverage collection" section for
> +details.
>
>  Prerequisites
>  -------------
>
> -Configure the kernel with::
> +KCOV relies on compiler instrumentation and requires GCC 6.1.0 or later
> +or any Clang version supported by the kernel.
>
> -        CONFIG_KCOV=y
> +Collecting comparison operands is only supported with Clang.

Are you sure?
I see -fsanitize-coverage=trace-cmp in gcc sources and man page.

Otherwise looks good to me.

> -CONFIG_KCOV requires gcc 6.1.0 or later.
> +To enable KCOV, configure the kernel with::
>
> -If the comparison operands need to be collected, set::
> +        CONFIG_KCOV=y
> +
> +To enable comparison operands collection, set::
>
>         CONFIG_KCOV_ENABLE_COMPARISONS=y
>
> -Profiling data will only become accessible once debugfs has been mounted::
> +Coverage data only becomes accessible once debugfs has been mounted::
>
>          mount -t debugfs none /sys/kernel/debug
>
>  Coverage collection
>  -------------------
>
> -The following program demonstrates coverage collection from within a test
> -program using kcov:
> +The following program demonstrates how to use KCOV to collect coverage for a
> +single syscall from within a test program:
>
>  .. code-block:: c
>
> @@ -84,7 +92,7 @@ program using kcov:
>                 perror("ioctl"), exit(1);
>         /* Reset coverage from the tail of the ioctl() call. */
>         __atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
> -       /* That's the target syscal call. */
> +       /* Call the target syscall call. */
>         read(-1, NULL, 0);
>         /* Read number of PCs collected. */
>         n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
> @@ -103,7 +111,7 @@ program using kcov:
>         return 0;
>      }
>
> -After piping through addr2line output of the program looks as follows::
> +After piping through ``addr2line`` the output of the program looks as follows::
>
>      SyS_read
>      fs/read_write.c:562
> @@ -121,12 +129,13 @@ After piping through addr2line output of the program looks as follows::
>      fs/read_write.c:562
>
>  If a program needs to collect coverage from several threads (independently),
> -it needs to open /sys/kernel/debug/kcov in each thread separately.
> +it needs to open ``/sys/kernel/debug/kcov`` in each thread separately.
>
>  The interface is fine-grained to allow efficient forking of test processes.
> -That is, a parent process opens /sys/kernel/debug/kcov, enables trace mode,
> -mmaps coverage buffer and then forks child processes in a loop. Child processes
> -only need to enable coverage (disable happens automatically on thread end).
> +That is, a parent process opens ``/sys/kernel/debug/kcov``, enables trace mode,
> +mmaps coverage buffer, and then forks child processes in a loop. The child
> +processes only need to enable coverage (it gets disabled automatically when
> +a thread exits).
>
>  Comparison operands collection
>  ------------------------------
> @@ -205,52 +214,78 @@ Comparison operands collection is similar to coverage collection:
>         return 0;
>      }
>
> -Note that the kcov modes (coverage collection or comparison operands) are
> -mutually exclusive.
> +Note that the KCOV modes (collection of code coverage or comparison operands)
> +are mutually exclusive.
>
>  Remote coverage collection
>  --------------------------
>
> -With KCOV_ENABLE coverage is collected only for syscalls that are issued
> -from the current process. With KCOV_REMOTE_ENABLE it's possible to collect
> -coverage for arbitrary parts of the kernel code, provided that those parts
> -are annotated with kcov_remote_start()/kcov_remote_stop().
> -
> -This allows to collect coverage from two types of kernel background
> -threads: the global ones, that are spawned during kernel boot in a limited
> -number of instances (e.g. one USB hub_event() worker thread is spawned per
> -USB HCD); and the local ones, that are spawned when a user interacts with
> -some kernel interface (e.g. vhost workers); as well as from soft
> -interrupts.
> -
> -To enable collecting coverage from a global background thread or from a
> -softirq, a unique global handle must be assigned and passed to the
> -corresponding kcov_remote_start() call. Then a userspace process can pass
> -a list of such handles to the KCOV_REMOTE_ENABLE ioctl in the handles
> -array field of the kcov_remote_arg struct. This will attach the used kcov
> -device to the code sections, that are referenced by those handles.
> -
> -Since there might be many local background threads spawned from different
> -userspace processes, we can't use a single global handle per annotation.
> -Instead, the userspace process passes a non-zero handle through the
> -common_handle field of the kcov_remote_arg struct. This common handle gets
> -saved to the kcov_handle field in the current task_struct and needs to be
> -passed to the newly spawned threads via custom annotations. Those threads
> -should in turn be annotated with kcov_remote_start()/kcov_remote_stop().
> -
> -Internally kcov stores handles as u64 integers. The top byte of a handle
> -is used to denote the id of a subsystem that this handle belongs to, and
> -the lower 4 bytes are used to denote the id of a thread instance within
> -that subsystem. A reserved value 0 is used as a subsystem id for common
> -handles as they don't belong to a particular subsystem. The bytes 4-7 are
> -currently reserved and must be zero. In the future the number of bytes
> -used for the subsystem or handle ids might be increased.
> -
> -When a particular userspace process collects coverage via a common
> -handle, kcov will collect coverage for each code section that is annotated
> -to use the common handle obtained as kcov_handle from the current
> -task_struct. However non common handles allow to collect coverage
> -selectively from different subsystems.
> +Besides collecting coverage data from handlers of syscalls issued from a
> +userspace process, KCOV can also collect coverage for parts of the kernel
> +executing in other contexts - so-called "remote" coverage.
> +
> +Using KCOV to collect remote coverage requires:
> +
> +1. Modifying kernel code to annotate the code section from where coverage
> +   should be collected with ``kcov_remote_start`` and ``kcov_remote_stop``.
> +
> +2. Using `KCOV_REMOTE_ENABLE`` instead of ``KCOV_ENABLE`` in the userspace
> +   process that collects coverage.
> +
> +Both ``kcov_remote_start`` and ``kcov_remote_stop`` annotations and the
> +``KCOV_REMOTE_ENABLE`` ioctl accept handles that identify particular coverage
> +collection sections. The way a handle is used depends on the context where the
> +matching code section executes.
> +
> +KCOV supports collecting remote coverage from the following contexts:
> +
> +1. Global kernel background tasks. These are the tasks that are spawned during
> +   kernel boot in a limited number of instances (e.g. one USB ``hub_event``
> +   worker is spawned per one USB HCD).
> +
> +2. Local kernel background tasks. These are spawned when a userspace process
> +   interacts with some kernel interface and are usually killed when the process
> +   exits (e.g. vhost workers).
> +
> +3. Soft interrupts.
> +
> +For #1 and #3, a unique global handle must be chosen and passed to the
> +corresponding ``kcov_remote_start`` call. Then a userspace process must pass
> +this handle to ``KCOV_REMOTE_ENABLE`` in the ``handles`` array field of the
> +``kcov_remote_arg`` struct. This will attach the used KCOV device to the code
> +section referenced by this handle. Multiple global handles identifying
> +different code sections can be passed at once.
> +
> +For #2, the userspace process instead must pass a non-zero handle through the
> +``common_handle`` field of the ``kcov_remote_arg`` struct. This common handle
> +gets saved to the ``kcov_handle`` field in the current ``task_struct`` and
> +needs to be passed to the newly spawned local tasks via custom kernel code
> +modifications. Those tasks should in turn use the passed handle in their
> +``kcov_remote_start`` and ``kcov_remote_stop`` annotations.
> +
> +KCOV follows a predefined format for both global and common handles. Each
> +handle is a ``u64`` integer. Currently, only the one top and the lower 4 bytes
> +are used. Bytes 4-7 are reserved and must be zero.
> +
> +For global handles, the top byte of the handle denotes the id of a subsystem
> +this handle belongs to. For example, KCOV uses ``1`` as the USB subsystem id.
> +The lower 4 bytes of a global handle denote the id of a task instance within
> +that subsystem. For example, each ``hub_event`` worker uses the USB bus number
> +as the task instance id.
> +
> +For common handles, a reserved value ``0`` is used as a subsystem id, as such
> +handles don't belong to a particular subsystem. The lower 4 bytes of a common
> +handle identify a collective instance of all local tasks spawned by the
> +userspace process that passed a common handle to ``KCOV_REMOTE_ENABLE``.
> +
> +In practice, any value can be used for common handle instance id if coverage
> +is only collected from a single userspace process on the system. However, if
> +common handles are used by multiple processes, unique instance ids must be
> +used for each process. One option is to use the process id as the common
> +handle instance id.
> +
> +The following program demonstrates using KCOV to collect coverage from both
> +local tasks spawned by the process and the global task that handles USB bus #1:
>
>  .. code-block:: c
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ4GvK-XCbrLp8cuH-xHYsCdh1f0948ZgkU2D0apfGG5w%40mail.gmail.com.
