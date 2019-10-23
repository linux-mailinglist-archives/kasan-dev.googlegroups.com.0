Return-Path: <kasan-dev+bncBCMIZB7QWENRBQGAYDWQKGQE7NYJQGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id A59DFE1669
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2019 11:41:21 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id v10sf14707443pge.12
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2019 02:41:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571823680; cv=pass;
        d=google.com; s=arc-20160816;
        b=d+8fwEQ/KRgYCe5KVbZb7Ru/zX8PD8qderhDeusFwbuJJ0SOGz3YFWGv9utOOrri3W
         xfkDMwwZtyAhnWa8nnHrExQCqaQZeUnDcA1yhSMOlonaQfXD63xEQ/wct+ZwM7ReWQ/E
         Kwbtu/eotr0eumcwWEua7Gbi78xdjNaGgD4b03p9MDvxfMaezjRjL1C97ohvvJ2C+FNS
         1MI2Q0vzzaQBu2VcRb3MPLViJossFnTFyExQ7ReHAo/ChSPad9CM6euy0bsaK/I3wdOK
         O5/VLqphhSKqROy4gxclZh8fLNsz6UyLZ8JsdhPkrKU0mOFhzu0FtEbHT45vmBb20HEw
         bFLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KQhM3KJLgGz2Sw0oVRvk87aQszwddWQOQI+1ZwznqZ8=;
        b=EsicT7xdiH+V44aUzL+9pR0PhDExzkV1F2/nUH1CbzXZMwpgQi47jpmG9XOviaGv7N
         uOm+rU9TFIUuzMGaF9o2w/R4hDjzVDZXC+DCuvbc21JEw/6DxDpbIqBEamvEVJY11/CW
         bAAvIokmM55pQTvTVhFDGHiodH3LiBg+9n89mOeYDNhuY0g8wqKsKkEQnVkshYDWznrv
         s+v6CrC8p6v+o9OpXlQ8OUop/q1yiY0hj79eyNV63RkBB+GczJlOVnzglx0Qo9l745JD
         Y4lHTTB2aovDywKV/9TEjKz4KDKb4N24YRxrZWe8E0AzMvCwW1ckBNW4fT6myPefNYZr
         9jhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V55CsmiO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KQhM3KJLgGz2Sw0oVRvk87aQszwddWQOQI+1ZwznqZ8=;
        b=FBdj6NlC+MuHu/3LbIsTYBnTiLK5asIenzr21ulrfLSWzJAE5Tpg0do+G4Nm7BU+EX
         gI3kRF3tZMGVL24HWLSuSFW3qc8K+xAvlI3fmwtKgxok139M6dQ/jBRVr0K9Te/xO0hd
         KXP3Xz37gScwHDaOO0ndcs23bn60kSOA28itV9G5attU8dNizukHytG20NDS+TwQyT/s
         P16TbriN2R994oxu+L93Gs90XWYMl0D2YuteD7j4F2rKmdpMbhntkDM1pdGqtqmXcPR0
         /C4kzN1Mp3qy2UHzuL3T0O/IwEuqH+bVyVSqSdeKXOqZAXLM9eGBWzFsG1KR/DVeFJ33
         mwSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KQhM3KJLgGz2Sw0oVRvk87aQszwddWQOQI+1ZwznqZ8=;
        b=p7JCaNRwENm17yuDB0LmS236ahc8dRUgboR5BmeMkschbGItkbvjiy5/44exAK3ETe
         Cx+YMJDPWvzUOYU6qW+0rY99hAMdbO66Y9ad3C3fV3dsUMDWPX9HQytuLyJxWl+N7llt
         EW6f5VuzObxhb6SMV6SKhorjEuLvuGLzyG7UiB2Ew9LL3sh4s+Nyf0mEAnlcTtYnG46u
         LOWITsIw64BBrNIHgeZkis6hXnWvDtNKC18+6wJuKLx4gQHQ91W4QW5EKUMJwiOmJE3z
         31T3QVxG/HXfOqgWNilcbwHBgXJcILJbgj6WhscxXkDuPCdp78HYs7ZfgKzVcIe+so/S
         w/4g==
X-Gm-Message-State: APjAAAUnnwsAEnT/WoH9KurdQRwnplofdxn5RiUyU3zL9fPhxtPNdm/T
	0bz4iBdwPW1fbgFSXZ9w5dI=
X-Google-Smtp-Source: APXvYqw+1/dwD+seoOomYcui/aVH6gqeilMbn+g/R7Ph+E9C0sz7i5LW/fzwMEL6brv8Ui2ysThalg==
X-Received: by 2002:a63:1609:: with SMTP id w9mr6695060pgl.184.1571823680127;
        Wed, 23 Oct 2019 02:41:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:204c:: with SMTP id r12ls560713pgm.1.gmail; Wed, 23 Oct
 2019 02:41:19 -0700 (PDT)
X-Received: by 2002:a63:cd18:: with SMTP id i24mr9260932pgg.333.1571823679621;
        Wed, 23 Oct 2019 02:41:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571823679; cv=none;
        d=google.com; s=arc-20160816;
        b=z8bKJxG/tk+rIVcc8xpDVBaqLiE9XiVyy+/DSvqw5hALgCOaeI0L9Pj5Gqtv7EVqso
         kxr45/V4HSuHTYju2eq32d+ZGaAXeISEUHY05eMlYFRC63jaIVUiBcDqg+asjl9MY8mx
         gQa0Vz7R9734MerZU/Bq2hjsklEzgGekGEb4tG8NjRJDAWC1p9h6DYut0T7AMeYNI/Wt
         +PoG7p/zw9IcQWQjfLtftwzS7PbOW0Mrr1ZwYnGHzo2mwukxIjUeSLmnsAgefMs4GmxT
         cnYw/kKR/MPWSXXfIC3SgzxktKIHlUTWjFunN0KgJi2IkvuHC3PNHClQz9+tZRpcncA0
         qz9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SPICzfN8jk9a5YVfl1sh7UIdtbJViu655bwlF7LS658=;
        b=lz2VRiEXyiygr/Q7CPNwLulIG71Kn85J7PHisFGPyNXXXjiXINIIVvmXnLCLAP3htG
         7AbZHl8EekJecRz2VQS/qAh9PAlgEtfr2DNHBFN81gf4D+OXLRXwCWZ6BWgmktD/m/1Z
         QWCu9QDTsesmkkil4JIzDV3k0k2288cxE0pBZOGZntI5rs+4g7xD1EMEhpWxCO/wnOQv
         JBUKuoNjtrzCOvI9Sj2oP4Jw55EKELIpffE9C7/76DJXmxNo1hBRZH/ia4g45JdH2JBt
         amJoDs2ifBt6z8bK07T8NBaz77OIwqALJZzKodslicb49v6UP3tvWvEITX+HA+UVjywE
         WQ8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V55CsmiO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id t17si374178pgu.1.2019.10.23.02.41.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Oct 2019 02:41:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id z22so10811144qtq.11
        for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2019 02:41:19 -0700 (PDT)
X-Received: by 2002:ad4:4345:: with SMTP id q5mr7859172qvs.80.1571823677972;
 Wed, 23 Oct 2019 02:41:17 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-2-elver@google.com>
In-Reply-To: <20191017141305.146193-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Oct 2019 11:41:06 +0200
Message-ID: <CACT4Y+Z0SNqx1FyK8rHYX6HeUfLSfifNRiQ5LXf3iParNYvCpw@mail.gmail.com>
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Luc Maranget <luc.maranget@inria.fr>, Mark Rutland <mark.rutland@arm.com>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	"open list:KERNEL BUILD + fi..." <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V55CsmiO;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

" "On Thu, Oct 17, 2019 at 4:13 PM Marco Elver <elver@google.com> wrote:
>
> Kernel Concurrency Sanitizer (KCSAN) is a dynamic data-race detector for
> kernel space. KCSAN is a sampling watchpoint-based data-race detector.
> See the included Documentation/dev-tools/kcsan.rst for more details.
>
> This patch adds basic infrastructure, but does not yet enable KCSAN for
> any architecture.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Elaborate comment about instrumentation calls emitted by compilers.
> * Replace kcsan_check_access(.., {true, false}) with
>   kcsan_check_{read,write} for improved readability.
> * Change bug title of race of unknown origin to just say "data-race in".
> * Refine "Key Properties" in kcsan.rst, and mention observed slow-down.
> * Add comment about safety of find_watchpoint without user_access_save.
> * Remove unnecessary preempt_disable/enable and elaborate on comment why
>   we want to disable interrupts and preemptions.
> * Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
>   contexts [Suggested by Mark Rutland].
> ---
>  Documentation/dev-tools/kcsan.rst | 203 ++++++++++++++
>  MAINTAINERS                       |  11 +
>  Makefile                          |   3 +-
>  include/linux/compiler-clang.h    |   9 +
>  include/linux/compiler-gcc.h      |   7 +
>  include/linux/compiler.h          |  35 ++-
>  include/linux/kcsan-checks.h      | 147 ++++++++++
>  include/linux/kcsan.h             | 108 ++++++++
>  include/linux/sched.h             |   4 +
>  init/init_task.c                  |   8 +
>  init/main.c                       |   2 +
>  kernel/Makefile                   |   1 +
>  kernel/kcsan/Makefile             |  14 +
>  kernel/kcsan/atomic.c             |  21 ++
>  kernel/kcsan/core.c               | 428 ++++++++++++++++++++++++++++++
>  kernel/kcsan/debugfs.c            | 225 ++++++++++++++++
>  kernel/kcsan/encoding.h           |  94 +++++++
>  kernel/kcsan/kcsan.c              |  86 ++++++
>  kernel/kcsan/kcsan.h              | 140 ++++++++++
>  kernel/kcsan/report.c             | 306 +++++++++++++++++++++
>  kernel/kcsan/test.c               | 117 ++++++++
>  lib/Kconfig.debug                 |   2 +
>  lib/Kconfig.kcsan                 |  88 ++++++
>  lib/Makefile                      |   3 +
>  scripts/Makefile.kcsan            |   6 +
>  scripts/Makefile.lib              |  10 +
>  26 files changed, 2069 insertions(+), 9 deletions(-)
>  create mode 100644 Documentation/dev-tools/kcsan.rst
>  create mode 100644 include/linux/kcsan-checks.h
>  create mode 100644 include/linux/kcsan.h
>  create mode 100644 kernel/kcsan/Makefile
>  create mode 100644 kernel/kcsan/atomic.c
>  create mode 100644 kernel/kcsan/core.c
>  create mode 100644 kernel/kcsan/debugfs.c
>  create mode 100644 kernel/kcsan/encoding.h
>  create mode 100644 kernel/kcsan/kcsan.c
>  create mode 100644 kernel/kcsan/kcsan.h
>  create mode 100644 kernel/kcsan/report.c
>  create mode 100644 kernel/kcsan/test.c
>  create mode 100644 lib/Kconfig.kcsan
>  create mode 100644 scripts/Makefile.kcsan
>
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> new file mode 100644
> index 000000000000..497b09e5cc96
> --- /dev/null
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -0,0 +1,203 @@
> +The Kernel Concurrency Sanitizer (KCSAN)
> +========================================
> +
> +Overview
> +--------
> +
> +*Kernel Concurrency Sanitizer (KCSAN)* is a dynamic data-race detector for
> +kernel space. KCSAN is a sampling watchpoint-based data-race detector -- this
> +is unlike Kernel Thread Sanitizer (KTSAN), which is a happens-before data-race
> +detector. Key priorities in KCSAN's design are lack of false positives,
> +scalability, and simplicity. More details can be found in `Implementation
> +Details`_.
> +
> +KCSAN uses compile-time instrumentation to instrument memory accesses. KCSAN is
> +supported in both GCC and Clang. With GCC it requires version 7.3.0 or later.
> +With Clang it requires version 7.0.0 or later.
> +
> +Usage
> +-----
> +
> +To enable KCSAN configure kernel with::
> +
> +    CONFIG_KCSAN = y
> +
> +KCSAN provides several other configuration options to customize behaviour (see
> +their respective help text for more info).
> +
> +debugfs
> +~~~~~~~
> +
> +* The file ``/sys/kernel/debug/kcsan`` can be read to get stats.
> +
> +* KCSAN can be turned on or off by writing ``on`` or ``off`` to
> +  ``/sys/kernel/debug/kcsan``.
> +
> +* Writing ``!some_func_name`` to ``/sys/kernel/debug/kcsan`` adds
> +  ``some_func_name`` to the report filter list, which (by default) blacklists
> +  reporting data-races where either one of the top stackframes are a function
> +  in the list.
> +
> +* Writing either ``blacklist`` or ``whitelist`` to ``/sys/kernel/debug/kcsan``
> +  changes the report filtering behaviour. For example, the blacklist feature
> +  can be used to silence frequently occurring data-races; the whitelist feature
> +  can help with reproduction and testing of fixes.
> +
> +Error reports
> +~~~~~~~~~~~~~
> +
> +A typical data-race report looks like this::
> +
> +    ==================================================================
> +    BUG: KCSAN: data-race in generic_permission / kernfs_refresh_inode
> +
> +    write to 0xffff8fee4c40700c of 4 bytes by task 175 on cpu 4:
> +     kernfs_refresh_inode+0x70/0x170
> +     kernfs_iop_permission+0x4f/0x90
> +     inode_permission+0x190/0x200
> +     link_path_walk.part.0+0x503/0x8e0
> +     path_lookupat.isra.0+0x69/0x4d0
> +     filename_lookup+0x136/0x280
> +     user_path_at_empty+0x47/0x60
> +     vfs_statx+0x9b/0x130
> +     __do_sys_newlstat+0x50/0xb0
> +     __x64_sys_newlstat+0x37/0x50
> +     do_syscall_64+0x85/0x260
> +     entry_SYSCALL_64_after_hwframe+0x44/0xa9
> +
> +    read to 0xffff8fee4c40700c of 4 bytes by task 166 on cpu 6:
> +     generic_permission+0x5b/0x2a0
> +     kernfs_iop_permission+0x66/0x90
> +     inode_permission+0x190/0x200
> +     link_path_walk.part.0+0x503/0x8e0
> +     path_lookupat.isra.0+0x69/0x4d0
> +     filename_lookup+0x136/0x280
> +     user_path_at_empty+0x47/0x60
> +     do_faccessat+0x11a/0x390
> +     __x64_sys_access+0x3c/0x50
> +     do_syscall_64+0x85/0x260
> +     entry_SYSCALL_64_after_hwframe+0x44/0xa9
> +
> +    Reported by Kernel Concurrency Sanitizer on:
> +    CPU: 6 PID: 166 Comm: systemd-journal Not tainted 5.3.0-rc7+ #1
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
> +    ==================================================================
> +
> +The header of the report provides a short summary of the functions involved in
> +the race. It is followed by the access types and stack traces of the 2 threads
> +involved in the data-race.
> +
> +The other less common type of data-race report looks like this::
> +
> +    ==================================================================
> +    BUG: KCSAN: data-race in e1000_clean_rx_irq+0x551/0xb10
> +
> +    race at unknown origin, with read to 0xffff933db8a2ae6c of 1 bytes by interrupt on cpu 0:
> +     e1000_clean_rx_irq+0x551/0xb10
> +     e1000_clean+0x533/0xda0
> +     net_rx_action+0x329/0x900
> +     __do_softirq+0xdb/0x2db
> +     irq_exit+0x9b/0xa0
> +     do_IRQ+0x9c/0xf0
> +     ret_from_intr+0x0/0x18
> +     default_idle+0x3f/0x220
> +     arch_cpu_idle+0x21/0x30
> +     do_idle+0x1df/0x230
> +     cpu_startup_entry+0x14/0x20
> +     rest_init+0xc5/0xcb
> +     arch_call_rest_init+0x13/0x2b
> +     start_kernel+0x6db/0x700
> +
> +    Reported by Kernel Concurrency Sanitizer on:
> +    CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.3.0-rc7+ #2
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
> +    ==================================================================
> +
> +This report is generated where it was not possible to determine the other
> +racing thread, but a race was inferred due to the data-value of the watched
> +memory location having changed. These can occur either due to missing
> +instrumentation or e.g. DMA accesses.
> +
> +Data-Races
> +----------
> +
> +Informally, two operations *conflict* if they access the same memory location,
> +and at least one of them is a write operation. In an execution, two memory
> +operations from different threads form a **data-race** if they *conflict*, at
> +least one of them is a *plain access* (non-atomic), and they are *unordered* in
> +the "happens-before" order according to the `LKMM
> +<../../tools/memory-model/Documentation/explanation.txt>`_.
> +
> +Relationship with the Linux Kernel Memory Model (LKMM)
> +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> +
> +The LKMM defines the propagation and ordering rules of various memory
> +operations, which gives developers the ability to reason about concurrent code.
> +Ultimately this allows to determine the possible executions of concurrent code,
> +and if that code is free from data-races.
> +
> +KCSAN is aware of *atomic* accesses (``READ_ONCE``, ``WRITE_ONCE``,
> +``atomic_*``, etc.), but is oblivious of any ordering guarantees. In other
> +words, KCSAN assumes that as long as a plain access is not observed to race
> +with another conflicting access, memory operations are correctly ordered.
> +
> +This means that KCSAN will not report *potential* data-races due to missing
> +memory ordering. If, however, missing memory ordering (that is observable with
> +a particular compiler and architecture) leads to an observable data-race (e.g.
> +entering a critical section erroneously), KCSAN would report the resulting
> +data-race.
> +
> +Implementation Details
> +----------------------
> +
> +The general approach is inspired by `DataCollider
> +<http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf>`_.
> +Unlike DataCollider, KCSAN does not use hardware watchpoints, but instead
> +relies on compiler instrumentation. Watchpoints are implemented using an
> +efficient encoding that stores access type, size, and address in a long; the
> +benefits of using "soft watchpoints" are portability and greater flexibility in
> +limiting which accesses trigger a watchpoint.
> +
> +More specifically, KCSAN requires instrumenting plain (unmarked, non-atomic)
> +memory operations; for each instrumented plain access:
> +
> +1. Check if a matching watchpoint exists; if yes, and at least one access is a
> +   write, then we encountered a racing access.
> +
> +2. Periodically, if no matching watchpoint exists, set up a watchpoint and
> +   stall some delay.

Is it grammatically correct "to stall a delay"? Shouldn't stall be
used with "for"?


> +
> +3. Also check the data value before the delay, and re-check the data value
> +   after delay; if the values mismatch, we infer a race of unknown origin.
> +
> +To detect data-races between plain and atomic memory operations, KCSAN also
> +annotates atomic accesses, but only to check if a watchpoint exists
> +(``kcsan_check_atomic_*``); i.e.  KCSAN never sets up a watchpoint on atomic
> +accesses.
> +
> +Key Properties
> +~~~~~~~~~~~~~~
> +
> +1. **Memory Overhead:** No shadow memory is required. The current
> +   implementation uses a small array of longs to encode watchpoint information,
> +   which is negligible.
> +
> +2. **Performance Overhead:** KCSAN's runtime aims to be minimal, using an
> +   efficient watchpoint encoding that does not require acquiring any shared
> +   locks in the fast-path. For kernel boot with a default config on a system
> +   where nproc=8 we measure a slow-down of 10-15x.

Is it a correct number? 10-15x does not look particularly fast. TSAN
is much faster.
If it's a correct number, perhaps we need to tune the defaults to get
it to a reasonable leve.
Also, what's the minimal level of overhead with infinitely large
sampling? That may be a useful number to provide as well.

> +3. **Memory Ordering:** KCSAN is *not* aware of the LKMM's ordering rules. This
> +   may result in missed data-races (false negatives), compared to a
> +   happens-before data-race detector.

Well, it definitely aware of some of them, e.g. program order :)
It's just not aware of some of the finer details.

> +
> +4. **Accuracy:** Imprecise, since it uses a sampling strategy.

A common term I've seen for this is completeness/incompleteness.
Do we want to mention Soundness? That's more important for any dynamic tool.


> +5. **Annotation Overheads:** Minimal annotation is required outside the KCSAN
> +   runtime. With a happens-before data-race detector, any omission leads to
> +   false positives, which is especially important in the context of the kernel
> +   which includes numerous custom synchronization mechanisms. With KCSAN, as a
> +   result, maintenance overheads are minimal as the kernel evolves.

The whole doc is sprinkled with explicit and implicit comparisons with
and diffs on top of a happens-before-based detector (starting from the
very first sentences, KCSAN is effectively defined as being
"not-KTSAN"). This is reasonable for us at this particular point in
time, but it's not so reasonable for most users of this doc and for
future. No happens-before race detector officially exists for kernel.
I would consider adding a separate section for alternative approaches,
rationale and comparison with a happens-before-based detector. Such
section would be a good place to talk about our previous experience
and e.g. shadow memory. Currently the first thing you say about memory
overhead is "No shadow memory is required", and I am like "why are you
even mentioning this? and what is even shadow memory?".

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ0SNqx1FyK8rHYX6HeUfLSfifNRiQ5LXf3iParNYvCpw%40mail.gmail.com.
