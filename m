Return-Path: <kasan-dev+bncBCMIZB7QWENRBI7VTGAQMGQE62NRWWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D8D38319F26
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 13:55:00 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id d8sf8541550ion.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 04:55:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613134500; cv=pass;
        d=google.com; s=arc-20160816;
        b=xx+JGRG2n/Igh1ISRBVzjzK+X3kF2CukwGnrWcXVf5uuJByGtJWtTBZzjcftUaZiza
         tIADpH01FOG8UbGzQPLyIJvE++zooULEDtTQ35kz0FGTWfb9T+C7x/S9rPp8/jIL946P
         Akt7MMyi0yX2YKMYppukFbGOBOGyB1VDyCGmVPibjZ8Sj5CqTVMa1SOyKBZ4UXnG4cCB
         m4Uzj5nFkX6HQJxt2uZBQta5CKF35rS8aPNuBvLdwkfjfqOSulWl7rTzlLvDxJygxarC
         eZoA2aq/mbB3rdfb2us1h13yF9PW798b2Sg0dsObV8RUwrasvRfy0587A9gmwdMbHuIy
         zkng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OMWEq+Uo8ueSmqnRl+W9g5zpxSDUSTg07vmow50yFMQ=;
        b=MrLWV3WwKxCJIZ9NQX4SiFc7Ld8S1OPlwj33F6sx3ztl7HkiPy9ChqdiWucu4Uquy4
         rYwzv00PKNLb9ThwGFI/Bxm9dMo+/ZUvChl4w7RSyfc/Qx06S0s7ZRDc3DjzLMNy0hBN
         xeu4dNoxcxoSJYcz8vtoZDcK7pVyb1l0GnRRHB/QBTtjjnObTOAgWFvrZFuaD9WPZ6jd
         Z6wfHV0EFa5YMh1L1FW9T8PM5VLUuL86QRoW0bFildO3ni950gZNuRdoDaZZw1V5YpHI
         9uCALFXqU3IuI4atf0aijNMkgYfPl0v+wIqoJZ7B5lWvko4+pO6aSamZqqDAz4Sh4w4J
         TPig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eb5OnfMh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OMWEq+Uo8ueSmqnRl+W9g5zpxSDUSTg07vmow50yFMQ=;
        b=P4JsqbJSk8QCkmjEcHnw/EwBmKG8ABS4koCBluZRaUnyNnZPBG3w2KfSoGC6mHbonl
         tC+zRt1IvbtPcCaccmpJ5laxx97wLptHipkWN/iWuuL7rJ52Bwtc+c9kpBbkkn3SfiFn
         2lY9e3Djo5QLQmxlWjYmbBaWsbYmxOxjAwlxO6bu0U/N9668mt/9koH1US7ZeTPkehTj
         Rh2LrKkUUQaS1JogtkvdJBzYG0P93OL3selzJifv2tnr4bHQOK22VMpfhOjBZitQmOJ6
         PvMCIG4gJIPZu/mQVIQoKPGaFNsDOdqCjAjBPJKoB3jbR7W01lR2Szb2Y3/3XkhUSHxO
         akrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OMWEq+Uo8ueSmqnRl+W9g5zpxSDUSTg07vmow50yFMQ=;
        b=PgVqNIlkxgWKJgyIa+XpAvCieVhPE6avm5gyZ/PlpFA/FlgApfnNAF9YH7doZ9TWl7
         ifRWrVSLzYnMERHDAmIJak26MFgMAIHGj6ZFNbKe6dfbAUDqnde2sd3KB5sdHjyxAG1T
         1s8OdA/N3sHbnlbGkW8z1Ri20/LHRtVnXovTISCy3ZAW0flzmLbxMATqdPlnYr1rohG7
         qO9U7UJKdHSvBAO+gwM+VmWeEDp6sYeNPI5TUXO8WHjM7YdCtU6vTSfNlNkg026exgyG
         C076ua2dxob+WXW00rC7KfgvWjXuhKteFZAYjJWMnxYyWHcDw6DNwEU0zLTCq7BLewHv
         71cA==
X-Gm-Message-State: AOAM532PkPRfSS+v0azGxm3KiTOkpgD6PDOw2+uTTCgR8S0BAwgFDVsY
	va+H5YIzr5NHMSspdaNl5wA=
X-Google-Smtp-Source: ABdhPJzGVOUwxaKmPzTXaNKSgthhCFK/QGchbWI9+KA4LWHms68U8bYcv5N5quO22azQPKwKDX6ocA==
X-Received: by 2002:a05:6e02:dc3:: with SMTP id l3mr2169233ilj.70.1613134499942;
        Fri, 12 Feb 2021 04:54:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7f0f:: with SMTP id a15ls2287348ild.8.gmail; Fri, 12 Feb
 2021 04:54:59 -0800 (PST)
X-Received: by 2002:a92:6408:: with SMTP id y8mr2231090ilb.203.1613134499556;
        Fri, 12 Feb 2021 04:54:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613134499; cv=none;
        d=google.com; s=arc-20160816;
        b=rrrM9S5rZH0XuCUZ8FlrDQuGwluKn7bchisuP4PQpRZUezMi8KenkMvQfER0clXrt4
         /Y5IACyliPOmFly7JIRKyKOzCOiwqUFMM0F0m6XMC397tbTizamP3LGh5y3368KHkF0Z
         1CJGSVmY1ETExd9ZOSpglkv3AFltdk2gW8B25vTuwlNFCvJpR7pPeU+lftq10s0fnTQm
         kXRaPuiXDCBx9jkszhcwkUYT8kjqPCO5FpK8ZEBhrl8CoSKmMPMr4m5CipAF2Ax7qXiY
         8K4MFySLOc6coHGfVZ78aqSD4HvgbH0Rx2IOFFYnsCQoWjT2U0p5+Yx2liSjHUoCflQu
         2e8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A09MlorbuFhAqvAFLbguPfavL7t6ToDr/07aTs43MbM=;
        b=qSh0M7UAJSXddzKebIvTHjQLVk9uxVuBDVToUyXuyZllP/PjheKMJsH3Iryafl7wBe
         ecGLr06sE214LID3KUxpIWDygCfsByg40+6hxWd1ixJ8bH89JfYjfI8hSl/hzUJcwOu6
         72Sbh+ztQOOn+sJRS/qHuWWbdSLDywBBl0NmH+Rv9SfILd5mabzT9403OZcBin9/XyWq
         q2Cp1irPJpslsUgQfj4tBT71l2yCkrAfCWHGaIH36MzM2tYoqhkUJbv35WZyuS0XvprJ
         SVO/fgSe5zH/8QdH7TBsZCzmA3cbO2Qz66TBobVw+ZTZM1oBhn96wn4BcV1y1YQKfYlI
         7Gug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eb5OnfMh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id y6si289958ill.1.2021.02.12.04.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 04:54:59 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id b14so8558588qkk.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 04:54:59 -0800 (PST)
X-Received: by 2002:a37:a757:: with SMTP id q84mr2310526qke.501.1613134498748;
 Fri, 12 Feb 2021 04:54:58 -0800 (PST)
MIME-Version: 1.0
References: <20210211080716.80982-1-info@alexander-lochmann.de>
In-Reply-To: <20210211080716.80982-1-info@alexander-lochmann.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Feb 2021 13:54:47 +0100
Message-ID: <CACT4Y+YwRE=YNQYmQ=7RWde33830YOYr5pEAoYbrofY2JG43MA@mail.gmail.com>
Subject: Re: [PATCH] KCOV: Introduced tracing unique covered PCs
To: info@alexander-lochmann.de
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Wei Yongjun <weiyongjun1@huawei.com>, 
	Maciej Grochowski <maciej.grochowski@pm.me>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Eb5OnfMh;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72b
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

On Thu, Feb 11, 2021 at 9:07 AM Alexander Lochmann
<info@alexander-lochmann.de> wrote:
>
> Introduced new tracing mode KCOV_MODE_UNIQUE.
> It simply stores the executed PCs.
> The execution order is discarded.
> Each bit in the shared buffer represents every fourth
> byte of the text segment.
> Since a call instruction on every supported
> architecture is at least four bytes, it is safe
> to just store every fourth byte of the text segment.
> In contrast to KCOV_MODE_TRACE_PC, the shared buffer
> cannot overflow. Thus, all executed PCs are recorded.
>
> Signed-off-by: Alexander Lochmann <info@alexander-lochmann.de>
> ---
>  Documentation/dev-tools/kcov.rst | 80 ++++++++++++++++++++++++++++++++
>  include/linux/kcov.h             |  4 +-
>  include/uapi/linux/kcov.h        | 10 ++++
>  kernel/kcov.c                    | 67 ++++++++++++++++++++------
>  4 files changed, 147 insertions(+), 14 deletions(-)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index 8548b0b04e43..4712a730a06a 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -127,6 +127,86 @@ That is, a parent process opens /sys/kernel/debug/kcov, enables trace mode,
>  mmaps coverage buffer and then forks child processes in a loop. Child processes
>  only need to enable coverage (disable happens automatically on thread end).
>
> +If someone is interested in a set of executed PCs, and does not care about
> +execution order, he or she can advise KCOV to do so:
> +
> +.. code-block:: c
> +
> +    #include <stdio.h>
> +    #include <stddef.h>
> +    #include <stdint.h>
> +    #include <stdlib.h>
> +    #include <sys/types.h>
> +    #include <sys/stat.h>
> +    #include <sys/ioctl.h>
> +    #include <sys/mman.h>
> +    #include <unistd.h>
> +    #include <fcntl.h>
> +
> +    #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned long)
> +    #define KCOV_INIT_UNIQUE                _IOR('c', 2, unsigned long)
> +    #define KCOV_ENABLE                        _IO('c', 100)
> +    #define KCOV_DISABLE                       _IO('c', 101)
> +
> +    #define BITS_PER_LONG 64
> +    #define KCOV_TRACE_PC  0
> +    #define KCOV_TRACE_CMP 1
> +    #define KCOV_UNIQUE_PC 2
> +    /*
> +     * Determine start of text segment via 'nm vmlinux | grep _stext | cut -d " " -f1',
> +     * and fill in.
> +     */
> +    #define STEXT_START 0xffffffff81000000
> +
> +
> +
> +    int main(int argc, char **argv)
> +    {
> +       int fd;
> +       unsigned long *cover, n, i;
> +
> +       /* A single fd descriptor allows coverage collection on a single
> +        * thread.
> +        */
> +       fd = open("/sys/kernel/debug/kcov", O_RDWR);
> +       if (fd == -1)
> +               perror("open"), exit(1);
> +       /* Setup trace mode and trace size. */
> +       if ((n = ioctl(fd, KCOV_INIT_UNIQUE, 0)) < 0)
> +               perror("ioctl"), exit(1);
> +       /* Mmap buffer shared between kernel- and user-space. */
> +       cover = (unsigned long*)mmap(NULL, n,
> +                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
> +       if ((void*)cover == MAP_FAILED)
> +               perror("mmap"), exit(1);
> +       /* Enable coverage collection on the current thread. */
> +       if (ioctl(fd, KCOV_ENABLE, KCOV_UNIQUE_PC))
> +               perror("ioctl"), exit(1);
> +       /* That's the target syscal call. */
> +       read(-1, NULL, 0);
> +       /* Disable coverage collection for the current thread. After this call
> +        * coverage can be enabled for a different thread.
> +        */
> +       if (ioctl(fd, KCOV_DISABLE, 0))
> +               perror("ioctl"), exit(1);
> +        /* Convert byte size into element size */
> +        n /= sizeof(unsigned long);
> +        /* Print executed PCs in sorted order */
> +        for (i = 0; i < n; i++) {
> +            for (int j = 0; j < BITS_PER_LONG; j++) {
> +                if (cover[i] & (1L << j)) {
> +                    printf("0x%jx\n", (uintmax_t)(STEXT_START + (i * BITS_PER_LONG + j) * 4));
> +                }
> +            }
> +        }
> +       /* Free resources. */
> +       if (munmap(cover, n * sizeof(unsigned long)))
> +               perror("munmap"), exit(1);
> +       if (close(fd))
> +               perror("close"), exit(1);
> +       return 0;
> +    }
> +
>  Comparison operands collection
>  ------------------------------
>
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index a10e84707d82..aa0c8bcf8299 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -19,7 +19,9 @@ enum kcov_mode {
>          */
>         KCOV_MODE_TRACE_PC = 2,
>         /* Collecting comparison operands mode. */
> -       KCOV_MODE_TRACE_CMP = 3,
> +       KCOV_MODE_TRACE_CMP = 4,
> +       /* Collecting unique covered PCs. Execution order is not saved. */
> +       KCOV_MODE_UNIQUE_PC = 8,
>  };
>
>  #define KCOV_IN_CTXSW  (1 << 30)
> diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> index 1d0350e44ae3..5b99b6d1a1ac 100644
> --- a/include/uapi/linux/kcov.h
> +++ b/include/uapi/linux/kcov.h
> @@ -19,6 +19,7 @@ struct kcov_remote_arg {
>  #define KCOV_REMOTE_MAX_HANDLES                0x100
>
>  #define KCOV_INIT_TRACE                        _IOR('c', 1, unsigned long)
> +#define KCOV_INIT_UNIQUE               _IOR('c', 2, unsigned long)
>  #define KCOV_ENABLE                    _IO('c', 100)
>  #define KCOV_DISABLE                   _IO('c', 101)
>  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remote_arg)
> @@ -35,6 +36,15 @@ enum {
>         KCOV_TRACE_PC = 0,
>         /* Collecting comparison operands mode. */
>         KCOV_TRACE_CMP = 1,
> +       /*
> +        * Unique coverage collection mode.
> +        * Unique covered PCs are collected in a per-task buffer.
> +        * De-duplicates the collected PCs. Execution order is *not* saved.
> +        * Each bit in the buffer represents every fourth byte of the text segment.
> +        * Since a call instruction is at least four bytes on every supported
> +        * architecture, storing just every fourth byte is sufficient.
> +        */
> +       KCOV_UNIQUE_PC = 2,
>  };
>
>  /*
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 6b8368be89c8..8f00ba6e672a 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -24,6 +24,7 @@
>  #include <linux/refcount.h>
>  #include <linux/log2.h>
>  #include <asm/setup.h>
> +#include <asm/sections.h>
>
>  #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
>
> @@ -171,7 +172,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>          * kcov_start().
>          */
>         barrier();
> -       return mode == needed_mode;
> +       return (mode & needed_mode) && !(mode & KCOV_IN_CTXSW);

I see this produces an additional check and branch:

void foo1(unsigned mode) {
  if ((mode & 10) && !(mode & (1<<30)))
    foo();
}

   0: 40 f6 c7 0a          test   $0xa,%dil
   4: 74 0f                je     15 <foo1+0x15>
   6: 81 e7 00 00 00 40    and    $0x40000000,%edi
   c: 75 07                jne    15 <foo1+0x15>
   e: 31 c0                xor    %eax,%eax
  10: e9 00 00 00 00        jmpq   15 <foo1+0x15>

I think we could make KCOV_IN_CTXSW sign bit and then express the check as:

void foo2(unsigned mode) {
  if (((int)(mode & 0x8000000a)) > 0)
    foo();
}

0000000000000020 <foo2>:
  20: 81 e7 0a 00 00 80    and    $0x8000000a,%edi
  26: 7f 08                jg     30 <foo2+0x10>
  28: c3                    retq




>  }
>
>  static notrace unsigned long canonicalize_ip(unsigned long ip)
> @@ -191,18 +192,26 @@ void notrace __sanitizer_cov_trace_pc(void)
>         struct task_struct *t;
>         unsigned long *area;
>         unsigned long ip = canonicalize_ip(_RET_IP_);
> -       unsigned long pos;
> +       unsigned long pos, idx;
>
>         t = current;
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t))
>                 return;
>
>         area = t->kcov_area;
> -       /* The first 64-bit word is the number of subsequent PCs. */
> -       pos = READ_ONCE(area[0]) + 1;
> -       if (likely(pos < t->kcov_size)) {
> -               area[pos] = ip;
> -               WRITE_ONCE(area[0], pos);
> +       if (likely(t->kcov_mode == KCOV_MODE_TRACE_PC)) {

Does this introduce an additional real of t->kcov_mode?
If yes, please reuse the value read in check_kcov_mode.


> +               /* The first 64-bit word is the number of subsequent PCs. */
> +               pos = READ_ONCE(area[0]) + 1;
> +               if (likely(pos < t->kcov_size)) {
> +                       area[pos] = ip;
> +                       WRITE_ONCE(area[0], pos);
> +               }
> +       } else {
> +               idx = (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
> +               pos = idx % BITS_PER_LONG;
> +               idx /= BITS_PER_LONG;
> +               if (likely(idx < t->kcov_size))
> +                       WRITE_ONCE(area[idx], READ_ONCE(area[idx]) | 1L << pos);
>         }
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> @@ -474,6 +483,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>                 goto exit;
>         }
>         if (!kcov->area) {
> +               kcov_debug("mmap(): Allocating 0x%lx bytes\n", size);
>                 kcov->area = area;
>                 vma->vm_flags |= VM_DONTEXPAND;
>                 spin_unlock_irqrestore(&kcov->lock, flags);
> @@ -515,6 +525,8 @@ static int kcov_get_mode(unsigned long arg)
>  {
>         if (arg == KCOV_TRACE_PC)
>                 return KCOV_MODE_TRACE_PC;
> +       else if (arg == KCOV_UNIQUE_PC)
> +               return KCOV_MODE_UNIQUE_PC;

As far as I understand, users can first do KCOV_INIT_UNIQUE and then
enable KCOV_TRACE_PC, or vice versa.
It looks somewhat strange. Is it intentional? It's not possible to
specify buffer size for KCOV_INIT_UNIQUE, so most likely the buffer
will be either too large or too small for a trace.




>         else if (arg == KCOV_TRACE_CMP)
>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
>                 return KCOV_MODE_TRACE_CMP;
> @@ -562,12 +574,13 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>  {
>         struct task_struct *t;
>         unsigned long size, unused;
> -       int mode, i;
> +       int mode, i, text_size, ret = 0;
>         struct kcov_remote_arg *remote_arg;
>         struct kcov_remote *remote;
>         unsigned long flags;
>
>         switch (cmd) {
> +       case KCOV_INIT_UNIQUE:

I think nowadays you need some annotation like fallthrough here.

>         case KCOV_INIT_TRACE:
>                 /*
>                  * Enable kcov in trace mode and setup buffer size.
> @@ -581,11 +594,39 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                  * that must not overflow.
>                  */
>                 size = arg;
> -               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> -                       return -EINVAL;
> -               kcov->size = size;
> +               if (cmd == KCOV_INIT_UNIQUE) {
> +                       if (size != 0)
> +                               return -EINVAL;
> +                       text_size = (canonicalize_ip((unsigned long)&_etext) - canonicalize_ip((unsigned long)&_stext));
> +                       /**
> +                        * A call instr is at least four bytes on every supported architecture.
> +                        * Hence, just every fourth instruction can potentially be a call.
> +                        */
> +                       text_size /= 4;

Strictly saying, we need to round up text_size to 4 before dividing by
4. Otherwise we potentially don't cover up to the last 3 bytes.


> +                       /*
> +                        * Round up size of text segment to multiple of BITS_PER_LONG.
> +                        * Otherwise, we cannot track
> +                        * the last (text_size % BITS_PER_LONG) addresses.
> +                        */
> +                       text_size = roundup(text_size, BITS_PER_LONG);
> +                       /* Get the amount of bytes needed */
> +                       text_size = text_size / 8;
> +                       /* mmap() requires size to be a multiple of PAGE_SIZE */
> +                       text_size = roundup(text_size, PAGE_SIZE);
> +                       /* Get the cover size (= amount of longs stored) */

s/longs/bytes/

> +                       ret = text_size;
> +                       kcov->size = text_size / sizeof(unsigned long);
> +                       kcov_debug("text size = 0x%lx, roundup = 0x%x, kcov->size = 0x%x\n",
> +                                       ((unsigned long)&_etext) - ((unsigned long)&_stext),
> +                                       text_size,
> +                                       kcov->size);
> +               } else {
> +                       if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> +                               return -EINVAL;
> +                       kcov->size = size;
> +               }
>                 kcov->mode = KCOV_MODE_INIT;
> -               return 0;
> +               return ret;
>         case KCOV_ENABLE:
>                 /*
>                  * Enable coverage for the current task.
> --
> 2.30.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYwRE%3DYNQYmQ%3D7RWde33830YOYr5pEAoYbrofY2JG43MA%40mail.gmail.com.
