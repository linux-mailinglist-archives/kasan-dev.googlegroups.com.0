Return-Path: <kasan-dev+bncBCJ455VFUALBB7VK7OPQMGQEJFMY6HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id E8D3A6A66F6
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 05:33:03 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id c24-20020ab023d8000000b006907ba8c229sf1794944uan.23
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 20:33:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677645182; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z32DtwohWS5sPPbtIQomIvBDqnqtyVxXcV9YbfnFBdikyYZR3aOmRHVVlf2FBFHfY9
         fOXBDLIfQs9bGUpe/D4dl8Od3/lTB0DXkjPX4Nwx4sytId7YWUzaXNoXk3K914uhlT0C
         6dXY7Xul+Cq3Af65g4t/oWVyPFpvzKxex9FrnzYUHoJzth/ypzRjlf/PUyfXZkuEsB4C
         n7DFZ0c3U0HdPOYC0kUIi/jxDxAuZX70gm4JkoFykKrnNCxmIthfFaKjW3F9CLxQdPt9
         Iz0ANJLIsHdNefu4k4dAMesrIDHaLh4DPELfB85ZB+sCEFM3E8erukOEzm4CZeEPuhrB
         yrCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=/V6N7efvwQF3JutnzWoc45Sn2Lv15/HU6EMAmAE1vWM=;
        b=dhFq832g6AOsc4h/qujBfEBY5U/Xn+fF4SsNz080FwPSQD7qombspTLmXa7js20Nw8
         aQ56KeBzOClR3ka29g3MbdpgvAzWnWWdLsYC5xGF+oPYy+wQ9Dnk6zDWHPA7ZdAJO/gs
         rIIc1Cb8YIgIrTaJJ5I2/lOYM6UU4xV+gne71bK331VMcckh44+8ZVikPqV/s8fgvHj7
         xkgy7lsNqTfyh/mFDSs9H3euBTgc0PsVVB/4XD6yG4PvGdY8XFw0Vxz4sFdZjMohA2Hk
         kZ7WkBXW9mSo9tEjZ83Rlkdko5f7tdeyBg6br7d0gF0vB6QPPu84CvXDfjtOa+jIDL4G
         mhtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JlPP0rfT;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/V6N7efvwQF3JutnzWoc45Sn2Lv15/HU6EMAmAE1vWM=;
        b=k9JTBCiT1SwnB0NkcL+ACCT7IZokQqGQLmIQdibKoOb60Olrld8Cut+LcLBxMcCiH4
         pX/MtDO5zjQwf4sjv0sJ76akKmlyvJHfb6/98Wr4L6pXDWLhWl+HuEVoEbMkmNciFkfV
         2b12K78yz+u+8uk5k8/y8QKoHrFvtwBN5KswvZwDkJpjALxxXHOYx+H/Ozumpo76dEe5
         kKX7t2y8xFWA8ncZlB1+0bQ32ZO7oFmGo47Rlf0GzUfCb/ZEwoqcZZjOU0mrA/1SEdi4
         kpnBhEO1GhuieJo4QZZsx59YOPdiI41dX8LHh31XqDfuLw9CSHBpE416PuzUya1UivK0
         9XYg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=/V6N7efvwQF3JutnzWoc45Sn2Lv15/HU6EMAmAE1vWM=;
        b=KNsixdwSeNRJAqs2Veaoc28ZhWIsogkmVojL4iqOozb7TYhpVriLEo30Iv010NBF7Y
         Th6Feh32iQVN2HC8+di4Dzk0IrF7lPm0F+0R9BxW/gNGdzMO4lM4fvd4Y/RgCRtwbqXG
         TJ7k2eNTCMm7jhWLjSWm4BzM3OxAysBjoBSePVbUbXmd6WfxiBft5pkt6XRnW4xOk+V6
         d4Y5GDT4vkbAQ/xKIN+X1MrwH/cC2LArrWETMaHSaQlhhGyBpFRfBPDJsc7wY/zjXX/J
         iB0TzyCwHuGX2Fqxupp5Ecz+xM2INL0U6bzZfDRbq8ImDshx+K6pTB8GM3Dwsg+JuSGi
         Wf3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/V6N7efvwQF3JutnzWoc45Sn2Lv15/HU6EMAmAE1vWM=;
        b=Y+LxxBWGpOkY8Uk3AFfyKrlCwqTzvLAQgLoDUwCn7b6atLXVPs+eaq8ws7M+QZe1QP
         MVrLQI2f4FKv6StZ1BiAq1llmro4Lo0fLy0Au7QFEUoce3QF9go2W5GEe18SMRwtCtlf
         3DahA3HuUELI3sGq8edkVq2kG5T6K4s+nARd4Qx9WvCREJFTeFTAEXRFGIdGlcYDHegU
         V5dzQPZFi8NViDAoloWbQ3lXWpXFuEwvygYFBkU0WoRxvEP8RtEnCqWDUsIAk2nkepHA
         xTKbPRJACFJtZCDvYkRitFagjGtchHcQrnVGL8Ux3hi9fulwVPEMtaXm+HBf0+eSobOP
         b6VQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWMNymIbSU/qQCzpbgzRDYW4Rq4smSE0eBWPYbcLyYFW/Db0ESe
	XmnV++F9kNR+nu3pEm5cLKo=
X-Google-Smtp-Source: AK7set+HssH+NZk6sp6iXiF6o42RFKDPci+1MXsdQHJTIfcDowvkKaLzji5SvZsefJd20Y8erqHB1A==
X-Received: by 2002:a67:eb8b:0:b0:402:9b84:1bde with SMTP id e11-20020a67eb8b000000b004029b841bdemr3574144vso.0.1677645182631;
        Tue, 28 Feb 2023 20:33:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:7d0d:0:b0:411:b190:fee5 with SMTP id y13-20020a1f7d0d000000b00411b190fee5ls2401618vkc.5.-pod-prod-gmail;
 Tue, 28 Feb 2023 20:33:01 -0800 (PST)
X-Received: by 2002:a1f:a04b:0:b0:401:5379:cd42 with SMTP id j72-20020a1fa04b000000b004015379cd42mr2374175vke.8.1677645181719;
        Tue, 28 Feb 2023 20:33:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677645181; cv=none;
        d=google.com; s=arc-20160816;
        b=dL3chJDM4VX6zRsrUFCCqXzKEKCV8Q7RJN7kSJn7iLi0dNYQp13bY9xcMeq5tEZqoJ
         xSTN9GSchFgv23zttTIhas+Hh0H+KYpQe5wFnlJ1e1+r0WNMUcGDxhMQAQVo3+TFAsZI
         9ynio4NYNZmJGzUce/mPNrQ7db0WUd8jj1DXb5+FzmGpvdvSz6ct+EkXh1gnVIBSJnr9
         wCYLkrsEhXmlYvqO7gzh0z7oyO85PUvWpFt31s7bjnjlJMNevIN+1LT54B06VCYuwgZU
         fMDv98D9Of0eRqGWNASUfae0Xw8KlFfDYTTkDXakBGwexGs5wObdrUaP1BzgzSVprm8u
         nItg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BUFS3+ohbwNXbu3J/sdx7ngaO9F+ivRU8ju2bKz74QI=;
        b=G3SCmfIZbItTTzPz+By2f+7eA/icd7GafrTWZihifhcKEDQ1lHEFy4Ob1Yygb3W3Qs
         /VuWWo6ezgCgUHFmBnpws9Y4KCFQ8BHQk/nFgE/kgzanVjlcHLB18vbtjDpxSWoeh2vh
         mJ6u2okdqkfOD0TiMVPuOBEF37dX7/xIcvyVYS+C+UbUGRUXsD5eqrefSjtSVBHC4iAo
         DJr4oRIO6zxRhZsUKiOSsroKDoBq489wD92zp60MTov7lYXB5V8eWZ2FEtxFuvFPjz8T
         2HCVUYmBE7NZZcX1l3TmHkT0ZCGdOPHdoog3gcxlpu8XhSMwK/Ak401cC7sLgQlIBZil
         P13Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JlPP0rfT;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id y1-20020ac5cf01000000b00400dba9ad27si667213vke.0.2023.02.28.20.33.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 20:33:01 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id y2so12075723pjg.3
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 20:33:01 -0800 (PST)
X-Received: by 2002:a17:903:40c6:b0:19c:d6d0:7887 with SMTP id t6-20020a17090340c600b0019cd6d07887mr4464395pld.30.1677645180693;
        Tue, 28 Feb 2023 20:33:00 -0800 (PST)
Received: from debian.me (subs02-180-214-232-73.three.co.id. [180.214.232.73])
        by smtp.gmail.com with ESMTPSA id b11-20020a170902ed0b00b0019602b2c00csm7279061pld.175.2023.02.28.20.32.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Feb 2023 20:32:59 -0800 (PST)
Received: by debian.me (Postfix, from userid 1000)
	id 969D8100FE8; Wed,  1 Mar 2023 11:32:56 +0700 (WIB)
Date: Wed, 1 Mar 2023 11:32:56 +0700
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Linux Documentation <linux-doc@vger.kernel.org>
Subject: Re: [PATCH v2] kcov: improve documentation
Message-ID: <Y/7VeHQBL43MzIPR@debian.me>
References: <583f41c49eef15210fa813e8229730d11427efa7.1677614637.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="MY45FsvfwBPyRUm7"
Content-Disposition: inline
In-Reply-To: <583f41c49eef15210fa813e8229730d11427efa7.1677614637.git.andreyknvl@google.com>
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=JlPP0rfT;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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


--MY45FsvfwBPyRUm7
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Tue, Feb 28, 2023 at 09:04:15PM +0100, andrey.konovalov@linux.dev wrote:
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index d83c9ab49427..4527acfa023d 100644
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
> +Collecting comparison operands is supported with GCC 8+ or with Clang.
>  
> -CONFIG_KCOV requires gcc 6.1.0 or later.
> +To enable KCOV, configure the kernel with::
>  
> -If the comparison operands need to be collected, set::
> +        CONFIG_KCOV=y
> +
> +To enable comparison operands collection, set::
>  
>  	CONFIG_KCOV_ENABLE_COMPARISONS=y
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
>  		perror("ioctl"), exit(1);
>  	/* Reset coverage from the tail of the ioctl() call. */
>  	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
> -	/* That's the target syscal call. */
> +	/* Call the target syscall call. */
>  	read(-1, NULL, 0);
>  	/* Read number of PCs collected. */
>  	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
> @@ -103,7 +111,7 @@ program using kcov:
>  	return 0;
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
>  	return 0;
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
``KCOV_REMOTE_ENABLE``
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

Otherwise LGTM.

Reviewed-by: Bagas Sanjaya <bagasdotme@gmail.com>

Thanks.

-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y/7VeHQBL43MzIPR%40debian.me.

--MY45FsvfwBPyRUm7
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQSSYQ6Cy7oyFNCHrUH2uYlJVVFOowUCY/7VcwAKCRD2uYlJVVFO
o8FUAP9eioDvchn/gsHMWPAWDem8tEFb8ktjTUVtjkrmtUde1AEA/Oe7b7Kxa8gX
2UHhhHntK61QsM/KZVs59oER+djYVAw=
=GJOE
-----END PGP SIGNATURE-----

--MY45FsvfwBPyRUm7--
