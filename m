Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4HV2BAMGQETP62JXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id EB80C3390BE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:06:47 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id b14sf9876041ljf.22
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:06:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561607; cv=pass;
        d=google.com; s=arc-20160816;
        b=RHVzWxoW/PTMPLGSIrGG4nPwfus9bSWv9NdfzTWQw8iJEkoratRcC1ZRcDxetXzAXt
         Py8KikeOeuI++RWLaiwmYTq1vbSUQiDE0JWNqzMiKGFDTKNyG76EarK5Gj97h+KZJnbo
         YtWRvTELDsjs8+e3pmSyGHbcg+mxLAZhOTnJcOfRrwW0zyV0pz11+ZAdC9NeOW/SCLA/
         NXmqwVoOvChLTXAKjc/BFTcuuHRf7CUO290ZKNklehipDGmym3so1rtCkaK6OFYLxIiE
         OVf9UcHooC5Iwh9J/jF3F9olzMR8qfNZ5KLd2B+9xrBh9RnnnNNXl0B6hmHXL9Smr42c
         jMJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OcxjYfHwru6O3fqTN0nmjT4cmt0/O0JzCBT0VBHqIpk=;
        b=bnWHbHOpeSROFuObtuXbaXV6cKREDfGMhcM4x0g+gajFTzfBbbsnE/Yj1/C7qDnC9d
         2MDvPgH9mP6x2ETsRWuNd6huw1C0m5WV2tZZMnTgkB6746m/HLgTTDkMvapEUM5QgiiV
         C7zRaMz++NX0pry7NGoYEZdbOzH8jZafhu0FJ10EcS03PrdXAMBzCOzLQRy755brw4t1
         gRnz99LUPgWwPjvYs+hytGS/9oAnEzL0fgBk+eL3Zalylg2VvBbdojRNw3rtDURudzA9
         4Rt0D9lGTG38MySWp3cxFU24uB6Kfgz6+bSsvk9YQDJpcXvXLzJ8keyf6tzcihcOLF33
         07JA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l0terJNx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OcxjYfHwru6O3fqTN0nmjT4cmt0/O0JzCBT0VBHqIpk=;
        b=HFcttnTER22WBFA85qiJ+NeTSNP6EJkn5P4eau41IUMI9DcAiJpmFojA9nD6d+vDO7
         A5wjeRop4l8QHvkd8UQ6Gd9zHmQAri3WAEODCspZ5CiVefQCi+Im4Nt3oAAuT4+Qs+oY
         85vi/WJbDCuPrtU3N+2gHXO1AJJJaiavURCU5JkrhZbDZ563lE6yifS3PCbFh2k9uqlp
         fFOSWlIMql2lGRrE1YsY3XOtbzTlMNRJJvAJj9X4TxranqNxbe72eZxRgehUgkb4JEoV
         DNoXrTOO/UUbdON4mE3fiyfXStmK/REB/GOdNcvv2v9vBSFfZ7wJ5Kely5vVqX45Ys64
         AulA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OcxjYfHwru6O3fqTN0nmjT4cmt0/O0JzCBT0VBHqIpk=;
        b=NP+k0el6g1ZQSUB2c7Jb17g4WYo91RsBGUpS7Fov1piIKajwLElFMmYlJJ21TvfwO0
         OjbAhOzYswzg+1a6YqM6VxBrUzQf6Jq+MXeGinH7aI5qNMqYsN4urIqNGJLZKr5AFQnQ
         xWiZZUk8ZU+5f1oz0n43+eIRcQYvuKHVS2TBrtSXwHedYVnaGfw0C5X2FJ1omK1UWFJW
         W0LoAeRYAj0V6ntZUp/i8BwvJqOSJ468Da078bYGg0DkLgovFRMa4DqRigHN5UQPw0wU
         3fUInDlf22CkKCnud5ZVeUXq/jx1tDwHIzEY/MxQXIxzccvywOQn1MZCCtRrjXkr3oxY
         n6hA==
X-Gm-Message-State: AOAM5307BLhYSyy2zNGk/rrh4PDCcENstZdefO+RPMGOQbQcozveHZzn
	KNyhQxStuc2eqxzxT6/D+xI=
X-Google-Smtp-Source: ABdhPJxiAolMYnXIZWyIV6f6xL+zb6iHnTi9thh4D2PYbyByYhZkzi1DlEIibEf3WH0kbX1ga2NKpw==
X-Received: by 2002:a2e:8e70:: with SMTP id t16mr2688088ljk.489.1615561607504;
        Fri, 12 Mar 2021 07:06:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:391a:: with SMTP id g26ls2015451lja.4.gmail; Fri, 12 Mar
 2021 07:06:46 -0800 (PST)
X-Received: by 2002:a05:651c:1214:: with SMTP id i20mr2647826lja.423.1615561606178;
        Fri, 12 Mar 2021 07:06:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561606; cv=none;
        d=google.com; s=arc-20160816;
        b=u5TFD0GHtSWDR++EYgC9BfY8W1hiEPqgNmUU/wkU+NhKA7FTblI/iQbl9Onag+Irji
         YnjgSf3Fi8U+GJZWXBkAs8eR3S4isHGZpdHIgoYvhRiluCabYZEiMMyZqs25pLurSbW/
         RIevU3MXP6RvCRzKiKs8sWuXMvMqjD2qk6nTtJPb5LWziNFhFFrZKbnax3Sw3TxyotzS
         +XAYPX0V10lFjECgdXmH/6rP8KPTwXz1ExuApr9QrfeNQ3Khgr/Lbtjb1M4g0gX53gRC
         VcaDpmrWIY6X7plR6AX7HLw30yXPPpPeh1OQsrDzdo1ZGEo5wp1THbzE04c9031iqIh0
         P0Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qBFp/gtR/nkmpiy/tuP54xC4mkMnllk9WWHQ5y9bp+8=;
        b=tygjtQpPdkZNfHJudI2Lnou02/WZ40YpVIoEEydaJfystMWPgE0uzf39Dlha+bKF1E
         EzOKUwyX4WDQyPwTugt6xoAibJfx0ZOoYPqbmTffT829sHbUbuaf3RKZPiG4QiqzDCKo
         Nviy9nol92YZll0r0OcLBG725vGUDj23gRHuBi6kBB8mzQxrYh0fmGC02H0KLlV3v+BB
         xpZKZzMFjYkOZVZuOKeEwJoqjtRstJT4QGIQagF1TKB/Y74/xYWEZh98VoBjUl/38Bfn
         ZWgZf+imd95Rt7/4eMZnuTw1arU0c7n4+A2XqpDOgj06JgQCE3zpTs9ZcOHi7nKUFOAV
         ROhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l0terJNx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id p18si229244lji.8.2021.03.12.07.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:06:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id b9so1966033wrt.8
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:06:46 -0800 (PST)
X-Received: by 2002:a5d:65cd:: with SMTP id e13mr14714985wrw.334.1615561601007;
        Fri, 12 Mar 2021 07:06:41 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id d7sm7830010wrs.42.2021.03.12.07.06.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:06:40 -0800 (PST)
Date: Fri, 12 Mar 2021 16:06:34 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 01/11] kasan: docs: clean up sections
Message-ID: <YEuDevgROKlHyCvB@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l0terJNx;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Mar 12, 2021 at 03:24PM +0100, Andrey Konovalov wrote:
> Update KASAN documentation:
> 
> - Give some sections clearer names.
> - Remove unneeded subsections in the "Tests" section.
> - Move the "For developers" section and split into subsections.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> 
> Changes v1->v2:
> - Rename "By default" section to "Default behaviour".
> ---
>  Documentation/dev-tools/kasan.rst | 54 +++++++++++++++----------------
>  1 file changed, 27 insertions(+), 27 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index ddf4239a5890..b3b2c517db55 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -168,24 +168,6 @@ particular KASAN features.
>    report or also panic the kernel (default: ``report``). Note, that tag
>    checking gets disabled after the first reported bug.
>  
> -For developers
> -~~~~~~~~~~~~~~
> -
> -Software KASAN modes use compiler instrumentation to insert validity checks.
> -Such instrumentation might be incompatible with some part of the kernel, and
> -therefore needs to be disabled. To disable instrumentation for specific files
> -or directories, add a line similar to the following to the respective kernel
> -Makefile:
> -
> -- For a single file (e.g. main.o)::
> -
> -    KASAN_SANITIZE_main.o := n
> -
> -- For all files in one directory::
> -
> -    KASAN_SANITIZE := n
> -
> -
>  Implementation details
>  ----------------------
>  
> @@ -299,8 +281,8 @@ support MTE (but supports TBI).
>  Hardware tag-based KASAN only reports the first found bug. After that MTE tag
>  checking gets disabled.
>  
> -What memory accesses are sanitised by KASAN?
> ---------------------------------------------
> +Shadow memory
> +-------------
>  
>  The kernel maps memory in a number of different parts of the address
>  space. This poses something of a problem for KASAN, which requires
> @@ -311,8 +293,8 @@ The range of kernel virtual addresses is large: there is not enough
>  real memory to support a real shadow region for every address that
>  could be accessed by the kernel.
>  
> -By default
> -~~~~~~~~~~
> +Default behaviour
> +~~~~~~~~~~~~~~~~~
>  
>  By default, architectures only map real memory over the shadow region
>  for the linear mapping (and potentially other small areas). For all
> @@ -362,8 +344,29 @@ unmapped. This will require changes in arch-specific code.
>  This allows ``VMAP_STACK`` support on x86, and can simplify support of
>  architectures that do not have a fixed module region.
>  
> -CONFIG_KASAN_KUNIT_TEST and CONFIG_KASAN_MODULE_TEST
> -----------------------------------------------------
> +For developers
> +--------------
> +
> +Ignoring accesses
> +~~~~~~~~~~~~~~~~~
> +
> +Software KASAN modes use compiler instrumentation to insert validity checks.
> +Such instrumentation might be incompatible with some part of the kernel, and
> +therefore needs to be disabled. To disable instrumentation for specific files
> +or directories, add a line similar to the following to the respective kernel
> +Makefile:
> +
> +- For a single file (e.g. main.o)::
> +
> +    KASAN_SANITIZE_main.o := n
> +
> +- For all files in one directory::
> +
> +    KASAN_SANITIZE := n
> +
> +
> +Tests
> +~~~~~
>  
>  KASAN tests consist of two parts:
>  
> @@ -409,21 +412,18 @@ Or, if one of the tests failed::
>  There are a few ways to run KUnit-compatible KASAN tests.
>  
>  1. Loadable module
> -~~~~~~~~~~~~~~~~~~
>  
>  With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
>  a loadable module and run on any architecture that supports KASAN by loading
>  the module with insmod or modprobe. The module is called ``test_kasan``.
>  
>  2. Built-In
> -~~~~~~~~~~~
>  
>  With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
>  on any architecure that supports KASAN. These and any other KUnit tests enabled
>  will run and print the results at boot as a late-init call.
>  
>  3. Using kunit_tool
> -~~~~~~~~~~~~~~~~~~~
>  
>  With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it's also
>  possible use ``kunit_tool`` to see the results of these and other KUnit tests
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuDevgROKlHyCvB%40elver.google.com.
