Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJXSWKTAMGQEV6G2YXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 37CBF76FC19
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 10:39:04 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4fe275023d4sf1866173e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 01:39:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691138343; cv=pass;
        d=google.com; s=arc-20160816;
        b=XkKPIZ/Lz4AQWeHscaGegPDIaddY/MrJWlInXa/7pAl9f0SVTYso8/j3GHAOKmDYz1
         2Rwm278Cuw+HCoRJSdbAZ4xr7uA31UANPerjlHhMyjSnI6/xdNqTKlIfntK9iR59b4ap
         YctEQCIUPbYE+wDz/JsFUtHXq1unlaet4C8BOeD3WeU/s2NQ0//d2WcNvu0+Ozi9Fyz9
         kvytklNMAJDAGWPj9HspPLg/jLlb+zwLbgUvD9U6jedb2zMtLs0zYwEXQFHWFhtVQ/Oa
         L6uRXuznkZ+TQDHBj13Si724bBlB0uFbcjuO4tiDLaybkUaYnw/nPcOQAe84DGgDFdN3
         7mfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oRY8pTcjLoezdj5LsOeo12PkIRjDLR97VSsIrqrMtwA=;
        fh=vBnbiWWE5J32xErlpv4Tfv+f3srTk71IWb3k/O49hfY=;
        b=M8RGiFv5AnKs/Z41tKTW0l4Uelr0Z8l3GDJYMgG1nBou6/sjvDRj51c0UpGBPCiMbs
         bIPYDijKJi5/45E0wNe8SDKv8qt2yCCZBfBEEOgtcAfqqkj1/GrPxvWlo9idtgeDWW0c
         1mr3QwH96m2lF/QoSz7Qjza3NOz9tG263Uf/4RfUwpD5ZhpCCIzdefXwZpNTJnSnQ5bI
         x4C6p4hUknfm3F3sarTTbaGJvHZ7WQQsZuqt8I1Mt9CPogE1RkVeHjiMqIqedHK4+jBr
         qrq+LdU34dAc72c1AsatJyOVoy0nn3r8rYssOTx2aGy9zrQbBfPXUMU/2pWDvHkZ+vBy
         GdDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4wbtWBqY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691138343; x=1691743143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oRY8pTcjLoezdj5LsOeo12PkIRjDLR97VSsIrqrMtwA=;
        b=fJAiGsOc3Phf+ZCofQewXCRVqgIft3TgjH2x8CNnKeu1+TLAQu6T/cpFZSkl2ciQRi
         InrHFOG8zWbMzIax1FasoQa97Iyl0OxXQ+SwjkLHxk8UmhgAxjIybfTmRI0FuMkQDMBp
         QhkQxPRA/VJP+kyoWDTqY0eteLXbKf7uSlJuJvD55A5QxhXiu/Y0H5oUlN0nmP+umgBi
         zTTx15ueQ3+sA+UvBPuoXLg6D42cwOnbLh/Mu9JNtDTcC0r0ibsXuKM4OGJl4V9eB+yX
         rnDJT73N1aLFzG5XIqiFIBL0XFf5sTuHHi4zcmG/lPhE/0wdW+VLXgLHKhsD8Wp696lS
         jy9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691138343; x=1691743143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oRY8pTcjLoezdj5LsOeo12PkIRjDLR97VSsIrqrMtwA=;
        b=WXbH8SfgO1+B6QxVA3F0Rwfba7Ij0b7kuXjgSY1B6DG3mq8nDTFfWP5khWfxkb70Mx
         hOA6DqkpJIYkWhoRqZmGL7Q524t70Q+1Lg1wSblWBkzIibldpam5ETcdfK7ekxXEmLPt
         O8BcHkmKRhH517IlQXx3YpCQgsEkitFc+0vcLtBRBUl1K6u0yQ3+/u+RB5KU4/hUoFjt
         HvRZyyune0YNP3n8u3Vio1De5GYkB/GO7TkMfZen3LiMWMbmaJRvbYf8ByFpHlxTI6v4
         5UzgBEBo7MAh7r7F/cbx8KHwUyYu4X4xf/dylGnnHmTAi6VeJgoJdMRbIpjsNv0uv+eF
         GM6g==
X-Gm-Message-State: AOJu0YwZTtWHP9R7VnMqR9/FsDM7EdVblqIovZt7kQvVlSekJqMH8J4V
	uvIo90TSMgjY77Vdojwez70=
X-Google-Smtp-Source: AGHT+IEAVqwd6+IiMm5j7RBwKDwRWMBTH2rpc/Z2tEkus9sHqqrnDraxONRzf9+jm2KGrCWMqd3C9g==
X-Received: by 2002:ac2:4db8:0:b0:4fb:8b2a:5e09 with SMTP id h24-20020ac24db8000000b004fb8b2a5e09mr810564lfe.43.1691138342768;
        Fri, 04 Aug 2023 01:39:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6517:0:b0:4fa:718c:85b0 with SMTP id z23-20020a196517000000b004fa718c85b0ls1160198lfb.2.-pod-prod-06-eu;
 Fri, 04 Aug 2023 01:39:00 -0700 (PDT)
X-Received: by 2002:a2e:8ec7:0:b0:2b9:dfd1:3803 with SMTP id e7-20020a2e8ec7000000b002b9dfd13803mr897743ljl.30.1691138340385;
        Fri, 04 Aug 2023 01:39:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691138340; cv=none;
        d=google.com; s=arc-20160816;
        b=nWvAzZ6h334id5Jd8ARK5lRnYoEl2fKMxyizYj6rHgs6cSNUIgZ0X8esohxyjyQ/EO
         DAQFVLFS5e7TvnjCFwtAzx7jeXhGFztdyG5wQk9hLRC2RA1rBe4d6aKxuzW/lihwW3Vn
         1vT6pb/FNsmsCi06FwWCBUAjkhQoBPr3g2w2FHccMf6WMUwR1d/SZ4cAdZBRKLuh4LGK
         8OooWgBWHzYUhAcXcFHNMslsOdR01zGm7xIvBFCg/1WwErvjraiU5+zd15f8tFLN0mNQ
         W5H0H2xt1CAkOhLI7McoiLl3X4r7VR5ns+fltEMkSfHcn3FMG25IJg6AJ24j9Rhyn1TY
         wbsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jQoJf42Fd/g+GKy4ubOkk+li/mbuiTLSPOgxMQ9ZBj4=;
        fh=ahrhZVISO1jYveklmU/89wijxTnW9d78RPzA3SY9Ywk=;
        b=V5zliRnjK/k7veiBg2E7ApgHLvn3M+4NKVsBJD8f4CWUHhzx5xkmw7e9Sm6k8l3K7y
         X++txnA6jJupFLSfpUk/yK9y6QEByn+JEhy00iWquVzYbvrHNEKI7WOigp9l0B3DYlnk
         qHVDg3ffsXaf7zB8L8W3hWn85UDGF9hIiDQ0ii7jM/dtVF1B8m5M6aZBbs2qj83zY82s
         mH9N3Ct7CpacWQkOZMMOSUxKbtL1uRQLIu9aPQcMrZCQAypww4LXUNsIyHemeqEpWcPT
         jYn3MKcbjSDlH3V5e+cLDsVh6IDOiGwM6zYnnca5EPBUH+8ScOHAdXAUMYua5F9V1zfV
         fFww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4wbtWBqY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id a32-20020a2ebaa0000000b002b98ad21968si150968ljf.5.2023.08.04.01.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 01:39:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-3fbea14700bso17939495e9.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 01:39:00 -0700 (PDT)
X-Received: by 2002:a1c:4c13:0:b0:3fe:485f:ed1b with SMTP id
 z19-20020a1c4c13000000b003fe485fed1bmr897546wmf.28.1691138339742; Fri, 04 Aug
 2023 01:38:59 -0700 (PDT)
MIME-Version: 1.0
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com> <20230804082619.61833-2-andriy.shevchenko@linux.intel.com>
In-Reply-To: <20230804082619.61833-2-andriy.shevchenko@linux.intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Aug 2023 10:38:22 +0200
Message-ID: <CANpmjNO5p5shpVoo1BLi9QzBc0Q0TSdfz-tUCrtgQj_ogHKx5w@mail.gmail.com>
Subject: Re: [PATCH v1 1/4] lib/vsprintf: Declare no_hash_pointers in a local header
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Rasmus Villemoes <linux@rasmusvillemoes.dk>, Sergey Senozhatsky <senozhatsky@chromium.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=4wbtWBqY;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Fri, 4 Aug 2023 at 10:26, Andy Shevchenko
<andriy.shevchenko@linux.intel.com> wrote:
>
> Sparse is not happy to see non-static variable without declaration:
> lib/vsprintf.c:61:6: warning: symbol 'no_hash_pointers' was not declared. Should it be static?
>
> Declare respective variable in the local header.
>
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> ---
>  lib/test_printf.c  | 4 ++--
>  lib/vsprintf.c     | 1 +
>  lib/vsprintf.h     | 7 +++++++
>  mm/kfence/report.c | 3 +--
>  4 files changed, 11 insertions(+), 4 deletions(-)
>  create mode 100644 lib/vsprintf.h
>
> diff --git a/lib/test_printf.c b/lib/test_printf.c
> index 7677ebccf3c3..9e04b5f7244a 100644
> --- a/lib/test_printf.c
> +++ b/lib/test_printf.c
> @@ -24,6 +24,8 @@
>
>  #include <linux/property.h>
>
> +#include "vsprintf.h"
> +
>  #include "../tools/testing/selftests/kselftest_module.h"
>
>  #define BUF_SIZE 256
> @@ -41,8 +43,6 @@ KSTM_MODULE_GLOBALS();
>  static char *test_buffer __initdata;
>  static char *alloced_buffer __initdata;
>
> -extern bool no_hash_pointers;
> -
>  static int __printf(4, 0) __init
>  do_test(int bufsize, const char *expect, int elen,
>         const char *fmt, va_list ap)
> diff --git a/lib/vsprintf.c b/lib/vsprintf.c
> index 40f560959b16..6774cf84e623 100644
> --- a/lib/vsprintf.c
> +++ b/lib/vsprintf.c
> @@ -54,6 +54,7 @@
>
>  #include <linux/string_helpers.h>
>  #include "kstrtox.h"
> +#include "vsprintf.h"
>
>  /* Disable pointer hashing if requested */
>  bool no_hash_pointers __ro_after_init;
> diff --git a/lib/vsprintf.h b/lib/vsprintf.h
> new file mode 100644
> index 000000000000..ddffde905824
> --- /dev/null
> +++ b/lib/vsprintf.h
> @@ -0,0 +1,7 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef _LIB_VSPRINTF_H
> +#define _LIB_VSPRINTF_H
> +
> +extern bool no_hash_pointers;
> +
> +#endif

It seems odd to create such a local header and then refer to it from
other subsystems.

What's the downside of just putting this into the new
include/linux/sprintf.h? If someone wants to access this variable,
they will one way or another.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO5p5shpVoo1BLi9QzBc0Q0TSdfz-tUCrtgQj_ogHKx5w%40mail.gmail.com.
