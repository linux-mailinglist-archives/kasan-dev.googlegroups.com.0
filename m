Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2VQ2HDAMGQECIC65UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb137.google.com (mail-yx1-xb137.google.com [IPv6:2607:f8b0:4864:20::b137])
	by mail.lfdr.de (Postfix) with ESMTPS id 22246B9C2EC
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 22:45:32 +0200 (CEST)
Received: by mail-yx1-xb137.google.com with SMTP id 956f58d0204a3-632edf1e41dsf210726d50.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:45:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758746731; cv=pass;
        d=google.com; s=arc-20240605;
        b=h80QU7rtHf60IxdJOCEGJ0yBZPPnOcec4FDMhm+/MoQRD0wAJpKNvDHwtu70ofKqPv
         mtzATSWkf2C4wiNMJR0Sx9EossVqNCmuI+XSL4S8xSC6/wDBhCI28OY8KwEkYRriW+lM
         sIth2pOhDeSqotjtF7bMGV7yVy4VnetYk7GrZUL7Wu1ZDRri0u51ol21kBiwaaxrbtWZ
         FFcEUtjLZHtcoL9BPLdfpV2G2ViiW0t9Fv0bTVNzXEiBoGdq6Kfj+z5y/iNC0zIXCx4y
         dJSwtEzCYdwrIh0zS6rhfV8ZglWplgN8VKsE4TVn7Upq0b/GPy3+W8QH+uu40VwR7ghE
         9j7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TCbIO7ABBBrG+cxvZqab37xKHRTaz4YXRUC5Z4HOZMA=;
        fh=cuPJ9HZrYhNpyJZdQp8EWVc7x8baPSSKdzoKuqkTZMw=;
        b=AuKInYmCgCvt/0zC6e/wGQJVtBAy2S0guu2q6gH0sV1So+SEc2YCM/B7NjdA6HfRel
         6ijQZvlAH8cTeZOIGZb+EbheZtY6rbh+Nu6nGveSzFPhyHYk39FTn+vn60Rn6Poc0ehX
         Xy+53K8GguIKZaObSgJ3GmxJEcO6EJZrSkpOgH+g0ZMGpIUW5OH3o4H5N9Qg8xwSKk3o
         PsJD7f/t0rx7yl6xfVx+5q7kPEMonVmbi89OKMlAw5IP/LL/d8Al1kXoYeCDP/0AV4K3
         YpcTjT6KosrC3TR49SCALm6jlG6tmLCrhBP6W1A+jIndcaorTxxTvJwGohUGbiAB0zUe
         EQyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HYvFhvK5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758746731; x=1759351531; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TCbIO7ABBBrG+cxvZqab37xKHRTaz4YXRUC5Z4HOZMA=;
        b=DufHPyeWYpb5KhgzZWwj95N2SJxkow6kUmzEPmW1cemp67oLSme3v3RklrQ/KokUJ2
         OzlXZOLUeIfklPId5URowlVehpclmoyidwXViNdtLO8v8b4nFjZ9zANeFbWwRCnuzPqd
         7SzSb6QZ5HKTnbRSO6sPWDd4RFq8AGAvXUKI72uo1vSdJOWwWgbmFpni/kLGnuU4zp1N
         Jre0wYe6ywvtsaSEZzUJ3QDDGtY2EEBvjph18Iq8+P6/ahv8mUySehho9nYKlJiyJcRK
         Z422hzsimRTH2GLACbMdWfL97Uf6rWb4CeTs/q7eMln6LU33XFUACC+It7HSY7ce8NB6
         7EEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758746731; x=1759351531;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TCbIO7ABBBrG+cxvZqab37xKHRTaz4YXRUC5Z4HOZMA=;
        b=O4svX/dQEewn+248IJ92olhXv6VuEQH41Fq2jEdyraXUEoXzg1fw9s4P54kjCq87s1
         bTN7Tc/W2UMxGAB4CLgLPsfGs9rRwf4MMrxT2goaR2o/9eQP4MOjcf64ymCEE/hKjC8l
         cTS7pYcr1XrUz9psK1A3KI8+7fSfEr8IpMiZeVegKEmHCd4lqDg7mSCckLBB17b7Bp/2
         UrRFs7IBVLOfWaGxuK3R0SavVUr9tQZ18c+x1dYDFRH3nDaR/NyCzXYmBnopFIJU49oJ
         YZhZegLgqys9BFfbryNJ/vljWtXFpgXwzLzPjY2ncjAYGSLKR8E++wIXH2UtFW0N0Qlx
         DriA==
X-Forwarded-Encrypted: i=2; AJvYcCW+7xrsTCPmbqAJWjnjcO6cO8aNtrZvQY+cLmpziPvw+iwzx2b+a6prh1QinDKfp6nktsOX1A==@lfdr.de
X-Gm-Message-State: AOJu0YxsTW91hyBZJ3kWAg+6R0yINvbPiSqgJ4XrFkI2Oe7RywFOoQkI
	A4KZjuoduy6Fo1lBEowYBxVOpu7PhEcbfBZsxAh6xzTOwbxtfnvBx1Sr
X-Google-Smtp-Source: AGHT+IEB20YNSxoBkCv5G2nHRhy8zCRi+9rZG17ZiIDzuP8bxoiOCH6NCxDGfdI600MwkKEc9Ti8Rg==
X-Received: by 2002:a05:690e:ee4:b0:634:76e1:7c5a with SMTP id 956f58d0204a3-6361a7b92b2mr625302d50.30.1758746730688;
        Wed, 24 Sep 2025 13:45:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7wb7zdl6y6RDxn9yA1anos5TXSnkvR3+HcdZ8S+FvX3Q=="
Received: by 2002:a25:a022:0:b0:eb3:57a0:33a6 with SMTP id 3f1490d57ef6-eb3814d5f6cls183601276.1.-pod-prod-07-us;
 Wed, 24 Sep 2025 13:45:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZY652npnLtbf2GRlafRNA0IF2PNmxN7WAv5fTBe7ULPolc7aY/FAHz4BEZ7pCXqRlutfIm+ryIcc=@googlegroups.com
X-Received: by 2002:a05:6902:f87:b0:ead:eaa:52c1 with SMTP id 3f1490d57ef6-eb37fcae0f8mr1291789276.37.1758746729607;
        Wed, 24 Sep 2025 13:45:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758746729; cv=none;
        d=google.com; s=arc-20240605;
        b=S5VqRPGUrPs2UMPYnAn2O94jy55i1Daka9CSTmj88xgie0w4VeWr655XkZDqAq8YAj
         ArD5N8SfJmtLbhp8K29RJEqiv0lyQ/OM9wAk29kKQcnJSQkm3v+q41UqAvyr46p23jEs
         l6N7lqvzMFzOoqc4xP0lflT1zU6U/6kn24n3XiveGNrsJcqCD2otxaVeTbxFYrt4ElPa
         A975T+2QxSItyDNSzIy9lWzoQr3o26pKprHuSGvAy9pQM1/fjj3hlFcY/+Eep+bakjYn
         bxLWxux9O+ZwO5S6fQO/nY1HSRMdi3LYrSIq9+WQzLSUV/6skonXTtjLP3Hzuw6IZFpS
         maKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w1mp7LI1ysXg3EhsS9eEgLmna2zUSv012OjKVUUaPuY=;
        fh=Rq0vSa9UlRnFAH/Z27LAdR1DBBW+M0m3VNxdKLc0q/U=;
        b=DDTHIUQSE1pjA3GW5FzMG0SmVllC0jpjOD6yOH49utNFwDnkVg5NV2Pfz0DwyKL4yf
         O2362z6JGSO0vyKbaVP2mD1gHoPeHXPs2mEFrVmiwSw58mxqAJwrXhgSqrRU/XZVhgX4
         X3ErVZAcBIEvjmCvwNNqmAZ2+kqetABq4oW5WgcVmJzo07Ezikrl6kFFvmQ592HhkMWu
         bP16gl1DjBWNPEZj67IlaWDgTRIYyAt+alCJkm/u7/uojsEt3m57dX8Hmhsbkz6srbqy
         iFE2MSpkPVOsFG7ZWt/QscswJtNs9GsLicTFbGjBeZXqMpWLuSUJhrKTlIaaxOYpKKxU
         dTqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HYvFhvK5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-eb38390f59esi1612276.3.2025.09.24.13.45.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 13:45:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-77f3405c38aso325429b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 13:45:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUYjN7wVF9PlalJWhHdcMm+GynLknyjd0KcoJfke0L0k4FieSTw/R+zakX3++ylZMMrhkXjTVptafM=@googlegroups.com
X-Gm-Gg: ASbGncuL5BBNswTpZHBjNL9gLHtHkLVaAqJT/9/KFscILTtkow16iljtI8NCOJ2nb4/
	pr6xCDDxe+kN5UUMu2f6xVTgsoCNMz6lZdKh64AEgym6KGa7xj8vdMC9pDP8d4l4QTxrXTJN8qX
	tTrCAcufEaL1doYTKzutbHZOLpeP5jVRNiuYVTHlmFrF16i83ZlT8FKPDZal9QJW/fDnZXQqlr4
	lYVE9ApsdOzcmbToAVeLRnTrOldiX3e/t8G9hSALVCVDiX6P3Yj2sg=
X-Received: by 2002:a17:90b:2249:b0:32e:9da9:3e6c with SMTP id
 98e67ed59e1d1-3342a2f9230mr918488a91.23.1758746727946; Wed, 24 Sep 2025
 13:45:27 -0700 (PDT)
MIME-Version: 1.0
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com> <20250924115931.197077-2-wangjinchao600@gmail.com>
In-Reply-To: <20250924115931.197077-2-wangjinchao600@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Sep 2025 22:44:50 +0200
X-Gm-Features: AS18NWALn8StkZt7OAMLGvWBoEjnvi0uixTT5lbJc-ZUHb99wQUtu6-AQu7N2zA
Message-ID: <CANpmjNNnVx3=dQsoHL+T-95Z_iprCd3FXeYpnHdmi4d06X-x_g@mail.gmail.com>
Subject: Re: [PATCH v5 17/23] mm/ksw: add test module
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Randy Dunlap <rdunlap@infradead.org>, 
	Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, 
	Valentin Schneider <vschneid@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Ian Rogers <irogers@google.com>, Adrian Hunter <adrian.hunter@intel.com>, 
	"Liang, Kan" <kan.liang@linux.intel.com>, David Hildenbrand <david@redhat.com>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Alice Ryhl <aliceryhl@google.com>, Sami Tolvanen <samitolvanen@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, Rong Xu <xur@google.com>, 
	Naveen N Rao <naveen@kernel.org>, David Kaplan <david.kaplan@amd.com>, 
	Andrii Nakryiko <andrii@kernel.org>, Jinjie Ruan <ruanjinjie@huawei.com>, 
	Nam Cao <namcao@linutronix.de>, workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org, 
	linux-mm@kvack.org, llvm@lists.linux.dev, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, linux-trace-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HYvFhvK5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::431 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 24 Sept 2025 at 14:00, Jinchao Wang <wangjinchao600@gmail.com> wrote:
>
> Introduce a separate test module to validate functionality in controlled
> scenarios.
>
> The module provides a proc interface (/proc/kstackwatch_test) that allows
> triggering specific test cases via simple commands:
>
>   echo test0 > /proc/kstackwatch_test

This should not be in /proc/ - if anything, it should go into debugfs.

> Test module is built with optimizations disabled to ensure predictable
> behavior.
>
> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---
>  mm/Kconfig.debug        |  10 ++++
>  mm/kstackwatch/Makefile |   6 ++
>  mm/kstackwatch/test.c   | 122 ++++++++++++++++++++++++++++++++++++++++
>  3 files changed, 138 insertions(+)
>  create mode 100644 mm/kstackwatch/test.c
>
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index 89be351c0be5..291dd8a78b98 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -317,3 +317,13 @@ config KSTACK_WATCH
>           A lightweight real-time debugging tool to detect stack corrupting.
>
>           If unsure, say N.
> +
> +config KSTACK_WATCH_TEST
> +       tristate "KStackWatch Test Module"
> +       depends on KSTACK_WATCH
> +       help
> +         This module provides controlled stack corruption scenarios to verify
> +         the functionality of KStackWatch. It is useful for development and
> +         validation of KStackWatch mechanism.
> +
> +         If unsure, say N.
> diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
> index 84a46cb9a766..d007b8dcd1c6 100644
> --- a/mm/kstackwatch/Makefile
> +++ b/mm/kstackwatch/Makefile
> @@ -1,2 +1,8 @@
>  obj-$(CONFIG_KSTACK_WATCH)     += kstackwatch.o
>  kstackwatch-y := kernel.o stack.o watch.o
> +
> +obj-$(CONFIG_KSTACK_WATCH_TEST)        += kstackwatch_test.o
> +kstackwatch_test-y := test.o
> +CFLAGS_test.o := -fno-inline \
> +               -fno-optimize-sibling-calls \
> +               -fno-pic -fno-pie -O0 -Og
> diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
> new file mode 100644
> index 000000000000..1ed98931cc51
> --- /dev/null
> +++ b/mm/kstackwatch/test.c
> @@ -0,0 +1,122 @@
> +// SPDX-License-Identifier: GPL-2.0
> +#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> +
> +#include <linux/delay.h>
> +#include <linux/kthread.h>
> +#include <linux/list.h>
> +#include <linux/module.h>
> +#include <linux/prandom.h>
> +#include <linux/printk.h>
> +#include <linux/proc_fs.h>
> +#include <linux/random.h>
> +#include <linux/spinlock.h>
> +#include <linux/string.h>
> +#include <linux/uaccess.h>
> +
> +#include "kstackwatch.h"
> +
> +static struct proc_dir_entry *test_proc;
> +
> +#define BUFFER_SIZE 16
> +#define MAX_DEPTH 6
> +
> +struct work_node {
> +       ulong *ptr;
> +       struct completion done;
> +       struct list_head list;
> +};
> +
> +static DECLARE_COMPLETION(work_res);
> +static DEFINE_MUTEX(work_mutex);
> +static LIST_HEAD(work_list);
> +
> +static void test_watch_fire(void)
> +{
> +       u64 buffer[BUFFER_SIZE] = { 0 };
> +
> +       pr_info("entry of %s\n", __func__);
> +       ksw_watch_show();
> +       ksw_watch_fire();
> +       pr_info("buf[0]:%lld\n", buffer[0]);
> +
> +       barrier_data(buffer);
> +       pr_info("exit of %s\n", __func__);
> +}
> +
> +
> +static ssize_t test_proc_write(struct file *file, const char __user *buffer,
> +                              size_t count, loff_t *pos)
> +{
> +       char cmd[256];
> +       int test_num;
> +
> +       if (count >= sizeof(cmd))
> +               return -EINVAL;
> +
> +       if (copy_from_user(cmd, buffer, count))
> +               return -EFAULT;
> +
> +       cmd[count] = '\0';
> +       strim(cmd);
> +
> +       pr_info("received command: %s\n", cmd);
> +
> +       if (sscanf(cmd, "test%d", &test_num) == 1) {
> +               switch (test_num) {
> +               case 0:
> +                       test_watch_fire();
> +                       break;
> +               default:
> +                       pr_err("Unknown test number %d\n", test_num);
> +                       return -EINVAL;
> +               }
> +       } else {
> +               pr_err("invalid command format. Use 'testN'.\n");
> +               return -EINVAL;
> +       }
> +
> +       return count;
> +}
> +
> +static ssize_t test_proc_read(struct file *file, char __user *buffer,
> +                             size_t count, loff_t *pos)
> +{
> +       static const char usage[] = "KStackWatch Simplified Test Module\n"
> +                                   "============ usage ==============\n"
> +                                   "Usage:\n"
> +                                   "echo test{i} > /proc/kstackwatch_test\n"
> +                                   " test0 - test watch fire\n";
> +
> +       return simple_read_from_buffer(buffer, count, pos, usage,
> +                                      strlen(usage));
> +}
> +
> +static const struct proc_ops test_proc_ops = {
> +       .proc_read = test_proc_read,
> +       .proc_write = test_proc_write,
> +};
> +
> +static int __init kstackwatch_test_init(void)
> +{
> +       test_proc = proc_create("kstackwatch_test", 0600, NULL, &test_proc_ops);
> +       if (!test_proc) {
> +               pr_err("Failed to create proc entry\n");
> +               return -ENOMEM;
> +       }
> +       pr_info("module loaded\n");
> +       return 0;
> +}
> +
> +static void __exit kstackwatch_test_exit(void)
> +{
> +       if (test_proc)
> +               remove_proc_entry("kstackwatch_test", NULL);
> +       pr_info("module unloaded\n");
> +}
> +
> +module_init(kstackwatch_test_init);
> +module_exit(kstackwatch_test_exit);
> +
> +MODULE_AUTHOR("Jinchao Wang");
> +MODULE_DESCRIPTION("Simple KStackWatch Test Module");
> +MODULE_LICENSE("GPL");
> --
> 2.43.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-2-wangjinchao600%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNnVx3%3DdQsoHL%2BT-95Z_iprCd3FXeYpnHdmi4d06X-x_g%40mail.gmail.com.
