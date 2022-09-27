Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYW5ZSMQMGQEZPDO2JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BE885ECA8E
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 19:12:04 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-34558a60c39sf97047727b3.16
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664298723; cv=pass;
        d=google.com; s=arc-20160816;
        b=DiGhC7zkGvkv6RCd4Oe7lQF8yNe32sz0uo7QYpfBQU8Evyg+qx08trlp1DGibabv/7
         btgSdXS84By/uU5d0NCMbeUbMLF9MVxdXftYip9b59I37BAbeKREwUgNxu/qsP0WDUbj
         +htFBKpUjdUq12eklIgEkKqz2H8wruNec4pOJawwIV6okWzkviYNkRBO4bzKDi3W8zxd
         VOVxHIEY0lfTAonAdTzVhacADGqFkSXPKi7Poja/RGKW/vtSJ9tWGswLC7zPtd7n21N6
         tHII6vf9+HUzjc+suEaPIXkjSstfAJBHs9zDe6Dzgcw1bs98jvkp7km2RLeg/HGopEk1
         BazA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=b7JbGchZ7HL1gnFqRCR0ypglNDv0AKQrmB15GA8QWYs=;
        b=QWsMmdAoVQVtR67W5GyghH7TkAagDRu30a9F2/LJKupaYdniiP1CLLNFn5lw8kfVgx
         5Z/l+X1iINc4Bt8eRKCGKTGFMZVzWNrgXtlPuIBmwmAXWN7cUyx0JaSvhUsrkHraX1Xs
         lJZoIoCJOQMNNsj6SKsMjxch85GSoQl4vetiHe0d2pIMqRhO93CmAfq/0e6CCUi+DO4N
         Nffx8nTIuVoyW0gqPbmKSDjhZ59x0UWJXfXJYJ11iZjOVVmKn0vqaQsaXFqh9xgfp3nQ
         OuOfZF8TVqmefsQ03w1fxBFSD5alRzhKQ0FUhEKtbvZiRR64KKYyQUGKjXcnh+yym0hB
         w6ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="b0Ze/1uY";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=b7JbGchZ7HL1gnFqRCR0ypglNDv0AKQrmB15GA8QWYs=;
        b=PdN7n3kXqksvWZ7WpzNLyf30iZ7n9kX+BClaLYQaO3hB5RUCfDAecknIfewi80ryDe
         T2hPRs+R4fTs2yjL0efZZnC0R69Zl7wNy36zHAVz3BlGouLsLDFMhONV1qZ7veZDyxxI
         Pnz+qz3Wz5ze4hTiuKODntThscidlU7EQwr4eeVXCUjpMv2CGgThsB5K5qvW8xL8zJvb
         8ROPGu9yvakPy/MyuC7CkFj+Auz8sAgQJcIjzp+ylBFZFUMTfIIpShdlYppx+nyNljYr
         IEfDJqW+LyVl39WWv1LM+pDITZHbOenj0yOT+devBaCgVkGE/CHl/Hyfh1i3ad92PLCE
         wzMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=b7JbGchZ7HL1gnFqRCR0ypglNDv0AKQrmB15GA8QWYs=;
        b=ckgzO6f2Ojrz88IGu9qomBsPbpckPHr5oznDfVCVxiazOgKWePAc/ChCLhk0AoS2BX
         iWOaZEIHGScrUuiglZfSUYJ+Z3qWrBqykkuS/TVXxb7w8A+yvkErXV48whO9b0hVSiCy
         O8viLIv38Dp7G0AC2plmfBgslVrSRtiFOZl7v6uCw58Ze/PT9VqopCTnfXXyI5e3Ql10
         m05Qmu1MGwdTxTNcQVPVcUhIHH7DQEUD1kNxjuia6dXZafisWzuhfiVO4ketAjiSmAno
         aXEHdVRHL3D/Y1bkN4n7CVYsM+dBnVbMmDFabEaQfYrB+Mov07vDI16Px61Cg81oybfA
         ry6w==
X-Gm-Message-State: ACrzQf1qsEOEqufbRNcjt4ri+N3cIk3i58iHmcpSxEfW3VHUnWBXgU+4
	QwweBG9MKOk9gxwyXXSQWAo=
X-Google-Smtp-Source: AMsMyM7hkmO48L0deQYywAfSrpA6fg+HrlyddPvLiRouijA+UH0wDNAEWXrX/6+oSDq/gKlSxwYIPg==
X-Received: by 2002:a25:40d0:0:b0:6ae:f1e1:ac88 with SMTP id n199-20020a2540d0000000b006aef1e1ac88mr27565096yba.490.1664298722810;
        Tue, 27 Sep 2022 10:12:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ce44:0:b0:6b0:b7:747a with SMTP id x65-20020a25ce44000000b006b000b7747als1912310ybe.2.-pod-prod-gmail;
 Tue, 27 Sep 2022 10:12:02 -0700 (PDT)
X-Received: by 2002:a25:320d:0:b0:6ae:c230:c50b with SMTP id y13-20020a25320d000000b006aec230c50bmr27511682yby.511.1664298722179;
        Tue, 27 Sep 2022 10:12:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664298722; cv=none;
        d=google.com; s=arc-20160816;
        b=j6KY2s/hWXnhHs+EP2Dv4fFfhJYLoYemzs1emUp6AjnoRz7dN8I2/y/Wkdt2wvYZJ2
         WuIXcIh9bBPauZ2XeQgk9x5mSOjWuT6VBCc+Kgt6Wnod9doCf4OagNIQa+zSWYyW7U2k
         wtBmIZVa++iYRjQiLvFtcMjWEfQL3oklUZzDOJamhkYwhZCIzJ3bWWH9g/l6X8lBYw+F
         ZxF7TRER00ycyg4aOFfJZHg+afBmOIDeRw9VXJhfS2iYKwY6X8+e1lx8cgm2uXJAPofb
         q/TsTwmMesPD95agkoSPeq5x1FJULksNXUo7iZHy301QIRoI2BqHghOKwGhikA++0Z1D
         HLrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EOArjIky/AkNPpcTEcaVfnMEqn6weqGC+GRvG7ybtic=;
        b=OX7vT60e/WW/meiotXfuTdYvTtiWeKwJtCl+DmB8NgCyzXV2FfYLU/9QReq1n3HzJC
         lMjavb5OH8gPYWsDSaD/5JuhMhFk/Wg0+0h+3IrG3YvtiwWMZjvQX6kvfM2KevgDnU0n
         AekdQSm5r5vGDfcQcbEXDqDCw+dUXPhqdzsi7GQGw2dApMNqKGQ2m3dTkCIZopCohMIv
         Cq6vUqaKZzBAHiPuhZLbq+HlkZYi0/XKtsJ3iE4tX6ppYJp2LbaWeMobfGwQGPb58gMB
         p3JnejWTwPE8u10VL75eeoRVZJ1NUb0wnlr5qzgYcspE88neS6cqurycAXJEDGMBJVU3
         /5KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="b0Ze/1uY";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id bf26-20020a05690c029a00b003527e25fd3dsi58547ywb.2.2022.09.27.10.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 10:12:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 65so5521676ybp.6
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 10:12:02 -0700 (PDT)
X-Received: by 2002:a25:c74b:0:b0:6b4:8d79:ee67 with SMTP id
 w72-20020a25c74b000000b006b48d79ee67mr26821134ybe.93.1664298721697; Tue, 27
 Sep 2022 10:12:01 -0700 (PDT)
MIME-Version: 1.0
References: <9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl@google.com>
In-Reply-To: <9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Sep 2022 19:11:25 +0200
Message-ID: <CANpmjNM3EYpq_qaN8yzt6eVzK59YCPeBdoFMjLRBqoTy2p=HuQ@mail.gmail.com>
Subject: Re: [PATCH mm v2 1/3] kasan: switch kunit tests to console tracepoints
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="b0Ze/1uY";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Tue, 27 Sept 2022 at 19:09, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Switch KUnit-compatible KASAN tests from using per-task KUnit resources
> to console tracepoints.
>
> This allows for two things:
>
> 1. Migrating tests that trigger a KASAN report in the context of a task
>    other than current to KUnit framework.
>    This is implemented in the patches that follow.
>
> 2. Parsing and matching the contents of KASAN reports.
>    This is not yet implemented.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>
> Changes v1->v2:
> - Remove kunit_kasan_status struct definition.
> ---
>  lib/Kconfig.kasan     |  2 +-
>  mm/kasan/kasan.h      |  8 ----
>  mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
>  mm/kasan/report.c     | 31 ----------------
>  4 files changed, 63 insertions(+), 63 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index ca09b1cf8ee9..ba5b27962c34 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -181,7 +181,7 @@ config KASAN_VMALLOC
>
>  config KASAN_KUNIT_TEST
>         tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
> -       depends on KASAN && KUNIT
> +       depends on KASAN && KUNIT && TRACEPOINTS
>         default KUNIT_ALL_TESTS
>         help
>           A KUnit-based KASAN test suite. Triggers different kinds of
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index abbcc1b0eec5..a84491bc4867 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -261,14 +261,6 @@ struct kasan_stack_ring {
>
>  #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
> -#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> -/* Used in KUnit-compatible KASAN tests. */
> -struct kunit_kasan_status {
> -       bool report_found;
> -       bool sync_fault;
> -};
> -#endif
> -
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index f25692def781..3a2886f85e69 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -5,8 +5,12 @@
>   * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
>   */
>
> +#define pr_fmt(fmt) "kasan_test: " fmt
> +
> +#include <kunit/test.h>
>  #include <linux/bitops.h>
>  #include <linux/delay.h>
> +#include <linux/io.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
>  #include <linux/mm.h>
> @@ -14,21 +18,28 @@
>  #include <linux/module.h>
>  #include <linux/printk.h>
>  #include <linux/random.h>
> +#include <linux/set_memory.h>
>  #include <linux/slab.h>
>  #include <linux/string.h>
> +#include <linux/tracepoint.h>
>  #include <linux/uaccess.h>
> -#include <linux/io.h>
>  #include <linux/vmalloc.h>
> -#include <linux/set_memory.h>
> +#include <trace/events/printk.h>
>
>  #include <asm/page.h>
>
> -#include <kunit/test.h>
> -
>  #include "kasan.h"
>
>  #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
>
> +static bool multishot;
> +
> +/* Fields set based on lines observed in the console. */
> +static struct {
> +       bool report_found;
> +       bool async_fault;
> +} test_status;
> +
>  /*
>   * Some tests use these global variables to store return values from function
>   * calls that could otherwise be eliminated by the compiler as dead code.
> @@ -36,35 +47,61 @@
>  void *kasan_ptr_result;
>  int kasan_int_result;
>
> -static struct kunit_resource resource;
> -static struct kunit_kasan_status test_status;
> -static bool multishot;
> +/* Probe for console output: obtains test_status lines of interest. */
> +static void probe_console(void *ignore, const char *buf, size_t len)
> +{
> +       if (strnstr(buf, "BUG: KASAN: ", len))
> +               WRITE_ONCE(test_status.report_found, true);
> +       else if (strnstr(buf, "Asynchronous fault: ", len))
> +               WRITE_ONCE(test_status.async_fault, true);
> +}
>
> -/*
> - * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
> - * first detected bug and panic the kernel if panic_on_warn is enabled. For
> - * hardware tag-based KASAN also allow tag checking to be reenabled for each
> - * test, see the comment for KUNIT_EXPECT_KASAN_FAIL().
> - */
> -static int kasan_test_init(struct kunit *test)
> +static void register_tracepoints(struct tracepoint *tp, void *ignore)
> +{
> +       check_trace_callback_type_console(probe_console);
> +       if (!strcmp(tp->name, "console"))
> +               WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
> +}
> +
> +static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
> +{
> +       if (!strcmp(tp->name, "console"))
> +               tracepoint_probe_unregister(tp, probe_console, NULL);
> +}
> +
> +static int kasan_suite_init(struct kunit_suite *suite)
>  {
>         if (!kasan_enabled()) {
> -               kunit_err(test, "can't run KASAN tests with KASAN disabled");
> +               pr_err("Can't run KASAN tests with KASAN disabled");
>                 return -1;
>         }
>
> +       /*
> +        * Temporarily enable multi-shot mode. Otherwise, KASAN would only
> +        * report the first detected bug and panic the kernel if panic_on_warn
> +        * is enabled.
> +        */
>         multishot = kasan_save_enable_multi_shot();
> -       test_status.report_found = false;
> -       test_status.sync_fault = false;
> -       kunit_add_named_resource(test, NULL, NULL, &resource,
> -                                       "kasan_status", &test_status);
> +
> +       /*
> +        * Because we want to be able to build the test as a module, we need to
> +        * iterate through all known tracepoints, since the static registration
> +        * won't work here.
> +        */
> +       for_each_kernel_tracepoint(register_tracepoints, NULL);
>         return 0;
>  }
>
> -static void kasan_test_exit(struct kunit *test)
> +static void kasan_suite_exit(struct kunit_suite *suite)
>  {
>         kasan_restore_multi_shot(multishot);
> -       KUNIT_EXPECT_FALSE(test, test_status.report_found);
> +       for_each_kernel_tracepoint(unregister_tracepoints, NULL);
> +       tracepoint_synchronize_unregister();
> +}
> +
> +static void kasan_test_exit(struct kunit *test)
> +{
> +       KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));
>  }
>
>  /**
> @@ -106,11 +143,12 @@ static void kasan_test_exit(struct kunit *test)
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                         \
>             kasan_sync_fault_possible()) {                              \
>                 if (READ_ONCE(test_status.report_found) &&              \
> -                   READ_ONCE(test_status.sync_fault))                  \
> +                   !READ_ONCE(test_status.async_fault))                \
>                         kasan_enable_tagging();                         \
>                 migrate_enable();                                       \
>         }                                                               \
>         WRITE_ONCE(test_status.report_found, false);                    \
> +       WRITE_ONCE(test_status.async_fault, false);                     \
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> @@ -1440,9 +1478,10 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>
>  static struct kunit_suite kasan_kunit_test_suite = {
>         .name = "kasan",
> -       .init = kasan_test_init,
>         .test_cases = kasan_kunit_test_cases,
>         .exit = kasan_test_exit,
> +       .suite_init = kasan_suite_init,
> +       .suite_exit = kasan_suite_exit,
>  };
>
>  kunit_test_suite(kasan_kunit_test_suite);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 39e8e5a80b82..f23d51a27414 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -30,8 +30,6 @@
>
>  #include <asm/sections.h>
>
> -#include <kunit/test.h>
> -
>  #include "kasan.h"
>  #include "../slab.h"
>
> @@ -114,41 +112,12 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
>
>  #endif
>
> -#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> -static void update_kunit_status(bool sync)
> -{
> -       struct kunit *test;
> -       struct kunit_resource *resource;
> -       struct kunit_kasan_status *status;
> -
> -       test = current->kunit_test;
> -       if (!test)
> -               return;
> -
> -       resource = kunit_find_named_resource(test, "kasan_status");
> -       if (!resource) {
> -               kunit_set_failure(test);
> -               return;
> -       }
> -
> -       status = (struct kunit_kasan_status *)resource->data;
> -       WRITE_ONCE(status->report_found, true);
> -       WRITE_ONCE(status->sync_fault, sync);
> -
> -       kunit_put_resource(resource);
> -}
> -#else
> -static void update_kunit_status(bool sync) { }
> -#endif
> -
>  static DEFINE_SPINLOCK(report_lock);
>
>  static void start_report(unsigned long *flags, bool sync)
>  {
>         /* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
>         disable_trace_on_warning();
> -       /* Update status of the currently running KASAN test. */
> -       update_kunit_status(sync);
>         /* Do not allow LOCKDEP mangling KASAN reports. */
>         lockdep_off();
>         /* Make sure we don't end up in loop. */
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM3EYpq_qaN8yzt6eVzK59YCPeBdoFMjLRBqoTy2p%3DHuQ%40mail.gmail.com.
