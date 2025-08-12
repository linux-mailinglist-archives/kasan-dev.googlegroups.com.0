Return-Path: <kasan-dev+bncBDPPVSUFVUPBBO7553CAMGQEYU5K2ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 765C4B23BC2
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 00:22:52 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-70741fda996sf107517116d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:22:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755037371; cv=pass;
        d=google.com; s=arc-20240605;
        b=V1pKJlyTd16nyvsGX+gJyHffi7WCym7IP8odW65Q7i09Sa/LcCbO6k9OzplxDg3WTJ
         xdMWmQAfm4rMMyGtAuOT0K/AYo1TTTKF8gbg+zFZBL36kDwlN2y5GTdcsNzxrlUx/Z7V
         fdJTMXS0ybC0NAXAXcCBSjvp6w1mU+c4PVURPCKQNjTpLjH2/GfSdBdO+F8pZWwktRL+
         2KHLwhCGaVPcQcFD/hA4H5GgTyxzaJ4xlfg9p0C8XhsNJCqS94kv2Sx2e0W/NEZyY6Ss
         t6y4ExCpJiXkZy/xeyYuJHwfoCpMIZywCQMtD1fq+ZbuUI9/VgSuqXIdxqZqHM5FbTMp
         rCkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KuRGPpiDo4WXPiJXADiKiVlWW4mdYO3kT3BGRdtdgXs=;
        fh=gpNQN/pEcr/aYLSmYIWlhNJREvzZxRijjYINEcG4BVo=;
        b=cvFfBe6IefYkZbMNajh9sx4b4Q4ZjGXOi8O9Yo6cqX/QmNJGKtnZZuuDono2OaYZRx
         SNgIjq+6sQw9CozOV3df6CXXDRGKvI0qjoL6zOjSK9eJa5u8iKcVJ/urqmedYTbnRVNe
         MbnTK6PYaVEASeQRUifbEn/QbbpH2t81WWdMdRI12C/4JSnsBmA/hM/KZIgzvFoyp+mc
         4XZv57EjC7DkcJcflqkWfm3Fe01wxt1f7VpkMPlelPnHZ1bIQOD4HVcXGCo6PZA7RZ6g
         hmSmc5sRYMzwI9ZtM9NFXzFAT2u0dwVjmZvnSgVS+HJOor6tEZ8OaRU/ByPVp+KENoa3
         J0KQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=goevF8Y5;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755037371; x=1755642171; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KuRGPpiDo4WXPiJXADiKiVlWW4mdYO3kT3BGRdtdgXs=;
        b=Qz7x7pIL3+jJjjfbNbRvjwHjrS+Vn+HvRpGwGi7hrHuoIo3yPWWmxOYbvySThnXCum
         aZbpeqUv2RYwgdZ9qDCq2y5RIyCIzAQZMuHSpTLf1sdXQkkUtf3mv4OJNkAlN+nQaNMV
         hQ+oxny/F6lbQVhLajFQmug8VnY761ACZsnuSsjLE+Ht6TC091T+c3LZkcqikUASk9yn
         wiE5TVGOWGAurg5qGlTvT2bI39ikzGH414GZ751uFx+ULF19WA2t2f1byExJ3FVIieer
         pbR1oYv/eR3rNWGMWS602epkY7pw2xoCnWqvBF8nj0EnBA7ALjrrjnzqZ7MOM9ymDA9T
         1DCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755037371; x=1755642171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KuRGPpiDo4WXPiJXADiKiVlWW4mdYO3kT3BGRdtdgXs=;
        b=N4lQE8NQJk2zEs4IZ1lO/rJFo8wYYOUfaUPLjGJkdPtIB6HmCF8ya0rzSM238M6tkq
         V8NZsyxB+qIcV1y0UoZWngWzNuUY9g7ARscX6GMVeCRe64A79xE+nE/iiJedBftQMPzu
         bKCBz/IKvnXgXM+dw1ktcPA6FOnYmfKbqytmNK27uQMZvIwyifAGi6Dvhm55YcOORh7K
         Kdr5g2KKzT/8HeUNGa1X2wZJvQId8EN/1T1mNMHRoZdMIeUdU6SaxcEja1JKny53fy3b
         w/jkIZqPDWY6ps8Aikn0wX/QRnrmdKTBe8NOe5BgHUSuwhwcinsEC1XZ7pMsa1tONPmm
         FiJg==
X-Forwarded-Encrypted: i=2; AJvYcCXhkGqoOmWM2p08DVFzZzSG1QeCI4Dhg/mD/f9IKklH+z5GsZkUXkhsFlP0r5miFzX2FHVivw==@lfdr.de
X-Gm-Message-State: AOJu0YwgV2VjBVMaCwOajUlrV2GbY/Qqh9j1bqcbwwGGTvrQ/V32G0Te
	69gho1Yx/J2VvUP6Bo9RjfT+jPVwb0aGaDCj67+5KSfvO2CVWOJLpLSp
X-Google-Smtp-Source: AGHT+IGgS/F8Fn7lWOedvyWGONkM1YWwgjBB50t7h1++84M14RavrKs00x9OpPO3T3/RSsysqz29rw==
X-Received: by 2002:a05:6214:d4c:b0:707:600a:458e with SMTP id 6a1803df08f44-709e8574227mr11912946d6.0.1755037371243;
        Tue, 12 Aug 2025 15:22:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfAEzNHxO39sCumgz1FhzmbV0JmUfoOWQLBNMW7SeJeDQ==
Received: by 2002:ad4:5ca6:0:b0:707:b7f:69d1 with SMTP id 6a1803df08f44-709883faf68ls108295776d6.2.-pod-prod-09-us;
 Tue, 12 Aug 2025 15:22:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2GNdObd7s+7/10CgDLlS2iZWG+BocpHIq0tGIzKyRJCCwtc/8x5qq7KP9QmPXLkzogx/vlwGdTdk=@googlegroups.com
X-Received: by 2002:a05:620a:8a83:b0:7e8:21ab:2846 with SMTP id af79cd13be357-7e8653207f2mr74823185a.36.1755037370455;
        Tue, 12 Aug 2025 15:22:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755037370; cv=none;
        d=google.com; s=arc-20240605;
        b=Hg6wt8VqgYlNjVVgsVMVNg0GaAouEkhh8ORKaSLfF6QGDfcZsc3QtCuj9PZi8eTRlJ
         2+IgRaCL6WUVW6S/qJn24tpsYTaCv1z/p13PrFKUIiNws/VqHjAJKvSMmWalPFIpF8Qm
         0UEUxGVISs5Bk0KOelCTzmjOwk1bWCXN8mBUj7rRXaW/eXL5tB1sLvvUke55QISL3yEj
         DA7b5v0wOhZB3EAYhNDA9Sa+/wVvnaE88rliRqw1ujdIj1wMhGoyhSkX6FqQO1fsoto+
         mbSh6WWvBi45pKSzs9k7IbZzPDRiAzRC01EjkDX9laIEMLv9lvrYlD3/ViWFbBkFdH/y
         V5Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z9tXKq/V2seTJ351XUNKOgdloxTrKq2rBSM9NpgLiyo=;
        fh=ykm8QOdc/8Q8lGcJqBa8kpIW7P8cDL3cE2NT39hIBYI=;
        b=HWimjtJzpVUPtY4nMGtBZvSmB1FM7+Z+oAD+f79zQF62FcT3NvJPi6rc0Mz+JtDqNA
         TTTvZzi5o+LosqKi0oKRa8wGZ1s79mqwzZ2LJloPhDtwiTMy4G+tL8URRYWxU1VYf09k
         KokJxkPTAZuKf6KHKKV27mAYFM/x/VdnsCRxuEINk5zUSP+yvdIkpi6uYOeyKHJrzsRJ
         U0/jfNo/BE0h5B9V9U/lugPorQaOOCHed6H41yfPDulzrIwxbTnfxxQHzz5zOwjxuIdb
         q4s9AT06EWvsA5nyaW4Xld+XsWiRBdo8CxIGJDQe2Mlm3YviLiKHwiYyPfBoqkQQ0S+b
         GeRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=goevF8Y5;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e858d1f2f6si17417085a.6.2025.08.12.15.22.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 15:22:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-70740598a9dso54141406d6.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 15:22:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUDvl8g9A7BJqXgLwGBryo/FLE2Hf0IVwSOko9MhJnZdwfyj71HFbPVdqQo9+Z23Yon2jc7tzn1taM=@googlegroups.com
X-Gm-Gg: ASbGncuaQiQJlh7jgdEyqIWK4FYA2Vx1H5bbrAK+mzea2DpjOSCiIHT/Q+iS266HI4G
	J2O7oENhBO4nmRjumji+4TWSH8Uex2HMXlO0dztGv38D08566MYgEThX/DhkNMeVcKZi/TdHPaO
	wnCd1koaCsNuW+ZpO45RpXDRXaRDDDevTBQnZFFNMWLT2z1ssB/jyw7xBlZ5JpPi8OQtnXNONZo
	f7Lmw==
X-Received: by 2002:ad4:5c6f:0:b0:707:5b4e:587e with SMTP id
 6a1803df08f44-709e8957a15mr12639536d6.25.1755037369639; Tue, 12 Aug 2025
 15:22:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-4-marievic@google.com>
In-Reply-To: <20250811221739.2694336-4-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Aug 2025 18:22:38 -0400
X-Gm-Features: Ac12FXzCBxiD-6lnoM1wi2pdHcOoqxDlVcJyEyDmKBIRdd3dc2gRgo7pWafDRyo
Message-ID: <CA+GJov64P8XKif=QQSdxDnrwFgCTw3KJzMk+9Eo=Tsn8PUWsZg@mail.gmail.com>
Subject: Re: [PATCH v2 3/7] kunit: Pass parameterized test context to generate_params()
To: Marie Zhussupova <marievic@google.com>
Cc: davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rmoar@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=goevF8Y5;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2a as
 permitted sender) smtp.mailfrom=rmoar@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Rae Moar <rmoar@google.com>
Reply-To: Rae Moar <rmoar@google.com>
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

On Mon, Aug 11, 2025 at 6:17=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
>
> To enable more complex parameterized testing scenarios,
> the generate_params() function needs additional context
> beyond just the previously generated parameter. This patch
> modifies the generate_params() function signature to
> include an extra `struct kunit *test` argument, giving
> test users access to the parameterized test context when
> generating parameters.
>
> The `struct kunit *test` argument was added as the first parameter
> to the function signature as it aligns with the convention
> of other KUnit functions that accept `struct kunit *test` first.
> This also mirrors the "this" or "self" reference found
> in object-oriented programming languages.
>
> This patch also modifies xe_pci_live_device_gen_param()
> in xe_pci.c and nthreads_gen_params() in kcsan_test.c
> to reflect this signature change.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---
>
> Changes in v2:
>
> - generate_params signature changes in
>   xe_pci.c and kcsan_test.c were squashed
>   into a single patch to avoid in-between
>   breakages in the series.
> - The comments and the commit message were changed to
>   reflect the parameterized testing terminology. See
>   the patch series cover letter change log for the
>   definitions.
>

Hi!

Happy to see this patch go through to give generate_params() access to
resources and context!

As before, this patch is:
Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!

-Rae

> ---
>  drivers/gpu/drm/xe/tests/xe_pci.c | 2 +-
>  include/kunit/test.h              | 9 ++++++---
>  kernel/kcsan/kcsan_test.c         | 2 +-
>  lib/kunit/test.c                  | 5 +++--
>  4 files changed, 11 insertions(+), 7 deletions(-)
>
> diff --git a/drivers/gpu/drm/xe/tests/xe_pci.c b/drivers/gpu/drm/xe/tests=
/xe_pci.c
> index 1d3e2e50c355..62c016e84227 100644
> --- a/drivers/gpu/drm/xe/tests/xe_pci.c
> +++ b/drivers/gpu/drm/xe/tests/xe_pci.c
> @@ -129,7 +129,7 @@ EXPORT_SYMBOL_IF_KUNIT(xe_pci_fake_device_init);
>   * Return: pointer to the next &struct xe_device ready to be used as a p=
arameter
>   *         or NULL if there are no more Xe devices on the system.
>   */
> -const void *xe_pci_live_device_gen_param(const void *prev, char *desc)
> +const void *xe_pci_live_device_gen_param(struct kunit *test, const void =
*prev, char *desc)
>  {
>         const struct xe_device *xe =3D prev;
>         struct device *dev =3D xe ? xe->drm.dev : NULL;
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index d2e1b986b161..b527189d2d1c 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -128,7 +128,8 @@ struct kunit_attributes {
>  struct kunit_case {
>         void (*run_case)(struct kunit *test);
>         const char *name;
> -       const void* (*generate_params)(const void *prev, char *desc);
> +       const void* (*generate_params)(struct kunit *test,
> +                                      const void *prev, char *desc);
>         struct kunit_attributes attr;
>         int (*param_init)(struct kunit *test);
>         void (*param_exit)(struct kunit *test);
> @@ -1691,7 +1692,8 @@ do {                                               =
                              \
>   * Define function @name_gen_params which uses @array to generate parame=
ters.
>   */
>  #define KUNIT_ARRAY_PARAM(name, array, get_desc)                        =
                       \
> -       static const void *name##_gen_params(const void *prev, char *desc=
)                      \
> +       static const void *name##_gen_params(struct kunit *test,         =
                       \
> +                                            const void *prev, char *desc=
)                      \
>         {                                                                =
                       \
>                 typeof((array)[0]) *__next =3D prev ? ((typeof(__next)) p=
rev) + 1 : (array);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {            =
                       \
> @@ -1712,7 +1714,8 @@ do {                                               =
                              \
>   * Define function @name_gen_params which uses @array to generate parame=
ters.
>   */
>  #define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)                =
                       \
> -       static const void *name##_gen_params(const void *prev, char *desc=
)                      \
> +       static const void *name##_gen_params(struct kunit *test,         =
                       \
> +                                            const void *prev, char *desc=
)                      \
>         {                                                                =
                       \
>                 typeof((array)[0]) *__next =3D prev ? ((typeof(__next)) p=
rev) + 1 : (array);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {            =
                       \
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index c2871180edcc..fc76648525ac 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -1383,7 +1383,7 @@ static void test_atomic_builtins_missing_barrier(st=
ruct kunit *test)
>   * The thread counts are chosen to cover potentially interesting boundar=
ies and
>   * corner cases (2 to 5), and then stress the system with larger counts.
>   */
> -static const void *nthreads_gen_params(const void *prev, char *desc)
> +static const void *nthreads_gen_params(struct kunit *test, const void *p=
rev, char *desc)
>  {
>         long nthreads =3D (long)prev;
>
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 49a5e6c30c86..01b20702a5a2 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -695,7 +695,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         /* Get initial param. */
>                         param_desc[0] =3D '\0';
>                         /* TODO: Make generate_params try-catch */
> -                       curr_param =3D test_case->generate_params(NULL, p=
aram_desc);
> +                       curr_param =3D test_case->generate_params(&test, =
NULL, param_desc);
>                         test_case->status =3D KUNIT_SKIPPED;
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT =
KUNIT_SUBTEST_INDENT
>                                   "KTAP version 1\n");
> @@ -726,7 +726,8 @@ int kunit_run_tests(struct kunit_suite *suite)
>
>                                 /* Get next param. */
>                                 param_desc[0] =3D '\0';
> -                               curr_param =3D test_case->generate_params=
(curr_param, param_desc);
> +                               curr_param =3D test_case->generate_params=
(&test, curr_param,
> +                                                                       p=
aram_desc);
>                         }
>                         /*
>                          * TODO: Put into a try catch. Since we don't nee=
d suite->exit
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov64P8XKif%3DQQSdxDnrwFgCTw3KJzMk%2B9Eo%3DTsn8PUWsZg%40mail.gmail.com=
.
