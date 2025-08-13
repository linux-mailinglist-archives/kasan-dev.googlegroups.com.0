Return-Path: <kasan-dev+bncBC6OLHHDVUOBBTNQ6HCAMGQECSU4Z7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BD5C7B2451D
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 11:18:06 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-70744318bdfsf174184846d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 02:18:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755076685; cv=pass;
        d=google.com; s=arc-20240605;
        b=PoFxYQ0D1SWYU6IiyXbRs1d73rqncVsgULfL8h76zN/fW38YaLfe9dM2Q6TT3+eyTK
         0+fCptfP25SsNftcxjztuOk0fmZBjyDyJnuo3Asv4XP4KPO1UbTifMYQVwAf9WmSGa3C
         3NIbVhcCYfPCE383zylLSesHRAW8xLuFsf7YNB9qrvamIrnQHwrD+6Llhq9LWeF9qgAs
         75eI7+RMJagm8KACYyvY3G9/AQV9ASbpjyh9nGa6qzYlbnPnsDTiUvJn//wu7mBC55wQ
         4ntCNHBq7vTs51Tnj5uJlt7d9RDQ0yUIX+GNscZVw+Dv27+xpq4C8gWzL5GtO5k2Zj1l
         Kt2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=v3GNaYZ17whk3dtgj/hZF1JhPMfAd9bpczUqaPfW828=;
        fh=/nHLf6cLjGMGlL7FseauVOnpIaIViawAsfUboWZG9Eo=;
        b=SVFxDGGUcsFbQWbdzk8OGbaZY3eO6rKX2U3+T+3wSd17QuiDAx64E9PiIjntnXnTTX
         oeOl3/YmE2k1UEhgbbMpwRurOo5kZZfv+Y/CuxMt0iRk+RgLlicj/DIAv1XIlu5fx51p
         0P0SlvhTW3Dor3JcXL/b+hJBFtsVKAxNDM1K/5zhgKxYwLB54spxrbkKZ450l++SPJdm
         JNANAA4ywXdzmwYC6vaNhZzx/7nExdH0A5MlGWr0ZwwJ/6/5IR23mUpc5mS7c9EPyuyf
         7hVWTlGeBMyDNFid/6PMPj3r3nVbCkVK4N5Hj4e5V31vLi5KpW4MKfWrVrBJBc4DyVse
         h/sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rHwmfeOE;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755076685; x=1755681485; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v3GNaYZ17whk3dtgj/hZF1JhPMfAd9bpczUqaPfW828=;
        b=TanGK50Rs+Sy+uof3G5R2H+AYLomTGlC1QggN8gMwl7EMiiu/F6rMYA6BTjrB5mFOb
         uRfkzRCPpvCopVW1MdJP0ulbjdSoNf5+iHEA+oWvh9VDv2+cFtMo+xIXkUIqM2p3ur9E
         hsg1LMrqx9tVtjPu+P9iKd0Wa0DP2dSCdbAJe1D4Lqq6tlhe8MfuMCtM3/pgS8tmuels
         T5ANPUnidkmSewz750dkZjNQMjNyHGX0Mtykjc50Wh36U2E+8LBYUTR7RzBnOw0vcMTf
         QWLI6qZTqql8Aop9rQ8etVlp+OAjJGNKFkNbvcQ8pphoIGIwYXoCH+sHkx5I2/aGIOix
         hs+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755076685; x=1755681485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v3GNaYZ17whk3dtgj/hZF1JhPMfAd9bpczUqaPfW828=;
        b=rC78pP/YBfnSIAj10QE+K5d462yF/w7wYTn5LLv+3bEpJtkVgqNMl6M0UoPAUKIKgO
         DlAncDoVyF4sk19ykwNzlrwWuTdDLaE6jPBzoX5pMrZdtKUJMHArzOWbNpXxSPhvyOfA
         gPqCCH9YOMV1CByUtsWvF6RSH+fMV1a8ibkj/sbMgtUTbbQwGpGJu6DZ0KGVWbYsTG+Q
         IGq9teBAZM4DO58210jr5VYxFQqzQfjldam3yUvh6PBgIDzTYrXEwh4/FtJiRhvIt/nW
         o2kGsTyCA/SEZV+5vJmNk+v9muLMUg2QwLbC2i9umKaARjS1+SbvbvGy1nFl8BkdqcEu
         X1ig==
X-Forwarded-Encrypted: i=2; AJvYcCVZHhwnw0cxLbnPv+kZO+pYW9Ys19Cw2qYFN+ukSS+Db8VBY82oY05vfGsAqm7M3UKyafiN0Q==@lfdr.de
X-Gm-Message-State: AOJu0YxnpsbHI5mZw8HHKeUmNawIskp68BqkXbe6tmwQwsanvl1m4ot6
	oJhn1QsJ4XC82XSpNy+C943HyRqBD8IL8iaWks6xaNQ5xvfwI3rXm9F3
X-Google-Smtp-Source: AGHT+IHHFp5A4NzmV2spbY+espDaDmjMT94w3TLxs7/28SxfupjqBVyd57/ug/EzqkmOVeIcVo/xlw==
X-Received: by 2002:a05:6214:ca3:b0:709:c827:4db3 with SMTP id 6a1803df08f44-709e89d3ed9mr31390956d6.51.1755076685390;
        Wed, 13 Aug 2025 02:18:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZckxHFctvCz+Ffx7xs+m4XTHcilu8n+yzjj+wgaD76bBg==
Received: by 2002:a05:6214:4ec2:b0:709:ad61:7fb9 with SMTP id
 6a1803df08f44-709ad618986ls59201706d6.1.-pod-prod-04-us; Wed, 13 Aug 2025
 02:18:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX234ww9QOC4iHDDRYKsMmHju5ZsuE5Uwx+isxI3I7g1kX9JgprVmONRJZqIEuCWI/bnUl+MAGHPlA=@googlegroups.com
X-Received: by 2002:a05:6102:161f:b0:4f3:1d:6b47 with SMTP id ada2fe7eead31-50e512a5cf5mr687623137.25.1755076684312;
        Wed, 13 Aug 2025 02:18:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755076684; cv=none;
        d=google.com; s=arc-20240605;
        b=WrZoEUxHAgUuXXM59fRLugs7w+BqN/DFrLxsA0atcg3ZxE0l1M07oXqYm+iasiHxfv
         HrFU9quNhCSTyN/0maCXB6wV5+0n+GpWVOa3lUCrBWbR9h3eLTd1+gCkJTDdDiPYpGbl
         XmrRThM9FXs/YJE1AMi3Vdb7MkwKuj2C6UoV3E8Bcl9TN6YwY+EAho2riQf1okws+NKP
         eYYWDjtGUez71UxkpJGc0160KNDNxM70Fk7VXD3UHJgDJfi5k4KYbH5IouaLUeC2kwAA
         XG1br8fHUL5jZYtWJzFOH1EXL/KyvvusLmaKWqfuAfQx342KuspNUt/3Mwi8ikxdHlwZ
         dGVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OA9UcPn0rpxScTNN2nLHwoGIj1L0Zyna2+48vzzJ+wY=;
        fh=y1FMIJnnsV9zjSg8pW01WxigAT4ZmLdmZPRcglExYQw=;
        b=b6yXVA1vhCrSYA/JymYAdabZb016FgcAsGX9DDQYKjWcClS6Bq1Eu1xuyaqy3AqMK5
         rYsJUoF6T/87E9SD8Srog5Ug+liP6T45upXybOPFbwN9Tk2WkSfx6hSWtvM8uLySH6CV
         OaaYpZFRZ+FLTNR0Fq2k+MVp5a3qlHB6ssRUg7SLaqHdRL71jCoK+03KpKsloL22lhay
         BibCZ0HDBoknsV4wK2sfTSc6y2ycAZGeIRxH7cRUmeOyRuExty8fJRSiTnfg5DdO0kYB
         WU9kQqSV/i5ZHc/x28Kisnj18upc6CGw73NO9Vf/Q3ufB6OdGZIPRRZTPjCYCtj0ErPK
         a+rQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rHwmfeOE;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-88e1ff5ef6esi488004241.2.2025.08.13.02.18.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 02:18:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-709ec7cbaa5so4682136d6.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 02:18:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNSM5xLCjrrO6VwQSUC/fEOZ4wZ15jHXCl2do+bUbqiztlKbVaGQ6m8n+avmIBwlI79QsKEnnJXcY=@googlegroups.com
X-Gm-Gg: ASbGncs/04ho0e6CfnxZEtpuuTzaB/AG0uY7MBtnYmmqjS+DIZKOV5y//ykdcVyfsxM
	/9RrUarMvRZxGrbejAimAIe2BambZJN3198p6Rb0zcee1IoyjcOsALtPGHDV5AgkH5f2tUUKLVo
	NwkCru2pGLLOl0NaUCRkXcxTLGxpzHCju4ATqlnZWWBlGMIAbnRizf7OM1quoT9QzrQbwRyXSPd
	2rEml4/HlfMgYjpL2k=
X-Received: by 2002:ad4:5969:0:b0:707:14d5:ee7a with SMTP id
 6a1803df08f44-709e89589f1mr29205596d6.36.1755076683316; Wed, 13 Aug 2025
 02:18:03 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-2-marievic@google.com>
In-Reply-To: <20250811221739.2694336-2-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Aug 2025 17:17:50 +0800
X-Gm-Features: Ac12FXwKclyKURhGUPeqD7q1-1Zy-xJEuYt-xIEpE9fLIlLMtHAftwqee4-Dzoo
Message-ID: <CABVgOSkhkwgoO8oUHRgzw5Env48vQ8JoGp=sx8-NRAT+my9xfg@mail.gmail.com>
Subject: Re: [PATCH v2 1/7] kunit: Add parent kunit for parameterized test context
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="00000000000050e8c5063c3ba233"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rHwmfeOE;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2b
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

--00000000000050e8c5063c3ba233
Content-Type: text/plain; charset="UTF-8"

On Tue, 12 Aug 2025 at 06:17, Marie Zhussupova <marievic@google.com> wrote:
>
> Currently, KUnit parameterized tests lack a mechanism
> to share resources across parameter runs because the
> same `struct kunit` instance is cleaned up and
> reused for each run.
>
> This patch introduces parameterized test context,
> enabling test users to share resources between
> parameter runs. It also allows setting up resources
> that need to be available for all parameter runs only once,
> which is helpful in cases where setup is expensive.
>
> To establish a parameterized test context, this
> patch adds a parent pointer field to `struct kunit`.
> This allows resources added to the parent `struct kunit`
> to be shared and accessible across all parameter runs.
>
> In kunit_run_tests(), the default `struct kunit`
> created is now designated to act as the parameterized
> test context whenever a test is parameterized.
>
> Subsequently, a new `struct kunit` is made
> for each parameter run, and its parent pointer is
> set to the `struct kunit` that holds the
> parameterized test context.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

Thanks, this looks good to me.

Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David


>
> Changes in v2:
>
> - Descriptions of the parent pointer in `struct kunit`
>   were changed to be more general, as it could be
>   used to share resources not only between parameter
>   runs but also between test cases in the future.
> - When printing parameter descriptions using
>   test.param_index was changed to param_test.param_index.
> - kunit_cleanup(&test) in kunit_run_tests() was moved
>   inside the parameterized test check.
> - The comments and the commit message were changed to
>   reflect the parameterized testing terminology. See
>   the patch series cover letter change log for the
>   definitions.
>
> ---
>  include/kunit/test.h |  8 ++++++--
>  lib/kunit/test.c     | 34 ++++++++++++++++++++--------------
>  2 files changed, 26 insertions(+), 16 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 39c768f87dc9..b47b9a3102f3 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -268,14 +268,18 @@ struct kunit_suite_set {
>   *
>   * @priv: for user to store arbitrary data. Commonly used to pass data
>   *       created in the init function (see &struct kunit_suite).
> + * @parent: reference to the parent context of type struct kunit that can
> + *         be used for storing shared resources.
>   *
>   * Used to store information about the current context under which the test
>   * is running. Most of this data is private and should only be accessed
> - * indirectly via public functions; the one exception is @priv which can be
> - * used by the test writer to store arbitrary data.
> + * indirectly via public functions; the two exceptions are @priv and @parent
> + * which can be used by the test writer to store arbitrary data and access the
> + * parent context, respectively.
>   */
>  struct kunit {
>         void *priv;
> +       struct kunit *parent;
>
>         /* private: internal use only. */
>         const char *name; /* Read only after initialization! */
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index f3c6b11f12b8..14a8bd846939 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -647,6 +647,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>         struct kunit_case *test_case;
>         struct kunit_result_stats suite_stats = { 0 };
>         struct kunit_result_stats total_stats = { 0 };
> +       const void *curr_param;
>
>         /* Taint the kernel so we know we've run tests. */
>         add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
> @@ -679,37 +680,42 @@ int kunit_run_tests(struct kunit_suite *suite)
>                 } else {
>                         /* Get initial param. */
>                         param_desc[0] = '\0';
> -                       test.param_value = test_case->generate_params(NULL, param_desc);
> +                       /* TODO: Make generate_params try-catch */
> +                       curr_param = test_case->generate_params(NULL, param_desc);
>                         test_case->status = KUNIT_SKIPPED;
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
>                                   "KTAP version 1\n");
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
>                                   "# Subtest: %s", test_case->name);
>
> -                       while (test.param_value) {
> -                               kunit_run_case_catch_errors(suite, test_case, &test);
> +                       while (curr_param) {
> +                               struct kunit param_test = {
> +                                       .param_value = curr_param,
> +                                       .param_index = ++test.param_index,
> +                                       .parent = &test,
> +                               };
> +                               kunit_init_test(&param_test, test_case->name, test_case->log);
> +                               kunit_run_case_catch_errors(suite, test_case, &param_test);
>
>                                 if (param_desc[0] == '\0') {
>                                         snprintf(param_desc, sizeof(param_desc),
> -                                                "param-%d", test.param_index);
> +                                                "param-%d", param_test.param_index);
>                                 }
>
> -                               kunit_print_ok_not_ok(&test, KUNIT_LEVEL_CASE_PARAM,
> -                                                     test.status,
> -                                                     test.param_index + 1,
> +                               kunit_print_ok_not_ok(&param_test, KUNIT_LEVEL_CASE_PARAM,
> +                                                     param_test.status,
> +                                                     param_test.param_index,
>                                                       param_desc,
> -                                                     test.status_comment);
> +                                                     param_test.status_comment);
>
> -                               kunit_update_stats(&param_stats, test.status);
> +                               kunit_update_stats(&param_stats, param_test.status);
>
>                                 /* Get next param. */
>                                 param_desc[0] = '\0';
> -                               test.param_value = test_case->generate_params(test.param_value, param_desc);
> -                               test.param_index++;
> -                               test.status = KUNIT_SUCCESS;
> -                               test.status_comment[0] = '\0';
> -                               test.priv = NULL;
> +                               curr_param = test_case->generate_params(curr_param, param_desc);
>                         }
> +                       /* TODO: Put this kunit_cleanup into a try-catch. */
> +                       kunit_cleanup(&test);
>                 }
>
>                 kunit_print_attr((void *)test_case, true, KUNIT_LEVEL_CASE);
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkhkwgoO8oUHRgzw5Env48vQ8JoGp%3Dsx8-NRAT%2Bmy9xfg%40mail.gmail.com.

--00000000000050e8c5063c3ba233
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIUnQYJKoZIhvcNAQcCoIIUjjCCFIoCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ghIEMIIGkTCCBHmgAwIBAgIQfofDAVIq0iZG5Ok+mZCT2TANBgkqhkiG9w0BAQwFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMzA0MTkwMzUzNDdaFw0zMjA0MTkwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFI2IFNNSU1FIENBIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDYydcdmKyg
4IBqVjT4XMf6SR2Ix+1ChW2efX6LpapgGIl63csmTdJQw8EcbwU9C691spkltzTASK2Ayi4aeosB
mk63SPrdVjJNNTkSbTowej3xVVGnYwAjZ6/qcrIgRUNtd/mbtG7j9W80JoP6o2Szu6/mdjb/yxRM
KaCDlloE9vID2jSNB5qOGkKKvN0x6I5e/B1Y6tidYDHemkW4Qv9mfE3xtDAoe5ygUvKA4KHQTOIy
VQEFpd/ZAu1yvrEeA/egkcmdJs6o47sxfo9p/fGNsLm/TOOZg5aj5RHJbZlc0zQ3yZt1wh+NEe3x
ewU5ZoFnETCjjTKz16eJ5RE21EmnCtLb3kU1s+t/L0RUU3XUAzMeBVYBEsEmNnbo1UiiuwUZBWiJ
vMBxd9LeIodDzz3ULIN5Q84oYBOeWGI2ILvplRe9Fx/WBjHhl9rJgAXs2h9dAMVeEYIYkvW+9mpt
BIU9cXUiO0bky1lumSRRg11fOgRzIJQsphStaOq5OPTb3pBiNpwWvYpvv5kCG2X58GfdR8SWA+fm
OLXHcb5lRljrS4rT9MROG/QkZgNtoFLBo/r7qANrtlyAwPx5zPsQSwG9r8SFdgMTHnA2eWCZPOmN
1Tt4xU4v9mQIHNqQBuNJLjlxvalUOdTRgw21OJAFt6Ncx5j/20Qw9FECnP+B3EPVmQIDAQABo4IB
ZTCCAWEwDgYDVR0PAQH/BAQDAgGGMDMGA1UdJQQsMCoGCCsGAQUFBwMCBggrBgEFBQcDBAYJKwYB
BAGCNxUGBgkrBgEEAYI3FQUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUM7q+o9Q5TSoZ
18hmkmiB/cHGycYwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEE
bzBtMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsG
AQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMBEG
A1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAgEAVc4mpSLg9A6QpSq1JNO6tURZ4rBI
MkwhqdLrEsKs8z40RyxMURo+B2ZljZmFLcEVxyNt7zwpZ2IDfk4URESmfDTiy95jf856Hcwzdxfy
jdwx0k7n4/0WK9ElybN4J95sgeGRcqd4pji6171bREVt0UlHrIRkftIMFK1bzU0dgpgLMu+ykJSE
0Bog41D9T6Swl2RTuKYYO4UAl9nSjWN6CVP8rZQotJv8Kl2llpe83n6ULzNfe2QT67IB5sJdsrNk
jIxSwaWjOUNddWvCk/b5qsVUROOuctPyYnAFTU5KY5qhyuiFTvvVlOMArFkStNlVKIufop5EQh6p
jqDGT6rp4ANDoEWbHKd4mwrMtvrh51/8UzaJrLzj3GjdkJ/sPWkDbn+AIt6lrO8hbYSD8L7RQDqK
C28FheVr4ynpkrWkT7Rl6npWhyumaCbjR+8bo9gs7rto9SPDhWhgPSR9R1//WF3mdHt8SKERhvtd
NFkE3zf36V9Vnu0EO1ay2n5imrOfLkOVF3vtAjleJnesM/R7v5tMS0tWoIr39KaQNURwI//WVuR+
zjqIQVx5s7Ta1GgEL56z0C5GJoNE1LvGXnQDyvDO6QeJVThFNgwkossyvmMAaPOJYnYCrYXiXXle
A6TpL63Gu8foNftUO0T83JbV/e6J8iCOnGZwZDrubOtYn1QwggWDMIIDa6ADAgECAg5F5rsDgzPD
hWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
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
jmkLAgMBAAGjggHgMIIB3DAeBgNVHREEFzAVgRNkYXZpZGdvd0Bnb29nbGUuY29tMA4GA1UdDwEB
/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwHQYDVR0OBBYEFBp5bTxrTm/d
WMmRETO8lNkA4c7fMFgGA1UdIARRME8wCQYHZ4EMAQUBAjBCBgorBgEEAaAyCgMDMDQwMgYIKwYB
BQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQC
MAAwgZoGCCsGAQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWdu
LmNvbS9jYS9nc2F0bGFzcjZzbWltZWNhMjAyMzBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3J0MB8GA1UdIwQYMBaA
FDO6vqPUOU0qGdfIZpJogf3BxsnGMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFs
c2lnbi5jb20vY2EvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQBF
tO3/N2l9hTaij/K0xCpLwIlrqpNo0nMAvvG5LPQQjSeHnTh06tWTgsPCOJ65GX+bqWRDwGTu8WTq
c5ihCNOikBs25j82yeLkfdbeN/tzRGUb2RD+8n9I3CnyMSG49U2s0ZdncsrIVFh47KW2TpHTF7R8
N1dri01wPg8hw4u0+XoczR2TiBrBOISKmAlkAi+P9ivT31gSHdbopoL4x0V2Ow9IOp0chrQQUZtP
KBytLhzUzd9wIsE0QMNDbw6jeG8+a4sd17zpXSbBywIGw7sEvPtnBjMaf5ib3kznlOne6tuDVx4y
QFExTCSrP3OTMUkNbpIdgzg2CHQ2aB8i8YsTZ8Q8Q8ztPJ+xDNsqBUeYxILLjTjxQQovToqipB3f
6IMyk+lWCdDS+iCLYZULV1BTHSdwp1NM3t4jZ8TMlV+JzAyRqz4lzSl8ptkFhKBJ7w2tDrZ3BEXB
8ASUByRxeh+pC1Z5/HhqfiWMVPjaWmlRRJVlRk+ObKIv2CblwxMYlo2Mn8rrbEDyfum1RTMW55Z6
Vumvw5QTHe29TYxSiusovM6OD5y0I+4zaIaYDx/AtF0mMOFXb1MDyynf1CDxhtkgnrBUseHSOU2e
MYs7IqzRap5xsgpJS+t7cp/P8fdlCNvsXss9zZa279tKwaxR0U2IzGxRGsWKGxDysn1HT6pqMDGC
Al0wggJZAgEBMGgwVDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKjAo
BgNVBAMTIUdsb2JhbFNpZ24gQXRsYXMgUjYgU01JTUUgQ0EgMjAyMwIQAUXA7LnOuRz2DvkWTeMc
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgj6AkrMeuWraXBi4BKuUZg+ibPtcw
6s37R786zGw6MiEwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODEzMDkxODA0WjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAhQFlCAgfqW0ZFpM1dzXMuhsHoXAgaZMpIJbbLVhCWktOP3wLrvQcer4XhArfYH7b
JwgB3ZemYeCWklQ8WDgPDZn8hRp2ZZ4NeqO8/1n0uKx24QspmwpzFq4Oq+hVb5V2PDz5XenwOtd6
M1Gwm837hIRK21aL0wRcC7BzZA90jeFGSZR/i8qGLX2z8UlKkLYcccSfHWxdK2VKnVXhlKsx4YQ4
ZIjK7f4FZvyvMn/srxcblk2aD0Qb7yVUp95JYd4yHyVmQZSOPNgdeVWLiYtVdjzYHD1AXtPbpPM6
nFXADoj8QCeADATqAieDruIi92KzoxLNXoQBvJhraKUJOgAerw==
--00000000000050e8c5063c3ba233--
