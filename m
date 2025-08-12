Return-Path: <kasan-dev+bncBDPPVSUFVUPBBGX553CAMGQERT6V4HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id A5485B23BBA
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 00:22:19 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4b065932d0bsf176086231cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:22:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755037338; cv=pass;
        d=google.com; s=arc-20240605;
        b=kMvCZju9jHNuW04SUOSjfejhxYKfT5sDwAw5xy0/KFk2pxCwey6B+Qjv2E2GhnM1B5
         XnQHDT1/+fMVNhFoAnbYIfW70/2Xnhu3m/xUDBp34ZfHssQNqqJFoetjTjSwVu3/toEi
         MPDsCgk7K0E/Hgr5l3upgPxSZATVtwFfa7Vvp9OfxSpdQfZCCNKof6noPmZGTogUv3aK
         25W0QNQvELEci1Qu4x0dctc42ptE+GlkATUvRCdeZI7MFHuZl6ag9l0XDmddlDHLjifD
         O+2zgPZ9rjaEeabE4q2d5G5cwZDmsg8bAsckMrv5E1qukOBT/iJxBO2QUBy9WUPPfvlG
         cw7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KM3so35RthqDK/dRJkF/zR4ITmVT9rYzcXeT70+sCp8=;
        fh=iqmCdim2q7Ek64k7EpQllX5LiF5U3bs0FiIMiB2+6sE=;
        b=CPfPeKAtqEVHo4Bd6zr7AnoTK6BQcovJrJxluq/WpQIaWEuSH8s5luTYHC9fszU3nU
         93JP2qFrvaIpDFI2jSwUGM91ZZVyfEaXSuMhthpU6oUojRaeO5le5fScgbEcCDtZ5PyP
         BFsvmFAujvhlfiYHK5iG5LfphXrZUyNsVu9qWnyROQs3PNYUegj0MW88UXdbAq1J9sIo
         iAd+hn0PflbEg9lZV0V14vaIbcql3ePrcH8kF1wkRPQhYV/rOWT/owu4wqjShmNuVaSK
         /U4xfoUP/dTyCBNWZZ0NJB4d/5kb16Uiu+TYfcvOic+gfReEGBOiqrdrLCzNiux/R88M
         nqDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YpTXpvX3;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755037338; x=1755642138; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KM3so35RthqDK/dRJkF/zR4ITmVT9rYzcXeT70+sCp8=;
        b=cdcpYDnlL8vq36FPVHCcWeokYVlc2lDYkSuMUqsDyojCQU5eNsdXhsZDlBmoEh7/yU
         QKp7Tl694zJZybTtqdI4TAG80qktkES2yfrOWHXPh0LUckL7ob3y90Xy26cT2r+kA6A4
         AKUT3LgzPaIs9uexk+7Qo6hMHNLhwrhQ0pM7wRMS658YYZ5u0T/3zNTbp63Iw1pXtFps
         kJRr/c+8ox8fjj0TgGSTTzFzPBXINVmatGjbJ1A7ZF6l04t/jsWdCUnZYN/yUVMHP4RQ
         uUtDAbQwZ/XNNDfUswCYufxQ4V8c7szZnXgtnGfNl+HrLMJ+AGmDzx5G0gN4HSU6rkr8
         z8bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755037338; x=1755642138;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KM3so35RthqDK/dRJkF/zR4ITmVT9rYzcXeT70+sCp8=;
        b=L1uv6QON7+W145LclSAWOz9muAohHIN7gqeoCnGyD6G4GOXpYxWvoPUAT6Rbqxm7u0
         qBfDOLYE6AR1Q68GmTb5zCktmgbJa8dz8P+QmNREJO3CKEBMzOwp4MV7cSqqpqtwp2II
         SxJAJCBSFeQZU1DUKEck4zOT7iVI6VK4YNbQ5xP2juho8SET9Dv3YJoBRmWK5MA27g28
         8O1MqdKpCA5fPpB2UMW8UxTlutf8YqNqwMP+NkVhKLOmhNs3sqbS5ehMhEceJ97OsJHs
         SSe/B5d+8XsfK5Gn2EXEYgLdWLwXyAh/p3+C/Nl0wlvSEsXujShU/1k2LEcMBj5+NDHU
         gbXA==
X-Forwarded-Encrypted: i=2; AJvYcCW5MeG3nMSn+K3dB2D8U4J9xET00wQXxDxnY2Q8Te5RHRl7JQRRWTG802mu31JufDihv11t/g==@lfdr.de
X-Gm-Message-State: AOJu0Yx9Mkltyygzu6K2It1KdjkKIfFA8YrtFakIpQt1iehJRvoX2kKa
	9V/IfGfMG+APbciGXcTZt7zrIfWf21aveQpPpxR92nESO5nOI77e22ay
X-Google-Smtp-Source: AGHT+IHwVGBNK6yxLGCVgc42e+vzCzLokkLDHdRpCEZRSQK/GBrpbOTaStjAfJZU5cZGf7KRytRQBg==
X-Received: by 2002:ac8:690c:0:b0:4af:2376:1a07 with SMTP id d75a77b69052e-4b0fc849125mr10398511cf.29.1755037338495;
        Tue, 12 Aug 2025 15:22:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcQctohfwc8qQ0NVpjaH7cC4zycMzaDqMuwNbad7vZ1SA==
Received: by 2002:ac8:5808:0:b0:4a9:e227:30b with SMTP id d75a77b69052e-4b0a06be026ls119148821cf.1.-pod-prod-02-us;
 Tue, 12 Aug 2025 15:22:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3GWTdVPsTHNBETXc2vZFvsI28YhDCqoS7lKFXyPxZwxiV1RepufE9XTLDTJGtUEXqGqGP4yLw3n8=@googlegroups.com
X-Received: by 2002:a05:622a:4290:b0:4ab:9586:bdd9 with SMTP id d75a77b69052e-4b0fc8ea4acmr11403081cf.56.1755037337248;
        Tue, 12 Aug 2025 15:22:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755037337; cv=none;
        d=google.com; s=arc-20240605;
        b=Y+3+4fjY2m0Cme3k+6PzubuUkB6KZnYIPAtAeJ5rI1MqFIFfUSvIEvLsfJDv0YRe/S
         v3L7BMGuxIvl0qNzJEvruhKx8tHejaenj5UEagvIN3zJwQvez0SNaVExuwMR9M7nSAb4
         VU0LwYI/leCIR1PpkIz+FYMIepAI0gCX4d35N9LVk/dJJ+FD+tbcmPveD35QcVjnETgJ
         /uIM17eB2cK3rsk0YSwPGvv3ybaW/9sU3b8RLVJz3BZmwsPr6pZkJAIbp89lUUuJvsmd
         pNJYTaLlzvTi2tsSA11Qu9OkzfYw2KVRkHdcZ4jUItnnODAorgVL9MBz2mDbbPrDy+dp
         L95Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rWuryeMFKkS3RAr2vCbtx7LOWzlUOf1ahWxEl9iGYmQ=;
        fh=bJjJhcM4HQvNDDuOn2lBaJjqdsm0uVKvejSREYQsN/c=;
        b=J9fWcBhDefWJiUj+12ZQgEvHxPI9hXCTaAto9L9+xHn2vFLRwgR4qDSg3xFm/QY0vx
         XWQVbr4jyuQgzwI43TCcclfVDdmtk28rbDKZgfC963tUm4/K/BGK+nMLPf3syyMW8JEX
         QkzzRlLEHVm0r+Vor9zwiGQlxrVkHLuxfA+8oxZQGvSx6fOAI09ZWiUqWgqNmQ6y8Bx0
         4+e+1U1jEFNFBSkxukg4JSZhb0FFbessoiKmEzHy8D1wnOfG6AtWWAgvdLhH7YTFaI3O
         /ZwWk1ANBXxDFGHSxCfQhYN2mtE2U6ESqCDFyntZRnNxzd2C8Q4FhbKqWF6lXY1ufjbj
         V3rQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YpTXpvX3;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b09b2d8f4fsi6955641cf.3.2025.08.12.15.22.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 15:22:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-7074a74248dso53826256d6.3
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 15:22:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUv8k/tsb9HqUMkeUFy57855+WMRGa++xat0WpytWamjBU829klju9EDLhwhCCI9+CCQpKgg45ZE8Q=@googlegroups.com
X-Gm-Gg: ASbGncuJf8boLOlUpqEAlXyHwRqOMSunucn8PxG5SzHGxme0QQd4ZdDKd+6iRsAa7Rk
	Wor2dip/4GCM7JBv+9oo//8ii6SyTt2SuSbm4vUQDFJONwbBfwc6FB88K+IrvC2gjM8SRkXqIe4
	7R+7ZkJsjrbTagGqVpfYcYNw/owu9uQG5B/4Dpz4iqmVL0Ct1ACcJlgw+FHplrV8LuL9QeQhw37
	G4mY/WrASTRJASqkle0d9Cgi7w=
X-Received: by 2002:a05:6214:dc6:b0:704:7df6:44b4 with SMTP id
 6a1803df08f44-709e893bab1mr14144146d6.23.1755037336426; Tue, 12 Aug 2025
 15:22:16 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-2-marievic@google.com>
In-Reply-To: <20250811221739.2694336-2-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Aug 2025 18:22:05 -0400
X-Gm-Features: Ac12FXy4odiVUbmTVSv_FQj3XmTzKCP2JeRGz1wZpwmC4BzXnA3qMhak1o8tSGs
Message-ID: <CA+GJov6aVg70yjXF3=3teg26AKhcOwLEOgGT8by61nMJvB15jg@mail.gmail.com>
Subject: Re: [PATCH v2 1/7] kunit: Add parent kunit for parameterized test context
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
 header.i=@google.com header.s=20230601 header.b=YpTXpvX3;       spf=pass
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

Hello!

Thanks for making these changes! I really like the change to the new
terminology for parameterized tests, as well as the description change
for "parent".

Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!

-Rae


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
> + * @parent: reference to the parent context of type struct kunit that ca=
n
> + *         be used for storing shared resources.
>   *
>   * Used to store information about the current context under which the t=
est
>   * is running. Most of this data is private and should only be accessed
> - * indirectly via public functions; the one exception is @priv which can=
 be
> - * used by the test writer to store arbitrary data.
> + * indirectly via public functions; the two exceptions are @priv and @pa=
rent
> + * which can be used by the test writer to store arbitrary data and acce=
ss the
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
>         struct kunit_result_stats suite_stats =3D { 0 };
>         struct kunit_result_stats total_stats =3D { 0 };
> +       const void *curr_param;
>
>         /* Taint the kernel so we know we've run tests. */
>         add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
> @@ -679,37 +680,42 @@ int kunit_run_tests(struct kunit_suite *suite)
>                 } else {
>                         /* Get initial param. */
>                         param_desc[0] =3D '\0';
> -                       test.param_value =3D test_case->generate_params(N=
ULL, param_desc);
> +                       /* TODO: Make generate_params try-catch */
> +                       curr_param =3D test_case->generate_params(NULL, p=
aram_desc);
>                         test_case->status =3D KUNIT_SKIPPED;
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT =
KUNIT_SUBTEST_INDENT
>                                   "KTAP version 1\n");
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT =
KUNIT_SUBTEST_INDENT
>                                   "# Subtest: %s", test_case->name);
>
> -                       while (test.param_value) {
> -                               kunit_run_case_catch_errors(suite, test_c=
ase, &test);
> +                       while (curr_param) {
> +                               struct kunit param_test =3D {
> +                                       .param_value =3D curr_param,
> +                                       .param_index =3D ++test.param_ind=
ex,
> +                                       .parent =3D &test,
> +                               };
> +                               kunit_init_test(&param_test, test_case->n=
ame, test_case->log);
> +                               kunit_run_case_catch_errors(suite, test_c=
ase, &param_test);
>
>                                 if (param_desc[0] =3D=3D '\0') {
>                                         snprintf(param_desc, sizeof(param=
_desc),
> -                                                "param-%d", test.param_i=
ndex);
> +                                                "param-%d", param_test.p=
aram_index);
>                                 }
>
> -                               kunit_print_ok_not_ok(&test, KUNIT_LEVEL_=
CASE_PARAM,
> -                                                     test.status,
> -                                                     test.param_index + =
1,
> +                               kunit_print_ok_not_ok(&param_test, KUNIT_=
LEVEL_CASE_PARAM,
> +                                                     param_test.status,
> +                                                     param_test.param_in=
dex,
>                                                       param_desc,
> -                                                     test.status_comment=
);
> +                                                     param_test.status_c=
omment);
>
> -                               kunit_update_stats(&param_stats, test.sta=
tus);
> +                               kunit_update_stats(&param_stats, param_te=
st.status);
>
>                                 /* Get next param. */
>                                 param_desc[0] =3D '\0';
> -                               test.param_value =3D test_case->generate_=
params(test.param_value, param_desc);
> -                               test.param_index++;
> -                               test.status =3D KUNIT_SUCCESS;
> -                               test.status_comment[0] =3D '\0';
> -                               test.priv =3D NULL;
> +                               curr_param =3D test_case->generate_params=
(curr_param, param_desc);
>                         }
> +                       /* TODO: Put this kunit_cleanup into a try-catch.=
 */
> +                       kunit_cleanup(&test);
>                 }
>
>                 kunit_print_attr((void *)test_case, true, KUNIT_LEVEL_CAS=
E);
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov6aVg70yjXF3%3D3teg26AKhcOwLEOgGT8by61nMJvB15jg%40mail.gmail.com.
