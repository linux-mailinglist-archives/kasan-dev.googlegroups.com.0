Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBZURV7CAMGQECJVEP7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id EAE35B176C5
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 21:49:59 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4588fb6854csf4597335e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 12:49:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753991399; cv=pass;
        d=google.com; s=arc-20240605;
        b=aTW/xXGTpPzwqgGhtmm9NtHK9dPU3jXeM032QCq8Q8f5QPgUVfmGSG2LA3GN5izesG
         qjPeTqX7PhOrM04r1sZscAzBBLqS3mFvnvUTqVa8OfgsiKfqAL+PJBIcEtc+VnGikjfS
         9dUrz4vDI9cJPktLI/cmbNIaO8t8YBCGy8m1LGjuJuu5No1HQ5Q7r03dNcqYwM6xQ9Sw
         4v9aNpxOZtqYEP2Tn6Q/TOpV98bL7yleDo2fNsdnwOjYOVFY9fLQVLq8q/EhWxgmLdXQ
         kScV3FxJ7Lm5drAMqOZJQgplJB6vbR0vp2zkKZO+Vu7YLsxcRVlVkWH4Qs6OeFJXY02z
         Patw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=X4eaZkHKYEGuaW5wG4FF+D20Fs5na662wTu7OkxDA9E=;
        fh=wqZxCyCZdITmDwvT9drXuRshNgCqUCxk1fH5+DSzkpQ=;
        b=Sp3F09qYhYJ5LZKR5MBdxcDIn+OGPFSiP+n6ZMjd1Tq0VSzOs7Du9BLFxIv5YjCizJ
         kbne347ANcG4VqKV/NyVUr6nyvg+nkUHN7WRFNmMRtMOCsRebWOB88CmW/SnwmTEfKmP
         Fp1v2EVd3L41uwYhADNP4zaQgOEvSH6edDtx59k0hUk/k/0JMRuU3NMqrswWVfckvnLP
         pRgI+In+ucjsUBwuX7BekTiALraodMjNgaWklNrAZlnH5s2vJIfdcTKejUUKZQQcDwr0
         hJPti1Gbq2grJ3oQxtibrgOHPodqz1T307NECbLpRLxT9f4Fx/e7afjAqBTaBywbroTH
         ugJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M11wsNCZ;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753991399; x=1754596199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=X4eaZkHKYEGuaW5wG4FF+D20Fs5na662wTu7OkxDA9E=;
        b=iqIWgrFM1CI3gjxhH+RwcbmVvu0ZERwpfYPpWqEV9b+2IC1qEzV0HT3X4wKI2ZStHh
         w7jzciI4aUUyii2q0ytSKmdURWlnM0OvsoGbJ46JwbH44nWYcoA0o1AYKvEUgk2JLc28
         T2UIFBPdCJf/VHDXWN8/B8Ekp/nfTUr/OvcTwLsBNaXR7vWm0ed5u/RgkXipBhTPU91n
         bV3w81ajkm116sGMLuAvPpm/GNeuS5sHE7I2UJ4vIfcKkqjgVYrJK721kS4/whXtHdLU
         G1D3QaNKRvzF411cDB7X2BCQ6sPDUzf+og6MqwDoFMSub8/9DsXcmqMUxnGDlOsaBz6y
         yLbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753991399; x=1754596199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X4eaZkHKYEGuaW5wG4FF+D20Fs5na662wTu7OkxDA9E=;
        b=uy4gFyiM80liMZajY3f/DhXQR+nNl5HioJzFC1zm3B0Wt1mIEsCYOZbz8+HjlaQ7BQ
         QySSF2QmWiMtz3pwimQB3nsn2AsrphMtmnLYLj8liMQyrdSLK0WcbLVXXR2tilkQ+VHC
         W80BCwZPWJ4Mo64ROS0HFMWnaFg7GVX5jlQ9yd4hRgD8s3KP46yZgLhIuNMwO6Ish3cr
         JTYTLAOmgH9c1wXQ1ro/as4ePAnsLQIWkuPupH+AcVXOsw2zqyqec9gxDQHBRRsUzdLx
         7BUFElXWxHrkXzHbQVSiwyCBbCaskR2VHCypzf+cFWQki2cPibeFvHghfn8HT7TYUgUA
         JDZA==
X-Forwarded-Encrypted: i=2; AJvYcCWIf1CkI7QdUkZYUwTN9Gw9CZcBBDTT8TPR78AvnaE8XWMo1KcyCZ+2n3dfvOO7e5vq73Xf9w==@lfdr.de
X-Gm-Message-State: AOJu0YzBZ/ElLrCKLhLvn3MeTdSxHcmU624qzonPo23zWFtga42EHNaF
	alA7yX9YMONh/Kae2GM/UTiUb3EXTVCZBSJpkNsJuxKnaNmfKznnbHiC
X-Google-Smtp-Source: AGHT+IGL6FlIWbwjbUzsiu4EIXP6Uqivs4tRmXEFxPu1a4BOVerLKWWK+xa13qxYubjRL9I5t1hYhg==
X-Received: by 2002:a05:600c:35d4:b0:43d:9d5:474d with SMTP id 5b1f17b1804b1-45892a37a93mr86600155e9.0.1753991398878;
        Thu, 31 Jul 2025 12:49:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfDs7mr4+s++3XPTUmp2XD4eu/Ri9DUULxR4ZrOwztc6g==
Received: by 2002:a05:600c:638d:b0:456:241d:50bd with SMTP id
 5b1f17b1804b1-458a8676ac6ls1031165e9.2.-pod-prod-04-eu; Thu, 31 Jul 2025
 12:49:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9hyjf9GzadxGAgDupDOEkXOtNajJzV8kRhTI9MtWAnJnhMsLC11LeFfCWXQtySZICvYUZ131jb2M=@googlegroups.com
X-Received: by 2002:a05:600c:37cf:b0:458:a829:aa93 with SMTP id 5b1f17b1804b1-458a829ab98mr13223475e9.16.1753991396382;
        Thu, 31 Jul 2025 12:49:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753991396; cv=none;
        d=google.com; s=arc-20240605;
        b=L6laDfcQpoBWDX8neU/b8M7k+MVlkLgmZqihDJjS3ElsP2IlanKa/jhOqFAf6GEtb1
         Dtx9qBJyJSkcDr5YEXIZRdxIqeStQz3useZJqkjUzDJGYY7oX594opcK6/JgAV3jC2/w
         YefHMbafmNr0IfM3PG5fWypbcyIz4961QaqTiDOeMtm0ILjrJG8Cwvx42BMSQnQsGWUy
         1BoGSIEvB6RFfCdyuXJBkK/osVAhgMcJo1oka5jNk5xEAaRnkdF+KwLfy4WnYk3ENDMW
         NYXC2wFdr87NQuFzF2jPd+EMzGjaGnWmze9AO2vdNiy84hMRkks1a+ZrPZ1FXHrrHuVa
         CUxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w0NmmPrgKMAdI4zT8cKWXm7HR1XmVftYuLV66NFbboQ=;
        fh=N7vwvFG56XdOXaZy0OkNmQJ18nWs9HW1Kimt1JSYqj0=;
        b=YNUzoA/veGd2gyaWpi9KsQV4b2TEzf8FZ00YrJJbeUzZB5atb/WCtLYiU0F5oePsKH
         G7z3SazuSfiSu/cIJppRaQERo8KToZpub7avpcOuneQNtPGYEf7xMpAY807czx/PvwC0
         5IvHoalkenfmhc2+W6ixCxaVFCh6NfaeD14ImLjwd6uhlrSOHz/1FSAvB/73RLzrn32t
         UgBxBcRdqbIdEY9HuGeIqUMZCS5QmeTE5XeELbKpqoB5YHH8M2dLCsferV+gM4XeS8p4
         UoQ7/6Lq9R/w2o7qbnZOXW2mzyzu3OSa5O7Iy8N4EcbiMwwmJaa7Lhd0k/DvC2RmfFpt
         jkVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M11wsNCZ;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4588dd3fe52si2700065e9.1.2025.07.31.12.49.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 12:49:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-61543b05b7cso2751a12.0
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 12:49:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWBOCCDa1EHpBfME3DsEtNnQ2ARS1Y8NKgKBvIVZF9zD4FFu+6i75Hq8NZEc+KUm08+3+IeezOxSAA=@googlegroups.com
X-Gm-Gg: ASbGnctvkhynHPmsmlDwMTOzwWN42Wv/TQJJbcQZJuJJp1YeYpi4jvHeW3q1LauIRhC
	sOBOHNGnl3xuVEGE4FdhMsLjUi187t+obPaMGjX+iREWZC1uN9ffJWu5UUpa9xbk2aoS3WKzfQi
	/hmIOjTCfKoQ5u00xq9esXh/HQ7Pr2k5DKxN8/XaXBSska91bKc9onVOQJae4joMezR3+1s2q1Y
	5voyFMLOgr0hKvkZf9CoTZELcKp1y8v10smWw==
X-Received: by 2002:a50:955b:0:b0:615:28c0:fac8 with SMTP id
 4fb4d7f45d1cf-615cb709cc4mr11672a12.4.1753991395595; Thu, 31 Jul 2025
 12:49:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-7-marievic@google.com> <5683507a-dacc-4e46-893f-d1e775d2ef22@suswa.mountain>
In-Reply-To: <5683507a-dacc-4e46-893f-d1e775d2ef22@suswa.mountain>
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 31 Jul 2025 15:49:43 -0400
X-Gm-Features: Ac12FXy9pctOjhAPWBrCxe7TRxwbUutDqcqHowGqJpY31Ox_2dkMf4vGOaTdX74
Message-ID: <CAAkQn5KtGMYqEP07xvs5GR_5b591Lo+YPu5uT9HiduMo900Mxw@mail.gmail.com>
Subject: Re: [PATCH 6/9] kunit: Enable direct registration of parameter arrays
 to a KUnit test
To: Dan Carpenter <dan.carpenter@linaro.org>
Cc: oe-kbuild@lists.linux.dev, rmoar@google.com, davidgow@google.com, 
	shuah@kernel.org, brendan.higgins@linux.dev, lkp@intel.com, 
	oe-kbuild-all@lists.linux.dev, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: multipart/alternative; boundary="000000000000137eab063b3ef2a1"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=M11wsNCZ;       spf=pass
 (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52e
 as permitted sender) smtp.mailfrom=marievic@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
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

--000000000000137eab063b3ef2a1
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Thu, Jul 31, 2025 at 11:58=E2=80=AFAM Dan Carpenter <dan.carpenter@linar=
o.org>
wrote:

> Hi Marie,
>
> kernel test robot noticed the following build warnings:
>
> https://git-scm.com/docs/git-format-patch#_base_tree_information]
>
> url:
> https://github.com/intel-lab-lkp/linux/commits/Marie-Zhussupova/kunit-Add=
-parent-kunit-for-parameterized-test-context/20250730-033818
> base:
> https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git
> kunit
> patch link:
> https://lore.kernel.org/r/20250729193647.3410634-7-marievic%40google.com
> patch subject: [PATCH 6/9] kunit: Enable direct registration of parameter
> arrays to a KUnit test
> config: nios2-randconfig-r072-20250731 (
> https://download.01.org/0day-ci/archive/20250731/202507310854.pZvIcswn-lk=
p@intel.com/config
> )
> compiler: nios2-linux-gcc (GCC) 8.5.0
>
> If you fix the issue in a separate patch/commit (i.e. not just a new
> version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
> | Closes: https://lore.kernel.org/r/202507310854.pZvIcswn-lkp@intel.com/
>
> New smatch warnings:
> lib/kunit/test.c:723 kunit_run_tests() error: we previously assumed
> 'test_case->generate_params' could be null (see line 714)
>
> vim +723 lib/kunit/test.c
>
> 914cc63eea6fbe Brendan Higgins     2019-09-23  681  int
> kunit_run_tests(struct kunit_suite *suite)
> 914cc63eea6fbe Brendan Higgins     2019-09-23  682  {
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  683      char
> param_desc[KUNIT_PARAM_DESC_SIZE];
> 914cc63eea6fbe Brendan Higgins     2019-09-23  684      struct kunit_case
> *test_case;
> acd8e8407b8fcc David Gow           2021-08-03  685      struct
> kunit_result_stats suite_stats =3D { 0 };
> acd8e8407b8fcc David Gow           2021-08-03  686      struct
> kunit_result_stats total_stats =3D { 0 };
> 8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  687      const void
> *curr_param;
> 914cc63eea6fbe Brendan Higgins     2019-09-23  688
> c272612cb4a2f7 David Gow           2022-07-01  689      /* Taint the
> kernel so we know we've run tests. */
> c272612cb4a2f7 David Gow           2022-07-01  690
> add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
> c272612cb4a2f7 David Gow           2022-07-01  691
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  692      if
> (suite->suite_init) {
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  693
> suite->suite_init_err =3D suite->suite_init(suite);
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  694              if
> (suite->suite_init_err) {
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  695
> kunit_err(suite, KUNIT_SUBTEST_INDENT
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  696
>         "# failed to initialize (%d)", suite->suite_init_err);
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  697
> goto suite_end;
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  698              }
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  699      }
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  700
> cae56e1740f559 Daniel Latypov      2022-04-29  701
> kunit_print_suite_start(suite);
> 914cc63eea6fbe Brendan Higgins     2019-09-23  702
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  703
> kunit_suite_for_each_test_case(suite, test_case) {
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  704              struct
> kunit test =3D { .param_value =3D NULL, .param_index =3D 0 };
> acd8e8407b8fcc David Gow           2021-08-03  705              struct
> kunit_result_stats param_stats =3D { 0 };
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  706
> 887d85a0736ff3 Rae Moar            2023-03-08  707
> kunit_init_test(&test, test_case->name, test_case->log);
> 03806177fa4cbb Marie Zhussupova    2025-07-29  708
> __kunit_init_parent_test(test_case, &test);
> 03806177fa4cbb Marie Zhussupova    2025-07-29  709
> 529534e8cba3e6 Rae Moar            2023-07-25  710              if
> (test_case->status =3D=3D KUNIT_SKIPPED) {
> 529534e8cba3e6 Rae Moar            2023-07-25  711                      /=
*
> Test marked as skip */
> 529534e8cba3e6 Rae Moar            2023-07-25  712
> test.status =3D KUNIT_SKIPPED;
> 529534e8cba3e6 Rae Moar            2023-07-25  713
> kunit_update_stats(&param_stats, test.status);
> 44c50ed8e59936 Marie Zhussupova    2025-07-29 @714              } else if
> (!test_case->generate_params && !test.params_data.params) {
>
>   ^^^^^^^^^^^^^^^^^^^^^^^^^^
> Imagine ->generate_parms is NULL but test.params_data.params is
> non-NULL.


> 37dbb4c7c7442d David Gow           2021-11-02  715                      /=
*
> Non-parameterised test. */
> 529534e8cba3e6 Rae Moar            2023-07-25  716
> test_case->status =3D KUNIT_SKIPPED;
> 37dbb4c7c7442d David Gow           2021-11-02  717
> kunit_run_case_catch_errors(suite, test_case, &test);
> 37dbb4c7c7442d David Gow           2021-11-02  718
> kunit_update_stats(&param_stats, test.status);
> 03806177fa4cbb Marie Zhussupova    2025-07-29  719              } else if
> (test_case->status !=3D KUNIT_FAILURE) {
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  720                      /=
*
> Get initial param. */
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  721
> param_desc[0] =3D '\0';
> 8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  722                      /=
*
> TODO: Make generate_params try-catch */
> 13ee0c64bd88a3 Marie Zhussupova    2025-07-29 @723
> curr_param =3D test_case->generate_params(&test, NULL, param_desc);
>
>            ^^^^^^^^^^^^^^^^^^^^^^^^^^
> Then this could crash.
>
> I suspect that this is fine, but I bet that in the previous
> condition, just testing one would probably have been sufficient
> or maybe we could have change && to ||.
>

Hello Dan,

As of now, test.params_data.params can only be populated in a param_init
function, which can only be used if we register the test case with a
KUNIT_CASE_PARAM_WITH_INIT macro. That macro auto populates
test_case->generate_params with a function called
kunit_get_next_param_and_desc()
(which iterates over the parameter array) if the test user didn't provide
their
own generator function. So, there shouldn't be a case where
test_case->generate_params is NULL but test.params_data.params is NON-NULL.

However, to be robust, we could add a NULL check  before calling
test_case->generate_params on line 723.

Thank you!
-Marie

>
> 529534e8cba3e6 Rae Moar            2023-07-25  724
> test_case->status =3D KUNIT_SKIPPED;
> 6c738b52316c58 Rae Moar            2022-11-23  725
> kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
> 6c738b52316c58 Rae Moar            2022-11-23  726
>         "KTAP version 1\n");
> 44b7da5fcd4c99 David Gow           2021-11-02  727
> kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
> 44b7da5fcd4c99 David Gow           2021-11-02  728
>         "# Subtest: %s", test_case->name);
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  729
> 8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  730
> while (curr_param) {
>
> --
> 0-DAY CI Kernel Test Service
> https://github.com/intel/lkp-tests/wiki
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAkQn5KtGMYqEP07xvs5GR_5b591Lo%2BYPu5uT9HiduMo900Mxw%40mail.gmail.com.

--000000000000137eab063b3ef2a1
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr"><br></div><div dir=3D"lt=
r"><div dir=3D"ltr"><br></div><div dir=3D"ltr"><div dir=3D"ltr"><br></div><=
br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Thu,=
 Jul 31, 2025 at 11:58=E2=80=AFAM Dan Carpenter &lt;<a href=3D"mailto:dan.c=
arpenter@linaro.org" target=3D"_blank">dan.carpenter@linaro.org</a>&gt; wro=
te:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px =
0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">Hi Marie,<br=
>
<br>
kernel test robot noticed the following build warnings:<br>
<br>
<a href=3D"https://git-scm.com/docs/git-format-patch#_base_tree_information=
" rel=3D"noreferrer" target=3D"_blank">https://git-scm.com/docs/git-format-=
patch#_base_tree_information</a>]<br>
<br>
url:=C2=A0 =C2=A0 <a href=3D"https://github.com/intel-lab-lkp/linux/commits=
/Marie-Zhussupova/kunit-Add-parent-kunit-for-parameterized-test-context/202=
50730-033818" rel=3D"noreferrer" target=3D"_blank">https://github.com/intel=
-lab-lkp/linux/commits/Marie-Zhussupova/kunit-Add-parent-kunit-for-paramete=
rized-test-context/20250730-033818</a><br>
base:=C2=A0 =C2=A0<a href=3D"https://git.kernel.org/pub/scm/linux/kernel/gi=
t/shuah/linux-kselftest.git" rel=3D"noreferrer" target=3D"_blank">https://g=
it.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git</a> kunit<=
br>
patch link:=C2=A0 =C2=A0 <a href=3D"https://lore.kernel.org/r/2025072919364=
7.3410634-7-marievic%40google.com" rel=3D"noreferrer" target=3D"_blank">htt=
ps://lore.kernel.org/r/20250729193647.3410634-7-marievic%40google.com</a><b=
r>
patch subject: [PATCH 6/9] kunit: Enable direct registration of parameter a=
rrays to a KUnit test<br>
config: nios2-randconfig-r072-20250731 (<a href=3D"https://download.01.org/=
0day-ci/archive/20250731/202507310854.pZvIcswn-lkp@intel.com/config" rel=3D=
"noreferrer" target=3D"_blank">https://download.01.org/0day-ci/archive/2025=
0731/202507310854.pZvIcswn-lkp@intel.com/config</a>)<br>
compiler: nios2-linux-gcc (GCC) 8.5.0<br>
<br>
If you fix the issue in a separate patch/commit (i.e. not just a new versio=
n of<br>
the same patch/commit), kindly add following tags<br>
| Reported-by: kernel test robot &lt;<a href=3D"mailto:lkp@intel.com" targe=
t=3D"_blank">lkp@intel.com</a>&gt;<br>
| Reported-by: Dan Carpenter &lt;<a href=3D"mailto:dan.carpenter@linaro.org=
" target=3D"_blank">dan.carpenter@linaro.org</a>&gt;<br>
| Closes: <a href=3D"https://lore.kernel.org/r/202507310854.pZvIcswn-lkp@in=
tel.com/" rel=3D"noreferrer" target=3D"_blank">https://lore.kernel.org/r/20=
2507310854.pZvIcswn-lkp@intel.com/</a><br>
<br>
New smatch warnings:<br>
lib/kunit/test.c:723 kunit_run_tests() error: we previously assumed &#39;te=
st_case-&gt;generate_params&#39; could be null (see line 714)<br>
<br>
vim +723 lib/kunit/test.c<br>
<br>
914cc63eea6fbe Brendan Higgins=C2=A0 =C2=A0 =C2=A02019-09-23=C2=A0 681=C2=
=A0 int kunit_run_tests(struct kunit_suite *suite)<br>
914cc63eea6fbe Brendan Higgins=C2=A0 =C2=A0 =C2=A02019-09-23=C2=A0 682=C2=
=A0 {<br>
fadb08e7c7501e Arpitha Raghunandan 2020-11-16=C2=A0 683=C2=A0 =C2=A0 =C2=A0=
 char param_desc[KUNIT_PARAM_DESC_SIZE];<br>
914cc63eea6fbe Brendan Higgins=C2=A0 =C2=A0 =C2=A02019-09-23=C2=A0 684=C2=
=A0 =C2=A0 =C2=A0 struct kunit_case *test_case;<br>
acd8e8407b8fcc David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02021-08-03=
=C2=A0 685=C2=A0 =C2=A0 =C2=A0 struct kunit_result_stats suite_stats =3D { =
0 };<br>
acd8e8407b8fcc David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02021-08-03=
=C2=A0 686=C2=A0 =C2=A0 =C2=A0 struct kunit_result_stats total_stats =3D { =
0 };<br>
8631cd2cf5fbf2 Marie Zhussupova=C2=A0 =C2=A0 2025-07-29=C2=A0 687=C2=A0 =C2=
=A0 =C2=A0 const void *curr_param;<br>
914cc63eea6fbe Brendan Higgins=C2=A0 =C2=A0 =C2=A02019-09-23=C2=A0 688=C2=
=A0 <br>
c272612cb4a2f7 David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02022-07-01=
=C2=A0 689=C2=A0 =C2=A0 =C2=A0 /* Taint the kernel so we know we&#39;ve run=
 tests. */<br>
c272612cb4a2f7 David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02022-07-01=
=C2=A0 690=C2=A0 =C2=A0 =C2=A0 add_taint(TAINT_TEST, LOCKDEP_STILL_OK);<br>
c272612cb4a2f7 David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02022-07-01=
=C2=A0 691=C2=A0 <br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 692=C2=
=A0 =C2=A0 =C2=A0 if (suite-&gt;suite_init) {<br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 693=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 suite-&gt;suite_init_err =3D =
suite-&gt;suite_init(suite);<br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 694=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 if (suite-&gt;suite_init_err)=
 {<br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 695=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 k=
unit_err(suite, KUNIT_SUBTEST_INDENT<br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 696=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 &quot;# failed to initialize (%d)&quot;,=
 suite-&gt;suite_init_err);<br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 697=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 g=
oto suite_end;<br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 698=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 699=C2=
=A0 =C2=A0 =C2=A0 }<br>
1cdba21db2ca31 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 700=C2=
=A0 <br>
cae56e1740f559 Daniel Latypov=C2=A0 =C2=A0 =C2=A0 2022-04-29=C2=A0 701=C2=
=A0 =C2=A0 =C2=A0 kunit_print_suite_start(suite);<br>
914cc63eea6fbe Brendan Higgins=C2=A0 =C2=A0 =C2=A02019-09-23=C2=A0 702=C2=
=A0 <br>
fadb08e7c7501e Arpitha Raghunandan 2020-11-16=C2=A0 703=C2=A0 =C2=A0 =C2=A0=
 kunit_suite_for_each_test_case(suite, test_case) {<br>
fadb08e7c7501e Arpitha Raghunandan 2020-11-16=C2=A0 704=C2=A0 =C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 struct kunit test =3D { .param_value =3D NULL,=
 .param_index =3D 0 };<br>
acd8e8407b8fcc David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02021-08-03=
=C2=A0 705=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 struct kunit_res=
ult_stats param_stats =3D { 0 };<br>
fadb08e7c7501e Arpitha Raghunandan 2020-11-16=C2=A0 706=C2=A0 <br>
887d85a0736ff3 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2023-03-08=
=C2=A0 707=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 kunit_init_test(=
&amp;test, test_case-&gt;name, test_case-&gt;log);<br>
03806177fa4cbb Marie Zhussupova=C2=A0 =C2=A0 2025-07-29=C2=A0 708=C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 __kunit_init_parent_test(test_case, =
&amp;test);<br>
03806177fa4cbb Marie Zhussupova=C2=A0 =C2=A0 2025-07-29=C2=A0 709=C2=A0 <br=
>
529534e8cba3e6 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2023-07-25=
=C2=A0 710=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 if (test_case-&g=
t;status =3D=3D KUNIT_SKIPPED) {<br>
529534e8cba3e6 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2023-07-25=
=C2=A0 711=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 /* Test marked as skip */<br>
529534e8cba3e6 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2023-07-25=
=C2=A0 712=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 test.status =3D KUNIT_SKIPPED;<br>
529534e8cba3e6 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2023-07-25=
=C2=A0 713=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 kunit_update_stats(&amp;param_stats, test.status);<br>
44c50ed8e59936 Marie Zhussupova=C2=A0 =C2=A0 2025-07-29 @714=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } else if (!test_case-&gt;generate_param=
s &amp;&amp; !test.params_data.params) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ^^^^^^^^^^^^^^^^^^^^^^^^^^<br=
>
Imagine -&gt;generate_parms is NULL but test.params_data.params is<br>
non-NULL.</blockquote><blockquote class=3D"gmail_quote" style=3D"margin:0px=
 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">
<br>
37dbb4c7c7442d David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02021-11-02=
=C2=A0 715=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 /* Non-parameterised test. */<br>
529534e8cba3e6 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2023-07-25=
=C2=A0 716=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 test_case-&gt;status =3D KUNIT_SKIPPED;<br>
37dbb4c7c7442d David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02021-11-02=
=C2=A0 717=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 kunit_run_case_catch_errors(suite, test_case, &amp;test);<br>
37dbb4c7c7442d David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02021-11-02=
=C2=A0 718=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 kunit_update_stats(&amp;param_stats, test.status);<br>
03806177fa4cbb Marie Zhussupova=C2=A0 =C2=A0 2025-07-29=C2=A0 719=C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 } else if (test_case-&gt;status !=3D=
 KUNIT_FAILURE) {<br>
fadb08e7c7501e Arpitha Raghunandan 2020-11-16=C2=A0 720=C2=A0 =C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 /* Get initial par=
am. */<br>
fadb08e7c7501e Arpitha Raghunandan 2020-11-16=C2=A0 721=C2=A0 =C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 param_desc[0] =3D =
&#39;\0&#39;;<br>
8631cd2cf5fbf2 Marie Zhussupova=C2=A0 =C2=A0 2025-07-29=C2=A0 722=C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 /* TODO:=
 Make generate_params try-catch */<br>
13ee0c64bd88a3 Marie Zhussupova=C2=A0 =C2=A0 2025-07-29 @723=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 curr_param =
=3D test_case-&gt;generate_params(&amp;test, NULL, param_desc);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0^^^^^^^^^^^^^^^^^^^^^^^^^^<br>
Then this could crash.<br>
<br>
I suspect that this is fine, but I bet that in the previous<br>
condition, just testing one would probably have been sufficient<br>
or maybe we could have change &amp;&amp; to ||.<br></blockquote><div><br></=
div><div>Hello Dan,</div><div><br></div><div>As of now, test.params_data.pa=
rams can only be populated in a param_init</div><div>function, which can on=
ly be used if we register the test case with a=C2=A0</div><div>KUNIT_CASE_P=
ARAM_WITH_INIT macro. That macro auto populates=C2=A0</div><div>test_case-&=
gt;generate_params with a function called kunit_get_next_param_and_desc()=
=C2=A0</div><div>(which iterates over the parameter array) if the test user=
 didn&#39;t provide their=C2=A0</div><div>own generator function. So, there=
 shouldn&#39;t be a case where=C2=A0</div><div>test_case-&gt;generate_param=
s is NULL but test.params_data.params is NON-NULL.=C2=A0</div><div><br></di=
v><div>However, to be robust, we could add a NULL check=C2=A0 before callin=
g=C2=A0</div><div>test_case-&gt;generate_params on line 723.</div><div><br>=
</div><div>Thank you!</div><div>-Marie</div><blockquote class=3D"gmail_quot=
e" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)=
;padding-left:1ex">
<br>
529534e8cba3e6 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2023-07-25=
=C2=A0 724=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 test_case-&gt;status =3D KUNIT_SKIPPED;<br>
6c738b52316c58 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2022-11-23=
=C2=A0 725=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 kunit_log(KERN_INFO, &amp;test, KUNIT_SUBTEST_INDENT KUNIT_SU=
BTEST_INDENT<br>
6c738b52316c58 Rae Moar=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 2022-11-23=
=C2=A0 726=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 &quot;KTAP version 1\n&quo=
t;);<br>
44b7da5fcd4c99 David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02021-11-02=
=C2=A0 727=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 kunit_log(KERN_INFO, &amp;test, KUNIT_SUBTEST_INDENT KUNIT_SU=
BTEST_INDENT<br>
44b7da5fcd4c99 David Gow=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A02021-11-02=
=C2=A0 728=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 &quot;# Subtest: %s&quot;,=
 test_case-&gt;name);<br>
fadb08e7c7501e Arpitha Raghunandan 2020-11-16=C2=A0 729=C2=A0 <br>
8631cd2cf5fbf2 Marie Zhussupova=C2=A0 =C2=A0 2025-07-29=C2=A0 730=C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 while (c=
urr_param) {<br>
<br>
-- <br>
0-DAY CI Kernel Test Service<br>
<a href=3D"https://github.com/intel/lkp-tests/wiki" rel=3D"noreferrer" targ=
et=3D"_blank">https://github.com/intel/lkp-tests/wiki</a><br>
<br>
</blockquote></div></div>
</div>
</div>
</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CAAkQn5KtGMYqEP07xvs5GR_5b591Lo%2BYPu5uT9HiduMo900Mxw%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CAAkQn5KtGMYqEP07xvs5GR_5b591Lo%2BYPu5uT9HiduMo900Mxw%40mail=
.gmail.com</a>.<br />

--000000000000137eab063b3ef2a1--
