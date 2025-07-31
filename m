Return-Path: <kasan-dev+bncBC65ZG75XIPRBKVFV3CAMGQEAY7YPGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 603CCB17468
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 17:58:36 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-73e797ccc81sf388504a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 08:58:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753977515; cv=pass;
        d=google.com; s=arc-20240605;
        b=eyRPTGGP9nFZ0ffZ8z1Zi34V2wk4de0M/22h5sIirE4fT3NAHtaC8i7tByQRa90Zmb
         99rg7xdNXeHnry1NpcnvpksGhfMHaMVAnAk0Q0Tmueq3+WIkHR3qS0WHzwPUt8nqDiXp
         5Xpx2bWd21BOOeoyFfNdl6wcSPGzqhXvXkMu3iaZA6td/Z5UYJVb4eUa9vR0hWGZh5Kp
         a/AZkLeI1iC/nRq9cSL+0QgqaUEi8Qv8Ldh65t4kDlIVkm5cko68LrgTniu4F/vyYVyK
         Y9aHMh6VnaPJ4On2Kzuy8Z2T34OlsSn3qDZJfL7YlPRwWCzzOTweiXHjRJ70QRgNn456
         sh4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eFlNpVsaL3xDBTPZgtLMxVAEy1Th/wobY9Ir1HhwyI0=;
        fh=7ByX6EQQZ3rQFsaVNA1P+1tyaNCjTDvOJQi/lIx7aNo=;
        b=d0W1pQAyNXNmemL+RkthPBQGeFNe+JwL2+x4OVasEyWw2W1Au6Jxa30pvtpZP9DdtH
         BfCMySQbMIKpeZp4JSkrXJWyIg37ALuwdvLOvVwoEv6PxpPe2s9pCn5cX2XsWzlHORtk
         svwXFWkTbQKNbWIJ3V8YKBNOhEM8AxfUCmh2D6OaZEhXVWVFzcfKtjABWAakEJ2uhFc+
         PEzO/NoL8wbQu53pW5KhKlNkt6luPgVZV2tvQ2e08woNJknMQ7h6ua5xpMduNZyOnrcI
         DpNNH3cd3jyVCJS0Wg/Dp+kw7EF5QmrVIVwN3rvU1JwVQSBqsysQ3kTWnnWi9LyIvyuv
         hVWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=oXyvrd7L;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753977515; x=1754582315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eFlNpVsaL3xDBTPZgtLMxVAEy1Th/wobY9Ir1HhwyI0=;
        b=VivEwxLt5H1yuNuErjwvy7Qu/HXNt56WLLpHKW3Om72fDcu9HGAf81CIrIjyhnuutV
         sZDf+RMMHprc+gSWOYBYi2UyxeA4qqtgMbcF5UgvD6Nc9xwPer8rAyyr0rf/NQDQ1ZqL
         xSCzkv0ifVK6wzDQo0RJ6xh1FFhlsf7xBvi93d+TphqXoIwecWLV16YRD037kiBJfZD6
         RIKySwTmdWmmnXu1ub3cnCxHXkvtP0njbcFvFab2vwKFmaH037x8RhUcZlg5ime8+VyN
         Me5ODlz2VIO+6db0AdiDV2OmeworvHo7adoA61bLmp17bpj9jONbD5fxgBxE3E2DfKtK
         IRRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753977515; x=1754582315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eFlNpVsaL3xDBTPZgtLMxVAEy1Th/wobY9Ir1HhwyI0=;
        b=AVy6oZj799rZfna7Lp1DuYzTREhx1ln8oghu/XBlPrdlFa6PrjOdyUyeaEmCkpcTFk
         UJO3acUDImw3eW1lj9AtwnPlD2/AbYAx+YTi1D35lM9I9ByvVP+dNuhxGovvEO3wg7gl
         gENs/d1hWGKFKqaXd0cfxvAQdu61wdN89H+yW6Dao1SivVxwP+Nfcvbi9NunFu2hQbyI
         lRkXcEvloCjCcEh6Z61q8mltljRm/SyG9d607E14p39o6oyqHbm+2mcx/j/hmoCq+9ep
         7oJBmH/wK+e8uABUvN7F6VWrSBywgpvfKjXIqJEmUWZlFVahExMPeWkMJsxqsDbP6aCr
         iA3w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6C7jJb4pikoej7Jeq2JoqWDnHLocxi4wxWFBMSSb5J1luJAlJzxBkH3w+6ktSLt0lDazJ/Q==@lfdr.de
X-Gm-Message-State: AOJu0YxesEy2rAgmWz5/+KSuFGTX2LAkyK7xw98PwWgPtkKax/319Z4P
	FcwNELWakxJfUFjB4roC5Z0Y+l5ocqJ5stWbCwsO8/fCtNaarJMId6iT
X-Google-Smtp-Source: AGHT+IHK8Qz3Uv8lz9fcfb4ysQnTbK1PkwRXFfhUczBdvwU/0wL7etsPBug1RCHg4xb326mFefFVPQ==
X-Received: by 2002:a05:6808:5093:b0:3fe:b1fd:527f with SMTP id 5614622812f47-431994c5dbamr4034615b6e.1.1753977514583;
        Thu, 31 Jul 2025 08:58:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf+fAHgIAxlyJvaHRHLbED1AdxIhwqp9EcLBbGQCGKoKg==
Received: by 2002:a05:6820:7819:b0:611:730c:a293 with SMTP id
 006d021491bc7-6196f7b8f01ls335294eaf.0.-pod-prod-02-us; Thu, 31 Jul 2025
 08:58:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvmESUIeREjCExl0fAuIBlEROjyw7idnlQ6+SRG7/f/6rgRs2wOA/bQaQiHZvDmx+/aVMOBPtDPJE=@googlegroups.com
X-Received: by 2002:a05:6830:6007:b0:73e:8b47:a3cc with SMTP id 46e09a7af769-74177c87481mr5602961a34.17.1753977513658;
        Thu, 31 Jul 2025 08:58:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753977513; cv=none;
        d=google.com; s=arc-20240605;
        b=i3dxWIKwqw1mkpaT1YuG/7wmrjzNlYP+EySUa8K5Bk7pssmiknkN1U113zgjPnjd1k
         WvUaDBK07KHnHK2zasaoS55py2BSKnjEhP+uHaGZ/EoIpTE9ihSSF0Nq5js/lcz9AzqZ
         pTajolzI4K4tgI9OfaktUvRsiHJAyXrfI2lPnn6ZGQG76cMvl4lZrGFYFi9Uy8a/gXwJ
         JMiThh75svvWn5cznX6bxZl24vf+Ipz+MIAlOvIhX5DsijpBMY5+/tQYKUZA3OaeSCA3
         EmBs79wmhFUvltBVOYnGp/d8x38EVzWwT5/zHot0mLGdeErN5H+rUdQk/Su1qjRWwJDm
         Na+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jKKboCZbQOuMPhW93A7UzwoZX1h4N/abO1uaKk6KKOQ=;
        fh=MuMiIB3YD+BNBVIUgiz6MyACMhWn++OCH1gdG1IuZeE=;
        b=gdTg/lZxcIeMOXKN7Rins0BqkR3vYpnK7+PHMZSoJLqNXom+aunMrdJC8N3FpFW/QF
         izDtAxXbRD9g/Y6BpU7hGdD84oytz1ALiE24sadmcCpTQ37ap4dvqg5OInHTWiFD+pHO
         g3/uFExktOrjrCcODRiAuvwFqZXpFZ8Gch0fV4Rl/46YupZPyVLUdKAaAOSS0Wy5Sxdc
         yjsH+17r3boxTa3joLMvk6AxZwYEJJDmMCOjyhAkGXAD+0REyzGVscVBsnHASiREwruV
         fEOkuNzTcdz8MHrSQoUdRhuqTt+2394N/P+3ClT4CojMBrD6EuuPtyhzhqkKkaOxWYad
         ukJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=oXyvrd7L;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-vs1-xe33.google.com (mail-vs1-xe33.google.com. [2607:f8b0:4864:20::e33])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-741869ec354si96098a34.0.2025.07.31.08.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 08:58:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.carpenter@linaro.org designates 2607:f8b0:4864:20::e33 as permitted sender) client-ip=2607:f8b0:4864:20::e33;
Received: by mail-vs1-xe33.google.com with SMTP id ada2fe7eead31-4fc1094c24eso423677137.0
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 08:58:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUO/O2F1zargcscxosZdSkCKCkaosYsbushY2jVQfQE+2A/vy/LzM9zRsgQyZIkIyo9WrCO8vMUA8Q=@googlegroups.com
X-Gm-Gg: ASbGncvIRkCR1EYuWtozBX8vHtujyc90yzvW0wGEvPn2wJHFuYR4JtZ2NY+rOhHk6Fx
	iuKc1QFt5y6JBLF5ltYL41sxi37UxvHQpPX4+ZjBqy2dQC/zmdPtJyihM2I4I30igVtVzCgf+RA
	abs+z9PunoQOMdVDeBH783c8zU0NB8tYNoAIDENzJsTFB5MRr+aBg+q/fsCUSCV6+G2DMaZf9qZ
	fC84DRbfVz2pAoELT5HKJxrnbV5gEIzVC1SgMJPSbNDf+urM6ca039icxeGtYOeMpnc56RZERVF
	OfHVSajeu3VByRTr7qytEY6uB9CUk7pE10uSX5SQ8EIVA7ZNaBZlnqXlJ92DJErA0Jbf8VcJxNd
	T3th3bsAtFwG+Ox39u28MAeGTXLE=
X-Received: by 2002:a05:6102:5686:b0:4e7:3e76:cd21 with SMTP id ada2fe7eead31-4fbe7f376f5mr4909961137.9.1753977512820;
        Thu, 31 Jul 2025 08:58:32 -0700 (PDT)
Received: from localhost ([196.207.164.177])
        by smtp.gmail.com with ESMTPSA id a1e0cc1a2514c-88d8f422459sm431284241.21.2025.07.31.08.58.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Jul 2025 08:58:32 -0700 (PDT)
Date: Thu, 31 Jul 2025 18:58:28 +0300
From: Dan Carpenter <dan.carpenter@linaro.org>
To: oe-kbuild@lists.linux.dev, Marie Zhussupova <marievic@google.com>,
	rmoar@google.com, davidgow@google.com, shuah@kernel.org,
	brendan.higgins@linux.dev
Cc: lkp@intel.com, oe-kbuild-all@lists.linux.dev, elver@google.com,
	dvyukov@google.com, lucas.demarchi@intel.com,
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com,
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org,
	Marie Zhussupova <marievic@google.com>
Subject: Re: [PATCH 6/9] kunit: Enable direct registration of parameter
 arrays to a KUnit test
Message-ID: <5683507a-dacc-4e46-893f-d1e775d2ef22@suswa.mountain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250729193647.3410634-7-marievic@google.com>
X-Original-Sender: dan.carpenter@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=oXyvrd7L;       spf=pass
 (google.com: domain of dan.carpenter@linaro.org designates
 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

Hi Marie,

kernel test robot noticed the following build warnings:

https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Marie-Zhussupova/kunit-Add-parent-kunit-for-parameterized-test-context/20250730-033818
base:   https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git kunit
patch link:    https://lore.kernel.org/r/20250729193647.3410634-7-marievic%40google.com
patch subject: [PATCH 6/9] kunit: Enable direct registration of parameter arrays to a KUnit test
config: nios2-randconfig-r072-20250731 (https://download.01.org/0day-ci/archive/20250731/202507310854.pZvIcswn-lkp@intel.com/config)
compiler: nios2-linux-gcc (GCC) 8.5.0

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
| Closes: https://lore.kernel.org/r/202507310854.pZvIcswn-lkp@intel.com/

New smatch warnings:
lib/kunit/test.c:723 kunit_run_tests() error: we previously assumed 'test_case->generate_params' could be null (see line 714)

vim +723 lib/kunit/test.c

914cc63eea6fbe Brendan Higgins     2019-09-23  681  int kunit_run_tests(struct kunit_suite *suite)
914cc63eea6fbe Brendan Higgins     2019-09-23  682  {
fadb08e7c7501e Arpitha Raghunandan 2020-11-16  683  	char param_desc[KUNIT_PARAM_DESC_SIZE];
914cc63eea6fbe Brendan Higgins     2019-09-23  684  	struct kunit_case *test_case;
acd8e8407b8fcc David Gow           2021-08-03  685  	struct kunit_result_stats suite_stats = { 0 };
acd8e8407b8fcc David Gow           2021-08-03  686  	struct kunit_result_stats total_stats = { 0 };
8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  687  	const void *curr_param;
914cc63eea6fbe Brendan Higgins     2019-09-23  688  
c272612cb4a2f7 David Gow           2022-07-01  689  	/* Taint the kernel so we know we've run tests. */
c272612cb4a2f7 David Gow           2022-07-01  690  	add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
c272612cb4a2f7 David Gow           2022-07-01  691  
1cdba21db2ca31 Daniel Latypov      2022-04-29  692  	if (suite->suite_init) {
1cdba21db2ca31 Daniel Latypov      2022-04-29  693  		suite->suite_init_err = suite->suite_init(suite);
1cdba21db2ca31 Daniel Latypov      2022-04-29  694  		if (suite->suite_init_err) {
1cdba21db2ca31 Daniel Latypov      2022-04-29  695  			kunit_err(suite, KUNIT_SUBTEST_INDENT
1cdba21db2ca31 Daniel Latypov      2022-04-29  696  				  "# failed to initialize (%d)", suite->suite_init_err);
1cdba21db2ca31 Daniel Latypov      2022-04-29  697  			goto suite_end;
1cdba21db2ca31 Daniel Latypov      2022-04-29  698  		}
1cdba21db2ca31 Daniel Latypov      2022-04-29  699  	}
1cdba21db2ca31 Daniel Latypov      2022-04-29  700  
cae56e1740f559 Daniel Latypov      2022-04-29  701  	kunit_print_suite_start(suite);
914cc63eea6fbe Brendan Higgins     2019-09-23  702  
fadb08e7c7501e Arpitha Raghunandan 2020-11-16  703  	kunit_suite_for_each_test_case(suite, test_case) {
fadb08e7c7501e Arpitha Raghunandan 2020-11-16  704  		struct kunit test = { .param_value = NULL, .param_index = 0 };
acd8e8407b8fcc David Gow           2021-08-03  705  		struct kunit_result_stats param_stats = { 0 };
fadb08e7c7501e Arpitha Raghunandan 2020-11-16  706  
887d85a0736ff3 Rae Moar            2023-03-08  707  		kunit_init_test(&test, test_case->name, test_case->log);
03806177fa4cbb Marie Zhussupova    2025-07-29  708  		__kunit_init_parent_test(test_case, &test);
03806177fa4cbb Marie Zhussupova    2025-07-29  709  
529534e8cba3e6 Rae Moar            2023-07-25  710  		if (test_case->status == KUNIT_SKIPPED) {
529534e8cba3e6 Rae Moar            2023-07-25  711  			/* Test marked as skip */
529534e8cba3e6 Rae Moar            2023-07-25  712  			test.status = KUNIT_SKIPPED;
529534e8cba3e6 Rae Moar            2023-07-25  713  			kunit_update_stats(&param_stats, test.status);
44c50ed8e59936 Marie Zhussupova    2025-07-29 @714  		} else if (!test_case->generate_params && !test.params_data.params) {
                                                                            ^^^^^^^^^^^^^^^^^^^^^^^^^^
Imagine ->generate_parms is NULL but test.params_data.params is
non-NULL.

37dbb4c7c7442d David Gow           2021-11-02  715  			/* Non-parameterised test. */
529534e8cba3e6 Rae Moar            2023-07-25  716  			test_case->status = KUNIT_SKIPPED;
37dbb4c7c7442d David Gow           2021-11-02  717  			kunit_run_case_catch_errors(suite, test_case, &test);
37dbb4c7c7442d David Gow           2021-11-02  718  			kunit_update_stats(&param_stats, test.status);
03806177fa4cbb Marie Zhussupova    2025-07-29  719  		} else if (test_case->status != KUNIT_FAILURE) {
fadb08e7c7501e Arpitha Raghunandan 2020-11-16  720  			/* Get initial param. */
fadb08e7c7501e Arpitha Raghunandan 2020-11-16  721  			param_desc[0] = '\0';
8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  722  			/* TODO: Make generate_params try-catch */
13ee0c64bd88a3 Marie Zhussupova    2025-07-29 @723  			curr_param = test_case->generate_params(&test, NULL, param_desc);
                                                                                     ^^^^^^^^^^^^^^^^^^^^^^^^^^
Then this could crash.

I suspect that this is fine, but I bet that in the previous
condition, just testing one would probably have been sufficient
or maybe we could have change && to ||.

529534e8cba3e6 Rae Moar            2023-07-25  724  			test_case->status = KUNIT_SKIPPED;
6c738b52316c58 Rae Moar            2022-11-23  725  			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
6c738b52316c58 Rae Moar            2022-11-23  726  				  "KTAP version 1\n");
44b7da5fcd4c99 David Gow           2021-11-02  727  			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
44b7da5fcd4c99 David Gow           2021-11-02  728  				  "# Subtest: %s", test_case->name);
fadb08e7c7501e Arpitha Raghunandan 2020-11-16  729  
8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  730  			while (curr_param) {

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5683507a-dacc-4e46-893f-d1e775d2ef22%40suswa.mountain.
