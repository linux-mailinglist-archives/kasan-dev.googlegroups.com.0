Return-Path: <kasan-dev+bncBDV37XP3XYDRBSEUYLCQMGQEONNFODI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 94DB3B3A708
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 18:56:41 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30cce8f9e59sf1449241fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:56:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756400200; cv=pass;
        d=google.com; s=arc-20240605;
        b=PW6nKDdzh8TIYuisG4O2/Wr58GoJbvijfSOkPHqrOYE41REMjDeaKg3zdz/WoWijSG
         zWd5G7OpW1teck6a6Cr4hmeJiZ1PiowqPcE4R8CU5xiPT7321oirunq4YLAq9PvaQ+7v
         9VRAlC+Wf8Jy4yWrXuDgxZ/U5MrMT2hmg2jbZyNEU6ps0e8Uij/giLd3KiikmAs3bmPH
         JEmz+siHbQ9tic9mWcSGc2fE9pne4on9HdcswXQnmnQxKTu2Vci2l96Ya/PPNKWrK5lk
         N9nMHdo5tPGQbnSC0zdlOyDUgs6m3MSFjbO7gnz1JEDYCTvRM5dIMG3vk8xBba7IDDAO
         E1hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S8JVJluuMFM0gIksx/HvkHpdxaA4mEsMXdE2UzIyDw4=;
        fh=wJfLag51a28Va68iKeHfMkbeC+fgY5tiEd82HTVi1Sw=;
        b=SyZE5RizxupZp7CL5AmL9rQ5opKSorqNdRseYvTyA2YbbS5cJPlwmN+iU9018XTNf7
         u6x5gJ9d+bVHYKKxFDCXx0/ttboIUi0dI5tuHMw0WKDnN+QyitjsXsdJx0otxvvxPhas
         LKhXZGykou/K1CyfTM33NQiHSfigxWFP0v/YAYqWxLKGEIjUFMKeuMZIgTM1UXAPzSiZ
         zU7ktilIkukc6W2w7T97lGbpkt3PApU0Y2YdWO5kFvntmIsU/Jd76XmU0U07XAe6X4zK
         MZj1CVztfnCMdnoR5RZZ5DkKrgqn7wSfxqLjbbHHGgbAL8chQDp0wctBdJ/0DFrICRNH
         jZRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756400200; x=1757005000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S8JVJluuMFM0gIksx/HvkHpdxaA4mEsMXdE2UzIyDw4=;
        b=vuqIGkKC8FVOu0jyApvrJ00pV6mJvpcGya2yOYCL8at8R5358Q2s41vfyeXLT4ldVx
         IVUd06lebezurrQG0+5T9iKZTi25AuLIdTfXIaQY7koarvBMnQh6Hfa3FnSIVKj5WeYr
         Y6eE+0JS1pn4BUvUCYBT7wXi+o7r0lFOKFusq1LF/gD5lxg+SkISGxqkqx87SpCefa74
         2WFBVdiQ8xPdEpbR8WPH2wuTh7u2OGfZ3/Uvc/nc4k8dmMC3fSS/usILrcqwFPYo2FJL
         dtgDzYGWe/3GSzxYOseU+Z9gzlX7vwAM6xbfAFA2S8/x4/akcsyT7Dyf5aVsum/WVSLR
         DRog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756400200; x=1757005000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S8JVJluuMFM0gIksx/HvkHpdxaA4mEsMXdE2UzIyDw4=;
        b=V99G2iyHQoDLIynoWuza7HarYtoF4YMa/MHpbtBC35HNfeln+9J+UQuIp/WbgQulkH
         NtE/pX/dmfRsOgJSSJy57n6l1xzUvzAzwNilrS8nFLRVXDeRyFHGa3CHz2oatYKzscvh
         gc/+SH9kWEkSN+/mwzeYIKRKCxAJtQBcQFhE7UYmLoaZLpw5THAgLP0boCLMbUKmqjNo
         0yt/lV5nzIPK5fmOwKFICUcsnXBGywsQVsME9e/Xy6CuGJ0Z2SfEvHwfl/eoZNpsZ2gc
         vKme9EbaaXcJk+e6ccQQWE64cyLeqUa6mb+LGp7Ehy5z3AHvNcaq+MA0e0KptzbYUl+o
         yBZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLebmwY5krKd1UAHEoGtyuIgEQ0jV/JgTYwhVl0EjS3ug4kmM2Fpe0Nz5/1WgbySKcASwBWg==@lfdr.de
X-Gm-Message-State: AOJu0YxruQhkJ+/UI3HW88Ijg9VzZDMWIdaKJ0v4Gd04+aQ8HmZW2OLl
	5w8U9mbB/kG4vn/3F8elFrSyyug0vDpEYsZqAeE4SGsxqUCQyQ/Rb1qc
X-Google-Smtp-Source: AGHT+IHG+TWuKIqxpbWpGY9e5IDMQSPmac8Cg5HWSxnIDEhicqYBM/kz7uJZxxhZ3da+adLE+W7Uug==
X-Received: by 2002:a05:6870:8e17:b0:314:9684:fe0e with SMTP id 586e51a60fabf-314dcee1f22mr14169486fac.41.1756400200286;
        Thu, 28 Aug 2025 09:56:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeOw61VS73LRi7zvooHRS67ZbIdHb/tn+Ym6FP/KEHJMg==
Received: by 2002:a05:6871:4396:b0:30b:8494:7c57 with SMTP id
 586e51a60fabf-3159603da1els512321fac.2.-pod-prod-09-us; Thu, 28 Aug 2025
 09:56:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2wrtM8fdRflfJbWkuVLeal9GvQ2nXybo5xpzV1SuKFShNldccS7o3nNzD5iZRkU4thcOWH1fYFi8=@googlegroups.com
X-Received: by 2002:a05:6871:bb13:b0:315:2a49:7e5c with SMTP id 586e51a60fabf-3152a498f53mr8193958fac.20.1756400199079;
        Thu, 28 Aug 2025 09:56:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756400199; cv=none;
        d=google.com; s=arc-20240605;
        b=j2CmZf2YSoy8co8OmhEM5ztcjW9Bkes9aX9ODm9LTMCnF6BykRzqZUCl7OHNNlbIzw
         6eIRSWHT/4Cr9IRFn5JqkzQU2Yyfr+/J3FDuLivYGwuOQarlLr8d8J5H78qIp5aEidNH
         BETwY8f6mX95xzMehmnsEOOzonliWYtGF8jYVmdg1ZOhHV6MuLEity916m+au3XVQuGC
         GrqRhNHGvc6XsGHGaL77gT94AHkZXs748yeR7aYonXtjdgt2J9d7NNnjTaUTt7Nf/krX
         6WONqNb6lIySaMmpyM32VU1pAskAPae3ocPR45TYsNgLMVaZPEfeuq+Yh6SyAYTZNxLN
         ptfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=+gl4DEZL9r5wfJ+Kye0Nn5LJQn0rT0WD0H1sEBOTbu4=;
        fh=CYC8GMfZK2Maa0e+XtHH3hYis3l25ddatN3NS0cHm/o=;
        b=BcohxVauW1XDtrdYGK6fpYlmn8WGDhheJ8uKE8ImSlaU+WADaJq8li57rvS1LOKGCW
         TFr24ME8qGD9s2qfdR49RfJBY4lGh7hLJ6AdH86KbU3C/6QLgfZMZYawDcgwujvwTN1E
         zm7Ra3/v4LmdVZve0fUj3zVDnL6k9l/OWMqU2pVErW9u582fHuyYtoztGevlhm/HlhY3
         a03Kl1vmXoJlOLFfBi1vKnP0Q7nMgHPFlhjfDxS+/+IcjHd52ItQp8oBzf9ZF0MPjZtI
         1qiweeHzq0da080KEzPqjtLk2I4rHZipiwDh+MiP6LtEDHXKvz3YkZTS8Zn+LU3Ag01A
         pGIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-315afb716f7si21936fac.1.2025.08.28.09.56.38;
        Thu, 28 Aug 2025 09:56:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 269EB1688;
	Thu, 28 Aug 2025 09:56:30 -0700 (PDT)
Received: from J2N7QTR9R3 (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D576C3F738;
	Thu, 28 Aug 2025 09:56:35 -0700 (PDT)
Date: Thu, 28 Aug 2025 17:56:30 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: David Gow <davidgow@google.com>
Cc: Marie Zhussupova <marievic@google.com>, marievictoria875@gmail.com,
	rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev,
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com,
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com,
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org,
	Stephen Rothwell <sfr@canb.auug.org.au>
Subject: Re: [PATCH v4 0/7] kunit: Refactor and extend KUnit's parameterized
 testing framework
Message-ID: <aLCKPieOlM8dD858@J2N7QTR9R3>
References: <20250826091341.1427123-1-davidgow@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250826091341.1427123-1-davidgow@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Aug 26, 2025 at 05:13:30PM +0800, David Gow wrote:
> Hi all,
> 
> This is a new version of Marie's patch series, with a couple of extra
> fixes squashed in, notably:
> - drm/xe/tests: Fix some additional gen_params signatures
> https://lore.kernel.org/linux-kselftest/20250821135447.1618942-1-davidgow@google.com/
> - kunit: Only output a test plan if we're using kunit_array_gen_params
> https://lore.kernel.org/linux-kselftest/20250821135447.1618942-2-davidgow@google.com/
> 
> These should fix the issues found in linux-next here:
> https://lore.kernel.org/linux-next/20250818120846.347d64b1@canb.auug.org.au/
> 
> These changes only affect patches 3 and 4 of the series, the others are
> unchanged from v3.
> 
> Thanks, everyone, and sorry for the inconvenience!

Thanks for this!

I had a go at converting some of my aarch64 instruction encoding tests
over to this, and having the ability to dynamically generate the params
array before iterating over the case makes that much easier to handle.

FWIW, for the series:

Acked-by: Mark Rutland <mark.rutland@arm.com>

I'll see about getting those converted over and posted once this is in.

Mark.

> 
> Cheers,
> -- David
> 
> ---
> 
> Hello!
> 
> KUnit offers a parameterized testing framework, where tests can be
> run multiple times with different inputs. However, the current
> implementation uses the same `struct kunit` for each parameter run.
> After each run, the test context gets cleaned up, which creates
> the following limitations:
> 
> a. There is no way to store resources that are accessible across
>    the individual parameter runs.
> b. It's not possible to pass additional context, besides the previous
>    parameter (and potentially anything else that is stored in the current
>    test context), to the parameter generator function.
> c. Test users are restricted to using pre-defined static arrays
>    of parameter objects or generate_params() to define their
>    parameters. There is no flexibility to make a custom dynamic
>    array without using generate_params(), which can be complex if
>    generating the next parameter depends on more than just the single
>    previous parameter.
> 
> This patch series resolves these limitations by:
> 
> 1. [P 1] Giving each parameterized run its own `struct kunit`. It will
>    remove the need to manage state, such as resetting the `test->priv`
>    field or the `test->status_comment` after every parameter run.
> 
> 2. [P 1] Introducing parameterized test context available to all
>    parameter runs through the parent pointer of type `struct kunit`.
>    This context won't be used to execute any test logic, but will
>    instead be used for storing shared resources. Each parameter run
>    context will have a reference to that parent instance and thus,
>    have access to those resources.
> 
> 3. [P 2] Introducing param_init() and param_exit() functions that can
>    initialize and exit the parameterized test context. They will run once
>    before and after the parameterized test. param_init() can be used to add
>    resources to share between parameter runs, pass parameter arrays, and
>    any other setup logic. While param_exit() can be used to clean up
>    resources that were not managed by the parameterized test, and
>    any other teardown logic.
> 
> 4. [P 3] Passing the parameterized test context as an additional argument
>    to generate_params(). This provides generate_params() with more context,
>    making parameter generation much more flexible. The generate_params()
>    implementations in the KCSAN and drm/xe tests have been adapted to match
>    the new function pointer signature.
> 
> 5. [P 4] Introducing a `params_array` field in `struct kunit`. This will
>    allow the parameterized test context to have direct storage of the
>    parameter array, enabling features like using dynamic parameter arrays
>    or using context beyond just the previous parameter. This will also
>    enable outputting the KTAP test plan for a parameterized test when the
>    parameter count is available.
> 
> Patches 5 and 6 add examples tests to lib/kunit/kunit-example-test.c to
> showcase the new features and patch 7 updates the KUnit documentation
> to reflect all the framework changes.
> 
> Thank you!
> -Marie
> 
> ---
> 
> Changes in v4:
> 
> Link to v3 of this patch series:
> https://lore.kernel.org/linux-kselftest/20250815103604.3857930-1-marievic@google.com/
> 
> - Fixup the signatures of some more gen_params functions in the drm/xe
>   driver.
> - Only print a KTAP test plan if a parameterised test is using the
>   built-in kunit_array_gen_params generating function, fixing the issues
>   with generator functions which skip array elements.
> 
> Changes in v3:
> 
> Link to v2 of this patch series:
> https://lore.kernel.org/all/20250811221739.2694336-1-marievic@google.com/
> 
> - Added logic for skipping the parameter runs and updating the test statistics
>   when parameterized test initialization fails.
> - Minor changes to the documentation.
> - Commit message formatting.
> 
> Changes in v2:
> 
> Link to v1 of this patch series:
> https://lore.kernel.org/all/20250729193647.3410634-1-marievic@google.com/
> 
> - Establish parameterized testing terminology:
>    - "parameterized test" will refer to the group of all runs of a single test
>      function with different parameters.
>    - "parameter run" will refer to the execution of the test case function with
>      a single parameter.
>    - "parameterized test context" is the `struct kunit` that holds the context
>      for the entire parameterized test.
>    - "parameter run context" is the `struct kunit` that holds the context of the
>      individual parameter run.
>    - A test is defined to be a parameterized tests if it was registered with a
>      generator function.
> - Make comment edits to reflect the established terminology.
> - Require users to manually pass kunit_array_gen_params() to
>   KUNIT_CASE_PARAM_WITH_INIT() as the generator function, unless they want to
>   provide their own generator function, if the parameter array was registered
>   in param_init(). This is to be consistent with the definition of a
>   parameterized test, i.e. generate_params() is never NULL if it's
>   a parameterized test.
> - Change name of kunit_get_next_param_and_desc() to
>   kunit_array_gen_params().
> - Other minor function name changes such as removing the "__" prefix in front
>   of internal functions.
> - Change signature of get_description() in `struct params_array` to accept
>   the parameterized test context, as well.
> - Output the KTAP test plan for a parameterized test when the parameter count
>   is available.
> - Cover letter was made more concise.
> - Edits to the example tests.
> - Fix bug of parameterized test init/exit logic being done outside of the
>   parameterized test check.
> - Fix bugs identified by the kernel test robot.
> 
> ---
> 
> Marie Zhussupova (7):
>   kunit: Add parent kunit for parameterized test context
>   kunit: Introduce param_init/exit for parameterized test context
>     management
>   kunit: Pass parameterized test context to generate_params()
>   kunit: Enable direct registration of parameter arrays to a KUnit test
>   kunit: Add example parameterized test with shared resource management
>     using the Resource API
>   kunit: Add example parameterized test with direct dynamic parameter
>     array setup
>   Documentation: kunit: Document new parameterized test features
> 
>  Documentation/dev-tools/kunit/usage.rst | 342 +++++++++++++++++++++++-
>  drivers/gpu/drm/xe/tests/xe_pci.c       |  14 +-
>  drivers/gpu/drm/xe/tests/xe_pci_test.h  |   9 +-
>  include/kunit/test.h                    |  95 ++++++-
>  kernel/kcsan/kcsan_test.c               |   2 +-
>  lib/kunit/kunit-example-test.c          | 217 +++++++++++++++
>  lib/kunit/test.c                        |  94 +++++--
>  rust/kernel/kunit.rs                    |   4 +
>  8 files changed, 740 insertions(+), 37 deletions(-)
> 
> -- 
> 2.51.0.261.g7ce5a0a67e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLCKPieOlM8dD858%40J2N7QTR9R3.
