Return-Path: <kasan-dev+bncBDCPL7WX3MKBBUGZW3DAMGQESELSJNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 79924B8B120
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 21:19:46 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2697410e7f9sf40312485ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 12:19:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758309585; cv=pass;
        d=google.com; s=arc-20240605;
        b=NDxeQ4agR5QhgrpU2fo1am4ZLnDfy9aTe/+mGUvCdgrTmntm7CQ97rmv2GZ09bRL2e
         o8gEI7vcylTveZzDPZfhnzz+yUYWj3wllnPBZIUkE1++qIVwJTCxTUTW7kL7r4a63lbT
         OnX3vUPgEe2s858cHAFW3jEkFyis/JFIdl7Y8W9KW5WQVwoqVdBsifGVIFpATOYhaE4W
         kvR+bhmViah462zOwArOyavKdgDHY/8Y7ufeM/2lIlV0LE4pseYbgAZHmUbkK0lDA3Fa
         KO/xhu3kfot2VkO0Ue+orglrLBLvdb7MJsW1KXBL0XJck60yc2lWBrQpbWk/7hru5a9E
         EXTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=M0YKgJaKYuhAulNu+MWVhzafQseQFv1YPVWxfuZ3W6g=;
        fh=Lus7hIH2NETQlAcpO8fXyB/7MuDpevSmkRZkUDUN5dw=;
        b=QRvOfE5bXovhazaRg3DvcNeF9vX2zj87CzwbzU/g83wPR1KSNwp+8MOZ0WgVSt7J9U
         80Mm+Ws56kJrJraJpqMG7yL3Pfc3P2qZeNU+s2uMlkwQvL7jH+HT5P17DOeDwISaAfqF
         hYL3wiwtfhnPQwUeyXetKbyqgJCY96naL0GXh54pxwuwoXz8knPoM7ee3kNbpb9rafHy
         wIXDH1AiMbVeKdpBDjr9u6xv3p+AQYnHcnx6df43TEVuEK3m78avLdDTCMw4csPX/sW/
         EzgJI/UiAwcpUKoutbXzTjGWJt7e8wGcpxrWNM4+QvMNhRnv3ap8y8BQlpGRoPOf/3oc
         f6qA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i2GtAhd8;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758309585; x=1758914385; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=M0YKgJaKYuhAulNu+MWVhzafQseQFv1YPVWxfuZ3W6g=;
        b=WbKX5KMIUMHeUvAP7dmqPOqMP/QyAsqUnQnpYyIsumPZa3/a4xju/g2m6ZBoB8+zki
         cq3FEmvyUgOAR5FAGNJrAeWMOBEEf/N60wky9PWeA9erkPqf8W6qqPiW4C9s3QC4syZF
         mRBDxVtt2PU2cfHdEvps1ScPPv05PRKoX7uPzJ5qrlYBbz9vzdFmgxLecK0Ls2kwiX0n
         7IIB4dRVZpwBCaldYMqtIbjcsLP2XoYHYdIylXpTFlFJcqDsS4aFsEwNwfl/JLd13sL6
         nZHbDLRYMQurnqYhSPZSzxRo+pdxMs9dehCuDe8VJJ9t8Z3KGOHpKH3JOl1lJpcItVUq
         xeag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758309585; x=1758914385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M0YKgJaKYuhAulNu+MWVhzafQseQFv1YPVWxfuZ3W6g=;
        b=gzT9kHkofBT6+PLszPSytgB8ooy4LL9s65rkXZWoYhp3AyO9UQ0NQRVkeiNH423bDZ
         uEHjmA+4onEFQmUO5BI2AjuzFJjX7BCYCgc2EIFPFbdEY814SppV9lPfklM2cbDDj8p+
         3AW1LRTLLZ4hQn2E6h7SoHYItqGVkqm9j1lWiHvisd5zb97vEiPzJYGWSFmCvqoQ+JKK
         yaEWzu0QxCk4sOEkhI/51CDr0r/t1Y63RxEnfOgQ1jFIAL6EW3AQTmog2eKAPDqSaHwS
         1sPiRNt4o2cO33eYNDDHeYmDtEaOvfHiRzTYExQxt+TLJDsJtIH4O7TEqMA3Tuj0N7kQ
         X/fQ==
X-Forwarded-Encrypted: i=2; AJvYcCVPkcjSVF9aSKT1QXg5aOF0Ex37nxC4Vd5PRwoxy7js/A1MFhGFeMRCK2ZgZTKBOLZdniSFKg==@lfdr.de
X-Gm-Message-State: AOJu0YzWFpFgQ4XDepAdyHpAvhznaLYSyg/PZDMyI+orsgyvxN+4AATr
	jf2x7yGb8HMDQi0M05EL/T89dEi0IPPP+ca9d5iLVcrIEYJxECXP1BgL
X-Google-Smtp-Source: AGHT+IHGDmVJl6EFvMnW73dvka/+GURxJmuhKxLjKLslyFzh1/+w+Pwxskoo3zLf4d15YENzZNrrrg==
X-Received: by 2002:a17:902:ce92:b0:24e:bdfa:112b with SMTP id d9443c01a7336-269ba592471mr51941405ad.61.1758309584974;
        Fri, 19 Sep 2025 12:19:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd74MMRJPLA2SoVVqw9zQflpcJpI5Q9R4vMgPSFnGRzvcw==
Received: by 2002:a17:903:7ce:b0:25d:b1dd:933c with SMTP id
 d9443c01a7336-26983fcc2c6ls14302895ad.0.-pod-prod-08-us; Fri, 19 Sep 2025
 12:19:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcj9mQZeqUTE1IAIVUNjLriSm6OYnurHlJA+ZK0jnQBaJKjIuXltXILfbGPwi9Gif8Zu1f+tEgbPI=@googlegroups.com
X-Received: by 2002:a17:902:e74b:b0:264:3519:80d0 with SMTP id d9443c01a7336-269ba516ec9mr66476895ad.33.1758309583669;
        Fri, 19 Sep 2025 12:19:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758309583; cv=none;
        d=google.com; s=arc-20240605;
        b=Qb0WIbha1ywqH3tUbEuoqRtzp8B1QdW17WkxFMf3DDqigr5FBbAvLNqiezojddoTMP
         ezAimPB0YT0Y3Yw/H0wCXvWFbAgANzogJjE37PlXUpaiJ5yRUbihlauVqM0Fp028lfPS
         X1SxY3ivHdKoWktWCooZBYQjdTnbbCsdafCOCX2zRF+f/LXtOVjUkfh8ckVB1xpYFhBX
         54L+VNpsGcnrgsvbVv/L7eidN89Jct7fkxzxTtuI93rkBmE9fMRBptxpNj8443vMxi1S
         scV13IJuj0WXOl0GlWRXD/1LI0KhSwSO8gCUTrSqn4LnuToo1D9kmqQVGkKV28HenXqf
         ME2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8yV55nY0fvSS+z77AKpGU5Td15J+ZOm7wtKdU5Fyu44=;
        fh=e5XdSZYxHgB58OrRh71Tuu5nIIlnRa1LtvK3lQRpPSo=;
        b=CgVszjsrUk11TAzkPYu45yZ7KJfyAcNIVEt5GF2HfeeXbhcCeh0z53NR21AUxP1r62
         jvjxviaMRJAKWh7a40zK1u6Vxa4359fHUx+anqxmaS5DOLuFxVfVAtFJ0rHT3fVIyvGD
         /dsW7yxzjWxB7IbBWYJZQAJ4ZUS0a5n5uk0Mh/2+A1OwUtPoZyCjw4NoAhDMMDKr2agG
         Fo0UYt6PCLg8crTHfVrHDmWJlKXtnF2bTV4Z8FNShWCKk76Rq0SLgKpRqPgLI5fZGDip
         fxNmREN9nNchGICXn+C43DBVcwn1H1JAFd2zeMrqh2DzDZdw66G04lynJdB3XzN74cu9
         264A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i2GtAhd8;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-330a48b1828si45836a91.0.2025.09.19.12.19.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 12:19:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3288743CED;
	Fri, 19 Sep 2025 19:19:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 083E6C4CEF0;
	Fri, 19 Sep 2025 19:19:43 +0000 (UTC)
Date: Fri, 19 Sep 2025 12:19:42 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com,
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev,
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com,
	dvyukov@google.com, elver@google.com, herbert@gondor.apana.org.au,
	ignat@cloudflare.com, jack@suse.cz, jannh@google.com,
	johannes@sipsolutions.net, kasan-dev@googlegroups.com,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, sj@kernel.org,
	tarasmadan@google.com
Subject: Re: [PATCH v2 09/10] fs/binfmt_script: add KFuzzTest target for
 load_script
Message-ID: <202509191208.D2BCFD366F@keescook>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
 <20250919145750.3448393-10-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250919145750.3448393-10-ethan.w.s.graham@gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i2GtAhd8;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, Sep 19, 2025 at 02:57:49PM +0000, Ethan Graham wrote:
> From: Ethan Graham <ethangraham@google.com>
> 
> Add a KFuzzTest target for the load_script function to serve as a
> real-world example of the framework's usage.
> 
> The load_script function is responsible for parsing the shebang line
> (`#!`) of script files. This makes it an excellent candidate for
> KFuzzTest, as it involves parsing user-controlled data within the
> binary loading path, which is not directly exposed as a system call.
> 
> The provided fuzz target in fs/tests/binfmt_script_kfuzz.c illustrates
> how to fuzz a function that requires more involved setup - here, we only
> let the fuzzer generate input for the `buf` field of struct linux_bprm,
> and manually set the other fields with sensible values inside of the
> FUZZ_TEST body.
> 
> To demonstrate the effectiveness of the fuzz target, a buffer overflow
> bug was injected in the load_script function like so:
> 
> - buf_end = bprm->buf + sizeof(bprm->buf) - 1;
> + buf_end = bprm->buf + sizeof(bprm->buf) + 1;
> 
> Which was caught in around 40 seconds by syzkaller simultaneously
> fuzzing four other targets, a realistic use case where targets are
> continuously fuzzed. It also requires that the fuzzer be smart enough to
> generate an input starting with `#!`.
> 
> While this bug is shallow, the fact that the bug is caught quickly and
> with minimal additional code can potentially be a source of confidence
> when modifying existing implementations or writing new functions.
> 
> Signed-off-by: Ethan Graham <ethangraham@google.com>
> 
> ---
> PR v2:
> - Introduce cleanup logic in the load_script fuzz target.
> ---
> ---
>  fs/binfmt_script.c             |  8 +++++
>  fs/tests/binfmt_script_kfuzz.c | 58 ++++++++++++++++++++++++++++++++++
>  2 files changed, 66 insertions(+)
>  create mode 100644 fs/tests/binfmt_script_kfuzz.c
> 
> diff --git a/fs/binfmt_script.c b/fs/binfmt_script.c
> index 637daf6e4d45..c09f224d6d7e 100644
> --- a/fs/binfmt_script.c
> +++ b/fs/binfmt_script.c
> @@ -157,3 +157,11 @@ core_initcall(init_script_binfmt);
>  module_exit(exit_script_binfmt);
>  MODULE_DESCRIPTION("Kernel support for scripts starting with #!");
>  MODULE_LICENSE("GPL");
> +
> +/*
> + * When CONFIG_KFUZZTEST is enabled, we include this _kfuzz.c file to ensure
> + * that KFuzzTest targets are built.
> + */
> +#ifdef CONFIG_KFUZZTEST
> +#include "tests/binfmt_script_kfuzz.c"
> +#endif /* CONFIG_KFUZZTEST */
> diff --git a/fs/tests/binfmt_script_kfuzz.c b/fs/tests/binfmt_script_kfuzz.c
> new file mode 100644
> index 000000000000..26397a465270
> --- /dev/null
> +++ b/fs/tests/binfmt_script_kfuzz.c
> @@ -0,0 +1,58 @@
> +// SPDX-License-Identifier: GPL-2.0-or-later
> +/*
> + * binfmt_script loader KFuzzTest target
> + *
> + * Copyright 2025 Google LLC
> + */
> +#include <linux/binfmts.h>
> +#include <linux/kfuzztest.h>
> +#include <linux/slab.h>
> +#include <linux/sched/mm.h>
> +
> +struct load_script_arg {
> +	char buf[BINPRM_BUF_SIZE];
> +};
> +
> +FUZZ_TEST(test_load_script, struct load_script_arg)
> +{
> +	struct linux_binprm bprm = {};
> +	char *arg_page;
> +
> +	arg_page = (char *)get_zeroed_page(GFP_KERNEL);
> +	if (!arg_page)
> +		return;
> +
> +	memcpy(bprm.buf, arg->buf, sizeof(bprm.buf));
> +	/*
> +	 * `load_script` calls remove_arg_zero, which expects argc != 0. A
> +	 * static value of 1 is sufficient for fuzzing.
> +	 */
> +	bprm.argc = 1;
> +	bprm.p = (unsigned long)arg_page + PAGE_SIZE;
> +	bprm.filename = kstrdup("fuzz_script", GFP_KERNEL);
> +	if (!bprm.filename)
> +		goto cleanup;
> +	bprm.interp = kstrdup(bprm.filename, GFP_KERNEL);
> +	if (!bprm.interp)
> +		goto cleanup;
> +
> +	bprm.mm = mm_alloc();
> +	if (!bprm.mm)
> +		goto cleanup;
> +
> +	/*
> +	 * Call the target function. We expect it to fail and return an error
> +	 * (e.g., at open_exec), which is fine. The goal is to survive the
> +	 * initial parsing logic without crashing.
> +	 */
> +	load_script(&bprm);
> +
> +cleanup:
> +	if (bprm.mm)
> +		mmput(bprm.mm);
> +	if (bprm.interp)
> +		kfree(bprm.interp);
> +	if (bprm.filename)
> +		kfree(bprm.filename);
> +	free_page((unsigned long)arg_page);
> +}

Yay fuzzing hooks! I'm excited about this series overall, but I'm not
a fan of this "manual" init/clean up of bprm.

If you're going to set up a bprm that passes through load_script(), it
needs to be both prepared correctly (alloc_bprm) and cleaned up correctly
(free_bprm). Otherwise, you may be fuzzing impossible states created by
the fuzztest setup. And having a second init/cleanup path in here makes
future refactoring work more of a burden/fragile.

But this is also kind of not a great example of fuzztest utility because
load_script _is_ actually directly accessible from syscalls: it is trivial
to externally fuzz load_script by just writing the buffer to a file and
execve'ing it. :)

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202509191208.D2BCFD366F%40keescook.
