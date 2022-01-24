Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL6CXGHQMGQE2O2Y77I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B021497A1D
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 09:20:00 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id m21-20020a1709061ed500b006b3003ec50dsf1762529ejj.17
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 00:20:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643012400; cv=pass;
        d=google.com; s=arc-20160816;
        b=F1BHut3/Q65+JnpFMWshIMIeh22aN1QIdFmL3/i+XLKVCbBmGl8bfb3z6xVp/11Mq/
         v2JaKaazoQnX+M7gMAojrZNRx7MjcD/EXT2eyeGmWKZxEXaagqayl9+FAaY4tWv4W8/u
         6Cot+Rb6iIGcQjSEGksfju6FON3lDpu5t2IAPiZUnvvchdY/x3JegeXJxAorzqWQKf9v
         iY9gNkTq+DoXIrlDGRjASIogm2EssxFXwoG5O3BPk/ytugtjolDavrimhc/juoG6DumY
         MN9vZ20xd19yNmob6XVRZK6yc+Cz5/s6rT5N66O93OxZOjRaOe/0g7o3CTdtn7cKuIIK
         eASA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=XM7LkwUyAV0Un2MNeuCn8jRpL6LXmVCowUmnbmstXoI=;
        b=p/ZeGI0REPXCZ+1Uv+0fIVGkDSxaXaQ9AiLx7wXzqbEZYf2DEKlI7iOalVTAMca5oB
         kQ7aKyUu6vuWBs4n+SSx7Qfc8a7/Bt+3mom1Qvv7QlxRRpUa5tkGs0cpd/2KkL73djs8
         FpwvlpJzAjzN/ZzuEuIj3zylE4rcCdYqJdlI3dbf8wfOHiov2AqMDGdFrl9Wmjus739f
         qzgTm5PzqtYxDs7ac4BJRWYtKh1AZmKpHTwD6SGQnVXTlT7oAucMkiIbvS1oiL6yzHL4
         0dY0E26XP3vbNPqwr8Dc7cSPfRdn2Kv4lfE1HYlbgJPXWqwC9S/B6m42dn32f2oztqqk
         djEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TOc2vC6S;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XM7LkwUyAV0Un2MNeuCn8jRpL6LXmVCowUmnbmstXoI=;
        b=rvRMMk3zowarSFnqxgFC52l9a62wsl3dUjtdz8evEaDkk+/4PLh8yp5m/CelL9cNN3
         W+qHaACx0B5v2zXRT2kQYhczHZKNNmH6ac0+IvTplvphEObyJ2Osl8sS3F9CF7AWsKJk
         tUzbFGHr5zGmBivU1T9bhH5IWh6ExsglaNX/XF3pzyv+Z78gyFCorYgkK8kjpC9DqM/A
         j3tkbYNBJQ3NB0xCXt6gz3UoSld8vOqS+ME1Ozb6J6Pv+p3uGrO+/Bf1xo0PPzX+mcQ9
         tSQ0FHA/DWcoKD6X75jcLSXBuZFzKVd9hiIHANO6vu368eRzIoimdX3/6jEJsltCUxn2
         0kOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XM7LkwUyAV0Un2MNeuCn8jRpL6LXmVCowUmnbmstXoI=;
        b=7T+khgnHmbLRY0aiGtO2DGskYmabPJaeQnqLV650yG+CR2p8zEiJbwi8Kwqckxwr16
         IEAR8wWnj7kNeJtFJytK2YF4h5ypPzMpeYjM8AVaMjpIvubbsqTKOjfCekkdg/U4p2Ge
         C69DF9hpE0nT3KEwdQec3YE+iutUrnj8Zb7lttWxbQ4ZOUHk6pSxAt6GigOF9bVj0x7E
         14dl5A9OkFIGkORaeb+U7z2OhV2Az+Dx3BHaLlzjh3am9bS3HZwjTz0FgKB1mIyiUjkZ
         W1rb94a4FXr3V8XjWYDyHlIHfVlqm6EGDYkXkCME8Kg3zb3h9dLYDcNXC9IcCm/Z8KjW
         LbTQ==
X-Gm-Message-State: AOAM530U83BjO1OOmtb5Tf4xjKQlPuQBg2/AdTXenveK1siR4fuYtbEI
	ITVeEDMQXucVMPoBiW+3LW0=
X-Google-Smtp-Source: ABdhPJxtaNVjYWjvqMWXjxH7PbmpMA8B5kYYFcPh/HnFWRtxE2ar3iC+RBsS8p6xe32SrrcnKWnQ+A==
X-Received: by 2002:a50:fd08:: with SMTP id i8mr14975967eds.394.1643012399893;
        Mon, 24 Jan 2022 00:19:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:370d:: with SMTP id ek13ls4284402edb.1.gmail; Mon,
 24 Jan 2022 00:19:59 -0800 (PST)
X-Received: by 2002:a05:6402:3489:: with SMTP id v9mr2186788edc.351.1643012398896;
        Mon, 24 Jan 2022 00:19:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643012398; cv=none;
        d=google.com; s=arc-20160816;
        b=wYG/dILdOFHv3wVnSR9nFfZm539yUxzDp/tH+oX2lDdIM/TguhL+Xl7/rhA+F+AjuT
         ggnhDuEj6c54J0vaYpwUpHlnRlUUSdJS1rbUxLGuz+5mz6psm7MWO6GSGcN8391GEJtS
         3bBVQKVw22MdXi1Rr7dqCBoDsOcHxD92uRssUeR6a2oLpm/4f623G8DKZRvfd8DtpyVz
         Z7zUJRKGHfWF9ZI7DoKHBchDTRlWZSXxyCTYnFFOU8WaDPRtgeKNIjkv14Fqlbf63eJw
         /X42ky3PJ1fbP8hNuxiZZi6KbN8b0WCy7D+3+G5L1Zka4eGyRffYq/22Stto3Rn2pVYq
         A/lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=c28QaxpAfuOEDq8LtprBB/owZVWinCLNDU++tnPYx8Y=;
        b=c8lVOzVSxX+gCeVEhU53Xp97xEAZ4ww2CHVlz2CGGPHXnXMjAqbiDlqe1L3PhczSJE
         qmTOtgeiINmaTVLL/tf1vbverN8jC/khIdiawa6DxAASFeFhXeIcV7gVekUMjo/hIb7F
         zEcfZQh9myX0eK7Wq+3JwYdBJAh4JVMiKVjvDiAvMue1e/ZUqrm1tRIJG4YfmEMEgJVF
         tJALjU7XpqciMu0+hUy9J4TSuOa1YxjExtnDazTkTGyr14E/F0T3DxVYmQ4gWHBQpvWs
         uA+ZxrzMn3d+vUH9qxwGf3J06MIOE0ukBB03Aq6j3iBits1yUCVw/Fj9cuEdKmr21iAZ
         4DAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TOc2vC6S;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id l16si610267edb.1.2022.01.24.00.19.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 00:19:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id r2-20020a1c2b02000000b0034f7b261169so1952188wmr.2
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 00:19:58 -0800 (PST)
X-Received: by 2002:a1c:3b08:: with SMTP id i8mr768071wma.52.1643012398399;
        Mon, 24 Jan 2022 00:19:58 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:810c:fb1:faa0:df2])
        by smtp.gmail.com with ESMTPSA id m5sm2460444wrs.22.2022.01.24.00.19.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Jan 2022 00:19:57 -0800 (PST)
Date: Mon, 24 Jan 2022 09:19:52 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peng Liu <liupeng256@huawei.com>
Cc: glider@google.com, dvyukov@google.com, corbet@lwn.net,
	sumit.semwal@linaro.org, christian.koenig@amd.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linaro-mm-sig@lists.linaro.org, linux-mm@kvack.org
Subject: Re: [PATCH RFC 1/3] kfence: Add a module parameter to adjust kfence
 objects
Message-ID: <Ye5hKItk3j7arjaI@elver.google.com>
References: <20220124025205.329752-1-liupeng256@huawei.com>
 <20220124025205.329752-2-liupeng256@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220124025205.329752-2-liupeng256@huawei.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TOc2vC6S;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as
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

On Mon, Jan 24, 2022 at 02:52AM +0000, Peng Liu wrote:
> KFENCE is designed to be enabled in production kernels, but it can
> be also useful in some debug situations. For machines with limited
> memory and CPU resources, KASAN is really hard to run. Fortunately,

If these are arm64 based machines, see if CONFIG_KASAN_SW_TAGS works for
you. In future, we believe that CONFIG_KASAN_HW_TAGS will be suitable
for a variety of scenarios, including debugging scenarios of resource
constrained environments.

> KFENCE can be a suitable candidate. For KFENCE running on a single
> machine, the possibility of discovering existed bugs will increase
> as the increasing of KFENCE objects, but this will cost more memory.
> In order to balance the possibility of discovering existed bugs and
> memory cost, KFENCE objects need to be adjusted according to memory
> resources for a compiled kernel Image. Add a module parameter to
> adjust KFENCE objects will make kfence to use in different machines
> with the same kernel Image.
> 
> In short, the following reasons motivate us to add this parameter.
> 1) In some debug situations, this will make kfence flexible.
> 2) For some production machines with different memory and CPU size,
> this will reduce the kernel-Image-version burden.
[...]
> This patch (of 3):

[ Note for future: No need to add "This patch (of X)" usually -- this is
  added by maintainers if deemed appropriate, and usually includes the
  cover letter. ]

> The most important motivation of this patch series is to make
> KFENCE easy-to-use in business situations.
> 
> Signed-off-by: Peng Liu <liupeng256@huawei.com>
> ---
>  Documentation/dev-tools/kfence.rst |  14 ++--
>  include/linux/kfence.h             |   3 +-
>  mm/kfence/core.c                   | 108 ++++++++++++++++++++++++-----
>  mm/kfence/kfence.h                 |   2 +-
>  mm/kfence/kfence_test.c            |   2 +-
>  5 files changed, 103 insertions(+), 26 deletions(-)
[...]  
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 4b5e3679a72c..aec4f6b247b5 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -17,12 +17,13 @@
>  #include <linux/atomic.h>
>  #include <linux/static_key.h>
>  
> +extern unsigned long kfence_num_objects;
>  /*
>   * We allocate an even number of pages, as it simplifies calculations to map
>   * address to metadata indices; effectively, the very first page serves as an
>   * extended guard page, but otherwise has no special purpose.
>   */
> -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
> +#define KFENCE_POOL_SIZE ((kfence_num_objects + 1) * 2 * PAGE_SIZE)
>  extern char *__kfence_pool;

I appreciate the effort, but you could have gotten a quicker answer if
you had first sent us an email to ask why adjustable number of objects
hasn't been done before. Because if it was trivial, we would have
already done it.

What you've done is turned KFENCE_POOL_SIZE into a function instead of a
constant (it still being ALL_CAPS is now also misleading).

This is important here:

	/**
	 * is_kfence_address() - check if an address belongs to KFENCE pool
	 * @addr: address to check
	 *
	 * Return: true or false depending on whether the address is within the KFENCE
	 * object range.
	 *
	 * KFENCE objects live in a separate page range and are not to be intermixed
	 * with regular heap objects (e.g. KFENCE objects must never be added to the
	 * allocator freelists). Failing to do so may and will result in heap
	 * corruptions, therefore is_kfence_address() must be used to check whether
	 * an object requires specific handling.
	 *
	 * Note: This function may be used in fast-paths, and is performance critical.
	 * Future changes should take this into account; for instance, we want to avoid
	 * introducing another load and therefore need to keep KFENCE_POOL_SIZE a
	 * constant (until immediate patching support is added to the kernel).
	 */
	static __always_inline bool is_kfence_address(const void *addr)
	{
		/*
		 * The __kfence_pool != NULL check is required to deal with the case
		 * where __kfence_pool == NULL && addr < KFENCE_POOL_SIZE. Keep it in
		 * the slow-path after the range-check!
		 */
		return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && __kfence_pool);
	}

Unfortunately I think you missed the "Note".

Which means that ultimately your patch adds another LOAD to the fast
path, which is not an acceptable trade-off.

This would mean your change would require benchmarking, but it'd also
mean we and everyone else would have to re-benchmark _all_ systems where
we've deployed KFENCE.

I think the only reasonable way forward is if you add immediate patching
support to the kernel as the "Note" suggests.

In the meantime, while not a single kernel imagine, we've found that
debug scenarios usually are best served with a custom debug kernel, as
there are other debug features that are only Kconfig configurable. Thus,
having a special debug kernel just configure KFENCE differently
shouldn't be an issue in the majority of cases.

Should this answer not be satisfying for you, the recently added feature
skipping already covered allocations (configurable via
kfence.skip_covered_thresh) alleviates some of the issue of a smaller
pool with a very low sample interval (viz. high sample rate).

The main thing to watch out for is KFENCE's actual sample rate vs
intended sample rate (per kfence.sample_interval). If you monitor
/sys/kernel/debug/kfence/stats, you can compute the actual sample rate.
If the actual sample rate becomes significantly lower than the intended
rate, only then does it make sense to increase the pool size. My
suggestion for you is therefore to run some experiments, while adjusting
kfence.sample_interval and kfence.skip_covered_thresh until you reach a
sample rate that is close to intended.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ye5hKItk3j7arjaI%40elver.google.com.
