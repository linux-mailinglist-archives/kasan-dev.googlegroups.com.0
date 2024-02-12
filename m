Return-Path: <kasan-dev+bncBCF5XGNWYQBRBT54VKXAMGQE4VTFCNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C5507852190
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:40:16 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-59927811bf8sf5143990eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:40:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707777615; cv=pass;
        d=google.com; s=arc-20160816;
        b=skGU7GWg69xSTt0OtiMJcExE5KaC1npuX98bu7GsyMy04XjfBen9To3VwOctpcKR4c
         rWY1AS/2p8CENxOMwPiGyx4++NBPRgpnW80tRu1cVjry96jvhx8ww9/XLZ0V0+Y8W4p/
         0dDd8/EmtDJcW+/QQiif+tDsJ8gd/tkaB+JizW40tYKLVSCev0BYgT+Y1a8UBO5QMTBM
         1VzJz722DUHu+yujri8UcrWmJxhCVj7WZwK6N2OBlifp8X3gy4sQ7+k/f0d/3OnzB94A
         HBqlN0HSumzHQe+54gJKnr9baSsoaPWkFEd/S/bwjEg1ouI+ATP+4gcdfQ5HaD0G024B
         KecQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UeTez+IYXHdr5xqdufegzO73J5voGi5gza/KHOMiiBw=;
        fh=a2owsRcf2bSzFQ48hEd1UbQxPoFspqGsBdyH2qR6c50=;
        b=y/f9qyixReFziBmgbTkQsC9g6rYSMgYtuWMlPYiw0lWuzkVIv0KRdA9ajctWipb8vi
         WHPZR2ZOsq1QoNsen5sWXIrouwxznA+LqW3ZelC7SaYzboi+nRAY4CPdsYAnyM9x1fPX
         PWBzsMwRE7tnef8PF7vhf/Yyofo8rJTnPg6a4W8uvRVrz6IFALvt9KtUV9MU4IDPOTKu
         MPyJ1vycwYeXx/mhoA3DkJPb9qDZvidClHE4s/eO1WzoINUAzyNKU5jHeOpy/JBsB9jy
         B/Jb2QbbZZ3RyTH3h2MwRHr2Vmtq3VXAGR0ujySa/IjSsFOl0LrhrLxVhl2AhdfEYyw1
         0zXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=HwkkrtPB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707777615; x=1708382415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UeTez+IYXHdr5xqdufegzO73J5voGi5gza/KHOMiiBw=;
        b=kO+Db7S4I2l+/4UsWKDcyxUQDRWXAE5LKBu26aKQgVet5C3w+QeEEUQ+9ay9vS8eIu
         6BosfPLJv5Ll7egZSmhJkIFXeqzir2lYmAwz5/Gk0QrkkwxKpOYOwzl5pY7GcKowhBR7
         1afKxWF35f5G684n4KKNTpwOnIyEgct1HIlb7LRMfTLVGmweeZOzLiYeBp1RTooSwIc0
         vTQCh+opXBq83PhlekiBnsBJ9DDo6KVX5Ojot02pAbG134ElzLqPgVD2hY4ulldz8QLV
         f+Nx3x5O4paYxsnJqjbzOm4AI+hGv9odA+bIhPzKG3Slr8GlEn+LN6SbnSjwVS3uDbsR
         /UHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707777615; x=1708382415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UeTez+IYXHdr5xqdufegzO73J5voGi5gza/KHOMiiBw=;
        b=iHGU3BJ0oG4fqUtAOs3FKVn+Bf7bpy98g3gCzm0xZcmIA7BdgzBw0qY1BFhboTxM8g
         rGWXssaKQNZiYJgDaZRv2iLJD5qZ71YnAXYqvXDZDCeyuw7Syfb6Yu+ADAM4eUJ1jrk0
         US6N2EZCqAevocXZLeoAlohSW0GkdfEZ+FyZVIcjheSFVaLeoz6Ov7aEueIqv1GmICQ3
         uTBfROE8t4MSpKdHMITXUebJ2KkOfqAxACR4Of66ISGuaRrd0iCf1f9AK2jLv2m/Gund
         /weuaqn0DnPL0yCmBKIigsvvg1ON7qgWno8sYVOhEOrsYziqBeX9XVg37YJkeVxH5LyD
         b+kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxU9hfOlqsi9Kd3m+qIB4cCAJUkyicX4PAiM0jGK2Qll7rC4AJY
	0qA/PDipPqkV+OW83m06+INz5i3PQY6RmJPDcrckhNpag8bDwqOR
X-Google-Smtp-Source: AGHT+IH7yRyZB9itFniZiFmL/P/so/nbyslgL4np+6DvQPl73li4TX2LSOhjRJ6sEjlbSYf2e0uKew==
X-Received: by 2002:a05:6820:284:b0:59d:5c69:4082 with SMTP id q4-20020a056820028400b0059d5c694082mr3670335ood.0.1707777615525;
        Mon, 12 Feb 2024 14:40:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ae08:0:b0:59c:8811:7841 with SMTP id z8-20020a4aae08000000b0059c88117841ls721688oom.2.-pod-prod-05-us;
 Mon, 12 Feb 2024 14:40:14 -0800 (PST)
X-Received: by 2002:a05:6358:5991:b0:178:de46:783c with SMTP id c17-20020a056358599100b00178de46783cmr14695056rwf.16.1707777614593;
        Mon, 12 Feb 2024 14:40:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707777614; cv=none;
        d=google.com; s=arc-20160816;
        b=fVXQwvjOObty4rY8TCDoGluRxGFSo+bX6EkgYB1qPITjzKXD8FA3+isw45YmJ/aoK8
         pEHJ8pypa1f6BOwzek963kbI4c0Ku/u3CkzSuUYn4THrxZx1+hJWJSNtsvyjmYj6UiF4
         EC4E6pciIdVSSVeL1FHDWq4eaVLzrtIzMZIbpUrq4Fi0VxKCZdrOjDkifuyZBRSFHlvy
         G6dl95MbFQ7A3dlkVrDR+f7Uc3vUpnaZ1ThwjkLf+wUkI73pDEsEbDZ/c8d6RctitXjA
         JsCkUqP8wuBuQmCrwqWT001WD+t7Z6vRhMo6PxF89jatYZpECka2dOtdBoEUnr/A9VZx
         vccg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hczO4cJiUHC8ASa5scEplagLmB2u+1lBcHrJWJ9tWV0=;
        fh=a2owsRcf2bSzFQ48hEd1UbQxPoFspqGsBdyH2qR6c50=;
        b=FzXZPVBBt2Gll3mdZ1ft5SU0SsYIT7+Qrw11vGcLIU4bN3xvNLYgfyzz876k7BrvTQ
         bAWLa108kDma9PBIEU2RMvtxOh942HNkpdatDFHfT/CO3e3Uqevv1YqVxwpgW8xbqAvZ
         BGVXJGf8ky6lGMRqiFuasf+u1JlVHe28YVa5+dQ7lRMuasRJTFZEE/t8P9qN2ukU6jAv
         R0AiC9SsN8czLZ7mItIVNzrhb8rW734/cy+NMCs0gnvfAIplnUtYxwedDDk81upFfAoJ
         7C8/tMaCP6MWpICv0KSoIbuRzkk5T9v/w5EODnV19DmTHM4TeXNAO05IQTxtk7vu2aSw
         mX/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=HwkkrtPB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCV0HcCW406fA1cAerS2mQkjNtf0/2pNx6kH0TNGt7Y+u2M9G7pleYYgppiMNyf+tP4pCcEdwAynYu+g7SAejjQI23Fz3qUyacreXg==
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id n63-20020a632742000000b005dc2e3165adsi151838pgn.3.2024.02.12.14.40.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:40:14 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-6e0a4c6c2adso1087806b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:40:14 -0800 (PST)
X-Received: by 2002:a05:6a20:9c8d:b0:19e:a9c5:2ef6 with SMTP id mj13-20020a056a209c8d00b0019ea9c52ef6mr8873075pzb.2.1707777614137;
        Mon, 12 Feb 2024 14:40:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV60xyI4YdXcZKOpfVtN0UNYQGxiEeJHYGSHlgfy81dQZLPDwXouYrQJh6AC1gRykYB+F/sPXWRXChxoGiGWkqFuM3ESxF44uZ29mvnLEWYq8nFvvsTeud1XiWsy/kQoDJkbYZtDLxboQhCJo3qjPcWvceZYtYmLpCThuelVu0/eU2Ek5N1kRVK5PR2zRAK/tLvpYtKV3ttl7WW/JAwmI2cGHSBd3mgAi0Pk6BBJ6eP8WWccqudPbEQCtUfGOtZvwdK4uNt8jzWpu3J8iY+MuaK1ToeuHpqOWsgoEW4WE6oDduTG3ikueiaVuF0+Cr6Eu6U/JQwxEdvFGNVNVu909c2VoauQiGzRq9TaM76ZtjBSj1mwh1oFbDhr3s5BFtjUIN/bCXwWr6Wqh71MZFHNYJ+oM0Of9IIMKie0LlOrX/NiOl4unjWXSPvJexz6Ec3kvEkDmSqDJvXapSWwwNJwdZ/lxwahQ7LAE2R2+U7k47qWlbPq+OakDjeXufALiYYbgop/bB6dEAVt20o8Ux9ru+nWC1wBrznlqwuzhw+snXa8aAHRP0m4sxQPjVok0BXxlrXGYfm1uqoTcAQa8f/3mzhs4bphSQC5vJ3Jeycqpki692nhqpUE9sWduKvcSCCTmznMGOoMl8YowMMLOKAH39pCQtmzF+15MFcLGPShtIfIjniV+jApWZJ1IjEeRG1fpRscBWvNSGG/4G2DQ8BxwyQUdgsfa+XSBTC7OA7t/Q/pFSEj5iGIcKR87pbfHceuq1L0XSjyK6dQgamI8RBKt3vLFCw2JzldAHl76JpIA4zHpNj4n3dQcQdyzKX8PlDXmJVtcg8NgCU81IOgONcKYjrrIChdbdRUlFhvJfYMkh97+C2d/6b+rVucc3qt8D+t4lcCrfZeQuWTNJ5q5RiU7atHpPJPY/ap14lvhGeZFCbRAq2j44fMRTRz58SuagqIadSZK
 fHCiU59SaTd2E/1KKSGjwbHbxAFVWDVBfM1G39L4w31cN8uWwh8XdwO+67yxdc2GL6xCx4gYooCfg3bzWwd3EoBmXYXeCXgYeUX+8zrNdnNi4Y/7fTeAVh7aoc1jVV91GUESXaXlH7nrWTEmdIJD3yeNES9Ta9bNqw4oMbsjg6+dHxHckXNShEOPjpFAN8EB1u7ow/DtYb2QiWhLomzzl0VO2b/r7AIgKKS5ujpdlZgXrdexHNZU4cbE034FfYZRPLo8fEfCZ2d+PJvg9to+L5RsT7oAErhbcAlKzLfVbH7/wQ0q6DqlNOAQIsZ07gysViOzfvIlfkWKime1rY33vCG5v1/JA17e5U3tZjNzYswM7rCp50Rexl9vg2zqEsYvGF04DBzgm7RcyQjYYcrFCgKNhSaxxYHGnlJWDztRC2uI0GKi35WKx0j0o+iUI=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id su14-20020a17090b534e00b002960e3745d9sm1072191pjb.13.2024.02.12.14.40.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:40:12 -0800 (PST)
Date: Mon, 12 Feb 2024 14:40:12 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <202402121433.5CC66F34B@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-14-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=HwkkrtPB;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wrote:
> Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easily
> instrument memory allocators. It registers an "alloc_tags" codetag type
> with /proc/allocinfo interface to output allocation tag information when

Please don't add anything new to the top-level /proc directory. This
should likely live in /sys.

> the feature is enabled.
> CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
> allocation profiling instrumentation.
> Memory allocation profiling can be enabled or disabled at runtime using
> /proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEBUG=n.
> CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocation
> profiling by default.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> ---
>  Documentation/admin-guide/sysctl/vm.rst |  16 +++
>  Documentation/filesystems/proc.rst      |  28 +++++
>  include/asm-generic/codetag.lds.h       |  14 +++
>  include/asm-generic/vmlinux.lds.h       |   3 +
>  include/linux/alloc_tag.h               | 133 ++++++++++++++++++++
>  include/linux/sched.h                   |  24 ++++
>  lib/Kconfig.debug                       |  25 ++++
>  lib/Makefile                            |   2 +
>  lib/alloc_tag.c                         | 158 ++++++++++++++++++++++++
>  scripts/module.lds.S                    |   7 ++
>  10 files changed, 410 insertions(+)
>  create mode 100644 include/asm-generic/codetag.lds.h
>  create mode 100644 include/linux/alloc_tag.h
>  create mode 100644 lib/alloc_tag.c
> 
> diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentation/admin-guide/sysctl/vm.rst
> index c59889de122b..a214719492ea 100644
> --- a/Documentation/admin-guide/sysctl/vm.rst
> +++ b/Documentation/admin-guide/sysctl/vm.rst
> @@ -43,6 +43,7 @@ Currently, these files are in /proc/sys/vm:
>  - legacy_va_layout
>  - lowmem_reserve_ratio
>  - max_map_count
> +- mem_profiling         (only if CONFIG_MEM_ALLOC_PROFILING=y)
>  - memory_failure_early_kill
>  - memory_failure_recovery
>  - min_free_kbytes
> @@ -425,6 +426,21 @@ e.g., up to one or two maps per allocation.
>  The default value is 65530.
>  
>  
> +mem_profiling
> +==============
> +
> +Enable memory profiling (when CONFIG_MEM_ALLOC_PROFILING=y)
> +
> +1: Enable memory profiling.
> +
> +0: Disabld memory profiling.
> +
> +Enabling memory profiling introduces a small performance overhead for all
> +memory allocations.
> +
> +The default value depends on CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT.
> +
> +
>  memory_failure_early_kill:
>  ==========================
>  
> diff --git a/Documentation/filesystems/proc.rst b/Documentation/filesystems/proc.rst
> index 104c6d047d9b..40d6d18308e4 100644
> --- a/Documentation/filesystems/proc.rst
> +++ b/Documentation/filesystems/proc.rst
> @@ -688,6 +688,7 @@ files are there, and which are missing.
>   ============ ===============================================================
>   File         Content
>   ============ ===============================================================
> + allocinfo    Memory allocations profiling information
>   apm          Advanced power management info
>   bootconfig   Kernel command line obtained from boot config,
>   	      and, if there were kernel parameters from the
> @@ -953,6 +954,33 @@ also be allocatable although a lot of filesystem metadata may have to be
>  reclaimed to achieve this.
>  
>  
> +allocinfo
> +~~~~~~~
> +
> +Provides information about memory allocations at all locations in the code
> +base. Each allocation in the code is identified by its source file, line
> +number, module and the function calling the allocation. The number of bytes
> +allocated at each location is reported.
> +
> +Example output.
> +
> +::
> +
> +    > cat /proc/allocinfo
> +
> +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
> +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kmalloc_order
> +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc_slab_obj_exts
> +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc_pages_exact
> +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable func:__pte_alloc_one
> +     1.16MiB     fs/xfs/xfs_log_priv.h:700 module:xfs func:xlog_kvmalloc
> +     1.00MiB     mm/swap_cgroup.c:48 module:swap_cgroup func:swap_cgroup_prepare
> +      734KiB     fs/xfs/kmem.c:20 module:xfs func:kmem_alloc
> +      640KiB     kernel/rcu/tree.c:3184 module:tree func:fill_page_cache_func
> +      640KiB     drivers/char/virtio_console.c:452 module:virtio_console func:alloc_buf
> +      ...
> +
> +
>  meminfo
>  ~~~~~~~
>  
> diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
> new file mode 100644
> index 000000000000..64f536b80380
> --- /dev/null
> +++ b/include/asm-generic/codetag.lds.h
> @@ -0,0 +1,14 @@
> +/* SPDX-License-Identifier: GPL-2.0-only */
> +#ifndef __ASM_GENERIC_CODETAG_LDS_H
> +#define __ASM_GENERIC_CODETAG_LDS_H
> +
> +#define SECTION_WITH_BOUNDARIES(_name)	\
> +	. = ALIGN(8);			\
> +	__start_##_name = .;		\
> +	KEEP(*(_name))			\
> +	__stop_##_name = .;
> +
> +#define CODETAG_SECTIONS()		\
> +	SECTION_WITH_BOUNDARIES(alloc_tags)
> +
> +#endif /* __ASM_GENERIC_CODETAG_LDS_H */
> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> index 5dd3a61d673d..c9997dc50c50 100644
> --- a/include/asm-generic/vmlinux.lds.h
> +++ b/include/asm-generic/vmlinux.lds.h
> @@ -50,6 +50,8 @@
>   *               [__nosave_begin, __nosave_end] for the nosave data
>   */
>  
> +#include <asm-generic/codetag.lds.h>
> +
>  #ifndef LOAD_OFFSET
>  #define LOAD_OFFSET 0
>  #endif
> @@ -366,6 +368,7 @@
>  	. = ALIGN(8);							\
>  	BOUNDED_SECTION_BY(__dyndbg_classes, ___dyndbg_classes)		\
>  	BOUNDED_SECTION_BY(__dyndbg, ___dyndbg)				\
> +	CODETAG_SECTIONS()						\
>  	LIKELY_PROFILE()		       				\
>  	BRANCH_PROFILE()						\
>  	TRACE_PRINTKS()							\
> diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> new file mode 100644
> index 000000000000..cf55a149fa84
> --- /dev/null
> +++ b/include/linux/alloc_tag.h
> @@ -0,0 +1,133 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * allocation tagging
> + */
> +#ifndef _LINUX_ALLOC_TAG_H
> +#define _LINUX_ALLOC_TAG_H
> +
> +#include <linux/bug.h>
> +#include <linux/codetag.h>
> +#include <linux/container_of.h>
> +#include <linux/preempt.h>
> +#include <asm/percpu.h>
> +#include <linux/cpumask.h>
> +#include <linux/static_key.h>
> +
> +struct alloc_tag_counters {
> +	u64 bytes;
> +	u64 calls;
> +};
> +
> +/*
> + * An instance of this structure is created in a special ELF section at every
> + * allocation callsite. At runtime, the special section is treated as
> + * an array of these. Embedded codetag utilizes codetag framework.
> + */
> +struct alloc_tag {
> +	struct codetag			ct;
> +	struct alloc_tag_counters __percpu	*counters;
> +} __aligned(8);
> +
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +
> +static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
> +{
> +	return container_of(ct, struct alloc_tag, ct);
> +}
> +
> +#ifdef ARCH_NEEDS_WEAK_PER_CPU
> +/*
> + * When percpu variables are required to be defined as weak, static percpu
> + * variables can't be used inside a function (see comments for DECLARE_PER_CPU_SECTION).
> + */
> +#error "Memory allocation profiling is incompatible with ARCH_NEEDS_WEAK_PER_CPU"

Is this enforced via Kconfig as well? (Looks like only alpha and s390?)

> +#endif
> +
> +#define DEFINE_ALLOC_TAG(_alloc_tag, _old)					\
> +	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
> +	static struct alloc_tag _alloc_tag __used __aligned(8)			\
> +	__section("alloc_tags") = {						\
> +		.ct = CODE_TAG_INIT,						\
> +		.counters = &_alloc_tag_cntr };					\
> +	struct alloc_tag * __maybe_unused _old = alloc_tag_save(&_alloc_tag)
> +
> +DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
> +			mem_alloc_profiling_key);
> +
> +static inline bool mem_alloc_profiling_enabled(void)
> +{
> +	return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
> +				   &mem_alloc_profiling_key);
> +}
> +
> +static inline struct alloc_tag_counters alloc_tag_read(struct alloc_tag *tag)
> +{
> +	struct alloc_tag_counters v = { 0, 0 };
> +	struct alloc_tag_counters *counter;
> +	int cpu;
> +
> +	for_each_possible_cpu(cpu) {
> +		counter = per_cpu_ptr(tag->counters, cpu);
> +		v.bytes += counter->bytes;
> +		v.calls += counter->calls;
> +	}
> +
> +	return v;
> +}
> +
> +static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> +{
> +	struct alloc_tag *tag;
> +
> +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
> +#endif
> +	if (!ref || !ref->ct)
> +		return;
> +
> +	tag = ct_to_alloc_tag(ref->ct);
> +
> +	this_cpu_sub(tag->counters->bytes, bytes);
> +	this_cpu_dec(tag->counters->calls);
> +
> +	ref->ct = NULL;
> +}
> +
> +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> +{
> +	__alloc_tag_sub(ref, bytes);
> +}
> +
> +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes)
> +{
> +	__alloc_tag_sub(ref, bytes);
> +}
> +
> +static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
> +{
> +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +	WARN_ONCE(ref && ref->ct,
> +		  "alloc_tag was not cleared (got tag for %s:%u)\n",\
> +		  ref->ct->filename, ref->ct->lineno);
> +
> +	WARN_ONCE(!tag, "current->alloc_tag not set");
> +#endif
> +	if (!ref || !tag)
> +		return;
> +
> +	ref->ct = &tag->ct;
> +	this_cpu_add(tag->counters->bytes, bytes);
> +	this_cpu_inc(tag->counters->calls);
> +}
> +
> +#else
> +
> +#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
> +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
> +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
> +static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
> +				 size_t bytes) {}
> +
> +#endif
> +
> +#endif /* _LINUX_ALLOC_TAG_H */
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index ffe8f618ab86..da68a10517c8 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -770,6 +770,10 @@ struct task_struct {
>  	unsigned int			flags;
>  	unsigned int			ptrace;
>  
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +	struct alloc_tag		*alloc_tag;
> +#endif

Normally scheduling is very sensitive to having anything early in
task_struct. I would suggest moving this the CONFIG_SCHED_CORE ifdef
area.

> +
>  #ifdef CONFIG_SMP
>  	int				on_cpu;
>  	struct __call_single_node	wake_entry;
> @@ -810,6 +814,7 @@ struct task_struct {
>  	struct task_group		*sched_task_group;
>  #endif
>  
> +
>  #ifdef CONFIG_UCLAMP_TASK
>  	/*
>  	 * Clamp values requested for a scheduling entity.
> @@ -2183,4 +2188,23 @@ static inline int sched_core_idle_cpu(int cpu) { return idle_cpu(cpu); }
>  
>  extern void sched_set_stop_task(int cpu, struct task_struct *stop);
>  
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
> +{
> +	swap(current->alloc_tag, tag);
> +	return tag;
> +}
> +
> +static inline void alloc_tag_restore(struct alloc_tag *tag, struct alloc_tag *old)
> +{
> +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +	WARN(current->alloc_tag != tag, "current->alloc_tag was changed:\n");
> +#endif
> +	current->alloc_tag = old;
> +}
> +#else
> +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag) { return NULL; }
> +#define alloc_tag_restore(_tag, _old)
> +#endif
> +
>  #endif
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 0be2d00c3696..78d258ca508f 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -972,6 +972,31 @@ config CODE_TAGGING
>  	bool
>  	select KALLSYMS
>  
> +config MEM_ALLOC_PROFILING
> +	bool "Enable memory allocation profiling"
> +	default n
> +	depends on PROC_FS
> +	depends on !DEBUG_FORCE_WEAK_PER_CPU
> +	select CODE_TAGGING
> +	help
> +	  Track allocation source code and record total allocation size
> +	  initiated at that code location. The mechanism can be used to track
> +	  memory leaks with a low performance and memory impact.
> +
> +config MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> +	bool "Enable memory allocation profiling by default"
> +	default y
> +	depends on MEM_ALLOC_PROFILING
> +
> +config MEM_ALLOC_PROFILING_DEBUG
> +	bool "Memory allocation profiler debugging"
> +	default n
> +	depends on MEM_ALLOC_PROFILING
> +	select MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> +	help
> +	  Adds warnings with helpful error messages for memory allocation
> +	  profiling.
> +
>  source "lib/Kconfig.kasan"
>  source "lib/Kconfig.kfence"
>  source "lib/Kconfig.kmsan"
> diff --git a/lib/Makefile b/lib/Makefile
> index 6b48b22fdfac..859112f09bf5 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -236,6 +236,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
>  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
>  
>  obj-$(CONFIG_CODE_TAGGING) += codetag.o
> +obj-$(CONFIG_MEM_ALLOC_PROFILING) += alloc_tag.o
> +
>  lib-$(CONFIG_GENERIC_BUG) += bug.o
>  
>  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
> diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> new file mode 100644
> index 000000000000..4fc031f9cefd
> --- /dev/null
> +++ b/lib/alloc_tag.c
> @@ -0,0 +1,158 @@
> +// SPDX-License-Identifier: GPL-2.0-only
> +#include <linux/alloc_tag.h>
> +#include <linux/fs.h>
> +#include <linux/gfp.h>
> +#include <linux/module.h>
> +#include <linux/proc_fs.h>
> +#include <linux/seq_buf.h>
> +#include <linux/seq_file.h>
> +
> +static struct codetag_type *alloc_tag_cttype;
> +
> +DEFINE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
> +			mem_alloc_profiling_key);
> +
> +static void *allocinfo_start(struct seq_file *m, loff_t *pos)
> +{
> +	struct codetag_iterator *iter;
> +	struct codetag *ct;
> +	loff_t node = *pos;
> +
> +	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
> +	m->private = iter;
> +	if (!iter)
> +		return NULL;
> +
> +	codetag_lock_module_list(alloc_tag_cttype, true);
> +	*iter = codetag_get_ct_iter(alloc_tag_cttype);
> +	while ((ct = codetag_next_ct(iter)) != NULL && node)
> +		node--;
> +
> +	return ct ? iter : NULL;
> +}
> +
> +static void *allocinfo_next(struct seq_file *m, void *arg, loff_t *pos)
> +{
> +	struct codetag_iterator *iter = (struct codetag_iterator *)arg;
> +	struct codetag *ct = codetag_next_ct(iter);
> +
> +	(*pos)++;
> +	if (!ct)
> +		return NULL;
> +
> +	return iter;
> +}
> +
> +static void allocinfo_stop(struct seq_file *m, void *arg)
> +{
> +	struct codetag_iterator *iter = (struct codetag_iterator *)m->private;
> +
> +	if (iter) {
> +		codetag_lock_module_list(alloc_tag_cttype, false);
> +		kfree(iter);
> +	}
> +}
> +
> +static void alloc_tag_to_text(struct seq_buf *out, struct codetag *ct)
> +{
> +	struct alloc_tag *tag = ct_to_alloc_tag(ct);
> +	struct alloc_tag_counters counter = alloc_tag_read(tag);
> +	s64 bytes = counter.bytes;
> +	char val[10], *p = val;
> +
> +	if (bytes < 0) {
> +		*p++ = '-';
> +		bytes = -bytes;
> +	}
> +
> +	string_get_size(bytes, 1,
> +			STRING_SIZE_BASE2|STRING_SIZE_NOSPACE,
> +			p, val + ARRAY_SIZE(val) - p);
> +
> +	seq_buf_printf(out, "%8s %8llu ", val, counter.calls);
> +	codetag_to_text(out, ct);
> +	seq_buf_putc(out, ' ');
> +	seq_buf_putc(out, '\n');
> +}

/me does happy seq_buf dance!

> +
> +static int allocinfo_show(struct seq_file *m, void *arg)
> +{
> +	struct codetag_iterator *iter = (struct codetag_iterator *)arg;
> +	char *bufp;
> +	size_t n = seq_get_buf(m, &bufp);
> +	struct seq_buf buf;
> +
> +	seq_buf_init(&buf, bufp, n);
> +	alloc_tag_to_text(&buf, iter->ct);
> +	seq_commit(m, seq_buf_used(&buf));
> +	return 0;
> +}
> +
> +static const struct seq_operations allocinfo_seq_op = {
> +	.start	= allocinfo_start,
> +	.next	= allocinfo_next,
> +	.stop	= allocinfo_stop,
> +	.show	= allocinfo_show,
> +};
> +
> +static void __init procfs_init(void)
> +{
> +	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
> +}

As mentioned, this really should be in /sys somewhere.

> +
> +static bool alloc_tag_module_unload(struct codetag_type *cttype,
> +				    struct codetag_module *cmod)
> +{
> +	struct codetag_iterator iter = codetag_get_ct_iter(cttype);
> +	struct alloc_tag_counters counter;
> +	bool module_unused = true;
> +	struct alloc_tag *tag;
> +	struct codetag *ct;
> +
> +	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
> +		if (iter.cmod != cmod)
> +			continue;
> +
> +		tag = ct_to_alloc_tag(ct);
> +		counter = alloc_tag_read(tag);
> +
> +		if (WARN(counter.bytes, "%s:%u module %s func:%s has %llu allocated at module unload",
> +			  ct->filename, ct->lineno, ct->modname, ct->function, counter.bytes))
> +			module_unused = false;
> +	}
> +
> +	return module_unused;
> +}
> +
> +static struct ctl_table memory_allocation_profiling_sysctls[] = {
> +	{
> +		.procname	= "mem_profiling",
> +		.data		= &mem_alloc_profiling_key,
> +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +		.mode		= 0444,
> +#else
> +		.mode		= 0644,
> +#endif
> +		.proc_handler	= proc_do_static_key,
> +	},
> +	{ }
> +};
> +
> +static int __init alloc_tag_init(void)
> +{
> +	const struct codetag_type_desc desc = {
> +		.section	= "alloc_tags",
> +		.tag_size	= sizeof(struct alloc_tag),
> +		.module_unload	= alloc_tag_module_unload,
> +	};
> +
> +	alloc_tag_cttype = codetag_register_type(&desc);
> +	if (IS_ERR_OR_NULL(alloc_tag_cttype))
> +		return PTR_ERR(alloc_tag_cttype);
> +
> +	register_sysctl_init("vm", memory_allocation_profiling_sysctls);
> +	procfs_init();
> +
> +	return 0;
> +}
> +module_init(alloc_tag_init);
> diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> index bf5bcf2836d8..45c67a0994f3 100644
> --- a/scripts/module.lds.S
> +++ b/scripts/module.lds.S
> @@ -9,6 +9,8 @@
>  #define DISCARD_EH_FRAME	*(.eh_frame)
>  #endif
>  
> +#include <asm-generic/codetag.lds.h>
> +
>  SECTIONS {
>  	/DISCARD/ : {
>  		*(.discard)
> @@ -47,12 +49,17 @@ SECTIONS {
>  	.data : {
>  		*(.data .data.[0-9a-zA-Z_]*)
>  		*(.data..L*)
> +		CODETAG_SECTIONS()
>  	}
>  
>  	.rodata : {
>  		*(.rodata .rodata.[0-9a-zA-Z_]*)
>  		*(.rodata..L*)
>  	}
> +#else
> +	.data : {
> +		CODETAG_SECTIONS()
> +	}
>  #endif
>  }

Otherwise, looks good.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121433.5CC66F34B%40keescook.
