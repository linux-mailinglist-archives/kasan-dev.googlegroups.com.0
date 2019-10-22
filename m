Return-Path: <kasan-dev+bncBDV37XP3XYDRBJHOXPWQKGQENDXZAOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 090EEE03E8
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 14:33:41 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id 4sf4935258wrf.19
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 05:33:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571747620; cv=pass;
        d=google.com; s=arc-20160816;
        b=zuKqi6BEWRjZr3vAbeyyx+kcaNFBU4AsawknGJ2kYtscJJ2WWxxzUy0mdxDp+gjpzy
         Vz2LHz5CNiL+MoP/LeNpTADdFngzKVIYh0M0joC3BqhePqh2jsst8Becs/YB9AbluluS
         PRiL8tlKpnVs0wy667LfHqXTn3dkiUH5Ujqn8/nDFTbRlhBYM3tswT5iHX1ysF5j5K/3
         mRXLNap2nCAo40XfkYK11BXIN2c6ABpD4A7JSZLf20FYO4acyGIJlK64s8cVlWA2PXW3
         TBO4E/p201fPLzfwmOdE2DTF0jYFFDDa0cJhTPeMuV3u5z8xhDqu68+5asIMxNBaIp8y
         vsAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=oinceNibgGF/cCCd/wEKcSA8ps0gfkXbPNhje9t0yvA=;
        b=QpptgswCmIJF/quSzITf40UeNrGiKCpXrQRoB74kA8r+eTrvINiJEdeQQ+H1khVjUs
         J/0dnuI6+/gsRUupfoL4yUH+N2D3dGVt1J75AzZgTV1xkmuvlozjXdrWuRv1zHW/3iYa
         Ymw7tCnp9H8z+YMJ9GPikJpAVt9E1grOeTxJ+sRgvgsRobvHkabg3RAdw+0DfN3kEJkB
         HThjCWg8CJ5Gvckw16P/mGeWX3BDJOhdVxqTzB6DeyNSmJ9MuppsagNL3zAVIL13ihsf
         0zTx+50nXYE9+LRZyclYmvhDO4fi4RHBckETWSvn1Q1TTiADsDPlgpuMZUZq6Sq1G+M0
         qS8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oinceNibgGF/cCCd/wEKcSA8ps0gfkXbPNhje9t0yvA=;
        b=aH/ItL/CVnSoFmwhkTWqBrO5TY6rfx3DVohB4GXhTSCQefpNpXgxuI+Cd/sWybb8/A
         OretZmEYYAO9AKU88ledUqfODE1YAP3ISTL9USrijfNll6gzrnca75O6x9SRuWorcon1
         ESlv9tQ9o5M8v7W5jx2fGWytZO99G7xrRiPcTiOZ3mRGiA0wj/9bosUSTVhUCbwEtOty
         OtkH3dRzAnB5ecEjYPfX1lVlfUN68P6hlpQtkaFVkGkOHmeufwzWFLPPSl89BKBKm0o4
         kIDVapY0ZMO0N6cGjHaf7V8X3v9LFY7OxF5TUHwiK+9jfZS3B8DV6s5pwefilmdQ7T7G
         RYDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oinceNibgGF/cCCd/wEKcSA8ps0gfkXbPNhje9t0yvA=;
        b=XCPPe4j47357UBjrXh8IEJB7pjLCoUnDOw984/sJQBsD/mNj5if1x2bptGNeMnvyHv
         KETkjffykikQAlQGQ7Yj1VTyNUmFWK2P6QWFU9tPX8aDotuA/xF2+IWhyonSVn/PL80t
         uNRO0vOlLxm9WbALJKGXy7g1ogrPDgJgwOMLSVoPtt1PVBy/PEql0UPZpt10GSv4qa1v
         UVFP9Mnaxlq8R74nZ9+8mwwSU1rjel8LBEwm74Vm3B3lg+bRonz9vngtNeuExmbZabc6
         hG+fGdKXdw6QA1aWN1tMhG9lnNToD2VCiDZa1AQHrlQ6kP7x/I+rwxPxM56AQSZp41CQ
         M41A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW08rtB88FMMcw6rkaytSJzfPw7EQ+DBj2X0kmP0AJ+SVUtacqw
	y1DYrmeKcqes++mpS01Jc9Y=
X-Google-Smtp-Source: APXvYqzwZse6p3DK75p6iaVai4PfIz0VGkJCdqovq7KeSVTVsDfJDW0dY1PQWyaSQKLnIMZxSP4IyQ==
X-Received: by 2002:a5d:5544:: with SMTP id g4mr3449736wrw.72.1571747620676;
        Tue, 22 Oct 2019 05:33:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9e01:: with SMTP id u1ls9206456wre.15.gmail; Tue, 22 Oct
 2019 05:33:39 -0700 (PDT)
X-Received: by 2002:a05:6000:128c:: with SMTP id f12mr3536645wrx.279.1571747619641;
        Tue, 22 Oct 2019 05:33:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571747619; cv=none;
        d=google.com; s=arc-20160816;
        b=fZnFNy06ocvvR9nqU1SftVIaIz0wEIpEpcmFDqcsK7zYRbR7sYJEcAwmhdPsV5zZxA
         4gWqeuuWWCHYhMCsBlqiYyNdSnc7i0UGJiNm7fRVPCQZ6pZgSA7tGVEo7UyZqjHn1aq5
         xgrTI3xy694fEtkZKGuQxe+EEXyQ0KYjMgyEixPFsaKaJzNl3EM4yoT+d4ZMsalcu/GX
         oxaVFCHeNM9JZAYIUk8WQV5YjWm56fWmsxNcEWM4KIgqcF7I8Riacluk0LWccuOjutmw
         HaNOYh8xojBjkj+/JKmF1yGtzd8DP1bZJP6lnL9eZ0gxnB2lMcH9RkXKuqpV17ZY/uud
         JRlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=qsGt3N5rGVfaOOeW7Dg4DMSXXksc7lobb5TBoauX9QI=;
        b=glvOI/QrCk/w92ZWOTYSsuFMATQkhxwFD/1ipYOmnI/t2tc6OwKdgPUm6p6Le3Qydj
         uJHUy/JTgX6hW3ykba5OIsPcFQniskkhRQYfn3QXZH7xZe+w33XHFpiva2FqXReyb9KX
         HFClAMj4srtfgbi3lloS1FboDau1zKHbXe845R8kLiHL+Rh77wgC/FLSiyOHRpBLLs80
         K8ljWKejUeetAdmhXS1BdIsHpSpw72kbPTyP/ouNtQ2sZlrnY3muNMc6kY2J2dbS7Jtl
         3RMD/T2iQu7LTD+L/l8liou4jVzfi6zY+MOzFvEql5drowCXIomDNn01e8I6G/RcQhCf
         jYcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com ([217.140.110.172])
        by gmr-mx.google.com with ESMTP id 5si1614949wmf.1.2019.10.22.05.33.39
        for <kasan-dev@googlegroups.com>;
        Tue, 22 Oct 2019 05:33:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D49D215BF;
	Tue, 22 Oct 2019 05:33:36 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5A5DA3F71F;
	Tue, 22 Oct 2019 05:33:32 -0700 (PDT)
Date: Tue, 22 Oct 2019 13:33:30 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, npiggin@gmail.com,
	paulmck@linux.ibm.com, peterz@infradead.org, tglx@linutronix.de,
	will@kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 7/8] locking/atomics, kcsan: Add KCSAN instrumentation
Message-ID: <20191022123329.GC11583@lakrids.cambridge.arm.com>
References: <20191017141305.146193-1-elver@google.com>
 <20191017141305.146193-8-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191017141305.146193-8-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Thu, Oct 17, 2019 at 04:13:04PM +0200, Marco Elver wrote:
> This adds KCSAN instrumentation to atomic-instrumented.h.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Use kcsan_check{,_atomic}_{read,write} instead of
>   kcsan_check_{access,atomic}.
> * Introduce __atomic_check_{read,write} [Suggested by Mark Rutland].
> ---
>  include/asm-generic/atomic-instrumented.h | 393 +++++++++++-----------
>  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
>  2 files changed, 218 insertions(+), 192 deletions(-)

The script changes and generated code look fine to me, so FWIW:

Reviewed-by: Mark Rutland <mark.rutland@arm.com>

Thanks,
Mark.

> diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> index e09812372b17..8b8b2a6f8d68 100755
> --- a/scripts/atomic/gen-atomic-instrumented.sh
> +++ b/scripts/atomic/gen-atomic-instrumented.sh
> @@ -20,7 +20,7 @@ gen_param_check()
>  	# We don't write to constant parameters
>  	[ ${type#c} != ${type} ] && rw="read"
>  
> -	printf "\tkasan_check_${rw}(${name}, sizeof(*${name}));\n"
> +	printf "\t__atomic_check_${rw}(${name}, sizeof(*${name}));\n"
>  }
>  
>  #gen_param_check(arg...)
> @@ -107,7 +107,7 @@ cat <<EOF
>  #define ${xchg}(ptr, ...)						\\
>  ({									\\
>  	typeof(ptr) __ai_ptr = (ptr);					\\
> -	kasan_check_write(__ai_ptr, ${mult}sizeof(*__ai_ptr));		\\
> +	__atomic_check_write(__ai_ptr, ${mult}sizeof(*__ai_ptr));		\\
>  	arch_${xchg}(__ai_ptr, __VA_ARGS__);				\\
>  })
>  EOF
> @@ -148,6 +148,19 @@ cat << EOF
>  
>  #include <linux/build_bug.h>
>  #include <linux/kasan-checks.h>
> +#include <linux/kcsan-checks.h>
> +
> +static inline void __atomic_check_read(const volatile void *v, size_t size)
> +{
> +	kasan_check_read(v, size);
> +	kcsan_check_atomic_read(v, size);
> +}
> +
> +static inline void __atomic_check_write(const volatile void *v, size_t size)
> +{
> +	kasan_check_write(v, size);
> +	kcsan_check_atomic_write(v, size);
> +}
>  
>  EOF
>  
> -- 
> 2.23.0.866.gb869b98d4c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191022123329.GC11583%40lakrids.cambridge.arm.com.
