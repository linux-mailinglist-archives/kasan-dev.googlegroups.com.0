Return-Path: <kasan-dev+bncBDV37XP3XYDRBIXZTPWQKGQERUGEEKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 015A3D8F2B
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 13:18:59 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id g21sf4689009lfb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 04:18:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571224738; cv=pass;
        d=google.com; s=arc-20160816;
        b=zs4akt89LjTOcqvA+C5wjA3PHDhMPVwOOWmAQfckDSJluTPFfRc0ZB7bduQ7H+bx3r
         H1g5u+x9SK/obx/sodm54Zwa39crTlSl1SYaNURNjmlvlaByJjzae9Z1sx65gvImxbyt
         bvt0DfAYj8P1i7u/SOEd0kWefG4Z2g7rNBM6yj1/cwo9wSfTcsw7zXKBivClsDA6k2DL
         4M7dDiIdUonNxEcQ2pFc8n1AuxjaGw/y1aiwaKPHEexG1tfYhIGxyZPonVRqLswUcNHg
         5xYOLPKkwZgMt2wYYl8+TZFF8l/tHyCn7DNe73w4lmyCy6hyZTx3kIwCZ0xM8BUNaRNg
         f0ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=qcQHUX3OLwxP53tzPGaTTseFgclA135JzIxwzNLep7g=;
        b=XLMFp6Xgrc75dcDUPER7UaBbBCJ81tJKPrH4xryeyo+DjgzrqNFdw5XilGwO7rUxaZ
         7TWttWbJZ3qv9FRlJj5XLkK81bGYiLRcYj+mwSwW3T6Q1h3ehVUA15GPogc42Aj46ZOL
         d22I2bhxfBokUc/ECSFif2Pq9OmN0ZceThVp9E+iyVkfnOKQhI+YJaEfo4NKRlo23RbW
         eyT9r4lztf/YocONXUXf9UEESi7mYgYk0h/zlfcy8h3TzBVn7Z4GRmFtq/bxNmdu4lvk
         ItYATga92qXOXHQlFp8MiG0xYcdyeArAwke4ow2dymVAMfCFVk8a/eB9vzv/uX5Dw0SN
         34Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qcQHUX3OLwxP53tzPGaTTseFgclA135JzIxwzNLep7g=;
        b=oNloDRt2fShwmY5OPtRyrGu68hTPtSvGq0PbJ0m/C5WTXPz5EhgdpLOquRw2ZHxJDL
         vTN4vsywBuck2RGBCTqz7BlGtZEjOXumBCzAjv393NM5vCZX7VzKGf1ckcvXN2sTtZnf
         Fe2G+Hf+E1nN1KeSb6nmzL3u+s7UZesNtZJ7WDjFrvpXPacRgVZTI3a2MYKqbzLU+7oY
         yV8ZN9V3GKuup3HgODTxAMfuZjwhJrOvzhZrB2aoWoOXUgXfZHJ06C0MpA6rpaJyl5Do
         CkE/jRES/t8tP6S2MERwmvzFdezbEXHGeA6pL/dEDy71ia0rogF87U746xJkUp93oJo6
         bEAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qcQHUX3OLwxP53tzPGaTTseFgclA135JzIxwzNLep7g=;
        b=tT9B9mf0sItBBf8WTDKibMA3xdyTN5ZAs5sA/Xv7R86ESbgDStgB3Whw4hJOJcSi0F
         cSfVnlxgUsfvdi6CCAIBqWHbJ9KWEgv7GsPxyrWUjO6AICr8qY8saBL0jdBSk7RjRK9Y
         Y0MXrtxBNAzyql3CfzpicaFs6HmeMjbNUL1LK3h95ntVWQGjpwC1vBTzuK/3/PFpuj+2
         p5V0HPzN5ugPdIsV+/lBZXqcgfGjeA4LNzD/5XBYQlcfakFzMz/4HumEV6D630aMK+pK
         bZTIly3BySbgWdjek6DNYTgnVz0iPJA1Ds9/N0OQ/wWHeeF666hOtQMhBldGBsw4I/ph
         TBoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU7ytj7nhm4t1+4s5u3e/nX/GDLMLcMXhQozNV13YyuXjJDcFjc
	rCxIvBagVYq6L3Gg5SesmDw=
X-Google-Smtp-Source: APXvYqxiama2gKq74vEpd1p5Z5QRDOCTyaukuST/VDqX+zjsNvTmx4phrCDx5ewZnC7yIeY9tqRr5g==
X-Received: by 2002:a19:491c:: with SMTP id w28mr24202756lfa.124.1571224738462;
        Wed, 16 Oct 2019 04:18:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:651a:: with SMTP id z26ls2673719ljb.2.gmail; Wed, 16 Oct
 2019 04:18:57 -0700 (PDT)
X-Received: by 2002:a05:651c:1213:: with SMTP id i19mr19054938lja.19.1571224737716;
        Wed, 16 Oct 2019 04:18:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571224737; cv=none;
        d=google.com; s=arc-20160816;
        b=z3wuNxI9CebUzbQ9+aZkZsZ+7I/jDdV+605r62EvVjNZWpA370dvxLmz6sECtp8YJF
         kvgW/BJIEuM9fRST7Dh9brQYmCPVASRUB1oQI/rUF68wnXU/wZ9vk6Cls52um7VfuPBI
         co2A2mMjicSbxeDWhfGuMSnAls4QH4iPLoHIdL/h+ISCYWU6w/rCjOJD7TcJ0nSdPFHI
         MtOJetRYMjJpJpxXAsFTBFQU8kkLf83/wKw40D7cBCH5cquZa9TZm8Ck6S4H9rxUNWXf
         I1T0QWtSOerMxN5w7xxcbkrZLRLCyHqAhW/q9+G3YyVEY6GBJqBvV/hSMK/0UHka9xq1
         1xvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=j7HHOUB6bpZeZILL1pUEQ3J3EW9j1OHFAgT0qYk+n1Q=;
        b=KJYvN17EstUBeqZrcZgDRJnTE7ALH3YZL3M3nY+La3II+yeyumyFfgcCLZXgCOsE8B
         K/dpSneIhSBQMpL53rIrhohIyuIg/YfDh5tTplBfqIxrZLp7FH0IKAkFWfgHpQi6vvf5
         H+RDQ7KvkDT/Jhgl3eBnZevbdqQiH8GR9S1r4bWZMcpnXjuzMD6yCMDwfz/jknVFYJrb
         1YXCMpDqVddc/1fE4KfNpYC/lTOuOkU/E+ljsd+UJYRG6RHV6J3zEwieehr9Jxfwpnn5
         jb8E9k0iX//D+D2KGxFgO4SrnRL/RWU6D03Jf2otpmjWhlTDrQSEDcvOEkkvY2+x9TxS
         MCzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z4si1601051lfe.4.2019.10.16.04.18.57
        for <kasan-dev@googlegroups.com>;
        Wed, 16 Oct 2019 04:18:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 005F828;
	Wed, 16 Oct 2019 04:18:54 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2B2573F6C4;
	Wed, 16 Oct 2019 04:18:50 -0700 (PDT)
Date: Wed, 16 Oct 2019 12:18:47 +0100
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
Subject: Re: [PATCH 7/8] locking/atomics, kcsan: Add KCSAN instrumentation
Message-ID: <20191016111847.GB44246@lakrids.cambridge.arm.com>
References: <20191016083959.186860-1-elver@google.com>
 <20191016083959.186860-8-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191016083959.186860-8-elver@google.com>
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

Hi Marco,

On Wed, Oct 16, 2019 at 10:39:58AM +0200, Marco Elver wrote:
> This adds KCSAN instrumentation to atomic-instrumented.h.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/asm-generic/atomic-instrumented.h | 192 +++++++++++++++++++++-
>  scripts/atomic/gen-atomic-instrumented.sh |   9 +-
>  2 files changed, 199 insertions(+), 2 deletions(-)
> 
> diff --git a/include/asm-generic/atomic-instrumented.h b/include/asm-generic/atomic-instrumented.h
> index e8730c6b9fe2..9e487febc610 100644
> --- a/include/asm-generic/atomic-instrumented.h
> +++ b/include/asm-generic/atomic-instrumented.h
> @@ -19,11 +19,13 @@
>  
>  #include <linux/build_bug.h>
>  #include <linux/kasan-checks.h>
> +#include <linux/kcsan-checks.h>
>  
>  static inline int
>  atomic_read(const atomic_t *v)
>  {
>  	kasan_check_read(v, sizeof(*v));
> +	kcsan_check_atomic(v, sizeof(*v), false);

For legibility and consistency with kasan, it would be nicer to avoid
the bool argument here and have kcsan_check_atomic_{read,write}()
helpers...

> diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> index e09812372b17..c0553743a6f4 100755
> --- a/scripts/atomic/gen-atomic-instrumented.sh
> +++ b/scripts/atomic/gen-atomic-instrumented.sh
> @@ -12,15 +12,20 @@ gen_param_check()
>  	local type="${arg%%:*}"
>  	local name="$(gen_param_name "${arg}")"
>  	local rw="write"
> +	local is_write="true"
>  
>  	case "${type#c}" in
>  	i) return;;
>  	esac
>  
>  	# We don't write to constant parameters
> -	[ ${type#c} != ${type} ] && rw="read"
> +	if [ ${type#c} != ${type} ]; then
> +		rw="read"
> +		is_write="false"
> +	fi
>  
>  	printf "\tkasan_check_${rw}(${name}, sizeof(*${name}));\n"
> +	printf "\tkcsan_check_atomic(${name}, sizeof(*${name}), ${is_write});\n"

... which would also simplify this.

Though as below, we might want to wrap both in a helper local to
atomic-instrumented.h.

>  }
>  
>  #gen_param_check(arg...)
> @@ -108,6 +113,7 @@ cat <<EOF
>  ({									\\
>  	typeof(ptr) __ai_ptr = (ptr);					\\
>  	kasan_check_write(__ai_ptr, ${mult}sizeof(*__ai_ptr));		\\
> +	kcsan_check_atomic(__ai_ptr, ${mult}sizeof(*__ai_ptr), true);	\\
>  	arch_${xchg}(__ai_ptr, __VA_ARGS__);				\\
>  })
>  EOF
> @@ -148,6 +154,7 @@ cat << EOF
>  
>  #include <linux/build_bug.h>
>  #include <linux/kasan-checks.h>
> +#include <linux/kcsan-checks.h>

We could add the following to this preamble:

static inline void __atomic_check_read(const volatile void *v, size_t size)
{
	kasan_check_read(v, sizeof(*v));
	kcsan_check_atomic(v, sizeof(*v), false);
}

static inline void __atomic_check_write(const volatile void *v, size_t size)
{
	kasan_check_write(v, sizeof(*v));
	kcsan_check_atomic(v, sizeof(*v), true);
}

... and only have the one call in each atomic wrapper.

Otherwise, this looks good to me.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016111847.GB44246%40lakrids.cambridge.arm.com.
