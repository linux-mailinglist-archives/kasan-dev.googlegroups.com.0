Return-Path: <kasan-dev+bncBDW2JDUY5AORBBPESWPQMGQEVUBPRCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id D73D469132F
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 23:22:00 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id i8-20020a6b7908000000b007132e024fb5sf2205013iop.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 14:22:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675981318; cv=pass;
        d=google.com; s=arc-20160816;
        b=TPIwrdsMLCw+2ijB8vTB7oYtU5tnJ5nY3TDnJFlAslbofqGTLLCrKe5uL+YFs3ZO0c
         NWz+P6trBiAcBKVQAd2t4jhBLNr2E/4TuOEoSVQRjpYwcVF/ZpnLYctr5YOBThK8ekea
         qIKtfMDwY0KuM2uWhLuZtgFQTvc/ven0MJIPCX9/b1DbJt3DBqi4gV3oGYWeQBmv2Zzr
         fy8N/heEfO8Wthkz7jIvcAFq9NSi0Q/bWCvNsluAPaist1VkwNYT+6nZhZGobSy21WvC
         jLFsRdwK31kog71x0mAbicocDytR3ir/1R8n0hgOyemqwHdsxGaLU8hgJcPJAum33joD
         pSdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=nTn6i5MSDjKOS3Tht2manZxe2IvNVgP2ULCkjvZJR/g=;
        b=W0c9CGSQ7z0vV4bzQNIo95+Yx9vyTs6gRlzN82HRHYNKQFuK9/H4UHYpKHinrXfUrH
         87CyH1DflCfZkkdKEkhDtKPgGh75PpkdCztD2F5D8X5xvbY1aMY9iPN90vAkngVPQPkN
         /NvxCZ89sXWs6pEiEwKMTNCCsE4Sb0MmK8s6Q74M98mUs0BjT3bdIqSaGnc8WhMeTxVn
         gS4zTCHXDQ8O8FqBsu0iKtYggKImjXPECdR+j+IAf4ZJEEE+tNKcN//qh7fNa945FPo9
         v6IPbKKOkonzSxUWcmYSd7NMPUW1E5FedbNQAbb1A2GbR6oGk03YGeQbsmlk+itSZoQN
         p+SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G66azLLs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nTn6i5MSDjKOS3Tht2manZxe2IvNVgP2ULCkjvZJR/g=;
        b=QGNCIU6HyLwQJuOwazETZ7G0Tu/3KJvKwtgD24zgIZfDxc3MvrpvnGi0fVLikp/D6x
         Xeh9jbX903uPUESPN9VEEikngd5AmAA4mGiOox0uI5mK4ZHCVOC7Qh+q5RbOoxj6QvV8
         7v7TVquIpngILWb8g9+ZbnnuVMJkLzOOiJ5ON6zugb3KOrlULL5J0Ae4OywBt9CNeByl
         86+PTSoyapBkKln+NiPOIMqUXTGNRYhFDzSkNfglBVnGSxWXI1mPwzF6wDTjDo8cQ/Ht
         Nw7owJlcfo6wEuMU4QG3avnrsx/R5no5fKjjTW3m4f4U0nm79cDBnomAw/izkyxluyee
         4uJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=nTn6i5MSDjKOS3Tht2manZxe2IvNVgP2ULCkjvZJR/g=;
        b=Tzdw+QQibKGMQYfo5AnEo8WDJMhuQ3cvrckcSiA6DXivO/CXp7K9UzcJBPJTYvAO1W
         Vf6VUshLPwQCsyghJojNELXTDCz1EfkxuIuDZDBhCaYOmM0s18iQ6j90KO8hJrobAXZG
         sGrB54rluAgtI3eanTxK9ploRwqTiiiFZgH2mdjElqm7J8Kibz/DM71suInyGML/CjnI
         V7aFhSlMNwejdAY3yR8RRMdHSlZ8jj24FaVNfjGeLlBaODiS2cd/YLXDcsQZBPy4h3UD
         y160AeB1KvTBDpwCWe1II3+meWrZsXSDRiplLiNzvdMwCoNbcY9kj7D5ELdvQaEFZ5GJ
         EZnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nTn6i5MSDjKOS3Tht2manZxe2IvNVgP2ULCkjvZJR/g=;
        b=CSAk04/bsZdBdMKImYszWndY/O+uC1ziGulewcGJUNYMDIBLGcHfjmmpIflqKKffl3
         gbzcna0oBRaesG3eJNICCkxYh1eaxPaqgfHRCknA9v0bZCffNk2S9+ATpupjQ2rKnShX
         INZSmHOrK2+pTh9e0BUIbXze2Xb26CQK8JLVygnxXRR+n+kOGkccxj87iIw5gDv3KXcA
         nfY7cJDBD8rjp76KKCPfEEQRtGrJElGy1k/3AA5yUlZX8m2LmB1E+putVYlhO8av50PE
         nIiaxChWiFLazDuyZLsxhXVQRL971clyawiYYDQv6U9Gn1yIehT9T0wW26iF/72am9gL
         sE9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVA52Ty+VJO2G18KCZ1egF8PhdvqTMam/UABHcnu5WBNiKETE6W
	fwNBO9ntEZ7PEMbmPPsWqBQ=
X-Google-Smtp-Source: AK7set8vAvHMZiBA2A39yjk+LfCY6Ap2z0bAjK5s9h9YkSFMlDtlyAMXrb6dmH+8FekxajhFkSEfFg==
X-Received: by 2002:a02:bb12:0:b0:39d:234a:8f18 with SMTP id y18-20020a02bb12000000b0039d234a8f18mr7788288jan.123.1675981317421;
        Thu, 09 Feb 2023 14:21:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:194e:b0:30c:27a9:a355 with SMTP id
 x14-20020a056e02194e00b0030c27a9a355ls1439119ilu.3.-pod-prod-gmail; Thu, 09
 Feb 2023 14:21:57 -0800 (PST)
X-Received: by 2002:a05:6e02:1605:b0:310:e7bd:c33d with SMTP id t5-20020a056e02160500b00310e7bdc33dmr15622410ilu.8.1675981316966;
        Thu, 09 Feb 2023 14:21:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675981316; cv=none;
        d=google.com; s=arc-20160816;
        b=nuHiH9Ezzr1R6DTkclLNam+C+G/pNkcwaesQJgobGeJgKicLPRQFmbVzlQh/qT3ApM
         7wzCrRrlVRSIafgR7VJD5M4zpf8UHqJyY7aAxt7t1DSPmsl2NVeEueZtEXWqihhw0YGs
         Nq2q+nPrYn0kxRzdYRWmz+Kp3rCMcbZT6m9NkWeyoTpNYxcoN81cSphpsCP09ppm/F1W
         vtTx/FMKE244fh34GJq0mviHIFYTAkB/QCWcf8Nd5dtkO7/490K60NLrPL/FZGZmwB5P
         +tBzWU3LUvVaHKej+U4eIfKs5KpkmqYm73kjwMjiz1+LqCJxKHmbz8lI3WVKGIapbpTT
         u1ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HBgooxc0T8xR3a6LCddpzQrYzp6lIglbhu4rq7s0u6g=;
        b=BaR7rgWFqpBec6c2qs3T1MaLfANjy0+oFJfDH8JsuuQpWFdQp2PAdUHKYr2g/wPVpo
         lyoMP5zibvcKMvj8sCB1PBfOodnV9X2IlIwq8HFrKpf8sgaRyHVgFedeAlwU1gdIQPwc
         N2SDY+DUaDZiBUsiGZfSav5w70Rooo0U+gjxs/bg+RczOyfeq+In88gkdeLITYlfUG7p
         qKvuo4yZ1Qb0YCepKHTO8A8ju291drSNNJWLDig6dy3+AnMzS16Z0QYGPswn3WGgDiDy
         Moy2LWzGwGQfIAljXf8jBPBqX+pE9kfuTGNvyOZP/++oflmdAUtNRaBrogtCz11HhFal
         4O/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G66azLLs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id ca15-20020a0566381c0f00b003b1f379322esi311436jab.6.2023.02.09.14.21.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 14:21:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id m2-20020a17090a414200b00231173c006fso7030538pjg.5
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 14:21:56 -0800 (PST)
X-Received: by 2002:a17:903:22c1:b0:196:6319:a029 with SMTP id
 y1-20020a17090322c100b001966319a029mr3284169plg.12.1675981316316; Thu, 09 Feb
 2023 14:21:56 -0800 (PST)
MIME-Version: 1.0
References: <20230208164011.2287122-1-arnd@kernel.org>
In-Reply-To: <20230208164011.2287122-1-arnd@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Feb 2023 23:21:45 +0100
Message-ID: <CA+fCnZe_BYgXff6OnU+L4SJC1kbzse9VtdwUS7tQinudL7n=Jg@mail.gmail.com>
Subject: Re: [PATCH 1/4] kasan: mark addr_has_metadata __always_inline
To: Arnd Bergmann <arnd@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Arnd Bergmann <arnd@arndb.de>, 
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=G66azLLs;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Feb 8, 2023 at 5:40 PM Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> When the compiler decides not to inline this function, objdump
> complains about incorrect UACCESS state:
>
> mm/kasan/generic.o: warning: objtool: __asan_load2+0x11: call to addr_has_metadata() with UACCESS enabled
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  mm/kasan/kasan.h | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3231314e071f..9377b0789edc 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -297,7 +297,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>                 << KASAN_SHADOW_SCALE_SHIFT);
>  }
>
> -static inline bool addr_has_metadata(const void *addr)
> +static __always_inline bool addr_has_metadata(const void *addr)
>  {
>         return (kasan_reset_tag(addr) >=
>                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> @@ -316,7 +316,7 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
>
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> -static inline bool addr_has_metadata(const void *addr)
> +static __always_inline bool addr_has_metadata(const void *addr)
>  {
>         return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
>  }
> --
> 2.39.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe_BYgXff6OnU%2BL4SJC1kbzse9VtdwUS7tQinudL7n%3DJg%40mail.gmail.com.
