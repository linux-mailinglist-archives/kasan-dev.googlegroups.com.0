Return-Path: <kasan-dev+bncBCT6537ZTEKRBRE65SNQMGQEEJDWEAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id E6ABA63198E
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 06:40:22 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id b1-20020a17090a10c100b0020da29fa5e5sf5422414pje.2
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Nov 2022 21:40:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669009221; cv=pass;
        d=google.com; s=arc-20160816;
        b=g/cYaxL3UV3qHGCOtqWLqq/VyfkiCxdhx58cLpH2bF9xooqt1f8qqqbC9wamhSrKXr
         FOhUPZBDXRzqPGK6VIvL4HnHcUP9ZfUOIW1Ig4vKMUQO9V6+JNLwtfDUCOyrMvD0PcvK
         6g3nZXpjq+s56yxTc2LtDk3jjm74OPdgkJrD72krJVrJ9jeI+ccd0kPyKbmM6TpMJmKC
         8G3rVKd82tx6Kn5DN+g8TAta63QVSiJMPXID6+w0TGqvH1HG8Git4tPpVVffWpZ0oaCy
         BSYeErPgBe0hbBp+aBbBVexhx15sHJS6OaUESmwSJBHkOqNnGW+mmNEKbPCuquu7Wfrk
         NkxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=N6PyG5jkn6I0dhYirmCFitk7LnbFBQUvUCh+75YeVu0=;
        b=goqJ+JdS3xjkUD+EHcPVnV8+Z14zRe7tKjDUXd/HuObZHpqKnEcQ4z9uZfiau9s1EW
         eQhr2cq3QLKr91ErOBzBukFB1XroGQgTIPwI4GCYSNoxinvCnTqATp2MX2abV7ZL8HBq
         5Zu1YDqbY8jHFFxWX/llNjwyECvIQ+gz0iDvmn6Cj1cgcIcxErOIJszoOnu+S0HYgkRA
         BOMaoHcEpldc/weQvzt2DZVNbl5+75zwtwrfF0f6j+/orNkwNozNs+UH1LC3KK0F/Hhd
         Rs8hPvdotMnx9GxrasA7MSWdjsbJhKUB7wirC2/2SZp/Xh5Ik4vpXK4lc8ItQS+WYDJ8
         +nvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=jF3s06QC;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N6PyG5jkn6I0dhYirmCFitk7LnbFBQUvUCh+75YeVu0=;
        b=Z/uVUs3Ayq2GzX4CP7RgZE5gFiGg21NwSNnOjd58FV0g44BEmSZ7+asz1LidBhuDMz
         Z9XqFyUjIhkJtafbsg+DAg4VAXuRyU/J1OHOmSTLK4iiTc9VZYXQhzd+jWOQdr6NPmVx
         rcTbfYVe7QyOqL3FCd0Os/wD0fhvd83CDCmnqlbZETNXeZkKjxM+cBkG3zGZpRU6+96F
         ttixEXdX1uhi742Pd94jHuYyD2D34QEz22WoNVHDN3gH82o9XR0qcQXx0Gxns0mAG+k2
         Gcumk9lbgBDANQGM07fS5PNvZmTvJTXhA1KAb0xzam8XJOLteuwFeXnW6zoVO23JPAME
         Efbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N6PyG5jkn6I0dhYirmCFitk7LnbFBQUvUCh+75YeVu0=;
        b=Nh6kjQiQ8EQyBPuwfwXoshq6N/NSO9s3UC485tJf7vOfozq17//o8zwqKpNEH08yKF
         J/3kZEI+4dZR+T3carFY5pde/ySXIZLCemQcD9CwiQnkKby+LrrNAIDIpvDs5y02xyil
         rV3REX8UudepVDoGlmw3nbuEd8kNN3tJRGP+fYN7DMm9n94qtt2YXbEvzhjanQ4aKRTE
         BHuKSoWmrOMZreRpDAKYIOt33CXXBqZLQh8Vz6dCNysjLL9eHyHCTMxeQ6+Bdt+OMohK
         7EXGP+yTDtCqD+GbPM4fUyUCjgSZX5SZvet73xyCYe/kgDHD7uoNVWJ05B1mpCZDp8IO
         6EqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnx7YO7xN4c3nEu6KSSX57QBXbbTc8q4CP1O5Xo/fhRT4ZoVUnN
	cZVAA3v56HItWvkN58RyywU=
X-Google-Smtp-Source: AA0mqf4AuNCwLFAh7h5EN8+eauF6XzxmdKFb14xg1MfXXvhhnyKSIAZCEZbDhFZJ1XE4x7vnG9MYBA==
X-Received: by 2002:a17:902:6b44:b0:188:afa9:ba76 with SMTP id g4-20020a1709026b4400b00188afa9ba76mr1577339plt.58.1669009220989;
        Sun, 20 Nov 2022 21:40:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:73ca:b0:214:246b:918a with SMTP id
 n10-20020a17090a73ca00b00214246b918als10712942pjk.2.-pod-canary-gmail; Sun,
 20 Nov 2022 21:40:20 -0800 (PST)
X-Received: by 2002:a17:902:db0b:b0:173:f3f:4a99 with SMTP id m11-20020a170902db0b00b001730f3f4a99mr895305plx.79.1669009220285;
        Sun, 20 Nov 2022 21:40:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669009220; cv=none;
        d=google.com; s=arc-20160816;
        b=BGV/kZcHppqc4Jn5BjOXEFSmFIKPoNwdU/B1LgBOkpkbY3zWgLadqhJ3/bDJaTw830
         o/IvEr9yP7VLAgHZZt0WQicDLW1WgyE53hRkKxd+ADfkbCJOkp7X9mdSjRZigH1odtfM
         s8jqiXvm09TObl32oF1E+zda6pVeBlZJeQMe7s659HI3bOxA1L8xE6qUZbp35zwc362n
         LRu7XyAWSEmoydYMB6kxZGHrs7yQ+Y8OBa6p/ygUq+LhQjSVc3LYsGbGxhJBcwwaJVVT
         mbWmCzwHfSluPztz8vNS082Ca0l9gkh+KITYUErzHGT9YCxdjnxcjxB13tg8OWFfEzHN
         qE3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/0dujvI66k8dvZ4+iOLkypH8JCTwbnK/z2RJps0YrtI=;
        b=Cn4DH5zGMWhrA5x1rAa5MY5HoDHteM4u0XOAdgNHY/UcEVH7ZW89/g7YHasnUUqEza
         gBiUnyD+t4TbFmKlQTjKYTUXdM54DYn3N8+nxedwgfWc+wAuUZPksyUfUU/u+IHq0T1p
         sdEVfnVUvqXjXfvEH09OoDlHjLgGT0DCCe2KZ1pSVL7uzdqIRFGQLdL28NTb1KShe3Ra
         FoNfuLd9hR+TYT9svd5fEaiZ9XZfT7QBiEdD/y69AL1cVIYHpN9IvorM7Lb4Lqjwq3CC
         qvlfzvTWbOzyDHjmSJstcCsjwhToiyEZh8mbcDCDkABr4AeTPhAelFmGIQnlJtcNTKEv
         Vayw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=jF3s06QC;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id mn22-20020a17090b189600b00212bf9345fasi462801pjb.2.2022.11.20.21.40.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Nov 2022 21:40:20 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-3704852322fso103609227b3.8
        for <kasan-dev@googlegroups.com>; Sun, 20 Nov 2022 21:40:20 -0800 (PST)
X-Received: by 2002:a81:142:0:b0:396:56a9:512b with SMTP id
 63-20020a810142000000b0039656a9512bmr11564228ywb.459.1669009219299; Sun, 20
 Nov 2022 21:40:19 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
 <Y3Y+DQsWa79bNuKj@elver.google.com> <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
In-Reply-To: <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Mon, 21 Nov 2022 11:10:07 +0530
Message-ID: <CA+G9fYt7WQWKNaNeTnxo19h9i84p5nVemqgwJkQQGeOmt14b_g@mail.gmail.com>
Subject: Re: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46 kfence_protect
To: Dave Hansen <dave.hansen@intel.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	regressions@lists.linux.dev, lkft-triage@lists.linaro.org, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=jF3s06QC;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Thu, 17 Nov 2022 at 20:04, Dave Hansen <dave.hansen@intel.com> wrote:
>
> On 11/17/22 05:58, Marco Elver wrote:
> > [    0.663761] WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46 kfence_protect+0x7b/0x120
> > [    0.664033] WARNING: CPU: 0 PID: 0 at mm/kfence/core.c:234 kfence_protect+0x7d/0x120
> > [    0.664465] kfence: kfence_init failed
>
> Any chance you could add some debugging and figure out what actually
> made kfence call over?  Was it the pte or the level?
>
>         if (WARN_ON(!pte || level != PG_LEVEL_4K))
>                 return false;
>
> I can see how the thing you bisected to might lead to a page table not
> being split, which could mess with the 'level' check.
>
> Also, is there a reason this code is mucking with the page tables
> directly?  It seems, uh, rather wonky.  This, for instance:
>
> >         if (protect)
> >                 set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> >         else
> >                 set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> >
> >         /*
> >          * Flush this CPU's TLB, assuming whoever did the allocation/free is
> >          * likely to continue running on this CPU.
> >          */
> >         preempt_disable();
> >         flush_tlb_one_kernel(addr);
> >         preempt_enable();
>
> Seems rather broken.  I assume the preempt_disable() is there to get rid
> of some warnings.  But, there is nothing I can see to *keep* the CPU
> that did the free from being different from the one where the TLB flush
> is performed until the preempt_disable().  That makes the
> flush_tlb_one_kernel() mostly useless.
>
> Is there a reason this code isn't using the existing page table
> manipulation functions and tries to code its own?  What prevents it from
> using something like the attached patch?

I have applied this patch and found build warnings / errors.

In file included from mm/kfence/core.c:34:
arch/x86/include/asm/kfence.h: In function 'kfence_protect_page':
arch/x86/include/asm/kfence.h:45:17: error: implicit declaration of
function 'set_memory_p'; did you mean 'set_memory_np'?
[-Werror=implicit-function-declaration]
   45 |                 set_memory_p(addr, addr + PAGE_SIZE);
      |                 ^~~~~~~~~~~~
      |                 set_memory_np
cc1: all warnings being treated as errors
make[4]: *** [scripts/Makefile.build:250: mm/kfence/core.o] Error 1
In file included from mm/kfence/report.c:20:
arch/x86/include/asm/kfence.h: In function 'kfence_protect_page':
arch/x86/include/asm/kfence.h:45:17: error: implicit declaration of
function 'set_memory_p'; did you mean 'set_memory_np'?
[-Werror=implicit-function-declaration]
   45 |                 set_memory_p(addr, addr + PAGE_SIZE);
      |                 ^~~~~~~~~~~~
      |                 set_memory_np
cc1: all warnings being treated as errors
make[4]: *** [scripts/Makefile.build:250: mm/kfence/report.o] Error 1
In file included from mm/kfence/kfence_test.c:26:
arch/x86/include/asm/kfence.h: In function 'kfence_protect_page':
arch/x86/include/asm/kfence.h:45:17: error: implicit declaration of
function 'set_memory_p'; did you mean 'set_memory_np'?
[-Werror=implicit-function-declaration]
   45 |                 set_memory_p(addr, addr + PAGE_SIZE);
      |                 ^~~~~~~~~~~~
      |                 set_memory_np
cc1: all warnings being treated as errors
make[4]: *** [scripts/Makefile.build:250: mm/kfence/kfence_test.o] Error 1

ref:
https://builds.tuxbuild.com/2HqMWcweeInju7rqVgGdNge7gby/

- Naresh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYt7WQWKNaNeTnxo19h9i84p5nVemqgwJkQQGeOmt14b_g%40mail.gmail.com.
