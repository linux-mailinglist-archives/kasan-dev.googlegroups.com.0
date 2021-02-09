Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBE7ERGAQMGQEVA3SSTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 60D24314E37
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 12:29:25 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id fa7sf1651271pjb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 03:29:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612870164; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWKUUc8cAwejpg1Jvlz6JVpNOcDAW7Vywd+7F4no3QJdx2ri12oapsJn/3eqOPwZ+b
         JeBMT1l3WzCPWhu/MfS/B6g8R4AD83kPoX9pwgwmoq9Vtr4gd0qygVc1NdfTUX++KQvZ
         xpgYCVHixTGgU2sWjyPnAIi7vzDhlPiL4mMJXFqj9GcRp61RQ6S+bRgOx45xnnrfAVUI
         QzyzHCZ1D784S0KijS6dRwRqGY7/pTW+o1j5qsD0FKPaUAqdaJSAtPu9Xc4pJnkyfU2L
         7a8cDG8AD8KtIv/m4Ht03D41d6nxdtYlj29oCyHOjDvMNZvWtmDjb16O9zyKj9oqgFsm
         9lIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=wFnv3OFBe1lXeFo/uJjtfVO0oqPp+XNUdAAhoq741IE=;
        b=o7lXhjMKXxcCmu2CEIBn3X/66d93MbmMKPC6Skxng8+e0GJfOz8pHNCk4dknNodbSK
         H17ui8eHI2k5lYFbaToxVCP/cnjTba+MybDe6VlQLpfOchlmxmjvH/W7dYWnx7wpm3+X
         kX0OTQmd+l6VixdAmVzEq8unlANzh+UYiX/RVbYj0Gan5TpB30u6urLKbyoKxkQW1xZC
         1r72wBrf65xb7FxK795A9C3DqVQ3fz2tXHXWTNldWzGcoxV5M3pDsWGs4XyH5siZ2MxC
         hi5fri1708kHLAtHlctZf9tUyyVrm8adTOPQeO73Qdv6Imx7qpp3rLvS5orzKhRDHbCX
         hWaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wFnv3OFBe1lXeFo/uJjtfVO0oqPp+XNUdAAhoq741IE=;
        b=NTZxuiNMMEl8OSnHyCwy/lBYewI8cEIu8NhHT9ZZ+CMgfi9yvVFPzFBYrKUUKNX7xs
         WKUevfk/tbWGQ2gQRSyKAwvJlOU5uApm8PKDpef6X6OQkaSvad0iLHUwt7rfX3LEvy5d
         xkmHI652r4fIdV17Crt6U2orExVmY+5WDsm4Xgmyo+nDDE8mIylCbw5qkfUEDV9sCw4Y
         zrYpYN3rVA8+PiQ1uft7b92NuW2op1ZgUCYR/FdZjx3eB3G35MrjDwoI+QwuNgblaF6N
         374mj9rWcdxh4QhFKe1JQJsbaSQ3UAI2RtOMs9p99b15p1rrwuHZyh6Ye9RX8BXTK+g5
         GpuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wFnv3OFBe1lXeFo/uJjtfVO0oqPp+XNUdAAhoq741IE=;
        b=jfI+d0enSdUu9AO95UKVzymkfN/gnMPNz5+4vW2GCV6I3kzNcm23zOD7EH/b7n8lcQ
         QUJSRL/cGh9XE0PyZkk0630UNhM26uyWzHa30vZkLcQc8i9Ze1QsSqVxuTDDqnHhk+43
         Vinvul0AW0VTTKfbZzG6LtvcbLv5iElYpneT29zNKkAU/z3RR+ljQEudv2by+Qm2MPuA
         dS16MaKr/xWABRirLIKIzs0ck9eNxbrFm5b7YvQ06iutLlD8qk+xS13fuNYSMRTWDMaH
         KuZYWGhHFHgLPEvuAKB5ErN6TzpNfBfGCEa0P3/3oDOCXtxCfsKlEeg0KLaveIU8FrjK
         UJ5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310HRVhMw6cFIHOg1UnEXCyIQ689n4jKc+NaprUdrhRTuHM1wMB
	o8uPUpMe7/L8f/6TLTAmD8E=
X-Google-Smtp-Source: ABdhPJyJM7TelcuBtSpQn1Pssf0Pm9KqB2XOGe8ET+1drQIWzQp3GKpSXYflSV9VWvxBGr9IVoYnHA==
X-Received: by 2002:a17:90a:5c81:: with SMTP id r1mr3596133pji.175.1612870164084;
        Tue, 09 Feb 2021 03:29:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7583:: with SMTP id j3ls9505626pll.0.gmail; Tue, 09
 Feb 2021 03:29:23 -0800 (PST)
X-Received: by 2002:a17:90a:5601:: with SMTP id r1mr3587121pjf.236.1612870163369;
        Tue, 09 Feb 2021 03:29:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612870163; cv=none;
        d=google.com; s=arc-20160816;
        b=pjeS0EfYRbd5mFx3+nHdk51udWbx1USkucJVfpMdiYF4PyOAufVeZpSDsUK+hhGeqm
         Fuau8maTgMcQV++vugCleLHUXzD6b/94mKUibmjRKNklFvImCvK9cS6j+ChzZGiK66B0
         QUZSFoR7DMYm9UL5n3/Y82Q7nDKuNHLwevyI56fE0IvnWDE2nPsciYvWc0zeGEGGc/0+
         a2aXSNiQc+tH6WX6aNf76Tnb5EWbT5Dw2VRTN+FSjbjMYGLznmMV1T/dA/nMC3KKKGTS
         LEcH08gqurs1i6+tUS9qtnc8ZQqb6g2Tqvkf16ArLXnSo2tlfQWgJOlUlg0Suijy0pk7
         TsCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=gfKJ9i4W4Xy2xvKXbYSdpIAuTweMzVwbLZtDdNKhO/E=;
        b=I8udZ9KEaFilRlcf4YMUKoAHL/R7g09kKNyoBnGa4Stg6TzHwlWsGjbZUQR+duJbjf
         TPfc7hFTxhlyPE6nqvOigVw59GgxokfuGj8I/0UdSImmiyPr2poP2XVmUt5O86HF+NAD
         LOrDBN/JzocjYz8WGBK9hwrvQgoSe3UK/k4vLY2sD4ZNEnvELXOmFfVrQrwrFne7lLNq
         rd39/rdJESpb4TUNo52xCuxN47r+AmaUmCskrFYPvhhRsBVJ2k3GBut4i5Aaeas54afH
         BdjQv+fpifROmhFVVX/wB3SOaaKiO6UsHkQBTADbF2w1HxFVnyDLPmVGpmOT9E0usf8E
         zIBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f24si140423pju.1.2021.02.09.03.29.23
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 03:29:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D6F23106F;
	Tue,  9 Feb 2021 03:29:22 -0800 (PST)
Received: from [10.37.8.18] (unknown [10.37.8.18])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 458CD3F73B;
	Tue,  9 Feb 2021 03:29:21 -0800 (PST)
Subject: Re: [PATCH v12 7/7] kasan: don't run tests in async mode
To: kernel test robot <lkp@intel.com>, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Cc: kbuild-all@lists.01.org, Andrew Morton <akpm@linux-foundation.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <20210208165617.9977-8-vincenzo.frascino@arm.com>
 <202102091438.SIWr9xAZ-lkp@intel.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c623a7ee-1efa-ecd4-501c-cf31303b2c27@arm.com>
Date: Tue, 9 Feb 2021 11:33:24 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <202102091438.SIWr9xAZ-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 2/9/21 6:32 AM, kernel test robot wrote:
> Hi Vincenzo,
> 
> I love your patch! Yet something to improve:
> 
> [auto build test ERROR on next-20210125]
> [cannot apply to arm64/for-next/core xlnx/master arm/for-next soc/for-next kvmarm/next linus/master hnaz-linux-mm/master v5.11-rc6 v5.11-rc5 v5.11-rc4 v5.11-rc6]

The patches are based on linux-next/akpm and since they depend on some patches
present on that tree, can be applied only on linux-next/akpm and linux-next/master.

The dependency is reported in the cover letter.

Thanks,
Vincenzo

> [If your patch is applied to the wrong git tree, kindly drop us a note.
> And when submitting patch, we suggest to use '--base' as documented in
> https://git-scm.com/docs/git-format-patch]
> 
> url:    https://github.com/0day-ci/linux/commits/Vincenzo-Frascino/arm64-ARMv8-5-A-MTE-Add-async-mode-support/20210209-080907
> base:    59fa6a163ffabc1bf25c5e0e33899e268a96d3cc
> config: powerpc64-randconfig-r033-20210209 (attached as .config)
> compiler: powerpc-linux-gcc (GCC) 9.3.0
> reproduce (this is a W=1 build):
>         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
>         chmod +x ~/bin/make.cross
>         # https://github.com/0day-ci/linux/commit/53907a0b15724b414ddd9201356f92e09571ef90
>         git remote add linux-review https://github.com/0day-ci/linux
>         git fetch --no-tags linux-review Vincenzo-Frascino/arm64-ARMv8-5-A-MTE-Add-async-mode-support/20210209-080907
>         git checkout 53907a0b15724b414ddd9201356f92e09571ef90
>         # save the attached .config to linux build tree
>         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-9.3.0 make.cross ARCH=powerpc64 
> 
> If you fix the issue, kindly add following tag as appropriate
> Reported-by: kernel test robot <lkp@intel.com>
> 
> All errors (new ones prefixed by >>):
> 
>    powerpc-linux-ld: lib/test_kasan.o: in function `kasan_test_init':
>    test_kasan.c:(.text+0x849a): undefined reference to `kasan_flag_async'
>>> powerpc-linux-ld: test_kasan.c:(.text+0x84a2): undefined reference to `kasan_flag_async'
>    powerpc-linux-ld: test_kasan.c:(.text+0x84e2): undefined reference to `kasan_flag_async'
> 
> ---
> 0-DAY CI Kernel Test Service, Intel Corporation
> https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c623a7ee-1efa-ecd4-501c-cf31303b2c27%40arm.com.
