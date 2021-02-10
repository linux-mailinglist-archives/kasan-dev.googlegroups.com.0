Return-Path: <kasan-dev+bncBD26TVH6RINBB3X4RWAQMGQERRVPQ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 58643315F84
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 07:34:24 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id t16sf919629pfh.22
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 22:34:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612938863; cv=pass;
        d=google.com; s=arc-20160816;
        b=XjjGJesriBdOekrRwraEltAqPox0Merh1+hOSKcZwSuvEh7PePD6oBgVps9jOTAYqn
         d/IFJH+J46wKZfzZIS6s5PBSWC1jRNdMtmkRX7ZqRDijJJtJkeVzCoBl7GMZUBj8jsQd
         zQBRcL++E7+1VFVbAB99gqXcVGOtXSvTPN40C5u5kzKzM8G26FcZ+6BnKsaScCU4kzyA
         jp6NukfmhGV3UBm3tAz2nEaBdRFR9p8nSV6vSCAUDvecG3Mr0xY4t3sa4wT+DybDC1qA
         JeEm6tavFacuGv6a3v4BPQOJM+foeYoQaLbKTmsdPEoOAkXy5J8VU7fxCFW4F6VBZZX1
         F20g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=xQ1tlYNGhJPd5zl3CuYrvltz19ozCkIvLHZOcyjoD+M=;
        b=zbBGLFWccL2OPI1GTp5hOm92wNwwR5SaTNkJO2a85s4/t/K2YEg8vfqRuiIVbRUddV
         jYeMYmegqg+vGEMdqKJXCiUz9KGbioNGvPDkvS0L9aeZxCfPz6yl/s+W/oM7CBGUnREM
         n9oAC5vg14Ufv/4adKPxchiIaE3RPUqK0X99ucuHomvbNJO4/2cleRzj6On5Q3LAjc7d
         8JNUviUAMF3kulTQAQH32aUjrZTQomNNIIBgGPLQTKT4K70dTJ//5NEc//aQB7v8ecLf
         Lh29mZtwxpfE+slKSnz/eSSYwRNPDKnRsXiYFyDbryLCf8sn6+Bb2EW5LafbRniJ/9QD
         qNMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of rong.a.chen@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=rong.a.chen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:subject:to:cc:references:from
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xQ1tlYNGhJPd5zl3CuYrvltz19ozCkIvLHZOcyjoD+M=;
        b=odIbRhYFDwZetHzam+11qXYRw65hyK5hUfF2LvUXwt228ZjcxoUrEOn2+Nwripha3v
         wZQapFkiK0GA6vDR+R5Fw1K3ordeMNzKgRwVJj3zSGAVVyYfZ+OX4Av6rUyy4By0Wqcv
         h8f+vOqTdhJJMnnwoJdD3d2HbabofXHB6QR/WvlnbJzXw3eNL7JMaLLmO9r6n6VaiWlq
         NlESnxAKdH1boKOvtCTdHi1aSAR9S8kwEjfJUtBe4UHdPBG6Kl4rNdG4rpLLwWXau75o
         i5/aWf6cHmrZ2EL36tZKGxBJmiRN1dbRkF7Aa0F38TWfMFGahojRo0BZPX1eBj6MaKAO
         7YPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:subject:to:cc
         :references:from:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xQ1tlYNGhJPd5zl3CuYrvltz19ozCkIvLHZOcyjoD+M=;
        b=sjftmscUrPcsukrtcW7WIys0jJ0y1eWMq18u6TIWF5AfjlFV+IfgBfEld2u0L/p6CC
         OBNcN5IHpjmWcP+KKbXjIAz0XaFa0o7JSrINVko6b1mC8E9BoLcpLkbk+BKewR+hZL8r
         0tw4ImJszMPCy/Yna6c0YOUYj0dFlIm6Ylkgxffm7PEsuoyOU4juCbFAB9N/i4OL0ZRN
         U+2xJwOUTjuwjeApKcTEeW2qV1PCyay3r33ri1xak0anuzLePWcEp0eACRcuf+BfaaYS
         X4z7i69gPn8lNMTyZ18oLWsxnY8idRL3vU9HVIoIH9+S0TrTGLN7nwu+0nEK+n4hDda9
         yHrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ArIsPGwoERbdwHdvNbe5WEuQpsMDbjFxap9oC8/8KrfUNOuEd
	t6eo4NLZh3uyCxkutfJEC4k=
X-Google-Smtp-Source: ABdhPJwQJUjOv0h5QNEaRAePr5uyWjPAK0LCdaDE800oiIwt0f6S4fkIGG1znaqWcBVMbH471mXmsg==
X-Received: by 2002:a63:504e:: with SMTP id q14mr1760205pgl.306.1612938863004;
        Tue, 09 Feb 2021 22:34:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fb01:: with SMTP id o1ls504496pgh.7.gmail; Tue, 09 Feb
 2021 22:34:22 -0800 (PST)
X-Received: by 2002:aa7:8815:0:b029:1bc:93cc:d6fa with SMTP id c21-20020aa788150000b02901bc93ccd6famr1908673pfo.26.1612938862330;
        Tue, 09 Feb 2021 22:34:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612938862; cv=none;
        d=google.com; s=arc-20160816;
        b=EGeYM7zLKkZDKwrwvdhGOOe0oLSbMCQAqCSO3e3W8YDH9/NpfAcLV3CARPoSB3164G
         HnRcg5MxgZH2wXoOFD2B5HnG1sF5QRIYeTle4S7sqe7f0O9fC5PggOzp+2kq5vnFxXeo
         44tOkpy+SVWO6Q1PTJMS1jxe6VMuZmemGWNMifwBtrCHSk/ymTNLCSvcIScblmHDYD2c
         U2LBuu4yI+6Uph5yzLlgIc05Xi5Z17jckzcUoRTmESXtd/vFLRy9kKg+QCh3QZ/bQDLt
         lW2vKyls/pSOQJ/TG0/fisH+ZMSgyNoUam4kgCeaCO3v9ENq/fGRg/vaoJJUaQ2qpF0L
         kN3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :ironport-sdr:ironport-sdr;
        bh=1KESrQ2r6Gfj7l1VQ6n9nxrY3RO5lq9ESAflGPoJhjE=;
        b=ce+ek7OZn1Q0Tk+Um2kueOSOmbXY7M+jvRivAyNAhjgdg9n8xtNIcFsTRLzl8dwojY
         +nmiyWnRxu6vtt+TkI/OR+mro+tC+I9mxi7aQufAzxf1cUejF4zLv6DHXtkiWdjOZSDF
         pkwZIKs5kK+uho5pww4asZp5eiwFi2mR7iYi8qllrnGeHaifxJrLzhVvge0tnDMASJH9
         1/kEXZbmb8b7Pv8Zpzt/GUdGlzV+FIvfKwkjdGCwhJfT+ykykAOs/sTDE+9TbC2wGvh4
         vUz/MofE7tbJkUSk6bCWFviyLByQ1Dm7X5o6oJvQauhH4o4vPtar04DN5jARw6h806QZ
         B8Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of rong.a.chen@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=rong.a.chen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id kk5si22802pjb.1.2021.02.09.22.34.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 22:34:22 -0800 (PST)
Received-SPF: pass (google.com: domain of rong.a.chen@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
IronPort-SDR: HiV4rKECHcSQ9J5Pp3c69LdTsebmt7Ule6mULpX86TTDwhb7X0r//z8GMcM6rf6484m1giO4/M
 7by9rRufhD/g==
X-IronPort-AV: E=McAfee;i="6000,8403,9890"; a="169146806"
X-IronPort-AV: E=Sophos;i="5.81,167,1610438400"; 
   d="scan'208";a="169146806"
Received: from orsmga001.jf.intel.com ([10.7.209.18])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Feb 2021 22:34:20 -0800
IronPort-SDR: /JYwczd0UfP7YdI15qZaSu1wjyFUYuqVLRnuLF0pLBop2BsqZ5N9KOM3UAX77T4gkduVR9dAI+
 fF/iAW641Eiw==
X-IronPort-AV: E=Sophos;i="5.81,167,1610438400"; 
   d="scan'208";a="436564642"
Received: from shao2-debian.sh.intel.com (HELO [10.239.13.11]) ([10.239.13.11])
  by orsmga001-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Feb 2021 22:34:16 -0800
Subject: Re: [kbuild-all] Re: [PATCH v12 7/7] kasan: don't run tests in async
 mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kernel test robot <lkp@intel.com>, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Cc: kbuild-all@lists.01.org, Andrew Morton <akpm@linux-foundation.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <20210208165617.9977-8-vincenzo.frascino@arm.com>
 <202102091438.SIWr9xAZ-lkp@intel.com>
 <c623a7ee-1efa-ecd4-501c-cf31303b2c27@arm.com>
From: Rong Chen <rong.a.chen@intel.com>
Message-ID: <aa3c1d8f-c206-0731-6eff-7fe29df35f85@intel.com>
Date: Wed, 10 Feb 2021 14:33:45 +0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.6.1
MIME-Version: 1.0
In-Reply-To: <c623a7ee-1efa-ecd4-501c-cf31303b2c27@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: rong.a.chen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of rong.a.chen@intel.com designates 134.134.136.20 as
 permitted sender) smtp.mailfrom=rong.a.chen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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



On 2/9/21 7:33 PM, Vincenzo Frascino wrote:
>
> On 2/9/21 6:32 AM, kernel test robot wrote:
>> Hi Vincenzo,
>>
>> I love your patch! Yet something to improve:
>>
>> [auto build test ERROR on next-20210125]
>> [cannot apply to arm64/for-next/core xlnx/master arm/for-next soc/for-next kvmarm/next linus/master hnaz-linux-mm/master v5.11-rc6 v5.11-rc5 v5.11-rc4 v5.11-rc6]
> The patches are based on linux-next/akpm and since they depend on some patches
> present on that tree, can be applied only on linux-next/akpm and linux-next/master.
>
> The dependency is reported in the cover letter.

Hi Vincenzo,

Thanks for the feedback, we'll take a look.

Best Regards,
Rong Chen

>
> Thanks,
> Vincenzo
>
>> [If your patch is applied to the wrong git tree, kindly drop us a note.
>> And when submitting patch, we suggest to use '--base' as documented in
>> https://git-scm.com/docs/git-format-patch]
>>
>> url:    https://github.com/0day-ci/linux/commits/Vincenzo-Frascino/arm64-ARMv8-5-A-MTE-Add-async-mode-support/20210209-080907
>> base:    59fa6a163ffabc1bf25c5e0e33899e268a96d3cc
>> config: powerpc64-randconfig-r033-20210209 (attached as .config)
>> compiler: powerpc-linux-gcc (GCC) 9.3.0
>> reproduce (this is a W=1 build):
>>          wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
>>          chmod +x ~/bin/make.cross
>>          # https://github.com/0day-ci/linux/commit/53907a0b15724b414ddd9201356f92e09571ef90
>>          git remote add linux-review https://github.com/0day-ci/linux
>>          git fetch --no-tags linux-review Vincenzo-Frascino/arm64-ARMv8-5-A-MTE-Add-async-mode-support/20210209-080907
>>          git checkout 53907a0b15724b414ddd9201356f92e09571ef90
>>          # save the attached .config to linux build tree
>>          COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-9.3.0 make.cross ARCH=powerpc64
>>
>> If you fix the issue, kindly add following tag as appropriate
>> Reported-by: kernel test robot <lkp@intel.com>
>>
>> All errors (new ones prefixed by >>):
>>
>>     powerpc-linux-ld: lib/test_kasan.o: in function `kasan_test_init':
>>     test_kasan.c:(.text+0x849a): undefined reference to `kasan_flag_async'
>>>> powerpc-linux-ld: test_kasan.c:(.text+0x84a2): undefined reference to `kasan_flag_async'
>>     powerpc-linux-ld: test_kasan.c:(.text+0x84e2): undefined reference to `kasan_flag_async'
>>
>> ---
>> 0-DAY CI Kernel Test Service, Intel Corporation
>> https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aa3c1d8f-c206-0731-6eff-7fe29df35f85%40intel.com.
