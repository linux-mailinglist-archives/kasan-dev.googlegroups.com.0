Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB7HDRGAQMGQEPFJ2FVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BBE6314E36
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 12:29:01 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id a22sf1487693pjs.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 03:29:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612870140; cv=pass;
        d=google.com; s=arc-20160816;
        b=WLX2ZOvWStPXIeMau5IcYjInpJMMTpyH7lP2GZ1Ckq3HBUTh3xo388P5tCQWB71S5a
         T7ratowEKVmKma0JaY7qIsE7UXrAp2J2BexNq1AUD9LaURiBUR5CLjLn0SF6894hruyk
         7vcq+SX9nr9K0xZSoTCln+3mzvjhswcCYbQzKkQwZJb+YBrsxjFd7gBnxhqFU+6atmoG
         VE56XjVTgQKSqSOfhKhgx7F/JPk7jEt1sSV7TEFRRci+ALaTjrzwGTKym48mgM0P7Qbs
         AD4jpa+cmUgklvW85g02KgGgPSnh+Cjo1R6vLMEwVh9RfBv4B0s6IblYWI+33CqXetuN
         ahbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=WrGISo3sNOuOUBroaoz29oQVJrz+LtPRMjHKQHMCYDc=;
        b=hns1AXs6XPFXaK1l115r8x00IHFACv8G43D4aJykY4H/iAw3iL/QHIjNsICeHTgAC7
         7DtQKOsXlgewgqJLoQOEhz9ofsBiRn/5c9sriaN21dnmO2O4JjJoAFG4snaovZdYT+JD
         F137+rQV1DXPQLKZuAS/gxNaAByhdLOe8eUbgC3I1u1+dyXAmsvLaXwsEdDGy7mOSIDt
         LtAWCthLyOat0dd3ZN/JqQTuc4X93BaMbUwPRlt1mUFpJ3NZobtBgkt3bDpKEY/SwTLN
         Hl23Kw5069nsLweEm86FNmySY+19aXCE6BZvNMKuBvCCVo7BmazmEYtKIAj8ntx2w8Hc
         8O/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WrGISo3sNOuOUBroaoz29oQVJrz+LtPRMjHKQHMCYDc=;
        b=VRVCQGkPHOXBdfutxtwyQQ/y46wDzu+Jvo/gi640O0YdtsR/aG5U27Zdt1FZ28zH9E
         HUfGXok0jFZR06lVidObUmBNhWDCd02oypN7lRG6YY3lT5MUuhzCD4GA0mWhQaiKHYSA
         +mGE+2j/qbzGhx8x8l4QQiPrAfOBoBrobdoiJWifNeXCwNg4x5oLtDfMaLr4YxUdWfS6
         VpOO+sBwBu/oH3N+uJICQVM/9cZ54W+e2cvbMJFhdTcr9m/0YIzXM4kzDyTkGwaSLWlL
         PbtPwqvbI5gx+uVMefcttJoHxTKFCaTwYmcNsh/AvCTBj6qFnliEruk4xW7VDOjjUxrY
         CLfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WrGISo3sNOuOUBroaoz29oQVJrz+LtPRMjHKQHMCYDc=;
        b=WIw6VB/PMAVdnyvulJvRAKT5d3Cz0a6SP3t45KiTEEnxrzFHCrIsV/cucfTeE9Ysfk
         5kmzoIiWJOKAx/636ySdwmn866y7H5sEs2vjdI/sNZSNdvGRtMEwCAmsOEvD+aNUv4Zn
         i/TijB+vFuFK7hgv7A7GLugl//DCYg+fD/I0qp3iDvrRsWGmaum/k65QQH6EXy7hjMKh
         gwrjy2k4sTQK6IzzRiGVmrnyvcwUn4CMPFwZS8e6wo2O5fzZWm+IZGTUlt01KO0lFCPc
         Us4ooU4jUmI6HgDp7aSDcFYuswYQ2+c18LtkKWCv2SqifMQ/S3lL3L12ZjgbeL42IbBE
         1sSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MRKsb9KtjlcMvqE5B19Y0I8/Sxy/ZTtwPeS8zQKT+0uxdrxP3
	q0OfEUrFykVwy/af6/CIZq4=
X-Google-Smtp-Source: ABdhPJwFMoFT/1ef7YoYm/+1R41snw2NN5dIfO/0QVzadGlyYaGgrVhh5l4H+cCBtoURA4HX50a3VA==
X-Received: by 2002:a62:2c50:0:b029:1b9:1846:b490 with SMTP id s77-20020a622c500000b02901b91846b490mr22077422pfs.76.1612870140206;
        Tue, 09 Feb 2021 03:29:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96f8:: with SMTP id i24ls8211094pfq.9.gmail; Tue, 09 Feb
 2021 03:28:59 -0800 (PST)
X-Received: by 2002:aa7:9736:0:b029:1b9:c4f5:54d5 with SMTP id k22-20020aa797360000b02901b9c4f554d5mr21736550pfg.47.1612870138524;
        Tue, 09 Feb 2021 03:28:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612870138; cv=none;
        d=google.com; s=arc-20160816;
        b=wvRg+NcLrRsIk4WpZzy2dvboDZef8ylhsLLQCFH6w5+qNeAxKngEK3ZgSG7EKMRx1G
         gNa3vFMKqekmXhU4slJPwPrbruziYLly+cWJPskIS2eBFae5AtjPVG7o+xIiVG7MXJWR
         INCUmZAGcbkJ3kBTBYaB5FGlhR1ulQyOVdTdYdheUhwny42/81jSOdJYE6oyfesuTCr+
         bDpNmKCIi5THRZh1ViEyyC1OvDPpwP+R+gCMHp/rYGbhnVRdQ6w/4qYwoVwSuXAa/ZZ2
         kod/cpM7wnEEgoPpJC2YMXG5+uASza6Nwg2fyuokKV8yn9Sp+otrgAP7LMFRhWCclwS6
         cAew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=BbeKQzYe4QYkVZahTiBxSlol5mKKsbqgbOIJ0SEiTis=;
        b=swN0vqu6fMfb0YxnShrRtNMS/d0LbdROR69NF3xo43M823aLlJCRTUu9/7fFcPr0mp
         ZvSgnwiWTTej6/mrxpmIS+2aD1z/ylzdh10qXiizlQXtBR6RsRFt4xepR8kxJiM0xoU0
         aaniHtHyiIbPssaI7EZpR1bRmDJ59tcdDDblEB8UZusIUjf5jkWq0G8loNt6goyvj0qT
         iI9ZKRFhSWzEjfstwT9F39H6ChBQ98XVrE1Jhfuq52VLRwaB+cMbKkwvhvpqy9+WOu5o
         xkFjRfZwCR5Zm573cya6wiaUNLZqG74RF0EevNYH9tPrbpc3v7HSY3t4Ju2FG8nHtYjE
         /2/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w1si70712pjl.3.2021.02.09.03.28.58
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 03:28:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9C6CEED1;
	Tue,  9 Feb 2021 03:28:57 -0800 (PST)
Received: from [10.37.8.18] (unknown [10.37.8.18])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0B1B93F73B;
	Tue,  9 Feb 2021 03:28:55 -0800 (PST)
Subject: Re: [PATCH v12 3/7] kasan: Add report for async mode
To: kernel test robot <lkp@intel.com>, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Cc: kbuild-all@lists.01.org, Catalin Marinas <catalin.marinas@arm.com>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20210208165617.9977-4-vincenzo.frascino@arm.com>
 <202102091512.8A2oHgsy-lkp@intel.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <58f30539-69a8-d695-8a7f-75be2bdd31d6@arm.com>
Date: Tue, 9 Feb 2021 11:32:59 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <202102091512.8A2oHgsy-lkp@intel.com>
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

On 2/9/21 7:39 AM, kernel test robot wrote:
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
> config: x86_64-randconfig-s021-20210209 (attached as .config)
> compiler: gcc-9 (Debian 9.3.0-15) 9.3.0
> reproduce:
>         # apt-get install sparse
>         # sparse version: v0.6.3-215-g0fb77bb6-dirty
>         # https://github.com/0day-ci/linux/commit/93bd347e4877e3616f7db64f488ebb469718dd68
>         git remote add linux-review https://github.com/0day-ci/linux
>         git fetch --no-tags linux-review Vincenzo-Frascino/arm64-ARMv8-5-A-MTE-Add-async-mode-support/20210209-080907
>         git checkout 93bd347e4877e3616f7db64f488ebb469718dd68
>         # save the attached .config to linux build tree
>         make W=1 C=1 CF='-fdiagnostic-prefix -D__CHECK_ENDIAN__' ARCH=x86_64 
> 
> If you fix the issue, kindly add following tag as appropriate
> Reported-by: kernel test robot <lkp@intel.com>
> 
> All errors (new ones prefixed by >>):
> 
>    ld: mm/kasan/report.o: in function `end_report':
>>> mm/kasan/report.c:90: undefined reference to `kasan_flag_async'
>>> ld: mm/kasan/report.c:90: undefined reference to `kasan_flag_async'
> 
> 
> vim +90 mm/kasan/report.c
> 
>     87	
>     88	static void end_report(unsigned long *flags, unsigned long addr)
>     89	{
>   > 90		if (!kasan_flag_async)
>     91			trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
>     92		pr_err("==================================================================\n");
>     93		add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
>     94		spin_unlock_irqrestore(&report_lock, *flags);
>     95		if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
>     96			/*
>     97			 * This thread may hit another WARN() in the panic path.
>     98			 * Resetting this prevents additional WARN() from panicking the
>     99			 * system on this thread.  Other threads are blocked by the
>    100			 * panic_mutex in panic().
>    101			 */
>    102			panic_on_warn = 0;
>    103			panic("panic_on_warn set ...\n");
>    104		}
>    105	#ifdef CONFIG_KASAN_HW_TAGS
>    106		if (kasan_flag_panic)
>    107			panic("kasan.fault=panic set ...\n");
>    108	#endif
>    109		kasan_enable_current();
>    110	}
>    111	
> 
> ---
> 0-DAY CI Kernel Test Service, Intel Corporation
> https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org
> 
> 
> _______________________________________________
> linux-arm-kernel mailing list
> linux-arm-kernel@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-arm-kernel
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/58f30539-69a8-d695-8a7f-75be2bdd31d6%40arm.com.
