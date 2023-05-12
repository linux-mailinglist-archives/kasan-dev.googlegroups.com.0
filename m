Return-Path: <kasan-dev+bncBC65ZG75XIPRB4H77CRAMGQEHCC5FAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A20D3700940
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 15:32:33 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3f4245ffbb4sf34966645e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 06:32:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683898353; cv=pass;
        d=google.com; s=arc-20160816;
        b=fhY95vmYij7aQVmE81taQ5mbmwCq6ynpHe1F0UDP5M99HopbDKZqLux52AhDF11TSJ
         O6HDQIhqbJKLaqc7pzCiMVPy65t92Kw94Fg0QJ83q+173SoJFIEI2IOfauv8j2faI4lW
         3Y85ta8PPoo2+tKIQ9Tf2xaBkETFofyLVv1IS/RVUyAzbrUnpAhDIQB13jA3sPBq41/g
         o7Vm0MD29taeU8NaIaoy3Ii/SeWYetW6UxsH3dJWEL/BVpyNHLEuUqUN8lUfYwJihMgz
         sCXUJ5qX6taCSxW6TBWTHnPsKgalJKrRjG3OaoCJeURr6a2Vo3wk8C6hqhWKEzbVgDQb
         s4/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=D9DHuKPwSxirvGVeumch1k7j4GXmgwUhiFHSOOotLbk=;
        b=rOpgOksfLeaPdOMVfeXWwyaPDek0MlcMuNmKcSUhPVS6KXMu0a//vRgJU/Pi9aiM2f
         tR/kiYppiNMJS3uxYwcThFcJyGttSXVrcIiobvLK8cZGHoB4p+UDaZ1RbV7TiQbX31LS
         8+7PaH4PWrdhCahzM/3IwEGaURVOze4c6hofqwEGNui8Hc4tNpjcleAk7ucavtGkFAxs
         C30cb15M84NaJnvJYbPJypvFCvgToFokCuLegg7SfpNBEqScGHPK9ID6RCSIyY6gRpyP
         x1eMrR03dH/uqc02qo+Ammq/rrPrG7o4svmMgCvMKl1qoMScNLpYYAiPrvcGXptYIn+1
         JSsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=bLixAcvv;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683898353; x=1686490353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=D9DHuKPwSxirvGVeumch1k7j4GXmgwUhiFHSOOotLbk=;
        b=OoVnhKqYD0yu84GIvEXVEDvqpltUu7PYWMjFPJ/IzbQa795bAIx/foXwT4v0nbJE8a
         /uBUpyAlqhpsVa0je/GgFzBE38Mc+oa9h3ozOt2Eu48/OegTqVWmhMLtAs50RFJQh2jM
         bpZ+m29RpOAqWnatspNZL/xySZk/lM4gVyuzmjed7zdBVcDL4fQkQS3Qg4ayNYwvVZY8
         +DkQamvu16rhHbGBUtmKsJuDobVJ2jZAqR+cq89mexq+DsVMjNi82gQvS4Tatm1Z1iFx
         tvOCcI3tCriFCqy4CbkkXlAdU/+/e5V0FYM0e14umSInk0+wvPCnfA0LhnWnBePTZtRb
         ZHsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683898353; x=1686490353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=D9DHuKPwSxirvGVeumch1k7j4GXmgwUhiFHSOOotLbk=;
        b=S//a3qFeNsLTXD3VCCu6Z/wno5eacD61tB0rQaybaE8lxPME3QMFrInQJUBiwl1MDJ
         aUfSeMBemQXnRJM+89Y8oTAk2chGaH4cJi6Lvzl+ynEoYYbW3J5GMbAobtXP04dpglaE
         +JHFlrXmi87khY7nfU57bmgvbC0xDed9GndFVexeKQy2ckk2GuheLmdVQe65ahQwu5UW
         02ouuyDAAnoTTXWxtarvUoibVdlaPoPHn6FXsV8x656uNlIwn33ks2cYCoqBaLwSkJev
         0xbZjQAFiyxOCzXi12P8yVDd10IbwBMxZvC/kcaksOjpNpCBiJfMke3JWzgBvnvnvz1+
         pU9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx/OMB7isy0BkszYNJeRo0ztHv+32xlSOqBxTwTvzharzJqW7h0
	7ya0Dpk6ZCFlMyn11yJvOIk=
X-Google-Smtp-Source: ACHHUZ4/bkkS9/xjrlhZ3nqnI9qGHIbEHfFMAi0/sBtEKkavjgr0bppgAzWVRlRdEY2yk8I6ew3Zfw==
X-Received: by 2002:a05:600c:1149:b0:3f1:72ec:400f with SMTP id z9-20020a05600c114900b003f172ec400fmr4336004wmz.3.1683898352919;
        Fri, 12 May 2023 06:32:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3115:b0:3f1:714d:c42c with SMTP id
 g21-20020a05600c311500b003f1714dc42cls428712wmo.0.-pod-control-gmail; Fri, 12
 May 2023 06:32:31 -0700 (PDT)
X-Received: by 2002:a1c:e90c:0:b0:3f1:952a:4bf0 with SMTP id q12-20020a1ce90c000000b003f1952a4bf0mr17266301wmc.33.1683898351638;
        Fri, 12 May 2023 06:32:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683898351; cv=none;
        d=google.com; s=arc-20160816;
        b=tjOpyBUTido6h7XPFLWK6JbmN4aKO6t9N8c3Z6yl7Op/3Mx+VraPIWatkiEs9HEfS2
         N9mYZrMyrNc53qWD+qzJ5sEzCmX+cs0Ffpk7R/2Hc/YsDMUWLh/LOe4f8M8YDAUacfQG
         PgvKjoGS6vN12EputUaM4Qpq8yvW0nJ93tbx686b7RTK6X+OtXpoKHsBh3tJUx42Ft5c
         /wEtjdwQS1txaANJgolIy+vikrS/VkTwdACNU8cFTtwEGcbYWce4b3veFe1BBQ4lCn/0
         gkP6tSdbFSZN8zmPlmx53QxLyFkbWe3g2G//a1jYY310KqDIhfqZRP/RsaGbZu9NQEJq
         Zq4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1SGcgNeMjoxieUtPpFqEKzKmtbMzY7/Fef/+6eMQ9tM=;
        b=eyoFyHKTiBTBdZ3WUsH9BMDHQG9ouX+LFboIgj+MQ+tU7PBSXs2OlDnw5s+aAn4yCl
         cz/ShWyDWEn8OIeZ+QuHnm28EuREGB091jes4e5vAnVbBpEze0JY0f9pkNxC4+MpziDo
         w+B8A5Bm/Nh4mRx1Il3vadwq6ZBzLFc7098z9hLmoQ8eVclkq8ldkXj3Npe1xKegbcPo
         ljiRya8v92w/yl3Gk0bauX04TyY8m+MoS6T0Zl3OcyuLbBPhhnaFuWrRkppvlJxV58CT
         12QudgA+KlHjnglg6Q3qLQ9gpOSflsvli4kc1slsbg3EFoi8jjvkS0kC1aZ/Sqk9BZkS
         LRGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=bLixAcvv;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id o18-20020a05600c511200b003f4241e235esi885072wms.0.2023.05.12.06.32.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 06:32:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-3f4249b7badso61646945e9.3
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 06:32:31 -0700 (PDT)
X-Received: by 2002:a7b:c7d5:0:b0:3f4:d18f:b2fb with SMTP id z21-20020a7bc7d5000000b003f4d18fb2fbmr6440381wmk.8.1683898351147;
        Fri, 12 May 2023 06:32:31 -0700 (PDT)
Received: from localhost ([102.36.222.112])
        by smtp.gmail.com with ESMTPSA id c3-20020a7bc843000000b003f31d44f0cbsm28824757wml.29.2023.05.12.06.32.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 May 2023 06:32:28 -0700 (PDT)
Date: Fri, 12 May 2023 16:32:25 +0300
From: Dan Carpenter <dan.carpenter@linaro.org>
To: Naresh Kamboju <naresh.kamboju@linaro.org>,
	Chuck Lever <chuck.lever@oracle.com>
Cc: open list <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com,
	lkft-triage@lists.linaro.org, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: next: WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744
 __alloc_pages+0x2e8/0x3a0
Message-ID: <6c7a89ba-1253-41e0-82d0-74a67a2e414e@kili.mountain>
References: <CA+G9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC=wQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+G9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC=wQ@mail.gmail.com>
X-Original-Sender: dan.carpenter@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=bLixAcvv;       spf=pass
 (google.com: domain of dan.carpenter@linaro.org designates
 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
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

I'm pretty sure Chuck Lever did this intentionally, but he's not on the
CC list.  Let's add him.

regards,
dan carpenter

On Fri, May 12, 2023 at 06:15:04PM +0530, Naresh Kamboju wrote:
> Following kernel warning has been noticed on qemu-arm64 while running kunit
> tests while booting Linux 6.4.0-rc1-next-20230512 and It was started from
> 6.3.0-rc7-next-20230420.
> 
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> 
> This is always reproducible on qemu-arm64, qemu-arm, qemu-x86 and qemu-i386.
> Is this expected warning as a part of kunit tests ?
> 
> Crash log:
> -----------
> 
> [  663.530868]     KTAP version 1
> [  663.531545]     # Subtest: Handshake API tests
> [  663.533521]     1..11
> [  663.534424]         KTAP version 1
> [  663.535406]         # Subtest: req_alloc API fuzzing
> [  663.542460]         ok 1 handshake_req_alloc NULL proto
> [  663.550345]         ok 2 handshake_req_alloc CLASS_NONE
> [  663.558041]         ok 3 handshake_req_alloc CLASS_MAX
> [  663.565790]         ok 4 handshake_req_alloc no callbacks
> [  663.573882]         ok 5 handshake_req_alloc no done callback
> [  663.580284] ------------[ cut here ]------------
> [  663.582129] WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744
> __alloc_pages+0x2e8/0x3a0
> [  663.585675] Modules linked in:
> [  663.587808] CPU: 0 PID: 1200 Comm: kunit_try_catch Tainted: G
>           N 6.4.0-rc1-next-20230512 #1
> [  663.589817] Hardware name: linux,dummy-virt (DT)
> [  663.591426] pstate: 22400005 (nzCv daif +PAN -UAO +TCO -DIT -SSBS BTYPE=--)
> [  663.592978] pc : __alloc_pages+0x2e8/0x3a0
> [  663.594236] lr : __kmalloc_large_node+0xbc/0x160
> [  663.595548] sp : ffff80000a317bc0
> [  663.596577] x29: ffff80000a317bc0 x28: 0000000000000000 x27: 0000000000000000
> [  663.598863] x26: ffff0000c8925b20 x25: 0000000000000000 x24: 0000000000000015
> [  663.601098] x23: 0000000000040dc0 x22: ffffbf424e7420c8 x21: ffffbf424e7420c8
> [  663.603100] x20: 1ffff00001462f88 x19: 0000000000040dc0 x18: 0000000078b4155a
> [  663.605582] x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
> [  663.607328] x14: 0000000000000000 x13: 6461657268745f68 x12: ffff60001913bc5a
> [  663.609355] x11: 1fffe0001913bc59 x10: ffff60001913bc59 x9 : 1fffe0001913bc59
> [  663.611004] x8 : 0000000041b58ab3 x7 : ffff700001462f88 x6 : dfff800000000000
> [  663.613556] x5 : 00000000f1f1f1f1 x4 : 00000000f2f2f200 x3 : 0000000000000000
> [  663.615364] x2 : 0000000000000000 x1 : 0000000000000001 x0 : ffffbf42516818e2
> [  663.617753] Call trace:
> [  663.618486]  __alloc_pages+0x2e8/0x3a0
> [  663.619613]  __kmalloc_large_node+0xbc/0x160
> [  663.621454]  __kmalloc+0x84/0x94
> [  663.622551]  handshake_req_alloc+0x74/0xe8
> [  663.623801]  handshake_req_alloc_case+0xa0/0x170
> [  663.625467]  kunit_try_run_case+0x7c/0x100
> [  663.626592]  kunit_generic_run_threadfn_adapter+0x30/0x4c
> [  663.628998]  kthread+0x1d4/0x1e4
> [  663.629715]  ret_from_fork+0x10/0x20
> [  663.631094] ---[ end trace 0000000000000000 ]---
> [  663.643101]         ok 6 handshake_req_alloc excessive privsize
> [  663.649446]         ok 7 handshake_req_alloc all good
> [  663.651032]     # req_alloc API fuzzing: pass:7 fail:0 skip:0 total:7
> [  663.653941]     ok 1 req_alloc API fuzzing
> [  663.665951]     ok 2 req_submit NULL req arg
> [  663.674278]     ok 3 req_submit NULL sock arg
> [  663.682968]     ok 4 req_submit NULL sock->file
> [  663.694323]     ok 5 req_lookup works
> [  663.703604]     ok 6 req_submit max pending
> [  663.714655]     ok 7 req_submit multiple
> [  663.725174]     ok 8 req_cancel before accept
> [  663.733780]     ok 9 req_cancel after accept
> [  663.742528]     ok 10 req_cancel after done
> [  663.750637]     ok 11 req_destroy works
> [  663.751884] # Handshake API tests: pass:11 fail:0 skip:0 total:11
> [  663.753579] # Totals: pass:17 fail:0 skip:0 total:17
> 
> links:
> ------
> 
>  - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/test/check-kernel-exception/log
>  - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/tests/
>  - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230420/testrun/16385677/suite/log-parser-boot/test/check-kernel-warning-ac79d2ca0f443d407d9749244f1738c9a2b123c609820f82d9e8907c756f5340/log
>  - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/test/check-kernel-warning-ac79d2ca0f443d407d9749244f1738c9a2b123c609820f82d9e8907c756f5340/history/
> 
> 
> --
> Linaro LKFT
> https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6c7a89ba-1253-41e0-82d0-74a67a2e414e%40kili.mountain.
