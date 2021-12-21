Return-Path: <kasan-dev+bncBCUJBAM67YFRB7E3RCHAMGQE5TB4MUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BC9C347C4FA
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 18:25:16 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id n31-20020a05600c501f00b00345b15f5e15sf1018903wmr.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 09:25:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640107516; cv=pass;
        d=google.com; s=arc-20160816;
        b=MNYr4BAyx68RMSR1Ay1DiExQcQwwd2izi6ZwaQnDq1ksixiQK/hsQAWZsjwcLGYjXl
         Ct3kHWgaYEyj+BDy8srjf/3fZpWg0YOb5dYHe+wgCmF3xcPIreZTv4azDWQOGzxNR+dL
         Z4tO91pKIFUSvW064sRg1DgM6YhQ8Gx1KxS4x2x7sW1SUtnv3/kJnOdUTaMVJutxRf1q
         pQ6k2gq56ZxQ48Jg90buNbC4xXIol45b9z5I2kzjrSLTvqjtiPzBUO+CxAED2T9K5gZo
         7WBA4NJUAO85PO7AGNZ6h0hvOGcQqUKZtKrOuG9xo0rvztE/1GaZzcVSIPizcynqZcmb
         JDWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=mhUVp+opRLPzYc3JkJ6Y6b8KuTAu869U3nWaeAwZTiQ=;
        b=E+ar32coI8wKab9byhDwu65I8KUoEjZhT0N7xPWTK2eBpwsd+RBrSLsyeHnIvLnRko
         OQBffCrxpxt3tNcYqgstKKq1ie9mPALhHoxzlCymC7xqwoSYnD9ClvM39rfhpJx+cOCP
         KHHr9IEkckgCjlBKLB294tEDOrirjJKf6xTh9SXoFA7KRTZJkQ6r7OOTo0wHLRSPUIw7
         vlC2KD5ZPh6S0mjWkzWUai0hGHa1IIKWL4hWVVEoRSW33e/kGI2duxRjPYCQYyIxkp4h
         zr5Snz8q0j/d8MXcRnqhd9FolFj4gLoFR7AAo4dzPFCmETzEF4lBgi61HyJ/++WibJNk
         b6Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mhUVp+opRLPzYc3JkJ6Y6b8KuTAu869U3nWaeAwZTiQ=;
        b=M6EhoYIKYoERbSRR8wsGSlKM1NrtUT/rvAUDpaCcfWRwEPqWMiDmTyneZpa9IDApMO
         LgGBxdW56jNoXiVc6ylM9CsMGt1lNzZQ8TSrLUupx8bmHvAPTn+WFZluW+m9esc5yZ51
         bcrdAhDKdYujslJ0/qneV86pyd20KvSXQG34PEzawrCXsfMOjOQYZitb31d9qK4j5iP5
         jlfY9oHELvEtuDyjHfeBUKdHupgVZsOXaOiGLO5WpHri/bGqb+kD9Zsnw/MUMvfaXtE8
         iz6eg751VbuoGrRHEKAktE+JNQaaN46wLv861nB3N3F+kcFoegC3fVEq2k315tFUPFtS
         kf5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mhUVp+opRLPzYc3JkJ6Y6b8KuTAu869U3nWaeAwZTiQ=;
        b=yhsrO8XlMDUzHNobzbJfmPYTFwEvQPFYbONyvI261uURaDjO2O+qUIdUl8ymtx5jzD
         CPVhRblqqeVwLco7Kd0jdepRPk4mDRsNDishC8mWn2uXFTPgImjJvgR5u/8J49psRdT2
         wSCnil96ybY5tfmYMuKeTg0pPc9HQE5xckfLpYvHamTwssorwcWqKe3EqdI59r5/AnfD
         MHVH+YINsmvoI6+Mmrv7YmSwq7ZDLjKtX6Mf/nMCzZMt/UYPK9JndjDd/q/NA1mGSxy4
         j6XaEz7ukxCeAUVsZwglLTatsJy8/+bAaIX7SettwwY7AcygLZwosU1MnPS/wAksIRFc
         v8zA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FcnHVc+585okQzrrdq273LPTODCbDXc4v5zWkmavGowwMTvuD
	vXP9HKtZ00liTuTpLrTqnCQ=
X-Google-Smtp-Source: ABdhPJx0ZY39eNuv+Pf3PN7BP5iwQF4Qgduf85bopfEx4HHOkky87GqLY/ypWYGHuRAI3JTmZgXi9Q==
X-Received: by 2002:adf:db04:: with SMTP id s4mr3533919wri.467.1640107516436;
        Tue, 21 Dec 2021 09:25:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:522c:: with SMTP id i12ls316666wra.0.gmail; Tue, 21 Dec
 2021 09:25:15 -0800 (PST)
X-Received: by 2002:a5d:6351:: with SMTP id b17mr3373438wrw.247.1640107515614;
        Tue, 21 Dec 2021 09:25:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640107515; cv=none;
        d=google.com; s=arc-20160816;
        b=rvIA2e2XWdKyT89HGXQUbMblvEBhDPmW7nqWduNkDIH552fKsTzBCimy0z5qP8KPh2
         AZBwPLVTY2+4+yBfe/mDgKGByHGADp5GI3LMWDoVk1LdpLW50KB/CJWNDLpcfDo8TYAr
         2sjpLkn9iJ9o9xHYWpm80IiPSCJvpEFy3UhzVANZbJPwdL1jo7TXoMtQwEsE8m5+0YJD
         gJC5msZNKz6CjxynlRem4GKgJrLQi/GuCo+QGuAeQyv+60Bm/EhRfKxhtJ4w9p7h5Uqm
         ky252fVJ26yBNJ4bt+W/hRS+jUHg7T6Jtf+NQje5FwPg4VAHwztmBgA1SdiLC3CJVWKK
         K2+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=WWcPaHySjASkjvLDyMhxBgZWhtUtMlaoxGmiE1ybw5M=;
        b=GTn1K8YtoQOeZKBdfr0/Qc49xfjcL7cChzpWKK7RVRyeeZQPNLHs8eqC7O1lS2xZB4
         SGbE8cSgXl+9ZFgaq32Imc8b9GFnMkxsInjFQimeu9UR/liJvuHnqLztmIVgwVXmBJQc
         QSdEQk40gls+4OjjSVf55SyOBOX5KL9hzJX5OE3jYYX/Oa+x05EEPF/kxojCYjjO84fk
         9RU8tgme0Pc55lEbj25Nn5RstIQf8CakNZr1DzvhDXqvW9BgOfGeCHPNDmnUdIfYWSvF
         k9cHDlxwjfh3itz4uZX0jc9ZVX86+MD1spyPR5Fc3u6KKnWm1AMF6LPWXsv6/ys6Y4bA
         c85w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l19si285627wms.3.2021.12.21.09.25.15
        for <kasan-dev@googlegroups.com>;
        Tue, 21 Dec 2021 09:25:15 -0800 (PST)
Received-SPF: pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 97EB4D6E;
	Tue, 21 Dec 2021 09:25:14 -0800 (PST)
Received: from [10.57.34.58] (unknown [10.57.34.58])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 27FF13F718;
	Tue, 21 Dec 2021 09:25:06 -0800 (PST)
Message-ID: <db0ba937-8785-a27b-afff-55c55456ae19@arm.com>
Date: Tue, 21 Dec 2021 17:25:01 +0000
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Content-Language: en-GB
To: Vlastimil Babka <vbabka@suse.cz>, Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
 Dave Hansen <dave.hansen@linux.intel.com>, Michal Hocko <mhocko@kernel.org>,
 linux-mm@kvack.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
 "H. Peter Anvin" <hpa@zytor.com>, Christoph Lameter <cl@linux.com>,
 Will Deacon <will@kernel.org>, Julia Lawall <julia.lawall@inria.fr>,
 Sergey Senozhatsky <senozhatsky@chromium.org>, x86@kernel.org,
 Luis Chamberlain <mcgrof@kernel.org>, Matthew Wilcox <willy@infradead.org>,
 Ingo Molnar <mingo@redhat.com>, Vladimir Davydov <vdavydov.dev@gmail.com>,
 David Rientjes <rientjes@google.com>, Nitin Gupta <ngupta@vflare.org>,
 Marco Elver <elver@google.com>, Borislav Petkov <bp@alien8.de>,
 Andy Lutomirski <luto@kernel.org>, cgroups@vger.kernel.org,
 Thomas Gleixner <tglx@linutronix.de>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 patches@lists.linux.dev, Pekka Enberg <penberg@kernel.org>,
 Minchan Kim <minchan@kernel.org>, iommu@lists.linux-foundation.org,
 Johannes Weiner <hannes@cmpxchg.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Woodhouse <dwmw2@infradead.org>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <YbtUmi5kkhmlXEB1@ip-172-31-30-232.ap-northeast-1.compute.internal>
 <38976607-b9f9-1bce-9db9-60c23da65d2e@suse.cz>
From: Robin Murphy <robin.murphy@arm.com>
In-Reply-To: <38976607-b9f9-1bce-9db9-60c23da65d2e@suse.cz>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: robin.murphy@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=robin.murphy@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 2021-12-20 23:58, Vlastimil Babka wrote:
> On 12/16/21 16:00, Hyeonggon Yoo wrote:
>> On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
>>> On 12/1/21 19:14, Vlastimil Babka wrote:
>>>> Folks from non-slab subsystems are Cc'd only to patches affecting them, and
>>>> this cover letter.
>>>>
>>>> Series also available in git, based on 5.16-rc3:
>>>> https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
>>>
>>> Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
>>> and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
>>
>> Reviewing the whole patch series takes longer than I thought.
>> I'll try to review and test rest of patches when I have time.
>>
>> I added Tested-by if kernel builds okay and kselftests
>> does not break the kernel on my machine.
>> (with CONFIG_SLAB/SLUB/SLOB depending on the patch),
> 
> Thanks!
> 
>> Let me know me if you know better way to test a patch.
> 
> Testing on your machine is just fine.
> 
>> # mm/slub: Define struct slab fields for CONFIG_SLUB_CPU_PARTIAL only when enabled
>>
>> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>>
>> Comment:
>> Works on both SLUB_CPU_PARTIAL and !SLUB_CPU_PARTIAL.
>> btw, do we need slabs_cpu_partial attribute when we don't use
>> cpu partials? (!SLUB_CPU_PARTIAL)
> 
> The sysfs attribute? Yeah we should be consistent to userspace expecting to
> read it (even with zeroes), regardless of config.
> 
>> # mm/slub: Simplify struct slab slabs field definition
>> Comment:
>>
>> This is how struct page looks on the top of v3r3 branch:
>> struct page {
>> [...]
>>                  struct {        /* slab, slob and slub */
>>                          union {
>>                                  struct list_head slab_list;
>>                                  struct {        /* Partial pages */
>>                                          struct page *next;
>> #ifdef CONFIG_64BIT
>>                                          int pages;      /* Nr of pages left */
>> #else
>>                                          short int pages;
>> #endif
>>                                  };
>>                          };
>> [...]
>>
>> It's not consistent with struct slab.
> 
> Hm right. But as we don't actually use the struct page version anymore, and
> it's not one of the fields checked by SLAB_MATCH(), we can ignore this.
> 
>> I think this is because "mm: Remove slab from struct page" was dropped.
> 
> That was just postponed until iommu changes are in. Matthew mentioned those
> might be merged too, so that final cleanup will happen too and take care of
> the discrepancy above, so no need for extra churn to address it speficially.

FYI the IOMMU changes are now queued in linux-next, so if all goes well 
you might be able to sneak that final patch in too.

Robin.

> 
>> Would you update some of patches?
>>
>> # mm/sl*b: Differentiate struct slab fields by sl*b implementations
>> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> Works SL[AUO]B on my machine and makes code much better.
>>
>> # mm/slob: Convert SLOB to use struct slab and struct folio
>> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> It still works fine on SLOB.
>>
>> # mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
>> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>>
>> # mm/slub: Convert __free_slab() to use struct slab
>> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>>
>> Thanks,
>> Hyeonggon.
> 
> Thanks again,
> Vlastimil
> _______________________________________________
> iommu mailing list
> iommu@lists.linux-foundation.org
> https://lists.linuxfoundation.org/mailman/listinfo/iommu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/db0ba937-8785-a27b-afff-55c55456ae19%40arm.com.
