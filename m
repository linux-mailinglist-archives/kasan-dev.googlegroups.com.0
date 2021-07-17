Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTUGZGDQMGQE2AKNIOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 126603CC0C1
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Jul 2021 04:41:20 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id u12-20020a17090abb0cb029016ee12ec9a1sf6528920pjr.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 19:41:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626489678; cv=pass;
        d=google.com; s=arc-20160816;
        b=kyrwIZAutk7jQauZrTC15ueK3w0b4UpAV5dglNaetkfu45RFE/dWJVsYpZ9uc525ro
         RbGqhah1BPGSkuvSeLDs4MjhkmxzrC6vXyLWn+lUANqdojyRX9TzFPugCE5k66ECJwBB
         POzGmY5GC9uriJaMby+SybiEuEXdGXJ0MH6krF2ywlkb8/ysDB3zPtRA3SFZziRQHle2
         MVWUJMjhWfmoPClU6VEjgVBmsR+owr+cP6Q4Q9UDH+OxYrzEeefylg0Bns6ZH1WNpsmw
         PkaUYEolWKIvTVtf5W9tu+EoFMokpRzoJjPppWr/ClrP/7GS3Oe7iA15IoP8U5sY/BPQ
         mWfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=oo/E06wZMGNatgt97IuRLFtkwSucz3rdlnsDRni0sWc=;
        b=wcME/4xxsiJoNYEE8x7LLQC1O+cbsnQ1WHFZwiUBEy80byijjSFUxSOCtchJCV8+IH
         x5Cif53twkQKTguN/nHX59Rj4kYwFsCvoh81m7NL7gys4b0MGZu5389/ZW2sM6/mEXVo
         pwTKgXp4xjeO1o8vzm6ZSqJ9I12vZFNNqLP0cUcNsk5qsBqjkLS7MKK1wcD99TWG9N8T
         6bjhaWpono0EE8Plh80ZQzUMGE+SreG/4WvGYqHcWY5gsLvxV6wpzjwku+WtGqRe8WUB
         iTTyQCOh97BCoEO1cd8AP4rsYFOaIMfiSIeL6fx9oJWOBZBoTFOEfWasGQMMjGSBD5Gy
         HzcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oo/E06wZMGNatgt97IuRLFtkwSucz3rdlnsDRni0sWc=;
        b=Ma9yYgpHRH5qyTo5gF8wiZCMV4B/vsLyTD6/bV0WstbRaB0PZdCYm2VwW/MO3/svGs
         9Hl6lMZJ5IBCiQLEi0lckKHn6Mv7Vd0OGsxCLwqy7z/VTL48PAfOYe1e4HqChyCr3rKD
         CZ4tCxTlcTC2gW6HpZC5u70whrW3ErfaKeiiRWui+WMD/xi2kUCZ1o+2boJHwC8hs7U4
         ceBMDRy3A+wsrcAR1v9n/7CQehbUTD/khrF9XxSSqFcktUHCZ+UwxZeZq0uH4Z3r3CFJ
         8meLq6tn0nKyHiJtop3BbxpwFlGzvZ1ya09OHXufHxMi1CyQgVkErALFgVUlb4KQu/qd
         LHDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oo/E06wZMGNatgt97IuRLFtkwSucz3rdlnsDRni0sWc=;
        b=W1xbOTV3t2VvPj4TZr/ysthn5LhDS7Jk1qC+6bscAVQSCTvyn6d7ze4kdiYzJEncoq
         lzc5UOPBF/s1N/XFIVvPk9vxtoEvpaf+afS30Vw4TKFuJ5w5lQEmJ6EKFBl/4FTGw1Gt
         JxPUg1XmB9Web27Rjlj8jDx90ukslMpwGjvV/QBIWvJVhz3I11xEXoq8qAb4Zjd/viJj
         ngYaoCeATYHPK1xsazpy/mzBNfpagN9kQNpcxTzaU89mzHCU+k24hSvd/esZzeTiDMm6
         LxHuViEI1I14GCGe5OkHBa5jGNuZhGeUMbeEp/ID8KitOz24DyyQpAsJihcqZ+5xXyp1
         Yyrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+jVcW8/1NBxRMsfaBKhlkOwOe1Pq5drFqGk4eimzelpMKFYrS
	tw5I1JV+lJcu2lHvQ6iXcwI=
X-Google-Smtp-Source: ABdhPJxyCTMcPew56NUQBlyjkj/djDjXBfl4UZ1FfyyR2O2y+svfRqI8xzbI4zDBA5pNCGG56i5ykw==
X-Received: by 2002:a05:6a00:84d:b029:329:a067:b1bf with SMTP id q13-20020a056a00084db0290329a067b1bfmr13383533pfk.47.1626489678238;
        Fri, 16 Jul 2021 19:41:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:680e:: with SMTP id h14ls1866508plk.1.gmail; Fri, 16
 Jul 2021 19:41:17 -0700 (PDT)
X-Received: by 2002:a17:902:f08a:b029:12a:a4fe:564d with SMTP id p10-20020a170902f08ab029012aa4fe564dmr10091506pla.56.1626489677663;
        Fri, 16 Jul 2021 19:41:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626489677; cv=none;
        d=google.com; s=arc-20160816;
        b=o/+nfcX8TtpT2fkpdqxra6EcSheQUFmFAzY/w4cicO9wkDDrucwMy6789jlSGub1l1
         aC8Q3lVGhLS6YnTW1N9ZP7ZD62aPkM2jhRQGrzx6wKr8AblEjjCnUDpKoQBDgnBeaU+j
         gWMVTsQ5ph9jqLEm+IhDalcYd8tzOQbCz2A9/iEs/sq6REOGD0l8N+Tcy7Z9lrPR/1F1
         ti3WxvLInv3/3GLO8MWndevWGEw6Vdy63HEEs0ArRKPc0E6tFsNnbdzCdlnCwz9sVgwc
         wEgEznoAAtHhiMKq/8IG9Tj1YPYkajGnWRRrrqIAjKc0xjAluNB8S98S2Xgldou4QiHC
         fkfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GMchn2yQ3hl5Z8sM21W6KyQt0+Xr+YfszooxJVQJiVM=;
        b=BcnDGXicGgksejO91cbXuRUTmMGgZMNOQeufWJjSssZl9fbDgqoUHd0lFtYcMVIPtC
         IIUNNL4XpMkz3vfZMr7ZOuhXorUoVlQgPDWebGWCul2hL5xdq2WvpgizleTZp2aACI47
         Cw2rOOEk9FOj7iPgZJqT+mUdZUosykumRJE4Nxj6nW0T1mVLwXm3R5zJtORzLxKUb1YK
         gg/yXMpkqv1dUEtjtVrjlAUR2sSoBNYYYACdhiJb9auoMLEPP1aHumcmpRVdEhWOkC6p
         OYWBq4VS0pjoMj+sw+AMINVQL3pQXousS8hDPiaLbmTKOVZjlKat8mrfBc2QsIoiAkk+
         tndg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id o2si1824990pjj.1.2021.07.16.19.41.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Jul 2021 19:41:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GRXJQ6H1gzYcrx;
	Sat, 17 Jul 2021 10:35:02 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Sat, 17 Jul 2021 10:40:44 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Sat, 17 Jul 2021 10:40:43 +0800
Subject: Re: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
To: Marco Elver <elver@google.com>
CC: Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas
	<catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Daniel Axtens
	<dja@axtens.net>
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
 <20210705111453.164230-4-wangkefeng.wang@huawei.com>
 <YOMfcE7V7lSE3N/z@elver.google.com>
 <089f5187-9a4d-72dc-1767-8130434bfb3a@huawei.com>
 <5f760f6c-dcbd-b28a-2116-a2fb233fc534@huawei.com>
 <CANpmjNP8Js3nKeVfwPqV7oQaBbGebKxFYRWe8TifTduP2q86xA@mail.gmail.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <a0431275-2ca1-0d5e-72e2-9ec6b256cbf1@huawei.com>
Date: Sat, 17 Jul 2021 10:40:42 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNP8Js3nKeVfwPqV7oQaBbGebKxFYRWe8TifTduP2q86xA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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


On 2021/7/16 15:41, Marco Elver wrote:
> On Fri, 16 Jul 2021 at 07:06, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
>> Hi Marco and Dmitry, any comments about the following replay, thanks.
> Can you clarify the question? I've been waiting for v2.
>
> I think you said that this will remain arm64 specific and the existing
> generic kasan_populate_early_shadow() doesn't work.

Yes, I can't find a generic way to solve the issue, if there is no 
better way, I

will send a new version(fix the build error and the wrong __weak comment)

>
> If there's nothing else that needs resolving, please go ahead and send
> v2 (the __weak comment still needs resolving).
Thanks. will do.
>
> Thanks,
> -- Marco
> .
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0431275-2ca1-0d5e-72e2-9ec6b256cbf1%40huawei.com.
