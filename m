Return-Path: <kasan-dev+bncBDKPDS4R5ECRB5WZTWKAMGQEU73FIDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B0C952E9E0
	for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 12:27:04 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id e18-20020a170902ef5200b0016153d857a6sf3951394plx.5
        for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 03:27:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653042423; cv=pass;
        d=google.com; s=arc-20160816;
        b=euiLfxpRxx4jGalJnOQylzTnV+FLZwPneIiAWLE6dxJJoxPa5eo4I1v5QG6cMdp3wM
         om16Hqvw1CCQy8oIK4D+AEhsQUaXmn7PT5Z4adnstdS5a6x0rcp4f9fXZZm9JFzbfa+G
         P1SYdmG/Lh2cXuizAmZ2XBJSjQ7C0J8w2KtSagkERrnpPbLhjHP6NLTpleli6xT9gGOk
         aOp/R7vzh8Mhw8jUqc7ApBu6D+hjiJYNSGn5XMyuNhH+DmkK7cKMDCSo/yds8gqcj8HG
         4MBKtKbfYC4dfdDDwyr9EzPaPkAul5VwuCWZTpXthL4CH9MmNSx7FHrwH4R9nTAqfUSO
         zjQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kfZpxXFUBh1Y0RKFiwoPG8Gc9YwdtzQe5pHt0wHgyfc=;
        b=mD/DOsyBt4KLsEQu01QNwCg+/vtP0VfyPDdbgzmpiUhAfWtL42UEpGqLieC9HO+rqK
         hXVkqGvdM8j+bDJyGOtv1ua+TaeVYsmR3htHslBKhVVKUmhsDxA2HQjOB1DNm7V+xy2D
         1tHxeZj57jN1eOoYMvveQyzlPvb5VmwEVQYhKvFHeMXJHwnA4jrMvwH7ae5OcD/Q7D7S
         9TAVM7FD4z4MBlq3ZFPimjOp/McosSSrX6VeYk1rARn3Zn1k19/NRTTgpwJ5Cgu9uF5h
         4EPmJdU7B0jJ7YfojNtPCspum0yN4Of8EgXOBpuDKxhIk2/sj1QTsHX7rGqKW4wBYouj
         7z+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=YLK9qX44;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kfZpxXFUBh1Y0RKFiwoPG8Gc9YwdtzQe5pHt0wHgyfc=;
        b=ce+z1hzzt707+Fmtkb+hwMv2HbLWhbVsQL2Lz+nbROypxzL0cLWk1XdxzXWeKqKFEI
         +uPnd0ypQKB88lYAywFuMf5lPxWp1HSZj24YoWV/k6xKd1BIRQ+iNde/Aqs4aNzYscYv
         mvrksPRoCVWi6X4DhkatJGjF+FIB2OcbtA/3Y+CK8GKMwSNNI4SmUo2l+lIc5i5dcRm6
         bV64sgz3vVuv7mz8Yx6a6+LOCVgJpRaDB0gKqGiQaBuMBxznF6CmbiPLCTgMQ8KmzDpJ
         Q4YhWohVdre+804D70QAAE0mlyYZnE99CMAA+hdYIDyXfPrtYCqqGcavIA6aFvAHsRCi
         XuMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kfZpxXFUBh1Y0RKFiwoPG8Gc9YwdtzQe5pHt0wHgyfc=;
        b=kH4xS7QvynMm6fT9BGSxi9Cjh9QhVCCs36yH/qwlMhvlInffDX4m2yF5DmJ+nICTkI
         cKKTzp38yCsbub+iw+NimgD9WuwiPvmC1eemp3Rnh7vO/GekkksckaeDpMfL+OHgbHdm
         Cd5eDFIWahJCKTk9irIBa8bZxcFb/83XrhVMHPxna6CXThTffs846+xCWkkLetUOqpge
         Yy2q3kyjOYgV6l9+sCKnI6y/CMONyx1vWFs0jdeyIwdl4mJLDyoKUaGx2iT6X73ZwKJK
         qViarDJS3CYEpngYMjnO4/e/jODdD1t6fJ/9mtxt8bIy/ZJK9KkNNzzOTQaLkObOQ9fC
         4vuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531DQA5DYdlOi/i21hNEcGxvXBDpPJDIjREXoT3lcyPLJTfUf8+O
	xscdMT7rYw6hElODXyYIzk4=
X-Google-Smtp-Source: ABdhPJz5IVA/ri1X8BJkT2V4nLsuHKCI+mbq/nthZ1AweU1l7VBjxdbvqQQ3mtOUyY/9Ydua3WGhZQ==
X-Received: by 2002:a17:903:1212:b0:15e:7d94:e21d with SMTP id l18-20020a170903121200b0015e7d94e21dmr9215372plh.92.1653042423027;
        Fri, 20 May 2022 03:27:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:82d4:0:b0:4fb:1450:22b1 with SMTP id f20-20020aa782d4000000b004fb145022b1ls2571221pfn.6.gmail;
 Fri, 20 May 2022 03:27:02 -0700 (PDT)
X-Received: by 2002:a63:1c1:0:b0:3db:3d7d:fbca with SMTP id 184-20020a6301c1000000b003db3d7dfbcamr7735176pgb.461.1653042422428;
        Fri, 20 May 2022 03:27:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653042422; cv=none;
        d=google.com; s=arc-20160816;
        b=e5y0881w2tjLIwNnakZRhANgnc8C5Q/tyDmhlgC8AcE/LMDF8YbNTo8xxxBiPpbJ5V
         o8cxLRPMavAAvHlctxY/c2P9L/1sRUGUCU1syDEtQCEw42JbKukat7iSE3mKfLdzqR/m
         aBMbHYi7SyOqdZzbV2fZwgXsRZefdwyrhl3nC+uG63VzdAlfcSucUFZCBCT4+mxM3Um5
         I0DW7alkdQE7yz2i5QZBPZwms3dUZ7QiItNYGyA5L+D+aXoWuX69iDBN1DredQ4BFM3S
         WNXBUHwJ5t1R0BCsGnLXabz2zWCKtOwlgUJ7jGTd+F/lf4ReHdMGkgUA4qlmxVCisgA0
         WcQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KAiDwasBy5DAIz42IdmCEQooFs9oAyMPV4lUPQlr0zg=;
        b=XZ4qzXAO9kR4ITcyMOivztdlDVvv24tLE/UWnCCeepRnMAbfpk87nAcdTgij0H2nr5
         v0RTsB4PLTt5YhdWlqfahAJZHBsVjtspNYQaIidF1YrPlmYbRnAmOjqG0cDpb312PbqA
         86QRpvL+p7zTCovmz/30N5Z+6ADbvPYIpmBDQANj9gjrzwRA8kQeWZyWxKCLWYLCEfOR
         e+DXWV1glARKO4V8DdOXKb3iG2Br+QQdRQwwOMZm8xilgJdWirtMUvecs2oLkSyZ0rWa
         OEfpIflzK1e2xW02raCCUw+I1lelhSCS+QD2qZbA7r1ATJ0Q6rfdMO0d5e9cIml52uUI
         jFFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=YLK9qX44;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id m3-20020a170902bb8300b0014f3d55ede2si308193pls.2.2022.05.20.03.27.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 May 2022 03:27:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id m12so7011495plb.4
        for <kasan-dev@googlegroups.com>; Fri, 20 May 2022 03:27:02 -0700 (PDT)
X-Received: by 2002:a17:90b:3e84:b0:1dc:5942:af0e with SMTP id rj4-20020a17090b3e8400b001dc5942af0emr10192435pjb.61.1653042422217;
        Fri, 20 May 2022 03:27:02 -0700 (PDT)
Received: from localhost ([139.177.225.250])
        by smtp.gmail.com with ESMTPSA id z2-20020a62d102000000b005183f333721sm1489964pfg.87.2022.05.20.03.27.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 May 2022 03:27:01 -0700 (PDT)
Date: Fri, 20 May 2022 18:26:59 +0800
From: Muchun Song <songmuchun@bytedance.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] mm: kfence: Use PAGE_ALIGNED helper
Message-ID: <Yods867HAh5NH2kN@FVFYT0MHHV2J.usts.net>
References: <20220520021833.121405-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220520021833.121405-1-wangkefeng.wang@huawei.com>
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=YLK9qX44;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Fri, May 20, 2022 at 10:18:33AM +0800, Kefeng Wang wrote:
> Use PAGE_ALIGNED macro instead of IS_ALIGNED and passing PAGE_SIZE.
> 
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>

Acked-by: Muchun Song <songmuchun@bytedance.com>

BTW, there is a similar case in page_fixed_fake_head(), woule you like to
improve that as well?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yods867HAh5NH2kN%40FVFYT0MHHV2J.usts.net.
