Return-Path: <kasan-dev+bncBDQ2FCEAWYLRBMFL32EQMGQEJN7GQWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 17AAE402CFA
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 18:39:14 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id r1-20020a4a3701000000b0028c9e077850sf6070416oor.17
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 09:39:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631032753; cv=pass;
        d=google.com; s=arc-20160816;
        b=amYsT/nuY4aR1Cgx3Bhu/cFG0GGxfLDHhoVJzU3weWuAkQh/q9ievAGbxeucD+e4LT
         7u1G7IRk+lBpomhaLpTUuhZ6wLzmXori7rU1B2yfP6rVfwsnDKaU8YKADh3S2SOz+FXe
         Fnv9PHwSroalZiYO7pM5lpjwjzNJwYxMTntEnXPTogWSRZ2e2hj5567wnfwm1nHKHc9x
         4CRu0DhTOSRPa28A+qw/x9uiZEMqTMiaLnjiBqOaFLfq3ipt/GNRNVlt11My2Nih2D5e
         LHgFoF1LUFgxxjUMR66PbFNSMppqAbU41CFoAfTsEdQrm8O+m7gJi46TMjaCPxTUbpUm
         uA5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=y1UV5rVM0GsUaismWSOOd5YOYxCU8q4eSvpLfPTpwIc=;
        b=eFeeRxUFrLEX4+Nio4ekOndDFmCYhs+67pxtNWOsxtNzUUFE2/E0DD/IhUQmwK0hIP
         4YJPuzFTOP2TXRHFFGAeg6hEC7z71244kALfGjReLF9WRj8gDu8ilIonxbXy/qVxhTz+
         5MgfBKNh6tONrOrQQfaDQN6YtTopgjkT7qe+GWbFp2JETx2/3tYv9GhWPEc+ntmS5fHW
         x0SidlNhdf2gGyGrQaYzG+axhlCZuk11zP4UW19bK9VQIL8jfGhP1R+CZWNFHFQ9ZAAt
         +WIYFdOl0rpJ4RKGsXGvyIEpg1AAJdHJt9lSk1o1/mByGEbg7sP4PrQxK+r9exMAv1uD
         1zVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="M/0bt3uV";
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y1UV5rVM0GsUaismWSOOd5YOYxCU8q4eSvpLfPTpwIc=;
        b=J2WlvJzX9Gitr0LAAgSrREsqxxTT7OVivik5W4ITDuPKR+aZWXHY40cugAB1aIqwgV
         ufnseU9qwOV8j7QTYIoYTNJEasZ9Yz1zX2awIVx23SS8wVPX4ZoNv6+1w++rpUj7EoRb
         mcNm29e7xi8/QHVhibz9ObL6au+SpHFV2qHCyisTcY1knmtOtCqo7tsqMYGzPQwHSQLq
         O8D9i6ZF4E3rJ27h3rONDOW75k9XmwCnedguTaGGHv4uNvp7sN+B8hGSEYmOdeAppVTF
         0JUmk7QfBcApTkh2JLGQlztbeR2d6jJ3UKl8U+p/jO8SH66s4pLZSZK26ULX1JplxIeR
         GcLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y1UV5rVM0GsUaismWSOOd5YOYxCU8q4eSvpLfPTpwIc=;
        b=HCQuRFLxG7h/lqFziirZC6i92R9HaiDu3L6zDWdY/NYRW8l6Q1dACSSrgOm1ctyrXH
         vxpnyonYJW2+cudKOKpbe4WUMzqFrYy38Ahnzte1znHUyVwJ8JYEFI7SyvwWViudUIew
         yCcMqwKLSuO7IGVFA6OqntC55fO6sPslY/FqStPbE/4AP5FbebqLAlq+jc2LrOLq+Adm
         gyV4PTqX16AG2Tjn1PpJrzIPexBT9fetRs/VhvEYxjYIyGskEAkP3cgQvgedLtG9p47w
         vF7VnygMV0jfSCvCn+5k31hjxvmMnkrJzHAcfCHPxe1dcpT9ZfFbOD34H9j5YihmdExJ
         kqVg==
X-Gm-Message-State: AOAM532ea9+GdBpQKToLKrIE0vXAAvjj3DRSei9JVm/9X1iMg/j5ECXc
	eKiHxsSbkA2c/Az1pvf5pxk=
X-Google-Smtp-Source: ABdhPJz2OGhBKZc+hPZiK/zxagyJ7aRDMse7H8SaFbvc/Znn+DURSOeKICknW13D4UgTVdK/wTIdiQ==
X-Received: by 2002:a4a:966d:: with SMTP id r42mr618062ooi.11.1631032753044;
        Tue, 07 Sep 2021 09:39:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:14d1:: with SMTP id f17ls2247538oiw.4.gmail; Tue,
 07 Sep 2021 09:39:12 -0700 (PDT)
X-Received: by 2002:aca:4509:: with SMTP id s9mr3663039oia.38.1631032752732;
        Tue, 07 Sep 2021 09:39:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631032752; cv=none;
        d=google.com; s=arc-20160816;
        b=iSIcCLKtyC0xhUaY5xx2A1DQazPbNhYV+vgBPyDEuXMN7782Uk+0lt+qbta842ZUA+
         XiqxBpNUX3Z2gb/ntqcxA36AKA75HasbAWYgXiW2LMSgvt1u/6wgtU4FWhe+RQ7jSJSK
         uKWOmq/CtrmlycMXbI7DkJvh6vPy9gcL5IG1Rw74TN5fIlKAzSIfAMn/DWOTu3eO4Ehx
         kvvRKV07OZVagkfQDZzkSZz70axCQveQJwXQETOJ+NYkqvHN8jkfX4bXTqMJKSxezKHG
         w+m1VMPWV5tWKygN1X+cga+GkiCHJT34cExnZ2G2ISnQTM5xpRHPvPzNKia8qABqQOo4
         Z5ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=9ggBt1/XcGMk1GgPoYY4NtuKRl2ZcdoZPPws/++QS6M=;
        b=DlNmPkFjhp2lAv3r1eVXCD2nvEtVYdw9zPUR9KSE583Aaa6zV9VLi8fGArDNCogLYi
         f61yh7z84/TnVsuPRL1VdgHoBZTlCYAw0saOrgZx7PfH/5EW3vybkGumMxqMAcMCqzef
         Tj8qffYuLbj8BchCzYb1+j1rcrjktucp4OMInEWf5V8tSraWcWTaOrxTaz9PfWFnPhKE
         PD8So1K8M9BjE+Cvy1d4hURleA9MGMuAlNdZw8pvkUfml7UeNRw4FgdL6QXWbpZALsnw
         vnCCk9LrznndTKWHNY6KehE5dtuT3z5/cLnGTpVdjGFGufE0cTMsZz1PC0sGKdyohsDd
         7JJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="M/0bt3uV";
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id c9si766214ook.2.2021.09.07.09.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 09:39:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id n13-20020a17090a4e0d00b0017946980d8dso1885873pjh.5
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 09:39:12 -0700 (PDT)
X-Received: by 2002:a17:90b:1e4a:: with SMTP id pi10mr4393075pjb.135.1631032752193;
        Tue, 07 Sep 2021 09:39:12 -0700 (PDT)
Received: from localhost (2603-800c-1a02-1bae-e24f-43ff-fee6-449f.res6.spectrum.com. [2603:800c:1a02:1bae:e24f:43ff:fee6:449f])
        by smtp.gmail.com with ESMTPSA id 126sm14850350pgi.86.2021.09.07.09.39.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 07 Sep 2021 09:39:11 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Tue, 7 Sep 2021 06:39:10 -1000
From: Tejun Heo <tj@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Shuah Khan <skhan@linuxfoundation.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Vinayak Menon <vinmenon@codeaurora.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Aleksandr Nogikh <nogikh@google.com>,
	Taras Madan <tarasmadan@google.com>
Subject: Re: [PATCH 6/6] workqueue, kasan: avoid alloc_pages() when recording
 stack
Message-ID: <YTeVriit6r82gWGz@slm.duckdns.org>
References: <20210907141307.1437816-1-elver@google.com>
 <20210907141307.1437816-7-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210907141307.1437816-7-elver@google.com>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="M/0bt3uV";       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::1032 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Sep 07, 2021 at 04:13:07PM +0200, Marco Elver wrote:
> Shuah Khan reported:
> 
>  | When CONFIG_PROVE_RAW_LOCK_NESTING=y and CONFIG_KASAN are enabled,
>  | kasan_record_aux_stack() runs into "BUG: Invalid wait context" when
>  | it tries to allocate memory attempting to acquire spinlock in page
>  | allocation code while holding workqueue pool raw_spinlock.
>  |
>  | There are several instances of this problem when block layer tries
>  | to __queue_work(). Call trace from one of these instances is below:
>  |
>  |     kblockd_mod_delayed_work_on()
>  |       mod_delayed_work_on()
>  |         __queue_delayed_work()
>  |           __queue_work() (rcu_read_lock, raw_spin_lock pool->lock held)
>  |             insert_work()
>  |               kasan_record_aux_stack()
>  |                 kasan_save_stack()
>  |                   stack_depot_save()
>  |                     alloc_pages()
>  |                       __alloc_pages()
>  |                         get_page_from_freelist()
>  |                           rm_queue()
>  |                             rm_queue_pcplist()
>  |                               local_lock_irqsave(&pagesets.lock, flags);
>  |                               [ BUG: Invalid wait context triggered ]
> 
> The default kasan_record_aux_stack() calls stack_depot_save() with
> GFP_NOWAIT, which in turn can then call alloc_pages(GFP_NOWAIT, ...).
> In general, however, it is not even possible to use either GFP_ATOMIC
> nor GFP_NOWAIT in certain non-preemptive contexts, including
> raw_spin_locks (see gfp.h and ab00db216c9c7).
> 
> Fix it by instructing stackdepot to not expand stack storage via
> alloc_pages() in case it runs out by using kasan_record_aux_stack_noalloc().
> 
> While there is an increased risk of failing to insert the stack trace,
> this is typically unlikely, especially if the same insertion had already
> succeeded previously (stack depot hit). For frequent calls from the same
> location, it therefore becomes extremely unlikely that
> kasan_record_aux_stack_noalloc() fails.
> 
> Link: https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org
> Reported-by: Shuah Khan <skhan@linuxfoundation.org>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Tejun Heo <tj@kernel.org>

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YTeVriit6r82gWGz%40slm.duckdns.org.
