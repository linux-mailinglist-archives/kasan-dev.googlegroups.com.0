Return-Path: <kasan-dev+bncBCT4XGV33UIBBDXR7CIQMGQEKCBGNEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 68BA34E7AE1
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Mar 2022 22:47:59 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id k20-20020ad44714000000b00440fd2c4a0asf6908545qvz.20
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Mar 2022 14:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648244878; cv=pass;
        d=google.com; s=arc-20160816;
        b=QSLBwfX125ZDlqEwDVmTkqgRP/04ssJH/fTKCt0kpNbCfI7V9gAEoaV0Sn9lSd+YV1
         IsK4ImZeR1kklwKVs+IAGe5YQ0FEoDuOr++NXl3b2KINfzPVMFVO8QegLIaMCGpAHHFI
         Wray9WeNlzzKw+o05Z8j+uanHqpMc0eCNGUzaxMu/aS33F9/UXWST2W7DHaQgBEAv1W9
         QDqFG1SeyV/ztM/TAVwSXsls55V/NXHuuZskpqURLMefcMZ5o2d7Qoief5NAYrgZreDZ
         lpnPHyZtvW5et91X6HsXnktlcwTWE+wXlAhALHrwHkp4o9Co1WUsSOzyynvbci+Jp/Wu
         sIsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=a6CCzMVbe+rBgXSjGVmdeqOHE23ticga5QaLLS/G5wA=;
        b=SDkhahbpQlFJS24iRI1Z5jlmL7O7HXw/fHm2GugnNDb+BOgkVgWpewdok/1QUS2l6r
         9RIGI7ITHltszu1nFoypWNlgvkvYmzMEShHiLCIatXt6wtT93Gkks8X23QXyB47Q3TOK
         Etj4lcZbBvyjGAmAxFviMJzcFEuhasRrkmq59f9MGpIPgs2AxshjUhi71vag+cBzmr5b
         EUWNZNw32nb+3NAu3+Dvi9WnRcQDEH8kPrZBk5p1BkvGFnx+d7hH2hZZQveQjtd5LuGi
         SSV+qpmbgceIil7JqbDGkdFyvKnvcMUGyMjqK1GweKIPmitxh4GOPbcEymm0qPAaV3uF
         GRWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=lOelYMRO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a6CCzMVbe+rBgXSjGVmdeqOHE23ticga5QaLLS/G5wA=;
        b=eYcAcpJ8hyJkw9jLlFlcvq/3RTLu88pxDeD0iqo+H5XsPd/WXRbACzXGjO1lfIqQh2
         eS5oolJ1YrYEvZlYGrjWTOn7y8Iiuipgi5llp+qTZM7q9E0kLzFByzxJwUdc40lLnGRP
         Sd37c4ajaFvIZtbuJ5rMLu0OmjOO2H28DkBLwCnxnrKvpxuFn2yAxh9VmAIX+681py92
         vkhYPx+zctqla0Ya6UFklhSnNc7snGEqJ7lDQ0pTNVl5yV7vipmoNOEInxwjZpATY/7T
         eRnreTqR5IKuv7+2x5z57Y6z0FAAZGkSWIwTIH6uLYJz3OWtXpkbH0rWDbBGSG20DlkK
         EXqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a6CCzMVbe+rBgXSjGVmdeqOHE23ticga5QaLLS/G5wA=;
        b=FBrAMz61xOWn4HFnhNGi7FvV12etNOraoQj9qkxIM3YNCjumxKFDPji9PjcyZxVHH4
         dlYyZDUOoxu0fqJKm642RIdRyKSmFVOuwYDrNeXKxzc9ogA/xs7v4P3a7SsBXP7kD6nX
         MfHlw1YEzWVrfq4sfJKYCpmmNEGiuimO0TIX3mxn0+pDb83WDH3Osgh+mFhGMAOT8Vxn
         3MzUcsl+byR+t4FhwJppS9PHaPlf3OxQqswtG+FggqJybhgDlH7aTHbuvJiOoWB4T3Dv
         hNiuWjvkvFRKE5FboUvBdWIi5bPs15NmyNLFFpMTtSfP1UQtDF4AVRNgbeVRlDs/62Lr
         10TQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332Ry3umEqgSzfdmVUt9OdrVJ23Zw0Bsd5/F5vPJTQIk2y7do6M
	x4S0aGIzz5YfGrP2hkK3G6M=
X-Google-Smtp-Source: ABdhPJyJQcwI8edXHAywDhuUDOaqzCQKnoPgIBlwuMenXx5rTX5+2bN1azlYQnUmy/e21jN6pAtigA==
X-Received: by 2002:a05:620a:424a:b0:67e:8860:55b7 with SMTP id w10-20020a05620a424a00b0067e886055b7mr8309722qko.26.1648244878371;
        Fri, 25 Mar 2022 14:47:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:230b:b0:442:6bf3:a86c with SMTP id
 gc11-20020a056214230b00b004426bf3a86cls916606qvb.11.gmail; Fri, 25 Mar 2022
 14:47:58 -0700 (PDT)
X-Received: by 2002:ad4:596c:0:b0:441:1281:789 with SMTP id eq12-20020ad4596c000000b0044112810789mr10966493qvb.84.1648244877971;
        Fri, 25 Mar 2022 14:47:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648244877; cv=none;
        d=google.com; s=arc-20160816;
        b=MWeCU1b5yi6fyDx3qvB63bj5ZpHePylRBpjxpDgPOhMx38iZ4C8DjazyB15nactVOP
         1il2oeOT+EJBQVKYil6BbVcoY4FaBo+J7hqHZcFzWJd9WOjAEWFJ0Pf4dZa/wuUcW52T
         4GC2CCN2S78xJg7L9kd9kfaEPQH1xEEteoOyqXRFhGkMN+6/FgWo0l+vjUKevd43CFcA
         Zym5Ib2L7Wlq4OoIw9HG09wT52OmWQauy1ZsSyjtpiRa6byFnYeJEv/rOPmXZV9DyutE
         8T50U9mIPHi3G9toHHdw5qWfFLWZ1yd8CZH4o76Z3/4zPInJid/5EwwQpTYm8vYwQfcu
         +9iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Rel2cA69nxFMycnAlTbLC9e3jy4Z5HkvrU+j7Z2Tobc=;
        b=EtWUa74iBJeMr1DrGqZABR1P7r1Cz5cpG9yE2fuiHKZk+LWn+KypJW1jQ+qgQElZMX
         rzMSFBiOXMQssDJd6kLscGSRyop7DlQPO3yKk8QL8wxViFG/YW6j2vXoP9AwqXHm2udB
         1eiOPO3+l8Jcj+Z1ygIQ+gMFd4LVMJnGM38Si5AY/SFerHjoQjjmHxH8uVYP3oLdS2T7
         5uFIbcVndr5f56aMfS4wHKMnTKrE264TL8fOv6SSJ06XKqvHqRSj/OImOd1hxviZ2pxz
         lrpib04+ghHt7dt+gRCZQyzEfyRjj30c48TgF0FrXp0EF/ivGunZ6ALjj2SeYsstwfBu
         PSAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=lOelYMRO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id j2-20020a05620a288200b0067ecd3f617fsi521930qkp.3.2022.03.25.14.47.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Mar 2022 14:47:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7D21261036;
	Fri, 25 Mar 2022 21:47:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 97DDEC2BBE4;
	Fri, 25 Mar 2022 21:47:56 +0000 (UTC)
Date: Fri, 25 Mar 2022 14:47:55 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: xkernel.wang@foxmail.com
Cc: glider@google.com, andreyknvl@gmail.com, elver@google.com,
 dvyukov@google.com, ryabinin.a.a@gmail.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] lib/test_meminit: optimize
 do_kmem_cache_rcu_persistent() test
Message-Id: <20220325144755.c0a92c6fd934b4cb98c41c16@linux-foundation.org>
In-Reply-To: <tencent_7CB95F1C3914BCE1CA4A61FF7C20E7CCB108@qq.com>
References: <tencent_7CB95F1C3914BCE1CA4A61FF7C20E7CCB108@qq.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=lOelYMRO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 23 Mar 2022 11:48:24 +0800 xkernel.wang@foxmail.com wrote:

> From: Xiaoke Wang <xkernel.wang@foxmail.com>
> 
> To make the test more robust, there are the following changes:
> 1. add a check for the return value of kmem_cache_alloc().
> 2. properly release the object `buf` on several error paths.
> 3. release the objects of `used_objects` if we never hit `saved_ptr`.
> 4. destroy the created cache by default.
> 
> ...
>
> --- a/lib/test_meminit.c
> +++ b/lib/test_meminit.c
> @@ -300,13 +300,18 @@ static int __init do_kmem_cache_rcu_persistent(int size, int *total_failures)
>  	c = kmem_cache_create("test_cache", size, size, SLAB_TYPESAFE_BY_RCU,
>  			      NULL);
>  	buf = kmem_cache_alloc(c, GFP_KERNEL);
> +	if (!buf)
> +		goto out;

OK, Normally we don't bother checking allocation success in __init
code, but this test can run via modprobe, so I guess checking is the
right thing to do.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220325144755.c0a92c6fd934b4cb98c41c16%40linux-foundation.org.
