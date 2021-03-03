Return-Path: <kasan-dev+bncBCT4XGV33UIBBDVVQCBAMGQE5YI27AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BF66A32BF30
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 00:23:59 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id q5sf20243908iot.9
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 15:23:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614813838; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDPS8JfQYRcgcgcV2fZMDMwRBSLRFT7erPqNY8KvQ2dlBuDJa7qM0TK+vPiteNHqTm
         71PTZmsIph0GBEZtKG096T9wQooWNEA1+5ERFDBhH+aWH1G3YdMNx2VnbifrCj9XPz9q
         MKfCUF4TfoT44M5sIU15njUGAZK/cQHvRmVQLGN9BgmHqnlp4Cgz1UPvzPL8ONKKHIWr
         pxQuIcSL6/3hxTL0He5+m2OkX9A/6+TyrpLywvSnIyRN1VbiyGp94pzc83WmTeXeL+BR
         c1YMAyL4qafOhaRvujn23Keus5QlXRhdlsxidVQNpwgXC628qqBunuBtrn4WMqlrD/8G
         ji0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=EUdMd0a86oR8sxpBxPmmvYWWZ+7og0tXz7wxMLm3pQE=;
        b=lVegmm/I8LaVrT7fsD3Gcew2RBfrUzRsGXX+srJgXfwoRsydSnukdDWNP7cR+RQx8g
         V0JVOxKtBVYzHI10lpZ/7AG3bu5dT+QA3D7lnYiz1euotFSyeRRIdPM6Q7dNcmPjLy7b
         il+MhQKX3R6nGLAEfghso5PgS9e1P3LL9Wtdko3YELnlGe8nnseeq5jCnaMpTmYPl3Es
         EMuADpYQ+DIYYhRY+NkeV4Wl7pZR7AInx173/GFl3ZNqLNlTOO57WA1ESjjb/KKMvl1j
         7bF3cMQlFfmQ+RGMIpTfb0pIrR+l6aJiLzdVQpn3uq0Hf0ErfdMwPUpLWHBFQkRky08r
         Fkgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2nTUbnis;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EUdMd0a86oR8sxpBxPmmvYWWZ+7og0tXz7wxMLm3pQE=;
        b=UzHw/O6hVeIjWVZwFUKe6X3Ju6SejXiybBHh6URzqwRH9nIj+FFsRVf1b48UTKLd7H
         O3eEUZMyAsN7cH1vtM5KijjnrSYOnJ2jImsbLBuMJjInUfA1eoHz8uTe6Lgodf5imggl
         eP6SHxhoUqaayutEuEQbA3u3UoStIM9ISyBg8+cnUq3bof6PCKR3XNozn1N3VUkP7v6Y
         MAeuzDsQoK7ltXfurgSKpa02068P0FvxifbbzlVu4e7Cl0BSjSHlhPubMmi2YPbQWcTE
         gnc7/bdSn4xjtJliPVxosLsK+un2JmSCQNcSjhNE60Oe5+wOnacDjUd0qJI5YCLfJDfV
         /Gxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EUdMd0a86oR8sxpBxPmmvYWWZ+7og0tXz7wxMLm3pQE=;
        b=oxRboE/UfNMVPwbgJdx9xQIzTcvl8o5mIgTU7dJ2XQXwysjwf8Vt/h+3WZM+bLTCCC
         HZBB0tEIuJ2UhIXyi8AkIdF2USFL4fNV5lZ7TSJpTFQCsVL5z1JLfLHJAKqZJgX5Lnzk
         Gm+aN73NJwmqSb+r/ITPmJuilxrrDkqRJvU1D2lBhzdEPla/bUVo2O6sXbXvOB0bUF/5
         QTS0/LDkkKVQ0hAv0e8IY7eOvkE6KRxmBdfE2rOUnuzEBuBw0Pvne296d5IZ3/0NnEm8
         H8ryi1dGo0O9Sd2T/vX7xFU8Naxt1iYAWEzCTsHQkc8HbJcENC+LSEMJpj+HwRvhJw3R
         bQXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530YYvIzKYzvZlrwjELepXTWzGYcVp6SCVWJYN268V5O+qyb+rQn
	M/zQaLj7UZt1focdHnB89tY=
X-Google-Smtp-Source: ABdhPJzsxpzKRWXo7dRle8ZLAStOFDLDvJkoz5Q/HNwMTPCds3P1Q17xVJu5v+z8tOXUoc44Wj31ZQ==
X-Received: by 2002:a02:9083:: with SMTP id x3mr1304911jaf.17.1614813838281;
        Wed, 03 Mar 2021 15:23:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b807:: with SMTP id i7ls673175iof.6.gmail; Wed, 03 Mar
 2021 15:23:57 -0800 (PST)
X-Received: by 2002:a05:6602:2d83:: with SMTP id k3mr1405906iow.26.1614813837808;
        Wed, 03 Mar 2021 15:23:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614813837; cv=none;
        d=google.com; s=arc-20160816;
        b=r6DW+CKPWnEMC5iIrviNSV2qslUt09kPc7UGv2TVA4VT0ROIM3+FZhC7ozVSTjmZcC
         XJ2bfFW7r61mnZwrBIv9eWeBjsdHbyCn278JrWjeQXEQFSotSPdvMfDR6zpUfsAjgfEa
         TcH7xzk6A63ckpzUtEz1m2CXMkBoDmKA3Q4lXHwoFIr9jCTE18IRi2fn8967t+wdOGz5
         9PzmR49/hmXH1gD5iGvy5LnADzPI4ma1NMgoYyAvBAtE9dyfBMfJFyz8T5k03QUB7viH
         VLXUDXpApFssCo9swLykw+HiAqPkxQxE3zD8IA/+YzJIaT3C80KOlmMBwLhI5xdr+HsK
         6AXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jVAhNseIKKywpmNw1s+ssEA10Z6ZYktMjUKY0hIg46s=;
        b=MXpGfF7mVqMwQq+HiVrkRhFAN5p0HOwmsmQiVEw+O1Z49dsKwQ1aOqGxY6Lvuoxckq
         V0Pd9NTOemXk1aJnZM2OmMKpIZ6iycgNaj3JrINZExXtcc6M6Z4Mzk6tK78f7emUHRW9
         ojowki8hNO/5fOLystk+51e8gkxaCAToWvGGbuUOK9ykc7bTTJ3tORDxljcbvaUKiMhC
         Prv/FbiGwpxlWyrHfgiqaV0nuiI15wBeu5FzAAzb4KFCNsZO3yskxlJyABoo1aKJ6IGF
         3AxMj5h/Up8xIMOOBOirhZuty6duVzZSUvlK5NEb+ZTmj0/LdGEg7luuKxT6sL/4hB3V
         MLVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2nTUbnis;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y6si1500543ill.1.2021.03.03.15.23.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 15:23:57 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 145A760233;
	Wed,  3 Mar 2021 23:23:56 +0000 (UTC)
Date: Wed, 3 Mar 2021 15:23:55 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Marco
 Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii
 Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig
 <hch@infradead.org>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC
Message-Id: <20210303152355.fa7c3bcb02862ceefea5ca45@linux-foundation.org>
In-Reply-To: <1aa83e48627978de8068d5e3314185f3a0d7a849.1614302398.git.andreyknvl@google.com>
References: <1aa83e48627978de8068d5e3314185f3a0d7a849.1614302398.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=2nTUbnis;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 26 Feb 2021 02:25:37 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
> after debug_pagealloc_unmap_pages(). This causes a crash when
> debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
> unmapped page.
> 
> This patch puts kasan_free_nondeferred_pages() before
> debug_pagealloc_unmap_pages().
> 
> Besides fixing the crash, this also makes the annotation order consistent
> with debug_pagealloc_map_pages() preceding kasan_alloc_pages().
> 

This bug exists in 5.12, does it not?

If so, is cc:stable appropriate and if so, do we have a suitable Fixes:
commit?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210303152355.fa7c3bcb02862ceefea5ca45%40linux-foundation.org.
