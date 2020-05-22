Return-Path: <kasan-dev+bncBCT4XGV33UIBB6OGUH3AKGQE772ZWYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D5DF51DF319
	for <lists+kasan-dev@lfdr.de>; Sat, 23 May 2020 01:42:50 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id m13sf6047472oic.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 16:42:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590190969; cv=pass;
        d=google.com; s=arc-20160816;
        b=T+JE5VbJcz3FQYuD8zG2sSz7Hzhl2IG8TEB/CUzt0T56UHSwIi+x3qtE9ar43/PwcB
         d6mzt3IqjLEzr1X1X7Fdd9Dj60z13Og3EqMU5h7A9bvfstyZPsEQhtDMiXNIlQl5f0zx
         x/0GEVIiOybpo93pY7YK0040wryAGkTTySqB0ZdYvvXLhCz84fvPklZTx+nb5tNJqBWj
         FFfM3W3ADKHXEZQ94tLEamAYSYnOyzJ6NO5YzUtP0XAR3DjSaE1E+Ap6pQ/WeNxKgKTm
         cLSyBvyGLSNYdCI4+/A6tsxQy+s6cGAr2J5qEDUWRSBENOIIa23WQE/8c9zSnonOOJHO
         REPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=UYiHfxCozP8GAMutnF0UQmemmsuooJ1US3jV1rdX48Y=;
        b=T4s0aMbHxR0DbAWz/kh8WMNHoWjbKFmuUOA/6wKG+014Fp9wXwLifF1ibWDuX/Ht44
         Xh6jJqZbkV67kx/uLVMyodOzYIH9iTzpkXS566Q8+FbPqacV6+fqas9/oiuqV2d66SsN
         9pbISP72s5Wx3papPJkBgnwmWZr9bPlSEtcpv9RQf57L/hMRnQLkPUVqLDwSx07uvC7c
         y7otfHu3ddwkzKpJ5X9bJeHmMgpjRGGaaABCMBKxLmFSfVHEbWWfi5cN3Nd/KCQpqswy
         nmGXQr7LOa3Tow6S24a6sZnFykYGZLd0URMiUbQKrfu5IiIG9KYRDmAEkVXpArBr/K1O
         o/ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mwbCPnxS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UYiHfxCozP8GAMutnF0UQmemmsuooJ1US3jV1rdX48Y=;
        b=DsZPXncSsdRf3Ggm/t7rIGmI2RN1KgSVOtGB9dzZNGB7+b5T+B+qfkdWP+2+8vvh4w
         +b1WIbzzvG9advgZ7qsrnvCLwsZkdDTxrPgwSFP01Ei/7zp00d/bWYnrY005KG5Aml0d
         f0fu33udEc2UAgKnj9OcFJ8TJRkMGSvZ2SbN57gg9VKGIplJIaeql18i+IOx12ipO2eU
         twKylIqPhopdcb/GGkS5sU49Cile+z96fF2/AoGkVBlNGIvYH6iq4kEu6+5ZB8YS+G3p
         FuodBNzCXsleLR6vZc+N64ejxnOULHWFs+cTSBzNAWDvoxMpN26CRfE+bh3ZF/De2v3K
         nZHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UYiHfxCozP8GAMutnF0UQmemmsuooJ1US3jV1rdX48Y=;
        b=DhkEcoDVeUMiWQd2BADQbIyHAXJTlnxoiNEuDS50IGy7tDJ94/wzWlhcmRaTivQivx
         6NZomH+ucftvR8Qr3Qb+d942dmYyj/VIvZtejKcppZRn7DoHZ/AaTpMzUT8Nb2P4MtBr
         HzRlaPsCo42gj9EpKQJNsRrRUFh58Qe10h7BpJDty4othzSFzLxBFlSb81K3BwkkMJOn
         DWymq0mpiETdyXea7vksZudhlgnct1Gz0E7bnPWSugFugqOMOq7hhUhK3SOKei9dEPqx
         CnO5uqB+JPH5BjkpJSWxA3+FMAOSIJKJ0BwpD6oHkhEoDRJBUH4IzNgXxasRVss6R7M5
         Ecjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zXo+R45EIl9zsmz/n1oE3gEBKFiybA7ak9jCYJgZynQRk7BnC
	yxLWmNwU+9ZG/rlKHDqnKos=
X-Google-Smtp-Source: ABdhPJzQvbZO35KJo0CV+oaM/7/fz5xy0w56cder/dVWuPL7SZwXn4X83RsvpybdKFPSDHaEkJsIiw==
X-Received: by 2002:a9d:70ca:: with SMTP id w10mr12903924otj.216.1590190969824;
        Fri, 22 May 2020 16:42:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e1a8:: with SMTP id 8ls163579ooy.4.gmail; Fri, 22 May
 2020 16:42:49 -0700 (PDT)
X-Received: by 2002:a4a:b346:: with SMTP id n6mr4941811ooo.18.1590190969432;
        Fri, 22 May 2020 16:42:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590190969; cv=none;
        d=google.com; s=arc-20160816;
        b=VCman5wro3STvKxEcNSlMHGolkzIBPc6Pce6IUMqlN8l7RRTTPb4RgQGQsnIKmqCAm
         wYxQOzPJ+hMxF2lMhw5F3G2hmpXsYU+E+94r8PmyWFd96Z9mnJyF4F45uAou5uEPxWkI
         1pHRKdQak90KM4nokTG42CAGvzitRP4KV4KL+PfblaO73WZT6hQbFAgrxbpurBHYa9Jv
         AYkbShNpjyTF0Cc/CbvsfIHRebFSBstuZ8+Ce3JTdxiOZAqS2i5eSKZlCSsKhCrIhBwh
         y2KAoJJ5jy4MJ/8CurHYM/SqbmhFgY8U8QgKosdC9o+vmkz4IifGXdrGGf+l1zPn9Wi9
         71EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pG2Rvu1hqf0wBe0whshoHy7zhZRMqOLGFffbMky0MSE=;
        b=yfh9LefOr6S8SfZGBSzg/ZwxC9mCglkq8fs5ILcy8bQIVhDh3BGq52HH8YxUYwAHkr
         aAvPNZNrN8AXJAvWIHx/8BQqGozegqeIqwFYNWgm6fI9Lz6zMWW1rEmczqESF8/Ztyup
         XVq+q146rwhO4VDrpmewoxYEkenpk9MdA/N7d3xc1lN4BUUmhzZ5bhemeNpnLJSVps6M
         9+IXEZhaJg2iYpiM4g4sMldyu+arreZNamormrj2SGECrKAXa0oIP7sGhqDa7AD5xxAV
         PcISlk6kUEmPhuWy3Z6HwcKIBhb3MJpohQ0jLYp/AOSvYLnJAmYJT8OQnxpHIpypfzg6
         HaMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mwbCPnxS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f197si753834oob.1.2020.05.22.16.42.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 May 2020 16:42:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2AF7920723;
	Fri, 22 May 2020 23:42:48 +0000 (UTC)
Date: Fri, 22 May 2020 16:42:47 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 aryabinin@virtuozzo.com, linux-mm@kvack.org, cai@lca.pw, kernel test robot
 <rong.a.chen@intel.com>
Subject: Re: [PATCH v2] kasan: Disable branch tracing for core runtime
Message-Id: <20200522164247.4a88aed496f0feb458d8bca0@linux-foundation.org>
In-Reply-To: <20200522075207.157349-1-elver@google.com>
References: <20200522075207.157349-1-elver@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=mwbCPnxS;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 22 May 2020 09:52:07 +0200 Marco Elver <elver@google.com> wrote:

> During early boot, while KASAN is not yet initialized, it is possible to
> enter reporting code-path and end up in kasan_report(). While
> uninitialized, the branch there prevents generating any reports,
> however, under certain circumstances when branches are being traced
> (TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
> reboots without warning.
> 
> To prevent similar issues in future, we should disable branch tracing
> for the core runtime.
> 
> Link: https://lore.kernel.org/lkml/20200517011732.GE24705@shao2-debian/
> Reported-by: kernel test robot <rong.a.chen@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>

I assume this affects 5.6 and perhaps earlier kernels?

I also assume that a cc:stable is appropriate for this fix?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522164247.4a88aed496f0feb458d8bca0%40linux-foundation.org.
