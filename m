Return-Path: <kasan-dev+bncBDDL3KWR4EBRB2PE7XCAMGQENZDKBWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BA06DB28557
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 19:46:19 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-88432e1ea71sf509536039f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 10:46:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755279978; cv=pass;
        d=google.com; s=arc-20240605;
        b=CktXcXTbGHpLdMLsG62268ySmcpWyFBeE8OtMEbE4ghSpFKHpr31HfD0SZAR1uaSxe
         YZdQZKZOqy+7QAR6uxUDwSTxD4RuibeaYDVd97So1L+Q3Knmm4DJ2TMooqmGdwba0zpN
         XKOb8h4dVPijlM8hQHzcO240dUuqdNdEZIhXu2ZEDQoYfdb9n7/HiiH/VctaZrTfsLAO
         +oPJkK09PoiJBPkTam3Q7YYQjXmrsneI9Vknh5UiPWhyiz1uD3gWOUP07XtOllfCGfNN
         VE25HaxS14FGslk4/u9jO+ncsk5tYZ4bnBUm//wxfGv/ocDWVjTZtIl+e3Oh3YRSm29C
         sGrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=V5UTWiL2tAsETkXCl6Kxqh/9i0srg5T6z/T1DDEhI4Q=;
        fh=VhmSpVVxpsG5AESNy/SzkTeoj/n7q1hpcMDQfbqatOQ=;
        b=jwVX3e1am/cM/ym1z3wsYJkDHk4yu8zUikR8l3tkPD2JqJ42coRQYGnjf6lKZJRgMG
         FZnAITyylPOwi/sDntAdmoVmKBZKbiYgMLWJGThlfgE+CWOtAVt360f/CZCq56QmmbOk
         SWFw9OsR9J9oQLtbycj5bttYtCsNHi7CObkzsXNWnrKbfd2tPerCtIqXkYFdQGRpCNf2
         OZsbcqAJjv0lIEz3C33jzJAvqaV7/otQgKzLR3++XdwnXnJy1WkwwvZd5i5TOfHo5wh3
         Gqj/rvkuqhXhKkiX8KrDtpzr/oXS8O2aYvdTEP+f1knrWNGf0QZRveMLSHJ7jT3CvnXK
         1QMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755279978; x=1755884778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V5UTWiL2tAsETkXCl6Kxqh/9i0srg5T6z/T1DDEhI4Q=;
        b=U+56dyMEwlSIJg8iLXlpbdMRLjc7rmUZJ8pGS2R8VYtOo9tURPeouliafoQfAd/6PR
         YMcJb+S8sYuKAgr7kgD0GunrujG6lDEdY9vcoyV1msiaVFL97WX1k1u0j5HIVMgE7C8m
         qB7GdWtim722Y2NUAI8NDH+3J5If3/7P6YYS+070UwnY9LyjmIbbzWSyqsRaHDOdeOxw
         uol4apKIJ8QfBOIfeGA4YJmup1X/Icldkfs/YanrjFIA13dx8SxI3V8/Fkx04muoT7qM
         AkjK2CwUrj0bO1yeIyGsiU+QAtaj8poEN8yBCKjhZN2+5UCK12YrQ6AnGbHO4gUT9Ulh
         TfjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755279978; x=1755884778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V5UTWiL2tAsETkXCl6Kxqh/9i0srg5T6z/T1DDEhI4Q=;
        b=Xhvy5RJJOOvBPNGDt4aTagtwR2sqrghEd19KUpqjlNoex/tK2pDNW0BpS7Q9c2xNca
         Rm+8U7H2UIy4jyHgTg3ic9dgp6e+I5Mq5opur6aduZ8jjucRstCrCafgmU5vrLEhgMcb
         ucJSXZpYrR7IKjvo0FVE7x+JcL6MMNdvHqxejjdVrfaYsqJdbiqqvhnNTz18p2NvN1++
         0lnMONiwl09vWvi42RCL0YEPt6nWgLmpc6s6i+zACkERp3gfAj2nF7gG22ppJMa3RXOo
         czVWMX839Q96wAk+dNDHnHilRpRYXr6wJa515ls8TtY4ELSjxVfptFvWQBEnIaz8SxU8
         8Wfw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvpycI6iy6PIf/fs92fFpVa0VR/OCnEKHvulTKoo1AMBJe5sHFX7MGUR6s2kclalWAOfv7Lg==@lfdr.de
X-Gm-Message-State: AOJu0Yz1mse92XuLJP52yGpZ6La4WZmzQ7NuuTpCaQNhBI4Wyi7TEf8k
	VJXtueAVyV6E8dxzNZdRZaYMtf8cLML+FaJj+X3mSq0TfMgpH/xCLgui
X-Google-Smtp-Source: AGHT+IGP7E9uNJ2qSZy0b2SNsY5h4i1ULMZHJYOL8aR1IobCk+1CHBrjtTa+9WwQFhIXdodjlE/O0A==
X-Received: by 2002:a05:6e02:156a:b0:3e3:f9db:c0f2 with SMTP id e9e14a558f8ab-3e57e804585mr48275795ab.10.1755279977660;
        Fri, 15 Aug 2025 10:46:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdzFPAXTpqCPgvcvOhfXQum381rLnfoZYyV4icJqzTMrw==
Received: by 2002:a05:6e02:4601:b0:3dd:b6c9:5f59 with SMTP id
 e9e14a558f8ab-3e56fb9b562ls22222205ab.1.-pod-prod-05-us; Fri, 15 Aug 2025
 10:46:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWasHoHlW2zB+et09qnW+vWpN/9q28FqGfY5N5rhMaUyZSK2a2fbAI8TYVANcia01zTWkKEERABMY=@googlegroups.com
X-Received: by 2002:a05:6e02:1fc9:b0:3e2:c6e1:7713 with SMTP id e9e14a558f8ab-3e57e9aa7d9mr63314155ab.18.1755279976744;
        Fri, 15 Aug 2025 10:46:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755279976; cv=none;
        d=google.com; s=arc-20240605;
        b=bTAXdMC6OZAe0zpFCTZt1hKb+pdULBNlvA4M6vnitcRynjGZNZddtk5/hl6yY32SXH
         UIcfmAoHb+xuszc2YQg/EPtYLJs8zvMXEWErBDQuKJzCmi+t97g+rlLS21eolWmX5TgM
         5Y2Ro7PnSCEDt6HWxAa2m3PT9olbwf0DnOdKvo+klF/mDidVU1liuGMZ3Ngqo2NF34P1
         uWzj05Dja5YO0mJJ9K/of6D9pCN/64m8PbyScoa1+e2dIGZCLvfga/hstfoMqOx1NRS1
         /c7oI0KaKJLKhBTAqE8rulq1FSiNGbAUo31KWwlWxAFhY9qU055JU530JM587c2Seq2m
         NKqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=CJWE0fXapacd+gC8whLCJ/jKuWcD9pMQH4hrEj0P1qc=;
        fh=EzR/B+1KMqNd9XTm1o6Oe7qwChDN7wGXNwHOALRhjRs=;
        b=ZvmgdF1sWhuAew6+tdV8476ItvgY9CuXB89eLPw8/NlUHxKRl3rver6ZWRJFJ4GeGo
         SJwx/FbRXsd4MywTs6v0kVmYbo8Qe7xdw1bofxxFwKOxxSZrs5lMFBqZaOpK6YMPeV5K
         iWHHyc51agS/WpVMHiUODP3qhX97MT+cQ/y5ucrSqXirZuBPNGAs2jXQpAOtMF4qau7r
         kMrKT43UOnYK4RQQ7WmDYM7B67Z6zMRKCmSZpeXO+wUZQ5AYkikGjwE+EAEnwM2rKxK7
         ilkibXI7Y9N2Uqp1V1iRdBFvQR6v0079xbTgJ6zIu/yqrHObAMEtAQvDJVUvazMtJ/g1
         Tcxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50c9454b4d2si59072173.0.2025.08.15.10.46.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 10:46:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E047F613EE;
	Fri, 15 Aug 2025 17:46:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 302C4C4CEEB;
	Fri, 15 Aug 2025 17:46:11 +0000 (UTC)
Date: Fri, 15 Aug 2025 18:46:09 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v2 1/2] kasan/hw-tags: introduce kasan.store_only option
Message-ID: <aJ9yYZyQtMHyS4n1@arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
 <20250813175335.3980268-2-yeoreum.yun@arm.com>
 <aJ8WTyRJVznC9v4K@arm.com>
 <aJ9IdVsSxppYh2QC@e129823.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJ9IdVsSxppYh2QC@e129823.arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Aug 15, 2025 at 03:47:17PM +0100, Yeoreum Yun wrote:
> > If we do something like mte_enable_kernel_asymm(), that one doesn't
> > return any error, just fall back to the default mode.
> 
> But, in case of mte_enable_kernel_asymm() need return to
> change kasan_flag_write_only = false when it doesn't support which
> used in KASAN Kunit test.
> 
> If we don't return anything, when user set the write_only but HW doesn't
> support it, KUNIT test get failure since kasan_write_only_enabled()
> return true thou HW doesn't support it.

Ah, ok, if we need this for the kunit test. I haven't checked the last
patch.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJ9yYZyQtMHyS4n1%40arm.com.
