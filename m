Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHHPTH7AKGQEIUY7R3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 428432CA942
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 18:04:29 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id k128sf1181369wme.7
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 09:04:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606842269; cv=pass;
        d=google.com; s=arc-20160816;
        b=lTgZNNdzY5Mrpa4QHmVmTtTrhv6yXmnGICPOwKE+Pne4rGm+DYBGPNHdCK+y68sO1x
         XIeHURR58radPnX5h8TMw52Q4xkK/gO4T8jhhsa2CzT/WMFHTlyJS8SrAh7hBW0TreBC
         +YWnG9OlqV7umWt/i9WXDMRi/ViLr41TjYEb0MinW3OgAMSRxXKudW5O+rDO3kromz+6
         9dByYKWEZBOrdy8N7q1ATXWltWVOqpZ7tdJYLb0PATCKc3sf3NhgbC2pRNNzdvtmladd
         YIy8cNWtqgh6OuwNliefS2eGwS5zDz7Rk0wB2k32wgrVVIv6/UhUUnO9iFLezrLYVUnd
         MrGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=sZnbKQfC9kJtleIdu1B6+OzfRtFfGSSUy0LJQ53mJPE=;
        b=Nq6RDAEUQLVQ5Aa5AlAcOQAFmAYAa2eUlNuvv18C1a1yBQZFb++CHEfzLIBVM0AhGJ
         rZbvuzQDqOR39d1gCZApoXrxGxQM7nvygZdU4xC7FIiAMYqaQkcqvCnLeXuGYxjPLh3u
         FFl0ufUeD6Mnfx1ETR7KXc+wZIp47QC2HZym9OcT0JfgvhX5sJJMdvd+K5nZl1V1Na6f
         NmgbevsIXQlcHebs9dfxMXhmDmWDqmU3YUGNuLmHtytaeHREVSwpeXFdUCDx9upAJBjj
         GcCeeMqHxcyzuq1iWAgm5HuxerczTOA3zzEetR+aIQH4OmFCSncO6Y+Lr/FlU5QrrChh
         mmMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oK6znZpP;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sZnbKQfC9kJtleIdu1B6+OzfRtFfGSSUy0LJQ53mJPE=;
        b=dwM1XsG8zINO0saxM4zwQBPP+YDZh29ADgQu5DvA7SJLp1biSzEap+VOl2TypjNpoT
         2Y+EWmM8IlgcZHEpe9xgDNXRZ/WFzMA5t9vRhEPykILbOmoYotyT04MdZgP/3zdnveAW
         rD8Y6LL1S5gq/SqjWZecjSGa+L4meEXL1i0U6IZGFsPFzCI/SvAmjn/bFlIdZlXrs0c6
         7PydJ13bb9xdsB5tfADRf55UzHn6N1sTUhIj5sda2LrOyJyvtiRY2aiZQ9M8WXvpiE05
         GzzF7IqNljP7JBisKTCtUm8jHPWpa/fM22uM+GgxYHQ5FxI6KEWwldtyr16iyYPjwSll
         Am8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sZnbKQfC9kJtleIdu1B6+OzfRtFfGSSUy0LJQ53mJPE=;
        b=Q5iW9ONPujSHpmWOIlEbb/sjAXbMBc7ifsM4KSj0k259RCyC595L2bbCL7L2PVR+pc
         0e90lfcT9eDpTKwjxHUgvBtr4g/tI4SYP2Oo5CQvz7gC1IC0ngTyypIIzfI/mA3ctZjL
         CheAEGghcFjIYY0rAITpds3ClROL9bHNvL/ogif5QOj+69mX0MnjpVC/IKkBd+6YuALZ
         Nc1u7Kp8PHYf68/rxP9SUFE5I1Hw57CH0p7n7HasPIx4wB/ZH/qmBK6PVfPeqkvDJr1S
         ap/d7ghce1a/X50ZQAlzcZa54D3ueS48q2/J+ghJSqWPHo/zw68vzI1NpOTSAI4rVZzc
         0n1Q==
X-Gm-Message-State: AOAM533z6BgiueMBYIxK6Zdfc87MNc059Y+sBQZSSZLJZoB/s8NInS3o
	GUxaeEjgvSxTjHcK0agLCb4=
X-Google-Smtp-Source: ABdhPJzyPhC47LOP7WnHPi1wPXRpu/WcxEb9WMgNA9xcYVbF07oHfpEGMn6aejCiYiISAT95PwuGxQ==
X-Received: by 2002:adf:dc83:: with SMTP id r3mr4920112wrj.223.1606842269023;
        Tue, 01 Dec 2020 09:04:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1fc7:: with SMTP id f190ls1248789wmf.1.gmail; Tue, 01
 Dec 2020 09:04:28 -0800 (PST)
X-Received: by 2002:a1c:f619:: with SMTP id w25mr3684445wmc.55.1606842267998;
        Tue, 01 Dec 2020 09:04:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606842267; cv=none;
        d=google.com; s=arc-20160816;
        b=Pvp/QCMRucD0QrB6/Nu+2JoGax+B5Pkgs99Izt/kcCPmk90KK2fSX2vxHfISnEoO7b
         izVQdEGhqqIlw5rTdy9fXgTJAQEItsxHigbYkLMvtknNAmKcGdxSLRxshS23iMVePX6z
         yL46pv1fCck/xZIu4OEyB/EatWRlYQPPQ9QVaCZprLp10lA8FevhYayA38NQF/U4Dh0x
         AnX/Y78OZ7ieyQcdCfclIS5grJLSU/HAwO3xv2mspPykJWR4x3anOqSa4V9YFQF8JGIX
         EGo+IYsl5YppF9A5e6tjOoPEBhFKm5IcCMdtH1BL0EnESWcxoIPoZ9KXo/JuCNRsWf9A
         UsTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cfFW7KVHwuHqdHc+004sCc3ASvBne4aoSX6rv8lR7RE=;
        b=zw6PIpTurykjf6ZuSANk1paEE25iq8OIfjOSE/GTHNUcwlafwGpIJU8syZEuEcWTZI
         eJH++0zADIqyrgChEpNLBXmB1J4h/kEegUMdDKkLhso6fsExy+p5DTXnxKsULBFkipWn
         dBO9Z466sBLsh0PW5w/GLWLBNJvlYPiHrxYEFYr8uPOK7exyC1+IVoey0eNs5PHLVtO/
         nP7GogizCT33/AqCrhH7/aSqWizomwJcmWF2DnOw3WSI9tOAYWJNmXyWH3EIrgHDVvHr
         Ie9jXkJwPmL830h6DRo1WW+inkUn3UIl+h6F96L7HL2BrZKUu21mwkLI+Q9fEBXizAoS
         5jxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oK6znZpP;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id z7si18829wmk.2.2020.12.01.09.04.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 09:04:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id h21so7019714wmb.2
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 09:04:27 -0800 (PST)
X-Received: by 2002:a7b:cc94:: with SMTP id p20mr1352007wma.22.1606842267471;
        Tue, 01 Dec 2020 09:04:27 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id e14sm222016wrm.84.2020.12.01.09.04.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 09:04:26 -0800 (PST)
Date: Tue, 1 Dec 2020 18:04:21 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@infradead.org>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	masahiroy@kernel.org, ndesaulniers@google.com, joe@perches.com
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
Message-ID: <20201201170421.GA3609680@elver.google.com>
References: <20201201152017.3576951-1-elver@google.com>
 <20201201161414.GA10881@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201201161414.GA10881@infradead.org>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oK6znZpP;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Dec 01, 2020 at 04:14PM +0000, Christoph Hellwig wrote:
> Why not use the kernels own BUILD_BUG_ON instead of this idiom?

BUILD_BUG_ON() was conceived before there was builtin compiler-support
in the form of _Static_assert() (static_assert()), which has several
advantages (compile-time performance, optional message) but most
importantly, that it can be used at module/global scope (which
BUILD_BUG_ON() cannot).

From include/linux/build_bug:

	/**
	 * static_assert - check integer constant expression at build time
	 *
	 [...]
	 *
	 * Contrary to BUILD_BUG_ON(), static_assert() can be used at global
	 * scope, but requires the expression to be an integer constant
	 * expression (i.e., it is not enough that __builtin_constant_p() is
	 * true for expr).
	 [...]

.. and there are plenty of global/module scoped users of it already.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201170421.GA3609680%40elver.google.com.
