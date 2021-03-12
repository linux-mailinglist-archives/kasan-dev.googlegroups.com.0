Return-Path: <kasan-dev+bncBDDL3KWR4EBRBRUKV2BAMGQELSXCXOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id B93043390EE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:14:15 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id md1sf3733141pjb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:14:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615562054; cv=pass;
        d=google.com; s=arc-20160816;
        b=vu85ijtqKxtzzs0ORbw2gt7bKY1awhC60uz071z+Lyx1lh/FdQKSKS77t8gHAefp7P
         fGlh6s++a++9oFNBGsk9xrX6env0ba7K/CWET13AKBhApIsMUSE039MFPOE74hYp13i5
         ylcSLuVm5gW3K3RCgWgBwYVVpzWv3RsrglADpV0oKYNEq8GnfcM64k7cXPIEi7Rr1wVa
         p5SVG8BCMtLxt7hgJHTuqCiUywbWSR+RykgwTm6bgR2X3gXfrQ+8W2tR1sCt5skRIvCQ
         wy883cmP0Er5zuVv0UM0K+ksnj4vI7HR4x+8V1QHXAu1EQAvIzEQknELt3hrFKKFwBNn
         cXuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=87LtEBUi6YeLf4lFnQ/wctnLgAxVgOGqXrQkFkrXtIQ=;
        b=oYG7DTTKDFEGGPcxSqM2KFb3dL957N9q9do+Q+GQWxKSK5JHKqPPAfLDHD7Y8RWNjB
         l+EVPbaV+Ox8bdNxKylAMqZNRGgqQWCDb1iFUjUFzEi0U5rAoq0nKgi8pkvjRBbc0bCk
         b63l8tWYlVfP75XfZqb+WOw5K+fcwskt5s5w2hykURxGOcqV0dxdD3zFFaSbtVO+5x47
         320JBUo8DU8VYpNrApHI46l7YhgHZx5WDJTxzo2yy1Lv0LaUVI00sL5UgVAUD+Lq0ZaR
         S27iEQmsx+TKMxKgl/YGjkEgrC+Ep3hgG5MdzQzctyYzvn392KIT0l0IgaPGlemD6cG+
         svNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=87LtEBUi6YeLf4lFnQ/wctnLgAxVgOGqXrQkFkrXtIQ=;
        b=q0lTU86caZv3SsTt2kVcL7J9bfgqy3+Fn5hFVt+58jdmNJv2E9IuiJZLsh8Lmg8OeS
         YV/5N9T9hJN/L2VH7VSjRwnEqU7Cq8gXdm5QDzJW1SDagGCl9jNkfiOAOQ0AYOuDJxZd
         pxr3VRH+UsaDprYme2JDPtpcT4gQL0k1b4fj0lFYOOf5e0Di26bdJeGJEU/mi5ArDaTm
         q33i3jdSEzGO4ekQTQadCpmbHaVW0c1pie1UjvffLPZ06ws5Tle7AJpuP4GxU2yYJOvp
         Vw6Zi/u0C4pki+KodnGlH3CNjacPujbKIuI8QqvMIUFGwpbgjER+1X5eXTZc5KQyvzRA
         04aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=87LtEBUi6YeLf4lFnQ/wctnLgAxVgOGqXrQkFkrXtIQ=;
        b=nJcNnVd2LUE8kD1hl5mX7k2WSbJyqYQVWyo8qLtLDhOyBZJSfiNX9N7Xl6vpZDDkk0
         C6aFDE8xWGetSN6EVXD7Rmk3OZlrdX/fPpBPz2zhmeaP8ErRpI6SiRRmUGMjUEn545ye
         pyAM/ISNflszRb0hni9d4lYbQGZp9dkBw9MNhc66GlUqonsNPRzYXOVqC78b0FNlWLDO
         /Y1SgodIiUBwzUqClosTrFCVdLdFTagylnRRiSV1RD3bR6TMyj5FqSbUEDyWSzrXJpwF
         6tMFAN2QsSHjVanD4vKNHHf7w9NCof9ogASaOjk8ZVnc4JzGztLlg9DlqQdvvxhB0Q0e
         /Y7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532G2X+qDYXA3lR5QfzCjABSmivUR9biJfVZKcC8Ths5gg8R2yi6
	OpX7H1MyL6y1QEOIvcQD7DM=
X-Google-Smtp-Source: ABdhPJxgteB1Eeiddxg04rOFF02OEsydNPDJzh1pVZWoEXJ192YCu7vYS4jG9ye+jKb8NbvObN/lTg==
X-Received: by 2002:a65:4141:: with SMTP id x1mr12018582pgp.421.1615562054406;
        Fri, 12 Mar 2021 07:14:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1693:: with SMTP id k19ls3862903pfc.0.gmail; Fri,
 12 Mar 2021 07:14:13 -0800 (PST)
X-Received: by 2002:a63:e858:: with SMTP id a24mr12104605pgk.56.1615562053809;
        Fri, 12 Mar 2021 07:14:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615562053; cv=none;
        d=google.com; s=arc-20160816;
        b=Kn/4bJsu72FYINql7R3cA3Y4IvzdOWHEEjlrGCdHNBjbkELFmF0gbg7GTp/CqcJ0Fx
         Fai3QQGD9xrEkANLbfmUprygamtrvu3ZdWJsCMpPlADtC+KA/5NB7cz7tN0IcwcZJEQP
         LkqA+XFxVqD176i9glbmDFNIdmqyMf7+LRSi5ecHPISlh9wiMKzMMtfIvDju5ctt3+Z6
         pL8MUiOsE1QI8cKB+ioGfQz15BiyzWuROa2u40sUt4V+E1OQNg/yjw2J+l+oGM7L18po
         tUGUtYhY+BYqtU6ZBlUd4b0wnNt/AvHHr4NY0ktNJScLUmPLW0bEm1dMBLy2X2Hh13lk
         KyXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=mKDjkPOhI5YuP69o6WW7slv25MRC5T9jTU1CwgZemDQ=;
        b=gDj9eAEuD+jHu2FweHMsvn5wfJQ8DuuhDkPAIPzV4Qix5tHKr7OZrmqwFROBfofNEy
         RXlf/G2VAMlVJJTc413S8x9A8cXzAhPPcFEkF+bTMfl0zGftgZwBxEZ37kS9OnOaUmpy
         O+wx7K/gq7Y/DiNg+Ok34wWO+ePWcIxpN1n+BP8o2kt7wtiTBxqUWBiO6Tf9Vi9V6aJ+
         RKShcLGV3fBIiVmqoB9ebv2zw1E5tHYCyC9tESsLt9KwsGreWs69XZ4pKwAkYtKEcJXP
         pmqsDuKq0To5EItxApCHNYe5D+Sqdd8Ihv06aBpRvy6SWypD6H3EN6oV9pebPlZ0Hz+n
         u+bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h7si430610plr.3.2021.03.12.07.14.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:14:12 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 65B3964DCC;
	Fri, 12 Mar 2021 15:14:09 +0000 (UTC)
Date: Fri, 12 Mar 2021 15:14:06 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v15 0/8] arm64: ARMv8.5-A: MTE: Add async mode support
Message-ID: <20210312151406.GC24210@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210312142210.21326-1-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
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

On Fri, Mar 12, 2021 at 02:22:02PM +0000, Vincenzo Frascino wrote:
> Andrey Konovalov (1):
>   kasan, arm64: tests supports for HW_TAGS async mode
> 
> Vincenzo Frascino (7):
>   arm64: mte: Add asynchronous mode support
>   kasan: Add KASAN mode kernel parameter
>   arm64: mte: Drop arch_enable_tagging()
>   kasan: Add report for async mode
>   arm64: mte: Enable TCO in functions that can read beyond buffer limits
>   arm64: mte: Enable async tag check fault
>   arm64: mte: Report async tag faults before suspend

Other than the comments I gave already, feel free to add my ack on the
rest of the patches:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312151406.GC24210%40arm.com.
