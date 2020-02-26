Return-Path: <kasan-dev+bncBDQ27FVWWUFRBUEH3TZAKGQEXLPWVKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 57892170CC0
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 00:48:34 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id z5sf474448pjq.9
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2020 15:48:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582760912; cv=pass;
        d=google.com; s=arc-20160816;
        b=OjXNABzM8AspsJKVWBq7Mjd6KrQT5Dttcqq1IXJxXBevkrsHv26zpy8yWnE4DldwsH
         AxRWu70/GeKaV11oBWJDBFlcsvWgmlSa9irxT0JXBdA0Hgkov+epbtwZ7gYrDAQd9oA9
         ap+Ny5uxUwZKApccxc7SlIpJgumGLjPdSv6RU/vQCF8EWb4I5MQXCfHKr691KyG1eZAG
         ZOsYxbL76I9MsFls/IDYmqthf9ziyciKXjtvs4t8Gf2wfA4cyAxF2YKF1N76vP5XPVWY
         X4UZy/s2uTqOfLOE+0stCjXDswJy040ZHngL1wmKhV+iMsucLcdJJub6XQh8H2H/w4mG
         AJOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=kkVqtJgCqdNP5gCWPI0Oiy92zmvmalMXy+Pj1mPoAk8=;
        b=txs4HJ6PrSxn8HA5coO51W2lUD12FytI979bzR5NlL4iSn9wBUKvYIWOpw2/7JzI2X
         +UC8wsD8/7mIwGS3CeZJsCCOm1WwwA66gGbHRVMjB+tbXIcaazxq886eXSbjG4+3gOeo
         e4qLC9tTto7rOAMqkFEMexjZKc3Ileitw97CyZJT6qvYeIHhErnhW5yyvr7AwNjs/Aqt
         iK81rkTVRJblODu/ftfEqbPk1XtQo4yCUhYbsr1UDvQnDLf98EMxzd2ZAneww+DZ69F+
         sTDkrBmmA32TXa3u0a6x431ClieJBOFZNCy3xPLUwquD75EsBeah+uugSh/trJro+rH4
         9jJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="p/9RYB8k";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kkVqtJgCqdNP5gCWPI0Oiy92zmvmalMXy+Pj1mPoAk8=;
        b=JV3OZNZM48ul+F8h0s3u+mouvN0TQeBWtOOD2WxiIeygR9LuWpGzN+0X7MsrM8vy0Y
         Asn4o2EqjRO24+oqsyDBd3AmJuT2Sdu8s6jsNbxxOqDKxlxKjJpdmajv7RD67BhAM8ml
         +yap78U7clf95qs6uS1HFOIKHH4V6d4iGW96F2h4+pV/bZEj3QkHR02wzBmKYBBoxaab
         oOde+CBWqrFvbCQ+TUCQOEMVtipcDyj9GWjwc8gB8K3HZ/IOvIFZszsxSmtE4xoY8eVr
         o34HE6GokYcPRB6ziCswtDKMDL2+314YsGdx4OJ+gPHgqGKkK20U+m6PxtHaD7w6dT3q
         WJQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kkVqtJgCqdNP5gCWPI0Oiy92zmvmalMXy+Pj1mPoAk8=;
        b=FAMZZtqOLaF9kFBXCinpSwMIJPj623BdAPWvyIRExGbP5NP2DGnd2KfU5FyCC/kwpU
         XATJRC3ohI10s8+zlBiqjJq+OSKzkZlNie6IgCbYtYgA8s0L4uIVaohLwRqcfm6NgVxT
         qZo6f/S1ceLYcF+3/xVBPBrYJXMNwrdcipTQBcPqSBRs49GEps6qW5OfeugFaWZJQUvX
         FmFui53AT1PzVj5GUnsRvoMFhZ1ahGGmknjn5B2xjImFduuO5/x/UjUX8ze2y2Blbl8K
         GCJnhhYFJUcS77vxU1+4w1Ynfyobng1yFlijHkvlYIfXIC/CkJU1178S4lMweRPfTAOT
         U5dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUU0mgs9v4BTqVVpAMuPui/n3JG6vhGH7jZefdJQzujL8uzrqUO
	p2sLB5RIUOPzDKzWdJOsvD4=
X-Google-Smtp-Source: APXvYqzwJPv0TSZPawpv8W+G7r84Dq5aKiPuZBjFMfdmcwcXfGToKT7dU5twB0fEcI9z/LhB2JtYbw==
X-Received: by 2002:a17:902:b58d:: with SMTP id a13mr1776606pls.155.1582760912672;
        Wed, 26 Feb 2020 15:48:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c583:: with SMTP id l3ls227134pjt.2.canary-gmail;
 Wed, 26 Feb 2020 15:48:32 -0800 (PST)
X-Received: by 2002:a17:90a:cb8c:: with SMTP id a12mr1731850pju.71.1582760912239;
        Wed, 26 Feb 2020 15:48:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582760912; cv=none;
        d=google.com; s=arc-20160816;
        b=ZTEZFlOjFuLd3O/tpFj/oi/0EBcXUi2Q8571RL8T1GWfQ3YcGxC4NZ1DrR6+b1ckid
         IviFkU7AdfQcvY19+s9zW0XqiiIHLN6ZuP2+4/WsfMX32rIAPBQd+96rL5vcuwqOwqQS
         ViDqB/kbX477LfjL+GQXiN6wPFRwLZrw6sfrOhvk2kg6rNFDb5KK7nUYqmQYE6OeHljo
         H1G4h6UNW0uY4NIATa5nmGpZ/GisU51PX0EKkigs43JDm7tJQASQi4nRC2ucRNvUW6ik
         NG3xYdDa8Km3rgJLIOOreqQ+Gn161QY44Kr4zAexAW35r6y9yFPTIJH8ahzqCNe5goyP
         xBSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=UW09MiMy2GaFwFAJ/K3zl0bfOBctGn1N/5oBnyfXBBo=;
        b=beNwY+Z0+ETrCB0kdVtpDFKYAprjQbZoZWZdgFhFLicIrQWN6HW6SYuhFJZfSbWnrQ
         ILJDisQF6gWMn5Mj/JLqYTDsAokXJSZbmxrFNZHbH1l1TnIfQYz3B8FEsQ9UsFH3XahX
         ClR47Y/iHB4xONA2jEYFpuBnabxlTLKZsgRSSDelpXfrMaQ9u8C0DYCbmkdYRuMD177n
         H1kj4mvXLjwcGcy390xxvnAzhLztYHPN9KLH68V2Gm0vnBt/0CsuwhikMuLMtdhikdyI
         iMrjcpyodpKvE6A4AKzTI8CuQpQcJ3YCfcIzSAQJ8u6b66znQ0WtNuZjqDWdo+gKpg5Z
         +I3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="p/9RYB8k";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id r18si64851pfc.2.2020.02.26.15.48.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2020 15:48:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id j17so332634pjz.3
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2020 15:48:32 -0800 (PST)
X-Received: by 2002:a17:902:ba93:: with SMTP id k19mr1782695pls.197.1582760911494;
        Wed, 26 Feb 2020 15:48:31 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-5952-947b-051c-ea5f.static.ipv6.internode.on.net. [2001:44b8:1113:6700:5952:947b:51c:ea5f])
        by smtp.gmail.com with ESMTPSA id f127sm4475804pfa.112.2020.02.26.15.48.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2020 15:48:30 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org, linux-arm-kernel@lists.infradead.org, linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org, x86@kernel.org, dvyukov@google.com, christophe.leroy@c-s.fr
Subject: Re: [PATCH v2 0/3] Fix some incompatibilites between KASAN and FORTIFY_SOURCE
In-Reply-To: <20200116062625.32692-1-dja@axtens.net>
References: <20200116062625.32692-1-dja@axtens.net>
Date: Thu, 27 Feb 2020 10:48:26 +1100
Message-ID: <87o8tkrjud.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="p/9RYB8k";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Daniel Axtens <dja@axtens.net> writes:

> 3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
> memchr, memcmp and strlen. I have observed this on x86 and powerpc.
>
> When FORTIFY_SOURCE is on, a number of functions are replaced with
> fortified versions, which attempt to check the sizes of the
> operands. However, these functions often directly invoke __builtin_foo()
> once they have performed the fortify check.
>
> This breaks things in 2 ways:
>
>  - the three function calls are technically dead code, and can be
>    eliminated. When __builtin_ versions are used, the compiler can detect
>    this.
>
>  - Using __builtins may bypass KASAN checks if the compiler decides to
>    inline it's own implementation as sequence of instructions, rather than
>    emit a function call that goes out to a KASAN-instrumented
>    implementation.
>
> The patches address each reason in turn. Finally, test_memcmp used a
> stack array without explicit initialisation, which can sometimes break
> too, so fix that up.

Hi all,

It doesn't look like this has been picked up yet. Is there anything I
can do to help things along?

Regards,
Daniel

>
> v2: - some cleanups, don't mess with arch code as I missed some wrinkles.
>     - add stack array init (patch 3)
>
> Daniel Axtens (3):
>   kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
>   string.h: fix incompatibility between FORTIFY_SOURCE and KASAN
>   kasan: initialise array in kasan_memcmp test
>
>  include/linux/string.h | 60 +++++++++++++++++++++++++++++++++---------
>  lib/test_kasan.c       | 32 +++++++++++++---------
>  2 files changed, 68 insertions(+), 24 deletions(-)
>
> -- 
> 2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87o8tkrjud.fsf%40dja-thinkpad.axtens.net.
