Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDVJ4P3AKGQEZJFGRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 457ED1EE2E0
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 13:01:36 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id v15sf4397966ply.7
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 04:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591268495; cv=pass;
        d=google.com; s=arc-20160816;
        b=lBTC5wS93bFVfYds5j4t1sUJpYlNV0mtkfLEUf+InAYpI1SfFEqOWDXyXHEfIv4Iz/
         8qbMlPRNxkmI6f0jm7XPpGL25jpvI/fj3bqbMCws3fSHpAGTaORxcygO5nq/45OpQCuE
         ODJLCobgo1iE1hJzI13KJYn6ovjbsLltBlPpnJk8lPi7Hx9fRLoWbUYzMzPVkFQqyAW8
         hQF0rWNstnhzKxVTbwSZ66piYhJoOOECuH+zeIOz0DEMgA/nDtd1N6UPuIcYZD00i9DZ
         VrqnJwLZHSt3GN82Npn6Lv6zPagMuZmidHScgw7QHeyQlMrhciFSA80NMPddYeD1lPBA
         gDqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PtS4UGFpDhhfVEFX6Da1Tv0U8cer7mkgy1TLPYcszDc=;
        b=GtyG/ncnIYRU2hHOGThdfcdIdy9nTC2nV2YTjGfFszt9xFjE3AY+gjRcIjIGUkodtL
         tz6KMEOqdeHtHgk6kSepWzHAQFhfvGLpzeQXCV2BL3EoQnYJ5/WbQ7f3rUHIedx+Muc+
         AhKvYdfE2GEmGJhRwFppvwJRNrTV7185uEzffSAsBmQs9EmRxAR3xQlwtLl/Bbt+L9QT
         E6iDKCQdtnzkHF/PsIkwFM25qzNW1/F9TAmbTv5lB/bL7kOW5+dJiHmxgM7d+CSfG0a0
         vkVObvPm/e7M1GFYpumEA++zCH2P7NGYNLl48Au/kPN3E1uG0O080ITjO+sJe3va2XMw
         0htA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="m8h/Af4r";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PtS4UGFpDhhfVEFX6Da1Tv0U8cer7mkgy1TLPYcszDc=;
        b=TcSRGmnjhmiPg6VywKllaWlTyFSBBmcUAkkB48d13ySsNJL0GvCXlWVVJJtDnzm/Ad
         7n6iRMEr5Kzs+V8OQltWFlf7AWQW7M3gOq7iNP9Spn6ENjXjVFrMdUJ+PurWnWcdmK7y
         IjQcYTTa1R3e2Dfgz+58mdVypLSWq++uZ0ILtpXx/BNwmtNJ55yIw5/UgZgKoKKHqQmi
         QNz+JEy+69vuYaRJAwYCY+HEFKWcoGuImHvjfia/6CDW3p65Z1tnnCdQTKzyqsIynoGc
         Tnl+tYoJpoVbcvGm6fe5jGoCR44Zp5myWhxxbvkm55OlluXlPtb9ZRwNIZ/UeJ9nq3nR
         WMrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PtS4UGFpDhhfVEFX6Da1Tv0U8cer7mkgy1TLPYcszDc=;
        b=b7Xiuf55J9twj+hXfhqkVVm1a+KySPlkBld2rrQfVykbEKtLmCnvDipRpZZfljIi+e
         4TnKQKMF9nARZWXuo59wVu1PROa/Sc/C8ikdiXwEBdsDMElhGUuv5YTE9FWcLxh94Ow+
         ouBhipVChwigNUbYnR6UBKMhkAEJVOpkWb3DPxPnn7eMndr7q0ACdofBlyW+KclfaOH9
         IawNHrGnkfiumBzJ9mVs4mXr7loe3Q1idAVUZboYJ0doO2xyrytny+uahE1KWwzGTcra
         jvrA7VtElEiOydPQU9sj3sOQIf/G8nEtKiVuul5Yk7gFyfHlLI+pHAJOG3AayIdXDSuv
         mYYw==
X-Gm-Message-State: AOAM530ev5iTM66ozEKmrEs8pSdQXNMtwvwkVH0XwvUuPyOVT8e8/9u3
	v/RvowLbm0l0/V7R6aJmPjI=
X-Google-Smtp-Source: ABdhPJyAVPd9lkcbkRWINMuWiNrl0dKfw4st2S/DdKDcSNn3UFoUoXH6RS3CaP3YaB3zJWGDhRgdsQ==
X-Received: by 2002:a63:7d53:: with SMTP id m19mr4113330pgn.168.1591268494861;
        Thu, 04 Jun 2020 04:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:104a:: with SMTP id gq10ls3101595pjb.0.canary-gmail;
 Thu, 04 Jun 2020 04:01:34 -0700 (PDT)
X-Received: by 2002:a17:902:eb14:: with SMTP id l20mr4467455plb.189.1591268494329;
        Thu, 04 Jun 2020 04:01:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591268494; cv=none;
        d=google.com; s=arc-20160816;
        b=mUCAlDqbgbOWv7EGTA+NZNlVucBVr8kwb3sPB9nQiMVzD9GsZ6132r92XmqTqvBMR7
         vm62Ncr6/zo377Nf5uLNj0vQ6vnMQmHk6BzawoDbDbRy3bSzjp6Ow68cT6A4wECowVFd
         enJx0qAz5IJcMoQf0G1Y6Uq0dACrGVQZc1LTyFJGpWD7r8rdvHgHAV4tzd2LzIZDLATZ
         kt6vdEtc577m/bwlhzdiYfZcQMqTUrRN1J0h2ovVo8xaS3apNKBWhwhWlw5vG/bkWHnD
         qoyWUDcd0nmVc6NadQGw9ko28iL54Vxr1GLAh1qa48f/uG+lg/L1hBsEbTXXCq3mrnJh
         qMfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XmhC5ZDmlvSYeMm+z9/lJsXTTmh0XfMq7M7Gwn0dqbo=;
        b=ZKlIjyeMaBWNuFbr6iy8ldfRv/tGR+OTmK7PtN6gyeAKApSLtNKHpFdff0fxfHMvTw
         V0t4BgDoOrhY87jWOj/M2mgbnPwT2Il30qy2vf+ODf103KQ77+NhuUv601sIpfBQsd2p
         KvAWAXlg5tV+7LXG9wTJwQKyqgaebXyj6UaUORe7weNXgyS/1ip1ROzbNR+DEVRhbGyg
         JvO+UD15IyyFQB/joxSKWJ2LqGsXgTdxacC7u4x8bjf6YsEAjs0mBexjgsZrbrQuUbBp
         pZ0xRiNjLvDzspqciYl4yDUG4Lm0Ve9fjE8uRS4wa9OvoNdCTQsKB5weTzJfV471I4jc
         UxDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="m8h/Af4r";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id q19si283545plr.1.2020.06.04.04.01.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 04:01:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id d67so4695297oig.6
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 04:01:34 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr2762211oih.70.1591268493393;
 Thu, 04 Jun 2020 04:01:33 -0700 (PDT)
MIME-Version: 1.0
References: <20200604102241.466509982@infradead.org>
In-Reply-To: <20200604102241.466509982@infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 13:01:21 +0200
Message-ID: <CANpmjNPEXdGV-ZRYrVieJJsA01QATH+1vUixirocwKGDMsuEWQ@mail.gmail.com>
Subject: Re: [PATCH 0/8] x86/entry: KCSAN/KASAN/UBSAN vs noinstr
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="m8h/Af4r";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Thu, 4 Jun 2020 at 12:25, Peter Zijlstra <peterz@infradead.org> wrote:
>
> Hai,
>
> Here's the remaining few patches to make KCSAN/KASAN and UBSAN work with noinstr.

Thanks for assembling the series!

For where it's missing (1,2,3 and last one):

Acked-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPEXdGV-ZRYrVieJJsA01QATH%2B1vUixirocwKGDMsuEWQ%40mail.gmail.com.
