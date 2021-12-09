Return-Path: <kasan-dev+bncBD4LX4523YGBBCWKZGGQMGQEOJAWI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 68AF846F4CC
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 21:20:29 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id w1-20020a056e021a6100b0029f42663adcsf8511182ilv.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 12:20:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639081228; cv=pass;
        d=google.com; s=arc-20160816;
        b=w3VzpZu2XQ5quGBjMNmcuyAP11mKZ/NFOXec53zDX2M/F1aK5SOUq8z8QZ53lVpbcx
         hcnHJnps0AdzezkN5jVhWZMBsIvfeV7ireyd+riVSJSlyI1k/upIMqgqzYrnfqCg/sZ8
         DyqfaKCPQ6nN84mTk/Mnd3MHoZHglakm2QuXX+KRzF44r2NbwZQ2O84V1tG0Tl+erdzk
         RLCqVwV+9ENOOQ10Bc2TBObYkDpI01A9N4tlxsuQLOuLV2tIWfZ8axtrqmoJk0m8i/Ev
         bp17x9gujAb36FCAQUUzD0OaWjy1bROb61LtgRpNCUcv49BWI5vf1qbgYOCd/+0prd9v
         jbSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=q/ON3YJTLQQrCVEFEihoFx53PQhUnbG/qC6RSbzqcdI=;
        b=JTXcOfIM/AddNztnoI0k6L4KN6CsyYWjpEmvvaCi+7aeLyEmaeKsddP++i6d/ngzIb
         64gmuQqfcAKKO4zqNC78WgS0tPSc7FGNNqFRdwva5H4TiixOiOmA3NMQzfUiTDFepq+K
         o1QIuxb/3IPJtSuba907T44+UwPeLXqP5emhqUMq3NZwucsbhkPTHouA9Whzovm7BAo9
         EkGTV1SBtQFtNegQkw655ZnnUka5IYfiwpAPMWkFc852RsJyWwf21PUADpHgqWSrx++A
         6nx9CZzij6LYxgyUSvdW0h2FcZbCypdBP/dwbwTGLJx5TBc3IM3rQmbH9UeebTfXM1Us
         dmKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q/ON3YJTLQQrCVEFEihoFx53PQhUnbG/qC6RSbzqcdI=;
        b=U811rhjV580/SAt8eQcvC9xWahRQm300bMIUAx7S8FTAnTQsjovB+PpjGvwHqtLdUo
         n/uD8Dg8ohCzsq4R3dooPKVgQg7PpBpQeRGSqIxbyUQUmHZNrDRpdQhTLKISpwEQoYzf
         B7D7AuV2ZVClALtpeDoSVMOixLkuHK0QQDiPuPkjs7kzH2toX5kxMTQWMyJ7A+8I8IBL
         aoQMQ4wO8O7uV2ZRC8xnk6Bi8W5FXW2l2vt+FO7enhceWiCKM+hIj4uLFltm5GkaUeLu
         nXwW1WR8eHYaZ10bb2GYMC5xBTf3DVspEoi/ie3RNj7SgAoAaymfLxF1qyj4eXuHTyES
         PNnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q/ON3YJTLQQrCVEFEihoFx53PQhUnbG/qC6RSbzqcdI=;
        b=jWf1btnpc7267lrgQIlsoJswuONvqS0NPuWJhWK9wPBM8PgMXtDNvYYsDINJokKnC0
         T3KPgjZRzzBp0+pT8sKHAhKeb15RrNcUOYTPJjWIPmbIxzAPS2F3J2jKmcBoCFvXXCWt
         dYsSOPTP0XDF0cEsUfUPZVcJuj1BzQXFJVQ1JquWTJfAw4kH5FbKkJEbx+87E6qSAuHy
         HFXKNok4sWWacRt3tltJCOP+yu2WYN1FDtg6MDiaILeonkmNJrDBheweBmjAo28f5f0I
         TS4Ex3/+DALm0cOnHOThAqTuacUCgMnncgkzjfD3QBbnB1glwCqNT/FQHTSI6Si0fSYD
         MC5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ejVau63LUcoPnabPoKZF90rYSBF/njHBC6+bTVlOL0Vs8VDDi
	xCbyjx0kRqQgJm7VGbnqQWg=
X-Google-Smtp-Source: ABdhPJxIYaA/CnHopDI+ePIlHkEVk2wqRpmEFh6LDdnq9edebLJjBYvxnBYGeqhgYIKsKNM8pAVSYg==
X-Received: by 2002:a05:6e02:156e:: with SMTP id k14mr15435465ilu.41.1639081228102;
        Thu, 09 Dec 2021 12:20:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d0a:: with SMTP id i10ls1020858ila.9.gmail; Thu,
 09 Dec 2021 12:20:26 -0800 (PST)
X-Received: by 2002:a05:6e02:1bec:: with SMTP id y12mr16947695ilv.40.1639081226610;
        Thu, 09 Dec 2021 12:20:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639081226; cv=none;
        d=google.com; s=arc-20160816;
        b=MG0OG9mU5w6IX1ypoMM92lq4HR2/nu93wAfcpv+w+sHdSLQcLHYDPt08ggxxQwoK8i
         qfdtb6Rr/sxoyCS14GJPK2rNRCUaEmOgpuw9CkQU6VhhRpNQFQGRvqPPVMculEDbKDEN
         PwwgjIXUAlJeJmg+j/J5l7uCS0sCEcKIknkHJ1kTj6SrEY1GxFokeolYNSWS/38aEOUd
         B2sbFHzJ8hKd5stNSawEOHdKoGLoQOv3bCXL1oo1kylG73ZUOn1MtpFj7lSOat/hTTD2
         vdNX7Rk2BIyk8XDsrejUycGy9/AtbhPtuDbf7YI+9i4e7aqq7DxRUZkgxr4lKKEziVVt
         fzBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=C6nG+gA59jnAyRs6tZ3bX5jIOHPVAp/2IGfa7zpdSmw=;
        b=WnR1ltlzpNLNeTyJaQOovs3h5hnDvuDR867XIDDTMZlFBhKrPmqVMS8x6lcK2A16oX
         TAftxKJ9Py6iB3gTspxRWsuFGcOLsI/zK5rYSUdBr+sWY5l1ivnoFdirdMU5dpyOw2tn
         scB0XZURcDUcQOZudQ0HQjCezAaE7hQhxPxtlDwJvLLHB88+Qe7BuYyQRUyPu8Gnptcc
         Yn6+3/Xgqu5/+gvCv+s96IOvbVn2lUYVZO8/ERF6eDYj5eAzaWQW8D3ohVayKwZycVVj
         KWR8Ti1RdCrVmbzd2b5SkZ4LAIQMCCtne6NoWKp2Id+M7E+jG4IhRSldozbidqiUGlCy
         LavA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id a15si200687ilv.2.2021.12.09.12.20.25
        for <kasan-dev@googlegroups.com>;
        Thu, 09 Dec 2021 12:20:25 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 1B9KGHTw015333;
	Thu, 9 Dec 2021 14:16:17 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 1B9KGGkw015329;
	Thu, 9 Dec 2021 14:16:16 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Thu, 9 Dec 2021 14:16:16 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>,
        Nathan Chancellor <nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>,
        Elena Reshetova <elena.reshetova@intel.com>,
        Mark Rutland <mark.rutland@arm.com>,
        Peter Zijlstra <peterz@infradead.org>,
        Alexander Potapenko <glider@google.com>, Jann Horn <jannh@google.com>,
        Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
        linux-toolchains@vger.kernel.org
Subject: Re: randomize_kstack: To init or not to init?
Message-ID: <20211209201616.GU614@gate.crashing.org>
References: <YbHTKUjEejZCLyhX@elver.google.com>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YbHTKUjEejZCLyhX@elver.google.com>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
> Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> default since dcb7c0b9461c2, which is why this came on my radar. And
> Clang also performs auto-init of allocas when auto-init is on
> (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
> allocas.

The space allocated by alloca is not an automatic variable, so of course
it is not affected by this compiler flag.  And it should not, this flag
is explicitly for *small fixed-size* stack variables (initialising
others can be much too expensive).

> 	C. Introduce a new __builtin_alloca_uninitialized().

That is completely backwards.  That is the normal behaviour of alloca
already.  Also you can get __builtin_alloca inserted by the compiler
(for a variable length array for example), and you typically do not want
those initialised either, for the same reasons.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211209201616.GU614%40gate.crashing.org.
