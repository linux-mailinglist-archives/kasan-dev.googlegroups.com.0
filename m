Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPVUVCBAMGQECBO6CAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5253D3373C9
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 14:25:19 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id k7sf6126714vka.7
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 05:25:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615469118; cv=pass;
        d=google.com; s=arc-20160816;
        b=rz4G+aOuelhbJTX2ljXDeQTFe/fJwPOlHpCft9ljF/RnkVAmAUta+dsVZNfS7wfVTk
         IZ6S3JFUdprwPMMc1mmLeqVPJH7iHZ0Bjwxq12HE2aG7WMSasPLmheo5diBlzsGrujqG
         ExW0UPTSoUZJq5ktDOzGHEIEZjY4CXo73T/4fjJBcoK4kmkuV0y8N3iLB2cKslauIyK0
         G+xdti4QJEDpZqCc5J7OYnIkPuImObN13ecK+bJUwUwK7ONPRBM2Ql8LwLgsGd2485K+
         4i0BUkt+MasmpYgrjMUQ7hpEdRXVKOSbfhWQUd3SAUac6ItI4hs1jya/+SAM5/+dhGwW
         IwUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Dma/wttNTToBzlV/noekgfE2Wzi5hKNrSIDWMBk1Ij4=;
        b=uyN9bWKYNvnTqzlllTurUikDb7cpv8NF2OZE1KMQHHhtvU/HzBhWOKjuWOyn4fyIiM
         lwUZwjwzbwmCGIXIrZ6leZtO/y4tMRn92uEQRlAPOxoYVOtbakOxL62N17QQuBOPCDEf
         lGUkELgC6rRm4PnugeS9budrfqdtVVXxVVSDv7u/STlbs/LGUyWlda7gXS3AW+PT5u18
         KcOl0Pb2eppGFvRsJ5xccF0G8YoB4hUFNkPcc+dlsPGdNls/xKAwD9lOD6Vb2EuEMvmF
         nzItjnSPLSEX3ENurAMcFr5iHOQOdGwm81SJSFcjd0XTEtuibV2E+5DJ0RD8UnRQUM9J
         v5xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Dma/wttNTToBzlV/noekgfE2Wzi5hKNrSIDWMBk1Ij4=;
        b=G55/xptK6sxeYYxW0kT70ch1XRLFD1mvPEt1L5Eeg2yFuxKSf1Vuoo3hLTTqYbLb/D
         +On56qxPKPpT7j6YCwd4hgKUdwQ4hURPbwa/+7frsACqSjF3vXmR7Xowod3lnFju2hB2
         1iXzN/HXaWSyJD7DBep9RuUk00uPhZejCk8yrB+F3spIikPqgfYgHy1UWIXGit772ZTP
         l55sKvumtoMvt+q+p9yGjSvpRobyY3gfLY5nP9NrmZet1NzJKLBeugxop01SD0YIaXp8
         IBsfwESwmZ/i9U4MpQJLeF87TCfOuFR3fpGqHLQuN1tOPeR9uGbgDaOEBh9nKdIw2lxg
         RqRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Dma/wttNTToBzlV/noekgfE2Wzi5hKNrSIDWMBk1Ij4=;
        b=emrrf3JcOwiIN2oCQ6IreBRRPzSiU7Y/hTcmW2TF6sssW+gdE1H1ibq3odpX7Wk4tn
         9K92daa5N7HTjc4C5R/RhSqFnULxUtB8lp3cv3s+sPleY5Ikv7NB5ScpUt8yR8od7fdQ
         e9g3aAtYKSBsLJrWhq1px1sFX+kXmkv/i+FmzeAdWa2r6ZHabLvrm6YdcXn6fjH/Q2RO
         XVuIhI8F/GjGNT+X5grum0IhIvTQaJvMrLLq2BevSDkxTrKupGSVbuIpUWspYoJsI7vB
         NWS5XDo7wfhal0LA5z0+1kFMVkSZt3SqeLo8pbe02ERCx4/krIHAuy/EWv6c2fUb/uy1
         s0UA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bvayIWJauPwNugIokT80Qj/ulYniZWLw0Pa7YVRJ+I+hrPPph
	lCD+8jyao/ogjbNPxuOks1s=
X-Google-Smtp-Source: ABdhPJz/yXvxSXhnZxgtJQQ8BreaitJe+DlD3cwokSNAo2x9IFVZuD3NoXtmByIuQo1djXdjcuxapQ==
X-Received: by 2002:ab0:7e89:: with SMTP id j9mr4838569uax.36.1615469118133;
        Thu, 11 Mar 2021 05:25:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:94c6:: with SMTP id w189ls299142vkd.0.gmail; Thu, 11 Mar
 2021 05:25:17 -0800 (PST)
X-Received: by 2002:a1f:abcf:: with SMTP id u198mr4764433vke.19.1615469117605;
        Thu, 11 Mar 2021 05:25:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615469117; cv=none;
        d=google.com; s=arc-20160816;
        b=KOyhcLE4YbtF4AWyMjYYwKOfFgFYikjXwx9Eu/GybXKiBj4bedg3gDGKBQT/9r245W
         Xl23NnRZAG4KveGTzXoM9KAGHY9/ggmIALJ27LIIx4i9i+IUs3R5OqH0SeLbWh3zS7EK
         Wx7YlM+nENAjozvVhSraKeVl5nKxv49EGjmfyC+Qmn60Xl5znqhlOJx2WRqNIfquII7l
         jvYcckavdsb7Xjs+CshprIXpeXhwk8vIQ9HOAEs+0xxbPu+MEiP7ukmXPXE5UH5esFva
         KA1P6Fp3mSWIBt3h8HHPSM7338/nP19sisrgZSOqgD1nU/44nBQIw9qfOhESh4pIl5Iq
         p7Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=qhNWHZYa7eynvrYHc3LRuunGbk/pMqdS0wGF41w/Aqc=;
        b=AOkocBpPo6a6YjOL7UKyh+dj4g6Lo78rWffqdpcccf6y0HQq5+BFTsydSbg6/jGJiR
         8YKVHE8wYFojFsNKCWyVhYP8Zklf7g6hugXgNfIttpdduBOguRFVPMbh17PKMWcYYu8B
         yy6careUM8gRDpph1Y/uR+iXUZ7TIxU+ywI0KuRMscHQJKGHfm3Q5uBmJotyrhS41xHs
         ek4NYFkge0Y6sg1mKaXlzQlqMa0erXsf00ncI3lPOJcVG9ZGyk1wRb1/3GtrS5XzWASh
         Ird67adzAS33V5I+OOUAJYTEZnur38rxRMfxUVcpDVRi4EQ4Bah8EwWWMCMrFe03/Bbh
         b2gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x18si127551vko.0.2021.03.11.05.25.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Mar 2021 05:25:17 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A17A264E22;
	Thu, 11 Mar 2021 13:25:13 +0000 (UTC)
Date: Thu, 11 Mar 2021 13:25:10 +0000
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
Subject: Re: [PATCH v14 8/8] kselftest/arm64: Verify that TCO is enabled in
 load_unaligned_zeropad()
Message-ID: <20210311132509.GB30821@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
 <20210308161434.33424-9-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210308161434.33424-9-vincenzo.frascino@arm.com>
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

On Mon, Mar 08, 2021 at 04:14:34PM +0000, Vincenzo Frascino wrote:
> load_unaligned_zeropad() and __get/put_kernel_nofault() functions can
> read passed some buffer limits which may include some MTE granule with a
> different tag.
> 
> When MTE async mode is enable, the load operation crosses the boundaries
> and the next granule has a different tag the PE sets the TFSR_EL1.TF1
> bit as if an asynchronous tag fault is happened:
> 
>  ==================================================================
>  BUG: KASAN: invalid-access
>  Asynchronous mode enabled: no access details available
> 
>  CPU: 0 PID: 1 Comm: init Not tainted 5.12.0-rc1-ge1045c86620d-dirty #8
>  Hardware name: FVP Base RevC (DT)
>  Call trace:
>    dump_backtrace+0x0/0x1c0
>    show_stack+0x18/0x24
>    dump_stack+0xcc/0x14c
>    kasan_report_async+0x54/0x70
>    mte_check_tfsr_el1+0x48/0x4c
>    exit_to_user_mode+0x18/0x38
>    finish_ret_to_user+0x4/0x15c
>  ==================================================================
> 
> Verify that Tag Check Override (TCO) is enabled in these functions before
> the load and disable it afterwards to prevent this to happen.
> 
> Note: The issue has been observed only with an MTE enabled userspace.

The above bug is all about kernel buffers. While userspace can trigger
the relevant code paths, it should not matter whether the user has MTE
enabled or not. Can you please confirm that you can still triggered the
fault with kernel-mode MTE but non-MTE user-space? If not, we may have a
bug somewhere as the two are unrelated: load_unaligned_zeropad() only
acts on kernel buffers and are subject to the kernel MTE tag check fault
mode.

I don't think we should have a user-space selftest for this. The bug is
not about a user-kernel interface, so an in-kernel test is more
appropriate. Could we instead add this to the kasan tests and calling
load_unaligned_zeropad() and other functions directly?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210311132509.GB30821%40arm.com.
