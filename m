Return-Path: <kasan-dev+bncBDCPL7WX3MKBBA5Y6PAAMGQER5J3TZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 74EABAB006D
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 18:29:57 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-60624d13c7fsf280515eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 09:29:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746721796; cv=pass;
        d=google.com; s=arc-20240605;
        b=jJ3tIVNx8Ynv9Q57jdSRG0PA+cv1+VVvp48JFnyAcH/swj6OBNKFKhrlO4N+xds+pS
         MixjAio4upuZpzJH9i6Zc3jwHz901iL+rYsQgnpVGlVvBiFEYnBi2bI6m6JhHYXG8Xph
         W+q9ZLOsGzGxsZmtZfRgfTr40dLvX5UnR1gQTViyVmZHXOiipXO/pGDNc6/keHg2OI9A
         4/U3AILwfW7LQdZ18PzgG0/TjVvvCBDvRyZ2d4dIf+W2PjAPUDUeiGQL6w3yQMS3aHA4
         EmiD91h0xWNPrltWYHM7PxMsllml8IumjyUf5u6J6pJpm+R9bNrnjRPip6aDcqlwauNC
         WiCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=GkeupmS9SlUjUkDP1lNEeaCBIaZfVTxbRbGgomawyhI=;
        fh=SO+aJLWDgKVtH9KKCFkitTn7TzhbqGpIkmR1M4QhRXM=;
        b=PLVFj/HPCIft1rjR+aiSpkzeLf6si6gnhe8yh7mOw1pGFv8AUgjt7o17EsRdGOZvWP
         hOK3dp11Fp6QUnO4hn+aYo2ogQvAz1wbhEUxsN1PBcbq5LeXfewLf08JODm25oMWti6o
         30UdhqtH6Pty45EGrwZqMVDUWowTPggqkkk6Ei5Ln5TGGtyxZ7gI69brqUfPRs/O7EKN
         x346nphx/7K2Qp2pe5TLHTUFJImqldVWT1Nz9DYssSFvO3WK0fe/L3tq8PT3U8xxCUXj
         jAiQmAA9EVpHtV4Q1b56jrXRvpBX8AYZxpW5tixYftNAJbcqncH9/yj43iGPcXPNfkxU
         P4BA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H8yVftdY;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746721796; x=1747326596; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=GkeupmS9SlUjUkDP1lNEeaCBIaZfVTxbRbGgomawyhI=;
        b=grAADl5xFfkRhVQzPbRkfFsX1ACoWay5YeExPb4nqMgfxE15XIurVMXkhtVQWKkQDa
         /TDmCniePvi45lHY2WniX2sMQjI9jlH6RkaX8poE7yWAxSmaOClwi4DTr6HA64pYdiJs
         GnT1m21I2UB1I3RO55Pgatsh2o7lZnt6oecIqaERC+0tZPGXZ491pzvkCztyBiHJSDfJ
         NvvIv270diBXtNkxlvsqmS67BnkfC4cPmBtuR1+InMHkwYhf0Kz90zsNA47CGKsB7pDg
         Ia2jYqlkkEclt/xAcbtGtCtp+Tlkn3rQ6C1d8koDfH1BMvVGUUHR7h0nFkNPSibOBsWD
         BpoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746721796; x=1747326596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GkeupmS9SlUjUkDP1lNEeaCBIaZfVTxbRbGgomawyhI=;
        b=g6jB/W/IJGeqThWdNmMFxRAHun6XLqFgeq0EF5EEd6vJgC4XbLb2H+IvyRXkWJ6K3P
         wuGpRAFt1tC4mp6l142Cw/X17ThBMvehJRyJjLH4oXmvuQKg4H7qlcBZ4v2YnAWVIUYT
         LmaqkhKD4wUiRJbLMz2YMBp7u6CKPGJFVBHfsbUF5YGXajRz+SAn5x8Gajpx2AnvcLYc
         dc8KVwLMj5s3bWf7O78koR2Jwd2mMRaFpiQOR8EVXPIQS2H58GPw0HQs4Uq+nQjPeQ2j
         0KVkRjeNmJhtx8vA7x8GRJkrAQT72jUnsjs7lOAWuFQNkSSN5aqNI7AgSzuuuRkdnHZd
         aUQA==
X-Forwarded-Encrypted: i=2; AJvYcCUYJiH4+lPclwti3A508kS+wo86ebmVfAfv6YXVWkuQWPFIo67esjsqk3suFA+TyPbzAAfzJg==@lfdr.de
X-Gm-Message-State: AOJu0YzjPcrzhmEPwgLNg/FnF1H2u0tRLGM3Zopi5rVBjMRL2XMVlrRf
	ymIw1MB44leLWUSjKmDXxAPHcCtpsQKlF0FxoDB+BTWH6kiVfeYM
X-Google-Smtp-Source: AGHT+IHt8bXmP3xyOWBCfhp4SSubkYzL7162PDg7Dkm/RVhCQUlb3IAJqwg3GuiFhdtOMM2nm6qyGQ==
X-Received: by 2002:a05:6870:5251:b0:296:aef8:fe9a with SMTP id 586e51a60fabf-2dba41f8894mr101421fac.7.1746721795588;
        Thu, 08 May 2025 09:29:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBE8/onG0hAYR+7tX5vdEqWbixOgu/Id10jLbyBobuO4fg==
Received: by 2002:a05:6870:ef14:b0:2a0:194f:b555 with SMTP id
 586e51a60fabf-2db804b06a3ls475838fac.1.-pod-prod-06-us; Thu, 08 May 2025
 09:29:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnWZJtqSUzAbYuoWWygh6VUeMunHNSNINZONqNkhs0+uQnvU3SGEGBJrO2W15e7At9MKcEvL5WlTk=@googlegroups.com
X-Received: by 2002:a05:6830:6611:b0:730:da:1165 with SMTP id 46e09a7af769-73226ae9d31mr316970a34.21.1746721794598;
        Thu, 08 May 2025 09:29:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746721794; cv=none;
        d=google.com; s=arc-20240605;
        b=J7+fDRU8Zt5V/L82gdWuK97fnSA4Letnnz2bgwPZsbzvsvaDWwzelax2kwfPYohanZ
         zaAiRRKb1JVOAThkqishm59Jx+TyHrbKHo1dTqO6IB7KCxcMsmjplBDybsfzaowMue9c
         G9bcKcmzyVzax8swSnVtI7CrcH10+oFbNaFAjNShE3mxNzotGn7upa9b4qXVTq/mEX9E
         jcJjocEOx59qsnNkLGR9hLHcaizy6oA0/QD/gI7rMHf1Dx59H7QoIwMlEwTu+ZAo6WEN
         yMUgQwN9qGArs3VQt+HbjmuojllPF8094DqwFabzwxpWkflCzSoKa5MdoZpr+yPmPEqH
         Qe1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mrMh/2wiSkYQT91ZxSHOrsixg9buFnJV0y6uLi5jFyk=;
        fh=rZ7B0OwPs6Bzh4ATvyl8JgQxAQTelb1sqys6HhuOQrw=;
        b=AcTVn2FbLULCPn+wLoYduAKHTIQcSyuNNC5yvewdg4sYRfuwuGmlsmFHz0u6v2WNTk
         FW1NlVqR4BwaJiNN/C0XXOGpQ26G+sW9O+V8C3x0oy6BcvLzhznCgLXnFitXIGZTmZLb
         GpBy5vGGKRjjBakiHsF52FPZcswfthrsAffM9EWVDV//9aCX3YvxMlbD7G3rzttDe5o1
         a51JiqsUI3rIKgk68q5pb7XiF/k7YpDaPT+Pu+v8X7BbteVB/N2IKcsF6SSbT7cjAE93
         6lVRxubN1EPEoLTW3JG/x9k1Ny3ySRIw2J/JJ1X6pDeY1zwET3efEalRJQmP5LHSeL28
         hqGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H8yVftdY;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7322658d974si8323a34.3.2025.05.08.09.29.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 May 2025 09:29:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id AFDD8629DF;
	Thu,  8 May 2025 16:29:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 575D7C4CEEB;
	Thu,  8 May 2025 16:29:53 +0000 (UTC)
Date: Thu, 8 May 2025 09:29:50 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marc Zyngier <maz@kernel.org>
Cc: Mostafa Saleh <smostafa@google.com>, kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, will@kernel.org,
	oliver.upton@linux.dev, broonie@kernel.org, catalin.marinas@arm.com,
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
	dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com,
	elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org, yuzenghui@huawei.com,
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org,
	nathan@kernel.org, nicolas.schier@linux.dev
Subject: Re: [PATCH v2 0/4] KVM: arm64: UBSAN at EL2
Message-ID: <202505080929.95B2310@keescook>
References: <20250430162713.1997569-1-smostafa@google.com>
 <202504301131.3C1CBCA8@keescook>
 <868qn8hfnp.wl-maz@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <868qn8hfnp.wl-maz@kernel.org>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H8yVftdY;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Wed, May 07, 2025 at 11:35:38AM +0100, Marc Zyngier wrote:
> On Wed, 30 Apr 2025 19:32:23 +0100,
> Kees Cook <kees@kernel.org> wrote:
> > 
> > On Wed, Apr 30, 2025 at 04:27:07PM +0000, Mostafa Saleh wrote:
> > > Many of the sanitizers the kernel supports are disabled when running
> > > in EL2 with nvhe/hvhe/proctected modes, some of those are easier
> > > (and makes more sense) to integrate than others.
> > > Last year, kCFI support was added in [1]
> > > 
> > > This patchset adds support for UBSAN in EL2.
> > 
> > This touches both UBSAN and arm64 -- I'm happy to land this via the
> > hardening tree, but I expect the arm64 folks would rather take it via
> > their tree. What would people like to have happen?
> 
> FWIW, I have now taken this in kvmarm/next. A stable branch is
> available at [1] for anyone to pull and resolve potential conflicts.

Thanks!


-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505080929.95B2310%40keescook.
