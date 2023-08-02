Return-Path: <kasan-dev+bncBCT4XGV33UIBBWVUVKTAMGQE4C424TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5567B76D660
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Aug 2023 20:03:08 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3492c39923asf165505ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Aug 2023 11:03:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690999387; cv=pass;
        d=google.com; s=arc-20160816;
        b=zbDeeT1U7aclZtYxRtGv5RXpKqvIVYFyFBb1eIEZbVPUa1LAY1zflgBlPnHpxDDeth
         GIcgs8TakFXJbnHujvoI1YvfZejTQHbUCELhcZrS9hIiKvl+v1ky73iD071st5brsr+D
         xKF4bnRBJc7vbxKyMKB4+b4089Lk3lQEJiIrhH9ueTxufNKSXfS7WaoIXkAuAMK2/uTJ
         LbyTkeEjo73sv2GXaawRBkIWGeK1o7A9eWoHu3o/GmWlehAi0Y9HMfNfze8LXN6C92Xk
         kpiJ6R3JgBH2VCGTdt3tcd8XqIC9ABu/YfZKav4VWBUSC6ekLpXZzf6flpdIumxRUCYX
         g5vA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1P6iwGvIt8vn4XbZR5RSL4EPEhH/GncqNPVTxGvrgNs=;
        fh=VQhsOL4ofHYk7xfRxlNuLN7/Hez7kHSGgGIs12/PrcU=;
        b=D8wAGogrcVvOqHVSgm0mdpHczc1c9CXTh3HLMszS6X7b+8tl5NqdSmOoN8HM1v/raq
         3D4tXeMeS2ds8u0p/eyeUgWyef0ZJ0HVMp10Xq1dCZAH98JbdzxFYwiY1qZPPL4UdOcU
         vZAXMDSmZeZXMQgDtHPYskmbTykH/fWWesDQIkU6dc2xK3NFi4Cb2SN3IACSV05lWq+l
         jef9VeWT2EIwb4E8HqPJXuuIUd7l1fya2HHzfcwgNuXJmDlDQxD2W2NhopheCajXdZEn
         IdyQP6HIrE5svGGLQbAOdQgPPHX4cXPTrHqE3yF4hVquPChKXyhKR8gMHpoD/qqoMq7Z
         0uOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="2Nmf/GfP";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690999387; x=1691604187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1P6iwGvIt8vn4XbZR5RSL4EPEhH/GncqNPVTxGvrgNs=;
        b=snC7jCEBTkPwJ/xH5LPD14zSDT0Xq796eo/3Dr50rRJnYv/NOB5B69oa8PM0Eninbr
         gdGPTijtS2JFP7BU33Zapp3Ij7Pvt5RPVsAs3HADUvqTpEVo+7SX7HqGGpl+BE9wXusF
         S8DRiH7Evwg3qePy/ojLLV1em5/Aj/MVK6ZSHpk8uIdDMW5h6uhGQTOiUucu8qaSQAiH
         aW3ebwdP26p4SA8XvG/0wxQRZpnkY13nr4Ypd3/0r1ITXQK6FggHwvtr9LNpJB31SnV2
         G+pzeWxodLJjRO3G2uztjG2bpVrFn8t33fpC3uPju4RfQottG+3Q8rWUzwKlSdvCLWdv
         vY9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690999387; x=1691604187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1P6iwGvIt8vn4XbZR5RSL4EPEhH/GncqNPVTxGvrgNs=;
        b=BR0IMeA3hXA9i3BVrtux4IkD00lHQNzcMg1f3BTWnNxMceHjpQh3yJJumzw37QT5zO
         W15YWtmUyMj5iTsXlLNCOxEnDwox2BvETOrIAJMDp9IMmiLcHhMDCxt4nmFMGcOvkYfi
         /KHZJBWffRG9yPYMD286+3PP2qey7S+FQ+BSfn7L7IUUKomkyN2yzY9mJctxEV33LI0C
         hTbLyxSuGmPO9F2dl2WHHJD1ZhxYmutwRKB8C7QBcI25pNpzUIOS8edEnEld+EQyj5Yh
         JuzJSE6cuM1EYj9fxgRRSbERqrrw3pdxvdNtaNARv+6IUnO8r+XAKh72sIXP6ha18Yhn
         3RlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzvXKNR9GITqU0GNeAoe2dywwhvIbghK7kA+vMPshhZTzpHf3/8
	qcTRKGRpbapQtYIoCAgKgoo=
X-Google-Smtp-Source: AGHT+IFNeYWagNI5l6RjSzJ4Cm4JpOaeqzfhNUD4kEmHmyUeyHzTc581S0zzzhLSPbWKztXa/SLW5w==
X-Received: by 2002:a05:6e02:1a4c:b0:349:3dd2:3cf1 with SMTP id u12-20020a056e021a4c00b003493dd23cf1mr145551ilv.23.1690999387080;
        Wed, 02 Aug 2023 11:03:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5209:0:b0:349:7b9:7d1e with SMTP id g9-20020a925209000000b0034907b97d1els569235ilb.2.-pod-prod-02-us;
 Wed, 02 Aug 2023 11:03:06 -0700 (PDT)
X-Received: by 2002:a05:6e02:218d:b0:346:d51:9922 with SMTP id j13-20020a056e02218d00b003460d519922mr19672656ila.13.1690999386219;
        Wed, 02 Aug 2023 11:03:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690999386; cv=none;
        d=google.com; s=arc-20160816;
        b=iTQxOTvxjt73KNNqTzPoXMV6HkBV8Jz3gpff+0oa7n0Ll3p1UiaFBHDwqVvuShIWVI
         kw8sWIdMV5xIKBFYjxixH7GUNliVgBiTlsAGfJLv/gQawQJPv4f3s33ddg/g21FcO256
         Ot2ZTl93kPexHL0GElx/fnlYh7i95bzo0Ni2XWYbIp3dAOhTasJF1rtDx53nglFHwIoA
         tv+0chDdYcKOhlKZHwxwf5y8XhcO1ih/mEV23JSamZ7MQ9Pb3YGMqBZyqCA+6AblIx/G
         J6hyfJvrTg+H4bsbjfEoVxM2xz9gQDCZLNhnxe7yTUmJOMKYge4mdvZ5Ml7zFec7KH68
         Flwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wI5fJCWtldNJpYYx2IN0TkebJJo3zlk8V0xQL2JeTko=;
        fh=VQhsOL4ofHYk7xfRxlNuLN7/Hez7kHSGgGIs12/PrcU=;
        b=Qp86YkTMhDHdUbAafCScKcZEEZyWdmpQDFeiFJujLS8CC0Tk4sVBAAdRcJat1Uowhc
         hWhqYSarJmdOt/eawkmvz5ZQlxI1q+Hkqkl0pQ1AKIdMwb50WydwY5OpuCva0U/VCs9f
         DvyyDeahtfmmeZDVB/Aqyo9v6O2/ClYnstQMXgcbI+W6x1IoYKLtDxI8QWp5plHRgCM8
         QK00SisJ9J2ZjY+gkTlwfbzDQWQf8NlYG2d0gPopNvqI8GpAfpsbzwYl/NtW4OMzUjHV
         2pSaSw55fGGPoNQ4sipXuuF2VmkDrZuAr6Aa95I/1qxLnTsSPhEDoezqqXrF23WjgQIQ
         07qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="2Nmf/GfP";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id g12-20020a92cdac000000b00349406de876si81421ild.0.2023.08.02.11.03.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Aug 2023 11:03:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CC8BA61A85;
	Wed,  2 Aug 2023 18:03:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 64E5EC433C9;
	Wed,  2 Aug 2023 18:03:04 +0000 (UTC)
Date: Wed, 2 Aug 2023 11:03:03 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Guenter Roeck <linux@roeck-us.net>,
 Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, James
 Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>,
 Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas
 <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Miguel Ojeda
 <ojeda@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Nathan
 Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>,
 linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev, Dmitry Vyukov
 <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 kasan-dev@googlegroups.com, linux-toolchains@vger.kernel.org
Subject: Re: [PATCH 1/3] Compiler attributes: Introduce the __preserve_most
 function attribute
Message-Id: <20230802110303.1e3ceeba5a96076f723d1d08@linux-foundation.org>
In-Reply-To: <20230802150712.3583252-1-elver@google.com>
References: <20230802150712.3583252-1-elver@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="2Nmf/GfP";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed,  2 Aug 2023 17:06:37 +0200 Marco Elver <elver@google.com> wrote:

> [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> convention of a function. The preserve_most calling convention attempts
> to make the code in the caller as unintrusive as possible. This
> convention behaves identically to the C calling convention on how
> arguments and return values are passed, but it uses a different set of
> caller/callee-saved registers. This alleviates the burden of saving and
> recovering a large register set before and after the call in the
> caller."
> 
> [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most
> 
> Use of this attribute results in better code generation for calls to
> very rarely called functions, such as error-reporting functions, or
> rarely executed slow paths.
> 
> Introduce the attribute to compiler_attributes.h.

That sounds fairly radical.  And no changes are needed for assembly
code or asm statements?

I'll add "LLVM" to the patch title to make it clear that gcc isn't
affected.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230802110303.1e3ceeba5a96076f723d1d08%40linux-foundation.org.
