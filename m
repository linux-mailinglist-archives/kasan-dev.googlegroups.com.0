Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6FST35AKGQERFVY4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 65EC3254450
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 13:31:06 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id m16sf3938412pgl.16
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 04:31:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598527865; cv=pass;
        d=google.com; s=arc-20160816;
        b=V54FI5cTA8jG9nI+9wxiVbMGDqxBdvaB6WutCQclAEHKZwclYU0RAe1+9S0Qut8dHg
         SFXu8lvg3h8513YIi9jxx9R6eqt4Oww8n3+b/h9yM0OquClUQ5g/aSGH3Yml250F/osE
         8FrVTZk8tRcl4pwYfcPKDzM5Ax6vOVCHpTXkxAdxrYiWoYwFfPV5/6AGRWP7RV3S30yb
         Ns0Kf43vs+noFpEu9VVH1gbEM1TchuwSQqkMuE+NL7eh1TG0eqPgHtZZtq55oY85f+ew
         c9gzVZoVG5iAta3OV/fLBxZhPZdTI04fsVJeLegnnkkDxf1V/D4F2yW3PMFLS199RFaP
         AH9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=9Z+ocKesa+roeSWmEkFeQYskqJco/jnpu+lpD1Fxr2U=;
        b=gHo4hBxiCklE7jBioZJPVmr1MEesjk38cYJgU1zqP23zcpE+eQTPG9KqTFXLaxVHr8
         e/ziqMdSSo5o+exzrTrpNNRb28RTthq/FjUENP7H/c1TSUV3nINSLOUAFXNubTVQEnKl
         rUKtGKvZjZRaSAQWTR25VUwjwsafXUJyeV/R89YHtmk4yQgy9ERqXr2vElJQsdUV0mj5
         KNQTmCpKmchaiDAfIAdLIFSWaioe9fR/hns7piOd7PrGFNlB3gTUwaFT1z96Re2waGF6
         sMobkqPCoWb1onfsc/WVtzxcxb/tj3tN3lgnJKEvFJ3fMFiEXGL9LbnjA3Va3iistDAk
         s7Lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9Z+ocKesa+roeSWmEkFeQYskqJco/jnpu+lpD1Fxr2U=;
        b=ghrk5e6XsIlXvdPFDfRmIcVRVTeXXL/1nzkpmQfu73aeg839r80yR7j0O5qxhgKLX2
         JQjsPDBHt2o8eiNfGDn/3Ee42RuiX1AbINrafp7OC0hiC7ftkXEohZOyS4qTDPy1F7fw
         UUnvX1tqN/e7SX5r3fT12/M5FBB9AKOKMJG3RCe7mQIQvdFY/5tc+n9CC7XTv4ro8Ylr
         OkM9HFy7NTze4KGStPQxSuD5Gu0hJNprW4qBWqaO9SZcEoHTdEDYriixFVV2pkyWMGN7
         PBjyWw/hx152WOr75TnISaZQOII29zHyI4vLxKPlMVUI0jNPEvbudF4xOndDUocmNXaj
         SyaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9Z+ocKesa+roeSWmEkFeQYskqJco/jnpu+lpD1Fxr2U=;
        b=pfFf0spP+Gpv94TqoWXcWORAgVU1CBEXbZmNewkDI0zCnR004ZJ+COnAw4FcXESThh
         mwcZdGsCv7oMOOVN62TSQ3FdcrgellJQVtWjfXSlwc7bQkOC91Se1P3JSUGu3w9mya6Z
         MT4n8rSEPAAmxsDFPFwuK0Llo/tMVHWB0xhmFtza61QyChrvAirFtc7X82BPFojSQZVS
         yvHUE/TX9BO+x7/oy3xkDl41lrfdgPYaKlXbyKawtr1WXT4CkhgirCNlfwm+EnPQkJNX
         UZPW6Darf5AH7a86qAIOp7JA4Ny56mnI/8m1OfIBrKjE76pHc26mbQeTNuJ5bYJWqM1c
         t+Zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NwOh7FKQ15yd1GOGh4DeAA46W/fNCj1BeqNf3haagTUu1Ne7O
	XXUlBxACN1501a5R+gezN7E=
X-Google-Smtp-Source: ABdhPJwZllGXdxi49CwnZ9xJ/SSg2nvy+RX/Bd97iUlS8HZnX2Cc0exrGroL8ohe2emTZYxYYEvSIQ==
X-Received: by 2002:a17:902:6944:: with SMTP id k4mr15590565plt.147.1598527865119;
        Thu, 27 Aug 2020 04:31:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:620d:: with SMTP id d13ls779998pgv.0.gmail; Thu, 27 Aug
 2020 04:31:04 -0700 (PDT)
X-Received: by 2002:a63:1216:: with SMTP id h22mr236845pgl.393.1598527864613;
        Thu, 27 Aug 2020 04:31:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598527864; cv=none;
        d=google.com; s=arc-20160816;
        b=PGrENQUq8vjf7W4VbSLgZsYINCSv/gCH5vEMiqhXGjvPAQp8JkUAYTdFWKgLL2ll73
         Bst7LWAhq1QzTporPgVe4S0yBJs3aalpFT3/MrbopojWdCkhYlqoORf/AmFV/Wqf4FZT
         SdgXLSO8q6HPD+sBHUWUwbrI8zfmUOwF7fIXYH2eUZ6D3aITPLhFN2vgkcbYF/OQm970
         nLHxMd8dIN/56jkm7SDg6cajOzsuxPBO44nThsGgTB7qlWMuRG69igO9/oc5l3r70/oM
         7l8Eq7uVJhiqPJdDH1qbgEiNZNyP4/kv61lgrzxuosQhDtoruZZnGJ1Hbkyybe/Z9+JP
         lmIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=mYD2a43kKc3zZammipRaW1kuBj0tmomCS1ox/aJYu7Y=;
        b=jMNprkmdm8p1uWZBofzzMhLmqv1HmW7wiWf8ryZHtz3lQtSxhdua3fmtMfhVu1bdTv
         qAIcqTlG9rjLJ2MIVlmUMnOI6UuP1ND/JBy9kwZzi91G5OnsZ1kuduIOFjFN2HiV/3g7
         CKpXqM0mucUE8j9MCCqbzhWUrfqAuJaXjNlw/QiFth2AMx1DMfSv4gPYvf3tJb5A/KG1
         +XVCWXmj3wZJn6pdBc3S5LIsw+CFzJvfqCMs8xh1nBxPLEkHZ051wdJkSJ/ULt+qTBk4
         R166dzb5KOebUq1TV3QYXcK+Y+bZHGE0zphOsPjk5yCLGmDD5HWeAFns6+CsgM+j7bQr
         O9rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id lb11si83815pjb.3.2020.08.27.04.31.04
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 04:31:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F3FAE1045;
	Thu, 27 Aug 2020 04:31:03 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E08D53F68F;
	Thu, 27 Aug 2020 04:31:01 -0700 (PDT)
Subject: Re: [PATCH 25/35] kasan: introduce CONFIG_KASAN_HW_TAGS
To: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas
 <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1597425745.git.andreyknvl@google.com>
 <8a499341bbe4767a4ee1d3b8acb8bd83420ce3a5.1597425745.git.andreyknvl@google.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <b7884e93-008f-6b9f-32d8-6c03c7e14243@arm.com>
Date: Thu, 27 Aug 2020 12:33:15 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <8a499341bbe4767a4ee1d3b8acb8bd83420ce3a5.1597425745.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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

Hi Andrey,

On 8/14/20 6:27 PM, Andrey Konovalov wrote:
> +config=C2=B7KASAN_HW_TAGS
> +=C2=BB bool=C2=B7"Hardware=C2=B7tag-based=C2=B7mode"
> +=C2=BB depends=C2=B7on=C2=B7HAVE_ARCH_KASAN_HW_TAGS
> +=C2=BB depends=C2=B7on=C2=B7SLUB
> +=C2=BB help
> +=C2=BB =C2=B7=C2=B7Enables=C2=B7hardware=C2=B7tag-based=C2=B7KASAN=C2=B7=
mode.
> +
> +=C2=BB =C2=B7=C2=B7This=C2=B7mode=C2=B7requires=C2=B7both=C2=B7Memory=C2=
=B7Tagging=C2=B7Extension=C2=B7and=C2=B7Top=C2=B7Byte=C2=B7Ignore
> +=C2=BB =C2=B7=C2=B7support=C2=B7by=C2=B7the=C2=B7CPU=C2=B7and=C2=B7there=
fore=C2=B7is=C2=B7only=C2=B7supported=C2=B7for=C2=B7modern=C2=B7arm64
> +=C2=BB =C2=B7=C2=B7CPUs=C2=B7(MTE=C2=B7added=C2=B7in=C2=B7ARMv8.5=C2=B7I=
SA).
> +

I do not thing we should make KASAN_HW_TAGS MTE specific especially because=
 it
is in the common code (e.g. SPARC ADI might want to implement it in future)=
.

Probably would be better to provide some indirection in the generic code an
implement the MTE backend entirely in arch code.

Thoughts?

--=20
Regards,
Vincenzo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b7884e93-008f-6b9f-32d8-6c03c7e14243%40arm.com.
