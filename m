Return-Path: <kasan-dev+bncBDW2JDUY5AORBFEC4HCQMGQEMYAAFOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 48843B42136
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 15:22:30 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-61cbc94f5b6sf5194699a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 06:22:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756905750; cv=pass;
        d=google.com; s=arc-20240605;
        b=S5lla2WqWNsLnL99GOYis3VA/1q1fMsY3fkpHRSuHLYIzCmwzaXfZuuZu8tE6UEvyA
         objOwIG3krJmtXJ7FTtq+X01OMHvACdHS75k53SLPEImFORIbyT2vR290w8l8TgvhyQo
         ZVdl/jXfopikB7uasX8AVdUrEqu0B8BrIrEWyq4N3YcgTDLMi4y2aIDVAOHJYkH9sTaw
         ktnNRmpOS1zKrER5cWdn+scCRBc2D7LVJQTD2wEIMOkIgimzj8L+4/MmXBI0FUPt1Acy
         mREu1EHEL88zwvND3sogIhQMtZOIUs7uXIXwhkDVq76viRPvd+QBqeMjgUcDc4nuCnwf
         jKsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=FicFsx3PDpUQqBM7FbuRaBQ99AslkFZxd/M7uORXpm0=;
        fh=MJXw46ERuBTpRiob5ipvg+k8zqlW3x4qYHyi8xMYHjc=;
        b=cuXL34d6pEHJpAUXfBK9+Nrw2mr8N49AnWx6+BlOK9ZWuFrW/XZ4A7CVYVM+pGPJAK
         ifwI/eryw3xgAp18tZoan588bohcivEK+hvy+rrGGtRzfs6jTJdgINpOXF5mgFFn+9gy
         x+pB3y2/5LcJ73ME1TKRGECiCepKlYrs787dkRKTPv1lbaHMhtknb5u4B51LDTjV8CIZ
         N5WQEETYaFt3vIe+p3Kqpy0a9GGCejjENVP+Oc2cxE4zOf5NE0N7Pm4SkglKkd8A9f3x
         4LOXdnuXZVpdf1Vk8mhjYyp1z7+yvUWZRMzGvWAJNBqnCaMcWAwE60GyWrv+n6epwMdU
         Q2/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IewtjoHt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756905749; x=1757510549; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FicFsx3PDpUQqBM7FbuRaBQ99AslkFZxd/M7uORXpm0=;
        b=V+DxLDQNFBxo9sJA94fmVKdPtVL81uc5/A4sX264hc0vjGSWrjyD1RTxyityLSIcpI
         tgR5XpOog72ovW5SIFmjGyfpcpKj+F+yYgXKhZnGrHnU9JmRc46XpKhoIAiYxH3JNMxW
         YY8KJUeFNy+stA4UIAw3JHHEBn6Qm35y0YxoTyaUSAmVwsJLI0td8CbFN+QH7HM+lttg
         D/etzzyzpnJxFtc62ko+gL9M4zZHIN58p8rhuYlpLBJ5eOCS0V5mRhfpUqRzFDb+RCMz
         NAQtuA+1H5fKhbEhNqbT8PF9v3ssBZb1rux7MjV8XIHC5RgQfLtbgUlhPnf5krRUFWj/
         Xwwg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756905749; x=1757510549; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FicFsx3PDpUQqBM7FbuRaBQ99AslkFZxd/M7uORXpm0=;
        b=Nfvxg977zqKzo0TSe/YCFJKh3qyUCze93rxck2cYOHkCDXgIZmHkHNfxAlIFPLXcq2
         +fv3IVDjIH3ZUstRTzvCMUGKis02rpWzTptzTiMVC8MkdckMk06A0DRGFlJd6r8C38sq
         9f9FZSkdgPZMJErXsskYvWGRw6RDd5ITB0NdG2FdbCLQBdflQ6XzayJehbicyMGke+fJ
         YwKusXHJ5ZPZUn9ovPYTz39XDugxj8u2Q7PDz4GYrCifiLwLjvGOmTvrxp1sWmo5RP0p
         WWpipRriAqqcFNRQeSkrRwpduBiP3a5Cd1ksz4NkZRyzp5Qw3zTEVyAwJt2/zplh9G6/
         MXEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756905750; x=1757510550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FicFsx3PDpUQqBM7FbuRaBQ99AslkFZxd/M7uORXpm0=;
        b=pj9ecTMWm6r9zBiBWBI0DgGSQKwviSm38rO61nSS1W2yW8U4+vnyYFYg59IZME3tnh
         OZSLDMDGygYS/uKJpvnuh6TrCoo6TUrfsbi7GgS68ahayPmanl7flptU6f2H3eaIJqvQ
         hyWx+lHh0mVhz4ZAzs1O7OOUspKrark/C1c8PS22y9+lFORhG8sywCRpNAWg3z7Rm7yv
         7B+lBv3nbt+I8H3mDt0uoHJfivkALLeTKI8rRWiAKNlxz+PkRU/kJPJ8Q8YIJwNJEZew
         EjnsiZtms55+Zx9UBV3wpsTucb+jBdQ3aX8AS/IP1nAwt8uJFwxSBWPa7G/QXC0M9BeC
         YSoA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9kT9FWk5kfvu6akdSRw9PiCD9eg5pGQeJ6ktFaeFwzt5ktQNsRHRHOOXt6prim/+MACZSSQ==@lfdr.de
X-Gm-Message-State: AOJu0YweGQWGgjJzlTs6yAoaRgLBtGN7KQu296WMlmLJ2VZHA4cPWmB7
	kfj1TLWnspBR7exu78tiI4o+ABc8m5X86o11H24oeoehlI2k6EYAkflQ
X-Google-Smtp-Source: AGHT+IF9JrOuKCM0Sc7G02rFbFzrjfI5RsGgDWfQDo0RNsOWkkTLVVwxg0uUo8n+NYAriaLmybxXAQ==
X-Received: by 2002:a05:6402:1d55:b0:61e:3b86:aac8 with SMTP id 4fb4d7f45d1cf-61e3b86ab95mr10289641a12.19.1756905749306;
        Wed, 03 Sep 2025 06:22:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdJMqkP5PwZMVwkiyLG/8X9oMigQJCGWLvgQTd1Ts7/jg==
Received: by 2002:a50:8d1d:0:b0:61c:3723:1d24 with SMTP id 4fb4d7f45d1cf-61cd427d53els5330110a12.2.-pod-prod-08-eu;
 Wed, 03 Sep 2025 06:22:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYmFseLeKb+oC6egPuvpMXl+eP76s6yZnmA58/hEn9OC19E+gUsOv4l4+0bneGzELHU23tGcOPqqQ=@googlegroups.com
X-Received: by 2002:a05:6402:35d3:b0:617:9bff:be16 with SMTP id 4fb4d7f45d1cf-61d26d91616mr14097707a12.22.1756905746289;
        Wed, 03 Sep 2025 06:22:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756905746; cv=none;
        d=google.com; s=arc-20240605;
        b=ev43dBrn+2ZjaMRl80Nb09UdY+BjScssW8oz/p4GtSJI1pVV87tF9rVSg4CKtp0PKJ
         JMXzYThnOB67wUOeQ0+QQ9gSDPZEGUxPOqZWsi4dojDePVK5f/Y0+UhPdMeeiLmI7ryJ
         VUlBImGMeiRyz6MK7laO6jZp5ST7CtwptJumzOXtXoNkhBAajhNZOhdwNOAJfiJC6EDL
         +phO3Z5IsIlVb1V8nIXY5/tGbnzvERGwlUoL312oHgamK0WDmQEhyaIr0ffQuv1vsdIq
         wCUCDqYXDOqNfNR+ie3fGS5ondGRAJPuZP0rXEL9ZyjCNjB3Vix9nQvcpj0xCWqiiYH7
         32Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+3/FvEb2tmp04THrfe7Q6R4Z9tV9DSLFC8M+VKKCGW8=;
        fh=RCHZtNjXtbXVQssCcVt9QMdVfB73clByH3i3f45wdMQ=;
        b=AIkAC9co/ydIUwzUNT44mRLMpQYLTfHSZrPHueBg/p/zh/cZTysRIRLs1X2DD0g9ax
         vl0DuFvmIaNCtFlvQqXnCZWYn0Dl/Cc2pgF1AHCkSHYSQB9wOSd6l8vtO/S66KgdjpYS
         DRX7MQG+j//sbjUAw/5hSFkx95pKqUN9YJzm2F4fAATUlFJQ7IeppqUmzlStkWoITtxT
         NC7F4iLmFW1l5h1SBAVntHkXvJTzT0LOA3iXGJjxgeOXve3k6szfdo1a32y4z9hJCcWN
         yt6P7FMbjnXZ4/opem9vc7C25hW5PZl0ZdCccP9/fovBe+bBNxR4T8Ou1bFY/ca4+6We
         7E7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IewtjoHt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-61cfc18bf34si303262a12.1.2025.09.03.06.22.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 06:22:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-45b869d3571so12098215e9.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 06:22:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX0p7N8qoEDaXPOZHqg4UswgINVxK64ppjx+zKR6MctlIF8cllYZiOqSBGxpFLu1kA2JcHDi/GOCKM=@googlegroups.com
X-Gm-Gg: ASbGncsSRjWUCsZ2+Bh4DFVQR/GUoq8xhiIzgX4nGeHSCuOAjMr7u87W8Zy8DMHzMgW
	Sgd/QilA8qSANHUjODw5y6xzUEh6nh6Q2cj3nfDVzaSpXGqqdjSTaRjCGfnQRbfFKkS7Dzhjx7q
	JXZVlHol154xSNhzhM8yaSJlM0YXF5+Lk3zfKPJEP7/kbJjqzrUoq/jpVNbbv0LJdZ1UxAWyJlD
	Kv5WR+L
X-Received: by 2002:a05:600c:c8f:b0:45b:7ce0:fb98 with SMTP id
 5b1f17b1804b1-45b85528677mr134028325e9.5.1756905745452; Wed, 03 Sep 2025
 06:22:25 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 3 Sep 2025 15:22:14 +0200
X-Gm-Features: Ac12FXx6JqZw2o7u1Ppz_iF81kfxsSp5T4xMMmvHYDtA-FZpsjtY5aXsfqZMrYM
Message-ID: <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>, glider@google.com, dvyukov@google.com, elver@google.com
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IewtjoHt;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 20, 2025 at 7:35=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> Currently only hw_tags mode of kasan can be enabled or disabled with
> kernel parameter kasan=3Don|off for built kernel. For kasan generic and
> sw_tags mode, there's no way to disable them once kernel is built.
> This is not convenient sometime, e.g in system kdump is configured.
> When the 1st kernel has KASAN enabled and crash triggered to switch to
> kdump kernel, the generic or sw_tags mode will cost much extra memory
> for kasan shadow while in fact it's meaningless to have kasan in kdump
> kernel.
>
> So this patchset moves the kasan=3Don|off out of hw_tags scope and into
> common code to make it visible in generic and sw_tags mode too. Then we
> can add kasan=3Doff in kdump kernel to reduce the unneeded meomry cost fo=
r
> kasan.

Continuing the discussion on the previous version: so the unwanted
extra memory usage is caused by the shadow memory for vmalloc
allocations (as they get freed lazily)? This needs to be explained in
the commit message.

If so, would it help if we make the kasan.vmalloc command-line
parameter work with the non-HW_TAGS modes (and make it do the same
thing as disabling CONFIG_KASAN_VMALLOC)?

What I don't like about introducing kasan=3Doff for non-HW_TAGS modes is
that this parameter does not actually disable KASAN. It just
suppresses KASAN code for mapping proper shadow memory. But the
compiler-added instrumentation is still executing (and I suspect this
might break the inline instrumentation mode).

Perhaps, we could instead add a new kasan.shadow=3Don/off parameter to
make it more explicit that KASAN is not off, it's just that it stops
mapping shadow memory.

Dmitry, Alexander, Marco, do you have any opinion on kasan=3Doff for
non-HW_TAGS modes?

On a side note, this series will need to be rebased onto Sabyrzhan's
patches [1] - those are close to being ready. But perhaps let's wait
for v7 first.

[1] https://lore.kernel.org/all/20250810125746.1105476-1-snovitoll@gmail.co=
m/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdfv%2BD7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w%40mail.gmail.com.
