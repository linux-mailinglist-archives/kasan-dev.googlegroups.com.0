Return-Path: <kasan-dev+bncBDE6RCFOWIARBN4M6C4AMGQEGMHHD3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 972BB9B10FB
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 22:57:28 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4315dd8fe7fsf22006935e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 13:57:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729889848; cv=pass;
        d=google.com; s=arc-20240605;
        b=hSbUE9BKJ5NiVLtavO0nIVQ7I+Lqlvh+ZPi2GqKo7ofpAqqe0AtkpoYbYALNajflCE
         C2SD2lPwsoL4/9qug2DYFdEO0OqRli4Rhcdh7oNdBE6fhO8Fk7RCqQ5fDXVV4CUVHdqL
         UNj3OPkstks/yrqN8G6TWPbbHXDorarZyLHGBQ5l1T7Tt2XemyLVtqXxGxkaz9YWmMXG
         R6CyNAYTUBsQlzwD7i0hxxo2S7TzxJ4uX3Q12j3FGl/e0GP189PSbfVYmo5pJ+2Mp22t
         VUmV0wyd+9EkfNA3Bbuw+NOfCzs2pwrrwR3OupqB1+JYY9XW37ESoqOVuX3xE11NXFqA
         VwoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=dJC+yTaeyTi3m96jt/KXFXk1OZvfzRyi5b9aVHKunXc=;
        fh=KyDIk/83VnfeiD/FY9JXxvYtrUbg6TSKv0dZRjcf4gc=;
        b=BCDw2F/gt97ATbtJDLR5LPyqVkcnAqs8AvUHcicNSW600Y5ioShuT8s00HNyP1QoHf
         KP1lCLhG1P5ZrS1eumPcPsJnHd1lV8pn4M0RbCqUTNf25nV+iy3EtJ9TjnBFsSZrrmhx
         gwxwEBHVXmZRMvQ1CPlU7ybJwfYxMojE9Yis+PhUaOtnJGHzVog1+SZCYWckZrguYezB
         Ij6y7i6j5fiy74a3oHxNxiYCGli1W+j+4GDGIM8RSqArkBz0FeW+a+vFoBtNAhEIkfD3
         5kHWR3m9hlWgAi/S1z0fJjEITcQH5ERNdlQJkViKgKi2BWbF3PGas5NkxB0pdFctEIkn
         yqRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=WWMTfyl1;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729889848; x=1730494648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dJC+yTaeyTi3m96jt/KXFXk1OZvfzRyi5b9aVHKunXc=;
        b=AXxHUUey6ouw8IO1nWcSXJF8aAJCZvDMfvZvxOgKQAZh8oAhSCJYR1w2XxG2P1qMyS
         /BzFa7lF9DtRJBgcIGd2xxS8+WX5vU9OFC9q3kBg4gXtsTK1zpewpAjubBjzRpu16EIF
         +wee9EwzSHCFV8YK/FNFltzWjoJQJYHeqsVQYKOrtFTqQv3W5NzwDTJGn1TDfEyg6qvz
         ri7qY39xhd+ewvg0W9gDHcdgE+gsjBNlwY1x4rqZe4ulYOzE9g/OItcz4Q8vcsS0x0GY
         r2CX0thctcWqF93UTFeiga2nh6flsNQFVZ1kxy+IqsZwnS2+7ap9mxRqfFbqQk7I5OTh
         xz1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729889848; x=1730494648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dJC+yTaeyTi3m96jt/KXFXk1OZvfzRyi5b9aVHKunXc=;
        b=LnAZuqMtulumLSmozJ3Y04U9q9wJUEeXmTPKy5m5Uzh9N0+BWAW8zC+s1xamVwlB+a
         FFx1ezFsEvjwmqNQobae1qstT3Hy71pL6PNqtp9dKwoKbX6/SlGK/ZzBqGblprRYLoms
         NPe9m6hV7XDUJ9ZITRNE7w+YKZWpHsN3ByDTKwWAC0x2ZYHEKlFOxq8qv/NPoc0zYu4I
         g4v9PSizwFhuOYbiTjF9Ft/hIhQYn9/giPbTv6zhsCM6OUZMooREQcbA87xno8NJd3nP
         kQLNukWTW6r138xgBhk+8esDJvPu51qg3H3s3OdGEzVfWhheHM/8SQSAF6FUHAC7W7xo
         AJuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVB4WhnT7c5LyG8eXxo2OGOIv3XOdc+fkGpQOfux2ExXpqimhoSZvL7g2fsULUnZ6G4aLo7wQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzt5g+BD2UYKceG33f+kT4Kc7c5NkK9ZnBoiatN6cwsj3uwV44f
	VOnGbsN9vA+8N6gNSApJwEoTZreshNNsaSsc2QKJXgbTqVCOejuC
X-Google-Smtp-Source: AGHT+IF5VmRNG1DzzJLSsI3iZfAvCZLM4TvcEH6HNQwHUNonTEV5icRRj1Bvi75mZYqFZMdfvLpMDg==
X-Received: by 2002:adf:e90e:0:b0:37d:4833:38f5 with SMTP id ffacd0b85a97d-380611d0aa1mr555684f8f.30.1729889847487;
        Fri, 25 Oct 2024 13:57:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c90:b0:42c:c82f:e2f with SMTP id
 5b1f17b1804b1-4318a28eb2els12188175e9.2.-pod-prod-05-eu; Fri, 25 Oct 2024
 13:57:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2VLIbMG/f21r+3eShX8bSMJEqgXh+VzcHXhr3t0d2EXLCGywbynw4TjrY4k8TVOCPABmDBHzNSF0=@googlegroups.com
X-Received: by 2002:a05:600c:3b8f:b0:431:4847:47c0 with SMTP id 5b1f17b1804b1-4319ac6f8f8mr4735895e9.7.1729889845595;
        Fri, 25 Oct 2024 13:57:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729889845; cv=none;
        d=google.com; s=arc-20240605;
        b=dOz1kSOmTcGV9kj+c52v415IBonyJD6AH7Sfst45LLBLk0oMocotNawP2yIYYhU9r4
         rp4crfy23ui929y4aJOqIgK6z/Nk8HVVY+H6J208iYw9tjW74NMXZp/daHszMsgFdKNl
         vWaiQzpH6BCOl8hjiL4X/GDjjdFGKyVSDFI6+85Ef9qmUsBHnSDe9ezYUY63Z6JNznoy
         f/6pLAxZbsO8vWv1OagQPaO9meUTDWY8powZ7URB+3PAACHfThNKwJ+lRHfKJPhNBPNx
         49DdWGs6HKy4o8FS/Tv2epDMRO9QgasdpK7hh4hUgMUKyAY7pH8SKpOLh0I1hPMPycAi
         7omQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hNPFlVbZVA/OKJ3932WwecR37g7+EI0egSRr36/qweM=;
        fh=Ou+/76NcSSuS1CcHvcVjpaKJPpPCjlgMY4+9YaZ0c0E=;
        b=B3BVarhLhvE9wjL5tWmA/TZVSZxTA3RlXC91AMizVd4XG1xk3aHHjJyham4SGxxsdL
         Kmc8AH8VDfX1dmUmetegUBbkAgucuBXjo8L9iX0MLJL+wr/SNqpbVefylla1VgYpFgK8
         zK3NZkuaJHo4a486xBbw+Gw09c9NVJykmwloh3D6mcCnwBDkEP9CT1DICtPLawVRDkfL
         nK96cswIoqhUw5Wv1W+Mzpi0ko4QZoXAmjsK5IV+fernvNuI62HmXYTS2Nc8nnEKDY5C
         sGOC7zvV/fisuBrtCIbDsz1aHq9p+phLXF2pG1iOTpo9BWSkOXbJ4tJjKRqOErqrVeoz
         ME0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=WWMTfyl1;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4317dde0840si3960115e9.1.2024.10.25.13.57.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Oct 2024 13:57:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-539f2b95775so2888633e87.1
        for <kasan-dev@googlegroups.com>; Fri, 25 Oct 2024 13:57:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXo73G5AdI8L2x7/9kLGeaS+hi96nclfGYDlCgriIoe+H7AQDtwvfaTZNQdC6MPgjMiBDGGT+yhD94=@googlegroups.com
X-Received: by 2002:a05:6512:3da8:b0:535:6baa:8c5d with SMTP id
 2adb3069b0e04-53b348cbb72mr418498e87.20.1729889844751; Fri, 25 Oct 2024
 13:57:24 -0700 (PDT)
MIME-Version: 1.0
References: <20241017-arm-kasan-vmalloc-crash-v3-0-d2a34cd5b663@linaro.org>
 <20241017-arm-kasan-vmalloc-crash-v3-1-d2a34cd5b663@linaro.org>
 <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com> <CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio+hVP52OBAJP0A@mail.gmail.com>
 <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com> <CACRpkdY2=qdY_0GA1gB03yHODPEvxum+4YBjzsXRVnhLaf++6Q@mail.gmail.com>
 <f3856158-10e6-4ee8-b4d5-b7f2fe6d1097@foss.st.com> <CACRpkdZa5x6NvUg0kU6F0+HaFhKhVswvK2WaaCSBx3-JCVFcag@mail.gmail.com>
In-Reply-To: <CACRpkdZa5x6NvUg0kU6F0+HaFhKhVswvK2WaaCSBx3-JCVFcag@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 25 Oct 2024 22:57:12 +0200
Message-ID: <CACRpkdYtG3ObRCghte2D0UgeZxkOC6oEUg39uRs+Z0nXiPhUTA@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] ARM: ioremap: Sync PGDs for VMALLOC shadow
To: Clement LE GOFFIC <clement.legoffic@foss.st.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Russell King <linux@armlinux.org.uk>, 
	Kees Cook <kees@kernel.org>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, Mark Brown <broonie@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Antonio Borneo <antonio.borneo@foss.st.com>, 
	linux-stm32@st-md-mailman.stormreply.com, 
	linux-arm-kernel@lists.infradead.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=WWMTfyl1;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

[Me]
> What happens if you just
>
> git checkout b6506981f880^
>
> And build and boot that? It's just running the commit right before the
> unwinding patch.

Another thing you can test is to disable vmap:ed stacks and see
what happens. (General architecture-dependent options uncheck
"Use a virtually-mapped stack".)

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYtG3ObRCghte2D0UgeZxkOC6oEUg39uRs%2BZ0nXiPhUTA%40mail.gmail.com.
