Return-Path: <kasan-dev+bncBDW2JDUY5AORBNVH5XCQMGQEEA5B4FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AD60B46562
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 23:18:47 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45b98de0e34sf20961565e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 14:18:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757107127; cv=pass;
        d=google.com; s=arc-20240605;
        b=VTVT2zlfkvAu/4R46+piVqcIZ5HknAnEwnnfxN8YONn695nXIdm3yL+isz3OpxkVu/
         qTb1Vnu3e1Z9ixtMJCCgMBTVR+ZzveLqYUgFkKiBRivryU/0fGf+DPxfNvNsUJcNHIJ6
         2iCG96L5GwsXuBUNeUoWDGrWmAE3J1z0bc8gmLrAucmqAlVEI8dPMjPvgN+zjwwexNdo
         5mHvgm/rSIiLp3MJQiZektdzTAgNG9yP73xu8zOLoWcmyldzCYFHtqF5S+98Sw5sule7
         SOhaAIvWwDCBU2gYq1BehDpxQkq+WE6eI8vXvFYfzzfhJZ+d1b6esEdECUqB7uG8RU7t
         bWeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=576Ioo986pVxHeSGh1NVgAkXkIS7A9ZaO0bCNC3xzjw=;
        fh=3pRVi0nuNPT29PN18OyMskiGXeAsz6IICE6bfndtEE4=;
        b=VFFRECxLj9mfZmyUViqUn41Hj1mEJxyySLnMF6JdEbB0/4tNHZDN011GITL1JL67a1
         gPU/YBo5sRAiS/ArdQ6910LwKr/85AkYa47EUWbmZjgusjkLsce9BqrTsFP5qQTvrkiY
         ECruArQdxiMBxIx7/v7NTDb0inVU+Td+3d+Rk+wh74ze5ZqTQwrR68McRwZP4FyBK70i
         Jv7eKpp5WN807PKREkzVGY/mnvfC7FyrkKhf4jqK62XoBWOAok5sY6iMa+hCuuwPRQSl
         EyOfLtiNm9OOiWrUEUdt4cWOO1u+/ekou5cnngUaMl/xZ4FzpbSb6Iphl3eD6WZBbHL2
         cBbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cYLgAOuA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757107127; x=1757711927; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=576Ioo986pVxHeSGh1NVgAkXkIS7A9ZaO0bCNC3xzjw=;
        b=HIgWURwxUX8pRWH9c5Xar0u+Af976h9w27xnq4UGabYbMjqO5DK+LUzoL6zUrE8ViY
         46Y1sO3LsxkCkK16W/eid/13j4w7BcFQ8XWwzu7Gyk9Fz9T18BjI2n9RG0khV8GkaEuo
         BAVaztXquN09Lwd1wF3kwMvRssuw5LDCDMcV/JWpmlEqSDz3sywbeYMv0ov6OU3pjE05
         3i7wUER90tjw2FSp7WyHBJjyiKIzz8fXFZ+VnyjngrVmarxSkekxm6ZOwJ4nD1E9bpyg
         uGHbo33qYhjFUiZTlrVdeilBsZrok5TPcf97Q4hfPeSx8QQWdEamEWit9cH9g62An3QU
         MM8A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757107127; x=1757711927; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=576Ioo986pVxHeSGh1NVgAkXkIS7A9ZaO0bCNC3xzjw=;
        b=SGiS7wxczcfqrau22oOPfQQcmZm9xsnGIhBfkTwEnd6/cwPhpKQSBJ6OaJATvmNK4r
         ZVaNX6RmESFrQ8vl9LGyl28FJU75cu097i/2VBkFif/Gs9cdfENxbKHTp6a67JibFoBb
         eZvUWvERu7urp8qNtZCg/BHZJetWhoXfTgxYWMoyQWkTF2HwAYcN+8bmxOgHemARsGF8
         E83WM77YCQTl5cQ1jtblRECXFopNZy18m+HsR2f73dvKBoJgU05cEG3ZKHwHuaRq3xBE
         pBmEUa/uklyVG3qGflWDEQMkzyJ7yENdzoQnM1denbtJGQNh/hCo9cAZ7BMR6zE4ekh+
         WZeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757107127; x=1757711927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=576Ioo986pVxHeSGh1NVgAkXkIS7A9ZaO0bCNC3xzjw=;
        b=mVYkfQlMr65nUm+p239ruGViUPU6jfAZIC5Y2V+rvL9Mzo/au0pjcOLwoV9syRwViB
         MqXYYqnQePiYyWa20nZ6IqbkOV2diTvwxy3E2WWusE1LgOlUVARe9QinIgQEvBBUMJNP
         LDS3NHvEX40VKKaHeBRe0VwOiBN063P8K6yOBgl4RsSIB3SynTLfn6E9yhe01KuT3R2P
         SQb9T8x9JWR7LErUvrHMyHaI7HbwxZOd8MOUA6s2PAcCB7e2iXR2I6aM0h5qPk5iI9Q6
         H0fdBKTZxYvZXiYxkS5MgvPoL+hEH6Ih/UxAbA4AY0YE8FYJAAf3IhoM6VU3yhNaLy2l
         0S/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWE41IQ8gKBB23KIUSAQxaTWcOpwBJ1ctDsu1yu82P/Cs6NXhGrNoLrMyfROAAd/IVm6c6pYw==@lfdr.de
X-Gm-Message-State: AOJu0YwdHWcB6qZWeyhCR3A/vX+hy3WgkqdU7NWfcj0m87YZhT0wZjTA
	YXSvlLuUFLsQ9+WOEPQS2HMTBnSYbtAdEU3yX0huPv9Z+7ALLOTibWa4
X-Google-Smtp-Source: AGHT+IE/H03lx/qLuThqCmMEBGXjj/XMP9jBt9gtUVXlyezrIii3XVuoYhGVxNBrz6yoTTaFy2uLZA==
X-Received: by 2002:a05:6000:40da:b0:3e2:b2f0:6e57 with SMTP id ffacd0b85a97d-3e642f91589mr26109f8f.36.1757107126687;
        Fri, 05 Sep 2025 14:18:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZds9WWZnWOa/gwzqJMVbVls7sLOQq7grk/O8v0DcntaZQ==
Received: by 2002:a05:6000:3101:b0:3db:a907:f1a4 with SMTP id
 ffacd0b85a97d-3e3b48980e4ls758477f8f.1.-pod-prod-02-eu; Fri, 05 Sep 2025
 14:18:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5jYxYWDhMvQMmgY4gNEnq9CbBDemnJPJtG1NR0SPdIgQrx8z7DUHB2kKqK+4bq//uIe/SMQlKIYk=@googlegroups.com
X-Received: by 2002:a05:6000:1a8c:b0:3ca:4b59:2714 with SMTP id ffacd0b85a97d-3e636d8fb41mr42567f8f.10.1757107123971;
        Fri, 05 Sep 2025 14:18:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757107123; cv=none;
        d=google.com; s=arc-20240605;
        b=cN+i1slRHUcVGUAyBVjL3SYz0x5YclC6Y0dRDnkPg+0UysFopijtL10OWz8XM02y+e
         SzX3SqyqETG05RC9UrhxqTSSylWQtjtydvstg4AmLx3h+uYjODku7/vn5ZH0+8uDAKVQ
         WVC9jCNrZt1ldb9Rvi6j45tZu+LYymVkJ3W1eKBuM9yfBzjLWaZMoO/NRx24dRCc7CAc
         QCqCMXL29GYWK9+Ds51Tj+LGjvZ4Dhwn5Y3+ufZyqEVRxsNdfUE9HXI5iYKEUFPdufWe
         yd+EUY+fRbnvsYD08IJL6ccWU5yUhwDWLu4myGguLIYToqeogQ0JPJXhAtfAp6uy91OO
         zYaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+ir+mQtnfx/4sLdud4ghKsNSgiyx0xtDI7KlyJXyioY=;
        fh=i/WcA/5edN+8og8Cey/2C5bwuKFR2oyMkgWydsSTwR8=;
        b=HP+aM/mb5Iyo+JfOKDhhlysMobCD+RrRw65ArAneYM7frQFXRBThuYLbrZE3Xhu1bl
         Gf+/a3znpPKslgAnbjJJckgLH3yca1BkGAhWGTTBXx5jeeQQNmii2ddloioTxnLSlvYZ
         eA5AfIHdzwRrJle1v3E5Vw5xLRK6ojIgkqhY/rgJDhqR/GWwJ68KW8VTk4vDMN2/ibfv
         0roSjQM4Kf11LUc7WHeFFqYpW2otgz/jKozkA3MIDJ/JNEoStuzrffpIpIsQfAXe8UYX
         7kAyKhvuNKMqWvELsIyEQjtJtJIiV7sqGWUnHdZI3ZeJtRG3B+eL3YeIF1vNnt95+qGv
         hq5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cYLgAOuA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3e278ac83dasi101244f8f.4.2025.09.05.14.18.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 14:18:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-45b9853e630so24036065e9.0
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 14:18:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUNh9zpqPTIY3smkQ9Yo7Yh1W9jkHXv8znL9KmX35w0m73dMaSMHOQpCDAC7mOe4hVNlp0HAgM2r5A=@googlegroups.com
X-Gm-Gg: ASbGncv2NCFsvMHcV6Kgtu/PRtYe8v0SIuRf2IDdtKlnoDgQypp7PoHZIfKdQ5n7CEz
	okcd7LElq79xVOyBmSTTX7DxdyhepKx2PQrRaMbdGHBOC05RhTslZ2qy6nJfPPD8hC3li0oiFWH
	qLyOFIrdItrjGRntJsD6JNNRvbxGo5ymc7OWi5pgdg8Rg582iNjMMd1JR9C90rzbPc61AYVyES+
	jkQvaAWd0qDFzvxUQ==
X-Received: by 2002:a05:600c:1987:b0:458:b01c:8f with SMTP id
 5b1f17b1804b1-45ddde8a55cmr3274575e9.8.1757107123278; Fri, 05 Sep 2025
 14:18:43 -0700 (PDT)
MIME-Version: 1.0
References: <01d9ec74-27bb-4e41-9676-12ce028c503f@linux.com>
In-Reply-To: <01d9ec74-27bb-4e41-9676-12ce028c503f@linux.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Sep 2025 23:18:32 +0200
X-Gm-Features: Ac12FXxfwzu8wekZMUNPG1-5QkyVVlkCYMyrLtAYUduk-8PvduVEITzaspdDKck
Message-ID: <CA+fCnZdQDDwkcd153qexNDP-61VAbB4iAJrj02UVtoL8KN2Vjw@mail.gmail.com>
Subject: Re: Slab allocator hardening and cross-cache attacks
To: alex.popov@linux.com
Cc: "kernel-hardening@lists.openwall.com" <kernel-hardening@lists.openwall.com>, linux-hardening@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Kees Cook <keescook@chromium.org>, 
	Kees Cook <kees@kernel.org>, Jann Horn <jannh@google.com>, Marco Elver <elver@google.com>, 
	Matteo Rizzo <matteorizzo@google.com>, Florent Revest <revest@google.com>, 
	GONG Ruiqi <gongruiqi1@huawei.com>, Harry Yoo <harry.yoo@oracle.com>, 
	Peter Zijlstra <peterz@infradead.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cYLgAOuA;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330
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

On Fri, Sep 5, 2025 at 10:11=E2=80=AFPM Alexander Popov <alex.popov@linux.c=
om> wrote:
>
> After experimenting with kernel-hack-drill on Ubuntu Server 24.04, I foun=
d that
> CONFIG_RANDOM_KMALLOC_CACHES and CONFIG_SLAB_BUCKETS block naive UAF
> exploitation, yet they also make my cross-cache attacks completely stable=
. It
> looks like these allocator features give an attacker better control over =
the
> slab with vulnerable objects and reduce the noise from other objects. Wou=
ld you
> agree?
>
> It seems that, without a mitigation such as SLAB_VIRTUAL, the Linux kerne=
l
> remains wide-open to cross-cache attacks.

I'd second the notion that without SLAB_VIRTUAL, the attempts to
deterministically separate objects into different caches based on the
code location or the type (as also with the TYPED_KMALLOC_CACHES
series proposed by Marco [1]) aid exploitation more than prevent it.

Many kernel exploits nowadays rely on cross-cache attacks due to the
high portability of the post-cross-cache techniques for getting code
execution or escalating privileges. And with these object separation
features, the amount of unrelated-to-the-exploit allocation noise for
a specific slab cache gets significantly reduced or completely
removed. Which makes cross-cache attacks very stable.

The only negative effect these separation features have on cross-cache
attacks is that the attacker has to use the objects coming from the
affected slab cache (i.e. the cache from where the object affected by
the exploited vulnerability is allocated) for the slab shaping during
the cross-cache attack (filling up the slab, overflowing the partial
list, etc.). In practice, this is usually not a problem: the attacker
can often allocate as many objects as they want from the affected
cache (by using the same code path as the one required to allocate the
vulnerable object) and only trigger the vulnerability for one of them.

Having said that, I think it's still worth working on these separation
features with the hope that SLAB_VIRTUAL will at some point end up in
the kernel and be affordable enough to be enabled in production.

[1] https://lore.kernel.org/all/20250825154505.1558444-1-elver@google.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdQDDwkcd153qexNDP-61VAbB4iAJrj02UVtoL8KN2Vjw%40mail.gmail.com.
