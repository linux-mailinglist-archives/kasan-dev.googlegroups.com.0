Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSGMZX5QKGQEH7KXCNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id B96DF27D3F1
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 18:52:24 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id l17sf1979626wrw.11
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 09:52:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601398344; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ZrFpcgJ4Px39fgs5kePjzinPocUvPXA0OxZmrkitG685dG/qvLbGaMZMWH8iYvwYQ
         c3K8QMBrIRS+Kec6rZnwdnL2Ke9Tnmrr2TfFxSBr8JNaYhvJIjmhukVDaXCSY18N2rmP
         I5QyGf/3jMLZ4mSrAxZAEBP3ACZZ8l63Lr+VTDbZWMpR3vI4Bl8sPJvc1wXpi1wmONHo
         kpg3mXyy0nn7Mf6mPGx0ccQn7yoliWrbfW2WbtDbZlIvIWYUwkUe6JQeSJKkPM8RF3mS
         ncVWPJaFgxaES/EdQY0B4lr5A4X2+vas/ujV8XxuaRjI7mB84jzee0xJOZrhCzLcr8tm
         xyug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R0lb3V/UUn5S0ipbcieUYRmVyEENbP5SJQdxqYesO3Q=;
        b=YJMSTCwBO3PdJxeuPihV94thx1hFi0y7/SFM5KEnVnSoqsYsKrFNWq1MoiDwGk2JlI
         91AADRcqhIiaH82gEHsKur081gubmeMLTUJ8cetweRgX0MSgsrGyS8ARMlw+pCEKtaeM
         MzZbms8KzyrL3ASIDQ/ZeOCwY38MohCF6h6FcsVOMXATW/3Yd+IQgMhug6IEoAOWRbr3
         IyBqVfSDgG5j8dpbalpLCR2o4QfqM4XrUCLL/pT82op8Q3BDm5f7R4lYD2LjLakOlaIl
         x4HD5F8gDo8TiltaJ1DWjPYxQUHKDG2nEJUQwg2IYPrHfs3J6Q1yNw68iZMEFlJ0JFTa
         YLfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VqnhGR7e;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0lb3V/UUn5S0ipbcieUYRmVyEENbP5SJQdxqYesO3Q=;
        b=Nfp3v5P6xUHDRXspWMYMX5/jl+D+hYyH95q7v3LDyDmzjHaWkEEqx4rKQfNooyLmV5
         F/PQ5X31m8zOitOKnDra58V+Q/sJqeSyWeUwUC0ICr2UO8JMhdWgpa8pZVy2yLtf3vJO
         VJ5hODZNVdq+BKbf3VDJJ+AXA75nnYQQgRjYQs9eM1rHPKoDT4KU3MEtEOPwr/qrwqUZ
         aX0TR9OQW0IjfMhTrrRleBre/WO8Nll16eidswXQi+e8Zr/rz+ZGhKZvoDRHe6iJ7jz6
         CMtsqBn6jd45kknddH0ahBNlFRF/qcjU4q2bz2v+IrEwRvd4WB7SD7ixKHWKPeti9VRF
         J/3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0lb3V/UUn5S0ipbcieUYRmVyEENbP5SJQdxqYesO3Q=;
        b=o+m63yhqHWyQE5+disHhGu7iuTRS8CuNBTIY084GNijXxHmtgUkgvYGUn24fGQL701
         uNUQxm54irXQ8fR+eOUiOroHzvXdh2U+LPU4Ef5MyyEA0lDCk7bGBG8DwQmvOf0iEJ6t
         KV10CoG5LjxJUMpIqUlnDF7qbAceM8k+rONlMs2VxWu56E8U1x074vFiC1tBVBJTfdl/
         3kJv4KoQtWMKPe+2/2peKJDwvuYynjPk1hVy9eOvwPLmCEQTqJLNELxfe4GwIRS70fzy
         +yyN+OCzCRPQEC0hLEH6lYr0VMnvGwcSkpIGI8mbtk5gpIjgEy0D4gXvI9b2M6psQJ3j
         y7jg==
X-Gm-Message-State: AOAM5327KGTsG/kjksEtyJ0JiBqK/61TM3KpJq5ibO8p+itDB/tx2U9h
	jMx5GayxKF/fw8d6nqaT3us=
X-Google-Smtp-Source: ABdhPJypNH/gIsii9vWK0X2N4cx7vQ6LM64Rln3cgr2aUKNmrllMaXIMu9UJLzIv2kRL9dWAsb16hg==
X-Received: by 2002:adf:ffca:: with SMTP id x10mr5765055wrs.342.1601398344500;
        Tue, 29 Sep 2020 09:52:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls2357859wrx.3.gmail; Tue, 29
 Sep 2020 09:52:23 -0700 (PDT)
X-Received: by 2002:a5d:5312:: with SMTP id e18mr5629519wrv.95.1601398343686;
        Tue, 29 Sep 2020 09:52:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601398343; cv=none;
        d=google.com; s=arc-20160816;
        b=gXvggnR6ydh5ovF8ir4LWZgIIdk3c881Eh/z591iguWqctsFRY7Tk03hvt66+ZjrYr
         +HVmwjrdVeVC3MEqqRxI61EsNiyfyA5E8wiKpbcJ/MoglkfKxqvRAeN/2phVro3HEWi7
         tXiCHQos4ZkYGHdriXtoH9IfzeJ9PthUak+x8Y/ne+86szVIIDSgvpY3/wSx0kQPmFgz
         dCL2K4u/Q1LyzikwKss2f91BBQtLKIfChKMYiJjjhnZgt9rgpUf3mvutDxiHTJtFcOgZ
         zG8myCvrOE7Wb8UDEJozycDOrf3tXTDnW6DXIzg8c0vqUGIiI85SarL+7UC4WsWBfWfK
         JtpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=09UR9SuLwWLskf/m2OzcloavK4YxVGusfREn6SghSM8=;
        b=wU9bUrSjliEzViszywCx4Kb3dHWXl35BOxkkI9APZxzvysdrC29P8dO6+iUQT97Vmi
         JZTF+PenL73PhRoZA8lVZHCH96aknUMZ7XZ9vWx3KmHKiksoRDUyhTZcDOBQwZBp4JJT
         jkWJPc5+WKgjVz6NBvD/5DClNpoA/iPIdZC3fewg3NMut6Jac2vatDcr8oFKGnBVRWC+
         Z+TsXs5TMArVUYtH4qaTNjT91REPENqcmWvPrtXdU4hQyWI/aYboh/oGfWnWcan7BMBg
         vW/xNsim28fbR1kDystQwDv1AN+A6xgX9tGVmpeyamrTYxJH8T56LZ2IpFPMQZo4ptsb
         SBTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VqnhGR7e;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id d19si125607wmd.0.2020.09.29.09.52.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 09:52:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id e2so5564679wme.1
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 09:52:23 -0700 (PDT)
X-Received: by 2002:a1c:b388:: with SMTP id c130mr5533839wmf.175.1601398343136;
 Tue, 29 Sep 2020 09:52:23 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck> <CAG_fn=WKaY9MVmbpkgoN4vaJYD_T_A3z2Lgqn+2o8-irmCKywg@mail.gmail.com>
 <CAG_fn=XV7JfJDK+t1X6bnV6gRoiogNXsHfww0jvcEtJ2WZpR7Q@mail.gmail.com>
 <20200921174357.GB3141@willie-the-truck> <CANpmjNNdGWoY_FcqUDUZ2vXy840H2+LGzN3WWrK8iERTKntSTw@mail.gmail.com>
 <20200929135355.GA53442@C02TD0UTHF1T.local>
In-Reply-To: <20200929135355.GA53442@C02TD0UTHF1T.local>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 18:52:11 +0200
Message-ID: <CAG_fn=UzvZfOzKEnc_ouqchNcg359yhykKc3tDTYdPhMAQooSQ@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, "H. Peter Anvin" <hpa@zytor.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VqnhGR7e;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > On x86 we just do `char __kfence_pool[KFENCE_POOL_SIZE] ...;` to
> > statically allocate the pool. On arm64 this doesn't seem to work
> > because static memory doesn't have struct pages?
>
> Are you using virt_to_page() directly on that statically-allocated
> __kfence_pool? If so you'll need to use lm_alias() if so, as is done in
> mm/kasan/init.c.
>
> Anything statically allocated is part of the kernel image address range
> rather than the linear/direct map, and doesn't have a valid virt addr,
> but its linear map alias does.
>
> If you enable CONFIG_DEBUG_VIRTUAL you should get warnings if missing
> lm_alias() calls.

I just checked that on x86 CONFIG_DEBUG_VIRTUAL prints no warnings on our tests.
virt_addr_valid() also returns true for addresses belonging to
__kfence_pool declared in BSS.
Could this be related to x86 mapping the kernel twice?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUzvZfOzKEnc_ouqchNcg359yhykKc3tDTYdPhMAQooSQ%40mail.gmail.com.
