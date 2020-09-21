Return-Path: <kasan-dev+bncBDAZZCVNSYPBB2GMUP5QKGQEQQ3WFAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 11FD92730FE
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 19:44:10 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id n9sf6717737oib.7
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 10:44:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600710248; cv=pass;
        d=google.com; s=arc-20160816;
        b=MIGHO4bwc8GXYo5aMOzZGttNoAj8ggLfv/QYt7IzTLdc7fhDItaCajSKLA7JlfUJhR
         5n1XSwdXuDfvDYpK6KI4T991Xt6/35oLUfO79AgZ2rJWJLjUXJxhjc5t4iJ4G0IW+VEb
         a94NyJRicmKBVVqSBJcrrAqvQmYhFU/SHy5xm3yN+qhYaL6kr9snvvkb42vKsZiZLD55
         anpPAnvk9gW+gTJ921PLifDkmK2MjrlJFxYWhQ25ZSBJvNmFzL+ydPd+Fhh80HIAl7fa
         +Ga1x31ar4cebXsBtMQNwZG6vh2HonVcd83G+270L99Ca1mmD97ixjh4oLxnWaDc+K65
         TTuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=d9IrUDdGAksxAmFZl6dkdp0wdmkp4iTkssd3f+iw164=;
        b=alL15h+zUGvzXSVAPcHcsyonq15/SAk5xuM4f77VuYyAunOk8BXqE7+UVv2GGeQoe0
         qD8swQad4hGX+dPu8YCpl3kp1UfROSEJGDorpMdWApwb3p3IMhicSWT32cYVRRmPrSm4
         ITLOK09gNAXXbEXIOnmjOLWkPFCDIABwIBX1oedfISt98Sjb6SZpU/K4acnD1u2tDOa5
         AF7GANlSsQ0FUPjEolbaCObvRCtRpJHuZwuvbgBUZguSh9fu+t557QMucc6rwU9si9mV
         O3WrV7m3jzAp0I3dJM05dumYugAspVMauuXw0qGcQKNt4G9I+GouxFtraxiAmrbL9dIh
         pPhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xdj8QUY3;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d9IrUDdGAksxAmFZl6dkdp0wdmkp4iTkssd3f+iw164=;
        b=aLaScXcjLUpUqp/ui9cFFu5iF9seYQ62DQ428yZfU/b1CJCaTgQIAQWrukvKAV6vpN
         BXO3KuIFcdakbvFZtd1sABOgsWlDRdFg3Y0KTkNXMKDUkjUsJK+qsGfUsMgJDMBX7r0N
         4BlJGnqhpjNu0KlqdB3bl2/qvBU9G81561LDiDQDkCZo8vKTqwivQE1f6wHSuvJL+mPh
         +G1/FfVrgedYuprsdCdHgyAzi9yoGPD0dR2ZzjKy7JtOLTkXlrxOAb8Cs5wYzbCFUaMl
         aXOpYfhghrXuqh6JYLd/Hs7lwVABxYYfgEYaGm2D/n/mS2OuhHyosYOVb5ZdYz32UgLw
         sh/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d9IrUDdGAksxAmFZl6dkdp0wdmkp4iTkssd3f+iw164=;
        b=ulnuHBiQKW1BPalMFmEPu0EZzus6AxBbKXWYLoQpLVxiKNLaJDrCHgCneLlB9ZuDtL
         A9OKJllMd7zcFsz7wIYMPJ72TA02BVY9vNtrN+i6ljYtHpA8m/MssL8ncBTqte9MzVuO
         /emwO/B0uCic4v30Irv21K703F/E6Ht8GjV5OdS617xHHXPED1exwhEHKgejZV1U2ss2
         oX+TlX4QJzZa1Gep5y19x5uEfRZcoUnaC16mYwkMqVxPIOdW5x2cO7sKD64TWjMWcz9u
         0d2RtKEdqVTIivyyP5Cloy2TWQfFhj4MuERZVPEyVbLIaQY0YaVnnDy4p7+IKlTMCd5u
         obDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336gkBwkk5+YsZ19NpoCR+V5aePAKnJo6PObzlhEygqVaifaIkU
	s9ZqTa4AN9zqdYE3JR9wyjA=
X-Google-Smtp-Source: ABdhPJxc/7HcIdEHSj2NRa+lqme86ZWy2ObtR77hSlcmNuvSGr+QHUxNg9UPyMK7UQGx0HlNfP+2qQ==
X-Received: by 2002:a9d:4818:: with SMTP id c24mr441495otf.128.1600710248800;
        Mon, 21 Sep 2020 10:44:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f0b:: with SMTP id u11ls3062891otg.3.gmail; Mon,
 21 Sep 2020 10:44:08 -0700 (PDT)
X-Received: by 2002:a9d:4c97:: with SMTP id m23mr416516otf.218.1600710248301;
        Mon, 21 Sep 2020 10:44:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600710248; cv=none;
        d=google.com; s=arc-20160816;
        b=jigooUBwVaR/4K90ityCdxMj3iAI7UpZsDgKBhRzRWgjtiUHhmjT2VZ2tdpU670Yr0
         SjGQ/z0L9ASBWj0tYU1zd9ms/JTeyQP+W29dA6cH5p2vPCByyoC2tzzxPSwCvQbtLjG5
         R8QNFdxkuArsORFjmJg6jj03/V3a+/F0VT7AMsegYl6je3jjIsskM9AeY7Tk76cVzsSg
         xi2FXkNPB5fXoiTtEP1poLSC66rbZPAW7aPRmY5KFk3CPBh7qTqzzf/o4ypXyVwXZY3G
         hUNzBv8TvFTNJC6uRXu/+I9UtBBcu07heA7M5oeWjaxsCluZllY6YifsO7jnUhTuVxyM
         1pXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=k3ZAse6fBHZTtGXuZq3UGtFKC8B+GnwZPbMc364KEqo=;
        b=sKGDFNp7OW14ePzz8tBzMN0qdoM5LXhIRAoNYle7hGhh42d6hrHGRSMPqFYDxMBjqP
         jSBG3UYtUyXUYotjq0x01LpJwwGA/CID+8a40B2ISsvubhlm1UTR7vQf4MnG0hh/3lfB
         WZ15n9rhGE4D04vJYY1nn7OeOZFIV1ENzQtdEFq6xOX7KoiTBgwEx3SeNbxf+D4d0k8u
         eGQcs5gp7X/tPUU47CiwRztdBc/PcahEtd7SpO1nTstnY2WPWDNrwTdnRhHPLd1KlewM
         P5WMHQfXnV2Z1IrDDM5F+GRyhQlWn4dNGHhc+wcHZCQ7iGP+Vs/q4+ZoIlOwHfQK1kYE
         gIPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xdj8QUY3;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i66si7069oih.4.2020.09.21.10.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Sep 2020 10:44:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2313C2151B;
	Mon, 21 Sep 2020 17:44:02 +0000 (UTC)
Date: Mon, 21 Sep 2020 18:43:59 +0100
From: Will Deacon <will@kernel.org>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"H. Peter Anvin" <hpa@zytor.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitriy Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20200921174357.GB3141@willie-the-truck>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
 <CAG_fn=WKaY9MVmbpkgoN4vaJYD_T_A3z2Lgqn+2o8-irmCKywg@mail.gmail.com>
 <CAG_fn=XV7JfJDK+t1X6bnV6gRoiogNXsHfww0jvcEtJ2WZpR7Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=XV7JfJDK+t1X6bnV6gRoiogNXsHfww0jvcEtJ2WZpR7Q@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=xdj8QUY3;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, Sep 21, 2020 at 05:37:10PM +0200, Alexander Potapenko wrote:
> On Mon, Sep 21, 2020 at 4:58 PM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Mon, Sep 21, 2020 at 4:31 PM Will Deacon <will@kernel.org> wrote:
> > >
> > > On Mon, Sep 21, 2020 at 03:26:04PM +0200, Marco Elver wrote:
> > > > Add architecture specific implementation details for KFENCE and enable
> > > > KFENCE for the arm64 architecture. In particular, this implements the
> > > > required interface in <asm/kfence.h>. Currently, the arm64 version does
> > > > not yet use a statically allocated memory pool, at the cost of a pointer
> > > > load for each is_kfence_address().
> > > >
> > > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > > Co-developed-by: Alexander Potapenko <glider@google.com>
> > > > Signed-off-by: Alexander Potapenko <glider@google.com>
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > > > For ARM64, we would like to solicit feedback on what the best option is
> > > > to obtain a constant address for __kfence_pool. One option is to declare
> > > > a memory range in the memory layout to be dedicated to KFENCE (like is
> > > > done for KASAN), however, it is unclear if this is the best available
> > > > option. We would like to avoid touching the memory layout.
> > >
> > > Sorry for the delay on this.
> >
> > NP, thanks for looking!
> >
> > > Given that the pool is relatively small (i.e. when compared with our virtual
> > > address space), dedicating an area of virtual space sounds like it makes
> > > the most sense here. How early do you need it to be available?
> >
> > Yes, having a dedicated address sounds good.
> > We're inserting kfence_init() into start_kernel() after timekeeping_init().
> > So way after mm_init(), if that matters.
> 
> The question is though, how big should that dedicated area be?
> Right now KFENCE_NUM_OBJECTS can be up to 16383 (which makes the pool
> size 64MB), but this number actually comes from the limitation on
> static objects, so we might want to increase that number on arm64.

What happens on x86 and why would we do something different?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921174357.GB3141%40willie-the-truck.
