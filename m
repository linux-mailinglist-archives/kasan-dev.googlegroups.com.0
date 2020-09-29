Return-Path: <kasan-dev+bncBDV37XP3XYDRBBHZZT5QKGQECTSRCPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id C4CF827CFFC
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:54:13 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id 60sf3003260qtf.21
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:54:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601387652; cv=pass;
        d=google.com; s=arc-20160816;
        b=tadUbBSNA93TKopsJOU2UQUaZNZTwIAp2wkuAjoqBVNjiv/JHMsh5eql1DFcFQGaoU
         3vZnH0Mqo9X0qs72FzW9SyMBA2fbAyzuUQYzfd2X1NgjTleKopyRO1etB7i9pvWH/qA4
         XNBtynyR5ztLqd+Bdr2YOpULTK69jlGJtZv6naUVoFnc0SIVtVIogrvSQPq+dsDkW9bc
         j52heZbV4dIMwdQAhB6lA+kP7yoYjB5AgNOmR+Canaf74e1UjdrDDhpKY3AtiXg0l16Q
         FUP4fcWjyuYn7OoN0vkneo10RqzfusT96HTJtiTSl0TXC0cw1FJaXBHyeROJeU+d3K06
         1zaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=y/NEhhT5jbmfXNd08VrbOrsucioYjbl2xMfSukTAkZo=;
        b=cuvbOs9FVN/+78DpucdekQrWHWu7lsKhqquxpFCQNFyccQhgikGzl9xWScUJFSxOQg
         T2PLcGXH/asskaaHduipWjTL3O7q0vVTk0pyVmZJi0KAyJmzI32US0amufWnJLoeA4Z/
         zH+/8vyjCkYmWokdmRRbXM/gK/Z04eaWV6+udDC/OncHcj1vUurB5XHfI8C3edM+F7d3
         mttoClxREM+njc//d1L89aV67TYbMT1wuY7qW4y9Vrh6WS+STol8ADlTLYFK74reQtin
         /4BOzagnCqCKjo9RWFUUacpom07KPWttm5PiqEfOPUCEbySIxPMoKmRqCslYeaDqXJQ2
         xEPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y/NEhhT5jbmfXNd08VrbOrsucioYjbl2xMfSukTAkZo=;
        b=XweTqf2REOOTrk6UPvNPTPw7T///CLaISqJi8yEvp2lG/IhTILcq3oqdYRBU6W5qUq
         LXVhNPmueuR+CJgbmLfWoXD4hq+iLTP+KlGKD7yPCYjLKwYF2XaFo340SL4/PLIRNMym
         X6hIg1FyDDbzrSxf8hW897gdEeQlJPHWLhXtMSn69BrS0l4hXawDqj0jzpWzgQmCudZ1
         ps2FvRmcolMZ52J3i6Jkk8QU9b5WMmHLUCk+0Pzw0wPUz08zPQ7h1VrkHqsC0uYccvBR
         pdlcHQiShVQwxN3pEOWOOgoiC7UOlNr37ZnV2auOX9EWhWMcvEewUvhSVfUl5N0RwSg3
         6vkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y/NEhhT5jbmfXNd08VrbOrsucioYjbl2xMfSukTAkZo=;
        b=Yllv0K8qpE/FdzMuMpFwY7qDOuxZSOEC+X0+jCaIWXBCwLofim6HIl9O9ZLsLy1idB
         l3c6a95aNZS1NrJoHarUI/IlNHsZA/Hopud6IbH5R6ean5yg75/GVAoJ6zZboRPYDo9f
         VKT4GbsN+CGW0ihCMLMjCBsmCW0MyoQQ2J32yCSWAUepRX2UBODF4QCwNB17BDghb0dy
         lXQ7XwLrYBfVySqlJSQxq5nUIVQlBAuKuKCSJaZ904kVlUHDJVuHgeyKxzWldVIfBwiz
         K20oM6FFDj3CXnwP2CUWhntVgoMDhhSOAC/oe4AlYpeXqYh0bZFrQtK3bDSvO4fdShSn
         FGdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533wgkvutKvNRpyWoYA3kieOTNrste7PpC4jBMLJ+p8h9b7OOyai
	Ct6pCNIHu1c7dvQq/gl5deU=
X-Google-Smtp-Source: ABdhPJylX6k4lsg4T5T1m1jAEUujFC2ODEIYvtuj1UhB4koNnpo+XrpfxGhomPMK45NKiRVrXbAxxQ==
X-Received: by 2002:a37:6307:: with SMTP id x7mr4449845qkb.455.1601387652602;
        Tue, 29 Sep 2020 06:54:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:136e:: with SMTP id c14ls1121821qvw.10.gmail; Tue,
 29 Sep 2020 06:54:12 -0700 (PDT)
X-Received: by 2002:a0c:b29e:: with SMTP id r30mr4710323qve.38.1601387652048;
        Tue, 29 Sep 2020 06:54:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601387652; cv=none;
        d=google.com; s=arc-20160816;
        b=BLG6AjzraWMAqeBtrjfYTaTRXmxDSbOZGOebzb2hTL5Cpr52ttNPWS10EmBL5ZXCk/
         98+fMYnfIMp72580Fv0Sql4+sr31MP7/TF3qqhushAHeQoeGryhkEWK4IWLU23/hztWM
         MAPZehtBsbF95LUHb9RZwqBXiZYPhZiQqC2CizKH1KUQHsTCvLCRX94ZusZpFQ6yA9Qx
         lkMluM9FqMhOmtw0DKhwMarXA6aTLRa1MHB44Wy8/ZkwwfsdaesrWvQClE1Jd1/zOhWi
         5sAvOPZqdmBCYfFcNL4N3zmlb8qUjsVHIeR61coyxB0TM8pGwovul1TtwQIkMBuQ1GDu
         9I2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=clGy5pe6mK14zjSjlyF+zDyIrixkDjERu3gsuDA6Cq8=;
        b=Fca1EUzx78rI+fotJkQEYDpNwdzygelJJqiEHAxDTKQL8AZiCnqJVHAORswwZQ2eL8
         IZmn66zS2bUpTRLwiJO9BE80DIIniGUXifaaAmYcpla/ELVqBgrqIZ0Xh/UYMHm92BWP
         sfj+3CMyUhwgmrqfNnsjt8Qa3DTxSrRMRRcQkI4rbGtnTdgBFrf648MGz+0t1gkXk/l6
         dgcku4uNNlLSCbWH33gFoHprW85CMDqKoPEz4RIopczmPJRtQYfKRte/1VJrzvvu3Itv
         7nKHZEyByjxX4OCG9LVuWS58H7ash/8HjzposIhj21CXsZ9I5XDNCLZRILC0uicLH/63
         7v2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c40si352260qte.3.2020.09.29.06.54.11
        for <kasan-dev@googlegroups.com>;
        Tue, 29 Sep 2020 06:54:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4BCA931B;
	Tue, 29 Sep 2020 06:54:11 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.69])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 055C73F6CF;
	Tue, 29 Sep 2020 06:54:03 -0700 (PDT)
Date: Tue, 29 Sep 2020 14:53:55 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Alexander Potapenko <glider@google.com>,
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
	Jann Horn <jannh@google.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	SeongJae Park <sjpark@amazon.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20200929135355.GA53442@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
 <CAG_fn=WKaY9MVmbpkgoN4vaJYD_T_A3z2Lgqn+2o8-irmCKywg@mail.gmail.com>
 <CAG_fn=XV7JfJDK+t1X6bnV6gRoiogNXsHfww0jvcEtJ2WZpR7Q@mail.gmail.com>
 <20200921174357.GB3141@willie-the-truck>
 <CANpmjNNdGWoY_FcqUDUZ2vXy840H2+LGzN3WWrK8iERTKntSTw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNdGWoY_FcqUDUZ2vXy840H2+LGzN3WWrK8iERTKntSTw@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Tue, Sep 22, 2020 at 11:56:26AM +0200, Marco Elver wrote:
> On Mon, 21 Sep 2020 at 19:44, Will Deacon <will@kernel.org> wrote:
> [...]
> > > > > > For ARM64, we would like to solicit feedback on what the best option is
> > > > > > to obtain a constant address for __kfence_pool. One option is to declare
> > > > > > a memory range in the memory layout to be dedicated to KFENCE (like is
> > > > > > done for KASAN), however, it is unclear if this is the best available
> > > > > > option. We would like to avoid touching the memory layout.
> > > > >
> > > > > Sorry for the delay on this.
> > > >
> > > > NP, thanks for looking!
> > > >
> > > > > Given that the pool is relatively small (i.e. when compared with our virtual
> > > > > address space), dedicating an area of virtual space sounds like it makes
> > > > > the most sense here. How early do you need it to be available?
> > > >
> > > > Yes, having a dedicated address sounds good.
> > > > We're inserting kfence_init() into start_kernel() after timekeeping_init().
> > > > So way after mm_init(), if that matters.
> > >
> > > The question is though, how big should that dedicated area be?
> > > Right now KFENCE_NUM_OBJECTS can be up to 16383 (which makes the pool
> > > size 64MB), but this number actually comes from the limitation on
> > > static objects, so we might want to increase that number on arm64.
> >
> > What happens on x86 and why would we do something different?
> 
> On x86 we just do `char __kfence_pool[KFENCE_POOL_SIZE] ...;` to
> statically allocate the pool. On arm64 this doesn't seem to work
> because static memory doesn't have struct pages?

Are you using virt_to_page() directly on that statically-allocated
__kfence_pool? If so you'll need to use lm_alias() if so, as is done in
mm/kasan/init.c.

Anything statically allocated is part of the kernel image address range
rather than the linear/direct map, and doesn't have a valid virt addr,
but its linear map alias does.

If you enable CONFIG_DEBUG_VIRTUAL you should get warnings if missing
lm_alias() calls.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929135355.GA53442%40C02TD0UTHF1T.local.
