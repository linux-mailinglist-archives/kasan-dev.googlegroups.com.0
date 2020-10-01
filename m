Return-Path: <kasan-dev+bncBDV37XP3XYDRBU5X3D5QKGQENTDYIUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F36B28064E
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 20:11:32 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id d30sf3903057pgl.21
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 11:11:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601575891; cv=pass;
        d=google.com; s=arc-20160816;
        b=eJzCBPC1bZIkS3bmoueCETOlABVe9KGf8OSoEEcjdHMzZHW8EDPqLdwcvmRHq8dBqH
         ztFeChwfc8OmJiNBjbOLBwS4sboHuNl+fYD8KhMMVO/lV28C2WdC3ZFPU09yVH8pkR/6
         rq8YO1bZ1EIYuEN7bK7IZLCwPygDANqquXMeqWBngIK0+GGZqH1aOPsNzGVgcfNhi7x9
         eCPxJ3Qk+FSisfy2vJhnMTW1nZY7k4zPMwr5F0UBS8Zt+/nK0zah1yRA4CviNsGzL3/j
         sChRHfww0zAa5dzKIMzkm1wgQh45P6d9mIHukzVEv+fUbSUotpbmRRT0lBu95gDJaOW5
         tayg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=m6VBclrwTMdDFo4+vvMgLWOgVd+aHTuOBS5csJbPcRE=;
        b=J05hlQv+PdjPa76Hyf1Jr2UTZWIiVg8XP1Sq28W1ePTwWjaibClD3LZnwXNpTWSiv4
         SI5GxRFsppiwnkEJRCmvSiHEHukQ82S95MiRtq8KQcVe4OhNhyy1l7sap882QXVtckUi
         /zKUhZWwV9c0NWrZLfg0G3PqEv98VxWCs9GiyJ6EOPpnKscgpp15neSB+R1gfbNmQMOd
         ix336joUQ7DpL5BoaUspO3x73/i3R7olwull3QEj8gmLBzFtqzP6TVKXhmW6My0cxoX4
         26znXvMIgqEoIt14uEsfUcS/XdP4GhcgPKkpIBG1ExA2OgIB2SqXwxuKCWbkAGpZWulx
         SQTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=m6VBclrwTMdDFo4+vvMgLWOgVd+aHTuOBS5csJbPcRE=;
        b=OUdMGu+reFI06ETnBkjehR5ETwHlfDWvT7y0biPW2nt1zzzfmUUGxabeob+3crSGlp
         +/AWivd1U3tOGecC1lfe0Pfl6uQuVP3ADuq62QKSAT9q9tCoVD22jH6G74BY+gvhsOHd
         YA25R1CR/Evw4C1zLIq/sDGVKplsZOqgklEXAmbTFNz/+ZoXCaYvUl8lLlJkelwL4A7G
         tuFzUUfoJHk/9x9kkXoo76Of+Opi46BD8j4gRXxOHuQ4YLsf0iDSdL4f804bnWaT0pZ0
         ra7sWR3HqQdKEVDD6ddMFoKNdwQZT/jj7PIurNth+Pvv8iGcSe2fIb522mxPZ2Ykp5+Z
         hRfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=m6VBclrwTMdDFo4+vvMgLWOgVd+aHTuOBS5csJbPcRE=;
        b=V7lJqJyjbpQ09S/a6cd85A4rJLFgXH/PVDWxhvUIawCLcAuPBYzEK5cZ6vtloJ0HiA
         KeKQgEjBcLQ10EOkcyHT6/2egKq58BtMKuKlQ+C7nY7GrKkHNUh6FpIdcUIsFbHzrpxd
         2rvsApIjS2aZJvTs4kU7xgUYWB7FK/FuArCLo69P4CrnmY74xMMDPeo2Pi16BsacWDGf
         DTrG0p7XaRPI0CCqKI6LWSspg4SjvCW0RTypyhYU96DWMYeErISJaneHcGBglMIQjJl9
         ips8x0Flcf9nGS9YB+ftSbxeDnvGcXza05sVDmUIu6b+gxpjUDyAjrybUvH1WmaVxxXM
         iidQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MLY2idVIuenO/v9/31dZGtAsrROUk8Vsoz2DAMSw6DM1GaQbx
	jze4bLnbRe8C2KjsH9hMceE=
X-Google-Smtp-Source: ABdhPJygo7dBNf2x1zuvN+zSJfkimZUxnXynRDshKYCeINTxf6hbxRMKRCRaxTnixypIupitxctC0w==
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr1127041pjb.201.1601575891207;
        Thu, 01 Oct 2020 11:11:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f993:: with SMTP id cq19ls237802pjb.0.gmail; Thu, 01
 Oct 2020 11:11:30 -0700 (PDT)
X-Received: by 2002:a17:90a:5a48:: with SMTP id m8mr1128745pji.181.1601575890565;
        Thu, 01 Oct 2020 11:11:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601575890; cv=none;
        d=google.com; s=arc-20160816;
        b=00KqUghNN8IBv1xeHvJV2wg6WY5YYo8+rcaKHOtuyn14o/oRmj5a/H2meE9x2i2Gzt
         vK/u/MmeHg2maeDqxrZiH0WSuMZzG+FAxHCh2m/juk7bJBnANs3NJ1pAe7yL1uJ0XXzK
         P6/qiXZyZ+FuTypptZ668AQXE62W0TxUWLS3gMlyMmgQD/Au6MHy/oDFzZ/u4yQcanW7
         9HmjSFEUwJjXgrx2Okyj4hnEsXTWokUNId80qUTO96OJwu80x+RLLHqj5eDS2IIkC9N/
         uk3ilRknpGl68tEPy8XNtspx0XvKyOnmOFVWML2B3FAAVwPL7VXcpULI+UGPIsYyfm3A
         zzew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=yz5v/rizjXEbZVuISlQ2rhr5W6A4CHl+vV6/5a8jivk=;
        b=xY5gBeja5ZqJrZ3SkF6FgZSs5Sr+eTmSAhH7k2omaNIFLlC7O+RXzeOhjy4NCTdHJY
         3lI2uNC/WxrKVoskJPjuT75ETVkGXDJ8e3V79atkX+dsVil53pmD0/ApFSoFYZGBlKwh
         UMFpMnq23zAdF2KfGKlF+7biyZAV4Ir3fLmHsamTBU3ldVV50HJ+gkOMg7/5DnBIEoYz
         aUE4I6e6bpSbC3VINUxlom5Qx3A6ALDo4Re4R8LpuPX0CsDCfrsVeU52dkMJ9PWHvV4x
         v8MqOo63Ifk3aOX077J0RZ8jKOFp7HuSGJ3BpiGxc3HJpMJy6kfw+9M31z9r1O4BebTg
         G7jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e18si423696pld.5.2020.10.01.11.11.30
        for <kasan-dev@googlegroups.com>;
        Thu, 01 Oct 2020 11:11:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2A6BD1042;
	Thu,  1 Oct 2020 11:11:29 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.119])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 218163F6CF;
	Thu,  1 Oct 2020 11:11:21 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:11:19 +0100
From: Mark Rutland <mark.rutland@arm.com>
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
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20201001181119.GB89689@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-2-elver@google.com>
 <20200929142411.GC53442@C02TD0UTHF1T.local>
 <CAG_fn=UOJARteeqT_+1ORPEP9SB5HR3B3W8830rA9kjZLoN+Ww@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=UOJARteeqT_+1ORPEP9SB5HR3B3W8830rA9kjZLoN+Ww@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Sep 29, 2020 at 05:51:58PM +0200, Alexander Potapenko wrote:
> On Tue, Sep 29, 2020 at 4:24 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Mon, Sep 21, 2020 at 03:26:02PM +0200, Marco Elver wrote:
> > > From: Alexander Potapenko <glider@google.com>
> > >
> > > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > > low-overhead sampling-based memory safety error detector of heap
> > > use-after-free, invalid-free, and out-of-bounds access errors.
> > >
> > > KFENCE is designed to be enabled in production kernels, and has near
> > > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > > for precision. The main motivation behind KFENCE's design, is that with
> > > enough total uptime KFENCE will detect bugs in code paths not typically
> > > exercised by non-production test workloads. One way to quickly achieve a
> > > large enough total uptime is when the tool is deployed across a large
> > > fleet of machines.
> > >
> > > KFENCE objects each reside on a dedicated page, at either the left or
> > > right page boundaries. The pages to the left and right of the object
> > > page are "guard pages", whose attributes are changed to a protected
> > > state, and cause page faults on any attempted access to them. Such page
> > > faults are then intercepted by KFENCE, which handles the fault
> > > gracefully by reporting a memory access error. To detect out-of-bounds
> > > writes to memory within the object's page itself, KFENCE also uses
> > > pattern-based redzones. The following figure illustrates the page
> > > layout:
> > >
> > >   ---+-----------+-----------+-----------+-----------+-----------+---
> > >      | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
> > >      | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
> > >      | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
> > >      | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
> > >      | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
> > >      | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
> > >   ---+-----------+-----------+-----------+-----------+-----------+---
> > >
> > > Guarded allocations are set up based on a sample interval (can be set
> > > via kfence.sample_interval). After expiration of the sample interval, a
> > > guarded allocation from the KFENCE object pool is returned to the main
> > > allocator (SLAB or SLUB). At this point, the timer is reset, and the
> > > next allocation is set up after the expiration of the interval.
> >
> > From other sub-threads it sounds like these addresses are not part of
> > the linear/direct map.
> For x86 these addresses belong to .bss, i.e. "kernel text mapping"
> section, isn't that the linear map?

No; the "linear map" is the "direct mapping" on x86, and the "image" or
"kernel text mapping" is a distinct VA region. The image mapping aliases
(i.e. uses the same physical pages as) a portion of the linear map, and
every page in the linear map has a struct page.

Fon the x86_64 ivirtual memory layout, see:

https://www.kernel.org/doc/html/latest/x86/x86_64/mm.html

Originally, the kernel image lived in the linear map, but it was split
out into a distinct VA range (among other things) to permit KASLR.  When
that split was made, the x86 virt_to_*() helpers were updated to detect
when they were passed a kernel image address, and automatically fix that
up as-if they'd been handed the linear map alias of that address.

For going one-way from virt->{phys,page} that works ok, but it doesn't
survive the round-trip, and introduces redundant work into each
virt_to_*() call.

As it was largely arch code that was using image addresses, we didn't
bother with the fixup on arm64, as we preferred the stronger warning. At
the time I was also under the impression that on x86 they wanted to get
rid of the automatic fixup, but that doesn't seem to have happened.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001181119.GB89689%40C02TD0UTHF1T.local.
