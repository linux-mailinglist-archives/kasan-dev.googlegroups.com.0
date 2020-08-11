Return-Path: <kasan-dev+bncBCV5TUXXRUIBBW5FZH4QKGQENAFSKYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 256E3241808
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 10:12:12 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id u3sf4263742edx.18
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 01:12:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597133532; cv=pass;
        d=google.com; s=arc-20160816;
        b=mIXf+km2HuFRpdIjxMoaC7B2PN1MbIia02dj6u8gDMD5pDX12CznqJaYjrqXfFpo4A
         7SNHmnJPskqkae4aO5LTEgN1Ux25CdD4y7gMfA8cg/2qS5sAAq0lsvnLlIp3CRcwX0wb
         IkZw87H2vx96jZLba3eVkEk/vYfaKHbiEDcMWG+wmWj5wLdcWzdsSrCGZm2qbdDsBM3R
         gX0Ywi/dpI2RZPglAwpHp3FhkRkvnDeyesRQAdbZWVx4mETclBpbEuS5VPZTClyIyYgj
         hiI49xmQ+MN6nZFN2gnPwprMKtIePp0zJMYnWA4JiP/oC0j2VYuXSfi1Y16FkU8crJn/
         Szzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=eNqdxZj8RHgoev4o2MG3eMih0TGQ7JsxxBP8wTyhbxY=;
        b=m8s8WpmRG+ZR/wBiu4YzV0sUuiFXCgzXOYzwK3Non50D6ymDHwz3AvLkhG3VXU2R8D
         +5yqnNFL55spwwG0XuFWWUmWmbJvVzCkmQSWZ+4DFBEN/+d70MVyO2zrFs4JAviGAGkg
         djpgYW0hsM+ha3fG4kJZf9NNfvv+ViteHY6HUJ82phAVKjIXY+6/9jSuM7nSdv8sc1gb
         X1jECEtO81eHIqkKbOYz/4DSF3DGq0Do3cM2XS6Rf/OuAjvbnRVQOMN4ZjhWhpwVqBWD
         SbIpq69REojllfjHjppqWsK3wJz0xegYf8s3rwrtuYD5qRNignjTEi0yMDAIL379FqpR
         DyVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=X5W5zo0+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eNqdxZj8RHgoev4o2MG3eMih0TGQ7JsxxBP8wTyhbxY=;
        b=tapeDJWejIC1kxjeo3GydG/BV7wistS/jzvmcgdO14L5Bo0rKssUxW4FnIF+Y/Lk3j
         rCJDPiG+v9MlSyC93NVikd3/L2U+3L8KmdiKSdKolWBHOFG63JO9zMn8a2STqQLUThR/
         ZRetX/kU5nheYo/607DaWhFT11r8vgMo1JXrdqT3KfO454dv+hLxXUZcTictf6ZN5Q19
         y9ugKCSV9JlbuPJVmETLB5KGYYkOKR3PZFC7RBrX5CeJjOWZt6NxZdOWTowCPSneNCIm
         tAS75mLcgrVWQ4jy4JKiDcpiTiKSE/I0MiiKxSFJAu/2T/f6dFy7tv1TVsXoJqJ2uuf2
         JLPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eNqdxZj8RHgoev4o2MG3eMih0TGQ7JsxxBP8wTyhbxY=;
        b=VifZFEnxamK5yQjFL6yZ7D8FtVtDiYxR1CItlZDJBemyQweISwEF5/NPAcICPEsHJZ
         ybqkxY7ldY2JVQsuYE/6AQ5xHOq50tO8g+gDkWsEatm2Aj2ACdxYqj7Ah5E6dm++eQdI
         CF/s6tVGkqHduB6zkNqhhQNkqZ2lJmEKMVQSo3WCpgDg5jifuFhC+XCbnTsfe2uSB17L
         uOX9Kf6vlDNGy5nfOYgp6qb6N5BnDz9USYkbRa/+fuob3blfpIOIiM5l93HHLvqkK/pP
         18UR58frBBeEm/EvmOwxfKung34dDO9jfZpyMCCdTizUn5dt0jDx80+ejhRjd58Kl8Db
         4vuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rlMtA6ASoIcyq0m3nhGNrvQ8LZOz86O2CL7DFGcFzycx8k2H8
	d9AWMXyU/sNKPnN6LuCt8oY=
X-Google-Smtp-Source: ABdhPJypxOle4FIy2wuDepwS/rGfWJfbm45GvoPcQqDXaTfhCaHsCir1rOqnXUD0nBFoIFrMJHPU4A==
X-Received: by 2002:a17:907:36b:: with SMTP id rs11mr26126278ejb.544.1597133531919;
        Tue, 11 Aug 2020 01:12:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:17ce:: with SMTP id s14ls1650072edy.1.gmail; Tue,
 11 Aug 2020 01:12:11 -0700 (PDT)
X-Received: by 2002:a50:d1d4:: with SMTP id i20mr25453672edg.320.1597133531487;
        Tue, 11 Aug 2020 01:12:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597133531; cv=none;
        d=google.com; s=arc-20160816;
        b=IH+qtbpzEqMvpemWHfwuovNhMTTeFtd54+CQ2xq3aDXZHsAj0Wj3MYZKPeg5RTGvBa
         KGHWghi5Bbs5DqnoLHNUulSQz2SnpUQ7plJluU7KO4JW/DgvSHc4QZF93xedzl9VlQKf
         7FnH90iLa0hhhbqrLu4vsLIk72PkJkmi4A3A1bxt6yG615XgQwg1eVkOcFK2FXSCAVbc
         +ZH0uRMBbuZgvMX25qlSZ8LIZykU4vvsPQjH1mpnKOOWLCnedrKJIVJVmhz/xV89CHnl
         zwVsxn3hGfkWXYhoe8ez82+NUuhgpUKrqfLFs15X6zqi0ofoUR/ioMlbYLu1D2Q+4X8M
         8ixA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Dh9BiEVz6epUQSvBxpIbJVz7h5uxpAes5kiPqWr2N0U=;
        b=jMlWYpNXIBVYRNcneTJ8PbMcPjpFcPnu/nA5RNggB/ShUoXljLS5CWn++Uxi6iig/+
         QHbzlTHvW8fc3Ge30Ef03rhJqR0zO/ywh/4llidKZ2m121o9KtBjxw1JDO0xgls3lRIO
         vzxaO9OSHiDn5qf0nJfyOaIhGOg60D1BH/AWOWws/LqZWkEUzHnFFbe6M2YJ5LtkxY+8
         k0g5WczGyd7Wd8rVOoTL8EWlAlpVC9sNp8gegCTuXWKVwsOzm2a01rVyHe5qPBV1WMYY
         l9OGeeXrrZauuAJrI9CR+9t6pnFLPAK5xe8cTa46gQ2tS8517VIO1GlWBRIOTsaSoJC7
         4yBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=X5W5zo0+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id b6si1047428edq.1.2020.08.11.01.12.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Aug 2020 01:12:11 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k5POA-00074x-1J; Tue, 11 Aug 2020 08:12:06 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id A3665980C9D; Tue, 11 Aug 2020 10:12:05 +0200 (CEST)
Date: Tue, 11 Aug 2020 10:12:05 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: =?iso-8859-1?Q?J=FCrgen_Gro=DF?= <jgross@suse.com>
Cc: Marco Elver <elver@google.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	sdeep@vmware.com, virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Wei Liu <wei.liu@kernel.org>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200811081205.GV3982@worktop.programming.kicks-ass.net>
References: <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
 <20200811074127.GR3982@worktop.programming.kicks-ass.net>
 <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=X5W5zo0+;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Aug 11, 2020 at 09:57:55AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> On 11.08.20 09:41, Peter Zijlstra wrote:
> > On Fri, Aug 07, 2020 at 05:19:03PM +0200, Marco Elver wrote:
> >=20
> > > My hypothesis here is simply that kvm_wait() may be called in a place
> > > where we get the same case I mentioned to Peter,
> > >=20
> > > 	raw_local_irq_save(); /* or other IRQs off without tracing */
> > > 	...
> > > 	kvm_wait() /* IRQ state tracing gets confused */
> > > 	...
> > > 	raw_local_irq_restore();
> > >=20
> > > and therefore, using raw variants in kvm_wait() works. It's also safe
> > > because it doesn't call any other libraries that would result in corr=
upt
> >=20
> > Yes, this is definitely an issue.
> >=20
> > Tracing, we also musn't call into tracing when using raw_local_irq_*().
> > Because then we re-intoduce this same issue all over again.
> >=20
> > Both halt() and safe_halt() are more paravirt calls, but given we're in
> > a KVM paravirt call already, I suppose we can directly use native_*()
> > here.
> >=20
> > Something like so then... I suppose, but then the Xen variants need TLC
> > too.
>=20
> Just to be sure I understand you correct:
>=20
> You mean that xen_qlock_kick() and xen_qlock_wait() and all functions
> called by those should gain the "notrace" attribute, right?
>=20
> I am not sure why the kick variants need it, though. IMO those are
> called only after the lock has been released, so they should be fine
> without notrace.

The issue happens when someone uses arch_spinlock_t under
raw_local_irq_*().

> And again: we shouldn't forget the Hyper-V variants.

Bah, my grep failed :/ Also *groan*, that's calling apic->send_IPI().


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200811081205.GV3982%40worktop.programming.kicks-ass.net.
