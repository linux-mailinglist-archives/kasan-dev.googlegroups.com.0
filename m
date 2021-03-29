Return-Path: <kasan-dev+bncBD42DY67RYARBVMVRGBQMGQEGFT7F2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 26CD434D9AF
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 23:47:03 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id z19sf8487023oot.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 14:47:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617054422; cv=pass;
        d=google.com; s=arc-20160816;
        b=TuEE3JbMpWpRCJ341mpe8kikktHRbYXWI0JQTsz53UqM/m0ulNAP8CJ2FN/ap9emru
         ATWU+gWOzQbZOr9ACaPxLIkjJxcyuP/lTluN67b8VZEud1NOsPf0EjvqUZ+vehpVRkO0
         JMagVgk/e+38Fc/e9epa4zKCIJ/NrLXGs/BruaP1vrcQ2BobSoIJHI++JhwM6/mqM6xA
         whFAHOzRubba37ehz64x5mDZwMl39Zu+i+fttrwVvlNLV7m2+13NXBtq7PBnu3qV17Yx
         H4XG60PQYOg2SL2RwsQFgWCVI5Hd4c/hUdzsBfJbY+eG21lkMJEXSvHW0Uf2vO7LrOPH
         mkrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=Zky1yU0P9dqv7/h7Y2pXllw8oIOwlNa4PJN/D+yPp4I=;
        b=Q/2RdBc2wszdL9QLcgx2xhYp4BAHcLS8dLcch8vURU0iRMtzuz2+GhllZda/jk6qnP
         dgNBK5x59bdsT6cifVM4lirPx5BYeIR+Lv7NR87QQrHS6c/8gBY85D3Rth/MgkUZC19l
         NBUU/txrfRE9SXSmV1hyAqhoewLRIVEZaxlxwd4joASz0Gv8j8ADesU5Eg129dO8Z3SK
         xM+LI1nX6+2lgtfTHoRZ1TCy4NA/phGsJD1mwf3aXUlYFLYykS4zTS3y5pFwweOO2N1Y
         bmv3G03U0riJCNFn8Gm3Jl8wUa5CewavcMOMyS2cHxl/jhuiyteJ4q1ncTSIlhvZ6kny
         LvAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=lDSTz4TC;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=luto@amacapital.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zky1yU0P9dqv7/h7Y2pXllw8oIOwlNa4PJN/D+yPp4I=;
        b=WdHWZQjDV/xa0UOmRvowOg9qy5n8tZ3m8d3S9Wlbf/Y68/FtOwCWNluta3GfEKurbB
         aUxmgf68k9d2uIjQaLfGE6Jx2KKBWJ6u7CrVGN1JXUytKSbmvauAwoay56KlsUtJ5LCq
         q+F3WEXDwmM+W9Q0ty5kwpiAbkFOjD6k3v5gVCRlLd0mkUy7yU2GzG5Fop7dVGNSKhMD
         5+ERTYL4Nu+npuWerLFBOAdb3R6CVmxvUcXWkTITC5HEygIunhUzPOOlapQZNKGi/IK3
         a57YnxIr84iitnIlk4Sue8TMnxJACsrMPz6Iw/J1m9OJ29+Vc6S+8kYevGkvcQga7DaB
         Oh5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Zky1yU0P9dqv7/h7Y2pXllw8oIOwlNa4PJN/D+yPp4I=;
        b=CQCPcKcVGiyGL2tHtrPj76aASDswCkIbZltIChSvtNrbzBVS9MiySiOgrmMnkjJeEC
         sEK70eAdiIxZHLpAHz4AkjFEpIKqvIxn1g9g6/KXGW8r9NZGBhcpmCHViMVSdGEvVJYi
         FrHCDxgspnIGcIv2gdACOdzNJrauFRa0D8TkgR2zqNf2wM39nL/q3vpBc0819Pjycjc8
         tVT5J9EWY6+Ec4ezE9SsRf5OP2dIltdMf4QuO+uFaY/dF74gdIRstmZ3pn9j1Eh/01//
         NLrJzL/5u72MvsaPRJp3Dhq4UE55NBz/d1KwHzChef8r1l92JhqQZC6HivVLhHKzGxhF
         Yfkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/lw/QLkfzQ8dM+zRGWS4ntPNTk5iQ/MfJNN6dl1oIkcJ0rw27
	4+rkp9oWgsER7EfBnGu2uo4=
X-Google-Smtp-Source: ABdhPJxT/0yNW6nbZx4wFehva/DdFKB3WsWYAcAAUvBUwx1c/pRKwYVEmEX2GM4LWJVcQdXEUdm82w==
X-Received: by 2002:aca:7516:: with SMTP id q22mr864473oic.158.1617054422003;
        Mon, 29 Mar 2021 14:47:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d54d:: with SMTP id m74ls4068532oig.11.gmail; Mon, 29
 Mar 2021 14:47:01 -0700 (PDT)
X-Received: by 2002:aca:1b01:: with SMTP id b1mr791511oib.177.1617054421610;
        Mon, 29 Mar 2021 14:47:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617054421; cv=none;
        d=google.com; s=arc-20160816;
        b=mN09m0+rUcUs/0DzQCqU06d4BV+reG1uC5M+e+nlw9XcWwxdj4dC4dIQK27CsR5xPM
         38uOZ+KfoAU2UT23YIgQoB28sTcZoVGuBnElPLI3D/9+j/OD/5niX4epJoWbQRFbRJPG
         FB5e3/a4lEnehGWWbvXsbS0o5OH/0dNYAGP/orBNPvGal3+7MyP6DajG/OnI1MBHFGOL
         9Zn6c69a6UnqQqJm2gnMYwfjaMkKoIlPKGiF7lYJuBFsRoapb6x31Jbdg6wAqT8zGyn5
         TtaU5Z/tvgPLho/FCwtOUTcfyPbf34ZFWNSOKXM5Draz6H5MU9Q0z6EdT7eZMjbrRULW
         QX5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=dINV1jr3ervdCKyPzOLdFI3Vz2vitsmiwNxQTrYH5RQ=;
        b=yGFE/aEFKqowp7LbEqLQu1ty5KxALnTWnL49ellvdGOLNTQFMSyrDbIr6V5jsbfzXN
         VmuCQaiRVscjUa9HNj0z1b2PYBZgszRDAsyhS1JpctegEjVDn25joW8kpnM51QrmQY9O
         qSlVHC22gKUQNK0z32KBwEFx0i3GUiO3qamn9PfufxCPGlFkkId671qwZTlvDq382UKu
         1oZph770sqLNTX8GXo010c49ZraXv4JUBsRkjv2IMZg13g9lB0cb4MQirxSFJt+HvV5G
         +IBmlTnyPl7KXE93IThIDBpKa6XaXAJlwAVECMJ6oDbQrDFg9cModbsshX/89rUdDTBl
         gWGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=lDSTz4TC;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=luto@amacapital.net
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id v31si619464ott.5.2021.03.29.14.47.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 14:47:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id x26so10788832pfn.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 14:47:01 -0700 (PDT)
X-Received: by 2002:a63:6a84:: with SMTP id f126mr25094745pgc.352.1617054420880;
        Mon, 29 Mar 2021 14:47:00 -0700 (PDT)
Received: from ?IPv6:2601:646:c200:1ef2:e17c:78f7:dc94:55dd? ([2601:646:c200:1ef2:e17c:78f7:dc94:55dd])
        by smtp.gmail.com with ESMTPSA id a70sm17413227pfa.202.2021.03.29.14.47.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 14:47:00 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Andy Lutomirski <luto@amacapital.net>
Mime-Version: 1.0 (1.0)
Subject: Re: I915 CI-run with kfence enabled, issues found
Date: Mon, 29 Mar 2021 14:46:59 -0700
Message-Id: <ED2525DC-4591-46D1-8238-0461D5006502@amacapital.net>
References: <CANpmjNPjj7ocn6rf-9LkwJrYdVw3AuKfuF7FzwMu=hwe7qrEUw@mail.gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>,
 "Sarvela, Tomi P" <tomi.p.sarvela@intel.com>, kasan-dev@googlegroups.com,
 Dave Hansen <dave.hansen@linux.intel.com>,
 Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, the arch/x86 maintainers <x86@kernel.org>,
 "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>
In-Reply-To: <CANpmjNPjj7ocn6rf-9LkwJrYdVw3AuKfuF7FzwMu=hwe7qrEUw@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (18D61)
X-Original-Sender: luto@amacapital.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623
 header.b=lDSTz4TC;       spf=pass (google.com: domain of luto@amacapital.net
 designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=luto@amacapital.net
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


> On Mar 29, 2021, at 2:34 PM, Marco Elver <elver@google.com> wrote:
>=20
> =EF=BB=BFOn Mon, 29 Mar 2021 at 23:03, Dave Hansen <dave.hansen@intel.com=
> wrote:
>>> On 3/29/21 10:45 AM, Marco Elver wrote:
>>>> On Mon, 29 Mar 2021 at 19:32, Dave Hansen <dave.hansen@intel.com> wrot=
e:
>>> Doing it to all CPUs is too expensive, and we can tolerate this being
>>> approximate (nothing bad will happen, KFENCE might just miss a bug and
>>> that's ok).
>> ...
>>>> BTW, the preempt checks in flush_tlb_one_kernel() are dependent on KPT=
I
>>>> being enabled.  That's probably why you don't see this everywhere.  We
>>>> should probably have unconditional preempt checks in there.
>>>=20
>>> In which case I'll add a preempt_disable/enable() pair to
>>> kfence_protect_page() in arch/x86/include/asm/kfence.h.
>>=20
>> That sounds sane to me.  I'd just plead that the special situation (not
>> needing deterministic TLB flushes) is obvious.  We don't want any folks
>> copying this code.
>>=20
>> BTW, I know you want to avoid the cost of IPIs, but have you considered
>> any other low-cost ways to get quicker TLB flushes?  For instance, you
>> could loop over all CPUs and set cpu_tlbstate.invalidate_other=3D1.  Tha=
t
>> would induce a context switch at the next context switch without needing
>> an IPI.
>=20
> This is interesting. And it seems like it would work well for our
> usecase. Ideally we should only flush entries related to the page we
> changed. But it seems invalidate_other would flush the entire TLB.
>=20
> With PTI, flush_tlb_one_kernel() already does that for the current
> CPU, but now we'd flush entire TLBs for all CPUs and even if PTI is
> off.
>=20
> Do you have an intuition for how much this would affect large
> multi-socket systems? I currently can't quite say, and would err on
> the side of caution.

Flushing the kernel TLB for all addresses
Is rather pricy. ISTR 600 cycles on Skylake, not to mention the cost of los=
ing the TLB.  How common is this?

>=20
> Thanks,
> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ED2525DC-4591-46D1-8238-0461D5006502%40amacapital.net.
