Return-Path: <kasan-dev+bncBAABBGWVQKKAMGQECVQZHJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EDB352763F
	for <lists+kasan-dev@lfdr.de>; Sun, 15 May 2022 09:24:12 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id l26-20020a2e99da000000b0024f02d881cdsf2955926ljj.6
        for <lists+kasan-dev@lfdr.de>; Sun, 15 May 2022 00:24:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652599451; cv=pass;
        d=google.com; s=arc-20160816;
        b=waivvUmMr/DnJQtaS2pYm/h5cjUTN7IPnSuz6nTbs9B/+tXfvb+HPRbpnGF0BLUTav
         Vwderob9KW3Kp6SfLdLLgb9zN4/SLzGE05A5L/kjKAsafQdmkSjuHlduuFmPHy7lYZoE
         MEw3DsXUmgsDK3ohZaKtWrpx8RhluOsgwPji7haYJnwxaMSKNl90K9IqbYXyFIw9g1UZ
         gO2H5FRVr/PcLEnh9nQ9YV0XUqY8MTgrntEf16mviJ5SBqbTvCgS3+OOrGXQC46aVrWv
         4w8HLmL9BFXOQijnT/xTn2QLMdR5paNW9C8+dwDW683M+TecCsCx7M+6rqKCBwQHIiiY
         PBhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZlmghvyTETx/vNdMe/9Y7B/OTMP+73qCjWXAmUZNebQ=;
        b=Tpsc00mpxj0/1LShf0p7wZRV+YYQP8XMzow1kRWP97CNbkYodOME5dEmptiAa10N2H
         r3o3EP5pM4kaLDFgHt67fh5CaC4szTsHG3gxu3bE4QFpDbFEXl7+bSvs8Jh5PCq5u/GS
         gJKSa4Pata/vTWKxaF/c1VcLoDPKZ5YH+Ems0wExixB722nqlB/7IOH7dUEySw7cSBZN
         D6J7q19uJXGg7nPX0/ChNCSH0bGnmDZpYy6NbbwbB5ioCMLQR03mgNQipqSJ1URF/Kfa
         TnxubvibRqaDqHUk/iYjRtW8Xn4EnQerVqARAb+AkC7pmSxPsBGymivutPHLKtLl64/F
         FwWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SX3l+6L+;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZlmghvyTETx/vNdMe/9Y7B/OTMP+73qCjWXAmUZNebQ=;
        b=SHFZk5UE0ye22cLX6rEGUTpaT8p3IT5p8U/APAoNJARn/r3lgueQbUNEULnA2KavoO
         hnkgXIBfSRyPqwu4RG/QRCUqwxI+KM7Un6pjPEO+wESIiCBddgWLiy8BlhJ74MrmIJH3
         0WWxPj7VBJ41Xb5HgcpFRE1Alk0qp0rbQL6fwqa901V6tG1I0kthKmfvkqFeM4PTWzph
         4GprDUP7D2XDxdcZiNFgUf/WrAjmdkU1ZTiL/s2zXOBtZuHkU9GTzvV/N94ydQM76FJf
         thbMPiJxGoI/7JEsWmJK293J7Qg/MnbarexUodqf76fx3KvXyJl6aNyu1BAgGxUUg0x4
         xkXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZlmghvyTETx/vNdMe/9Y7B/OTMP+73qCjWXAmUZNebQ=;
        b=wJSZdcp3+XMLUO0EXKgS36Prm8qQpqShgZFsVQofPdOVJYFB589kASqr+uX3voxhr0
         tfAWRd7Jtk5U3BGbHTPjOxehn4nuKe+7CJaubhWs9JHwSw41M+k9LGuW/KD9TwDdg6te
         sRhPA8RTAf6YgoCuScxbBrCoPJn+BMa8axe+q774Mum/OIV5eYu9bWyZDzJcA6kR1m33
         j1uIsQwb2VgRidet/6E7xHW5/nZQRe9c7rUEsVvVnkOqT9FIR6kXkP/bfWAX0TzZ//pa
         VqZzqD4337a5UY+gnbQ+k+iaFjcobRn3gG62pRvwB/xk5NUtln+OMn7KlyAsvaGVAEzb
         46/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qDPpvvO2RD6x2FBMN0digJUU7a6kzGs7W3tz7h+xQ51M4LHOH
	vK8TtBxnQiHUhATmK4wC634=
X-Google-Smtp-Source: ABdhPJyfMwZA5LtOpwLxw6XaPu4IyHJGKs1XZMKdSRatZfi8E8sXfvCjACSNfK+tuWbxxXpXEbtJGA==
X-Received: by 2002:a05:6512:1095:b0:473:bf36:b6b with SMTP id j21-20020a056512109500b00473bf360b6bmr9253550lfg.479.1652599451218;
        Sun, 15 May 2022 00:24:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:4ca:b0:24f:f52e:16e0 with SMTP id
 e10-20020a05651c04ca00b0024ff52e16e0ls2070032lji.3.gmail; Sun, 15 May 2022
 00:24:10 -0700 (PDT)
X-Received: by 2002:a2e:8247:0:b0:249:8615:4242 with SMTP id j7-20020a2e8247000000b0024986154242mr7642547ljh.108.1652599450291;
        Sun, 15 May 2022 00:24:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652599450; cv=none;
        d=google.com; s=arc-20160816;
        b=ptJONsCHgZJoVsE1au07H+aBa1lvRE3M7OfeP7z6jT9QDzz6YEXJTtu1kMMFT2KBDY
         XG9bVzUMc5Bx362YVu1WlR2RfL1n5H6XAQyKr99HXLtUvGpzmswmRgKHFK9FfxtGiKJg
         1lPfNvrqGNOp5+2+C4bMMbaNAg3FVRJOZDPYWPeZNFkvEoatNcnO5DvBqCCJ1YPhPn2T
         Xv3MzVWFMIhOelZva0sTtVS8ZuB5vUxJbqbLKfd+xPiAq1XbcPy4dYBzXIiCsSkGP5Bo
         0UQOP6j5P15fL3EpV+1Q5q/DkpzOf6JrDy0RjbFGpVclJ8uXHRzkWzVduReRNs4SnNDU
         nmGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QvExm+tMUmaKc7qlA+TmenKI1CiWuA8Uw+heVaVZmfg=;
        b=VaguO7R7E/sb1Kowhd/fHeTLnogTEGCgXvwBXtTdUbCFVzaqdOJ+ZEiA6kRSsHegPh
         TYItad10EN2JXzXxy2Ez8p7iK04sBIPAj5i5OpG0qZ7syGTCihXQLvBBvZ8+wqETZaTb
         AM1sT3e2kSLS4Qw33B5ZdtErC3Y7sZX2A8aWY7dQHlbbvylMO49OG043rW4w4SfiMogL
         OEDYXSWJoUWeO2AQuhYAUQQCfOoK4A2/W5jnd7s2zFtBWVyYLJa5VA5JcudG5/Iupni8
         ZLtuXDoVszDE8YzrqN37hU1omm3S+zZoghagUPEvWZa/zRR3Q13Yzc8Zox1gl0RcOEVZ
         U/nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SX3l+6L+;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id e13-20020a05651c04cd00b0024f0dcb32f8si277777lji.5.2022.05.15.00.24.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 15 May 2022 00:24:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 64C4CB80AC5;
	Sun, 15 May 2022 07:24:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E4741C385B8;
	Sun, 15 May 2022 07:24:04 +0000 (UTC)
Date: Sun, 15 May 2022 15:15:34 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Atish Patra <atishp@atishpatra.org>
Cc: Anup Patel <apatel@ventanamicro.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	linux-riscv <linux-riscv@lists.infradead.org>,
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 2/4] riscv: introduce unified static key mechanism for
 CPU features
Message-ID: <YoCollqhS93NJZjL@xhacker>
References: <20220508160749.984-1-jszhang@kernel.org>
 <20220508160749.984-3-jszhang@kernel.org>
 <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com>
 <YnkoKxaPbrTnZPQv@xhacker>
 <CAOnJCU+XR5mtqKBQLMj3JgsTPgvAQdO_jj2FWqcu7f9MezNCKA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAOnJCU+XR5mtqKBQLMj3JgsTPgvAQdO_jj2FWqcu7f9MezNCKA@mail.gmail.com>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SX3l+6L+;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 11, 2022 at 11:29:32PM -0700, Atish Patra wrote:
> On Mon, May 9, 2022 at 7:50 AM Jisheng Zhang <jszhang@kernel.org> wrote:
> >
> > On Mon, May 09, 2022 at 09:17:10AM +0530, Anup Patel wrote:
> > > On Sun, May 8, 2022 at 9:47 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> > > >
> > > > Currently, riscv has several features why may not be supported on all
> > > > riscv platforms, for example, FPU, SV48 and so on. To support unified
> > > > kernel Image style, we need to check whether the feature is suportted
> > > > or not. If the check sits at hot code path, then performance will be
> > > > impacted a lot. static key can be used to solve the issue. In the past
> > > > FPU support has been converted to use static key mechanism. I believe
> > > > we will have similar cases in the future.
> > >
> > > It's not just FPU and Sv48. There are several others such as Svinval,
> > > Vector, Svnapot, Svpbmt, and many many others.
> > >
> > > Overall, I agree with the approach of using static key array but I
> > > disagree with the semantics and the duplicate stuff being added.
> > >
> > > Please see more comments below ..
> > >
> > > >
> > > > Similar as arm64 does(in fact, some code is borrowed from arm64), this
> > > > patch tries to add an unified mechanism to use static keys for all
> > > > the cpu features by implementing an array of default-false static keys
> > > > and enabling them when detected. The cpus_have_*_cap() check uses the
> > > > static keys if riscv_const_caps_ready is finalized, otherwise the
> > > > compiler generates the bitmap test.
> > >
> > > First of all, we should stop calling this a feature (like ARM does). Rather,
> > > we should call these as isa extensions ("isaext") to align with the RISC-V
> > > priv spec and RISC-V profiles spec. For all the ISA optionalities which do
> > > not have distinct extension name, the RISC-V profiles spec is assigning
> > > names to all such optionalities.
> >
> > Same as the reply a few minutes ago, the key problem here is do all
> > CPU features belong to *ISA* extensions? For example, SV48, SV57 etc.
> > I agree with Atish's comments here:
> >
> > "I think the cpu feature is a superset of the ISA extension.
> > cpu feature != ISA extension"
> >
> 
> It seems to be accurate at that point in time. However, the latest
> profile spec seems to
> define everything as an extension including sv48.
> 
> https://github.com/riscv/riscv-profiles/blob/main/profiles.adoc#623-rva22s64-supported-optional-extensions
> 
> It may be a redundant effort and confusing to create two sets i.e.
> feature and extension in this case.
> But this specification is not frozen yet and may change in the future.
> We at least know that that is the current intention.
> 
> Array of static keys is definitely useful and should be used for all
> well defined ISA extensions by the ratified priv spec.
> This will simplify this patch as well. For any feature/extensions
> (i.e. sv48/sv57) which was never defined as an extension
> in the priv spec but profile seems to define it now, I would leave it
> alone for the time being. Converting the existing code
> to static key probably has value but please do not include it in the
> static key array setup.
> 
> Once the profile spec is frozen, we can decide which direction the
> Linux kernel should go.
>

Hi Atish, Anup,

I see your points and thanks for the information of the profile
spec. Now, I have other two points about isa VS features:

1. Not all isa extenstions need static key mechanism, so if we
make a static key array with 1:1 riscv_isa <-> static key relationship
there may be waste.

For example, the 'a', 'c', 'i', 'm' and so on don't have static
key usage.

2.We may need riscv architecture static keys for non-isa, this is
usually related with the linux os itself, for example
a static key for "unmap kernelspace at userspace".
static keys for "spectre CVE mitigations"
etc.

In summary, I can see riscv_isa doesn't cover features which need static
keys, and vice vesa.

Could you please comment?

Thanks in advance,
Jisheng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoCollqhS93NJZjL%40xhacker.
