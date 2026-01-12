Return-Path: <kasan-dev+bncBCT4XGV33UIBBYN6SXFQMGQET6PPQXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A269D15555
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 21:53:56 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-34abec8855asf6645112a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 12:53:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768251234; cv=pass;
        d=google.com; s=arc-20240605;
        b=CsJZBpG3RksoFiczh8yKAQj67PSTCrdlM0RGxi1crXPoVBw9JE0nV0g2ojRI7iX9MK
         jwZrobzI48eRu1GGrv22+b5xhUiPjL92EybrliDcigeonhJxBYgr5yLtflSDiQu5zLhp
         P50KTiVw1dQWsetUTT8CGN7pvK98tgh/JtHe5cALvfPieuvEvBR4WQjar7KltmsYFkcU
         Kcn9h/52nPlu8mXee8pikDJo0IC6lbGN/LG9lk8NtgKlVvdkesxAnO4ZFraDEPEeorzr
         F7Cco5dIV2EieOTVzHxtKbdvTn2C/BQlOuGlXuNXwcGsWend/ZnQb6Nw0+RqXmJYkAqn
         YU9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=/YeGDeDpWGi0NjLCHYvnekRD//JjbacjdVJnIkxy/Uo=;
        fh=xR2rj1geJInbivbfCFfNbl4Eiducuk44gI5/TdCwACs=;
        b=RmjFPa0+I8e/Wg+3dH2PAES9+sNGTDVTJtyLWQeZIuaRC8TjFyufTOFGEY9zGMN3z6
         GguETqM5kKUcdI9vIpr5flaO9HPRrO0YNS0+s45+liOGJC+4ILSIAX9B86JX44c/lB8J
         EX+mhGEJAOT+0LdXtBZjsMbcpWrJgc2m7uQvko3AXgktVzYaCPgcqf4pycqkMdb1KW8K
         rjtVZxiTHSBIicQ2F9jNWG7rITExzNPI0T7AtPKB0+QLu63PQpOpvFxriNTldc2hnSTj
         3I1GgIoCcd5shIp7ZnliM6mdrGG18KYv84B2zGc+ApAgDJTDtyl+Qtwk+2NC5taQ5csB
         lK3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fcrLqdsd;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768251234; x=1768856034; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/YeGDeDpWGi0NjLCHYvnekRD//JjbacjdVJnIkxy/Uo=;
        b=XHw94dnqA4Sr16qvqNd7VOBskoCj43L8kREZlQmOdmcgA/x0thsDxkd2TW2noJUiRo
         K6N4JLbz4oqxpO3gBV0mmNdzH4UqQ9ynsK2uBqWFDhWj3oG5oT9tqcocGYmO/APzITWB
         bt05EoKxLHBXNX8dUTTPQrbGP60lNHmDcBF0k6vQiIiu0U8ZN4ysBKR4sJO3cRqJnmMq
         hcFqR9mioNGvAA2YSjGtcj1+TwowKe3/ssBdL9i70a6FcMeN1tAazoYN2n5qZCsQ7A2u
         ZeK9gsIfA1nUurUNjreEOTC5WWsBkY1Wtx0ouIZkuTIDLQU+dVeqxmgQSBUs49bvEMaA
         OlIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768251234; x=1768856034;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/YeGDeDpWGi0NjLCHYvnekRD//JjbacjdVJnIkxy/Uo=;
        b=AUTSp8KwsW1h2oVVzxr3R+YfTG01uwwG+70PzTt9oZeFtvEeoecPBIXpzpp8CmlBY7
         nW9qGH+QkiWO7tUi3w1FzKWvYZs5XjiGb412X5j6ZmbXKXuFhXaq+nKMW44T5NellkX/
         IFivWFZc2h6pnk9wMhq6rHmr1kZ12qumOGylj7SPBX4N2GJ79BYG4397l8BV3EEDeCCg
         K4Ys2xIC5+SAq5e0KqJ3DrtMNPP3DUh7VKwAg1ZQH8ajw8c5bPtUNE8H2p7zssX8Rhje
         difzTuLDgDgA1VyTvIWO1X1rgKGd02M6++1smT0oOAwxV/ykJ/+bpuuM3sFPu2tBroeZ
         lONw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZicFp0xzkupXwmJnXybkf/AN2QCs51MoEngVyZAJIdyVruZvyXbk5cyjZEAd3L/Xevm1Ddg==@lfdr.de
X-Gm-Message-State: AOJu0YzkMWMHjWbBH1bfKvdhuI2gDIUHQURuYZaAa9hzdpJfDDye2A7p
	+oecev5mT+8/ZPXsMLHaA1exyKzPt0CUl+Z97Y34MD3ZkcwBCHHMFeMi
X-Google-Smtp-Source: AGHT+IFOnHNetQE/Bhph+z7sIV5Jop41+q6p2T8Q0wbJxub7h4NssAzyiMaDP9n8st9O8tv/AtpFGw==
X-Received: by 2002:a17:90b:164d:b0:340:2a3a:71b7 with SMTP id 98e67ed59e1d1-34f68b661f5mr20638158a91.12.1768251234292;
        Mon, 12 Jan 2026 12:53:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gp3koIE0b7h56YySUNta1EcnmzKnx1QCLS7tWHVgsIsA=="
Received: by 2002:a17:90a:6345:b0:34c:3502:8adc with SMTP id
 98e67ed59e1d1-34f5e955b49ls4623991a91.0.-pod-prod-05-us; Mon, 12 Jan 2026
 12:53:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5tvyw3Qr4XjHnB1ewxNl/gXrr8gCArQXob1IWJ6khnX4hk538MydZMEGdBkMS7a5dK27kEBaFCcY=@googlegroups.com
X-Received: by 2002:a17:90b:5884:b0:33f:eca0:47c6 with SMTP id 98e67ed59e1d1-34f68c27d86mr15807861a91.30.1768251232675;
        Mon, 12 Jan 2026 12:53:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768251232; cv=none;
        d=google.com; s=arc-20240605;
        b=Cm+HPmtUQSr08msze/gZpvKDk46Ov2vf82ubvQx4c4aE+lHuqNeVqGrFT9yZhH6Tlr
         oCTYF/6Ddx6p1NTAfUBt4rRvfGpDmrTdk63Mz/CU2KbOaJdN1FI8cB6Wo8iKSeb8WGhn
         uwlBnrGKnAuvLqhqCdqt/X8PEbQx38G7ZHDXvk728zY4DMNXyiJglGE+g9WZjEAaCtRw
         0G1686R8vS++AX7wsIyrM7JuQ2yvwrZWaO+CJyONMtDjiLLB90+sLqXq3hFJD+OeLO/9
         I+gIt7xLzmsMylwQXPRsigVjFyo+VUARi3YqF3h9WjBoE26u1P9Q8OKkbzMHgbJmCCBN
         1A5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uBXXF5o0pdnEYmS+0GgHzhXXXUzX8EvhUfTcXmNVDzQ=;
        fh=6Ao7a81sN+vHiCkIKHFsT/8bGGMQ0oaw8InzgIeTqo0=;
        b=bH9FDrfDrsmHB0CwU/o0YGHibPZOZib/jPrk81cioqkv+oLs1BaI3TPtszI8xpSnN4
         VHj9et2CjEJSEEdS8LjRWK0fb0thxroxBV8DhdDvFv7KKsTaMUJXz2axaGQyNRDVIgRz
         RPZKN1EuWtRTgL4CUiCM83lXe2DAhTj2Zvf8z9YRqZPKeCUzs6lOVV6KkbJGXdCfdwDZ
         Yn6LewxIWAuTgUpCt8DPAQ++cd0oxCazlOxGNFl+AU7Zw95kQmR60EX20Hv7K32MrP5f
         kuV/HBbmuv2m0pvzmJuoxP4i5WDpkihpyUMFroc9nCuHxeicX7hFo9Ip010F/2uBQbgy
         pNCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fcrLqdsd;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-350fe7bcdf0si1093a91.3.2026.01.12.12.53.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 12:53:52 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 5BD516000A;
	Mon, 12 Jan 2026 20:53:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F3ADAC116D0;
	Mon, 12 Jan 2026 20:53:48 +0000 (UTC)
Date: Mon, 12 Jan 2026 12:53:48 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Maciej =?ISO-8859-1?Q?Wiecz=F3r-Retman?= <m.wieczorretman@pm.me>
Cc: corbet@lwn.net, morbo@google.com, rppt@kernel.org,
 lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com,
 vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org,
 catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org,
 jackmanb@google.com, samuel.holland@sifive.com, glider@google.com,
 osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org,
 Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com,
 thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com,
 axelrasmussen@google.com, leitao@debian.org, ryabinin.a.a@gmail.com,
 bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com,
 urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com,
 andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org,
 vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com,
 samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com,
 surenb@google.com, anshuman.khandual@arm.com, smostafa@google.com,
 yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com,
 kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org,
 bp@alien8.de, ardb@kernel.org, justinstitt@google.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, llvm@lists.linux.dev,
 linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org,
 linux-kbuild@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for
 x86
Message-Id: <20260112125348.124d201ef2baf762561a43af@linux-foundation.org>
In-Reply-To: <aWU-oL8oYS_PTwzc@maciej>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
	<20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
	<aWU-oL8oYS_PTwzc@maciej>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=fcrLqdsd;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 12 Jan 2026 20:08:23 +0000 Maciej Wiecz=C3=B3r-Retman <m.wieczorret=
man@pm.me> wrote:

> >OK, known issues and they are understandable.  With this patchset is
> >there any way in which our testers can encounter these things?  If so
> >can we make changes to protect them from hitting known issues?
>=20
> The gcc documentation states that the -fsanitize=3Dkernel-hwaddress is
> similar to -fsanitize=3Dhwaddress, which only works on AArch64. So that
> hints that it shouldn't work.
>=20
> But while with KASAN sw_tags enabled the kernel compiles fine with gcc,
> at least in my patched qemu it doesn't run. I remember Ada Couprie Diaz
> mention that passing -march=3Darrowlake might help since the tag support
> seems to be based on arch.
>=20
> I'll check if there's a non-hacky way to have gcc work too, but perhaps
> to minimize hitting known issue, for now HAVE_ARCH_KASAN_SW_TAGS should
> be locked behind both ADDRESS_MASKING and CC_IS_CLANG in the Kconfig?

Yes please - my main concern is that we avoid causing any disruption to
testers/buildbots/fuzzers/etc.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0260112125348.124d201ef2baf762561a43af%40linux-foundation.org.
