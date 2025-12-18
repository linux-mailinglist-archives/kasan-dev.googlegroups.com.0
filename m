Return-Path: <kasan-dev+bncBDBK55H2UQKRBFM5R7FAMGQEZUIHBMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 35FE6CCB422
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 10:51:19 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-595904df717sf340153e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 01:51:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766051478; cv=pass;
        d=google.com; s=arc-20240605;
        b=hzyEVTBuHweZPFkeQ2iblsPwEDlupvb/kFv3wR+wAhfi4vUC0KsigFyD8lNVdnJ1hT
         D2AciimiLIklCvCST/X4QNDpWURxe9eb6dh6Tg7c2Y/8j9X17HkWiAb80clxRvgjlOvq
         6/pilcsrPfqLvGFu/us2luCR1N++/wqZm0waJQ6CpsHJKO2PSnX5cfdstiPD+CF/WFH9
         JKDPEqJNNsDno1auwiz2VoqemHpCCcIjgLDeSaPSrsCDnD5rMf+EScQBNXuVkXwlp9lG
         TinyQbpOcsyu+5A0zFj4C1XrrgYYww3W1wXb3wrOM73sK5iKepwe8KMs6xJDZxCDg7At
         Ko+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=P9tzVJoKtfqOLbU0aztUOe7rwsloAhYLjMX7X9vGeG8=;
        fh=k7QN96AAVPL+UCDCj52CiUsLBDXBLdSIn1C5MIeWiGk=;
        b=Fy6Db/fgIUu5ezGOK94pz/dPj1QotI52CW34gouwCFQoNdYqWCInzkHkKs4Hylz+74
         j0OYzfMJpdsKSFNv0kd6upQgXztBx4R1PN3mXlW7wLQwY6mPgv6llpSX4db2/G4XmPfp
         chjWbF4ScAS49Ulhmq/aEjI77WgNgwsxI83mxmVSXyHaL7NPjyLn+1v8NLDX1YU5Z7VT
         VY6Tj/6t+oyO2JYoujiYKua3jv2VoyprIGQ/9nlQg45JHPFUT/YntkLy6z17qq3VohIH
         CYYc1l5+5ASIFrVUkiTF7gtAseM4cDrbrYrl/VoQfWZdzTHsZjGJzSLeGNx+wvglzDwS
         /ELQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=AdPcosY7;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766051478; x=1766656278; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P9tzVJoKtfqOLbU0aztUOe7rwsloAhYLjMX7X9vGeG8=;
        b=ic1++0fcida3c8cY5peKNaY/oxYb+5eGuu2molIB80GaQapJYIWXywmFIXntjwTNGi
         t6Wxk3JDE8VEFav21f8Q0xBuaX4tE3K14FdqUQttVjNc2IezN8dhnxw2Tx6FsFXCz3I1
         SUec5RqJfnutwW+OeLyAhFba+IoA/2dv+cDQD046IJ3hTbTlhTnYpqlU2atMzqP0kx2R
         FH8B/Ghgscx1/qIGXU6Wt87UKqPI2KAvNpepHndI4SZPMDFPdR9lBFOkqtlrSSZ923bW
         m1fMCzOrqxdZO8pWg8tA/o8I6/E5eFQMiK4hkFRDtiLe/Y9y21Mkixcc++ZxXDxo8lvd
         PZJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766051478; x=1766656278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P9tzVJoKtfqOLbU0aztUOe7rwsloAhYLjMX7X9vGeG8=;
        b=E5119D/veElaii9ok9GhhqkdHwQSvawhNeo3XOnRmGtWjIdbe6nRSsk66LdJ5lLE6J
         ZSlG91ODPyYNG9TMTviUWXvrJNoqzAtrsCm+d+5tt+RXPEeu2DwoYkWiUmWtrV9bDEbO
         c0kI3uPl265G0J4DrQUEG8drBO4HPgJ7N8eXudPsaoTDvWWCCNBoD0EhezHNv83z9Utj
         gwP2Es45di9zI+8DF9hFbmbNpAFPvVBbq8jaIr9DPX5u8BF0FQuwSP/YyJBx20tiBkH5
         S2iG09YC5gUrr4GCfA/6i4XGGfmjWl5lVdht8Tdf0scTu1Ejm6JTiIEj5k7KHyE31V1M
         eIjQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXldGI7dl6nN+28mKjUvGDuEIz/0shcjC8aOVl9xWMUBFaHh9PFw/O41u2lWm+6jSafzGI9VA==@lfdr.de
X-Gm-Message-State: AOJu0YxAK9M9db5hSj1HtTi5iJj8zGYUrEY+qy2g9L9zdw2Q9USsWBd6
	zRtWRfiMoV2dVN6HaMWjp3iFYutffy/skOVQJTdzA5DfqfBvesUxxU/t
X-Google-Smtp-Source: AGHT+IG+K+R5aIK0PgtTmaQVqKvUG//SFrCOPt0tcrG3oMDROfy5hK+IT5gQepBbSWHAyEpATpdFrw==
X-Received: by 2002:a05:651c:507:b0:37b:971a:212c with SMTP id 38308e7fff4ca-37fd1f4391cmr65954671fa.22.1766051477860;
        Thu, 18 Dec 2025 01:51:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYnRpBMgUS/SIenDkTHYjk2c1Mm8FSRtdebJPpBHOowFA=="
Received: by 2002:a2e:9059:0:b0:37f:ab54:159c with SMTP id 38308e7fff4ca-37fcf00af37ls10847871fa.1.-pod-prod-01-eu;
 Thu, 18 Dec 2025 01:51:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVFGyI/E4sTCnpTl6Vh4V2o9/vDEFmSScBtIFitEKEQ8MNtuH40bQfvzVSI5+Z1l3zTcgj2DtsNYds=@googlegroups.com
X-Received: by 2002:a2e:bc02:0:b0:37e:87a5:4d09 with SMTP id 38308e7fff4ca-37fd1e78e38mr58220201fa.12.1766051474714;
        Thu, 18 Dec 2025 01:51:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766051474; cv=none;
        d=google.com; s=arc-20240605;
        b=Zg0yDOQYMt6by8ofinl8e8jgyDnC6iJP0kBxCXMJ6IH6CPloiRCDByJsUuOCWucIcd
         mHKPYtYVEEDguTFly9K3x9ADg0j+ub+TK+AfBBjxHfIf00McP6phGsGearAy43Us5z32
         tsgots9yV0TbnRZYbrZJFJCCHHlDskrts3RGBavU/E4HjZgjfHcgdsFyQean7Iv/gfXK
         G7LKtXGUiO0AtgL5W00k8fUrf+PMarcgk35xpQSUqvEXD0VAqgbOeDHI3t4xXO00r3B1
         aXKYILCHd6hZCM+YexsovOtvxokgRoJElud/vxFrUrsg6v3YJqkJA2gyTC6/1wjv2zz2
         3Uyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CV5CQCad42/bUva9s7fv3RzPqF2E+dAhvuamq71vXP4=;
        fh=V/tRzV+EqYayI5Vp1a76gsoKN0T2eErltA0Dm58jVe0=;
        b=ODGLA0b9zi6X4xX1hbKS93BeWTCo1n0BxRThm16k9dNHd487NbGtF1HkHbSyeBAMMe
         9HJOJII/QDJ8ov3bbKIR5HRdXqRHTABQ2mgKRMtyBc1bChZYrpY9uPuoqsei4Nawwzvo
         r6Srre58lb6sVTWLRXxEZM0iJ6tDCpu0/LsYlw3Q39zcY6cRrnSmV9NjsBpqTagRmV9K
         ptkl9G8RU6KeZxtfeoOJ2ybBTwk5NeUB+cJrmMY/dhURR3cLu2dwWkFz0Kt46nQvje/2
         PTCT+9+dsC94rkBjQjKtlVdRTvu+jxMOJNwoqSXwymMleqZcV6erXJFi7z8X3CMvjtZk
         QNNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=AdPcosY7;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3811365869csi297611fa.5.2025.12.18.01.51.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 01:51:14 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vW9ni-00000008Ur8-3Uah;
	Thu, 18 Dec 2025 08:55:59 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id C90A230056B; Thu, 18 Dec 2025 10:51:12 +0100 (CET)
Date: Thu, 18 Dec 2025 10:51:12 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Marco Elver <elver@google.com>, Kees Cook <kees@kernel.org>,
	Brendan Jackman <jackmanb@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
Message-ID: <20251218095112.GX3707837@noisy.programming.kicks-ass.net>
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
 <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
 <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com>
 <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
 <DETBVMG30SW8.WBM5TRGF59YZ@google.com>
 <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
 <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=AdPcosY7;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Sat, Dec 13, 2025 at 08:59:44AM +0900, Ard Biesheuvel wrote:

> > After that I sat down and finally got around to implement the builtin
> > that should solve this once and for all, regardless of where it's
> > called: https://github.com/llvm/llvm-project/pull/172030
> > What this will allow us to do is to remove the
> > "K[AC]SAN_SANITIZE_noinstr.o := n" lines from the Makefile, and purely
> > rely on the noinstr attribute, even in the presence of explicit
> > instrumentation calls.
> >
> 
> Excellent! Thanks for the quick fix. Happy to test and/or look into
> the kernel side of this once this lands.

Well, would not GCC need to grow the same thing and then we must wait
until these versions are the minimum supported versions for sanitizer
builds.

I mean, the extension is nice, but I'm afraid we can't really use it
until much later :/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218095112.GX3707837%40noisy.programming.kicks-ass.net.
