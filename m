Return-Path: <kasan-dev+bncBDBK55H2UQKRBMVR6PEAMGQEVZOHSVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 62BBDC6BA35
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Nov 2025 21:36:04 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-42b2ffe9335sf6076716f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Nov 2025 12:36:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763498164; cv=pass;
        d=google.com; s=arc-20240605;
        b=isx7FtQNQyv/a1DLL4MTFEvZTKQewR2dvjQmapOe2jdsWrZh/dNA4XnUYuBYiIhNKU
         SB4lLt1/6C+G5pnuVoSemWMwOhp+6Kmz3EhDTdsdXPq6ZsNqjj4DwBnho9cIBbMvXc+v
         G5E/ElbkpNXOMje1Sq6cynjeb8tCeBrSPp7Q0cCYLFkHMFfrFHfjRULBKm+7SLlwLboB
         cEC+Mcrk3uAmDvQsRXawuZr76ucm00CukRPja4C4w9YP88nVFXcCBQYFp7/+Jcs8Vhww
         0h6vuVpTQH7iXYDQT8fo+22/AyWv3XATko62//aihfq0qXysM11XocFpNmePjywOI998
         CGIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=UzpMPkL8oWop25oA3kN8Jzq9CC399nqZWdBf7TFseao=;
        fh=aVpXy0MlVreh7bcXdbGk/B2vl9G/FwAE5iY1uIIztII=;
        b=KsBdF2wd13nYkd7L0Hi2qZAyXY1cHgeZQ14p/FYFmCkfIPfB7OAwPrFV02OoB2Icji
         SQkJMHQPwl80nRHjdYsAqM4HbOXC2lnBrelYl0Q0LtVshSH1vdGuznh2zvPWaXkNyDhT
         rcq5+mahPnarqEu0D06Ga8h9mM2pV3vPhFdCu+em1XkaA4kwz/kNechEhEBloIajwJHm
         GH/rIHhHuwEK8sImomBPdzS/KlK8cyVOkTaDX7nnN7Fn9jufVNfqxOrd+X16R894Zf2v
         l8uVwhfCcggvrVdMWvKkj2peLqGMCgftCQ+2nnoYT7MIuOe0J4bVVIi2I+D0bkv/mD7B
         W9SQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=dQYjUwS0;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763498164; x=1764102964; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UzpMPkL8oWop25oA3kN8Jzq9CC399nqZWdBf7TFseao=;
        b=TULFpBcCfamhXFbnsIGnLBqLdAcGkSQQr6sXWgA18U3XNKJ9H5FO51rlHLKXbPF8Mf
         y4KS5pI/F96HYRQzqfXt9RVzp2m+ob7EYQHueXo+qPF+CmtwEEa1+8SxDPZb7Es4JH3h
         Mx/4hmHwAczFP+R24ys13ZGrzOXibC6UnvU62liXw3bpJA+vcUM9minQgmFMSbN0k1q/
         uYP0BR64wWGkHWW/vjWirad55W1VqLcDV6fJT8IDAYeiI8zgEqqtYtjviqvzI2Ls/4Ik
         RHa9rEeRP9hS+OqQ+Vv0xwcDAw5uEu8xcGugyOT2krZXNZ3dywRTTKPk0ThCzRXAR/fx
         BGDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763498164; x=1764102964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UzpMPkL8oWop25oA3kN8Jzq9CC399nqZWdBf7TFseao=;
        b=bGGdrbxPFqPs6HANFoClS84N3uu6BNMegZ7Ge4l99/ORREiX/vUYAhTbaLPPDd4gci
         fd9/xJL3G+Rl2vbX2JZhc0GHIHlO1ofqNOQY0d0mXW/v2FIEX9/6zLECuilf/tsRnIso
         TrvAex+hEfKUyPQXgXGWlgd2qXgoFzFte0W76hFifW5eoPnlry3MIRGOxHZ5JqesMhEC
         dtWBTSxs1UCYllA9OS2fFdD+ooBTCpCcgxv09HddhrEGwx77nn3vATOxzViV1Xp47bCF
         7IMWu/oADoT30UIA3bBeFyt9eBdUSytZUXfJ27q4u/MdM1U0oW+I7Pm2u4Gbiuk5bgeZ
         PhWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWs/Jn/c8m9e+xBoQIorAEPYTaqW43bSpkasKziqOn7xFq1IstuzWhOvxCTdaB6nZGCM7IjiA==@lfdr.de
X-Gm-Message-State: AOJu0Yweg548mcbMLcm71/jnu1uiG1h8/zsp1e66fdTpMS9JirWSsBjJ
	Upta8iwRQrhzd5VuLCbTP2fZjI917pTFQceIfRJm8dxDsrLnE2jlb80x
X-Google-Smtp-Source: AGHT+IEfXypz0NThAakIoSKm/bEWsSyCfH9D3TdBbprKTolYJ5Ty1pgL/0miFOiSggFub/CrRfPv1w==
X-Received: by 2002:a05:6000:2c05:b0:42b:55a1:2158 with SMTP id ffacd0b85a97d-42b593497c2mr17528656f8f.17.1763498163394;
        Tue, 18 Nov 2025 12:36:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zx5CahJuSq9/lMWh33kI8k6I7tjbDcYBZsqFBFr7fERA=="
Received: by 2002:adf:e381:0:b0:42b:52c4:6647 with SMTP id ffacd0b85a97d-42b52c470afls3626585f8f.0.-pod-prod-02-eu;
 Tue, 18 Nov 2025 12:36:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU+I86NjzPu68lhSpa41xWZdvc1tMoSND1uIKDULM1hwwRvyGFm1fnKjEe7PZkix1NcYwQ0SMjUyvk=@googlegroups.com
X-Received: by 2002:a05:6000:2405:b0:42b:3b55:8917 with SMTP id ffacd0b85a97d-42b59377ff8mr16565761f8f.36.1763498159994;
        Tue, 18 Nov 2025 12:35:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763498159; cv=none;
        d=google.com; s=arc-20240605;
        b=cgmWofB6q+b6JMrqJcHhy0BSxEIe3UBkDeoPp/27f7v7beZVY0QjK9q7C77d1j8YgY
         8YGTkwSLOFtWZHs1gUQYIEzzaelpZLjNINbb3KXIlSP4kkeFYpsL+TKBvjAm2tmbIC4v
         XgJ/FrcYNSa6rS4uC6whsr3KGD0fSBeydT3RvtGFuKOEHOv7FiV7+F7WNsESxhY5BojN
         PdnOaNu3Od7a5IqC/IfFKTAeCowncNUQIkAS7QNi7zKpAvOADF/4KpZWEBGdDMnNLg5/
         2aeJNbxcxAS1UjFsaroJz2Dl18P1evtb5zSActAC44ZWNa9xedCbzyLtp5Txn9tXiquI
         Xaqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=8ne+SHPq+6VfT3qkrqy+bvDWVXNhMCjamVWYxqPzmM0=;
        fh=/iZLVU4250YMBjfJj0F6LRE3iDX8RQQ1U9+ttyjj8Fo=;
        b=g+PQpfmOm83hPmQwJS06jgDVPVXPw1zb40iOjF2SpFxb/6E9yACg+85phNlka0jbwx
         gSI5G1EnhBnmgCXZjsUhVE/mYCEHZreE4yhCERXxtsQtwqfXkzRqsCrk0LExb8f3dcR2
         VYd+nU3/1YDycLzrnDnkRxKb8A+0vkC1Yhs71AeCzIM4xScaqSN1TP+tNWpX+/L7HUyc
         amCwdAIIzuQP7CSt1IduEJmJjmwDN3tAUJ2qJhvhTRhBAI1cMy3ER3BKgg2JWvZvHeOc
         JmfZJ/IICdmvWsqVQbdtzDVTr5/C3I6iWzNZAcFc04f1/xRRCrHPiDrCX/4CpY1E/pOd
         kfcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=dQYjUwS0;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42ca56301b3si71477f8f.9.2025.11.18.12.35.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Nov 2025 12:35:59 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vLSQb-0000000G1y8-01Pb;
	Tue, 18 Nov 2025 20:35:53 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id A093D30029E; Tue, 18 Nov 2025 21:35:51 +0100 (CET)
Date: Tue, 18 Nov 2025 21:35:51 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Maciej =?iso-8859-1?Q?Wiecz=F3r-Retman?= <m.wieczorretman@pm.me>
Cc: xin@zytor.com, kaleshsingh@google.com, kbingham@kernel.org,
	akpm@linux-foundation.org, nathan@kernel.org,
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de,
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com,
	kees@kernel.org, baohua@kernel.org, vbabka@suse.cz,
	justinstitt@google.com, wangkefeng.wang@huawei.com,
	leitao@debian.org, jan.kiszka@siemens.com,
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com,
	ubizjak@gmail.com, ada.coupriediaz@arm.com,
	nick.desaulniers+lkml@gmail.com, ojeda@kernel.org,
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com,
	glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com,
	jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com,
	dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com,
	yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com,
	samuel.holland@sifive.com, vincenzo.frascino@arm.com,
	bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com,
	kas@kernel.org, tglx@linutronix.de, mingo@redhat.com,
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com,
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org,
	rppt@kernel.org, will@kernel.org, luto@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, x86@kernel.org,
	linux-kbuild@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 15/18] x86/kasan: Handle UD1 for inline KASAN reports
Message-ID: <20251118203551.GQ3245006@noisy.programming.kicks-ass.net>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
 <8b0daaf83752528418bf2dd8d08906c37fa31f69.1761763681.git.m.wieczorretman@pm.me>
 <20251111102719.GH278048@noisy.programming.kicks-ass.net>
 <a4vtlaxadmqod44sriwf2b6cf5fzzvngl6f5s2vg6ziebahjtv@yctbqspkdn2b>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a4vtlaxadmqod44sriwf2b6cf5fzzvngl6f5s2vg6ziebahjtv@yctbqspkdn2b>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=dQYjUwS0;
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

On Mon, Nov 17, 2025 at 09:47:20AM +0000, Maciej Wiecz=C3=B3r-Retman wrote:

> >> +void kasan_inline_handler(struct pt_regs *regs)
> >> +{
> >> +	int metadata =3D regs->cx;
> >> +	u64 addr =3D regs->di;
> >> +	u64 pc =3D regs->ip;
> >> +	bool recover =3D metadata & KASAN_ECX_RECOVER;
> >> +	bool write =3D metadata & KASAN_ECX_WRITE;
> >> +	size_t size =3D KASAN_ECX_SIZE(metadata);
> >> +
> >> +	if (user_mode(regs))
> >> +		return;
> >> +
> >> +	if (!kasan_report((void *)addr, size, write, pc))
> >> +		return;
> >> +
> >> +	kasan_die_unless_recover(recover, "Oops - KASAN", regs, metadata, di=
e);
> >> +}
> >
> >I'm confused. Going by the ARM64 code, the meta-data is constant per
> >site -- it is encoded in the break immediate.
> >
> >And I suggested you do the same on x86 by using the single byte
> >displacement instruction encoding.
> >
> >	ud1	0xFF(%ecx), %ecx
> >
> >Also, we don't have to use a fixed register for the address, you can do:
> >
> >	ud1	0xFF(%ecx), %reg
> >
> >and have %reg tell us what register the address is in.
> >
> >Then you can recover the meta-data from the displacement immediate and
> >the address from whatever register is denoted.
> >
> >This avoids the 'callsite' from having to clobber cx and move the addres=
s
> >into di.
> >
> >What you have here will work, and I don't suppose we care about code
> >density with KASAN much, but it could've been so much better :/
>=20
> Thanks for checking the patch out, maybe I got too focused on just
> getting clang to work. You're right, I'll try using the displacement
> encoding.
>=20
> I was attempting a few different encodings because clang was fussy about
> putting data where I wanted it. The one in the patch worked fine and I
> thought it'd be consistent with the form that UBSan uses. But yeah, I'll
> work on it more.
>=20
> I'll also go and rebase my series onto your WARN() hackery one since
> there are a lot of changes to traps.c.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251118203551.GQ3245006%40noisy.programming.kicks-ass.net.
