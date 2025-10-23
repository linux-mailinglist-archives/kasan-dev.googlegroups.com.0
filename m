Return-Path: <kasan-dev+bncBCUY5FXDWACRBYUO43DQMGQEBMRTN6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 763E4BFEDC3
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 03:39:48 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-378d710cb33sf773121fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 18:39:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761183588; cv=pass;
        d=google.com; s=arc-20240605;
        b=cCUo6Hp1GF0wOI3e3tNuqFLAOvBCqyS3kRUq0YouZNodroZB5k75JADkuYBHdF7C6y
         mNpLWHDoDBWGunMlg0wV2OVJQdjVD2xtV4vP51WAN98XHbbXiZq01tQN2AXhTRUC9MSZ
         2iWdnMV37cDOL7WusrbgJIlney4OvybaJsTXHA8RFYaCumuhRvC5DM8P6Vis5Dw4rFzo
         yUAGNQpqM9urYjURT16+RaL3ZUgSVsgwpJsJqm6L7VL2OTEGsbGm3CLWBFw31ZIS/n5s
         kqyHaxBSIhxn4T4VbC3Ii5zyPA0WLxDsjc7EHqJF2kyNVclNT3n2+gmrj4LSuxNmzWtE
         Pz3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=zRySiGyJZimkAvEq9U2mkEFiUhGeQ5kJFMqOeKDYJ+Q=;
        fh=tZ06P25LNgruYh5I88VhHB5E99IkUh8ZVBz3T8E9XS0=;
        b=fgt6wsJa+3mZJZJvUUTUT9bDnDiFATk+UI57KfZ9/89lXVWYNWfEapxSDJIP4NHDIo
         AphTnYk5aiXeJ3RBXAb++0wBRYBEbYAxyWAyBLyyTfnj1GvTuBmfnpwSpVMQiATsdM62
         D+tKnp2jbggpvYkGXlERO4wzd/4maINq9lywaVrCs9iG/qHa/AteTdzd0CmAxSvEbgUb
         A/BrF0/6ZiIF6uVwhwrgJeObafZaKvdj7Ktr3eDTGCm2QrMP/zHXCPoFC1e4rVLCKUXb
         8/Wlb51IgwcChdWhZLWZ21yK7Ustl7sn0Z3L7E2U5NJ5H7+C4H0DC9mMn7Un9l1ncEvk
         R86w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PbCb0eEX;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761183588; x=1761788388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zRySiGyJZimkAvEq9U2mkEFiUhGeQ5kJFMqOeKDYJ+Q=;
        b=pw8EYp780nM7m10u7DbGlSqA13p24X06z8XrpDSgxQqJgcAUGkpSmkA0tfJwp0a+d+
         Wa8B/PruwFhkSzSGenVlPcxdAnd/HNspS4dv5oEwJWg2Tn1RhV6ItF4KHuVnO6CusrVE
         nAV1ONi8wDtkoIVI4DxmGTHxuCl6V0UK31v01pBevY2+ag7eHSvmOos7YoXeYY5RS6JR
         qT/B6eSjFcCioFWuvqNhZFMdPXufmMKKWn09wFG2pTxN4AF6U7qpD9Khrdkb2fpEYwdI
         Zd154/xHAU/BHEKRBazJtF7x5k2sGR0D5GJbJH60DkeIF5XjHdRtaEbHQccJZ8Zd3Xg6
         ypLg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761183588; x=1761788388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zRySiGyJZimkAvEq9U2mkEFiUhGeQ5kJFMqOeKDYJ+Q=;
        b=GvLGBTWQk5qVmrRR0AinWWxdozEsGsU2V4IPadir1Wxilo3kpvh4TUTdF4zQQDiazu
         CdQzsxCGMWGj2a2hFr/Gym8pR1OvJSwzLeTE1+GkvRNZuYAFDdcMACb4PeI74yReZbeS
         QvT4CmDO1zxcywbdnHpCHrh7sCcRjTIuVbfZvhTQhofl2Ahb8K0BfSTz8be3Tw20vqh9
         ZhD8LXnT138ekgiHg1ct2GSGDZYC+OyajZhalqXTywaIrMquPuvr5Yz33T6ABhOIMMWX
         cwpMDgT1Q1p1Qz4Zo6M3cyr0DoF26fHjt0YxkSErjbubNrGYCOoe3Id58xYtySzBQQnl
         o/MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761183588; x=1761788388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zRySiGyJZimkAvEq9U2mkEFiUhGeQ5kJFMqOeKDYJ+Q=;
        b=WY/MWFz5gfISjmD70k8x61EF8scKXb7fJ9iaV78Untxc9YBPl2GqjBwVPzmXYWwXlQ
         zxFV0cmQ9IMdNa6ljyUafw3vJ4ZhZPE/dmEMLLtezP8tyF0Qi4ykM74SXG5ZPDVytxQl
         JGLDSPI7J3QtcDD5pfNF7bWjEQPom0dBhGdl1yGxNuCJLnc3X6QPc1JduDyX41yO3k52
         OFhXk7gumFGiXi6lF4d6ctBnsyaIwb6qdt/+gX8tRcxverD90uSfxD2TQC2wAFH744Mo
         xyyWJDaf/jWlYiRnUmY1ZUUFRuVKRcI+WXuta0Ga+DU+n29nWmV2hBdVOhOClxhOejWu
         GFnA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQ2DpaujK78PgNNiRPVE/Afflc6IsqBEhxFPux43tP7yzXOilOd5H6a+cfRsPJ314nlW0/sA==@lfdr.de
X-Gm-Message-State: AOJu0Yx/oi5SOKiasy5FNmlXWh7R6buPKNXI8XteWCB/9mesKwdtvGRF
	/MdMN6ndxJ3o6+uGvRFCdCGhitjJQB/IbvyDUTxIFY/Mm58S0zgDk5we
X-Google-Smtp-Source: AGHT+IGS9D3eqWDMnofffY9HTVUVDNWpEF+DPcksbcbvhmBV8QxH7olOg509cItxxRUqeE0xM2t6OQ==
X-Received: by 2002:a05:651c:198d:b0:332:1720:2ec7 with SMTP id 38308e7fff4ca-378d699694cmr1891031fa.0.1761183587264;
        Wed, 22 Oct 2025 18:39:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd740+p7zvCQvZAwTFFhLYEIjC1GKVea6dhc/AmrhYwn7w=="
Received: by 2002:a05:651c:25d3:20b0:338:4aa:556a with SMTP id
 38308e7fff4ca-378d63941c0ls267841fa.0.-pod-prod-01-eu; Wed, 22 Oct 2025
 18:39:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6T598S2cdAU0ba4AtE8OKL6MauOtLJ8mqAIML8eGvmS3f5NWHDu5nESQQenWX4LDWnhVG904jn/k=@googlegroups.com
X-Received: by 2002:a05:6512:3e1f:b0:587:68fc:c4f with SMTP id 2adb3069b0e04-592f5a6f6fbmr190379e87.53.1761183583618;
        Wed, 22 Oct 2025 18:39:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761183583; cv=none;
        d=google.com; s=arc-20240605;
        b=NXK/+Iyf7Y2M/nrCMksvu1lRFu+NISvUM9mnYTePJmZcmuMGqzhR1OSz9cwnu7QE3K
         G+Obf4Znm7vYZme8aQwDlwZ4szNYkh+TBDXXp0bhacjLBAbHEMjKA3dS8Evy8oTdXZmn
         uBzhHLNFdsgRKeiWGqN6QmzqTORtmOQwSDoaz+rRzOmGznUVvTqf7F9psd8cSYuBh6mw
         mJsIz44PkoMSmbYPYoA9jJVMnpAWQTJ39Ln325QreSwFC4JD0bMSlM0e7yt0l0uicdbw
         12opAb2ipgEy7jNVP9xbc4pltV4If5lOdze6CrfSH5/QudU/j57djZrT/BUZ/no8SoEp
         kfyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aCgsnRi7DdXq+4PeoxX5w1Bin2sJADD0GjGW6qb07u4=;
        fh=ECBtgaBlFzPdeVROOjOZYZe3ATgfWC8g+0d/GZhwNLo=;
        b=fwQF8qXvSWwyiT/cfwSDSGRDLjs6mtQUEjFCxcLW1EZh+YLJHU44dxSItkHtKCJVgW
         HyQSGEzTDXSSxdjLHhQDWnQUN/OwQ//0nRdjo2npb5KtPSbG5f2rRNrFvR2P10kRbGnV
         PqacIwg9UyG6D/zHM+7+yxIda1ouApBUon3ExxsXUko2wT9bdo+s4TqwzQRrvpl4mIy0
         AiNZcn9NusLwWBjOrOeRutRxV9S3rBkBV9hdDYh5tqDaOdl7Jl4gAvGni2CHOjSr85er
         kbbOkbsqENAc7Yac3m9jEPswYCrQ9RrcbzDH9xXEpy2J+CvFHB3TDy0W2bY0n60m/oWH
         Qo0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PbCb0eEX;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-592f4cd5588si16098e87.2.2025.10.22.18.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Oct 2025 18:39:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-4710665e7deso934125e9.1
        for <kasan-dev@googlegroups.com>; Wed, 22 Oct 2025 18:39:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX2hG4fOvcsCR7bb1Hm9fqomH03AQh3p0JBr/o+nzftBqmvh/Q+r/95qKtQKYZy0L4l0shUmAH2FXg=@googlegroups.com
X-Gm-Gg: ASbGncvzgfFDdic7irbRso7iwSpV4d2bP7woGQqtjNRNoLvAbpfnr1ikh3VPlNxx6Il
	HMUrrjheYsU7kkzgHFk+vV5KyBixYQnhWiMJ9cJWxFY6upWWAOhc30mxIHjjA9volHSFvB4xMhe
	nE9qlWuHkxz2GnKXItlKG8FLtgrT4mErDGlnjFCI5vup77EiOcIfkZHZ+rQ9xGOiuiIKQipzudG
	ml5em8Y3dfREYEeZTWMVKVzzdvgaiOffG0bJWbsDArjyGnJTwy9K941i4pUrSWenwp7qlVVBoXV
	OHXgsDLIg24YxBP5V0BRwEqzGYYw
X-Received: by 2002:a05:600c:34d0:b0:46f:c0c9:6961 with SMTP id
 5b1f17b1804b1-475cafae8b8mr3068325e9.14.1761183582636; Wed, 22 Oct 2025
 18:39:42 -0700 (PDT)
MIME-Version: 1.0
References: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
 <20251008203111.e6ce309e9f937652856d9aa5@linux-foundation.org>
 <335827e0-0a4c-43c3-a79b-6448307573fd@linux.ibm.com> <20251022030213.GA35717@sol>
 <20251022143604.1ac1fcb18bfaf730097081ab@linux-foundation.org>
In-Reply-To: <20251022143604.1ac1fcb18bfaf730097081ab@linux-foundation.org>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Wed, 22 Oct 2025 18:39:31 -0700
X-Gm-Features: AS18NWCpy-eVIKqwjq3HvvI-t1t4YZx5136aumXfPGuarDyJS0x745rdekxcgMU
Message-ID: <CAADnVQ+o4kE84u05kCgDui-hdk2BK=9vvAOpktiTsRThYRK+Pw@mail.gmail.com>
Subject: Re: [PATCH] mm/kmsan: Fix kmsan kmalloc hook when no stack depots are
 allocated yet
To: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Harry Yoo <harry.yoo@oracle.com>, Michal Hocko <mhocko@suse.com>, 
	Shakeel Butt <shakeel.butt@linux.dev>
Cc: Eric Biggers <ebiggers@kernel.org>, 
	Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Alexei Starovoitov <ast@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PbCb0eEX;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 22, 2025 at 2:36=E2=80=AFPM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Tue, 21 Oct 2025 20:02:13 -0700 Eric Biggers <ebiggers@kernel.org> wro=
te:
>
> > On Fri, Oct 10, 2025 at 10:07:04AM +0200, Aleksei Nikiforov wrote:
> > > On 10/9/25 05:31, Andrew Morton wrote:
> > > > On Tue, 30 Sep 2025 13:56:01 +0200 Aleksei Nikiforov <aleksei.nikif=
orov@linux.ibm.com> wrote:
> > > >
> > > > > If no stack depot is allocated yet,
> > > > > due to masking out __GFP_RECLAIM flags
> > > > > kmsan called from kmalloc cannot allocate stack depot.
> > > > > kmsan fails to record origin and report issues.
> > > > >
> > > > > Reusing flags from kmalloc without modifying them should be safe =
for kmsan.
> > > > > For example, such chain of calls is possible:
> > > > > test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
> > > > > slab_alloc_node -> slab_post_alloc_hook ->
> > > > > kmsan_slab_alloc -> kmsan_internal_poison_memory.
> > > > >
> > > > > Only when it is called in a context without flags present
> > > > > should __GFP_RECLAIM flags be masked.
> > > > >
> > > > > With this change all kmsan tests start working reliably.
> > > >
> > > > I'm not seeing reports of "hey, kmsan is broken", so I assume this
> > > > failure only occurs under special circumstances?
> > >
> > > Hi,
> > >
> > > kmsan might report less issues than it detects due to not allocating =
stack
> > > depots and not reporting issues without stack depots. Lack of reports=
 may go
> > > unnoticed, that's why you don't get reports of kmsan being broken.
> >
> > Yes, KMSAN seems to be at least partially broken currently.  Besides th=
e
> > fact that the kmsan KUnit test is currently failing (which I reported a=
t
> > https://lore.kernel.org/r/20250911175145.GA1376@sol), I've confirmed
> > that the poly1305 KUnit test causes a KMSAN warning with Aleksei's patc=
h
> > applied but does not cause a warning without it.  The warning did get
> > reached via syzbot somehow
> > (https://lore.kernel.org/r/751b3d80293a6f599bb07770afcef24f623c7da0.176=
1026343.git.xiaopei01@kylinos.cn/),
> > so KMSAN must still work in some cases.  But it didn't work for me.
>
> OK, thanks, I pasted the above para into the changelog to help people
> understand the impact of this.
>
> > (That particular warning in the architecture-optimized Poly1305 code is
> > actually a false positive due to memory being initialized by assembly
> > code.  But that's besides the point.  The point is that I should have
> > seen the warning earlier, but I didn't.  And Aleksei's patch seems to
> > fix KMSAN to work reliably.  It also fixes the kmsan KUnit test.)
> >
> > I don't really know this code, but I can at least give:
> >
> > Tested-by: Eric Biggers <ebiggers@kernel.org>
> >
> > If you want to add a Fixes commit I think it is either 97769a53f117e2 o=
r
> > 8c57b687e8331.  Earlier I had confirmed that reverting those commits
> > fixed the kmsan test too
> > (https://lore.kernel.org/r/20250911192953.GG1376@sol).
>
> Both commits affect the same kernel version so either should be good
> for a Fixes target.
>
> I'll add a cc:stable to this and shall stage it for 6.18-rcX.
>
> The current state is below - if people want to suggest alterations,
> please go for it.

Thanks for cc-ing and for extra context.

>
>
> From: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
> Subject: mm/kmsan: fix kmsan kmalloc hook when no stack depots are alloca=
ted yet
> Date: Tue, 30 Sep 2025 13:56:01 +0200
>
> If no stack depot is allocated yet, due to masking out __GFP_RECLAIM
> flags kmsan called from kmalloc cannot allocate stack depot.  kmsan
> fails to record origin and report issues.  This may result in KMSAN
> failing to report issues.
>
> Reusing flags from kmalloc without modifying them should be safe for kmsa=
n.
> For example, such chain of calls is possible:
> test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
> slab_alloc_node -> slab_post_alloc_hook ->
> kmsan_slab_alloc -> kmsan_internal_poison_memory.
>
> Only when it is called in a context without flags present should
> __GFP_RECLAIM flags be masked.

I see. So this is a combination of gfpflags_allow_spinning()
and old kmsan code.
We hit this issue a few times already.

I feel the further we go the more a new __GFP_xxx flag could be justified,
but Michal is strongly against it.
This particular issue actually might tilt it in favor of Michal's position,
since fixing kmsan is the right thing to do.

The fix itself makes sense to me. No better ideas so far.

What's puzzling is that it took 9 month to discover it ?!
and allegedly Eric is seeing it by running kmsan selftest,
but Alexander couldn't repro it initially?
Looks like there is a gap in kmsan test coverage.
People that care about kmsan should really step up.

> With this change all kmsan tests start working reliably.
>
> Eric reported:
>
> : Yes, KMSAN seems to be at least partially broken currently.  Besides th=
e
> :_fact that the kmsan KUnit test is currently failing (which I reported a=
t
> :_https://lore.kernel.org/r/20250911175145.GA1376@sol), I've confirmed th=
at
> :_the poly1305 KUnit test causes a KMSAN warning with Aleksei's patch
> :_applied but does not cause a warning without it.  The warning did get
> :_reached via syzbot somehow
> :_(https://lore.kernel.org/r/751b3d80293a6f599bb07770afcef24f623c7da0.176=
1026343.git.xiaopei01@kylinos.cn/),
> :_so KMSAN must still work in some cases.  But it didn't work for me.
>
> Link: https://lkml.kernel.org/r/20250930115600.709776-2-aleksei.nikiforov=
@linux.ibm.com
> Link: https://lkml.kernel.org/r/20251022030213.GA35717@sol
> Fixes: 97769a53f117 ("mm, bpf: Introduce try_alloc_pages() for opportunis=
tic page allocation")
> Signed-off-by: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Tested-by: Eric Biggers <ebiggers@kernel.org>
> Cc: Dmitriy Vyukov <dvyukov@google.com>
> Cc: Ilya Leoshkevich <iii@linux.ibm.com>
> Cc: Marco Elver <elver@google.com>
> Cc: <stable@vger.kernel.org>
> Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
> ---
>
>  mm/kmsan/core.c   |    3 ---
>  mm/kmsan/hooks.c  |    6 ++++--
>  mm/kmsan/shadow.c |    2 +-
>  3 files changed, 5 insertions(+), 6 deletions(-)
>
> --- a/mm/kmsan/core.c~mm-kmsan-fix-kmsan-kmalloc-hook-when-no-stack-depot=
s-are-allocated-yet
> +++ a/mm/kmsan/core.c
> @@ -72,9 +72,6 @@ depot_stack_handle_t kmsan_save_stack_wi
>
>         nr_entries =3D stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
>
> -       /* Don't sleep. */
> -       flags &=3D ~(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
> -
>         handle =3D stack_depot_save(entries, nr_entries, flags);
>         return stack_depot_set_extra_bits(handle, extra);
>  }
> --- a/mm/kmsan/hooks.c~mm-kmsan-fix-kmsan-kmalloc-hook-when-no-stack-depo=
ts-are-allocated-yet
> +++ a/mm/kmsan/hooks.c
> @@ -84,7 +84,8 @@ void kmsan_slab_free(struct kmem_cache *
>         if (s->ctor)
>                 return;
>         kmsan_enter_runtime();
> -       kmsan_internal_poison_memory(object, s->object_size, GFP_KERNEL,
> +       kmsan_internal_poison_memory(object, s->object_size,
> +                                    GFP_KERNEL & ~(__GFP_RECLAIM),
>                                      KMSAN_POISON_CHECK | KMSAN_POISON_FR=
EE);
>         kmsan_leave_runtime();
>  }
> @@ -114,7 +115,8 @@ void kmsan_kfree_large(const void *ptr)
>         kmsan_enter_runtime();
>         page =3D virt_to_head_page((void *)ptr);
>         KMSAN_WARN_ON(ptr !=3D page_address(page));
> -       kmsan_internal_poison_memory((void *)ptr, page_size(page), GFP_KE=
RNEL,
> +       kmsan_internal_poison_memory((void *)ptr, page_size(page),
> +                                    GFP_KERNEL & ~(__GFP_RECLAIM),
>                                      KMSAN_POISON_CHECK | KMSAN_POISON_FR=
EE);
>         kmsan_leave_runtime();
>  }
> --- a/mm/kmsan/shadow.c~mm-kmsan-fix-kmsan-kmalloc-hook-when-no-stack-dep=
ots-are-allocated-yet
> +++ a/mm/kmsan/shadow.c
> @@ -208,7 +208,7 @@ void kmsan_free_page(struct page *page,
>                 return;
>         kmsan_enter_runtime();
>         kmsan_internal_poison_memory(page_address(page), page_size(page),
> -                                    GFP_KERNEL,
> +                                    GFP_KERNEL & ~(__GFP_RECLAIM),
>                                      KMSAN_POISON_CHECK | KMSAN_POISON_FR=
EE);
>         kmsan_leave_runtime();
>  }
> _
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQ%2Bo4kE84u05kCgDui-hdk2BK%3D9vvAOpktiTsRThYRK%2BPw%40mail.gmail.com.
