Return-Path: <kasan-dev+bncBDDL3KWR4EBRBO6F2O6QMGQEOS42LQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 60D09A3A7DA
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 20:42:53 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3d05b1ae6e3sf46908305ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 11:42:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739907772; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q4e+1pog15MylZqhoArukAJp1Pa8NtkQR9EMufW661Lp/ekDeWYKZzGCuh0mtJeTGf
         Xd3j0AQ2pDYyLX3oG9Qxyb71nFyo4f7wRUhjQQO6cdBd+Uq6uPehQJ0recpWsRJa8cda
         04lutulB8uBn5gU9YzkWgx1DnKn0hHdAm8YekKWBjt9fHNcKdJWWYc4GXdN3nRRVMihH
         Mi83qnaJ+tW8xdSE+THhyXjBze2JobrSAqz/RizpuNd352vD9MyBBXkVw81/Qq/oN+Dt
         ltST76kvLRwN2sfGe/7TuUU69ki1MsltUnxmmsJjMZGFh3q+fi7jb1L1Wb1acWzGycof
         HuDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=35l0J1E22i/kxY8Hb7BAnxwzXdVoiU+UG7G0coPYTEs=;
        fh=LiqUPaaclNyoKp6sBsGNZf2cHGV/dpIIP3Tr/fdmLbo=;
        b=i0Kfn+N6OhmRdBM40rGY5XHmim+ScQox0kbSoraBy+/kCrCedwxSr+Ax+nebKqwveh
         WWdy/b5SIq7bbyQ5mR+VLOwlCVtIA+p223FQe5xgRO4eZPEQW+QDG7krbx9cS+bUZI4g
         AX7VckEikr8viPdVeZc8eYOUStENwy9j96XYuxswaDGR8bA76uuelSliwV/Y57G65zrG
         /+mmCcCeKi2SWuaYjDZqS3SP+S4xU38zYQoO73Qne9M1rO37idjwc9KgrvCoU0z/NXfc
         JNr1aw7iSopg4KazNX4/YzStLgXNlhaEuUfT7NA0gDkw6ZrRTPB2EzxjHSNW03zjUpxi
         tpJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739907772; x=1740512572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=35l0J1E22i/kxY8Hb7BAnxwzXdVoiU+UG7G0coPYTEs=;
        b=XXOk+s8xb9vHl3uxGQXSRE/O2UhDb8Bi8vbser8eObZDY0D9FpQeFTv1tpl+EmYz4A
         LjPSurPBCiaGth4PtKEL6x0cE4vIeM3WvRZ6mLkyj5yEUJ5TRbq84TvBD5yUDyyrx0p3
         pkkb7dCdKLELTTN60MGOBkDJ5VllKWuBw/mFp6ou42Y02zRQbmMDEq7AtrEMoU3yA4Qk
         X0icZ9TWxEucWdffEotPHqPXCqeO228dep/yHeQwLtA3ZYmoBv67OmvHeDDDqEdB02u4
         vg2cuJE5E4yXMsy+G10kEzGfRANQrj9yItJcll+4jxZfrk6Gaqj5dTCCsM61qGue1EM1
         IXOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739907772; x=1740512572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=35l0J1E22i/kxY8Hb7BAnxwzXdVoiU+UG7G0coPYTEs=;
        b=k3rwa4dMO30N3a+mGcPe0BdrqXWDlJRsY2Q+RGgJD45PURSgN21bjlgg1Qj/3UbrF2
         /Dp+/gGoQiWr2M3nT+BLyc5m68dawCev6i5Kah6AdIDTeP4b7skKZHZsStkgMIH90Y97
         WAjMQ8UQBa5aay9h5euoENAVx4LFedihzR8jzAJanH/vGT3GJ7oxRsBGJ7z4jRzQ0kPI
         rAe06NgtsNf4elXPm6HjZWMP+gQKvAzWFbqRkJ4UlJDB/y8Aqhtg5zJOhHWGV3iwncUc
         yQ+IDL2I6KektIEoz+8IXi7W4rlk9rYujNVgfUTG26xqR+hp58UPmQ5t3pwthjgWHTVH
         P3tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURYQ7s8QuGseOX5PqLHGs3Kf44Xwfgv3bgyRSiw7kcZZ72ypQlkgppTzQ5MJYhP9Hwa/6RQQ==@lfdr.de
X-Gm-Message-State: AOJu0YxFlbOlLzirSRp/h4wOArf+zGqrelJ1LIcUIMgVh2YKZKOUtAal
	9ouUdKbvafE4fnSCFrzCfkSAVSSy2Tgb0YWDcxpdlXIB2Fmrl1jM
X-Google-Smtp-Source: AGHT+IGmMdGWRplykTdiAvKMZhHG/VC9+BZIlIE1fses+10HDKtRMJ09lAguzaMgxkAZb4T5EGzgww==
X-Received: by 2002:a92:ca0a:0:b0:3d0:d0d:db8e with SMTP id e9e14a558f8ab-3d280771c6bmr152986125ab.1.1739907771865;
        Tue, 18 Feb 2025 11:42:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEteQ8wsY4HBd7L23w5rhqZkqHiXT7ekPb/b7qD2aesig==
Received: by 2002:a05:6e02:2167:b0:3d2:af50:1124 with SMTP id
 e9e14a558f8ab-3d2af501351ls2714955ab.2.-pod-prod-04-us; Tue, 18 Feb 2025
 11:42:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDG+MV1x1F4IkCI6AMWoTyfj0TwxPnzF3iRrUmjMtOdkkf8BlO/Th75hMHNXtkBWjY1cs07TJNCFA=@googlegroups.com
X-Received: by 2002:a05:6e02:19c8:b0:3d0:1db8:e824 with SMTP id e9e14a558f8ab-3d2807fd1e2mr133273735ab.10.1739907770330;
        Tue, 18 Feb 2025 11:42:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739907770; cv=none;
        d=google.com; s=arc-20240605;
        b=J94EguN26L1xB/i3NFW+SIji1QjfPFKNhKYf3IrNJWh4JLZTDNIeaa66FMHOHD3Ci6
         J0GUsiRrmgAKfE1bXb9s78FCwSxbDGgK8u4+hlj5pEBpMLH0+1cLS0nJjNozX71eFE81
         C/ruWFGIhfbKKsWBuxcUR7B8D5s+BVhPmpHvxnCRz5v3qxDD0oJvKxWyy/xd5lU0GpA/
         Whz3Q11NeW3qcIaScxN6YxzgWKFbovDmUvLV67dtUT7fSIHcNupHrRlSRJyzEezEv9F7
         mAINN+pYHyV2mfkeUOyGO2693UCpRJGZgJUtfJsdrjEKp1B5vAp3EhRKJCgXTanoD6vL
         N5HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=l0OefYp6gIJsoBkqWu85YVPRb1yh3g60mRPL0+SvOSs=;
        fh=md3ANKhaGYZbuc9iasr19RDG3GmpFkCH4nzOFRqlDfA=;
        b=aiRm1pY4J22bSGBKILKpPV0+lEQ8wxbHh+vw2sjoqrK5v2LJJuiiziBMyeNW8IwHBU
         sorP4Cn0n9zMqhsQ3WxqWiYXpMEBB+PCeD+e5Bx/rW3tkVU2dwImm3yNTpPK/QuqQXSj
         rjmJrZjaBZBWehuPiOMJV3fHprzSFwdK9UFfDsSK5jTr4ALOd34cTxG+vpVWk24aYEH7
         MuguTh39bxfZWLmkTKToWiJf2346sucHzATBqk9Sh8ZVr/93wnVkh3jcQLaao60pGnku
         yzwCuYKks0hDenS89DVeKRMrgb3t/dp03N3GRZEHcpPmVhTmMoAsEmVFd6NRLmVrQRt3
         Q4qQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d2843909acsi4193105ab.0.2025.02.18.11.42.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Feb 2025 11:42:50 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id E0790A414A0;
	Tue, 18 Feb 2025 19:41:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 637C7C4CEE2;
	Tue, 18 Feb 2025 19:42:44 +0000 (UTC)
Date: Tue, 18 Feb 2025 19:42:42 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v13 4/5] arm64: support copy_mc_[user]_highpage()
Message-ID: <Z7TisqB5qCIF5nYI@arm.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-5-tongtiangen@huawei.com>
 <Z6zWSXzKctkpyH7-@arm.com>
 <69955002-c3b1-459d-9b42-8d07475c3fd3@huawei.com>
 <Z698SFVqHjpGeGC0@arm.com>
 <e1d2affb-5c6b-00b5-8209-34bbca36f96b@huawei.com>
 <Z7NN5Pa-c5PtIbcF@arm.com>
 <3b181285-2ff3-b77a-867b-725f38ea86d3@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <3b181285-2ff3-b77a-867b-725f38ea86d3@huawei.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Feb 18, 2025 at 07:51:10PM +0800, Tong Tiangen wrote:
> > > > > =E5=9C=A8 2025/2/13 1:11, Catalin Marinas =E5=86=99=E9=81=93:
> > > > > > On Mon, Dec 09, 2024 at 10:42:56AM +0800, Tong Tiangen wrote:
> > > > > > > Currently, many scenarios that can tolerate memory errors whe=
n copying page
> > > > > > > have been supported in the kernel[1~5], all of which are impl=
emented by
> > > > > > > copy_mc_[user]_highpage(). arm64 should also support this mec=
hanism.
> > > > > > >=20
> > > > > > > Due to mte, arm64 needs to have its own copy_mc_[user]_highpa=
ge()
> > > > > > > architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHP=
AGE and
> > > > > > > __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control =
it.
> > > > > > >=20
> > > > > > > Add new helper copy_mc_page() which provide a page copy imple=
mentation with
> > > > > > > hardware memory error safe. The code logic of copy_mc_page() =
is the same as
> > > > > > > copy_page(), the main difference is that the ldp insn of copy=
_mc_page()
> > > > > > > contains the fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR, the=
refore, the
> > > > > > > main logic is extracted to copy_page_template.S. In addition,=
 the fixup of
> > > > > > > MOPS insn is not considered at present.
> > > > > >=20
> > > > > > Could we not add the exception table entry permanently but igno=
re the
> > > > > > exception table entry if it's not on the do_sea() path? That wo=
uld save
> > > > > > some code duplication.
[...]
> So we need another way to distinguish the different processing of the
> same exception type on SEA and non-SEA path.

Distinguishing whether the fault is SEA or non-SEA is already done by
the exception handling you are adding. What we don't have though is
information about whether the caller invoked copy_highpage() or
copy_mc_highpage(). That's where the code duplication comes in handy.

It's a shame we need to duplicate identical functions just to have
different addresses to look up in the exception table. We are also short
of caller saved registers to track this information (e.g. an extra
argument to those functions that the exception handler interprets).

I need to think a bit more, we could in theory get the arm64 memcpy_mc()
to return an error code depending on what type of fault it got (e.g.
-EHWPOISON for SEA, -EFAULT for non-SEA). copy_mc_highpage() would
interpret this one and panic if -EFAULT. But we lose some fault details
we normally get on a faulty access like some of the registers.

Well, maybe the simples is still to keep the function duplication. I'll
have another look at the series tomorrow.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
7TisqB5qCIF5nYI%40arm.com.
