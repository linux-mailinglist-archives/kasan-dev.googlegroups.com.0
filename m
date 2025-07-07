Return-Path: <kasan-dev+bncBDDL3KWR4EBRBH5RVTBQMGQEQ4WAHAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 238B8AFA8A9
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 02:45:21 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-702b5e87d98sf57659316d6.0
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 17:45:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751849120; cv=pass;
        d=google.com; s=arc-20240605;
        b=B8SaicyjuCFucH2Ehwp+WAKXBZJTaX6Ht/IE1gFkFn346OjaDw7nqmf6quD3OGIrWh
         HvcfZiw9XtsCIdxz/9tqiCrX6+h+J1/A8LC7910a4hhuT9cUlzM5QZXYCMFlEX90zyxq
         Tx8X9mWcJ7ki7c3MVvqrs/DwAyqgMyIjcSN3g3DJ8jhHGNMb+2wxw2h0l2jr+sJjUhTb
         HJ3qs4TZd72Wp+gOZOB3ka/6wDwcx9n+JDXigRxkrBFRG8ufyhL8jVrOTn1pbGp+Bee7
         Ea7otm8Hv1XP2dwbN4T+0DNTe6TnEVWoLsKVMpDjUiluDyEOz4WB9y2/jGNJAvOFfJ97
         dRtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=P0X0RK7ZCWHGqsKZ+4z4SbGPq4Bgm/VvXOBPycRciSU=;
        fh=aPRzgEFq33qegkDSuHg+WVRVqpQLtxAr2ixGoWK8CI4=;
        b=iPrb1eQvVV2x4E3wz4t6YVRVOPLpVMiUBq89hqnMm0s2Wh2Wsr599TlLbDmfoIl1Jx
         l9yeNLWTIgVpOvupb7sHrxvperfNpgRk3UpnNmz0QaAu/oaCP7SvVKvGFpEMpNFrji23
         H0v6UfISHMD3tgtEFqIev3MDxkk2EuT40wnJi/UnWx/VhJUuCDO49Swyjn2vW4UULMXP
         v8Ee7pDkaJHZG2YCG+I0DbMTGfV8S0UBrLp22GjwDeKLb8Y/eichgnPKcYTXhhKRjxaz
         K8UuFqUSRaGVvPz6hoQRiJD7DJIjunol/24zKaQ7hOBikZzg/p4IEtetAxi4sjVLuZ62
         Oisg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751849120; x=1752453920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P0X0RK7ZCWHGqsKZ+4z4SbGPq4Bgm/VvXOBPycRciSU=;
        b=FC8xz5/Uqin307XeVrpwaq01bIaCyK4qnJ0H2shxiPPbS/b9zGOGK5wL2tGrnDXXAK
         HAhk2zwI3l105yDqgH6k8VqAy7sVUfSLVA2iN7j5URdv1GISefyr8h4X2lMU9VZ9ETum
         GrwSwb8e22FokqK4MzhcW9EHjhbCfx2tIYrQTpTW3D836PyQDk5GfA5rMVf01xezFe1f
         mp7Wju8vDJehVTg9CxzBgK1lPhTc50oJJOCXxF4tt4yS6sBO5Runded8bv9zFQtfI8d8
         5K07wcq0WEiF+a8p6/no1hLPUSE2HojTCfjQ2+R3ByvHF4oyAstA+fcI368SRTMfWUf4
         RSeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751849120; x=1752453920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P0X0RK7ZCWHGqsKZ+4z4SbGPq4Bgm/VvXOBPycRciSU=;
        b=OuovIIVUnfNBLAl1BNGnsUCaP2vzh/yvo0L6yvNknwaGtvKZEL9h3A0ayC1kcypmsd
         jSQ/m/14MHF2mzrcClcD6Xbfh7f/cWprhzWOXErAWD6OPxWmIuL54B5auuw53ucSwZLB
         +MG8Md8lXZ1zkp8hEA5tAf21FyasKVIOUjnEfIvMuEB//TERgo4fn7yniT0oKu/tJnnE
         d3wZHnlHiNOnXtt0MZ4yZKy44HlwLbHdEudkGr0T1vz1VtQ+ssPMSvMBkJM0InFTp/H5
         gtibqILwgedZd/NBNxlJwAIs184UAd8meN5b/kuzW+zIyCM0gef4FVe45dHm0nAlDWYy
         TxEA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4GLJtiayZqqS/bltar5TpJjjxTgaH8lbUuNmbbc93HC7JhIsOHwL5A1svszxpRET7gAjcMg==@lfdr.de
X-Gm-Message-State: AOJu0YxIw9Zj+fmKtHzaWFLu3Nkn/fRytCsSiokxyf6aONaOCybOSKVZ
	sZMo0iwfrUVrQ2mXcxkV095MLe4aKJQGsncFrJ87hvgsHcxw7xzC+dKD
X-Google-Smtp-Source: AGHT+IEFLjHeN250lmtMDX3dyMtJ8abKYjfWIWB130PW273eDvtlfQ358McSBscR2RMw6olcSlIcNQ==
X-Received: by 2002:ad4:5ceb:0:b0:701:b10:b089 with SMTP id 6a1803df08f44-702d151b3c7mr115443046d6.6.1751849119608;
        Sun, 06 Jul 2025 17:45:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd24LNeOhNtUuPcMKu3c8o+7HIwWqwMfyphlMZNO4P0Hg==
Received: by 2002:a05:6214:234f:b0:702:b6a3:76fe with SMTP id
 6a1803df08f44-702c9a702dfls35303536d6.0.-pod-prod-03-us; Sun, 06 Jul 2025
 17:45:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7/AtvTDL37PJVTyz8+fzdPagazk2Gl4tHEBwVQAKwLw3z7bhWSiDcDu/pxGzpg5olErCGhE57wOA=@googlegroups.com
X-Received: by 2002:a05:6214:5b84:b0:6fd:609d:e925 with SMTP id 6a1803df08f44-702d16a38e9mr118026126d6.36.1751849118635;
        Sun, 06 Jul 2025 17:45:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751849118; cv=none;
        d=google.com; s=arc-20240605;
        b=ImTy7XgFX1Pu4lpV85hSPkiJqLSi9Fs9vg2jOhNU2ssTXhuji96BReFI6M9DjWNv5K
         Qu/kbgDqh7MVidxAGwnxq3A3+VmGwbYljMwnZtK+FXOIMySrUslz2IxTQC496uJI6wrv
         BUIJ52W40quErOxOVnkQDKBeABnA5M9eDP5XMpgVRQwl37hiN0pNsxqaQV3Y3q8oP3GN
         AfyShbnUMaCZi8y/4ukv7D9SquZ967vdjm4w4Ac3PDv5WkhqhrleRxTFqLqN6/Mh6iWw
         jIMIbA84/TPi96X0OavwBzN5b7VibYvbVqkZixmdtLi2+EJ4lO26dcZEI7r73Pqf8PbE
         834g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=t67lzjuNhuqGREvzVTrkwcsIDvrKBgIXJKoX7O/nXzA=;
        fh=iXBF4wWvJRsFYA/2PDkGH1oSOWi8NALGKVaSiKVOfH0=;
        b=OD8yoOUYZruiVCyTVf7OT6jy/JPjumySIJWs3XAQsRmqjjlDQxzzug0niQrN98m5tv
         6AvOwMGfD5cBQMg8ywN3+Uo/EWLLq3h1pg0Er8CowmUg6vqm8aN/1ifPsJ+FIP5awNSG
         UFqjR6FY6gHUdDS+qdSr71E1b80eC+uLL+lBXBTsXHcPWICE3Fr/ZZ/qEKrTNR5TJUcL
         0xpk4nlK0rBBS2vfto9OmlM3PpRvsg2xPu3KHxW5ye0PdZIYjLS8bc/B29I3Ocj6woev
         rSC/IjNm7XtAJliFUJmEupbLzN+b7Ehs7V8XzjEVsiGGvXGvEIO0H6/UNF1ShvxebwST
         DQBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-702c4d1a442si2607506d6.5.2025.07.06.17.45.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 17:45:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8792A45453;
	Mon,  7 Jul 2025 00:45:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E5E09C4CEED;
	Mon,  7 Jul 2025 00:45:06 +0000 (UTC)
Date: Sun, 6 Jul 2025 19:45:04 -0500
From: Catalin Marinas <catalin.marinas@arm.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>, Breno Leitao <leitao@debian.org>,
	Ard Biesheuvel <ardb@kernel.org>, usamaarif642@gmail.com,
	rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime
 stack
Message-ID: <aGsYkFnHEkn0dBsW@arm.com>
References: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
 <aGaxZHLnDQc_kSur@arm.com>
 <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
 <aGfK2N6po39zyVIp@gmail.com>
 <aGfYL8eXjTA9puQr@willie-the-truck>
 <aGfZwTCNO_10Ceng@J2N7QTR9R3>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aGfZwTCNO_10Ceng@J2N7QTR9R3>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as
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

On Fri, Jul 04, 2025 at 02:40:17PM +0100, Mark Rutland wrote:
> On Fri, Jul 04, 2025 at 02:33:35PM +0100, Will Deacon wrote:
> > I would actually like to select VMAP_STACK unconditionally for arm64.
> > Historically, we were held back waiting for all the various KASAN modes
> > to support vmalloc properly, but I _think_ that's fixed now...
> > 
> > The VMAP_STACK dependency is:
> > 
> > 	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
> > 
> > and in arm64 we have:
> > 
> > 	select KASAN_VMALLOC if KASAN
> > 
> > so it should be fine to select it afaict.
> > 
> > Any reason not to do that?
> 
> Not that I am aware of.
> 
> I'm also in favour of unconditionally selecting VMAP_STACK.

So am I.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGsYkFnHEkn0dBsW%40arm.com.
