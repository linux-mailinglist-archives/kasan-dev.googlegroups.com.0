Return-Path: <kasan-dev+bncBDDL3KWR4EBRB3U3ZW6QMGQEAI6M3YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id CA50FA38708
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 15:55:44 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2fc43be27f8sf6542793a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 06:55:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739804143; cv=pass;
        d=google.com; s=arc-20240605;
        b=NV0mcTPRUi/T3mBFbGyF/ewtdubNFwfhO16Ka/DDVs8gQp99cLQOIjaAnVnugpk3k7
         ILt3BxQ+XZuN5iiyatj6MPByfoqEbXvQxy8xQuPcmYKI5EnHxF6xV/nWVgQ21vQnDlEM
         w3Q4JuS+J6xDVimnz6rEcMufc8GlDAvOjgWQ67Kd5scuWLzP8xIZ48HbcCQwTSr2kjkU
         Cf0NvKrJ2tIN6yj4XHxYIjNgPOJ+Mw5arwyHEbHBpsVOXXqyRr3XweNbrmgeUZTyV9p/
         clQIHN6hhpGvIwqVaTFIj79RxFjb1Iz8Y0ygNZy8K9RdrVAkwOCy3QCEv7hLOM7v6vGp
         GxNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=8LcQ5chSRnpOqyd/eGq6r1QGHOx1sPJ3L0fAQqH7KDY=;
        fh=BVY/XmZdF8Ifo2yZjFRBCUab7OX7Tun2LWKyYCCikHU=;
        b=Tb/tUPfnFWTTL1F/33pCQSeqevgjPtBl+xbeBXhN5sN87CAVtle0d8DRClrg1CTqPj
         bDaeyXa8CfPa34jEqsNw9clMDAY3hx+/0MDGwa78Ovkgpdq5sOGj2FwUuKnahQfexlgH
         nWtL9PyIKy9Ra5Ws2Rs6yqalT5YbMKk20y5NyS3bKeNfwFXM3E6Am1bL3UJ+SMFwvuRF
         cEcbYNKJPlJ9Oxw45/2CaWiH8JK6WffpBAKYYSnMkCHVCxEzB22ngjXt9wwCMZh/4zi7
         +S/kHrnV/SFydOJAmfu+VM6CjfCGZqmMmhNPYN5qiO8kUgC9TIYpvW/Rdcr466Nr2qMD
         2png==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739804143; x=1740408943; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8LcQ5chSRnpOqyd/eGq6r1QGHOx1sPJ3L0fAQqH7KDY=;
        b=Y8unBhtiFstNKu3g8YaJuY4j7UxPNSC8gtEN9H+JcDG5RXz56vwc+8p2bO1Crz/5Kp
         yHXA/rRb4iyp3P3bkHG6BBcnqo8zF7REizH1r25XPRyXPa0FMQpmldAhaRKG3CsWfFd6
         wG9oAbrFgZUjqk7mcR6VL0vVvqRUsRru1WQ0QUF75J9xNg9VK4D5I3X1puQtVTfzel/z
         NGGvqI2KhOAAO+TfDXNatTQyyzFhUUAsta/6g6KSfTdoGC53eH7b5mnL16RDJ+kzpS1e
         F+s3K10uA+8pDj02mSqfwGoRJsE3wzNkFyENGIffZjS2GiuNVfFiHcnN431/PWMN4aTX
         rjfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739804143; x=1740408943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8LcQ5chSRnpOqyd/eGq6r1QGHOx1sPJ3L0fAQqH7KDY=;
        b=GITHOWXQ3w7efgVAkTSN5BKdUm93JOXF3Rkri/WkFBHiVbf2y3d8eHESzb+gPUb8xL
         BlCY5LoR6vW3AZpjyiUT7oxFExXmI37hAyPaQmUqQjK6fm/d26sjVWBPyx68c5VTm5dW
         R8+lMdGDG77kN11FDVrClALkPgNxhsDvcnQFEhNpsUfipGFoQCB3lY2YnFaTG9lpXzVg
         NSNdLAN0Nl4sHGdSvw/GYAiC3l+nuOuvqitTOXIIcg5/WQNko0gKLjHEkRceLsRcXD6j
         jz+e2OZyl1pSfvsjwY+kH+R5rZ+HbVhcp5XxzEEP7h/CJlb7WztiJjK8RnPU93HZB6kF
         dVxw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5W21NWjIRj3PtmRrYubGACupRMtRdfRMkTwCZYc48lqQ4mVUyfLb1iKskhP96kzix8gnBeQ==@lfdr.de
X-Gm-Message-State: AOJu0YzXtmCTvJB788gcJSCS4yvEc7zxKMIeefzu0VMt1IXamzDgeBWu
	uKDkBQ/mmJWxUj1qrGsGUt83XhqPZ44PvIW1m9YSfJrK7/T92a5+
X-Google-Smtp-Source: AGHT+IGTO/+pEZAsGqbqtZmCL8yRR9YVkn1Y5KiUgiy4h0DpWkoFt6t+Pw10a89MyU2qiUcEjth9Pg==
X-Received: by 2002:a17:90b:2248:b0:2fa:17d2:166 with SMTP id 98e67ed59e1d1-2fc4116bec9mr13959241a91.31.1739804142600;
        Mon, 17 Feb 2025 06:55:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFOmZvAsiiOWEPJ3ORTGL6RemcKw8URnhj2s6NhMIvVNg==
Received: by 2002:a17:902:fa87:b0:21f:1d1d:dd27 with SMTP id
 d9443c01a7336-220d2369326ls40000305ad.1.-pod-prod-08-us; Mon, 17 Feb 2025
 06:55:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVq8VR3ZyN4lHGz3V420Yv/8IPN/cWgiMoKzEV1PpfoWQ9bjT/vpzXJuFs1s/EthjZHroN1WbPpz4s=@googlegroups.com
X-Received: by 2002:a17:902:d502:b0:220:ff93:e12e with SMTP id d9443c01a7336-22103efc101mr151004925ad.1.1739804141279;
        Mon, 17 Feb 2025 06:55:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739804141; cv=none;
        d=google.com; s=arc-20240605;
        b=D9wQennQ12a4OhILQ/04STm3+DTbJJH9AJnHuT00dEMZwZ2Fg5YrF0tHn5D4+5fbDV
         6wKVoVLYXM6xYs+A/eIUOqWb81hZEDc6cBMg6tgYm9grLlhSBMgwG7Hn1OGUSn4I+QaD
         9/VyPvhOvEXuoI1FLk2Hqx+dsFqDfKr4J5I/hK5z5r/M9Eqnf6ZAttpAFMvigLk8KBMs
         o7Vy1nMbx1/35EHg+dyNzGA0OdI/V2r9boPK8O60QGc2CQmsosZLg63IvPHRzMIODm2a
         RTak5FU67Hry3L7UU5oJshbVZT8RtfpNBF4AhZZTyuPjI6uCTtjBCB13CtAmVemdsA7I
         /ViQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=+M34uV/zkct1kEAaK2pLJ3/QmCI3GfHP6imSRuJbcm8=;
        fh=md3ANKhaGYZbuc9iasr19RDG3GmpFkCH4nzOFRqlDfA=;
        b=i+ORVSvHFyZEjgXNm+jrtv77mKHSEYR801fYdu//fIqfibs3Jdy0vrFVPc13YhmyPQ
         RhxJ/Qv9Xf9hIl9k7iQLp740EdjMZVRwRlKgNG9LoDiHkhoO3UEF52sktKb0EGM5NIYm
         Jaq6CeykRLCSKn4H+Sv6wh34qhK5Kn27y1DfgYSxgkztqwfQwahF7EShaOudLtQJOhUl
         XKADJyaIoj1si+1uNBwiQ/Jg564Y+vKqwa8RjFBizWlLJgaZrnIaEUOOU/MJvFaNgZ6i
         wEXRABo5IPAwHIv4f/wp2jZwVSP1e+Rz7S26/w6X9+u4jK8Er7BDTMU248xwCD3mWelH
         vbOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2faa4aebb95si1341239a91.0.2025.02.17.06.55.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Feb 2025 06:55:41 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4E9CC5C57AC;
	Mon, 17 Feb 2025 14:55:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 453CDC4CED1;
	Mon, 17 Feb 2025 14:55:35 +0000 (UTC)
Date: Mon, 17 Feb 2025 14:55:32 +0000
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
Message-ID: <Z7NN5Pa-c5PtIbcF@arm.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-5-tongtiangen@huawei.com>
 <Z6zWSXzKctkpyH7-@arm.com>
 <69955002-c3b1-459d-9b42-8d07475c3fd3@huawei.com>
 <Z698SFVqHjpGeGC0@arm.com>
 <e1d2affb-5c6b-00b5-8209-34bbca36f96b@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <e1d2affb-5c6b-00b5-8209-34bbca36f96b@huawei.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
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

On Mon, Feb 17, 2025 at 04:07:49PM +0800, Tong Tiangen wrote:
> =E5=9C=A8 2025/2/15 1:24, Catalin Marinas =E5=86=99=E9=81=93:
> > On Fri, Feb 14, 2025 at 10:49:01AM +0800, Tong Tiangen wrote:
> > > =E5=9C=A8 2025/2/13 1:11, Catalin Marinas =E5=86=99=E9=81=93:
> > > > On Mon, Dec 09, 2024 at 10:42:56AM +0800, Tong Tiangen wrote:
> > > > > Currently, many scenarios that can tolerate memory errors when co=
pying page
> > > > > have been supported in the kernel[1~5], all of which are implemen=
ted by
> > > > > copy_mc_[user]_highpage(). arm64 should also support this mechani=
sm.
> > > > >=20
> > > > > Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
> > > > > architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE =
and
> > > > > __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
> > > > >=20
> > > > > Add new helper copy_mc_page() which provide a page copy implement=
ation with
> > > > > hardware memory error safe. The code logic of copy_mc_page() is t=
he same as
> > > > > copy_page(), the main difference is that the ldp insn of copy_mc_=
page()
> > > > > contains the fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR, therefo=
re, the
> > > > > main logic is extracted to copy_page_template.S. In addition, the=
 fixup of
> > > > > MOPS insn is not considered at present.
> > > >=20
> > > > Could we not add the exception table entry permanently but ignore t=
he
> > > > exception table entry if it's not on the do_sea() path? That would =
save
> > > > some code duplication.
> > >=20
> > > I'm sorry, I didn't catch your point, that the do_sea() and non do_se=
a()
> > > paths use different exception tables?
> >=20
> > No, they would have the same exception table, only that we'd interpret
> > it differently depending on whether it's a SEA error or not. Or rather
> > ignore the exception table altogether for non-SEA errors.
>=20
> You mean to use the same exception type (EX_TYPE_KACCESS_ERR_ZERO) and
> then do different processing on SEA errors and non-SEA errors, right?

Right.

> If so, some instructions of copy_page() did not add to the exception
> table will be added to the exception table, and the original logic will
> be affected.
>=20
> For example, if an instruction is not added to the exception table, the
> instruction will panic when it triggers a non-SEA error. If this
> instruction is added to the exception table because of SEA processing,
> and then a non-SEA error is triggered, should we fix it?

No, we shouldn't fix it. The exception table entries have a type
associated. For a non-SEA error, we preserve the original behaviour even
if we find a SEA-specific entry in the exception table. You already need
such logic even if you duplicate the code for configurations where you
have MC enabled.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
7NN5Pa-c5PtIbcF%40arm.com.
