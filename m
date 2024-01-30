Return-Path: <kasan-dev+bncBDV37XP3XYDRBIOK4OWQMGQELPD4QAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A2A3E84244B
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 13:01:38 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-36391592f0asf105845ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 04:01:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706616097; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZRSufWOLVoxwYKSxHN/UDEZQrpZrFALeZdx0dbyK3ZgUHw27F1mjJeIqZ0yWQP/tmU
         F1HIo2tE1jyCs+yFgbSd3xY6kuu7ve7aE8BbdVNzqa1utQfhqYk2hEeZJmtyj6Cg31Rp
         bze3mGFmDZGFnnMw3NGrzgOcHkZiF3SVs0ba+hloOyPgKYYSjvrqdaCnpcPsYOAY2mp4
         +flGd0uPUoydepEFrYNFoRRZXsXj60UBOusSfz4AqDXYIHYQVDuj836OAHWkrqMkGkc4
         nkQ0eFVJBpKKPnPwTR8XJkrj+36rnG5qCpOAjOBJH88FiA0Qbz7bLW55rUsxpAYRQrDz
         L13A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=hAusbNkk6rckE64KbET8intiwyWmozHtcudjb7LlhVc=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=jxNcTlt91WINALugyKAy0+5nn+pPPi7bsrqMiO6d8Amr6CEjmBnpERN1gTIVb5JbCy
         U8onEbJryGv/3k/MPpdy1JXyy7dkzuCE/H0ESEKwiPQ4pNiMUC7i5JH6PjpDtcOvZkce
         MT9ypfUHeuJhBZiTaDnn4L9aRbbw8WPq/HMTEk6s5gMhXEFeNmbH/TrKvOxuSHmM8OSb
         S7dkCNjKkNXEUoeR4CuFBvynsWYd8K5ZQaxcUUJL7bvyvr4gld1Bu34hz76+tfqt+xWg
         AJzL0Fm1+2Rs8MpRX3sZgKvchgFWgeNIrlZ57YofKYeZM6GYC9rN0QLvp9BI9fkbbcDw
         S/3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706616097; x=1707220897; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hAusbNkk6rckE64KbET8intiwyWmozHtcudjb7LlhVc=;
        b=jJ+khH7/HBcrHFFf5Qlc4xH3JEHXO8fqw3naaJJ4bK1vYnajiiuNOu2VYWfq7vws3D
         ElMM8FPLL3LrLiACIBNZps9MNiMcp5Kga/YyJtSYqtueeOrtLQL+2iTdsw01aol+c62m
         /8lHOIamv4NvxrC532716mdnpm5XBK1miz/BybiY6/vDgnIqav3bomFMlC7L2OTbUVKh
         HoZtLovEWXG/LxHXg6A3hjah+lmUcdzWICtyF+8gv2IkafgIazFB0Wa8vt/aH88wpdhn
         ouX69/ruzzbXnRvQL/hJ/T5LnOT0Xth+24sggKgcqqjH9fwYM81Uhh3hSJgjt3sTGaE7
         Xinw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706616097; x=1707220897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hAusbNkk6rckE64KbET8intiwyWmozHtcudjb7LlhVc=;
        b=bWcVY51ipVWc9JAomWYgJQVcjpIDxOLxzV9HWos2RejIHS2ueF4jMmZGHc1wsCqDa2
         aNLNijai4B5yKCVHUbckgWRWu93FGz3RJ1dsOmqupSdhjapj7jzB8V6SQoVt9boyct4E
         qeT4D2NkwKmBXA2yMDUZPWPCfki8UTdEyKlW2Q2LlhKfWL1gfRfE3V9TszM1GDH0am9p
         h3ocR8R5wFcjINMV4qYeVwnvwEqH5Cm7jetoU4NI2OipkSxBjslGfPCD4BfEP3Np8MNh
         0SRvuvB5OCaYTkJYT9MXsMU2bRmUS4HM2ue0l7CZFONmX+EnRe0PhIHyPd0TXCa3eBAV
         i+UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yynkz22RdZVSin8Yyh/MwjMZ9i9wscQ3l6AARy6+B+VaRqL8g9B
	8Zp/IUuxtuQFmh5YTgWyfpzMFx/ou2n9sPo0PBt2vcd+kYzs9lV9
X-Google-Smtp-Source: AGHT+IGsOevet/6G1h3d8HWcoPe1vNO/RppdFlG58C0rck09eycwEgvURcTXFF2MUhwszdo4aqBLiQ==
X-Received: by 2002:a05:6e02:2186:b0:360:968d:bf98 with SMTP id j6-20020a056e02218600b00360968dbf98mr9857561ila.1.1706616097395;
        Tue, 30 Jan 2024 04:01:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3521:b0:360:b01b:2c13 with SMTP id
 bu33-20020a056e02352100b00360b01b2c13ls1476725ilb.0.-pod-prod-09-us; Tue, 30
 Jan 2024 04:01:36 -0800 (PST)
X-Received: by 2002:a05:6e02:1d9c:b0:363:856f:bcf0 with SMTP id h28-20020a056e021d9c00b00363856fbcf0mr4488017ila.21.1706616096471;
        Tue, 30 Jan 2024 04:01:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706616096; cv=none;
        d=google.com; s=arc-20160816;
        b=wWKzEOEJAYsrIwqhjpodh+AN47FZlB/wxt5q3zQN7dZ10stzU+Vr3KocSNCOrgNYFs
         mXvIhsgKBEMiNhcCGZC79ERrfoSIp/IC9GblyNYrOnUSMcGrUUWZ7znAz3mCOGOJvnLW
         aWL4ZzbLBPVycET4mLnOOriayYWLoZoOvkoaPRhLh8Gp7eYdIY6SFlCThxV4Dj2IozwN
         YB7zKuzxmq/noiKpYCY6v/ezGBDsmaqi9sIVs41+J0NMk/+30FHOxxoMpGq6FTNeruHL
         xdmn0zq0bvCnBaKllOlN5o6VRZAFnHJUjckJhOxWmg0594pbyV3npjpYslnWS5QxBnpY
         TK8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=n0WbJbv6fzoimQXx65ShQdRhm3qiZXY+n9VOiK6k8oY=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=JCx43uWOdMKEA0CLbWXC8mTI6jPhPrmgyonAYBlEDtiv783quNSNSF0Mj02V7MDVpR
         DH5c0CFAsi76+cs69Ib0k8n3VWWWp54NM0phlk938RQa5b1m1LivkV0FG9HejdIZCZof
         LmConMQFTGDtTPSuEKy2n7Pk7rljWK6t0IeE0c40KthCZJpkFi8OMF/I83Mwn98uExah
         6+MMF3NwSfjSp8FcTQm+M6gCXFkcnP33bh04/mXJeLZ0CJWDvtz7ctLLiVMoZrEOPgnU
         2mXqpWl8XdI3RNRVNleId6OoHAWVlO7nwvZn7Izjs03nK1Qu12mnMDtjDXTGx+b1x82v
         IdCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b3-20020a056e02048300b003637985b825si539685ils.3.2024.01.30.04.01.36
        for <kasan-dev@googlegroups.com>;
        Tue, 30 Jan 2024 04:01:36 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3DDFDDA7;
	Tue, 30 Jan 2024 04:02:19 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.48.92])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 57FCA3F762;
	Tue, 30 Jan 2024 04:01:31 -0800 (PST)
Date: Tue, 30 Jan 2024 12:01:26 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v10 3/6] arm64: add uaccess to machine check safe
Message-ID: <ZbjlFXVC_ZPYbKhR@FVFF77S0Q05N>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-4-tongtiangen@huawei.com>
 <ZbfjvD1_yKK6IVVY@FVFF77S0Q05N>
 <23795738-b86e-7709-bc2b-5abba2e77b68@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <23795738-b86e-7709-bc2b-5abba2e77b68@huawei.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jan 30, 2024 at 07:14:35PM +0800, Tong Tiangen wrote:
> =E5=9C=A8 2024/1/30 1:43, Mark Rutland =E5=86=99=E9=81=93:
> > On Mon, Jan 29, 2024 at 09:46:49PM +0800, Tong Tiangen wrote:
> > Further, this change will also silently fixup unexpected kernel faults =
if we
> > pass bad kernel pointers to copy_{to,from}_user, which will hide real b=
ugs.
>=20
> I think this is better than the panic kernel, because the real bugs
> belongs to the user process. Even if the wrong pointer is
> transferred, the page corresponding to the wrong pointer has a memroy
> error.

I think you have misunderstood my point; I'm talking about the case of a ba=
d
kernel pointer *without* a memory error.

For example, consider some buggy code such as:

	void __user *uptr =3D some_valid_user_pointer;
	void *kptr =3D NULL; // or any other bad pointer

	ret =3D copy_to_user(uptr, kptr, size);
	if (ret)
		return -EFAULT;

Before this patch, when copy_to_user() attempted to load from NULL it would
fault, there would be no fixup handler for the LDR, and the kernel would di=
e(),
reporting the bad kernel access.

After this patch (which adds fixup handlers to all the LDR*s in
copy_to_user()), the fault (which is *not* a memory error) would be handled=
 by
the fixup handler, and copy_to_user() would return an error without *any*
indication of the horrible kernel bug.

This will hide kernel bugs, which will make those harder to identify and fi=
x,
and will also potentially make it easier to exploit the kernel: if the user
somehow gains control of the kernel pointer, they can rely on the fixup han=
dler
returning an error, and can scan through memory rather than dying as soon a=
s
they pas a bad pointer.

> In addition, the panic information contains necessary information
> for users to check.

There is no panic() in the case I am describing.

> > So NAK to this change as-is; likewise for the addition of USER() to oth=
er ldr*
> > macros in copy_from_user.S and the addition of USER() str* macros in
> > copy_to_user.S.
> >=20
> > If we want to handle memory errors on some kaccesses, we need a new EX_=
TYPE_*
> > separate from the usual EX_TYPE_KACESS_ERR_ZERO that means "handle memo=
ry
> > errors, but treat other faults as fatal". That should come with a ratio=
nale and
> > explanation of why it's actually useful.
>=20
> This makes sense. Add kaccess types that can be processed properly.
>=20
> >=20
> > [...]
> >=20
> > > diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
> > > index 478e639f8680..28ec35e3d210 100644
> > > --- a/arch/arm64/mm/extable.c
> > > +++ b/arch/arm64/mm/extable.c
> > > @@ -85,10 +85,10 @@ bool fixup_exception_mc(struct pt_regs *regs)
> > >   	if (!ex)
> > >   		return false;
> > > -	/*
> > > -	 * This is not complete, More Machine check safe extable type can
> > > -	 * be processed here.
> > > -	 */
> > > +	switch (ex->type) {
> > > +	case EX_TYPE_UACCESS_ERR_ZERO:
> > > +		return ex_handler_uaccess_err_zero(ex, regs);
> > > +	}
> >=20
> > Please fold this part into the prior patch, and start ogf with *only* h=
andling
> > errors on accesses already marked with EX_TYPE_UACCESS_ERR_ZERO. I thin=
k that
> > change would be relatively uncontroversial, and it would be much easier=
 to
> > build atop that.
>=20
> OK, the two patches will be merged in the next release.

Thanks.

Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZbjlFXVC_ZPYbKhR%40FVFF77S0Q05N.
