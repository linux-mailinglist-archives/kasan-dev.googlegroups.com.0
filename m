Return-Path: <kasan-dev+bncBDDL3KWR4EBRBUXYXW6QMGQEYOEJU2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4419FA3647A
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 18:24:36 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2f83e54432dsf7548189a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 09:24:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739553875; cv=pass;
        d=google.com; s=arc-20240605;
        b=lf8KQ36ISYkghT+uFwAUy/OxKo+b/L1e5yB3fFZzYL3EMA5LUHuGqt0Btppk+Xehi4
         /VhaptLnsH1LrftBtaeSgGklk7/tlpn483mgtJDZw2mru+J0ExA4bTz/95S/PfTI67nZ
         Q/qftifMvczXIKBF/BLVbJEZ5jZDvpEXss+0Q1JbyTNzVszXAR6oCPmpV3rqHy8CAn99
         elOXdQIXl/lMSs8IerW93lgEpaB8hgWl0tnK9bPrB9TnwjsRaHE+ElZZ42V3ZMakeKr/
         PNf3xiHlUdW7Nqpn7ELTmZ8kVFfQ01/KLQAKdbXWywFHIEwb1EUZxrbpiVJh30WXOaH+
         3WHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DUWuRgy/hQzNdIG5Utg3uou2AQYt7nr0M5ZTk49EYlI=;
        fh=DcDqn0d3P1yd2DiRjuHGrshk9NoyAHtXluZT0D6+c0E=;
        b=lFKU0/2LOis4g/3z1ym8gnARt797Cs8ATVU6ngE4avosCHDej3zZyupllhw/PFc0Gr
         iGvHHiKmutGKHjj2An3XGO4eMp3GyLgytM5CN42zL0j2B0G73nyp0zMOAn0Fh2vqvtco
         wO/eN1+yGSyDXSUAiQvpwhTFYhWh9R4msNxhVzJL4mq4/8N8Nfng6r5nWO/y4wfDVL2i
         o+bqAgeNnocRdsngUf6x6BHc+h6gWbeeUv2cZ0bfXhnxNgr3lOhRd5GJLpAi/QTA4XJd
         vo63Go5pzXc7Wnx1GDpy0dCIZ2fnzXRUyiiDChyYjBrXBKeQoo0g94qxbT5RVwRM/CJt
         xG1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739553875; x=1740158675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DUWuRgy/hQzNdIG5Utg3uou2AQYt7nr0M5ZTk49EYlI=;
        b=lxgdiDB07I9yIWkDSipSQJPfyoYrvYim6V48DZ2BMpg3XHtT+RN5CydF1wIEuOJeny
         VKNRO8lY9KC1flFSqdZYW+GfBQJ1kg/gfkU7/Bj3y+uWytm4D56WvHKW6IXmMPGHMqCX
         AJCNyzW/mdRYZ+/wJn0bGU3hDQk9eAiB30pS4dhvx9KtCwouF7YZ+2CkcjPypKllVekB
         MjguZTU9yD2e7ioecGQVRP9OGJ8k0Fj48FvilCS7Tj2Z3YnReSAsJtpkiwr3HToS1qya
         55ejrxMI7glLc+UNVQgjjpNCMZdLiDU2ZUnbekLdwitMkPjzMvSfp0f73zSP5U2PtH8y
         odmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739553875; x=1740158675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DUWuRgy/hQzNdIG5Utg3uou2AQYt7nr0M5ZTk49EYlI=;
        b=nKhUT8aG2RBgG9ke1Vee7iWYPpt+HiJEKRr2Jjc4AFUndi//qLldnJJ6+VrG25f3cy
         EgjO5sfDPsk0bhtIcCAj7G3I44yAlDIpncMTaZVBrVFS+a48AT/LnzEbanNs+mB9UoFd
         2BPrkujWDXkK9+gMkPzXDER4khgmHQhq4vAFFd1GbpzmhDpcoFJPhBpUtrKlJ7NYvySI
         f3PjqxggwhXKPFr3s3yIDDbUaz7gg2L1NquTB3tjlOK9F/YsJSFgYI02K+BsQI7SPb7C
         7oWpk5fZwxPfcVDq6ng10eNpDQXyJZ7ZkSFakPrT52DdvHhziVNdQ9JvgYi7xelNY6xH
         fCjw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWkXqS5D/fKIcG7b5fjRSW8Z6DKi+rqMmwLsiEhOx19Mig9N+dLFPHjSQMge9fsSmt02IbJ1Q==@lfdr.de
X-Gm-Message-State: AOJu0YwVtYGeOX6Tz1OHD/WpLkCimdjDStzNx2Tioxs7Xrxg+Gry7k3d
	dJDDeZX0RlUa1eIST7SHVD+v50JtWIrDAgDBq+Mruh0ycWt8AZTJ
X-Google-Smtp-Source: AGHT+IFyYT4MacL7+r1V42vsUsb1V+t6q9QmYJccQNN4+H7JEp7MNLVYjxwe2AT8RzBcJEEBjJl+Lg==
X-Received: by 2002:a17:90b:2549:b0:2ee:d193:f3d5 with SMTP id 98e67ed59e1d1-2fbf5bc1e3dmr18762606a91.7.1739553874743;
        Fri, 14 Feb 2025 09:24:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHsPXb+Lbhnu22cz6hN6MHPyk+9i1rQNwusO3np9A7Skw==
Received: by 2002:a17:90b:128e:b0:2ee:eb83:1eb0 with SMTP id
 98e67ed59e1d1-2fc0d57af12ls1992018a91.0.-pod-prod-08-us; Fri, 14 Feb 2025
 09:24:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCALwy928pLoj3mLTSijsHRPIyLRabQUXsnyvchotV3vF0bE1Do0QeL4gN5KDPKJpIj40Aw02UpBg=@googlegroups.com
X-Received: by 2002:a05:6a21:150b:b0:1ee:67ec:2279 with SMTP id adf61e73a8af0-1ee8cbbd6a0mr386397637.26.1739553873337;
        Fri, 14 Feb 2025 09:24:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739553873; cv=none;
        d=google.com; s=arc-20240605;
        b=D/E61zzuZzKzwUv+s5VBFwFJJQl19x3dtnEgsPk6qtQhasso4HVc5QbbT0T1Xlr0mi
         octgA5ABnQ1Z30Jto1aF9YkmXf8LeE0qiyX7M6Soblt4k8Z0xqAlU/aJs5HPTgUvDGgj
         st/LXkx7CmB9BQvNMwvp/pLU8HpxmgGop5+z92eftQeDzrivyD4MKB/QIo87Dm+2uiUL
         k7+tALv9C/1NRoEp3M1rxagvZf5151CrvYMslbHqkC9p/V8okyAG4WYoc8GywQpH3f+i
         K7ZHGvxIxBiKEMO+4sCUv4pGxeWn4e9CijRlhHGdCG4RXCJ9PMDzGbvzQOIXOTG8smCk
         Cr9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=5YtMi32FHQ7+fawZb+ziAVgUu2Jkosuh7gVhJkARHqY=;
        fh=md3ANKhaGYZbuc9iasr19RDG3GmpFkCH4nzOFRqlDfA=;
        b=Ck+PbnAlDUguxtBDRMI3UDF0y3p+2vByDN8oQRoUBovgYRgT5d17nx4W4tiWgHIkAV
         xxB70S2aUtvoQDCmAkcFYeKhM7VrK3lONNEm9FeTbLIquJdrEsAgSTQlvXCgIJYTTP33
         9mW8H9FPefCQZcNkp7qvhjOkkmcQrbzzV6gX1v+FnIukbooRfpDcLfVSuLriOzLVM1od
         GtTj+g+GyOfzNlxOgnGDpXY3cqbsyMaHygIdfyzeJwHPI0R3DVIXYYqU2LhZ6Le1PyHO
         LacXyMX/nfNuUSq9mVb61Ohy88sRhDADizqTcmPoyHZ7p+lK4vx+il3AbBHAHBXbArTT
         KJOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-adb57c5e0aesi164855a12.2.2025.02.14.09.24.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Feb 2025 09:24:33 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 30CE55C5A25;
	Fri, 14 Feb 2025 17:23:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4AF84C4CED1;
	Fri, 14 Feb 2025 17:24:27 +0000 (UTC)
Date: Fri, 14 Feb 2025 17:24:24 +0000
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
Message-ID: <Z698SFVqHjpGeGC0@arm.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-5-tongtiangen@huawei.com>
 <Z6zWSXzKctkpyH7-@arm.com>
 <69955002-c3b1-459d-9b42-8d07475c3fd3@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <69955002-c3b1-459d-9b42-8d07475c3fd3@huawei.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
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

On Fri, Feb 14, 2025 at 10:49:01AM +0800, Tong Tiangen wrote:
> =E5=9C=A8 2025/2/13 1:11, Catalin Marinas =E5=86=99=E9=81=93:
> > On Mon, Dec 09, 2024 at 10:42:56AM +0800, Tong Tiangen wrote:
> > > Currently, many scenarios that can tolerate memory errors when copyin=
g page
> > > have been supported in the kernel[1~5], all of which are implemented =
by
> > > copy_mc_[user]_highpage(). arm64 should also support this mechanism.
> > >=20
> > > Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
> > > architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
> > > __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
> > >=20
> > > Add new helper copy_mc_page() which provide a page copy implementatio=
n with
> > > hardware memory error safe. The code logic of copy_mc_page() is the s=
ame as
> > > copy_page(), the main difference is that the ldp insn of copy_mc_page=
()
> > > contains the fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR, therefore, =
the
> > > main logic is extracted to copy_page_template.S. In addition, the fix=
up of
> > > MOPS insn is not considered at present.
> >=20
> > Could we not add the exception table entry permanently but ignore the
> > exception table entry if it's not on the do_sea() path? That would save
> > some code duplication.
>=20
> I'm sorry, I didn't catch your point, that the do_sea() and non do_sea()
> paths use different exception tables?

No, they would have the same exception table, only that we'd interpret
it differently depending on whether it's a SEA error or not. Or rather
ignore the exception table altogether for non-SEA errors.

> My understanding is that the
> exception table entry problem is fine. After all, the search is
> performed only after a fault trigger. Code duplication can be solved by
> extracting repeated logic to a public file.

If the new exception table entries are only taken into account for SEA
errors, why do we need a duplicate copy_mc_page() function generated?
Isn't the copy_page() and copy_mc_page() code identical (except for the
additional labels to jump to for the exception)?

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
698SFVqHjpGeGC0%40arm.com.
