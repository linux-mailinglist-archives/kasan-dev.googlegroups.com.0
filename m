Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBBFRUS5QMGQEB6KK2VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 50D3E9FAB5A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Dec 2024 09:00:06 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-3023de5b71bsf18832341fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Dec 2024 00:00:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734940805; cv=pass;
        d=google.com; s=arc-20240605;
        b=dNDr7NaWcJy6+p6rnX5FfmAgHlLOc3z6duNdJThKjiwJ2vPk2xlVYtxAXNILMmLz6e
         Ok9jQBRLO+Ob/3pvhlfZmEGroey02LDxIuiSdSEPzoUhID3dgSvFRfqrzBchRX5vUYFO
         Y4WfSLb+p3HHARZ9JpuvncAj251lLUiV9Pq7AQ9P/ahHk8BZRQPCEsN6Xqv0+La8zz9W
         u4KLVMkh6fbq+gejCQ1QY7Uup36LqBz8t7NGtOla+Fmmn4XMIOXsIdIlRbz+YFFaqOjD
         HEti9u6KTUF1fvuEpFfCdZ/OX3gFhB7vFXQGDZK/pfae8tE1IZcPb6qxRsDXVVTXT/0G
         y5Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=UBydxPt8UbWumDvI6waRszvHwDQkwibh5zLqLn8v3xM=;
        fh=Jq+nEQEXIADUgh/fgkPA40Bn49GggCiICmRbD7OgYYw=;
        b=MUqxV/4Evpgdu+YG7vs4TIazDSNdaG4d/dqNH22B0EagmvkhAo6EU3o0tL/SvZ7pwl
         kJUXamu46R0WqH0ZSf82mqsnocE9UBD3vUmjokFCEqBKVqs85/0U8EaJNKxPF5snYSLl
         won9Nt+gNIER+dHrDL/w9dAjN+NVeW3+YIME5atrymRB5GpCtqMyj9c/xTkMC1p+Ng8h
         pi2+2W6OXcW/zMYxbHFgnNBzoXITb12mHnNw+1CTtnOEpPNq+2fCMBsZctqu83XxJx/s
         HFuPxHpKe1x0MFmWNewwqrxkrTAYJKyUoeAjnxJESiONhwrrFx5tb8E49YZzQSJwijX+
         bcnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=neutral (body hash did not verify) header.i=@alien8.de header.s=alien8 header.b="NwAS/XG2";
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734940805; x=1735545605; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UBydxPt8UbWumDvI6waRszvHwDQkwibh5zLqLn8v3xM=;
        b=ZZqHoJXwN+bhEo+8A6TMTrlJxgoTlEAN+3ibInRKJSMYeZvduA1Vshm/cltR6tNRmt
         F862Beg0Jc+RFrmjh52jyDVFMMmuVR8rRY2GqwH+TvP/KSdqZkhEd5x0+Z8o/SLr4ZgR
         6DX87ng9rrPC7l7mFLQwSSLhfbpPDUuPIg+Wa4G0YbKw6Q9ONLUglSnSH03aXIftOap8
         zE4FpBzixkikpZd78vRK4a7XNa1zfnRgJQE8JQ+9wapouz8DB3Fdl6xGf4vOp8IcsaoY
         eGRQPDmN2ZEf+RxfgXrxTdaOVx21+mvu0CDCYlM8DH8Rm+317n628GcUBXc9hiWc3FVf
         c/Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734940805; x=1735545605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UBydxPt8UbWumDvI6waRszvHwDQkwibh5zLqLn8v3xM=;
        b=BY6mG2rmkrxFHEoVJdi7RkvnyAE1bd/x96a6a5cNBsmigA2ie75RhdoFet16FDr5w7
         z9oj0cwE8FDfn0+daoJKq4c/BX52n01XvAyRdEbD8WvPpQ8NPWBNfUZhh3qI3E2nTgV1
         k+ObYA4Qw0pJYYuWb2R3z+j5wwChrKjXip7sxqo2h0dAiPy3jDTW7wiazsacTltRgynC
         abU9zlhVvNFQbAd1sT6Ao2DEGqiR8lGm+OlQKL9UbI8Nwuv0NSMhfggptIkwlBAzAZ2n
         VCGF+eyk60EnYB8nd3+th+TX2igKJCNlM3Yom2KYeLobQVuQ0GhQtKQTogJyZFcff0eh
         zEnQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbCWlZPpcx0r09fDNQz0I8gAyaXCWrkUeiqCqlP7QkjyrvTGvqjZrsrlqZ3NZQ1VAgUFEsyQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy1CnfJFTi2hhXPClN5fXA7H/TVdLz/mEAEUUh8SYNbTye8iLVt
	wv3hzbG7/XDwEy5pE5H0AByP9IxlsCcr0v3QznExs9dfPyiochkN
X-Google-Smtp-Source: AGHT+IGSdM7JTZ0P4zZhi1/oWwodtg3PXhC/f1wO8eXA3Uj7ckLXgUVnIqEEl8E3jj1feJoVxb9+ww==
X-Received: by 2002:a05:651c:b14:b0:302:4147:178d with SMTP id 38308e7fff4ca-304685c1ad4mr47622031fa.28.1734940804528;
        Mon, 23 Dec 2024 00:00:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9199:0:b0:300:168c:dda5 with SMTP id 38308e7fff4ca-3045809066bls5330251fa.2.-pod-prod-05-eu;
 Mon, 23 Dec 2024 00:00:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWfp7SnHiuaL5N2Fc6OPOBkXi7XPgaPdnielAgswmPQoAZcMSleZYVumEDXNGB4XXjhmtX0Sif4knI=@googlegroups.com
X-Received: by 2002:a05:6512:281b:b0:53e:2900:89b4 with SMTP id 2adb3069b0e04-5422959cfa1mr3900208e87.49.1734940802164;
        Mon, 23 Dec 2024 00:00:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734940802; cv=none;
        d=google.com; s=arc-20240605;
        b=HvpUrxgLQKIK01aylnI7Q2z2BWeR46JxTq+wJRbVRgbuSkWqfrhZYylvNbNH3YUtKq
         f76TZO5gmcbq4BBULwh8UF3X7bBCRmWEWjsbRQLUkk0I9D19UNQWncVy7znGotf2KNI8
         UpK0dRkbWphsYw4oCejsqz14d1JOEYAXgAfaxq5nF906eEMWJ7nNUJzKcU7R2g9oFuMN
         UAiodAL/3Rp9a7SI4GqwG49jTZLkvxCgIo0KR+F9/EQTG+TMLZgks26KVveD8zDHpPDz
         Yx60xGXPSSgTIm1Cz+KgIKMwbTdZG+gxz7Oig3ZDwe9+FHNe2G1tV4BjzvBaksahRW4F
         +omw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=YB+gFlVnZ5PUQr1POGl1EZ9GI6OWIXEqAYn2x8miLt0=;
        fh=VjHSSSNpMM0ZHlFIlQvm22uy26+yYkwvw58YZx1c5HA=;
        b=W+4SVmxmGlQheJvkZePYpVMqisQpH04Gt6ILuFT8t/x1bVeR5lISWWMAMrlzsVwvkd
         7gcI0Pk8Tb+C21Ehgn4eqLeuveGM3EzZdMoPibftgDAAoJ+KoUxZTtqzzfGF5QA5NY6n
         GsdRaJrMisZigI1m+xlNycgTdKxw+U1LUVZLHK11TSjB1fROSxPJvRtXbHVWaiWbhaK8
         wV8Iz8Ld52WgQZsSW/duYjkblL9Ptz9+GHKgG/HHSyP8OulsTvKw4VLyWcZbx4CVtaj3
         KMWUqcHwKKIiiT9IBSO2Fp1VOFcDw/h0LDK8+1m5zVNbpUaTLd+odVonSd6K6zPl16yK
         GaRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=neutral (body hash did not verify) header.i=@alien8.de header.s=alien8 header.b="NwAS/XG2";
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54223818939si209494e87.10.2024.12.23.00.00.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Dec 2024 00:00:02 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 20CD440E02C4;
	Mon, 23 Dec 2024 08:00:01 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id ZuI5ArBa_EaL; Mon, 23 Dec 2024 07:59:57 +0000 (UTC)
Received: from nazgul.tnic (2-228-221-6.ip193.fastwebnet.it [2.228.221.6])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id C580D40E0286;
	Mon, 23 Dec 2024 07:58:32 +0000 (UTC)
Date: Mon, 23 Dec 2024 08:58:11 +0100
From: Borislav Petkov <bp@alien8.de>
To: Weikang Guo <guoweikang.kernel@gmail.com>
Cc: Mike Rapoport <rppt@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Sam Creasey <sammy@sammy.net>, Huacai Chen <chenhuacai@kernel.org>,
	Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Oreoluwa Babatunde <quic_obabatun@quicinc.com>,
	rafael.j.wysocki@intel.com, Palmer Dabbelt <palmer@rivosinc.com>,
	Hanjun Guo <guohanjun@huawei.com>,
	Easwar Hariharan <eahariha@linux.microsoft.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Ingo Molnar <mingo@kernel.org>, Dave Hansen <dave.hansen@intel.com>,
	Christian Brauner <brauner@kernel.org>,
	KP Singh <kpsingh@kernel.org>,
	Richard Henderson <richard.henderson@linaro.org>,
	Matt Turner <mattst88@gmail.com>,
	Russell King <linux@armlinux.org.uk>,
	WANG Xuerui <kernel@xen0n.name>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>,
	Stafford Horne <shorne@gmail.com>, Helge Deller <deller@gmx.de>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Naveen N Rao <naveen@kernel.org>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Geoff Levand <geoff@infradead.org>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	Yoshinori Sato <ysato@users.sourceforge.jp>,
	Rich Felker <dalias@libc.org>,
	John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>,
	Andreas Larsson <andreas@gaisler.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	linux-openrisc@vger.kernel.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
	linux-um@lists.infradead.org, linux-acpi@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-omap@vger.kernel.org,
	linux-clk@vger.kernel.org, devicetree@vger.kernel.org,
	linux-mm@kvack.org, linux-pm@vger.kernel.org,
	Xi Ruoyao <xry111@xry111.site>
Subject: Re: [PATCH v7] mm/memblock: Add memblock_alloc_or_panic interface
Message-ID: <20241223075811.GAZ2kYEwZ93CYkatrD@fat_crate.local>
References: <20241222111537.2720303-1-guoweikang.kernel@gmail.com>
 <Z2kNTjO8hXzN66bX@kernel.org>
 <CAOm6qnkRUMnVGj7tnem822nRpJ8R6kFVf6B4W9MhMSBQY8X7Kg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAOm6qnkRUMnVGj7tnem822nRpJ8R6kFVf6B4W9MhMSBQY8X7Kg@mail.gmail.com>
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=neutral (body
 hash did not verify) header.i=@alien8.de header.s=alien8 header.b="NwAS/XG2";
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108
 as permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Mon, Dec 23, 2024 at 03:32:01PM +0800, Weikang Guo wrote:
> First of all, thank you for your reminder and patience. In fact, this
> is the first time I received a patch discussion when submitting a
> patch.
> About Reviewed-by or Acked-by tags, I will not add it myself in the
> future. Regarding this patch, do I need to provide a new patch to
> update it? Or will you modify it?  Looking forward to your reply

It is all explained here:

https://kernel.org/doc/html/latest/process/development-process.html

Go read it while waiting instead of spamming everyone.

Lemme get your started on that reading:

"Don=E2=80=99t get discouraged - or impatient

After you have submitted your change, be patient and wait. Reviewers are
busy people and may not get to your patch right away.

Once upon a time, patches used to disappear into the void without
comment, but the development process works more smoothly than that now.
You should receive comments within a few weeks (typically 2-3); if that
does not happen, make sure that you have sent your patches to the right
place. Wait for a minimum of one week before resubmitting or pinging
reviewers - possibly longer during busy times like merge windows."

--=20
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0241223075811.GAZ2kYEwZ93CYkatrD%40fat_crate.local.
