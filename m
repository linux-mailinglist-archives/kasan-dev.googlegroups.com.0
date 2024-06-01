Return-Path: <kasan-dev+bncBDCPL7WX3MKBB36V5SZAMGQEJX2X2II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D0948D705D
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Jun 2024 16:06:42 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2c1e99654fcsf1204961a91.3
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Jun 2024 07:06:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717250800; cv=pass;
        d=google.com; s=arc-20160816;
        b=VasxFru682VWgO6yOBw66jrYmQw1NODMtus32lCieR8KbClac/cwAz+q8RahZP7b/i
         magebfI4urVhJ71xsHTLADx2UQi4+sL5CO5wGauPicaopZLgWi1Z6Q38Vtuk2mk5I/5q
         ufsNrLm2aMJBrgJG7VlTkmoePOoaEr6dk3tww24dFCkVy663I9gB1V7r143yN7K4p7HL
         +EMQTLzdNVPV51lZ0bIHTc0EQkP6IANekMj8BDfi0RPH0VRQlX7gWEydwXSuS+jBl9D0
         c7yb/Ra1W1LvcUgndMy8fxJiX38/1lvKla6ILKLQRJrARHbtw8s3+nxqUxH1JQgQPY8b
         J24g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1cRds7ALxH/ixnsGs2vj7E0CVG0r/lkV9PvL1/XVoyI=;
        fh=rj8fcemgelpSwU8V7wTD7pR2U+9QIDkx1p50l11qz9U=;
        b=uSa2Es4iDlSDnuPeCpXGC8vdzdNMjuUCAcLIZHzQ7k9cTd9tuzI/oQC18A/or/PoMv
         n6vDQV8X71c02IQ34Jn2AfyNUNVWtWJr0AcYkn4gfbN12knWKa3+6ZUIRkyI4wcNzMSO
         LbHKl5OUBDRY9n4kCI4fGRdCdPRk63Ve3J93sBNe1usdOSvQnlS1+P8s+AF9XuQX03d+
         vhIOhPASYBJ2R7g5aYhKVhMNvDPlmtmIu32B/1bLhfQzow2JtxXr6tEDO7DE4Aox0EWP
         4GjSAOKr1IUW6S+sgwvOhVpfxRGFu7VPxVI0Kxm8jRbqyFkuH8OKZtPlYuF3TUdBWKtr
         5Daw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=unBUsn8O;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717250800; x=1717855600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1cRds7ALxH/ixnsGs2vj7E0CVG0r/lkV9PvL1/XVoyI=;
        b=bBX5NCTMVT9ghHjmoUzQhwuYq6r7+onGSQBsavUH3axtbxFBG6V6NWVTl3oEZL8JMr
         oyLZg0sF70nIHhQG1HLJLAU4LvrL661sdP6gbxPlxeYRuSHv1CTXggNK8hOWMPaevbid
         5kfrCkemrOWnDiSdAJDvZCGdkOq30GOdwfd/JvH/GxBfE7lxX8boxusScvDeTVQTJCWk
         f5EZVmEu1wxoxUbVFF4Ag/EG9U4Wz+X4K0a7e32aNG+yH2b79PRtpJ8KW0orswKPgOld
         JrJbtdEKmLCmz1cZi/ZZm+SjUs9IoAe7p0OWfrp7mkMe9XxNifZKplATg9rNyLsiDqf8
         AbQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717250800; x=1717855600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1cRds7ALxH/ixnsGs2vj7E0CVG0r/lkV9PvL1/XVoyI=;
        b=btgJWINHdHn4mcpGxudxdncKCTpkBGBcfFIGm3jKFolKFhUaYDCF3QSOIIudEMrR4j
         ACvc0WiDZXfZBaHdsbwPzn45MYrN+vJlLCq55Ebh/uLC7ey0SYTEoUqEyWj6669GiJDq
         /d3Tlts0Aa9zIzpSevhuLqDrN9uFp1L2VrFFO52bBNEdO8+RBfpx0jy4/Ntua+ofIZof
         RD6V4kwPwv/LFpl2v+67gramTC70GHEDaO1gqyhvGlgy8aNKZw6fbklMc5MY5EPBtO42
         B8/ym9e1HwCql+tXKSSGhJjw2kupIkZwl4Io5F9FzRwM56/HbQd7mR+QBWzsAYtOhFMV
         rSkw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1nF6DaLyDM7zYXveH+bi41EWCBUzQN3SFGUzWOEbwRiKsn0Dc/SKp3AZb4c+3ly2g37lr8YL272LtKsVfahcV86CxxK57zQ==
X-Gm-Message-State: AOJu0YzwVtcPZ83z1a/yJI1zPVqbIlT3yhZCz/8WSTEUSzCgnXEckgmB
	tCVMcW6AThIjIEhJmG6dlLy8poSi3Tid6rXGMSk4gjiZLpjPS0n0
X-Google-Smtp-Source: AGHT+IGzRCXio8gR/D5RIQnR9kr7t6oZYIuvNZnpUWQj04ZUHJoLW+RZGxXgxa+vMgjphaTcZ1NZ5A==
X-Received: by 2002:a17:90b:fd2:b0:2c1:97c2:5cbb with SMTP id 98e67ed59e1d1-2c1dc58b314mr4382639a91.21.1717250800054;
        Sat, 01 Jun 2024 07:06:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad93:b0:2c1:a500:48c6 with SMTP id
 98e67ed59e1d1-2c1c18fba3als425943a91.0.-pod-prod-01-us; Sat, 01 Jun 2024
 07:06:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqI4VcKjymE40URD6UHfrArZi8VjxE1y0GpDlkFMP+HoqHbqMXbTwDA9/oDnff0YDO/a3aWwRZoZVaP2JmXoBcarWZudLZ9EQQ8A==
X-Received: by 2002:a17:902:e848:b0:1f6:3dea:790b with SMTP id d9443c01a7336-1f63dea7df7mr45023485ad.44.1717250798746;
        Sat, 01 Jun 2024 07:06:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717250798; cv=none;
        d=google.com; s=arc-20160816;
        b=QsSkWAffnhCiOCVIa1UTpKodY1LnK1rGlLYavkNHZmFDc72ZBurZOgKHIs9DRySxO+
         VkVYHNtcu426Cf9blbU7cdUEPwiCEKK9mgMAFi79eMPwa6MyHLRZoWMrHItfFkeTXcuw
         vVMgYcHRwVt/VDhVWYqhLcrJPb098fh/lVuuUTqDRbMYxgUAGQu9JSp2TzZr/lHsJFec
         QGt7lNsoLAQcZaERZ0KJUEUvtbFmPOkgIlc59+7OPXJ9QU/Yu9hQcU8j18kUrWHlXQgY
         3tIhLw0pEA6dT4jwbYVv3vkXlgO2lJriSKE+HRdeqL8VEfWBTUk0env/hRrJa93H87Dh
         l5sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2YrNxlAfm8atSSMWUuO/bV9+KAJblkjpZJhGMH5prSI=;
        fh=QLazlS7EGh5PYxYf9NzlI0mDL+ZY77OPKlGcX7oWOmI=;
        b=gzMMtrFjHRbgzY8FWjOefbpBJ0eJ2FeL4w4f+r99gwgUW+p5zpxr9hz1yvYZ2OmdXc
         2f7aZvEgbeDiY/wA5pl8vsaBdd0vdK5vZfJn1oZDtfS5GAinncuCtB7urz27mERPvjNp
         r0gSoeY6NH46LejlttY0UWwQvUsQFuTjE6kAocxRRn21GevGkPxFolbuzmOsWRnC1YV9
         FSSr0TCGkuhNOzTvfCiXjXxD0lqXCHnNWccOdeC7G+TnNXRnpU5QtvXfXBsN1Eysq5Ir
         AZhNCTWoz2Cf6WbCWuUWItb+lEVK3rHkhmmRwZCT0Jc43ZjyYWW8lrdpatNN1cLqgo10
         1KAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=unBUsn8O;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f632338b6bsi1781605ad.2.2024.06.01.07.06.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 01 Jun 2024 07:06:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E754A603F5;
	Sat,  1 Jun 2024 14:06:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8E446C116B1;
	Sat,  1 Jun 2024 14:06:37 +0000 (UTC)
Date: Sat, 1 Jun 2024 07:06:37 -0700
From: Kees Cook <kees@kernel.org>
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Baoquan He <bhe@redhat.com>, Changbin Du <changbin.du@huawei.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>, Tina Zhang <tina.zhang@intel.com>,
	Uros Bizjak <ubizjak@gmail.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v2] x86/traps: Enable UBSAN traps on x86
Message-ID: <202406010700.39246BA@keescook>
References: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=unBUsn8O;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Sat, Jun 01, 2024 at 03:10:05AM +0000, Gatlin Newhouse wrote:
> +void handle_ubsan_failure(struct pt_regs *regs, int insn)
> +{
> +	u32 type = 0;
> +
> +	if (insn == INSN_ASOP) {
> +		type = (*(u16 *)(regs->ip + LEN_ASOP + LEN_UD1));
> +		if ((type & 0xFF) == 0x40)
> +			type = (type >> 8) & 0xFF;
> +	} else {
> +		type = (*(u16 *)(regs->ip + LEN_UD1));
> +		if ((type & 0xFF) == 0x40)
> +			type = (type >> 8) & 0xFF;
> +	}

The if/else code is repeated, but the only difference is the offset to
read from. Also, if the 0x40 is absent, we likely don't want to report
anything. So, perhaps:

	u16 offset = LEN_UD1;
	u32 type;

	if (insn == INSN_ASOP)
		offset += INSN_ASOP;
	type = *(u16 *)(regs->ip + offset);
	if ((type & 0xFF) != 0x40)
		return;

	type = (type >> 8) & 0xFF;
	pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);



-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202406010700.39246BA%40keescook.
