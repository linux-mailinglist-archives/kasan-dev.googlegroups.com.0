Return-Path: <kasan-dev+bncBDCPL7WX3MKBBCUDYOZQMGQEMI4QQJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D1EF290BF7E
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 01:06:52 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-2500b8a716fsf3864646fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 16:06:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718665611; cv=pass;
        d=google.com; s=arc-20160816;
        b=jLqHmz/6Qk6F1EP5Cp9DOjampeTx9bWps5NkUXh46DxoOO5GTjdW+hmzUDHdPBWuyM
         s9tMJmKB5xL1SFm+Q17rJuuzVHtCLvabVLedE7nsJK68O1++ClmK8wrX358NVrUPDcSl
         Sp/Ge0rdb7d+Vk82MwJaZWB2wPBlJ5cGqmkhi3Fv251SYobmBi/HzD0vv+Dz+erb9UAn
         /ksEmpBQ5aaRM7jj1ctvHc/3/PrwegcRBoZQMhU5ezAQu+a+YetCzljnA5mZ4vJHyi87
         z7a5NjW4TJR3zoaKMSK85RI1nNzLLVu53qNb5iESPjW0k3q/C80tjFF9V848uZmxxsJi
         kA0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hg4TiXvXdV6ZmO9fE51+wZHfNw6B7y7gTBfuEZU1hTA=;
        fh=oHkHHZPRYKJCTKHGGXZmPShBzpJRFQVNtK1BUZxkK9E=;
        b=R028t5XhRErPeHl/+TiC4Bqtc4Vwa1LwjE1sXihIXrtLC0/SIkz9+zW73onbYXwur4
         F9He9jUWtP6JyenTz5aIMw4gn58KZY1OEqSssOWFlq2Qi7MzHB/zPmKB800g7tOZEm0P
         vuDAYAUEkZe4RNCauB5lqScWsa0yMjY4y9JmkcZBrly7TMBxzy5bMHfhxkGjDDHxzVXE
         4v7yXd7Dq5UyXrrYI/KakTDaG22Q1C0GlXsjhDfzLVQi1X+VV8NEZkIfLgvomPr/vYz5
         Vbi47AHkchzBum7JR/la4RZm/K8HN7pjABCSgGris4k0qzRBoBC0FVEa37yZQZIVR0mM
         F6TA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NeTUngKQ;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718665611; x=1719270411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hg4TiXvXdV6ZmO9fE51+wZHfNw6B7y7gTBfuEZU1hTA=;
        b=B0RBCR35B94aM1xnhK9gpuwINwkHqrM2/KzLn0l5D5Bcxn6QxV6QxM0RGNRhROkrIR
         9zjqbrKDel+0v+jsBjryXOxlObTV27+RdXxNI6Bdl5lv9JbExAlccnldlZEPiCyRB8Og
         kYUq++D5PAbIecKmjMlQbYDV2bQMK7KcyLvHwqGzCz3F3k22co5LnfkwCL8EGljYAcoH
         s/fPgDa3AgN6tE7DFj+D//aOrV13beaBlO7K5XWUnm/Vd5A3oJi1RmOHCAlMIrqMpUbk
         LjZ1xdWaCnIDVuNieRSpNpIZMpge/FDhtmpK3R6S+ns7pJBRui2kPgJcFAet+eFqLg7m
         bvUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718665611; x=1719270411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hg4TiXvXdV6ZmO9fE51+wZHfNw6B7y7gTBfuEZU1hTA=;
        b=Y/T/XLGeBgTCnPHcCx7taOXOV0iEmZdC+AL7rPd+cSvW6pM3oJFDLDGjZB8CiCMJiT
         yjAZD9b7FxLSIGZtSieWZ0+woCW8cp4m/aYmYLqlQ8LkrBrCIJAlohkAnYdVzLPp1djB
         lzZgGJ3r0LN9ZHCmgg1DMMMei/0LMs7gf78BGgldx0B9Yo01L3d4OwESM1+ypuq0QGy4
         CLFFq+B13hVR6ba9M1zcI9G5fADpCtzgCkgir5TlNDcEhV+OCztcs387zlNjA3lhv8uc
         59VSNthlZGbRftLGw/BJOPuOL2JeaFOMnSVcuIi8Ws7u8szAeQjrG1LFevWcVq3FQSUM
         AVdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXoYJPxUMcHO2v4sqiRBXa1nl26wVm7q5NSJh2rCZbsNTBnOwHogLxj1B5ciWgVJwdyNiQxA7rlxlA9+K9QUTmPlyW6NK5x4A==
X-Gm-Message-State: AOJu0YzUaUsSsgOaqI8M1uh+ic9QDkQQNj2X3sx1PSBO1sXt+6H4Ay3Y
	4xTG0K7XwWw/v5L8QkwzGBHg5agFibP7+i34lC85IhGuHdiTgQFk
X-Google-Smtp-Source: AGHT+IGzVMeSftUb/egUiw5BjobmX20qewESYHTtuv5pYtOOzZtbtOF/Aji7B/XVqKB87orIwELBLQ==
X-Received: by 2002:a05:6870:638c:b0:254:a5cc:f20e with SMTP id 586e51a60fabf-25842b78cb9mr11535494fac.44.1718665610966;
        Mon, 17 Jun 2024 16:06:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f6a8:b0:250:fcfb:2c1c with SMTP id
 586e51a60fabf-2552b66ff1dls1765220fac.0.-pod-prod-07-us; Mon, 17 Jun 2024
 16:06:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHDSO4EdrztHBNBc4fy+sACOylTsL5H3328T2k4O2u9NMEQjYxz5SV5n33wLm1bIs5HjckLmvo/1iuzhHhyQCAv37unOoI4/vhXQ==
X-Received: by 2002:a05:6871:3a09:b0:24f:c9e3:b76f with SMTP id 586e51a60fabf-258428eb30cmr12690986fac.19.1718665608497;
        Mon, 17 Jun 2024 16:06:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718665608; cv=none;
        d=google.com; s=arc-20160816;
        b=Vp+l99cVlAKy4pGEcD+NBJVwEC/azzRO+/noIZc3dznyyVIjCx2w/M8F6d8IFCnKI+
         NUG54TPAghTl1VUJzFRoV5020TIrtsiSuiPaL2YkGH/WZMLxENKGxjQRCMpb0Z00NiMW
         RPDpKmS36THoC/gikp9NP7CMhs4p5wieZwV292dO1InE8Z6ebDRKAMRg3t3rkkVrZxuL
         BS9t2kbdbrIbdyutFaNv4j12MOIzj+Y9eUlh7iEUWqSA7ATDlsp8bJOKHzr/VZjdYiuv
         3QcelrtlojgQDFFQ33Pd/lWZxrqKZDFkkZMpZBFZ0Fz96Jxv4FCkfSVyDqq+eQWwjs0V
         yKoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=e10JYjTKb/8urY49hoCqXeUG2LNVHwcFOIuokkkLTR8=;
        fh=kSEd0C/TZD87ZP5jXeo62GhHy1VmrIzGlKPBHEpnbUU=;
        b=jEEe9FnlJriuiELm/M2ODYZklr4EjqUgev7O0pxBuunOdANlsRKS8u9Sul38/1kgpx
         YqntaQDR0l2bTwn6oEygO+kaMXRLcfXXAbfecJs8Iqr+e3Qvo0jNSSckmLYFNau46WQo
         9larJWuWIqetpz4ysYtsX729DkeEw1C8dShT+T8uFxaAbV3WeyTS+3fNscxxkf+preif
         XGJa3MZbszDzve3Vu++4G/Ek3FyHQxMgyYlG4hUNHzDRv21jolfIBB0aKlJs7VAEDUNv
         UDayr9qQYhZqhXMyb+zBeSZ29oCQtdXM4+WMU1ZXhbbKgPdWIyHQF6UlcizElqnADrOf
         VsTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NeTUngKQ;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-256493f13c5si503852fac.0.2024.06.17.16.06.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Jun 2024 16:06:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3F99C614A2;
	Mon, 17 Jun 2024 23:06:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D9AF6C2BD10;
	Mon, 17 Jun 2024 23:06:47 +0000 (UTC)
Date: Mon, 17 Jun 2024 16:06:47 -0700
From: Kees Cook <kees@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Gatlin Newhouse <gatlin.newhouse@gmail.com>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
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
Message-ID: <202406171557.E6CA604FB@keescook>
References: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
 <878qzm6m2m.ffs@tglx>
 <7bthvkp3kitmmxwdywyeyexajedlxxf6rqx4zxwco6bzuyx5eq@ihpax3jffuz6>
 <202406121139.5E793B4F3E@keescook>
 <875xu7rzeg.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <875xu7rzeg.ffs@tglx>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NeTUngKQ;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jun 18, 2024 at 12:13:27AM +0200, Thomas Gleixner wrote:
> On Wed, Jun 12 2024 at 11:42, Kees Cook wrote:
> > On Tue, Jun 11, 2024 at 01:26:09PM -0700, Gatlin Newhouse wrote:
> >> It seems that is_valid_bugaddr() needs to be implemented on all architectures
> >> and the function get_ud_type() replaces it here. So how should the patch handle
> >> is_valid_bugaddr()? Should the function remain as-is in traps.c despite no
> >> longer being used?
> >
> > Yeah, this is why I'd suggested to Gatlin in early designs to reuse
> > is_valid_bugaddr()'s int value. It's a required function, so it seemed
> > sensible to just repurpose it from yes/no to no/type1/type2/type3/etc.
> 
> It's not sensible, it's just tasteless.
> 
> If is_valid_bugaddr() is globaly required in it's boolean form then it
> should just stay that way and not be abused just because it can be
> abused.
> 
> What's wrong with doing:
> 
> __always_inline u16 get_ud_type(unsigned long addr)
> {
>         ....
> }
> 
> int is_valid_bugaddr(unsigned long addr)
> {
> 	return get_ud_type() != BUG_UD_NONE;
> }
> 
> Hmm?
> 
> In fact is_valid_bugaddr() should be globally fixed up to return bool to
> match what the function name suggests.
> 
> The UD type information is x86 specific and has zero business in a
> generic architecture agnostic function return value.
> 
> It's a sad state of affairs that I have to explain this to people who
> care about code correctness. Readability and consistency are substantial
> parts of correctness, really.

Well, it's trade-offs. If get_ud_type() is in is_valid_bugaddr(), we
have to call it _again_ outside of is_valid_bugaddr(). That's suboptimal
as well. I was trying to find a reasonable way to avoid refactoring all
architectures and to avoid code code.

Looking at it all again, I actually think arch/x86/kernel/traps.c
shouldn't call is_valid_bugaddr() at all. That usage can continue to
stay in lib/bug.c, which is only ever used by x86 during very early
boot, according to the comments in early_fixup_exception(). So just a
direct replacement of is_valid_bugaddr() with the proposed get_ud_type()
should be fine in arch/x86/kernel/traps.c.

What do you think?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202406171557.E6CA604FB%40keescook.
