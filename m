Return-Path: <kasan-dev+bncBDCPL7WX3MKBBTU32XAAMGQETL2P3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3442EAA7C86
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 00:57:20 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-739764217ecsf2345846b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 15:57:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746226638; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zk+uMMv9fIkwt64//scjbguEzvcJ8ScU8PeSoPr8INq1MhNEEjmUyffH+uQBc3NAsS
         zuhmlrqaK5B3hUiBzgqIkZr6L4aaan+Xz1b5mfdO1C+VhVvYghFZth9AGOSP5fk2L0Tw
         fO73UtkQgvLLRedhGMVtq9NSDENXd0WLs2k+TPARrTATGE43R5PgUl1lk7fKjuoCrNoI
         7FbIQ/hbOYcf9/4/nDb2NYtailCCT35CqY3uhGjRGQqT9e1HJhJvg0gNI42gTF7gMjnb
         Wn5ksNRHvGsX9z3E4O7ycrOcOIN2e12CNX2pvh+6+3lfCLOibqT2dGZJYAwcTJhh+JIw
         SLzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=s2RUo02Uj4mmCJu+qWlumlNZ/wkH6dBJ0xdi4Q+61TQ=;
        fh=ApZnmgUNCpjQrtJZ+L+PJB7WjJPoOIsuwBplVe7UD5Q=;
        b=aDolCdTbwkpVMGSYxOVyFg1dX//QZQ7JF+hCGzi28j2NjWVxDE/XZSDnWmlHwsBONw
         rriDbOUulqN+kL+gaXcwsm9AGYn8ZHKdH563S6BSzTPmw5EE8iQbCDAe4Beih1l6lGXP
         mmKe18e0X7jENlPPHreA/wbULcVQoO5Hq8VlSGzjW502WXSl2vKGjl+qU3LJaeoR8gaU
         3vnsqfQR2wZyHNzBsfCp/LmnZ+qSRaqQTYpwC0d9d6Jy9LtHc80/9loR6jelVwGtxLxB
         n38POaWivlgbRbAdT0d5xvFvg4KWOpxAlHQ7J+Da0gZBy3O591Vv86RWWbP1ZqBfg2Jk
         3O8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UDDD+ufi;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746226638; x=1746831438; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=s2RUo02Uj4mmCJu+qWlumlNZ/wkH6dBJ0xdi4Q+61TQ=;
        b=rgUYB888EIFZ2nmWhmKkBsHrdsRgy/z+j7GxQ81Mye/ZmAi+jKqmnguuabcSBRT2bX
         ioZoknot5LyZLdzALiCDALEXWMm1KVmiALZazpeNiyRA8gqAUWCXRIAGFHnNqDeiXvdV
         P+EN+ZRT4VxmPlxttWz6Y+nwJKQZsFOqPMa/k8YxEHtHxsbpjMQ7UN9FLjKfXDqJvuPz
         apl+26hXnsJHi10xsiwf45K5Wyg04TaevbPItfjvM2BQatproRfGPxvPCc/6nTR8IxRS
         I1jLbEFQIMTcIP5RGHT+mo9QEbjicrqHp07fKIQy8fCoywoLZlYniMPLFXsrjmR09u1G
         RsXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746226638; x=1746831438;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=s2RUo02Uj4mmCJu+qWlumlNZ/wkH6dBJ0xdi4Q+61TQ=;
        b=aZmgUhPqWsTYy4e7jF5Euau/DgaZTdykZYHpGGCmkHJItRnu69KwWdipri0uc8hGJJ
         ZxjkNMHpjO9LHlGXn+yOCZ6Z6Icuqc9owr0pxwmWemfwk4BSqcrKnBHlR+bzg+brNh5T
         T5hShYhf4i4DicXjlSW3/iCtvXPoaUOJftE3gQfKbnUPKMfayGoMkJXQ6eAIc54oQAgJ
         TMlaeuD2YQPuKxzLopUPvGNuixizCDUnIZ07CQvajUPye5MCOC/nYELEQtCO0FHRhjJf
         0F6dLK8UeSRun468gtdsW5HGVB1GV8nf0rgiT8q0zvCxZywx/2WKHRf3GGc76hVoGdTI
         cxUg==
X-Forwarded-Encrypted: i=2; AJvYcCUzM6mx5Mc2OXnlL3Cj1r4ZH6CrZftSDR5sWV7c+bkRrY45Z6WA7v/Qeapjt+xkEftda0ic2Q==@lfdr.de
X-Gm-Message-State: AOJu0YyMnziV4x4envkCY3wwsxveOrMCV4gkhCk2fNxtv8n4nif+Mm/l
	H+PncjvPnat+OKD7ygmdELOHL9MrAuvkA1rhxNtHtBWhADgfTYQV
X-Google-Smtp-Source: AGHT+IEAr+ageZJR0bRTDt25rh8zsGIvYHaL/tdcTsoj0Us6rnFTTlonsJTTUVh3Cb/xKpn1EYkn4A==
X-Received: by 2002:a05:6a00:4c17:b0:73d:f9d2:9c64 with SMTP id d2e1a72fcca58-74057c54811mr7000631b3a.10.1746226638524;
        Fri, 02 May 2025 15:57:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHVZH5MfUohCPzADH2ciWSRuRilbyuvPybkC68z7IqHkg==
Received: by 2002:a05:6a00:acd:b0:736:cffa:56ce with SMTP id
 d2e1a72fcca58-7404599e653ls1882297b3a.2.-pod-prod-00-us; Fri, 02 May 2025
 15:57:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCmWb39nwg8tPsj+AJJ/Yoyl9vfEd+4npKcDpO4a5JJypACsKXHKblMbXIs83rFktepH4dPylOaKw=@googlegroups.com
X-Received: by 2002:a05:6a00:1c81:b0:728:f21b:ce4c with SMTP id d2e1a72fcca58-74057b2f03amr7690853b3a.5.1746226637111;
        Fri, 02 May 2025 15:57:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746226637; cv=none;
        d=google.com; s=arc-20240605;
        b=hp8t4rmDfluf53WWHqZNg5bsjAGJrdS5TFNJTC/I67ad2NDUxURqrUqjB0QKu4GyPQ
         XTumU7BGTB0Kvg2l0jkEbe/znIfTSFdFg1t8RheRx9j1VaOJZBoQptEzp2BGhagiBzrL
         3GCDCf74v0pjbYqmkYum3P7ho9EVgV8yB1zpJIsY5Rgmjk8qSD9DuUmKQBQlia/K8S9r
         hTUdUFeDzeamwgp6ull/zj1+0cJTWnvvddrmtSJdyUAWQQqr9KBEkRcKxIA1gsupFTd2
         lcY1x4DnqRRlXVR0j0oSeMi/jUyn86X2dTAtPinUdjoezUCuyTgHmCorPenp1lI48cD7
         6xZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=OF71mq3f6k7ZdWhUbXDjvrYK50J1ywSODyajNT5qxeI=;
        fh=niiA5I2J8lTTlUahYB0OXL29q9NejwiTbINZ1Mj7alE=;
        b=hYTGQoC3YSK7qYSuuOtEwxQVHOLNfGiDx8HumTZfZI3tjmiXT/TQgwSQ8C+upE1iGi
         kSNSCA2Xj3oHgWViJaVXY89vv3pkgamOaLEVyoUwW5TnFLGSuHNdHv2Mu4NsKea6iH9X
         +Xh2BCFUG5FnAHNF6PkHmbjJoo4DObZ6QwjINwOhmNHR585kqUI0dL6bQS3IzPXKAZ3c
         cc8CrjwY4yuPvpkzuS67h8o2g6Q+vKouaHsMieXDhiQ39QzQMeqqMFPDU4x22O5BV1Rs
         AhpDBjRfeBSGottPhxWji5o+Npy4nEtQHXSBkyKfmxvsGqbWyp4qeGe007qnA5L7AKvZ
         YkoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UDDD+ufi;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74058db9223si126339b3a.2.2025.05.02.15.57.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 15:57:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4DE565C562E;
	Fri,  2 May 2025 22:54:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 17B3BC4CEE4;
	Fri,  2 May 2025 22:57:16 +0000 (UTC)
Date: Fri, 2 May 2025 15:57:13 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-kbuild@vger.kernel.org, Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/3] randstruct: Force full rebuild when seed changes
Message-ID: <202505021555.A74E678976@keescook>
References: <20250501193839.work.525-kees@kernel.org>
 <20250501194826.2947101-2-kees@kernel.org>
 <20250502161209.GA2850065@ax162>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250502161209.GA2850065@ax162>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UDDD+ufi;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, May 02, 2025 at 09:12:09AM -0700, Nathan Chancellor wrote:
> Hi Kees,
>=20
> On Thu, May 01, 2025 at 12:48:17PM -0700, Kees Cook wrote:
> > While the randstruct GCC plugin was being rebuilt if the randstruct
> > seed changed, Clangs build did not notice the change. Include the hash
> > header directly so that it becomes a universal build dependency and ful=
l
> > rebuilds will happen if it changes.
> >=20
> > Signed-off-by: Kees Cook <kees@kernel.org>
> > ---
> > Cc: Masahiro Yamada <masahiroy@kernel.org>
> > Cc: Nathan Chancellor <nathan@kernel.org>
> > Cc: Nicolas Schier <nicolas.schier@linux.dev>
> > Cc: Petr Pavlu <petr.pavlu@suse.com>
> > Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> > Cc: <linux-kbuild@vger.kernel.org>
> > ---
> >  include/linux/vermagic.h    |  1 -
> >  scripts/Makefile.randstruct |  3 ++-
> >  scripts/basic/Makefile      | 11 ++++++-----
> >  3 files changed, 8 insertions(+), 7 deletions(-)
> >=20
> > diff --git a/include/linux/vermagic.h b/include/linux/vermagic.h
> > index 939ceabcaf06..335c360d4f9b 100644
> > --- a/include/linux/vermagic.h
> > +++ b/include/linux/vermagic.h
> > @@ -33,7 +33,6 @@
> >  #define MODULE_VERMAGIC_MODVERSIONS ""
> >  #endif
> >  #ifdef RANDSTRUCT
> > -#include <generated/randstruct_hash.h>
> >  #define MODULE_RANDSTRUCT "RANDSTRUCT_" RANDSTRUCT_HASHED_SEED
> >  #else
> >  #define MODULE_RANDSTRUCT
> > diff --git a/scripts/Makefile.randstruct b/scripts/Makefile.randstruct
> > index 24e283e89893..ab87219c6149 100644
> > --- a/scripts/Makefile.randstruct
> > +++ b/scripts/Makefile.randstruct
> > @@ -12,6 +12,7 @@ randstruct-cflags-y	\
> >  	+=3D -frandomize-layout-seed-file=3D$(objtree)/scripts/basic/randstru=
ct.seed
> >  endif
> > =20
> > -export RANDSTRUCT_CFLAGS :=3D $(randstruct-cflags-y)
> > +export RANDSTRUCT_CFLAGS :=3D $(randstruct-cflags-y) \
> > +			    -include $(objtree)/scripts/basic/randstruct_hash.h
>=20
> As the kernel test robot points out (on a report that you weren't
> included on for some reason...), this breaks the build in several
> places on next-20250502.
>=20
> https://lore.kernel.org/202505021409.yC9C70lH-lkp@intel.com/
>=20
>   $ make -skj"$(nproc)" ARCH=3Darm LLVM=3D1 clean allmodconfig arch/arm/v=
dso/vgettimeofday.o
>   clang: error: cannot specify -o when generating multiple output files
>=20
> There are places in the kernel that filter out RANDSTRUCT_CFLAGS and
> this appears to cause other '-include' flags to be filtered out as well,
> such as the one in the efistub that includes hidden.h.

Thanks! Yeah, I have been poking at it for most of today. =F0=9F=98=AD

I think I have a viable solution, that I actually end up liking a bit
better, which I just sent out:
https://lore.kernel.org/lkml/20250502224512.it.706-kees@kernel.org/

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02505021555.A74E678976%40keescook.
