Return-Path: <kasan-dev+bncBDV37XP3XYDRBNH2XPWQKGQEOZIPINY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D1BA6E0455
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 14:59:32 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id u17sf1884338wmd.3
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 05:59:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571749172; cv=pass;
        d=google.com; s=arc-20160816;
        b=EG8RkVyHAYyURLkY/aUqHnnKWcnU294V0LcxuXFTr8x2E5Tj40N3cjMqzKth222Aam
         ccuk9SYl4mK04cLu6ECl0a9pfqOz2J1RG9iKdTXweHNC+3sAERL2cqxOXiplPY1iTnsv
         lR2nx+ya2ToTH3IZhQy8ZBFtZd/QkV1gITqXHVTXVPWknC5sODGpI3iVZZLv1dM5udOC
         AX52qzIhbzF7TUCH2wckI9nuRg8w97Nu1CdTWxtLs3HiCFBb9kdCGjU3YzOfHABGmVku
         tr1kTiwBapn8ChRouTPqPQW6eIV6t+ly6d8sCQZRjBc9DXFMBFI6R4oAZ3zBeQo6RwY4
         mjTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3lNL7u4nVcvOhkPjzXEOKhKc54LRN/dqDM1FGV7biWg=;
        b=FA6TBbFiqMT7PX2B2jGIrRBeoHMX+Jzp/J2MWyD2bP1Li/3pmpodFC4JzUgGHedqTK
         W+7GVQOr6NPfhkh3vqvki/VlzfeYgHgH2RJS9wAZaEHeO4OLG9oWnoSg17c5Mba9Td5j
         qnvmgLkTmfcZofgr6uBeRXCs3D9420NNtHcspWMF000Kb1/4qldgZEXcfOi5LZQJHRJO
         2Bu2jI5WoKWtpZamAuDKgMiYnc7s1FhzEQwcna4qad5Fnowae990uXPDuV0N7scdgmeo
         m0QWw4S6MiGaDUWqc8/iMXaXOuGlD3b3Qn4Oq+HoPe8w6Y/+JOdVwLS3r+xMNSIfsPuk
         FMQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3lNL7u4nVcvOhkPjzXEOKhKc54LRN/dqDM1FGV7biWg=;
        b=CohRmjSGlW/NVwG3rmOwL8cYE+mte1MlbDGsxznt1xUuc3XyO9RYQkYFI2fFvwlTQS
         Zha/yuy1MeFib33I+HQ9iVCf3akN6EWDNIPAj+38bzxXMomrjl8qokfFYYy4aNRfeTkV
         /Z1MaibUVH4IU78nurToxiAFw6oSE/RM2I5vkJjF69SATnBN/agVO1OA15wUFnsTKCws
         eW0ddsaBK2D+XZ1Ym/D6gptnMrRLxLbcdbmMFtntmVGS9E66yZApI8y+Nrt+9aYJJfXY
         9/uqV6drwEc+4p2eWKSu037a0pjbP6f62eqWs4p9DqGmH7LozgsiGkb+8pffwy57VrRy
         x5lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3lNL7u4nVcvOhkPjzXEOKhKc54LRN/dqDM1FGV7biWg=;
        b=JNu47ygQrovFUyFvKPTD6Dh0USTrsQf1CRXgz9VTAOpFMP85boOHpkIpf89T+FgUks
         VW8EBNRdcjoAa3+ARdbU1gyoXA7KrWw2seSXqMKP7IfEETOwdURS8/aopzbn7na8X+n3
         2P371CYPtOcGGfbQ9tX16GJqc7G+PkzOVgHXNTT8A4nEhheWTBStyt6DlriR0RPCkSFM
         0pZXCxnb0PfYFUsTYqJPbr7wT/85LUv8EAiql+Kelrjdv4euRZEa0XZb9b4wJ2s4d64p
         a/O8Af4Zkps2vsSthHhruGvK4UNpwzlEqbkluoP7uaVd2OFbX8ij0nqq/3LQIFmKc4+q
         YJPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXIRCvkLjvctlXaS9UKOrNT36YxlLDGZdEM/n/OU43Ld69CUz3Y
	NT9t/IZj6cPfkxuXDrwz/RU=
X-Google-Smtp-Source: APXvYqxPOjAzeOGR4qdiwtW4jSWlR9hcRIqDJY02uJT0j2iAAVSPvVoAxvH6SHyVcvqTf+4Wgx0GhQ==
X-Received: by 2002:adf:e446:: with SMTP id t6mr3367779wrm.7.1571749172494;
        Tue, 22 Oct 2019 05:59:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fa0f:: with SMTP id m15ls4163890wrr.13.gmail; Tue, 22
 Oct 2019 05:59:31 -0700 (PDT)
X-Received: by 2002:a5d:55c2:: with SMTP id i2mr3488889wrw.176.1571749171876;
        Tue, 22 Oct 2019 05:59:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571749171; cv=none;
        d=google.com; s=arc-20160816;
        b=JnHHbm2CUHztwi8ps0q+Gwd0fYxxiS6K1/t9fE1o9HwCaZbuQvGCI+Pox9VtRC0V+n
         iJOAbAYE4YDnTs8xfzIqduzKArITJET1Ho3+zhy+O+sNH16SlhvDB07b1hThevAkz2au
         6YWzX1UhyTEq/LloSz3kdxZn9jA6z2sqBDTvdjBotNOOrP1HM3mCDwghLt7dErQhmALo
         5AvInCEhpecLbsWPVExaYR+eljKwKESmXWnFINJJ4EAdadIXP1C1vU8nz4rbU7o3cA5+
         5wDs8wgf6whEEoMxeQthcajgrPJ/Arf7Mm3mtEWrLNTxqQ+vatfHoA3EI7ExT3iyq0Ja
         lA6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=P7P6nh2dxL/dy5O3OCgGIizE4lzpwf4XtocM+aVpJ8M=;
        b=sLWF2gNl2TzxruNNIvylBGZbnGETDwgkVz+ui4aZwsnOrf7QB+ExBz1n57ecOLBBBL
         RWMC0oJVzAzyamfs8IXdYNlqDMhhKqqp/37l3kTUSf97Aw5nvitv6KmHrHW95FSiz5nd
         AEo1Z2qUcqjWW4K31w9COzADSo6EtaKPZ7BwI0WEPE3KiyIdT7OO3QZCXNJQ7ELrxN9B
         48bDye4uMB293iYMcWf+smwrPgi/tC98uIc6i5mqgYsvWXZGa+DYnEP45/HrFO4cA6/+
         baF/4YKMAjIrV9jHIW72BL9IXqoptH2kfjyjsKYIy+nSSada6s/XiMt2/fAci1Um0W4C
         J0MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com ([217.140.110.172])
        by gmr-mx.google.com with ESMTP id q73si271037wme.1.2019.10.22.05.59.31
        for <kasan-dev@googlegroups.com>;
        Tue, 22 Oct 2019 05:59:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 19CE1168F;
	Tue, 22 Oct 2019 05:59:29 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D48AF3F71F;
	Tue, 22 Oct 2019 05:59:24 -0700 (PDT)
Date: Tue, 22 Oct 2019 13:59:22 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, npiggin@gmail.com,
	paulmck@linux.ibm.com, peterz@infradead.org, tglx@linutronix.de,
	will@kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 8/8] x86, kcsan: Enable KCSAN for x86
Message-ID: <20191022125921.GD11583@lakrids.cambridge.arm.com>
References: <20191017141305.146193-1-elver@google.com>
 <20191017141305.146193-9-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191017141305.146193-9-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Thu, Oct 17, 2019 at 04:13:05PM +0200, Marco Elver wrote:
> This patch enables KCSAN for x86, with updates to build rules to not use
> KCSAN for several incompatible compilation units.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Document build exceptions where no previous above comment explained
>   why we cannot instrument.
> ---
>  arch/x86/Kconfig                      | 1 +
>  arch/x86/boot/Makefile                | 2 ++
>  arch/x86/boot/compressed/Makefile     | 2 ++
>  arch/x86/entry/vdso/Makefile          | 3 +++
>  arch/x86/include/asm/bitops.h         | 6 +++++-
>  arch/x86/kernel/Makefile              | 7 +++++++
>  arch/x86/kernel/cpu/Makefile          | 3 +++
>  arch/x86/lib/Makefile                 | 4 ++++
>  arch/x86/mm/Makefile                  | 3 +++
>  arch/x86/purgatory/Makefile           | 2 ++
>  arch/x86/realmode/Makefile            | 3 +++
>  arch/x86/realmode/rm/Makefile         | 3 +++
>  drivers/firmware/efi/libstub/Makefile | 2 ++
>  13 files changed, 40 insertions(+), 1 deletion(-)

> diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
> index 0460c7581220..693d0a94b118 100644
> --- a/drivers/firmware/efi/libstub/Makefile
> +++ b/drivers/firmware/efi/libstub/Makefile
> @@ -31,7 +31,9 @@ KBUILD_CFLAGS			:= $(cflags-y) -DDISABLE_BRANCH_PROFILING \
>  				   -D__DISABLE_EXPORTS
>  
>  GCOV_PROFILE			:= n
> +# Sanitizer runtimes are unavailable and cannot be linked here.
>  KASAN_SANITIZE			:= n
> +KCSAN_SANITIZE			:= n
>  UBSAN_SANITIZE			:= n
>  OBJECT_FILES_NON_STANDARD	:= y

Not a big deal, but it might make sense to move the EFI stub exception
to patch 3 since it isn't x86 specific (and will also apply for arm64).

Otherwise this looks good to me.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191022125921.GD11583%40lakrids.cambridge.arm.com.
