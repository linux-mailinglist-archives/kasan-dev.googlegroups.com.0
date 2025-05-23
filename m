Return-Path: <kasan-dev+bncBDCPL7WX3MKBB4NUYPAQMGQETZDFWHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A11A5AC2AD5
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 22:28:35 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3dc811bfa10sf4885415ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 13:28:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748032114; cv=pass;
        d=google.com; s=arc-20240605;
        b=VHITsIlYbCts12b/5FcmmMU3suIEUqz6DLR2ovrQMZoc4srzHsBlVD/Hqgq7ik8Fbt
         GBoxbb8ynBi4MFG7OP2N4DjeoHv1OvlZQtEVAXjNYodoelFxaOvUTBQ7r4SFYLnKnnN0
         0r+ipDdgj6vTbo3SiMmaM4br+7lY+nq12yuZUKIsyQKQBO0rE89PLXQSmgYV2AYOIoJ1
         lKjb4CE5vlbzdUN8wDRZuY2zwGJn9du6rGNuXEMTDE0dM5ZBY3WPq6DY/KlmWWpUhyPM
         hfFuoNEsdNiHaHJIIWKpshB6piL5p3ePAKeVPR5LTVLalirY6NM6D838BCF9J21eDjda
         ahQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1lwEsO/uWLcgLOnbc21W1iCIXsO2IEFW1yLWty3GjNc=;
        fh=AuK9uO0ulszdUb8z5IvBityF9Diuxgw0+OHLdN1++/M=;
        b=cB8S8Y63MvljAiUIe5MTw0Cwc/ycHhvXYpj7CtMrSjfcGkTINID5MEjOk9QmdRTeIY
         egmyxaTEbZTA3DMsc8wRQqHjRTlQeaBnW3BQHYoS2mNUtKYcu1TY7pEcNwcwiAxorHYc
         M0ef2zwUQUyrGXbmIaad/R2ppY8cCw6qBbTL2A905t3duA3b1J+1xis7A/0ZBpSvkQGd
         faDYvHEgTh2AGflRsdlDnzl0ZyoJ4I+WA2vCB/xsVLsj9x1gWCRWpKjc+BO8mpfquAyn
         6L/JxvndOTHWzmZYDZ7H1mHvSep3vuJ1NcvR6SJNha4aMRRftACzHlKr3+mzOeA7xDY6
         lcMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cKCTWrMO;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748032114; x=1748636914; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=1lwEsO/uWLcgLOnbc21W1iCIXsO2IEFW1yLWty3GjNc=;
        b=prg9QbFnkHW4F31eGkzdCuvhO1kW1na/7zARm7Zb2jiZDlthOFLBbV+zD49+/08nnO
         zrN9l5veJeMMPRk4kA1hTtDTq8z3kg4l2rFChxkSE9+2PH+FrPLP9/p5zHaVIzzw5rmp
         /Xt2nStTZDmeeD6/vAWLWC3SzaQgJe0sJc69ovJmZzvu/VGQ3/rVdIvCtvKTtu4t29HS
         EC0iJsKI9fHHKlMzcfFN1qy+Qk2UaO9/UckhR4ZQ1udhyP0yd4sJ6BXd4Y2pk//qlUrp
         C8Q8r0+tc+cASICYPVaC8aH/Yg95CJi9YFr7WHsefEtREI+/Tx2sK8EOPhyJoBREvWKx
         3/Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748032114; x=1748636914;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1lwEsO/uWLcgLOnbc21W1iCIXsO2IEFW1yLWty3GjNc=;
        b=c9IZuA7yWjEas0vZM8KB+6QsiYWeIe0rGOmPKfgtY7BYhmdorCzbAPvKzUoOAAW44c
         Lcqc7h5ZplgZxYvMiq1+AhMKf8B9ePD/33AYH/z9KmVIEQgwPlkodAPn3jYhP+2pYelh
         en3HqbUdUozFnDjCxN8U80UIQgmKjAP5hbjappe4Vq4j1neSprYNBsUf7gVL1Fz4SRSc
         oPh1J497RncD1gBfhgYY1OnlqeWQaKk+jiR6Ism+JmnPHQOFK4rX07vIbdEUgXntTeIG
         2PavQ1WU0ghfHpmd65LeYAsl6F/5U1diCXuGoJNtAGAffD9Am3BUw5q+YXNnteO6fv+c
         CLvA==
X-Forwarded-Encrypted: i=2; AJvYcCV1IDsj1r+PRwQ8hvqxFuqSKei8cmPmeaekelYXcX3kg14i7+50furSvJtfYgokyoEfYltMGg==@lfdr.de
X-Gm-Message-State: AOJu0Yx/zP4v9kHPgxS7rwX4ZiIHqUK2Lg2iryf/j7RH5xhhOhMFQxX7
	wBDFO5rMpACzPt2l/2ZK/riacOZhW/MCcjWmFOOaqanQE2aLxJ++hA0A
X-Google-Smtp-Source: AGHT+IGilkeVDukORVdNGG9ezl6N2d4Eu6ZrAmEi26EYLF06U9k7vM4YM6QHn5Cj4erZhz0mbr5I5g==
X-Received: by 2002:a05:6e02:2185:b0:3db:6fb2:4b95 with SMTP id e9e14a558f8ab-3dc9b723cf4mr6159405ab.18.1748032114018;
        Fri, 23 May 2025 13:28:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG1b2L2++1+8OeeExgunBiD2jpMDhgZ5+lFGuOsDTyMww==
Received: by 2002:a92:6909:0:b0:3dc:82ff:ca6b with SMTP id e9e14a558f8ab-3dc9a9b3fedls1934665ab.0.-pod-prod-05-us;
 Fri, 23 May 2025 13:28:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURVhbzKrTznXmTY3oBFurM0vVdEJTM9YnMM+o9AUpen9CRwjo4PDPS0d8vhCPKl5DQhnMVXUT+sw8=@googlegroups.com
X-Received: by 2002:a05:6e02:164b:b0:3dc:7b3d:6a37 with SMTP id e9e14a558f8ab-3dc9b6a5643mr5374695ab.8.1748032112523;
        Fri, 23 May 2025 13:28:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748032112; cv=none;
        d=google.com; s=arc-20240605;
        b=Guan8C1tY+N3Oo6yRiIi8OOaco37G2GvoR6b8B4KsDXewFyh29ilNd0Wwl6GA5+axD
         LUtg7NfFFom8cwZnyebL6iHRHcPSVMK6RmwtvC5zQiZ211FxtswIG4TNzC5GZPfClc6p
         cwD/T2wYeJRjXSsuHcrcrdsTOCxl7M8V286DWROzqoE/wCfXxvfPhP+O3FlMIpQD5VWQ
         N8wfcoJDxHTznFkIlAMmYsTTdqiSaePSS6Km8GSi+fC1Uhz2f2mv+klGI3RdJpJWgToI
         u46OtuxMea059La4DvOWliKup/5GriSW9Xugba1PeC2yvDFAruYu+4s4CKq+ygu6xt9K
         gaZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6aeXDyZRCKQtQf+44JC7dc6tXRgMsqq93+WCOHWY+ak=;
        fh=UID7jbMVi//O9TWRqUdwIzzNzyce0b5D8nk2GODPBFw=;
        b=YNRFtEj8QKqKCBTODOPLTjFMKafHh6hUbE+7SXs8f+5Cr8K4mldZ2f+y21NESkXJ44
         bI3gwbgFHs8iFiRHCthwX6exIVV0gz9OKGRUomTLScaUoKMVriVxIXmx0JgrfdPjUyyI
         5e6XyQ0ykfBX/jGGTO2NVyo6D8MkHvkoFnQT3dc5qVbNIT/dU9Bw6geOYyPNTIeiFcWI
         AhCNB7b45gda064f3iNxC0rz1w2UO3nXVHqEA3Fx5BSiss8GhWUdJOXcPHPHoQ3dhSf3
         Z2ZzZxRJ4ST74DbCUwlicQM/IvbqrNDYXH8VCvub9Dq+ddoH+RbG581WtJud4QZaQ/Ky
         zLKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cKCTWrMO;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3dc8b0422dasi2137445ab.5.2025.05.23.13.28.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 May 2025 13:28:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A175F45078;
	Fri, 23 May 2025 20:28:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 74E60C4CEEF;
	Fri, 23 May 2025 20:28:31 +0000 (UTC)
Date: Fri, 23 May 2025 13:28:28 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sean Christopherson <seanjc@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hdegoede@redhat.com>,
	Ilpo =?iso-8859-1?Q?J=E4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>, Mike Rapoport <rppt@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>, Brian Gerst <brgerst@gmail.com>,
	kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org, "Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v2 04/14] x86: Handle KCOV __init vs inline mismatches
Message-ID: <202505231327.3FA45E4B@keescook>
References: <20250523043251.it.550-kees@kernel.org>
 <20250523043935.2009972-4-kees@kernel.org>
 <aDCHl0RBMgNzGu6j@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aDCHl0RBMgNzGu6j@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cKCTWrMO;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
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

On Fri, May 23, 2025 at 07:35:03AM -0700, Sean Christopherson wrote:
> On Thu, May 22, 2025, Kees Cook wrote:
> > diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
> > index 921c1c783bc1..72f13d643fca 100644
> > --- a/arch/x86/kernel/kvm.c
> > +++ b/arch/x86/kernel/kvm.c
> > @@ -420,7 +420,7 @@ static u64 kvm_steal_clock(int cpu)
> >  	return steal;
> >  }
> >  
> > -static inline void __set_percpu_decrypted(void *ptr, unsigned long size)
> > +static __always_inline void __set_percpu_decrypted(void *ptr, unsigned long size)
> 
> I'd rather drop the "inline" and explicitly mark this "__init".  There's value
> in documenting and enforcing that memory is marked decrypted/shared only during
> boot.

Sure! I will swap this around. Thanks!

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505231327.3FA45E4B%40keescook.
