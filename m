Return-Path: <kasan-dev+bncBAABBXVCZ3AQMGQEJI6BZ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 89D98AC371A
	for <lists+kasan-dev@lfdr.de>; Sun, 25 May 2025 23:53:36 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6f0e2d30ab4sf29731116d6.1
        for <lists+kasan-dev@lfdr.de>; Sun, 25 May 2025 14:53:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748210015; cv=pass;
        d=google.com; s=arc-20240605;
        b=KfMvy53wiArzL2aR2dSxDNFO4KK3IWkyQ0EgJRRMrx51ZZP5+oHEr3MYzgLZgspcOc
         D1cX/JIq7KTSWfkSG8TM64Z0YUGeIhxyZ5c9Yk43VCn7ilga9cAWUd+k6bkTcGe2Uo7K
         MZPVCZ2eLY9elP5jZUWb4Wdjk6xdKADynr3KrQie8W+DBKUebAQJnxgyg9a8VLu2vnDe
         N5vJU0zDv/gS8kDeqjz9QnFgk9oO1A0HCwv5dfhn5cZbuawrdrCLV0snJLVfbLfNzpf0
         kF6A3fDi65kNg74OxQZqeVNM4VbVfmZ4LDhfQuIizas0DNAYjbsyqPKnjmrNz8pmGn3R
         c2Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-id:mime-version:references
         :message-id:in-reply-to:subject:cc:to:date:from:sender
         :dkim-signature;
        bh=2yLiUDxJdGWmDmoqxLwEk3A4hd4dltqWLfCBkORWCGc=;
        fh=oOY4uoJZcHL//PYym2grWkM9JNLWd9+QjOz79EAOjZg=;
        b=d0osKmZbPx8u4lw0JRwX037KVpgVCAuleeiO+n/LadGHSM/U0ACEi4k7RxMLLFpfDg
         HxlM02xImF+N0/F1uMoIS+w2GEaNdnR+PZizfyg6W2fnE0p384rR5vskKH6ShPcWeAJM
         tAUXfh9h2lvX5PeXNfw24SDbC4pIkIUQYdFx8WF4zQ1QJeAdSYINP8whK/ewfprFMdIf
         PM+37fFXVqyZBwbTk270qNM58JstuNGhrUdM0kNfr+IJduwhoidEogQJYk03nYRV8aGz
         2MqWfkAzFRXI/T1hrRqmvvTJJtccwfc/4d5DMOcaeiLobYStULZs7pvPpzUdoNrC5dga
         l9SQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=n1thvU2n;
       spf=none (google.com: ilpo.jarvinen@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ilpo.jarvinen@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748210015; x=1748814815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-id:mime-version:references:message-id
         :in-reply-to:subject:cc:to:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2yLiUDxJdGWmDmoqxLwEk3A4hd4dltqWLfCBkORWCGc=;
        b=mmB9Jhv2vK2RCVwPnw37ir4U+xkyf9y/PEA+pOXwhD53Dh2hp2IAMOTmDsijWltok/
         NsJxbU209yW95WNKHOQvgdzt04jlqJvr3ScCcp/mi0Gtr5aXkBrLBMg8o/0t+4clJ6fn
         B740E057Yvte6nzRB3attjhBeFa+rVTIOv+hPY5nAgjCicbIkCzsDZoI+vBEbVYJiGdP
         YbD8WbpaBVT0GPxPn3yWx2+FrSPO0dkMl9cinYqL/iXN1hgqdXbjMYepKUU6yymOrmuo
         5VvErF+AQYXnZHZqNg2cY2Olb5XPW/GBIWCohLG3d9cQXuo4BN0YAvl5zeWtbI+xzkPx
         71Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748210015; x=1748814815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:content-id
         :mime-version:references:message-id:in-reply-to:subject:cc:to:date
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2yLiUDxJdGWmDmoqxLwEk3A4hd4dltqWLfCBkORWCGc=;
        b=hGC9DgZSqHzBTiW7Yc3gYXfoNp7B+4fny5v+XiLcRyEj5Wy6dJodt5BVGq/JR/kIaQ
         jWc7FLZdH9ybKC6t3rMfUEU/bnYCRCwzWAl1QgyaQJHOU7DMYzyTSwQhWWodxdUTaU65
         PfpPTYI6TKkPHU5jIp0zC/WHQIlgwYsNlKXo762WCTn1/KROqPWmAJoZUFacHsk5s0rk
         5ulAQDg8YLNCLYCQUlVXGGIVFfTjNCrwtaZ7eADYeAHaWEhRu35WhnVd4mphe87KBkmJ
         RntY8sOun1qUjg5VsGm95GTmSLC6n7itIXg8Lv2rVDBglvmBDPgBHh2rxOdABxrkQngg
         w2iA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhlh3M1txQK26DPNfrC3/IzJZQZUgn4TSHpBNB41nhwEtfbQZ5gNezbgSQ7DAObM9z9s5s7A==@lfdr.de
X-Gm-Message-State: AOJu0Yx7LRz0P5wv7qZOWDNtaWdfAU0cbYSbv1f0NIakr5lHN1ZOMXoo
	pzk5nLUiMWEfF+ZGfVka4lQHzXxnsNySzRdbtaAJX0cNr0ZZn/oXswl8
X-Google-Smtp-Source: AGHT+IFtNMnoTUAXytJUmgzFLSoeP4si3k8h+2wFPTQdgmz9InCRsRCREko5VRnmCL+EcTtTmFLKaQ==
X-Received: by 2002:ad4:5bad:0:b0:6f8:b7cd:984b with SMTP id 6a1803df08f44-6fa9d28167dmr131812236d6.37.1748210015136;
        Sun, 25 May 2025 14:53:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdEjPF7Sm9F7p7LUnO5vxRfh7drbMaqN9TXF5EpDjbwyA==
Received: by 2002:ad4:4e63:0:b0:6f8:d662:813f with SMTP id 6a1803df08f44-6fa9d0274e0ls27480506d6.2.-pod-prod-02-us;
 Sun, 25 May 2025 14:53:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPbjhMi9mxI+zn9Kc1Z21utCiqPXFTHWIuIBuETjuuIIAtU7Sq1nQqumxdkgW0U2q6qNRT5TWxHnA=@googlegroups.com
X-Received: by 2002:a05:6214:401b:b0:6e8:fcde:58d5 with SMTP id 6a1803df08f44-6fa9d29d21dmr122072866d6.42.1748210014530;
        Sun, 25 May 2025 14:53:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748210014; cv=none;
        d=google.com; s=arc-20240605;
        b=i1jr7WMWJKfDq0jz3DgzD7Ut6YkZXxKaBSd4RwejVJnsFqGSCvyMdake4DTKberMtc
         ChoassGEu/OVWDuWlANSKrLxX8F+y2BHBzU7r1/KMjeK/tht8o6nVqjJXzSMVDV/WRAT
         WPvXwAGnuE/Wy+2OaQxQ3eT9+f0Hdc7wmStbYFG2KmhZz6fSaOIa5C61/tZ0JeTZJUC7
         7pdysr5i23K/MBiAmr2Id4TTy2oVp6XfVp+0WGylIy/FRkPN6eStiLGX4/DLiyX3Doap
         pT/3uSbdxkLDkDnnkOWw7Xwj5lEINHyOC9n+Aa+ebASAMb4fCzZFXpAJt9+OClwlKLkP
         EBHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-id:mime-version:references:message-id:in-reply-to:subject
         :cc:to:date:from:dkim-signature;
        bh=av9VsxIknWUUfE4hYtNhEtgrxuLaquIfnPWePa13ql4=;
        fh=xW0yzeoN+w4fy5faxD6g4x7sOTmmWh+owFamprqmBPM=;
        b=VXGhANLQjiLnnXqzAedNHD53aR8uW1G87qmqp/WNo/9h6NHQoH492eOx0AtNbntHtO
         t3Zre94bo8mIfwHSUOT5FRbHYPDAC7g/fcetu68rxQe/4evFNpPzXoRI03sVbTteCJEi
         fiNdEXQjg6zjifEAmdmGLU/K/YRhzJ1XGYl9yeHQ50h6QsSCEfcjZZ49LUb0Rpj+uXHf
         nDt8OyUASWg5hUF5+tXxxQP5QDu2UsSiJzAu3xJAdso9jb/5RHmR1+iomY8ja5r2Wgcv
         G8O4mU7oFQ2XGk1n2VmruixGfnkj3xJpFGL9leg/aG1UacBNV7IM36QOC32Y2ZwVQeSg
         T4Hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=n1thvU2n;
       spf=none (google.com: ilpo.jarvinen@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ilpo.jarvinen@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6faa57d2c46si670216d6.4.2025.05.25.14.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 25 May 2025 14:53:34 -0700 (PDT)
Received-SPF: none (google.com: ilpo.jarvinen@linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: owCIdD7ATCaAFdGqegdZDw==
X-CSE-MsgGUID: JC/BAdVFToOGXAsIwcHfCQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11444"; a="60435786"
X-IronPort-AV: E=Sophos;i="6.15,314,1739865600"; 
   d="scan'208";a="60435786"
Received: from orviesa006.jf.intel.com ([10.64.159.146])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 May 2025 14:53:32 -0700
X-CSE-ConnectionGUID: srkUUk2LSiS9AVRoLfAP+A==
X-CSE-MsgGUID: abYToWTKQVe6L6ZrKUUaNQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,314,1739865600"; 
   d="scan'208";a="141991367"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO localhost) ([10.245.245.99])
  by orviesa006-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 May 2025 14:53:16 -0700
From: =?UTF-8?q?Ilpo=20J=C3=A4rvinen?= <ilpo.jarvinen@linux.intel.com>
Date: Mon, 26 May 2025 00:53:13 +0300 (EEST)
To: Kees Cook <kees@kernel.org>
cc: Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>, 
    Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
    Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
    "H. Peter Anvin" <hpa@zytor.com>, Paolo Bonzini <pbonzini@redhat.com>, 
    Vitaly Kuznetsov <vkuznets@redhat.com>, 
    Henrique de Moraes Holschuh <hmh@hmh.eng.br>, 
    Hans de Goede <hdegoede@redhat.com>, 
    "Rafael J. Wysocki" <rafael@kernel.org>, Len Brown <lenb@kernel.org>, 
    Masami Hiramatsu <mhiramat@kernel.org>, Ard Biesheuvel <ardb@kernel.org>, 
    Mike Rapoport <rppt@kernel.org>, 
    Michal Wilczynski <michal.wilczynski@intel.com>, 
    Juergen Gross <jgross@suse.com>, 
    Andy Shevchenko <andriy.shevchenko@linux.intel.com>, 
    "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, 
    Roger Pau Monne <roger.pau@citrix.com>, 
    David Woodhouse <dwmw@amazon.co.uk>, Usama Arif <usama.arif@bytedance.com>, 
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
    Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
    LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
    linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
    kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org, 
    linux-s390@vger.kernel.org, linux-hardening@vger.kernel.org, 
    linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org, 
    linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org, 
    llvm@lists.linux.dev
Subject: Re: [PATCH v2 04/14] x86: Handle KCOV __init vs inline mismatches
In-Reply-To: <20250523043935.2009972-4-kees@kernel.org>
Message-ID: <ba4f4fd0-1bcf-3d84-c08e-ba0dd040af16@linux.intel.com>
References: <20250523043251.it.550-kees@kernel.org> <20250523043935.2009972-4-kees@kernel.org>
MIME-Version: 1.0
Content-Type: multipart/mixed; BOUNDARY="8323328-965883235-1748206555=:933"
Content-ID: <8656ab6c-8f8d-81d1-5dfa-740e7f21544c@linux.intel.com>
X-Original-Sender: ilpo.jarvinen@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=n1thvU2n;       spf=none
 (google.com: ilpo.jarvinen@linux.intel.com does not designate permitted
 sender hosts) smtp.mailfrom=ilpo.jarvinen@linux.intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

  This message is in MIME format.  The first part should be readable text,
  while the remaining parts are likely unreadable without MIME-aware tools.

--8323328-965883235-1748206555=:933
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
Content-ID: <fa62886f-fdfb-f2a5-84db-475ce3a46169@linux.intel.com>

On Thu, 22 May 2025, Kees Cook wrote:

> When KCOV is enabled all functions get instrumented, unless the
> __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> x86 this means forcing several functions to be inline with
> __always_inline.
>=20
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Ingo Molnar <mingo@redhat.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: Dave Hansen <dave.hansen@linux.intel.com>
> Cc: <x86@kernel.org>
> Cc: "H. Peter Anvin" <hpa@zytor.com>
> Cc: Paolo Bonzini <pbonzini@redhat.com>
> Cc: Vitaly Kuznetsov <vkuznets@redhat.com>
> Cc: Henrique de Moraes Holschuh <hmh@hmh.eng.br>
> Cc: Hans de Goede <hdegoede@redhat.com>
> Cc: "Ilpo J=C3=A4rvinen" <ilpo.jarvinen@linux.intel.com>
> Cc: "Rafael J. Wysocki" <rafael@kernel.org>
> Cc: Len Brown <lenb@kernel.org>
> Cc: Masami Hiramatsu <mhiramat@kernel.org>
> Cc: Ard Biesheuvel <ardb@kernel.org>
> Cc: Mike Rapoport <rppt@kernel.org>
> Cc: Michal Wilczynski <michal.wilczynski@intel.com>
> Cc: Juergen Gross <jgross@suse.com>
> Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
> Cc: Roger Pau Monne <roger.pau@citrix.com>
> Cc: David Woodhouse <dwmw@amazon.co.uk>
> Cc: Usama Arif <usama.arif@bytedance.com>
> Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> Cc: Thomas Huth <thuth@redhat.com>
> Cc: Brian Gerst <brgerst@gmail.com>
> Cc: <kvm@vger.kernel.org>
> Cc: <ibm-acpi-devel@lists.sourceforge.net>
> Cc: <platform-driver-x86@vger.kernel.org>
> Cc: <linux-acpi@vger.kernel.org>
> Cc: <linux-trace-kernel@vger.kernel.org>
> Cc: <linux-efi@vger.kernel.org>
> Cc: <linux-mm@kvack.org>
> ---

> diff --git a/drivers/platform/x86/thinkpad_acpi.c b/drivers/platform/x86/=
thinkpad_acpi.c
> index e7350c9fa3aa..0518d5b1f4ec 100644
> --- a/drivers/platform/x86/thinkpad_acpi.c
> +++ b/drivers/platform/x86/thinkpad_acpi.c
> @@ -559,12 +559,12 @@ static unsigned long __init tpacpi_check_quirks(
>  	return 0;
>  }
> =20
> -static inline bool __pure __init tpacpi_is_lenovo(void)
> +static __always_inline bool __pure tpacpi_is_lenovo(void)
>  {
>  	return thinkpad_id.vendor =3D=3D PCI_VENDOR_ID_LENOVO;
>  }
> =20
> -static inline bool __pure __init tpacpi_is_ibm(void)
> +static __always_inline bool __pure tpacpi_is_ibm(void)
>  {
>  	return thinkpad_id.vendor =3D=3D PCI_VENDOR_ID_IBM;
>  }

Hi Kees,

What's your plan on upstreaming route/timeline for this? I'd prefer to=20
retain full control over this file as we were planning on some=20
reorganization of files into lenovo/ subdir.


--=20
 i.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
a4f4fd0-1bcf-3d84-c08e-ba0dd040af16%40linux.intel.com.

--8323328-965883235-1748206555=:933--
