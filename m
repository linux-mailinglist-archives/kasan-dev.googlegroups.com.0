Return-Path: <kasan-dev+bncBDAZZCVNSYPBBIMEULCAMGQEWMEPWFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 7622FB149C6
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 10:11:15 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4ab60125e3dsf123451151cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 01:11:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753776674; cv=pass;
        d=google.com; s=arc-20240605;
        b=iRGHnppPq8L742DvibpkXMuiw1PpIZzaUxch1/OXCgK4gWCGcuOkxJdnRjKXr/9nBa
         BRy+zMGT31aGmGREz8J6bMrfiFYCGU2pvz59AXfygVvOBDYKJV2gVjjI0/wsAaEcLLo2
         jxPrgetkLvalCKcf9fOcq9N1EhV902MwqyYBo6+ve1dk8jEflLihE1TdhzA/ftjPYQeD
         UsO3WTpW1qKMVpg6oS6KAYDI1eTDulP3Q1gigXopmU40gtIZVE5yltRaP/XKHYUZCcec
         iOi3lX6od41QurMhrJjU9j85LRb+G/PNnrxnNcthwUIlsMdqf4lAnaBBBne/h4jHYMMF
         xLgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Zkje2H4K8WKc2P00AFboRKTZRfuDqixofIkGzAF3i0U=;
        fh=7GvEWw/QIdYyrvPNP4gSa9grxt6jQJVTc8XMiIzJUBY=;
        b=U/n6EM93D/PZJ5JZHPFvrJSSq9zS13cmzG58Di39kwZ2OBE+wJK1cG13NGbWt81T6p
         tMo5KftxywZNmt8wSBM7dnUe9sSFDqMaSJUZw02OdhdOGhFx1NTQ52xqXPIAy8WiLqh5
         YmbIEOL+C1cPiVc3VTnnie0ZFCXMswfiIS9RY3lM5NT2oN5ynf+S1rMh60duhPlNODIe
         8vkkp6AAhT2GXJgBmBF90gHF68d+DOksGmzFH6hZDI5X03o0Grk/veEC+maOnAc0XOm5
         9IB2Yn+uHTvKIoEFsGOPKfbpOGZWz1l7WzyCEpiCBPBQLPCuOY0eX+mv2T6GEAnHyDWC
         Cbrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=F+W04S5x;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753776674; x=1754381474; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Zkje2H4K8WKc2P00AFboRKTZRfuDqixofIkGzAF3i0U=;
        b=LyA8IuXfhksWzASDxYDov5q3nSToLoShvZSzoClWyOUnFofO+OHv2qtXf3r64/JRtz
         Ah934g748/4PAjTb4c9rXRzyFWUcrtVsDxcnY2Oa+ZXCj3yohWWtbtYDGLfTIOU96G5l
         ND9SkkQ0qxCH00MoC/R/4ZiFrDS0+D3syodAunObzfc5JXeaBmuIJPW9xvj9i4NkA0YS
         /EB23F7QG2rYgKi05ldlidy8jI1aMekirrjEm4h0R79YRcXxQ6i0jsztVzq5855HcA1h
         kD5aiWypjIyOgovGkU23S0UPP0D1XBdaUUOwgKxB1sh76L4aXF7qCy6CR/QC3ACnZpHD
         nVgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753776674; x=1754381474;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Zkje2H4K8WKc2P00AFboRKTZRfuDqixofIkGzAF3i0U=;
        b=SV3PL0ydQ+Bb8LDb7eOjrMLzbiX/2nsf39s6Bcmx8rHB6/P/v1bYVxkc/bmcJFrh8u
         7cE17ADuJoW87iVEqJzA+q8OC1jqF0OHDhNUx4Oi8BQ+uUb/dcAxi5oPx0ZKK+PK2Fxj
         e80pJpvPdf/80FfPviqLqpQZOWluH8jkXkYAVTur0pb5VZV/wBFzo6ECSQACGzhzwzX4
         03KHVRE7p9PA6FA7RL4Q/c7/YKSgtmxvuavCxNJ5uJjt3zzRy35HiCIP+WwH2tydoNSW
         o9OnlC8fHXpMIGx3HyOh7pj7BDL+X4kHNdBhNjgI0O/RkJdO8+kEQMuALa1reJOapg8L
         f3Yw==
X-Forwarded-Encrypted: i=2; AJvYcCVdeCd5hO1kMLv2+pBaWxvQRtD2jQ7KUigmUG8XZL7Xch/7yaZOYJPivvDdieV249KoXRScDw==@lfdr.de
X-Gm-Message-State: AOJu0Yz9JrcJn36f+HcfUUerIXOLUwiz4in8vhtH11zMPBiblTqgelFA
	FPTnTI6F7JFekZGIclF8JJJSacVuvq3H63bTIst1/ytFGrSjZDqI2nPR
X-Google-Smtp-Source: AGHT+IHD4+MTH1Nl9BZhS4VkyXmDY8HKru3oBJUSRDfTYWIzoHW1VttFg4iC+ZIUTzzVPJMYKIh9+Q==
X-Received: by 2002:ac8:5941:0:b0:4a4:3449:2b82 with SMTP id d75a77b69052e-4ae8efafe32mr190700421cf.13.1753776673967;
        Tue, 29 Jul 2025 01:11:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdp4VY/EO81t9+zSC+6jYY4CcO4iMRpM+LO/Yrolw1Fng==
Received: by 2002:ac8:5714:0:b0:4a7:f568:5323 with SMTP id d75a77b69052e-4ae7bb9122dls80968041cf.0.-pod-prod-07-us;
 Tue, 29 Jul 2025 01:11:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5BBOYjJMxqvv2uRHxvclU7Z/4VUlVKCnL2rpw1Q9vW20u7nNBV6Bj1htMfd+rGXWnj2zUCEnKn0U=@googlegroups.com
X-Received: by 2002:a05:6102:f93:b0:4f7:ecc0:4f92 with SMTP id ada2fe7eead31-4fa3fda3932mr6103985137.21.1753776672875;
        Tue, 29 Jul 2025 01:11:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753776672; cv=none;
        d=google.com; s=arc-20240605;
        b=SSRy8MfUPLW9HpLTuRbDHMX2XagOQoEPFgoE+++4UYredmnJnG5wQMwYVflRav2bVv
         aDLtC0xidD4fcWRScZdpS8jadGmaU6L4Dgw68FGiA6vd4RJ/h7fYmEKkG8pCdNOQhJqr
         tJbqDHsmSTtBGBvY+2EQCKwB9bBTiQCZYhUr/m0H/3r3R+YBTEWfPuDnqxL8BUtYbVbC
         wtWWArKI8o1msXj+uiL9PlsVEs55XnzlyV49L4MskaCkGj4DgqiCZblaGED7NQHv4XcI
         WniN45Hm9CiSqlfaGRko7XjADZgpbzuLmZs29aDPT5L+2se+o69pvUg+rtFxxAjbrb/i
         6CLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=O9JlasXi5thdYj6KfusHycPKdfl+LKE1gmMwQIgNpXY=;
        fh=EpJwtFaF5IbzTuS/AFOr6OahQ4ETNBjAvTBxLbYVf+Y=;
        b=Cu+Kd5dvihPT47NkMMpSqF+Qcs3JUJNGHKX40knz7770egTY21TivgiM7gHwIcRPFS
         31/8LfZHcw1S0sn6xfaNJFBvQolAQJ0+aYKUrxQFel05RpFG9sxG6OJepSaz8mFtNmXM
         2VF4F26N5ZUngZTVvoc6l1fiYVMMHDjVq+UETmHx2hEvGbbjRK7UV0U1JNq0X+QjkLJy
         JbtiYWkfPmM1bBJoW3cJGDldsaIj2J0EazbEckLZXGpqhXSfdXYqHMUEBlviE3j+o4nB
         MMSn248JlXaGxDdUtojuceD9Q1XOrMI60g03ZACzNAjRfijdYrz97gdi/4GMQ4x5F3ZP
         YX+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=F+W04S5x;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4fa46bb4a46si479386137.0.2025.07.29.01.11.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jul 2025 01:11:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 26C8FA54A2F;
	Tue, 29 Jul 2025 08:11:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 46400C4CEEF;
	Tue, 29 Jul 2025 08:10:59 +0000 (UTC)
Date: Tue, 29 Jul 2025 09:10:55 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Ard Biesheuvel <ardb@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Mike Rapoport <rppt@kernel.org>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hansg@kernel.org>,
	Ilpo =?iso-8859-1?Q?J=E4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kas@kernel.org>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>, Brian Gerst <brgerst@gmail.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Andy Lutomirski <luto@kernel.org>, Baoquan He <bhe@redhat.com>,
	Alexander Graf <graf@amazon.com>,
	Changyuan Lyu <changyuanl@google.com>,
	Paul Moore <paul@paul-moore.com>, James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Jan Beulich <jbeulich@suse.com>, Boqun Feng <boqun.feng@gmail.com>,
	Viresh Kumar <viresh.kumar@linaro.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Bibo Mao <maobibo@loongson.cn>, linux-kernel@vger.kernel.org,
	x86@kernel.org, kvm@vger.kernel.org,
	ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
	kexec@lists.infradead.org, linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v4 1/4] arm64: Handle KCOV __init vs inline mismatches
Message-ID: <aIiCD5V1MaI3ORqA@willie-the-truck>
References: <20250724054419.it.405-kees@kernel.org>
 <20250724055029.3623499-1-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250724055029.3623499-1-kees@kernel.org>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=F+W04S5x;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Wed, Jul 23, 2025 at 10:50:25PM -0700, Kees Cook wrote:
> GCC appears to have kind of fragile inlining heuristics, in the
> sense that it can change whether or not it inlines something based on
> optimizations. It looks like the kcov instrumentation being added (or in
> this case, removed) from a function changes the optimization results,
> and some functions marked "inline" are _not_ inlined. In that case,
> we end up with __init code calling a function not marked __init, and we
> get the build warnings I'm trying to eliminate in the coming patch that
> adds __no_sanitize_coverage to __init functions:
> 
> WARNING: modpost: vmlinux: section mismatch in reference: acpi_get_enable_method+0x1c (section: .text.unlikely) -> acpi_psci_present (section: .init.text)
> 
> This problem is somewhat fragile (though using either __always_inline
> or __init will deterministically solve it), but we've tripped over
> this before with GCC and the solution has usually been to just use
> __always_inline and move on.
> 
> For arm64 this requires forcing one ACPI function to be inlined with
> __always_inline.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Will Deacon <will@kernel.org>
> Cc: Ard Biesheuvel <ardb@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Jonathan Cameron <Jonathan.Cameron@huawei.com>
> Cc: Gavin Shan <gshan@redhat.com>
> Cc: "Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>
> Cc: James Morse <james.morse@arm.com>
> Cc: Oza Pawandeep <quic_poza@quicinc.com>
> Cc: Anshuman Khandual <anshuman.khandual@arm.com>
> Cc: <linux-arm-kernel@lists.infradead.org>
> ---
>  arch/arm64/include/asm/acpi.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/arm64/include/asm/acpi.h b/arch/arm64/include/asm/acpi.h
> index a407f9cd549e..c07a58b96329 100644
> --- a/arch/arm64/include/asm/acpi.h
> +++ b/arch/arm64/include/asm/acpi.h
> @@ -150,7 +150,7 @@ acpi_set_mailbox_entry(int cpu, struct acpi_madt_generic_interrupt *processor)
>  {}
>  #endif
>  
> -static inline const char *acpi_get_enable_method(int cpu)
> +static __always_inline const char *acpi_get_enable_method(int cpu)
>  {
>  	if (acpi_psci_present())
>  		return "psci";

Thanks for improving the commit message:

Acked-by: Will Deacon <will@kernel.org>

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aIiCD5V1MaI3ORqA%40willie-the-truck.
