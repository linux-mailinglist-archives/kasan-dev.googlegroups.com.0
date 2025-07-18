Return-Path: <kasan-dev+bncBDZMFEH3WYFBBJ4P5DBQMGQEFVTU2UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FBF0B09E1F
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 10:36:57 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6fb2910dd04sf30188226d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:36:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752827816; cv=pass;
        d=google.com; s=arc-20240605;
        b=QAb08qNf/FPKgPEO8TNBLa5uwGa46fcnat92FblMrO+dXjp3YaOoKU2c8OmqVvwYM4
         6wK8yYPRAbO4Z/TLWZhuEfqocED/JZH1SXvm0DI3tOai4gv4ONAToInGNuhk5gvce321
         2rlXFGP1q9adlZjFjIVR8QcBZortdgrZcAxLIGqtPlrasK24CPm4GJisKj+jREAwLyhz
         zsRxoMkNohOSU/1Ff+933nlJKYa+l78gS13IWJHIkvVi71yCGQknNgTG0xSGTeqCZDra
         EDn37RpQPcej2fmublj82l5xXWNW68rnk6u8TL+yjKztO8g5s2dcMLz06ShZmJ7WMR9/
         omXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=nwfhffQKeZORWc89cFhgGe0KyWF+apj3BlogoazfUsw=;
        fh=W1fy3aIktvgsTve4b9zKgEloyYv5mOkOt2d6Fku2t6M=;
        b=OvttCOtkKk/wgHO9D+wHy/QJDObBn4Hd7Q5d4pFFiJej01IAch3rhH7VvEJavWsOvt
         ZR4BDxmD6AuO8Q604qmoafWhqJj/so9a8t0hgS8fIjTJPVnRZNWYVz2eh3G6+1NHbnvy
         rQbblaZ2zmQ6F6Ij5wEQqBqq/zaeJFMvcP60dKrgW1L0qgRXbhOefWTQQ2YVQkLWPqYo
         xTM3qoVo71K5GkXGOMcvz8DIkv86Q6iMgFPF5qP6PY1ZGYrqMJnElZyH+0XhpbB/ktZB
         6y5kPpYE3NjynyJr71xOhLlLmAD7AI+D8YDl6QkdkDUB/yvLXTE6BUXbafjRi/nR5HuE
         MgHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GmH8kuFD;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752827816; x=1753432616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=nwfhffQKeZORWc89cFhgGe0KyWF+apj3BlogoazfUsw=;
        b=ouRiX0xhR6vie4mzgI6U1wmeLFXpsAe8bclMpTcoNGeyE/h+/tgzVkfnJydSsY1VBE
         mFSIV6GDLg9eNtQYNLKJDRvbalXJyh6/xxXSRl9veLD3C4UqIFYxv4OjJ54iFXMjt9Ip
         JKSg/V0HNUkeA8sPX8I9gBkw5+PnRHnzBv8b+Sk+Ov9jWyVCpP5vlilrrH3w9dvnMJYs
         9NFabT6+qcjA+Xla4+2ey2uHbJUdJYmYdbrK/CecT8yUN0DWxmWCsRF1ykToRxVXJ0Mu
         pqqOqDftuRzU3ivxcndNxeWReuEgwzfhwz6kUauO48P2Yi5I5mwruk7AuzdZ0+gmOakj
         S5gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752827816; x=1753432616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nwfhffQKeZORWc89cFhgGe0KyWF+apj3BlogoazfUsw=;
        b=Tfoc5IvtsQ/cD5u/9goQbym5IEpXWff2+OchlYbTQn78Y4ZOAGhLUmELr7fMIEJ7Jt
         jG4bjFx3h/O4FcQ6F6Rq7y6iW6ykqboAF0ayFbdo8BLLstJI8gdd2wvCB2Hp/b9HwklK
         5DgQYOEeecEh8MWzUNGxoi+T4p7SCdIw5cTl563XH/4VdxDqqVNT4kzki3OozdK21vOB
         S5H6kpTOQsoQOTz3wU8F0O73x9QqjvIDsbTErIu3ZylwhcltfO9iP4bS6ltFw3nqB8qX
         vBuTGff9msjHmYb2ruoKq3IkpdGKYCP4/o346/0x5xiQgJARvwJ8dzVxNG+N7CBcbFNW
         Izfw==
X-Forwarded-Encrypted: i=2; AJvYcCXtqYqmpiXu1zdViG1ZL1tXPlbC+tT+ny85sQWSRjurt7S4ZkZkbVZhSlVsnLVIXGl5tOsBXQ==@lfdr.de
X-Gm-Message-State: AOJu0YyE1rXhHut5fuoSFIwNkSLP0MJkEqCbF/88LX2COtpo+UDyXpr/
	M3AjDAgQJl15E67MZR+WX4ujLZOBV2i+4x5f6I13e/qxSJsiA7JWjVh4
X-Google-Smtp-Source: AGHT+IHZHy2dpS/ogqIR2u2SjK78C8On++sAG0otz0UpPWbANNypJs6Y3A9mqee2ps4LRNHU70WDkA==
X-Received: by 2002:a05:6214:3f93:b0:705:1649:1555 with SMTP id 6a1803df08f44-7051649163cmr49093936d6.28.1752827816056;
        Fri, 18 Jul 2025 01:36:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdAlRWCS0x0rZv9xZsUNeJV5+Hn9o80S8cg9tLM5QSLuQ==
Received: by 2002:a05:6214:2246:b0:6fa:bc23:a7c2 with SMTP id
 6a1803df08f44-70504c49350ls30414526d6.2.-pod-prod-02-us; Fri, 18 Jul 2025
 01:36:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4B4lfANASIcbxuFixnEUSYx37obKt1umMhq6z+ywOdDHLAfT0T5k5Fu/wID+65lyZrLABI5janYk=@googlegroups.com
X-Received: by 2002:a05:6122:1d93:b0:537:3e57:6bdc with SMTP id 71dfb90a1353d-5373e5784bamr5819549e0c.12.1752827815048;
        Fri, 18 Jul 2025 01:36:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752827815; cv=none;
        d=google.com; s=arc-20240605;
        b=DrkDnPv60gDuLtTIHakbBW2LP50uRGgO2t66bp5+4O03J08c44k3PYccf2huFrqNCH
         jeMvML7InDdR0doH/3bP0jm9fJyjgvgtzsHheG7PYQ264nyeYDmFVHo9PcZxeKl8RgMU
         vOVxhjVmKb2Jc8mnyEwgWAjolUL1vM488ND9DxX/QZczeZTfVSnHADl0ibH/Gus8QtzN
         aH953rQgmAf34QtugafJ9jJwuXtJ9TDCK6VY3dVla4/iLKF0wrtHYcpvh4RCFMG+cNHR
         1CYL//EbF/JDLP1B7D00AXRt4DCLx6xp+ixwP4y/f06OFbiqiI4Cg0SUZIV+zDFrRjfP
         rMiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=inHdJPS1iKdIaaojY28b0ZRuhQUhLrBV2HxD58xasXg=;
        fh=T+uXUWKWQF54Sq6wjI2e7Ujd+FABGJLVubK6IVreDcA=;
        b=R3HFQmIp5kAMbiNhhQV7mMsGBCVDk/W/HjWyj2DVe54RnFV2ZS86G5wNMyKovuQ+Gy
         xo0dLA8qcGkZ3tSHlQUHra2rSBQbKcCTxpGXbziz+dnA8SnuOfabA3zY0/ScguBmTOhk
         52hV7taupCzTXYTPgAucU7+Rpnpz2f4ddMwCg7L8oVcPrn0cyaSagE0qApSXsgPebUfw
         dJwnqgvwzvBNAXt2jxGdh9Lwsj2wgO2OORmfK/+M+DDjSjBa+q58ztaQharQs0mJEdGa
         HkmPKyIFEFHVIMvD2wyfdlhNw3kTXKHKuILKYe8kN6Z01jahvpGsZQGUCO89Me/kdpjc
         GjIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GmH8kuFD;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-537650eb601si67691e0c.5.2025.07.18.01.36.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Jul 2025 01:36:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 373645C5996;
	Fri, 18 Jul 2025 08:36:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4E585C4CEEB;
	Fri, 18 Jul 2025 08:36:36 +0000 (UTC)
Date: Fri, 18 Jul 2025 11:36:32 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
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
	Ard Biesheuvel <ardb@kernel.org>,
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
	linux-mm@kvack.org, Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
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
Subject: Re: [PATCH v3 04/13] x86: Handle KCOV __init vs inline mismatches
Message-ID: <aHoHkDvvp4AHIzU1@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-4-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250717232519.2984886-4-kees@kernel.org>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GmH8kuFD;       spf=pass
 (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

Hi Kees,

On Thu, Jul 17, 2025 at 04:25:09PM -0700, Kees Cook wrote:
> When KCOV is enabled all functions get instrumented, unless the
> __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> x86 this means forcing several functions to be inline with
> __always_inline.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>

...

> diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> index bb19a2534224..b96746376e17 100644
> --- a/include/linux/memblock.h
> +++ b/include/linux/memblock.h
> @@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size,
>  					  NUMA_NO_NODE);
>  }
>  
> -static inline void *memblock_alloc_from(phys_addr_t size,
> +static __always_inline void *memblock_alloc_from(phys_addr_t size,
>  						phys_addr_t align,
>  						phys_addr_t min_addr)

I'm curious why from all memblock_alloc* wrappers this is the only one that
needs to be __always_inline?

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aHoHkDvvp4AHIzU1%40kernel.org.
