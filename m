Return-Path: <kasan-dev+bncBDCPL7WX3MKBBSHKSHCAMGQEI5KPEPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 662D4B1292D
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 08:27:22 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-7048088a6fdsf47041066d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 23:27:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753511241; cv=pass;
        d=google.com; s=arc-20240605;
        b=JBRGLeQEqH05oMFKflY5c27wO9JmmgwqO7C81kAd8F1I98RXD3zfo+EhxinYcoV0ee
         FnTFrTgUx/bgWgtQ226TvfhOY0XmDgGi7PXTQZ5HnTbUAIYVGPf2bs3z0Dbq0XMpmkkG
         Flh7LP9gZbtw53jytZrbaKOsmikcST7VcnblYICrESTUjOqJ9/mbY4rPfjFcJfCu07UT
         08bqmlt9Iv00nWuaGHKKAIkloq8T2JGnOb5pN5uj5+UiKfIvWPaTZBMfHXVIQKMpdffo
         7wpblsbOdgLrBEwsSpBqQjVM3KyxVlZTHfIAbBex9goUiIUqlA4IoEwkd7NIyvvzxN+e
         KSTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Z15Feb8GDxvjG1qyvKKhNEVYk7oUjbdg3lkjo4KKlJs=;
        fh=JX0MSm9VW60gHcSZUz8S8qK1AgwITi8cVOhtTaOS2Ss=;
        b=im/Eb5eY6G1BAyOYDO7/+7J1OKIUQCY5F7q0NoTglmDSSnxokSKBtzN5DUa7E+whk4
         ev7+wRC9yOLs1Jaauf/yqKv/doZDev0ZM19EkdkU3VgI5ogxukdDHlqb798CVqfEts2/
         vIBEK3JSh3oKybDl3WOMAd61A1GYmCUCO/HPZn6RO/sqvVHepgeCFtAetSaBjHe8Fti1
         oOh2XBdSOzY/U9BHAcxev5BFZdm1pYesvj0DNTxHdvXsof7+uxvAfiz9txz0WpfzjzOT
         otXiE22BEVPQxr6V+fQjKGLH1616bUnzc+RlUDNhx5pLdi86wun23vt8HGxhDcy4dG/K
         KlbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fq2xnjNp;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753511241; x=1754116041; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Z15Feb8GDxvjG1qyvKKhNEVYk7oUjbdg3lkjo4KKlJs=;
        b=FVChwtYAv3eOGg0nJvJdM2nvAtuuO5nA6qhrvEYliS4q78437s+wpbHuZTz0j1x5k4
         +IinsygEQHy5qALWKCNpbrcMPTxNXwV1dDEioUedMXEzHMIDDo3Gi10mjtlIoOnLcafO
         H4A4naJHDQOnGhLu0030c9D+vK/ZxelI23vYO1nxLeX8j4JNBIjKUWDQ3H5UjGeo9mxx
         ezC3ONCcPRiETq4uantnlxoKI9VY7g8BP3uOkHr9BXMzVBjE1QZmjHT28PnUquWwuiF8
         uwfb+Y//hKxEkqfh0ixNATgcs28oznOK4HDnOmeVjDq5Hk3P88eSl4g6uja6pUaNtI4/
         78rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753511241; x=1754116041;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z15Feb8GDxvjG1qyvKKhNEVYk7oUjbdg3lkjo4KKlJs=;
        b=s0bF7L/DH5atRFyd8NYvJtGYF9UaR5mAIN7pk1g3aikpOQOBBP8Y66jsa9uLaJ0XL3
         uUeJsEG1cwWcRxgi4fJY8EyVoNOXeZjEMJcKTOF76gUMKSNp/LVPw7x8dupfAfnW7TKR
         xpdkHLthrmA495ofbQ8dkCjUjc37xcfAc9955yKj8PdBiTU5QNuzRXSTCpy/EfcCEUl8
         DxHxqwsUVDiPvxmE6WhF3P5Zi6wPaE3OkHEcQ66YlzIMtXYfg5pmbfvwSstGOx7amfLN
         gs+jL2JkxrHjiVyipvJ9BeoMSjVQharjKVclr3hn8cIF+qk5ZdtJCY3c/3pYA4LP0UfM
         bb8g==
X-Forwarded-Encrypted: i=2; AJvYcCWp1PH5CXb6a4KpS9LsSXJntoHerWqw0ywJ7ZM3UyCLsJVpDe6Jy8Ae9V23Hn3QgCQoBv3m5A==@lfdr.de
X-Gm-Message-State: AOJu0YyeiMhBJzHygHQ2dIOlkGjP0DM1vvwcLJg0b2ho+UF9FtFhoZ1y
	tKb3uzD1lm+D2htV3/FqsZquEA6ZW+Eveb4lnCkL/7SbmuraDs0zSRCc
X-Google-Smtp-Source: AGHT+IHZCh9yb6WHMacjyFePLsqmkG8eW0roGqjnz6HO6tl01CzXrT7j2pN44E34ZVbnC05SDhLAgg==
X-Received: by 2002:a05:6214:808f:b0:707:2da8:eca7 with SMTP id 6a1803df08f44-7072da8f0f5mr15488496d6.3.1753511241065;
        Fri, 25 Jul 2025 23:27:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcDeNQ1EL2L+u7egPCYs4I4Q/Fxk45SxQ3+N2Jc8vj7Fg==
Received: by 2002:ac8:7c55:0:b0:4ab:722d:38b9 with SMTP id d75a77b69052e-4ae7bbafad6ls47856511cf.0.-pod-prod-09-us;
 Fri, 25 Jul 2025 23:27:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVWcFS5gj6w0BU+31cuGk1rb/+1WhvdFZXofCZ7tDQClMoT5WJlFepWL3FqV4ikdV9taQZRG2VaLE=@googlegroups.com
X-Received: by 2002:a05:620a:4627:b0:7e3:4415:8dfe with SMTP id af79cd13be357-7e63c1b31fcmr499130185a.59.1753511240162;
        Fri, 25 Jul 2025 23:27:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753511240; cv=none;
        d=google.com; s=arc-20240605;
        b=UM4Ym8uUc1aHgABLhVVPuVf5zYqI5hBa5rHTmaejfIqHPShaDoCkEUH1W6t9oUBvGq
         My0gQ80yyP3u0CDIkNkSexGZWpE7GkPnBXsKOUtyHqqb6QGDYSzVNy4c7zCFTElfvqap
         EULGisQV6OVGv7bFo+qXzpCswETbPCUyml6yEp5wK7/wIB0U3o1V7KfJXNw4dSjIXflz
         puQHbjKsXGZoUT57MldFihCtM9zR/80x2x/QkYcELsX3AgX3rA/ja3oczon53x0puRJ2
         p30l3OjILxC5HwzVAySwM7CJSv7QuLXqBhBaRZDiVYCyf1EjsVjFewOOWGVBNHulwz7R
         4YOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DWe1h6lAgsNkrVeizukL0vDDaalZ++F813ABZF5oc44=;
        fh=LHpruR+ABs0JYPCPK57s6mWY5xR/svvkH4rO/yAMWbQ=;
        b=RWQyrOu4KRn+hqTeGAUBE6611dvnqUUk54eX+ntorNvX6/XjZJPEr7/HGNgLfrqn64
         FJVUQD+qxiAsVhyhso/ZylXyfj5OSu8cIWcYrQzLHOw/EA5ni+g3zEwR/D87t8MQ5A6K
         hXnvtnBAMhFUPHxBLDFY+h8iDmyJ8S1taRJUnXwlq01YCrzOpv3/+1DH+tyLTEeaNOjQ
         /PcdgDp7BB374xKRCYU0To8+Kd9hLFh0FChTNYcmfboOUgtwUSpqAGxXtdQQlU5Phjgp
         Fd7yF01A4Cf3eW6C+9zfLag2z5V4fYdLF8Mh8MSlz/hWHf7ovJAJbOJOOPLSdiLNo47b
         JkeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fq2xnjNp;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e64329aec4si9395585a.1.2025.07.25.23.27.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Jul 2025 23:27:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7057E5C2989;
	Sat, 26 Jul 2025 06:27:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C91E9C4CEEF;
	Sat, 26 Jul 2025 06:27:18 +0000 (UTC)
Date: Fri, 25 Jul 2025 23:27:18 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Will Deacon <will@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
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
	linux-arm-kernel@lists.infradead.org, x86@kernel.org,
	kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
	kexec@lists.infradead.org, linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v4 0/4] stackleak: Support Clang stack depth tracking
Message-ID: <202507252322.8774CA6FCF@keescook>
References: <20250724054419.it.405-kees@kernel.org>
 <20250726004313.GA3650901@ax162>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250726004313.GA3650901@ax162>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fq2xnjNp;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Fri, Jul 25, 2025 at 05:43:13PM -0700, Nathan Chancellor wrote:
> A few build issues that I see when building next-20250725, which seem
> related to this series.

AH! Thank you for letting me know!

> 1. I see
> 
>   ld.lld: error: undefined symbol: __sanitizer_cov_stack_depth
>   >>> referenced by atags_to_fdt.c
>   >>>               arch/arm/boot/compressed/atags_to_fdt.o:(atags_to_fdt)
>   make[5]: *** [arch/arm/boot/compressed/Makefile:152: arch/arm/boot/compressed/vmlinux] Error 1
> 
> when building ARCH=arm allmodconfig on next-20250725. The following diff appears to cure that one.

Ah-ha perfect. Yes, that matches what I was expecting to fix it, I was
just about to start working on it, but you beat me to it. :) The same
was reported here:
https://lore.kernel.org/all/CA+G9fYtBk8qnpWvoaFwymCx5s5i-5KXtPGpmf=_+UKJddCOnLA@mail.gmail.com

> 2. I see
> 
>   kernel/kstack_erase.c:168:2: warning: function with attribute 'no_caller_saved_registers' should only call a function with attribute 'no_caller_saved_registers' or be compiled with '-mgeneral-regs-only' [-Wexcessive-regsave]
> [...]
> when building ARCH=i386 allmodconfig.

Oh, hm, I will figure that out.

> 3. I see
> 
>   In file included from kernel/fork.c:96:
>   include/linux/kstack_erase.h:29:37: error: passing 'const struct task_struct *' to parameter of type 'struct task_struct *' discards qualifiers [-Werror,-Wincompatible-pointer-types-discards-qualifiers]
>      29 |         return (unsigned long)end_of_stack(tsk) + sizeof(unsigned long);
>         |                                            ^~~
>   include/linux/sched/task_stack.h:56:63: note: passing argument to parameter 'p' here
>      56 | static inline unsigned long *end_of_stack(struct task_struct *p)
>         |                                                               ^
> 
> when building ARCH=loongarch allmodconfig, which does not support
> CONFIG_THREAD_INFO_IN_TASK it seems.

Oh, eek. Yeah, I'll need to make an explicit dependency I guess? ("How
did this ever work?")

Thanks again!

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507252322.8774CA6FCF%40keescook.
