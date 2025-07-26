Return-Path: <kasan-dev+bncBDCPL7WX3MKBBEM2SXCAMGQELPCV7OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id D8048B12CB8
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 23:48:03 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3e3c5c03a75sf16359455ab.3
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 14:48:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753566482; cv=pass;
        d=google.com; s=arc-20240605;
        b=IUmLk7FEuJQXPNSmrcvo2yR4ENW5pSsjG/xTpR/jd2dC4BMzwFz1WyOo7yy8s9URuv
         NXPfFPKfv9w8qeDcLha7aRe7tlEwKeVgdn9N4C9gNGnJsSQY32f0T6QTI07I003qad5t
         gvHGkb61+Ml+dgzwhseNICh+fenfUwpIqoxcGFHCQjYSgzTU/0f0t6zSbudN8QAtZdV8
         TWBeJHZBY4LF76ZYP0y1IjkyYgril4yOjRYKq/TfwOp9iWPQrmP1hrUWaWdXFVj+907l
         cF+k6piTM+AMvWeVY/NkAEyHT8pKv9Z3VN23o6meM1X4ZxPlM/3bBVUC9lEVLZToLxyJ
         6Rbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=EBP7+vP2UqwWWHR0dPsEFMpGk8xdh0W8HSXKtFAceEQ=;
        fh=0FU+1W3jLAv02P8Eq2uJEVongSzgh+hoXeBgok7KQe0=;
        b=Eals46o9p7fFsfbll7SdDEY5dhxxEM+t1o98u9gnqZMx6JpiBhuE8z++0zAY6g0eLD
         SRNuU4BoWVWnkKPhPy9c3+IMWkU3u3hGLBzjLadmpPrPefO0gNtLvJpLZsd+FB2cLETl
         u2nmreQManVC6V/V0V/DNqrV0LmIXbonUQclz7rnLGmwuoXXiV12vjGUPwaeEg6EebDV
         bg9iFKhGUAvmn80cbEy3LNZ9VhgYHrp0veSEYM6ZrdNMGQb3ajZNEHhZeyI5XpMiAmYD
         XUb8kj82/NFh+tnGilu37FZbc+VKdFBwinMPRLbcPPBO/pYknemDN4RF3CqLJ5dI0UMR
         cmWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="fLV+aIK/";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753566482; x=1754171282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=EBP7+vP2UqwWWHR0dPsEFMpGk8xdh0W8HSXKtFAceEQ=;
        b=b19UEtKCDPEHHiuwjnuopJCZNOfOT5AK/duY7gTc2n7+80ZiAZo7yFGQN1vIhp+OT3
         G8DtUbZfK5naPIQdenvtdS6xAYcbia7wUEyr65u5Rx5NUQr9Hcg0V9eaNoj/7dNvjwXF
         Xxaxuzj1LXar6wJmJIned1+MJecdnYv/DbJIOeUSCSLX/VAefdwlYYsNKHoPQNwPhqVA
         1/E1iQ99Rh8osWvHH5cOSwXSwM7LcLTtsUDU91oshi+m+QP4a8DAY6YE3jlIktFKW0Ah
         aUEtMeOSA510ZCJW2g+wpR73qMQlX5TtgDicC3eETT4hDJSdmoyFQu0tkWxpAw9lcF46
         BBrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753566482; x=1754171282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EBP7+vP2UqwWWHR0dPsEFMpGk8xdh0W8HSXKtFAceEQ=;
        b=chJK9o/pf0S/NmZqssGmi/g9o4HUodZwzlCxaSg23tUNnTP2PLzAsc9XAzIwsYk+cf
         UZFgPvKLT191WHG3IYeJXUsiE1Te8t9/EPp3jdh0DzYOJSdpbdcIsp2I0y1wkvoeqdZC
         kHQw/K1/KsspODtBVq4B4cb+dF+xd4RRzwcRbntu/9MhAK324KoDjrEussYP9Lw+tSM0
         XaL9T7aMQLEjmuuKFkv40zfAwfEYhqpPyeRLBM/vYTpb3/mzBIYh7AXj8E4UWu3Pemf/
         CKhJIFMVJ4Mrj9v5OMBNN5X5B1r0FiIZIUAyoNhkuhZEavl5j+yQykEwFTNuv3oHJtu1
         Zssg==
X-Forwarded-Encrypted: i=2; AJvYcCVhdkP2kNRaaeYy4b/+4NNZUv0jzh3dMoJ4/he9b2m6/5e0ql+z5YG3SlbWl24u8bEvpZiASg==@lfdr.de
X-Gm-Message-State: AOJu0YyTITcQACbPTtm9BzfjGTBwMbsdU5bRTlWuO2A/E9oqmGWKqcqT
	AYFniVJylTuYDgimNpsibF8wBJO0HJVW7X+4lQDdY3Q9Dq5aLUzK1tzD
X-Google-Smtp-Source: AGHT+IHL/s/uWoLqyo3g85N+d4vVOd2qx74alSTGU99WOl0A15RZuJgUHDv7nG8tvJaCCC24qL6YNA==
X-Received: by 2002:a05:6e02:744:b0:3df:385d:50a8 with SMTP id e9e14a558f8ab-3e3c527c275mr106319425ab.6.1753566482385;
        Sat, 26 Jul 2025 14:48:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZezRqp/qxSTlzwGnz8V8c1Um+VMIaZpxNsilfJc7MMoJA==
Received: by 2002:a05:6e02:9a:b0:3dd:b672:7f90 with SMTP id
 e9e14a558f8ab-3e3b5190fc6ls23713835ab.1.-pod-prod-06-us; Sat, 26 Jul 2025
 14:48:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTLc9s2sS+WxVGd/9IyXL1/msG5Yr0i9c0k2kNPS7AZHSNlQz6XN/hFOEDtqKulI1xO2O/QAtqRYQ=@googlegroups.com
X-Received: by 2002:a05:6e02:198d:b0:3df:39e2:f1a8 with SMTP id e9e14a558f8ab-3e3c531c607mr98973015ab.16.1753566481152;
        Sat, 26 Jul 2025 14:48:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753566481; cv=none;
        d=google.com; s=arc-20240605;
        b=hJs59WcHTWKJuAd13LioOGgCobk7z0sjh7vLynuPEkO0Uklx9k2HnN7sJ3CO3NZIb6
         LxKZoxkUU5e5kn9bI7SuVQ5GkoWqlwBo3C439VcyIdrIx26wJ1T0LBDDZ9C0/X+rdm2o
         kHa8mMgKagUn2jRqwLslhtujkF8sp9d/No0g+ZNtR9e3kLdxPBGy3/wsd4/5t5KKzz1Y
         jK7ABMxGEvLvBzmjaLkoFmS263JFb9nhd7NLov88locOjJOZGxOvyOQXiEQvolq/CcW7
         rBk8TBnaDS/LUbYJS2Jhl9GW1z+fKbXZ6WwjdsE8avQvNTv7x0Tm3VlporF/Ec2PV9cV
         1IAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gpEW/IT9jhTobSNbCvdFZFzFslfquWaEscBQfdtNojw=;
        fh=LHpruR+ABs0JYPCPK57s6mWY5xR/svvkH4rO/yAMWbQ=;
        b=h5zzJHBUFijJXFH1gDLErCA1vNxSPcUwv7SrEEi8HhU6L+FfndQsuMgmVMQxSOW9lX
         aVlQWJpfSWnclSC+2cxoI6V7xO/ZdN0uIFTher2hi8h2mBBCjMKe2VkO0MFRoyaPL9pC
         jTmZmxO3S39fXAytXbi6WyLSzKeLwjoa7wXkru/7nLEg2L4v0LjUKqwd6CNVD9yt3Oiw
         +LJTnFCTE1sf/GCRNXsYDfP9a0csvjbQpwjZfxUmClaY4AhToCATEeBEPYeJ4ksR7+dY
         s65dQ1QqcyLyPPICbXqTKJ8HEVl23BE+RlSq1k3mB+5jhb1Gc2dCE+WWexb7qqXe3AYV
         URLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="fLV+aIK/";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-508c905e79esi146343173.0.2025.07.26.14.48.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Jul 2025 14:48:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id BE3AD45B23;
	Sat, 26 Jul 2025 21:47:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7D861C4CEED;
	Sat, 26 Jul 2025 21:47:59 +0000 (UTC)
Date: Sat, 26 Jul 2025 14:47:59 -0700
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
Message-ID: <202507261446.8BDE8B8@keescook>
References: <20250724054419.it.405-kees@kernel.org>
 <20250726004313.GA3650901@ax162>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250726004313.GA3650901@ax162>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="fLV+aIK/";       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
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
>   ld.lld: error: undefined symbol: __sanitizer_cov_stack_depth
>   >>> referenced by atags_to_fdt.c

Proposed fix:
https://lore.kernel.org/lkml/20250726212945.work.975-kees@kernel.org/

>   kernel/kstack_erase.c:168:2: warning: function with attribute 'no_caller_saved_registers' should only call a function with attribute 'no_caller_saved_registers' or be compiled with '-mgeneral-regs-only' [-Wexcessive-regsave]

Proposed fix:
https://lore.kernel.org/lkml/20250726212615.work.800-kees@kernel.org/

>   In file included from kernel/fork.c:96:
>   include/linux/kstack_erase.h:29:37: error: passing 'const struct task_struct *' to parameter of type 'struct task_struct *' discards qualifiers [-Werror,-Wincompatible-pointer-types-discards-qualifiers]
>      29 |         return (unsigned long)end_of_stack(tsk) + sizeof(unsigned long);
>         |                                            ^~~
>   include/linux/sched/task_stack.h:56:63: note: passing argument to parameter 'p' here
>      56 | static inline unsigned long *end_of_stack(struct task_struct *p)
>         |                                                               ^

Proposed fix:
https://lore.kernel.org/lkml/20250726210641.work.114-kees@kernel.org/

Thanks for the reports! :)

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507261446.8BDE8B8%40keescook.
