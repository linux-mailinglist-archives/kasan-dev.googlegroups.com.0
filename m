Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3WLSHXAKGQE65O45NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 88C9DF376F
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2019 19:43:59 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id x191sf2715766ybg.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2019 10:43:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573152238; cv=pass;
        d=google.com; s=arc-20160816;
        b=C9PlGerXgTEqJO5ALrII/dvXgruODJnlT4SyZS7XNBnI4B5hbqIRrK316ih0MqNPd3
         SsHnVUl3hq2FukEXpKem5NbXCWtR3oWd3yEthw8ycbCdJambuMJbnc+elKq8hcLvSuY3
         4efotAommIT5VUWrXq1EqaGdRvsnbVnakGlo1YJkAFsmTmYE3buU7NzwvBj0sVKdmoHy
         1AD3H7rVa92psRm3kZ0ZJo8g9dVckja/OVXBv+y9noTFSmXyMmeTIhNpWLov3JuHmxvi
         JrcWS/EFkXtC8jysZO8jLMOs4r7qCsQz3z8K9NIB2+VI2N4Pz+nlECitzOincz7b3E7C
         ynnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5qwN5Qq5xrhI/CDk015dr6PsPuEgc3wPuWInibiLe9Y=;
        b=UCYjEVkE2LCtBs0y6jjAu4jUGXGogjPOuSdKxZo2Jn7q6Zs6ruMNK3zmnyiGZqwuwa
         MoxQngrT/GnlJWEGosoZE9KGbAXuXw31W5EsVh6MtkjoMUJjVbTvb2UbOjwO1LjyslxF
         aGsY8Ti3JrMjSlJsAsfGS3Uhaa1CziZ9/7k7hcsQWPxWWq1UI8CXn/DuflUpNsSJyANS
         hS6hpPtuGbnpZAAHnjMwbjMo+SMrRwcYkrqpX32lGND5meqygFuwvPVarsI6TcneZGW3
         qhBkGrQaJh3uD4DnfLNNxvTGWcEO6BbMbfcvxmuVc6Pe+g8PkbXfttXHSD+zfTZqeLrs
         BQow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X+s4tLRe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5qwN5Qq5xrhI/CDk015dr6PsPuEgc3wPuWInibiLe9Y=;
        b=o9Pmk95zZFgp6XQprO3tT4nzjYAkcmuzQ8xGme4x/DxzrSTz54Px0Epq3cNX0ehMih
         puk5bl6Rk+EHpiLGFEw20hks/GpQy8hzeTBLKr59i9urghepccWulu/3k/B9V47YAreC
         2WO+mwhvz40gn449wYt/V4F7ynhXjMt5LIbyppM6pDgrGAb9kOoeCsBMN+R6OwVGfaTa
         LaWr9BQMHnhExFaMHFHsAd+eIPquhXl3nZgaDYYfuWx8MRr1GXq5vaP2U+bzm9+9jWSI
         vqgoCxSGb21R6Vs1a52ZbGi/XrTiFHOPkIP7h2Ld3VZM86RKF4agzvETRiLKE0PAcsX+
         i1Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5qwN5Qq5xrhI/CDk015dr6PsPuEgc3wPuWInibiLe9Y=;
        b=HgjZzZ7Y3L4OeUpFXAtaHTnrcgf0LU0xciqTPjHj4aDyWn5aftS7+qwh3eKHqkbIjg
         6RwZM0KA2k/uh2AgEadQx6yYdwAx/HOCRypbn9kokEQZg35xFCaEp/XhBWndRB8keNio
         ENXPVqaKIRACWTjxNFr/AbZo3lQFdSEMu4NvsLgrP8pB0jp6xBNS16xJlO7XByPwpgM1
         kTM3VTtu0b9cPyJbl7qVrduHgvO/Ob2kSI1jD6TlQT9gAgfsCsemJ6NvkUDp8CKeyxuk
         F2B2EmRVf65DH6tW57B2OLoRV9MMIhxuQAjRyVy45WL8KqmgYmq8eHTd4ejxDSHNtko0
         rH3A==
X-Gm-Message-State: APjAAAVj65SZTKAaN3Hou/liq2NryhqeMxhD4F9D7kYoE3Bw+hkNZxOY
	bntvcViC69LZ5KkHZazzfZA=
X-Google-Smtp-Source: APXvYqy0vCssrHdOT6KOquTJjQ6vz1W5rYhG8xT+M8fnPIO0RdpxwQxb6pSwGU92QKAy+5HCdRiXgA==
X-Received: by 2002:a25:3410:: with SMTP id b16mr4985503yba.84.1573152238253;
        Thu, 07 Nov 2019 10:43:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:4816:: with SMTP id v22ls1045887ywa.0.gmail; Thu, 07 Nov
 2019 10:43:57 -0800 (PST)
X-Received: by 2002:a81:89c7:: with SMTP id z190mr3839645ywf.114.1573152237733;
        Thu, 07 Nov 2019 10:43:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573152237; cv=none;
        d=google.com; s=arc-20160816;
        b=VKqE3hZBlPwSazaXW5WPmISZwSG9IaPxcLjrddoVmRvbNeRbpidht6nFPzBVrfeWL7
         XS2/q07B0nHiMTyHvGrgEv4NqGbI6UHEGfKBiLdMvtUt8x1ofubS0a3wQhBjTlxTUKVa
         bU1omHrewsAed0P39m2FEbUH0wzLzPWVqm2xX/uuSfrF/ddbcJrsLKRv1pg2HjoD+80j
         uviDCEBVSy4QFu/K3ImiwF6WMFKl8TwnXMjgpfA+LgQWqvCxhdO39muiumgcx0PxXL6T
         XtwprDPRPVma1DB+1NxI5aoxpFVvq5Gt68eEC2KKdLfruofJJ4NNik9QYnGvuTQJ7w8b
         bP1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Np0FlikDqTmwL51OIp1+s+VGLrj6Eo2iSbS+rqBgcFU=;
        b=VtlxAnJ1mCpvhFdieTGJ2jU25efhiZMIp3TTUUpAMzGJgOsO+lQrB9YdcOWhryAFy6
         HCP8vDHHQr85b2CvR62sEyKiSROAzyMeakgsxMGx6ydcaZ5DlqzmYGkKqMhF9jQy0X39
         /fKE0z9BPGchG1+kxxqrtkJhYeUhMFfCDXZ7NOv2HYF+qw4jVMgU6c0iA7weNCe/Be6j
         x7uYzTy2Oi/X9q9Q/I8EtAdb9ozorsASpqActdlRUkO84yEw0fos1/m1L/x5j7SO55/F
         zxKtZxCkFdKtp4V3JRlkgj24ybt7flDWb/1CZsr0Xvoe3HLGfKCKQHnxXY5MebgGEEtA
         QbHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X+s4tLRe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id u8si265403ybc.2.2019.11.07.10.43.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2019 10:43:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id z6so2935410otb.2
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2019 10:43:57 -0800 (PST)
X-Received: by 2002:a05:6830:1e84:: with SMTP id n4mr4371298otr.233.1573152236918;
 Thu, 07 Nov 2019 10:43:56 -0800 (PST)
MIME-Version: 1.0
References: <20191104142745.14722-2-elver@google.com> <201911070445.vRUSVUAX%lkp@intel.com>
In-Reply-To: <201911070445.vRUSVUAX%lkp@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Nov 2019 19:43:45 +0100
Message-ID: <CANpmjNNWeM91Jmoh8aujpBA9YVfL6LSqH-taQO-6BJQwUZfCkw@mail.gmail.com>
Subject: Re: [PATCH v3 1/9] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: kbuild test robot <lkp@intel.com>
Cc: kbuild-all@lists.01.org, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=X+s4tLRe;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 6 Nov 2019 at 21:35, kbuild test robot <lkp@intel.com> wrote:
>
> Hi Marco,
>
> I love your patch! Perhaps something to improve:
>
> [auto build test WARNING on linus/master]
> [also build test WARNING on v5.4-rc6]
> [cannot apply to next-20191106]
> [if your patch is applied to the wrong git tree, please drop us a note to help
> improve the system. BTW, we also suggest to use '--base' option to specify the
> base tree in git format-patch, please see https://stackoverflow.com/a/37406982]
>
> url:    https://github.com/0day-ci/linux/commits/Marco-Elver/Add-Kernel-Concurrency-Sanitizer-KCSAN/20191105-002542
> base:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git a99d8080aaf358d5d23581244e5da23b35e340b9
> config: x86_64-randconfig-a004-201944 (attached as .config)
> compiler: gcc-4.9 (Debian 4.9.2-10+deb8u1) 4.9.2
> reproduce:
>         # save the attached .config to linux build tree
>         make ARCH=x86_64
>
> If you fix the issue, kindly add following tag
> Reported-by: kbuild test robot <lkp@intel.com>

Thanks! Will send v4 with a fix.

> All warnings (new ones prefixed by >>):
>
>    In file included from include/linux/compiler_types.h:59:0,
>                     from <command-line>:0:
> >> include/linux/compiler_attributes.h:35:29: warning: "__GCC4_has_attribute___no_sanitize_thread__" is not defined [-Wundef]
>     # define __has_attribute(x) __GCC4_has_attribute_##x
>                                 ^
> >> include/linux/compiler-gcc.h:148:5: note: in expansion of macro '__has_attribute'
>     #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>         ^
> --
>    In file included from include/linux/compiler_types.h:59:0,
>                     from <command-line>:0:
> >> include/linux/compiler_attributes.h:35:29: warning: "__GCC4_has_attribute___no_sanitize_thread__" is not defined [-Wundef]
>     # define __has_attribute(x) __GCC4_has_attribute_##x
>                                 ^
> >> include/linux/compiler-gcc.h:148:5: note: in expansion of macro '__has_attribute'
>     #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>         ^
>    fs/afs/dynroot.c: In function 'afs_dynroot_lookup':
>    fs/afs/dynroot.c:117:6: warning: 'len' may be used uninitialized in this function [-Wmaybe-uninitialized]
>      ret = lookup_one_len(name, dentry->d_parent, len);
>          ^
>    fs/afs/dynroot.c:91:6: note: 'len' was declared here
>      int len;
>          ^
> --
>    In file included from include/linux/compiler_types.h:59:0,
>                     from <command-line>:0:
> >> include/linux/compiler_attributes.h:35:29: warning: "__GCC4_has_attribute___no_sanitize_thread__" is not defined [-Wundef]
>     # define __has_attribute(x) __GCC4_has_attribute_##x
>                                 ^
> >> include/linux/compiler-gcc.h:148:5: note: in expansion of macro '__has_attribute'
>     #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>         ^
>    7 real  2 user  5 sys  107.26% cpu   make modules_prepare
> --
>    In file included from include/linux/compiler_types.h:59:0,
>                     from <command-line>:0:
> >> include/linux/compiler_attributes.h:35:29: warning: "__GCC4_has_attribute___no_sanitize_thread__" is not defined [-Wundef]
>     # define __has_attribute(x) __GCC4_has_attribute_##x
>                                 ^
> >> include/linux/compiler-gcc.h:148:5: note: in expansion of macro '__has_attribute'
>     #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>         ^
>    In file included from include/linux/compiler_types.h:59:0,
>                     from <command-line>:0:
> >> include/linux/compiler_attributes.h:35:29: warning: "__GCC4_has_attribute___no_sanitize_thread__" is not defined [-Wundef]
>     # define __has_attribute(x) __GCC4_has_attribute_##x
>                                 ^
> >> include/linux/compiler-gcc.h:148:5: note: in expansion of macro '__has_attribute'
>     #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>         ^
>    In file included from include/linux/compiler_types.h:59:0,
>                     from <command-line>:0:
> >> include/linux/compiler_attributes.h:35:29: warning: "__GCC4_has_attribute___no_sanitize_thread__" is not defined [-Wundef]
>     # define __has_attribute(x) __GCC4_has_attribute_##x
>                                 ^
> >> include/linux/compiler-gcc.h:148:5: note: in expansion of macro '__has_attribute'
>     #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>         ^
>    In file included from include/linux/compiler_types.h:59:0,
>                     from <command-line>:0:
> >> include/linux/compiler_attributes.h:35:29: warning: "__GCC4_has_attribute___no_sanitize_thread__" is not defined [-Wundef]
>     # define __has_attribute(x) __GCC4_has_attribute_##x
>                                 ^
> >> include/linux/compiler-gcc.h:148:5: note: in expansion of macro '__has_attribute'
>     #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>         ^
>    In file included from include/linux/compiler_types.h:59:0,
>                     from <command-line>:0:
> >> include/linux/compiler_attributes.h:35:29: warning: "__GCC4_has_attribute___no_sanitize_thread__" is not defined [-Wundef]
>     # define __has_attribute(x) __GCC4_has_attribute_##x
>                                 ^
> >> include/linux/compiler-gcc.h:148:5: note: in expansion of macro '__has_attribute'
>     #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>         ^
>    8 real  24 user  10 sys  405.87% cpu         make prepare
>
> vim +/__has_attribute +148 include/linux/compiler-gcc.h
>
>    147
>  > 148  #if __has_attribute(__no_sanitize_thread__) && defined(__SANITIZE_THREAD__)
>    149  #define __no_sanitize_thread                                                   \
>    150          __attribute__((__noinline__)) __attribute__((no_sanitize_thread))
>    151  #else
>    152  #define __no_sanitize_thread
>    153  #endif
>    154
>
> ---
> 0-DAY kernel test infrastructure                 Open Source Technology Center
> https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org Intel Corporation
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201911070445.vRUSVUAX%25lkp%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNWeM91Jmoh8aujpBA9YVfL6LSqH-taQO-6BJQwUZfCkw%40mail.gmail.com.
