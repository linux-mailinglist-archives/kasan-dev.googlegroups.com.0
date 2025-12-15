Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ7W77EQMGQEXSRF3XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id DB5D6CBDB99
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 13:12:24 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-8b17194d321sf457034385a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 04:12:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765800743; cv=pass;
        d=google.com; s=arc-20240605;
        b=BGz9fZnsNduCHu5UeeClwxBWChw4rLykOxOCAxeyR/T5hldY/eqgAz0KO6Qftg0Y0E
         TUBwuZQH65syOwA2tvchnDf6bA3leevkHxIlVq33fpPkEraaGDc6KxXBFXRj4SFJBcxW
         /VVUoUZPV8kTuyaPU076iNRm4pBxjOBOry/hh06qtQ7s1Pha0OQ9UcWIX6YpkNUBJL0E
         rAk1BLcuT6izcpd4MKOO9KQ59BIsfskoaMD9w3+bHR4SDkYY/0obUo9mxD7/hl/G/T2+
         gT/ugH4vuyFswxsJ6LF62TLZxp9xLdYo+i0HrT23oEya0NZnyyGYUxzMzU7R/ItCPcEr
         bu6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kezKk/CQc9x/istKk145KgV74kbLIr+Y/5DMQgJuOw8=;
        fh=9QdmDBPE4zT60DzMEkoQiNW6mO0uozxjG6Mq5c7IRHQ=;
        b=AhKxEKjzw2kI4H5v2DDnlxIsF+8C+LR0BuO/SlOJ3xh2clQiNq3ZXRajxwpYyLUAkb
         I57L9Ro61zxGv3+uYBIEu+57pw06ylrQZlIKsb85pqg2qOFcls3bxa6YzURXsdxxFfzb
         3EYA3dcUW46xEGBKBiw6ttmZdTKqfwYojC0gbI0OeLpLoIZ+ilIQ0UNpR2cR/ExBcryZ
         VvlWkduGywdsbyPA0dbX1ERZsqvTnQFMLr8cRhJKuEwNZ5bmV68UBZPDvczovd4Zho2B
         jEqwEmah0m64SmxgWDKaHYfAzOFkONsB0wGzgfY5x0FEFnXTJlkwwzopjrkk2VMs0QRa
         q/ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fPtAHLy3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765800743; x=1766405543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kezKk/CQc9x/istKk145KgV74kbLIr+Y/5DMQgJuOw8=;
        b=FSvzt5Qyf4nroVaNjZzsgLXL1zyUiei2jm9rh6/hUUa9v3haKt5ZsqHV3pm23Ee3BL
         9MskbqVGFbBXc8BxsBDQAQlgR1//rmdF0FaWYhU8etA5arVUG8iOKo632r6+somHqr60
         H9iHn1BxKnw9Ml5QolJHF5NTeP+UvhZi/SnwnZ6ju5HBp0VXaTGsyBPxpMGLIHsqWnt2
         78YKD8oe9ZDink3BOzG6OvGnhTX66AWlqBC13OuZSYXxPXM07L6HYutoZfzh2rJ+LWdQ
         WP2/aCsuRngBM+HnioK+JyYnsEe9ctfKfhI86xEa+ZfkSEKQB3EYOjKiD6ECAElnejWe
         jjhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765800743; x=1766405543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kezKk/CQc9x/istKk145KgV74kbLIr+Y/5DMQgJuOw8=;
        b=uI2MOui+aVkmpuLHshEahIk5weQQcs9SK0E+GG57AulALYL5FtILBbQiNxVixDuock
         y9YMnsF9bc5jsZe9sVhHnBRLE06djlH25Mo6dtVdbloOORAgmcZVxQs95x4EM9CCDBE5
         98VprocqSurV1b0MWHLTqvZBsS0Bq/jWgHP/PHJuQYObIN4y653gJKEw5s6pYYGFIm/P
         ANT7V+xNUxdRwQPDgQLxi2sW2xrhm+snI4XNMcwxtfa910DiTVU52bk/zJ2d1FVPbY3v
         UfSZ/cSEF20k5yneLQyj+pQkJxwErSYZxwkfNPsjGiwM8dPjGKp3mSFTNJad6sROHeIa
         975Q==
X-Forwarded-Encrypted: i=2; AJvYcCUyxQWnbgfbavACJpcDc557MXkCP1IJEwjGGNh5YE/Kwo05kHItW6OcakPjqdipkB6AsbLGiw==@lfdr.de
X-Gm-Message-State: AOJu0YwNSlt/ugg29gAR68GjwkWBNBum+qLkKLHG0DmwB1cYMyCQQjB4
	TwgN2t2WNRAFdr/WxV0fCN2ZD/bJT5pHv99pZdygGPT08ud8Kiagza68
X-Google-Smtp-Source: AGHT+IEceTGKE4CsrLjpy1PjBETNo3HGcz/EKRGLF0t76xykTl6qOchI/UI56+1sS+V5ZJKvuoqo9A==
X-Received: by 2002:a05:620a:4509:b0:8b2:a4ec:6f5 with SMTP id af79cd13be357-8bb398dedefmr1451894985a.11.1765800743533;
        Mon, 15 Dec 2025 04:12:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZoraTjQ728xuzbifC7Ny1w+1Tm/CJbEMwbsbbQUP3Gew=="
Received: by 2002:a05:6214:4007:b0:882:4be6:9ace with SMTP id
 6a1803df08f44-8887cd3a225ls51905916d6.1.-pod-prod-08-us; Mon, 15 Dec 2025
 04:12:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWmwPRsHD0/MHRsC0M6Oxh91Zaxq/lAa0dVBdzZmHmdDM3Ue5u4zRJ/cVupu2ZAKgiLFS7X25SNG9A=@googlegroups.com
X-Received: by 2002:a05:620a:404b:b0:8a9:b034:901a with SMTP id af79cd13be357-8bb3a248cf2mr1299431385a.41.1765800742632;
        Mon, 15 Dec 2025 04:12:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765800742; cv=none;
        d=google.com; s=arc-20240605;
        b=IdXkBkzFOaNIFhSaJ847vlz4JMKBA0ApZlJFILq3UkpfnjmIf/P5ZHNwdQJfAZdyIH
         4ONx06ErIa0sHsV1ZG15qj7dB+GOpkdNHMdLxQMY6ZAXRXFIO5OLYAVz9mrG7Z2pLdXu
         E02Cx03osTi1MDoa4Cb/23iRJ0hIJr891sASmmnR3NPnfJBgARiXaS/fcAWi41lVv5fF
         qTejmh/G/N2UAaxv25Apm0K6Qh1+SNLLf1hHbczCGD++8oIEvkjogaOgW3912JRO+tbc
         KfvJTv1m0xQJ9OivmHANIeCxryPync9Ngvhc1/OhtlNVUSkbQATE17H+Zf+ST+wCf4fH
         QNCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zUEC2LAFDhU/R+3AEc9YA1eCbqJdYnhGFoftFOwwqxc=;
        fh=ndHiKcwLr5ZWPaD3PS6b1KJ3T8exiabUTByZA4znPCs=;
        b=Gc4ommtcwCiPVuTDD61pSZTiRHM/WCqNt19njPfomKF5gahIaQNYVqUusJBIZeY2mu
         MBMouYA0vVb59LFlUq9CjPMpo5qklNc4HZYTf7f7tlUPMrnA9/TtSfhgK5dwlSXnuVVj
         EVsid3Uqi1PYCTI4SVm3xjS+hJtloazrtqc27MIx70REyR3y41CfxKehMF/hQhcjNQof
         ZdNs461YLmNweVdalT9EVs0J0pcoo/GKqN3VROKVcdUXOtfhPWI0BJXe9aoqZZp2K3Kk
         26q/l6MPNBq0T6kc1AGrBIWpG3OmuP1LggZHtopdXHipVp32KpQ8wEaSy0kbmaKfM2x6
         /i3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fPtAHLy3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8bab57900bfsi60720285a.4.2025.12.15.04.12.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 04:12:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-34c84ec3b6eso1121382a91.3
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 04:12:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX8z9SGsz1OLb5PCR9y5voKVRz/ja1ywoekC8UaWky5a748OIgRNltGiQ/BtBQqsSFHgVFISzV91Q8=@googlegroups.com
X-Gm-Gg: AY/fxX5FD56Xz54yz1hgU3iHtMxFYyyPEByVhqYFE76pAYei+y9XeM+eqpc2LXuvoWU
	e3WpihGtK1qpJRI3cvkgWsrmlOArqwTXz6CMSVgYBQ5D7zYXinSnEIMByatsvBOX+luk7//Qb0o
	6olGmhzahaPs1rIzrZ1kqlFni3fOdC99n32FZzdNKPhDrruURM9ovryC4cfNMTeeFJ9sPJ6Bz/y
	nJ0IRaasAe3DCwFy6iurogagAKfOZZbpgDFnDLKmmrwsh3aKCu0i/LqjtgoScIc9EAnGljR8uVl
	jXapRp4Tx02x/G1JWpplm3rxVQ==
X-Received: by 2002:a05:7022:1589:b0:119:e56b:c753 with SMTP id
 a92af1059eb24-11f34c26244mr8741206c88.24.1765800741331; Mon, 15 Dec 2025
 04:12:21 -0800 (PST)
MIME-Version: 1.0
References: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com> <20251215-gcov-inline-noinstr-v2-2-6f100b94fa99@google.com>
In-Reply-To: <20251215-gcov-inline-noinstr-v2-2-6f100b94fa99@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Dec 2025 13:11:45 +0100
X-Gm-Features: AQt7F2oJijaxONSQXeHmIxdofJLbZAtJZeJF4in_95-GOXfTl-Lf4DlFaoC3c1U
Message-ID: <CANpmjNP=_g4Ecfyk7h-Z1bSWho3MXNU3CO_a77zs+phhUZu76Q@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kcsan: mark !__SANITIZE_THREAD__ stub __always_inline
To: Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fPtAHLy3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 15 Dec 2025 at 11:12, Brendan Jackman <jackmanb@google.com> wrote:
>
> The x86 instrumented bitops in
> include/asm-generic/bitops/instrumented-non-atomic.h are
> KCSAN-instrumented via explicit calls to instrument_* functions from
> include/linux/instrumented.h.
>
> This bitops are used from noinstr code in __sev_es_nmi_complete(). This
> code avoids noinstr violations by disabling __SANITIZE_THREAD__ etc for
> the compilation unit.
>
> However, when GCOV is enabled, there can still be violations caused by
> the stub versions of these functions, since coverage instrumentation is
> injected that causes them to be out-of-lined.
>
> Fix this by just applying __always_inline.
>
> Signed-off-by: Brendan Jackman <jackmanb@google.com>
> ---
>  include/linux/kcsan-checks.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 92f3843d9ebb8177432bb4eccc151ea66d3dcbb7..cabb2ae46bdc0963bd89533777cab586ab4d5a1b 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -226,7 +226,7 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
>  #define __kcsan_disable_current kcsan_disable_current
>  #define __kcsan_enable_current kcsan_enable_current_nowarn
>  #else /* __SANITIZE_THREAD__ */
> -static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> +static __always_inline void kcsan_check_access(const volatile void *ptr, size_t size,
>                                       int type) { }
>  static inline void __kcsan_enable_current(void)  { }
>  static inline void __kcsan_disable_current(void) { }

It wouldn't be wrong to apply __always_inline to these 2 stub
functions as well, but I think it's fair if you just limit this to the
ones used from <linux/instrumented.h>. Either way, please
double-check.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%3D_g4Ecfyk7h-Z1bSWho3MXNU3CO_a77zs%2BphhUZu76Q%40mail.gmail.com.
