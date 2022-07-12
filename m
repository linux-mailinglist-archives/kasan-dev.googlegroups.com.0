Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBUFW2LAMGQED6C3WQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 19F21571C1F
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 16:17:44 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id m12-20020ab0138c000000b003820c57eda7sf2212037uae.20
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 07:17:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657635463; cv=pass;
        d=google.com; s=arc-20160816;
        b=XjOG99ycvLGIE5DtbhgY84IRPUA2eZC1SJxHPYkchAlTr/wH7mMLMnLJbaAQgsQ7T7
         x/0ir+ZO5pvlVLclSmJciJAw7JzsyEupZv47RVMB2Zft+yyyQ2MyqQOkJPMBWVJ2LkMF
         VghMufDOJjsz7T5D1EKkiysx73f5NngzX1R9e0loVdPgxWyvHjRRawnyRMHz9kZGRZzm
         BW+ILvPnQy3qLmmB2kIFrSWizl1A+QNDDSX/p73rpmZ6bpgyTRnY42feUTxIZ6nW8GYS
         7+hab0vIWawE634J0WMdN44Yf3jBk1msKjVOEfOPJsIN1y1H8NSavPbBeG8h5CUGBIix
         UWfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=31bEuJPm43KCojYmAImO+orID+6Sq0uXVDOmiPkyIdM=;
        b=Up5NoZHBLUsF+rO8a0kyRer+8MyErc6N68IQijfdC4C4pnjMMy/rIs8wiwl1i7q5hA
         cgcgd3bdwp4F2nAQwEJnAwQWYqwV5WuXVNo9ThlKx9LZpFivwlV+QwSVgdQT6XWqO7Lm
         mZ1r+U3mgX/KcXhMHqSZD3QM2xFCLTNoNQfDDf6bzecwmZBdFshfN5EAGzaiu2Yb9kFA
         8wEhuL+njzfkyoUBMM45L5g7LBELwfRwrshPVaYWrgvMAaEPZNEIV3Bw1sKQu0xvPA0V
         9Z06RJgyJy/3hyyZUOGz72GontU8tsgr+wFNlnRrud7Bi5XnfR7UPQtkFeZHmKPGwogE
         /3WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sQLMjweS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=31bEuJPm43KCojYmAImO+orID+6Sq0uXVDOmiPkyIdM=;
        b=PQbxnyPkZOQY3jSFq9uGj/YL4LHwPoTL3mYngFrKl967yy7YL8Cwdy5XAsQYwX4ZTF
         F18e74lJpmSYoatWj84MUF+jWP+bi2M+CMCviUMeMZuYZS86pQuakFUcbI36xrG2F7l/
         TPpnIXVm+ZAhuNG8TiCpW8dThmRIyP0qEiervFf1o2UMm8510YcWrzVwauSaj8hJDciP
         Fr45SuK6m4TiczBgNV8dVKDXc9p2XpAjBGn30pwTA8LRNveszcx02s1Uvacra5QeRWAc
         3dBS7eBVgryZUgOpsVOmC2Z7X0I8+95JdUrBxpSxUY/jXsLFcljPHvKLyoDsT/0xrHiD
         nS1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=31bEuJPm43KCojYmAImO+orID+6Sq0uXVDOmiPkyIdM=;
        b=Gqhevvm274lhN2j+KICvSUV0NeLB21RLGEyJJBZYW4dLOH/69gsfATxmFfkvCVw15e
         F7uJTUvWxS0aPv3sXJWwg9NxWogcKiwllARrolk6PMcLaSRdsEGveJfD5husW9f22LdX
         M4mDriraUYvPxm8UfgejUQOXoizgfm8xhEj1jImo+vNCI0ha9avYPFQH/1XtrO45XaDf
         5kUL7W2AmYGAarWhZaFIBayYewg2kZuKBem4YDnKLXZk+Umj1o/YCUJK2ABz6y8Q1/gL
         /LNI+FjBMY6OeS8PQWhq7ccBOEvxemOuVAKM++7eL1ArW2z7ayMBIFz1gLA1wU+bhx06
         OUZw==
X-Gm-Message-State: AJIora/Gp/TYNY4sYJMODPvwbSD11Ovx6mwwKdXBGbni5P1+xKdKFpE+
	56XAwg6XXd6Y+qjgyHxtqlU=
X-Google-Smtp-Source: AGRyM1t2F3XoYTbnRIsNYBs+axwUx27tyYq/KktqrFKTQnsZ5vLWGsYh1JdvdAifX/lUjn0EwgC34Q==
X-Received: by 2002:a67:ad1a:0:b0:357:1109:4941 with SMTP id t26-20020a67ad1a000000b0035711094941mr9760080vsl.85.1657635462990;
        Tue, 12 Jul 2022 07:17:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:cd22:0:b0:374:6c5b:3e0e with SMTP id a2-20020ac5cd22000000b003746c5b3e0els246922vkm.2.gmail;
 Tue, 12 Jul 2022 07:17:41 -0700 (PDT)
X-Received: by 2002:a1f:2fc4:0:b0:374:bbbf:263c with SMTP id v187-20020a1f2fc4000000b00374bbbf263cmr4138454vkv.6.1657635461631;
        Tue, 12 Jul 2022 07:17:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657635461; cv=none;
        d=google.com; s=arc-20160816;
        b=nSQr//gYf4i2Wj+/Nf9RtarcDEsWtgeMXmtdhrxrKIQb5/HJ502VvSdUbnxcTVJB68
         Zjv0uUnAYopbbpuF+3k0Z7TYBIzw6Wcr8VxsAomOsxDS0574pmzul6x9JEZ+xyoW7UDA
         +FRsKVD9eTPNbK5PxfGzSi+Crf65S0TpE3fdkHhelOSUMO5/d2KgrP65u8RM+3RdLDFI
         k0ujpJgtW10y2hutxq4Q3nQBjFdSGKqUEHRZLtQt6S81o5qgrKXtM8UKTTc6vL1YwKAl
         raefGgBt1H1bikBMPmZ0zEyjpdAIq7Qd4Sd/BV7L9KqbEqJAp046XrIm4DZnMj+tcp37
         51Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Buzecpksdj/ppXJ2ucKEbyUfR5ZsYfyO7TYuavzyvD0=;
        b=qnW24HbOyglA+twlw+EpfdpMGozmrLvmbruXOAcRNJzR4jOExkHUaj7nh02nkRUtHp
         Up7oLX+NzAD2c0zHoHzN7gJNLWYGi3bAa7RdxcN/jscWeAVOZQ+F+A/EnC5t7FHNaYqB
         KNP4/QKMPo0/RZPF0J1YqImIiWW6sB9+FvJRREEEavSnau+9fcXUe4YBaxFLvhbTqJrV
         Ggu7Njp9u9L8Xr2dfzsXUmTJi83rcL76A83lpNxambR1SskfCPNon195FQ6iwxxgYDvI
         V2shognVzaiiXPslR/qh3oIbFNjT06jcvx8V0aDd00hVqOcCMqgoEoekFx7BfHr/ZMaB
         b3QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sQLMjweS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id p5-20020a1f2905000000b0035df1d45071si337208vkp.1.2022.07.12.07.17.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 07:17:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-31cf1adbf92so82517467b3.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 07:17:41 -0700 (PDT)
X-Received: by 2002:a0d:e60d:0:b0:31c:8046:8ff with SMTP id
 p13-20020a0de60d000000b0031c804608ffmr25882367ywe.412.1657635461215; Tue, 12
 Jul 2022 07:17:41 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-4-glider@google.com>
In-Reply-To: <20220701142310.2188015-4-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 16:17:05 +0200
Message-ID: <CANpmjNM9RkiXnqqdVSmpBJ0aw2hjZfmXGPQLgxAwWw+UfRHd7Q@mail.gmail.com>
Subject: Re: [PATCH v4 03/45] instrumented.h: allow instrumenting both sides
 of copy_from_user()
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sQLMjweS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
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

On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
>
> Introduce instrument_copy_from_user_before() and
> instrument_copy_from_user_after() hooks to be invoked before and after
> the call to copy_from_user().
>
> KASAN and KCSAN will be only using instrument_copy_from_user_before(),
> but for KMSAN we'll need to insert code after copy_from_user().
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
> v4:
>  -- fix _copy_from_user_key() in arch/s390/lib/uaccess.c (Reported-by:
>     kernel test robot <lkp@intel.com>)
>
> Link: https://linux-review.googlesource.com/id/I855034578f0b0f126734cbd734fb4ae1d3a6af99
> ---
>  arch/s390/lib/uaccess.c      |  3 ++-
>  include/linux/instrumented.h | 21 +++++++++++++++++++--
>  include/linux/uaccess.h      | 19 ++++++++++++++-----
>  lib/iov_iter.c               |  9 ++++++---
>  lib/usercopy.c               |  3 ++-
>  5 files changed, 43 insertions(+), 12 deletions(-)
>
> diff --git a/arch/s390/lib/uaccess.c b/arch/s390/lib/uaccess.c
> index d7b3b193d1088..58033dfcb6d45 100644
> --- a/arch/s390/lib/uaccess.c
> +++ b/arch/s390/lib/uaccess.c
> @@ -81,8 +81,9 @@ unsigned long _copy_from_user_key(void *to, const void __user *from,
>
>         might_fault();
>         if (!should_fail_usercopy()) {
> -               instrument_copy_from_user(to, from, n);
> +               instrument_copy_from_user_before(to, from, n);
>                 res = raw_copy_from_user_key(to, from, n, key);
> +               instrument_copy_from_user_after(to, from, n, res);
>         }
>         if (unlikely(res))
>                 memset(to + (n - res), 0, res);
> diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> index 42faebbaa202a..ee8f7d17d34f5 100644
> --- a/include/linux/instrumented.h
> +++ b/include/linux/instrumented.h
> @@ -120,7 +120,7 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
>  }
>
>  /**
> - * instrument_copy_from_user - instrument writes of copy_from_user
> + * instrument_copy_from_user_before - add instrumentation before copy_from_user
>   *
>   * Instrument writes to kernel memory, that are due to copy_from_user (and
>   * variants). The instrumentation should be inserted before the accesses.
> @@ -130,10 +130,27 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
>   * @n number of bytes to copy
>   */
>  static __always_inline void
> -instrument_copy_from_user(const void *to, const void __user *from, unsigned long n)
> +instrument_copy_from_user_before(const void *to, const void __user *from, unsigned long n)
>  {
>         kasan_check_write(to, n);
>         kcsan_check_write(to, n);
>  }
>
> +/**
> + * instrument_copy_from_user_after - add instrumentation after copy_from_user
> + *
> + * Instrument writes to kernel memory, that are due to copy_from_user (and
> + * variants). The instrumentation should be inserted after the accesses.
> + *
> + * @to destination address
> + * @from source address
> + * @n number of bytes to copy
> + * @left number of bytes not copied (as returned by copy_from_user)
> + */
> +static __always_inline void
> +instrument_copy_from_user_after(const void *to, const void __user *from,
> +                               unsigned long n, unsigned long left)
> +{
> +}
> +
>  #endif /* _LINUX_INSTRUMENTED_H */
> diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
> index 5a328cf02b75e..da16e96680cf1 100644
> --- a/include/linux/uaccess.h
> +++ b/include/linux/uaccess.h
> @@ -58,20 +58,28 @@
>  static __always_inline __must_check unsigned long
>  __copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
>  {
> -       instrument_copy_from_user(to, from, n);
> +       unsigned long res;
> +
> +       instrument_copy_from_user_before(to, from, n);
>         check_object_size(to, n, false);
> -       return raw_copy_from_user(to, from, n);
> +       res = raw_copy_from_user(to, from, n);
> +       instrument_copy_from_user_after(to, from, n, res);
> +       return res;
>  }
>
>  static __always_inline __must_check unsigned long
>  __copy_from_user(void *to, const void __user *from, unsigned long n)
>  {
> +       unsigned long res;
> +
>         might_fault();
> +       instrument_copy_from_user_before(to, from, n);
>         if (should_fail_usercopy())
>                 return n;
> -       instrument_copy_from_user(to, from, n);
>         check_object_size(to, n, false);
> -       return raw_copy_from_user(to, from, n);
> +       res = raw_copy_from_user(to, from, n);
> +       instrument_copy_from_user_after(to, from, n, res);
> +       return res;
>  }
>
>  /**
> @@ -115,8 +123,9 @@ _copy_from_user(void *to, const void __user *from, unsigned long n)
>         unsigned long res = n;
>         might_fault();
>         if (!should_fail_usercopy() && likely(access_ok(from, n))) {
> -               instrument_copy_from_user(to, from, n);
> +               instrument_copy_from_user_before(to, from, n);
>                 res = raw_copy_from_user(to, from, n);
> +               instrument_copy_from_user_after(to, from, n, res);
>         }
>         if (unlikely(res))
>                 memset(to + (n - res), 0, res);
> diff --git a/lib/iov_iter.c b/lib/iov_iter.c
> index 0b64695ab632f..fe5d169314dbf 100644
> --- a/lib/iov_iter.c
> +++ b/lib/iov_iter.c
> @@ -159,13 +159,16 @@ static int copyout(void __user *to, const void *from, size_t n)
>
>  static int copyin(void *to, const void __user *from, size_t n)
>  {
> +       size_t res = n;
> +
>         if (should_fail_usercopy())
>                 return n;
>         if (access_ok(from, n)) {
> -               instrument_copy_from_user(to, from, n);
> -               n = raw_copy_from_user(to, from, n);
> +               instrument_copy_from_user_before(to, from, n);
> +               res = raw_copy_from_user(to, from, n);
> +               instrument_copy_from_user_after(to, from, n, res);
>         }
> -       return n;
> +       return res;
>  }
>
>  static size_t copy_page_to_iter_iovec(struct page *page, size_t offset, size_t bytes,
> diff --git a/lib/usercopy.c b/lib/usercopy.c
> index 7413dd300516e..1505a52f23a01 100644
> --- a/lib/usercopy.c
> +++ b/lib/usercopy.c
> @@ -12,8 +12,9 @@ unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n
>         unsigned long res = n;
>         might_fault();
>         if (!should_fail_usercopy() && likely(access_ok(from, n))) {
> -               instrument_copy_from_user(to, from, n);
> +               instrument_copy_from_user_before(to, from, n);
>                 res = raw_copy_from_user(to, from, n);
> +               instrument_copy_from_user_after(to, from, n, res);
>         }
>         if (unlikely(res))
>                 memset(to + (n - res), 0, res);
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM9RkiXnqqdVSmpBJ0aw2hjZfmXGPQLgxAwWw%2BUfRHd7Q%40mail.gmail.com.
