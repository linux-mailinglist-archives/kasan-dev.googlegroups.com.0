Return-Path: <kasan-dev+bncBCMIZB7QWENRBAHW5OMAMGQEYNVCYHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C32F15B31D4
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 10:36:16 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id i129-20020a1c3b87000000b003b33e6160bdsf784332wma.7
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 01:36:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662712576; cv=pass;
        d=google.com; s=arc-20160816;
        b=vCMpiRt7IyCOcsRhxNoEGcEsnAdVRokGFUwS2ISRRQ9/Ey2silwQoR1Ow+R5SeaNmo
         7F+ZD5k9wB9lNstuQvFFT9Pak4pX23LA2afr1x+ucPZtcZKGTEZd4Z/uImpcIaZLTR41
         pDhXi4mmQTiZZKi8cE/JgqBl5wzV3E/WBeSVufqU0KQWZVxUapctavbnEL+c5+pLzsXV
         Xlt8avaTb+g5qpT+3WZK/PA2VY1iTKZrwVkFxinANyp4PXn7G324Opnf5XPAa5Yed6el
         hByFp0w+LRDJTFDmce4pBJcMsJEsB/PO0kBgZsz4XclTukTZ3t6sSajA6VOCKy9d7zIb
         cnpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1ixsV3bEHOhR3LhaoH5wowzqP6EpcDy3ELTMi236mnU=;
        b=tl1wTctfKYy/boEzJXfyj3NA1+eDwh6NSzmXGOCETXi8gkqUVqQtbvuIXaXIGEJScn
         ryQJ2HUAc5V/W09W/6+Tfy9nX99tB4vv3pKn1Tg8fIBn/79L8tvi3fnOWI4YoG6SjbN0
         223HlI+3bWkirtPlzMRvk2s04tPsioQ7MRkgyx6miwcF7TZyAGFIJayduVryvddlYSvk
         ecYWxanQi1WFSHpiY1cQqGz99zMgCdRmDnmhW6TBOtFaMERPFrJLOnSqgcQQEMDz6VBy
         zJ2A9L6VxMArmxj5eI/Yzd3MD2JkVghuT4XmEleeYQglqKixiQX1hOeqA+BtHI/CiPTd
         opyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dy2bPFFG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=1ixsV3bEHOhR3LhaoH5wowzqP6EpcDy3ELTMi236mnU=;
        b=F303D9pi3y9He3B36veZJK97jz8makKu28xmEsSh6l1/O5M6zAkAUUQqjbdVA6yCEh
         JyxwtO4YT7/OuqRNyXxAdrO52mqZu1/5xE8GJsRsnFw2H5yTRFcytumTxHnx+bOsT7FJ
         G4KxGgrImZSx8CYmCSXpQYU7R0CS0QGiAiBNt9ht1p8zy7v/ptbtPE9WGsAI1SqaTRgY
         iwjRh6Yv+J1TeErlu20uscdUzVQ/0DZb7HGnfLekr1Wd1V4nb9ZOAOS/oyyTobF98jfT
         lYjdv/ZPO9yiJHObkmLRqYszbWipMk2U7UYF1GqUfJ5vj6iX7EADIRghig46GJSsSNYf
         Yzpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=1ixsV3bEHOhR3LhaoH5wowzqP6EpcDy3ELTMi236mnU=;
        b=ObNW1j0IyyswuW++zDOvBjTA2+DKSAouVtDp8uLcaDUSmy1rq68HudY+2vRIAPdEzb
         a/uAyjh1hwVOPlOhhMSUomWngDkP2Oa+9qZ6bVRVh/fwXjSCGZDLI4UkKUeNiJI6NSZO
         zrZOJtNniwJZS4I5B7gcO3LVjO9i/3rKGvXOwi0HDz5trDL4hzyRG8TjIQUPFwTg2WOX
         Y/kvy5uy8nMYHb8le3sZAmqshtFHJ8oGRvahOb+dsdYtjC9uiL2j2Zi1B/7wg41ZPn3L
         OEl9R1gLScwRFhmLecQYQu2k5fNtZZ8wdEP17L2TjS4Ib2I8Pa3uLIMfSeBEbnrxRrLA
         FESg==
X-Gm-Message-State: ACgBeo1lQ5YKWRM1mPpa5LdMcqjv2Lf1nQ+OKK0+r60QcMnn5Veu/zjG
	22tJZB+j5a/+rroS+R0mz/E=
X-Google-Smtp-Source: AA6agR40PbC729qCnHlQat84s5YefJyLcQMLdFS+FT8RmWZUjaV0VUsD+x3EsjN1okXeqgr8mNUorQ==
X-Received: by 2002:a05:600c:3509:b0:3a6:1888:a4bd with SMTP id h9-20020a05600c350900b003a61888a4bdmr4773441wmq.191.1662712576384;
        Fri, 09 Sep 2022 01:36:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6028:b0:3a8:3c9f:7e90 with SMTP id
 az40-20020a05600c602800b003a83c9f7e90ls2218372wmb.1.-pod-canary-gmail; Fri,
 09 Sep 2022 01:36:15 -0700 (PDT)
X-Received: by 2002:a05:600c:3205:b0:3b3:3813:ae3f with SMTP id r5-20020a05600c320500b003b33813ae3fmr3472240wmp.158.1662712575411;
        Fri, 09 Sep 2022 01:36:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662712575; cv=none;
        d=google.com; s=arc-20160816;
        b=qabvIof3B9KFyp9R9HvdsTtx6nOc16ncEWCeqgA5UNKApKntycCA2HhsTFdbvfRJAk
         gikOnOb+GSxWdTeoG4a5FwNb4/ssn5f9vhR0Acnv3rd4Ls2F6yp+YPCIclCh3tPBf2tF
         5z550C67NwFLVRBuRfOQtg6ZhtN7RlzcJgnVNzUcBQJ6VkRCxz6GfajuwI5OL17nbI3w
         hG/qdqLICbBP7NmI//pllFbYhQshcqqVMc3LjD/+xZG2dM3W+lFWC3iDaEox4mtEzv88
         VWEp9QavJalPCmjdE1m8vKaysIBQ1lpOyNvS2Pk33Nkm326dTZ2c57J3kjLwgtdBjTqC
         YMiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BbZr2IDF5mYuV07dt5XpEzbm+CGWl8GmrLDRuGPtC7E=;
        b=ByGxFEJUsJhM4JwCJy/zuMOIaBmtp6152UibZpezk6Tz43CQuM8noqqZnnLwAQZwXy
         fOAkuBYIhVsIYRhausypRFgDwU8J0b5Tvla/b2YNouKzbHCoTnuzpGwokvKpLfssIO3i
         MaL/TQo5OPTURVGTYYF2dBQcOXD3ilInqrA0pvVyL4Z4jRSwuCmEtj7TVsrUPQQnj3+T
         xWPC4l+mzJaJqF9XsWUPh51DxvRf5Q+vi/7wWa2V2N/xKlK1cJqLn1AAYsRbVJwzFkk4
         SA9DVXNA4fELAe4YU91BxAFlGticb7UwTVrKy9FfmInXm5eC4A3jCPqoHWwsLA9XWM3Q
         mNXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dy2bPFFG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id bi20-20020a05600c3d9400b003a83fda1d81si148516wmb.2.2022.09.09.01.36.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 01:36:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id q21so1562050lfo.0
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 01:36:15 -0700 (PDT)
X-Received: by 2002:a05:6512:401e:b0:48f:ea0d:1171 with SMTP id
 br30-20020a056512401e00b0048fea0d1171mr4372971lfb.137.1662712574759; Fri, 09
 Sep 2022 01:36:14 -0700 (PDT)
MIME-Version: 1.0
References: <20220909073840.45349-1-elver@google.com>
In-Reply-To: <20220909073840.45349-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 Sep 2022 10:36:00 +0200
Message-ID: <CACT4Y+bY1SkME7343-EZw_C2tORWrJU0MweArrPf2om8R_wfoQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] s390: Always declare __mem functions
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, linux-s390@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dy2bPFFG;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 9 Sept 2022 at 09:38, Marco Elver <elver@google.com> wrote:
>
> Like other architectures, always declare __mem*() functions if the
> architecture defines __HAVE_ARCH_MEM*.
>
> For example, this is required by sanitizer runtimes to unambiguously
> refer to the arch versions of the mem-functions, and the compiler not
> attempting any "optimizations" such as replacing the calls with builtins
> (which may later be inlined etc.).
>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * New patch.
> ---
>  arch/s390/include/asm/string.h | 7 +++----
>  1 file changed, 3 insertions(+), 4 deletions(-)
>
> diff --git a/arch/s390/include/asm/string.h b/arch/s390/include/asm/string.h
> index 3fae93ddb322..2c3c48d526b9 100644
> --- a/arch/s390/include/asm/string.h
> +++ b/arch/s390/include/asm/string.h
> @@ -20,8 +20,11 @@
>  #define __HAVE_ARCH_MEMSET64   /* arch function */
>
>  void *memcpy(void *dest, const void *src, size_t n);
> +void *__memcpy(void *dest, const void *src, size_t n);
>  void *memset(void *s, int c, size_t n);
> +void *__memset(void *s, int c, size_t n);
>  void *memmove(void *dest, const void *src, size_t n);
> +void *__memmove(void *dest, const void *src, size_t n);
>
>  #ifndef CONFIG_KASAN
>  #define __HAVE_ARCH_MEMCHR     /* inline & arch function */
> @@ -55,10 +58,6 @@ char *strstr(const char *s1, const char *s2);
>
>  #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
>
> -extern void *__memcpy(void *dest, const void *src, size_t n);
> -extern void *__memset(void *s, int c, size_t n);
> -extern void *__memmove(void *dest, const void *src, size_t n);
> -
>  /*
>   * For files that are not instrumented (e.g. mm/slub.c) we
>   * should use not instrumented version of mem* functions.
> --
> 2.37.2.789.g6183377224-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbY1SkME7343-EZw_C2tORWrJU0MweArrPf2om8R_wfoQ%40mail.gmail.com.
