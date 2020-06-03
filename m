Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNGO333AKGQEG7YHQ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FC721ED0F3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 15:35:49 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 67sf1454760oto.14
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 06:35:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591191348; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oyul4WPNdLl1gbdFrL9tph+fuDNUrMqusspyurkSU3j9wuX0UTljvYDnUwLwIJNGFu
         KxUR1lh8CxSbyVGiQUM5ySk+AHoYCQ/EGeno5L7ommPFYL3cgUEB3tNsFpdbojSAorUx
         60a+1hlWlUZvWi3NiVBKrcQnX8dQnr0B58UPqUuMA8/VbHhcKupuhAOCirZkfccMQmf2
         zVXIhbQB/vf8xPjw6Kiy9NjukH457x4nLAGT1I4NXzlhbmytx3eRu1YZyESkJLIqrDW7
         nueXSOiguKOTslAMHldJfrO4Z3RzcQ+7LBRvfPazdm6TRloY5bvuMa+rDos1xooG7DXO
         Lz3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cF+uJR2dgRqjWOERh/cFxk5w4y/M2N1jedxbdZWlswA=;
        b=X5kInR7oIBiR8LQyZnNTFrB3Mu6+Px7Os+JE0nup6cSzaGH/b1VWQiiAwgbyhSQauJ
         zedqyXIKDFNn5BkHbkFe+8sboSXc497w0gWZ8qbDijWZIBGYkTReHZDqtgqgVCTTj+qM
         LZRDwiBOEb3PycQwK5JHJppTO7BLbLdqiFKvvZTesaPODvvzNj5noNGz940bkCkkJl+V
         Y+x/RKipSq4pPD1B5K/Qit9PbBC7u0PkLKjN0NqCXXtBiPU1KRhl21d9qJxAAuiumzg/
         g091ac+ygriOKRoefVZSxGhklQDDVpQUOOtwyMJ5x/yCmc2oq9WBjLfpe5akhq8Suh29
         CSTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ECLofNCH;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cF+uJR2dgRqjWOERh/cFxk5w4y/M2N1jedxbdZWlswA=;
        b=c6wVodbkuEE+SU3dQ6cSCSSncOgU5Rlavq0E/VUmI/CAc3Iu6VNU/NoYO28GHNwy8n
         Qx11jO8slDHbzZsf9fJtJ54h/PrJln+jxhhY5Ri0x0OcRIlgP5TtWLlszpQTuWYDgTzC
         PKFoZ8etK67Nw5yuz+qDj/mHPrvBJOEjjapNszEi3icoTaG5UAzucuPgjeANXuWuYbhC
         4MyXgRRLhehlpk3gEifINbtnFAAjBbz4R/1nLw7rvo2H2KLxVi2EDSjGxRZMR3ZqTWSO
         OZzcvGUhEsj/jwIW4/VLFIPyTtPhaoKz9l4y5M7oPLBCc5Wv0sem+V4DkfUSoyijSqrz
         YpNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cF+uJR2dgRqjWOERh/cFxk5w4y/M2N1jedxbdZWlswA=;
        b=kLMq9cpBjkFHhXO+XJSIXcmGTKRYxHOJxt1S1UkmRs45RyUVXbFbhinzre+1+kGvsy
         s7epnS2moEnC97u94UMZ/yUbVQBaDA1NXJj5YOl4iY+gjQfkHnhrJPevVOwcMpkCXxaB
         wnOD1tVTsGb2CmdlHCQS2zH5rimt+1Cbf0SJcLRspQC862FtwZHyLuCqkpp55juKdoB7
         fPCgA9gBq8XQIpMAXe41EwmPnkd5KGzFW5fxml/nzg25S/i8MYb0AxxzKHDQTAEOtVbD
         epeZz8F65Jyp3W2Xm67do2y2kgy4m7JAZ3xGOncAALgn2e0WI7DeEsFlDkVoUqapcczT
         E1hQ==
X-Gm-Message-State: AOAM5320sEv1Yid5I1wTbQkXcTQlMAYvxmfNkwEVVsjUoq/AdCFBNsVS
	xDrtLeHrNbvbBbVw3eaK7lc=
X-Google-Smtp-Source: ABdhPJzMaMmtl8GT4kbS0WdNDDbJC+m22IsCtsvmLCRkSv1C+dYnB7Tnrc1hdGeGeqCrlqY5BB8AwQ==
X-Received: by 2002:aca:568b:: with SMTP id k133mr6433847oib.143.1591191348523;
        Wed, 03 Jun 2020 06:35:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:11ce:: with SMTP id v14ls435453otq.0.gmail; Wed, 03
 Jun 2020 06:35:48 -0700 (PDT)
X-Received: by 2002:a9d:640a:: with SMTP id h10mr3361092otl.323.1591191348046;
        Wed, 03 Jun 2020 06:35:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591191348; cv=none;
        d=google.com; s=arc-20160816;
        b=qENHoTGYq+vx2Hfx8ra+yP24J6E6wNByYirPikwVqC4auerD3mTiAccZRDWsGtXipN
         siFh1o/S+SCUpSwGnOuMAeEUMuHVvkk16MdHptV+AA8CPCcwPzuHuR4fLUYO4mPZvv+X
         dVVJPhHuP7Q83daVmJs9KOXucCVT35SPOz8NvTU08BrvRCWTfcA1nEQuKvLy8X764kQZ
         5pokAxQzsu1L6ppSEwSAX7T+qmt3/i8C6TD6nAM+EFuKg0Gs6iAqEukWEfoiYovwXaxq
         J+A4qA8BZjOcI3AhkmYLHeeENeLLfHcTPJiD52clR3uc22duTeFlBeUgrAVInrfeS115
         S2iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pzgEpVCSH7j0u78t2npqiORwBbG9mOLC23VmgaWMcFo=;
        b=pEomvV31TfAbfLo3zPKB4sHogWZ6QRne6E2bIjaAG5wIYC3uTYw48NrriEeh3Yfw7l
         HWlbtTbT6KRHorr0TqThaewEjRYKuAwDEJbrc91UHJQogBSy+bWDFEY7teqD+VAfiS0P
         xRY5Ty2hKDCyeB5T3X9FIv770XSb+TVYP1SFhRYm9cXJAhYZyMlHSdL5zwJeVecVWsDp
         dDuGPhP0ZFYclrJNKUKiH5eFFIrWHpgYHZxbZlYNrEIpPh3hmeQRYnOp4SfjknStxyLk
         HU0LhvAB3PblzGCkBqpa0tVSCynCTiWTL+WvZEBnQ+Ci75qwsRB3NFYBcMQLmaEBQhM+
         /rRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ECLofNCH;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id p28si156874ota.3.2020.06.03.06.35.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 06:35:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id b5so1617779pfp.9
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 06:35:48 -0700 (PDT)
X-Received: by 2002:a17:90b:1981:: with SMTP id mv1mr5878381pjb.41.1591191347177;
 Wed, 03 Jun 2020 06:35:47 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <20200602184409.22142-2-elver@google.com>
In-Reply-To: <20200602184409.22142-2-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jun 2020 15:35:36 +0200
Message-ID: <CAAeHK+wZegLFPms5_TkBgkoQMeT14UDkY63YoJKmkMaMYnUWQg@mail.gmail.com>
Subject: Re: [PATCH -tip 2/2] compiler_types.h: Add __no_sanitize_{address,undefined}
 to noinstr
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ECLofNCH;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jun 2, 2020 at 8:44 PM Marco Elver <elver@google.com> wrote:
>
> Adds the portable definitions for __no_sanitize_address, and
> __no_sanitize_undefined, and subsequently changes noinstr to use the
> attributes to disable instrumentation via KASAN or UBSAN.
>
> Link: https://lore.kernel.org/lkml/000000000000d2474c05a6c938fe@google.com/
> Reported-by: syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by:  Andrey Konovalov <andreyknvl@google.com>

> ---
>
> Note: __no_sanitize_coverage (for KCOV) isn't possible right now,
> because neither GCC nor Clang support such an attribute. This means
> going and changing the compilers again (for Clang it's fine, for GCC,
> it'll take a while).
>
> However, it looks like that KCOV_INSTRUMENT := n is currently in all the
> right places. Short-term, this should be reasonable.
> ---
>  include/linux/compiler-clang.h | 8 ++++++++
>  include/linux/compiler-gcc.h   | 6 ++++++
>  include/linux/compiler_types.h | 3 ++-
>  3 files changed, 16 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
> index 2cb42d8bdedc..c0e4b193b311 100644
> --- a/include/linux/compiler-clang.h
> +++ b/include/linux/compiler-clang.h
> @@ -33,6 +33,14 @@
>  #define __no_sanitize_thread
>  #endif
>
> +#if __has_feature(undefined_behavior_sanitizer)
> +/* GCC does not have __SANITIZE_UNDEFINED__ */
> +#define __no_sanitize_undefined \
> +               __attribute__((no_sanitize("undefined")))
> +#else
> +#define __no_sanitize_undefined
> +#endif
> +
>  /*
>   * Not all versions of clang implement the the type-generic versions
>   * of the builtin overflow checkers. Fortunately, clang implements
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index 7dd4e0349ef3..1c74464c80c6 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -150,6 +150,12 @@
>  #define __no_sanitize_thread
>  #endif
>
> +#if __has_attribute(__no_sanitize_undefined__)
> +#define __no_sanitize_undefined __attribute__((no_sanitize_undefined))
> +#else
> +#define __no_sanitize_undefined
> +#endif
> +
>  #if GCC_VERSION >= 50100
>  #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
>  #endif
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 02becd21d456..89b8c1ae18a1 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -198,7 +198,8 @@ struct ftrace_likely_data {
>
>  /* Section for code which can't be instrumented at all */
>  #define noinstr                                                                \
> -       noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
> +       noinline notrace __attribute((__section__(".noinstr.text")))    \
> +       __no_kcsan __no_sanitize_address __no_sanitize_undefined
>
>  #endif /* __KERNEL__ */
>
> --
> 2.27.0.rc2.251.g90737beb825-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwZegLFPms5_TkBgkoQMeT14UDkY63YoJKmkMaMYnUWQg%40mail.gmail.com.
