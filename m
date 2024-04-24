Return-Path: <kasan-dev+bncBCF5XGNWYQBRBPMRU2YQMGQE3LNGWYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 86AEE8B1638
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 00:33:35 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-de5520c25f0sf793587276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 15:33:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713998014; cv=pass;
        d=google.com; s=arc-20160816;
        b=zxLEdZn5mFEKSwBTywtYJuuyRuxVUVUlcE/F02kgV0HIn9ynE9Lwkk4ZUJSAn9gpxX
         N+wK6f9jhFIUT9F7TZ3rPQIm15dSWv7HN1aH24PZ4Se6w196V+tB7BRWLl5XGmHZ8agz
         DmqDEcWevEFdmBvXecvnxro79KL+E4HYchZixBx+afobTy1NVWn4O7FYT71Wk/cCWbF2
         rOmmYSxwSW2HxzLVoJSYsL8QqLuzV2o11xhDNdMAkhKiZlCIlPrkIru18ooiTeZtmJnq
         oMNvfr2T5X9HCypfP+NaSOvbpmtCd6mCOvgTqfyZv/wVggRfE8vr9Goh4NY51PIeJTyV
         uAtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HLjfZeJ8CXvCgUV9lflOU3uLEY5VibI6oW6mdXsq8M4=;
        fh=EkY+LMw6Bu3eL7A0PLqX/GdovlEVgLYQ/t6Y8aKnz6g=;
        b=lam4WMwlV/+/Bm+r/Pv8edJQ0yKeE1TZv4pHfvf8gwzQIel//7Xy0ZLNZF4Ls3XQdZ
         +HmTQlSNS05u4YJ1m+GgEXde+ItgUAGVopD85WcBtaMoRzQ7dFoFMHoeASV9678AkHX7
         Lt9TdD8wok/rdCO1b6yd2buKKfEGo291yPsquogHRmIUhn9ATPmtJAsxsm1fbju8QTP4
         dEXpcQCqEzApbcbGVtoVpPZjhN3QGQJmIYeeIyiK85OR/A+k+J1HBrW2wFsWHxUABsut
         /gHZFhreCrYrpJ/Kn3iAktwk52OQTeeuDnL0F2pldOYP+3Kf4o1XgYBvlDzWWH+oQVO9
         Emtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PICLBFDD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713998014; x=1714602814; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HLjfZeJ8CXvCgUV9lflOU3uLEY5VibI6oW6mdXsq8M4=;
        b=Gy/RqJed31HtmggRMBWB6HoJD0OT1Ka/mQxewMSXy2Xa46RbgeBEBSYYUHzoLHbsUz
         ijYiQOjHL9TlX7CLIZYSupbYft3e2A2YGmBqMcVnct7cq5ZQWxA4jza7DWvMjYTMhMB2
         rWMpLWPpke3004n9nA25v14Zstu/pwYxwFRrgJzKVOhC1UILiBBYrqAgGpmXkvVt9i2t
         orvGP4TKlMWCcQQjdIY0VovpBkxDJQ1vMX7nBQsgEQW0KHhG1dsDXNaCdGqJEgHYd4JJ
         RRbxytBBDeV1lOnmzzA5tfrWZlobW4sHMHZvkGw5O9WQPFFNs7MPmbG87yqkVahbuP5j
         l+Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713998014; x=1714602814;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HLjfZeJ8CXvCgUV9lflOU3uLEY5VibI6oW6mdXsq8M4=;
        b=NWulY1fQ/qN4NVNpXJJarsRNF3l4UCpYjDW7V4PCObzLzIOZ2X576z1jnzwqghtPqH
         42Sb83ugwWjDEyktO7cVaqnhPIacZ98xeiIxWJgxmRiU3wMG8PxpPgrjlSFsFphUNtxC
         sCnZ4GxnjdQ57EJASOwVoplaV8/z+1kLCqzPvGLb1/xSXktdDHpUVJdFhY1Kn79emdYJ
         km3UfocbnE8gJge+AO+mzUIO//yu4isuEr13BuX/dRAmzMMWcO5MJvLDziAwCydeozKc
         jgCS50Tlp3mUw3+giS1Nk2A12RYiefeoZIYQzbggyg9K5zUfNcVkYcIsUoRQi26IVvG3
         Y/Fw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6S5fDVeHQi6v2yKmbKruSYpBY1CcLgG3Y+LI+zeLbj3m/EMFu/wUEhLuzn4gIaGLdzuOTAaUy0o+PeHcptcqFzvTDK2VMng==
X-Gm-Message-State: AOJu0YxVUKo0WGx6Q1Z8BTJDpPdaVcDKNhmbXkL/cQb/o5yBRpxvDYv3
	VDbr4HehOtC772j7lb5VIAZWLDGyZqgrU6zOxlZQXYzUyzcjeqtC
X-Google-Smtp-Source: AGHT+IEOG2Bkylt+Q0+0zJoXCCTNwftMggjSwux8Sma2BUHIn+rf6ryIne1ktXGuABae309ICmgAfg==
X-Received: by 2002:a25:8483:0:b0:dc7:3165:2db1 with SMTP id v3-20020a258483000000b00dc731652db1mr4090734ybk.49.1713998013941;
        Wed, 24 Apr 2024 15:33:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:abab:0:b0:dcb:b370:7d13 with SMTP id 3f1490d57ef6-de586141ccals333232276.2.-pod-prod-04-us;
 Wed, 24 Apr 2024 15:33:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUy1w8ejP1ZP4RfURpqGSWqyZBikBwz2z/95LXbVIPH912Spxh2clBwLTVqYav/0RYqME1yEJywETl8lBlkz+IxKWi9oybKM5t6uA==
X-Received: by 2002:a05:6359:4294:b0:17e:8e7f:59f9 with SMTP id kp20-20020a056359429400b0017e8e7f59f9mr4906444rwb.26.1713997932480;
        Wed, 24 Apr 2024 15:32:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713997932; cv=none;
        d=google.com; s=arc-20160816;
        b=UDeiQvR1Grz2UNyS/SVJVty03zFjK5r0s41PBn/rDeAR39g3lRk64g/lHrTIZXoRr6
         0SGtT6UEbw8YTe76ggHopk7ExoQ23Fm77LW+kD/9PMYJMtO54K8Jyn10RiDtRE5X1ny5
         vKZpzzqnOQz3tdrFgy2VKnkh/KVZ3wnQRcyIZXVZK2AgZA0JIQfrTUp2lwLbBZTxyzPv
         wTYAivBqIzOBRPPQhkHX682r5NToTxxAG2cyf+4BG2tqDJASqJG8VpNjqcsAvZa9waDx
         9Bhh+WucB8qI/r1dm2q/pF1rgFO91oskiV9UXahowupGxxeuOCCTUrY4Rra9zzkDgjzF
         XmdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=W5XW2EeZa2xzGai521vbraJwVDegbnZlLcrpCRyHG1Q=;
        fh=fD57kHwWCGiSCEooo6/PaZRoUcg7ZcPWf//EjnPx3pQ=;
        b=TtQ1x1npwVSuo/kU58kBrdDsuFhTrz07fIGbXBEpvismICjURD82bIQYwNtfl/tUCm
         +dmIA62gXaNUxRMlOgzhLmB4ZlNe+Rt56pvkxe3YkPbsjnxaEDnOv7XLY5KohRy712yQ
         NZBNG9wR1bxizRvKLFwX+CFWT6y1W1P9TZwOhcf3yx3fNdZJHb3TtbbY7CFW41tohezy
         LSR/QFhaPeO7ECezLNuXnGAjwoU4foxTD5Fa3Noj7yIO9CMsZEDRQNGj0k49fPr2sIFo
         z5SpE6VsynnXVsb9ZekZK6WRHrOu/hdGM1tzgp6OUSxaHp4tQGxlWTszKtppqPBJ/9zO
         nqzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PICLBFDD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id dj20-20020a05622a4e9400b00439085c647csi1481000qtb.0.2024.04.24.15.32.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Apr 2024 15:32:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-6ed0e9ccca1so418574b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Apr 2024 15:32:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVNVopD2EgSJ5lwOHfR6kQ5PNm4hahP7ka9AHYJT79z+TBqKDlZs+dI3Nf8/Z02y5FaqcywNsVNBgFsGfmVS/j8x6dSV/s9KhsiwA==
X-Received: by 2002:a05:6a20:de89:b0:1a7:870a:86eb with SMTP id la9-20020a056a20de8900b001a7870a86ebmr3750218pzb.15.1713997931478;
        Wed, 24 Apr 2024 15:32:11 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id u12-20020a056a00098c00b006f09d5807ebsm11488861pfg.82.2024.04.24.15.32.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Apr 2024 15:32:10 -0700 (PDT)
Date: Wed, 24 Apr 2024 15:32:10 -0700
From: Kees Cook <keescook@chromium.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] ubsan: Avoid i386 UBSAN handler crashes with Clang
Message-ID: <202404241530.A26FA3CC2@keescook>
References: <20240424162942.work.341-kees@kernel.org>
 <20240424192652.GA3341665@dev-arch.thelio-3990X>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240424192652.GA3341665@dev-arch.thelio-3990X>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=PICLBFDD;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Apr 24, 2024 at 12:26:52PM -0700, Nathan Chancellor wrote:
> Hi Kees,
> 
> On Wed, Apr 24, 2024 at 09:29:43AM -0700, Kees Cook wrote:
> > When generating Runtime Calls, Clang doesn't respect the -mregparm=3
> > option used on i386. Hopefully this will be fixed correctly in Clang 19:
> > https://github.com/llvm/llvm-project/pull/89707
> > but we need to fix this for earlier Clang versions today. Force the
> > calling convention to use non-register arguments.
> > 
> > Reported-by: ernsteiswuerfel
> 
> FWIW, I think this can be
> 
>   Reported-by: Erhard Furtner <erhard_f@mailbox.org>
> 
> since it has been used in the kernel before, the reporter is well known
> :)

Ah! Okay, thanks. I wasn't able to find an associated email address. :)

> 
> > Closes: https://github.com/KSPP/linux/issues/350
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> > Cc: Marco Elver <elver@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Nathan Chancellor <nathan@kernel.org>
> > Cc: Nick Desaulniers <ndesaulniers@google.com>
> > Cc: Bill Wendling <morbo@google.com>
> > Cc: Justin Stitt <justinstitt@google.com>
> > Cc: llvm@lists.linux.dev
> > Cc: kasan-dev@googlegroups.com
> > Cc: linux-hardening@vger.kernel.org
> > ---
> >  lib/ubsan.h | 41 +++++++++++++++++++++++++++--------------
> >  1 file changed, 27 insertions(+), 14 deletions(-)
> > 
> > diff --git a/lib/ubsan.h b/lib/ubsan.h
> > index 50ef50811b7c..978828f6099d 100644
> > --- a/lib/ubsan.h
> > +++ b/lib/ubsan.h
> > @@ -124,19 +124,32 @@ typedef s64 s_max;
> >  typedef u64 u_max;
> >  #endif
> >  
> > -void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
> > -void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
> > -void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
> > -void __ubsan_handle_negate_overflow(void *_data, void *old_val);
> > -void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
> > -void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
> > -void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
> > -void __ubsan_handle_out_of_bounds(void *_data, void *index);
> > -void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
> > -void __ubsan_handle_builtin_unreachable(void *_data);
> > -void __ubsan_handle_load_invalid_value(void *_data, void *val);
> > -void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
> > -					 unsigned long align,
> > -					 unsigned long offset);
> > +/*
> > + * When generating Runtime Calls, Clang doesn't respect the -mregparm=3
> > + * option used on i386. Hopefully this will be fixed correctly in Clang 19:
> > + * https://github.com/llvm/llvm-project/pull/89707
> > + * but we need to fix this for earlier Clang versions today. Force the
> 
> It may be better to link to the tracking issue upstream instead of the
> pull request just in case someone comes up with an alternative fix (not
> that I think your change is wrong or anything but it seems like that
> happens every so often).
> 
> I also get leary of the version information in the comment, even though
> I don't doubt this will be fixed in clang 19.
> 
> > + * calling convention to use non-register arguments.
> > + */
> > +#if defined(__clang__) && defined(CONFIG_X86_32)
> 
> While __clang__ is what causes CONFIG_CC_IS_CLANG to get set and there
> is some existing use of it throughout the kernel, I think
> CONFIG_CC_IS_CLANG makes it easier to audit the workarounds that we
> have, plus this will be presumably covered to
> 
>   CONFIG_CLANG_VERSION < 190000

Yeah, that seems much cleaner. I will adjust it...

> 
> when the fix actually lands. This file is not expected to be used
> outside of the kernel, right? That is the only thing I could think of
> where this distinction would actually matter.
> 
> > +# define ubsan_linkage asmlinkage
> 
> Heh, clever...
> 
> > +#else
> > +# define ubsan_linkage /**/
> 
> Why is this defined as a comment rather than just nothing?

I dunno; this is a coding style glitch of mine. :P I will drop it.

Thanks for the review!

-Kees

> 
> > +#endif
> > +
> > +void ubsan_linkage __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
> > +void ubsan_linkage __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
> > +void ubsan_linkage __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
> > +void ubsan_linkage __ubsan_handle_negate_overflow(void *_data, void *old_val);
> > +void ubsan_linkage __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
> > +void ubsan_linkage __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
> > +void ubsan_linkage __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
> > +void ubsan_linkage __ubsan_handle_out_of_bounds(void *_data, void *index);
> > +void ubsan_linkage __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
> > +void ubsan_linkage __ubsan_handle_builtin_unreachable(void *_data);
> > +void ubsan_linkage __ubsan_handle_load_invalid_value(void *_data, void *val);
> > +void ubsan_linkage __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
> > +						       unsigned long align,
> > +						       unsigned long offset);
> >  
> >  #endif
> > -- 
> > 2.34.1
> > 
> > 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202404241530.A26FA3CC2%40keescook.
