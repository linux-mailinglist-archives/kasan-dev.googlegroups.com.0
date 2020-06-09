Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAF47X3AKGQEHBV5IDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C0F41F3780
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 12:01:38 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id z6sf9212470otq.8
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 03:01:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591696897; cv=pass;
        d=google.com; s=arc-20160816;
        b=DZOiAbZfGu09M9f2uHGwQLTi7L+t2TLVV1ImQuLm2MxumVUIrnIhJpyDBUEtweW0lQ
         cgioa2H7WskYK9I4OMmcUsA3a0LlOkAIn+J/C2rItI8I9B4v0yH0CHUrylFBCHTf/Toq
         8kjPuis54MnbX5YGIy6i/7PcLRzCj4ZPoP8eKYolG+VeELHhiq5Ufwe1eHdvcyWa7CDm
         9B3W6ikyGDxrtgJSf1g62uJDrM57eNfR7pQoQv2v+moc0QuCt/GMLMxCJwRZO+d1qekH
         VoIF+SN+/KQ9A59kqEFgC9V4RXfuSCg0C5DyYCUbKX/RfRu4wT+UxYykKndIB8+8AF7I
         uR3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=a7AIbYOjYf8Q60DJMfvWfvoWL5RqmXkgp6ta4W7/U5o=;
        b=IQzePVvRsHImMxmqOEauiIoZiI0b/hXkainhZhzqp5JVl7qZwPukHZDKV7yReK9lrM
         qoo2SgiyCOpYB4myZQRn1kWlL3PYYkG6xcSfpUfOoBxGJ71l0386Qhq8QxFS3F1BUk6+
         i+54RY+smUo12tlvJK7U/7TexF39BqtVOrSb7gbu+jDUtYkV/srNG86znH7jt09hviig
         LQndRo9YXMs560bvuxu0oMke7JRz7B4Z5cDNSuWMAXhkFB6oTX5MGQgr4iKOxmInOmTU
         UaiWZcYfXT7rs8MKwuNr0NqQv6zScDA47ptq9DL2b8hRA2y1YBEUaW13zyRpuDjWlO66
         tqDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SBJ51LPH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a7AIbYOjYf8Q60DJMfvWfvoWL5RqmXkgp6ta4W7/U5o=;
        b=TLTWANqGX38y6F8AY4QqTZFucVheaDBVQoSDParDSJaa6M5q5S6iKMnvuADu8D+Irv
         XBoIa8jjEJdCfN6YVRBkAEyJWyXW7RJmWXI0nIwhf93JMGiXiaxIFsanMl7BsRuEgbR+
         f8Yk+JtYAxBr/H5VFrcl413S+uV9OQ+Tu63MV744cn9b49UdBJSwu+l4J3qU4OnghSqF
         sY8Emk4Qj/X+oMaLosqzf5eOv0FHuR2EGZryU7uirKKJ4Ox24KRbPjag/5yPYcU8jAes
         9Eft39lezNdubhZD9Lg9DJEYjIIASrX82gNyhrczS3to7zQeE/PBTZO5TaTOoL52UvvU
         GtxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a7AIbYOjYf8Q60DJMfvWfvoWL5RqmXkgp6ta4W7/U5o=;
        b=h4cl8rxlD0kIhR1FirJic7yij8HAQ08GUX+Kpxrt0UbiakEF6yKwDVR/kKnYQQjxgS
         7k9lXNOEcnAMEqvPEy4t45ZFR5J+I+IzBdD2y/Wq5q2t47ZXx2VF+RHAHPPkQL21WoWl
         GsPsz9c1FbzCafsy4vvOe3qm1DZ6Y2swWAfgtbh9mZAM0iaL15XwnBmrJZUPL2dt8t/A
         DkbnC4j1nnz7nYYjEL0up04kAjI2FJ/TICfyE/wwyB8SN3ex7EEIp5ZdNtowfmYfy1w4
         7nLhm2UjxiapH/EUsgbm4rxIZFto6+L1lv1KP8v1ZjQQHY94xuD3xfTREoUSWG5bao+/
         VkXg==
X-Gm-Message-State: AOAM532YccIioXC2KEV7FRLP+eKr6d2CvtBHVUa6av92p4RVDZq8mETD
	xBsslV3z5V8CtuYJPPE3S2U=
X-Google-Smtp-Source: ABdhPJwa6DIzHP6rHDsfxdn/HWGw6KIpQbIkpcUHHiLurF2c+pzblDYP4WOIIt1Vcm0Ye6yntZFygA==
X-Received: by 2002:a4a:3811:: with SMTP id c17mr20151268ooa.91.1591696896932;
        Tue, 09 Jun 2020 03:01:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7051:: with SMTP id x17ls4173346otj.4.gmail; Tue, 09 Jun
 2020 03:01:36 -0700 (PDT)
X-Received: by 2002:a05:6830:118d:: with SMTP id u13mr8416756otq.323.1591696896596;
        Tue, 09 Jun 2020 03:01:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591696896; cv=none;
        d=google.com; s=arc-20160816;
        b=vBXXPejrANCQt+5zL97gTVvOlTPBKK9ZvmH0afbxyAeeiTH7owWvAPDvN/YAr2RGPq
         OVgMPUyu9NISQq9rapwJ70m5WalnYUpsuCnHOVg5pv5+y8DwTFWT4ZkJz1JSIQstfKmZ
         gPI3jLFv5qizyb8DnWhPprTwoHXzyHEeKnzo+YGXQapZxRjAnZDfaO96xRxXlGOC5ZMD
         bP/VQwPyL5d78FnzYLKbv1YhKn4E7Y4Mr9JnX4TDAWTsnIS2ysr7bPwYtrwFHzoWKIVG
         r8bVW6b1ewPzSi0JN+J6stR+OkDc60I69wYyhN1pwFccxwDthXGH9y7ZlpSYWtQjqi2n
         ptaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mPIilv60ROZjyaBUtEBoOUnRahe0YH6Jj785VbfhQH8=;
        b=Q7mnN4ej+VF3epLMnpdm7vDp7XU+UGT70AUmytgZSbjASKdpCJ07NaS85JyQO2FVpz
         pG93WSMm2sjA3AKZFXUX8RGtpPOrH3XiteHFb+OqQLfLhyikcSy+XkGdEL8AL60QpSx7
         gZan46fVcaf14OZOgY2dIIpaohyY8j0R0f/cwtKCXBL7PfS9oLCVxxO71+eeatD0yq+1
         9Kr5KtYOVWjFRCd9nU1a7lcFELkbGhwID5DMHJkgjz1EvyTfq+gPPUFzm3P21sqY1L+B
         ILcGuxLgmt+EX2peN6uFGSLQU94Ammk4XaMQJtHc400cQ2jNMiMxI6k0CVXwTem8ukRl
         2a1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SBJ51LPH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id z10si140456otj.3.2020.06.09.03.01.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 03:01:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id s13so16117349otd.7
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 03:01:36 -0700 (PDT)
X-Received: by 2002:a9d:27a3:: with SMTP id c32mr22206479otb.233.1591696895980;
 Tue, 09 Jun 2020 03:01:35 -0700 (PDT)
MIME-Version: 1.0
References: <20200609074834.215975-1-elver@google.com> <20200609095031.GY8462@tucnak>
In-Reply-To: <20200609095031.GY8462@tucnak>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Jun 2020 12:01:24 +0200
Message-ID: <CANpmjNMgyHEZYqa4nEhwT1wJ7RY6WyxPqJxJgHBqRuZkS=LcKw@mail.gmail.com>
Subject: Re: [PATCH v2] tsan: Add optional support for distinguishing volatiles
To: Jakub Jelinek <jakub@redhat.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>, =?UTF-8?Q?Martin_Li=C5=A1ka?= <mliska@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SBJ51LPH;       spf=pass
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

On Tue, 9 Jun 2020 at 11:50, Jakub Jelinek <jakub@redhat.com> wrote:
>
> On Tue, Jun 09, 2020 at 09:48:34AM +0200, Marco Elver wrote:
> > gcc/
> >       * params.opt: Define --param=tsan-distinguish-volatile=[0,1].
> >       * sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
> >       builtin for volatile instrumentation of reads/writes.
> >       (BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
> >       * tsan.c (get_memory_access_decl): Argument if access is
> >       volatile. If param tsan-distinguish-volatile is non-zero, and
> >       access if volatile, return volatile instrumentation decl.
> >       (instrument_expr): Check if access is volatile.
> >
> > gcc/testsuite/
> >       * c-c++-common/tsan/volatile.c: New test.
>
> In general looks ok, just some minor nits.
>
> > --- a/gcc/params.opt
> > +++ b/gcc/params.opt
> > @@ -908,6 +908,10 @@ Stop reverse growth if the reverse probability of best edge is less than this th
> >  Common Joined UInteger Var(param_tree_reassoc_width) Param Optimization
> >  Set the maximum number of instructions executed in parallel in reassociated tree.  If 0, use the target dependent heuristic.
> >
> > +-param=tsan-distinguish-volatile=
> > +Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRange(0, 1) Param Optimization
>
> Do we need/want Optimization here?  Optimization means the option is
> per-function, but to me whether you want to distinguish volatiles or not
> seems to be a global decision for the whole project.

Adding Optimization here was Martin's suggestion. I'm fine either way
and just wanted to err on the conservative side.

Do note that in the kernel, we blacklist some files from
instrumentation entirely, which implies leaving '-fsanitize=thread
--param=tsan-distinguish-volatile=1' off. Although given that the
option is only used with -fsanitize=thread, maybe it doesn't matter.

If you strongly feel that Optimization should be removed again, please
let me know.

> > +Emit special instrumentation for accesses to volatiles.
> > +
[...]
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile_write16",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>
> This last entry is already too long (line limit 80 chars), so should be
> wrapped like:
> DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16,
>                       "__tsan_volatile_write16", BT_FN_VOID_PTR,
>                       ATTR_NOTHROW_LEAF_LIST)
> instead.
>
> > --- a/gcc/tsan.c
> > +++ b/gcc/tsan.c
> > @@ -52,25 +52,41 @@ along with GCC; see the file COPYING3.  If not see
> >     void __tsan_read/writeX (void *addr);  */
> >
> >  static tree
> > -get_memory_access_decl (bool is_write, unsigned size)
> > +get_memory_access_decl (bool is_write, unsigned size, bool volatilep)
> >  {
> >    enum built_in_function fcode;
> >
> > -  if (size <= 1)
> > -    fcode = is_write ? BUILT_IN_TSAN_WRITE1
> > -                  : BUILT_IN_TSAN_READ1;
> > -  else if (size <= 3)
> > -    fcode = is_write ? BUILT_IN_TSAN_WRITE2
> > -                  : BUILT_IN_TSAN_READ2;
> > -  else if (size <= 7)
> > -    fcode = is_write ? BUILT_IN_TSAN_WRITE4
> > -                  : BUILT_IN_TSAN_READ4;
> > -  else if (size <= 15)
> > -    fcode = is_write ? BUILT_IN_TSAN_WRITE8
> > -                  : BUILT_IN_TSAN_READ8;
> > +  if (param_tsan_distinguish_volatile && volatilep)
> > +    {
> > +      if (size <= 1)
> > +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE1
> > +            : BUILT_IN_TSAN_VOLATILE_READ1;
> > +      else if (size <= 3)
> > +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE2
> > +            : BUILT_IN_TSAN_VOLATILE_READ2;
> > +      else if (size <= 7)
> > +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE4
> > +            : BUILT_IN_TSAN_VOLATILE_READ4;
> > +      else if (size <= 15)
> > +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE8
> > +            : BUILT_IN_TSAN_VOLATILE_READ8;
> > +      else
> > +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE16
> > +            : BUILT_IN_TSAN_VOLATILE_READ16;
> > +    }
> >    else
> > -    fcode = is_write ? BUILT_IN_TSAN_WRITE16
> > -                  : BUILT_IN_TSAN_READ16;
> > +    {
> > +      if (size <= 1)
> > +        fcode = is_write ? BUILT_IN_TSAN_WRITE1 : BUILT_IN_TSAN_READ1;
> > +      else if (size <= 3)
> > +        fcode = is_write ? BUILT_IN_TSAN_WRITE2 : BUILT_IN_TSAN_READ2;
> > +      else if (size <= 7)
> > +        fcode = is_write ? BUILT_IN_TSAN_WRITE4 : BUILT_IN_TSAN_READ4;
> > +      else if (size <= 15)
> > +        fcode = is_write ? BUILT_IN_TSAN_WRITE8 : BUILT_IN_TSAN_READ8;
> > +      else
> > +        fcode = is_write ? BUILT_IN_TSAN_WRITE16 : BUILT_IN_TSAN_READ16;
> > +    }
>
> The above gets too ugly.  Please use use instead:
>   enum built_in_function fcode;
>   int pos;
>   if (size <= 1)
>     pos = 0;
>   else if (size <= 3)
>     pos = 1;
>   else if (size <= 7)
>     pos = 2;
>   else if (size <= 15)
>     pos = 3;
>   else
>     pos = 4;
>   if (param_tsan_distinguish_volatile && volatilep)
>     fcode = (is_write ? BUILT_IN_TSAN_VOLATILE_WRITE1
>                       : BUILT_IN_TSAN_VOLATILE_READ1);
>   else
>     fcode = (is_write ? BUILT_IN_TSAN_WRITE1
>                       : BUILT_IN_TSAN_READ1);
>   fcode = (built_in_function) (fcode + pos);
>
> We have other code that already relies on certain *builtin*.def ranges being
> consecutive.
>
> > @@ -204,8 +220,11 @@ instrument_expr (gimple_stmt_iterator gsi, tree expr, bool is_write)
> >        g = gimple_build_call (builtin_decl, 2, expr_ptr, size_int (size));
> >      }
> >    else if (rhs == NULL)
> > -    g = gimple_build_call (get_memory_access_decl (is_write, size),
> > -                        1, expr_ptr);
> > +    {
> > +      builtin_decl = get_memory_access_decl (is_write, size,
> > +                                             TREE_THIS_VOLATILE(expr));
>
> Formatting, space between VOLATILE and (.
> And perhaps you don't need to use the builtin_decl temporary, just:
>     g = gimple_build_call (get_memory_access_decl (is_write, size,
>                                                    TREE_THIS_VOLATILE (expr)),
>                            1, expr_ptr);
> would be fine.  The reason to use the temporary in the other cases is that
> it gets too long and needs too much wrapping.
>
> Ok for trunk with those nits fixed.
>

Thanks for the quick review. I'll try to get v3 sent out later today/tomorrow.

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMgyHEZYqa4nEhwT1wJ7RY6WyxPqJxJgHBqRuZkS%3DLcKw%40mail.gmail.com.
