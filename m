Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEPKQXXAKGQEXNWU7AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E2A64EFDFF
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2019 14:11:47 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id 20sf16142483pfp.19
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2019 05:11:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572959506; cv=pass;
        d=google.com; s=arc-20160816;
        b=tC7JaKyBW+RcOJofIsfM7gFYoHpk44mlYeGm6GxaoP5W92V4stX2AtVV+HLOzT5O9+
         s+DppuSRz0okffK4OEjZoZe/6qcLll9lyb4saKQ+N8THzUMLU+EblENiodoRviPDsasG
         vr4R6+cptT6paTd9GIUKlNss2fbszxxgvSq6nAD8lTzJX9lz7tFK/KwkNbBug7kPIUzH
         KdNhy3BjaU9v8telxWQjYs8UtnpD5AgsypLZ/llnji6sAuB+tH4ZWrt+/3P19CklXsc1
         oMxne93l1eEwAuY3eGRX7d1Sw/5NUkDnfQxhP3QckXm6jRQ58LYhCX1WA10HfyoXj4rm
         K/5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jRHjnOufC+EjV/vq2voyRocbfsajdDZtPq2fUQAOTxE=;
        b=WmVaMLsU+ZNmyXTyE2AW4Nr38CuJ9d4NUp0Ic/vZTT1RzmURqqJPjy2orkEcLZgWHW
         EqMmIykwIxq4IzXunBSpiHpXnvBGupMwSZnQo437bZzI5wxnIpY8g9BQuDrhkZU2eWF8
         I4jNIWA10yDpj9EQ4mjmID4cFMxbvhx9rCQQPzO/+F4CK6GYz58wVQ/lrPSJdeMV21lq
         5bw3D0/+YyCXO0j79oyI+E7EJ4QrMvRSqwk6gGLSLLesMlq3SOgdNLDRAORBgTfZapPN
         /d28aqFD5ycgzF6A52zo/kx8x2GBr1I2vJkHH0dR/ypZCfS0ePi25NI12ZNe+n4QhSwZ
         eU6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p4YWYjuS;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jRHjnOufC+EjV/vq2voyRocbfsajdDZtPq2fUQAOTxE=;
        b=pvLPGXRQL7JAkv2MKEIbJfvwzxitgxEDdC1BhDiVXpTA8kL5L/w341WMCxJM46rdCs
         De1niuFt1u1SnI4x6B2BLAFwPV5EibLsyDCr8Z+mI/8kGPY7ECSxeV2zjAp9A0WOfPKn
         aba9I+2urMmGx2/Uuto/KJS6xotwyaiMGmTGr8vdiAyORQ6hV+mjVdOsywRu3YjzcamU
         Z+rGe+L2LMDLHIOsyqCJQe73d0O10q2MecyPGCq/w84TMPWucXd6QHp1cBantz8CFdkS
         KIo/YYGRGUP+16ZHZKTTLlmXGxDX0xJIho9/XcOSyjNGYfdSGS+XS6weV/3zsqpsqytd
         fT2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jRHjnOufC+EjV/vq2voyRocbfsajdDZtPq2fUQAOTxE=;
        b=Aws0K7LwvxvTKFwDFekZsbnkoJNQLR2YgDLC0kvBMb5zElN2qsXuePUQ0+BQecSeMA
         Bu2k0eNgkFBYxaC4vto0iIaRrMFmO6xdR8t7rbmJaXXxs/rRv5k63XupaUGEtCNwlFR4
         q4sshzNpr29ZPOew4WJFQvFWTZQ+CIkJB3dIm2Fi9YJUqpTo4oRDCQR4vzWu1WxyH8PZ
         tEO2DyCScLZKFjCrLvNqMCS4yPmn8BMooCaJv9KOFuo/8I4IOIRxXpAhWqVMZiPVpfMf
         cmTjTMsyhoqtV1zPnM+x/y/+XNRg3T7oaA9IBTypBiGbRa553MKNZFTA/tMh+Tb/pgyr
         KAiw==
X-Gm-Message-State: APjAAAWNm1Mr3jBEdLFexnltuN53L8QEFHD/tjJVWwVP/n9IkRBEK6T0
	T1mTXGhj9neZRk/ImrbJrtM=
X-Google-Smtp-Source: APXvYqxy0C78Bw934jrpeXHZTlIdTA+ZpV0cld1A1/feFo7LLEaKIMu/vvxdqk6kMn+IW568UkY9eQ==
X-Received: by 2002:a63:7c18:: with SMTP id x24mr35101196pgc.390.1572959505980;
        Tue, 05 Nov 2019 05:11:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8dc2:: with SMTP id j2ls4340707pfr.8.gmail; Tue, 05 Nov
 2019 05:11:45 -0800 (PST)
X-Received: by 2002:a63:1b41:: with SMTP id b1mr36740905pgm.335.1572959505491;
        Tue, 05 Nov 2019 05:11:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572959505; cv=none;
        d=google.com; s=arc-20160816;
        b=wFpnYIROVrtJLe2L8VEkDJeXzVCe7prw9BShaOdInEl1OT6SzZu0GlWRhLp0zUxb23
         b/4mDuyacTMNB6n8QpB7NhcAvTAw2G0wiyjjutVMMa1mKo6LR99tZLITaraNs1lWGElG
         +7k378Ze4J+TDM0qO+TgSbOWu285Yylu2iEZJLyTkmvaVVdCalrK/5fVCRuQ7aI3pjUS
         TQKC6c57UsFWs7eAOd3Z51nhLIKbXtLddkXS5NU0hAlrsxmx7U7ShPYBwjuh9WOn1GCr
         zzLUecrvA0YEWZraoxM4WuXXdIsjT+rFHEKRbpu/f+MQs/Re+z8yNNUoRd33jzhLVARr
         6krg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jFDls01ZGu9Dh9stupeFWMj93mXXEPW2J/EvuD8cgkQ=;
        b=H8YJQlD4VaeyMgk6Lc+7CavDwrcikzbsG3ZUel04y/2Vby8mFGEUh7bMxv5ImuhlIa
         NKTajUIXq8HrwJ63tWcsBGJgafX2AQ+b6wT2vYy4O54vWocjsMMlEAncjbSPSL4GD4IJ
         LpaToikfSVL4DSn4ZvBhKgEy7kBLci8814EKrRIhMjMyFwsF0IAcWdTn747YdZekac8K
         Jw1mlf4aloRFsl8MOW9zFk8uasp+5s3aq8wbFf+pww4S4UR6x4JNGzjjltaAaBuGCLSG
         VfShi1AK7/rONydhcIVWZIwlbUSa9RGkBebuy8Oz/mLf/ckTZBRB5lOadkw7fsEzQNjK
         0B3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p4YWYjuS;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id 83si1000055pfx.4.2019.11.05.05.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2019 05:11:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id q22so6535487pgk.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2019 05:11:45 -0800 (PST)
X-Received: by 2002:a63:541e:: with SMTP id i30mr36373738pgb.130.1572959504330;
 Tue, 05 Nov 2019 05:11:44 -0800 (PST)
MIME-Version: 1.0
References: <157295142743.27946.1142544630216676787.scripted-patch-series@arm.com>
 <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
In-Reply-To: <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2019 14:11:33 +0100
Message-ID: <CAAeHK+wcYBtNn_ST7L2yEz2Zwge38UGCWthOKuepn3zQ90gZww@mail.gmail.com>
Subject: Re: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and
 argument parsing
To: Matthew Malcomson <Matthew.Malcomson@arm.com>, "kcc@google.com" <kcc@google.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, Evgenii Stepanov <eugenis@google.com>
Cc: "gcc-patches@gcc.gnu.org" <gcc-patches@gcc.gnu.org>, nd <nd@arm.com>, Martin Liska <mliska@suse.cz>, 
	Richard Earnshaw <Richard.Earnshaw@arm.com>, Kyrylo Tkachov <Kyrylo.Tkachov@arm.com>, 
	"dodji@redhat.com" <dodji@redhat.com>, "jakub@redhat.com" <jakub@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p4YWYjuS;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
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

On Tue, Nov 5, 2019 at 12:34 PM Matthew Malcomson
<Matthew.Malcomson@arm.com> wrote:
>
> These flags can't be used at the same time as any of the other
> sanitizers.
> We add an equivalent flag to -static-libasan in -static-libhwasan to
> ensure static linking.
>
> The -fsanitize=3Dkernel-hwaddress option is for compiling targeting the
> kernel.  This flag has defaults that allow compiling KASAN with tags as
> it is currently implemented.
> These defaults are that we do not sanitize variables on the stack and
> always recover from a detected bug.
> Stack tagging in the kernel is a future aim, stack instrumentation has
> not yet been enabled for the kernel for clang either
> (https://lists.infradead.org/pipermail/linux-arm-kernel/2019-October/6871=
21.html).
>
> We introduce a backend hook `targetm.memtag.can_tag_addresses` that
> indicates to the mid-end whether a target has a feature like AArch64 TBI
> where the top byte of an address is ignored.
> Without this feature hwasan sanitization is not done.
>
> NOTE:
> ------
> I have defined a new macro of __SANITIZE_HWADDRESS__ that gets
> automatically defined when compiling with hwasan.  This is analogous to
> __SANITIZE_ADDRESS__ which is defined when compiling with asan.
>
> Users in the kernel have expressed an interest in using
> __SANITIZE_ADDRESS__ for both
> (https://lists.infradead.org/pipermail/linux-arm-kernel/2019-October/6907=
03.html).
>
> One approach to do this could be to define __SANITIZE_ADDRESS__ with
> different values depending on whether we are compiling with hwasan or
> asan.
>
> Using __SANITIZE_ADDRESS__ for both means that code like the kernel
> which wants to treat the two sanitizers as alternate implementations of
> the same thing gets that automatically.
>
> My preference is to use __SANITIZE_HWADDRESS__ since that means any
> existing code will not be predicated on this (and hence I guess less
> surprises), but would appreciate feedback on this given the point above.

+Evgenii Stepanov

(A repost from my answer from the mentioned thread):

> Similarly, I'm thinking I'll add no_sanitize_hwaddress as the hwasan
> equivalent of no_sanitize_address, which will require an update in the
> kernel given it seems you want KASAN to be used the same whether using
> tags or not.

We have intentionally reused the same macros to simplify things. Is
there any reason to use separate macros for GCC? Are there places
where we need to use specifically no_sanitize_hwaddress and
__SANITIZE_HWADDRESS__, but not no_sanitize_address and
__SANITIZE_ADDRESS__?


> ------
>
> gcc/ChangeLog:
>
> 2019-11-05  Matthew Malcomson  <matthew.malcomson@arm.com>
>
>         * asan.c (memory_tagging_p): New.
>         * asan.h (memory_tagging_p): New.
>         * common.opt (flag_sanitize_recover): Default for kernel
>         hwaddress.
>         (static-libhwasan): New cli option.
>         * config/aarch64/aarch64.c (aarch64_can_tag_addresses): New.
>         (TARGET_MEMTAG_CAN_TAG_ADDRESSES): New.
>         * config/gnu-user.h (LIBHWASAN_EARLY_SPEC): hwasan equivalent of
>         asan command line flags.
>         * cppbuiltin.c (define_builtin_macros_for_compilation_flags):
>         Add hwasan equivalent of __SANITIZE_ADDRESS__.
>         * doc/tm.texi: Document new hook.
>         * doc/tm.texi.in: Document new hook.
>         * flag-types.h (enum sanitize_code): New sanitizer values.
>         * gcc.c (STATIC_LIBHWASAN_LIBS): New macro.
>         (LIBHWASAN_SPEC): New macro.
>         (LIBHWASAN_EARLY_SPEC): New macro.
>         (SANITIZER_EARLY_SPEC): Update to include hwasan.
>         (SANITIZER_SPEC): Update to include hwasan.
>         (sanitize_spec_function): Use hwasan options.
>         * opts.c (finish_options): Describe conflicts between address
>         sanitizers.
>         (sanitizer_opts): Introduce new sanitizer flags.
>         (common_handle_option): Add defaults for kernel sanitizer.
>         * params.def (PARAM_HWASAN_RANDOM_FRAME_TAG): New.
>         (PARAM_HWASAN_STACK): New.
>         * params.h (HWASAN_STACK): New.
>         (HWASAN_RANDOM_FRAME_TAG): New.
>         * target.def (HOOK_PREFIX): Add new hook.
>         * targhooks.c (default_memtag_can_tag_addresses): New.
>         * toplev.c (process_options): Ensure hwasan only on TBI
>         architectures.
>
> gcc/c-family/ChangeLog:
>
> 2019-11-05  Matthew Malcomson  <matthew.malcomson@arm.com>
>
>         * c-attribs.c (handle_no_sanitize_hwaddress_attribute): New
>         attribute.
>
>
>
> ###############     Attachment also inlined for ease of reply    ########=
#######
>
>
> diff --git a/gcc/c-family/c-attribs.c b/gcc/c-family/c-attribs.c
> index 6500b998321419a1d8d57062534206c5909adb7a..2de94815f91da5a0fd06c30d0=
044f866084121b8 100644
> --- a/gcc/c-family/c-attribs.c
> +++ b/gcc/c-family/c-attribs.c
> @@ -54,6 +54,8 @@ static tree handle_cold_attribute (tree *, tree, tree, =
int, bool *);
>  static tree handle_no_sanitize_attribute (tree *, tree, tree, int, bool =
*);
>  static tree handle_no_sanitize_address_attribute (tree *, tree, tree,
>                                                   int, bool *);
> +static tree handle_no_sanitize_hwaddress_attribute (tree *, tree, tree,
> +                                                   int, bool *);
>  static tree handle_no_sanitize_thread_attribute (tree *, tree, tree,
>                                                  int, bool *);
>  static tree handle_no_address_safety_analysis_attribute (tree *, tree, t=
ree,
> @@ -410,6 +412,8 @@ const struct attribute_spec c_common_attribute_table[=
] =3D
>                               handle_no_sanitize_attribute, NULL },
>    { "no_sanitize_address",    0, 0, true, false, false, false,
>                               handle_no_sanitize_address_attribute, NULL =
},
> +  { "no_sanitize_hwaddress",    0, 0, true, false, false, false,
> +                             handle_no_sanitize_hwaddress_attribute, NUL=
L },
>    { "no_sanitize_thread",     0, 0, true, false, false, false,
>                               handle_no_sanitize_thread_attribute, NULL }=
,
>    { "no_sanitize_undefined",  0, 0, true, false, false, false,
> @@ -929,6 +933,22 @@ handle_no_sanitize_address_attribute (tree *node, tr=
ee name, tree, int,
>    return NULL_TREE;
>  }
>
> +/* Handle a "no_sanitize_hwaddress" attribute; arguments as in
> +   struct attribute_spec.handler.  */
> +
> +static tree
> +handle_no_sanitize_hwaddress_attribute (tree *node, tree name, tree, int=
,
> +                                     bool *no_add_attrs)
> +{
> +  *no_add_attrs =3D true;
> +  if (TREE_CODE (*node) !=3D FUNCTION_DECL)
> +    warning (OPT_Wattributes, "%qE attribute ignored", name);
> +  else
> +    add_no_sanitize_value (*node, SANITIZE_HWADDRESS);
> +
> +  return NULL_TREE;
> +}
> +
>  /* Handle a "no_sanitize_thread" attribute; arguments as in
>     struct attribute_spec.handler.  */
>
> diff --git a/gcc/common.opt b/gcc/common.opt
> index 1b9e0f3c8025a3b439f766edcd81db462973037b..d8ba9556801e5afc479c33ba3=
59125d6354ca862 100644
> --- a/gcc/common.opt
> +++ b/gcc/common.opt
> @@ -215,7 +215,7 @@ unsigned int flag_sanitize
>
>  ; What sanitizers should recover from errors
>  Variable
> -unsigned int flag_sanitize_recover =3D (SANITIZE_UNDEFINED | SANITIZE_UN=
DEFINED_NONDEFAULT | SANITIZE_KERNEL_ADDRESS) & ~(SANITIZE_UNREACHABLE | SA=
NITIZE_RETURN)
> +unsigned int flag_sanitize_recover =3D (SANITIZE_UNDEFINED | SANITIZE_UN=
DEFINED_NONDEFAULT | SANITIZE_KERNEL_ADDRESS | SANITIZE_KERNEL_HWADDRESS) &=
 ~(SANITIZE_UNREACHABLE | SANITIZE_RETURN)
>
>  ; What the coverage sanitizers should instrument
>  Variable
> @@ -3289,6 +3289,9 @@ Driver
>  static-libasan
>  Driver
>
> +static-libhwasan
> +Driver
> +
>  static-libtsan
>  Driver
>
> diff --git a/gcc/config/aarch64/aarch64.c b/gcc/config/aarch64/aarch64.c
> index 232317d4a5a4a16529f573eef5a8d7a068068207..c556bcd1c37c3c4fdd9a829a2=
8ee4ff56819b89e 100644
> --- a/gcc/config/aarch64/aarch64.c
> +++ b/gcc/config/aarch64/aarch64.c
> @@ -20272,6 +20272,15 @@ aarch64_stack_protect_guard (void)
>    return NULL_TREE;
>  }
>
> +/* Implement TARGET_MEMTAG_CAN_TAG_ADDRESSES.  Here we tell the rest of =
the
> +   compiler that we automatically ignore the top byte of our pointers, w=
hich
> +   allows using -fsanitize=3Dhwaddress.  */
> +bool
> +aarch64_can_tag_addresses ()
> +{
> +  return true;
> +}
> +
>  /* Implement TARGET_ASM_FILE_END for AArch64.  This adds the AArch64 GNU=
 NOTE
>     section at the end if needed.  */
>  #define GNU_PROPERTY_AARCH64_FEATURE_1_AND     0xc0000000
> @@ -20839,6 +20848,9 @@ aarch64_libgcc_floating_mode_supported_p
>  #undef TARGET_GET_MULTILIB_ABI_NAME
>  #define TARGET_GET_MULTILIB_ABI_NAME aarch64_get_multilib_abi_name
>
> +#undef TARGET_MEMTAG_CAN_TAG_ADDRESSES
> +#define TARGET_MEMTAG_CAN_TAG_ADDRESSES aarch64_can_tag_addresses
> +
>  #if CHECKING_P
>  #undef TARGET_RUN_TARGET_SELFTESTS
>  #define TARGET_RUN_TARGET_SELFTESTS selftest::aarch64_run_selftests
> diff --git a/gcc/config/gnu-user.h b/gcc/config/gnu-user.h
> index 95a3c29f7cee86336f958bef1d7fe56b82e05e6c..90b1fa91742c6a7d76aa6c7e9=
31f8014fc4fff0c 100644
> --- a/gcc/config/gnu-user.h
> +++ b/gcc/config/gnu-user.h
> @@ -129,14 +129,18 @@ see the files COPYING3 and COPYING.RUNTIME respecti=
vely.  If not, see
>  /* Link -lasan early on the command line.  For -static-libasan, don't li=
nk
>     it for -shared link, the executable should be compiled with -static-l=
ibasan
>     in that case, and for executable link with --{,no-}whole-archive arou=
nd
> -   it to force everything into the executable.  And similarly for -ltsan
> -   and -llsan.  */
> +   it to force everything into the executable.  And similarly for -ltsan=
,
> +   -lhwasan, and -llsan.  */
>  #if defined(HAVE_LD_STATIC_DYNAMIC)
>  #undef LIBASAN_EARLY_SPEC
>  #define LIBASAN_EARLY_SPEC "%{!shared:libasan_preinit%O%s} " \
>    "%{static-libasan:%{!shared:" \
>    LD_STATIC_OPTION " --whole-archive -lasan --no-whole-archive " \
>    LD_DYNAMIC_OPTION "}}%{!static-libasan:-lasan}"
> +#undef LIBHWASAN_EARLY_SPEC
> +#define LIBHWASAN_EARLY_SPEC "%{static-libhwasan:%{!shared:" \
> +  LD_STATIC_OPTION " --whole-archive -lhwasan --no-whole-archive " \
> +  LD_DYNAMIC_OPTION "}}%{!static-libhwasan:-lhwasan}"
>  #undef LIBTSAN_EARLY_SPEC
>  #define LIBTSAN_EARLY_SPEC "%{!shared:libtsan_preinit%O%s} " \
>    "%{static-libtsan:%{!shared:" \
> diff --git a/gcc/cppbuiltin.c b/gcc/cppbuiltin.c
> index 60e5bedc3665a25fa51c2eca00547f12a9953778..e8d0bedfc2eb22d1e72e7e487=
5155202c8389a38 100644
> --- a/gcc/cppbuiltin.c
> +++ b/gcc/cppbuiltin.c
> @@ -93,6 +93,9 @@ define_builtin_macros_for_compilation_flags (cpp_reader=
 *pfile)
>    if (flag_sanitize & SANITIZE_ADDRESS)
>      cpp_define (pfile, "__SANITIZE_ADDRESS__");
>
> +  if (flag_sanitize & SANITIZE_HWADDRESS)
> +    cpp_define (pfile, "__SANITIZE_HWADDRESS__");
> +
>    if (flag_sanitize & SANITIZE_THREAD)
>      cpp_define (pfile, "__SANITIZE_THREAD__");
>
> diff --git a/gcc/doc/tm.texi b/gcc/doc/tm.texi
> index 0250cf58e72b4df8fec19cfb4399ed0e2594342b..bf53df715391128d6fbe9be4e=
77906650309ab2e 100644
> --- a/gcc/doc/tm.texi
> +++ b/gcc/doc/tm.texi
> @@ -2972,6 +2972,10 @@ This hook defines the machine mode to use for the =
boolean result of  conditional
>  A target hook which lets a backend compute the set of pressure classes t=
o  be used by those optimization passes which take register pressure into  =
account, as opposed to letting IRA compute them.  It returns the number of =
 register classes stored in the array @var{pressure_classes}.
>  @end deftypefn
>
> +@deftypefn {Target Hook} bool TARGET_MEMTAG_CAN_TAG_ADDRESSES ()
> +True if backend architecture naturally supports ignoring the top byte of=
 pointers.  This feature means that -fsanitize=3Dhwaddress can work.
> +@end deftypefn
> +
>  @node Stack and Calling
>  @section Stack Layout and Calling Conventions
>  @cindex calling conventions
> diff --git a/gcc/doc/tm.texi.in b/gcc/doc/tm.texi.in
> index 0b77dd8eb46dc53fc585d7b3eac9805c6ed79951..005cef05999d7c334f16ffa36=
8903c3b66806231 100644
> --- a/gcc/doc/tm.texi.in
> +++ b/gcc/doc/tm.texi.in
> @@ -2374,6 +2374,8 @@ in the reload pass.
>
>  @hook TARGET_COMPUTE_PRESSURE_CLASSES
>
> +@hook TARGET_MEMTAG_CAN_TAG_ADDRESSES
> +
>  @node Stack and Calling
>  @section Stack Layout and Calling Conventions
>  @cindex calling conventions
> diff --git a/gcc/flag-types.h b/gcc/flag-types.h
> index a2103282d469db31ad157a87572068d943061c8c..57d8ff9a1a010409d96623014=
0df1017bc3584a8 100644
> --- a/gcc/flag-types.h
> +++ b/gcc/flag-types.h
> @@ -256,6 +256,9 @@ enum sanitize_code {
>    SANITIZE_BUILTIN =3D 1UL << 25,
>    SANITIZE_POINTER_COMPARE =3D 1UL << 26,
>    SANITIZE_POINTER_SUBTRACT =3D 1UL << 27,
> +  SANITIZE_HWADDRESS =3D 1UL << 28,
> +  SANITIZE_USER_HWADDRESS =3D 1UL << 29,
> +  SANITIZE_KERNEL_HWADDRESS =3D 1UL << 30,
>    SANITIZE_SHIFT =3D SANITIZE_SHIFT_BASE | SANITIZE_SHIFT_EXPONENT,
>    SANITIZE_UNDEFINED =3D SANITIZE_SHIFT | SANITIZE_DIVIDE | SANITIZE_UNR=
EACHABLE
>                        | SANITIZE_VLA | SANITIZE_NULL | SANITIZE_RETURN
> diff --git a/gcc/gcc.c b/gcc/gcc.c
> index 1216cdd505a18152dc1d3eee5f37755a396761f1..cf1bd9de660f32f060b9277f8=
9a562873a48684a 100644
> --- a/gcc/gcc.c
> +++ b/gcc/gcc.c
> @@ -708,6 +708,24 @@ proper position among the other output files.  */
>  #define LIBASAN_EARLY_SPEC ""
>  #endif
>
> +#ifndef LIBHWASAN_SPEC
> +#define STATIC_LIBHWASAN_LIBS \
> +  " %{static-libhwasan|static:%:include(libsanitizer.spec)%(link_libhwas=
an)}"
> +#ifdef LIBHWASAN_EARLY_SPEC
> +#define LIBHWASAN_SPEC STATIC_LIBHWASAN_LIBS
> +#elif defined(HAVE_LD_STATIC_DYNAMIC)
> +#define LIBHWASAN_SPEC "%{static-libhwasan:" LD_STATIC_OPTION \
> +                    "} -lhwasan %{static-libhwasan:" LD_DYNAMIC_OPTION "=
}" \
> +                    STATIC_LIBHWASAN_LIBS
> +#else
> +#define LIBHWASAN_SPEC "-lhwasan" STATIC_LIBHWASAN_LIBS
> +#endif
> +#endif
> +
> +#ifndef LIBHWASAN_EARLY_SPEC
> +#define LIBHWASAN_EARLY_SPEC ""
> +#endif
> +
>  #ifndef LIBTSAN_SPEC
>  #define STATIC_LIBTSAN_LIBS \
>    " %{static-libtsan|static:%:include(libsanitizer.spec)%(link_libtsan)}=
"
> @@ -982,6 +1000,7 @@ proper position among the other output files.  */
>  #ifndef SANITIZER_EARLY_SPEC
>  #define SANITIZER_EARLY_SPEC "\
>  %{!nostdlib:%{!r:%{!nodefaultlibs:%{%:sanitize(address):" LIBASAN_EARLY_=
SPEC "} \
> +    %{%:sanitize(hwaddress):" LIBHWASAN_EARLY_SPEC "} \
>      %{%:sanitize(thread):" LIBTSAN_EARLY_SPEC "} \
>      %{%:sanitize(leak):" LIBLSAN_EARLY_SPEC "}}}}"
>  #endif
> @@ -991,6 +1010,8 @@ proper position among the other output files.  */
>  #define SANITIZER_SPEC "\
>  %{!nostdlib:%{!r:%{!nodefaultlibs:%{%:sanitize(address):" LIBASAN_SPEC "=
\
>      %{static:%ecannot specify -static with -fsanitize=3Daddress}}\
> +    %{%:sanitize(hwaddress):" LIBHWASAN_SPEC "\
> +       %{static:%ecannot specify -static with -fsanitize=3Dhwaddress}}\
>      %{%:sanitize(thread):" LIBTSAN_SPEC "\
>      %{static:%ecannot specify -static with -fsanitize=3Dthread}}\
>      %{%:sanitize(undefined):" LIBUBSAN_SPEC "}\
> @@ -9434,8 +9455,12 @@ sanitize_spec_function (int argc, const char **arg=
v)
>
>    if (strcmp (argv[0], "address") =3D=3D 0)
>      return (flag_sanitize & SANITIZE_USER_ADDRESS) ? "" : NULL;
> +  if (strcmp (argv[0], "hwaddress") =3D=3D 0)
> +    return (flag_sanitize & SANITIZE_USER_HWADDRESS) ? "" : NULL;
>    if (strcmp (argv[0], "kernel-address") =3D=3D 0)
>      return (flag_sanitize & SANITIZE_KERNEL_ADDRESS) ? "" : NULL;
> +  if (strcmp (argv[0], "kernel-hwaddress") =3D=3D 0)
> +    return (flag_sanitize & SANITIZE_KERNEL_HWADDRESS) ? "" : NULL;
>    if (strcmp (argv[0], "thread") =3D=3D 0)
>      return (flag_sanitize & SANITIZE_THREAD) ? "" : NULL;
>    if (strcmp (argv[0], "undefined") =3D=3D 0)
> diff --git a/gcc/opts.c b/gcc/opts.c
> index efd75aade6c879f330db1aa7b8ef6b9100862c04..88a94286e71f61f2dce907018=
e5185f63a830804 100644
> --- a/gcc/opts.c
> +++ b/gcc/opts.c
> @@ -1160,6 +1160,13 @@ finish_options (struct gcc_options *opts, struct g=
cc_options *opts_set,
>                   "%<-fsanitize=3Daddress%> or %<-fsanitize=3Dkernel-addr=
ess%>");
>      }
>
> +  /* Userspace and kernel HWasan conflict with each other.  */
> +  if ((opts->x_flag_sanitize & SANITIZE_USER_HWADDRESS)
> +      && (opts->x_flag_sanitize & SANITIZE_KERNEL_HWADDRESS))
> +    error_at (loc,
> +             "%<-fsanitize=3Dhwaddress%> is incompatible with "
> +             "%<-fsanitize=3Dkernel-hwaddress%>");
> +
>    /* Userspace and kernel ASan conflict with each other.  */
>    if ((opts->x_flag_sanitize & SANITIZE_USER_ADDRESS)
>        && (opts->x_flag_sanitize & SANITIZE_KERNEL_ADDRESS))
> @@ -1179,6 +1186,20 @@ finish_options (struct gcc_options *opts, struct g=
cc_options *opts_set,
>      error_at (loc,
>               "%<-fsanitize=3Dleak%> is incompatible with %<-fsanitize=3D=
thread%>");
>
> +  /* HWASan and ASan conflict with each other.  */
> +  if ((opts->x_flag_sanitize & SANITIZE_ADDRESS)
> +      && (opts->x_flag_sanitize & SANITIZE_HWADDRESS))
> +    error_at (loc,
> +             "%<-fsanitize=3Dhwaddress%> is incompatible with both "
> +             "%<-fsanitize=3Daddress%> and %<-fsanitize=3Dkernel-address=
%>");
> +
> +  /* HWASan conflicts with TSan.  */
> +  if ((opts->x_flag_sanitize & SANITIZE_HWADDRESS)
> +      && (opts->x_flag_sanitize & SANITIZE_THREAD))
> +    error_at (loc,
> +             "%<-fsanitize=3Dhwaddress%> is incompatible with "
> +             "%<-fsanitize=3Dthread%>");
> +
>    /* Check error recovery for -fsanitize-recover option.  */
>    for (int i =3D 0; sanitizer_opts[i].name !=3D NULL; ++i)
>      if ((opts->x_flag_sanitize_recover & sanitizer_opts[i].flag)
> @@ -1198,7 +1219,8 @@ finish_options (struct gcc_options *opts, struct gc=
c_options *opts_set,
>
>    /* Enable -fsanitize-address-use-after-scope if address sanitizer is
>       enabled.  */
> -  if ((opts->x_flag_sanitize & SANITIZE_USER_ADDRESS)
> +  if (((opts->x_flag_sanitize & SANITIZE_USER_ADDRESS)
> +       || (opts->x_flag_sanitize & SANITIZE_USER_HWADDRESS))
>        && !opts_set->x_flag_sanitize_address_use_after_scope)
>      opts->x_flag_sanitize_address_use_after_scope =3D true;
>
> @@ -1827,8 +1849,13 @@ const struct sanitizer_opts_s sanitizer_opts[] =3D
>  #define SANITIZER_OPT(name, flags, recover) \
>      { #name, flags, sizeof #name - 1, recover }
>    SANITIZER_OPT (address, (SANITIZE_ADDRESS | SANITIZE_USER_ADDRESS), tr=
ue),
> +  SANITIZER_OPT (hwaddress, (SANITIZE_HWADDRESS | SANITIZE_USER_HWADDRES=
S),
> +                true),
>    SANITIZER_OPT (kernel-address, (SANITIZE_ADDRESS | SANITIZE_KERNEL_ADD=
RESS),
>                  true),
> +  SANITIZER_OPT (kernel-hwaddress,
> +                (SANITIZE_HWADDRESS | SANITIZE_KERNEL_HWADDRESS),
> +                true),
>    SANITIZER_OPT (pointer-compare, SANITIZE_POINTER_COMPARE, true),
>    SANITIZER_OPT (pointer-subtract, SANITIZE_POINTER_SUBTRACT, true),
>    SANITIZER_OPT (thread, SANITIZE_THREAD, false),
> @@ -2363,6 +2390,14 @@ common_handle_option (struct gcc_options *opts,
>                                  opts->x_param_values,
>                                  opts_set->x_param_values);
>         }
> +      if (opts->x_flag_sanitize & SANITIZE_KERNEL_HWADDRESS)
> +       {
> +         maybe_set_param_value (PARAM_HWASAN_STACK, 0, opts->x_param_val=
ues,
> +                                opts_set->x_param_values);
> +         maybe_set_param_value (PARAM_HWASAN_RANDOM_FRAME_TAG, 0,
> +                                opts->x_param_values,
> +                                opts_set->x_param_values);
> +       }
>        break;
>
>      case OPT_fsanitize_recover_:
> diff --git a/gcc/params.def b/gcc/params.def
> index 5fe33976b37bb0763986040f66a9c28681363535..a4b3f02b60898f54aeec40238=
ad417e423f56e01 100644
> --- a/gcc/params.def
> +++ b/gcc/params.def
> @@ -1299,6 +1299,17 @@ DEFPARAM (PARAM_USE_AFTER_SCOPE_DIRECT_EMISSION_TH=
RESHOLD,
>          "smaller or equal to this number.",
>          256, 0, INT_MAX)
>
> +/* HWAsan stands for HardwareAddressSanitizer: https://github.com/google=
/sanitizers.  */
> +DEFPARAM (PARAM_HWASAN_RANDOM_FRAME_TAG,
> +         "hwasan-random-frame-tag",
> +         "Use random base tag for each frame, as opposed to base always =
zero.",
> +         1, 0, 1)
> +
> +DEFPARAM (PARAM_HWASAN_STACK,
> +         "hwasan-stack",
> +         "Enable hwasan stack protection.",
> +         1, 0, 1)
> +
>  DEFPARAM (PARAM_UNINIT_CONTROL_DEP_ATTEMPTS,
>           "uninit-control-dep-attempts",
>           "Maximum number of nested calls to search for control dependenc=
ies "
> diff --git a/gcc/params.h b/gcc/params.h
> index 26f1236aa65422f66939ef2a4c38958bdc984aee..ad40bd0b5d3b217e6d0dc531f=
ce04faba97b5f60 100644
> --- a/gcc/params.h
> +++ b/gcc/params.h
> @@ -252,5 +252,9 @@ extern void init_param_values (int *params);
>    PARAM_VALUE (PARAM_ASAN_INSTRUMENTATION_WITH_CALL_THRESHOLD)
>  #define ASAN_PARAM_USE_AFTER_SCOPE_DIRECT_EMISSION_THRESHOLD \
>    ((unsigned) PARAM_VALUE (PARAM_USE_AFTER_SCOPE_DIRECT_EMISSION_THRESHO=
LD))
> +#define HWASAN_STACK \
> +  PARAM_VALUE (PARAM_HWASAN_STACK)
> +#define HWASAN_RANDOM_FRAME_TAG \
> +  PARAM_VALUE (PARAM_HWASAN_RANDOM_FRAME_TAG)
>
>  #endif /* ! GCC_PARAMS_H */
> diff --git a/gcc/target.def b/gcc/target.def
> index 01609136848fc157a47a93a0267c03524fe9383e..0ade31accab25bf121f135cbf=
02c6adfcd6e1476 100644
> --- a/gcc/target.def
> +++ b/gcc/target.def
> @@ -6706,6 +6706,17 @@ DEFHOOK
>  HOOK_VECTOR_END (mode_switching)
>
>  #undef HOOK_PREFIX
> +#define HOOK_PREFIX "TARGET_MEMTAG_"
> +HOOK_VECTOR (TARGET_MEMTAG_, memtag)
> +
> +DEFHOOK
> +(can_tag_addresses,
> + "True if backend architecture naturally supports ignoring the top byte =
of\
> + pointers.  This feature means that -fsanitize=3Dhwaddress can work.",
> + bool, (), default_memtag_can_tag_addresses)
> +
> +HOOK_VECTOR_END (memtag)
> +#undef HOOK_PREFIX
>  #define HOOK_PREFIX "TARGET_"
>
>  #define DEF_TARGET_INSN(NAME, PROTO) \
> diff --git a/gcc/targhooks.h b/gcc/targhooks.h
> index 5aba67660f85406b9fd475e75a3cc65b0d1952f5..463c27c7d7b550bf63630f210=
2681b37ffd265cb 100644
> --- a/gcc/targhooks.h
> +++ b/gcc/targhooks.h
> @@ -284,4 +284,5 @@ extern rtx default_speculation_safe_value (machine_mo=
de, rtx, rtx, rtx);
>  extern void default_remove_extra_call_preserved_regs (rtx_insn *,
>                                                       HARD_REG_SET *);
>
> +extern bool default_memtag_can_tag_addresses ();
>  #endif /* GCC_TARGHOOKS_H */
> diff --git a/gcc/targhooks.c b/gcc/targhooks.c
> index ed77afb1da57e59bc0725dc0d6fac477391bae03..d7dd07db65c8248c2f170466d=
b21449a56713d69 100644
> --- a/gcc/targhooks.c
> +++ b/gcc/targhooks.c
> @@ -2368,4 +2368,10 @@ default_remove_extra_call_preserved_regs (rtx_insn=
 *, HARD_REG_SET *)
>  {
>  }
>
> +bool
> +default_memtag_can_tag_addresses ()
> +{
> +  return false;
> +}
> +
>  #include "gt-targhooks.h"
> diff --git a/gcc/toplev.c b/gcc/toplev.c
> index d741a66f3857a60bcdb6f5c1b60e781ff311aad4..3920ef5c40f27b27a449dc6bf=
1da795f0d40e77b 100644
> --- a/gcc/toplev.c
> +++ b/gcc/toplev.c
> @@ -1752,6 +1752,16 @@ process_options (void)
>        flag_sanitize &=3D ~SANITIZE_ADDRESS;
>      }
>
> +  /* HWAsan requires top byte ignore feature in the backend.  */
> +  if (flag_sanitize & SANITIZE_HWADDRESS
> +      && ! targetm.memtag.can_tag_addresses ())
> +    {
> +      warning_at (UNKNOWN_LOCATION, 0,
> +                 "%<-fsanitize=3Dhwaddress%> can not be implemented on "
> +                 "a backend that does not ignore the top byte of a point=
er");
> +      flag_sanitize &=3D ~SANITIZE_HWADDRESS;
> +    }
> +
>   /* Do not use IPA optimizations for register allocation if profiler is =
active
>      or patchable function entries are inserted for run-time instrumentat=
ion
>      or port does not emit prologue and epilogue as RTL.  */
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2BwcYBtNn_ST7L2yEz2Zwge38UGCWthOKuepn3zQ90gZww%40mail.gmai=
l.com.
