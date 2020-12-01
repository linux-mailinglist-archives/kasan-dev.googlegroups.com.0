Return-Path: <kasan-dev+bncBDYJPJO25UGBBQ6BTL7AKGQENSJ7VJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 62F752CACDC
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 21:00:04 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id t24sf1553816oic.15
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 12:00:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606852803; cv=pass;
        d=google.com; s=arc-20160816;
        b=BN2lVc3C5p/jLIp7iz7mnqM1LAZFddPDP/BD0Z1M90g6Mv6VIcMx93Q3AI7udorZFw
         Fj19nT0+2LHaZmfqK0kDq+Z+VUCbXseVrwXWjPovvs+ymib8xnKiaad6Dn/jXy3Q7iMK
         buzkubult8dDxgLzfi+sjNuvAA9dksOxu+FJZbl2nIdipwqKCU3npOXNvRk0Dg4uY+yd
         Z2K36t4QVm6TxukCeqm7OfLPzNsFMnM60DB0Mao3lLlrMxZWWiSLI1mKOInKwwVHHqnW
         OsGxgJDNZUxLSDfH5UGe7QYYSsTbq4N1LNtFUJZtyimct+6NJZu9gigLfSVN+Ap5RWBA
         0mmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=D/KFJ0hWNXX2LzNzlUY3yQdyD98k0w1CnCgAvMv56zs=;
        b=gyCIHNQWVlsk1wYhvsM7+2O/dhYiMwM7GvwZhwHgx8pBuvDaBtEqekLXzCpIkkaNgC
         O9ePAWFv5Dk2rzxu5sf+Krw7CfyifoWPRYrPJX7LUaYYepNO88cbGHRKGihN5MaVWkSC
         PR2G96La0nHEbnyyHSAGDMOpzG4d0JNQt6h1YpUKBrN8xTulukq6CuTZ/BHIeL/fGTcb
         nSHx08Frf9uemQu+kW2noe5xJ8NfDjCezsognDwFx/4rDpNcWEpUFv4+lSGKu9Rg8Gwl
         MnvcPXvb7rvQ5PhZapOrs1JoTmVgMDRsavaJxZt5jx/Rf5wL9O5btS/5TRwoHMffHh6T
         F+KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tTFhE9yu;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D/KFJ0hWNXX2LzNzlUY3yQdyD98k0w1CnCgAvMv56zs=;
        b=UB7CQ5OA4oKpBBZkUnbaq2g8zdR3JLCZ/WG36899pfK1LlfEh/3qHbnsyYOuaJJYRy
         YDuODkVSvwKxBtGZ3R6X/s6tU5QviIBkPw9L/MO7ZcnL4C+J8U1BPmV2RFuqhh4dxTfS
         3b4xXfGTU+8csm6/IU3idTm9TcTmfgCXb6PisD4isPnbWjkwB/6zl03yE9sUOcrfDSz4
         nGmXh7o8aWGZjUN/csmQqIOSakChTzsxLmYa3S4t5AFJud/3Fz3wZvdm0AOcAKOicAL2
         XwUAlyhES6Y4vcSuEM3ReDSlhw0IiJ9pw+9D/qgp7jeeS4bCoYIt9Zzq1or6v3LtQY9g
         HW9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D/KFJ0hWNXX2LzNzlUY3yQdyD98k0w1CnCgAvMv56zs=;
        b=GoLQZ8KjuW+8J+6FhRjxM8ZzWxFnB2upVmhcHZ/Fs2hUfJcS+7/IJHQta4YvBdnx2W
         RXx4JCpNQDEDEHEjTiDEv3T5a/r1/d5rTTj2CZ9wCx56PkTcLf29fy95UGn7a417S+Kx
         r9GQFB84dU3vYuVMwugp95yChCKnwExLrSkIUuPHEF9LoDTE5MV05qElOxP33/qYRJdy
         5671eDY6l4mOTW77qAbDrD06nVVCm1fL0HUry7zGeSrYYsJuImLX1R1YXS97ShnE6g9W
         AghIDuLJLWG7tWLyAuYiUhA6DtZYkemg1ihceGdIWRhhUH6hKCMOqwvOVxE8EuRvChql
         rYWw==
X-Gm-Message-State: AOAM533cq+O40gZQ7cp24K8G5Pyb8/AI/TwaKoUMQ0AZL6Ajdq1Cj/+g
	mbKaCTNRnWTVDawouE1Agf0=
X-Google-Smtp-Source: ABdhPJz+TJoyzjvtUySaMGUICzrlEQOH0Z7zVY9HaUZ0NHOE8dmJC+HeT0Jm/cw5hIvy9mhfm96Zkw==
X-Received: by 2002:a4a:d347:: with SMTP id d7mr3038308oos.47.1606852803375;
        Tue, 01 Dec 2020 12:00:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:448b:: with SMTP id v11ls771489oiv.7.gmail; Tue, 01 Dec
 2020 12:00:03 -0800 (PST)
X-Received: by 2002:aca:c506:: with SMTP id v6mr2851797oif.122.1606852803073;
        Tue, 01 Dec 2020 12:00:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606852803; cv=none;
        d=google.com; s=arc-20160816;
        b=oObaOpwQB0XVnmtBWtRFvU+m875ZYHl+5wnHHk9uBLBZMRySmpzkiCMHcza2S2rOUP
         Zo5wjr74TmVmItQwBqZNyqJvIakMAxhxo85C5CIhRyWG+NqU2f9sHjAlW6w3BNiD4kVq
         LwR80K6zbd/Pz43iqbAl0Y1cGvjK+VNpO4m1oYY07G+HK8f+y+uLhmRrkxIoO4TpvFmQ
         Az8GDX3NfznzoVWOK1Jvc/bhCjZG9WuGhjjOrRsJvSxjrEdMpw381wxH4h7VmtauOo0i
         ReBXDT1eTEBQOcUyw2lCGtB69dRyqyFNVR7DhHVxKZGlXgPDEwmXm4UgzQ6t26nAte7S
         tl8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ST3hE6QaFWUSPeZl1LBt0eW3vQwZ9yVBdwV//6AR6/I=;
        b=w52FQdhya9kKLtRqTKq6rvprOYXKwZqaBw6cxrsxN5KBqpa/Kzo5bTspyc99EvEUA1
         w0dqnGndaw36aPQFjeY+dFMGdhr9NhMTp65lWPf0e0/Daql7nuPqKtICHH0JStXxJGJo
         f6E09Y2W/8IG4d3mDwHgOr+lL93UpuLEVRXixf4g2foNH7EsgaMDou3RGuIB3vkJfjSI
         kLOKV6AOuiKwGF7pbdhMtekPtKnDIuQEbT4Ts4fHZsszCNxABzJ+yuAHis/cZTBIz9ZB
         BEXlcWHEAmkgh+WKLILLXbV93ECoS+vxQ1qUxCXSgUo6CTOiSSpnSbJsNkNMaT5G6AqC
         uiqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tTFhE9yu;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id m13si114665otn.1.2020.12.01.12.00.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 12:00:03 -0800 (PST)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id t3so1831380pgi.11
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 12:00:03 -0800 (PST)
X-Received: by 2002:a63:3247:: with SMTP id y68mr3731226pgy.10.1606852802273;
 Tue, 01 Dec 2020 12:00:02 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com>
In-Reply-To: <20201201152017.3576951-1-elver@google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Dec 2020 11:59:50 -0800
Message-ID: <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Joe Perches <joe@perches.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tTFhE9yu;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Tue, Dec 1, 2020 at 7:21 AM Marco Elver <elver@google.com> wrote:
>
> The C11 _Static_assert() keyword may be used at module scope, and we
> need to teach genksyms about it to not abort with an error. We currently
> have a growing number of static_assert() (but also direct usage of
> _Static_assert()) users at module scope:
>
>         git grep -E '^_Static_assert\(|^static_assert\(' | grep -v '^tools' | wc -l
>         135
>
> More recently, when enabling CONFIG_MODVERSIONS with CONFIG_KCSAN, we
> observe a number of warnings:
>
>         WARNING: modpost: EXPORT symbol "<..all kcsan symbols..>" [vmlinux] [...]
>
> When running a preprocessed source through 'genksyms -w' a number of
> syntax errors point at usage of static_assert()s. In the case of
> kernel/kcsan/encoding.h, new static_assert()s had been introduced which
> used expressions that appear to cause genksyms to not even be able to
> recover from the syntax error gracefully (as it appears was the case
> previously).
>
> Therefore, make genksyms ignore all _Static_assert() and the contained
> expression. With the fix, usage of _Static_assert() no longer cause
> "syntax error" all over the kernel, and the above modpost warnings for
> KCSAN are gone, too.
>
> Signed-off-by: Marco Elver <elver@google.com>

Ah, genksyms...if only there were a library that we could use to parse
C code...:P
Acked-by: Nick Desaulniers <ndesaulniers@google.com>

> ---
>  scripts/genksyms/keywords.c |  3 +++
>  scripts/genksyms/lex.l      | 27 ++++++++++++++++++++++++++-
>  scripts/genksyms/parse.y    |  7 +++++++
>  3 files changed, 36 insertions(+), 1 deletion(-)
>
> diff --git a/scripts/genksyms/keywords.c b/scripts/genksyms/keywords.c
> index 057c6cabad1d..b85e0979a00c 100644
> --- a/scripts/genksyms/keywords.c
> +++ b/scripts/genksyms/keywords.c
> @@ -32,6 +32,9 @@ static struct resword {
>         { "restrict", RESTRICT_KEYW },
>         { "asm", ASM_KEYW },
>
> +       // c11 keywords that can be used at module scope
> +       { "_Static_assert", STATIC_ASSERT_KEYW },
> +
>         // attribute commented out in modutils 2.4.2.  People are using 'attribute' as a
>         // field name which breaks the genksyms parser.  It is not a gcc keyword anyway.
>         // KAO. },
> diff --git a/scripts/genksyms/lex.l b/scripts/genksyms/lex.l
> index e265c5d96861..ae76472efc43 100644
> --- a/scripts/genksyms/lex.l
> +++ b/scripts/genksyms/lex.l
> @@ -118,7 +118,7 @@ yylex(void)
>  {
>    static enum {
>      ST_NOTSTARTED, ST_NORMAL, ST_ATTRIBUTE, ST_ASM, ST_TYPEOF, ST_TYPEOF_1,
> -    ST_BRACKET, ST_BRACE, ST_EXPRESSION,
> +    ST_BRACKET, ST_BRACE, ST_EXPRESSION, ST_STATIC_ASSERT,
>      ST_TABLE_1, ST_TABLE_2, ST_TABLE_3, ST_TABLE_4,
>      ST_TABLE_5, ST_TABLE_6
>    } lexstate = ST_NOTSTARTED;
> @@ -201,6 +201,11 @@ repeat:
>
>                   case EXPORT_SYMBOL_KEYW:
>                       goto fini;
> +
> +                 case STATIC_ASSERT_KEYW:
> +                   lexstate = ST_STATIC_ASSERT;
> +                   count = 0;
> +                   goto repeat;
>                   }
>               }
>             if (!suppress_type_lookup)
> @@ -401,6 +406,26 @@ repeat:
>         }
>        break;
>
> +    case ST_STATIC_ASSERT:
> +      APP;
> +      switch (token)
> +       {
> +       case '(':
> +         ++count;
> +         goto repeat;
> +       case ')':
> +         if (--count == 0)
> +           {
> +             lexstate = ST_NORMAL;
> +             token = STATIC_ASSERT_PHRASE;
> +             break;
> +           }
> +         goto repeat;
> +       default:
> +         goto repeat;
> +       }
> +      break;
> +
>      case ST_TABLE_1:
>        goto repeat;
>
> diff --git a/scripts/genksyms/parse.y b/scripts/genksyms/parse.y
> index e22b42245bcc..8e9b5e69e8f0 100644
> --- a/scripts/genksyms/parse.y
> +++ b/scripts/genksyms/parse.y
> @@ -80,6 +80,7 @@ static void record_compound(struct string_list **keyw,
>  %token SHORT_KEYW
>  %token SIGNED_KEYW
>  %token STATIC_KEYW
> +%token STATIC_ASSERT_KEYW
>  %token STRUCT_KEYW
>  %token TYPEDEF_KEYW
>  %token UNION_KEYW
> @@ -97,6 +98,7 @@ static void record_compound(struct string_list **keyw,
>  %token BRACE_PHRASE
>  %token BRACKET_PHRASE
>  %token EXPRESSION_PHRASE
> +%token STATIC_ASSERT_PHRASE
>
>  %token CHAR
>  %token DOTS
> @@ -130,6 +132,7 @@ declaration1:
>         | function_definition
>         | asm_definition
>         | export_definition
> +       | static_assert
>         | error ';'                             { $$ = $2; }
>         | error '}'                             { $$ = $2; }
>         ;
> @@ -493,6 +496,10 @@ export_definition:
>                 { export_symbol((*$3)->string); $$ = $5; }
>         ;
>
> +/* Ignore any module scoped _Static_assert(...) */
> +static_assert:
> +       STATIC_ASSERT_PHRASE ';'                        { $$ = $2; }
> +       ;
>
>  %%
>
> --
> 2.29.2.454.gaff20da3a2-goog
>


-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdkcv%3DFES2CXfoY%2BAFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg%40mail.gmail.com.
