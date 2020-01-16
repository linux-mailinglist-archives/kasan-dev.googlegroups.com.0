Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3NPQHYQKGQEYC7FNHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6371213DA16
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 13:32:47 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id c4sf7774788oiy.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 04:32:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579177966; cv=pass;
        d=google.com; s=arc-20160816;
        b=e1CHIf8EGOhO0dVtY585AUxvLA3JYB3o2Fwez/7x1cVelK6tRILWm3pO3b2rCe1yx/
         yGWjq3mcVmYYkY7mGhxcxDTlyAiFz+DgKmft/P4BvSMvQ1yn/i9G3Zzv34Mms2RKd1WN
         LY+VcYU/2+zjcaW+ojFoCVVdsZS59N/8RjFbYDQde2QseJpKwpEFUDDBDDZoWxC8ardS
         SpxWrSn8ebxs2KSHf+wki2OcmeIBjaavG0ANk0c5rhxDE9m2ltk7W4rs4gm9cN7A0iXG
         jvCnGLS9M9oW7y/yAgXFX1L4gEDKPdcA5Mj2k4W1Qre125JUYkwx70dO5oJ8k2LUX+ua
         QnCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MvIPvktRTf8giGNUiKfoUFpnFBz0O6PAOYKqrLCHA1g=;
        b=oyoMDdoLFWCGjBEHC5HBQGYbPXnMJNcEcRUER9JNbtIqBTO9fM5FY3ruUPYeM01NLL
         wKpzwIfnOdfbCI8ENBH7hfTkXStoJFjI1gqDlqOhYaZh13h5NkFri4SMOwuxxOOM4kdB
         wINbxQj8gSX2PnzwOd8pdI46N/SkpZc6OQfs1ubKXzGtSXqacfkjPc+VCKf0yrbjA/3y
         G7FkIkGc6FJJAuUflovRGdCnUca28UPbaE+NWNX91aFMf3rTOAW1iIHocue/eXpI3b+P
         5O7y3f4+AfoYzQkn24EG/K/BU35ev9rT61fBhn5955bSmEui92YbZjIG6oleNo45L4H2
         wqlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UXGYA21K;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MvIPvktRTf8giGNUiKfoUFpnFBz0O6PAOYKqrLCHA1g=;
        b=O9eLTFM5+PQFzhKpWgBLlELHut7ENU2XrkuhjS3S+mPx+7APdz5P7grDU2tr3aG6z4
         +gyMuviXkvwRoij6X2iM6OCoRD65VX0XL3uyiSfpk0i1EyiD6eghmhkz3ksjX8+g04zM
         4ZvaJmR+vdPcC1WFx1WIW5a7H1TagH80T7Ec+TfMmnKBNFXWHLZ0VQwT8H6SgWUq9dxE
         2eKfA6ZMIrRnF5dnb/Fppn5ykhtlTwbHPm5iC9/iest5iJVI0m6DbNWMZkimaTxSsgV7
         jiCw4FPlZPwC88+Hw/s2VXoEZCKWH67RD5pxZHTkNYfG2u5drF3JU9itsctCFjKJhYQw
         pH/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MvIPvktRTf8giGNUiKfoUFpnFBz0O6PAOYKqrLCHA1g=;
        b=h7MvRZexPidiVKg+7xgQcIKuoFLsfC/UODCI3Je0iNICXK+vw/tNWHTkTziJk06+0b
         8UKw+F71MdhkdLlczCmSQNVu2ka6TY8ysSDVX+08LrpD8KNX7yugKfL/y97wgVY6osC9
         Y8a4U4gVtphg4AymTImk89VkD4H4Enf5qS557dkF9hCPN1YuacFwEWMZo8CdZzqprlz8
         5Y7/0pNw/JM5DnSsVj2O/I5vOIYhjxt6FrdzpdJiZdeVvjBO0hd1PL3qV9JmWhbtivHt
         5kqZ5g45YGY+ia3i9imgSsaOuBcqRo0+yfF8CkZ8leKzfDrlCQEmquM0qYuWopXeEq9w
         scDQ==
X-Gm-Message-State: APjAAAVqWBl1Jp86bVBgcVc7SfKnLK9slJe45OtYzJJgG4bgdCxT4Ns/
	6o2p3GnsLECZuK6IC6LFpis=
X-Google-Smtp-Source: APXvYqyhqNhb35jiBjAbHa0V1Z8IzpAPxaux0XcrJuYYE2VWcAaDWFmkhN9a8tAIIgLS/ODb+2uRqw==
X-Received: by 2002:a9d:f26:: with SMTP id 35mr1798086ott.260.1579177965782;
        Thu, 16 Jan 2020 04:32:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1a0d:: with SMTP id a13ls3946299oia.14.gmail; Thu, 16
 Jan 2020 04:32:45 -0800 (PST)
X-Received: by 2002:aca:c507:: with SMTP id v7mr3883545oif.157.1579177965408;
        Thu, 16 Jan 2020 04:32:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579177965; cv=none;
        d=google.com; s=arc-20160816;
        b=fH6V4ef4+YyR/g32YyCsSp6H0Q2a2ijT07zWNJr7BQmEDdwrtyMHnd1ew2lwK0Fgvk
         WCgTOVz5fw2QDm3GVIL67HYdBBpODtpWiB+YHQOMxpFCqxRDUpVHzEZmKjn8VOo6fGmz
         tpkrerrEYWtYRJhfSN6Ufvse594yC0Ca0rzdmIgkvoj4a/uD9hjQSsA1wjWAQv6/2sA6
         07NaqWi+09aijxJISMEVUxyIqf5PRBmjioaeDzNIPNCbZqzxnhs6WAh7S5u/A267IIr+
         1gp2exenglJMfqTu7u1e7SEet/H6kaHT8vjqGZbakU6AGVqPm0pFznGa0P8EoxlE+e+H
         rBnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kUo0X8yHvUiQ3XC8YUK28eSRhJfh+ll6/ugw3Oe1M1Q=;
        b=YFEbwcLmGVq64GSBUWUwa8ldFGpDaJOoz0BqyBxvfL4lGo6b/k1zufphOW0+NN6f+a
         n1rRgq7MCfwOb7vCg8aZpeSyLn3afz0/cew49/1URFi2kEP7uNIRqPlw+Q+6X541XFkA
         Zn5KVO/j9tFVDvlQpVSuhW+9OobPr2DXazaCBum2n6rstscYJ6J7YUv3CkQsuE1kosHa
         3lD8ycm1LLGC4lkAJYhDkqSkQtGq8iPWXSngvcrYJtd2fKoKESM9+Fdt4qzr8kKjRAoQ
         7JMx9gBW5GsZHfYjIWliM8Fe/5O0tRaYeDvvVlZ+9IrIrSPGwa0hDpX3FmtgHpRvFyGp
         Imcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UXGYA21K;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id d16si981605oij.1.2020.01.16.04.32.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 04:32:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id bg7so1516802pjb.5
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 04:32:45 -0800 (PST)
X-Received: by 2002:a17:90a:660b:: with SMTP id l11mr6404502pjj.47.1579177964411;
 Thu, 16 Jan 2020 04:32:44 -0800 (PST)
MIME-Version: 1.0
References: <20200116012321.26254-1-keescook@chromium.org> <20200116012321.26254-7-keescook@chromium.org>
In-Reply-To: <20200116012321.26254-7-keescook@chromium.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 13:32:33 +0100
Message-ID: <CAAeHK+x5pLce4Uig6O03YS6MrSJtu6FR9DbcTsjy29BbgEZM4A@mail.gmail.com>
Subject: Re: [PATCH v3 6/6] ubsan: Include bug type in report header
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Alexander Potapenko <glider@google.com>, Dan Carpenter <dan.carpenter@oracle.com>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Arnd Bergmann <arnd@arndb.de>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kernel-hardening@lists.openwall.com, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UXGYA21K;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
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

On Thu, Jan 16, 2020 at 2:24 AM Kees Cook <keescook@chromium.org> wrote:
>
> When syzbot tries to figure out how to deduplicate bug reports, it
> prefers seeing a hint about a specific bug type (we can do better than
> just "UBSAN"). This lifts the handler reason into the UBSAN report line
> that includes the file path that tripped a check. Unfortunately, UBSAN
> does not provide function names.
>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://lore.kernel.org/lkml/CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  lib/ubsan.c | 36 +++++++++++++++---------------------
>  1 file changed, 15 insertions(+), 21 deletions(-)
>
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index 429663eef6a7..057d5375bfc6 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -45,13 +45,6 @@ static bool was_reported(struct source_location *location)
>         return test_and_set_bit(REPORTED_BIT, &location->reported);
>  }
>
> -static void print_source_location(const char *prefix,
> -                               struct source_location *loc)
> -{
> -       pr_err("%s %s:%d:%d\n", prefix, loc->file_name,
> -               loc->line & LINE_MASK, loc->column & COLUMN_MASK);
> -}
> -
>  static bool suppress_report(struct source_location *loc)
>  {
>         return current->in_ubsan || was_reported(loc);
> @@ -140,13 +133,14 @@ static void val_to_string(char *str, size_t size, struct type_descriptor *type,
>         }
>  }
>
> -static void ubsan_prologue(struct source_location *location)
> +static void ubsan_prologue(struct source_location *loc, const char *reason)
>  {
>         current->in_ubsan++;
>
>         pr_err("========================================"
>                 "========================================\n");
> -       print_source_location("UBSAN: Undefined behaviour in", location);
> +       pr_err("UBSAN: %s in %s:%d:%d\n", reason, loc->file_name,
> +               loc->line & LINE_MASK, loc->column & COLUMN_MASK);
>  }
>
>  static void ubsan_epilogue(void)
> @@ -180,12 +174,12 @@ static void handle_overflow(struct overflow_data *data, void *lhs,
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, type_is_signed(type) ?
> +                       "signed integer overflow" :
> +                       "unsigned integer overflow");
>
>         val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
>         val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
> -       pr_err("%s integer overflow:\n",
> -               type_is_signed(type) ? "signed" : "unsigned");
>         pr_err("%s %c %s cannot be represented in type %s\n",
>                 lhs_val_str,
>                 op,
> @@ -225,7 +219,7 @@ void __ubsan_handle_negate_overflow(struct overflow_data *data,
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "negation overflow");
>
>         val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);
>
> @@ -245,7 +239,7 @@ void __ubsan_handle_divrem_overflow(struct overflow_data *data,
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "division overflow");
>
>         val_to_string(rhs_val_str, sizeof(rhs_val_str), data->type, rhs);
>
> @@ -264,7 +258,7 @@ static void handle_null_ptr_deref(struct type_mismatch_data_common *data)
>         if (suppress_report(data->location))
>                 return;
>
> -       ubsan_prologue(data->location);
> +       ubsan_prologue(data->location, "NULL pointer dereference");

Not crucially important, but I think it makes sense to use the
single-word-with-hyphens bug type format like in KASAN here, e.g.
null-ptr-deref, misaligned-access, etc.


>
>         pr_err("%s null pointer of type %s\n",
>                 type_check_kinds[data->type_check_kind],
> @@ -279,7 +273,7 @@ static void handle_misaligned_access(struct type_mismatch_data_common *data,
>         if (suppress_report(data->location))
>                 return;
>
> -       ubsan_prologue(data->location);
> +       ubsan_prologue(data->location, "misaligned access");
>
>         pr_err("%s misaligned address %p for type %s\n",
>                 type_check_kinds[data->type_check_kind],
> @@ -295,7 +289,7 @@ static void handle_object_size_mismatch(struct type_mismatch_data_common *data,
>         if (suppress_report(data->location))
>                 return;
>
> -       ubsan_prologue(data->location);
> +       ubsan_prologue(data->location, "object size mismatch");
>         pr_err("%s address %p with insufficient space\n",
>                 type_check_kinds[data->type_check_kind],
>                 (void *) ptr);
> @@ -354,7 +348,7 @@ void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data, void *index)
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "array index out of bounds");
>
>         val_to_string(index_str, sizeof(index_str), data->index_type, index);
>         pr_err("index %s is out of range for type %s\n", index_str,
> @@ -375,7 +369,7 @@ void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *data,
>         if (suppress_report(&data->location))
>                 goto out;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "shift out of bounds");
>
>         val_to_string(rhs_str, sizeof(rhs_str), rhs_type, rhs);
>         val_to_string(lhs_str, sizeof(lhs_str), lhs_type, lhs);
> @@ -407,7 +401,7 @@ EXPORT_SYMBOL(__ubsan_handle_shift_out_of_bounds);
>
>  void __ubsan_handle_builtin_unreachable(struct unreachable_data *data)
>  {
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "unreachable");
>         pr_err("calling __builtin_unreachable()\n");
>         ubsan_epilogue();
>         panic("can't return from __builtin_unreachable()");
> @@ -422,7 +416,7 @@ void __ubsan_handle_load_invalid_value(struct invalid_value_data *data,
>         if (suppress_report(&data->location))
>                 return;
>
> -       ubsan_prologue(&data->location);
> +       ubsan_prologue(&data->location, "invalid load");
>
>         val_to_string(val_str, sizeof(val_str), data->type, val);
>
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/20200116012321.26254-7-keescook%40chromium.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx5pLce4Uig6O03YS6MrSJtu6FR9DbcTsjy29BbgEZM4A%40mail.gmail.com.
