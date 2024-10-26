Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEX36S4AMGQEJWMIT2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FD5E9B1A87
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Oct 2024 21:05:56 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-28861cecac4sf2266903fac.1
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Oct 2024 12:05:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729969554; cv=pass;
        d=google.com; s=arc-20240605;
        b=lwGet986o0b07rkht4l0hIz5lzq8AHshBIgbOh9mBPjkVCgApF3QPTJRf9N0yRvyzN
         IMS6p0Xb9UJRbfyb9S1c2I+PX9V6nfiZapMUGXg6mxAI/E7w2mvN3ZDU1cNOKPwwtO1j
         gSmPq78/w4BIoW9ae5dCCNPXMZIhIRvlaSfu8U6tikPrK+vZTaXHWAv/YNQUdWkwSbm/
         iJVBelepdiD2Gv8p5gPMoxLY0aQfwF20xQ3bMRiLhGfqw46Nso53SrtK2lHxz09gGkvD
         O2ZD9nxNMY4U0kVKx+r09Qxk2KxWHLzczbnMgL+spgx2pRRs1UnlqWcy5X0ZBwyHVclG
         2m2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RBQnV2c/7zY3S91ppGpC3gipiY4li6sGXwSzhVwOSVw=;
        fh=YeVCGwVXrtxz1G7wtANcsK/t4kwlH5qxdBUrZx9MCJA=;
        b=FjmMB+1xONNZMmgPO7HfEio/LIbMF4nR6IfQSHIRY0LKdMcc7W3Asrek3upbwgYhDc
         +OsLIlmqRNawQJsl9JImRCzRdEw8ueuWT0tguVEhTTKM3suX+fQZDN1fg5IA8J8uvDue
         vOUqbyTPvjEwfesCJHi8HCCIDADK92ooSHIJvZbIQxvNTGw6dWmOh/u9L8NYKBfpfDSA
         eIrI6vqS2WbDXUjDsb4eLoiyIk2eA8JVs3xB4ZLsOaHnakVqpUF2exOCVlEqanNy/LQA
         5hyGv0UxxiMJyQhSrg1XmTL4NGxdjwT6xTBxlGYZ/o7Wll+4htTv/ttrvcL7fL6rxk61
         JfMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bPZXanCA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729969554; x=1730574354; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RBQnV2c/7zY3S91ppGpC3gipiY4li6sGXwSzhVwOSVw=;
        b=OG2ZvBmmKX0D9sdNxLXuAcShCY9oxV2Zt9LUXOOnlGCL15gORPvN8KYjaeI0cRLW0P
         5+EbhmDXKUH3+peRbSXy2/U20xokz7GO9DXO3tKhz9yBF4+MnlIg4ksumPnpUEiHXepa
         YPK00lVIUEqjAl1jNcW4oDjXH8tuqecutDkkD2JL+8mjs5JIQsm3/zN8WOPnWgy8iyAQ
         GYkcACEr8kHskjI0K1cVzD+6CWwv7LQiWB+dngIukX5NbdNzT46AAsA+v/J72TL2deqR
         8YF6LNTVYCxDk7DW/vWpBKO/pfOppdBcqDCItCqVISy9KsKOuxWuDIlIBrWp5+nopgEI
         gBCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729969554; x=1730574354;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RBQnV2c/7zY3S91ppGpC3gipiY4li6sGXwSzhVwOSVw=;
        b=fjqcHeFJN67Nyks7nr5ovFOpn332bXuyEDqdd4k6zB+jes5LUrj0Llgl/7ZtgkdSVF
         SnS6wLV6yzDMaNBgRIlFkFsZj8uoCNWIqmxkut5JpaawAgwHeqY+l9/XbLOhH5q1Ndu+
         0iQQZzJHJvHtQhohykpEFNfg++stTwZCvSeAEg+Rb8CVyCYVm4TcYP98GoeT/Z5wqPMe
         l1tOXJzAlfxOiLrQd4m3tZpVbKF5L+KWtlFKIj++4vnPyMbQ8D3sUHjTZ/s/Pzwim5uJ
         vzFkJQbU/NnPPZcINb/Hh8KM427pEcsD1Hy7LLtoK291TdHY/DUbLiSGXmuriwCwux3Q
         RfQw==
X-Forwarded-Encrypted: i=2; AJvYcCX56RMHZPf7UVuF5lgcceeYRbTQz7u/FfmiivhpzneqRAbLwUWC0py//oj9YVjOe6f5weMYdA==@lfdr.de
X-Gm-Message-State: AOJu0Yx3ekEAtoeDNO0Sj04dDoeeS1AzzwKtZeJp/U/JVhU4NCtgI/E7
	maiwFZi/X1gul2nqFIdSjW2FOxbzHtdkskhkUZdVd5I+jMn7NRWZ
X-Google-Smtp-Source: AGHT+IG2ebGrDgBu8WWBC2orJ7/DRdXordleJhLVxCgqYUqynheFENraawpTze8ZvKwlQIfxtT34KQ==
X-Received: by 2002:a05:6870:1cd:b0:25d:ff4c:bc64 with SMTP id 586e51a60fabf-29051af0f90mr2185418fac.6.1729969554329;
        Sat, 26 Oct 2024 12:05:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ad0d:b0:27c:4263:6191 with SMTP id
 586e51a60fabf-28ce46ea96fls657957fac.2.-pod-prod-06-us; Sat, 26 Oct 2024
 12:05:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUKN6+M54gCnBIaCjLyib9Z4J9Glz0DQ51oi+gotl1PEuZm1DsNGgPTTqdLxw4lzFdZw+DojBy/w54=@googlegroups.com
X-Received: by 2002:a05:6870:e303:b0:261:1aad:2c03 with SMTP id 586e51a60fabf-29051dd93c7mr2448909fac.43.1729969553336;
        Sat, 26 Oct 2024 12:05:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729969553; cv=none;
        d=google.com; s=arc-20240605;
        b=U+bFmBV6yK4EQEosiGqX3Lb6iUHlHIm+JvaRxnPfbA6XvaQMxRwYJ3i0JdEA2sLlt3
         aHdf7F5humArkR/TvLjT8EYAk9RW+dlmtcVbbJpJvxUJB26jjhGWSjV7E/GfhcXN1AJk
         vCyOY2LkqXWe8F1UR8yQdXDotLyf6UMkxXf5AQVNavNK46vxhA5UjVInpdTxAcRl3DBU
         /WH5ztQBlkwK6pZqF7ABmbndVeoi0nc2Zn0cAVzORg14wbg93UNToXuIEMEGDXhmqg9W
         XGwACGX41PbyyNPzutMIqZI+60+SjPGvZSsEUwHvXaMmn88YI4fQ5ju2v/GaHp90u7Zh
         6Vaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mMu6nFv9m1WVpI3Z0zFLZSZgLAEo3FaBzaLQot1713w=;
        fh=xYOcWEM0CFc7/2QvMYPrVJqlmxolxdCWhCBoHYEFmwY=;
        b=kc1xcPTH8a5kxpWTk1GoAF8sA9/yjH2Q4sOT0zCmiemj0hxgLMyyipRTNWvOYhYC64
         /ICjcOyGBMWGuebD0i8A8eKlZf0j0ptD+ROERuIS2dyp8vxthvW4a+KgXXszxm/Av7AP
         tY1ujTAMtGsMH1zppuVUljO/0DuGsoV3zxw6VD9LBGKJ0MQJX9HS4fIdaWpExYOVXEae
         eAXBx0JGBCjJQ6qvzopnMMoQ/nEHmRQj5EAoa0Hl0zgs/7LJPaJgdOYNBY/Eu3CZ079G
         szO6vlhnCVb8xy6vdqwCdCpaGfhOnf6xttDTGGlgsRQz1lJuqzjBmVTggCF7K8DpojI3
         wx0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bPZXanCA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-29035da4ba8si169011fac.2.2024.10.26.12.05.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Oct 2024 12:05:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-7ea68af2f62so2384121a12.3
        for <kasan-dev@googlegroups.com>; Sat, 26 Oct 2024 12:05:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXklQRC6tiZqj1oNRgDrJfXLjOLemqO1LRSkFse1Yr0heNkZ0S+zvbaxVd6W5wCkIT65YJvCZyZc/k=@googlegroups.com
X-Received: by 2002:a05:6a21:1743:b0:1d9:77e1:9e57 with SMTP id
 adf61e73a8af0-1d9a83d019emr4901773637.11.1729969552489; Sat, 26 Oct 2024
 12:05:52 -0700 (PDT)
MIME-Version: 1.0
References: <20241026161413.222898-1-niharchaithanya@gmail.com>
In-Reply-To: <20241026161413.222898-1-niharchaithanya@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 26 Oct 2024 21:05:14 +0200
Message-ID: <CANpmjNPQQid6UirgZkBov-WhpyRR_5tqazvfS5f_K3PoAF3WYw@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: report: filter out kasan related stack entries
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: ryabinin.a.a@gmail.com, andreyknvl@gmail.com, dvyukov@google.com, 
	glider@google.com, skhan@linuxfoundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=bPZXanCA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as
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

On Sat, 26 Oct 2024 at 18:17, Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> The reports of KASAN include KASAN related stack frames which are not
> the point of interest in the stack-trace. KCSAN report filters out such
> internal frames providing relevant stack trace. Currently, KASAN reports
> are generated by dump_stack_lvl() which prints the entire stack.
>
> Add functionality to KASAN reports to save the stack entries and filter
> out the kasan related stack frames in place of dump_stack_lvl() and
> stack_depot_print().
>
> Within this new functionality:
>         - A function kasan_dump_stack_lvl() in place of dump_stack_lvl() is
>           created which contains functionality for saving, filtering and
>           printing the stack-trace.
>         - A function kasan_stack_depot_print() in place of
>           stack_depot_print() is created which contains functionality for
>           filtering and printing the stack-trace.
>         - The get_stack_skipnr() function which employs pattern based stack
>           filtering is included.
>         - The replace_stack_entry() function which uses ip value based
>           stack filtering is included.
>
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=215756
> ---
> Changes in v2:
>         - Changed the function name from save_stack_lvl_kasan() to
>           kasan_dump_stack_lvl().
>         - Added filtering of stack frames for print_track() with
>           kasan_stack_depot_print().
>         - Removed redundant print_stack_trace(), and instead using
>           stack_trace_print() directly.
>         - Removed sanitize_stack_entries() and replace_stack_entry()
>           functions.
>         - Increased the buffer size in get_stack_skipnr to 128.
>
> Changes in v3:
>         - Included an additional criteria for pattern based filtering
>           in get_stack_skipnr().
>         - Included ip value based stack filtering with the functions
>           sanitize_stack_entries() and replace_stack_entry().
>         - Corrected the comments and name of the newly added functions
>           kasan_dump_stack() and kasan_stack_depot_print().
>
>  mm/kasan/report.c | 111 ++++++++++++++++++++++++++++++++++++++++++++--
>  1 file changed, 107 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 3e48668c3e40..648a89fea3e7 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -261,6 +261,110 @@ static void print_error_description(struct kasan_report_info *info)
>                         info->access_addr, current->comm, task_pid_nr(current));
>  }
>
> +/* Helper to skip KASAN-related functions in stack-trace. */
> +static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
> +{
> +       char buf[64];
> +       int len, skip;
> +
> +       for (skip = 0; skip < num_entries; ++skip) {
> +               len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
> +
> +               /* Never show  kasan_* or __kasan_* functions. */
> +               if ((strnstr(buf, "kasan_", len) == buf) ||
> +                       (strnstr(buf, "__kasan_", len) == buf))
> +                       continue;
> +               /*
> +                * No match for runtime functions -- @skip entries to skip to
> +                * get to first frame of interest.
> +                */
> +               break;
> +       }
> +
> +       return skip;
> +}
> +
> +/*
> + * Skips to the first entry that matches the function of @ip, and then replaces
> + * that entry with @ip, returning the entries to skip with @replaced containing
> + * the replaced entry.
> + */
> +static int
> +replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip,
> +                   unsigned long *replaced)
> +{
> +       unsigned long symbolsize, offset;
> +       unsigned long target_func;
> +       int skip;
> +
> +       if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
> +               target_func = ip - offset;
> +       else
> +               goto fallback;
> +
> +       for (skip = 0; skip < num_entries; ++skip) {
> +               unsigned long func = stack_entries[skip];
> +
> +               if (!kallsyms_lookup_size_offset(func, &symbolsize, &offset))
> +                       goto fallback;
> +               func -= offset;
> +
> +               if (func == target_func) {
> +                       *replaced = stack_entries[skip];

All this replaced logic is not needed for KASAN.

> +                       stack_entries[skip] = ip;
> +                       return skip;
> +               }
> +       }
> +
> +fallback:
> +       /* Should not happen; the resulting stack trace is likely misleading. */
> +       WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void *)ip);
> +       return get_stack_skipnr(stack_entries, num_entries);
> +}
> +
> +static int
> +sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip,
> +                      unsigned long *replaced)
> +{
> +       return ip ? replace_stack_entry(stack_entries, num_entries, ip, replaced) :
> +                         get_stack_skipnr(stack_entries, num_entries);
> +}
> +
> +/*
> + * Use in place of dump_stack() to filter out KASAN-related frames in
> + * the stack trace.
> + */
> +static void kasan_dump_stack(unsigned long ip)
> +{
> +       unsigned long reordered_to = 0;

Do you understand what this code is doing? The whole "reordered_to"
logic (along with the "replaced" logic in replace_stack_entry()) is
very specific to KCSAN and not at all needed for KASAN. See the commit
that introduced it:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/kernel/kcsan/report.c?id=be3f6967ec5947dd7b2f23bf9d42bb2729889618

You've copied and pasted the code from KCSAN, in the hopes it more or
less does what we want. However, the code as-is is more complex than
needed.

Please try to really understand what the most optimal way to do this
might be. As additional inspiration, please look at how KFENCE does
it: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/kfence/report.c#n49

In the end what I'd like to see is the simplest possible way to do
this for KASAN.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPQQid6UirgZkBov-WhpyRR_5tqazvfS5f_K3PoAF3WYw%40mail.gmail.com.
