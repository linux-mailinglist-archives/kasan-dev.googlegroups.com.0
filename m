Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4WAT66AMGQEVVU4L7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E88E1A12885
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 17:21:07 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-29e2c0d98bdsf12365474fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 08:21:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736958066; cv=pass;
        d=google.com; s=arc-20240605;
        b=NrcaFczwr6dy8Cnc3YtXXT6H+uYKEwtEko9hFjyl4hd3bloAEiUgxHiJakFj/RzMYp
         jJE8LCCuI1SnXAdPt7fqsK+YCJRO79KRbWoA9pNzCrOa8ev1jHrNQc3p9p+K6xKLj4aj
         klSRL5by+2vSAKW7Wigqx/XIPnlWaF0Y9THYjg8+bQboOG7SGgCxK4WmGmXZsbXJYNlj
         YRRHmVLFGcxJUozMr4OuvboM0iwbYnnMLEL75nZUNmHe02mRYfwy8R0banDLBzDIWlYj
         2iIrCikKQtqLLhzq9IKnL3HF4Fz7z6xHoeypF/rwo+NE9FvSXngVnWtdQCHg+uFkzaXI
         WLUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g2j2zRIpNqkYezyMWgaWNDS+qCyaoOeG+JgSyF7Ocww=;
        fh=VHrKdbkB6psHS7AmmAddCSu8AwXnQ+KE0vNGch5xXFg=;
        b=PO6bVVXOgUu/OIq9Ei+rhYm/fTtwYVdoOlcfmyqjz8YzdTy33KJH/XGY/tiaa5+M51
         udpcLoMPwFXfC8JDZN9cMEYktx7p8CCwzpHfH6+bYPGD00eDmF2wxjOqkjh7Yat9LKvB
         VVfzF0yDzpmTc/Kp1KKHLHX4gLoYTUeSfz2i/yzqiCPwVFs9aM91Mav3DGQ4mTNnjM2l
         /N6y/32vcHTfV1rmszHDOEaqNdvS9z2QxFBpfLHXyKXrTlJsW4Dhk2Wv3KUMXfhK6j+o
         pEZr3Ra37mMEx65XDZ94bbt7Qi0xBZuBzU7f+Ip7zahYU5nCur++K1e28mTH4HAcjICR
         k1bQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eIxt4bs8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736958066; x=1737562866; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g2j2zRIpNqkYezyMWgaWNDS+qCyaoOeG+JgSyF7Ocww=;
        b=tPtjwsoGiNsaBaWaQpzytFkYGdwhB+HBTefLXUhHsbupROVowp+/2IyZeJG8Zwu7V7
         PhfEb3E8u1Qb4uDJdSIPkMg/8k1zsJYzTqPo2j7X/Rm4sajdb/Ni+N3Yg+vfKItkQb7d
         awtWvH7PcESo+jUBcV2W/9qucdOkVFh6kLoIlVrtdLIfp7TyK0cOnPJrF8x4KGusA6o4
         dwbm4WXOWNajJSoWPtVpNffOipS22Ve4novbtMPef5+r8zJiG72mVnY0hwUqv36zwO2Z
         ni4vEhmGEMLwCUtA2sYTxunfjSD6UNxEAV7XucwKCE95mdZpLKQIc23/eYP++JZ3Irtd
         m5iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736958066; x=1737562866;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g2j2zRIpNqkYezyMWgaWNDS+qCyaoOeG+JgSyF7Ocww=;
        b=sBda983wvpUHjHZ2cvWw1w8gYYDWkGMF9p4dq1wimwwZ50l73lijfnEMCX3BWtF6g3
         3zdWDOOxXKOE/zYjxgvbgvdYaewNtJ+VXbRNRQx50cD4WTmbWq1qHunZLkaUVsivvU/x
         M2TvaBVxka+Knd4CsxHmrz0c50VDJsSQhfCpwLIwYOdniS4GFOuacuQu0hJ0ViPSvvNp
         7wdVVJbolSBfTpgL16tmCXtNV6lmTGCHxxccRivLooUiJ4ELxEEvozdacu+3Eh8mllUP
         yIzlNRm+FX9kat48DEFDOUCwSeqD3PgbFxO+xrCbjMNrClTVQgarhhAVTDkb6ZNejBKO
         AOfg==
X-Forwarded-Encrypted: i=2; AJvYcCXShPhY4LFEC0FARbIu2r8P/YKZ8kndMpGWlTwWi9hEt+6ZCnHWqyLRqy7H+PIADYXlSZwcVw==@lfdr.de
X-Gm-Message-State: AOJu0Yx1rJxRyhORUriPGrVzGKjzDL3f9ZjljBKQVHwfQZaTvy1IrLZB
	54sccN29Fc+yflL5mRVa/mAzXg/Vycikml9Xs5GD17u2xUDsdeTn
X-Google-Smtp-Source: AGHT+IFqreGZGRV2F3e5bukmyjSXSfWfH9rHAxGOy6Z4hrPGQMzeLzYhfF3duyscTb8oDLCo8LoU+g==
X-Received: by 2002:a05:6871:3a8a:b0:29e:7a09:d92a with SMTP id 586e51a60fabf-2aa0652f61cmr16954026fac.5.1736958066318;
        Wed, 15 Jan 2025 08:21:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:20c9:b0:29f:ffdf:5a69 with SMTP id
 586e51a60fabf-2b1a0706636ls3375fac.0.-pod-prod-09-us; Wed, 15 Jan 2025
 08:21:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWWiUbLZfhxnlgOmg0sKP3eeCIbbCbKEh/fKQ3gkNhcJTm7ZAcb7ecXc8gW/zdg4PPPoKEdzIIxgD4=@googlegroups.com
X-Received: by 2002:a05:6808:198c:b0:3ec:d34f:4c82 with SMTP id 5614622812f47-3ef2ebf6481mr18242458b6e.16.1736958065467;
        Wed, 15 Jan 2025 08:21:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736958065; cv=none;
        d=google.com; s=arc-20240605;
        b=Wl1IEwnDrByp66BG6TlgO7P6qBOPHlzu9N7uDoFqGtfUgQypzR2ZUUmVIpz7Vt+S7+
         wt1t9HIOLQRTQb41wezecRlGfEy016XcrefxjIw7bnGNWiVargE9GTExTMhMFpzE59ek
         n0zH0Kc//z3S6hcAG0LHnW5+BTIeigeYLM9v/j7T9hKJoMFNikXJrqTr5Wj6Ap6uWnwq
         pTleY2dysmw1MYapYL/RWrqZOFyg+pBf6djC4sT10OHWaDe7b71qZZSOAuZFZINFCILb
         VGEMrj7tkVsHVfSZKFYIzk5PZJkaiE+EGgRy214hlm/PMeQcXfHKG79VTv0YSE1ts5Lh
         Azng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z0swpJpnqngIgl9tsMO0EehO0BF6GXb/S4Vl2pslhD0=;
        fh=B6dZG6Y1qHo1gruWe4OFrlQF49R3UHHtEUB9UpZVic0=;
        b=f8i0V/NgMy6RhOt2SBg4bm1LRzwjR6Vogx5cmyqF37JQiHS1z/dATVBaP5mB8bImiU
         NV1eWOLuNZSn8q6CM2z7gLhwqGE/WO9TMyJB7Vno4S+YqtvFZrQxtNpUEDaPKjikizjy
         YjVvovYtOYFS0jYw8fptSImC1Lfljy0xwH7jg1DKe/aOQN/kCqvwgpfc+jOaLNhbLRpT
         oH9RK6kPmXqdrG4Y7GLWWBtH6DhIdLRObCm4Sg/VhNmqOXNfAjizysSqEVNXzLre1Jg3
         ao0H1Mzq1OHVrV+9faOPFQcDBxiuW6ODxWNaOsf9T25OpIvJsS19i+8D/avqAUdZM+UX
         jB6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eIxt4bs8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5f882500afcsi484148eaf.0.2025.01.15.08.21.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2025 08:21:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-2ef8c012913so8697188a91.3
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2025 08:21:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXf88jdirZ7Q0aas84GrC7vvZrT1uQ33sKXOZZCjIDXm+hA5+VDIsVVubEQ6ulgEA80V8nsWFvxlmo=@googlegroups.com
X-Gm-Gg: ASbGncsRC64wmccBnUSYKtT8frMG+qKGWNPv+ID90sSoT0IAySVVAwMvTDvDR4MkTGU
	+JiY5HsQvVklVSsHP3R7GaSd2wC68oZM8ET3179pOUeheMNOLD6dWPh8/nqAONCMXh/vc
X-Received: by 2002:a17:90b:2f4e:b0:2ee:f550:3848 with SMTP id
 98e67ed59e1d1-2f548e98ea9mr39134653a91.5.1736958064515; Wed, 15 Jan 2025
 08:21:04 -0800 (PST)
MIME-Version: 1.0
References: <20250115155511.954535-2-thorsten.blum@linux.dev>
In-Reply-To: <20250115155511.954535-2-thorsten.blum@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2025 17:20:28 +0100
X-Gm-Features: AbW1kva0IzuJXTuUluEZw7TyyHnuEPZQASxfInZXM9pB4COpApVcMzBsRaYzxzs
Message-ID: <CANpmjNMazT2xihFdiqqf9BP-uCb7Hf5BhCoKicuBXhZtu2_TLA@mail.gmail.com>
Subject: Re: [PATCH v2] mm/kfence: Use str_write_read() helper in get_access_type()
To: Thorsten Blum <thorsten.blum@linux.dev>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Anshuman Khandual <anshuman.khandual@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eIxt4bs8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as
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

On Wed, 15 Jan 2025 at 16:56, Thorsten Blum <thorsten.blum@linux.dev> wrote:
>
> Remove hard-coded strings by using the str_write_read() helper function.
>
> Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
> Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
> ---
> Changes in v2:
> - Use str_write_read() in report.c as suggested by Marco Elver (thanks!)
> - Link to v1: https://lore.kernel.org/r/20250115090303.918192-2-thorsten.blum@linux.dev/

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/kfence_test.c | 3 ++-
>  mm/kfence/report.c      | 3 ++-
>  2 files changed, 4 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index f65fb182466d..00034e37bc9f 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -20,6 +20,7 @@
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
>  #include <linux/string.h>
> +#include <linux/string_choices.h>
>  #include <linux/tracepoint.h>
>  #include <trace/events/printk.h>
>
> @@ -88,7 +89,7 @@ struct expect_report {
>
>  static const char *get_access_type(const struct expect_report *r)
>  {
> -       return r->is_write ? "write" : "read";
> +       return str_write_read(r->is_write);
>  }
>
>  /* Check observed report matches information in @r. */
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 6370c5207d1a..10e6802a2edf 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -16,6 +16,7 @@
>  #include <linux/sprintf.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
> +#include <linux/string_choices.h>
>  #include <linux/sched/clock.h>
>  #include <trace/events/error_report.h>
>
> @@ -184,7 +185,7 @@ static void print_diff_canary(unsigned long address, size_t bytes_to_show,
>
>  static const char *get_access_type(bool is_write)
>  {
> -       return is_write ? "write" : "read";
> +       return str_write_read(is_write);
>  }
>
>  void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
> --
> 2.47.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMazT2xihFdiqqf9BP-uCb7Hf5BhCoKicuBXhZtu2_TLA%40mail.gmail.com.
