Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBGN6CXQMGQE5INRXVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A843885902
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 13:22:30 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-366ab316910sf251335ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 05:22:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711023748; cv=pass;
        d=google.com; s=arc-20160816;
        b=sNkkSICsJnzOJx6ZuOmaEvyvP4ml6g0ICBkEFmz0Hi2U9lIH/1rH3HTbuM4+5HGkjW
         iLs7TpRxVmsldl0c/nPEJxthZpzmkfXTvvcdOkFzV+Gy577CUouchQ0S6TCT6ikQzibU
         gmGpWxRhpp0/DLLwHSkCPXj8Ii1GNos8HvewnWPqSVQeQWT67F+p89hEzsgmVaQrhANb
         9SusuN5UPyK9AXN6Hfz4z0eRHc/5msSDSwcg/Ij8BT7duEMLaZ92i2bfKtH+SIPH8VBI
         njKgWpQAiO1NLGso9nrBmZiA+rQPicWFz/hXeYNp09P/Gh/aWGKs3znhLyix2cntrUHd
         o4qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SS/I7reXgX/XMD6tUi23/dBcDVJJFkN+yknUzUc+A/o=;
        fh=+7D5B4BsT0p2QARgw0d5QrJ/ID7Lo4hd7aFq7yB2dD4=;
        b=EvbKiqDipO7G6KVRZZnzMMv57h+1YWJVbXoH+oh8K0yvdNxF/3MT36ot3strSLT0Za
         qYBs2er5T/dGxX5Z5fC1j+GQal82S3/rdwvPwIbP0BjIKWq/Hu7guRwDkQ/Xm6GmKSTY
         uVyIHw75hPk6D2CLrrY1qIkMNXEW/kIKeKmzC0XtpjrGqi4hr+SE+l31X+6ZiivgIpBX
         vDMjGYy7SSta/DQWmhuoZ4rRAZvO3Ox2CMJWFxJ0P+gsvbFQJQ51+S6WRMErx9s045V/
         fu4C39xkmA9AUiVXjveWhwMa4aaJHYqt2dG65V3/rH7RQkdQNX1MmodkLZ+f7cTY+qKT
         LVIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PeAbK31t;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711023748; x=1711628548; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SS/I7reXgX/XMD6tUi23/dBcDVJJFkN+yknUzUc+A/o=;
        b=nGj3tbsoV9+oVZhZmQLG5u6IP/IEaLqjP4JvlBupadZorRIbRX6O4Qzs8l03ZVYa66
         0DDqys8XDVPnPhxjO8iuJPc1fWM0QC71rUMuaz6IT5idhn76a6s8zgj5+jH8LTo0YUpB
         WPxpfyZ6ywnBknb+Hcpndqcc5O3LjVrFrh/jCYIXB85Ga1cglhElQrslag0t7BRm0iAl
         fh5/IFBgl/UBpHjS22MO6wvCr5CKj0v4+y07nj2zH/s8VhJgPAQZD8r+z5iBv2v2u2ZI
         kHtIjIGm5v7cBhhM5XaWyLOYys3tGOF2Ml+JeCDfngs8qr5D8l2tdrfDaDffdDFchPPf
         m2Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711023748; x=1711628548;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SS/I7reXgX/XMD6tUi23/dBcDVJJFkN+yknUzUc+A/o=;
        b=PoAV/Gs5UiyoOX01w0Vhtfq1lw/1kRoGbetLGxIkzY10LOSo6gvFRmZ3iOSPpGUQZn
         iV633yjr3DOzEW9gB1gSAqJpzoeQghZ0Qas0ObaviyFukeL5F8vahxx73CiDlaaeG0U7
         SYV6NlS59fh78lPxiYIxZxK1DglYXF/gVYSbFpxDc6Ktm3e7titKdbM07e8SRkaA2ikb
         X4ldMfDrL9M8Qb1EwUz31PEZjdroml36rtx8IqclUZyREkFvJDRXjeAmD4nEAvrqNq3I
         DoCVIJWvjegRkasCYp0Nj273Y9fcoO8YUcBJTxaZLBGVC2B7VdkohKoRujkQAUtkPr3+
         ikgw==
X-Forwarded-Encrypted: i=2; AJvYcCU9NIcDTklBen6SZ+IHilubjNcyhJz826u+FznVWWegaGOC46RkydyQv4fT1gama5z5Z3W9fmREgZsEQRGRKPDgljaDTvRAbw==
X-Gm-Message-State: AOJu0YxrSf5LCFKKGxHW0vvXs37JEL31pzlmkRZj4ckdDI7RHjdpWq95
	y3U6cK3YjhLp27Av4Jw5yaybIalT2WpKV7QrHk77Mj51rcvvPDkq
X-Google-Smtp-Source: AGHT+IEGGgkbI9d7bsG2K+zCaKEmwMuAA+0X9T15y3w9Kc8M1hEkxPlVTREixBnWx5DadaJ878fYzw==
X-Received: by 2002:a05:6e02:156c:b0:366:4898:6c15 with SMTP id k12-20020a056e02156c00b0036648986c15mr186636ilu.21.1711023748595;
        Thu, 21 Mar 2024 05:22:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2208:b0:366:a0b4:7f7c with SMTP id
 j8-20020a056e02220800b00366a0b47f7cls637716ilf.1.-pod-prod-08-us; Thu, 21 Mar
 2024 05:22:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVneoiXUrauKX5bQMmzH4xlumz7TF3/cHh5bOmNeC2XuNksYDg2cqmIp6DHX6M/r3+XIbBD1TvOHPQhTd9J6voWpMDjU9WDnow7MA==
X-Received: by 2002:a5e:d71a:0:b0:7c8:d7fd:7f54 with SMTP id v26-20020a5ed71a000000b007c8d7fd7f54mr9825637iom.3.1711023747580;
        Thu, 21 Mar 2024 05:22:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711023747; cv=none;
        d=google.com; s=arc-20160816;
        b=Ui60TndoA7JGyjZLYhxr7YwlnWFj4kIOFLkpopaXWLeKYb8U60OU/M+lhGS8oau+8r
         c9ORKVKXaAN/Z/xcxZ6vPK1yIYxuADAthmS55H5yg1Ey/agvr880tDUAlBpU5f59OeDe
         5UZYL1HIEcM15vHdNNlW/JgsG8FD8DTV2K8pfOeq8H+kDoQYxSMh+PZ651SPKRBhk3+x
         khLkGuLEmx6NTVYa2gO0gC0QRRLLP4QnlzJd8es/6Ekvw/7GVlzZuZfuhqXZXnq5stpK
         F7MP/7s9flrKEXBDvFZjBQCTsskorRRQfXEghvgul40HGLmQ9aeTipjYMa264775WxkJ
         TOXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BJtjyUU93UByaqE7DctDE27rbESuDSaozbO+roW89C8=;
        fh=BkkMJ3R7o1GuK0d9YYF9KymyH4oMhJw1c1pEiH0ghPE=;
        b=FlgNoC/l9CKpWIQbVLMN5BIzyMrZjlJrVLhUFSUKQLwFNRJls5DrQqbxxMWyLD8Hqv
         D8FFnG69ZXnE2MzDv8hi5N/soYUqeFSecwwD8IHEwEzZL9/Bk1H6Mv/Wj/RxIUBhzjw/
         t3lyvz4PC6vZsoxR7YjDpC4nqt4044SBUUhPbMnrIXKv/q3yRi5LZvyQ/yqMygu3xnV6
         1FNunN7nRv5r154QofihAwQGIHqs75Cyw9e/aL8Qhg8bKCRhn2faQgc70o6hNhJlrW0x
         NLGRQfDgQO4xvmfQrh+4Oy/6a42bfJF7blSOeAi7zLYc8yh5ek9qdOfBTosXXG7mLdL2
         s3CA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PeAbK31t;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2e.google.com (mail-vk1-xa2e.google.com. [2607:f8b0:4864:20::a2e])
        by gmr-mx.google.com with ESMTPS id z9-20020a6bc909000000b007cc589ab5c9si1226537iof.0.2024.03.21.05.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 05:22:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) client-ip=2607:f8b0:4864:20::a2e;
Received: by mail-vk1-xa2e.google.com with SMTP id 71dfb90a1353d-4d4226edea8so331035e0c.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 05:22:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVTmFeNiAq386LNJs9/uSK5Xn+tA+mYXt+dVZIGxubdNQG+Z/EXXM6jd2OxstqDmGsJjKXtR1qrIxwziBbt3+YjXxlQp3UQp/VZeA==
X-Received: by 2002:a05:6122:3659:b0:4c0:2d32:612f with SMTP id
 dv25-20020a056122365900b004c02d32612fmr5775412vkb.15.1711023746707; Thu, 21
 Mar 2024 05:22:26 -0700 (PDT)
MIME-Version: 1.0
References: <20240320101851.2589698-1-glider@google.com>
In-Reply-To: <20240320101851.2589698-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Mar 2024 13:21:48 +0100
Message-ID: <CANpmjNMNL9At6Ow41TxQUhg_HK7ctxk6XAG1=Ndh0nxit+K8Sg@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] mm: kmsan: implement kmsan_memmove()
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Dmitry Vyukov <dvyukov@google.com>, Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PeAbK31t;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as
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

On Wed, 20 Mar 2024 at 11:18, Alexander Potapenko <glider@google.com> wrote:
>
> Provide a hook that can be used by custom memcpy implementations to tell
> KMSAN that the metadata needs to be copied. Without that, false positive
> reports are possible in the cases where KMSAN fails to intercept memory
> initialization.
>
> Link: https://lore.kernel.org/all/3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp/
> Suggested-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Linus Torvalds <torvalds@linux-foundation.org>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kmsan-checks.h | 15 +++++++++++++++
>  mm/kmsan/hooks.c             | 11 +++++++++++
>  2 files changed, 26 insertions(+)
>
> diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
> index c4cae333deec5..e1082dc40abc2 100644
> --- a/include/linux/kmsan-checks.h
> +++ b/include/linux/kmsan-checks.h
> @@ -61,6 +61,17 @@ void kmsan_check_memory(const void *address, size_t size);
>  void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
>                         size_t left);
>
> +/**
> + * kmsan_memmove() - Notify KMSAN about a data copy within kernel.
> + * @to:   destination address in the kernel.
> + * @from: source address in the kernel.
> + * @size: number of bytes to copy.
> + *
> + * Invoked after non-instrumented version (e.g. implemented using assembly
> + * code) of memmove()/memcpy() is called, in order to copy KMSAN's metadata.
> + */
> +void kmsan_memmove(void *to, const void *from, size_t to_copy);
> +
>  #else
>
>  static inline void kmsan_poison_memory(const void *address, size_t size,
> @@ -78,6 +89,10 @@ static inline void kmsan_copy_to_user(void __user *to, const void *from,
>  {
>  }
>
> +static inline void kmsan_memmove(void *to, const void *from, size_t to_copy)
> +{
> +}
> +
>  #endif
>
>  #endif /* _LINUX_KMSAN_CHECKS_H */
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 5d6e2dee5692a..364f778ee226d 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -285,6 +285,17 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
>  }
>  EXPORT_SYMBOL(kmsan_copy_to_user);
>
> +void kmsan_memmove(void *to, const void *from, size_t size)
> +{
> +       if (!kmsan_enabled || kmsan_in_runtime())
> +               return;
> +
> +       kmsan_enter_runtime();
> +       kmsan_internal_memmove_metadata(to, (void *)from, size);
> +       kmsan_leave_runtime();
> +}
> +EXPORT_SYMBOL(kmsan_memmove);
> +
>  /* Helper function to check an URB. */
>  void kmsan_handle_urb(const struct urb *urb, bool is_out)
>  {
> --
> 2.44.0.291.gc1ea87d7ee-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMNL9At6Ow41TxQUhg_HK7ctxk6XAG1%3DNdh0nxit%2BK8Sg%40mail.gmail.com.
