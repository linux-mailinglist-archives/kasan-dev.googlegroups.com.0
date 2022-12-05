Return-Path: <kasan-dev+bncBCMIZB7QWENRBZONW2OAMGQEC7NYBNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A959642414
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Dec 2022 09:08:06 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id bd24-20020a056808221800b0035b94fc144asf4748353oib.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Dec 2022 00:08:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670227685; cv=pass;
        d=google.com; s=arc-20160816;
        b=x8VMXxMJQlARHtoYXUKzzo7l2s0rS4f4SmrBWQHGmE3NErGe4bz0sxQbgzTL11rKk9
         orjRYAG9X/aBiddouCWKBCrhbw8q47iy5e787XbqVqGfqgmYQjGKlPHLuPMicAFUCHmY
         YDMfpzymEaLhAFQdqwt/pxs1Ijk/S4jouBiUxLqld8ul2lzSJT19O0PsHSmzmyLcHUih
         4JQlc09EzBv1+lTU3Obh1ce6x+gFeoqSajXoe1mt0iOHuaAH/SzwZ9cDn97lRYXittQV
         /oOEvZjV0RWJmmcpseFx4m9lT4pFZ6+ze3ZfKFprva1B8eRmbMsv7PSOkseA55QM0v80
         MrGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nMIqaltlL+qLzcocfXrTKrc/Jk22S3ocOj/dE11E9WY=;
        b=PALvAA9SmRMwlFsNExhuha2Iour89FgkVun+G+N/GUb0hGJ4HVsvnJh8uZbLNTA2ka
         XfgaGwlDn+eXEI+K3bybXvHnQKAtltzErAQdJ7Ly9IYjp79lM3+ZX6bY5qAvuDyxG4d5
         96TWrlvvM/V4nIxCWHmCOeXS08+CbKyQt0k6KXDC/GhkSewfyFqJ11Zvi83+xo09g9RP
         RefY4Vdgf8M4t/DeutFrG6pKDkF/V215A4GxoWrJTV3YHXnFhZBDGY/bwaJrDiI710ba
         HtNw9rKUIZZekKyNACRzDqtTTMhchq20AW9+wzi3se8p3DrxLczqCnrHvyoYn991eUI5
         amAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HgrtIe3j;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nMIqaltlL+qLzcocfXrTKrc/Jk22S3ocOj/dE11E9WY=;
        b=S0rZK/PZKKVFtZeByTtZrLBZCuyeT0gsNrCr9AbLO5h5RoJMG64RDGTyFcGZBb91ig
         /1uGpxjboWiX9w7gifoMyCr6xJE3Sy3CYmpk4PERdZwwdgb5kf60E1wqL7lfVbDHwRBU
         yA9tvz6A/Q6UcpbEdkWH//4gutZCZ0mIR0v9x2ssqVQOIpkUu/Vi7sPxqPhFnbh1XVf7
         STseM4zd2Ve/1FHAcRLpx4RFjQf5lxiKnVVDEBkb5Zh5Yfs2zOEAuWvCwGfJp5dHGNyu
         baQy6TLll4F0UpKLSAYvLzuVRzIjjoxPprPiWgNSruVkVjdB5r02RJ4/4vnzwkWiYwZk
         O/bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=nMIqaltlL+qLzcocfXrTKrc/Jk22S3ocOj/dE11E9WY=;
        b=e0bxK9wsIG3au9AFC6X5fr4YpgOkIGY/W5+76oYbZFDAeLILmP68y+jlGkzKkkxoB9
         pueBiqy7br/lst7u0MPGgNDYkqlW2QUAKxS7GfFNQ8qiDR9IaREEPOuQQ6WYl2hdmctu
         OgDui1Mi67gHwV+ivKyeD/gTgEXlKmqHicgeC8fFrpmXV1LF4JWYYDd0ocmO4Z5KDnTV
         N0o7k0jWKebMd1vuWjrVyJDcKFLc5FQfZ8Sksm+zoT91T5gbzoNOele5szjRK3f9n7Uo
         kmKOmnBlAEoA5Uhsl9wg6qYhbwvvzuAEavIV8pN/uH+thf6B8T+pMrKAVPW3EdVY3Q5s
         coPA==
X-Gm-Message-State: ANoB5pnk1iQ3TGgYC6wJAVDiZw6eEuwxXCg7WCw+5Ggh6BghCiU2+/nl
	Ulfr4UdNiqSWcqpRKd9bxu4=
X-Google-Smtp-Source: AA0mqf6dqbi9T978C16fb8LZFiREoTjjWnPjTR5CbzPSY4Vkzay+GLUg1sv2ovX3NsOxXUbkb5HxyQ==
X-Received: by 2002:a05:6808:1210:b0:35a:1e63:58a8 with SMTP id a16-20020a056808121000b0035a1e6358a8mr43415327oil.27.1670227685251;
        Mon, 05 Dec 2022 00:08:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:37d6:0:b0:4a0:92c2:ea41 with SMTP id r205-20020a4a37d6000000b004a092c2ea41ls161450oor.0.-pod-prod-gmail;
 Mon, 05 Dec 2022 00:08:04 -0800 (PST)
X-Received: by 2002:a4a:aac5:0:b0:49e:c838:2e40 with SMTP id e5-20020a4aaac5000000b0049ec8382e40mr27624115oon.42.1670227684819;
        Mon, 05 Dec 2022 00:08:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670227684; cv=none;
        d=google.com; s=arc-20160816;
        b=aAUhbQV9r8QO1Ix7XTb3ThPfBPL55k3nWKusk9N8tWVtFXcZ3GDhAoVSG+oOcZNkKN
         u6pgANdIdBTfp2YvZpCF/KMapvZNIIo8+wzL/N5DIXA9uO1XCJJLEDG8NGhJJGlLDj+0
         hw4kSHk3cLb04zZp7l9dR5iDN6Xg3w8Jcjk0ZOljQ/hSSOe537Xwvrv2el1XTuygURxf
         RUlXKwP6K7oZEYU1ZTVJ7B05gwtnvg/MH78SX02FbgiEQruyIG/IpOeEmFL64sMCz93h
         Y/CFvEBS8uF5NwRLAc/gJGfX+27rcej74JYxdGdJ3ViAJzpH9t+64IJxtr4GGn8qfSE9
         bx2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4Il1L0a9yN5jMi0NqFU5WFtlB3kT0mSKTxZJfZftf5Y=;
        b=aHe4Owtsl0hs0BpPdBlk2ABuYzjHu0mwkj35i72alBkuhP1cFZIvBev9yVtJ/bK3bk
         o6LuiAs7+EHDaUkInmaRIqZhsFIJ+Y1CvFRXblOD9cm8OhwOyWzz5VGJFwmNiH+XLYDn
         +zXFwr3VbunxYq+tALG+uvI1en3QbnzDViAibqxzOpfK3Pw2zc64svgFNC8cHjN0qVIe
         5vJoUv4uN+7PxNqwRcdW7v65fp1eH5ps5CJQzs1XTiB3kgrZ+FAIPDOVqwIzdAaKtWBA
         uTJ8+KiEZ90lxNAxs7mor78sRmWHtQv9+tcml6eznDqWKy8POKEi/267pgWo23NJL0/t
         KQCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HgrtIe3j;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id s125-20020acadb83000000b0035bf27206c8si492546oig.0.2022.12.05.00.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Dec 2022 00:08:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id v19-20020a9d5a13000000b0066e82a3872dso4751067oth.5
        for <kasan-dev@googlegroups.com>; Mon, 05 Dec 2022 00:08:04 -0800 (PST)
X-Received: by 2002:a9d:351:0:b0:66e:6cf5:770a with SMTP id
 75-20020a9d0351000000b0066e6cf5770amr10433067otv.269.1670227683785; Mon, 05
 Dec 2022 00:08:03 -0800 (PST)
MIME-Version: 1.0
References: <tencent_922CA94B789587D79FD154445D035AA19E07@qq.com>
In-Reply-To: <tencent_922CA94B789587D79FD154445D035AA19E07@qq.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Dec 2022 09:07:52 +0100
Message-ID: <CACT4Y+a1nRTs-yu-5U6dfBB==-WN2ELXM_DdqrtFVRNRGxVRcw@mail.gmail.com>
Subject: Re: [PATCH] kcov: fix spelling typos in comments
To: Rong Tao <rtoax@foxmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux-MM <linux-mm@kvack.org>
Cc: Rong Tao <rongtao@cestc.cn>, Andrey Konovalov <andreyknvl@gmail.com>, 
	"open list:KCOV" <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HgrtIe3j;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::329
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

On Sat, 3 Dec 2022 at 11:25, Rong Tao <rtoax@foxmail.com> wrote:
>
> From: Rong Tao <rongtao@cestc.cn>
>
> Fix the typo of 'suport' in kcov.h
>
> Signed-off-by: Rong Tao <rongtao@cestc.cn>

+Andrew, please merge this via mm tree

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  include/linux/kcov.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 55dc338f6bcd..ee04256f28af 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -56,7 +56,7 @@ static inline void kcov_remote_start_usb(u64 id)
>  /*
>   * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
>   * work around for kcov's lack of nested remote coverage sections support in
> - * task context. Adding suport for nested sections is tracked in:
> + * task context. Adding support for nested sections is tracked in:
>   * https://bugzilla.kernel.org/show_bug.cgi?id=210337
>   */
>
> --
> 2.38.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba1nRTs-yu-5U6dfBB%3D%3D-WN2ELXM_DdqrtFVRNRGxVRcw%40mail.gmail.com.
