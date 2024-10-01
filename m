Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVH7563QMGQE4PWFO4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 29A5898BEA2
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2024 15:57:42 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e25c9297cc8sf8302422276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2024 06:57:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727791061; cv=pass;
        d=google.com; s=arc-20240605;
        b=dZ1scvTOMmEryot5z9G8Td19OBj+qJ/qXL8Re/x+yLayjRhFH7guHyNaTOgacK2JMa
         o4g23yb5wk4zM0pSKomCfk1mNxwYUDX03UxigUw+EdTTSHofTmfkDDw7NLkNq9H23AN1
         5yieApJcs9Ifks0lXG5LFz+mgcskEinE2QwyroYH7P15UdUrxZMQLnxNCGSE7oJ97huT
         swHZC8Q3jLJYmIUqQkL7vMEA1ei+b+QXIJU5ojftg126hyKyA2odRiYRSWpi11TFsBEv
         T9K/p7UwQRGvVq0V5EcbQtwWpFMM4OG1eYl4AfnkdXrbIeHNMBxhsvYziC7CWwTOoBwh
         7rbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mzYB/Y4n8iskJDxviHVYU4NGrnB2ch4tQBGMaMfZFIk=;
        fh=3X1+8f1fx9kNgNyDJFWOaY31NUH2O8HGTgcXleMZdgA=;
        b=KTovZbto0k0GD7mWIOlssI8pPtvSULAA9Xxa8gdWZecbgV2kIerFFZOUDmmWn+Fgbp
         fU8IkLGg6aep8zlrmltP5IL3YWJ44ERwp3sa80mh0PX2Y/aASF0nkRoVeLxJR2yMXo2a
         uHMor6nYeWHQ0KmwCKGxdxcOo6LgJzklzCM6Y6UGjRqNNYjMILJyqkL9QqpbscrZekaA
         oVqMo8SBDtZc99M/sgMhtQL8a/G6WBln74/V5QfgEdj4Aukevl/ubiMpIJMa9bwalWCd
         TmtK1tmPlfG11rzHjBZPMqznhxcxh2zlbX44golEI1sFLHZEpPhdce3y5hvAeqSGfmOW
         X4Iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QuJzXIlt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727791061; x=1728395861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mzYB/Y4n8iskJDxviHVYU4NGrnB2ch4tQBGMaMfZFIk=;
        b=sFHzQLbMmL/84iM42RGYpNHe41flY0tv+CWdnO4KuFMl1QtITeBK+Is9vhjqOAAG3R
         fvlW2gNm2Q/hapxcLLpuq0WXWGmko5Ia7bWVDR+c7BTo+BUhDJYfog7M+wekd9UNqJGG
         PdFvY68eTYGBYXXaU8rQ68A9C4gngqjzJ4k9+LXZoZz70BIG/COrvGZ2v3cQQcFbneok
         njsoimlvl6Pa9G+0RQ0GC4oyYKgX5/aqvamMsMENGogKA08a2BL3GragTM34BgUHwKiU
         GMAiDupQ9mh5D+uS8dozngchIG8VxPgUuBNroz/99y+1cCA5y71nUu3Eaa+2k8TaY6qC
         uicA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727791061; x=1728395861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mzYB/Y4n8iskJDxviHVYU4NGrnB2ch4tQBGMaMfZFIk=;
        b=Z0+sSvBFwzxL03CmgWNJHl6YV0teIfEhTafMttKe4tufgh7BZ19unpeFLv9r3YGSZX
         e+sylWHtuBUV7wz7FL12s34K+bsRS2OrdSjOwmCqjHGY6pm/8rlAs8FhIwVPRTfd2a8i
         K3TzRzJNs+hcJX8IyWLTrv29qOwLNPsWMECLWcg2qTvgRy6/OjJK4IQ03L34gRL5xb8F
         XdlyAA6JoUKNsm/fc7xy/DECujwwqD5qkSHndfTi9KDnZI8azQCm+BxLhn/GK7fY+Zgt
         fRqsqcP7TWvEQpxO9MQEAnXAp6rlKgCm8SkOQ0L2m8e9TA2XB8q7CILMse4sQGk9kNja
         VTYQ==
X-Forwarded-Encrypted: i=2; AJvYcCVGIpOq4+NlnyffuCJSBCa2O/wz193GRAfT29LTPJQRru65NfMOw4YLryRpRuhqcgBZPVFzfQ==@lfdr.de
X-Gm-Message-State: AOJu0YwKypXV8CZzbAfkEXlRtgIZCu6w7pVt2cklzR+oqtvGHBuwon7d
	lju3HfyQdxPsbvaQkyGE+dLnmebudoM3ZhOGXoHY9uA3Stwc3XLV
X-Google-Smtp-Source: AGHT+IHSmrS0ZR2f9jVaTBEkSnxoTJpbD90z6EoF/7GPUz/xz+X7o8xmqyhNrDF6TVO2wXdjzp9rqw==
X-Received: by 2002:a05:6902:2191:b0:e1a:a665:1db4 with SMTP id 3f1490d57ef6-e2604b6d766mr12818149276.14.1727791060829;
        Tue, 01 Oct 2024 06:57:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1022:b0:e11:6a73:8ffd with SMTP id
 3f1490d57ef6-e25c9faad14ls1413870276.0.-pod-prod-02-us; Tue, 01 Oct 2024
 06:57:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTP6AcRXLQRnaKZkpV0bBflicuJu+1lDuGn0kpYJ3IL2Fs1vBZcWu4mVJWMHK9CQGMmnpokh3Kb0Y=@googlegroups.com
X-Received: by 2002:a05:690c:d07:b0:6dd:ba9b:2ca7 with SMTP id 00721157ae682-6e247632809mr106335777b3.46.1727791059693;
        Tue, 01 Oct 2024 06:57:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727791059; cv=none;
        d=google.com; s=arc-20240605;
        b=N48LBdfwylSXEhVnWvk9W5bC0/KKIB2/tvPEQt+VHVC55vcaDRmMnnpLUJPgUwZCyR
         NY/mB9LLkqIFyT1LtGqoZP6xN6eqNf/8+XAnlBIHuVLPPXLnxaV1x6TcThbzKEjb0LTN
         46PMSTsm+PnXos4EWxyo2xCvMZqmf1syd36SfzZsBrrm0KKVWlghUbaHecByyMmAStsp
         0qZfK0dIhn8MBwuTotnZoz2n+vIpQiDXe+1KTPsCimITAuFmnlpmwP8aMBNcQ4c04Xfr
         fpHaNgR9icQXkkLUL1yr97ieI33cV1GWpD//ZwIamE0J3EBDIJiJ//v1GkRjTxAjV1qD
         3GVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tZuvfapWSfcTxW9oAzTmyzPbGIeg43d+eoh3qwTSmWA=;
        fh=U24Vh2/lnYWUqk+6upIrFRxg7CQak67Aoj4CKAuERA0=;
        b=PmmcE0WcoXTzOb+QQaGDPU/90IELe7vEpuvIsS4G8NZPf6Ej3xPJBKDYAH+LQS/p4k
         hV5qmChLyDYBa54c2c689FdPM2L92DGIfT5ZRKJC/dD+k1m0WJN8GelMPXDK6pcDISQG
         aLb0nqBWTR48zTS4CDXWkjQhO110Hd2bRD/I/ndSXybNGXZUywYXcwYcIuaFHVACFA/8
         c812DdlFusDwd/UWp4kTy9wqRJW3IsKdbjvVbJcR6gd1wHMPKfRkq6h69e7AEZy+x6KY
         BE8oYdFBZxSus54zJwam34ZiuZH3PmMUlhH9/bQ7geQTjxw2QsFvg7x/lbHY2oW920y4
         054A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QuJzXIlt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6e245380df1si7865077b3.2.2024.10.01.06.57.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2024 06:57:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-2e07d85e956so4727038a91.3
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2024 06:57:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVnuDs7/YdH4gDZC0BZWIWovbRMn4YCxvPrXpjB+7wgCtfn+E1Y0MzuyJdh9TwvuxYk1cmXHtJy0gE=@googlegroups.com
X-Received: by 2002:a17:90a:a88c:b0:2d8:71f4:1708 with SMTP id
 98e67ed59e1d1-2e0b8b1c5c9mr17858783a91.19.1727791058530; Tue, 01 Oct 2024
 06:57:38 -0700 (PDT)
MIME-Version: 1.0
References: <20240925143154.2322926-1-ranxiaokai627@163.com> <20240925143154.2322926-2-ranxiaokai627@163.com>
In-Reply-To: <20240925143154.2322926-2-ranxiaokai627@163.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Oct 2024 15:57:02 +0200
Message-ID: <CANpmjNM-DHav6B7h4ZeTQd9KERY0dKD9qYQ1RT966aLTvbYnfw@mail.gmail.com>
Subject: Re: [PATCH 1/4] kcsan, debugfs: Remove redundant call of kallsyms_lookup_name()
To: ran xiaokai <ranxiaokai627@163.com>
Cc: tglx@linutronix.de, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Ran Xiaokai <ran.xiaokai@zte.com.cn>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QuJzXIlt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as
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

On Wed, 25 Sept 2024 at 16:32, ran xiaokai <ranxiaokai627@163.com> wrote:
>
> From: Ran Xiaokai <ran.xiaokai@zte.com.cn>
>
> There is no need to repeatedly call kallsyms_lookup_name, we can
> reuse the return value of this function.
>
> Signed-off-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>

Reviewed-by: Marco Elver <elver@google.com>



> ---
>  kernel/kcsan/debugfs.c | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index 53b21ae30e00..ed483987869e 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -181,8 +181,7 @@ static ssize_t insert_report_filterlist(const char *func)
>         }
>
>         /* Note: deduplicating should be done in userspace. */
> -       report_filterlist.addrs[report_filterlist.used++] =
> -               kallsyms_lookup_name(func);
> +       report_filterlist.addrs[report_filterlist.used++] = addr;
>         report_filterlist.sorted = false;
>
>  out:
> --
> 2.15.2
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM-DHav6B7h4ZeTQd9KERY0dKD9qYQ1RT966aLTvbYnfw%40mail.gmail.com.
