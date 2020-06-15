Return-Path: <kasan-dev+bncBC7OBJGL2MHBBENXTT3QKGQEWOQ2VJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id E3BD21F8ECB
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:56:18 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id o100sf11995960pjo.9
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Jun 2020 23:56:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592204177; cv=pass;
        d=google.com; s=arc-20160816;
        b=zZl/jCblwxvx8Pg5jVzboUBRP4Yr0toy1I6AO1c0c3+oeCa3yDaZtsUs2dao3AFllB
         5iReHlCFB2qEfBtrVnyr1q6X5r9iClJ+t/tPREqo2G4dDMyWShVn3ZiJpye+midgngB1
         2ZfCQKkLXN9A+hjmQ9RBM47CtEHav22lJECrGLuDDYAOG+ajB/n8WiQbflQ6ET2CnpVl
         /mYlYr4wkGF9CWUJi3SSLufgYULMr2dgrS0R/xZzVPD9EGMtvB60bOa1dDn8roAzNhMI
         RC2EPFxmdlYkY6Jbb/Xe5A8qgTDRkRcuXquZDS6Iea9yj/GtXBePCIp6RSpXEQp0c88W
         Vddw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c6ZVmQyo1M/fV+pl41nq9WZICT7enJApODKqOS9a2H4=;
        b=gxIIAk3AyPJTdmo7JdHIuWJYbPCj20QIqDoAWjye5+0i6lFrvIQoc3OsWb/zWSxu7B
         EmZNMOMzRxzhCBmHWDdg9EuLSwFwvSdDYEvCMD87RnlWsFMV6Uz9orSwLdzdswjC+VfI
         lYILdblS5+wJwp72MeNy3BfuDRAAaNWhW19SlqY8hCQcV6Z3gMdZa1errfNZdwKeajvd
         SQ2UXQja6zOBG8d1bkTzzDYK55aO5/38aGmhghRVv5OQer5Fr1OKAioS9A5iK1hVXtYb
         8g9aRptwgI8VPsAHXJ/jNrZi23T9+eKbghsBKGap8SM3CbvckQ5hTNTfC0/gzBkBHSNw
         115g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nGQLYmHs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c6ZVmQyo1M/fV+pl41nq9WZICT7enJApODKqOS9a2H4=;
        b=ogtQqO4lpvBTvHVwhN+thwzhBHPMK2d2X+7gTRXvKv4qZOSL3XUc/e5b7nMMgReJa3
         NzXZ0FczoU+KsM21q9q4NFdWcBJ5HjEiG86IZETBQ/SRxcU0lmLltNi1ZrhkYg1THL9E
         LIj+0IzTq9b9RxQxD9xxofdw0oq05+9znH27wIJoN0AyldnkuUI7PqQqUI8P8Ea6eYDi
         7Y3L9U3GJ3q2jcGeKTFYAfDcj86UNDFCXjjsvXLKWZaPXPIMVWMzIm541vSqa5YrBAy/
         s4OZbm7BsoW6BsGbwzH8DbkzP9Hh7WifCDmrFRwL7tKTiN3yguGCuapFBDQrZBs9uSGZ
         HrJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c6ZVmQyo1M/fV+pl41nq9WZICT7enJApODKqOS9a2H4=;
        b=O5/PZ/S9RGJixNsz4PvRy1kIPqOsj8njxUQPF4ZFZ5BjD1BcgbsT/iR2dY/pTWT0Hf
         qUSJ2P5jOJODtURGjU9BMybz5Bukwn2TGsZiO7XAZ9QuV9bdvJGX294apasDMIIS272z
         iLrLe805MOfhTT/UWDG9MqdvNv4bj5mlC1VBm0b0rsUV9l0XRRG04Rc7py4txLMLXj64
         kNVOfGNTd2LeRKadihFd3HCuz2JmECpt1MLDZyDYkgD6a4TfTbRqc11MLx4vY4vWaCec
         ii1Z+hcGOpvIyPDmxszsFuvlqVAytcxVJbVGvV83CGljE7+DQVw1QaO7bWjtxScfvwak
         V8qw==
X-Gm-Message-State: AOAM5325bLSUaNugvCt+q4GnRxFrAbRxjJMl3Q516YOLB7xV6ELcZ/3x
	y9CGDG35rAuzoTWyiaP/NkU=
X-Google-Smtp-Source: ABdhPJxJrvLqG77NzqzRVV1i6hnM9ted58P001NQdQYrL6iQ6NtbcHnC6+MlUbDcZNGm+n5Cw8Zo6Q==
X-Received: by 2002:a65:6883:: with SMTP id e3mr20425195pgt.5.1592204177372;
        Sun, 14 Jun 2020 23:56:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bc4a:: with SMTP id t10ls4512606plz.4.gmail; Sun, 14
 Jun 2020 23:56:17 -0700 (PDT)
X-Received: by 2002:a17:902:6a83:: with SMTP id n3mr10381846plk.42.1592204176935;
        Sun, 14 Jun 2020 23:56:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592204176; cv=none;
        d=google.com; s=arc-20160816;
        b=rmnUqlFraWa+otc36kw47TEvm7D2o1qC9KkkebqwAG4Upm/1ufWVMwrjhuZrNlENUW
         U5tPaguV7vH6IcindyNzXvDfZJ7U1TsLV2+s1I5HgyMNc/jE5dnVjdzJBwZnyDU0LMM0
         utvlOFsak6NOjivQq4wLSGT/4mLw2mlx4oXq8yZQfUgFtZ/WxzpzwR6eIiVm52qPIwgr
         0ZwmoYH20z6dBh9MbERLipeAj/tQlEBIW4WyvX6jbngJP/55gJPpXl2Ub+Rd5DY1Jq/+
         yiDkplAGp3mI+Hvyu565Mu3ei/4LG/VO5aPUJFuRtcRM8CeEDkv6YAeuDZm81BITM6hy
         ZJcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=73Ts2qMXH6Mk0E17JEUm55xx1LaHy8Bs/ltMabJ68jY=;
        b=hJPzFJv0GH4M47cMlWu1nWfi+Ipz/KF0/w37tZANiQz8uymofQ+GSNiEmFosX7NRXg
         q6Av7eCtMsHu8qO85s3USY0y7C+iQJE/LUbFKVpLAwBn6i9UebKrD8wpyI9sKUKJsP+L
         S4KZru/1oVjxKVA6ezf99u3SoyTKPLsj58eLXD1zgYK9rJJDCQ7VLQo5boafH4saMLdH
         /yb/dak0yja75uiiTXQQC3A/XAUMgvO4mLwnAZu7q3ZABddIv5h0JBoTnJtPlfB8yO06
         S+9oe4abLI+IRW8JgGRKO6IapFGGOjqkW/xAp9WpHO6yG8axcKdTq9zy8BFjzeIJjKP4
         Bkng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nGQLYmHs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id q194si931070pfq.4.2020.06.14.23.56.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 14 Jun 2020 23:56:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id a21so14951082oic.8
        for <kasan-dev@googlegroups.com>; Sun, 14 Jun 2020 23:56:16 -0700 (PDT)
X-Received: by 2002:a05:6808:34f:: with SMTP id j15mr8004157oie.121.1592204176060;
 Sun, 14 Jun 2020 23:56:16 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1592203542.git.mchehab+huawei@kernel.org> <019097f1fe10e38a04b662f1d002ecc0ce8bef8a.1592203542.git.mchehab+huawei@kernel.org>
In-Reply-To: <019097f1fe10e38a04b662f1d002ecc0ce8bef8a.1592203542.git.mchehab+huawei@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Jun 2020 08:56:05 +0200
Message-ID: <CANpmjNOG2PmMoCQgNk3cJrm+ZFP0+VYpBWma=xRfqoyxbLZp9A@mail.gmail.com>
Subject: Re: [PATCH 09/29] kcsan: fix a kernel-doc warning
To: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
Cc: Linux Doc Mailing List <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Jonathan Corbet <corbet@lwn.net>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nGQLYmHs;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Mon, 15 Jun 2020 at 08:47, Mauro Carvalho Chehab
<mchehab+huawei@kernel.org> wrote:
>
> One of the kernel-doc markups there have two "note" sections:
>
>         ./include/linux/kcsan-checks.h:346: warning: duplicate section name 'Note'
>
> While this is not the case here, duplicated sections can cause
> build issues on Sphinx. So, let's change the notes section
> to use, instead, a list for those 2 notes at the same function.
>
> Signed-off-by: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>

Acked-by: Marco Elver <elver@google.com>

Thanks!

> ---
>  include/linux/kcsan-checks.h | 10 ++++++----
>  1 file changed, 6 insertions(+), 4 deletions(-)
>
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 7b0b9c44f5f3..c5f6c1dcf7e3 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -337,11 +337,13 @@ static inline void __kcsan_disable_current(void) { }
>   *             release_for_reuse(obj);
>   *     }
>   *
> - * Note: ASSERT_EXCLUSIVE_ACCESS_SCOPED(), if applicable, performs more thorough
> - * checking if a clear scope where no concurrent accesses are expected exists.
> + * Note:
>   *
> - * Note: For cases where the object is freed, `KASAN <kasan.html>`_ is a better
> - * fit to detect use-after-free bugs.
> + * 1. ASSERT_EXCLUSIVE_ACCESS_SCOPED(), if applicable, performs more thorough
> + *    checking if a clear scope where no concurrent accesses are expected exists.
> + *
> + * 2. For cases where the object is freed, `KASAN <kasan.html>`_ is a better
> + *    fit to detect use-after-free bugs.
>   *
>   * @var: variable to assert on
>   */
> --
> 2.26.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOG2PmMoCQgNk3cJrm%2BZFP0%2BVYpBWma%3DxRfqoyxbLZp9A%40mail.gmail.com.
