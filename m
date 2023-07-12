Return-Path: <kasan-dev+bncBDW2JDUY5AORB2VBXOSQMGQEZQ55ORA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 23038750DB5
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 18:12:28 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1b895fc0f4bsf1382125ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 09:12:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689178346; cv=pass;
        d=google.com; s=arc-20160816;
        b=mqap5YVX5hhtSm7U3Pj9ZmcGJjhM9kTlHUiGCxqciJl7WjpNz/vneBrAKZbWfjPBt1
         giaItXk7nY6TnnE3cwvl1NO/+B5glPrkHOn1UB9QTf6ekEC0XlqnCcbRezyNw37RjYR2
         l6HsqeNhLqrq730HnVVi57ra+G4nbmtw9Vc6BJg5yOAFaKAhahNK6WgVKCCs1ZLCpFNj
         tWrJrUSlYJEW4d/ZJOsQ6LyxBpggVmO2K+YDgQb6T+KCdvfp30tAOE2YBJkcIjNrG1C6
         ViEk1QQlvuKWqM748dm8otbyujlWo+SxTF0/gDwm6G/JduJHVZD8O6sSxvzuXOe/vutn
         7kUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=2Tw7izpfeQRVwPRHlDRzTZGivkl7HN5GC/fm/yHx1xA=;
        fh=ldIy8FL/D5HsJP3a2jHoNyhY9DsoSk+zMyQbLNMxpx0=;
        b=DnZ8Qh3qRYCOQjhzEdZ/lewoT3/5nan4iSXgPTigF1szbLkdStPTqNNb1wsPc4tZJa
         e98KzYwkPlO5kP4idSiIe9uHUUBR68JAgT6+s8AjH4TOWSxxFqI18PjdNxVsoYchkHek
         r66Pj6P6oZarxutZKa8OcFtMqwYf6dekG+k62k7gWmysC58QnpskO+T5SjMHIe4bVW5p
         KTzQmoaS6QeBkBhLfEc0n5yZfqrOImR2VATnNdoEcn4cQO7rED9IzVvyn2zTFqAcEjYl
         JgjszkNPZN86om2/brd4jp1/+j50M7jgSSNPx1J1diP1rz3KhsXsEUQIOEsSgHjm77Xo
         0lkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=GVbvj3Ub;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689178346; x=1691770346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2Tw7izpfeQRVwPRHlDRzTZGivkl7HN5GC/fm/yHx1xA=;
        b=MhmWaFGDrJTAsq6luL0T2HhrcjoWmuHJyP/sLAmBTeHeVfr2D1HsO6+rbBoUz/5RMZ
         RXW94p/3sqwXh/WeQWTn8LuPSbtpzw8CIAQcJ4q+Tq3WM+kH0GpEZaZeiT6g2C4VHyME
         IQ0SBDr/PZcTJPI5wDKH7qkHJPMagf7TWpQkzCyj9+UsSQ0ybAEbOHQG42IFKKPvwyk5
         mhC6xeb/L/Y/6nRnp5S9YmWVIVp35kumSjLkAb+n47Yv3EbObFEoc51MkS0rssmEYlZI
         BZ1RqkZAGKQUTcAdj+jFxBsznNkcgkQlS5na2lY2ey1ou5Q0coiFwNjfO6ykM6mzpc5L
         e2zA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1689178346; x=1691770346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2Tw7izpfeQRVwPRHlDRzTZGivkl7HN5GC/fm/yHx1xA=;
        b=p/i6fLzvL4lcCrVMTPpWjMjdSJl14OxgAq97w+1ElKJ3y24L661tJn59ngnpfIhWJY
         /6GcV4WYs9zhI2cGBnnup37l5nBLXEORKTfkx+2D8viYlxEYxpRfq2btKnNG7b1bfHBe
         C5T62cZQVHQ3P4nWHiTycfjnczQvbKFyaTLOiaUPzV2je1Exhl480KVhnRapOhBrdLoy
         +6Fn4L732vNLEXJ5i7095/KoHDya7rZBVSDW/1aswrhHYVLRgKFMVv6ZL7V9nYhXpvPW
         2UQbjbvRRl0sKhNvJgsri9IZV+za+pWI/yxCcZ4D+UMDuAWot+C71teymkgy++x/7Knb
         9EXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689178346; x=1691770346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2Tw7izpfeQRVwPRHlDRzTZGivkl7HN5GC/fm/yHx1xA=;
        b=SdIpJtlqp1k518tD8NaN3BibhIdEVrE4hi9ILuznseNmWb0kt3dXYAY7PIq+6wH+SA
         HA7lvm40cgtD7HqjPITbVkHf/0v22jYQov20m+hMDkyWBjuJ6qBITwIlByHxDptTayhz
         +XPaIG7tSx7Eytq3DqfLJHe777y6e81EPASDEKlGvy2h591PLHhNtIfIFlQcymzwaFVN
         O/kQeRcbRy0zY/j+x+kyoyQ0sl6LNClRf/ZvGRFxk4v/MqoDiZs+dOJ/o6SAj7DQIlXT
         N+c5iptjBRW5+5RAnsns9wXUlzCle1t7v+FzF+WvuiOOuhOmn0NUVSWz/FQ5CbeRYHsP
         GL2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZMO/FbP6IDIgDbK16kVbK2LrrPSYGEo4cpII9AX3Jc+iwShwZ1
	1UURzcLqItq0Dgh7Gcbq5Vo=
X-Google-Smtp-Source: APBJJlEzI0PQmPGbRcbmCljm3ajLNXDrC2zM3+RkSX1ejbHcjrFnIjIArX+J/PPSGWDk/1g15GeuGQ==
X-Received: by 2002:a17:902:c652:b0:1ac:8835:b890 with SMTP id s18-20020a170902c65200b001ac8835b890mr245858pls.14.1689178346201;
        Wed, 12 Jul 2023 09:12:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9ae5:0:b0:666:fa2f:83ad with SMTP id y5-20020aa79ae5000000b00666fa2f83adls4205617pfp.1.-pod-prod-01-us;
 Wed, 12 Jul 2023 09:12:25 -0700 (PDT)
X-Received: by 2002:a05:6a20:2450:b0:12c:e745:78b3 with SMTP id t16-20020a056a20245000b0012ce74578b3mr17370455pzc.62.1689178345370;
        Wed, 12 Jul 2023 09:12:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689178345; cv=none;
        d=google.com; s=arc-20160816;
        b=nCM8sYk4vH+UdNlvaEk7OK040It3VjWtDYR3Vk/PEemQsnMLmL3TFPoDEoZBEUNA2R
         f5BnlEFBGvB0rzdVTRt0vEEqL1q45aPRrccEb1mJdEsiHQ6LYUbovZQEOXIaTVw/5GI3
         j22YWFSNNrfoBhmYtJYPzrTHBkRNxmYUdD6ZyjwdN96XOUoc9vVXk6cU/rldKauMqLJr
         g9MUMKeS6CwdNmy/IQVSsnm6s+n4QyiWQ3fEjrf2oMGcAtgegOnHr8GNyEjQmrVrjZmK
         ZKHtGqa/N6GvwpxkHTZryprMMTatE1dCrRP3zFXfk24PoP2r9Aknq14SrlUipE2l3TQ+
         ZWwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MyVC8plAjDRDlIDMwD83lQmMSOA5t9Sq9p0cX84tJA0=;
        fh=ldIy8FL/D5HsJP3a2jHoNyhY9DsoSk+zMyQbLNMxpx0=;
        b=kSbWm/nmv3dvUFpG/nCDXe8qS5pEok7QbkU6pWeb+PzS6iAT6as1xglGwkhyj94iKn
         nfiN3F4yI0n1+R2RmPyKyA85oG6VRage/mLJeZ9bv9+EbBmS/54JoUBbldADn97I0ymO
         AUVGylODMLrWMsTEeyF8Cb4B8Gmxx+udptZdqfZmOTMk7doycPEMPmaOpVYXShL70IPY
         bwE8S+cXCAoCfEu4fgJUBtXcz7LykmsgRr7sooIlpW0JZsmTRwZMeki3R/BjTDWtpVc+
         iVDcJql7Rtrzhch1OK3Gw6toLb4DkJdtyaHLhkiCUgd9lECcV+8n1G1190aA2gBorILX
         U4CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=GVbvj3Ub;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id fh5-20020a056a00390500b00681f56016b9si444884pfb.4.2023.07.12.09.12.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 09:12:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id 46e09a7af769-6b73b839025so6244622a34.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Jul 2023 09:12:25 -0700 (PDT)
X-Received: by 2002:a05:6870:d1ca:b0:1b0:35b2:a19a with SMTP id
 b10-20020a056870d1ca00b001b035b2a19amr25457083oac.36.1689178344616; Wed, 12
 Jul 2023 09:12:24 -0700 (PDT)
MIME-Version: 1.0
References: <20230712101344.2714626-1-chenhuacai@loongson.cn>
In-Reply-To: <20230712101344.2714626-1-chenhuacai@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 12 Jul 2023 18:12:13 +0200
Message-ID: <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tests by removing -ffreestanding
To: Huacai Chen <chenhuacai@loongson.cn>, Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Huacai Chen <chenhuacai@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=GVbvj3Ub;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Jul 12, 2023 at 12:14=E2=80=AFPM Huacai Chen <chenhuacai@loongson.c=
n> wrote:
>
> CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX hopes -fbuiltin for memset()/
> memcpy()/memmove() if instrumentation is needed. This is the default
> behavior but some archs pass -ffreestanding which implies -fno-builtin,
> and then causes some kasan tests fail. So we remove -ffreestanding for
> kasan tests.

Could you clarify on which architecture you observed tests failures?

>
> Signed-off-by: Huacai Chen <chenhuacai@loongson.cn>
> ---
>  mm/kasan/Makefile | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 7634dd2a6128..edd1977a6b88 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -45,7 +45,9 @@ CFLAGS_KASAN_TEST +=3D -fno-builtin
>  endif
>
>  CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> +CFLAGS_REMOVE_kasan_test.o :=3D -ffreestanding
>  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
> +CFLAGS_REMOVE_kasan_test_module.o :=3D -ffreestanding
>
>  obj-y :=3D common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o report_generic.o shado=
w.o quarantine.o
> --
> 2.39.3

+Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ%40mail.gmai=
l.com.
