Return-Path: <kasan-dev+bncBDW2JDUY5AORBLUX3K4AMGQELWVU6RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 710E09A70BB
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 19:13:19 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43151e4ef43sf34809685e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 10:13:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729530799; cv=pass;
        d=google.com; s=arc-20240605;
        b=ND2tOXj2C4kEtxnH+GAQH5AzMXpwjNsUbJT7RjYtPcKsHGNFiR4MvECyBiiUdccVam
         qmAkVb+qEJZkmNumD/HftbW8lSoU3EUMptPg1dqavd4vF1NYeAQgr0lImjE96GoqPXyM
         bYVyieUAIDfsGdT27zSp2lPCG7ASejiU3agT4qSUDkcctaFGB89wgsQyAK1qVNDO0hRe
         B9wu0hXcvj+DfUkdICgxqF8ZsurS/RbsufXHmARRpw+nCedLtyjksQlgBhR6IUJNL8f5
         okz8USg/qGaDUjULaRmHPG7eI78drpKdZqOkoG1O90EAbS/wnX6USOpljXgfnmEWpsnj
         8luQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=z9cQycCXHJZCRBi+Ewnn37qSfM/g5QsdS7Jlbwt2DeU=;
        fh=7LOGi2vIfOFguezi4r4ZcENFLXM5IxKNAQeSqu6IWv8=;
        b=FND6KluhjRq/8gXOAoLqKCetVTM+hctcXA3C8273ihm3Y0cbB6FzY9k5Evr9aXI4ef
         Cmx3Up9JMa9e/nNvkC3838eKN1NdxyFZKvuhxT+7Q/X4LCz3AmSxM1JcHR/y3h4fS9+Q
         pZGVK9+z3/Nk3ugLENz1Us99Sl16gJaPrhxXBvi7WCdaQj0I4jLnsj++HCK7JEZTc1C0
         XmxybWRNXheZrB9IbHO8dAamFDVzDg75VKZIJ0HoVnk5TDjiqjGUGwhJrOW3yiGAmQwm
         7VUEh6GJ8+3PbtQ3wFOSbtec1pWaGw4J9qltf2+HZ9d+eymoR3gvOjwcmJi2PVe6MvhQ
         vvxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VVgg1f+A;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729530799; x=1730135599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=z9cQycCXHJZCRBi+Ewnn37qSfM/g5QsdS7Jlbwt2DeU=;
        b=cmWa7pl0zVO057Sit+rm1Z22TgUcQJZJ4y6Nn3KpVkF/LW38CJU2OyXQF/RmzRKuxx
         nSTfooFqn4UiTKJO9oMQA/uTcxhg8/PbzQQ81OM/eXqdg0RxlZmAVuTLdO9Jw/wiwUOt
         id5v1Fvhtp7Db6ZFpzCLrxQOS5B4HKe23NqKS67/kWRG4xPYZH2VncXFaL42ExVUinTr
         Df5R9b5V2xuw7S+rilvPPONXGjT/d6iITjkRJWKfF0weBLCrFEGenLe5HyXAF5PO6OeF
         hvGCDK8JitPuHLcQoq3EqnvI49Z8C/skHQ7Cif49bJAvTDmY0EMYP10wYb/WN6ImFUrd
         7yqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729530799; x=1730135599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z9cQycCXHJZCRBi+Ewnn37qSfM/g5QsdS7Jlbwt2DeU=;
        b=ekTDg5kDHnZO+MaJbgvlo6fAp9cx6GRaJqAdN5d57FVaL3YHQM4xzAPNbfGOPTUJiB
         Jm6pT3hjruhgr9CoQbQaUA6JxsdOY1zHthHPaEnVw9P5sz+wH4DSiW58idf9ZpCFnQv6
         H4hpHhT8VfWL652lzxZBJnrU0uYw2t/t87Mt9MlwyKp/SrjU5BpXGt6T4aiD4LO15ul9
         NSCq+1YHTkePkz+UzSnq5fXf85gR8jqqna7JqYfuLmjSu/EQCl8j21Hb+As1p5xNsuuX
         sUfkg0TSryWnvzNyYNdNOzdIAEx3HkuTUn6cOrFGoDJIuRIbY6kNeMMk7WALQemDAIt6
         MsdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729530799; x=1730135599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=z9cQycCXHJZCRBi+Ewnn37qSfM/g5QsdS7Jlbwt2DeU=;
        b=U/EGTOgGWVm0HXgWvT/VGKTaUedeBjTfL1FZcXEOXMSyiPvHQ9ifMFSGgEzMhc15Ds
         fJIK1Ws+tAyO+g15zFYj+hpWj24XugEeP0PBTM4vnlborgOzGTSd4Z6Uyp8xG6aYUq/f
         BfXMjgj886HDeZx7Qv4oo3Ib0yszLr3sWhobxhcBGd3j5B7Aqz5y2FTe3ZGHAESFnflT
         bP0HO84ZT5aXybhYpcrEXLhYuJtNRyoZLffTcGzoOe9SMJcr16C2PtkfBEyg6mybuWmo
         yENwyr21t8NBcJsc9SGkzF/eUpBhmtpcm34iccg0vxPESdZAnFOxCqKkxgJiPVypc1yJ
         upnA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWIPC92+4+QkTPDdpKCLMifBWHkeARMPjig32L1FIirrPD0ayEjQcwQLtJeXQ76X+Att6d6MQ==@lfdr.de
X-Gm-Message-State: AOJu0YzxnG+uNSqzrnt05WWssNdvN4+4SXVdTrfrTmsbPkcmLEJ9ygBJ
	w0PUk2YMyViICsxwhTukodzVOnUaNhPYWIFDU70cGxSzHz9V8PWY
X-Google-Smtp-Source: AGHT+IF1b2chTjcDECz1o+a0lA6ZDEf2zoVBrT9jtfKVWsUvQBAYY31ICzpl34iy81zZTGMJd846Uw==
X-Received: by 2002:a05:600c:4fc4:b0:431:5194:1687 with SMTP id 5b1f17b1804b1-4316166a1cbmr75206425e9.18.1729530798604;
        Mon, 21 Oct 2024 10:13:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c29:b0:42c:b1b4:daf0 with SMTP id
 5b1f17b1804b1-431585a4265ls3967885e9.2.-pod-prod-03-eu; Mon, 21 Oct 2024
 10:13:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0CgQgZ35cQTVGvzWyYoNAydh47VAVLs3YoVl/5/IqOUkHf/9TOKeQ+D14QSqRRP4fjszxF4Kj76o=@googlegroups.com
X-Received: by 2002:a05:600c:4f4a:b0:42c:bae0:f05b with SMTP id 5b1f17b1804b1-43161636fd6mr100558615e9.1.1729530796752;
        Mon, 21 Oct 2024 10:13:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729530796; cv=none;
        d=google.com; s=arc-20240605;
        b=eMOSEjGOicTzqzg1ADejbUWoxBHa3XF9fbIBlQYs6dRU3/ZHf4z9UbRrcKjgBjNJlP
         BIdRejuhD/9VdK1yNWhS7IJnME6M6QFLwBIUStZLOzH6Q8I0acfjkKo26XGqIYWtG158
         V5kRlmkP3T9/oWsxA/ZPKpzGyBnNJcGLaRX2b67P/7V+n1B1htRMQj10xyqm3QcS4MUW
         xyoH4mgX2d2sCj3OT+Ske2yTHVIGYnegkd1BaD3AfQLSlGXu6eeiAf5e1sUYk7F2lYyg
         txM/JFFcIrv8dsIFvWFfj7xJIr+Hki5JIj7SIUBPQkHqDqF+JkkS1ja6U01ZrI6Nxay8
         txRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vIluIAwMUTUE/eR1vRRj+RdoUmdMgjbC2v9uVOonL6s=;
        fh=8fTWlR7+1LczE5m7svZo/PCc0j8JkJWqrI6QgIkj5hs=;
        b=DQJtvRXUSAHKpTwV/DrHTu3ky/+rZ85rrPsOEu/mAlZG1mVuHQkoSFluWxmCJtIp+X
         xYRA0ByLMJ+3VlafTB0ZfNFoFUQPl5Bs3OOkk3rtwxouZPn1XftNLRTv/rxiFe158Wpq
         qrcxNoLro+f9xcVZBckNFhQebmfLxInb7hLPVbv/2t5ncCCYZSOOFkbgYCE+4tP83lR6
         TCsulcDtek4e0Mu+mK4n/SX2QWjhSLRhu/H3KXy9wSmbCVlg3ryJ2xoNLK7YQE7iEjUA
         nKAq8gIK6h+/QagZNn8qSORMgSsM03Uou3+X6nRrpu6/iVrmOBxn3Okdiq80KgHgyh++
         GyNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VVgg1f+A;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4317c61a934si445e9.0.2024.10.21.10.13.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 10:13:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-4314b316495so45603845e9.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 10:13:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXIeJa5Izi0XWgzgHn2DHPzokXW4OqvD//37HubzFPolTvHmK7r1v/tkbDalJ7kuLyZkZwcfMAcrpk=@googlegroups.com
X-Received: by 2002:a05:600c:19d2:b0:431:3c67:fb86 with SMTP id
 5b1f17b1804b1-431616a404dmr89446045e9.33.1729530795938; Mon, 21 Oct 2024
 10:13:15 -0700 (PDT)
MIME-Version: 1.0
References: <20241021120013.3209481-1-elver@google.com> <20241021120013.3209481-2-elver@google.com>
In-Reply-To: <20241021120013.3209481-2-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 21 Oct 2024 19:13:05 +0200
Message-ID: <CA+fCnZcU1P5RxLmHekgsWGWQZ+oOQQLqH_LC0JxqBtLJqR3c7A@mail.gmail.com>
Subject: Re: [PATCH 2/2] Revert "kasan: Disable Software Tag-Based KASAN with GCC"
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Mark Rutland <mark.rutland@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, Andrew Pinski <pinskia@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VVgg1f+A;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 21, 2024 at 2:00=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> This reverts commit 7aed6a2c51ffc97a126e0ea0c270fab7af97ae18.
>
> Now that __no_sanitize_address attribute is fixed for KASAN_SW_TAGS with
> GCC, allow re-enabling KASAN_SW_TAGS with GCC.
>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrew Pinski <pinskia@gmail.com>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/Kconfig.kasan | 7 ++-----
>  1 file changed, 2 insertions(+), 5 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 233ab2096924..98016e137b7f 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -22,11 +22,8 @@ config ARCH_DISABLE_KASAN_INLINE
>  config CC_HAS_KASAN_GENERIC
>         def_bool $(cc-option, -fsanitize=3Dkernel-address)
>
> -# GCC appears to ignore no_sanitize_address when -fsanitize=3Dkernel-hwa=
ddress
> -# is passed. See https://bugzilla.kernel.org/show_bug.cgi?id=3D218854 (a=
nd
> -# the linked LKML thread) for more details.
>  config CC_HAS_KASAN_SW_TAGS
> -       def_bool !CC_IS_GCC && $(cc-option, -fsanitize=3Dkernel-hwaddress=
)
> +       def_bool $(cc-option, -fsanitize=3Dkernel-hwaddress)
>
>  # This option is only required for software KASAN modes.
>  # Old GCC versions do not have proper support for no_sanitize_address.
> @@ -101,7 +98,7 @@ config KASAN_SW_TAGS
>         help
>           Enables Software Tag-Based KASAN.
>
> -         Requires Clang.
> +         Requires GCC 11+ or Clang.
>
>           Supported only on arm64 CPUs and relies on Top Byte Ignore.
>
> --
> 2.47.0.rc1.288.g06298d1525-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcU1P5RxLmHekgsWGWQZ%2BoOQQLqH_LC0JxqBtLJqR3c7A%40mail.gm=
ail.com.
