Return-Path: <kasan-dev+bncBDW2JDUY5AORBXWPXOHQMGQEULPRR2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 55E3B498749
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 18:54:39 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id g67-20020a25db46000000b0061437d5e4b3sf26802396ybf.10
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 09:54:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643046878; cv=pass;
        d=google.com; s=arc-20160816;
        b=r6ppnjAO4RGyoB+L3aTuj8n/SlBOTus/f0aoncInSv+KOUBz0liY6qxc+ETrx/1V3h
         qvX4pjKu5KZWDeMrkZVRivGnHHCXLdicKOULV7wk0JdgeNajBFTo1PjLAe19y9zat65m
         T4t+tGITpLjl5fBxqjVQcRDDwcYJ6ZqIvtEBm21fbkxLx0GKDg6yUawDgkG6Vlsc3MgO
         N4W+0CbCvUp0LCYcZlaI6H313E8uzOEDXd8b/rrnlrcuzH6OEgjHfOCN3pNO+PcFP7f+
         bB309iVA4ZaWFnrv0M3LY3JPNHRve65IVvI4VoFDrZtOoIleyFsfL41ffx+O8am89NwZ
         Chdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4z98L4Z/uRDv/b15JZB4EmZ5JPtWenFsxSyTrmQ02Ew=;
        b=PyOCyWGpoUVmi2tx9VnDDcWYIjYktG2cHpS/dVGLp+cRbdllyOQJ5Ti2rwEhAdwoBf
         dzpHvNX6tMFSqlRX8ZYkKh4e84JAUxwFuEaqY9M80TG5Gqv9SHhasmiGo4DkZBFHBn6c
         Bv/ie//+fiRRg8CFmO5CPN/MbJiNBFx6MsSK/7htm7YhOjBzb+ajTsGnK7pcPBg6gSVv
         ug5E6jjXGcjav3dM1iS9LJPMdQlwfhdMb8omNau5GwGSdcsfkLCyQWgaleLLXC+zZtrP
         p7ocrF94Ga/fMsf6RFr6rfIGpeR58xvogboS+SNWF40G6xIIpTPLkMIES+VL/RCN1wv6
         DXmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dWoGsnVb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4z98L4Z/uRDv/b15JZB4EmZ5JPtWenFsxSyTrmQ02Ew=;
        b=LlC8EVfPMUP5wRmtgpbN7rSOMBcaUsixhRiRxmJFA9/hAfG8nSuqjFcu9263MdaKCk
         pwnGaaVCDvqmEr5ftVpgnkdnXUXIU5ehjthcHn0dPcgtXjq8hA7gjzsfSyO/CFTeLKWS
         9nZgn0ODRasoVLVBuTfft+PpU3b0PLX75E5KU31LFsNL4Ffpkz94BoZNT5Cb3BJhuIoq
         m3LTkmn3Q/o5MEQY4fkCPmpPsQGbZ9Nb5te3rvhpk3+ErAc4oLp/BxYWU61qCrtdi61d
         7lb0iP3mviebF8lzvhSSTdsZzzdttBpn1kqeaG4mJFRxRJbLTpBikby2Q2Tl0TIpYiCX
         aDVQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4z98L4Z/uRDv/b15JZB4EmZ5JPtWenFsxSyTrmQ02Ew=;
        b=Mm1jwnzMM2sxUnRSDyZN9FPHS2pDEmqryt6PrdoLZjgQT/b0RJ+Ys/mOTjFEVZsTCr
         VecUpTlE4qLLhDmC7VwhJCDzkCXgWL3gXOYczERjP0TWRD5RGWNm4gJ3VN7FKuonAT0u
         zKxHZj9q0Nxc+pRM2E3qbnhOdtxOn+8SXvEUcmXw7GXBfK3DEJF6ls15PCVbdyw54WGU
         sjW4Cm8lKk5jZS7khocbaH6QLVEGpl+S5omuYOvZFWZKi9zJT7k9bp/6q0BiEBL9ru78
         YnZRNaI1fHDPtJwVI9qM49pjtcxZMupKfCF+HZl+isvJMzLomLAS4o9rXG/dC2D4Cbi4
         BsDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4z98L4Z/uRDv/b15JZB4EmZ5JPtWenFsxSyTrmQ02Ew=;
        b=I2nNcQWFxnDpoN7xxWhy2TdyjgwmTc1LZDGvfbfetWEerQbbshzNOXSH36mBiNzo7N
         tY0UlBu1OIxzK9N9Bz/51NUY2ZKpm8GCiFsEy6d0Zpo3rHD07eeWMdXsfI3g+WpVSSDD
         go6htwlK1XF9OfCLsbzR59JRQ3OmjJWsufA0Alz2vPgaBoqCRD6SKLiXa8MV1dH6jCjm
         f42fC8iyj31BJgmOG0acISaFqMcoGsbS8zknQACIbXrrsKfOSsL0Q2DkazurdyfHnTQG
         utxCqfMe0OUDS3LckCW/gKi9a8zlUPygMU/plwDFNwxIJMqvjpK+57CqInjDwPUXMhMk
         NCeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319Pdgdc6NAr7cePexCmRSDZej9ExiaYqqa1E6Fw0mv31sDMBqK
	BHFlbOb6A2Hs0/Z132SvuMg=
X-Google-Smtp-Source: ABdhPJykzzQk+AE5h7SDkbSiKFK/EpJ6v3oqb0lsayRX31YqdfOzRC6slJD6AQDBx5UyW63TaHpMqg==
X-Received: by 2002:a25:2f86:: with SMTP id v128mr5330063ybv.662.1643046878166;
        Mon, 24 Jan 2022 09:54:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6103:: with SMTP id v3ls17596802ybb.0.gmail; Mon, 24 Jan
 2022 09:54:37 -0800 (PST)
X-Received: by 2002:a25:b284:: with SMTP id k4mr5427601ybj.652.1643046877738;
        Mon, 24 Jan 2022 09:54:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643046877; cv=none;
        d=google.com; s=arc-20160816;
        b=0CdUrFoikZUT+2891tLRKJWJDr0xQVx3wgAZA0cg1/zqTMIJuK8ls0mQ9aUCYzCzm1
         9iyCCqbnfQoB5ONAG8g6BkvJFz66VbSsnt+EHuj+xKO5wqMzLT9lHPyIRtAMNEHZmIF/
         ZQ0tbGnZRAaBCcuFE4s871KFAPaQzbhxNgCHgoquh3goaHsST9x2CiQe/8bK/NYdY4HA
         s7yzbJ4VD7kjxVGXis85EYKf5M5Y5ardSfGuVef/gNkIG2fLT2viV6KJwVoD1ra3xRLh
         x3r28tT0t2uzc1NF07ig5q2mfhQcNitXHJYqRnCzPIR30LObNzAvhq4eyN3yi1tOa6qs
         rbJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v3YviFAQ/40r1Ln+w4BlMxkBPCxENdD7r0D/7v9ETwo=;
        b=mDti1xZa79bVWnENX23s8+/JPMEhZq5bpHLy7os0PVJb9T1jGJAzt+hH+xcNXMexcy
         qMJZcCvlqEMndWa/QW3SS2907zKlHPLR8F5USXc668LZq6yRvnnxT9n7TbQ9drWemRrN
         al8ksx32++PWlnYbkboTDCSiaYQZrZf9Hs5Dx09zRFWhCq5M8+imkORhAoXUnq+oSHhB
         Fh139reO9RXtXN6r7VLw1hzwtBqeQ2tGcd9DauQDFvCll96R1OrPhCIv2RUJi9wYQC3K
         tYRPpd3R4rmzN4VWCLd+9ZLJPuezFET4IfMKHmIJqADKlrkWpkB6hXJFax+goZS+qS0J
         ZxhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dWoGsnVb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id w1si1048365ybu.5.2022.01.24.09.54.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 09:54:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id o10so14622812ilh.0
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 09:54:37 -0800 (PST)
X-Received: by 2002:a05:6e02:1568:: with SMTP id k8mr7648938ilu.235.1643046877495;
 Mon, 24 Jan 2022 09:54:37 -0800 (PST)
MIME-Version: 1.0
References: <20220124160744.1244685-1-elver@google.com>
In-Reply-To: <20220124160744.1244685-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 24 Jan 2022 18:54:26 +0100
Message-ID: <CA+fCnZd9fhv0RShoSF5xStQZuXFC2DGv8JQpthffdm6qVA2D3w@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: fix compatibility with FORTIFY_SOURCE
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Kees Cook <keescook@chromium.org>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-hardening@vger.kernel.org, 
	Nico Pache <npache@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dWoGsnVb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136
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

 -On Mon, Jan 24, 2022 at 5:07 PM Marco Elver <elver@google.com> wrote:
>
> With CONFIG_FORTIFY_SOURCE enabled, string functions will also perform
> dynamic checks using __builtin_object_size(ptr), which when failed will
> panic the kernel.
>
> Because the KASAN test deliberately performs out-of-bounds operations,
> the kernel panics with FORITY_SOURCE, for example:

Nit: FORITY_SOURCE -> FORTIFY_SOURCE

>
>  | kernel BUG at lib/string_helpers.c:910!
>  | invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI
>  | CPU: 1 PID: 137 Comm: kunit_try_catch Tainted: G    B             5.16.0-rc3+ #3
>  | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
>  | RIP: 0010:fortify_panic+0x19/0x1b
>  | ...
>  | Call Trace:
>  |  <TASK>
>  |  kmalloc_oob_in_memset.cold+0x16/0x16
>  |  ...
>
> Fix it by also hiding `ptr` from the optimizer, which will ensure that
> __builtin_object_size() does not return a valid size, preventing
> fortified string functions from panicking.
>
> Reported-by: Nico Pache <npache@redhat.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/test_kasan.c | 5 +++++
>  1 file changed, 5 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 847cdbefab46..26a5c9007653 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -492,6 +492,7 @@ static void kmalloc_oob_in_memset(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                                 memset(ptr, 0, size + KASAN_GRANULE_SIZE));
> @@ -515,6 +516,7 @@ static void kmalloc_memmove_negative_size(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         memset((char *)ptr, 0, 64);
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(invalid_size);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> @@ -531,6 +533,7 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         memset((char *)ptr, 0, 64);
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 memmove((char *)ptr, (char *)ptr + 4, invalid_size));
>         kfree(ptr);
> @@ -893,6 +896,7 @@ static void kasan_memchr(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 kasan_ptr_result = memchr(ptr, '1', size + 1));
> @@ -919,6 +923,7 @@ static void kasan_memcmp(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         memset(arr, 0, sizeof(arr));
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 kasan_int_result = memcmp(ptr, arr, size+1));
> --
> 2.35.0.rc0.227.g00780c9af4-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd9fhv0RShoSF5xStQZuXFC2DGv8JQpthffdm6qVA2D3w%40mail.gmail.com.
