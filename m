Return-Path: <kasan-dev+bncBD2OFJ5QSEDRB2VL3GCQMGQEHWNCKZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 879AE3976FE
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 17:44:43 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id j14-20020a05620a146eb02903a928cc3769sf2894198qkl.7
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 08:44:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622562282; cv=pass;
        d=google.com; s=arc-20160816;
        b=XDWU37M4NehRnbdnKaPjfaAqK6im/LyaXqAguGB67nTSyjZwZpJdulP37w4EaU5+1e
         svHXRV5xMHmnXVVPOG+1rPP1WkEayqIkcmluSPciWvKL3YT5RF8jvR2b+LlzS6zBBkWU
         G79gQnDYFqBFGV7Tk+8b7SYQWLbu712vzZLFKRf3eDTEYS8egsfjbWrOeYfvQE1SlTmV
         8VKEqXSxtpiCBS3jQFE7NZtaPTACLXwv8uOLrRNJlSh+8ZzhRbzeruo22EszaBhcECLa
         KTasErLx4uAOgM+GySM2Bjw1yiwDV43VkkcUJLrhDhOYvIkA9H5TPCZbAL74mTg35JYU
         1HyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Duq29emHZLRDGoRIoNW6CZSBfUeOwAoBRTRTo1LWZmY=;
        b=wnFXZs1VgJRctcqLzAL9tEoLdH47kHJtz5ySMQmlVHw0rPOXOD8FgupJTsWAsJJisF
         l1shSEj1dHDcMevwtpTXL3f9NoetD40KLcWdhJfjp0B793IhPUcLtvzi2r5tROPG91Fv
         +SiXIO+fT8khn++Rn+Kiu54wj/f1AqPuu9+nQG1RMTIAkeRqHalq1tIo7nIEGVnFwiz7
         k7iLJ/aKPJ1tWCiw7Lf1nLsx5CftgwZ1a2YqgXglC15EniwnVilsaHG8MbaDZQC5p+tM
         z1K8hCfeGyUoObgaq0BOINqH2L0eQVWilkeWRuofON6Ql9Y6Wo+iyo0VOItRtRv7Znaj
         cTYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kRP9Rlun;
       spf=pass (google.com: domain of dlatypov@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Duq29emHZLRDGoRIoNW6CZSBfUeOwAoBRTRTo1LWZmY=;
        b=M4DhjLHLp7GVXB8OEnk1UDJvaSA8FY46qZuK6z45AQWSjPhc0YT/g9cp9lY7ashFfY
         sw49V/OwY/Kego3/LOjKfTlOG+eAab1VqsA5KhfN/h1LyFryHo4ncE1uSKDkbPElN4d4
         TgSbR8B/VLjnl7YvfPGm02X9bj7V979B7SGIUmkEinVbFvf6XuZBsqus0HLPNk6u0Yay
         4keZoCGiw4M3t/lzVZ3qbAep5/rIZGO8I6ccXTzjBl5gSf8UUX5G8BG9JZQ+QbKpYEzD
         hg3vIMWCijJDNyDEydIie67HTGkNxWCpKdTXsththHVQR6p/skRU/LayupGZyvhIalVr
         Drpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Duq29emHZLRDGoRIoNW6CZSBfUeOwAoBRTRTo1LWZmY=;
        b=pt11v+hulDYw4yJsEIyiD0I1ShbXIqobFeOUZTsnXDcKp5+I4yW11zsPaxgN2sT1qP
         9KiylVNrX+053KlpAEP+sPVajxDmhp4tsWxlLCzhHFTtoOrMrn6oUdvUnCDvICk+LDpy
         QmmNvSlJVEh/w+jqlhjbdb0LWtoscLwhbYK1phHP5xY6Ep15CPV/Tm2/Ak2JUE8beQjQ
         gpg+ckk9efgEuhKg9C2ELU3/PljescUUHIK2U6sOOG9UloAGIC9TAIT/jFC9H/uX3DLS
         AxZPofVQvhchj7WCiYm53yXGl9AriEt3HTqYse4ybS4YgM9WmICc6J29KMQrUmlAIR1N
         kWpQ==
X-Gm-Message-State: AOAM531QWv4Q7s4jfis4uVEAHV+0vbx+9un8YJ2QlSuvMrqyZB2v0bxp
	HT1pWXUqlTMhXhLTPM33Iw4=
X-Google-Smtp-Source: ABdhPJy/7kLOCRIc96G6yyjfFJQT78XAAGzevnKEz93NcPtWldTVOyUe7AZ15HKx2hgBoMta74e9pQ==
X-Received: by 2002:a05:622a:13d0:: with SMTP id p16mr11484856qtk.30.1622562282552;
        Tue, 01 Jun 2021 08:44:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d49:: with SMTP id g9ls7966505qtx.6.gmail; Tue, 01 Jun
 2021 08:44:42 -0700 (PDT)
X-Received: by 2002:ac8:6f06:: with SMTP id g6mr11863005qtv.87.1622562282055;
        Tue, 01 Jun 2021 08:44:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622562282; cv=none;
        d=google.com; s=arc-20160816;
        b=qfDEK37rmDTMDl/YkwqAaw63T9/9vmDOJF6CSxATd9S5Mv9a4X+naiKmymIxEnF6Vl
         J/bxIevpmw5GSugZJ44VkCHUWOXZw3DzTJFZujVozOcytkz/IFqJUSfpAwIKtQu8uOt0
         Vqcrda/jcmoCQU/v56LY13ihRkaTNbY7kZFfHohWULXOiaClIojVsLH+7iICTvsLWjhB
         tQSpUwz1mTshuz8mS+VckZEXDuTDEwS+/VzGs77URmsPX9ekaU/b2ymIZQzHuFK55T85
         ho4RpZ9NOui2CLYNyO8hDIRwt1eNuE+hgrRZb6FTEjWuCDD+035ijsbe56PiS0weWPi0
         U/pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nvfBq2aXtJ08TGHS8dCWxvUmTewAGJbPcj6f0TWlUiY=;
        b=Hzl3IPR2MSBvevsrPI8XZujkiLD5iRUGvnPrWapoNuEw12S/1TW50huGXfc9crRWUL
         7DdBVXgt1kCQhV3TSXSfrKcqt+189+b6zPb0atT12Z/tSE82ptBab1IheOCiRMs3shj4
         gJF3/Y8rHqEFldQfwQuLqRsJ4kauaWzZ0rwZbMZF9FNKB8q0jFVIOGRosMwpI4671hif
         3pwfGgJ6/qsR/cEz9qDyqB7IA1wrXZagpZbJABFgSt1Q2TPbE/Myxa1brHkc3Hr6N4my
         gd+lE4K2gyEl+CTu1AnE/slcL0TzAds+udanhGdIiq/nBxl1Pr3l5U82Ch/na2TajoD6
         qcBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kRP9Rlun;
       spf=pass (google.com: domain of dlatypov@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id d207si1466641qkg.5.2021.06.01.08.44.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Jun 2021 08:44:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id a6so15856848ioe.0
        for <kasan-dev@googlegroups.com>; Tue, 01 Jun 2021 08:44:42 -0700 (PDT)
X-Received: by 2002:a02:5b45:: with SMTP id g66mr11315101jab.62.1622562281646;
 Tue, 01 Jun 2021 08:44:41 -0700 (PDT)
MIME-Version: 1.0
References: <20210528075932.347154-1-davidgow@google.com> <20210528075932.347154-4-davidgow@google.com>
In-Reply-To: <20210528075932.347154-4-davidgow@google.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Jun 2021 08:44:27 -0700
Message-ID: <CAGS_qxr+nOBoL86GzX3o+CUvp0FFGv7qJh70ALUxe-Hr6X7+xA@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] kasan: test: make use of kunit_skip()
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Alan Maguire <alan.maguire@oracle.com>, 
	Marco Elver <elver@google.com>, Shuah Khan <skhan@linuxfoundation.org>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kRP9Rlun;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2607:f8b0:4864:20::d33
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Fri, May 28, 2021 at 12:59 AM David Gow <davidgow@google.com> wrote:
>
> From: Marco Elver <elver@google.com>
>
> Make use of the recently added kunit_skip() to skip tests, as it permits
> TAP parsers to recognize if a test was deliberately skipped.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: David Gow <davidgow@google.com>

Reviewed-by: Daniel Latypov <dlatypov@google.com>


> ---
>  lib/test_kasan.c | 12 ++++--------
>  1 file changed, 4 insertions(+), 8 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index cacbbbdef768..0a2029d14c91 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -111,17 +111,13 @@ static void kasan_test_exit(struct kunit *test)
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> -       if (!IS_ENABLED(config)) {                                      \
> -               kunit_info((test), "skipping, " #config " required");   \
> -               return;                                                 \
> -       }                                                               \
> +       if (!IS_ENABLED(config))                                        \
> +               kunit_skip((test), "Test requires " #config "=y");      \
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {                 \
> -       if (IS_ENABLED(config)) {                                       \
> -               kunit_info((test), "skipping, " #config " enabled");    \
> -               return;                                                 \
> -       }                                                               \
> +       if (IS_ENABLED(config))                                         \
> +               kunit_skip((test), "Test requires " #config "=n");      \
>  } while (0)
>
>  static void kmalloc_oob_right(struct kunit *test)
> --
> 2.32.0.rc0.204.g9fa02ecfa5-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxr%2BnOBoL86GzX3o%2BCUvp0FFGv7qJh70ALUxe-Hr6X7%2BxA%40mail.gmail.com.
