Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQP4R2UQMGQEEHEPY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B14A77BD596
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 10:48:02 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1dce622ac79sf6524500fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 01:48:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696841281; cv=pass;
        d=google.com; s=arc-20160816;
        b=0aDoTfmYrj148Eog/zQJj0y6zH4WCV6VyHOToqZJiF7qQ02Wvbmbf5jPZm/9YbY29v
         8dzhlil3rKXOZTV7fwk0L6Asf/xsvUczi1+Ku9UvwXWQ9xzLM1QLU/ZQJOjSeNOsVU6f
         4ggiAJMUComONCYMn7SWOdhlyVV1Fq7vIiElvw9B9xm/cJGrYScko/VwoIpAOS7n/QMt
         8V9AUbZfyDgGV5I2Q9nksbY3oiwl6HdMpXLA/qXTYq7/nozEYgYgWv8B2BKuHfN4qBGD
         oeor8AFGhzwL+gfjX5jt41VOYLzFusyB2d/7q3ga1ZJrG0ewOrkgSuu+85sVR66PYZ02
         gqIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wi/0DR6cg7gkuwZoFr58Wzh9lbaAQbxV3i7vSpW0xrs=;
        fh=q6y84gx18i99TfJF8tbibDRNSfyqMCePsVYLC6XVWHE=;
        b=CUtZpdRWVTkJ3wWvPE6TcE2KGB6XiWFH5vngip3UAT16+nDGhW+goKi1W41eJn2npW
         jig1GFlRJgt3r214Jeub6Gsb5/i7yjSDzjwIZSW5Xo8nx6c5gKXFJz48Cf//tTKvFybQ
         4JB7QsHJoE/pk/0yVhsKhFkdCZofNk6V9bh9h1ms/SCYZy5+ysJWIngO+pTkEOfYrTcR
         fppDTKOTDLtSGFD4UxeOM9e5werpXhuIh7jUjVEGrvAK0mCkdG+yq+Y8BDzy0GgHlzws
         YXU3v4X6CYrlONp/bE7XdTbLbnuTef9mxr5KqJBeNN1xfvhJ6ZDeriq4+kTNVvwjh5VF
         +G2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=lORnn7W+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696841281; x=1697446081; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wi/0DR6cg7gkuwZoFr58Wzh9lbaAQbxV3i7vSpW0xrs=;
        b=g3EQAlEXI9MlEYf7e8Oc3jSO7QWs+fJuaAdK2DVQ5/4G01r4eNP2oiU5bDd6u8sdAi
         E8oivBzRyWfZs3LNYPBnN57rabuVN2UA8gjBlVYPQJuDFiinwnOnTbg0eER8fg76GQ4I
         NSPHbwD+dbYEvootkB8RxEFmJDW61cS+JuErgCMm24xk0qwr9C2U+TI22wrFtkBlglQq
         bzJ6Xh42n6wrTUjBXo9IUOxiEYVCy+vKWk/fgvHMwZe1s9lg5gYglW63ms1DHv3vqc/G
         Jf7WYQ5XTPSBYan1zS4cE8rUfXiA43CMT54Ob2LEyx6RCVWPjYd/j8xFVYTDHrTyLiHF
         ltAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696841281; x=1697446081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wi/0DR6cg7gkuwZoFr58Wzh9lbaAQbxV3i7vSpW0xrs=;
        b=fMjmkE6G/iT4YG3ynIRt0KzK4nbCmHTujrsdLi9okP7vUTA4ECcb1cxPFZCLH8Z4ZF
         M+MgbQ2NUsGHbMiRiWm/HRwTGp4zLnlQyiJRlrBfwdn6yoI76TFe59Mi1Qgc1Rs6WHVN
         MnlEXNDic+Vg9hkMSQEr77S/bRvIxSMe6FRvLze31errPtpEtOlWCVHfyUREGREakmnn
         rM+69lw73Gi2pl8ItTL/k4xDXG80ldNTEKP3M0rB+2Sk4u01XLqiSJaHLHZHfQzGMmzS
         xojGkIIgruTS+i599Wf6NBUd2t6yKVRMGAm8gijjIjQYzcX+dbStIh6BMmxAYXXGEb8m
         sU1g==
X-Gm-Message-State: AOJu0YzfAPb26P4vjAJWOj3T9PCP/SWgbjT9NCqfq4UmB4Di26QHWAuU
	VzNxgn+WKVVK9neJYMmZmYo=
X-Google-Smtp-Source: AGHT+IEL2hCU1w0k5WsM1bnrvqGO9lma28ROp3jc6WeUurkSvgNrzO/+wLv21B6iqViDGuidhCY7Qg==
X-Received: by 2002:a05:6870:d795:b0:1b0:649f:e68a with SMTP id bd21-20020a056870d79500b001b0649fe68amr16650287oab.25.1696841281237;
        Mon, 09 Oct 2023 01:48:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:88e:b0:1e1:371:c3f8 with SMTP id
 r14-20020a056871088e00b001e10371c3f8ls6772374oaq.2.-pod-prod-02-us; Mon, 09
 Oct 2023 01:48:00 -0700 (PDT)
X-Received: by 2002:a05:6808:1b0e:b0:3af:6cb9:ffc7 with SMTP id bx14-20020a0568081b0e00b003af6cb9ffc7mr20157739oib.16.1696841280402;
        Mon, 09 Oct 2023 01:48:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696841280; cv=none;
        d=google.com; s=arc-20160816;
        b=yKa3D6u+BsW0X8LG7NtEYErM//+6iRUoqJJnzso4f6p9KBUugzJ1RvYg9QulA58Co9
         GR8GIgG9JnHZ5RlcPmGCTDVtnQKmIzk+uDw/zD04B+1E65RfJ/E9u/tfz9SOAOye7ppZ
         2HBNi8jc83EFzGJqQV94iIDjRvH9E084uvflbAp91AdVsa26c5Ae7SlKs795qXfkWZ28
         UMCd0fMef5UYJHeLGQiwU2AEtTLWb1voYNEeSFAtmCIvgqsHECjXgk/8dG0amRSkvnYG
         rytqbCyaJbhli3Hv94oz6/ipfxRHF1Zev6j/OsEurJTWWOPDuWiYBEjkPP6NQbc/AF6x
         HgFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dE3lQgYQrglH+136jeW6uJyH+jXehuS7mvTlptTmP9s=;
        fh=q6y84gx18i99TfJF8tbibDRNSfyqMCePsVYLC6XVWHE=;
        b=TQ1IV3Eh7zaCE0l9FHTdpoXyd94x6OAJ7sdXdzLHoYYn7Z2qTMSEgoH8YWhrUdm4kB
         OlxVgYnHonhHrqC3PQh3BEK1/jKMI1i/8RAznii5x08hkp26HPzMPAH838uoXVV+ryMe
         UyXbaOyHQFQZqloskodsEKlXrjjiOPhOGIeX7boqs2yoHu9HeXCv6/FTV067ULTxxads
         A4mC/uCw7QwMsc3dCiuwIOs2YD8hzWUkfGTunxCtL6ekvEEQ+M9KB11j0ilApPrSJKz8
         i79iq8jvwOeaeK6sXE8oqxn8D38bgIjhBR7A7H+oicFYTt2YJJePxaNDDCdoJy6Cin71
         +LDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=lORnn7W+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x932.google.com (mail-ua1-x932.google.com. [2607:f8b0:4864:20::932])
        by gmr-mx.google.com with ESMTPS id et7-20020a0568303c8700b006c4dce426adsi1011692otb.0.2023.10.09.01.48.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 01:48:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) client-ip=2607:f8b0:4864:20::932;
Received: by mail-ua1-x932.google.com with SMTP id a1e0cc1a2514c-7b07548b085so1823886241.2
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 01:48:00 -0700 (PDT)
X-Received: by 2002:a1f:d3c4:0:b0:49a:b9ed:8c22 with SMTP id
 k187-20020a1fd3c4000000b0049ab9ed8c22mr11374478vkg.9.1696841279791; Mon, 09
 Oct 2023 01:47:59 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1696605143.git.andreyknvl@google.com> <6fad6661e72c407450ae4b385c71bc4a7e1579cd.1696605143.git.andreyknvl@google.com>
In-Reply-To: <6fad6661e72c407450ae4b385c71bc4a7e1579cd.1696605143.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 10:47:23 +0200
Message-ID: <CANpmjNOp0yq2vQmSmTim=AF7bm9XdStbaQE9B=wVwpKkO_y6tQ@mail.gmail.com>
Subject: Re: [PATCH 4/5] kasan: fix and update KUNIT_EXPECT_KASAN_FAIL comment
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=lORnn7W+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as
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

On Fri, 6 Oct 2023 at 17:18, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Update the comment for KUNIT_EXPECT_KASAN_FAIL to describe the parameters
> this macro accepts.
>
> Also drop the mention of the "kasan_status" KUnit resource, as it no
> longer exists.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202308171757.7V5YUcje-lkp@intel.com/

"Closes" isn't a valid tag? Reported-by + Link should be enough to attribute.

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/kasan_test.c | 9 +++++----
>  1 file changed, 5 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index c707d6c6e019..2030c7ff7de9 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -91,10 +91,11 @@ static void kasan_test_exit(struct kunit *test)
>  }
>
>  /**
> - * KUNIT_EXPECT_KASAN_FAIL() - check that the executed expression produces a
> - * KASAN report; causes a test failure otherwise. This relies on a KUnit
> - * resource named "kasan_status". Do not use this name for KUnit resources
> - * outside of KASAN tests.
> + * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
> + * KASAN report; causes a KUnit test failure otherwise.
> + *
> + * @test: Currently executing KUnit test.
> + * @expression: Expression that must produce a KASAN report.
>   *
>   * For hardware tag-based KASAN, when a synchronous tag fault happens, tag
>   * checking is auto-disabled. When this happens, this test handler reenables
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOp0yq2vQmSmTim%3DAF7bm9XdStbaQE9B%3DwVwpKkO_y6tQ%40mail.gmail.com.
