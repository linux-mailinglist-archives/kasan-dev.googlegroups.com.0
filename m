Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBOGWYKLAMGQEESAAHLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 685C6575826
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 01:48:09 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id e10-20020a19674a000000b0047f8d95f43csf1349715lfj.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 16:48:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657842488; cv=pass;
        d=google.com; s=arc-20160816;
        b=uTAhGN6GUBYGOAWgyIdOkukkb4ruQbUUALJwCJbhvo9ITXBOwk1iFdO76sFcTs9BRk
         nKdwiUWGXTzxYWdaGsKO93HCZXNZ31aN0uBbl3crN6cyQe8pOq8XdZCm/1BUEkhP7MoG
         cE6Q6sSf6bQ96UHuiRk86ivzuuQLSqUbFJ3n3hRz3i+oJdEQsFUNmN/6ED7nYdc/k23r
         cen1gW+8BvpH3DcMcbV4Ww7+/Lreg/58jwhYQ2hGQJMRT7KzHFw9IN9yOBPU2fF8z19p
         NKrtCV6IwarkbnpNb3KxAaaMRl12eu5BvsUTGKvChuH9uISbTNFLIkyDYi2EkIZVQk/0
         b8AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PUnG3r22P1VTYMGK5KE9XLX+utoq5wvGPtvHXKmviSc=;
        b=rj+aTStOAuG+oYNK6w+jn5AD2oUwyIQaVpSm0tNsbTTMzk62I8xQCJYp3lC5duuHZc
         leWrO6vSCd4bQ2D5t4Dmx9c9OF3v9HPGzVDTdiSFRTI4G2r+TyQbWMDnjUuDWVHTYQV4
         BnjM3cUtgh6FGbbbDfMRpPb7RCQ91O+gwGABSwOC2tzoEcIUn0FUVCOIEL1mm1mWOY6R
         gXDKXmzx6TvhVjsQlt8+KxQz9uKMrdogeOi1o6iXdpYcwL1K7KPzxd39+9R3YVX/ch43
         kmzm/7APmQaAGgj76lW5GdpR9Ov3idFNJXhADMpXp87NDRKdCuJTCtzM++VHhSLg+wN3
         8CmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bFleYVBq;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PUnG3r22P1VTYMGK5KE9XLX+utoq5wvGPtvHXKmviSc=;
        b=lypPQaMW46vhxz2i2ZkAXkNdqCGAjTsxdVI5YWlY9V64Hfb0IkL/S82NcdapCYux6z
         z6jEtcxrGEsQguvhrfMdflx3ax+LaqKvgQ1XPz1QnLm44QgJWWH7rtBKxebavZsDLfvN
         VSGrNu6dRJBJ1hzMgJypHr5G+9Gj+sFUnx0X6m65XiA8bpUG+4JiF9AZ0Y92sy/QLEi8
         oy3vgfZRHoQz6HywVf07oUBynvqe7pnyrbvmNgqhx5q3qmZ6u1+Qkivcggr/Bzijielj
         3YmazcO4PB92tplmzItnr+AELBRNYSmCePpd5dy9zJKM4VdLwHwOA5P6XWxD2UosirHC
         vNzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PUnG3r22P1VTYMGK5KE9XLX+utoq5wvGPtvHXKmviSc=;
        b=FK3WBHMOq8/+boAFaz+s2PQ7sIcEhqVJXt0Sh1WxSoazueEgAMkHm7p8XuvbgLgFLt
         jE2PpJ5t0CkcHPdmCKxjDRWlUbDMIWXmWaTzsiWKSXtaxbwMuwNCUNr1iqAmZFEWT5x+
         UP3hzJW/EKbkLb9p484oKFjwjCcCunrW/VW4rYHhR+emE9Eg1cyI6K3pIeefvCq4nSca
         XeMEpDGdFpt39GuuzmNhfL/yCtRY5ccRqDBBVoa1oc9/KxjQDiyJ27qPEpQZIqbsoyZT
         30B4ot/xcPVjVPz8XKlxDFvuMzmNwFcKuQCg237nY3kER+PjUb6ybkvGyUspbjsPw+hm
         auGw==
X-Gm-Message-State: AJIora/qRsN3kuWw50b+CqUyFfeOy53SHGm1/puEpT7WptMI34e7/RAQ
	2sqQKxqSaxj2sqhADV/zU1o=
X-Google-Smtp-Source: AGRyM1up3WPpa9244FF8O4lTynjZ/lFAotwLvcDvb6nAUhRKEJKehqGdIB9tvO6p9B8cc5LBIrpqCw==
X-Received: by 2002:ac2:55b5:0:b0:486:5e71:3555 with SMTP id y21-20020ac255b5000000b004865e713555mr6466551lfg.582.1657842488573;
        Thu, 14 Jul 2022 16:48:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b9a:0:b0:25d:8520:aeb with SMTP id z26-20020a2e9b9a000000b0025d85200aebls1266258lji.8.gmail;
 Thu, 14 Jul 2022 16:48:07 -0700 (PDT)
X-Received: by 2002:a2e:a4a8:0:b0:25d:4977:92b7 with SMTP id g8-20020a2ea4a8000000b0025d497792b7mr5688515ljm.294.1657842487387;
        Thu, 14 Jul 2022 16:48:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657842487; cv=none;
        d=google.com; s=arc-20160816;
        b=QqGSi++og0x8EtfVOA0I/sXHq3zm+X7BXtcuS+F5hH/zcO7zwLqqt0KPwW+P+GjZPz
         DUmUXovj9cl3OkHqEot8YPzoN8gSutNjz1llVE0ciax3VwTFOrEj8oGN8NiV17BFXAPy
         1C3Jv8aHFJIQSHYi8ylNMXaautM/DWwhbikJ08vmpdkNhf/W6VVcA5mpQS3/h9YtpKwT
         m8uNnt/0gaCVhaC8vR53HsEnLXKHtxiJ8BCORq3NB4c0OO9hM9rtbdID/+tPA3QNL8Zq
         Ymv62EAVwxUCmKueh2S1HD7dnjQz3es25jji09I23xqEMk3dRbWWHhstUOVzD49I40J2
         atNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jtB7Ozk+Cxa7ka7EGUvIpISJLyIGflqVSLPjqA/TC+E=;
        b=tmCIEc4UaUvMdSG7BzVu3rZ2sY1XaaA6tiHMqw756p3VQOxspzZSE+lRq5a2VpGQcv
         L8pi8r6pGwtSR6v2OShD5K1ZiZ+USNFCQtwKyrA3skoB78EWFC4/OQKJGsaoRQ3636PM
         lCcqyHfAoGGV6zPt9bw/ncd6JzTDPurEUarZQ5DIJBoaY65sqNVWSsNpPxtCHmV70NLl
         7e6YqmFITWovKUPpk8y10GRRTP8Mv3JOjtt14j8cOyn7fApN+WsKAdvFVuhRWsqyZDbI
         BXC2avESv7177QX7v0l6xJh27DxrG3ls3RMtoIM6jFLLdATVlgmmzM4gEdihQUPpFuoE
         tx8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bFleYVBq;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id w8-20020a05651234c800b004830f9faad9si97495lfr.1.2022.07.14.16.48.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jul 2022 16:48:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id b11so6139551eju.10
        for <kasan-dev@googlegroups.com>; Thu, 14 Jul 2022 16:48:07 -0700 (PDT)
X-Received: by 2002:a17:906:98c7:b0:72b:20fe:807d with SMTP id
 zd7-20020a17090698c700b0072b20fe807dmr11332291ejb.75.1657842486964; Thu, 14
 Jul 2022 16:48:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
 <YoS6rthXi9VRXpkg@elver.google.com> <CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ@mail.gmail.com>
 <CANpmjNOdSy6DuO6CYZ4UxhGxqhjzx4tn0sJMbRqo2xRFv9kX6Q@mail.gmail.com>
 <CAGS_qxr_+KgqXRG-f9XMWsZ+ASOxSHFy9_4OZKnvS5eZAaAT7g@mail.gmail.com>
 <CANpmjNP-YYB05skVuJkk9CRB=KVvS+5Yd+yTAzXC7MAkKAe4jw@mail.gmail.com> <CAGS_qxq5AAe0vB8N5Eq+WKKNBchEW++Cap2UDo=2hqGzjAekCg@mail.gmail.com>
In-Reply-To: <CAGS_qxq5AAe0vB8N5Eq+WKKNBchEW++Cap2UDo=2hqGzjAekCg@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jul 2022 16:47:55 -0700
Message-ID: <CAGS_qxpNHrWxGBV6jcee7wPzkWTb1Mh0fpE7j4_0LrgeLv+4Ow@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: Marco Elver <elver@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bFleYVBq;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62c
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

On Thu, Jul 14, 2022 at 4:45 PM Daniel Latypov <dlatypov@google.com> wrote:
> Ack.
> So concretely, so then a final result like this?
>
> $ cat kernel/kcsan/.kunitconfig
> # Note that the KCSAN tests need to run on an SMP setup.
> # Under kunit_tool, this can be done by using the x86_64-smp
> # qemu-based architecture:

Oops, this bit would need to be updated to something like:

# Under kunit_tool, this can be done by using --qemu_args:

> # ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
> --arch=x86_64 --qemu_args='-smp 8'
>
> CONFIG_KUNIT=y
>
> CONFIG_DEBUG_KERNEL=y
>
> CONFIG_KCSAN=y
> CONFIG_KCSAN_KUNIT_TEST=y
>
> # Need some level of concurrency to test a concurrency sanitizer.
> CONFIG_SMP=y
>
> # This prevents the test from timing out on many setups. Feel free to remove
> # (or alter) this, in conjunction with setting a different test timeout with,
> # for example, the --timeout kunit_tool option.
> CONFIG_KCSAN_REPORT_ONCE_IN_MS=100

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxpNHrWxGBV6jcee7wPzkWTb1Mh0fpE7j4_0LrgeLv%2B4Ow%40mail.gmail.com.
