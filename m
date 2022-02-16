Return-Path: <kasan-dev+bncBDW2JDUY5AORBXFMWSIAMGQEIFKO65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FBC64B8C4A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 16:21:04 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id fq2-20020a056214258200b0042c39c09e5dsf1999212qvb.18
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 07:21:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645024860; cv=pass;
        d=google.com; s=arc-20160816;
        b=tIAgA8hTIXdNKK6r5/0hBYYBGDmKCL22ErMrx4zzhjDu6ze4QpGRjmkjCownoYht9D
         CBYf8EbnTqfIC1yKkJCUlsMRA0Udo4IfaFnU5m/g4LvIvoKGc83q0h1fv7lZXMtVFyyC
         7DFi5BwD2QITttnV5IrO2St//iL4xN4Ka3SWBRCTkPPXeds1SsW898cMlGYhpiiXz+au
         UdZ9tpaa2wx2/mheGZWjuKCaK2cNHITyzrFPQeP0MpXg8L6K7/T+0Hh2mdadvdrKcEoj
         JDAD0WWH2dvDuHg3uOue85nVvLTnQS9qQVeGMndeB5I4IigjWczhGa3ZC/F0sgYOzAlo
         TlcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Ylk2t9BbgQXG1JUOXiLwSMb3P9RU8/AuMs5Jw3B1Vb0=;
        b=RIZdfiY6ATGdhIt0vQLuDibhabaXlDWzBmkKkLj64jJFjhi4mIMA17w+cvhj+d9E/f
         KvHjFBiI/GUAcORz8LTUc3L+7lWbh8W4Kx50/WkAJ9bYI86bGf6SBQqeuGHOVF1Ke3IO
         5SK2ieH8NpTLnCp9PrEWs0FG/761IHXKl66f72GNhp07K2ks9IWvu1YKIE5fNInSQKZU
         IjvAwgcwHu9Ny482YHWLqS8Rki/0hT0iamOu6gZs3y7PPF4Z9CHo/wnU2fXlJa3tbR8J
         Aey8Rg2G54XgyGGxq5SVnfZo6Rcw1OrTj43UklR4MFxVb72mRNh4gFLOME6ng8K1D7Au
         UTMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=i56LMHid;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ylk2t9BbgQXG1JUOXiLwSMb3P9RU8/AuMs5Jw3B1Vb0=;
        b=LD4nm1+ZbMIfDlmp8kXio3ECtXo4JsNwyQKZy8206EyJpDgCPaI0YCoQ1O/5ATbCEh
         W53932DJiXfeYlwCLn3yknymG8CEowfEA1ZJcUP2GOHM0gwCwDtj91SJ4uGbe/DX7ch9
         PG6ffSiDfzho1AGejAMKCZPHP+gPJMvpBt/OPwSfbOEBAXS3FIlgm5Ensw3A8eN0tBj6
         sDS/sBYJV38Y/s+ja4E27QLZB5pXWQIx35Qks0Dw2dA4MqCLgico2xDAqH9fIL3gdSmK
         OqK3SzV5DscfQgdemJhaGb8SzHdc2qFusoGcbH0yhGy+dJeZ8B9sKkAUgEzRpNy/zuaA
         e+xA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ylk2t9BbgQXG1JUOXiLwSMb3P9RU8/AuMs5Jw3B1Vb0=;
        b=MuNY2pbzZeSqqtStd8AReBs0664ZME3XAJtuqm7UQrA/+ztLeoFqyiMZwmMw87iFHX
         UJTTdx6dmlK3ileTSIXWj/0ACcFwza7faapkG4w6gnR6/6NkNILNxgXKmKnZYCqu1yBD
         hsIPKwz1itDzH7Io5FBwuhgCW6A9MuXwjsDwz+Yl/qnx9hKyUxsIhVeJe3HnxgwoG0IS
         YykYIUv47VIg3mNRsyulIivqGxy7MceCTlmD92miK16BDA5QeXgWf9uiiY7bP5WxFLzi
         mlN7hmiQLUeCPFkkTK86xLP8S6B2dl1vFJSDguRu4SvqhWecthzW7Xmt0KnMrRfaTwqJ
         BUPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ylk2t9BbgQXG1JUOXiLwSMb3P9RU8/AuMs5Jw3B1Vb0=;
        b=HS9Br5luQRHsou4QApFcSGh3gofFLw7m/3PheRQccayMLSXwy8omSIIiRQDFcIfDGD
         93hP1VxHzpGbtQSZEC4U2E2JQQqSZ1yjGo4sAfAQbIzjUiaSjFRG7VtOEZkH+4cZOTCM
         KEGUqYfyWDhxNTfjKZlSGBkOMJSjMEVbX+VxVfWjGth64rJ6X4vz3QD+dDi+i/ee3Evt
         zL/vJ5ZdF5pYg54Xcv2Drrg3fRtngmNzuE+84oCxTZeo0+TH2gxOK8cPg3ZfE+sFBOn5
         GTxST3ZhCLbP/rxBOfm9JcxzSXTpboBZ0lmr8Hk87JRP+YT407RqIR+pCRlmHG2Oxlcc
         ylMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530h3S4fWYM5TM9xdmyCrSVq5NOgkCz+3mzgYEXHHWZY+h6iJwFs
	/3uExglKqk2155Lkk6Eihuw=
X-Google-Smtp-Source: ABdhPJy6SX6p5EYZKg3q6Ly7Yrium7/Jzdn5bnLCpR8VMckY/L5n5DUubpukGvMvg9vCMo2+neJE7A==
X-Received: by 2002:a37:5d2:0:b0:5e9:5876:7f0 with SMTP id 201-20020a3705d2000000b005e9587607f0mr1512173qkf.4.1645024860373;
        Wed, 16 Feb 2022 07:21:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4244:: with SMTP id l4ls2378488qvq.9.gmail; Wed, 16 Feb
 2022 07:21:00 -0800 (PST)
X-Received: by 2002:a0c:eb02:0:b0:423:39f9:3952 with SMTP id j2-20020a0ceb02000000b0042339f93952mr2135844qvp.19.1645024859972;
        Wed, 16 Feb 2022 07:20:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645024859; cv=none;
        d=google.com; s=arc-20160816;
        b=ZQ3Gxq5zb03LSjyP7HQBGbQkQUIDppIcVWvQIc5s9PhHHnoo+esxC8aQmiUIwDGQhp
         ShsOmJR6qNFebZppdq0oR6FtAytgk1NKBpx7Tu8nx4XcGoplWvNmwRjYY2oLG3ayoeWQ
         KCoIZu5Tiq9zw+Rt4Cyv80/YBVj7tbHmTy3rFcdLXFlKF6hp+JMp4jNOApuyjYPcknAs
         rnUu8QqaFET2S9dNeQOS8vjkB/jmcGU1+OCA1RaKh3/j5sSWIQrheMkDjSa7hGmzjdEE
         6bcNBYcqU8h9iyAg9t856fis7Ys0mlvLVyo9BASh3AgBet0/ldwsIu4sr8R3GayEX+BV
         H+ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uBW1C5wFk0wpTZVzu222A5UngO/IWRNu9ZiYVflWd9Y=;
        b=qdz5tMVZlvmB0b3VpB7aeae2V+e5subLpheOzdVXaNszpRVe2TI6LNV0qd3fia6cxq
         R4qGcG1N7oruDx5y0y/EbmaQv2BVAPnZPQoj3E5YmQOwg2pvgbhhT2onrgGsXLqcAnn+
         ISpAP/0GMcHE3GKtho8rjACmIgu1A47J/FG2S2LPTr5IokT4nHkRLWnrFgQgu18unrtg
         IKdjggaCu95HZC4GbPPulSbv9aZVaXLs888GPTC5w+E5WCgDhGdjI6CyFeFXuZBAVJQX
         JdoQSLZ2bZlp6hrHrcJB714YzpE4sJbY65kHTlrffVwH0vD74qi63WmOva4MG9lx9CGs
         EpDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=i56LMHid;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id i16si1588549qkp.5.2022.02.16.07.20.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 07:20:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id q8so43127iod.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 07:20:59 -0800 (PST)
X-Received: by 2002:a05:6638:1409:b0:30f:843:f953 with SMTP id
 k9-20020a056638140900b0030f0843f953mr2079611jad.22.1645024859660; Wed, 16 Feb
 2022 07:20:59 -0800 (PST)
MIME-Version: 1.0
References: <f50c5f96ef896d7936192c888b0c0a7674e33184.1644943792.git.andreyknvl@google.com>
 <CANpmjNPG2wP9xiGDJboMJzf-YD+skOO532O+bKkAz+tpvDsF=g@mail.gmail.com>
In-Reply-To: <CANpmjNPG2wP9xiGDJboMJzf-YD+skOO532O+bKkAz+tpvDsF=g@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 16 Feb 2022 16:20:49 +0100
Message-ID: <CA+fCnZf3x3rWDNbDVYSbbO6PztWm7EfbhQN9bCHiXaScg8J+kw@mail.gmail.com>
Subject: Re: [PATCH mm] fix for "kasan, fork: reset pointer tags of vmapped stacks"
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=i56LMHid;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c
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

On Wed, Feb 16, 2022 at 10:59 AM Marco Elver <elver@google.com> wrote:
>
> On Tue, 15 Feb 2022 at 17:52, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > That patch didn't update the case when a stack is retrived from
> > cached_stacks in alloc_thread_stack_node(). As cached_stacks stores
> > vm_structs and not stack pointers themselves, the pointer tag needs
> > to be reset there as well.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> Did the test catch this? If not, can this be tested?

Kind of, the kernel crashes on boot. I got KASAN_STACK accidentally
disabled in my SW_TAGS config, so I didn't see the crash until now.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf3x3rWDNbDVYSbbO6PztWm7EfbhQN9bCHiXaScg8J%2Bkw%40mail.gmail.com.
