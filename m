Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPUF7SFAMGQEHJYIJXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 33DE742554B
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 16:22:55 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id n6-20020a9d7106000000b0054e474ad3ccsf391401otj.15
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 07:22:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633616574; cv=pass;
        d=google.com; s=arc-20160816;
        b=wQATOAKrm2qw8BhqW9IHhfAyLEvI9/c45YsDKKkH7KzqRqr04TfwBgR3yOHhUMMo+A
         j5EXkEFE1Vcn+IEWpRtP8hY2IgnMJ6c21OFso3RRkQK1F7ZrPx1JxG/uo3d4uxeVq25Q
         EZUuNFqewheeMUbJmd7Q8KvBSgq2JDmR7HXxljRC1Dg0OlEA+2I5k4rr0ScqAmaThEe0
         33TH4cFawKIbLAB3FuwfEheOsNRdHlgTQUUAasrbtIJfz4Z9Hj1K5TuOaB3tM8S/jpwK
         sMYtC1Y3mOOOJcIzpG8cKrLBADNZh2EpcbWbbvmU/LCQiT95C4UB3zCklewzeNpIGddc
         Kx6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R4cJz7qFUOopezXmazqUc9liBiJtdD+cq9v4OyIutMg=;
        b=ZC5RqD9P214rBPz4ZYt/aYme2TfUluG1QW3vG1YBpIhwpgMzPentPeTKTGat9xoUHF
         vRB6IBmBjYbYtm+9zF7J4Tb6CqS+6cFodi3RebUaU3nmbbGqelESYqCZAxgRavxK+jR4
         XmxjZ//xlM75jUFHTdiav9ZEuEptRDtq+pgasIoLH1xMi0/Dp5Kwuk2PYzfvVBtinfrb
         oBkktQnl44oKiocqetwnEZNkMzXaRz60hdHGOpxCUF/NHKdU/IGfNNXF0jW0gXZCFRL5
         Mf8KCALzSpQuAEC3J9DD8iWzTjmVwKTs0XEigl80iuyqqhPAvDFN9cWMPqx+YyTW464W
         Mnqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iReQzGwY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R4cJz7qFUOopezXmazqUc9liBiJtdD+cq9v4OyIutMg=;
        b=L2VKcAy/hPDDSjNiQtu4qn1EGFupweLvsne10PJdGZeW4ud7HZT7GjNOkXVooeGsxw
         k5XIozZOSOP2cxQeTTecyuN5V7kflxo0XDMsQIUbpTe+EsSai6U8xBp+U+TY7898Cibz
         EDF/cOZ9eCu1Db0oq4+/Cbj4XwOIv9la6HiV1fPZp966W1dDWSj8MZRt0URiO3dhi+Jh
         YVx5P7AGelx5QCYw5q8UADeT6ec+Wv3IgalOKux9eF8JKVGJYMnaMds4iPxfTA2L4dVR
         NWBtqKUuAwnqr650X5Xdze1u9d6RcuoO15nSrceTV3clmIoox8wYOdq5/iys/sOslwCb
         Wtxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R4cJz7qFUOopezXmazqUc9liBiJtdD+cq9v4OyIutMg=;
        b=F4uMG/7BY4eXh8Gmsi1o2+Womqlj8mUT+ngL+tlG71AMy4PDFQyFxhnd6TTeTsRfId
         kwYXag1VNe2Eb+P6kKRkNa7qfUAxZ0tlZzUI0ASapFCJqhKadwBMHoIqgK3eKrIZrqMp
         eHfxFx+5xfVkX26wtJnEwNh+Xh0NcKKnHKSdOVsro2rdXobuY6YTgO/s3PrQliTa8vJW
         e+wSbnygM0Gx3DXANBwTt2RuvMGoQhGO0KT3LH3hhB3YnMubuoB0jlRG7N78XZvjQeCg
         Czmt4vwTuqmS6o7WS/bVJtwTivSXNTocykgd0rC04ysS0e5dy+Tpas3VUEnXHw2feCfx
         IOYg==
X-Gm-Message-State: AOAM530NabHCbNdDLIUBmpdhsuG1+ESsU0Yk4pa5N1lCIejfqECSzxwF
	pYrZXKC04ikqb/xaQTHQlJg=
X-Google-Smtp-Source: ABdhPJyly+iynZIn8gtYE9jjuhxhEKcRwiMti/Y+M4C/Cfda80QZ9lX2J/VYHaBMIfIz65uzVyE7ow==
X-Received: by 2002:a9d:5f8f:: with SMTP id g15mr3703612oti.384.1633616574068;
        Thu, 07 Oct 2021 07:22:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:196:: with SMTP id w22ls28829oic.9.gmail; Thu, 07
 Oct 2021 07:22:53 -0700 (PDT)
X-Received: by 2002:a05:6808:17a9:: with SMTP id bg41mr3323796oib.88.1633616573679;
        Thu, 07 Oct 2021 07:22:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633616573; cv=none;
        d=google.com; s=arc-20160816;
        b=NYqUsyEvy8BR85HkpksUEjT+pZ4jujsTHfFvF2Uxkb/59oYV/AlDMGq8YbChT5pX2b
         bGngQHnK/oOdzjZ8KtCvd+gqhOLPpskCBgk2r78LcpSaAMUIz1WI2fUJ+jPyR8YJGFMN
         klw82CEcb7lVN3DffqHRthE4s9kZ3wOTd/MR4qL0GyBwiJ4h+W8e0CPOB+MxjFkLfL1x
         prjauD1mgZIlwbnuWauxVfw22ay4tkjyzW9UrOYgYJi776Ibl7xsgrIFV3VdqTvcjOKo
         JhwEJdOeBTM/y7ulH5aeVTXjaFUYwdEULKQUl+qXWVI5cYbvAkDsF9pC1F/inOQ9CU/m
         LuTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=68r40UeTS22EPeHnKpLst2NJmGcOMP8BmVA3Kz2GylI=;
        b=tJ68u7fXex4Qr/5QJPl7NWhEofHKjoDdx/Buqyti+uZ1/GiEXCIDUL4uj43lhJlMxa
         Vu7KgAXpFaYY5EUft+Yv3RXHa3zznMgezT6UgrzVQ2eDzQr1PQdwYnswIclhuAdJNIwI
         7lhX51hJ++4m7AXwD5VaXb+lm8NwhsEkFDB4lQt1L/3v64X0whkRzOPL0NNoNffxTBnW
         MEyAyTJvOynsHxFM6IAAKdmVmFfTIr/ODWLfE9T3CQuSY1xPxQZ6UFJri50bSPdxtIhv
         ZH5Ci+lDSGSs30UD5Y2pV+7m/ooRH2CDEbVGj55fcbXe7cJj1Fqfzmj+vKu9KJCzYMhT
         K1pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iReQzGwY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id m30si2371228ooa.1.2021.10.07.07.22.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 07:22:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id h11-20020a4aa74b000000b002a933d156cbso1958466oom.4
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 07:22:53 -0700 (PDT)
X-Received: by 2002:a4a:dfdb:: with SMTP id p27mr3556642ood.70.1633616573163;
 Thu, 07 Oct 2021 07:22:53 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux>
In-Reply-To: <YV8A5iQczHApZlD6@boqun-archlinux>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Oct 2021 16:22:41 +0200
Message-ID: <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iReQzGwY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as
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

On Thu, 7 Oct 2021 at 16:16, Boqun Feng <boqun.feng@gmail.com> wrote:
[...]
> > Also of importance will be the __tsan_atomic*() instrumentation, which
> > KCSAN already provides: my guess is that whatever subset of the LKMM
> > Rust initially provides (looking at the current version it certainly
> > is the case), the backend will lower them to LLVM atomic intrinsics
> > [1], which ThreadSanitizer instrumentation turns into __tsan_atomic*()
> > calls.
> > [1] https://llvm.org/docs/Atomics.html
> >
>
> Besides atomics, the counterpart of READ_ONCE() and WRITE_ONCE() should
> also be looked into, IOW the core::ptr::{read,write}_volatile()
> (although I don't think their semantics is completely defined since the
> memory model of Rust is incomplete). There could easily be cases where
> Rust-side do writes with lock critical sections while C-side do reads
> out of the lock critical sections, so Rust-side need to play the
> volatile game.
>
> I'm not sure whether rustc will generate special instrumentation for
> {read,write}_volatile(), if not, we need to provide something similar to
> KCSAN does for READ_ONCE() and WRITE_ONCE().

For volatile (i.e. *ONCE()) KCSAN no longer does anything special.
This was one of the major compiler changes (-mllvm
-tsan-distinguish-volatile=1, and similarly for GCC) to get KCSAN
merged in the end.

So if rustc lowers core::ptr::{read,write}_volatile() to volatile in
LLVM IR (which I assume it does), then everything works as intended,
and no extra explicit instrumentation is required.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOA3NfGDLK2dribst%2B0899GrwWsinMp7YKYiGvAjnT-qA%40mail.gmail.com.
