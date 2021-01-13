Return-Path: <kasan-dev+bncBCH2XPOBSAERB4UO7H7QKGQEHB3WWDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E6422F40F4
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 02:05:56 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id i1sf278377qtw.4
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 17:05:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610499954; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWNBJMg1hvS1qeBrnm4ICKK+bLqsa05V5/m2e2E4B47y19jNKBExKEmbfL0KcIgaFH
         +Cl30nrszTBKrfKgUoU6+6fPSimK2M4jT4sGuk8Te3nff6dlgePZv7tjauqfJNFQepaw
         BMBPTMuCjliBw4+Ye6HRXVriiHBV908dGpu5VUtleeZCDXJKti6jyXZRa2bOb3Qdue/T
         joZwUZ1aM8tE50xdOa5GkjBRmmif4G6GSkd69ykfGFxFxn+OBToKRPdyO0S8rxwBkYZL
         3gtiY8jRx0pkt1LErrpJflM/D4m+kUcNdIpJeUROFA8gHg6vkwNz1eCfIo4vvxn9OsSY
         7aXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8ex1tvfzq61V5Q+nyS+YVz+ja0OF6LE9rEIzYEQICdY=;
        b=Iumr94lnViRTJE38UkKKBtGlfrReDuVSgfqfkvGnxITWrNpwNIxH41qn40y0ajouel
         NbRkA9Q9b8r9BJZBVIfrkikrcl1gycs/JgOzPwsrUzSdt3mFD3diHHle7zDGVzcFgcGp
         vn+LaqdkU+QMQSWR3wILxneN9cIBuxeqt17RY/mQLR2B2swKr2dL+PAyGo+7/mS1vO51
         etVwMQXTZwoxwun92I7R7CeI38OvcQw8CAlEPo5O/IYzOl7S16nXHRnvH/FyaW+SF3NJ
         BZl1J8aUxerg/En77ttP22WJ9pqHI5WbAwO/Oe4joYJpQU8bjQ1tOHgjMn88FvvfY7ap
         pfGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eSDsp61Q;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8ex1tvfzq61V5Q+nyS+YVz+ja0OF6LE9rEIzYEQICdY=;
        b=VL21B5pbfRzRpeywMMUomLdkSSqt3ZxKsD8Dz81Otz/yP2B0VNxSfFGJb/dqlsC74N
         4ZgrBrS0QZcV1eOibg9PTaKvmrL5++td41aR/jSj9Dk4FKtjU6taxYb0AR6h5uojZc2I
         DIvUtjsc7ff7WLHYb0X9rPaX2UMZjry7oIL3wfZL54JIkicfz4ZQqZzIwgsumgdHF4qu
         Elfyrun2ipeNCcSbVwZKdi9wA9FD6FTYlrALIiJORpv+dCCepMHdmy/uysNs5/nAC3p+
         6d76zv/rcObNVT1peMWNaINARKxyQN3oSvzeaNQCiSGUssjVotGP/NDrBxJYiDrMpBVv
         nCWg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8ex1tvfzq61V5Q+nyS+YVz+ja0OF6LE9rEIzYEQICdY=;
        b=E4pR5APE5TNlDZbagLIjovoroO3MC/K23ctuGYZYd/60txZDfWj4qx8NjUwvG/GunH
         YsDM9wFul/I0/EKO5MRX1ZMKYFzvysLln29VYnVRVXK8fBVbcZfy627Yzf25LlFEr+iZ
         nBt6mv1AZxtTBgpSpE//0n+zttBaPHAf7gbuOPQQrlrXsEg/HDRfSc6SqMgL/R115uET
         npyA+iwET3rUtTld2S1mYRSqwh/iehLyR1Er+4aAr7OCHnklw3JFaalyDBd6eUJVG4/S
         yA4OF9VMHgtnkDSvPTpk8ClKkt6PZLQSu88TXD7KtQyo2PvH5SVP22zLaLQjMYv81CFx
         UwpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8ex1tvfzq61V5Q+nyS+YVz+ja0OF6LE9rEIzYEQICdY=;
        b=djSMi5DH/v1LKSvtIvwBDG0MKrs6tnqpO3vT4HWbfCTJSaYNvdZU0BXWPza+r7ChRk
         DiHUAi6I7ows92GuW3F+5b0NOD+pgZaxjd02kMEBAkcQZE8HrH7HyxMPP/A624hFInqk
         HVHIe8QOEW26sRcyTRt7+pFuoNKLkDgSPHJRacKi3/YblK1ak706xdsBJa226GFYtbS2
         9eL6UVbP5P6islN3rFsVdv+zpQjgAGVShPHiJSOWP3fShn/vEDtcUKXsbuozeyBqOkwF
         BnuKn7oSQU97DZcUminwK8UILceNUH7U0wT72rY9UPuY7QLnpBWIPjEbQG6YREhCL9vf
         vFEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5307K+OtbapUHP/m1UUvmnWbR3095Z4+B8KgY1EzCFQA88gVzGbH
	KwB55zUAdasNw7u/LIHTHJ0=
X-Google-Smtp-Source: ABdhPJxGFJFBuu/m4DPJT6ELnoSOMrCouwEGQEbxMoCLAGJ7o/o9BmON6/OEgRWRwQfvh9jmHZxS7g==
X-Received: by 2002:a05:620a:22ee:: with SMTP id p14mr2473020qki.343.1610499954610;
        Tue, 12 Jan 2021 17:05:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:205e:: with SMTP id d30ls323136qka.3.gmail; Tue, 12
 Jan 2021 17:05:54 -0800 (PST)
X-Received: by 2002:a37:9d0e:: with SMTP id g14mr2398985qke.125.1610499954197;
        Tue, 12 Jan 2021 17:05:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610499954; cv=none;
        d=google.com; s=arc-20160816;
        b=p/fWXOUROGXo0wP99dcXNemPERXhVGSWzQ+U04DGZOv/h+V4qlNksYSnqPmxNgXpsA
         RmSTps1wqXY9I8GkRqLShm/lwOGqCrMunQrbYCDfPDXSipY2RBWtSS7OiNX8EhF7D0Ae
         qfKYdMfs6x1N4gxAyz63y5fDK81+RC+yuUXzYSt0ejdLOpKTCR7DX4YOLM1KMDKCX0nB
         RWJU286yhBWxXpfe7oV6LzqZ2oO5Wf1C1el0IwLzf2l9OR5eNZRzOOk0T/GqKbDaBRJZ
         jgbVGarpdWbILin46T2i0oMCbCJfQq76XhFLjBBIz8omK2KcLHGLUCi0uJ+RdiaQnysH
         a2og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZzcZdwtEwuTkjg1UGigIozdrGb7hGGAIRM2egaUKPBY=;
        b=aLmFNqr3Q6520l12QMwtOac7KXOhCAiUs+S/9ATMtBefgSyM7xUrfh384p8mS++bbs
         dY5kHUizMXQ/bXbeXuN1nFU25+SJXTO4jNLK4gvp8jNwutLnc/McKXW99VI0gMnLfWjr
         OFNaQ00TEJt0WDLBXTr18TydWWotfMtmWHqk4NgtI2zXyGIDmPDIyQk88Cgr1D0sORFx
         mPBLkxNLPiEBQi+dH05zV+IUobV6c9hDIZENPOulyYxUow+c4u5c0TQezWpA9SwbmtfX
         44AVaacHAY68YE6T4DEn7CmB1m5Kci67YdgCJHzrHedECZkG1Hww8l/NbDXW2zWZvejT
         yRqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eSDsp61Q;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id j33si41389qtd.5.2021.01.12.17.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 17:05:54 -0800 (PST)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id k78so552619ybf.12
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 17:05:54 -0800 (PST)
X-Received: by 2002:a25:880a:: with SMTP id c10mr3069173ybl.456.1610499953872;
 Tue, 12 Jan 2021 17:05:53 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QUZzBtGAk7Tghf+ZXxnnjPuSvHLHTs3imM5N9ZmVFSC7g@mail.gmail.com>
 <CAAeHK+z03_kxkzj=sckT87PdrtjcZAYszq62=bUD=FwZTjjSag@mail.gmail.com>
In-Reply-To: <CAAeHK+z03_kxkzj=sckT87PdrtjcZAYszq62=bUD=FwZTjjSag@mail.gmail.com>
From: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Date: Wed, 13 Jan 2021 09:05:27 +0800
Message-ID: <CAD-N9QUO6xyB+xYMQybzWfwqU1Yv2creD5qzChd3_dM6Byu-hg@mail.gmail.com>
Subject: Re: When KASAN reports GPF, when KASAN reports NULL pointer dereference?
To: Andrey Konovalov <andreyknvl@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=eSDsp61Q;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Jan 13, 2021 at 1:06 AM Andrey Konovalov <andreyknvl@google.com> wr=
ote:
>
> On Tue, Jan 12, 2021 at 10:30 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliang=
abcd@gmail.com> wrote:
> >
> > Hi all,
> >
> > from my basic understanding, KASAN can catch invalid memory access,
> > such as NULL pointer dereference. However, recently I encountered one
> > case - BUG: unable to handle kernel NULL pointer dereference in
> > x25_connect(https://syzkaller.appspot.com/bug?id=3De4a61ec2a7dc1ec61617=
142a0f7a7d0427f8c442),
> > the kernel reports "BUG: unable to handle kernel NULL pointer
> > dereference" with KASAN enabled. I don't understand why this occurs.
>
> Hi,
>
> If the memory access is not instrumented - like in this case where the
> access is done from inline assembly - KASAN won't detect a
> null-ptr-deref.
>
Thanks for your clarification. That's really helpful.

> Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAD-N9QUO6xyB%2BxYMQybzWfwqU1Yv2creD5qzChd3_dM6Byu-hg%40mail.gmai=
l.com.
