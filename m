Return-Path: <kasan-dev+bncBCMIZB7QWENRBHMC72UQMGQEITD53UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 3739C7DB77B
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Oct 2023 11:10:39 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-542d3c2a236sf14124a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Oct 2023 03:10:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698660638; cv=pass;
        d=google.com; s=arc-20160816;
        b=eGXXCRyfqEso24R24hQsFlPqg4cTg2qcnkrLd63DDRXAzNiQ0PbUENshDSqFvgCX8N
         QrBnkcN25THC8W3ON6YertBBT5TQDXn5t1D7wyEsBYIzRYUWGWGLnyilTYZmeKaJB5D2
         33+azbD20PD/9MFtsDxsZjDQrZZj+uyKMyTpoaPddcQCqgT30pjDnBxelgSXwq1ZaIk5
         b9VQ+ngDlL9hbAkpz6sDZKPFdnqZa3g7eKhnDRDCOwvA+4a3jvYc7qMyG9eJcy8swCsH
         YZppVrRUPzJHZ4cc6jW/C+u/42aVxedDbXAVdoDX0g5M8vJyc8S2lN83ymI57Nr7eZYo
         DpFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=podd3BNBti3HQLIxz7A8vRdlxN8ZxX0aAQJ2Dj/NX8I=;
        fh=1GhISFj8qt6/r9hzz/0ybewQWm8QJ4axWqUmoX7FGws=;
        b=i9RCs0l86z/bAu37LKsRzWBDKS7ChBskqgfVE3zXL8a6uyh/ueXMcwVwMBPLfjyyvj
         0cDYsQtLrWe0e+5LZMYZ/DR0NP1ivYWhgI8DCcUnzVuqcVKBSXs6ePTFZi+DebWwW+51
         AFBsWIsUC+gi7v8Rm1MAJd6WL84BoV/jBQdt07Z8NbZRE3L7u6F3goIKyTrGrJFseLZ4
         JBthVZmXeQXy2JVQSpd4rNZLHeBQTQoUeORGZxPXV2XijxiZXvqpv5gPP4JH7HbLRpjl
         swrtFsJdI/O4xWO4i+1X1BtbbxF2C6iElibdcfQlqcelN2fDZRbwAunyd0B0hAsfzodB
         NMTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="pjtCho//";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698660638; x=1699265438; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=podd3BNBti3HQLIxz7A8vRdlxN8ZxX0aAQJ2Dj/NX8I=;
        b=EUOHQtTjaa8xNwr7nvBwFKBdCdP5YTSdS6cQqt5Fuit36aHMv3y9N+ELrSfQESY2af
         wlRX8HnaDk+VQzOlM+TuZcTZIukaXy1L23oENDBZY8lCFaD1lnUqQgdy/L0I2bLP5qXW
         MKRkie8qSrlcXEYNopI0QBfEFFz/2X+oTAAfRYmJHq04Wop7ZaKcQgrOl+v+D8SAJ+i8
         QTxuoopRrowIJtAZ1U27/XZmQeTj9RmOMOldbuUwYg+cVnXEMO2U6aLWMUBldGAGmvyn
         HPea4frT3QsQcHIAZl4kXcJjEstHITb+5iczBAnSQgQo0yEqB0/UxZi3PoOHFa3VVe41
         mejA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698660638; x=1699265438;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=podd3BNBti3HQLIxz7A8vRdlxN8ZxX0aAQJ2Dj/NX8I=;
        b=doB4GRVRvUGM7UL50kVrl4ZcG0UGBTu+nF7cShQxZXFeh6SW+w6gKAi0lbyQQe6+98
         FFgZ5v6pkktwp6CXAUfKuMhflYZeBKqr1Kd50RRZnBgYJHbJxunteAoGm65uPLLdEvAi
         +MfiSOnMquc1wnYYAXqK3ljhbZBAL6UPqq9IN/LTUQqtLuUIpDb0QXOUJo+gUNidRQrF
         fuyUFlGkCCaQMpFZHxgBOeX4DY6m9250A7XYbxX0cGCjLYi9Dp6uBL8HTC8D2doGyiPf
         d2FrjxYhwxaqEhqrZf0uXFS4ifFpueGI0ENKORKljyFpbEXmECRphrD6o0hl158Y0hxX
         NbKw==
X-Gm-Message-State: AOJu0YyJwH4dbafmlVuewVK9pVWJjLP5WsIpfhXjLeVd0F8nmtcKNcg8
	Gz6vOqsiA+RwmrgAAgcjKpI=
X-Google-Smtp-Source: AGHT+IE6/4MM3nj85REXioECvaIOcJYvOcfwh3ecdYUH7AXsRsNb/Qdy2ueNmJ/BKDtRapsdUoYRoQ==
X-Received: by 2002:a05:6402:f0a:b0:542:d861:593e with SMTP id i10-20020a0564020f0a00b00542d861593emr123983eda.2.1698660638049;
        Mon, 30 Oct 2023 03:10:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1043:b0:509:105e:64f2 with SMTP id
 c3-20020a056512104300b00509105e64f2ls109375lfb.0.-pod-prod-04-eu; Mon, 30 Oct
 2023 03:10:36 -0700 (PDT)
X-Received: by 2002:a05:6512:1586:b0:509:1ecb:5a04 with SMTP id bp6-20020a056512158600b005091ecb5a04mr2660745lfb.19.1698660636319;
        Mon, 30 Oct 2023 03:10:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698660636; cv=none;
        d=google.com; s=arc-20160816;
        b=aGXHWK2mAnShvpYt38zc5qAZeQtT+4FZRovAu/fkOt+VH0M5WGer4RGAFIYb1O/YK2
         0EEkOpKoMv5ncT4jnUJ+XlAS56n5deUer30yCy4nzZkkunlUeJq0/NcObRF6DEdzaAK5
         2S93HNa4U93b8QXW7GCjOk9z1vIMjRmzEWJvvcDwOQssEcd7QbRq3ud51tRK8FnBNRkj
         P+dmlVQOyZvjR10PZHCn7T+xaQyrqwRuroBK/W+ee6upN1fl14PuGb55IO4+5aPKApzJ
         o4Sq2HK7hBcpde3gsazJuBXkip60INV++I2p762jV06SZZrEjzgrvB6V8grZY+nuaxJd
         j3rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=T3zgy30RJ+D4CBrJvlTQXpMKazTmgNjyYtW3+p1yMKE=;
        fh=1GhISFj8qt6/r9hzz/0ybewQWm8QJ4axWqUmoX7FGws=;
        b=Dhed1imNi0vsQuoRKs8DgY9gvhLWeyqSXNt3xCEbiASoXk3bNi2u1rEtiepPTy305K
         24cTGJBzVCf8JomvFSAfcNrE/1B/s5jk5L+GAjBIoVMOs3SNW368lKAE1f+CiAyTQwFH
         XwOU3qdBdIakDsuNq/iKrKqpx/yOTHHd+q3ZKAqrRqNEKXUf/uunCEKSRf0oNl/VNRH+
         t8BnYDxBhsguVKBT3WP9maE4nRW5u84XJTbSUhLPAZTvubVd64sog0Sst/2/EXM3xT92
         dvX5wPyH4O+4GLHdJonBivQzb/4d/fvIqwahjn+lwCF4mF9RdM5e1BGB6aseV5ODEiuA
         aGkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="pjtCho//";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id d1-20020a05651233c100b005056618eed7si479385lfg.4.2023.10.30.03.10.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Oct 2023 03:10:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-40837124e1cso78675e9.0
        for <kasan-dev@googlegroups.com>; Mon, 30 Oct 2023 03:10:36 -0700 (PDT)
X-Received: by 2002:a05:600c:1d17:b0:400:c6de:6a20 with SMTP id
 l23-20020a05600c1d1700b00400c6de6a20mr92585wms.3.1698660635350; Mon, 30 Oct
 2023 03:10:35 -0700 (PDT)
MIME-Version: 1.0
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
 <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+a+xfzXBgqVz3Gxv4Ri1CqHTV1m=i=h4j5KWxsmdP+t5A@mail.gmail.com> <VI1P193MB075221DDE87BE09A4E7CBB1A99A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB075221DDE87BE09A4E7CBB1A99A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Oct 2023 11:10:22 +0100
Message-ID: <CACT4Y+bxMKEVUhu-RDvOMcbah=iYCWdXFZDU0JN3D7OP26Q_Dw@mail.gmail.com>
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN report
To: Juntong Deng <juntong.deng@outlook.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, ryabinin.a.a@gmail.com, glider@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-kernel-mentees@lists.linuxfoundation.org" <linux-kernel-mentees@lists.linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="pjtCho//";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::32a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 30 Oct 2023 at 10:28, Juntong Deng <juntong.deng@outlook.com> wrote=
:
>
> On 2023/10/30 14:29, Dmitry Vyukov wrote:
> > On Sun, 29 Oct 2023 at 10:05, Juntong Deng <juntong.deng@outlook.com> w=
rote:
> >>
> >> On 2023/10/26 3:22, Andrey Konovalov wrote:
> >>> On Tue, Oct 17, 2023 at 9:40=E2=80=AFPM Juntong Deng <juntong.deng@ou=
tlook.com> wrote:
> >>>>
> >>>> The idea came from the bug I was fixing recently,
> >>>> 'KASAN: slab-use-after-free Read in tls_encrypt_done'.
> >>>>
> >>>> This bug is caused by subtle race condition, where the data structur=
e
> >>>> is freed early on another CPU, resulting in use-after-free.
> >>>>
> >>>> Like this bug, some of the use-after-free bugs are caused by race
> >>>> condition, but it is not easy to quickly conclude that the cause of =
the
> >>>> use-after-free is race condition if only looking at the stack trace.
> >>>>
> >>>> I did not think this use-after-free was caused by race condition at =
the
> >>>> beginning, it took me some time to read the source code carefully an=
d
> >>>> think about it to determine that it was caused by race condition.
> >>>>
> >>>> By adding timestamps for Allocation, Free, and Error to the KASAN
> >>>> report, it will be much easier to determine if use-after-free is
> >>>> caused by race condition.
> >>>
> >>> An alternative would be to add the CPU number to the alloc/free stack
> >>> traces. Something like:
> >>>
> >>> Allocated by task 42 on CPU 2:
> >>> (stack trace)
> >>>
> >>> The bad access stack trace already prints the CPU number.
> >>
> >> Yes, that is a great idea and the CPU number would help a lot.
> >>
> >> But I think the CPU number cannot completely replace the free timestam=
p,
> >> because some freeing really should be done at another CPU.
> >>
> >> We need the free timestamp to help us distinguish whether it was freed
> >> a long time ago or whether it was caused to be freed during the
> >> current operation.
> >>
> >> I think both the CPU number and the timestamp should be displayed, mor=
e
> >> information would help us find the real cause of the error faster.
> >>
> >> Should I implement these features?
> >
> > Hi Juntong,
> >
> > There is also an aspect of memory consumption. KASAN headers increase
> > the size of every heap object. So we tried to keep them as compact as
> > possible. At some point CPU numbers and timestamps (IIRC) were already
> > part of the header, but we removed them to shrink the header to 16
> > bytes.
> > PID gives a good approximation of potential races. I usually look at
> > PIDs to understand if it's a "plain old single-threaded
> > use-after-free", or free and access happened in different threads.
> > Re timestamps, I see you referenced a syzbot report. With syzkaller
> > most timestamps will be very close even for non-racing case.
> > So if this is added, this should be added at least under a separate con=
fig.
> >
> > If you are looking for potential KASAN improvements, here is a good lis=
t:
> > https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&component=
=3DSanitizers&list_id=3D1134168&product=3DMemory%20Management
>
> Hi Dmitry,
>
> I think PID cannot completely replace timestamp for reason similar to
> CPU number, some frees really should be done in another thread, but it
> is difficult for us to distinguish if it is a free that was done some
> time ago, or under subtle race conditions.

I agree it's not a complete replacement, it just does not consume
additional memory.

> As to whether most of the timestamps will be very close even for
> non-racing case, this I am not sure, because I do not have
> enough samples.
>
> I agree that these features should be in a separate config and
> the user should be free to choose whether to enable them or not.
>
> We can divide KASAN into normal mode and depth mode. Normal mode
> records only minimal critical information, while depth mode records
> more potentially useful information.
>
> Also, honestly, I think a small amount of extra memory consumption
> should not stop us from recording more information.
>
> Because if someone enables KASAN for debugging, then memory consumption
> and performance are no longer his main concern.

There are a number of debugging tools created with the "performance
does not matter" attitude. They tend to be barely usable, not usable
in wide scale testing, not usable in canaries, etc.
All of sanitizers were created with lots of attention to performance,
attention on the level of the most performance critical production
code (sanitizer code is hotter than any production piece of code).
That's what made them so widely used. Think of interactive uses,
smaller devices, etc. Please let's keep this attitude.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbxMKEVUhu-RDvOMcbah%3DiYCWdXFZDU0JN3D7OP26Q_Dw%40mail.gm=
ail.com.
