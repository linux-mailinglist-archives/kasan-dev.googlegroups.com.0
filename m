Return-Path: <kasan-dev+bncBDN3ZEGJT4NBBGNG42AAMGQEFYMR23Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C90A30C8B1
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 18:59:54 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id k90sf14877838qte.4
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 09:59:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612288793; cv=pass;
        d=google.com; s=arc-20160816;
        b=aP92svv+Lm+EFMvQFWhIhOvk3XM3RiT9vg67rgwI362Ow3MhdbXop5yKHtbYlc8QlV
         VRHpfOFc++lw+Vscd4bJjJMMsw8ygBVyzZLn4p0xJaFAQ1Us2C66HL97qOwvrBdsde3n
         U04mGt+49yDO12ik4zkPdJGMrqjsY2oysjZbpgPoeumw58M8JNSc+BwMZ61RwUhi97Jk
         9AA1zTwCFGVsR3VqC+5Qox0qQvBLdIabJ7bwlqLd6oKO28R7qwPFLtVkytGq8BPNQoxm
         CRkEow6/IjxLdCjd2pZyCYR0uf5vMQu13s3KcUtOCSRxyvMLvYiO7QPiZDgQG1SvBliW
         wd2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bOotPUTDTZVLF1CQeuqilQNDPviQxjdep12coJTuhT0=;
        b=EbneJrsFOV8E3bXoGQk5Nl3eiv0sFSi+fI9nHh0qZt6nicvdQ2k+tjMPW17ICWX8S8
         kWolL80AQtphDmQFGTwYErVcWBEzD+evALKHNdw9vo4NimHIF/OWjvw1CHPzBLqsIGod
         vojXQ+rPlIzbNJlj9q7ClHm2Hl2F6AfxAFvMeALOsOmx+4k/4AzHGhZz9iK4k4Anl3tr
         1O3+XNAFiFT1DLqudR8X8RvRub9eVh38jies1ZTiCDYode3zYnTNgmcXJwlLGHoj9f0t
         OI/pxPQrGwCN63HzgR11BpGUhobJLJlk2tXcJ5tT/4KPgel0E7uvAJ8c9zJNRRCbFA3F
         Yc4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ApRAVOsX;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bOotPUTDTZVLF1CQeuqilQNDPviQxjdep12coJTuhT0=;
        b=f7X8re7m4i5DgW6Di0HBEsdvQJFfUnZZFdW1oXxGizVXf+D+6QFMzPP+K3rzc6NYVv
         jZbGYFACxTGhyxkYiCaUcAaUJp6yxehcynEh2G9zc1JFFXh6fxLgcDSJyJ6hFSn0a/O/
         Y2IMYJhGdbmEGJEQdfBk2IcQ4rjMTN/hTpZUILi1EJQG1l1NrIwDo/YGvyfv3gxLzilh
         bzDz3B97PyFPvvTHBJa1Hxo6ZorwbRNObvu7o/2q8NmFSD7u5Pw07X2HzY29cvFK7iyI
         VSHxNFo4uSTo7Bo+6ja3ezARVmdtGIX9o8wR5XzvkM0kmIov11UbrFvzNqNgpNBCBgiT
         seIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bOotPUTDTZVLF1CQeuqilQNDPviQxjdep12coJTuhT0=;
        b=GvK9gIoeVw94fFrhVBoh4z9HHSd+MCxToLqYJ6vjZY4OAfGZNYYotXPzDEOm+ldwGS
         GEQrg7nnKuVeY2bpy/hd1baVitZsppRuRJrpQhxV4bFAG08kn7+GZ43W6Km8ncei/cMf
         S77WWuy+KFO2HZf9PFFddIesYa6WTwo6oxvqLkSJGcPuFcYEn5SjTQFQABpkyoC7RiGU
         wEaONH9v8Z4NF6y4mNz5oZn6v/0eKXJSByheGwcs67OU/hB67NjcrcXET9lINUaXeG30
         dh9JdEkLpi51/Xts0N6li3rCrlBUsrk+2yYkM6mV8PmywCgGksxbiJbDKumA1LrTM5Bi
         v5uw==
X-Gm-Message-State: AOAM530Knjo5YJwJpMSIyqJLpWj6xeBam4YU4kJFpviTxpvmofSnGpuY
	3f7F6js6EbFeeqFAnoZJq0M=
X-Google-Smtp-Source: ABdhPJy1gl5BqB3rMWnC05XvJx99IVr/STYNdi8/dMLiATJFLuMXK8nrYvSiO8mZsywmbYINX85B5g==
X-Received: by 2002:ac8:4f10:: with SMTP id b16mr20561292qte.291.1612288793062;
        Tue, 02 Feb 2021 09:59:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:248f:: with SMTP id i15ls10905303qkn.11.gmail; Tue,
 02 Feb 2021 09:59:52 -0800 (PST)
X-Received: by 2002:a05:620a:12e8:: with SMTP id f8mr21502666qkl.337.1612288792765;
        Tue, 02 Feb 2021 09:59:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612288792; cv=none;
        d=google.com; s=arc-20160816;
        b=jLUuC4tdkHiICwNTTOK7YvxmwOZSZ7m6bv4azyLuPiK78itWkl+Z1Tws6XJ5t2ojlr
         ShdmMjRjmN9Mugm8K7A2zG3J+tVnP3OyucGR9E0SX36qHCL7wXqq4WLqMlo5NaILjmao
         rWaCgFapNDucAKk+lA9Hwdcxj/Gci7zLe5496uYy69UjfcyicM2JDIi9cmbeAEtpMeIW
         yzLvX/Z3raRrNITwNNx/uGCYoWZKTCx8SI+OGsu+PzIxBKMxcc+KTdZJg0K1TSJdCyJo
         /v+OKDk1S/kgfcHopZkvzsXyl5PSz58NX31VR6flIy0BneaH23sDQngsGDyYzhBVbLP7
         Ag9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IzDi96523sahyObx2Yd6Yye0zu9EowaSoOEtWhQZYPw=;
        b=NLFiL8B79F1NcOKX2VDcabU8GA//xWyNYRwTGCpnGCUtgPA/NANWXsLaoYjSTD/GkY
         1TWQAlnfAH4EQx1O3JmfYMm1psuPhhPGospTLdXHtIQmylymR/4dNGebbo5p0h/HBPht
         fTIz6ezY2sp1kYYkqiRQqnhsRKXXBlkd573QvuqF4ANvrYAEVbaN3ZSB+qeHQ2YCH0wT
         LTMvnz/Ljp+p2EQsySCF05ADHb47D40mtCi76MVEZb3MOk1AhmegaapvuuxlDSxSpAYV
         WXb0x165O1snqYCYWbIH3rt3V/tB4Pnhq16rdUel7Ui2bYUzLfjwNtFrqFfGk+Dd27+R
         UkzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ApRAVOsX;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id a26si1219264qkl.1.2021.02.02.09.59.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 09:59:52 -0800 (PST)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id u17so22343330iow.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 09:59:52 -0800 (PST)
X-Received: by 2002:a5d:94cb:: with SMTP id y11mr17689016ior.117.1612288791921;
 Tue, 02 Feb 2021 09:59:51 -0800 (PST)
MIME-Version: 1.0
References: <20210201160420.2826895-1-elver@google.com>
In-Reply-To: <20210201160420.2826895-1-elver@google.com>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 18:59:40 +0100
Message-ID: <CANn89iJFvmLctLT99rYn=mCwD8QaJfEaWvawTiVNV4=5dD=Tnw@mail.gmail.com>
Subject: Re: [PATCH net-next] net: fix up truesize of cloned skb in skb_prepare_for_shift()
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	David Miller <davem@davemloft.net>, Jakub Kicinski <kuba@kernel.org>, 
	Jonathan Lemon <jonathan.lemon@gmail.com>, Willem de Bruijn <willemb@google.com>, 
	linmiaohe <linmiaohe@huawei.com>, Guillaume Nault <gnault@redhat.com>, 
	Dongseok Yi <dseok.yi@samsung.com>, Yadu Kishore <kyk.segfault@gmail.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, netdev <netdev@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, 
	syzbot <syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ApRAVOsX;       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::d2a
 as permitted sender) smtp.mailfrom=edumazet@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Eric Dumazet <edumazet@google.com>
Reply-To: Eric Dumazet <edumazet@google.com>
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

On Mon, Feb 1, 2021 at 5:04 PM Marco Elver <elver@google.com> wrote:
>
> Avoid the assumption that ksize(kmalloc(S)) == ksize(kmalloc(S)): when
> cloning an skb, save and restore truesize after pskb_expand_head(). This
> can occur if the allocator decides to service an allocation of the same
> size differently (e.g. use a different size class, or pass the
> allocation on to KFENCE).
>
> Because truesize is used for bookkeeping (such as sk_wmem_queued), a
> modified truesize of a cloned skb may result in corrupt bookkeeping and
> relevant warnings (such as in sk_stream_kill_queues()).
>
> Link: https://lkml.kernel.org/r/X9JR/J6dMMOy1obu@elver.google.com
> Reported-by: syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com
> Suggested-by: Eric Dumazet <edumazet@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Signed-off-by: Eric Dumazet <edumazet@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANn89iJFvmLctLT99rYn%3DmCwD8QaJfEaWvawTiVNV4%3D5dD%3DTnw%40mail.gmail.com.
