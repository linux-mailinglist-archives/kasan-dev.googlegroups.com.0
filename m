Return-Path: <kasan-dev+bncBDRZHGH43YJRBCMPTOFQMGQE6CPPTSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 03C9342BF2F
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 13:48:28 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id z130-20020a256588000000b005b6b4594129sf2806013ybb.15
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 04:48:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634125707; cv=pass;
        d=google.com; s=arc-20160816;
        b=CAbrzVuaFtaIEtnjdYokxs9AcIrr6cLJHgxLIZ1rUCQfo9eiY0S6rnikFmXKnhfk/U
         2HlStZgazBocrBkmp26SpcefEhNhJhuKVCDRM0rb2xUnjM/gwAlLY03s7oTo55jVyRvC
         Jxse+KIWUQctGdabSTw4UDlA8MqRjK49mb3b/mnYvKQmQAjvm+UoNlRpj8dIy3Ujc5ep
         TeaOeR1H0gj66sCR01L4EFDjQ1Si9Z9cuxiM91JOOy4TtJpdAbpcku1m3L3P8pA0RkfP
         03yDGN8jonQvGPd+fF8cYa/JJ6fAHKM5TPnRjo+wL6sfbutwMFAj6SjycSZpTNj2eG68
         TxKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=2aVtAG23JP7Pqa/JdV8KisQJPFJzq1v9kSm/HvkVNSY=;
        b=eK9aeF8uswG03YR2mzWhmp9U8N4BwR39hAR2q2lviBdyqa3bcfJV+EuOyE8TBP9McD
         VqaipfsFtZaBLjYh7/LsSchnTiToGdDRPznCSF0/82u2DqadZTJNhPAlFm5vu5T3FW6q
         Yx6n1yjYs9q8MxXopTPmx0ykPCyuTS8QHdXTbxsKO0UBxioDDLDxblra++X9HSLlle1N
         l0AvVQ6XmfnXA3/TfF6rU58i33VAt6bH9C8HCZ6+zME/wOSEYllhRLV6QW3mikMNF/ba
         +doH82s5ZB9dJGBOEY5c+YUBcA/54jDpASN+DVkuZpnuS2Ulz7eNLfjeoLKkvF1GhX7x
         Foeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aOl3f4kY;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2aVtAG23JP7Pqa/JdV8KisQJPFJzq1v9kSm/HvkVNSY=;
        b=Ro1Epa1TsJHW5TihmQ9WsQaoyslk4OZ13N+z7CwZQJLDnEoJXFN7dibZ/RfDCNFpjS
         SxwkUrc6r4cC6Nq6k7KYD97eQHV5eeKuQr0ZfxyJekk7HGT/zUWTUUxCH9B65v590lU3
         aMfNEwTxC7roGq8KTnvkef0LjTglkokryXDF7eEpQ1AQRAcZ7/Vx7kvij0BFLzkV/4Nq
         2iLqEPstWMQV1Fdnn11HizYzKhME1RZwmwSMWcka+MkT0/E4rC81NXQ5YCs8AZh2ERa8
         +nS0hbQoF/sBe/T8UFzUxHpjHS4gZgKVOGRb3XWq18DTfpKmPGzXReIZ3uhYVpJ9R7Ra
         98lA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2aVtAG23JP7Pqa/JdV8KisQJPFJzq1v9kSm/HvkVNSY=;
        b=iCMahk7yqp358SbHfPjCvhOs3Z16FBsu6Zaf2oWXfgT821LnpMykwiSfn7El5Y/9aq
         U8plbUVxvEWGY6Xgwq4uSBAb3Lgo3qxDJb7hkoo9RM9wmKuDtZJu1/AjyWHoqMSYf74+
         UZHzNWKyLqPg+K/GsIr++pKolBc+q1Iez/oIEXWoz5XDrFeBmL4U+toejEa+kNA5LKBl
         WZfsMqwyhFmcoqJn0yPlIw5t5mEHv8iSZc85xaNKBKUlk6a0sN1+uEQuhFNaN36mlFJh
         2HPWcdrSU7P3agobcUYLar9NJeLCAB94D/IXzDqsjUI0DSZPDXXv6X+/fFVicgq/fkGV
         ODAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2aVtAG23JP7Pqa/JdV8KisQJPFJzq1v9kSm/HvkVNSY=;
        b=Cmnr7oxEgKaT54InWoWiPZvkGFA3NW7C9yqbVVNpG7F7IC3huiMI1vlqU7fReVrXq1
         BAG5psIXEquYzSgHW7tQGGIsN/63loZ/GG3oR5ax9skUasPeRCmYBEpYjxt8OuGk0a8N
         yqiimY2BBsqLCMOITTmS0aP3vhWLlyy2ocXw9iF5/05kfgafPZurZSlAwkwSnJtISd4A
         iIacLObojsoryRwhJyzPLcxGidYLn2vvy5gWTbET849jiqkjGZKI1lIzTrQ0LkWTDBB2
         9Zy75J8M1+PFTuPFMdkiYMoTdEFo5N7Qu+sy2U4YMRnUHCSo8R2obJBaUN3U19+3SNp+
         QQNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+P0LXSt33u9qejcmYnqcqYwT/Xlr5jK6w8/n/1LIlOD+uCbeA
	7zVYe3UymtDonTJmBOTSTtQ=
X-Google-Smtp-Source: ABdhPJx+gEL8CJ1hdgb3kQIEUzjgiSBv3viNSNnoXB2/5+hshQ825J1orCLDaNDaECpR5tdL/0AVGg==
X-Received: by 2002:a25:7c42:: with SMTP id x63mr35605385ybc.225.1634125705876;
        Wed, 13 Oct 2021 04:48:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9904:: with SMTP id z4ls1315812ybn.5.gmail; Wed, 13 Oct
 2021 04:48:25 -0700 (PDT)
X-Received: by 2002:a25:dac5:: with SMTP id n188mr25102780ybf.85.1634125705352;
        Wed, 13 Oct 2021 04:48:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634125705; cv=none;
        d=google.com; s=arc-20160816;
        b=nlG69an+z/Z05po7CM74bV2iW77MVZ6PtO0B3L4hY0lC4tdZG8RigHMlPjNbI62Zfi
         o0kmOT9w+V6ofqtgvj4SANO2ddXNdGHYLq7/F1Qgb1GcQ5xOM5CxYnhc9VRirTIbW80q
         5t1Xqm1UUusr7gtBHOXJJ3Iuyh/ZvoRLELCQ5XtsWixK65re/y7D7Oc5kElvUwNVXpoI
         yeZdmXQW15+fufmjU9NY4tHuScsyYcpZf8b4tq8UJ/LgZ2ikUDlL/318XpslTcM39ZgR
         +AfH5TTugoFDB7QQlhQS+rO0gqlUv5bVo4f+gm4bIjdmklMAIEvqTjIj2eiKp/6c0mDj
         83QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ELh1ETW2BQMRKmMeuZ20a3+0xvnisIhgucjoSJxtDIw=;
        b=kMGe33epxN3BXJXZBXd4skTGfKNEtjTOp7DyTEzJRCxf7eF7GNiEFBmkKwVnW153jy
         5CG5YSI0IXnhSy0UaDFKKw7Jpdppu712pNlJktmh0NTsnTZajfFL8FeTC99V50uk+rKz
         qHOT0Gc2Zn4nZSMobhdm+2DB6QecotZ3av5tzo5rnYvJ8SrEJ4PpxNWoDqEcCXv63YBJ
         9omvboJQGZ5+jmE5xtuu6a8pDtrQ8KGSLZmt4oZcjZTLHoMxHxFxyA6BYcfcoI0oOrI2
         lTaJe/Q7sWlRJ5ksl4YGnHHDQ2rrzEpARzy27AQE1eb4OrZP9DnuB3l4Um/HlFYnp3JI
         bnLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aOl3f4kY;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id k1si1043863ybp.1.2021.10.13.04.48.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Oct 2021 04:48:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id d11so2368429ilc.8
        for <kasan-dev@googlegroups.com>; Wed, 13 Oct 2021 04:48:25 -0700 (PDT)
X-Received: by 2002:a05:6e02:1688:: with SMTP id f8mr28645833ila.72.1634125704955;
 Wed, 13 Oct 2021 04:48:24 -0700 (PDT)
MIME-Version: 1.0
References: <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net> <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008005958.0000125d@garyguo.net> <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
 <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
 <20211009235906.GY880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72mj9x7a4mfzJo+pY8HOXAshqfhyEJMjs7F+qS-rJaaCeA@mail.gmail.com>
 <20211011190104.GI880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211011190104.GI880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 13 Oct 2021 13:48:13 +0200
Message-ID: <CANiq72ny0RCnO1+E_wBgx0C6NCaMfv82rvkLVuwmW8Y+7Kii0Q@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=aOl3f4kY;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Mon, Oct 11, 2021 at 9:01 PM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> The main issue I was calling out was not justifying Rust, but rather
> making sure that the exact same build could be reproduced a decade later.

Yes, but that is quite trivial compared to other issues I was
mentioning like adapting and requalifying a testing tool. For
instance, if you already had a team maintaining the configuration
management (i.e. the versions etc.), adding one more tool is not a big
deal.

> There are things that concurrent software would like to do that are
> made quite inconvenient due to large numbers of existing optimizations
> in the various compiler backends.  Yes, we have workarounds.  But I
> do not see how Rust is going to help with these inconveniences.

Sure, but C UB is unrelated to Rust UB. Thus, if you think it would be
valuable to be able to express particular algorithms in unsafe Rust,
then I would contact the Rust teams to let them know your needs --
perhaps we end up with something way better than C for that use case!

In any case, Rust does not necessarily need to help there. What is
important is whether Rust helps writing the majority of the kernel
code. If we need to call into C or use inline assembly for certain
bits -- so be it.

> But to be fair, much again depends on exactly where Rust is to be applied
> in the kernel.  If a given Linux-kernel feature is not used where Rust
> needs to be applied, then there is no need to solve the corresponding
> issues.

Exactly.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72ny0RCnO1%2BE_wBgx0C6NCaMfv82rvkLVuwmW8Y%2B7Kii0Q%40mail.gmail.com.
