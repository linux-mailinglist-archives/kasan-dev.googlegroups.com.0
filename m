Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSXDWXDAMGQEFS56N7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 236BBB8A2F2
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 17:08:13 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-42486b1d287sf11249905ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 08:08:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758294475; cv=pass;
        d=google.com; s=arc-20240605;
        b=IIDCblNivhUGlvgF98sXUhYVh7V3LGBaN2sfBB+T7v17wWIsaqFmyMjSzreHGGU5eu
         quDqKWmB7HxwsPJXXS2nOu9rKTpF5UYH4G35XXJUDFBn6L0MhSFvgH8j6uWI5YeUNWFE
         LcTRhbzz3nJIFWHADg+zOS8iT5n2tyAZYq+6GftYAigJ3GNQQRnvjtl8cytcAOfuFGlW
         2g9ALSZGLb8rPNjxhP2c7yLvEq9ExrwanU2Q+bupztuOFgvDmde1KBsubsiNc7NmCCgt
         42+UEaNrjaN3jfR4ajWvn42Fliw/nBrrlYSr/l+9kpXmY6/muCb5igJNV83ErIHKsifm
         TBAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oa/e3tM6RfUp035xbo5JCpYmublyb5JmVEIdhkhMwMw=;
        fh=AF0wErJ9VEGWVm3ZjHY96YP/xA/HXIArEZ6k014tkws=;
        b=hsH7SWgWd7EfKHspwmM8MmRMOrnG5I3aehM8Yb/HiT0t7Xb/hqCaHqfyvhrsfSPinv
         ska6g/V1lU2znthtXck9+7V+pjodH+a2dTynhTDmwpIEh25bKIOouiMmvL2NUVDU6AQr
         QdXGQUz9u3C1wOO48dy0/OYD70aLRfxctofKCaf48taAGdvByjLnDJaVCURwvw1j72tm
         RMl2rdFkllzKQIL8SOQWsi42RpOzMMA7HtBmq0dvihY5Rp0bvZ50nxxO4T8NJMJ3dkQj
         L6Yok5nHWW29Gn1W1bw2Ax7kTarMYX9KSSNm/ptzneVCoLJhdDgHLrCwejtnAIfN7ewZ
         fOtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="CQr/fjMB";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758294475; x=1758899275; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oa/e3tM6RfUp035xbo5JCpYmublyb5JmVEIdhkhMwMw=;
        b=DeF2M0s5V9/lfgkqbVMAzCdbCmXNF9lOhSWrahTnMYrHr5kKwojs4SkKDfuDcSu0ov
         uL6ZkZJEH8pS0KoXu2CRl48hD/X2q0HsnTmqOsQuJx35LzPuD9TTCClUVtBZSqP3eAxC
         pJMckE2BePYT2e1KABn/DAkcNnZA91UqciB5vcLLi9JLlv+o/x6wH4RHq4gGOaMIhBsO
         0+WUEy0UrJhdlf00CmVrR0nkcuTDSaFKn6DZ6ydbILlQ+pdgzGCuEUft3Uf1ELfalLLX
         xwTEIcJwuc2c56PIBHIHzZOuWPjisi+puXHENV8j9YufqCy/qpVXOj0z5Ar8wFkG6R0F
         EuYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758294475; x=1758899275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oa/e3tM6RfUp035xbo5JCpYmublyb5JmVEIdhkhMwMw=;
        b=dWc5KguHcjKTkDoA4JLObnc46odEUQz3rZrN2ExBaU88+0OIzX6pmW8/GX0/18aqzv
         2Bu9q9UkcDEHRtkzmX38Tv7vm0gSiucfhyIOB8em8wyBAOhainSahjxv8USGJaGVsMU6
         R5dnoJQhYWhhNU7YdTH94kRb0NgF98fL3oLkFD7WrUei9pwNaiDisMDFcaNBawE/Zu4k
         TL1rGvxDReFXQpvsTBD01TdvQQPnMTyntw/c2j7OwA6TZ2Djp3/lLVE/FaJaqPSssphk
         bPOtXmz3aCRNYFTO/nr6ls6QiWez3Ue2bxG+JBJqsXqQLjnd/58bSOoW1z9B7ULzdBSH
         njRA==
X-Forwarded-Encrypted: i=2; AJvYcCW52AVi3SHN4YMtYZ9+gB0TXXZHgCKfClwg/H5uO0WRbUKYfx9BH2MLWKubox6TwSP3PIM6OQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy9CS61jUtYJ+5s7ErjF3fpPoCdhxb111GukqSVHPwruDdqTava
	8RBnFT2GeEEmfGhTHA6B5XMKwuYd282H+w7TFarYIeROBPftkKSnnCUL
X-Google-Smtp-Source: AGHT+IFiZvAa38OwNLFGscDFEizHeL8JqhUC4biw5rdOV5V59EkHmG8UPdwq+ef4XGyavz4u+fFcow==
X-Received: by 2002:a05:6e02:12e7:b0:411:7b83:c9f2 with SMTP id e9e14a558f8ab-4248196892dmr54406605ab.17.1758294475191;
        Fri, 19 Sep 2025 08:07:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7RQOMGnW8663OQG3FwledWi6pQ6X7CH6ahepJZY6UjRw==
Received: by 2002:a05:6e02:1251:b0:424:1d26:fe7c with SMTP id
 e9e14a558f8ab-4244da32582ls17128475ab.1.-pod-prod-02-us; Fri, 19 Sep 2025
 08:07:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXwDswOlL5dN3c4mDRq+/jhnzIvDsn4Jlt3tVbIJ6scs77iHAQgnHCmxPO9Mdnh/FuaT0y09JMAc5U=@googlegroups.com
X-Received: by 2002:a05:6e02:1685:b0:424:7633:9e72 with SMTP id e9e14a558f8ab-424819919e9mr53848285ab.30.1758294472763;
        Fri, 19 Sep 2025 08:07:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758294472; cv=none;
        d=google.com; s=arc-20240605;
        b=DHZtAA7kJG7Yu2/4DkSfCIJ4F/sz5JsMW6ckh/wqwbDUVF1K5K0/DhJ6bd6iT2dlOy
         IOpzXsUbFxarenWtOCSFGpwjyyZGoYOr6Hxo072FuWOe9+x4ywpujVPu92ysAreXfAZH
         D5MYJbh8jVEfqQDM2+l1Dh/RXNHbIOneQzKeOeqWDM1sLRz2kfyAeucWxAgz65HLtKfK
         IxBGDSChSfS34gITHUVA6On9dJQySMisMeXBuvDjTYc0BXe4F7wBMk1SANYNrhdhAP6L
         F2SHbu+IDs8ZE0dBtqAuA0q3DCEJcBA82sjKanap9AP7kbFwXSBw9Ruy1ZHQ/GpGRVwR
         Gxcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ls0ueed/BxHP3QtDBUTzflUrtNvfsIQ0artI+JKf/HI=;
        fh=Muz1JHXxD7CwqQGGw1w2cNfco6va2XWc6TMJdHyWYjY=;
        b=Ba2fQckGme/phzazsSsc3JpW3d6oOEUl318hzAl8aQhVFrbV2bft4IKpmN3xXH9Icf
         dsTnsbwcz7FX5RoXXz1tQAFID/E5fUDPXQtwZVmtdk0hhb+CirtAqSn+lJC0ZFGFJNSs
         MyR/UJurMvuCHCi3CZlqv2TNsUt6QNdguzWGFnj1Su6PRxVjqrzTI5DE7geXj6j8dkVa
         57pxtEOjyMPByOawJ4mqrui0DmHcAv1alOEZ9NLphntSFE4S/g3tX46droBxBvzerGv2
         +ROMPjXsRxroQwIYHNmySSBB8+940b0EsbKWnOR/EIkHvZPtgC9lJcGxOp1ZBQSyvGcS
         O10g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="CQr/fjMB";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-53d37e62d63si261340173.2.2025.09.19.08.07.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 08:07:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-79390b83c7dso18488086d6.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 08:07:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWhSHjana/67KDs11Ymq78e6ha+cBXJvwR6fad7mbq8Q0JQBeJw/GFn/ffCxLsxCu03t74t4ITM4Y=@googlegroups.com
X-Gm-Gg: ASbGnct5h4L1JD4CXBS6ZSEfmVD5/MB5xosusm98Wfukqc1ugzhqXeI6JqrdvNalXQr
	bdJVfg5V8cJOS0rxjxMfILuYcXZvH4K6HBMb3pM6OCFLybjEr3e+9OpBrGbQGEKxxS4tK1fjGf7
	hSC761J0PfqHdRso3JVBnGWq3ghbf6avH+fa7h/uYVnFJXfukjLoHhOSaKsaWLhKSPOovWPgGCC
	wr8RBtiDrIuduY9/iJ6fIY/K1X+qWLG0x4f/A==
X-Received: by 2002:a05:6214:260a:b0:780:24d7:fd35 with SMTP id
 6a1803df08f44-7991b0db9bfmr38784486d6.43.1758294471475; Fri, 19 Sep 2025
 08:07:51 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> <20250919145750.3448393-9-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250919145750.3448393-9-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Sep 2025 17:07:14 +0200
X-Gm-Features: AS18NWCM6kR1_nk7adaxFawciRK7byb-Gyk4MeMsfOVVpcb45qo2C2pvMXupxjs
Message-ID: <CAG_fn=Xvkz_-UGuR8_4Jb_9HmwQn7dTHdJuDRe6usZX61CF0xw@mail.gmail.com>
Subject: Re: [PATCH v2 08/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="CQr/fjMB";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Sep 19, 2025 at 4:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add a KFuzzTest fuzzer for the parse_xy() function, located in a new
> file under /drivers/auxdisplay/tests.
>
> To validate the correctness and effectiveness of this KFuzzTest target,
> a bug was injected into parse_xy() like so:
>
> drivers/auxdisplay/charlcd.c:179
> - s =3D p;
> + s =3D p + 1;
>
> Although a simple off-by-one bug, it requires a specific input sequence
> in order to trigger it, thus demonstrating the power of pairing
> KFuzzTest with a coverage-guided fuzzer like syzkaller.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXvkz_-UGuR8_4Jb_9HmwQn7dTHdJuDRe6usZX61CF0xw%40mail.gmail.com.
