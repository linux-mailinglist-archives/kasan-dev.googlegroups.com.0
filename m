Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLMY3H3AKGQEHTTBKFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 58F021EBC21
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 14:55:10 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id m22sf4100250ejn.4
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 05:55:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591102510; cv=pass;
        d=google.com; s=arc-20160816;
        b=G8PseYej+jndEo8w/1GO03AVqlxVMBssSRK6+4Qvz8r/xD3cV/PthLQSWuK9aJ2LSW
         usAzz8hIffiZrkzI3VNMrXpvfkMz0nentxAoBVo8/vuhQNmFBUmu6D2hbrdgygh1amdo
         GMyw77/DjrBOopwpYoy9D4KZZhAXjdWwDZ/VtbK7lmN4hIoPep6JoaeUXM6q092Ufq1T
         LGIMvlQiUIXny963V2CfAQZjLo/ysApHk3x5Empq1cAO56qQqD+gyHdjMKd6LzCtVauN
         +n59erR8H6zwHYhc/X1AM62avjCqM/cACRfOt8vzPfle1eZRfFc7tndBTxeY09UR+AyW
         U2Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aiN8zo45FO6YiYVtaMYbebC55UjryR8idMFrkiGXEcA=;
        b=Ff+pJpfQu4sXoIaVH5FVhESwZTPZ+C4rmVN1FJAWSRJI+8l/mdypTXbcrXB5/7BFSE
         sIGUscS2opJS3iLvdyDZUD0YDzLJ0wAhdZFxfx/6BzIZqt9xpk5Y4XiZ7UrhYY08yfrQ
         har1rGPf5n8/CLadkumSZHfJVX/uajkyNrl29BV//Y7voLv4FnDc3bDX7as5wybbhQdD
         SpshIaOn2DIWPKpjrLxxi0jUYhKxshp85nWL13rWwXGwlIQCBe55DQQXm090izZs5HXi
         8XAFKCLbE/qLlbOz2fLKIvwq/xLcrVtzmQRbH5IA4VxmQzmK6JMLskZgNJQN5PdzVKBY
         8hGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YfhA6U7o;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aiN8zo45FO6YiYVtaMYbebC55UjryR8idMFrkiGXEcA=;
        b=LxeDiufUol14M6uliNLujd/3okTdQaZhCUYiyJGXMqGi+BAz79eOxo2hKvqYUzWSiR
         e4rbBzUS+G0R/ZALV2xdcAE30KsTxB1IPFDH4uKKmPR8JH0bTkx84dl2v4hedKj7A1B1
         iUqhX28K3pV1FRUszCNSg6m6AnUTHJQSlilGoCcuqOK9Wzeh0RxGSkgd6crHUwsyR5cj
         DIbuG7Vx8NksrbXEBRsaAX04KXY7j41wkkWe4kj22Udj9IgaGxJ+acFN7+8MplNo9R2y
         QbEOYd7+qc/bvoKrjEjqmAEzkvANrBxFFFEA9tOscGjNIVv3PWfCmqy15Pn00JM2Roez
         kpUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aiN8zo45FO6YiYVtaMYbebC55UjryR8idMFrkiGXEcA=;
        b=mERNC7GNE1SmapS4RZusMeiaSTr+PqkD3YUxqvrVToELIRmx0Zb8VsGqO8FDBDMFNH
         TIUGAacudTMRyD7wyiICoIMjTG3aE2fd6FO6vuJ8v3tnnjICYCUyirklQQltaPudK868
         eix0sNjxbhwmS5Obax+3RkxCbN8xPTAbrYOSSXpbbMKUywwO2dIgYsaRT9FfoxF38D+9
         fsi0B7eZpdTC+1httObgZ3prEV1F35unsD5x8c80s5PwzQ+wXthZjZHHbzNy/VDehkvO
         Fo6/RJlkljtpFbKeHAiiDd3GBXUhWUHdlV+et6r5lEftbDjdrajC/Mlnk9lFv+WY9mp3
         hYDQ==
X-Gm-Message-State: AOAM531mMO0QfRW33zfEfvS2jRg0q0Oz67J15eehnNGUzXZ+rfMPt2EK
	ZdMlK9/TCA2C+UoTF2xEdTo=
X-Google-Smtp-Source: ABdhPJx8me8VdR91xff/ICf5mdHlavw+sN3ZXCR0fJjd4qumUJAem90uAjBY43YIYNGNQS7kvSJ/+w==
X-Received: by 2002:a50:f18f:: with SMTP id x15mr26947162edl.228.1591102510046;
        Tue, 02 Jun 2020 05:55:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d987:: with SMTP id u7ls1317020eds.3.gmail; Tue, 02 Jun
 2020 05:55:09 -0700 (PDT)
X-Received: by 2002:aa7:c143:: with SMTP id r3mr26977502edp.203.1591102509589;
        Tue, 02 Jun 2020 05:55:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591102509; cv=none;
        d=google.com; s=arc-20160816;
        b=rrBv9SXnWcBIoyIt1s3rOv4POMq924EGbV8cFobzrkPvuFxwWT7HvTJ6/FLcxrgMYU
         tDFVVrxd6nsee+C1zEqDeKK4F6nHp/QFZXDugs/xsAXIMUn8R/LGWZoYRVwXXcGOIcK2
         3tA6+h6xLtjnqAb/yptBJ2oVJcYmFOPqOOChtiaWqVf5dyogmNeHs+NFGKKF9YkGjT/e
         9ZNQNige9G3xy7bSX7zIsl+LIJPSGs8xDHCatruFJm58ThFPrB40nqb4e8U/77L+/RHy
         0Z6/1zF0Besjs4n1/VVs8xFwsH/9dErsmLxYKkTNpp6BbJxRBVZf7rmuqi3llLMMo/EE
         axHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YGemWGVRP1eDt5QSiA4SBjB1hSXWBpdxyq7Ig5+zrSY=;
        b=DjcArb1cGr/j3pFvjbOOnn30e+9qX/9EPOo6zDvNmtWoSFM0PkT7cQrXa7AbDEX3lc
         WjMaZ5/5LZivRl9U6UKmieJQosQ2rrL9/Cavp16UCQphgCzp/fkp/1eqVIz3ShE/pIu9
         NxF8jxiyk6VRWINOPGurWm7vXLuY4pkx9+DbDgr3ibvcM+6SeZocII4kVSpjdmtOdACL
         uao8j6LDd5RlbyzTl4XORC427xt57Gr/KCJr/v3FUPpHvMRgTPQwgT5G+iCb52Ydhmv4
         foiARLOZfwtIKZLGZLzFQ2Shn4T7/Vml9odXMCQ3gzhIcwn7Csxi+Wvz/U5VJrl8giMU
         UaNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YfhA6U7o;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id fx6si153233ejb.0.2020.06.02.05.55.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 05:55:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id q11so3322510wrp.3
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 05:55:09 -0700 (PDT)
X-Received: by 2002:adf:9b9e:: with SMTP id d30mr27048389wrc.345.1591102509101;
 Tue, 02 Jun 2020 05:55:09 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
 <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
 <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
 <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com>
 <CA+dZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA@mail.gmail.com>
 <CACRpkdY9pbM--gBU2F_3Q=AdB1Fsx4vHzc5O-3Fq0M105SQWLg@mail.gmail.com> <CA+dZkann4Z1TavtJ+iq9oBrAiAaohZfke8aoyhcqvs_CYSuirA@mail.gmail.com>
In-Reply-To: <CA+dZkann4Z1TavtJ+iq9oBrAiAaohZfke8aoyhcqvs_CYSuirA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 14:54:57 +0200
Message-ID: <CAG_fn=XjmgyxDANUN0a8kY2CuucQ2gHFfQqsk6TF_XpiqWGCgw@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YfhA6U7o;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::429 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Jun 1, 2020 at 10:18 PM Raju Sana <venkat.rajuece@gmail.com> wrote:
>
> Thank you Walleij.
>
> I tried booting form 0x50000000,  but  hit the same issue.
> I tried disabling instrumentation by passing KASAN_SANITIZE :=3Dn  @ arch=
/arm/Makefile , but still no luck.

This only disables instrumentation for files in arch/arm, which might
be not enough.
Try removing the -fsanitize=3Dkernel-address flag from scripts/Makefile.kas=
an

> Thanks,
> Venkat Sana.
>
> On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <linus.walleij@linaro.org> w=
rote:
>>
>> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.com> wrot=
e:
>>
>>> And I am  loading image @ 0x44000000 in DDR and boot  using  "bootm   0=
x44000000"
>>
>>
>> Hm... can you try loading it at 0x50000000 and see what happens?
>>
>> We had issues with non-aligned physical base.
>>
>> Yours,
>> Linus Walleij
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs_CYSuirA%40mail.=
gmail.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXjmgyxDANUN0a8kY2CuucQ2gHFfQqsk6TF_XpiqWGCgw%40mail.gmai=
l.com.
