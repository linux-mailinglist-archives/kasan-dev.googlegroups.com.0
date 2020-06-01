Return-Path: <kasan-dev+bncBCFLDU5RYAIRB7WE2X3AKGQEVAR7ZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 92BCA1EB014
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 22:18:06 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id k12sf2576810lfg.7
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jun 2020 13:18:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591042686; cv=pass;
        d=google.com; s=arc-20160816;
        b=qw6/3J4WzViAnjuJ6CW3Pj84Mh3uXiItpmUush2wNQyEkGXzpU759z/jtpYHfE/CCa
         hN6sUkUhVxXk5pqhdN2e+3iUyNdAQ2LZqgKrGkiQ5baJoryWqCxsd8ELoAjA9ndD+BBB
         1RjzBq2bqUkxRLM4MWIXgb1KUP1Yjz7rQAzEEYYEv/UjcYTAJXt+bJDSttJ8AZzB2+jI
         LV1058Pe77Uz5OiK0N2PrxFjrdQ7xFqRd/M8kHgA4vIv/tZn67b6k7mzcnboZw+FONuk
         OG9SPH3sxSykgFUnSh3U3E2tA98ZSh1lcacuI5d+kenQaYJySw+RUxJIqm04PKAk7G2g
         jztA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=059elHasokKMO0Z4DUmt9pCdqOJ2MW/9c5haX5eDfpM=;
        b=ldt/QsUnHCF6DpEa6D6wd5s778iONxbuWqiAVyS5CIGpw/E9Bi4eCUAGi1PD5WTRnJ
         zb44LBEVRTVvEQbDGMmmYuCgtkWYg/sBxobfhdLsrkI89AtoxSmZ92udhLs1OxYc6ckX
         xyAa8fR1lJw/u8jQVsK6qJKvXDMMhN3G6IH+lyykjWGyDr8ST3iC22Lt6TL6XAz9XCfb
         +hN6I62pLnjwdyisyXraFU4xJMquDf+CU9pRyGQHREETzjzH/NcDMr1cQe17I+NZPvBH
         2Q6gHI9KZT1BSDOhId5K00bYSt0RZiYqD4WKj/MetA/v6QUlE6ZFgEwQvibrmGPjf+M/
         BZhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="b/udcz/1";
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=059elHasokKMO0Z4DUmt9pCdqOJ2MW/9c5haX5eDfpM=;
        b=YvDjsetNdODkSF5HqmbvSX4hAoFHJqBxyABttua4NM8zZj79z8G1Y9h3+n0UtEMwhd
         MUlH/gqN0igsnSW9dSkm2JE8rBdxNrkmzQeAzwVSe0vLGUqI0ocNjPW4EJCHbXYrlwPo
         oXXB1DWh/FV/0N168e5k5EvXni86cQjo7zmjbOy+/nKXmT0SIWDd1sZkVXXG827PmmNY
         kVweDdgIZYfNmbEWOrxt4hQ1KKq4N18pFLVP/iKiEPIUu7M81pRnex2m1UoYZGyGh+Z8
         cuTsGA3DRe4hwp27aw89cjJ4zJwRxN6jH7ZXxISDHQ/6OP4ZaQVJwbcV6a9FkK+dIZ0l
         8yWA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=059elHasokKMO0Z4DUmt9pCdqOJ2MW/9c5haX5eDfpM=;
        b=QgxM135D1WdycgtqMy5qSKIrYJuBwK9GDfuDETX4R+RI2+E09D1wpcdC6usRWl92Hu
         l5ZrAi8muTfuJp8ChvzhXoZQAPB1UZvuIt5g6dnNll0BQtpFXKRlks4o6EvhnKs9GL6Z
         BF7BTwUmfDpV8SkFxbyF19wDYLhqO50BnGKEyWjCmtGionOgcPOoiL17yNYVv3YXyW3b
         meXfDidt2cdsdtwRf0jxd+TF3Ulnzl3BE4c+d0P9x1uIxtwBdlbpykHNuFSIwjKrq1B8
         Jap+3n9IYjkmcxOa/WJmECzZqLTttbm8nY7/VfhN0WjY0FmK3FmfU0cp6PqgH2vNcfW5
         gDsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=059elHasokKMO0Z4DUmt9pCdqOJ2MW/9c5haX5eDfpM=;
        b=aODRtyyp/aqklFpo4SXktc47VBBPCns1QEC1incsEJ4q1FpaqqWsDRlijDwkM0+lQK
         yNlCuVmP9XOHe8BXZveRanbprybX9HI8nT8K3wWUDOZUAmJUgWZdVmNJpmnBWTCSxcU8
         QtO/nUpgrL5zp8QKpEd+0W76Lkex0zjgi8wM+Ut9D8sJJspUKwxF52PwIFmHCeerJp0a
         zMP9NS2zNUErXBlPvQV01fQRvD7K4vWXlsx71/w5JEiRS50+uMx1hr1jSzakcg8xXoWY
         rHrxFteFR3QRlrw4j5vgCX5PmOq77gSaGjZEde7w6qIehA3pu335KgzPNvX81yPew9Pz
         QQVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532srFoK5OD2NOk3v7XAwed0bHJ3E4x+2ad5Y3hPYgiINEgB9Atz
	xMaVH0sZRUvtLB4iEkDQfDg=
X-Google-Smtp-Source: ABdhPJyoFyfC1gafNIH6upXUXBYvDk77ovCeyHc2YR87If42DeNZS68jRGPCw/6e6+GRD2hFVJlZkw==
X-Received: by 2002:a2e:998c:: with SMTP id w12mr11935799lji.143.1591042686068;
        Mon, 01 Jun 2020 13:18:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:89d8:: with SMTP id c24ls699233ljk.2.gmail; Mon, 01 Jun
 2020 13:18:05 -0700 (PDT)
X-Received: by 2002:a2e:a49b:: with SMTP id h27mr3282535lji.395.1591042685338;
        Mon, 01 Jun 2020 13:18:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591042685; cv=none;
        d=google.com; s=arc-20160816;
        b=pei9vzerjMFniUdA/8SKar/w65K0czuFHTGoETSA1/H+CaOvvBaYby14BgL4ephJRe
         t6Za1YfzS21ZPLlZ+BFEc72928CI0+bVmY+OXAHgiikzUbn2UnE3/Q37+sSxcI9pyMhK
         jeFmYicBKKWDG9X90/F0w4wtpGR+m3DNl8OJLGFtiJ3VLHaWOGAmommQHsBAF7905WXu
         UxcJwkDD12+PBX0kqd7lFfVL7EGl62sTVGnS5ujCt8/cBU5B30M0zVvSM8Ii5hY5HQDS
         13hAGkwE99+uvnVp+uxrNDXpCo0DC+jp6K9b9JSTtBxNrSj8HTO5hqMYcgTVOs+SgRaS
         kA/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+QPbMq00dH71C8KGlDohLVZ3DubJbOrZEv5/F8VgKo8=;
        b=ZeGUaiMdsTeTvlBSswAoKqU6Vi1mH5dtzJ70SVP+ijrF7kJf2uPuf9SC/bvzwohBQE
         m20MmDn0F+6VA/xUdpVnSiCtNiDYzs1OzDsgopUUn+V51leqj3UoZZj5RRI/t+1AvYJ/
         OXNdSymGcx/+Jz45FJE6cZQQL7FQqmOl3R+pcaCiLxMUdBut0CDogMnpSBclOFlQo0RC
         9s1XjJxchMlx75WAnmGhooXSoHYKnyUjz6Uvv5vrnMJB8ienOlV08ZPFRE+InaMnfRgT
         w/qHXQV1U6gk+EHZjp9h2US9F3da5q9wfi82gRDldySOZ7Zd5BYCpmP9UEecQwtvhlAT
         7p2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="b/udcz/1";
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id o10si17327ljp.3.2020.06.01.13.18.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Jun 2020 13:18:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id e4so9800500ljn.4
        for <kasan-dev@googlegroups.com>; Mon, 01 Jun 2020 13:18:05 -0700 (PDT)
X-Received: by 2002:a2e:a284:: with SMTP id k4mr6968735lja.234.1591042684989;
 Mon, 01 Jun 2020 13:18:04 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
 <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
 <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
 <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com>
 <CA+dZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA@mail.gmail.com> <CACRpkdY9pbM--gBU2F_3Q=AdB1Fsx4vHzc5O-3Fq0M105SQWLg@mail.gmail.com>
In-Reply-To: <CACRpkdY9pbM--gBU2F_3Q=AdB1Fsx4vHzc5O-3Fq0M105SQWLg@mail.gmail.com>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Mon, 1 Jun 2020 13:17:53 -0700
Message-ID: <CA+dZkann4Z1TavtJ+iq9oBrAiAaohZfke8aoyhcqvs_CYSuirA@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="0000000000000fb5f905a70b7e8c"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="b/udcz/1";       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
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

--0000000000000fb5f905a70b7e8c
Content-Type: text/plain; charset="UTF-8"

Thank you Walleij.

I tried booting form 0x50000000,  but  hit the same issue.
I tried disabling instrumentation by passing KASAN_SANITIZE :=n  @
arch/arm/Makefile , but still no luck.

Thanks,
Venkat Sana.

On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <linus.walleij@linaro.org>
wrote:

> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.com> wrote:
>
> And I am  loading image @ 0x44000000 in DDR and boot  using  "bootm
>> 0x44000000"
>>
>
> Hm... can you try loading it at 0x50000000 and see what happens?
>
> We had issues with non-aligned physical base.
>
> Yours,
> Linus Walleij
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs_CYSuirA%40mail.gmail.com.

--0000000000000fb5f905a70b7e8c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Thank you Walleij.<div><br></div><div>I tried booting form=
 0x50000000,=C2=A0 but=C2=A0=C2=A0hit the same issue.</div><div>I tried dis=
abling=C2=A0instrumentation=C2=A0by passing KASAN_SANITIZE :=3Dn=C2=A0=C2=
=A0@ arch/arm/Makefile , but still no luck.</div><div><br></div><div>Thanks=
,</div><div>Venkat Sana.</div></div><br><div class=3D"gmail_quote"><div dir=
=3D"ltr" class=3D"gmail_attr">On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij =
&lt;<a href=3D"mailto:linus.walleij@linaro.org" target=3D"_blank">linus.wal=
leij@linaro.org</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" s=
tyle=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);pad=
ding-left:1ex"><div dir=3D"ltr"><div dir=3D"ltr"><div class=3D"gmail_defaul=
t" style=3D"font-family:&quot;courier new&quot;,monospace"><span style=3D"f=
ont-family:Arial,Helvetica,sans-serif">On Mon, Jun 1, 2020 at 1:07 AM Raju =
Sana &lt;<a href=3D"mailto:venkat.rajuece@gmail.com" target=3D"_blank">venk=
at.rajuece@gmail.com</a>&gt; wrote:</span><br></div><div class=3D"gmail_def=
ault" style=3D"font-family:&quot;courier new&quot;,monospace"><span style=
=3D"font-family:Arial,Helvetica,sans-serif"><br></span></div></div><div cla=
ss=3D"gmail_quote"><blockquote class=3D"gmail_quote" style=3D"margin:0px 0p=
x 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex"><div d=
ir=3D"ltr">And I am=C2=A0 loading image=C2=A0@ 0x44000000 in DDR and boot=
=C2=A0 using=C2=A0 &quot;bootm=C2=A0=C2=A0

0x44000000&quot;</div></blockquote><div><br></div><div class=3D"gmail_defau=
lt" style=3D"font-family:&quot;courier new&quot;,monospace">Hm... can you t=
ry loading it at 0x50000000 and see what happens?</div><div class=3D"gmail_=
default" style=3D"font-family:&quot;courier new&quot;,monospace"><br></div>=
<div class=3D"gmail_default" style=3D"font-family:&quot;courier new&quot;,m=
onospace">We had issues with non-aligned physical base.</div><div class=3D"=
gmail_default" style=3D"font-family:&quot;courier new&quot;,monospace"><br>=
</div><div class=3D"gmail_default" style=3D"font-family:&quot;courier new&q=
uot;,monospace">Yours,</div><div class=3D"gmail_default" style=3D"font-fami=
ly:&quot;courier new&quot;,monospace">Linus Walleij</div></div></div>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs_CYSuir=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8aoyhcqvs=
_CYSuirA%40mail.gmail.com</a>.<br />

--0000000000000fb5f905a70b7e8c--
