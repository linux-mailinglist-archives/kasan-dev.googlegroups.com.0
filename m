Return-Path: <kasan-dev+bncBDNLRFNCBIIPNBG77QCRUBCKEFP2W@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FFF629A4D9
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:47:20 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id i129sf379650ybc.11
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 23:47:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603781239; cv=pass;
        d=google.com; s=arc-20160816;
        b=uKuRFwIdomN/Oc6sXeieKE6UJcETF25YGJ7hYfLit/0I0R2o69UYJSHddGt7xDNXlJ
         5xIgUdynB/9p10rV3PydnQk1W0DLy6axXi2QuWyGunx3xpDeYioMD3xv8kDLAMLLDAUN
         43pDMZRZc7/ZfMj/jgh92vBO/BNRBVRsZ7EEgr+bGl+SJZDKlxw1tQLBk1IcxvMjHB7G
         7LcKuX6yrlas1lcv/XqC7NIAxGc4pA9dTEzraRONQ2iEKycdLAUj94ujHr+LEUttewUU
         P+fIgMaghg66hYuLy4DW5A7s4SWjd3eYVkOe5DJAOxBGLxhvfbkYzyYGDXvUq6XgurWS
         sm6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=L2JTAkgZzKRo1nFiF0z4ZJCAzoLUblpCoEkdLujNxfs=;
        b=c/L1LLcHzOducdHyOrlIaO7nW897adhAJpoZ405yC4zcwCxuDhxiun/K7uDAf4AgD/
         eqzWGCe3ibwMMrslphl4ze7UMiMDTTtd4w2QPM2dvWQ5XamIpm+4MiwRKVTggZTcaBlp
         thSHn+lgoUqN9LE/bAhY3BZTKLTGzQUrIWhIzjqQFKaozSHy68b7TVuZiD1KhTFVf882
         X1KA0ahueM3N1ffA3r9+w/ZJYJWmkXIyb1DHdIKbiw4D4yUL3EOrIBHq9u6ZDkf5l/6w
         mQ3oJAcUYX5wSL2J8hw8i40euQ0QQ4zLUtDx6245CIqYf58KNCI8XsIgezMwonG7wwAR
         5TlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@udel.edu header.s=google-20200914 header.b=Ix1qnqoT;
       spf=pass (google.com: domain of zeyuchen@udel.edu designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=zeyuchen@udel.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2JTAkgZzKRo1nFiF0z4ZJCAzoLUblpCoEkdLujNxfs=;
        b=iPf4OdAlWzXUUY6+CWnQOCO+QPvhawjZmBnmKL+RJwxBtM/g+OZ/LrdydKZLHCLXd+
         nGAHomoInH8csuMNqMjBN4QeXueGgdJq82qPYAlBh+1TWVxNu4FmUjj/ti/zrYdvgUhe
         1TK6pGsr1QLUhKxyrFSuuFTcSjC89LBuP8TFUusg+m6wS2h/oLb8TizJF2igBdLoOKLs
         hrqz2eWDaoLdU9tTln4WPb835WykSvj25w9shRoCV4vOM2IPHtIKrYjAMln1SnP49a36
         Yc5rARU97J4h+w5gfvPJ+BA0YuJM+PMsB9rgvBwk4OUIvg4vC4I3/MphCMCkUpmmkTbC
         miMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2JTAkgZzKRo1nFiF0z4ZJCAzoLUblpCoEkdLujNxfs=;
        b=AzrQiQ0dlHqdAQLXhflfWolad7Cs8ExNaX0Xf+4CVfZv5m4hMsJPpy79gwoAjrm+ZA
         tOPNMDakTUab3wEeOmnHNwmlw7pMxeE6CiSijc6YmaElrbAYTgnuZ+klWj23XIsz6x5j
         iurp6IJhaHADRo7ALV84EpQDJbV6nqwneO5sImhuwA4zwV9cx8h0XKJy6WFsV6mvvoRx
         KupzCyGgHqnR/a6L5x/n51JXIxo6BnO6kyoJNzvRHY8ZNB342U/KUp5vvvxZZVtNrPRy
         OH6L28dyadx8vu2ooZU654yGBoOJc/fqnJhB7+LdnCQ8jHiRhUIpLwGabsns8ncrMCzb
         /X+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532bxACFgBeM4WRT/6LnTox5YgX9AJmKK9rfN8ZQPMukMqLpljmi
	A4FEVtP6HQhcFFqBjuOdc6U=
X-Google-Smtp-Source: ABdhPJxKQcUuwxiA/jrJ3FTyx+yFduryQcZtKUVXjO7B30ApHwmL0RGjDnWBZOVTsSVuo+SclmTrHA==
X-Received: by 2002:a25:705:: with SMTP id 5mr1137924ybh.239.1603781239095;
        Mon, 26 Oct 2020 23:47:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2689:: with SMTP id m131ls296729ybm.7.gmail; Mon, 26 Oct
 2020 23:47:18 -0700 (PDT)
X-Received: by 2002:a25:aa72:: with SMTP id s105mr1168051ybi.105.1603781238564;
        Mon, 26 Oct 2020 23:47:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603781238; cv=none;
        d=google.com; s=arc-20160816;
        b=eb6E48SHSQp+hSEjUGNF+1hb3Mh2vAb3VwSokASkVzsaqjLqaO28tuve7jH2wFlSJG
         zfqEvvKgY5SEvBKeI2mE4OgUQir18YtOW/vdUCaUtFyzsg1KltBEu/PHX6lKiXGpCPVQ
         pJDkf9SbdCPi57w6nlvJw/2VVsTKMCLAhnfo5XMVanCMV6mbFA2DnEZEcWX1zbejufxj
         V1vZA/myYtTdYVbus70vlpr4uDkRKD6U7ZWGkvFuonC7eeY9xAqsywIZ0UJisaW/+Gao
         X88xLQOFrkZv+ChbCCkBx9fkPE6473GYzPMaX1n48T9HSGpp2iQcx8lSDc//XXZB7f8G
         vXsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zRgtgYESrT7ccFKuDqqwoLTa+kz368AAngSCB8WeMpw=;
        b=r6AVGFms1cw8RkFWddz0qzbnAJm+5NUF64bwPLgl66RyV+o45dCRgMSvmESHTyyood
         zbZLvL9e1HAOZFaGFerJCM6JpelwflYc3fV2NbeX+jUm5OzP0gcH+y84PfhFqdFZ6poT
         ujFcOBDm2cxvDuOB3tFJAykPk1HocaOZEA/AG86oel4XKGUjzvijpLCba5sw+hjztQcD
         MqTIap40XW/Zt1HqetApq5FcWmVhsl7Qq50crw5adQRyF8LXTg7/YEKJ0og6vd6koVsz
         pYuWYkPR/McEjeqkWtyrDbplxrytvW0MQ86FRvxcUHSa3e3xGQVrmqP+S6NeglENa+OC
         3FoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@udel.edu header.s=google-20200914 header.b=Ix1qnqoT;
       spf=pass (google.com: domain of zeyuchen@udel.edu designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=zeyuchen@udel.edu
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id h89si32008ybi.5.2020.10.26.23.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Oct 2020 23:47:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of zeyuchen@udel.edu designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id s21so276196oij.0
        for <kasan-dev@googlegroups.com>; Mon, 26 Oct 2020 23:47:18 -0700 (PDT)
X-Received: by 2002:a05:6808:b24:: with SMTP id t4mr412416oij.93.1603781238094;
 Mon, 26 Oct 2020 23:47:18 -0700 (PDT)
MIME-Version: 1.0
References: <CALZ+MD2orvStubdgL4zEH8L6ADSvqmgvsEjLWdfak13N6vaKww@mail.gmail.com>
 <CACT4Y+YCZTOmxbE6qHobsbQ5mj6rqH5ZGrRxOL_yWQ=_wRLchw@mail.gmail.com>
In-Reply-To: <CACT4Y+YCZTOmxbE6qHobsbQ5mj6rqH5ZGrRxOL_yWQ=_wRLchw@mail.gmail.com>
From: Zeyu Chen <zeyuchen@udel.edu>
Date: Tue, 27 Oct 2020 02:47:07 -0400
Message-ID: <CALZ+MD3W7dnsaoc8sTQVZ_YiJLUcnutFd6sWmn9UTattWj-pxQ@mail.gmail.com>
Subject: Re: Questions on KASAN quarantize zone
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="000000000000fe9fd105b2a16aa4"
X-Original-Sender: zeyuchen@udel.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@udel.edu header.s=google-20200914 header.b=Ix1qnqoT;       spf=pass
 (google.com: domain of zeyuchen@udel.edu designates 2607:f8b0:4864:20::230 as
 permitted sender) smtp.mailfrom=zeyuchen@udel.edu
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

--000000000000fe9fd105b2a16aa4
Content-Type: text/plain; charset="UTF-8"

Thank you very much!

On Tue, Oct 27, 2020 at 2:45 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Mon, Oct 26, 2020 at 10:47 PM Zeyu Chen <zeyuchen@udel.edu> wrote:
> >
> > Hello Dmitry,
> >
> > I just start to use KASAN for my research on kernel use-after-free bugs.
> One of the key factors is the quarantine size. In ASAN, you can set up the
> value via a flag quarantine_size_mb. Basically, you can run the code like
> this:
> > ASAN_OPTIONS=quarantine_size_mb=128 ./a.out
> >
> > I am not so sure how to do that in KASAN. I have been noticing in
> quarantine.c, its implementation seems a little trickier with a global
> queue and per-cpu queues. There are two static parameters:
> >
> >  #define QUARANTINE_FRACTION 32
> >  #define QUARANTINE_PERCPU_SIZE (1 << 20)
> >
> > Can I understand that QUARANTINE_FRACTION is the quarantine size 32 Mb
> for each cpu and QUARANTINE_PERCPU_SIZE 1 Mb is a local cache optimized for
> concurrent implementation of per_cpu queue?
> >
> > In addition, I am wondering if I could change the quarantine size by
> changing the parameter QUARANTINE_FRACTION.
>
> +kasan-dev mailing list for KASAN questions
>
> Hi Zeyu,
>
> QUARANTINE_FRACTION is fraction of RAM for quarantine. There is a
> comment on top of the define that explains it.
>
> Yes, you should be able to change QUARANTINE_FRACTION to change quarantine
> size.
> Try it.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALZ%2BMD3W7dnsaoc8sTQVZ_YiJLUcnutFd6sWmn9UTattWj-pxQ%40mail.gmail.com.

--000000000000fe9fd105b2a16aa4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div>Thank you very much!</div><div><br><div class=3D"gmail_quote"><div dir=
=3D"ltr" class=3D"gmail_attr">On Tue, Oct 27, 2020 at 2:45 AM Dmitry Vyukov=
 &lt;<a href=3D"mailto:dvyukov@google.com">dvyukov@google.com</a>&gt; wrote=
:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;bor=
der-left:1px #ccc solid;padding-left:1ex">On Mon, Oct 26, 2020 at 10:47 PM =
Zeyu Chen &lt;<a href=3D"mailto:zeyuchen@udel.edu" target=3D"_blank">zeyuch=
en@udel.edu</a>&gt; wrote:<br>
&gt;<br>
&gt; Hello Dmitry,<br>
&gt;<br>
&gt; I just start to use KASAN for my research on kernel use-after-free bug=
s. One of the key factors is the quarantine size. In ASAN, you can set up t=
he value via a flag quarantine_size_mb. Basically, you can run the code lik=
e this:<br>
&gt; ASAN_OPTIONS=3Dquarantine_size_mb=3D128 ./a.out<br>
&gt;<br>
&gt; I am not so sure how to do that in KASAN. I have been noticing in quar=
antine.c, its implementation seems a little trickier with a global queue an=
d per-cpu queues. There are two static parameters:<br>
&gt;<br>
&gt;=C2=A0 #define QUARANTINE_FRACTION 32<br>
&gt;=C2=A0 #define QUARANTINE_PERCPU_SIZE (1 &lt;&lt; 20)<br>
&gt;<br>
&gt; Can I understand that QUARANTINE_FRACTION is the quarantine size 32 Mb=
 for each cpu and QUARANTINE_PERCPU_SIZE 1 Mb is a local cache optimized fo=
r concurrent implementation of per_cpu queue?<br>
&gt;<br>
&gt; In addition, I am wondering if I could change the quarantine size by c=
hanging the parameter QUARANTINE_FRACTION.<br>
<br>
+kasan-dev mailing list for KASAN questions<br>
<br>
Hi Zeyu,<br>
<br>
QUARANTINE_FRACTION is fraction of RAM for quarantine. There is a<br>
comment on top of the define that explains it.<br>
<br>
Yes, you should be able to change QUARANTINE_FRACTION to change quarantine =
size.<br>
Try it.<br>
</blockquote></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CALZ%2BMD3W7dnsaoc8sTQVZ_YiJLUcnutFd6sWmn9UTattWj-pxQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CALZ%2BMD3W7dnsaoc8sTQVZ_YiJLUcnutFd6sWmn9UTattWj=
-pxQ%40mail.gmail.com</a>.<br />

--000000000000fe9fd105b2a16aa4--
