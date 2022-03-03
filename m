Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3EJQKIQMGQEJJO57RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 20F394CB9CB
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Mar 2022 10:05:50 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id z10-20020a634c0a000000b0036c5eb39076sf2466002pga.18
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Mar 2022 01:05:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646298349; cv=pass;
        d=google.com; s=arc-20160816;
        b=YAlpinfZ4YaHr77wjXdnJvREgWmiSlvvufyDaRm97z3cN3A1f8yng2c3489XuK21nt
         Ui0GK5z8w1MZmAt2wb6njETj5RLKdx9uRWWV0eg/VwQkd3soUHz/ezMT/uxbg2cgnyo5
         h5PPJmoxXFudqvBHNm7AqXSKoZHx3gXx1XKaXJbXarfc/RRpkEzHz9j4S6+mx7cdFCRq
         Vdg4K/OECE7jn4suEyW9ipkObH9C8t/o9r5DcnKjwDG3vVB4aRl3ol2aAOBWFUosR4Xd
         t8rW4JKl/LP5dhERW1UWEx4+UxtYl7FwJG8Gyegfb42tS7L444g5q2oz8rU5Ii/pZ3Qh
         zufQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PCW8PbK9RYq3ZMkzhm+Vf+oqIxEFbmA9teMFyhFHoYY=;
        b=qihSlKa5GtJv8sJcKhS+8W/qBUwlVp88zQMmdH8EHt0fd+uj2TMjv9xPOD6VSFIwwu
         RUDuU2Ru3TjmaDPJIbBKWRgJdDnM7+rCWZovxWMxOVy2a6K/IaYOiSXnFRX7EF57mu3q
         A/a2hx7BP/acNO3YiebfHxwlD3NeJrWZQ9+0ERPf9JqLOB7SB6DH5M7s3zf9H08Ba74E
         fnbCXLbbHg3J6hQ5UO7GvkyqU+qMQcXV7g1IIlKYPRuQ4VPBSjChkbyLkgSnxGCeByQS
         NGJK0CPvqYXYdhT+lcbawP286mxXsk8ZCxyWA0gTNFIdnqNS3CNFtzMWCu7f1AnvxqBc
         Oq+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VvG18cLn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PCW8PbK9RYq3ZMkzhm+Vf+oqIxEFbmA9teMFyhFHoYY=;
        b=jjTeN6AHzO35YmeU934cZNm1dr0h3BGErIz9VZbG5akCb8szk6PuKo6AICyCOm2RnJ
         5bVi6rNMV36rgDSVoZIid1t2in1p/f0DP++P/9jPgy2GAJNsChDjq/9NimTprckDOubh
         +tbUCrdD8UGUS5ZdDiRfkSkUMFN3zjZbrzrBkOJbatK32ewzRfFCBAsD14HTS8Dk3kyN
         A7aFB5VXWYSLfpjJs/hts22vr7Uu4mSt8Ck9waphgiDBBPYJoNKHI1Hz++mdoWAwMJAO
         cPkw8e4JIEcG3oP+EEPHG0ZJItpoMUqqB1Zr2vNgbHkqw8u+BcYVzroPqL8POLJLsG4O
         C3YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PCW8PbK9RYq3ZMkzhm+Vf+oqIxEFbmA9teMFyhFHoYY=;
        b=JdyfR0qYVr6rxGXE2rbcwmk+iu0jyQCsv5Wzk+6qKp5exvUzrp52Oi+g3GmdMBlmel
         oH+D/WW4Eprh6rfNifZL8YitJi/E64rPpCavk42cf7fi5wYV2+xUoRnRsW0XLdkSJVnI
         rD+ueWBVG6BQF3RqdY/cgIo8E60cp3l+U0g1lEn9EL3fm+9jd1V9Hhd5lt2kOE1k11KA
         4x1Ma84fvbYUddZqwT42659Uv9Idow/5HKSDxXxQRB9ynKYQ2C1ESENudPdCcCJfkH8B
         n2ZcTnKtwrPOBRu9hHebuluWIZT9+7/gRTbEhK+rVv7BzFQ9i/wf/hvaQLfxDTsbHVxb
         x/8w==
X-Gm-Message-State: AOAM531lKEzIloNXralkEYNjCYCzYXALQSd9G4sC0ahp2QOINFPDQeK2
	bkAhzgxuoUm+39MTkUcZX78=
X-Google-Smtp-Source: ABdhPJyAuT7t1UnLZnJI7JoUVD6GfawcGSPyO4TesmfjCv13vQQ9JZJvsaDQ7QEujSm0pWRt4DEeXw==
X-Received: by 2002:a63:5f42:0:b0:373:d440:496e with SMTP id t63-20020a635f42000000b00373d440496emr29781205pgb.529.1646298348863;
        Thu, 03 Mar 2022 01:05:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8c0e:b0:1bf:1a38:d505 with SMTP id
 a14-20020a17090a8c0e00b001bf1a38d505ls84068pjo.3.gmail; Thu, 03 Mar 2022
 01:05:48 -0800 (PST)
X-Received: by 2002:a17:90a:728d:b0:1bc:1e1f:7eb9 with SMTP id e13-20020a17090a728d00b001bc1e1f7eb9mr4179448pjg.99.1646298348235;
        Thu, 03 Mar 2022 01:05:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646298348; cv=none;
        d=google.com; s=arc-20160816;
        b=TVRYlHRydOVNTeNhy4Vf2mwXhkHFFpVdQhUjNeVJGdDnX5f0btpJyShPZ/NEg6xpeH
         KtH1fHYJcxCwLKNp+GU6UhOxFg5pt3pQ1EHm0eWHFwfx7vydFgWk81heBm/mBhBMetGO
         QWOeYWaylLRwUEt8PpubVcQx96wBJQTwyDoyoS6ygjmFHHhw+u/GfMvPf+PwyjKMGFsn
         nnpWJkKlv/zmtG+8NlpIgP+4I165OsrxiTMzbM76PNndhhWD9V33A+Gnz4FTTN663zdt
         PwX9uHOgSTFcQq2XGLfERG/UqQjaIpqvg334Ow8lRNQVYIF1zvoXoud6/uEe9Zsx9HMG
         JGLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eQHLw8Ru5kLYCIL9yWgjZohvip//HVgKRsBfoCA5L4Y=;
        b=wU0uDCJu0dSOq5nta+ScKSEmNfINn50OpI0M2z7AinHdimSbncCvS/epUhhQAzH6Au
         y1K5GsgcAN1yhDO/Rcm7hsu+/icLfo55evrCfXNirW58Yk90dhJDduCRZsY+4G4JVTql
         R5hr9N9TuxvLS8ibmKZrss4QilBIrDHm/JxZW1BPQZNw48GWBx/YE4CoqQJ9j3mhypUl
         y5QSRhTmQYom3R3RotR5JDXcyolbDfM577oXgRtyRz2pBRoNkgQrOArNxrTMFFeMwH9V
         3lqHmw1dtdfNeLNOWz0eeU8T6SC3VTVI/mR5vPr7Km0FKcQ5ghXt1EOKwHthXTrPjmNQ
         y6rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VvG18cLn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id jx5-20020a17090b46c500b001bede07ed67si330722pjb.1.2022.03.03.01.05.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Mar 2022 01:05:48 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id b23so4030094qtt.6
        for <kasan-dev@googlegroups.com>; Thu, 03 Mar 2022 01:05:48 -0800 (PST)
X-Received: by 2002:a05:622a:18a6:b0:2dd:2c5b:ca00 with SMTP id
 v38-20020a05622a18a600b002dd2c5bca00mr26538672qtc.549.1646298347233; Thu, 03
 Mar 2022 01:05:47 -0800 (PST)
MIME-Version: 1.0
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
In-Reply-To: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Mar 2022 10:05:10 +0100
Message-ID: <CAG_fn=Wd5GMFojbvdZkysBQ5Auy5YYRdmZfjSVMq8gpDMRZ_3w@mail.gmail.com>
Subject: Re: [RFC PATCH 0/2] Alloc kfence_pool after system startup
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: multipart/alternative; boundary="0000000000002ef18e05d94cb460"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VvG18cLn;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as
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

--0000000000002ef18e05d94cb460
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Thu, Mar 3, 2022 at 4:15 AM Tianchen Ding <dtcccc@linux.alibaba.com>
wrote:

> KFENCE aims at production environments, but it does not allow enabling
> after system startup because kfence_pool only alloc pages from memblock.
> Consider the following production scene:
> At first, for performance considerations, production machines do not
> enable KFENCE.
>
What are the performance considerations you have in mind? Are you running
KFENCE with a very aggressive sampling rate?

However, after running for a while, the kernel is suspected to have
> memory errors. (e.g., a sibling machine crashed.)
>
I have doubts regarding this setup. It might be faster (although one can
tune KFENCE to have nearly zero performance impact), but is harder to
maintain.
It will also catch fewer errors than if you just had KFENCE on from the
very beginning:
 - sibling machines may behave differently, and a certain bug may only
occur once - in that case the secondary instances won't notice it, even
with KFENCE;
 - KFENCE also catches non-lethal corruptions (e.g. OOB reads), which may
stay under radar for a very long time.


> So other production machines need to enable KFENCE, but it's hard for
> them to reboot.
>
> The 1st patch allows re-enabling KFENCE if the pool is already
> allocated from memblock.
>
> The 2nd patch applies the main part.
>
> Tianchen Ding (2):
>   kfence: Allow re-enabling KFENCE after system startup
>   kfence: Alloc kfence_pool after system startup
>
>  mm/kfence/core.c | 106 ++++++++++++++++++++++++++++++++++++++---------
>  1 file changed, 87 insertions(+), 19 deletions(-)
>
> --
> 2.27.0
>
>

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise erhalt=
en
haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich bit=
te wissen,
dass die E-Mail an die falsche Person gesendet wurde.



This e-mail is confidential. If you received this communication by mistake,
please don't forward it to anyone else, please erase all copies and
attachments, and please let me know that it has gone to the wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWd5GMFojbvdZkysBQ5Auy5YYRdmZfjSVMq8gpDMRZ_3w%40mail.gmai=
l.com.

--0000000000002ef18e05d94cb460
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Thu, Mar 3, 2022 at 4:15 AM Tianch=
en Ding &lt;<a href=3D"mailto:dtcccc@linux.alibaba.com">dtcccc@linux.alibab=
a.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"ma=
rgin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:=
1ex">KFENCE aims at production environments, but it does not allow enabling=
<br>
after system startup because kfence_pool only alloc pages from memblock.<br=
>
Consider the following production scene:<br>
At first, for performance considerations, production machines do not<br>
enable KFENCE.<br></blockquote><div>What are the performance considerations=
 you have in mind? Are you running KFENCE with a very aggressive sampling r=
ate?</div><div><br></div><blockquote class=3D"gmail_quote" style=3D"margin:=
0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">
However, after running for a while, the kernel is suspected to have<br>
memory errors. (e.g., a sibling machine crashed.)<br></blockquote><div>I ha=
ve doubts regarding this setup. It might be faster (although one can tune K=
FENCE to have nearly zero performance impact), but is harder to maintain.</=
div><div>It will also catch fewer errors than if you just had KFENCE on fro=
m the very beginning:</div><div>=C2=A0- sibling machines may behave differe=
ntly, and a certain bug may only occur once - in that case the secondary in=
stances won&#39;t notice it, even with KFENCE;</div><div>=C2=A0- KFENCE als=
o catches non-lethal corruptions (e.g. OOB reads), which may stay under rad=
ar for a very long time.</div><div>=C2=A0</div><blockquote class=3D"gmail_q=
uote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,2=
04);padding-left:1ex">
So other production machines need to enable KFENCE, but it&#39;s hard for<b=
r>
them to reboot.<br>
<br>
The 1st patch allows re-enabling KFENCE if the pool is already<br>
allocated from memblock.<br>
<br>
The 2nd patch applies the main part.<br>
<br>
Tianchen Ding (2):<br>
=C2=A0 kfence: Allow re-enabling KFENCE after system startup<br>
=C2=A0 kfence: Alloc kfence_pool after system startup<br>
<br>
=C2=A0mm/kfence/core.c | 106 ++++++++++++++++++++++++++++++++++++++--------=
-<br>
=C2=A01 file changed, 87 insertions(+), 19 deletions(-)<br>
<br>
-- <br>
2.27.0<br>
<br>
</blockquote></div><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr"=
 class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<br>Software=
 Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, 33<br>80636=
 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebasti=
an<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz der Gesellsch=
aft: Hamburg<br><br>Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4ls=
chlicherweise erhalten haben sollten, leiten Sie diese bitte nicht an jeman=
d anderes weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und l=
assen Sie mich bitte wissen, dass die E-Mail an die falsche Person gesendet=
 wurde. <br><br>=C2=A0 =C2=A0 =C2=A0<br><br>This e-mail is confidential. If=
 you received this communication by mistake, please don&#39;t forward it to=
 anyone else, please erase all copies and attachments, and please let me kn=
ow that it has gone to the wrong person.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DWd5GMFojbvdZkysBQ5Auy5YYRdmZfjSVMq8gpDMRZ_3w%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DWd5GMFojbvdZkysBQ5Auy5YYRdmZfjSVMq8gpDMR=
Z_3w%40mail.gmail.com</a>.<br />

--0000000000002ef18e05d94cb460--
