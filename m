Return-Path: <kasan-dev+bncBC7KJLMS4AJBBYOBV2VQMGQETVBGZNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C2016801EA8
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Dec 2023 22:25:54 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-58d11a85f90sf3880611eaf.3
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Dec 2023 13:25:54 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701552353; x=1702157153; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=D146lnGMigsL9QUo8LoVT4349JrLh63di1n+n/0HZFs=;
        b=X/+oaHrbJ/3v2l7VPF4wYCg4zTE2XybWuk4ERzEazrBzvQI4bOiayzLcl5TqgUTA+T
         Ub4LaG5RKSEbV7ToNnmzCtYG3gP+CoIdkQ1dFFMPqjqi2a17qulumjW/vmxLJvfwyy6e
         sePc/4/D5oSU2qVZRnWjwSIRHt4r7f3r9vpo9L6+LUsiIWr8Wu7cTHoUsb6B4Chx1DRI
         /K+9r4DSyk+j93sTYPlAljLXx/HcTC1sE8JAg4XBgpFUkfeH3rUfAXkq7Z4pWDQN8YCY
         Xv/SkIlZIq1G6T4+v7IEAkUwzGyMFOTYXgSAPOwGc3wai3QMLpuybvYKB+c2ZsBbqDRR
         3D3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701552353; x=1702157153; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=D146lnGMigsL9QUo8LoVT4349JrLh63di1n+n/0HZFs=;
        b=KoU+6S33GgnpFsGMISImLUYMSPr5N0j2H2SIO+1/GudsgFNSB59iN6gSLOaO48psiQ
         7wBDuS5DC1S0876E+CeR+AyeglyJFxP1JuNvNMSxfxhxuHOi67aaWiiQfD6L3DFHdaLY
         s37vi6qpZYs6sA1hwJqvscHIqxfRavhBHMS/yW9jkaYR+4htH4z7TKZuXFDnTiCF6qMN
         ut0M/LlX7QUMg/VkU7uz+646qPqITXgdgSL/6XmMbSl+nOcYY1fPXld/CgFoTcKFFxvx
         HnuXrCc8c2i8jHFq9Twexq/iubXWJy13ZzN6MngIm6AzpmAqeBYOCZ3gvyLCoSNbLy51
         +4vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701552353; x=1702157153;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D146lnGMigsL9QUo8LoVT4349JrLh63di1n+n/0HZFs=;
        b=Hgb49NuMxX+Ft8GsV1orjMS/qqegQHn531DWiVRK7z+VMnnQ0METdPXz2Jt/A+0dyv
         tIZ50X8gEL41iIL1xXqIxMgPlXhRBOu7uHZO//uEYm14yKWwriMDY84Sg+TwCaGVUGbV
         oRxybeaxG0+zI+Vo3KPCK/4dVUW5wFW7/+uL7iMN/0D+TQrbnPiRwp5J+CWx8LiJZStr
         uxITVZasfDubcL9qxjEBC3NDaqZhEXK+EVFvQQlZQjgjHkDPKLLHHr9ja+HxNSivSqwy
         bZtciXrU5H1bJfhbPOAF3gSIJ0sRfsAn+OyXykNy1yw/nkLOu2qlkJWpxfSqsl7gKc2Q
         BR8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxTkHJ5Ca4gG2dAYmq5RdcWWrpUQYR5Gouju9dEH6+cg9/S6MMM
	2Gn3J4dbky0QrdDVqvfKxMz0JA==
X-Google-Smtp-Source: AGHT+IGHQhOaylxXayoYKt1EgR6xheUWdMV0eRxrl2/uOEFQB3Yoi3OSUonRiqoqaXiU2Ro+MNjQOA==
X-Received: by 2002:a4a:3c0c:0:b0:58e:32a8:2ff8 with SMTP id d12-20020a4a3c0c000000b0058e32a82ff8mr29643ooa.4.1701552353279;
        Sat, 02 Dec 2023 13:25:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:82c:b0:58d:582d:7fef with SMTP id
 bg44-20020a056820082c00b0058d582d7fefls1719733oob.0.-pod-prod-05-us; Sat, 02
 Dec 2023 13:25:53 -0800 (PST)
X-Received: by 2002:a9d:5548:0:b0:6d8:5a82:b9ab with SMTP id h8-20020a9d5548000000b006d85a82b9abmr832575oti.2.1701552353006;
        Sat, 02 Dec 2023 13:25:53 -0800 (PST)
Received: by 2002:a05:6808:1a0d:b0:3b3:ed04:dbd0 with SMTP id 5614622812f47-3b8a856eed0msb6e;
        Sat, 2 Dec 2023 11:34:55 -0800 (PST)
X-Received: by 2002:a05:6870:fb93:b0:1fb:121c:c29b with SMTP id kv19-20020a056870fb9300b001fb121cc29bmr938711oab.1.1701545694819;
        Sat, 02 Dec 2023 11:34:54 -0800 (PST)
Date: Sat, 2 Dec 2023 11:34:54 -0800 (PST)
From: Javad Zandi <jzand002@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <f8c28cc4-beef-40af-af44-616bcaa916e6n@googlegroups.com>
In-Reply-To: <bf45cf22-662b-e99c-4868-bfc64a0622b0@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
 <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
 <20210222175825.GE19604@arm.com>
 <6111633c-3bbd-edfa-86a0-be580a9ebcc8@arm.com>
 <20210223120530.GA20769@arm.com>
 <20210223124951.GA10563@willie-the-truck>
 <bf45cf22-662b-e99c-4868-bfc64a0622b0@arm.com>
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_58025_1347864504.1701545694612"
X-Original-Sender: jzand002@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_58025_1347864504.1701545694612
Content-Type: multipart/alternative; 
	boundary="----=_Part_58026_1987175825.1701545694612"

------=_Part_58026_1987175825.1701545694612
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

I am not sure whether this question is proper or not. I stuck at enabling=
=20
MTE for Apple-M1 process and ubuntu22LTS. Is thee any chance on how to let=
=20
me know how can I enable MTE on ubuntu22 with apple M1 processor which=20
already has MTE feature?

Regards,
Javad

On Tuesday, February 23, 2021 at 9:21:03=E2=80=AFAM UTC-5 Vincenzo Frascino=
 wrote:

> On 2/23/21 12:49 PM, Will Deacon wrote:
> >>> I totally agree on this point. In the case of runtime switching we=20
> might need
> >>> the rethink completely the strategy and depends a lot on what we want=
=20
> to allow
> >>> and what not. For the kernel I imagine we will need to expose=20
> something in sysfs
> >>> that affects all the cores and then maybe stop_machine() to propagate=
=20
> it to all
> >>> the cores. Do you think having some of the cores running in sync mode=
=20
> and some
> >>> in async is a viable solution?
> >> stop_machine() is an option indeed. I think it's still possible to run
> >> some cores in async while others in sync but the static key here would
> >> only be toggled when no async CPUs are left.
> > Just as a general point, but if we expose stop_machine() via sysfs we
> > probably want to limit that to privileged users so you can't DoS the=20
> system
> > by spamming into the file.
>
> I agree, if we ever introduce the runtime switching and go for this optio=
n=20
> we
> should make sure that we do it safely.
>
> --=20
> Regards,
> Vincenzo
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f8c28cc4-beef-40af-af44-616bcaa916e6n%40googlegroups.com.

------=_Part_58026_1987175825.1701545694612
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

I am not sure whether this question is proper or not. I stuck at enabling M=
TE for Apple-M1 process and ubuntu22LTS. Is thee any chance on how to let m=
e know how can I enable MTE on ubuntu22 with apple M1 processor which alrea=
dy has MTE feature?<div><br /></div><div>Regards,</div><div>Javad<br /><br =
/></div><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">O=
n Tuesday, February 23, 2021 at 9:21:03=E2=80=AFAM UTC-5 Vincenzo Frascino =
wrote:<br/></div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0=
.8ex; border-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;">On 2/2=
3/21 12:49 PM, Will Deacon wrote:
<br>&gt;&gt;&gt; I totally agree on this point. In the case of runtime swit=
ching we might need
<br>&gt;&gt;&gt; the rethink completely the strategy and depends a lot on w=
hat we want to allow
<br>&gt;&gt;&gt; and what not. For the kernel I imagine we will need to exp=
ose something in sysfs
<br>&gt;&gt;&gt; that affects all the cores and then maybe stop_machine() t=
o propagate it to all
<br>&gt;&gt;&gt; the cores. Do you think having some of the cores running i=
n sync mode and some
<br>&gt;&gt;&gt; in async is a viable solution?
<br>&gt;&gt; stop_machine() is an option indeed. I think it&#39;s still pos=
sible to run
<br>&gt;&gt; some cores in async while others in sync but the static key he=
re would
<br>&gt;&gt; only be toggled when no async CPUs are left.
<br>&gt; Just as a general point, but if we expose stop_machine() via sysfs=
 we
<br>&gt; probably want to limit that to privileged users so you can&#39;t D=
oS the system
<br>&gt; by spamming into the file.
<br>
<br>I agree, if we ever introduce the runtime switching and go for this opt=
ion we
<br>should make sure that we do it safely.
<br>
<br>--=20
<br>Regards,
<br>Vincenzo
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/f8c28cc4-beef-40af-af44-616bcaa916e6n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/f8c28cc4-beef-40af-af44-616bcaa916e6n%40googlegroups.com</a>.<b=
r />

------=_Part_58026_1987175825.1701545694612--

------=_Part_58025_1347864504.1701545694612--
