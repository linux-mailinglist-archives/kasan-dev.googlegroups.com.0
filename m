Return-Path: <kasan-dev+bncBDPJLN7A4MFRBPVJ3CGAMGQEZWWXSXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id DDD3E455767
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:54:22 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 205-20020a1c00d6000000b003335d1384f1sf4034624wma.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:54:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637225662; cv=pass;
        d=google.com; s=arc-20160816;
        b=ox4uQ1pPfY0eThh5ob5inh2ziaEDLiU8WiIJOE3qqs70EXlPv2k/b7WztZzj3Ooqj4
         Mw+QXHN6mgdkuxjI0qckWG+8CItDqaUgnJ2VC3QpVc3kcbJQsEcofw2yMv+m8hfMXJob
         uEkKQAQfwOhIajaSNxngVXd+G4WDp2BqrVFNfbzqvNViTDGIFghdtDCvJqrh0oIrOM/R
         vtgHGT6iTsNvIpONl9InbmuVXUgzI6WXNvXO+b5b3guUrjNwDdCUdwybNqQwnh2X6kej
         rFThonbKthPqsRS5f+/2bOq2mYQSYEck7cDYuHcDgrYglvEbR2x7d0/BYe6HjL88RmOr
         YTHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=v9acqGOvWzTvK6G6Z9RHzDH21X+yfgeeW5TI2dxWNGw=;
        b=Ltm1BM7IBP2x3TymcTYSMtixxpZPVafkR58zA6I//1gCOe46YxaPYcglexPYSLdcnm
         7zb1IOtDvJRIqlo610lDgjURQIs7XJqXooFTSvUsRKaOdDxyU5GBT6+P+NfJ7ypcMKwq
         zP22NbQTER6e+t2W28+HR4W5OynAmuUegGZSbhkwp/FUEVbq5yLuYGxR6xb3DYKoQSsU
         7mlBewOcet/Qzm1lY4DlCAlnrSGiX8NM+u1pVfgr5tO8AdR1yh/iuLUhCyk4J2NVa+Pt
         R6ciidJL2kPHNNVKtylD6/H/lYs8PCa3SxrqYcqTUhlxU9/etyvpKTkZxgotZ8RHvtb3
         Xwgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YRgL1wCN;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v9acqGOvWzTvK6G6Z9RHzDH21X+yfgeeW5TI2dxWNGw=;
        b=N9hSRhLMm98PNrovZ6NY7ZmLndFd8DwRPCnm4MZxowWQnbcy8ZEnMoYWhp3hQYefjE
         StyLD7lCji4s+AiYyHWYWswL+DosKZttd5Wadt3zrh4RnyAgRnUSGm5Z+UZ4BEuwRuJj
         jGfkdMhWpA7XmJmuU3ECKfAOzRuxLb48hnwziZzIvStcMfm83Ci2oWY3huQ45lpq5Otu
         ZJlVMhhBYbmq7YvU/MgcdIxO8aChNiKPYJX/e2+ar0vJ+ADJuEKMyQvgOIkbE1vNPEEF
         TvTtohJXOYz1356SVCTiLtHHc+Hty6pnM3B/QIYnp6mm5PAvYwyn94RcqoNQl2iPN9PH
         kRNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v9acqGOvWzTvK6G6Z9RHzDH21X+yfgeeW5TI2dxWNGw=;
        b=qlxXH5+zv+xFEzrh+xZjcWXXbxDiSW9+TE7R3Tuy0wjBbukQ4Zk6O7qk9JPoiSJ3Zj
         poYtcxHmHLBbu+xQACTx6a04o0l+SJaNb3wFSoqqaFJpVcDOFHueMryZpV3cESxYNKfi
         V3vuRdQDgBjlZdkXHVNEd5TfZasREpYWmXH6kj3yKxGOhJ2Zmxa+0EuJf4+q5LSIKj6O
         qbC/ZzwjNtpT1wcE8je2MzR4oVHJ3QNnl3SUui1kE9bJ5NmYxMg5ov/Hespg9PVTwraO
         y6fKY6OGwDuX+oLREvQh2oZnC7z3c7Lrceq4uNvwbhMgDyQ+avF/zEfzrhXZ+NiWtTWF
         snDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v9acqGOvWzTvK6G6Z9RHzDH21X+yfgeeW5TI2dxWNGw=;
        b=nTfOUBZMlVyRatvL4hemMjMLicguwB/Bd3s9Z3zGsSaNsvtUytTlVHeFJAl3oiefb1
         pD1HKvH4ERKdkRjJqMn8QUUSY1SDcTeMbpUo0EFuEZn9/pcYY/YxS1yEeQFeFx08giSc
         MNOe83shg2ab7tHfqvA3c6hWT+Z0GVq5dMc5sbSTcIlvFBU1eQIullTBuR5jvruw0Avi
         2rAeTvSZkVjdO4o034l69m485syV+XbAofHPezl5k1LWgayg8AwglECociIoViEaDA8E
         GpnzQZG6As2DQDBWO4rouxu8Y3YobJVBf9j6vQbDIWEc1WNaJVtZbNSXTtbJeiw7Y5AM
         KKJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oqdpd+PwLc0Z1IhQ3Q/kYnLlhYv4fz7zvnlapFg1sj9vcLxa6
	N5ic2PM+VmrV0Ho14CiF3rY=
X-Google-Smtp-Source: ABdhPJzLxPRIz0HMkDl7acQCt+mLi5yXUfRpfcjF5JZFFlx4HGteFtq+pc+nBABJn9lIkzgenhgYOw==
X-Received: by 2002:a05:600c:190b:: with SMTP id j11mr7805230wmq.112.1637225662664;
        Thu, 18 Nov 2021 00:54:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls2483169wrp.1.gmail; Thu, 18 Nov
 2021 00:54:21 -0800 (PST)
X-Received: by 2002:a5d:4e52:: with SMTP id r18mr26787338wrt.224.1637225661658;
        Thu, 18 Nov 2021 00:54:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637225661; cv=none;
        d=google.com; s=arc-20160816;
        b=nxqv5/Ay5GeM2Y0y9IApLrznuscP+U5dlJFXdG4ANAJSqgigKwMPnPdfG2evfAKp7A
         ml6shmo2xXwVCq50lc/6dqJ5WtNYoALKkRs/Ncs72Q3Q/4CKBb2ehXLY8e03b+POM/X+
         gLB5g317o5IjKs1p1wWl1beKQNCK7IGjX+Su1sXScbM0sKlkUTXpUrnY6AtIpjtICuNw
         BBLHXxfDPRelcbjPuBpt6phMY8nRCOP1bsd68xMJUqKWGYS8ZsDzN4sW60pPcOaXHcma
         IDn8k9DfdWrzgayEhOWPkkw+eXG4I491NTzSm1PohHxVf3AWXqOqWhInDUY6CNztEkv1
         v0JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d/QIJd6SO3Eh7Nd0TeN0hyCU4FksH7wOhTIoVbkbxn8=;
        b=xlLp7vn47uXEYDQ2EmqO+usbbNKO4dK5557Sl8gkR8q9VB5C/dKxvJg8+K18q9DyGv
         34bSneW/7lTEinynVX+QNk4m22VsTXzD60v9GGDpFzYJyLNV+AzLI2SQV6CVLn23XVIU
         IwjjQLZSW7EQw/Ada2z8a+qWuDZEZNgJk5DbrvnbfZ8mcbjyStaOC5x7e4szViXT0nTH
         gLyMzCsVSOK6/GTU+T0fwJxIv0PB1SQJKmx211ZRTmChAPXi7KJ2qAzPHXTJIGujFcLY
         /o+Kkit0TM/hhltVeDbjg6Qnjvf6yhWvSglg7qF4vPQa6M9LSzOBQ91wbzWiLJZuPVH8
         MISg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YRgL1wCN;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 125si580487wmc.1.2021.11.18.00.54.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:54:21 -0800 (PST)
Received-SPF: pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id g14so23777680edz.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:54:21 -0800 (PST)
X-Received: by 2002:a17:907:c1d:: with SMTP id ga29mr30458439ejc.180.1637225661407;
 Thu, 18 Nov 2021 00:54:21 -0800 (PST)
MIME-Version: 1.0
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
 <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
 <YZPeRGpOTSgXjaE6@elver.google.com> <CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA@mail.gmail.com>
 <CA+LMZ3r9ioqSN31w5v_Bkgs7UyPux=0MO8g0dQC16AxEiorBcg@mail.gmail.com>
 <CANpmjNMzv2b1srETOp1STjVWYZx-1XpdMm5yY485vSmd=wjJiw@mail.gmail.com>
 <CA+LMZ3qhJ1dnS3O9vKRA1DCF93Lpi-xq9PmStwhWC+ykRSGr_g@mail.gmail.com>
 <CAPDLWs9TR4gNHg+n2j2958yff+F6Ex0gVZxD8qtcPrgcYghfWA@mail.gmail.com> <CANpmjNO5AQ_Yhk6k+N2u_sFPRP2JWRvkPqUSrS6koAYrqCx5-w@mail.gmail.com>
In-Reply-To: <CANpmjNO5AQ_Yhk6k+N2u_sFPRP2JWRvkPqUSrS6koAYrqCx5-w@mail.gmail.com>
From: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Date: Thu, 18 Nov 2021 14:24:09 +0530
Message-ID: <CAPDLWs8gt6vStwi86FT8cKEcjHkJsybSVn_q7eQKiAu7sqo0zA@mail.gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global memory?
To: Marco Elver <elver@google.com>
Cc: Chi-Thanh Hoang <chithanh.hoang@gmail.com>, kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="000000000000f72e0005d10c4de7"
X-Original-Sender: kaiwan.billimoria@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YRgL1wCN;       spf=pass
 (google.com: domain of kaiwan.billimoria@gmail.com designates
 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
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

--000000000000f72e0005d10c4de7
Content-Type: text/plain; charset="UTF-8"

On Thu, 18 Nov 2021, 14:06 Marco Elver, <elver@google.com> wrote:

> On Thu, 18 Nov 2021 at 06:56, Kaiwan N Billimoria
> <kaiwan.billimoria@gmail.com> wrote:
> >
> > On Thu, Nov 18, 2021 at 8:29 AM Chi-Thanh Hoang
> > <chithanh.hoang@gmail.com> wrote:
> > >
> > > Thanks Marco for creating the bugzilla.
> > > I will post my findings.
>
> Thanks for adding your findings.
>
> [...]
> >
> > Really interesting! Am trying to replicate along similar lines but it
> > doesn't trigger !
> >
> > static char global_arr1[100];
> > static int global_arr2[10];
> > static char global_arr3[10];
> > ...
> > int global_mem_oob_left(int mode)
> > {
> >     volatile char w;
> >     char *volatile array = global_arr3;
> >     char *p = array - 3; // invalid, not within bounds
> >
> >     w = *(volatile char *)p;
> >     ...
> > }
> >
> > I also find that the global arrays seem to be laid out "in reverse",
> > i.e., if i print their kernel va's:
> > test_kmembugs:global_mem_oob_left(): global_arr1=ffffffffc07db8e0
> > global_arr2=ffffffffc07db900 global_arr3=ffffffffc07db8c0
> >
> > And the last one, global_arr3, coincides with the BSS start:
> >
> > $ sudo cat /sys/module/test_kmembugs/sections/.bss
> > 0xffffffffc07db8c0
> >
> > Can we infer anything here?
>
> Infer why it's broken? Not really, there's no guaranteed order how
> globals are laid out in memory. It's entirely up to the linker (except
> if you explicitly put the symbol in some section)
>

Ok..

>
> The reason why GCC is not detecting this is because last I checked its
> implementation of adding globals redzones is based on increasing
> alignment of globals, which is really not the most reliable way to
> ensure there's always padding. Clang explicitly adds data after a
> global and doesn't rely on alignment.
>
Ok. But, this had been done on a kernel and module compiled with clang.
Thanks, Kaiwan.

>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDLWs8gt6vStwi86FT8cKEcjHkJsybSVn_q7eQKiAu7sqo0zA%40mail.gmail.com.

--000000000000f72e0005d10c4de7
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div><br><br><div class=3D"gmail_quote"><div dir=3D"ltr" =
class=3D"gmail_attr">On Thu, 18 Nov 2021, 14:06 Marco Elver, &lt;<a href=3D=
"mailto:elver@google.com">elver@google.com</a>&gt; wrote:<br></div><blockqu=
ote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:1px #ccc s=
olid;padding-left:1ex">On Thu, 18 Nov 2021 at 06:56, Kaiwan N Billimoria<br=
>
&lt;<a href=3D"mailto:kaiwan.billimoria@gmail.com" target=3D"_blank" rel=3D=
"noreferrer">kaiwan.billimoria@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; On Thu, Nov 18, 2021 at 8:29 AM Chi-Thanh Hoang<br>
&gt; &lt;<a href=3D"mailto:chithanh.hoang@gmail.com" target=3D"_blank" rel=
=3D"noreferrer">chithanh.hoang@gmail.com</a>&gt; wrote:<br>
&gt; &gt;<br>
&gt; &gt; Thanks Marco for creating the bugzilla.<br>
&gt; &gt; I will post my findings.<br>
<br>
Thanks for adding your findings.<br>
<br>
[...]<br>
&gt;<br>
&gt; Really interesting! Am trying to replicate along similar lines but it<=
br>
&gt; doesn&#39;t trigger !<br>
&gt;<br>
&gt; static char global_arr1[100];<br>
&gt; static int global_arr2[10];<br>
&gt; static char global_arr3[10];<br>
&gt; ...<br>
&gt; int global_mem_oob_left(int mode)<br>
&gt; {<br>
&gt;=C2=A0 =C2=A0 =C2=A0volatile char w;<br>
&gt;=C2=A0 =C2=A0 =C2=A0char *volatile array =3D global_arr3;<br>
&gt;=C2=A0 =C2=A0 =C2=A0char *p =3D array - 3; // invalid, not within bound=
s<br>
&gt;<br>
&gt;=C2=A0 =C2=A0 =C2=A0w =3D *(volatile char *)p;<br>
&gt;=C2=A0 =C2=A0 =C2=A0...<br>
&gt; }<br>
&gt;<br>
&gt; I also find that the global arrays seem to be laid out &quot;in revers=
e&quot;,<br>
&gt; i.e., if i print their kernel va&#39;s:<br>
&gt; test_kmembugs:global_mem_oob_left(): global_arr1=3Dffffffffc07db8e0<br=
>
&gt; global_arr2=3Dffffffffc07db900 global_arr3=3Dffffffffc07db8c0<br>
&gt;<br>
&gt; And the last one, global_arr3, coincides with the BSS start:<br>
&gt;<br>
&gt; $ sudo cat /sys/module/test_kmembugs/sections/.bss<br>
&gt; 0xffffffffc07db8c0<br>
&gt;<br>
&gt; Can we infer anything here?<br>
<br>
Infer why it&#39;s broken? Not really, there&#39;s no guaranteed order how<=
br>
globals are laid out in memory. It&#39;s entirely up to the linker (except<=
br>
if you explicitly put the symbol in some section)<br></blockquote></div></d=
iv><div dir=3D"auto"><br></div><div dir=3D"auto">Ok..=C2=A0</div><div dir=
=3D"auto"><div class=3D"gmail_quote"><blockquote class=3D"gmail_quote" styl=
e=3D"margin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex">
<br>
The reason why GCC is not detecting this is because last I checked its<br>
implementation of adding globals redzones is based on increasing<br>
alignment of globals, which is really not the most reliable way to<br>
ensure there&#39;s always padding. Clang explicitly adds data after a<br>
global and doesn&#39;t rely on alignment.<br></blockquote></div></div><div =
dir=3D"auto">Ok. But, this had been done on a kernel and module compiled wi=
th clang.=C2=A0</div><div dir=3D"auto">Thanks, Kaiwan.=C2=A0</div><div dir=
=3D"auto"><div class=3D"gmail_quote"><blockquote class=3D"gmail_quote" styl=
e=3D"margin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex">
</blockquote></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAPDLWs8gt6vStwi86FT8cKEcjHkJsybSVn_q7eQKiAu7sqo0zA%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAPDLWs8gt6vStwi86FT8cKEcjHkJsybSVn_q7eQKiAu7sqo0zA=
%40mail.gmail.com</a>.<br />

--000000000000f72e0005d10c4de7--
