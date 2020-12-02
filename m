Return-Path: <kasan-dev+bncBCH2XPOBSAERBMUXTX7AKGQEFJ7XY3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D582A2CB663
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 09:09:23 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id f15sf582766oig.11
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 00:09:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606896562; cv=pass;
        d=google.com; s=arc-20160816;
        b=C3ePCD4j3jZieBlV4H1TVkGoRs40lC3Orwy/YnZMCPygX+r6Q0XYY8ZPDXpW4EMWx6
         nOXbjekghoG6gpEn3fWJF1k/g5pW2TrJG5v17lqFbukeh7qh1e1goofLz6bnbkxhQfHe
         30W3SiLjTSS90IzRiDR8BFBx1mmIjIstkRebbJs+x6jrweQ7JiUG/EAKQOt6tjSQgKFz
         mi4Dxug5ZORoe3tnW22wOSAEcGY3BROgCpcssY6anccal4Xp3jZqi2nZozf4OQjgbCco
         UDgQZysn5YfWZ11itaF/r2nxTWHRGCtEQ2E9WzBpWA1028hsQwm0SnynbMrQjkdCsGiw
         9dbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=TVeZwvBCTq2V8MPVd2fvFyByUj3g6bzYHLW77QAo928=;
        b=RJ5DdJ52Xvmg1xrGUAWbd2z54C02HSxEnc02HdWby7l/0tclKGi6/2mU4wLxGi7wPt
         ZGMQBxPmiwVZBBSZRTquim2dmgLSRjgtZzhxMQrVyWsxuF+fc4CEVvHgOxkwtayieRXa
         s/FWjZcT/kKHJeuLqFlCGBGbr8aLnmsvBnYSO2P6UmsopTQm666y4hbrw/oGh4Q5DjkK
         SO+A6JAfXkYmGOiHnrGmEXfA53gbz8QVSkm83mYyODgwSzuWUco6U+cWPdkI1g8Z4PAH
         DwWeGbC3I/LRKm+1FuK4D2TPccbYamWDBv/q981jUtf2dq/s6LFf1YEWInvI2cjWvamB
         0iZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eWjMspC4;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TVeZwvBCTq2V8MPVd2fvFyByUj3g6bzYHLW77QAo928=;
        b=qIZMUX9Mpq7A3BjX5PMU8LHd4bdet0EjnP1fUKYZezXUkrYPEePSs5CXR8Q4dWLcVc
         G49h0SSCKOjvVCD5pVF1EEjhr8rclJQFYU1apEvD8Rw2EKHhvckHpBgg5Y8z6cP1+FZw
         OCVVOmDYO6GGQOgj8yGTsEA++RuaIiMUB7dArcA2owmeYih3dHIIy1/jebvidoCPHbg9
         ETrfIZzRpqTmgUMPzOSZJS/Jk0bDVFdhOnTaVDlLN7xY8au5+OIbvT7r6LY4aWIE98/x
         IUmHNyfSJITplomDoFOI6YqfaJLw1rOqH0aJ4ZnFG8GOxS76NQAMEufFa9cbNFGhR1MT
         XsMg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TVeZwvBCTq2V8MPVd2fvFyByUj3g6bzYHLW77QAo928=;
        b=HcADO+968Np/0DDvgvnV5lwoJi0zxy78kPrwfyjZOeAF3VTBI7UvDZIEgtQlg0z5FN
         94chVETJQT/IbIypap5wnU/OzMzNgomDACYeR67z5UsxzXnJU2Jzt5RGquJnSgfMq0ew
         Voa01kNEujwzeYJXEji5/g/EKTdnMe8sB9ZzC93HOvPzvt6U29WQew/cetd9NYip49zT
         hNlcz/1so95b9mYhctWujrbKdfpK3LrSmOgymXl4A0f2OLljNwVplmjQVpGts3SKiqOQ
         cCoXDhHdysKORfGuMScrKofmlP0I9I+8uIteM4xkZftBeOXWTvBKw0c4p4HJfWkrMABK
         u5kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TVeZwvBCTq2V8MPVd2fvFyByUj3g6bzYHLW77QAo928=;
        b=RAhjt2P9plQ7aZ0QFAbOhnu/1+u3hBN2/kupqzT4X0cOHgRgBRqc1YEZrYZW6tVucv
         aIVJFgQxg0Z2+AtGSc/Gy7l17cniyV10M71LL+pZ2QXHEn1QJTLQ85t9fzPV2+QOCb27
         jL53nCoKUFN4PY9JNJivXC/VMHUIE19ykFNPbBPoK4iWXiSm9STz8Gy1tM/N7aVXnIX4
         SK3VbdVN5X921D6brSaNsIujCh/bz+CleOQyBQymlGT1XGVsFNOlGBa2XuglZf/u0aF5
         Vfde0txqz9q1733YbZkpykOFjhQEmo6CvCWFRBh7Udsw0LW0074LNMGHFAF8PEfEMPQQ
         0hQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533D0gf9gtqRUnBHPtiz8A6q56YomkAvtKRRJDDthkbjlMEEovej
	3ap7NbUeQvGvfxiI4vQQ0nY=
X-Google-Smtp-Source: ABdhPJwH5LSV6e9Fg9FRBRoXZRNWMwKcUlI1p2dBlkPFFZIJ+LRafth5YugJRNa2pjKoFvRQBTN38A==
X-Received: by 2002:aca:58d7:: with SMTP id m206mr821674oib.0.1606896562769;
        Wed, 02 Dec 2020 00:09:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f1b:: with SMTP id u27ls203920otg.5.gmail; Wed, 02
 Dec 2020 00:09:22 -0800 (PST)
X-Received: by 2002:a9d:69d2:: with SMTP id v18mr1036639oto.165.1606896562350;
        Wed, 02 Dec 2020 00:09:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606896562; cv=none;
        d=google.com; s=arc-20160816;
        b=oMtnAbzK7hgGz6BgQurEJTcem2JTDquSkv/gKXUptVN36aVSKM+Y/nAQxPr6Irrt6b
         BqsLJvXPK7JzHsC5suRvvK/H1RlnO7F0HM3yszr1JNPPSA09dS1M+ETlyTrETrWhblvq
         tKoSoLBmc7sFpJszYuxHOIIMm3H0dBCHgAKIO+qKmG63hZZjl5rEcDStA3pMxsPuaQlT
         qKGgiQcabFvAiKR3ECuKxRp3wnGKgiwB2joxbhD47b+G0CwzqE1r5STjOzD5IY0KjwxJ
         OnFJQseClTdgZRSmGkgdQVZfGMwaz/PTXm7t99jPv13AZDoaG94hciKc5nKZs9fcBn0F
         KzKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=b9Ey6z/bSweBIjDeGqhGj9J7oiz9AjN2CZ0WHXNdL8U=;
        b=Yu0M0gfG06YuP6jJTGosjZOIk/Z3A9hgwUDzT4+2mHSOvfTBRo5dueapUD/BLF3keH
         lmzaWws4xJ7LUpAC9KLJuED3tgKirQv1PIEeJFhU+A3WtGP7PhaxDt5/kexVt8MfkHJ7
         E7nK1b+ZZ/IO1ewS/hik3Wt7qtAvDPVdwRjAeJ3RcEipFCCazNzO57x/HmF0c9KvRg4H
         p+UfUlGBu4iNDxs+x3AUYJZ5Yfh4kBWBoo7LRGQdUi56k057IDWhlYxozfgeV+J6plpW
         iHo9f2rH0WdpfhtKf+IebUkV5waR0UdEhC6dAG3nfQD9UoGmnKpDSk1xWcaeedFcWFmS
         tL9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eWjMspC4;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id o23si67613oic.4.2020.12.02.00.09.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Dec 2020 00:09:22 -0800 (PST)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id g15so824551ybq.6;
        Wed, 02 Dec 2020 00:09:22 -0800 (PST)
X-Received: by 2002:a25:c343:: with SMTP id t64mr2896425ybf.94.1606896561919;
 Wed, 02 Dec 2020 00:09:21 -0800 (PST)
MIME-Version: 1.0
References: <8f21ac5c-853e-47b6-a249-0e0d6473c4e5n@googlegroups.com>
In-Reply-To: <8f21ac5c-853e-47b6-a249-0e0d6473c4e5n@googlegroups.com>
From: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Date: Wed, 2 Dec 2020 16:08:56 +0800
Message-ID: <CAD-N9QXH0uC40gOcp9h7Z-d3KdzeFAvfgYvJL_DKC4ceR--wDg@mail.gmail.com>
Subject: Re: Is it possible to reproduce KCSAN crash reports?
To: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="000000000000c39bca05b576c2a9"
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=eWjMspC4;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
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

--000000000000c39bca05b576c2a9
Content-Type: text/plain; charset="UTF-8"

+kasan-dev <kasan-dev@googlegroups.com> mailing list

On Wed, Dec 2, 2020 at 4:08 PM mudongl...@gmail.com <
mudongliangabcd@gmail.com> wrote:

> Hi all,
>
> I am writing to ask the possibility to reproduce KCSAN crash reports. I
> once picked up one KCSAN crash reports and tried to reproduce the crash
> with logged syscall sequence. However, no matter how long I took (with
> thread mode, collide mode, repeat time on), I cannot see any crash report
> appear. So my questions come:
>
> 1. Is it possible to locate a PoC from the log file?
> 2. If the answer to Question 1 is yes, is there any guidance or tricks to
> help reproduce KCSAN crash reports?
>
> Thanks in advance. Looking forward to your reply.
>
> --
> You received this message because you are subscribed to the Google Groups
> "syzkaller" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to syzkaller+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/syzkaller/8f21ac5c-853e-47b6-a249-0e0d6473c4e5n%40googlegroups.com
> <https://groups.google.com/d/msgid/syzkaller/8f21ac5c-853e-47b6-a249-0e0d6473c4e5n%40googlegroups.com?utm_medium=email&utm_source=footer>
> .
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAD-N9QXH0uC40gOcp9h7Z-d3KdzeFAvfgYvJL_DKC4ceR--wDg%40mail.gmail.com.

--000000000000c39bca05b576c2a9
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><a class=3D"gmail_plusreply" id=3D"plusReplyChip-0" href=
=3D"mailto:kasan-dev@googlegroups.com" tabindex=3D"-1">+kasan-dev</a>=C2=A0=
mailing list<br></div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=
=3D"gmail_attr">On Wed, Dec 2, 2020 at 4:08 PM <a href=3D"mailto:mudongl...=
@gmail.com">mudongl...@gmail.com</a> &lt;<a href=3D"mailto:mudongliangabcd@=
gmail.com">mudongliangabcd@gmail.com</a>&gt; wrote:<br></div><blockquote cl=
ass=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid=
 rgb(204,204,204);padding-left:1ex">Hi all,<div><br></div><div>I am writing=
 to ask the possibility to reproduce KCSAN crash reports. I once picked up =
one KCSAN crash reports and tried to reproduce the crash with logged syscal=
l sequence. However, no matter how long I took (with thread mode, collide m=
ode, repeat time on), I cannot see any crash report appear. So my questions=
 come:</div><div><br></div><div>1. Is it possible to locate a PoC from the =
log file?</div><div>2. If the answer to Question 1 is yes, is there any gui=
dance or tricks to help reproduce KCSAN crash reports?</div><div><br></div>=
<div>Thanks in advance. Looking forward to your reply.</div>

<p></p>

-- <br>
You received this message because you are subscribed to the Google Groups &=
quot;syzkaller&quot; group.<br>
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:syzkaller+unsubscribe@googlegroups.com" target=3D=
"_blank">syzkaller+unsubscribe@googlegroups.com</a>.<br>
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/syzkaller/8f21ac5c-853e-47b6-a249-0e0d6473c4e5n%40googlegroups.c=
om?utm_medium=3Demail&amp;utm_source=3Dfooter" target=3D"_blank">https://gr=
oups.google.com/d/msgid/syzkaller/8f21ac5c-853e-47b6-a249-0e0d6473c4e5n%40g=
ooglegroups.com</a>.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAD-N9QXH0uC40gOcp9h7Z-d3KdzeFAvfgYvJL_DKC4ceR--wDg%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAD-N9QXH0uC40gOcp9h7Z-d3KdzeFAvfgYvJL_DKC4ceR--wDg=
%40mail.gmail.com</a>.<br />

--000000000000c39bca05b576c2a9--
