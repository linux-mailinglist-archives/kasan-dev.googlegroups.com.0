Return-Path: <kasan-dev+bncBAABBHOQYD3QKGQEWPNWTWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 5573E202EE8
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 05:40:15 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id c4sf11060754plo.6
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Jun 2020 20:40:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592797214; cv=pass;
        d=google.com; s=arc-20160816;
        b=SD3uwjlIbOt9MXZj1S8CmPnWwwp1HKLlyKESgMe7Eh+BCwNxH3yuyQCvWCcQ7tcavb
         Eo2xTq0+WlPtQNAZeZzMOT/xb6rPMjxnRVuRQoSOn5hzCkzISxWfyvZYp/bQttU4Nas5
         5aAUthp4MroJ4xJRuKenLCTQYS4/cZwQxv1UjK1eNaetBVkh2DzUAF0eGTgSZrIFrV4k
         Gjeg7wGviQDnjPlp59nl92kjZEgAEmn2xAy58Kf1Ubcnqb3QtgP+DB1GmmJPR0iChoiS
         Oe3+hkqaXRQEZcgU0UZMJOGCV6MQwHkGxQPnI9/olGBrUdG9S7niTML+Jjt75lZhN00C
         iLrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:subject:references
         :in-reply-to:message-id:to:reply-to:from:date:dkim-signature;
        bh=MaR+OOCejowGT8X/gXT5XxpgT2laQSQYyHO5YBRU7RA=;
        b=L+RcDcXzyTH16ib/RU7qOTd3SAby68pbhJOJ5cLz7rZa3fBqNND/MV6thwEZBNBbOi
         1xbN5zq37nW/d68hQCgek0pmPHrD0EAJroIT7uNrAKBvz3gOlFthV/3db7HdJxgAERwi
         eJ+eTH3pqGQqyj0FgXabc4HePZ2oZnFco47pyzBWM6lSf/z42xWgXrq7BALDBykJLLfx
         EXFVvOOw/7wgsnHCEQjJ88h8zRHGucqqZvw8Fs4O0DpRcMjIWhD3gIOMKx0qBOX2qxVl
         1QUu+Xsp5+0mPrVhj4iGFpGDcpc1q2g9ijErElWW3FebLb6CkgG/A4TFkz1I5mT1ejVE
         ZMsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@yahoo.com header.s=s2048 header.b=UV+D5871;
       spf=pass (google.com: domain of c72728@yahoo.com designates 74.6.133.125 as permitted sender) smtp.mailfrom=c72728@yahoo.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=yahoo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:reply-to:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MaR+OOCejowGT8X/gXT5XxpgT2laQSQYyHO5YBRU7RA=;
        b=ePhczY4o75Nd+swHcm1Z59XTA3siUUJWAB7TL8N9YuoRCtQbqDUCMvhZDrp8CVF/wi
         KiXXtVHj4wt5icTVf6BRXOykJDXYD8tO3OXmmeDUCOQ5oH5NKJwk5RX99D95PwQdm2wU
         P0wHuokZ2TcuOBB/MHAb7shKxuXPqjT7TywHuAYnEF+RAUS2FNZEAEwK2aSxwwdw6zJ0
         9f4+urTjbnyQmeijTHXXPcWudexWLDEGCRY0Kf/Ckla9wtue9WPG06g1s3j+KEFbi+O5
         +qp4tp7GLscdlPLFpPMeXFGL+Wqm7h5CGelrj57TWeyWNiZ+Kmhjk63+jK6C1LuazaAc
         +Ezw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:reply-to:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MaR+OOCejowGT8X/gXT5XxpgT2laQSQYyHO5YBRU7RA=;
        b=QUjQ18G1PDELgo/2t018Ufm4BCJMF8bHHVpFROEc/WCSjQOOOVaRngHySbCHAL9sh9
         kptUIGpIU7IwZmYVl6H0sKDPxnEbNTGPlA7USdJqGRzpGAphQuuvfahsjFTIt0lVLRpL
         Gh/kWEwycIKSJAQjC2tYcaiAc4KpZtR0lmA9DvWk5RMExqfPWsuIT2nCJMReWC5rnHi3
         QiZCIroq2fCzSGZn3NDSGGiOZWGgvb5XzqxZr5v0yIcQOFUYoDfFaJLxFBnQIkZFBxe7
         tHG5KpSlvoQdPOmZOHZQ5ORXL/BpuOlbaoZFTyGyVhZmWuWduJPUMzCc/Yl/QDqYNlwS
         CS7Q==
X-Gm-Message-State: AOAM531rNJNoHXwm1bh9BW65gVoLDL/oizc+NJmdnZYLHXLfI2zNOP/x
	IbafE1ZP7bvVYBpN8ORefks=
X-Google-Smtp-Source: ABdhPJwKonJL2ZvBzJNTYUhmCU169vz3zjidYVkD8LZHQtAb7oJzCqxJVxJU12ngKPfh/ByqkI2ILQ==
X-Received: by 2002:a17:90a:f184:: with SMTP id bv4mr16370179pjb.57.1592797213838;
        Sun, 21 Jun 2020 20:40:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9007:: with SMTP id a7ls5865216plp.3.gmail; Sun, 21
 Jun 2020 20:40:13 -0700 (PDT)
X-Received: by 2002:a17:90a:b013:: with SMTP id x19mr16669198pjq.229.1592797213562;
        Sun, 21 Jun 2020 20:40:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592797213; cv=none;
        d=google.com; s=arc-20160816;
        b=bxLuXWUbrq5gbqibF830SjglGro6mvlcbQdSow97bO+i/p4pJiQ/H0N67NrPpjDbY1
         rlk+e+SqGPQF5Qv4IHdkU1t8jxgzexkvzLweAf3BwTLENgWkfnpEdALE9ZNqSKqDViQl
         3MHvkVtvBsIZ31xu7WFdFMfn8Cn50vQVY6b0NJZHpP9VcHaRrRCqXRxVRyAxDV7tILMK
         0C2MvBjYf8TxuMrzZEHqxrk3SYQ1GDL/r5PHWdrdEOUdLfYa311MOOdBGmEwpq2cUzjI
         8ECqg68bN96Tv/ry5Zgr5aAouS8uZ6da8EQsDgOCpEhWEhGILGu/M0XKrXJkhI0OTuO4
         4bzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:subject:references:in-reply-to:message-id:to:reply-to
         :from:date:dkim-signature;
        bh=X7c4WiLPoiXcFLJRl1K222EaId4Olunz6y9AQ+aPjGA=;
        b=tmpcLP4TB3QcBeN1Gvv+arnhsXWiwXq7asoNjaNhk4pxHcWu1JEjLbCglNRNOoEINJ
         jevdvM7vsICbeumaR1N8j9Q2klTgmkZAYY7+ZxZ+9rvfizjyqGRt1jT/kFwWhRXi/ZmI
         yKrr3tPB+FdLbBw/As+IQOe20CgP9YpM4hpIv1HcUtzMRqLD9Q2ImFTo5O/aaJcEPD4G
         tt5vB83YQrTrgrUksjjYz0eWSCjeavrXzxf878Jbigw5rBUwCvPtD5Z7vodNqe1VOXQ4
         WF0RoxOyhQmHNJcuxWitlbPkUyugdYXm2rfBmxXPLEo6V9+Lq7vowFc49cK7emzXyn1i
         fJVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@yahoo.com header.s=s2048 header.b=UV+D5871;
       spf=pass (google.com: domain of c72728@yahoo.com designates 74.6.133.125 as permitted sender) smtp.mailfrom=c72728@yahoo.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=yahoo.com
Received: from sonic313-15.consmr.mail.bf2.yahoo.com (sonic313-15.consmr.mail.bf2.yahoo.com. [74.6.133.125])
        by gmr-mx.google.com with ESMTPS id a22si943642pjv.3.2020.06.21.20.40.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 Jun 2020 20:40:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of c72728@yahoo.com designates 74.6.133.125 as permitted sender) client-ip=74.6.133.125;
X-YMail-OSG: YLHPHNQVM1nMG802pe4FM27MmWP0Ifuh_c_MPp50m3S2wXc6Mfczu033c_UGF1d
 x2kFM0Xic_m27orZpcAnV.I8jsz3v05KCoEFlg63ULcNrdmX3_xRo5CwIoH2kf4J5XVvwa9CnxTU
 L3ED7icMfh6wOLDF0cfnZ2AkYsHTo6gzLvC4p14uJXyz5wFi4kiN34qH1U58ECX3BJEe0Slmi6Z2
 2bdJ.XXOHUs73YJd3Cu48DADh5tl8.seI.H3ebaKQq3XSD9bGD1oj7CuUbFTw0TSNHISiBZ99Ks2
 HJXgbYncLsofbXWoJgkS9OgL71koSrGEp5Z0yPwF0TlmNU0q.vY.WtA9sr0Nkhs1OYkr6lzBxR1O
 Xncne0lQ2kUI3f2b6KJ7idJ4aBVA5MoN_ZftInwBDGTlpAAv47W.CnPj.gFgcL3P59pFWmxV2xJ0
 uG4.5TiQr1zfEYbX2IwnijbQpfNPWvB9MM6ocqi7RU0y7Rpw3i5WtcKAojxYG.NGnIKu8zbxQfeK
 hqA.U7iceXlYNgTmb3puhQXGAmOVbJi.QO5vZOHfp1QlOuFNknJo389CGYIqNuVdQ_pIUUZeI5lT
 U6MeViXq4vrn5VyZ23RQHjaEjOck_9mVjrczlqcaJz7LIejVJ2xvXs0SFRGWzaZ0gxWVXqn_kWvV
 hvIq21HRuI9rL0pCcqpSzHtQanFBqzW32skN6PEFEQwJvCrSXvBAWUjdyGXMWQlKviMK4FNJD1Zu
 vsXGZ2lkOc2RPnySGwoWc90KdevFVBLQFSJLjHAaKLRHz4WCUzmoOnTfIOcz3Gy5v4HH42mkzTG9
 YTK49qLEmdOx2bQvYLMsmNylXTzH7hPkKa1FMZJXYkEHcgjvKaJv5m5IpDQu0WlifsxCwugwmLbZ
 BdQ0lvB7a6uJeiK.nCuox187U4VUZTpT_uEa8WKxzAmsutqFmmcdH0Pa24_.ofv4ymb35Nug1rDc
 gU79wvO0y50TY5rTwkOxxquhl7LdGykS3XDnK4RRGBeedjD8Wex086VP_fNMAZiP_HsPRTw9q4GN
 a54qqDHVWWEjcbBXTAWHE6e631ghlKYfDiZeZcizJNLa7MnqJ_4E.VZzEMVA1nv_KIiK23cf_Xwa
 cXL9Y.dAUwr7k9yCxOIG54rsIvovN1Tsx7Gvv1uaEHllRj0VGc0Jwfgh0gsTj0D.KFiINr_qDegG
 teDKtkBGMcdZJTay6hMy9JA7wGf.gjw9b0WVPIy6IXYC94od1oquaLNps6kqArmXMMy.xJyRdc_1
 NSZ_p_qPCbkP2rlwIHI_pEkUOmpgHZMecB8._G4XPveWsr7GvnZZvNGx8_YkU65FuKJWxUy7jeb2
 ohdnr4dvBrI.OAeHeVmk4HD4jFHQi
Received: from sonic.gate.mail.ne1.yahoo.com by sonic313.consmr.mail.bf2.yahoo.com with HTTP; Mon, 22 Jun 2020 03:40:12 +0000
Date: Mon, 22 Jun 2020 03:40:08 +0000 (UTC)
From: "'Christy Wilcox' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: c72728@yahoo.com
To: c72728@yahoo.com
Message-ID: <782527173.1143749.1592797208205@mail.yahoo.com>
In-Reply-To: <1705927180.1154180.1592797171602@mail.yahoo.com>
References: <1408139245.1302051.1591161262589.ref@mail.yahoo.com> <1408139245.1302051.1591161262589@mail.yahoo.com> <368102206.1302961.1591161296756@mail.yahoo.com> <662368049.94387.1591161344870@mail.yahoo.com> <1705927180.1154180.1592797171602@mail.yahoo.com>
Subject: Re: Hello
MIME-Version: 1.0
Content-Type: multipart/alternative; 
	boundary="----=_Part_1143748_2091053298.1592797208204"
X-Mailer: WebService/1.1.16138 YMailNodin Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
X-Original-Sender: c72728@yahoo.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@yahoo.com header.s=s2048 header.b=UV+D5871;       spf=pass
 (google.com: domain of c72728@yahoo.com designates 74.6.133.125 as permitted
 sender) smtp.mailfrom=c72728@yahoo.com;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=yahoo.com
X-Original-From: Christy Wilcox <c72728@yahoo.com>
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

------=_Part_1143748_2091053298.1592797208204
Content-Type: text/plain; charset="UTF-8"

 Hi,

This is Christy, I hope you are alright. I have been trying to reach you, did you get my message? please respond back to me as soon as possible thanks.  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/782527173.1143749.1592797208205%40mail.yahoo.com.

------=_Part_1143748_2091053298.1592797208204
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div>                Hi,<br><br>This is Christy, I hope you are alright. I =
have been trying to reach you, did you get my message? please respond back =
to me as soon as possible thanks.             </div>           =20

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/782527173.1143749.1592797208205%40mail.yahoo.com?utm_m=
edium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-=
dev/782527173.1143749.1592797208205%40mail.yahoo.com</a>.<br />

------=_Part_1143748_2091053298.1592797208204--
