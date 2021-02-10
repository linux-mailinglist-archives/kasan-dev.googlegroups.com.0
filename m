Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBIO2RWAQMGQEY6DVM3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 50921315EDE
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 06:20:34 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id z188sf3700298wme.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 21:20:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612934434; cv=pass;
        d=google.com; s=arc-20160816;
        b=INNcVpMwDT5AgXOz7ZYkErsv7V2oNNtTFhhOSrno1ELgmaYHDLoNrDuf2l+QkigfpF
         quAI2Z+LIS5hcDeNSuWTwSgm1WB8RYtqLYoEc6bHqzLU1SLywjeRL/hv/fVIPiUTXH29
         qrE762G8/pJ3P6X6FUuChN0wyT/vXEzlNRQQMTx4SFbK23dmx6qYfnsbZCbzCHFeb6gT
         7g2t4AvZoHI2rZmZ08TE1yiTdU4erYWh1WFp21cE92of16koz9cITjuejMwYz8E7dFWm
         nK0r7TOYyTQim73UYZWGl0kCvNviKiG4PvYtaeMDSm+Yc7H3kgPM7b8pZ+ZHBKlajAXS
         k8Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=qk6hx30kWpGfWYhznTquLkW3N4yi6EtkhIzPs8vuRJA=;
        b=KgcJP7nGpsQ70AFhDe6XcE62VES+Nn1uHvjYl0UToZw7IUGCnmB58/+4tfI6MqsS37
         JQipTlcerocVTTj4mHI7Zm4UiLMKt3L5QlFCAH4o3nf4IkYTqoasZRkofzUEGa2sWWcV
         5O1eNKxGG6KZuSOia2TkLPRZPIw/cJhpgCzDfEg/ZGl9wTYIQS91fpABLjCO79gMDoUW
         XLyGu7TNXWEM5J3ullZ4TCTGLUu1FWsjEk/t5RT3LcKQ7O3MzlWbEp4EgUd0C/PUT/yc
         MOqQUoJhbbAYtMdQotvpcEggG1LFu61uqyDWMgacyAMie2ZJC46nccMP8VNMLtaVGD08
         mUjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XHtOUrZd;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qk6hx30kWpGfWYhznTquLkW3N4yi6EtkhIzPs8vuRJA=;
        b=QKaN8RP5Qt3d5rBUDiTLhG0rKJyVgsZTaaU4MZr3j8bXr57nUD2e76J/xW8pb/IKZL
         f3E2JzGn/vy98Js+QznLL8Ws56fB76DMyrdFXOQz6oMdqq1/FQ3RS4PYceJTEz1A9T9m
         BYdRvjwWO8KssrYK2iORDs5w7zhT1ibRtyP7WDhpAR7q6lh/0j2sxgPKOoyE6/1btwex
         y5XNtPBy1VmvMMBOrFOsv1BbNHl6Zozt/yxHAQEf5Q1q4PxSYzSMn/Rk64gBXQgl6iBi
         EmaTaKrgOloEtyVdi5HKwDEBw8JlGgZLtgfd0gOsEe7Mr8Po7ObL8Pin1xZDzunQz8DB
         JIkA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qk6hx30kWpGfWYhznTquLkW3N4yi6EtkhIzPs8vuRJA=;
        b=T8cXOp971uv1qhwgUDNIlIONry0/dmTjbWxWxVJQHhSWWp4FtmGbz2HSMNmbUxKDfV
         U+S9w0pH42wxkupQfOdT0Cd6979u8jWO/WauMBsEKniHPp1Wgoet8AfCEi0g5p+4jOjM
         6Iz5sbHwqP02g8MMae+Tcz0FRfJtuki1y5GgqdCato0P/4OwyBFxyN0pVEJBBt//fhf6
         Ge05v2n4YkgYf1N8trFE9h5lZxPfgo/b+O4wej7AcWVnMgAvhm/07narGvH4roLpMgex
         lGEV7rCA6wiDfOONNSANjyr+vyUpjUBdfCYAo64axEDTL9UA9O1SOJIH1mmpAf0sBUoX
         r8qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qk6hx30kWpGfWYhznTquLkW3N4yi6EtkhIzPs8vuRJA=;
        b=HOVeaz6slBb93OVF7gL9ot/QQMLCuB1b/wOApFFCY9cyqvh0SwJWBZXFy/2sfRMLgZ
         Y0arB1KFvpvcZarGqFV5/IKF67AXC4z0PYi+TZYEkwjC2ztBby/qVWA1E3EHYzj9su4X
         0gdr7Ds5I1YwfRd5Lky7ltVw5b55wa0yXwzCFxwaPWka2JCofM8w0DvTQTdnMaFG2PKb
         O/QaxuwE9K1jqAOyBIM0Xfro+S3x8k1g2HgPtLdZDpXI6wbjbHdOphPaAz4GUSenLNx/
         k6in9z1aCvEz5onj8tfVr+4kcITycmF+ftN3EpUe6xsRwdg7nCi3BNFnNOvRsCAsnVar
         WHXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WcUpPt9GHZmbLIpxSKfBQH0hViRMKkKFF/TLcIVGEiLjqWHHW
	FOmSX+zJ4bP1vUlSBRXp4r4=
X-Google-Smtp-Source: ABdhPJwTpKxTvp65UJ4vyxj8tYIJL341p+YReWmp32xiVI/iHujgY3ILODglpYZd5jJXwy4pjYStWw==
X-Received: by 2002:a1c:20cf:: with SMTP id g198mr1135643wmg.173.1612934434084;
        Tue, 09 Feb 2021 21:20:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4d02:: with SMTP id z2ls844450wrt.3.gmail; Tue, 09 Feb
 2021 21:20:33 -0800 (PST)
X-Received: by 2002:a05:6000:1788:: with SMTP id e8mr1534874wrg.171.1612934433069;
        Tue, 09 Feb 2021 21:20:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612934433; cv=none;
        d=google.com; s=arc-20160816;
        b=lmIXHse3bv8xoCUe/pFkG0l2nwpQC16Jr/NpNJh75U2JhecIY4YfX6TidgRWPakQ6v
         xcZTcRTjHa3GgkteVj8/930jum1a1/7kxD9AZpNrX23H9dM1fhF7GXMZEbwnIaqo3bzJ
         xxbjpUPibhnv2NII02cCraEfB4NF+68REEJqvoAC2CHZ7M0qGFmDgNtnOh+Tg5Ux/w35
         3HsegF562ioZoGBY8viCyLWKic0LE3R/GQHnUcY5e9wdGlWPm/o1E5hCfzDOuFxsxBEK
         5u+NjncGoh1v8D0pSXxM5eyMhtDo3kT32c7gGJA/6sqjZdrkb4Jk1rb/JaT4+0rt9lkI
         sRAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=DJ8lPzk0+bLKPqgqkDTiqpj+bJ31E2iGg+Hd8t5uOPY=;
        b=YSJ1hF4Wz5qyBFyxJFWTopNNZJUMe+GIGi7Nej0oKwxQIXHX+mL6eBzDYgGBc3Mb/b
         TqGK8/CBrsqzwSTde5dtojx+33dm5TY2n4Nn1/MIN8TCn/WiimtBgFToGDS3g/RRIAjT
         TqFNk5cWxGxUe8dIo+HwwcMSJyO8TjXdpVauaMPE+b2nGnt6iilWGwZg4+GlDCh8L1rK
         Iqh8mqZgPMTNWj3rg4AiIJ8vwW8kikznp3dTaWiOmd+Y/GDznaUaVVMOjR0QWczy7ykL
         hLFqWxtvFfeKAlvquDAhmhXigtpWcy8XGZ/ifjdbanl3Q81tuopJ+INP1JjUPtPEvpiw
         HY3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XHtOUrZd;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id w7si27733wmk.2.2021.02.09.21.20.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 21:20:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id w2so1637990ejk.13
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 21:20:33 -0800 (PST)
X-Received: by 2002:a17:907:9483:: with SMTP id dm3mr1240222ejc.120.1612934432493;
 Tue, 09 Feb 2021 21:20:32 -0800 (PST)
MIME-Version: 1.0
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Wed, 10 Feb 2021 00:20:21 -0500
Message-ID: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
Subject: reproduce data race
To: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>
Content-Type: multipart/alternative; boundary="000000000000e513f105baf48ffd"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=XHtOUrZd;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::633
 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000e513f105baf48ffd
Content-Type: text/plain; charset="UTF-8"

Hi, my name is Jin Huang, a graduate student at TAMU.

After running syzkaller to fuzz the Linux Kernel through some syscalls I
set up, I got some KCSAN data race report, and I tried to reproduce the
data race myself.

First I tried ./syz-repro -config my.cfg crashlog
It was running for about half a hour, and reported some KCSAN data race,
and stopped. And these data race are also different from the one I got
running syzkaller.

Then I tried tools/syz-execprog on the crashlog on vm.
And it is still running, and report some data race as well.

I think there should be some way for me to get the corresponding input for
the syscalls fuzzing I set up, so that I can reproduce the data race
reported, or as the document suggests, I could just get the source code
through the syzkaller tools to reproduce the data race?



Thank You
Best
Jin Huang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2Bnar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG%2B0JRP0%2BiUvh_KQ%40mail.gmail.com.

--000000000000e513f105baf48ffd
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Hi, my name is Jin Huang, a graduate student at TAMU.=
</div><div><br></div><div>After running syzkaller to fuzz the Linux Kernel =
through some syscalls I set up, I got some KCSAN data race report, and I tr=
ied to reproduce the data race myself.</div><div><br></div><div>First I tri=
ed=C2=A0<span style=3D"background-color:initial;font-family:SFMono-Regular,=
Consolas,&quot;Liberation Mono&quot;,Menlo,monospace;font-size:13.6px;color=
:rgb(36,41,46)">./syz-repro -config my.cfg crashlog</span></div><div><span =
style=3D"background-color:initial;font-family:SFMono-Regular,Consolas,&quot=
;Liberation Mono&quot;,Menlo,monospace;font-size:13.6px;color:rgb(36,41,46)=
">It was running for about half a hour, and reported some KCSAN data race, =
and stopped. And these data race are also different from the one I got runn=
ing syzkaller.</span></div><div><span style=3D"background-color:initial;fon=
t-family:SFMono-Regular,Consolas,&quot;Liberation Mono&quot;,Menlo,monospac=
e;font-size:13.6px;color:rgb(36,41,46)"><br></span></div><div><span style=
=3D"background-color:initial;font-family:SFMono-Regular,Consolas,&quot;Libe=
ration Mono&quot;,Menlo,monospace;font-size:13.6px;color:rgb(36,41,46)">The=
n I tried=C2=A0</span><span style=3D"color:rgb(36,41,46);font-family:SFMono=
-Regular,Consolas,&quot;Liberation Mono&quot;,Menlo,monospace;font-size:13.=
6px;background-color:rgba(27,31,35,0.05)">tools/syz-execprog on the crashlo=
g=C2=A0on vm.</span></div><div><span style=3D"background-color:initial;colo=
r:rgb(36,41,46);font-family:SFMono-Regular,Consolas,&quot;Liberation Mono&q=
uot;,Menlo,monospace;font-size:13.6px">And it is still running, and report =
some data race as well.</span></div><div><span style=3D"background-color:in=
itial;color:rgb(36,41,46);font-family:SFMono-Regular,Consolas,&quot;Liberat=
ion Mono&quot;,Menlo,monospace;font-size:13.6px"><br></span></div><div><spa=
n style=3D"background-color:initial;color:rgb(36,41,46);font-family:SFMono-=
Regular,Consolas,&quot;Liberation Mono&quot;,Menlo,monospace;font-size:13.6=
px">I think there should be some way for me to get the corresponding input =
for the syscalls fuzzing I set up, so that I can reproduce the data race re=
ported, or as the document suggests, I could just get the source code throu=
gh the syzkaller tools to reproduce the data race?</span></div><div><br></d=
iv><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_signature" data-s=
martmail=3D"gmail_signature"><div dir=3D"ltr"><div><br></div><div>Thank You=
</div>Best<div>Jin Huang</div></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2Bnar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG%2B0JRP0%2BiUvh=
_KQ%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CACV%2Bnar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG%2B0JR=
P0%2BiUvh_KQ%40mail.gmail.com</a>.<br />

--000000000000e513f105baf48ffd--
