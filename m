Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBJWJSCAQMGQEAHFKT4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EA18316E70
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 19:23:35 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id h24sf1482928ejl.16
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 10:23:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612981415; cv=pass;
        d=google.com; s=arc-20160816;
        b=aI8KkzfIKWUmQDm1ZzvtjQzu8iBYkHjn471mel21+WCf9ZTUhMH5eodXCl/ZtNK0Bt
         +9oO3mrv29a9MnU+dabRc3x1PZO5A0jHTE8gQrjCAksqgOw14bp4TqJ35gFnEUBgTZ77
         HJ0+fwIKW7kHdolSgi8Vxgzu5tc0qXJjM1NUDsRi/T41pnz4rFeIxq0HdUYmczVbUfcO
         DRL2mo+aZwdhjF70z92pi61iqGkgeLtqdcWcuTG0UcvZPWTmiQKzlr4mLu2psXPr9hpy
         l/62QvGnDSBpaS20g5lv3fh9yizGQrVM6Yk4n8S4I7byLNjQU7/OBzLDTNNLxEUN5uvs
         MFkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=h524v/UI0we+oroNOVZFtcIDtldcI+6zxgwVW8b+Qi4=;
        b=C04oj7IcEa4PF/TsLI0ij7mXkgXZL9RPsgMstmJIhYQt5DAEWFGiIk7iyxlvDgJjLR
         BIQoUTnPMzIGzf3xIzVHwOu0i5P6CzhbPj4QhkVOXFjUyH9+AzeQ1bkxntoaMo8DhRKW
         K5IvFy0G4l49btmFJJ/EbpSCw4r3GQQQcchY+poanCnhKpK0lM6QQ6MaXhc6BtuGzWfc
         T4scCBWubNgB3556NsD60Kn/jIM4oShLvTMhElSMH/dasNzUap6K/IUHQSwDwQ3YvP5r
         ZLTpciR1pzcRjHlZwpE7QZinU0J7+eo4POjUe1tlOueiDEHjCcrhwHkkSwNIfRliu/FH
         Iwjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rtGoG8Ry;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h524v/UI0we+oroNOVZFtcIDtldcI+6zxgwVW8b+Qi4=;
        b=f6QxOAlKnkDiI6gSp6tDGoeYj535JODlNRTe7G8llG2JmQ+xJQA5E0k+aGY0oi6S2X
         sRBNiUFoh2unMKcm8aIpTCOwYbKSUgAG1oHkMejT9Oo+FOPe2A5ns3p3+yoU11+0AiR+
         zgOifwMZnN0uN8B+MsikbJl0z3psr3hyIU5oCyZ2NNac6CgzU4rmp7evZwqYeHOK4ivx
         xX73NoiqWRegTwzi3HeqOfP7p2f1Js8u+gUSmDV3BHNDzzcjIr4eKz9py7CGEtswLdyX
         X4hLugZ3yKeP0PT5uSIbK7zwvXbcbrkBvKj5mmVOjH5y5RKum7PgbQndmSrCy4BUHxEp
         QFzA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h524v/UI0we+oroNOVZFtcIDtldcI+6zxgwVW8b+Qi4=;
        b=d0N6rZpQU+oLw3m0aaO6cgkVo0ZiD0dYyf6FxKvVdledEJVgPOndLGp3TYhaBlZDGD
         zQjIWOVZTehq6Ls0z8pWh0J4nZrqspfGNkVoXrgVsxt6dlRPXLnT0Ex2lTD9D2JeT993
         p7/BdSP4sW2Avlx5jOcvW/0Cf2H5gyc3+4mi2zfPn8/krujz9zMb6AIPSiYq3/oF4yNd
         y3lANN9X3RqP/LYfF1bX+B2H4S7ccJgBSr6ehlcxHeJvAMuiGD7hqZrTfrteAYi0hnwB
         JoH1Vrup5sUnzySRksFRviipM+NnDxDFVLOaXi5idtQTYg8oWhfjpDWgHFL9ji8bjaaA
         Bdog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h524v/UI0we+oroNOVZFtcIDtldcI+6zxgwVW8b+Qi4=;
        b=GKImjIp3UNWhELsvtB/ENcdd9fZfl4BEPEMvxhXnMdprbHmA7cveTN8z13277Czs5i
         LgwoFj1Qusp3D5x53tS04Z6LDgQDWfvLplwrTO1e7CoMKYzK3rE9k/PqMs136QO3HnIF
         +ot8HXtIvhmAmyK2qLla16b49QNca4R4MLHDCUYpup9Uydy6yyovpkN/1OAK9UrGY2zb
         qMoLyTBMD898xydL602dqAfcvnfoZVX8uRt2xciP1V4Ue1zf01+jVqc69HI/dW6ISwfQ
         1hIpUodRNB9PN7FCD3d30IhOvTC/6btKnWdDajU4YFeuwFlaBLxgsBUYUVqNmJb7z+LU
         fYuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ouwdpZLPjzqfje75A9Sw2s5evvv5MOQ+8c2mzz79ibWOlr2Jc
	rxn+bCpUQ84WgWNlnQfu7p8=
X-Google-Smtp-Source: ABdhPJwAC79cBtgpvSQ9S4BrISBCmj4qB+NMpyA62U8pnCQyTFCWExAtE70EiumkF7FX1udMgyVVlA==
X-Received: by 2002:a17:906:5659:: with SMTP id v25mr4335513ejr.8.1612981415036;
        Wed, 10 Feb 2021 10:23:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1432:: with SMTP id c18ls2328411edx.0.gmail; Wed,
 10 Feb 2021 10:23:34 -0800 (PST)
X-Received: by 2002:aa7:d696:: with SMTP id d22mr4332001edr.361.1612981414014;
        Wed, 10 Feb 2021 10:23:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612981414; cv=none;
        d=google.com; s=arc-20160816;
        b=h2k0JlTZ3L21gTz/EtsRbB+Clh+ApOsBmVhMkLTbVEt3PuDZ1yaYS1IN78qDUMsmPD
         mZifFAalXukmiNBez1gT1UiHROFrN7v2wTA63BhZS7Kk08QUS4trfuc/rtpwCyMEErRf
         NJ3c7wY1gtdrNqBoxeDC+NIl2sP2FnOZQdx+iaKeHPpqRnh1aNwzzQokmw5U4+ZfVyT/
         N5j7Nk5UhZEv0ZQGfGug56PfKxlh3yCKlbNGWpDwQcVQUo4Dk1bEAs8njbXAUN0D1rXi
         1n2Kz26Ykv3ykRcBSgfj8ky0xAAWdm5CRHJkUeX3lfbDpjTMxqg5uhPiapD4fFHReWf0
         B/Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OziyBaC2HBWCoaD3db7R8w00Gf+rPcacsA/MfSrU8OE=;
        b=WgcxiFCpfYeuRV1K/9ANvbBKfd2HCYotyXL5KOm/GDVxCrT8BO/D+jcAae407vIjwv
         ocBK+0t8ciLKR1QoEI75kGwmDAhZL9ng25Jsi5SnsNLUnRE3eDA/kYdvUbB3uYDaGVIe
         2ix1z0nwAhwQkLs2U9GRfJoiyuFgLpEnHxv5WnptlB0uHhd2oINIxzcIIygZpbl3euC7
         iwXngNNVol458ApPHpqs32gF/aN33QDRfm4dMwwRpwXpmMndsxk/hBa1jZ7Qhph95/u/
         lkBcG9MbADz04lRu0LnCtg1sz5oPxVoZJ3hdyF72PA9kkKWrHUk0VT9N02jAwGNadpgn
         wSuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rtGoG8Ry;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id c14si156811edr.4.2021.02.10.10.23.33
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Feb 2021 10:23:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id q2so4161414edi.4;
        Wed, 10 Feb 2021 10:23:33 -0800 (PST)
X-Received: by 2002:a05:6402:1013:: with SMTP id c19mr4475760edu.86.1612981413718;
 Wed, 10 Feb 2021 10:23:33 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
 <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
In-Reply-To: <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Wed, 10 Feb 2021 13:23:22 -0500
Message-ID: <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com>
Subject: Re: reproduce data race
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: multipart/alternative; boundary="00000000000031b13a05baff8038"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=rtGoG8Ry;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::536
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

--00000000000031b13a05baff8038
Content-Type: text/plain; charset="UTF-8"

Oh, I see. Thank you for your explanation.

Now I want to reproduce the data race myself based on the syzkaller log
information.
Since I can not get the reproduce source code from syzkaller tools, like
syz-repro, syz-execprog, I want to write the C program to reproduce the
data race myself.

The crash log file generated by syzkaller already shows the syscalls
triggering the data race, but all the input parameters are numbers, like
fd, and other parameters, hard for me to recognize. Do you have any
suggestions if I want to get the inputs. In the end, I can just write the
program like yours,
https://groups.google.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z4Xf-BbUDgAJ?pli=1

Maybe I am still not so clear about how to use syz-execprog. As
described here,
https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md,
I can run syz-execprog with the crash-log, and it will run to produce the
data race but seems it will not stop, always resuming the programs and
stuff. As I understand, it should produce some output file so that I can
further use syz-prog2c to get the C source reproduce program, right?



Thank You
Best
Jin Huang


On Wed, Feb 10, 2021 at 3:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Wed, Feb 10, 2021 at 6:20 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
> >
> > Hi, my name is Jin Huang, a graduate student at TAMU.
> >
> > After running syzkaller to fuzz the Linux Kernel through some syscalls I
> set up, I got some KCSAN data race report, and I tried to reproduce the
> data race myself.
> >
> > First I tried ./syz-repro -config my.cfg crashlog
> > It was running for about half a hour, and reported some KCSAN data race,
> and stopped. And these data race are also different from the one I got
> running syzkaller.
> >
> > Then I tried tools/syz-execprog on the crashlog on vm.
> > And it is still running, and report some data race as well.
> >
> > I think there should be some way for me to get the corresponding input
> for the syscalls fuzzing I set up, so that I can reproduce the data race
> reported, or as the document suggests, I could just get the source code
> through the syzkaller tools to reproduce the data race?
>
> +syzkaller mailing list
>
> Hi Jin,
>
> syz-mananger extract reproducers for bugs automatically. You don't
> need to do anything at all.
> But note it does not always work and, yes, it may extract a reproducer
> for a different bug. That's due to non-determinism everywhere,
> concurrency, accumulated state, too many bugs in the kernel and for
> KCSAN additionally
> samping nature.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2BnaqJOptZa2e1%2Ba9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ%40mail.gmail.com.

--00000000000031b13a05baff8038
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Oh, I see. Thank you for your explanation.<div><br></div><=
div>Now I want to reproduce the data race myself based on the syzkaller log=
 information.</div><div>Since I can not get the reproduce source code from =
syzkaller tools, like syz-repro, syz-execprog, I want to write the C progra=
m to reproduce the data race myself.</div><div><br></div><div>The crash log=
 file generated=C2=A0by syzkaller already shows the syscalls triggering=C2=
=A0the data race, but all the input parameters are numbers, like fd, and ot=
her parameters, hard for me to recognize. Do you have any suggestions if I =
want to get the inputs. In the end, I can just write the program like yours=
,=C2=A0<a href=3D"https://groups.google.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z4X=
f-BbUDgAJ?pli=3D1">https://groups.google.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z4=
Xf-BbUDgAJ?pli=3D1</a></div><div><br></div><div>Maybe I am still not so cle=
ar about how to use syz-execprog. As described=C2=A0here,=C2=A0<a href=3D"h=
ttps://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md"=
>https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.m=
d</a>, I can run syz-execprog=C2=A0with the crash-log, and it will run to p=
roduce the data race but seems it will not stop, always resuming the progra=
ms and stuff. As I understand, it should produce some output file so that I=
 can further use syz-prog2c to get the C source reproduce program, right?</=
div><div><br></div><div><br></div><div><div dir=3D"ltr" class=3D"gmail_sign=
ature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div><br></div><=
div>Thank You</div>Best<div>Jin Huang</div></div></div></div><br></div><br>=
<div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Wed, Fe=
b 10, 2021 at 3:23 AM Dmitry Vyukov &lt;<a href=3D"mailto:dvyukov@google.co=
m">dvyukov@google.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_qu=
ote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,20=
4);padding-left:1ex">On Wed, Feb 10, 2021 at 6:20 AM Jin Huang &lt;<a href=
=3D"mailto:andy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.c=
om</a>&gt; wrote:<br>
&gt;<br>
&gt; Hi, my name is Jin Huang, a graduate student at TAMU.<br>
&gt;<br>
&gt; After running syzkaller to fuzz the Linux Kernel through some syscalls=
 I set up, I got some KCSAN data race report, and I tried to reproduce the =
data race myself.<br>
&gt;<br>
&gt; First I tried ./syz-repro -config my.cfg crashlog<br>
&gt; It was running for about half a hour, and reported some KCSAN data rac=
e, and stopped. And these data race are also different from the one I got r=
unning syzkaller.<br>
&gt;<br>
&gt; Then I tried tools/syz-execprog on the crashlog on vm.<br>
&gt; And it is still running, and report some data race as well.<br>
&gt;<br>
&gt; I think there should be some way for me to get the corresponding input=
 for the syscalls fuzzing I set up, so that I can reproduce the data race r=
eported, or as the document suggests, I could just get the source code thro=
ugh the syzkaller tools to reproduce the data race?<br>
<br>
+syzkaller mailing list<br>
<br>
Hi Jin,<br>
<br>
syz-mananger extract reproducers for bugs automatically. You don&#39;t<br>
need to do anything at all.<br>
But note it does not always work and, yes, it may extract a reproducer<br>
for a different bug. That&#39;s due to non-determinism everywhere,<br>
concurrency, accumulated state, too many bugs in the kernel and for<br>
KCSAN additionally<br>
samping nature.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnaqJOptZa2e1%2Ba9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLY=
Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CACV%2BnaqJOptZa2e1%2Ba9pNYP7Wh5yLwKtDSgzEz7yQa=
TB4uzLYQ%40mail.gmail.com</a>.<br />

--00000000000031b13a05baff8038--
