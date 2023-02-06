Return-Path: <kasan-dev+bncBCLYNXNHZIJBB2GCQGPQMGQELHQ6WGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2482C68B413
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Feb 2023 03:09:46 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id d25-20020a193859000000b004d88a065790sf4252092lfj.19
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Feb 2023 18:09:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675649385; cv=pass;
        d=google.com; s=arc-20160816;
        b=oYmzqfX3Ycwwfsyh5nFZfwuJs7ztc3mZen+qfAjcOOT5CZRWr36gAMXzxys/5S/ehC
         Vcg0CeilQWcHNY4y7tf82LDjyVzmA+VD4R9a0VibvxQ34axLF52S73xKo8MmyQ2iaX1l
         rZuwcPvl2ZYi/9i0pdUrtYoDdfT8aMnMCJf8R96kexHKAjipqgzsEn2jNUCghoSZyruy
         sfWmx6Jj6xzoJiIRfQajq2PiEhJYdayYKpofQa0D7dGW+DDSJZZy/FhHqrmj6lCZCBDV
         1TheTDf4Lu6w+GQbXA8NbAc6DJsSdZp73/XAPjYjVSNbTxpdP2PUoYRRD9JyZc85XYDS
         vxlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=3DQfKcV6Zndxt+NBJ0b/+1jneCvd5NTovkem9KIpUys=;
        b=rnU9y9sPYYb/AC90LLkNk1HE92UDazNWYFMYZt9qKGPYkhYz4+0oTz7o7uIkfRCrfk
         NqclaizVxd0WBLe85g/6eDRj6dHI3erj9ObqJj++SqAxNWEMjzlYchLJTWplh4tPZXqE
         EFFL+tnNGGGLEcsLbO7srTo4CDDrvT6PkzOjiwPStpJot4qIjDMzVCHsicyvCVTE0yEV
         zxGWWe80fXPS5ZDAGDJ8Fs8l6Rgn91SPvlU0Xs73Eq47imcIB9BLkTRJDBfwfoVbz6Bw
         JVb3BZ0FeZ73oe5oEyD26HUxmuVQJUnlJpyi8NP/4BgQevK82bsOQ93NKNzJzmMCQPvM
         sViw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QXVMiNv2;
       spf=pass (google.com: domain of ashielmiller597@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=ashielmiller597@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3DQfKcV6Zndxt+NBJ0b/+1jneCvd5NTovkem9KIpUys=;
        b=T+LRNKz7QOMg0KEK9PFtPLAJv1S/yayu5CwH3V1K+qudTH+0TK8lmsr1Az7F/FykK4
         Egm1X28pTYbt0Zx8PWsiv4GGRaPH0qSjwycon/W002/jz8fgpVGly6NWM/Jod9Ohxu9M
         quzB0854NzIWvqxKtjI/is+Vdx8Yz/1mG3QAuYCsoK0G58Dd1e0FjL42Es0iriqbrDZg
         OIB6/W4D6iztYHareRSR9O4nv0lBATCZzqQZYjGzOBU05xJMSWac/PDOEp0atiMzxnEz
         ODXQpeeuMVBlJrEJETUpfs15aJIBauSQe6jSw3LVt6eGRdtgBlVzCR/0qzODGz5LJ1OT
         TIsQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=3DQfKcV6Zndxt+NBJ0b/+1jneCvd5NTovkem9KIpUys=;
        b=fnm8fzlhdLX86qdwXo2Xr8YnSg7rljsuFFvIu/w8A2ua6/omH+4MUaEFQjEB2D+oJ5
         HBpCpFVV3IKMZJtt8RxEves1Csx0FCN+fAlrg2v4jdYTwJtRxR9vhmRLHZ/pZl9DQW5V
         yG5J3v43RDt5BSrO5/68147VJoHeLfFSgdqqQ/Iffd1ki4c41PTw661S/8L7IoLyzVmQ
         /Ux9E38qumvABPc6ml5g3/skGAWRKH+2XWDjiZetkequ7vWnlORMQdJHx3enKy03hy8N
         3Zg4nZnNeImCNlW96BMjuR9aWKauMjDmt+Mcaoz39nI2UsHY96xDoXXQ2M69Y/6D4M0K
         3PSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3DQfKcV6Zndxt+NBJ0b/+1jneCvd5NTovkem9KIpUys=;
        b=A0EawqZ5Myv9nUTePaYCP5CwvnHbvE4q0hYTaP/sTqt9VlDFttPvN1/5Tb4n7DCGVK
         T7Uu5V4DHKGYlEDe0R5MMjgUhFD7xJRdIwEK3cTtopXL02pVgynASprYysi/7QQTJ5vk
         u3ZsV3jPMhtNVi4KRzIgwRxfokZNlu8vE4Sl34TftsdMPbmE9dRcUGdxKg+ertiF6LCz
         iAtwYF5/MWhSjifcLAPkUBHPwjMvKwdr63V/kHpuar8nyympve2VGy+nB3VZ1WF14B6S
         pRiSqR9TywcOC38R4d0kW+1WmvPf1fChYP8EchEdoidmREVkBCvB08YmjIrBiO604XsH
         HKhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUhDs26WBw/i8H2aCSOxt5a2BDRqNcB4lmo9wWxf2nWGmR9EGqM
	NHiMT14/HG5ZDG4+DEE0cGY=
X-Google-Smtp-Source: AK7set/395SFLIPKumTxQkqruTMP2oddn5tiXHtDRMgFxeP+ec3AEBdC8u7qq1C0tFMjoCvh9ezXFA==
X-Received: by 2002:a2e:3c10:0:b0:28f:bf21:4616 with SMTP id j16-20020a2e3c10000000b0028fbf214616mr3118930lja.30.1675649385176;
        Sun, 05 Feb 2023 18:09:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ac5:0:b0:28f:4d46:197e with SMTP id p5-20020a2e9ac5000000b0028f4d46197els1325961ljj.6.-pod-prod-gmail;
 Sun, 05 Feb 2023 18:09:43 -0800 (PST)
X-Received: by 2002:a2e:b8c4:0:b0:290:5102:49e4 with SMTP id s4-20020a2eb8c4000000b00290510249e4mr7292538ljp.41.1675649383664;
        Sun, 05 Feb 2023 18:09:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675649383; cv=none;
        d=google.com; s=arc-20160816;
        b=wi0dfr2MaV9L1dLcHi2Vrk3yxogwGfAkXyWGLbuzRCPb1NEW/rjxyZUnEiPfZkfWlU
         Or090T/gFa/hkieLQvfyHd/QbrErS9KukMHi8YHjowX8A2YNB1tkNOC/NMSAsz5C3SIE
         +VvcF6ofEqwYRmiJmL35ITwhu1rXl3VYNBRDkz8Zs5CxEuKbnJGG8h8sA7mDm5Dyy2H2
         mOaBQMCCBIwFeVMCkT4BUVv4e6woxHbkqkv9ez5aKyZ97I5S86CsyO46lTHw3S4hWDn9
         yRn8URQgVeds0M5k/28VadzkM5ZIjJFv9BRObAOQ1PeVFOWUcwWzq+9mDpI/WlESDehb
         M5JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=lB6Ue8D90PIkUclXGlVDvJULUUDuNPDBZE9K6l0MQlw=;
        b=a+Z2sA2Kb8SqTJe0EawLvGGOMalb1MJLm50cCy27cNQ25qKw3XtigU6jYDgwFZ8jrC
         rd46GP3mlfuhpefQ883VP8sBe5omuVNKW6TQhRLJw8hNW/O1mMUYHB8AaR5xR5jLXyVt
         92fqlMA/+fbrT4cRkypQK9AwyXflBH7ywQ2r05QR64BUWJjgqqzlwR6D8/+4zS2ng1Bk
         wLg5RL0YLxBqNZnkG640xEhZSNxfsbr8847+d6Oz7088Su3CzRrRAixaTwA/P0msbDeB
         2++po/gH5Tt5jeBX1yuGBG/afYQQjvQjIor6QPyecD4Wee0hk2vRiz80qepWFTbnxiWm
         3sww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QXVMiNv2;
       spf=pass (google.com: domain of ashielmiller597@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=ashielmiller597@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id f36-20020a0565123b2400b004a222ff195esi416259lfv.11.2023.02.05.18.09.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 05 Feb 2023 18:09:43 -0800 (PST)
Received-SPF: pass (google.com: domain of ashielmiller597@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id mf7so30230852ejc.6
        for <kasan-dev@googlegroups.com>; Sun, 05 Feb 2023 18:09:43 -0800 (PST)
X-Received: by 2002:a17:906:34d5:b0:886:fe7f:4d62 with SMTP id
 h21-20020a17090634d500b00886fe7f4d62mr5318793ejb.305.1675649383065; Sun, 05
 Feb 2023 18:09:43 -0800 (PST)
MIME-Version: 1.0
From: Ashiey Miller <ashielmiller597@gmail.com>
Date: Mon, 6 Feb 2023 09:09:30 +0700
Message-ID: <CAHoo0mRbRDLN8YhVc-Ohx4PSO-oFU0gO_Q4VkchCh5qXVcO6gw@mail.gmail.com>
Subject: My name is. Mrs Ashiey Miller
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000003eebd905f3fe867c"
X-Original-Sender: ashielmiller597@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QXVMiNv2;       spf=pass
 (google.com: domain of ashielmiller597@gmail.com designates
 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=ashielmiller597@gmail.com;
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

--0000000000003eebd905f3fe867c
Content-Type: text/plain; charset="UTF-8"

My name is. Mrs Ashiey Miller  I Am a I bring to you a life changing
business proposal which I consider very confidential.

I wish to ask your assistance for the transfer of US $14.75million dollars
into any of your nominated bank accounts in your country. This is because
you bear the same surname as him. Are you in any way related to him? If you
are, I think we can work things out. I am an account  officer. I can
present you as the next of kin, I will prepare you with the relevant legal
documentations that will facilitate the release of the fund to you without
any breach of the law.

I  am still waiting to hear from you.

Regard
Mrs Ashiey Miller

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHoo0mRbRDLN8YhVc-Ohx4PSO-oFU0gO_Q4VkchCh5qXVcO6gw%40mail.gmail.com.

--0000000000003eebd905f3fe867c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">My name is.=C2=A0<span style=3D"font-family:Roboto,&quot;H=
elvetica Neue&quot;,Helvetica,Arial,sans-serif">Mrs=C2=A0</span>Ashiey Mill=
er=C2=A0 I Am a I bring to you a life changing business proposal which I co=
nsider very confidential.<br><br>I wish to ask your assistance for the tran=
sfer of US $14.75million dollars into any of your nominated bank accounts i=
n your country. This is because you bear the same surname as him. Are you i=
n any way related to him? If you are, I think we can work things out. I am =
an account =C2=A0officer. I can present you as the next of kin, I will prep=
are you with the relevant legal documentations that will facilitate the rel=
ease of the fund to you without any breach of the law.<br><br>I =C2=A0am st=
ill waiting to hear from you.<div><br>Regard<br><span style=3D"font-family:=
Roboto,&quot;Helvetica Neue&quot;,Helvetica,Arial,sans-serif">Mrs=C2=A0</sp=
an>Ashiey Miller</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAHoo0mRbRDLN8YhVc-Ohx4PSO-oFU0gO_Q4VkchCh5qXVcO6gw%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAHoo0mRbRDLN8YhVc-Ohx4PSO-oFU0gO_Q4VkchCh5qXVcO6gw=
%40mail.gmail.com</a>.<br />

--0000000000003eebd905f3fe867c--
