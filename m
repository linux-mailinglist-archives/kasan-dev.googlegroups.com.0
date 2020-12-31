Return-Path: <kasan-dev+bncBCV2XZ42VYMRB5X4WT7QKGQEZABNSMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id CC6702E7DCE
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Dec 2020 03:59:03 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id q10sf5323165pjg.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Dec 2020 18:59:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609383542; cv=pass;
        d=google.com; s=arc-20160816;
        b=dwY4Cp13nh2bVYmhIliaoEh/C3OOFtOYFCcJ9QvilrJVpDAj21w/q95KhFx8nTS0KI
         g5FuAwlN/EuOsNwRQ+JWgx81Mmt47z15vp/pRgZOhn7K4j7GgOctzwQj4JMKMf7Ntrtk
         iOMjxOFvwzIpj87zGOGfH3EhzfPGPUEOqR08ZirWKzjj9KswuOWiXb4h/0xkyKE99SfV
         QCgGZOYfFA/hfqW+Acamp+l7Bei+N0lT1m3GZuyrAVZKcj8VSP9t40SQQQjsR25VnTt5
         4ImwydhSZRfz83EFfABlaRYTzUJ95Tgjqx0gGrpJ+GbAZUhb7E5x9ulLQrPKJ667BoGq
         q6aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:content-transfer-encoding:subject:to:from
         :mime-version:list-unsubscribe:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=2RCPWsT0seQAZK0l4SF26miwVpeHr1Nwoh3FqrvUBk4=;
        b=vd/n7iVVFHLEzB1wV8YaHAaz9IcwrYMWIJDFIJV0VODUXhxlK1537uhbaJxuzssuov
         xUqcU+nP/Eu8YUx7xAlbt6g+JqBHsKp/6SJbNVCVwU/Lh3rz1ST9VoxMNsaW/AB81nvK
         fILPHA+s9tE9exY1CCd+YEG5QCKeVVBjYVWCi9/qWBgRyZjFsNGgY5BmTqN8z+8nQJx3
         RV+MbvlmAfqzZmzAwnYVxl/libiIDqtjmFlL1FVZZZ1FfS3sDnSEdi7Ke9JgA7bWWhmr
         6jeWFTJ0MSOyTpqIHBND8gF14qQmIDQ667TWrtbGBFn4PdDwjzYifkNwVbXqvdefnc/5
         ENHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UnVwhVQC;
       spf=pass (google.com: domain of thachle969@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=thachle969@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:date:list-unsubscribe:mime-version:from:to
         :subject:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe;
        bh=2RCPWsT0seQAZK0l4SF26miwVpeHr1Nwoh3FqrvUBk4=;
        b=hzk6pZ8iite8y/e5asl/1YdkWM+H4TKtqjtLP1Eik4EPN/ac/eVyeLFYh6GpdvPnaY
         MjSn0VZxIvBJwV33KjVeMWIfP2ktdEQZYHwA6WYbPKP1qLhcT1Mwc/yJLdUZ0+m4cGzg
         ZcvGTdkI+94ObqJossUexHkBLAYDUei8tQWv+cQ1gHW5XgF0FVXA8WZs/K25HgX9Jfof
         ymhagUDgpjyMF1T1JuDbvfYOQuKlUKETYIhhhcNUmUp7J8MLu0u+Xyrvx5WLoTOBwCo8
         m0iX10dwkMT/PtGAjU7eFYUM0miKDCBbhunvvrfXxn7BZKAigW+uxGoAH1RAvh6lA4n+
         mG7Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=message-id:date:list-unsubscribe:mime-version:from:to:subject
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe;
        bh=2RCPWsT0seQAZK0l4SF26miwVpeHr1Nwoh3FqrvUBk4=;
        b=eWckMFJ9q2ybFxpHj4IjThoaFCwMgK52tntsppWMdYBGxqqRLPfuttNUyokziuKAHE
         h+aP8FmisoVo8NnfhE8u2p3/zrHiBNr3kwxieD2Kr+Lrp74n34jRPQRf/R1+T42XWq4c
         YkTO0SA8hdbFy53/71ggB7SFWGNIwgob6dQdAL2/3iNadWD3lYNzYnWdmQENZxwj/5OR
         71L1EnLVyrVWWBPtFbtpqcWrHuEXep2P6lu0kEW/pLof6NO9+RxtA1ePteZ/egUvLNdE
         iWW7g1PakbE9DGwX1XXmCLQ4lKu/u5wEUutCSfkvGWItPV/24hw37dXwTa8pxC/DBvxd
         nRQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:date:list-unsubscribe
         :mime-version:from:to:subject:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe;
        bh=2RCPWsT0seQAZK0l4SF26miwVpeHr1Nwoh3FqrvUBk4=;
        b=YUjFfvYk+btzOF9GO3L7Vtxkd0RYoClUfZSLvRFu1o4E3rCZfbymVVMQIvhZUV3Q9B
         JMKq71ihdWy85gHqJrZBm6vlzk21/VbXyQqmq01I6rCqodg9oVqzEEZJo3Lr0CDU0q5Y
         xiyI20V/7bFLw3L5angyeF7SXyfqkFw960V88jt0zGkSEyyBSBSHY7kr9NeQrXmvMwM/
         dum8JYSp8U5Aj6CcQhgvN1ORqVP6wcWZJD/B65f0Pk0H4FpQ8phPflZIgR9fi9pXzFzB
         1yX6WdSoyFIz1+q1lCZQta/A6bBSL2+Tn5Kgh6pV+d7I3jUIgH76rp3r1S2Gea1hY9IX
         dsXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532w8MEZojTEpHQFo/XuQ1H7dviJJIhpGgES7mCTImdQ1tU7MgkF
	zxZ3GFdqF41ixhYypswUYHU=
X-Google-Smtp-Source: ABdhPJyAI/ZKsGSpoKqXMyGaWhmRM+USVf+kXyev3IeRfFEef1b30itYtVOiSI37ds9boOjVpt/lMg==
X-Received: by 2002:a17:902:b605:b029:dc:2263:1b2c with SMTP id b5-20020a170902b605b02900dc22631b2cmr55801800pls.23.1609383542581;
        Wed, 30 Dec 2020 18:59:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3192:: with SMTP id x140ls23224852pgx.6.gmail; Wed, 30
 Dec 2020 18:59:02 -0800 (PST)
X-Received: by 2002:a65:6207:: with SMTP id d7mr55473975pgv.92.1609383542032;
        Wed, 30 Dec 2020 18:59:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609383542; cv=none;
        d=google.com; s=arc-20160816;
        b=pJH3Vs5eJWE6FOGVD+dumZ4H2p1rtwbFeRS/RoeMWGTjORbk8Y9VAQm2WXa+pwdi6w
         K31Qybfj+TLRT+58R9edc+fn64HaClySznqvujo1G6p3Q5NDHtWS0LIyg0a9la2qM5zO
         FhXlToPVQsvbwiYWS7t5sL8cNsaOfjA+fphLToAE1FDMw++Ea8SBTYSA26/3oyhVesvG
         BjM1Zv8gpUud/O5O0Hi8VSzEECxanR0wCDKHCPF/OuSyqNpqQ0UT849MYAJ5csRUEypm
         Z0CRdQOZEkopB7GrItvef5qXY5NoH7TqJ1bRlZfwof/SLSDT4u5SEbOK+eI2gBgCC6/W
         RaYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:subject:to:from:mime-version
         :list-unsubscribe:date:message-id:dkim-signature;
        bh=mFZEHZCm/AscCTiHJwsQFqr5b6jwFC3Gk/HKYUo/A8g=;
        b=gGigt1UCqUpZiaLkDGW+J6fBnmp9MeutVcgRcivPd2NXbHUgkbR4MABSJgnJhEkpOu
         Mfr5lIe5BNu7r9D/tIa9m/P10HjqDqhxDQmTcumtSr0qjN49Fnj4RE/0g69fIo35MiJl
         NMiRfVzmIqurr2tmoXiMJImqwg0106AS6rVDzRE8nd8HYWxEPb9AaSVmHlCB5aiM665i
         5v8Ph6Htwueb3HWTtBq+mXlNxvnelna1aT8L70Glw6ZxEXDBiA/WjCAcLWZgeh4GsxN7
         OrSQm+V+NQq6xNiF0jKzd6D5lY7MrsBKEGgcwfPnP1IPRwqWEJQAUB7sY6QPvkycXKfp
         J1Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UnVwhVQC;
       spf=pass (google.com: domain of thachle969@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=thachle969@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id q32si613827pja.2.2020.12.30.18.59.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Dec 2020 18:59:02 -0800 (PST)
Received-SPF: pass (google.com: domain of thachle969@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id be12so9494896plb.4
        for <kasan-dev@googlegroups.com>; Wed, 30 Dec 2020 18:59:02 -0800 (PST)
X-Received: by 2002:a17:902:8d8d:b029:dc:4609:58a9 with SMTP id v13-20020a1709028d8db02900dc460958a9mr36982149plo.27.1609383541723;
        Wed, 30 Dec 2020 18:59:01 -0800 (PST)
Received: from DESKTOP-DI4367S ([27.3.184.35])
        by smtp.gmail.com with ESMTPSA id mq8sm7464267pjb.13.2020.12.30.18.59.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1 cipher=ECDHE-ECDSA-AES128-SHA bits=128/128);
        Wed, 30 Dec 2020 18:59:01 -0800 (PST)
Message-ID: <5fed3e75.1c69fb81.b6224.0420@mx.google.com>
Date: Wed, 30 Dec 2020 18:59:01 -0800 (PST)
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
MIME-Version: 1.0
From: "Tamika" <thachle969@gmail.com>
To: kasan-dev@googlegroups.com
Subject: =?utf-8?B?a2FzYW4tZGV2P+WKoOWbveS8muiuruWRmOWRvOWQgeaAu+eQ?=
 =?utf-8?B?huWQkeS5oOi/keW5s+i9rOi+vuivieaxgiFGcm9tIFRhbWlrYS4=?=
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ThachLe969@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=UnVwhVQC;       spf=pass
 (google.com: domain of thachle969@gmail.com designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=thachle969@gmail.com;       dmarc=pass
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

<CENTER>
<p><div style=3D"font-size: 27px; font-family: verdana, arial, helvetica, s=
ans-serif; background-color: rgb(255, 255, 255)"><font color=3D"#0000cc"><a=
 href=3D"http://theuocxua.com/getdocuments/RDyLC21sVi220VgArrgjWH7v0GXrUEq0=
t3YGOu7QnAsiqCc2VeMPimuNF7h4zmGA/U8AAAAnCdKU0dOLLBl4gxdpCw=3D=3D/kasan-dev?=
=E5=8A=A0=E5=9B=BD=E4=BC=9A=E8=AE=AE=E5=91=98=E5=91=BC=E5=90=81=E6=80=BB=E7=
=90=86=E5=90=91=E4=B9=A0=E8=BF=91=E5=B9=B3=E8=BD=AC=E8=BE=BE=E8=AF=89=E6=B1=
=82!From Tamika." target=3D"_blank" rel=3D"noreferrer">The truth.info</a></=
font></div>
<div>
<img src=3D"http://theuocxua.com/getdocuments/RDyLC21sVi220VgArrgjWPYWO5DJD=
hvCiXgAglpNUtoEWrBBBBWcQRPDBBBBHQWtb5omtVyOniCxO4wahrfzmv4UYQLFhFiAAAAevRaw=
Zr4iRZmTJ7BBBBc=3D/fcWlxICdBWCAaPGg727CFOte9Cwfgv7KVwA27SJCOokZjkcJKlsVyOxU=
6OMzvbwB/kasan-dev?=E5=8A=A0=E5=9B=BD=E4=BC=9A=E8=AE=AE=E5=91=98=E5=91=BC=
=E5=90=81=E6=80=BB=E7=90=86=E5=90=91=E4=B9=A0=E8=BF=91=E5=B9=B3=E8=BD=AC=E8=
=BE=BE=E8=AF=89=E6=B1=82!From Tamika.">
<img src=3D"http://theuocxua.com/getdocuments/RDyLC21sVi220VgArrgjWH7v0GXrU=
Eq0t3YGOu7QnAsiqCc2VeMPimuNF7h4zmGA/X2YPlsbVzgAeS9HViCHwqdY32AAAAKGs9XdClBI=
DLxQ6EvquyTUVAWBgQms07s2TZnF/kasan-dev?=E5=8A=A0=E5=9B=BD=E4=BC=9A=E8=AE=AE=
=E5=91=98=E5=91=BC=E5=90=81=E6=80=BB=E7=90=86=E5=90=91=E4=B9=A0=E8=BF=91=E5=
=B9=B3=E8=BD=AC=E8=BE=BE=E8=AF=89=E6=B1=82!From Tamika.">
<img src=3D"http://theuocxua.com/getdocuments/RDyLC21sVi220VgArrgjWH7v0GXrU=
Eq0t3YGOu7QnAsiqCc2VeMPimuNF7h4zmGA/d7BGIiBxIj04wZLPJenokIQl7sHEhFMDMImYMKN=
iC95pkkOaAy6c88MlJXBBBBJ1kS0RzGH9eOp0uDPW0NMAol78W8AfcHVUn3A9KMJmUA4W1Y=3D/=
kasan-dev?=E5=8A=A0=E5=9B=BD=E4=BC=9A=E8=AE=AE=E5=91=98=E5=91=BC=E5=90=81=
=E6=80=BB=E7=90=86=E5=90=91=E4=B9=A0=E8=BF=91=E5=B9=B3=E8=BD=AC=E8=BE=BE=E8=
=AF=89=E6=B1=82!From Tamika.">
<img src=3D"http://theuocxua.com/getdocuments/RDyLC21sVi220VgArrgjWH7v0GXrU=
Eq0t3YGOu7QnAsiqCc2VeMPimuNF7h4zmGA/d7BGIiBxIj04wZLPJenokIQl7sHEhFMDMImYMKN=
iC94F24UrfeAMnBBBBpmI8N3keqWxaijCP5y9J9Kp9BBBBJKktZSk1m633gsKAF3FPXjlR0lBo=
=3D/kasan-dev?=E5=8A=A0=E5=9B=BD=E4=BC=9A=E8=AE=AE=E5=91=98=E5=91=BC=E5=90=
=81=E6=80=BB=E7=90=86=E5=90=91=E4=B9=A0=E8=BF=91=E5=B9=B3=E8=BD=AC=E8=BE=BE=
=E8=AF=89=E6=B1=82!From Tamika.">
<img src=3D"http://theuocxua.com/getdocuments/RDyLC21sVi220VgArrgjWH7v0GXrU=
Eq0t3YGOu7QnAsiqCc2VeMPimuNF7h4zmGA/d7BGIiBxIj04wZLPJenokIQl7sHEhFMDMImYMKN=
iC9406bqmGnvDg5lsHRxCHlMLSQKFBzkbPZAZeKjOsqd3r4Khpx9WusvhZHUK72EO5Cc=3D/kas=
an-dev?=E5=8A=A0=E5=9B=BD=E4=BC=9A=E8=AE=AE=E5=91=98=E5=91=BC=E5=90=81=E6=
=80=BB=E7=90=86=E5=90=91=E4=B9=A0=E8=BF=91=E5=B9=B3=E8=BD=AC=E8=BE=BE=E8=AF=
=89=E6=B1=82!From Tamika.">
<div>
<em>*=E5=85=B6=E4=BB=96=E6=96=87=E4=BB=B6:</em><br />
<em>https://www.mediafire.com/folder/inj2vedwe7cj3</em><br />
<em>http://coduyen.info/mh/00/9&pi_n.g.pdf</em><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/5fed3e75.1c69fb81.b6224.0420%40mx.google.com?utm_mediu=
m=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/=
5fed3e75.1c69fb81.b6224.0420%40mx.google.com</a>.<br />
