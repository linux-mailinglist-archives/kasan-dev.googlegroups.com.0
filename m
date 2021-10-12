Return-Path: <kasan-dev+bncBCB5PE6A5AKBBPH5SWFQMGQEUNVSZCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7661D42A45E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 14:25:34 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id b17-20020a17090a551100b001a03bb6c4f1sf1485023pji.5
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 05:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634041533; cv=pass;
        d=google.com; s=arc-20160816;
        b=xrtfReabxawTvBk0FbRyFL6wK1g3k0Xc5Z6O7dHSbfCaPhBvFPkAFxoRsNvH5DXk7J
         icBqCrsSF9eLs8kdOTOckWMwq9UZpmL9qGSUGj1IKMvmaQgJY13gjoOYCt1zo3cwqByL
         VIKOhvkjU3rHrUHi/MiO6S9nMbcvZ9BZfaUPr9NvtSE+wwRMXvUMhi+/U/c3ga+vf8xu
         JPBDaB0fFhAh83COu7sxG0BuXH9ndXrwXyIY4LwUT2Ds39Cb+U1WmuQk7cft7rZav5nq
         V3qiZyQ81cQ5kuHs+uqgsYWys8vDOwFrKzpH7wYJlAXagwUAoMJwSmLOVpxP5jcAcbSq
         kthg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=b8krmQeo1Rv2536ij09IngK25G40lp+sZCZpZu9++A0=;
        b=EtVDFg/EJbH1wcrhKBrOZUw3NXr+Ort9YPjtCa+qKqdXZaAiSjHSSEzVPGwilL6rRS
         bxN6ppXkW8zRJ0ey1My6JsQ4SDJm5JL+cFVynmusyBxLrjrfTu+zBnmMRKyhJreOIN7s
         WIFMDStd/yuLqkRxBsa3PtMnW2atMj+Ga3rJvLTUJKegPEBbUmb5E3jyTcll32wrpV37
         0Ba1MAuE2UpQ35gM9Ysy5bz9tIBJHsdMgxZxwOE9chsxE0xb+8TU/smFJDJnhIKtWxO4
         BDmN0/DJ/vszEbRud393tEN8PcX761ngj+b0mSvqFBAk+34dyJqaVy7QWRYHu4q5HBVh
         20tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XQ4vqMq0;
       spf=pass (google.com: domain of beliyambanyomi@gmail.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=beliyambanyomi@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b8krmQeo1Rv2536ij09IngK25G40lp+sZCZpZu9++A0=;
        b=O5uErj1k6kqrp5BI6d1ZgqIPJtBtert0XOjuyubi9t7MkpG+fviJDfzqBt6QaR1P63
         YQNZgAOSJ5kFGJiuiwCuutHyBn9It0hJv6SyfaV8eaAuLh+X3miMmdqq30QuUIsb2YNd
         731LfJWjeDw0+6t3jZJMWa62rBgN12H2zOzZpPdn7LqLwucS0tDNVt1b1Ii0W6WUwFhH
         KZcqyuiEQnPDjC8lpufpZK0xGTFpaPGxbdiP2ozkDfenBtdJYGCjRAsx62qkIuraEJZX
         DMqp8xAlrGggFfl32yETLUAPnmP3q2DXhyrX4vwJIusiE6nE9cKNeVvKH7kksTvzwZDq
         +fLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b8krmQeo1Rv2536ij09IngK25G40lp+sZCZpZu9++A0=;
        b=PbJXU78mpZUHFDhFMUv73wJeb/aiLgiRN9/daUpUmu+nN98h6kSOWe9nS2GQJ51QBY
         412ODlUk51LfdLfiW8ndrztviwo5jZrXPfQgFazVtEQsxU1KeEoo9SKQBSr1x3Cw5qvH
         J83PW5nw+AzmU7frTdR4ECOY9X1CA4MHd7wNnRlfX5bK4OeQM0abSllbSXXaTwQkmeCV
         ppYv544zBp38VgQV7lBivKYuN/LWV8JTqZc9SVp+yPR4U2JJZyQhqmLJ9+VnSmAwPOOe
         1SE6MyDITBwAn42s3BApkHEcQp0AmlWSP7TWON+TSMD0P8FdlRBf9hC10Ent3w0rfngO
         c93Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b8krmQeo1Rv2536ij09IngK25G40lp+sZCZpZu9++A0=;
        b=kUN96mT9B1+JZmDAmdv/+cu67F2WoHMGVaweKZuzzrTwD7G+9yRPgJW8ZzsQIWkpsH
         2IRhQZEQGKxktlQZRqjTe9bG+hFJv42KtH9IS9HSr24Iq/0qOm5csjv171Y5/kTJ8OZC
         qiZNaNocalIl255/CDt4dLnEIruwphd/zw/5bx1v6Bf53OTuVA1HbO1pAG1kfrTN3iPM
         vreck0DJPGYLW0xIKd/5F4Du6myBPJlqVNwvDH1S1z/ILNUeruaCm0saoG6F355EmVb6
         Sirj7RVnmV11ZcR9880zc3NSzmrkZD2fRclH0S6bYX4VPEzdaJQcz5kC6/ydSQUY+z2j
         Bckw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dDDDTY/8uPTk6EJ6v2yhW59IN3qMMleGyCWb/zHbzaAoMbhom
	p/E8EVP/yPwUrCLdp2eLXbI=
X-Google-Smtp-Source: ABdhPJwIbSR3ch37uvXASh26qq1MvUjK7QNogqzOZCaPsdOXfMtnzFmwEe8SVdR6HOX4eVoMmTNcNw==
X-Received: by 2002:a05:6a00:c1:b0:44c:ec40:b47 with SMTP id e1-20020a056a0000c100b0044cec400b47mr20932677pfj.76.1634041532772;
        Tue, 12 Oct 2021 05:25:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3d45:: with SMTP id o5ls1410570pjf.1.canary-gmail;
 Tue, 12 Oct 2021 05:25:32 -0700 (PDT)
X-Received: by 2002:a17:90a:3e0c:: with SMTP id j12mr5689175pjc.23.1634041532060;
        Tue, 12 Oct 2021 05:25:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634041532; cv=none;
        d=google.com; s=arc-20160816;
        b=ehNVABbpBwK4t9yj1NZJhLA+WCICSXx5hA1IZPGYsQQZ2FpyPzVj9MAWwvA0SB/2cu
         u7eAEFnrJ0CiI23dewh9n2YHtgcyi/1s8UWaOBvoKRGyRopyPCChcKEObAXD03Z1MJVr
         hW9WGWk7bB2dZWglNDhfafO9KudDGPpaURgWGNABAQ8yjA7/owfA6bj4cXZxKd5vNIGi
         xoC+xmu812spMheyD6p0wO5UMMS1YtpVMUGRwaKUQvLwCXfW4nFjpfcBZLeE3CgCw9SA
         16qB0+ZFsfxl7lZ7GwzlEeDQgwMIy0POi/kM9rZQnNI7RdfzjF+NEfalSvUb6ZS3jrbm
         cJFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=I5X5qdjmZC2vSdMDkqWAXqMRv7UWQ15al78ZKJ1s5v0=;
        b=e4iNGs3DTYZnX8ff0igj44DmlHLuH8CrS7iZxCBV61EP5jHnRdxqEEjvGedE6kyqTf
         xvTOZtEf+v8v0EL646z7tDsR3CSCJluBlwJlETkUmlSnLC/UtgNUr16o7DsK+JgAB7C0
         8//dzk24upCok6aYzuTEDZBAzsM1nXxWKjOK0+mVj0KiMoAlvN5tZ/PGmOg9wz6GDTrq
         StkO2pCofIlqwoN7wtoZ6ejFjctMg9u9EDGJF+uJk2na9NbMCLpGcNoYwv0rLo8AUzb0
         k8/pln6ShHxNxPKnOxowUmm4uLHksxfz0iTydZtWe9Lv2ulMnpoGodRdPfG1MLkoBkML
         BJ7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XQ4vqMq0;
       spf=pass (google.com: domain of beliyambanyomi@gmail.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=beliyambanyomi@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id c62si470301pga.1.2021.10.12.05.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Oct 2021 05:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of beliyambanyomi@gmail.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id y10so2511359qkp.9
        for <kasan-dev@googlegroups.com>; Tue, 12 Oct 2021 05:25:32 -0700 (PDT)
X-Received: by 2002:a37:9c50:: with SMTP id f77mr9202856qke.221.1634041531368;
 Tue, 12 Oct 2021 05:25:31 -0700 (PDT)
MIME-Version: 1.0
Reply-To: clemiraosman1@gmail.com
From: "Mis,Clemira" <clemiraosman1@gmail.com>
Date: Tue, 12 Oct 2021 12:25:19 +0000
Message-ID: <CAD8FkiU4tgLM7TpdV768d4DTVOzUa6+TJKgU-gv0VW81TB+j_g@mail.gmail.com>
Subject: Hi
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000000688a305ce26f13c"
X-Original-Sender: clemiraosman1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=XQ4vqMq0;       spf=pass
 (google.com: domain of beliyambanyomi@gmail.com designates
 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=beliyambanyomi@gmail.com;
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

--0000000000000688a305ce26f13c
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

5Lqy54ix55qE5L2g5aW977yM5pyJ5Lu25LqL5oOz5ZKM5L2g5ZWG6YeP5LiA5LiL77yM5L2g5Zue
5aSN55qE5pe25YCZ5oiR5Lya6K+m57uG5ZGK6K+J5L2g55qE44CCDQoNCi0tIApZb3UgcmVjZWl2
ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUg
R3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAg
YW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2Fu
LWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lv
biBvbiB0aGUgd2ViIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNh
bi1kZXYvQ0FEOEZraVU0dGdMTTdUcGRWNzY4ZDREVFZPelVhNiUyQlRKS2dVLWd2MFZXODFUQiUy
QmpfZyU0MG1haWwuZ21haWwuY29tLgo=
--0000000000000688a305ce26f13c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">=E4=BA=B2=E7=88=B1=E7=9A=84=E4=BD=A0=E5=A5=BD=EF=BC=8C=E6=
=9C=89=E4=BB=B6=E4=BA=8B=E6=83=B3=E5=92=8C=E4=BD=A0=E5=95=86=E9=87=8F=E4=B8=
=80=E4=B8=8B=EF=BC=8C=E4=BD=A0=E5=9B=9E=E5=A4=8D=E7=9A=84=E6=97=B6=E5=80=99=
=E6=88=91=E4=BC=9A=E8=AF=A6=E7=BB=86=E5=91=8A=E8=AF=89=E4=BD=A0=E7=9A=84=E3=
=80=82<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAD8FkiU4tgLM7TpdV768d4DTVOzUa6%2BTJKgU-gv0VW81TB%2Bj_=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAD8FkiU4tgLM7TpdV768d4DTVOzUa6%2BTJKgU-gv0VW81=
TB%2Bj_g%40mail.gmail.com</a>.<br />

--0000000000000688a305ce26f13c--
