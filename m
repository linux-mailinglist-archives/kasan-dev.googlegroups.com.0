Return-Path: <kasan-dev+bncBDB3FA7TTYFRBU573CHQMGQE6AZR5JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C4604A3419
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Jan 2022 06:19:16 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id e15-20020adf9bcf000000b001de055937d4sf3208167wrc.13
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Jan 2022 21:19:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643519956; cv=pass;
        d=google.com; s=arc-20160816;
        b=JfgFiqI0emJZxDe7JbZ9eUplMlgPlO29yV4I6LBVvE3ohP3q2qTBUAXBul8d+LpGRt
         CNXO/HMbadd+7YHXQbMlBjv8Omy677OzxmRoOpYjeouNDJlrBv0RWX3/9HNgGalq1kRZ
         uahnD2P8DKO62hoRPbpT4sE89TrYWa5ZC+3ftAA0JumCvz0LV/d0ZVaS2W1hKAk1Stnr
         LTNIyu/SHYeyGlikjiU/6Ef0+4OWOxpK5FdYC+lMB6PHHrARVUIKonLATtHNbEJyILuX
         Cwo5z8cUm3qM0YazfOevuNWY1lPKGxqOJYY2JCnF85IBzpdNiul++LMNUlUCzULW5HE/
         g8fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=1RYOmljHlNWmHppmrjEYf8R4bs8uy1CSnwfzBiicQtY=;
        b=sEuHwGhxh/3ssSfrxNuQLmwPbtTX0yM3LmTIWtk8GVE2h1aHnwf+vPkENgQTZCVn/h
         I/hTm0bnV5FkYFYEKTlIbsNVpV9LLu+ZXV/FKqBN+2MRKWK6u9Hjz8Zkf4hv2ptnTfF8
         ktoIiP8Ulv7VR8U5JgS+HBIsqFrNjEqTJdUNPBGwwqVC3mBbnVDfj/iayb/joufHQUlg
         ADoh6Wjld33vD9RU7HaC3Bs/a4xgKBruyS3y1oreoMDkK7ui2Pq2d92oJHKtjlSoF9rM
         H72rNbnDjwcNR2pUFPTEbmCaXNs/OxlZQI7fYclxDfWbutUixTRF4aoqjClFVGb/wY2/
         990Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mCsmFsCC;
       spf=pass (google.com: domain of jj2hhenry@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=jj2hhenry@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1RYOmljHlNWmHppmrjEYf8R4bs8uy1CSnwfzBiicQtY=;
        b=M2E2sbT/ox1J/2LMvm5BRCjhfBOMg0z/uqK+IeL4SdQKpwtPiPY7pd1zVUDvXCicOY
         27IXcA3fPduCxevXi1QgdvcXp82Biu8ItOPcPNg4BRJY+X2kkASOBvJ4jfecTpAwQrlV
         eGoQLLEHDpMMMlA7yOVwK2yj7FwlS/6d1MsLPiGID4DcXM/umXdlEVoEnytGlpAb7q7M
         tBE/+29mUJlE80mCFGaDx7Rwzr85QBkJhdpaedrkFZogxWFtTctnGmUQccSQL29BNxpt
         aDQYLPacj0/JyCiVg+gJ4WCrDpwJYYAQJPz+F7g6M+evcgT7WiM63zsCIiVS6HRjsYhR
         i7LQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1RYOmljHlNWmHppmrjEYf8R4bs8uy1CSnwfzBiicQtY=;
        b=oOEig0GrNOcRW5/uw731x1Qg//BtvYmUVyaLcGdapTwHLQO3nlu4oCS3pCaY+v0POl
         QQBybQH7WtwnyomwQ6Ln44qZ3sYZ+zodRckx2+QZkm9r1e/KfIEa5Ey4NeaWhNZKmAY0
         L0oLX4OFJ0tXw/cxw1B9Et4L0KCYxaZ3RCLnWqspS+Fjv269rGZxZGXPgiRWHdLlXKhN
         U3Wily+UkCaNWZkJZuDTUgEKiXttS4ec/kKDIT9KzEl03OWfiI+eksAZ6qkm/nsAmD6Y
         w204HiHCii1HdfG2dyYcxTyeNEym3D/ERobtzOCFyOUcF+GQ5NxdG0l75h/E/podVJHy
         CR6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1RYOmljHlNWmHppmrjEYf8R4bs8uy1CSnwfzBiicQtY=;
        b=ac5u084RusUV9g8sOFWcSMSSDMof3hgJU96Ny4aRFtfB5fq9hgx5T4eMmhJUwhYaDZ
         AU/SIk44fUYX7LmH3vApIYoeqVv9KQshKcu63S34n+tUBoZ4ZbnRRF7MIaWJ6LBhGS6w
         07xmjkXeptX9DOj9iX1XqXQZbyVrE3ofKVSTTr/pMAGMsObzJhoc2/tDePYquNfyF8HT
         pWRT8zdAp1Q3kW9sdwSqZAP4B6N689vQCotK0R4Xz3vFbgULpiq7zQ+3cKnjdpZ/Ya8W
         Rbtbo0ytaZ63aYOFFKQ0Mndpu++hofL/prKgjfdm9YhZiye8UhxccIG1k+YHwKd4YoRa
         vEVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530icKXRR8geO9Cp1uuVa+NH51mmESamaDe5/ptrFC3HlW1zS2Ty
	ExhfkeDb3F0G5qrM3NkCHlE=
X-Google-Smtp-Source: ABdhPJywnMkXQkw67SHNb9IM+qv9F6BzDiwR4ZTd83YPkUh/efDJ5FhxGJ9EVW3w0zadZP7x7llapQ==
X-Received: by 2002:a05:600c:3d0c:: with SMTP id bh12mr22570591wmb.179.1643519955863;
        Sat, 29 Jan 2022 21:19:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3487:: with SMTP id a7ls643208wmq.2.canary-gmail;
 Sat, 29 Jan 2022 21:19:15 -0800 (PST)
X-Received: by 2002:a05:600c:3641:: with SMTP id y1mr13106131wmq.53.1643519955067;
        Sat, 29 Jan 2022 21:19:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643519955; cv=none;
        d=google.com; s=arc-20160816;
        b=Et8O/H74HA7QB3grO2T8Kj/B130mvbqW3HM1dbI2kScd6Rf1to3Yb5ETZ1ReZddSvy
         TaweeMKsmtBtnnRX8IQe/MWmQQp753nsnmz4kb9WoF2+ngtaZCOicb1Zz2FCLQYbouLD
         A9rGbb3J2Tn/Avvfkd23gta3okNE3Kvo7NkdlDZ2DuJjVHsQSDTHqUOuTbtfX3+erooB
         ApRuWAhZZkLEzAa0U4IKrAPKZCPtElKG991SwuTxcaP/oSnXM56mitqm9udcSNCg2xWD
         8GvT3LC0QYxZEcj48zggnERqQ6S1bxMC3wX7aVn/fZUSWg7cVyN+FJPRfLYORy6+j+tQ
         Y0pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=zsGDwx8J79R+PpgdwPTQrH5aHDiZN2RVvB7a0IY3D/0=;
        b=KzcOWEBJzBE3TEwuGVXmGFtbeancgzaAxQwFXKl2u0zBcfFPXZs5u3v6JapI1889lE
         Pq02+Sas/5fOWkPio2OOE1OFJlHb/t51NkQ0m9QE9f6Y+vtBZq9yQn0mBI1fsvVhA2/U
         oztDOFdydq6RKKEEEdp7rVnh9tcB/tK4xWip2yMateMHUKWCxhfF24CXMtYGxWZLWx9d
         nf8CZ34ImPRU66i5f/4hFkjxyfQCrj08UQuI2bXxhUaK2zGVlQupZtJRFP10i97nWc0p
         ai4m6r6IPqGu+DdnJl388/LaZdy/RENFT13ahRW2cCb2Q1UBOYWt5EAYgkjqQG3m3GiP
         cf1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mCsmFsCC;
       spf=pass (google.com: domain of jj2hhenry@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=jj2hhenry@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id h2si1068649wrp.7.2022.01.29.21.19.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 29 Jan 2022 21:19:15 -0800 (PST)
Received-SPF: pass (google.com: domain of jj2hhenry@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id o12so19987613lfg.12
        for <kasan-dev@googlegroups.com>; Sat, 29 Jan 2022 21:19:15 -0800 (PST)
X-Received: by 2002:a05:6512:b11:: with SMTP id w17mr11120075lfu.381.1643519954601;
 Sat, 29 Jan 2022 21:19:14 -0800 (PST)
MIME-Version: 1.0
From: "John H. Jarbman" <jj2hhenry@gmail.com>
Date: Sat, 29 Jan 2022 21:19:01 -0800
Message-ID: <CAJ+hgbgxJUE44z-aq0iZrycAHnGN2XNh5_O1bZ9H=Y1TYG8SDQ@mail.gmail.com>
Subject: Your Message.
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000134ab605d6c5cf17"
X-Original-Sender: jj2hhenry@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=mCsmFsCC;       spf=pass
 (google.com: domain of jj2hhenry@gmail.com designates 2a00:1450:4864:20::132
 as permitted sender) smtp.mailfrom=jj2hhenry@gmail.com;       dmarc=pass
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

--000000000000134ab605d6c5cf17
Content-Type: text/plain; charset="UTF-8"

I tried reaching you several times since Friday, Oct 29, 2021 till now,
unfortunately I couldn`t but if you receive this message, kindly reply
back..

Thank you

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJ%2BhgbgxJUE44z-aq0iZrycAHnGN2XNh5_O1bZ9H%3DY1TYG8SDQ%40mail.gmail.com.

--000000000000134ab605d6c5cf17
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div><div dir=3D"ltr" class=3D"gmail_signature" data-smart=
mail=3D"gmail_signature"><div dir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr"=
><div dir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr"><div d=
ir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr">I tried reach=
ing you several times since Friday, Oct 29, 2021 till now, unfortunately I =
couldn`t but if you receive this message, kindly reply back..</div><div dir=
=3D"ltr"><br></div><div dir=3D"ltr">Thank you</div></div></div></div></div>=
</div></div></div></div></div></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAJ%2BhgbgxJUE44z-aq0iZrycAHnGN2XNh5_O1bZ9H%3DY1TYG8SD=
Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAJ%2BhgbgxJUE44z-aq0iZrycAHnGN2XNh5_O1bZ9H%3DY=
1TYG8SDQ%40mail.gmail.com</a>.<br />

--000000000000134ab605d6c5cf17--
