Return-Path: <kasan-dev+bncBCUMRQ6ZXQKBBEGV46BQMGQEOCY237Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 21C583628E9
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 21:50:42 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id r204-20020aca44d50000b029013da91480a0sf9867616oia.17
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 12:50:42 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NB21v+iuVLpyy7zK3sACTPSUEAwPiqIZ/q6NZ17ATPU=;
        b=E7ifJR0kRMLm4PaapHvW8SDF7G/CggN+VT5JtQ8MA1c7NUElzb87dXa39pd6wPGqRO
         N1P7+j+vEmHXRMfG/HG/VQqMyUsjEZJb2s7RS7rtzCT1oxkUkIWNScS2Gxba2ep1MbfD
         LCcYUq2TBPoT3Jebz3fXohP5FboFLQ0I7eMFjh/f7o2SG4auX03GMy9c2C4mMBr40DVy
         tq3zrznDaWb9ZoXY7s/f9ah4DMFoey7G9HyUT9DYBAl42BAiZsGW8W8xNhvTdcUzoNs5
         7AVzs/jUTzEm4Ae9ZTuswbtfTRZcXg0Uc4OxDSDMhf+plF7Lwi0+rHrbTCiOvDpxv4aw
         Lbug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NB21v+iuVLpyy7zK3sACTPSUEAwPiqIZ/q6NZ17ATPU=;
        b=Mw6UKuwrlFb9dp6YKRTxlk3ukE/kvG6uSHQv6ZEUafjDxGhCfufg/vOCQ3IzQ9TYGW
         ZgkAVFvGF9tiTqXNA4zQQNv9eS7Su71Jc9u0KDwUEU0c0e29juvP1/3p9urwS4DA8g1K
         9FXsLTcQHh2YbbSgCg6QNM2rKIN6nkeKxs12C7GOZLChD1E9Uhk8RWFxhPqzKlruA9RK
         6HLfesaeGrb0MUE5rXWm5T6GZ8gU3kbmGN5vN8DtL6/OOZlnFpUGuiAYM+PiXq0YH7Rc
         2hF3itLBjIiQLtmugJNSW15PPtJv3et9he1Ucaoai+9HzAld6HcDnZXwXbt1LUhiFwcF
         azhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NB21v+iuVLpyy7zK3sACTPSUEAwPiqIZ/q6NZ17ATPU=;
        b=XPHC1QUdv2TtPd1y1NlRPZKOvA1EitmHteBCRLdr/aETY093bsjISS5fXr7Ebuc+NP
         dDTYv8GAArMsktC8I6OuanzF7MhTlunKsaXH84kgg4r9qSj1fFlodBGLtUGwv7sT/7Yo
         mWphFoQjgMJ5TdDCW/wHvBideCgt/Qk3G8yLVfsVop0iK76BdvNSiJnqTiEXKc9WMMJ5
         U1YVoxCYXOodyLQSFXpKkgdkd4bqLsNYlNHclZDECgIAQXDylom3V/QDkV9iSrZ7qMdl
         kujd2TlaE1Ioja6a2gRsGmgmyD6fwtVe4CFHlXemVuc34DNT1KX097/wlgzi3o2qfq6E
         1pCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zOryhsU6OTcUIFBVzui+91Ho5rkNT4cbIQxAalUOZmJSJJnRx
	np9BGCsLt4JL3LekGL6qI4k=
X-Google-Smtp-Source: ABdhPJxH6Kmau+ofySkh+Y8G4oesh75iGabQADkXwwE6TQQnfKkNoHbaD0pxOUt6KVySLo3ZqcJJ2Q==
X-Received: by 2002:a9d:7003:: with SMTP id k3mr5126060otj.351.1618602640981;
        Fri, 16 Apr 2021 12:50:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf8e:: with SMTP id f136ls2542941oig.11.gmail; Fri, 16
 Apr 2021 12:50:40 -0700 (PDT)
X-Received: by 2002:aca:4d04:: with SMTP id a4mr7820402oib.175.1618602640522;
        Fri, 16 Apr 2021 12:50:40 -0700 (PDT)
Date: Fri, 16 Apr 2021 12:50:39 -0700 (PDT)
From: Tareq Nazir <tareq97@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n@googlegroups.com>
Subject: Regarding using the KASAN for other OS Kernel testing other that
 LInux
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_4330_1434450808.1618602639704"
X-Original-Sender: tareq97@gmail.com
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

------=_Part_4330_1434450808.1618602639704
Content-Type: multipart/alternative; 
	boundary="----=_Part_4331_1107725671.1618602639704"

------=_Part_4331_1107725671.1618602639704
Content-Type: text/plain; charset="UTF-8"

Hi,

Would like to know if I can use KASAN to find bugs of other open source 
Real time operating systems other than linux kernels.

Thanks and Best Regards,
Tareq

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n%40googlegroups.com.

------=_Part_4331_1107725671.1618602639704
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div>Hi,</div><div><br></div><div>Would like to know if I can use KASAN to =
find bugs of other open source Real time operating systems other than linux=
 kernels.</div><div><br></div><div>Thanks and Best Regards,</div><div>Tareq=
<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n%40googlegroups.com</a>.<b=
r />

------=_Part_4331_1107725671.1618602639704--

------=_Part_4330_1434450808.1618602639704--
