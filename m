Return-Path: <kasan-dev+bncBCWN7IUKQQKRBKWIY37QKGQEAC6UK7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B1C72E8BD3
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Jan 2021 12:02:05 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id o19sf9799485pjr.8
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Jan 2021 03:02:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609671722; cv=pass;
        d=google.com; s=arc-20160816;
        b=zX5nmMW0Eq+Dk3U21DQgnEMG0bMll09sWnGe1zcmXYTkmxAE0yZir/yVgCOyXoVWat
         viB15qLxz3sgXLLA1AWFE3maswX3rmMFlFmkQQSU5Q+SuLjjR+FL67hlVuTEYoQHZMRo
         1N9e3sAronK9/3PO5LQTBotrVvr3tUOYJwRwMoOd6T2AdiS0DzImWvCue4NiHCx2vHXh
         MHa6o3FjIGizXLN0h+iEVbZsVLv479MXtdK+zpcw2uGy+Kq9MG3SZVA7PhcSlIg+En4A
         pDMoRoDWF7IZCoqMl/ArLXDnYZwPAR0gcOz37CUyL76GK+D8R3sfYkEsxK0gBh+9CoYU
         1WxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date
         :content-transfer-encoding:subject:to:reply-to:from:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=6jLbsG0xA+LtSqecTEnw8gDjhwB737sF7enTwVe5BiM=;
        b=k3b0QUN7TZ/cqWt60z2Mqopl2eax2JMBaAbT5Q/6AOaMCdpRBB4U2utO4uk84k2uPP
         jukr3bfHvyCClv3CVZr+6U6rTMTlD43myHgM25VGKmVvKOVdQGPbEvjKCtDwW/mm5dBm
         oI2YMBr2coQWx++0kebIVTM+fJhvaDvSh2+Z3ryN+vxMHv6wEi8QMvF9q8CYRDdV4HMa
         WUXY2YEiDWDqOuw2koJTpgh8cc5tgZTH0c0wPC+O8RXexencOK95Y13viNsO87Sf/DlZ
         5PJcnOBWer/KDj12WmxZSitcTY3i3WSJR/zXXWtsBE3XBYZcJiwawlVxss/3opZWadHw
         wXFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=W8G6YzRZ;
       spf=pass (google.com: domain of barbaralimon90@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=barbaralimon90@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:reply-to:to:subject
         :content-transfer-encoding:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6jLbsG0xA+LtSqecTEnw8gDjhwB737sF7enTwVe5BiM=;
        b=jZG0fYHbpTAMXfREo0gePk5arQtkJbUHCzycTdpJ0qk2HJ5vnjDKhkGLrY2JW6zJrU
         pB4PwlbjXtbUleGuZHZKRfFeDnoNKZp16zQEcgMD1JtMjS829snPGcbFrcmAT2V/wAsq
         si7Ay7W/MaekOKKXhuUlwQYpKH0yAHoaY4s6ZBDjDGkQ51eRf9Z2l2FLrfMPpGuk1K05
         7XcZ95FLs6zSdD1oPk45PEQq5CQvGvEMNEu8o6Priu3ExrV2k5TzMfPT6RMZmqfqVwMe
         ATcRKC4gZr2jtr+Nhk5KDTfdojsTzWxw2+gNUZhDkT59hdmL6Oq+SqjAZzC3PtrW/cyK
         XaHg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:reply-to:to:subject:content-transfer-encoding
         :date:message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6jLbsG0xA+LtSqecTEnw8gDjhwB737sF7enTwVe5BiM=;
        b=Yr0hfYUprMG26nBVK6P2O7hamgSRJ7MdDmuQpD8d+nAYbSIaKOLTVjhbDNfAD0rQop
         U6vdLnnhR+5WF17w+yIc9Gp5Umh20n1hGKXVU5sGi1Qql1U9pWwpRGvYXsIsKBbVRX1A
         qasMkKZu3mw8l10qBjWjfhwWfeFdaIFiiYS3hD5N0L+j8knFET6NvbUc2d16AG3w/0bK
         TuC2TmilXsXiVu8QC02eCbmK2Xh1e5+jmYp7/mlNUCl5Tj2SHlPhqJh1VeEI75jcsGLr
         DD4b/nNWz9L5TwU0/hHIo/Q1BrKD9y6FJbpi21FJIj3FxmpjrdEyjAd8uOJB6w1xjYsy
         YeKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:reply-to:to:subject
         :content-transfer-encoding:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6jLbsG0xA+LtSqecTEnw8gDjhwB737sF7enTwVe5BiM=;
        b=OZNKtAm1K32sbHa1o/vz2cUgZVrlQbyfQu2z9u7Iap2DnVW6Mh+93rrQqIdOfpMbK2
         jyPqXoIkJX4KvlvW8c3Uq5xMcUsqyNDq3sJq453MSu/6Hi/7IAbsE98lVVO4i0IBhY9t
         C5jz5pbl7U1+AVjvwMjmRzyBuahgwXX3BK+jzROajtiChEmN0atebBm57jSiY+VtyzQh
         ZSqKszMKqmrCvBTYWCdol6+EIbdygSwD2Mox0NttGT2EMV/viYq/bRr8e47Ks/Uhl6wY
         00cWT2v9bNKW53iwLEkGgupMUT6vOeVfcHJjzCZ2fL9eOHuGI17GcVGRcuvCOxsN7W62
         vHHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530HkmBVSJlNAIHZsmHQIIPjVckkn9buanmF+GDywFjmP6Xnrj4N
	PZTdQXbq5DUMEvrSKQyEXB4=
X-Google-Smtp-Source: ABdhPJwQ1wa0SIXIZCyT0G1fTy+g57jO7SVkE7GtqweD2u+AYSarrunPh/07ptW0mN9LAVOpsN/eAg==
X-Received: by 2002:a17:903:228d:b029:dc:8e14:a92e with SMTP id b13-20020a170903228db02900dc8e14a92emr3995780plh.43.1609671722238;
        Sun, 03 Jan 2021 03:02:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:78d4:: with SMTP id t203ls14753540pfc.6.gmail; Sun, 03
 Jan 2021 03:02:01 -0800 (PST)
X-Received: by 2002:aa7:9f97:0:b029:1a5:94d8:9cbf with SMTP id z23-20020aa79f970000b02901a594d89cbfmr61209702pfr.79.1609671721725;
        Sun, 03 Jan 2021 03:02:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609671721; cv=none;
        d=google.com; s=arc-20160816;
        b=KEeBrRd4C1mjIIkyA2d4qf927IpctjsQVCigE95Pwbh1gCO3Wb8ai3IvElXmfJsHq0
         LW78LPNM69p7VjeEJ//UH3emCArHZUOR+5nnxjEQziAY41JfyJWb1bbVgSFwwns6vpmX
         xUpKT0MLKz1UfShH1ldzlkhsJOIn9r9tGt851URiDvmMxtrXsElcK7v1iikTHdKuexqi
         XutrIsMdhU+iE+tuHXltpVPZQQRUT25Pfrb9VT5KN5O1oAuG7nWrMmyMrX5qWmJG3IfZ
         GZu4ErTkYfLeD9M0DyqD3KFasTdpyMzZqNeW8rsIgIXpDmVIVrfwVbPArPFHZ0tHv24a
         V+EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:content-transfer-encoding:subject:to:reply-to:from
         :mime-version:dkim-signature;
        bh=p5Qfb5AKKl/JqHMFQnfYUQrXymdVnV4fiENxA5S+duc=;
        b=ZPCfBgAwmsT5vgAj0VFgq2yqw1jwIvv5TUBYUoUdpVkmP08gm4D8xPe+iwA+7+Pnyz
         iR7oeVRBhYo866l3KMpIJtourKe69E9sWgI2rOfYzPq8owJ4MBx78qmjNr96h/8Jfg7f
         qQjYFBUXPIjtJZfXEa9pBgOIaXOri5BzafqVZy+9SkMrDiIuY7Y8RL49bG6OfyK8Ztaw
         qpyg0aNM0PPIfq90WfW4JgvbbXQn48pWyl8e+vBA3bdEJFhRsoygJS80C2x2KxQUBDLf
         D+UQj+y6mgf3wEBtQcsXILaJ45cjw5cqUK68ut+vTpyJOvmniiqxebTYD6SHl8seblns
         6Nyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=W8G6YzRZ;
       spf=pass (google.com: domain of barbaralimon90@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=barbaralimon90@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id lp7si981659pjb.0.2021.01.03.03.02.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Jan 2021 03:02:01 -0800 (PST)
Received-SPF: pass (google.com: domain of barbaralimon90@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id x12so12895816plr.10
        for <kasan-dev@googlegroups.com>; Sun, 03 Jan 2021 03:02:01 -0800 (PST)
X-Received: by 2002:a17:90a:d90e:: with SMTP id c14mr25035212pjv.85.1609671721187;
        Sun, 03 Jan 2021 03:02:01 -0800 (PST)
Received: from DESKTOP53F6QH8 ([103.99.182.34])
        by smtp.gmail.com with ESMTPSA id z10sm53811448pfr.204.2021.01.03.03.01.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 03 Jan 2021 03:02:00 -0800 (PST)
MIME-Version: 1.0
From: "GiftCardoffer" <barbaralimon90@gmail.com>
Reply-To: barbaralimon90@gmail.com
To: kasan-dev@googlegroups.com
Subject: Get Free amazon gift card is here
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Mailer: Smart_Send_4_4_2
Date: Sun, 3 Jan 2021 17:01:50 +0600
Message-ID: <18468464491672312778087@DESKTOP-53F6QH8>
X-Original-Sender: barbaralimon90@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=W8G6YzRZ;       spf=pass
 (google.com: domain of barbaralimon90@gmail.com designates
 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=barbaralimon90@gmail.com;
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

<head>
  =20
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dwindows-1=
252"> =20
<meta name=3D"GENERATOR" content=3D"MSHTML 11.00.10570.1001"></head>=20
<body>
<p class=3D"MsoNormal">Here's&nbsp;</p>
<p class=3D"MsoNormal">how you get to enter for the&nbsp;</p>
<p class=3D"MsoNormal">Step:1 =E2=80=94Click this&nbsp; Link: <a href=3D"ht=
tp://giftcardoffer.org/amazon.html" target=3D"_blank">Amazon</a></p>
<p class=3D"MsoNormal"><br></p>
<p class=3D"MsoNormal">Step:2 =E2=80=94 Choose measure for your gift card v=
alue as $25,$50=20
 yet $100;</p>
<p class=3D"MsoNormal"><br></p>
<p class=3D"MsoNormal">Step:3=E2=80=94 proof you are human or verify humani=
ty</p>
<p class=3D"MsoNormal"><br></p>
<p class=3D"MsoNormal">Step:4 =E2=80=94 Complete to the one simple task or =
offer for=20
 unlocking your premium content</p>
<p class=3D"MsoNormal"><br></p>
<p class=3D"MsoNormal">Step:5=E2=80=94 Check your account</p>
</body>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/18468464491672312778087%40DESKTOP-53F6QH8?utm_medium=
=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/1=
8468464491672312778087%40DESKTOP-53F6QH8</a>.<br />
