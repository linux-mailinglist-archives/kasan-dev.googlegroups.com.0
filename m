Return-Path: <kasan-dev+bncBCMN3YO5RYBRBE7LXCPQMGQEEMQNPEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CA8E699668
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 14:54:29 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id x17-20020a05620a449100b00731b7a45b7fsf1223069qkp.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 05:54:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676555668; cv=pass;
        d=google.com; s=arc-20160816;
        b=gtLr/qcmnKazms47+RHpqr1URuSOqF6j1lz2qtI/JXY6e0Jr16CZTHwCBZCvgdUWsm
         UyNdZ28f/NrMU37l88QMGJh8Xozj89fGEHEXl4/cftO2UTsJ/q1+PjNQwGcKUj37dLz8
         99eL1ZB1pbn+bHhqQRbsCePX3LPOJhwMd7ueOoAN68xjK1Zll5fmewKZDi71Nwh1vq6z
         CEy89aZlf+eZ3jQOwcxgZ+YE8DUU7adYlDuD47go38+CJ24wt447b5/CnFTMX+8DlkXA
         aTmyfoinpZDngkdFcsL0pig6wNMH1dGY/z1mpd7vy2uSZSH18MxiLHIbhsADC6w0ZzXW
         2uWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=L6vseZrE7Uj0p/cqnrzYOKLjjqGu2gw6qq+N9cQC8ro=;
        b=Akk19v1BJz7E6mlYdL8koyOoxitl5S07msAbM63We8rTRJOp1FfLvy2ZC4MGk6+uCR
         8u6mcK7TDlJTYlGaDROr1qkHLu0mYZ95HQuAN8vzehB23kvWtoCm7YEymreW/L27xI8Y
         REYK2NAA92fh9/G8jlE2Ui1HtGMO40e29muWlO4yWzcqvvFl/o/7VT/a3IRkvs3jbP7C
         zmTWqru9haUMXLpQnSIsJs6Mt/76zEe+OPoQwiKuo1YILa1oWczD79rMwJJ1/gt6adaC
         l+yozYVrr57Qt7U7qG1QKb1eOZcGta4kGtUYKjMJAQU8QkhZ5R0nfLJxgdbmbaf5jzG/
         NfZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QckPO7xe;
       spf=pass (google.com: domain of abdulkuddous4@gmail.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=abdulkuddous4@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=L6vseZrE7Uj0p/cqnrzYOKLjjqGu2gw6qq+N9cQC8ro=;
        b=Ua3lc+sJ5ekI39yQAZXCmJV5XmLVVqVcHBOLwFgSbyiGo5ci3d36CATSFlbaoIXDPc
         84u93WPAcbLjiUTEACgffl8yFhZEI/cqV/u9xQkBA/UDIOn+ZP1lg/44LR3SPVuwZt05
         zeUuKBRnNSJl9VBGf1S6N3fYzxeclnUEeD16EjdpQ40+Y9BxmZkEPX6wvDjE3yg1wION
         +UJiA43CDAzBBjj9H92hIp3cE5mSvH/7e2ANcdpS+QmjLD7+0xtvKFBPyXC/W+Aq/iBK
         upMHMCTjHuTQXQ6p43v0L5j4eE2BEGBqIxVc/WTvf+G8VzL9izqe8qul2G7kQ8/UOyru
         NthQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=L6vseZrE7Uj0p/cqnrzYOKLjjqGu2gw6qq+N9cQC8ro=;
        b=ELUiuZszvsrQcYwQifqAIECnsRMWJErweiB3fazRueEnX66t1IOuWkLitIJizMTp5b
         DoyvSNzcIqyZsR+Oynse/41AMhNC77Wb5NccUi3K8KfMkX/JxNebtzMiZ/+ILOw3waja
         pEAXRY6sqZw4FIoofmk/M36vi5fWjPhJKoiv6o5fJX8kUn4YGoBLOrEIhxV/uaxXIOLm
         5Y9B7AnrkXHbwBoPG30Ml6razfowUSI6EJlUUsHJIKfk9o8zNsG8z107JnIO/gOpvbF1
         xJ++/RMP8Y/PwfHZVFqNuTax6pmZwS4+MT58dsLhEv+9wNaUyNdsj83erd+CgAKN5Rfh
         VR+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=L6vseZrE7Uj0p/cqnrzYOKLjjqGu2gw6qq+N9cQC8ro=;
        b=gfeoW7hHzi0JBmMtqzuco60AT+xthC0Pdh/Bt2Kz7z5weqKifFDrWQmp7zpsnsU/K1
         O4OXVxDMxdo6hHAysAxysWyU052La+UgOBc37Y7h8EJsXGOjMHBbDYcNpBMy7GmzZVWl
         urSBXmbtfSEoOwV4Rx51t5Cu4mvf5H6KeKehmRE8AB1RCFhaSyj51c1cnE4hsgdba/BK
         u7BxPraRfVaf25n2mjmqli4sMDMV6eNendsENGYGqkeVrmj0Y7UZjhMeNidzULY8LP40
         qwdtZhRI0tYRoQzOWIwRD5AUI2DpCKS8IDVm7zThSOYkRYhr7NweDon/uiWKpv3pV7lr
         UvzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWBgUvHfKkuhVkviDFkG4XS4sdR99AnXPfDplkC8W/C/PDqoKWz
	4SVczo1MqDnd3YR1vUu5du4=
X-Google-Smtp-Source: AK7set+sxlihT1Ulep57BCMyh3mKLahSRRxotf6yna4PR/+87V4iPFPVB5idGY7d0eGdaRrMewR3aQ==
X-Received: by 2002:ac8:7590:0:b0:3b9:b148:cfa7 with SMTP id s16-20020ac87590000000b003b9b148cfa7mr296469qtq.5.1676555668020;
        Thu, 16 Feb 2023 05:54:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d6c7:0:b0:56e:8a76:960e with SMTP id l7-20020a0cd6c7000000b0056e8a76960els1357146qvi.9.-pod-prod-gmail;
 Thu, 16 Feb 2023 05:54:27 -0800 (PST)
X-Received: by 2002:a05:6214:4007:b0:56e:c1da:f68f with SMTP id kd7-20020a056214400700b0056ec1daf68fmr9413759qvb.26.1676555667323;
        Thu, 16 Feb 2023 05:54:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676555667; cv=none;
        d=google.com; s=arc-20160816;
        b=zkNk6TFtGFPy4wADt9tWwD7AGGuWIWLowofE5Z7plW6uVCGu3AwynwmBM4yVuPvopw
         YG3gjpClVBjdxmoyO+Qw+8VwbwkxVRE+OsP9HL86VPxzh9AbVGo5lYht97krFZEXrQaM
         CQwFGFIXpLt6YHbnVjWzZ5/Kg+GE2ALIbK70x8GMh5oLJRpy88jXFG2vT6ls2F3ewfYi
         M8A2gwuquIikfDZ2HEdZe9YeD2t7SOt4V91oLVPCTsAFv0YYicsNwT+F0nSmjCWo5hdH
         C5mn22ZMK4zgczOOb5sT54ehjenxIqtGOuuBiLEcj9/LjC0jG+x9hVDPlea7VrEHgL4c
         f/zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=RpR8OeXQJSlc4Jo2wq080LpB6AzJaz2xM2B4IE0d2bQ=;
        b=z8bcH8npgh5+DHMdQIO/0dRJAF06iWfabGpPZGoG/w780dRoFCDFSc5UX/eU9QgaD6
         RZ3uzL9QvIn9lolFyTEMa+NWzoBT2xVxul64QRP7KnHBSLRb3yf+ZRw5eYtxovh/XxAS
         Zv2p+hfpRfmVU9W141MW1tMRGZ67xf5oIlAcmPG/ANMUbrds1FB7TKFEbrAOWLQ8AG2T
         TdtAwION2pYToOilr1z92/D1xzWhW8XE1u2yQJmBgwg83rgv0IlSxVL6JBcTmfZuj/bD
         1c/dVnWeALweMdsYzPfFY0Nw+Aq3Cw/K6g/SKqHI7uOJ/malsA6f85/b6gGSmiUPJjvV
         JJnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QckPO7xe;
       spf=pass (google.com: domain of abdulkuddous4@gmail.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=abdulkuddous4@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe30.google.com (mail-vs1-xe30.google.com. [2607:f8b0:4864:20::e30])
        by gmr-mx.google.com with ESMTPS id 141-20020a370c93000000b0073b8e384737si112684qkm.2.2023.02.16.05.54.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 05:54:27 -0800 (PST)
Received-SPF: pass (google.com: domain of abdulkuddous4@gmail.com designates 2607:f8b0:4864:20::e30 as permitted sender) client-ip=2607:f8b0:4864:20::e30;
Received: by mail-vs1-xe30.google.com with SMTP id d66so1946983vsd.9
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 05:54:27 -0800 (PST)
X-Received: by 2002:a05:6102:2010:b0:412:99b:1ac4 with SMTP id
 p16-20020a056102201000b00412099b1ac4mr972388vsr.81.1676555666941; Thu, 16 Feb
 2023 05:54:26 -0800 (PST)
MIME-Version: 1.0
From: Katie Higgins <kattiehiggins001@gmail.com>
Date: Thu, 16 Feb 2023 13:54:14 +0000
Message-ID: <CAEGEtf2eyrjcqwrLqG6o6-oN-FtY1EFrzra-O+jwK_mA1WWmSQ@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000f96c0705f4d18898"
X-Original-Sender: kattiehiggins001@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QckPO7xe;       spf=pass
 (google.com: domain of abdulkuddous4@gmail.com designates 2607:f8b0:4864:20::e30
 as permitted sender) smtp.mailfrom=abdulkuddous4@gmail.com;       dmarc=pass
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

--000000000000f96c0705f4d18898
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

=D0=9F=D1=80=D1=8B=D0=B2=D1=96=D1=82=D0=B0=D0=BD=D0=BD=D0=B5, =D0=BA=D0=B0=
=D0=BB=D1=96 =D0=BB=D0=B0=D1=81=D0=BA=D0=B0, =D0=B3=D1=8D=D1=82=D1=8B =D0=
=BB=D1=96=D1=81=D1=82 =D1=8F=D1=88=D1=87=D1=8D =D0=B0=D0=BA=D1=82=D1=8B=D1=
=9E=D0=BD=D1=8B?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAEGEtf2eyrjcqwrLqG6o6-oN-FtY1EFrzra-O%2BjwK_mA1WWmSQ%40mail.gmai=
l.com.

--000000000000f96c0705f4d18898
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">=D0=9F=D1=80=D1=8B=D0=B2=D1=96=D1=82=D0=B0=D0=BD=D0=BD=D0=
=B5, =D0=BA=D0=B0=D0=BB=D1=96 =D0=BB=D0=B0=D1=81=D0=BA=D0=B0, =D0=B3=D1=8D=
=D1=82=D1=8B =D0=BB=D1=96=D1=81=D1=82 =D1=8F=D1=88=D1=87=D1=8D =D0=B0=D0=BA=
=D1=82=D1=8B=D1=9E=D0=BD=D1=8B?<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAEGEtf2eyrjcqwrLqG6o6-oN-FtY1EFrzra-O%2BjwK_mA1WWmSQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAEGEtf2eyrjcqwrLqG6o6-oN-FtY1EFrzra-O%2BjwK_mA1W=
WmSQ%40mail.gmail.com</a>.<br />

--000000000000f96c0705f4d18898--
