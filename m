Return-Path: <kasan-dev+bncBDB35KMNSQMBBHNDUOGAMGQEP7YNODY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BFEA447AE6
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Nov 2021 08:28:30 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id x7-20020a056512130700b003fd1a7424a8sf5960975lfu.5
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Nov 2021 23:28:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636356509; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ywh9J91q0kgwlm4bPakJwiQZMnLt9RAqffxaXSqyGFIHp5S0pdHT5gPJjojB1Hbwfh
         dfRyh7J0HQ92WmpUFqSlueGinVjsADzX9WiBJpCcy5Y8d7TIGl3OKK/DwGMWYSArLWgf
         PqYeg6fMrRMLPaMtzy40LcWZV3r6xaWHKjWckrPZNAz3i8klnfYvA56DqVD6OaaLYKQx
         zNa0lzG7uRHFMtf0Xtl32OvqS8YK2a+tWZvpxgRfFgvPBOzHjtoWVsK2UnZrzsRqommK
         mIH4/mxehhF3lrc/U/FChSODGMWgMoTohJdb4XNjJBWTFffShhu8/3vchKwpDwBB1z3n
         JS0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=yAPMgkBy6FwXLAO+Ve4CJuB2zW8+2+uyON5Poy3Dty4=;
        b=FrxnV3AipE1LyMIuKre7TwSJ9RLawf+B8m2UYn29huVV6gitkFLF3CM3xDCYD0U8iE
         Ab/aLCqqgV6A1z8K4oLvkI3pe1T8by0AZ3eH1kJgp919NcV/xHhxLZCShU520MEBVely
         +EqGK3YW4v61xzcjhMGJ3wYY6/I5/M9+d0vuvOAKRxpzlFgNmSB2vk/PvKafFVFpw9MG
         mvBSdJg8vqso4tmnK/4hl5p2+hBXWS/KDBexsR5D7zLJIwPvxZgfjQNNPao924mZC4Xg
         sNRNhiVnDar6ZwYv4p/2UpUppvhgJ5PqMuna/puQqyTbsr6fT82XITXLCUyGiUEjtEaT
         pUyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HIUIDtux;
       spf=pass (google.com: domain of ziskoraa@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=ziskoraa@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yAPMgkBy6FwXLAO+Ve4CJuB2zW8+2+uyON5Poy3Dty4=;
        b=TEM68jtrG0z6FUs38B/1cQHmQwzB1R/XFDT1Y5JJB6z2IWifgWqN41MmEVg2fNwQQi
         L4HT06u6MEdt3ilXLe6aMn+nFlW/h1+8CuD3dCKUG4fiGDX5wQO5XE/sf2oi09kqVCie
         X5q3zLeOIMhxQXWoGzniYi0e+Wqr/kSWLnGugafPgp1F9goMvv5Vxwwa+aoliaFG6UkV
         fIh9F1lijSUJL08Nx+vibmlWjUCTHN+Ts44HpW+4Aq3Rbv5wVsXcenM7n0PVaO8uS9WT
         UU4a8frpHG6gDsDUc1YesRCW7+sE9vDPy9CZwW/fv/YxjX4AntpiU82q4acqmChw7nlA
         GLyw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yAPMgkBy6FwXLAO+Ve4CJuB2zW8+2+uyON5Poy3Dty4=;
        b=Pg3hgsyrGQv+xBJoj+6lMkTwbPtrGeROThWQJpNJoQYbBGFVYj4/XRvUh2trUzJcF3
         T04+WHMQED3RTSsbGu4BWxMX9MAfZ/acu1o9WVbIFvDiL8UPz4gxputESLdHIcpINJrN
         Uh9B/9afOr4driS7ElCCUTLtRJotxzBogdXuxY/CInTe7RKEYAntmnKT7RT0Dn4sjLyC
         L90WT71wTqcP5+DtyeIP1Iu6HbqxN9I3TMpQjgZmL48L/epHCWwmPfajIuN2V+2gdXC4
         Is0z6ozWDRvKinfQ9cTnETx9yrTLv7kA9cRhcaTSn3JJZeFexlk8FK3gIAGs9Wvtq28a
         qZ9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yAPMgkBy6FwXLAO+Ve4CJuB2zW8+2+uyON5Poy3Dty4=;
        b=ecopiXumF0w6Hti4Nz96wws2cWO3XtpAI1u4wyhzzY6IYhnZu1Vw3IH32VIJbpBSXn
         vUUPNM+z0VRhSUUxVC7rI3a2CpMT5iUEdoe2BpfVYgq+8lBp53CVFkAvk5yMQe0JskUW
         JWeW3feipFItnEYyWHEmEyUjqThVQhIQxKN8piD0RQfdxJSP2spfR/TyraXZtIwKBe24
         gSJUeKgEoDNbT3sIageNXn0lbIaHz2sn26baCAeLVHqqgSdUThJDyEhFQENkPyFzNO/R
         Bl2FoGI5p7+tiHKE4XgxCynXZ7adKW61dH6WTFR5BR3SaJ08c1qnVEOQmEmtlvLt0NqE
         nTDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315FBDeA7w664PRiRBIbIE2wIb+HjhjKqu8GxgrAPPJF7tfFe1n
	vtBKGJRnpnUMBLu1BRERE/0=
X-Google-Smtp-Source: ABdhPJxGeCjwZE2OpKz2bNVMgzvkS/Fsvar47GLAzp8LuUOXJIRUkW66eJmOaqPPy+SAi4H/s5Vq7g==
X-Received: by 2002:a05:6512:ba7:: with SMTP id b39mr9807723lfv.529.1636356509564;
        Sun, 07 Nov 2021 23:28:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b8cb:: with SMTP id s11ls2431797ljp.8.gmail; Sun, 07 Nov
 2021 23:28:28 -0800 (PST)
X-Received: by 2002:a2e:8507:: with SMTP id j7mr40405890lji.83.1636356508673;
        Sun, 07 Nov 2021 23:28:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636356508; cv=none;
        d=google.com; s=arc-20160816;
        b=UDlygC+WekV1uOKQ5bSGcLI+vgRjhgLltT+zLVHyDWW/3hEu9/kd0Bc3D2x7rd/Rbd
         WnLCo9bjtzlZ0vpyHwzwDSOIv9da1q4iS1ChBfuPqoOCtuSpofIfumpkbJR/9TFX+kdW
         8QdqQyRWfCYY7bRpohFpef/WwH92uewyALQ7U4NI23LWNANY/PvzTe+ZVvfPkQyz0ni/
         0xAEWFUB5Gr7yzPbNOn8jFcicaI1Khxt1pY2oPPr3mrXycB2cbxdhD6/qOk8cFdQEC1o
         y1OU+6lyNAhEUNTpa2W6oazwCv7xWkjigShNg9UQflCfUcGOpKyX2keWvVAB4od8JC+7
         merA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=gS+G2bXPLTc8QV9oSOsVFPfildfSifO+gabOlUjPn+8=;
        b=JINRJyw+vibcU4iTTTFMOwfpBO51saja749THM5SF7rvBVGwnvK/7EZh4/R9yQH0jQ
         ugx2ErM/0DDWhMt+SxmVTUeoG1dbg+CS/n5ZjKejebgfTcBqBnC3TJNaEeyBfxHRdi8K
         nKwbvf+Evsa0ea/siCWwja4CAOwhhM5hIASuq1IAReL46cXE/N4pl0W/7bFtdRc6sBSh
         vi9J3JCD9WzBM200hUTR7NZRYJKW80l4CE3SwPmhbC9f2XQPQx46u7MIWvl3PlBUbRlh
         UMSYFI1Z9LzdAoRolQ8l06SYN0SGGzjQemgtz+x1OnHfvi3wSjqElu7H0/XFvKB/sjG9
         77Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HIUIDtux;
       spf=pass (google.com: domain of ziskoraa@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=ziskoraa@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id h4si912480lft.8.2021.11.07.23.28.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Nov 2021 23:28:28 -0800 (PST)
Received-SPF: pass (google.com: domain of ziskoraa@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id o8so58518986edc.3
        for <kasan-dev@googlegroups.com>; Sun, 07 Nov 2021 23:28:28 -0800 (PST)
X-Received: by 2002:a50:e184:: with SMTP id k4mr104851528edl.217.1636356508425;
 Sun, 07 Nov 2021 23:28:28 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:a50:2501:0:0:0:0:0 with HTTP; Sun, 7 Nov 2021 23:28:28 -0800 (PST)
Reply-To: mariaschaefler@gmx.com
From: Maria Schaefler <ziskoraa@gmail.com>
Date: Mon, 8 Nov 2021 07:28:28 +0000
Message-ID: <CAJh0Fjj+5-8NULH+GVA+s0+4imctuwfUNeTNJOA+cgiK6UAKiQ@mail.gmail.com>
Subject: MY HEART CHOOSE YOU.
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ziskoraa@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=HIUIDtux;       spf=pass
 (google.com: domain of ziskoraa@gmail.com designates 2a00:1450:4864:20::532
 as permitted sender) smtp.mailfrom=ziskoraa@gmail.com;       dmarc=pass
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

Given my current state of health, I have decided to donate what I
inherited from my late husband to you to help the poor and needy. I am
Mrs Maria Schaefler,a 57years old dying woman. I was diagnosed for
cancer about 2 years ago and I have few months to live according to
medical experts. Email me for my directives

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJh0Fjj%2B5-8NULH%2BGVA%2Bs0%2B4imctuwfUNeTNJOA%2BcgiK6UAKiQ%40mail.gmail.com.
