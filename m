Return-Path: <kasan-dev+bncBC24VNFHTMIBB5M4WXVAKGQEXBCWAXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D77A877AF
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 12:44:07 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id n4sf56710313plp.4
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 03:44:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565347445; cv=pass;
        d=google.com; s=arc-20160816;
        b=u8FTMadMG/4ufNJCfeaQVmwzPI6pW/syxI7Zr0I5GnDpAQg6iGHBYg/yyJOVfBppHu
         WTN+IeWQtZPPEBErkyiM0VlryAuitnC7XVKyYHsm07JMN2mb3sSA778gxls8Dnm4HST6
         uStYQ1p6cgb4ysCzvNW1WqDHZrs1kVpn3K4OjmgbYb1spNvq0dryALz6zC0oDmQPxAnd
         OaWuiD9dy1hDDhGJvNHPx25ud0xrfHdKbDmo989LvWrdVw+Rtt8Rcb8uggssR9K6ud5u
         i+rL2/y2KUulzwI/p2vSDMarPZITSBfUcwPnAk/aCzV/3gEw1kQdd3ulUnCFle9wyCL9
         j92g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=lF60NJ/+n5d0V31UL5e6sUarRnQbqXDmCh4aTJN7Gqc=;
        b=uzc3KO+SkZxk+rYar+/La63FUhpH4hWeHJe3UQohMVHeydPlk0nSnqCJ4Ao57IJMNr
         Ghmt1FJetEWxu23pNsDXzaUv2bgeHvX0iNQHZ4zpVlkvvIZg2oyDLJlH9jZS5eL78Tf8
         juVMDbYrgAN66LZVfpPPhV0HftCOdZKjoMI8q/++6oxaHKfK1wGa7PFNwoQgeSloAXIT
         zHJpLlz2M51v1Tby5wr1Qvvrjv+O5x6lf3EcdjmUoOWtG1+msFhWslPzeSqX9I8NDdNG
         J8gRKGVV1I2VgQ6LXr/ACUJXSv8EhVZhCDgoPQ5+FFlNpgp4IPw3SJXF8kobLkROUVyC
         zE3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lF60NJ/+n5d0V31UL5e6sUarRnQbqXDmCh4aTJN7Gqc=;
        b=hWutkjTwZaenV+Vkl7pltDFY54NUw4AAr17JlX1ffuAfGz+poZgHt2XpObwAGc6iDS
         +dZv0BVjwDs6hVnlfHVlCMDgnaLM721r+z5/ZVqx0gDXs8ndDwbUfF/l9grR45Z9IoFC
         f6p+/qXPvRYZsbrHmbmNen9vpYk+QDDtt0WSLcHVDeD7+i9/XSVpnS5+/IawoY6ZabD1
         BWmTpqra1q/TPh/Fc1RevOPAmKEhX3wgY0MEAGmHD1B/8JEhLgoSawtqObg1/PViVOuU
         RI7A1tQefoG/zxsDDoz4AwRkYR6Sc/2bHadf0pSdAU16LfLR+twN/GOjgviDM6CT+MQo
         oKYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lF60NJ/+n5d0V31UL5e6sUarRnQbqXDmCh4aTJN7Gqc=;
        b=azt0Zm4IDhjIEK2l0suNUKX97ziuTCDm0VAJgIZVZV6QF/T2pwjWr690YX35Rrlsf0
         7tj/YoHZ8rtjSSEKKY4Cv+GFBa1VUFUlqywqQqU79rJuoIfP7Fl9kH6pzdQPiKcmtN1y
         YxCtt3QDTmHPi8hgFJxjUvywOmzqRnr1OqBAfFj80Mkafh6AlEaB/jFhG1vci7zspFR/
         n0PM4VA0vWGu+lvluzhc+S9q2WSsUf/L17HKTSJqU8uYPf00OzvL3ISoF48tFRgI3ZK5
         yRefTE1cjvn54TaQYURaaGs6sIQ1etkpGBfSkntFLx1VTnrzDo8J15qa5UVy+/6Z/xzO
         P0fA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWmlrINUWr1KCFGwkWnZzUJJzx4lAV2TlrBaiNPhjD/mif1aJAz
	qtZ6Foewz5UZslPj4C30WD8=
X-Google-Smtp-Source: APXvYqztC/m2/1p49zPs+p4K0KaHYBNdTwaZtjYHn+itCJwH+NpTuIHbELab+DqlUAfE+j0ER6KYww==
X-Received: by 2002:a17:90a:23a4:: with SMTP id g33mr8988741pje.115.1565347445466;
        Fri, 09 Aug 2019 03:44:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5ec4:: with SMTP id s187ls22604674pfb.1.gmail; Fri, 09
 Aug 2019 03:44:05 -0700 (PDT)
X-Received: by 2002:a65:64c6:: with SMTP id t6mr17296111pgv.323.1565347445130;
        Fri, 09 Aug 2019 03:44:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565347445; cv=none;
        d=google.com; s=arc-20160816;
        b=nnYaas8e6g7L+KNYoEdSJhQrnGpdtIou8W1vdGTW8bYMi+u5ox9QxwI3FuYdGIf3Zn
         AHOq79MkYjcndZaAkPzE90r9cMjEg1PJAa+iVTVnvgQPqCktZQyUbGWW8cDyonkhMspJ
         gD0ZrjkV/kwV/n//ydRnSSKnPtJOxj8i8J2yndD2nIgK8a/aYxa8OaPB4spLu3iVBsfx
         fXEgk5hGWaVZxsbUsvEv6DQ2iLtYPZHKDMdGyPc7pxnTSQkpc3ei0+/i3qMEVXwaF8NU
         lo5Fv5kGjnPuWSVIJS4LfWnO5ET5/PTWwQrskUSa+Ado1R+s+EjOVcGEruGxYqFOXXyL
         8QLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=uyl2QkxI8bjHWzDs6dHWHl28hgtBHC5CtGBb4tU9kiI=;
        b=vABrqpaTUezeAMOD19aOOz8s32QasDJHvf/9tZd1V4yFm26fGBszK1UmHtoRgFmsn4
         RP3HCeoxbXRNM2x7uR62W8wehzV5UisNEfxsY/Et+x3CAwXUhh8ADhPZEeM9DbPFZ5Um
         eshJXjucjoSAv35+fYPDxwNY9m7qottrH7WoKJ3jPWOtT99ZxdhMaG1D7vmT+0l6zvln
         wwiDjWC22unl2tIIa9TKCL023I4soRfdcY1ftyp0/4qBGASXD0qEKn45klODctPoxMEN
         BjMsd/LLFRFeYxUqlG1pvQwpaiPKxTIg9/1oy6BJ7sO78nsY+uubgcPbPQMilQOuLqIM
         SGOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id f125si4715270pgc.4.2019.08.09.03.44.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Aug 2019 03:44:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id CD77828C6C
	for <kasan-dev@googlegroups.com>; Fri,  9 Aug 2019 10:44:04 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id B6ED928C5A; Fri,  9 Aug 2019 10:44:04 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Fri, 09 Aug 2019 10:44:03 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-204479-199747-6c1Hhfpz9Y@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

--- Comment #10 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 284297
  --> https://bugzilla.kernel.org/attachment.cgi?id=284297&action=edit
dmesg (kernel 5.3-rc3 + patch, without CONFIG_SMP, PowerMac G4 DP)

Here's the dmesg with the kernel built without CONFIG_SMP.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-6c1Hhfpz9Y%40https.bugzilla.kernel.org/.
