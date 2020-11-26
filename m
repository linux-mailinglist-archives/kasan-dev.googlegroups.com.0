Return-Path: <kasan-dev+bncBCSPV64IYUKBBCXZ736QKGQEWXNRXAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f56.google.com (mail-wm1-f56.google.com [209.85.128.56])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A8792C5726
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 15:32:46 +0100 (CET)
Received: by mail-wm1-f56.google.com with SMTP id k128sf1453555wme.7
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 06:32:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606401166; cv=pass;
        d=google.com; s=arc-20160816;
        b=hegxPQcfHpjI0m3mmi5bOvEf5Djfuddnf3nrY9d8zNe0acCTuo4AabU4sWHuqE4bdW
         d+mIrQQe8bmTFWMOh2NAX3605J4aDLmE02ORXEDrDl2L+CUqX4CWRTqyGvV54f/GerZ4
         qCOm5OK3hP9DStaWL6Kl4dpiSaBanDGhEdUjC/xIu1jf0mP6Zdh3sQTAj7UDDEkcm18Q
         E5XbfdQ7HlOc8dvE7hWAKUMjQ3twn7BfUOEnomtyo9E62G2KBtbOzQpe6yBYi8b7TNKY
         6NQ60NL5fxtJaQNBxJNPUNB/ZZCl3ByHX5mOEhmoU5uM1ecRJIyHNRN/jgesX/SrNJNC
         oSng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=ZenjeN/yT4I/PXvVda+zfqc6E+pqFYJUZucgoJSkxXU=;
        b=IMHjAbt5CellXWgA02oBGE/Lw9s+JgHJVYONARG6r7xQIvz7YhK6m6+A84qMyH9b7i
         GQK8be74VmwFj0bWEuE4Nl8vrVZtMTE2f3kVCX/qHK59mHCpSXS2i3mbmTn+vWDs0VBZ
         qKLljGWt7/mUv/yhcO5pZQriaAjuivHgAxVD9Li4+n/+GKb644WE3KINtRZ9Jd3hTxfK
         iFxd8qCgSrMx7WdiimT3TAjSaciBifZa8No2loZoyiPhbXgLTsJmvBfQ4wUEj8AP7p8r
         ctjlUJhvsAloooO8F34GqBpNELGC7LHa4FUAVUcxel7f3s8ahPzOhgUrUGEpkV6VFaUJ
         6gmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=Bn0ztgSn;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:sender:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZenjeN/yT4I/PXvVda+zfqc6E+pqFYJUZucgoJSkxXU=;
        b=gWh0fv7O8V1ANkYqzLI72lvmKyFKgmPMeq5sUnlWgxe5GqlD+xdZpD8NmjOARjox/C
         fU+bqZbeBk6Vz2KJo4wLBT2DN0wwKcj6fhbwwYk9CSpvkOQ8p9hnnSRorZMoLFm9gRmr
         yI79dbtSnX2j0zhFvR+N6zdbgbX/x3o1AG+rPswnV6Pichhv25DHkUSYtgrkVVhLS+4h
         0UYqOQ97FZnzK2fcBNKb5AOIr1Qu0KTvsgb2ZnfGYR1gNg8j1Dug0nPA8DNAMl3y+2CC
         9Ew1hyHxoS7LxYp4DyUBaRA1roS7vgE/lY4L3B7yrkA331iUHyyLSE1iXxLG6hsKB5Ro
         MVbw==
X-Gm-Message-State: AOAM5325dKSBeZOiuJ0XTfPjtkqWHiiXEMdClF2XHntOr0ySIsCKPWzo
	E2NPm/24/wAdmJTEdOYzdO8=
X-Google-Smtp-Source: ABdhPJx7zBf4jJVDjGD+8GfTehDN5W/7v3sYnS4RJ5E2zlDcHfxMY0lLFljPFRH4CPM+qf12K2FcwQ==
X-Received: by 2002:a7b:cd10:: with SMTP id f16mr3766948wmj.69.1606401162699;
        Thu, 26 Nov 2020 06:32:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a4c2:: with SMTP id n185ls1065405wme.2.canary-gmail;
 Thu, 26 Nov 2020 06:32:41 -0800 (PST)
X-Received: by 2002:a1c:b486:: with SMTP id d128mr3347513wmf.95.1606401161429;
        Thu, 26 Nov 2020 06:32:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606401161; cv=none;
        d=google.com; s=arc-20160816;
        b=GLTRyozUPb1HupCKke4+V48X8geXAB/uySLgWhxx4r6i6P6TR4jTpxcMZe0xPooK+d
         gAhP2B6u/lqrZoihy8aud05BcTvaubW7x8V/nIGzeQtfHTc7mCO9W49IyOVF/hkK8wQR
         sMTh4QDFeV+sB2O6oThQeINKqKBpLxFUE6OvQ/rs5GANZbuoLX8cvJtEhSZpVwl+KdbG
         yGdLl9T2nlTJkcNGaMNkvyL8k3vajsFmJLpprJHQhmMTaIN3TizIsiKHw4TF5qm+XuoR
         dBuWHXB1lS/ohotpcSgd8LiPCCAXFB5uVPS2JTu7uBSaU5dYMVwd1jWyM9+C69NQ1pcj
         Q2MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QTfMxziQKyFbMgmeFNP3IA9HsryyERPG4sSiOy7QmlE=;
        b=zz8Zj0GuPRI3/r02ffwiJzQhimOnhy+GuBdTw0iVhTftTbMLfmI8s5SgBXk/qIwA8x
         F2q0ROucfO2vRMfeh9DEMp5W7DluOvd3Xrgh7+o6zxNxDFKwWs7alb4LW0JiLho1eNJl
         WBLTUfaz9K/SeJB/whoP5yYfB+YKq1zPxsIJC8tGUQBVAbTY7fr59EW6ymihhtkgFVAY
         LYfkSzWitEjBEkc7GpKJe1ePoGmWT0w+GeHvFd6VVCbRGvpFC5UU+4CLnS8UpqbQLCNc
         m9LTE9xmf1GoyoeziHx9AXVMDxhdDH0tia5Z2Qzv7ov9m0Y7CF3D+ZvKDDFvLLDcBFq9
         l6ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=Bn0ztgSn;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id 3si132879wra.5.2020.11.26.06.32.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Nov 2020 06:32:41 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:36356)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1kiIK8-0001sP-Kk; Thu, 26 Nov 2020 14:32:40 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1kiIK8-00010c-21; Thu, 26 Nov 2020 14:32:40 +0000
Date: Thu, 26 Nov 2020 14:32:40 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Valdis =?utf-8?Q?Kl=C4=93tnieks?= <valdis.kletnieks@vt.edu>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Subject: Re: linux-next 20201126 - build error on arm allmodconfig
Message-ID: <20201126143239.GM1551@shell.armlinux.org.uk>
References: <24105.1606397102@turing-police>
 <20201126141429.GL1551@shell.armlinux.org.uk>
 <28070.1606400573@turing-police>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <28070.1606400573@turing-police>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=Bn0ztgSn;
       spf=pass (google.com: best guess record for domain of
 linux+kasan-dev=googlegroups.com@armlinux.org.uk designates
 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

On Thu, Nov 26, 2020 at 09:22:53AM -0500, Valdis Kl=C4=93tnieks wrote:
> On Thu, 26 Nov 2020 14:14:29 +0000, Russell King - ARM Linux admin said:
>=20
> > The real answer is for asm/kasan.h to include linux/linkage.h
>=20
> Looking deeper, there's  7 different arch/../asm/kasan.h - are we better =
off
> patching all 7, or having include/linux/kasan.h include it just before
> the include of asm/kasan.h?

I wouldn't like to say definitively - it depends on what the policy
now is. However, linux/linage.h is way cheaper than linux/pgtable.h
so it probably makes sense for linux/kasan.h to include it given the
number of asm/kasan.h headers needing it.

--=20
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201126143239.GM1551%40shell.armlinux.org.uk.
