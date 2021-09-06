Return-Path: <kasan-dev+bncBCSPV64IYUKBBOVA3CEQMGQEHA6BMCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f190.google.com (mail-lj1-f190.google.com [209.85.208.190])
	by mail.lfdr.de (Postfix) with ESMTPS id C49A4401BA4
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Sep 2021 14:57:30 +0200 (CEST)
Received: by mail-lj1-f190.google.com with SMTP id v2-20020a2e2f02000000b001dc7ee2a7b8sf3197000ljv.20
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Sep 2021 05:57:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630933050; cv=pass;
        d=google.com; s=arc-20160816;
        b=W1kfYTC/I/b1zqBGk7JcZE/q1fVsZApfR9mPrEeSIekWUqveThgPJPxcF7XoD43nTf
         6ObW2i/i8tYiG7ihfKGQnWjH0Jz5OdJbuXR+aSy8VIKjtpbaVA3R1ACY1RFRhOb06+MS
         TaRiFB/8BhxvpwrBYNO0uBCo8l/9rxpv7lxmbIqTZETIR27TvodN0sWtvuowDBn68Zhw
         WNRSCm257X+Kn7P0HTXyyUk0b+fO/pBN0SlRmCz2/5R6lu3nXzx09nCZUeTHYol2v3a0
         KPO3yEGiWVD7EiPx64Qp87I0/X74Mz0U6XHQdnIwfa8fDAQT1BopKzSVXwOOyWyEEHN2
         ymFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=uwCgJln8HqY78yHRlYLCO1lfWIscNSg1esJBx74jhsY=;
        b=pNsylJPJt9JrhrQPLGp0eSP/S1ngxBwlcyz0/737xYmON8znOkGhKkzLDzXjcgJiQ5
         1ittIHRQs9STtVnTKq5jwgUIXfB18PhnAlDuKhkSf5MtoyPpV09rKi7It781HbfbT+25
         tRhCUhe30Zgl6M2AI4lXf8EHY8Rqy5MdYQ0A1IWgfyXhkKRB2Ro6bVSOLIckIK3mUXNc
         wGGnce+9DVo0qSo3ReRuyv/8FMW3A8QiZGyg9GEl0StRSjHrN8fyd+eWMpHgGn/r8TTF
         R62sMYyH5qVHtc3/yC6ZQTitL4HBnoQEYt1LC9xBeeqPhTpX4aQJqT3Vin77q5SrS1Nw
         2uoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=c7+UTnfH;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uwCgJln8HqY78yHRlYLCO1lfWIscNSg1esJBx74jhsY=;
        b=jcEPqKzwHKP+PYh9bKT8Qecst8OgWBej92dP9SFgWpn3gCGANFUIE4N5hd/px0j7Ia
         nnlTBh7Xbe0ICWNe31ue8UPrWWhuMLAM1f+yk60QDpQ2cdexzsLFoz01u6gSUdY1/pa+
         FzD2iQ5qvQiT9jjeAjCGzbmhsqy38OQtqAlEPf17kS0clc/Ll9k+gBG5SEj6Qw+w4WGu
         sfdsVq32FwDw6eOtllLW2dZytYGzdwHk5naK0xxH4rqvnKo01feOo6E+dWxen8ozTTsY
         2dHqjt2/Y7ENIvipgfDIYbauVCce/+y5C1voe9ZhAiDOixu5Tytwt6prBjn2G6Ou0hrq
         N7Qw==
X-Gm-Message-State: AOAM530xPRPn3atTq+7VtMzZ779HZ1hk5CTVF/Rd2xk55z8v65YhHge1
	5WV/vaofaj6DN4xDv500Z4c=
X-Google-Smtp-Source: ABdhPJzsdc/6ARSGVaeGrE44+NN03jQdGqdp4da0OATeXTxDgMWNjcJzITI4FOv3FPwCqw3RrrfOmw==
X-Received: by 2002:a2e:1556:: with SMTP id 22mr10342558ljv.253.1630933050352;
        Mon, 06 Sep 2021 05:57:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:597:: with SMTP id 145ls1040611ljf.7.gmail; Mon, 06 Sep
 2021 05:57:29 -0700 (PDT)
X-Received: by 2002:a05:651c:b09:: with SMTP id b9mr10353448ljr.307.1630933049345;
        Mon, 06 Sep 2021 05:57:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630933049; cv=none;
        d=google.com; s=arc-20160816;
        b=HLSWRDuGi3gyUIGSvw86aakwSc3q2AUg7fyzGGNPqenwV/INV/xfA48XLNdQoN2r3t
         gmKeYfZhkXOQV1v21N/C4p9+UVrgpz5H3R+RYZHEl/9K1SwKExIXIlv/ILI0UJqf6vcm
         L1cfarX+nMRqrPXvqUGXQiRKq5UdzYveTtWahko2BQEyn5wdKttRNDnp/m+mbkSwAQPm
         ueUdFweUQea9VFhJm5mTqOf5cVrCkZlqAG264t5DuwPGUEsQCO0bOKcS/Fc5x4V9yCju
         s/DhmtvF2oUq9pTLK2MMaB8GP02HYfI6hSHgXEWTsEEMj+BwVHb4vYGWag7HzpAatFGs
         DfbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SpHVySU81J3sESD43nj/2jkGTDf8wGJk/uyN68gQocs=;
        b=OguXFdeZPyR7JPHLg2/ePnEbtVe0iclSSfB3fApKXvU2ly5VMskyMmmIxt+w8cLcSY
         G8w3DXqDnBDopp3h0ntPEPqRumo+tdbSkvPQg+Gcir+99hnga1CkqTc0f9l3qq3kIj+y
         UEwSSsYxNuKN1UTNiTR1MVyxbj21W0/Ug8JJr61Z+4WE56WSQR/z1t7W+WYt3jgZKNub
         rcY/gaP5bQ6notErFUyHdN6yaG4xKDpZ0jsUPZ8h9KnzVxTiclUJtcSggeoXSgclkIgM
         kYALjJC/h/DnF6ub1VY7yjUXRSt82AXHRz7lPdqzs2EbfUcPy9TDUK56CpkK3Lbl+2eI
         ufCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=c7+UTnfH;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id n9si288817ljj.8.2021.09.06.05.57.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Sep 2021 05:57:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:44978)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.94.2)
	(envelope-from <linux@armlinux.org.uk>)
	id 1mNEBa-0001jY-Ed; Mon, 06 Sep 2021 13:57:18 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.94.2)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1mNEBW-0003IF-13; Mon, 06 Sep 2021 13:57:14 +0100
Date: Mon, 6 Sep 2021 13:57:14 +0100
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Maninder Singh <maninder1.s@samsung.com>
Cc: "catalin.marinas@arm.com" <catalin.marinas@arm.com>,
	"will@kernel.org" <will@kernel.org>,
	"mark.rutland@arm.com" <mark.rutland@arm.com>,
	"joey.gouly@arm.com" <joey.gouly@arm.com>,
	"maz@kernel.org" <maz@kernel.org>,
	"pcc@google.com" <pcc@google.com>,
	"amit.kachhap@arm.com" <amit.kachhap@arm.com>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Vaneet Narang <v.narang@samsung.com>,
	AMIT SAHRAWAT <a.sahrawat@samsung.com>
Subject: Re: [PATCH 1/1] exception/stackdepot: add irqentry section in case
 of STACKDEPOT
Message-ID: <YTYQKgKspSPORGH8@shell.armlinux.org.uk>
References: <1629270943-9304-1-git-send-email-maninder1.s@samsung.com>
 <CGME20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a@epcms5p6>
 <20210906124351epcms5p6020fbfe5f885f1e8834a72784b28d434@epcms5p6>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210906124351epcms5p6020fbfe5f885f1e8834a72784b28d434@epcms5p6>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=c7+UTnfH;
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

On Mon, Sep 06, 2021 at 06:13:51PM +0530, Maninder Singh wrote:
> 
> Hi,
> 
> Any inputs on this?

No, I've not heard of stackdepot, I don't know what it is, or what
it does. It doesn't appear to be documented in Documentation - case
insensitive grep for "stackdepot" gets no hits. No help text on its
Kconfig option.

How are arch maintainers supposed to know anything about this?

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YTYQKgKspSPORGH8%40shell.armlinux.org.uk.
