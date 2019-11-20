Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBDEE2XXAKGQEHO5IBYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 279D8103BEC
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 14:39:25 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id z10sf4099559wrr.5
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 05:39:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574257164; cv=pass;
        d=google.com; s=arc-20160816;
        b=OAUTYCTVQR8Y/CmPc/z9lhRf2AdxoetuP+fBtp+m4SlojLgGZUFTgjvk53NYTPAI7j
         xndhNLGnGoD6rvn8HHUfnZmXe47ulnSCHdKt3cNcSSl9y+ZpbOIV7s/Z3zv0ZYrCOirh
         gYvYXaakzWCDatwHQEC7I0qE2NkzlVTrXGOZwm1vWoozn7AthRPyRQMX5fD9QaUxyCYa
         uBGqISofONxsSym0gWDZTd9aYPYTgrQmPMxNqUTpWCMd7waaULsTzm7g749KSKWKEBNt
         btx2BYRI59U1nuPEt7A75F9hETWbOhHmgVSXXQXIbMYp/TFVa3hXxCPn6zSpKytc5Xdk
         nUtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=XKuZTE+wHkqCc2Hr0o5OsLGmKTYNk9TCUKgHO6ELOAo=;
        b=CWxiTESQIslUNCdfUTUl8PO422yxG3XapaLPxVl69FgI9/l8X9Bj2vtxd/NuczGyFM
         0Z8u90fZ6S/iHM7CLpc8KsbCZQjHfFYt58O2K/3SU1x/udc+tZlPNySaZZ8rZCT8ZHOE
         8D/4X/PKx2M0mAyu7olpTbpSd0c/t01dUIlkaOavfaW3MJKJaoHrByr8ir50DNetyxJ2
         OEgeMoK32/AHd4aSn9x9SQB4AQwWCcZSUIi/+2U6bPGYGniJiMLkGxB/861ai/jMUcKT
         Vk2sc75Ws5CpV+usgQesS85DLbmgwYgdUq3d0UDGByEZbyFDbWn+KD+7zKNRIq1yttRk
         NAIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=HWCY1Uyq;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XKuZTE+wHkqCc2Hr0o5OsLGmKTYNk9TCUKgHO6ELOAo=;
        b=kMWJpjznAtdkOj0/YiAKS0mEbjXXqpTCViKi1QByijRUb8iOVtKg5hMddarNLTx8eT
         7uWzUIq1Fu3mkm5/xPnhtZHfW+r5Io6+8RSz1J4tKhxUqtk8MtCqTFvz41JYYmp7oleM
         9AhTd+GQ7DJwgsCfeSmXUUjcOEGIUQumgcxfzVVDFpI/QhOKI3e3JZB6jO1/JRQ+OyfY
         kLxMDzUF0xx7YzAdAHe/1YHx5HBj3nt9bZLszcKoVGcovEd/hbKXiEPGdzz9Bs+FyR+L
         C2juNY2lZlvXfchbjrS0+Fjc+8gpwD2AEg9EBGZqG7iOAbH/kAzaEkkeSssDZktfacyv
         w2xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XKuZTE+wHkqCc2Hr0o5OsLGmKTYNk9TCUKgHO6ELOAo=;
        b=fVGC7fkQjDvREN4pr4cU0deOYB5KXaEw1kq7Vc85U+jLtX9gn2l768nYXs7aJ1a3tb
         qrslcpZa/d5y/7K2oXKQXcUONtIdy5vM8Aen3rvhq4pKhWLy83K/IRANBmxNKLpUQK7Q
         rkXCegPqSGd1YyoS3hkOeRftrdWasURzdoEwvidRElOeCDlXbigNTBTSyb1PF9HAyVpJ
         ZNpkS0QKQ5NqtC/aSo0XtFkL+6AHuHGLEWSKvk25IbcKzthVB7M+kLRlJhHwxuxQrsUs
         +VxcgdUYGXUgdOSwuEEZYandPXLPmTo4ASF2xMoApvt4XT6W79ZpIOV16NLKjcVHlgl/
         s8zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUgdC5TDj1MdZvh2vywcPThud+aPo0ozlRKhvf7RJb5E6ou2XOa
	+uvbegMM0p1K/FunU91M2yc=
X-Google-Smtp-Source: APXvYqzjkvaZ8CgggKcbF7Zijs3c1XbIF3LVs+NY5qW6RK6MNPOXPwo6qQOY3u5MuzQmVflzm6Tccg==
X-Received: by 2002:a7b:c95a:: with SMTP id i26mr3395703wml.41.1574257164843;
        Wed, 20 Nov 2019 05:39:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f10c:: with SMTP id r12ls874190wro.11.gmail; Wed, 20 Nov
 2019 05:39:24 -0800 (PST)
X-Received: by 2002:adf:e40e:: with SMTP id g14mr3543236wrm.264.1574257164389;
        Wed, 20 Nov 2019 05:39:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574257164; cv=none;
        d=google.com; s=arc-20160816;
        b=CuYEnLjNLA8FRHnYtXoHLZoNFhM1/MSh6lsoycS8XLssDVEHbwbGJBSkCAjHkS5Z34
         PUaR9fFewYyu1ssaCsQ9mA8q9TYlVVw5STCpEFqvmcomWKwQMZboBNLI+dKnLcbMTgyA
         B1ZDLiuRn4xe1SOP8N/kbbhB5i8HrHYI1QN+FVuuSHI9eq7BhOAkp0SLYSk01L7gtJsf
         hihrLN84rTEFwin/9oVXeyWI4OT43wbsAjO9ryOmmY9H6PlSgc7gdiKJx9sVwC0zEOxz
         hDsIzBOr0cmQbTQbpXNC8HhEsgYoVw3NLrv7Xnz9PkIMYwRPouOQlb4gMKxXyf0M5XbN
         T7wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QFI3bxCqn+b0PFcULsjiFv5KvKyUWgIUFkTaCiU0Ovw=;
        b=psohyKgNFr1MrSQKdgWh4auLZSOVkTT4Lhp4uJQG2VTiwiqL3pTMM/chDXQU1cV1KX
         t6kEQZZt8O3AE3tEnbD+45RTwyYzSvLyaUAKW0shQaAARnS3T7vlLwXpUaFfL9/T2CSA
         MqWlG4VjoFdoE3Biq0DoBzWS7iEIPBP5ZGtd2IqWruRffEqvHYDrfsUK2t6pNZa7yiYD
         vL78DJafSidZwsW42vuv6T+kV03DjMf2r/bGD3ifc7HLG7YdPZClHnsrO5n2HXDrby/l
         FOdKDpxIZrQCbFOKG3a/FDVy2N36Kadvb9b+NWQXUsij4O2YODxpNWBPgVd7I7laqac1
         9REw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=HWCY1Uyq;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id s126si228859wme.1.2019.11.20.05.39.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 05:39:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F0D8C00B1B17C12861BCCA4.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:8c00:b1b1:7c12:861b:cca4])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id C79B21EC0CC2;
	Wed, 20 Nov 2019 14:39:19 +0100 (CET)
Date: Wed, 20 Nov 2019 14:39:13 +0100
From: Borislav Petkov <bp@alien8.de>
To: Ingo Molnar <mingo@kernel.org>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120133913.GG2634@zn.tnic>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
 <20191120123058.GA17296@gmail.com>
 <20191120123926.GE2634@zn.tnic>
 <20191120132830.GB54414@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120132830.GB54414@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=HWCY1Uyq;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Wed, Nov 20, 2019 at 02:28:30PM +0100, Ingo Molnar wrote:
> I'd rather we not trust the decoder and the execution environment so much 
> that it never produces a 0 linear address in a #GP:

I was just scratching my head whether I could trigger a #GP with address
of 0. But yeah, I agree, let's be really cautious here. I wouldn't want
to debug a #GP with a wrong address reported.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120133913.GG2634%40zn.tnic.
