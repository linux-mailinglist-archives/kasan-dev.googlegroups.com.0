Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBDHPW3YAKGQEU7N22KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id EAC5512E466
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jan 2020 10:27:40 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id z14sf21543573wrs.4
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Jan 2020 01:27:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577957260; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kf4f1Y2rI6w6dT/wrQlf0AyQpPxQt3He7S2FI4O9GNkE3K9SKjwl5qSgiLAOBDVI6x
         uDADjQFphtK/VeMkJL/m7L4zWo5KfKRCezJIMiAXyrIkP17O4Qw5ooVSTKSfY6DT2ZFN
         dedm6YFYa5ry3SqwQu8t1nRnaEW/cqiSmxkG3zkZ+6L2CA6csdjk721KD/mimcODNUoi
         /OcRES8SiyEATrvA+YxJN8PDi5ArvmUizLz2WfJxoclnsIWbHYxm9BYs6xhc55an9xbL
         Fw62AHJkGeiOzlRdOBPFYjrnubprwWikUiWh+6DCQYiytWsuigqDoBWTbGrZrvS+pv09
         PZmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=FKOwxCigBgCHLdtAd9MXBvJZKQcAQN9UgK+uDiSn7gc=;
        b=DDtEJiDUbTtotRJVMvqMZoZqeFAJubXy+/l3EbnnoHeCYV2VNMzYBF7BbyD0ll6uFJ
         1/M1YZ6a3WWFm/9tkNR8H/h9iAKXj6ZIq+zJ4zisxJ8sPEYUAKXI3xPJBGEXwwJMSE0m
         SXNz6sQ3s/5ml4FKnAlDQkUwxU2jgEKz4MxQSVLAhTkUYxDC3VGWvquT4XrSvtOgJTWP
         bK6gtBgdLlrTbuqmNBvR9pyyVtDpc9javym0YtMLw4y/kM41Ur8tZcfB4AporoTe4M+M
         V+wj/3mu0T1BvnpSTmNOYuyqjBrZeQLPcTy5bmMI630URVZC0BAO68uWKc6DPmTHlgUb
         6dzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=MUKjLCQD;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FKOwxCigBgCHLdtAd9MXBvJZKQcAQN9UgK+uDiSn7gc=;
        b=JA+pSGQVjhi6tw1eEmSM5RzPhVEJpJWjGVKiq/m7JwOGxtknM6C4bnM+sgHVbq7WpX
         N9zhvyB8Dmna1VzUSCpffkC3U81Z/PraZ02UH9M4egroVEwTkeyY3Lj/6gbmevXza9Rp
         ZTv2K0Bhh7TB7TP4YiATW275SeMkU3S7VXBA+xUEFjPqNeuoZblPWPSwFbZnvwf6nnQW
         F6QopWV71KDoN6XkivGfrQqAoXepQ8fcITvFJf9TEz7lxCmDHykcogDx8ViZnekO2+a3
         HsbCcuB3IoJgQ9juQwkF4v9JNF1JZvmFkIAUB6rcziHSYOpTnmgJz+rojQ6WpGrEFvZo
         6XTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FKOwxCigBgCHLdtAd9MXBvJZKQcAQN9UgK+uDiSn7gc=;
        b=NJy8nvLKhkHo4gaZRrBIMGAsiFceRWvLlMyyR+6gbDnk7QIBBKmz9SXi5dB72mEb1O
         XZeDb8YoaiHGaCMcINZjFqvSX+ttVixsf0qaYKonE8yRF35rGXrB+OO8RqMwqfXpAb4l
         tU0MhF1TqR1zj1l30pEjPyvpNp4nvHeO6+f7mI1Etr8OLB27YB2qHCtdcsAzz43Y6kky
         OqN8ViQWwVEUvZkvQRWhlBifrKjUMzFsbyrRt5cQBG+x7uj8WnqQcjPO7r4EE+gQhWGZ
         VMkVTJOx8idyGU+wd9Jb3RQbPmRe6XzWFIjBxzg5W7pinfaMtiimXvMvu4mAEif8iNtQ
         bwIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVmabWZRM9+RPEWT5KUkOMWoudxPrE+yBl+wUz6H+i71gSRiONz
	i2mf+IcQqzsvHaAu/8zB7ew=
X-Google-Smtp-Source: APXvYqxHug4OrZ/yOgr85TV53y7t7FvMTF8GDTuV8NJlc7SjF8V7H5vV+f0tlZEdZ7prBzcU0DYIvg==
X-Received: by 2002:a05:600c:2c50:: with SMTP id r16mr13040982wmg.74.1577957260670;
        Thu, 02 Jan 2020 01:27:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c3d8:: with SMTP id t24ls1800969wmj.5.canary-gmail; Thu,
 02 Jan 2020 01:27:40 -0800 (PST)
X-Received: by 2002:a05:600c:290f:: with SMTP id i15mr13757169wmd.115.1577957260211;
        Thu, 02 Jan 2020 01:27:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577957260; cv=none;
        d=google.com; s=arc-20160816;
        b=XOQ4pi5QNk0AKMItv0oU+L4V8SlRdHlnqy06trMDCH3eOa1hUJJl1DHYS5qPqlUZeT
         F7vzzJ9dTo7iEGWilLiv+eSeNvNwFtLaLCxJYlLylHiUNSsSHeBlVpIQm86fQB1m4Ua3
         27erI16WNOEP+gQwVAq/AXTUreJtRCYLJHfdAvs6Qa1QA0ED0LEBhgOuetSeUPJVqMBD
         LgOwLu10znRG/9nOFjGNoGpOq8bw2a+HpMgjaLXL/1vW0NGWaXnFydlwPDrbZ+Cjzc2L
         xyp5HH6QRHlQTsf0ojJJy2mlAOvcdvoI8bvRHpeX54IItdMf0E6LFYhtvXncTqsQh4lJ
         u1eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qFX5xVhEa7R6fr10YXKpmVLCawy4p5svcRjomdy8DBQ=;
        b=1HtPGdwv/pCG1KKzUXdA3XFl9v5/nUCZR1T4ggOX/AfWB2CizubRCmVxchCTnQjbyc
         g7u9HKEJZT0Xst0tmbCfzq2Zs81I/gtrdbOKRMHX27nwFLGPVPX5v0WEoBwVhuAog+UY
         ooFF3B26IBk23Fnt4rv1QLbhFLGfnkuTe2fPnfSVG3lGNay36OFH/jsxQjbT80+1UCiO
         vGqlla2etpIPeJnRvIK7rdx9Ss/bLWVclfZlDCqvdxT34riB+byalmMcbH7vXLvnc4eR
         EKegaAvJcGtOahuU6IiOtl+j/yahE+0HMSvVMxjPINl7Kd3ol/TST2WtWa9arz6PXt8i
         zqNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=MUKjLCQD;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id x5si433140wmk.1.2020.01.02.01.27.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Jan 2020 01:27:40 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F00E700329C23FFFEA6A903.dip0.t-ipconnect.de [IPv6:2003:ec:2f00:e700:329c:23ff:fea6:a903])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 69C2D1EC0716;
	Thu,  2 Jan 2020 10:27:39 +0100 (CET)
Date: Thu, 2 Jan 2020 10:27:33 +0100
From: Borislav Petkov <bp@alien8.de>
To: Andy Lutomirski <luto@amacapital.net>
Cc: "Kirill A. Shutemov" <kirill@shutemov.name>,
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v7 1/4] x86/insn-eval: Add support for 64-bit kernel mode
Message-ID: <20200102092733.GA8345@zn.tnic>
References: <20200102074705.n6cnvxrcojhlxqr5@box.shutemov.name>
 <498AAA9C-4779-4557-BBF5-A05C55563204@amacapital.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <498AAA9C-4779-4557-BBF5-A05C55563204@amacapital.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=MUKjLCQD;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Thu, Jan 02, 2020 at 04:55:22PM +0900, Andy Lutomirski wrote:
> > In most cases you have struct insn around (or can easily pass it down t=
o
> > the place). Why not use insn->x86_64?
>=20
> What populates that?

insn_init() AFAICT.

However, you have cases where you don't have struct insn:
fixup_umip_exception() uses it and it calls insn_get_seg_base() which
does use it too.

> FWIW, this code is a bit buggy: it gets EFI mixed mode wrong. I=E2=80=99m
> not entirely sure we care.

We'll cross that bridge when we get there, I'd say.

Thx.

--=20
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200102092733.GA8345%40zn.tnic.
