Return-Path: <kasan-dev+bncBCSPV64IYUKBBJNXUGYAMGQEA2EGZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f186.google.com (mail-lj1-f186.google.com [209.85.208.186])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BDC8892C90
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Mar 2024 19:36:24 +0100 (CET)
Received: by mail-lj1-f186.google.com with SMTP id 38308e7fff4ca-2d6ebaf2199sf24210311fa.3
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Mar 2024 11:36:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711823783; cv=pass;
        d=google.com; s=arc-20160816;
        b=ihC8j26dPdoW/O7FC64iYphHTZVtVNHsSpaD1XThZ/25SZGMfm2r3KIQQeO4jr2/DS
         lWz6EqGsTMY3bVrFjMe7lCLFdf0PA4pjPsW4fcOFXZq1yqC9nAOx+aG7eozR9VJ/ke0E
         6udhzHAvzi4x5r1S7U95tpPPA+mEyMeU0WBrTiD2m5usjd7LwoPAybDV7Rbe6Dpl5UFJ
         lUMCjxLPmrgnWLnUWz41Cm7Zcna50xImxX6LclWdadXW+EBlnGwgYl0Q4+xOI7V5furG
         6/5XuTHlfycfkuhN8OU0WYHqy5IjaYqf1kh9nR2PwNpcHBJYrQcZobI1w7jvVf4f012R
         R4PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=0gUHG38C1ul/7VACK8ZYd5qEWWmx7ujFTNsIz3CS9X0=;
        fh=iRCqzM2l/tX007E5ihSPoyHuMBK8p7WOJ60FNWYKRZc=;
        b=Ixtyp8Ah9gueTNx4uLEQ2I0GffMplj6tS9PDZjgP5Zri+3fyWB5T0vtlvPBFhbKuNn
         NedFpurDsivthi8sW5qFo5gnaXkCA9CNWnR2LPo/pdOGbNv6riu0NFmz539KZFNin1ym
         9HyhvZEgAauv2wrQmtsNJfnTNxjcmGFcTdR+gEDTXOOyIZ1vmzNyO14bZL/BzObvlhpi
         43DmOETQHv1wWgq5a59hZyv9njRT0Ipk8ef+fTmgfowaEqEwX1Z6dETYgSxWQKK0j9d1
         uSHFwNJmjalzKhOccgwh2L4n0OpIcyLHVStyhLnvWNmo3l2AoeKoDYM/XJrulAKQ3upG
         kU4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=KnWNOYYg;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711823783; x=1712428583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0gUHG38C1ul/7VACK8ZYd5qEWWmx7ujFTNsIz3CS9X0=;
        b=YtC+iub4uj99pvbboZLRY9AuiKvyKL+UNbI9Kv2A4q3CohQvfJCkQ2n480yn8ppwub
         32gO5+1KNjqnjGhjlGKqh3/2bqYSiOPn73Y46LxhGs8PUkMQjtWMIHzXllBkAMj7uFYX
         BgK1bALDThbehLGVU4OzQeoxx4Yz4QVsDZDjswWJ1gMGyNA81vBfrUPkazpVxjxtNuXr
         O1yelveF/Dt+gakazewzMrhTH68h//cLgqVRpPc7ji4Ci+Kx2cFCVJ/IedVdND1xFV+6
         u5s2XPZ5BDOATd7tn6rqtdLLFoFzNz7P+lSJuPAyJ+oI0/Pj+DWUGcrYrZTXlfgkG30Y
         WJlQ==
X-Forwarded-Encrypted: i=2; AJvYcCVbeE68NypAAni1ipMnz/NEmvSdE8229qs23r1kYRtg37jstFYz78zLwtgVtxeaWARIbt+WWW9AZcJElBbuBwiEanjIn4XQBQ==
X-Gm-Message-State: AOJu0YzfWUyP6uWpQUnxlVqN8gm4ogDKrqouPky5pOslcZvJm6tdwitm
	QCOfhSAqSSjVm0CAbvNCowXSBM/hefDQhLySEY2twmICAolnSYEN
X-Google-Smtp-Source: AGHT+IHHZz2gHwd5UD4nkKVjyQozHozAffGI6yKyIiy6HbV2DnMHw2mfeChnLNnstXnXA5t1jq5MTQ==
X-Received: by 2002:a05:651c:4d2:b0:2d3:e954:221d with SMTP id e18-20020a05651c04d200b002d3e954221dmr3734011lji.34.1711823782012;
        Sat, 30 Mar 2024 11:36:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8495:0:b0:2d4:714b:4e96 with SMTP id b21-20020a2e8495000000b002d4714b4e96ls1430102ljh.2.-pod-prod-02-eu;
 Sat, 30 Mar 2024 11:36:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVc/AkgHmGXIxh9I94SptH3mKk1rKFukM6WF95BBWpIfTJx0wpKx64zHXGRn9WJpe1fN1O4S4CVrEEWRAdgp7rckKXUJQNbs8OxSA==
X-Received: by 2002:a2e:a17a:0:b0:2d8:fe7:a119 with SMTP id u26-20020a2ea17a000000b002d80fe7a119mr54489ljl.5.1711823779947;
        Sat, 30 Mar 2024 11:36:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711823779; cv=none;
        d=google.com; s=arc-20160816;
        b=A1DIvGK2EAHhmkgCONxniFh1CLxHQ5V+FEEXlvs7H7gcOaIixAHJt+jDMZnyFO+XOp
         kqNDm6mdue1xoKozIglraKag8VgyYKhdd5wv4rFrSnwB3Uun9hnoEP9cleequ3JbyXV/
         MneSGhLRxT1to7bn+52yRMca62g04ztkOpONCY3S7QffJdwVnUgSu1rLpP31CKtzT4m8
         Ckp7LgmmfXoLI6lC3PXHqtDpUfRFv7iuLgf5eEKbKO+KkrB9uutH+jyn2PNvnsypKcUg
         R0XqA45ivsCD34HFYmfCBcj6p/OFfjqv9cxKbrb7U7uJpSHua1ASwWZGbLrCu1I4x7uK
         XLFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ujY+2Fajyw/i8qIuOZQSTD217NXANw6Wgvcz9uBaBAs=;
        fh=DlMOp5k+WKMtqlAw6QIl+fxHNo5azW6W2Z8cPICtaS8=;
        b=enAo8FchZyi3fVeiHRO6XuQ6RbUDdLJFg+NB99R+YQrLNLoCML/oNHM7bMWbiNFGuw
         4OtZf6iAvldi7Uex+1L24GMeG2ySFWmwWAZIpRxuUZX11BlgKU1SVGbn4AKIvNDa14O3
         m1cW2FpeU1mdmvW/oOpzovbEga7LDpoeCv9suujZfmR+AfRAadqXnHcYbBOQpyePuFRE
         9nRsmp1ImVlSs/HIrbwbzbmekYRuG9ez9SeBsnbxI6iP2ibSyPBxdU2kXuPwdy9liz4j
         FykTpp8/2OL7Ew9BMPNzuLVdMwGO0uRdAV+Agp6mxk2s4dlL6wRNMN2eJ7uYFhrv1B7w
         gNRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=KnWNOYYg;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id a22-20020a2e8616000000b002d471e919d7si185006lji.7.2024.03.30.11.36.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 30 Mar 2024 11:36:19 -0700 (PDT)
Received-SPF: none (google.com: armlinux.org.uk does not designate permitted sender hosts) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:59452)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.96)
	(envelope-from <linux@armlinux.org.uk>)
	id 1rqdYl-000387-35;
	Sat, 30 Mar 2024 18:36:08 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.94.2)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1rqdYi-0003rl-38; Sat, 30 Mar 2024 18:36:04 +0000
Date: Sat, 30 Mar 2024 18:36:03 +0000
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Boy Wu =?utf-8?B?KOWQs+WLg+iqvCk=?= <Boy.Wu@mediatek.com>
Cc: "matthias.bgg@gmail.com" <matthias.bgg@gmail.com>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"angelogioacchino.delregno@collabora.com" <angelogioacchino.delregno@collabora.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>
Subject: Re: [PATCH] arm: kasan: clear stale stack poison
Message-ID: <Zghbkx67hKErqui2@shell.armlinux.org.uk>
References: <20231222022741.8223-1-boy.wu@mediatek.com>
 <6837adc26ed09b9acd6a2239a14014cd3f16c87c.camel@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <6837adc26ed09b9acd6a2239a14014cd3f16c87c.camel@mediatek.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=KnWNOYYg;
       spf=none (google.com: armlinux.org.uk does not designate permitted
 sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
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

On Fri, Mar 29, 2024 at 03:17:39AM +0000, Boy Wu (=E5=90=B3=E5=8B=83=E8=AA=
=BC) wrote:
> Hi Russell:
>=20
> Kingly ping

I'm afraid I know nowt about KASAN. It was added to ARM32 by others.
I've no idea whether this is correct or not. Can we get someone who
knows KASAN to review this?

--=20
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zghbkx67hKErqui2%40shell.armlinux.org.uk.
