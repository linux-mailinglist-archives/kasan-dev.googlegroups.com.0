Return-Path: <kasan-dev+bncBCSPV64IYUKBBGOCXGYQMGQEBYL2OJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f57.google.com (mail-wm1-f57.google.com [209.85.128.57])
	by mail.lfdr.de (Postfix) with ESMTPS id D475D8B4C33
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Apr 2024 16:45:46 +0200 (CEST)
Received: by mail-wm1-f57.google.com with SMTP id 5b1f17b1804b1-41be609b854sf4285255e9.0
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Apr 2024 07:45:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714315546; cv=pass;
        d=google.com; s=arc-20160816;
        b=aRXOdjGeDPPM/HpNbZaNd+ym1SqNk/tP4C29HY86KPOLZrvqt5LW86GOhvfseJQx+L
         uvIfKA5KzZ+kmAdXNE6lRRW746TaI+6POkv1gET+0Am27goZ/CQAWyTMD0aJB5jGFbLV
         LPehfUzPRI6jV+H+nlyftvMnfrUOrKjs1uRUd0HZOJhqi5CPcEW4EpaKsYm6a6/JhTQr
         mAxi7dIrcECbhUyC4qrHleJsukCb0y7SabrfZls6eoyl7ng0VMCFFnTT/g1aX8JPa9bS
         ok8GOim+cqaC1uyLH6wGY/VdcY6DnblOd/lTm4fdp/yiOZEGd8y9T5N6REkAClipLmU6
         eArw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=DAUliQL/eP/Tfq5ZNGUdVMeZPqaKmIZRpBWlCkxnuiE=;
        fh=ezj9q0GJyTk/Amfo9PZxn8/4WoETwEt6BbhSwQPqRNQ=;
        b=TIkBv5hZcjMNtn7f5Ou0RRqxwhY4pa9PtCrpLtE4ePfdDcQxrJlF81y07snClLg43y
         zNS7sZWGO4zd59TRUI0AgRDgUaEWBRMGr8eadcARkxc4xnFErZ1VwFHlXf45DS03mbsa
         BMIthj2whOD3iwa0J2ij9N9HMd303O5L1T3aDo1bcD13fkAh74UmtuYzPu793TN2SMsC
         OU6oLxN28wq7ZAQzCb6/4Q/9EPr6xXZ9FrIbnZsZXV9CuEBEaIh07xNvZlJEslkMBiA/
         VrfmOwO7fgRsKHx8o8cNZWXTW+NBAU1I6GhD2RZdRgaX2vCznDW0PaHlZS5tgqiTJAsx
         CziQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=abUND1j1;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714315546; x=1714920346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DAUliQL/eP/Tfq5ZNGUdVMeZPqaKmIZRpBWlCkxnuiE=;
        b=acBFYt04CFd4un/FeGdUciAyWLpzbiPbfW8YPTGZlVZ4KTUp/Ys5KzBGiwmBW/EqX/
         vELAPQResG+HDMkGlbDgXw4qpsbpt3sgAbFj9FG+lA5/zC6OhcIJg4zu4gHz86ni9YIM
         Wxd+3/si0Gfp/BnmTAbvYzMGQOFCwTYFxHQq8f4TJJHYdEu5mud9GBlsoIjpyMFdP/Om
         xsT/L52C9RR4fMXRz0gpTJZuRXo6RiEhFXbt4AdQVEpSlfs7avriPsDQnu8wxSxoRH2c
         hMErEBNpCJrNKl7E4gDJR6MEQ2s2ceG76vsLq0zvoI5Kr8q+0sD3apWOXsHZ9tOn+pfP
         pBFQ==
X-Forwarded-Encrypted: i=2; AJvYcCUuIgoET74jdC7zlsA+GhzSBZMu6QoN3NMJvwZrQYFaqmMg1M4tUDUCCRPCeXtQK+X/5yKJIYTiVDHoGjRX7j4M8bWq1k3c/A==
X-Gm-Message-State: AOJu0Yxt6ErpFFTu8sjNF2Jp/Zq70kjeHyLeXOwyqzZSoodFcipsWNoU
	CIvXfOCIAiysUFOFJ1X3x4iCTScVGq37NtlzUY1j0xSqUyO9GatJ
X-Google-Smtp-Source: AGHT+IEXQ4HM/1oSwwvmAUYFrtqM9M3me1mW7TB+HvsOFOgqftbYD2PDllWgKRiYHzSlsfFkRrPOXA==
X-Received: by 2002:a05:600c:4d8a:b0:41b:f30a:4221 with SMTP id v10-20020a05600c4d8a00b0041bf30a4221mr2824494wmp.15.1714315545945;
        Sun, 28 Apr 2024 07:45:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:418:d423:a2d3 with SMTP id
 5b1f17b1804b1-41aed928b07ls12768325e9.1.-pod-prod-00-eu-canary; Sun, 28 Apr
 2024 07:45:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrcjL+h5z0mF4GNS1DJUrBsQiymc5Uzh8IS23zd5TC93pr0k4ZEXUXQJ9Jj170oJlKQIQaQPtNgNtfYF4q2/N/gGE4wOO+13M7mA==
X-Received: by 2002:a5d:5889:0:b0:34c:f919:d7c6 with SMTP id n9-20020a5d5889000000b0034cf919d7c6mr1155327wrf.5.1714315544093;
        Sun, 28 Apr 2024 07:45:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714315544; cv=none;
        d=google.com; s=arc-20160816;
        b=j5kf9V2Zx22tU+RbG0ks2mbFFTuF1iQ1PX9KxDp/RGmvi6jpy0aczbs4qkSLziLfAQ
         65OK/5cQy6LRd22pis8E7vyYi1+B9u0mOdR029KLOQXU3D43nlVWS7aSR7omGHs6fFZZ
         mUsOemArkX8kWkrj/G1DAOYMa0+8+tTkza9S7rEr/tIAEQ52wmFJ562vwtGw8golL9Ge
         oz3wKWJwuci3zvmp+EqL3JPnKFeUhArFvvdHktQcidTBcQo1wTAfK2wQQA8vERsl1iQ2
         EG3clRzjn5PbNE3d8eP364akwRqbcpvuzv5SiTWtUvcol9hw4GIIG8THyyL3gU2HNTCL
         jCbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9yWj9gnBpdQvY/FOoP2JiH4HKhrBwyUXjDq6sLrBxgw=;
        fh=+d8lygBbKIh1CEZ2pYCecM85UCoROVi+ORhQMTbubhM=;
        b=VnnTKDbdQanF77uXE6VHBppiHe7QR93dQ5AfM+V63jKUgPK4kJLtZlg5lU4YHZqkX3
         88pMKvnkFV2RFNeOzRzdMvtkqSY8bP/VHavA0vBQmTOdugm6oxcDC21fCcVwNUuOYfCq
         8wc8j/vvQZrrm7gTOSrJIBfxtWwQUGJMau960bjC0eU1V4K6A8Bqz4IlwoxVftwc4yeb
         b0lchbY9VK2uEoF0rALlpDxse+RzVlMVoYdjFntn5plE1qzv+mzeRnTm9MfOtMqLUT5D
         9y6sFCmwQAe34PBPC/NnQVBmCxpQV8T6CJ4SbmXifHYBzbABbSHpxIy22H1LPaT8z4p4
         wDVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=abUND1j1;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id p3-20020a05600c468300b0041c42b455e2si8321wmo.0.2024.04.28.07.45.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 28 Apr 2024 07:45:44 -0700 (PDT)
Received-SPF: none (google.com: armlinux.org.uk does not designate permitted sender hosts) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:41668)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.96)
	(envelope-from <linux@armlinux.org.uk>)
	id 1s15mY-0002Eu-30;
	Sun, 28 Apr 2024 15:45:35 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.94.2)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1s15mX-0008Qb-89; Sun, 28 Apr 2024 15:45:33 +0100
Date: Sun, 28 Apr 2024 15:45:33 +0100
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: "boy.wu" <boy.wu@mediatek.com>, Mark Rutland <mark.rutland@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Matthias Brugger <matthias.bgg@gmail.com>,
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org,
	Iverlin Wang <iverlin.wang@mediatek.com>,
	Light Chen <light.chen@mediatek.com>
Subject: Re: [PATCH v2] arm: kasan: clear stale stack poison
Message-ID: <Zi5hDV6e0oMTyFfr@shell.armlinux.org.uk>
References: <20240410073044.23294-1-boy.wu@mediatek.com>
 <CACRpkdZ5iK+LnQ0GJjZpxROCDT9GKVbe9m8hDSSh2eMXp3do0Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACRpkdZ5iK+LnQ0GJjZpxROCDT9GKVbe9m8hDSSh2eMXp3do0Q@mail.gmail.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=abUND1j1;
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

On Fri, Apr 12, 2024 at 10:37:06AM +0200, Linus Walleij wrote:
> On Wed, Apr 10, 2024 at 9:31=E2=80=AFAM boy.wu <boy.wu@mediatek.com> wrot=
e:
>=20
> > From: Boy Wu <boy.wu@mediatek.com>
> >
> > We found below OOB crash:
>=20
> Thanks for digging in!
>=20
> Pleas put this patch into Russell's patch tracker so he can apply it:
> https://www.armlinux.org.uk/developer/patches/

Is this a bug fix? If so, having a Fixes: tag would be nice...

--=20
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zi5hDV6e0oMTyFfr%40shell.armlinux.org.uk.
