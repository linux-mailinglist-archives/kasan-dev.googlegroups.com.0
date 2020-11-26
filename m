Return-Path: <kasan-dev+bncBC6Z3ANQSIPBBI7S736QKGQE4VGCTGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-f189.google.com (mail-vk1-f189.google.com [209.85.221.189])
	by mail.lfdr.de (Postfix) with ESMTPS id 180E32C56E1
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 15:18:18 +0100 (CET)
Received: by mail-vk1-f189.google.com with SMTP id h22sf750814vkn.22
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 06:18:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606400292; cv=pass;
        d=google.com; s=arc-20160816;
        b=nwrM+VgyDEyS5JnAHy4GEVbRTeuz9i6VFc6K4c9Y890lkh3zPjn5krQgCLfokroLCH
         z67xWGDDky9yle38tAAg0gml4m6M7oiNu4UdkpeGa50gkGuj/DcJLx1PyPC/mV/2xn/y
         FmRu1RTfKvIxaHn4x2x9Pq10uRINBz3dLmPFnmMs3sLg/w/XCI90s6MrmmN+Fml4F4Z+
         XHyJ1EoNeKnSUqyxUHd6/60bMB6m4F+rc6nZzDR8V3CqCQjkHChjPSHaWt0f4uO8GHlX
         aRLHsw6SSCjVv6OpoafJWmpF96fEHdlOhL/LouF7WhUglNuhz2LrQP4M4gvOAG9DTz4N
         LKSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date
         :content-transfer-encoding:mime-version:references:in-reply-to
         :subject:cc:to:from:sender;
        bh=JdzZvLZ/t5xOdPkbM1SytwxCRUiLfy1nQ3KQfSAqR5U=;
        b=eXUw8kF3B0xY3A8XCW7wlyQJKfArfA8PiczbF5V+pL6fdayWLoQhiApbXJuadGb9x9
         LY9ONdHiSZyNFofdUqoR1vSRZgF4708p1oG23iveC6Ma7eddUT1gM0fERrYBvZfAjmx4
         CKjxv6/s4HPIjIxOnmaKAVje2qa1pTKKOow5jwx7GaFoAfq27AT+hzY+ZvG2GDWYvOZR
         UswgoDyBv8W9wzoZmmL35EBekDNY8FWDldymlZMDrrZtSTXhkfXju45woz5s2V3fQzFl
         FTNQu2kw2Cp0sBGSy70RWVSZcXr6SCD7Fq66odB4Np4WeApCuZHHUiIfnc0Q4ujFdEZs
         tO/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b=k29quvvY;
       spf=pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:from:to:cc:subject:in-reply-to:references
         :mime-version:content-transfer-encoding:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JdzZvLZ/t5xOdPkbM1SytwxCRUiLfy1nQ3KQfSAqR5U=;
        b=eAxn+Zl+x8QlvJIk9nqKrrv5UBTwoFwI+wfUfoP6REIXWvnCeHIm9E54mT0tlcE4Nk
         wP4czWSv7t9iKDNwD+ubamCzyMi3AwKBl7ivWNnK0qzAtY7Worb161e7DfKTJL6d9Io5
         R0sJsdKAltkK6L6hgvvceipUIQYdDMLHuj+fw60NmDFlCAhWkcyE9chqPNnf5AAFi1OD
         WOBE5gNtqwL06DqUzFI25VIJpr1JC4D2oJjwi16009Vm1mPZx1jfPR+1igMh2FLqg1r/
         d97tQHXSSOlg6xTK235nSXRADd2vCCcGy0Q69ma9TkYo9E6j7VTxg/nHMsB5KwvmIVWz
         H17Q==
X-Gm-Message-State: AOAM531ook8e2SYqFtLX/NESZ4rjm/UIC6ORE73N3Mwk9j1R3h8LaIPm
	nt8ErWL1Wgv5aX4vD+fxqAI=
X-Google-Smtp-Source: ABdhPJypvW7EFpmTBK0Jsa0QNQRUSDLZjJuTI0OpgyoPHLzSAYy7OSqYtBsi56vHzVMAss20z4aYcQ==
X-Received: by 2002:a9f:36a1:: with SMTP id p30mr1705246uap.64.1606400291790;
        Thu, 26 Nov 2020 06:18:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1145:: with SMTP id 66ls118366vkr.2.gmail; Thu, 26 Nov
 2020 06:18:11 -0800 (PST)
X-Received: by 2002:a1f:3105:: with SMTP id x5mr1966401vkx.1.1606400291061;
        Thu, 26 Nov 2020 06:18:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606400291; cv=none;
        d=google.com; s=arc-20160816;
        b=EMHuCW1P1L7gyXDMUv478dYBAGIMSvOJ0pWas6N1lRMPm4WyXJPaT2YVz6K/85CBIX
         z1pdGAGImhIJ/rM14uo97NZvXRFNAFaveXLHamVr/Bm4riYBSNiNLfFvL2o6MML/rvab
         Z9t/Sz7AX9GaJwmXD+gJxjMrYjjzaU0a1SM3hQH7vj1HlWUi1rh4V364cdAsSOEy4XoL
         K7ju6eRa2H0tdhjJsYgHMg7CequgMFaR45pp1u/eg5V2sRmcLK4buIEYz6wjFEO6y1id
         0jFpRJKW2pHy8tTV/k4YjzqgSUrD9jDfhiu5K54Tsi8qx/88QUXBiVHFxlT2BqMvgR7v
         yRjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:content-transfer-encoding:mime-version:references
         :in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=R6BrEWkteQvQbjsApcd3N42+tWQEuLbo/lT+UxHp8d0=;
        b=RS4F8Bp8MhQEJNZOLPVFBaj1cwrSP20fsA36BSM8I2YbD7fUfujJlw3p6PxsE0tGMp
         QyWFmXiCDZYWQho/1UK5OuuOgZAZL9as6xhD1+L5fG35ge0avxUxBQvQ6qTCLsqJvhJz
         PKxr+lgfl3lrKpzNzfb5UbYrvSZZm6GyXuzSWL7H0M7vEkZDfTAtr2Rf8ITqrG8oxQes
         WAMltm46A5B2lE/+fShoy4Uo3Zt9N/gCFCfDt53YE4sYniHvE0TIi2vHpk5BKEnFe9Q1
         /kA/tvA9h5HYb6yb0h0qUqB+3Kn7wiimVZqAu/vhRvzD1sOMS5RM0oZHPJszVdccKr4M
         wW1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b=k29quvvY;
       spf=pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id b25si382825vkk.5.2020.11.26.06.18.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Nov 2020 06:18:11 -0800 (PST)
Received-SPF: pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id 1so301814qka.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Nov 2020 06:18:11 -0800 (PST)
X-Received: by 2002:a37:5444:: with SMTP id i65mr1818763qkb.263.1606400290743;
        Thu, 26 Nov 2020 06:18:10 -0800 (PST)
Received: from turing-police ([2601:5c0:c380:d61::359])
        by smtp.gmail.com with ESMTPSA id n125sm2636977qkd.85.2020.11.26.06.18.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Nov 2020 06:18:09 -0800 (PST)
Sender: Valdis Kletnieks <valdis@vt.edu>
From: "Valdis Kl=?utf-8?Q?=c4=93?=tnieks" <valdis.kletnieks@vt.edu>
X-Mailer: exmh version 2.9.0 11/07/2018 with nmh-1.7+dev
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
    linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
    linux-kernel@vger.kernel.org
Subject: Re: linux-next 20201126 - build error on arm allmodconfig
In-Reply-To: <20201126141429.GL1551@shell.armlinux.org.uk>
References: <24105.1606397102@turing-police>
 <20201126141429.GL1551@shell.armlinux.org.uk>
Mime-Version: 1.0
Content-Type: multipart/signed; boundary="==_Exmh_1606400287_2385P";
	 micalg=pgp-sha1; protocol="application/pgp-signature"
Content-Transfer-Encoding: 7bit
Date: Thu, 26 Nov 2020 09:18:08 -0500
Message-ID: <27841.1606400288@turing-police>
X-Original-Sender: valdis.kletnieks@vt.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b=k29quvvY;
       spf=pass (google.com: domain of valdis@vt.edu designates
 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
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

--==_Exmh_1606400287_2385P
Content-Type: text/plain; charset="UTF-8"

On Thu, 26 Nov 2020 14:14:29 +0000, Russell King - ARM Linux admin said:

> The real answer is for asm/kasan.h to include linux/linkage.h

OK... I'll cook up the patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/27841.1606400288%40turing-police.

--==_Exmh_1606400287_2385P
Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
Comment: Exmh version 2.9.0 11/07/2018

iQIVAwUBX7+5HwdmEQWDXROgAQJMKA//eov2gfD2DBYzF0uuV+ihRR8rhFilRQYh
5/GbflGzyksBKdpX3muKRi4MCJ/6TTvBAJmwcXUNtxCdV9Bv+OR49BmAdouPT5My
3+SA8KPA6Gx4kzBsYHF9TXRfqPT0ocB48rLdr2Nl9UiCXgcRu7Cchc9slJJfQ5gJ
Cst8Iw1QMm2T4Ez4BOyz4Mb7qaCz0obRz1OSmZCN00NKAdBxwtd2h87wFCbIRnB2
1X0jZXAj/rZ5tFPFNIzR9DWHxV+WbLlBHehSdpp/xrS/1G0t28lrKd4AKoXzKEpK
BiAmQr3WTLok25FS6OUkcRBF1PKOEcAac5GxPhafnHvZxVIPgz9C1JZ0meJb5adj
S6Q7br2Rldsc7Ug9jJdGi3o6ns2gjjKQTY2nSRrAkySBtv+zgxgX7tjiQHSCJQm8
GUFnGSdWX7ht9OUrUUaAKBjo9kqDIhHQTNGWLe/iNmGkoYjYDihqolATHbWE6r3v
pAbzTKc5phxnByP/R4MhubaBQZwkguNafOuqtPpiMI74rzeUMSHfeRb3e/ku2BJV
pIALKrQqKA4QXrGgwpsclW+zv4zkeV0tc7gVQv6uZqwHU2a1UIi7Q4Nzv+IWhaww
XrCD7RUUL8RuJGshi/4L1JDG4JUrJJVVKDhhQxOMvVnkQmfDtcXjBtqWaZp6p73L
93xqF71a4Lc=
=nqtk
-----END PGP SIGNATURE-----

--==_Exmh_1606400287_2385P--
