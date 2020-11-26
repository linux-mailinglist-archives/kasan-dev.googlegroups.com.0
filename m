Return-Path: <kasan-dev+bncBC6Z3ANQSIPBBQPU736QKGQEDBRNQWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-f185.google.com (mail-pl1-f185.google.com [209.85.214.185])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BA762C56FF
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 15:22:58 +0100 (CET)
Received: by mail-pl1-f185.google.com with SMTP id 1sf1618211plb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 06:22:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606400577; cv=pass;
        d=google.com; s=arc-20160816;
        b=jB/VWsc+uqiYWpY7FvWo//FVUpsAr8i/SCohpxSN8OJ8RWMNLkggIl4nDfmOqtDx8X
         aho4TOhCECy2NKYUFVoXIVJAQ1CR0iol/Ran+hwQuBmLJ8CyQ/yloZ5egqBZ5UELS1sX
         fLUFKvfdnM6FrpyKN8XRyrTQyTQVIYGKD/lBqAKW77YAdR8RFsUtA6e/svETkzRRl8kX
         uT+hqe3dMKFnp+0cvMlNPgyA9AW9AGjisVRjGnDKjnQh5EgzZJG1Yu+cK60oSLp2qvgT
         n04VYcMXBnW/8QToT7nN+jo11fbmWSR3yI+u5r1BcAPb108hdNdjFBqzZeOFItrxfbxJ
         vzGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date
         :content-transfer-encoding:mime-version:references:in-reply-to
         :subject:cc:to:from:sender;
        bh=E1xHeX39WGi01ICR/c2CIx/JKChv0lMbn2QYjf9TqnA=;
        b=jCOrc9x/PR8Ge9WqDy+dZTD54i+Gc5hOeBdOyMMedVIywdoN7qX0LwsNEYXeDOFXgD
         QGJRsGkxcPDLi0eE9qzKlEs2lcgi3dCzme0PIwglP7rdmDTOHWjampcBkPYOXbq9Box+
         33f7BInYkqe39Yvpdkmyl5kppvDA7Nd7hk5JHG/l0dGMrpkt95oCKuVayA4LvtTfPns1
         aQL7aTMTWU5189eMJUky9HhrXCaPpgL7yR0u581DUz3xveGZ9hTmq33UtOJHFviuJqi9
         jzxuLw6wqcuT0CuA+V03LLtk6sFMG2BzmPz1zvbWkt3zt5JyrZgv3Rk4e68tCkfCrFrl
         24Sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b="E3fZ/jdU";
       spf=pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:from:to:cc:subject:in-reply-to:references
         :mime-version:content-transfer-encoding:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=E1xHeX39WGi01ICR/c2CIx/JKChv0lMbn2QYjf9TqnA=;
        b=V36kGg3mP5U/a9b3+OGeYx8hqo3PuOBOzFPTTuCAX9Q4IwIAugGsgk/cah6KntDQU1
         c4Rvh9E9GWcpLDcZMCOBKaDUL4SL4H9QLvl6xoVzlJZ15cjlR25uQgTUhT5U3x1mMi1P
         wgI5fJwcuPukz3TmqvGB9yGRwJ8CR0EOiRR6x5CV/yhRqC4LqzAfLObjqTtMYdI0nDUT
         Krqzk0WG/Zk9A5vmE6LE047zLVlDGCbmxL6tyd9K2HZ9ML+liGy2RELR44IZnCsuO0YS
         pCManAApsOFlRECol2WP+jC+8QkoEJZVAEr8I+hSXdVPcmi8G7FcDnB9pmvjfQUcqpmF
         MTIw==
X-Gm-Message-State: AOAM533YRqa7a8hj1MhI2TUm2ttP4mcal87vvJYqQvgStWYHIYG1anty
	1YOJK5dK4AVKwTPwLGsXx24=
X-Google-Smtp-Source: ABdhPJwDTdqs/2vhWrDGWVyGkBHYQVJvpiARg7q2VOt/yXG7hXJw4QiweKtNoggPZUH1xWrAmCLYRA==
X-Received: by 2002:a63:2322:: with SMTP id j34mr2763867pgj.367.1606400577155;
        Thu, 26 Nov 2020 06:22:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ee90:: with SMTP id i16ls1478348pjz.1.canary-gmail;
 Thu, 26 Nov 2020 06:22:56 -0800 (PST)
X-Received: by 2002:a17:90b:14d3:: with SMTP id jz19mr4048015pjb.196.1606400576516;
        Thu, 26 Nov 2020 06:22:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606400576; cv=none;
        d=google.com; s=arc-20160816;
        b=LbqHcsg8SpeOxu0wpT5kVypvH/UMVkeC0OxMT25Y0nlSbLV7tXa2QuiTlgw+6CrLeB
         1WD8VbWqROwz6ByHpa2uau/Ntd6TttkAqSbL/RyYV6CQxXxwpik6tzfLN915V5Qw2IFl
         RtnYb89pGiaHhJ9n8wFEXGd46rwZkA5bTBYwkNkpfxRzGdNcskyVXQFwEkqkIeoDheTG
         LbAtzJ+/iBh1VuoAESDIy5CSVmjTXjGN9qf0rKTAW/ztiL6f83C6FJwaMAS8mXkJgzrz
         z9ArBV1bKG1ewBct4KAAhTDtVDfTUqXlgEkBg8BzhX2hBXxko0oxBfwK27hAjacfipFQ
         duNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:content-transfer-encoding:mime-version:references
         :in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=m89IS3+NJnDZHLlfyB8HbE86AZvHXf8J1YjiWjq9clo=;
        b=UegtkPxCCAeOSpTMUB/v9EHsxDo0sNLPVoJ+XXagh0vKBkm1cJkYwgeAhPo/nC4T6H
         nkI99xw1pp0xpoSfCSZJO9e4ig1sgXKmBFS0tT6nAbPrA0qqgYb15HGETC5ulgpxQ4j+
         SryZGoOd9d59vVzvwzfMwOUeSJq6QeMt1Z2Ek0mnkYue7708JgVZtPrdB6eAi0jV8/KN
         QBRlHAMyguwptFwjxRME3XGQAyGuUCFQIhWoR3dVhLxtZkEwt1Ybd3fXycVuvBW98kqP
         rXgc4Ugz7sJXO/YD2giLsT6MIQNjQSeywh/JnOczayFY92GPnlhN+IXYplLvDJVwFeIB
         KUYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b="E3fZ/jdU";
       spf=pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id j124si338038pfb.2.2020.11.26.06.22.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Nov 2020 06:22:56 -0800 (PST)
Received-SPF: pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id h20so1665080qkk.4
        for <kasan-dev@googlegroups.com>; Thu, 26 Nov 2020 06:22:56 -0800 (PST)
X-Received: by 2002:a37:8681:: with SMTP id i123mr3346233qkd.54.1606400576123;
        Thu, 26 Nov 2020 06:22:56 -0800 (PST)
Received: from turing-police ([2601:5c0:c380:d61::359])
        by smtp.gmail.com with ESMTPSA id 68sm2726148qkf.97.2020.11.26.06.22.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Nov 2020 06:22:54 -0800 (PST)
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
Content-Type: multipart/signed; boundary="==_Exmh_1606400573_2385P";
	 micalg=pgp-sha1; protocol="application/pgp-signature"
Content-Transfer-Encoding: 7bit
Date: Thu, 26 Nov 2020 09:22:53 -0500
Message-ID: <28070.1606400573@turing-police>
X-Original-Sender: valdis.kletnieks@vt.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b="E3fZ/jdU";
       spf=pass (google.com: domain of valdis@vt.edu designates
 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=valdis@vt.edu;
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

--==_Exmh_1606400573_2385P
Content-Type: text/plain; charset="UTF-8"

On Thu, 26 Nov 2020 14:14:29 +0000, Russell King - ARM Linux admin said:

> The real answer is for asm/kasan.h to include linux/linkage.h

Looking deeper, there's  7 different arch/../asm/kasan.h - are we better off
patching all 7, or having include/linux/kasan.h include it just before
the include of asm/kasan.h?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/28070.1606400573%40turing-police.

--==_Exmh_1606400573_2385P
Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
Comment: Exmh version 2.9.0 11/07/2018

iQIVAwUBX7+6PQdmEQWDXROgAQJNBg//fVo82C2jT44d3GrdMgaG7Zjcuk1EqjfD
Qetxzjrku4UIYGH5r/eWkzI05j+qf3hPy0zabd+LMwDmg2J67RaLHq28GD0z+s5J
fjqRLSwwTtaHySdSXyQjoX0MH8dWHzaaVRLvUXYwzgv6Ku7M9C9KN1tJAWJAVkxX
HsweS+i2lPhS6TueQBpayhxLCBB5fe9V6jagshYzxX11ZhctCXpz6sAjgeYDZS/X
hAf0JvUe5f4Vy4l4AY8RJQ/tn3EagVZE3O02IY0zCTHo3/vEqXcUerT1ZslqeRMP
Gbutin5Ftl2BHSWRIrVhHTUKVR2DvvyRmq3bRSg82/Gn4E4AdDyqcxsOsMO1zaiD
8hmEt/oIveEtaKK4a2BxSZkOlcScehS7yBsO1RkaUKaoKozPOy3N85Wm6v4TdEoj
i/0J7kX3RJNvE6kpndsBZYxeb48drtc1V+JGlrpv4wARwqyzLxAhPtVN1EaRbutb
tALyIGGGti+UYxo4IKO9t3bhQptd8hWT/YxCH1tqqFnLeiTlddNFedlCiNOKWh2G
eX4TlttqeaJz7Oekuu/86ZXX3A2vBT9wA0+499uRDytggddtz6JG59r8Nte5vf3/
oiWnO9HDGmkLKbAF3GhIXwFoZRbuV7krit0JpNZ05HzxwGvWdoCvnsebFSEyZc9N
ClOec9Hx8Ik=
=ameD
-----END PGP SIGNATURE-----

--==_Exmh_1606400573_2385P--
