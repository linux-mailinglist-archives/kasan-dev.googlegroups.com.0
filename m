Return-Path: <kasan-dev+bncBDGLD4FWX4ERBXMNVXGAMGQEJN4XNEA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KDtgGeBGi2kJTwAAu9opvQ
	(envelope-from <kasan-dev+bncBDGLD4FWX4ERBXMNVXGAMGQEJN4XNEA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 15:55:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05D7611C267
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 15:55:27 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-66317aad908sf13946378eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 06:55:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1770735326; cv=pass;
        d=google.com; s=arc-20240605;
        b=S+5FKAHVQOHrmE+Zs5vZu4nj4d8LyoYgFYLA/9pSzSaUArByVNmuNxz9Eg1eypcGWI
         JZU2Cpfwa0uTK6sx1J39xaY5rnfrCAmFxfB4DjBcAYcUDzGYG8GMD2OKKDlVDqu2tpH0
         MEnLOxarmv2FcBOOs617AAeby/MPNCq69JZuYqDTrIjOA39tA6w96dVMULVD3bgvnx7H
         CXtJuXfYyJ/dG+xxuIiCtSXIxwQuuYWS7qilrDUUGyee2chkeg9/5RQVfC59Gll8JKq9
         I+Uh2G3DjpeKQAG0Bvj2Q8zhpiPf7zG5lchv74h5FbO/WaMnwOqc7E+YaDIABbgv37BM
         ip/w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:content-id
         :wdcipoutbound:content-language:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:dkim-signature;
        bh=KKWSe0TqeMRJ2z1VdGDXCiQRTVlFWcspQNTjJRa8eMo=;
        fh=Qf//6nOFl7TcVM8VCxQ5RiEFzwf1eg6mn7mVJvmER5Q=;
        b=SazuHzPPlMpL/L/ZY7gbDkbjb/DJxfO/vs6pt7GRTzBFktzZ/DOD/W7wY/Y/JzDC+D
         H28iQc7YyXMAbzuhJe7SASOcJomPN/LwjOAduicm1qTxxZ7a7w/6nEHMe7ON1dO1bedw
         h7ifvVYRJsCYJRHfm41LwmKOwpF2RhMJIkIsixdRV5YzcmA+lWnYQu2fzFJOqpC1Rlyx
         IZtwTCtI9dC7QDMFnohv6Kma0XILDNdZzjBr1n73gzsaqH8EA48+7WmGx7J+EB0sKmtV
         XKHgMwOpEp0HVmJfbUSIPCupYD/YxwETIGQY/93ic4FYruHwdKTzNXpoC9ZioBAKdw6A
         IU2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=Mz69jKcJ;
       dkim=pass header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com header.b=Q2CKJ2ou;
       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);
       spf=pass (google.com: domain of prvs=494c0bdbe=shinichiro.kawasaki@wdc.com designates 68.232.141.245 as permitted sender) smtp.mailfrom="prvs=494c0bdbe=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770735326; x=1771340126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:wdcipoutbound:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=KKWSe0TqeMRJ2z1VdGDXCiQRTVlFWcspQNTjJRa8eMo=;
        b=TmiRHOdgPvgJi5UtNvWHJntHcDiLgbHY/fYs11sG0vhNhoiYoKEAtyF6oE2OVtQAW7
         VroB6Cuk7cZPFyR28HCta2xyQFq8//Y+MIPOhgMINhgsse29nNSrjWhRIDU5k2GZZIlT
         Ut8me47JgukWwSmk29zyppPgF0vNFwm8Jw/dqA4F5kq9yJuRIMIxSIJbDDtSAMITxN86
         1itWZeGBGqO3Dnq/LpOHpYJXTJFzspBVEHsSKWbb1bVk3Xl/I7TcySCHSYxhdUw0wpa+
         AvJ9qHn/xWM3EhWY//59zzW8Y+ecToI5bsccutF1TGE41Sh4szCMC/ytlOzEGO7coQ/B
         Akmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770735326; x=1771340126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:wdcipoutbound:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KKWSe0TqeMRJ2z1VdGDXCiQRTVlFWcspQNTjJRa8eMo=;
        b=vxnhAZbZwRpXmJsb7+SjW+Y5rNZtHXeNORGibqUx3TEbgPJueAZygG7Ut/jeaoaU2m
         j2pE8XC2dQAXaRC6RJSJNmfBPnvCqTZaeBOtyLA9tTEsk+eDuBYRH4YIum2i0Ln/1dS4
         419zrive3it0ytVXQs6j6e0zzy2nO6ZHGuLlKoEkYtxSm2kKyWOaNQciKTBAu3yEGv42
         3mG5isUOQp3kjFtet9QW7jI4iUpi0taz+Xy+OnCXediSxkEDjmo7kf1SIJSeU73dmyuE
         CVi9TNGohPNhNGim0n5znf84bE/hxzw27wELjQw7uquOaVjtryWXyYXFX5namgutsmzp
         yGUw==
X-Forwarded-Encrypted: i=3; AJvYcCVi2qHm0ykdclQuB1qdrg0+vstFLlewqXvD08nU52OJBwiAsMevuAK0moGCCK3iCmorJHSt1A==@lfdr.de
X-Gm-Message-State: AOJu0YyaERGTqhJmbqZLuqGULYv2fI2TjAi10ZOJU+3Q9jFbQhc2IHCb
	ZrQE+A+aR4Lc+as/UPBTGx7lpXWlnOBRU7+G3nvJMOUIVs80KY6/YUcX
X-Received: by 2002:a05:6820:162b:b0:664:86ce:df30 with SMTP id 006d021491bc7-672fdc0ad57mr1082524eaf.6.1770735326135;
        Tue, 10 Feb 2026 06:55:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HGrwZ82fZl6bPKsJ/4LxKKnOSaoqchxMmo84RxNtKQXQ=="
Received: by 2002:a05:6820:162a:b0:673:2fc:bf65 with SMTP id
 006d021491bc7-67302fccd3els418059eaf.1.-pod-prod-02-us; Tue, 10 Feb 2026
 06:55:25 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWrXTBVSRxcVjm6aIOl77RlidY9ABzr6MyMs8EGak7JGYotrFejYjLi+oPW3mgjEbOw7SobKciB9v4=@googlegroups.com
X-Received: by 2002:a05:6830:411f:b0:7cf:d191:2a50 with SMTP id 46e09a7af769-7d49980e28amr1126648a34.13.1770735325286;
        Tue, 10 Feb 2026 06:55:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770735325; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wswj8fMi59Itb/vllsEEX6aPUxTlqYtanHdpiNopHuWBNRQfeyRQARyd3lHoqjru8z
         S3lyxmxlotUWSgz/nthArwmHx1C0PeGiH4GFiRxVYG2LqPkZBIYbK5CgNLOXXkamzoO0
         A+0zuWBTwtQFNCm2zEAQ6pOOvfuiYPsuk/6d9a1Q10rNffqYkN4FMJu+vtAaPV4yeR1i
         5EC1hpZk5SytuW3bw4OehMwR+nZjTIAkcvsrJBZYcVqR4tqifoh7O7q2BxTqtYfiu7VV
         vfMWKeGk4mQzQR0orB8QHe0hCvZ2hdzQGYhw1XaZMAjeNSmcZ5DrezK+oRaRqRWwzdmn
         rIKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-id:wdcipoutbound
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=142PJDlOd8M5O7dENqxXl72SfMFIUlr3XSM5FzafyVc=;
        fh=dkeVo/AlndbvWZaVLZnABtMNMWHA8YhZeX/vqFXPYZY=;
        b=gC5A+VD6YKQQSRB+eo8vAemjspC0n//BWf093a3NcrMAu/KupslTbtb6Lb/LsQcewj
         qa+YQnCdMue22osAuimMrA46XlCn60lzyY30TzFgCY+yypRGtwd4s84xJA9/TepjSWX7
         WcfALfFAZhQOAiWGIYN0MwO0MB+x8I71OWHi+h1stwBbsbm+5T5MXdnWfd3rRC+z2FF1
         qzBbV/eq+JwFbodTEOPmPLmWAU/rmSxpbVA9/GSe8kpflbr1GWBHeSezRRn489YxuCvh
         zMncK8mp4Jb4GJzPzNqfxSs/n+rfU3GHR4latMKb+xMb08vFx3zRgd9trPgb/BoRFgrv
         BljA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=Mz69jKcJ;
       dkim=pass header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com header.b=Q2CKJ2ou;
       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);
       spf=pass (google.com: domain of prvs=494c0bdbe=shinichiro.kawasaki@wdc.com designates 68.232.141.245 as permitted sender) smtp.mailfrom="prvs=494c0bdbe=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
Received: from esa1.hgst.iphmx.com (esa1.hgst.iphmx.com. [68.232.141.245])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7d464786515si467836a34.7.2026.02.10.06.55.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Feb 2026 06:55:25 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=494c0bdbe=shinichiro.kawasaki@wdc.com designates 68.232.141.245 as permitted sender) client-ip=68.232.141.245;
X-CSE-ConnectionGUID: 3lcvjZwWQM2ZuM902iQtJg==
X-CSE-MsgGUID: +D0YtpVGQtmD1aVLpFt1Xw==
X-IronPort-AV: E=Sophos;i="6.21,283,1763395200"; 
   d="scan'208";a="140463554"
Received: from mail-eastusazon11011012.outbound.protection.outlook.com (HELO BL2PR02CU003.outbound.protection.outlook.com) ([52.101.52.12])
  by ob1.hgst.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES128-GCM-SHA256; 10 Feb 2026 22:55:22 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=pFTOFTlXIM+EZkv599t7lErNAN9nO63Q+uNcZ9eCLoKJh8yIP0rHIOggd6NmEbd82IIwGSBPi5f8zXgXE9DSr6UTmvKSwWITBO4Odk4on0X+Zq4MD4kXON5BplnSfgx8mlzd3CjMg+rnzqZPQHSgCpaoxOD9RCyAI9zHIpZRVRo0MzJsDtxHIM5vBZfyinL4HHl47EWMx4NUWI6sJNgNiXvd5dkq0dSU354iRxFvdmbSH2xy7O9N/AHU4630MkGx3SmdE3KNrjPxFNFXhZ2PYJCUxcHAB9Os+LiPFNGPWP5wbObsDmQN1c8+8/VvkN+G+T90vJ+rysSRJN3t811MXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=142PJDlOd8M5O7dENqxXl72SfMFIUlr3XSM5FzafyVc=;
 b=TmJzlSMP3BWwbuBkLMqEV/YN9XfkYf3BOA0yr7e+FqG2RTbrn4RL182N63zDD/+p1i18CNfUNyrG1iO91A6uR3LIsNTtJFzCBDXQNnF30qvTabDUEMWI7uZ6sY8gPLGwLBHxOaAqEwiT367Mwd86sI2QgOG/bNx5OaHchuMGF3lfCm6duoa6qmK2ZVSXg8BN80SqW8HzjqAMZ47ors20S+uAoJC1Z/q01SvG4QbgNQHe7Uxna1jIR+RJX6L2TBx5ciNu/PUl+T1+gK9E9+kX6Zyf5xwdSk2lCn4r9GVaJHWNyFJWIJkezDecpm5r8q8oaLC5QJRISCXQtz8frW+Y4Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=wdc.com; dmarc=pass action=none header.from=wdc.com; dkim=pass
 header.d=wdc.com; arc=none
Received: from SN7PR04MB8532.namprd04.prod.outlook.com (2603:10b6:806:350::6)
 by SA1PR04MB8855.namprd04.prod.outlook.com (2603:10b6:806:384::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9611.8; Tue, 10 Feb
 2026 14:55:18 +0000
Received: from SN7PR04MB8532.namprd04.prod.outlook.com
 ([fe80::4e14:94e7:a9b3:a4d4]) by SN7PR04MB8532.namprd04.prod.outlook.com
 ([fe80::4e14:94e7:a9b3:a4d4%5]) with mapi id 15.20.9611.004; Tue, 10 Feb 2026
 14:55:16 +0000
From: "'Shinichiro Kawasaki' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@kernel.org>
CC: LKML <linux-kernel@vger.kernel.org>, Ihor Solodrai
	<ihor.solodrai@linux.dev>, Shrikanth Hegde <sshegde@linux.ibm.com>, Peter
 Zijlstra <peterz@infradead.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Michael Jeanson <mjeanson@efficios.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [patch V2 3/4] sched/mmcid: Drop per CPU CID immediately when
 switching to per task mode
Thread-Topic: [patch V2 3/4] sched/mmcid: Drop per CPU CID immediately when
 switching to per task mode
Thread-Index: AQHcml+PLO/xV8naRkaVyFCdn6e9irV7v52AgAASugCAABywgIAAFsGA
Date: Tue, 10 Feb 2026 14:55:16 +0000
Message-ID: <aYtE2xHG2A8DWWmD@shinmob>
References: <20260201192234.380608594@kernel.org>
 <20260201192835.032221009@kernel.org> <aYrewLd7QNiPUJT1@shinmob>
 <873438c1zc.ffs@tglx> <aYsZrixn9b6s_2zL@shinmob> <87wm0kafk2.ffs@tglx>
In-Reply-To: <87wm0kafk2.ffs@tglx>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: SN7PR04MB8532:EE_|SA1PR04MB8855:EE_
x-ms-office365-filtering-correlation-id: 42fa786f-a39a-4fee-0669-08de68b46724
wdcipoutbound: EOP-TRUE
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230040|7416014|376014|366016|19092799006|1800799024|38070700021;
x-microsoft-antispam-message-info: =?us-ascii?Q?cF3+Zmy1XsQLKzRpiNT1uhaZQbYmFueRErYs8gcU6WZlLsyWRAyS7+vVXHnP?=
 =?us-ascii?Q?aEVu9MkcnynHwH/swAE46Erg/0+apQqIpSYYe1/6DJNOChUbhjaWI/g30BzO?=
 =?us-ascii?Q?uZ66RSBFMUCxjB7qN3O2iO4iX39qbhNdf8S4L9pSFwMiFfFu8nb5DEnqsUNx?=
 =?us-ascii?Q?LduipD8u+CM7t2S8GQhkiAZ33rUCbUTMRWpy8KHD8y+EoJhNFgrH/lnIvF6f?=
 =?us-ascii?Q?dh8c7HxaToBRTwjohLCNVqGAdp0InOs1keX52SweD118i/mRbS45jl02AzNL?=
 =?us-ascii?Q?WffQwGQ7FDbhhTO4e4RLzpW5mDbvqqUC2ss8E6JGngdVjzy2s5NCdsASArM1?=
 =?us-ascii?Q?IW/Ky1jIE72TGReID3d1ZGDW/qOvQnjuKsedPqOknh/Gqyh+hoOlI+bhZzpJ?=
 =?us-ascii?Q?CQuYgWFe6rHJC27BmcQZVVg+PacxoWhvvoKftGVJH0KW/z8AtyawPcfyyGat?=
 =?us-ascii?Q?qu7SS/qgOtOrvwibUJht+HvsgWNF2XkuGhdfh5Qy4wzz8cj4c/l7dAHpgWVc?=
 =?us-ascii?Q?bW154HOWjVrrB5RcSM/9Yt++BR0s96L2388j1rJlsWF6Ka7ToNz49KrT77em?=
 =?us-ascii?Q?YaIl18dOdA5cZCGbaEyb7/L2k7tvIeYF2NNmFPg1tT9Xo4WHOj3uCPngfiY5?=
 =?us-ascii?Q?Hf76Z/pRpnyhWRIdsVP5Wx4A9tN7LI+39cabZM9LOWSpertXsllJ+ruiRsui?=
 =?us-ascii?Q?CXHqxiTDHGW4dtuexkp8rDEC8BlC/vKRdgjy0DNgUQoL/+XQRb215c5zVs7O?=
 =?us-ascii?Q?W/0Y49c0myt5nOakyf2+5s9GE5vOUydLyhE5rstYtyCeDKjsB+q15j6tRpNM?=
 =?us-ascii?Q?lMYWBQnnZAlh5PlSLI8bnWeJyxKOYLlrCud23Kg+vrxRY6/9YjDCnw7eOnqQ?=
 =?us-ascii?Q?7tzF+uoZIQuotjfUXVrxsec+PHOkbzYWPP7Z6686EqoMraxnkAeuy/Fb1jIq?=
 =?us-ascii?Q?AF3n0AnhMpJLXGIykdbryZ19f8lcjMp1DoAlj3R17op3cwHKMvS57n3Y2xrv?=
 =?us-ascii?Q?PSH3QHs5pEkloNtAVow4vqxr0ybG/ICp+skKucBdJ+OKf7qpZEyudSHVvGPS?=
 =?us-ascii?Q?OpcwjSPjzE3yMn8gih3Uyujc60bPzn9unpDnvDtjSaaVZD4fa8lYzZPoW4Mb?=
 =?us-ascii?Q?xMyA7n9iRXJzEhGFh90fx2LgdjAYSIoknCYSfJm84ErGRQypTmkgpkbM1DyO?=
 =?us-ascii?Q?ObY+tAiaHBoILfP09FHJihcS1nvlot8vy3ISvQ2ceLylfAxEeGeH3K/gJGF4?=
 =?us-ascii?Q?eNgrYNr5IVb9n4GGWAXBYylEMcnVELgXS6sw25wWPCSOOXNiYUWNlZGVnDRv?=
 =?us-ascii?Q?7gVD8xH0JI1gND5uXKugRMrNclCjpwRbq2UNMhERZXmiYkFPDHqUVp9zO1v/?=
 =?us-ascii?Q?x7T3AIvaKxLhj7ZUKHSUtQvBNnsA8CwnHZ9VO4Sce9YIXbKiW49rN/y2smUO?=
 =?us-ascii?Q?4LZ7aMJeFu/DhP4GWJkploeFynHorgstJ2e0vNVKzCBXyngo76+W1KRqOqtX?=
 =?us-ascii?Q?8omy0blbHHcT5uLdhleGkJPumGzUav4HaLdQ4PplRT+AwyMIJQk7vrRvJ9zD?=
 =?us-ascii?Q?PNoM+CCBilmuUm/uUZeRr3q+t1cqWtGzujs2LLGfgnvF94ksFQSShapVQuar?=
 =?us-ascii?Q?vh+NGe/3M+Govp5bcNe3sKc=3D?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SN7PR04MB8532.namprd04.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(19092799006)(1800799024)(38070700021);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?5RO5IpxX0YRJjF/6RXkpWul1fxk9gKkYK/dg71XNiKIzktHMQ/5LTaQSa3SC?=
 =?us-ascii?Q?X4NPUpLtumxoN9wgxq5BfGK5kKu5GQ64BHWXlnJrcIBKCVwzBZepsMZyEAi0?=
 =?us-ascii?Q?lyAJTy4Y7Q+r4X5hGvJdgyxpjIKnRmI8r5fRQ3Np5nkzDvZYClkhqz3XSfxu?=
 =?us-ascii?Q?w68ZWZ6A8Nik3oryZtmp14sWY080dZFeASnWaK/215t/1hT0/27kk9LqhQZo?=
 =?us-ascii?Q?2oh2lQr8JnHwOv1zhlloKFr7Xa+Kptc7mrWvlAvsOG+eIpOgle22VakuURJR?=
 =?us-ascii?Q?k+wPXZGbKthFBVHkS08k5Jx8JZlgnLMW1iScnVsQLwIy0byk/Xe/G8GIGDft?=
 =?us-ascii?Q?i1go5nkzQOecwsI96aA8di//ZWrnPU4x6flb8UZGcxkvyB6U4gZQlwloKqcZ?=
 =?us-ascii?Q?H2IPUDDxkcPM6Cp9bpJjdpkw/0bHylmWoom+2j35b1fOviyoqjOEthb9kh4B?=
 =?us-ascii?Q?JTiyh+DoLG4SMJYK96RlDSQEp2r2OktFtdnvXa26SJoQvfG+hokytrD9l7dg?=
 =?us-ascii?Q?ZLtEXH1aSbzRhttBzxRw/ho3atEfmEagVr+LthOdVPjm3b8Lu7hpr4+shgu5?=
 =?us-ascii?Q?A7oLuSdUPY+3p6/pO0xesChJ4Va381M1nYnkVP+ISrRzce7cdjb2JkMw8gCk?=
 =?us-ascii?Q?9QxHjQNff8DY45a+F1w5NsP63RXyzc9AVwC91G/TD0U6FK7+Rds8kwjS3ES+?=
 =?us-ascii?Q?OzdmOIQ4mJmc50YtxpVEJKJyMIFym0laXRzBspb2zhPZT71QeYbXnhJQQ3A6?=
 =?us-ascii?Q?N4NUQQSIvS5Faq9wri7IxcUSO/mR+EUBRu3Lcj0Hva3ZGhO3bVD7C07gHvcn?=
 =?us-ascii?Q?Xtdti2Z381Jk6Ii+jrqmuaKw3HxAiMy+JHXJ66f8aIjsyg8TBp410bEIZebn?=
 =?us-ascii?Q?AuV7GlzRBnNGbfDMTxFnehZE/f2RtxMiS3mEHbQFFE64m0Q+QALKnFbZ3VL3?=
 =?us-ascii?Q?Os5pS7QaoHtIbveJimWr0wXzTfP3K2hPI7NN9pYdd/PLO5U3sIbB7gT5HKi1?=
 =?us-ascii?Q?LlCoW3QTy4iYnZWjxSM5XSAaqYAekXUd313745JRbfycyfygYEL4GSkg52By?=
 =?us-ascii?Q?q+5seC+Zs4zBzyTHycNxHyx4ouhYxFPV3euXYPqERd+OhGsm0HUOx48LboEF?=
 =?us-ascii?Q?/14Kl3Td294w4ir+SwvWgFSTzPOR2ItcgamMjga1EKgYx1XlAHZytI0nIYhp?=
 =?us-ascii?Q?vvLMTFJdp7nRw/mMpTGzzX4IEeKb5CbwaTXap4d2q1Vrb7DF2wEDBeTvCY3h?=
 =?us-ascii?Q?CDZjsalb2kLZnwujSK0ofAfIddxfN6tIp3SRTY856wNEpho7MmEnNlOXoWJM?=
 =?us-ascii?Q?PJIh4OOxy8ZYyKobyXah/tF8IkPYa8BKcR+cNTBXFXtxvQBgKWAQY3ZcC7rM?=
 =?us-ascii?Q?J9f6vDUnJ+uY+R21946JloJSk+r48RwrkQfnMOdsv/dJN98fWfptjyzqcW+B?=
 =?us-ascii?Q?btSH8f/O+JTNd4kvhJKCaQoxERuLFMSuuyHKcQVUhffkHZPdOh8B2Bt3VuTb?=
 =?us-ascii?Q?/zQpijP/l3qA6j7/M/iOX+uOpId/so/cYOdnNoVrCB8JfeqBtzxrekYX1u1J?=
 =?us-ascii?Q?Vch0vhpxAECZiBL1u4iRvSooyfzlR1LFVCrh6sHpfXaZD7/AyL1DAJ9Ee1yu?=
 =?us-ascii?Q?V+ZUJ8uMgAxYTtw0gqqcxdhOERsHit/Wr8C4wEMM1ocvbOXZ8o3IJ84giIEM?=
 =?us-ascii?Q?ZfnstOeR4uapPSp9kCG9GCM1eSfuvea99HyNlmrrnGUglxN9oykR1ZwaQxNU?=
 =?us-ascii?Q?pXAEOK5cGnvrxQJEiX05hVvCwGSlAjOsWVu4SV7eXCKych3Dp0dL?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <A7A65DE7FEB029469A0B7467221CDD60@namprd04.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: EJPoqrKZISjVpA/3s9akh6QOuS0dtqVAqsqCvyaF7HH81tDxEALzsubDrWymsYfA9Mf2o1vnw8pwDGOcI6tsow8WneHMkeo0oUxf/dgyHCEKlmetDH0iNO746DPUBzVSXzTu3j8pS2jcmJkl73fulYYAUEPmUc9z76VTEHRum6vzVPW5dTv2AShWt/M+3c17eU5UiUWMrW1eP3YtmndW8d7oW1J6Tu9zXaDFI7w0Mu4TM7UAxlqMGX5985z10M8jrPq8ATwlz8bs5NWclNCgjqcM0L0QgA2hDtn6u2bLXAFWfvTCGaafLXRRZKK9IXz3GgyrFgy0D0QXQZK6S/08CEZ7Sc5XukfAITcIL6AgJzSw76weVpYEaedfo6v7sajM+YICpCOCepj1JvMoUlrMI2hzJsmz8bSy9HI8q1q/WdAGpH6DNMOg6oNxSPqrW35Q5dQmT06xzQVBLMJ2GDuol7LEWGKAaU62sRmw4PiiXRYBDFMXLIzFeBbxsWaj23Kh9V7+swBCceRvJDGtNVFgkWZCDivJbCnyzs1HIfe4EYF9q/5wjlbDR7QIIXeRsvprBGLWifm18q5EN6ofma4hPWzHxeLGmsAbC9bqYR+PzbHi1mSXHklTEVCbZZJseV7Z
X-OriginatorOrg: wdc.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SN7PR04MB8532.namprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 42fa786f-a39a-4fee-0669-08de68b46724
X-MS-Exchange-CrossTenant-originalarrivaltime: 10 Feb 2026 14:55:16.6617
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: b61c8803-16f3-4c35-9b17-6f65f441df86
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 4FkEut/kkFY5nZOHg6uIHE9mWImTE37LGB+vMGKRVU+SzPZnaVvrWHC0bYSDIGgbB9zrWyLoZP3/JZWQ5chK5cJeSLGBROnk7zyxauc2d4s=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR04MB8855
X-Original-Sender: shinichiro.kawasaki@wdc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@wdc.com header.s=dkim.wdc.com header.b=Mz69jKcJ;       dkim=pass
 header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com
 header.b=Q2CKJ2ou;       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass
 dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);       spf=pass (google.com:
 domain of prvs=494c0bdbe=shinichiro.kawasaki@wdc.com designates
 68.232.141.245 as permitted sender) smtp.mailfrom="prvs=494c0bdbe=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
X-Original-From: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Reply-To: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.21 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDGLD4FWX4ERBXMNVXGAMGQEJN4XNEA];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[vger.kernel.org,linux.dev,linux.ibm.com,infradead.org,efficios.com,gmail.com,google.com,googlegroups.com];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	HAS_REPLYTO(0.00)[shinichiro.kawasaki@wdc.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-oo1-xc3b.google.com:helo,mail-oo1-xc3b.google.com:rdns,wdc.com:replyto,wdc.com:email]
X-Rspamd-Queue-Id: 05D7611C267
X-Rspamd-Action: no action

On Feb 10, 2026 / 14:33, Thomas Gleixner wrote:
[...]
> Can you please try the fix below?
> 
> Thanks
> 
>         tglx
> ---
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 854984967fe2..61c2d65156b5 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -10729,10 +10729,9 @@ void sched_mm_cid_exit(struct task_struct *t)
>  					return;
>  				/*
>  				 * Mode change. The task has the CID unset
> -				 * already. The CPU CID is still valid and
> -				 * does not have MM_CID_TRANSIT set as the
> -				 * mode change has just taken effect under
> -				 * mm::mm_cid::lock. Drop it.
> +				 * already and dealt with an eventually set
> +				 * TRANSIT bit. If the CID is owned by the CPU
> +				 * then drop it.
>  				 */
>  				mm_drop_cid_on_cpu(mm, this_cpu_ptr(mm->mm_cid.pcpu));
>  			}
> diff --git a/kernel/sched/sched.h b/kernel/sched/sched.h
> index bd350e40859d..1b4283e9edc3 100644
> --- a/kernel/sched/sched.h
> +++ b/kernel/sched/sched.h
> @@ -3758,8 +3758,10 @@ static __always_inline void mm_unset_cid_on_task(struct task_struct *t)
>  static __always_inline void mm_drop_cid_on_cpu(struct mm_struct *mm, struct mm_cid_pcpu *pcp)
>  {
>  	/* Clear the ONCPU bit, but do not set UNSET in the per CPU storage */
> -	pcp->cid = cpu_cid_to_cid(pcp->cid);
> -	mm_drop_cid(mm, pcp->cid);
> +	if (cid_on_cpu(pcp->cid)) {
> +		pcp->cid = cpu_cid_to_cid(pcp->cid);
> +		mm_drop_cid(mm, pcp->cid);
> +	}
>  }
>  
>  static inline unsigned int __mm_get_cid(struct mm_struct *mm, unsigned int max_cids)
> 

Thomas, the fix patch worked! I applied the patch on top of v6.19 kernel, then
the KASAN is no longer observed. I confirmed it with my two test nodes. Thank
you very much for the swift fix :)

In case the patch will be posted as a formal one,

Tested-by: Shin'ichiro Kawasaki <shinichiro.kawasaki@wdc.com>

P.S. I stop working here tonight. If my response will be required, I will do so
     tomorrow.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aYtE2xHG2A8DWWmD%40shinmob.
