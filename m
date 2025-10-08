Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBPULTHDQMGQEKULOGUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 84F59BC480D
	for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 13:06:40 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-46e44b9779esf27597285e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 04:06:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759921600; cv=pass;
        d=google.com; s=arc-20240605;
        b=O7Qq6zHRThDy/2RlbGzEI/n5tqiauGSJf+ElmXIZUJMMPYP7RmXs6X2TFYjzOK1G/D
         bffCl7DK7q9G839THR2X5XsGasXL776zpItwnWArBzMs07nyU49B4e29hMt4J4GVx73l
         Ij571lhp/3LBDHJR3dI3TnSmSH3or3wpG1gY6SPr9V17yBCgjRT3jYpQNdDVXwC73JVG
         1CSEjJBd1He+NRpK3TCz3j27bNZGhcZiYYufQ34C7x29OPDz6DOFJHPc/IPfSqE7jdtI
         1EQdStUymZXcnkaiPvf77VOyLGNWjXoWw+jl2tKPZ7w5+HSCDAXoQDnCwOpXO9meITF0
         AXag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=FRYDx4OIZdExO5cUZfZKJSMqGYBHj367mq5uAsflu08=;
        fh=pHGvNmtFNWskN4Zu8zu5I0ely+AQY/n2OpYSTuYAI4Q=;
        b=I31UMIInUIIqMJ4hq6VIUSjJbZChV66DmJd1ACl/Wj+8VG1DsnnE/XWZ62upuQKoj4
         i4KFFmtxFqhmgpQQqjM2AMcP0ZHAfXAgvOlO1aWED7ev9zxIv+tXn7YmOjnDol1SbaQO
         UDsjCzAgqyO8q3RksvqPPioCZHSRNLi2rM2O2tLS85+nMPwr9ATtmqt+ieDx7q+qV6XT
         v3FmwLlimqlNyR3aqan2S6oJviGRptp13uvyyu9ZLvNAcSo3w6bb/0k8S0ZgchcsceOz
         9iWld7ymRYb1fSM5ISUfaKVSLHD0In9Tyake5HULw/R4zhmuMhM0qt2/zCWt9gAEP5DK
         vWWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q0an3nRk;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759921600; x=1760526400; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FRYDx4OIZdExO5cUZfZKJSMqGYBHj367mq5uAsflu08=;
        b=Mx/Mrt2w1H3Rw4b1VhmjfSX+nQMYUDf6yhl/sm1cJWov7mRBgyhc2MWzz0iVsnMMv3
         qZc5qKkb1jBB+5+9QMGQIFSDy26oAMP8hxq1VVTTlCKHbawhy7/BXFufSWIy7eJMvU2v
         WCkqI8syNeyeYH+2Ltiz0xP/r5CP2baJMNqo9ZlSKQiWeiH4NOfC1cxXyrbuH4KjeQEo
         bzf39Y2Td8LJPWqTeR4zM4Bag4f03xJbkkAZjFWkyvxByy3HjZMr9mJHLomOMSP93bCM
         D/hk0PG1glbIXcBSWYR+npN2Y9hy+M4J14lhvJbosvz9maH9ugBvqBRh9EPmVZY98OxC
         2kXw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759921600; x=1760526400; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=FRYDx4OIZdExO5cUZfZKJSMqGYBHj367mq5uAsflu08=;
        b=Nu07rZqyR4UDocxi1EJa/Q7EtqWcX+8dYpDsFSXTvmmEFirlC1NEf5o5Nl2OcaheB3
         jBl0Y0VLztdidYLcPdw37FpkojY1o28642sYuEIIS3cDGrjguPecRET8WSyUm8rX0Bna
         ipEXYrAWVy4ZzO/4LjCpLfnk8HN2fhSmr9qS8PDiNXAYGXTm5dRlRIix/p/6fg4LpEpo
         qAb+1zlrWraTrz3qP0hD08S52DICT5290JgsHWtGGdRDpA+lePvammCqJ3gu3ZqLqPiI
         ffks3iEXncRi5Npn3cf+GDxkQUzz9MeDRa/u8OUKBYvYPJ8mGYietslX67Lk4WXI2rZB
         DCkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759921600; x=1760526400;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FRYDx4OIZdExO5cUZfZKJSMqGYBHj367mq5uAsflu08=;
        b=AwyIkZ53hC3Pk94dh2lM8JN/0XhwRgmgwIE00PRgO3dgqfIMDRYKCBypYcwuivqXof
         UmfTqkevjuTVH+gFTTAZeA8mYy2FNgKoFJ5pj4eZez8RACjkhnqab/KZVgTsmfXND0S1
         ek2FXMTSU+rpR8PFjp/mJb0y0v+KpQqzrX3/vFdvJZAgcIvP4xysccDuH8H/YTEoE4IM
         fzUorGFQn5We9VzBICrXWQBNjeo5Zr2eleHflTVeKzjoYii9xj2S7R3Lcu2kIUZtghY3
         Mgbn3RwL6Eu6D/slbWEv3u0k70jIHpaWp2V9zFUQF7FNIkd87PT3f9m+hZuA22rhXWdg
         sD6w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3WYCx07hvOh7IQYxhlvNRbTDH/G8TAuJR/oRd53cplR8b7KH4av0yBm4fsgUul+U1Z0FAMw==@lfdr.de
X-Gm-Message-State: AOJu0YzvkAUDd1gJ70kuJYImJfSOqdU/AiaQ5PuM9yW1yfWHFSazz+tJ
	7fdluucVyNHVYmH00BP3oHWLmTO4M58GeLghlHEuUuvSXexqd1j7HtlS
X-Google-Smtp-Source: AGHT+IGVCL2sLw3CLBRufLHSqrRDox0sxAB0eLIH71N9zt74GTADlYTWLrIxucStcEDsvOzOuLphyw==
X-Received: by 2002:a05:600c:8487:b0:45b:79fd:cb3d with SMTP id 5b1f17b1804b1-46fa9b13ab7mr21926005e9.36.1759921599506;
        Wed, 08 Oct 2025 04:06:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7e72irEn8gskseKEdDIlU3rxeenLlqtfePY294Pt5+RA=="
Received: by 2002:adf:ec09:0:b0:3f8:e016:41ab with SMTP id ffacd0b85a97d-4255d27f6b7ls2661988f8f.0.-pod-prod-03-eu;
 Wed, 08 Oct 2025 04:06:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmcO0MvlmS159NF3SBLr3utvnsKIUAHGVdSjNrHuDYrmQiLtmslMhC/uooo486VP1o1bPCyLzxszw=@googlegroups.com
X-Received: by 2002:a05:6000:2586:b0:3ec:e276:5f43 with SMTP id ffacd0b85a97d-42666ab87cemr1472937f8f.18.1759921597045;
        Wed, 08 Oct 2025 04:06:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759921597; cv=none;
        d=google.com; s=arc-20240605;
        b=eZ7A0f+pIk/L6uPcRxSDkxiqY8JfaNs7IFO+/HcTYZzxPABA0VS9UMYlfKGWTxvWI9
         YGpUIYFte060sGubiyHbUeLgvVm2LJfXh9gOH/CHcJB6gTMSnPGXlXFYJK98vaIdEGT3
         kYdpP7URSP6iWY2qSp1n0FB5b2ySEdxarP4c0vxsZTXab2ykwG1rN4tEpqfUFnCbVWiP
         BnfeZg9M+74rCbHgyJwAFSbX3N2SCumFJhj4rszaWktIF7S1FpvreYHdCnMGPR70zc3w
         Vu1nO6LabR8YFMTRCIWd2ggBo+AJsZrEV6/rrlHZ7kQC2uXEq4jF8aLBOnCmHDWresoM
         hKOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=TO5gGJha213T8TgICa5STyaclSeDBJJatm3imSDwdxQ=;
        fh=mbgCwXWUYr5yYpEBk74es/I6pcRQq3G3rpCzbfnHWzk=;
        b=Oy9J2efZyRMyhkvLVxXZq/l9gFkfIECutVj1M8Cf9lavdHaX0bsTY6jF2cgQOC+rYi
         5SFs2l09pFzxtF3agCZPdHXsiH3RaCDp+RYcIbz8zS04yPFwlQAFsv+V4v/VrhlMSwYZ
         cis/WwzOEg6+xTHlpb/yy+ZYuwyBYzXt4PFRACcBnACHPhaqa33CtGYiWbXUS9fCvEHK
         IvkfyG2UcMUUj9SguUSAT9jUVm6lME0/h3TRes1Ht5doB+yVBgbwvhJq3KnBa2mtwI+U
         WPQlRR3kEx7Q1aTXxJB41CoPbg4Aqfiyha2kLIwcoytVPor5Lw5qzgfVvmsFUWM01+FS
         Qe2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q0an3nRk;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46fa9ba9381si413915e9.1.2025.10.08.04.06.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Oct 2025 04:06:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-63963066fb0so525578a12.3
        for <kasan-dev@googlegroups.com>; Wed, 08 Oct 2025 04:06:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUocJVMUKyiw/Gw1o8D/JH537wXTQTwkeNyjmxTKTHxX5uWQ884pe+KEvvCI8WVcagi4U6jXsjOOBg=@googlegroups.com
X-Gm-Gg: ASbGncuVbA+9eumS5pYo9AL489spSMuQ1eiZJQ1Q7Z9m0mBEvywUj0eRzVghPxjh1Y4
	HN5REB17Ku8YU4FJ1jdKmKLNGYG0ZcixnhFVsb2WChl7tr8P4cTUJdUS5BAr191svNSFLKEmpg+
	3kbIXeQTVfYM+5gQY1UnBCXVYJWTk5/2wH2ku+AN6BzqTbsFbELMrg27l7FsYs4a1ay6bHpAEnC
	UnT6uJ7GMnQ5xD15AU0wXcjUL1PDRrevcGmhA==
X-Received: by 2002:a05:6402:268f:b0:637:e2b8:604e with SMTP id
 4fb4d7f45d1cf-639d597b400mr2455089a12.0.1759921595947; Wed, 08 Oct 2025
 04:06:35 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Wed, 8 Oct 2025 13:06:23 +0200
X-Gm-Features: AS18NWDPEcwuGQDbQ_dcf_GKQgVvZXKYuASTL5uDA2uxFhrwZGnggDUv3iEgsBA
Message-ID: <CADj1ZKmoRrrBkppNCzzTzk5_u0eKo67zMvNa++T09Aq0tcrgJQ@mail.gmail.com>
Subject: =?UTF-8?B?2KXYr9in2LHYqSDYp9mE2KzZiNiv2Kkg2YjYp9mE2KjZitim2Kkg2YjZgdmCINin2YTZhQ==?=
	=?UTF-8?B?2LnYp9mK2YrYsSDYp9mE2K/ZiNmE2YrYqTog2YXZhiDYp9mE2KXZhti02KfYoSDYpdmE2Ykg2KfZhNmF?=
	=?UTF-8?B?2LHYp9is2LnYqQ==?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000008f209b0640a3aded"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Q0an3nRk;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52e
 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--0000000000008f209b0640a3aded
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

INmE2YUg2YrYudivINiq2LfZiNmK2LEg2KfZhNmF2YbYuNmF2KfYqiDZhdix2YfZiNmG2YvYpyDY
qNil2K/Yp9ix2Kkg2KrZgtmE2YrYr9mK2Kkg2KPZiCDYpdis2LHYp9ih2KfYqiDYsdmI2KrZitmG
2YrYqdiMINio2YQg2KjYp9iqDQrZitit2KrYp9isINil2YTZiSDYo9mG2LjZhdipINiw2YPZitip
INiq2LnZitivINiq2LTZg9mK2YQg2KfZhNij2K/Yp9ihINmI2KrZhdmG2K3ZhyDYqNi52K/Zi9in
INin2LPYqtix2KfYqtmK2KzZitmL2KcuINmF2YYg2YfZhtinDQrYqtij2KrZiiDZhdio2KfYr9ix
2Kkg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KXYr9in2LHZ
itipINi52KjYsSDYqNix2YbYp9mF2KzZh9inINin2YTZhdiq2K7Ytdi1INil2K/Yp9ix2KkNCtin
2YTYrNmI2K/YqSDZiNin2YTYqNmK2KbYqSDZiNmB2YIg2KfZhNmF2LnYp9mK2YrYsSDYp9mE2K/Z
iNmE2YrYqTog2YXZhiDYp9mE2KXZhti02KfYoSDYpdmE2Ykg2KfZhNmF2LHYp9is2LnYqSAg2YTY
qtiy2YjZkdivDQrYp9mE2YXYpNiz2LPYp9iqINio2KPYr9mI2KfYqiDYudmF2YTZitipINmI2YXY
udin2YrZitixINiv2YjZhNmK2Kkg2KrZj9it2YjZkdmEINin2YTYqtit2K/Zitin2Kog2KXZhNmJ
INmB2LHYtdiMINmI2KrZj9ix2LPZkdiuINir2YLYp9mB2KkNCtmF2LPYqtiv2KfZhdipINiq2LnZ
g9izINmC2YjYqSDYp9mE2YLYsdin2LEg2YjZiNi52Yog2KfZhNmF2LPYpNmI2YTZitipLg0KKtil
2K/Yp9ix2Kkg2KfZhNis2YjYr9ipINmI2KfZhNio2YrYptipINmI2YHZgiDYp9mE2YXYudin2YrZ
itixINin2YTYr9mI2YTZitipOiDZhdmGINin2YTYpdmG2LTYp9ihINil2YTZiSDYp9mE2YXYsdin
2KzYudipKg0KDQoNCg0K4pymIOKcpiDZhtio2LDYqSDYudin2YXYqQ0KDQrYqNix2YbYp9mF2Kwg
2KrYr9ix2YrYqNmKINi52YXZhNmKINmI2YXZg9ir2YEg2YrZh9iv2YEg2KXZhNmJINiq2KPZh9mK
2YQg2YHYsdmCINin2YTYudmF2YQg2YjYp9mE2YXYs9ik2YjZhNmK2YYg2YTZiNi22LnYjCDYqti3
2KjZitmC2IwNCtmI2LXZitin2YbYqSDZhti42YUg2KXYr9in2LHYqSDYp9mE2KzZiNiv2KkgKNmF
2KvZhCBJU08gOTAwMSkg2YjZhti42YUg2KXYr9in2LHYqSDYp9mE2KjZitim2KkgKNmF2KvZhCBJ
U08gMTQwMDEp2IwNCtmF2Lkg2KfZhNiq2LHZg9mK2LIg2LnZhNmJINin2YTYsdio2Lcg2KjZitmG
INin2YTZhti42KfZhdmK2YbYjCDYqtmG2YHZitiwINin2YTYqtiv2YLZitmCINin2YTYr9in2K7Z
hNmK2Iwg2YjZhdix2KfYrNi52Kkg2KfZhNil2K/Yp9ix2KkNCtmE2KrYrdmC2YrZgiDYp9mE2KrY
rdiz2YrZhiDYp9mE2YXYs9iq2YXYsSDZiNin2YTYp9mF2KrYq9in2YQg2KfZhNmC2KfZhtmI2YbZ
ii4NCg0KDQoNCuKcpiDinKbYp9mE2KPZh9iv2KfZgSDYp9mE2LnYp9mF2KkNCg0Kw7wgICAgINiq
2YXZg9mK2YYg2KfZhNmF2LTYp9ix2YPZitmGINmF2YYg2KrYtdmF2YrZhSDZiNin2LnYqtmF2KfY
ryDYs9mK2KfYs9ipINmI2KXYrNix2KfYodin2Kog2YXYqtmD2KfZhdmE2Kkg2YTZhti42KfZhdmK
INin2YTYrNmI2K/YqQ0K2YjYp9mE2KjZitim2KkuDQoNCsO8ICAgICDYpdmD2LPYp9ioINin2YTZ
hdi02KfYsdmD2YrZhiDZhdmH2KfYsdin2Kog2KrZhtmB2YrYsCDZhdiq2LfZhNio2KfYqiDZhdi5
2KfZitmK2LEgSVNPIDkwMDEg2YhJU08gMTQwMDENCti52YXZhNmK2YvYpy4NCg0Kw7wgICAgINil
2LnYr9in2K8g2KfZhNmF2LTYp9ix2YPZitmGINmE2KXYrNix2KfYoSDYqtiv2YLZitmCINiv2KfY
rtmE2Yog2YHYudin2YQg2YjZhdix2KfYrNi52Kkg2KXYr9in2LHZitipINiv2YjYsdmK2KkuDQoN
CsO8ICAgICDYqti32YjZitixINiu2LfYqSDYqtit2LPZitmG2YrYqSDZhNmF2KTYtNix2KfYqiDY
p9mE2KPYr9in2KEg2YjYp9mE2KzZiNin2YbYqCDYp9mE2KjZitim2YrYqSDZiNiq2YLZhNmK2YQg
2KfZhNmF2K7Yp9i32LEuDQoNCg0KDQrinKYg4pym2KfZhNis2YXZh9mI2LEg2KfZhNmF2LPYqtmH
2K/ZgQ0KDQrDvCAgICAg2YXYr9ix2KfYoSDYp9mE2KzZiNiv2Kkg2YjYp9mE2KjZitim2KnYjCDZ
iNmF2YfZhtiv2LPZiCDYp9mE2KzZiNiv2Kkg2YjYp9mE2KjZitim2KkuDQoNCsO8ICAgICDZhdiz
2KTZiNmE2Ygg2KfZhNin2YXYqtir2KfZhNiMINmF2K/Ysdin2KEg2KfZhNiq2LTYutmK2YTYjCDZ
iNmF2YXYq9mE2Ygg2KfZhNil2K/Yp9ix2KkuDQoNCsO8ICAgICDZgdix2YIg2KfZhNiz2YTYp9mF
2Kkg2KfZhNmF2YfZhtmK2Kkg2YjZhdiz2KTZiNmE2Ygg2KfZhNmF2LTYp9ix2YrYuSDYp9mE2YXZ
h9iq2YXZiNmGINio2K/ZhdisINin2YTYrNmI2K/YqSDZiNin2YTYqNmK2KbYqS4NCg0KDQoNCiDi
nKbYp9mE2YXYrdin2YjYsSDYp9mE2LHYptmK2LPZitipINmI2YXZhtmH2YrYrNipINin2YTYqNix
2YbYp9mF2KwgKNij2LPYqNmI2LnZiiDigJQgNSDYo9mK2KfZhSkNCg0K2KfZhNmF2K3ZiNixINin
2YTYo9mI2YQ6INin2YTYpdi32KfYsSDYp9mE2YXZgdin2YfZitmF2Yog2YjYp9mE2KrYtNix2YrY
udmKINmE2KXYr9in2LHYqSDYp9mE2KzZiNiv2Kkg2YjYp9mE2KjZitim2KkNCg0KMS4gICAg2KfZ
hNij2LPYsyDZiNin2YTZhdmB2KfZh9mK2YUg2KfZhNit2K/Zitir2Kkg2YHZiiDYpdiv2KfYsdip
INin2YTYrNmI2K/YqSDZiNin2YTYqNmK2KbYqS4NCg0KMi4gICAg2KfZhNiq2LTYsdmK2LnYp9iq
INmI2KfZhNmC2YjYp9mG2YrZhiDYp9mE2KjZitim2YrYqSDZiNin2YTZhdi52KfZitmK2LEg2KfZ
hNiv2YjZhNmK2Kkg2LDYp9iqINin2YTYtdmE2KkgKElTTyA5MDAxLA0KSVNPIDE0MDAxLCBJU08g
NDUwMDEpLg0KDQozLiAgICDYp9iz2KrYsdin2KrZitis2YrYp9iqINin2YTYp9mE2KrYstin2YUg
2KfZhNio2YrYptmKINmI2KrZiNmB2YrZgiDYp9mE2KPZiNi22KfYuSDYp9mE2YXYpNiz2LPZitip
Lg0KDQoNCg0K2KfZhNmF2K3ZiNixINin2YTYq9in2YbZijog2KfZhNiq2YHYqtmK2LQg2YjYp9mE
2YXYsdin2KzYudipINin2YTYqNmK2KbZitipDQoNCjEuICAgINmF2YbZh9is2YrYp9iqINin2YTY
qtmB2KrZiti0INin2YTYqNmK2KbZiiDYp9mE2K/Yp9iu2YTZiiDZiNin2YTYrtin2LHYrNmKLg0K
DQoyLiAgICDYotmE2YrYp9iqINin2YTZhdix2KfYrNi52Kkg2KfZhNio2YrYptmK2Kkg2KfZhNiv
2YjYsdmK2KkgKEF1ZGl0KS4NCg0KMy4gICAg2KPYr9mI2KfYqiDZgtmK2KfYsyDYp9mE2KfZhdiq
2KvYp9mEINmI2KrYrdmE2YrZhCDYp9mE2YHYrNmI2KfYqi4NCg0KDQoNCtin2YTZhdit2YjYsSDY
p9mE2KvYp9mE2Ks6INiq2YLZitmK2YUg2KfZhNij2KvYsSDYp9mE2KjZitim2Yog2YjYpdiv2KfY
sdipINin2YTZhdiu2KfYt9ixDQoNCjEuICAgINij2LPYsyDZiNmF2LHYp9it2YQg2KXYudiv2KfY
ryDYr9ix2KfYs9in2Kog2KrZgtmK2YrZhSDYp9mE2KPYq9ixINin2YTYqNmK2KbZii4NCg0KMi4g
ICAg2KrYrdiv2YrYryDZiNil2K/Yp9ix2Kkg2KfZhNis2YjYp9mG2Kgg2KfZhNio2YrYptmK2Kkg
2YjYp9mE2KLYq9in2LEg2KfZhNmF2K3YqtmF2YTYqS4NCg0KMy4gICAg2K/ZhdisINil2K/Yp9ix
2Kkg2KfZhNmF2K7Yp9i32LEg2KfZhNio2YrYptmK2Kkg2YHZiiDYr9mI2LHYqSDYrdmK2KfYqSDY
p9mE2YXYtNix2YjYuS4NCg0KDQoNCtin2YTZhdit2YjYsSDYp9mE2LHYp9io2Lk6INin2YTYqti6
2YrYsdin2Kog2KfZhNmF2YbYp9iu2YrYqSDZiNin2YTYqNi12YXYqSDYp9mE2YPYsdio2YjZhtmK
2KkNCg0KMS4gICAg2KfZhNiq2LrZitix2KfYqiDYp9mE2YXZhtin2K7ZitipINmI2KPYq9ix2YfY
pyDYudmE2Ykg2KfYs9iq2K/Yp9mF2Kkg2KfZhNmF2KTYs9iz2KfYqi4NCg0KMi4gICAg2KPYs9in
2YTZitioINmC2YrYp9izINmI2KXYr9in2LHYqSDYp9mE2KjYtdmF2Kkg2KfZhNmD2LHYqNmI2YbZ
itipLg0KDQozLiAgICDYp9iz2KrYsdin2KrZitis2YrYp9iqINin2YTYqtiu2YHZitmBINmI2KfZ
hNiq2YPZitmBINmF2Lkg2KfZhNiq2LrZitixINin2YTZhdmG2KfYrtmKLg0KDQoNCg0K2KfZhNmF
2K3ZiNixINin2YTYrtin2YXYszog2KfZhNil2K/Yp9ix2Kkg2KfZhNmF2KrZg9in2YXZhNipINmE
2YTZhdmI2KfYsdivINin2YTYqNmK2KbZitipDQoNCjEuICAgINmF2LnYp9mE2KzYqSDZhdmK2KfZ
hyDYp9mE2LXYsdmBINin2YTYtdmG2KfYudmKINmI2KfZhNi12K3ZiiDZiNmB2YIg2KfZhNmF2LnY
p9mK2YrYsS4NCg0KMi4gICAg2KfZhNil2K/Yp9ix2Kkg2KfZhNmF2KrZg9in2YXZhNipINmE2YTZ
hdiu2YTZgdin2Kog2KfZhNi12YTYqNipINmI2KfZhNiu2LfYsdipLg0KDQozLiAgICDYpdi52KfY
r9ipINin2YTYqtiv2YjZitixINmI2KfZhNin2YLYqti12KfYryDYp9mE2K/Yp9im2LHZiiDZg9ii
2YTZitipINmE2YTYp9iz2KrYr9in2YXYqS4NCg0KDQoNCtin2YTZhdit2YjYsSDYp9mE2LPYp9iv
2LM6INin2YTYs9is2YTYp9iqINmI2KfZhNmC2YrYp9iz2KfYqiDYp9mE2KjZitim2YrYqQ0KDQox
LiAgICDYqti12YXZitmFINmI2KXYr9in2LHYqSDYp9mE2LPYrNmE2KfYqiDYp9mE2KjZitim2YrY
qSDZgdmKINin2YTZhdmG2LTYotiqLg0KDQoyLiAgICDYo9mG2LjZhdipINin2YTYsdi12K8g2YjY
p9mE2YLZitin2LMg2KfZhNio2YrYptmKIChNb25pdG9yaW5nIFN5c3RlbXMpLg0KDQozLiAgICDZ
hdik2LTYsdin2Kog2KfZhNij2K/Yp9ihINin2YTYqNmK2KbZiiAoRW52aXJvbm1lbnRhbCBLUElz
KS4NCg0KDQoNCtin2YTZhdit2YjYsSDYp9mE2LPYp9io2Lk6INiq2YPYp9mF2YQg2YbYuNmFINin
2YTYpdiv2KfYsdipICjYp9mE2KzZiNiv2Kkg4oCTINin2YTYqNmK2KbYqSDigJMg2KfZhNiz2YTY
p9mF2Kkg4oCTINin2YTYt9in2YLYqSkNCg0KMS4gICAg2YXZgdmH2YjZhSDYp9mE2YbYuNin2YUg
2KfZhNmF2KrZg9in2YXZhCDZhNmE2KXYr9in2LHYqSAoSU1TKS4NCg0KMi4gICAg2KfZhNmF2LLY
p9mK2Kcg2YjYp9mE2KrYrdiv2YrYp9iqINmB2Yog2KrZiNit2YrYryDYp9mE2YbYuNmFLg0KDQoz
LiAgICDYr9ix2KfYs9in2Kog2K3Yp9mE2Kkg2YbYp9is2K3YqSDZhNiq2LfYqNmK2YIg2KfZhNij
2YbYuNmF2Kkg2KfZhNmF2KrZg9in2YXZhNipLg0KDQoNCg0K2KfZhNmF2K3ZiNixINin2YTYq9in
2YXZhjog2KfZhNiq2K7Yt9mK2Lcg2KfZhNin2LPYqtix2KfYqtmK2KzZiiDZiNin2YTYqti32YjZ
itixINin2YTZhdiz2KrYr9in2YUNCg0KMS4gICAg2K/ZhdisINin2YTYqNi52K8g2KfZhNio2YrY
ptmKINmB2Yog2KfZhNiq2K7Yt9mK2Lcg2KfZhNin2LPYqtix2KfYqtmK2KzZiiDZhNmE2YXYpNiz
2LPYp9iqLg0KDQoyLiAgICDYp9mE2KrZhtmF2YrYqSDYp9mE2YXYs9iq2K/Yp9mF2Kkg2YjYp9mE
2YXYs9ik2YjZhNmK2Kkg2KfZhNmF2KzYqtmF2LnZitipLg0KDQozLiAgICDYqti32KjZitmC2KfY
qiDYp9mE2K3ZiNmD2YXYqSDYp9mE2KjZitim2YrYqSDZiNin2YTYp9is2KrZhdin2LnZitipIChF
U0cpLg0KDQoNCg0K2KfZhNmF2K3ZiNixINin2YTYqtin2LPYuTog2KfZhNiq2K/ZgtmK2YIg2YjY
p9mE2YXYsdin2KzYudipINin2YTZhtmH2KfYptmK2Kkg2YTZhNiq2K3Ys9mK2YYg2KfZhNmF2LPY
qtmF2LENCg0KMS4gICAg2K7Yt9mI2KfYqiDYp9mE2KXYudiv2KfYryDZhNi52YXZhNmK2Kkg2KfZ
hNmF2LHYp9is2LnYqSDYp9mE2K7Yp9ix2KzZitipINmI2KfZhNin2LnYqtmF2KfYry4NCg0KMi4g
ICAg2KPYs9in2YTZitioINin2YTYqtit2LPZitmGINin2YTZhdiz2KrZhdixIChDb250aW51b3Vz
IEltcHJvdmVtZW50KS4NCg0KMy4gICAg2KXYudiv2KfYryDYqtmC2KfYsdmK2LEg2KfZhNij2K/Y
p9ihINmI2KfZhNis2YjYr9ipINin2YTYqNmK2KbZitipINmE2YTZhdix2KfYrNi52YrZhiDZiNin
2YTYrNmH2KfYqiDYp9mE2LHZgtin2KjZitipLg0KDQoNCg0K4pymIOKcptmF2K7Ysdis2KfYqiDY
p9mE2KrYudmE2YUg2KfZhNmF2KrZiNmC2LnYqQ0KDQrYqNmG2YfYp9mK2Kkg2KfZhNio2LHZhtin
2YXYrCDZitmD2YjZhiDYp9mE2YXYtNin2LHZg9mI2YYg2YLYp9iv2LHZitmGINi52YTZiToNCg0K
w7wgICAgINil2LnYr9in2K8g2LPZitin2LPYqSDZiNmG2LjYp9mFINmF2KrZg9in2YXZhCDZhNmE
2KzZiNiv2Kkg2YjYp9mE2KjZitim2KkuDQoNCsO8ICAgICDYqtmG2YHZitiwINiq2YLZitmK2YUg
2YHYrNmI2KfYqiDZhdmB2LXZkdmEINmI2K7Yt9ipINiq2LXYrdmK2K3ZitipINmC2KfYqNmE2Kkg
2YTZhNiq2LfYqNmK2YIuDQoNCsO8ICAgICDYpdis2LHYp9ihINiq2K/ZgtmK2YIg2K/Yp9iu2YTZ
iiDZiNmD2KrYp9io2Kkg2KrZgtin2LHZitixINiq2YjYtdmK2KfYqiDZgtin2KjZhNipINmE2YTZ
hdiq2KfYqNi52KkuDQoNCsO8ICAgICDYpdi52K/Yp9ivINmF2LHYp9is2LnYqSDYpdiv2KfYsdmK
2Kkg2YLZiNmK2Kkg2YjYsdio2LfZh9inINio2K7Yt9ipINiq2K3Ys9mK2YYg2YXYs9iq2YXYsdip
Lg0KDQoNCg0K4pymIOKcpti32LHZgiDYp9mE2KrYr9ix2YrYqA0KDQrCtyAgICAgICAg2YXYrdin
2LbYsdin2Kog2KrZgdin2LnZhNmK2KnYjCDYr9ix2KfYs9in2Kog2K3Yp9mE2Kkg2YXYrdmE2YrY
qS4NCg0KwrcgICAgICAgINmI2LHYtCDYudmF2YQg2KrYt9io2YrZgtmK2KnYjCDZhdit2KfZg9in
2Kkg2KrYr9mC2YrZgtiMINiq2YXYp9ix2YrZhiDYrNmF2KfYudmK2KkuDQoNCsK3ICAgICAgICDZ
gtmI2KfZhNioINi52YXZhNmK2Kkg2YjZhtmF2KfYsNisINmC2KfYqNmE2Kkg2YTZhNiq2LnYr9mK
2YQgKFNPUHMsIENoZWNrbGlzdHMsIEZvcm1zKS4NCg0KDQoNCuKcpiDinKbYo9iv2YjYp9iqINmI
2YXZiNin2K8g2KfZhNiq2K/YsdmK2KgNCg0KwrcgICAgICAgINi02LHYp9im2K0g2KrZgtiv2YrZ
hdmK2KkgKFBvd2VyUG9pbnQpINmE2YPZhCDYrNmE2LPYqS4NCg0KwrcgICAgICAgINmG2YXYp9iw
2Kw6INiz2YrYp9iz2Kkg2KfZhNis2YjYr9ipINmI2KfZhNio2YrYptip2Iwg2KzYr9mI2YQg2KrY
rdmE2YrZhCDYp9mE2YHYrNmI2KfYqtiMINiz2KzZhNin2Kog2KfZhNiq2K/ZgtmK2YINCtin2YTY
r9in2K7ZhNmK2Iwg2YLZiNin2KbZhSDZhdix2KfYrNi52KkuDQoNCsK3ICAgICAgICDYrdin2YTY
p9iqINiv2LHYp9iz2YrYqSDZiNin2YLYudmK2Kkg2YjYqtmF2KfYsdmK2YYg2YXZitiv2KfZhtmK
2Kkg2YLYtdmK2LHYqS4NCg0KDQoNCuKcpiDinKbZhdmE2KfYrdi42KfYqiDYudin2YXYqToNCg0K
wrcgICAgICAgICAgICAgICDYrNmF2YrYuSDYp9mE2LTZh9in2K/Yp9iqINiq2LTZhdmEINi02YfY
p9iv2Kkg2YXYudiq2YXYr9ip2Iwg2K3ZgtmK2KjYqSDYqtiv2LHZitio2YrYqdiMINmI2YjYsdi0
INi52YXZhA0K2KrZgdin2LnZhNmK2KkuDQoNCsK3ICAgICAgICAgICAgICAg2YrZhdmD2YYg2KrZ
htmB2YrYsCDYp9mE2KjYsdin2YXYrCDYrdi22YjYsdmK2YvYpyDYo9mIINij2YjZhtmE2KfZitmG
INi52KjYsSBab29tLg0KDQrCtyAgICAgICAgICAgICAgINil2YXZg9in2YbZitipINiq2K7YtdmK
2LUg2KPZiiDYtNmH2KfYr9ipINmE2KrZg9mI2YYg2K/Yp9iu2YQg2KfZhNi02LHZg9ipIChJbi1I
b3VzZSkuDQoNCg0KDQrZiNio2YfYsNmHINin2YTZhdmG2KfYs9io2Kkg2YrYs9i52K/ZhtinINiv
2LnZiNiq2YPZhSDZhNmE2YXYtNin2LHZg9ipINmI2KrYudmF2YrZhSDYrti32KfYqNmG2Kcg2LnZ
hNmJINin2YTZhdmH2KrZhdmK2YYg2KjZhdmA2YDZiNi22YDZiNi5DQrYp9mE2LTZh9in2K/YqSDY
p9mE2KfYrdiq2LHYp9mB2YrYqSDZiNil2YHYp9iv2KrZhtinINio2YXZhiDYqtmC2KrYsdit2YjZ
hiDYqtmI2KzZitmHINin2YTYr9i52YjYqSDZhNmH2YUNCg0K2K7Zitin2LEg2LnZhdmE2Yog2YbZ
hdmI2LDYrNmKOiA1INij2YrYp9mFICg0MCDYs9in2LnYqSkuINmK2YXZg9mGINiq2YPZitmK2YHZ
h9inINmD2KjYsdmG2KfZhdisINmF2YPYq9mBICgzINij2YrYp9mFKSDYo9mIDQrZhdmI2LPYuSAo
MTAg2KPZitin2YUpINit2LPYqCDYp9it2KrZitin2KzYp9iqINin2YTZhdmG2LjZhdipLiDZitit
2LXZhCDYp9mE2YXYtNin2LHZgyDYudmE2Yk6INi02YfYp9iv2Kkg2KXYqtmF2KfZhSDZhdi52KrZ
hdiv2KkNCtiu2YTYp9mEINin2YTZgdiq2LHYqSDZhdmGIDIg2KfZhNmJIDYg2YbZiNmB2YXYqNix
IDIwMjUNCg0KwqggICAg2YTZhNiq2LPYrNmK2YQg2KPZiCDZhNi32YTYqCDYp9mE2LnYsdi2INin
2YTYqtiv2LHZitio2Yog2KfZhNmD2KfZhdmE2Iwg2YrYsdis2Ykg2KfZhNiq2YjYp9i12YQg2YXY
udmG2Kc6DQoNCsKoICAgICAg2KMgLyDYs9in2LHYqSDYudio2K8g2KfZhNis2YjYp9ivIOKAk9mF
2K/ZitixINin2YTYqtiv2LHZitioDQoNCsKoDQoNCsKoICAgIFvYsdmC2YUg2KfZhNmH2KfYqtmB
IC8g2YjYp9iq2LMg2KfYqF0gICAgMDAyMDEwNjk5OTQzOTkgLTAwMjAxMDYyOTkyNTEwIC0NCjAw
MjAxMDk2ODQxNjI2DQoNCtmG2K3ZhiDZgdmKINin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZ
hNiq2YbZhdmK2Kkg2KfZhNil2K/Yp9ix2YrYqdiMINi02LHZg9in2KTZg9mFINmB2Yog2KjZhtin
2KEg2KfZhNmC2K/Ysdin2Kog2YjYqtit2YLZitmCINin2YTYqtmF2YrYsg0KLg0KDQotLSAKWW91
IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUg
R29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlz
IGdyb3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0
byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRp
c2N1c3Npb24gdmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRl
di9DQURqMVpLbW9ScnJCa3BwTkN6elR6azVfdTBlS282N3pNdk5hJTJCJTJCVDA5QXEwdGNyZ0pR
JTQwbWFpbC5nbWFpbC5jb20uCg==
--0000000000008f209b0640a3aded
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:jus=
tify;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"RTL"=
></span><span dir=3D"RTL"></span><span style=3D"font-size:14pt;line-height:=
107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;colo=
r:rgb(64,64,64);background-image:initial;background-position:initial;backgr=
ound-size:initial;background-repeat:initial;background-origin:initial;backg=
round-clip:initial"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0<span lang=3D"AR-SA">=D9=84=D9=85 =D9=8A=D8=B9=D8=AF =D8=AA=D8=B7=D9=88=
=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=AA =D9=85=D8=B1=
=D9=87=D9=88=D9=86=D9=8B=D8=A7
=D8=A8=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=AA=D9=82=D9=84=D9=8A=D8=AF=D9=8A=
=D8=A9 =D8=A3=D9=88 =D8=A5=D8=AC=D8=B1=D8=A7=D8=A1=D8=A7=D8=AA =D8=B1=D9=88=
=D8=AA=D9=8A=D9=86=D9=8A=D8=A9=D8=8C =D8=A8=D9=84 =D8=A8=D8=A7=D8=AA =D9=8A=
=D8=AD=D8=AA=D8=A7=D8=AC =D8=A5=D9=84=D9=89 =D8=A3=D9=86=D8=B8=D9=85=D8=A9 =
=D8=B0=D9=83=D9=8A=D8=A9 =D8=AA=D8=B9=D9=8A=D8=AF =D8=AA=D8=B4=D9=83=D9=8A=
=D9=84
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=AA=D9=85=D9=86=D8=AD=D9=87 =
=D8=A8=D8=B9=D8=AF=D9=8B=D8=A7 =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=
=D8=AC=D9=8A=D9=8B=D8=A7. =D9=85=D9=86 =D9=87=D9=86=D8=A7 =D8=AA=D8=A3=D8=
=AA=D9=8A =D9=85=D8=A8=D8=A7=D8=AF=D8=B1=D8=A9 =D8=A7=D9=84=D8=AF=D8=A7=D8=
=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=
=85=D9=8A=D8=A9
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D8=B9=D8=A8=D8=B1 =D8=A8=
=D8=B1=D9=86=D8=A7=D9=85=D8=AC=D9=87=D8=A7 =D8=A7=D9=84=D9=85=D8=AA=D8=AE=
=D8=B5=D8=B5 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=
=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D8=A9 =D9=88=D9=81=D9=82 =D8=A7=
=D9=84=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D8=AF=D9=88=D9=84=
=D9=8A=D8=A9: =D9=85=D9=86 =D8=A7=D9=84=D8=A5=D9=86=D8=B4=D8=A7=D8=A1
=D8=A5=D9=84=D9=89 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =C2=A0=
=D9=84=D8=AA=D8=B2=D9=88=D9=91=D8=AF =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=
=D8=A7=D8=AA =D8=A8=D8=A3=D8=AF=D9=88=D8=A7=D8=AA
=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=88=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =
=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D8=AA=D9=8F=D8=AD=D9=88=D9=91=D9=84 =D8=A7=
=D9=84=D8=AA=D8=AD=D8=AF=D9=8A=D8=A7=D8=AA =D8=A5=D9=84=D9=89 =D9=81=D8=B1=
=D8=B5=D8=8C =D9=88=D8=AA=D9=8F=D8=B1=D8=B3=D9=91=D8=AE =D8=AB=D9=82=D8=A7=
=D9=81=D8=A9 =D9=85=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D8=AA=D8=B9=D9=83=
=D8=B3 =D9=82=D9=88=D8=A9
=D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1 =D9=88=D9=88=D8=B9=D9=8A =D8=A7=D9=84=
=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=8A=D8=A9.</span></span></p>

<h1 dir=3D"RTL" style=3D"margin:0.25in 0in 4pt;line-height:107%;break-after=
:avoid;direction:rtl;unicode-bidi:embed;font-size:20pt;font-family:&quot;Ca=
libri Light&quot;,&quot;sans-serif&quot;;color:rgb(46,116,181);font-weight:=
normal"><b><span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&=
quot;,&quot;serif&quot;;color:windowtext">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=
=D8=A9 =D9=88=D9=81=D9=82 =D8=A7=D9=84=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9: =D9=85=D9=86 =D8=A7=D9=84=D8=A5=
=D9=86=D8=B4=D8=A7=D8=A1 =D8=A5=D9=84=D9=89
=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9</span></b></h1>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;margin:0in 0=
in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:11pt;fon=
t-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-=
position:initial;background-size:initial;background-repeat:initial;backgrou=
nd-origin:initial;background-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>=E2=9C=A6</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:AMoshref-Thulth;color:=
rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;colo=
r:rgb(255,192,0)">=E2=9C=A6</span><span dir=3D"RTL"></span><span dir=3D"RTL=
"></span><span style=3D"font-size:18pt;line-height:107%;font-family:AMoshre=
f-Thulth;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial"><span dir=3D"RTL"></span><span dir=3D"RTL"=
></span> </span><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:10=
7%;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;;color:rgb(83,1=
29,53);background-image:initial;background-position:initial;background-size=
:initial;background-repeat:initial;background-origin:initial;background-cli=
p:initial">=D9=86=D8=A8=D8=B0=D8=A9
=D8=B9=D8=A7=D9=85=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;line-height:107%;font-family:AMoshref-Thulth;color:rgb(64,64,64);backgroun=
d-image:initial;background-position:initial;background-size:initial;backgro=
und-repeat:initial;background-origin:initial;background-clip:initial"></spa=
n></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=AA=D8=AF=
=D8=B1=D9=8A=D8=A8=D9=8A =D8=B9=D9=85=D9=84=D9=8A =D9=88=D9=85=D9=83=D8=AB=
=D9=81 =D9=8A=D9=87=D8=AF=D9=81 =D8=A5=D9=84=D9=89 =D8=AA=D8=A3=D9=87=D9=8A=
=D9=84 =D9=81=D8=B1=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=D8=A7=D9=84=
=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=8A=D9=86 =D9=84=D9=88=D8=B6=D8=B9=D8=8C
=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=8C =D9=88=D8=B5=D9=8A=D8=A7=D9=86=D8=A9 =
=D9=86=D8=B8=D9=85 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=
=D8=AF=D8=A9 (=D9=85=D8=AB=D9=84 </span><span dir=3D"LTR" style=3D"font-siz=
e:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sa=
ns-serif&quot;;color:rgb(64,64,64);background-image:initial;background-posi=
tion:initial;background-size:initial;background-repeat:initial;background-o=
rigin:initial;background-clip:initial">ISO 9001</span><span dir=3D"RTL"></s=
pan><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;l=
ine-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif=
&quot;;color:rgb(64,64,64);background-image:initial;background-position:ini=
tial;background-size:initial;background-repeat:initial;background-origin:in=
itial;background-clip:initial"><span dir=3D"RTL"></span><span dir=3D"RTL"><=
/span>)
=D9=88=D9=86=D8=B8=D9=85 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A8=
=D9=8A=D8=A6=D8=A9 (=D9=85=D8=AB=D9=84 </span><span dir=3D"LTR" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&q=
uot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial">ISO 14001</span><span dir=3D"R=
TL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size=
:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;san=
s-serif&quot;;color:rgb(64,64,64);background-image:initial;background-posit=
ion:initial;background-size:initial;background-repeat:initial;background-or=
igin:initial;background-clip:initial"><span dir=3D"RTL"></span><span dir=3D=
"RTL"></span>)=D8=8C =D9=85=D8=B9
=D8=A7=D9=84=D8=AA=D8=B1=D9=83=D9=8A=D8=B2 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D8=B1=D8=A8=D8=B7 =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=86=D8=B8=D8=A7=D9=85=
=D9=8A=D9=86=D8=8C =D8=AA=D9=86=D9=81=D9=8A=D8=B0 =D8=A7=D9=84=D8=AA=D8=AF=
=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A=D8=8C =D9=88=
=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=
=D8=A9 =D9=84=D8=AA=D8=AD=D9=82=D9=8A=D9=82
=D8=A7=D9=84=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=
=D9=85=D8=B1 =D9=88=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84 =D8=A7=
=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=D9=8A.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>=E2=9C=A6</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:AMoshref-Thulth;color:=
rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;colo=
r:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&quot;serif&qu=
ot;;color:rgb(83,129,53);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81
=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D8=A9</span><span lang=3D"AR-SA" style=3D"fo=
nt-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,=
53);background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-=
size:14pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=
=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Ti=
mes New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64=
,64,64);background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial">=D8=AA=D9=85=D9=83=D9=8A=D9=86
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=85=D9=86 =D8=AA=
=D8=B5=D9=85=D9=8A=D9=85 =D9=88=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=D8=AF =D8=B3=
=D9=8A=D8=A7=D8=B3=D8=A9 =D9=88=D8=A5=D8=AC=D8=B1=D8=A7=D8=A1=D8=A7=D8=AA =
=D9=85=D8=AA=D9=83=D8=A7=D9=85=D9=84=D8=A9 =D9=84=D9=86=D8=B8=D8=A7=D9=85=
=D9=8A =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D9=8A=
=D8=A6=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=
=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Ti=
mes New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64=
,64,64);background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial">=D8=A5=D9=83=D8=B3=D8=A7=D8=A8
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=85=D9=87=D8=A7=
=D8=B1=D8=A7=D8=AA =D8=AA=D9=86=D9=81=D9=8A=D8=B0 =D9=85=D8=AA=D8=B7=D9=84=
=D8=A8=D8=A7=D8=AA =D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 </span><span dir=3D=
"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTit=
le Black&quot;,&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:=
initial;background-position:initial;background-size:initial;background-repe=
at:initial;background-origin:initial;background-clip:initial">ISO 9001</spa=
n><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" st=
yle=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black=
&quot;,&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;=
background-position:initial;background-size:initial;background-repeat:initi=
al;background-origin:initial;background-clip:initial"><span dir=3D"RTL"></s=
pan><span dir=3D"RTL"></span> =D9=88</span><span dir=3D"LTR" style=3D"font-=
size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot=
;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-p=
osition:initial;background-size:initial;background-repeat:initial;backgroun=
d-origin:initial;background-clip:initial">ISO 14001</span><span dir=3D"RTL"=
></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14=
pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-s=
erif&quot;;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial"><span dir=3D"RTL"></span><span dir=3D"RT=
L"></span> =D8=B9=D9=85=D9=84=D9=8A=D9=8B=D8=A7.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=
=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Ti=
mes New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64=
,64,64);background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=84=D8=A5=D8=AC=
=D8=B1=D8=A7=D8=A1 =D8=AA=D8=AF=D9=82=D9=8A=D9=82 =D8=AF=D8=A7=D8=AE=D9=84=
=D9=8A =D9=81=D8=B9=D8=A7=D9=84 =D9=88=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =
=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D8=AF=D9=88=D8=B1=D9=8A=D8=A9.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 0.5in 8pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:=
11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:1=
4pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=BC<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-s=
tretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New =
Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=
=AE=D8=B7=D8=A9 =D8=AA=D8=AD=D8=B3=D9=8A=D9=86=D9=8A=D8=A9 =D9=84=D9=85=D8=
=A4=D8=B4=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=
=A7=D9=84=D8=AC=D9=88=D8=A7=D9=86=D8=A8
=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=D8=A9 =D9=88=D8=AA=D9=82=D9=84=D9=8A=
=D9=84 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>=E2=9C=A6</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:AMoshref-Thulth;color:=
rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;colo=
r:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&quot;serif&qu=
ot;;color:rgb(83,129,53);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D8=A7=D9=84=D8=AC=D9=85=D9=87=D9=88=D8=B1
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81</span><span lang=3D"AR-SA"=
 style=3D"font-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color=
:rgb(83,129,53);background-image:initial;background-position:initial;backgr=
ound-size:initial;background-repeat:initial;background-origin:initial;backg=
round-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-=
size:14pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=
=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Ti=
mes New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64=
,64,64);background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1
=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=
=D8=A9=D8=8C =D9=88=D9=85=D9=87=D9=86=D8=AF=D8=B3=D9=88 =D8=A7=D9=84=D8=AC=
=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=
=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Ti=
mes New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64=
,64,64);background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84=D8=8C =D9=85=D8=AF=D8=B1=
=D8=A7=D8=A1 =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84=D8=8C =D9=88=D9=85=
=D9=85=D8=AB=D9=84=D9=88 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 0.5in 8pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:=
11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:1=
4pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=BC<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-s=
tretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New =
Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D9=81=D8=B1=D9=82 =D8=A7=D9=84=D8=
=B3=D9=84=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D9=
=88=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=
=B1=D9=8A=D8=B9 =D8=A7=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=88=D9=86
=D8=A8=D8=AF=D9=85=D8=AC =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=
=D9=84=D8=A8=D9=8A=D8=A6=D8=A9.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an lang=3D"AR-SA" dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font=
-family:AMoshref-Thulth;color:rgb(255,192,0)"><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span>=C2=A0</span><span dir=3D"LTR" style=3D"font-size:14pt=
;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&=
quot;;color:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-SA" style=3D"f=
ont-size:20pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;;color:rgb(83,129,53);background-image:initial;background-posi=
tion:initial;background-size:initial;background-repeat:initial;background-o=
rigin:initial;background-clip:initial">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=
=D8=B1
=D8=A7=D9=84=D8=B1=D8=A6=D9=8A=D8=B3=D9=8A=D8=A9 =D9=88=D9=85=D9=86=D9=87=
=D9=8A=D8=AC=D8=A9 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC </span>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:107%;font-family:A=
Moshref-Thulth;color:rgb(83,129,53);background-image:initial;background-pos=
ition:initial;background-size:initial;background-repeat:initial;background-=
origin:initial;background-clip:initial">(</span><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:&quot;Times New Roman&quot;=
,&quot;serif&quot;;color:rgb(83,129,53);background-image:initial;background=
-position:initial;background-size:initial;background-repeat:initial;backgro=
und-origin:initial;background-clip:initial">=D8=A3=D8=B3=D8=A8=D9=88=D8=B9=
=D9=8A </span><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:107%=
;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;;color:rgb(83,129=
,53);background-image:initial;background-position:initial;background-size:i=
nitial;background-repeat:initial;background-origin:initial;background-clip:=
initial">=E2=80=94</span><span lang=3D"AR-SA" style=3D"font-size:20pt;line-=
height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,53);background-ima=
ge:initial;background-position:initial;background-size:initial;background-r=
epeat:initial;background-origin:initial;background-clip:initial"> 5 </span>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:107%;font-family:&=
quot;Times New Roman&quot;,&quot;serif&quot;;color:rgb(83,129,53);backgroun=
d-image:initial;background-position:initial;background-size:initial;backgro=
und-repeat:initial;background-origin:initial;background-clip:initial">=D8=
=A3=D9=8A=D8=A7=D9=85</span><span lang=3D"AR-SA" style=3D"font-size:20pt;li=
ne-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,53);background-=
image:initial;background-position:initial;background-size:initial;backgroun=
d-repeat:initial;background-origin:initial;background-clip:initial">)</span=
><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:107%;font-family:=
Arial,&quot;sans-serif&quot;;color:rgb(83,129,53);background-image:initial;=
background-position:initial;background-size:initial;background-repeat:initi=
al;background-origin:initial;background-clip:initial"> </span><span lang=3D=
"AR-SA" style=3D"font-size:20pt;line-height:107%;font-family:AMoshref-Thult=
h;color:rgb(83,129,53);background-image:initial;background-position:initial=
;background-size:initial;background-repeat:initial;background-origin:initia=
l;background-clip:initial"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=A3=D9=88=
=D9=84:
=D8=A7=D9=84=D8=A5=D8=B7=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D9=81=D8=A7=D9=87=
=D9=8A=D9=85=D9=8A =D9=88=D8=A7=D9=84=D8=AA=D8=B4=D8=B1=D9=8A=D8=B9=D9=8A =
=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =
=D9=88=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D8=A9</span><span lang=3D"AR-SA" style=
=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-se=
rif&quot;"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=A3=D8=B3=D8=B3 =D9=88=D8=A7=D9=84=D9=85=D9=81=D8=A7=D9=87=
=D9=8A=D9=85 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9 =D9=81=D9=8A =D8=A5=
=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=
=D9=84=D8=A8=D9=8A=D8=A6=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=AA=D8=B4=D8=B1=D9=8A=D8=B9=D8=A7=D8=AA =D9=88=D8=A7=D9=84=
=D9=82=D9=88=D8=A7=D9=86=D9=8A=D9=86 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=
=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=
=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D8=B0=D8=A7=D8=AA =D8=A7=D9=84=D8=B5=D9=84=
=D8=A9 (</span><span dir=3D"LTR" style=3D"font-size:14pt;font-family:&quot;=
AlSharkTitle Black&quot;,&quot;sans-serif&quot;">ISO 9001, ISO 14001, ISO 4=
5001</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"=
AR-SA" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&=
quot;sans-serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>).=
</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=
=D9=84=D8=A7=D9=84=D8=AA=D8=B2=D8=A7=D9=85 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=
=D9=8A =D9=88=D8=AA=D9=88=D9=81=D9=8A=D9=82 =D8=A7=D9=84=D8=A3=D9=88=D8=B6=
=D8=A7=D8=B9 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=
=D9=86=D9=8A:
=D8=A7=D9=84=D8=AA=D9=81=D8=AA=D9=8A=D8=B4 =D9=88=D8=A7=D9=84=D9=85=D8=B1=
=D8=A7=D8=AC=D8=B9=D8=A9 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=D8=A9</span><=
/p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D9=86=D9=87=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=81=D8=AA=
=D9=8A=D8=B4 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A =D8=A7=D9=84=D8=AF=D8=A7=
=D8=AE=D9=84=D9=8A =D9=88=D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=D9=8A.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A2=D9=84=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=
=D8=A9 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=D8=A9 =D8=A7=D9=84=D8=AF=D9=88=
=D8=B1=D9=8A=D8=A9 (</span><span dir=3D"LTR" style=3D"font-size:14pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">Audit</span><s=
pan dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-se=
rif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D9=82=D9=8A=D8=A7=D8=B3 =D8=A7=D9=84=D8=A7=
=D9=85=D8=AA=D8=AB=D8=A7=D9=84 =D9=88=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=
=D9=84=D9=81=D8=AC=D9=88=D8=A7=D8=AA.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</=
span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=
=D9=84=D8=AB:
=D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=A7=D9=84=D8=A3=D8=AB=D8=B1 =D8=A7=D9=84=
=D8=A8=D9=8A=D8=A6=D9=8A =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=
=D9=85=D8=AE=D8=A7=D8=B7=D8=B1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A3=D8=B3=D8=B3 =D9=88=D9=85=D8=B1=D8=A7=D8=AD=D9=84 =D8=A5=D8=B9=D8=AF=
=D8=A7=D8=AF =D8=AF=D8=B1=D8=A7=D8=B3=D8=A7=D8=AA =D8=AA=D9=82=D9=8A=D9=8A=
=D9=85 =D8=A7=D9=84=D8=A3=D8=AB=D8=B1 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A.=
</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AA=D8=AD=D8=AF=D9=8A=D8=AF =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=AC=D9=88=D8=A7=D9=86=D8=A8 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=
=D8=A9 =D9=88=D8=A7=D9=84=D8=A2=D8=AB=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D8=AD=
=D8=AA=D9=85=D9=84=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=85=D8=AC =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=
=D8=A7=D8=B7=D8=B1 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=D8=A9 =D9=81=D9=8A =
=D8=AF=D9=88=D8=B1=D8=A9 =D8=AD=D9=8A=D8=A7=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=
=D8=B1=D9=88=D8=B9.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</=
span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=B1=D8=A7=
=D8=A8=D8=B9:
=D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=86=
=D8=A7=D8=AE=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D8=B5=D9=85=D8=A9 =D8=A7=
=D9=84=D9=83=D8=B1=D8=A8=D9=88=D9=86=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=86=
=D8=A7=D8=AE=D9=8A=D8=A9 =D9=88=D8=A3=D8=AB=D8=B1=D9=87=D8=A7 =D8=B9=D9=84=
=D9=89 =D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=A4=
=D8=B3=D8=B3=D8=A7=D8=AA.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A3=D8=B3=D8=A7=D9=84=D9=8A=D8=A8 =D9=82=D9=8A=D8=A7=D8=B3 =D9=88=D8=A5=
=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A8=D8=B5=D9=85=D8=A9 =D8=A7=D9=84=
=D9=83=D8=B1=D8=A8=D9=88=D9=86=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=
=D9=84=D8=AA=D8=AE=D9=81=D9=8A=D9=81 =D9=88=D8=A7=D9=84=D8=AA=D9=83=D9=8A=
=D9=81 =D9=85=D8=B9 =D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=
=D9=86=D8=A7=D8=AE=D9=8A.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</=
span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AE=D8=A7=
=D9=85=D8=B3:
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AA=D9=83=
=D8=A7=D9=85=D9=84=D8=A9 =D9=84=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=
=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D8=B9=D8=A7=D9=84=D8=AC=D8=A9 =D9=85=D9=8A=D8=A7=D9=87 =D8=A7=D9=84=
=D8=B5=D8=B1=D9=81 =D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=8A =D9=88=D8=A7=
=D9=84=D8=B5=D8=AD=D9=8A =D9=88=D9=81=D9=82 =D8=A7=D9=84=D9=85=D8=B9=D8=A7=
=D9=8A=D9=8A=D8=B1.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AA=D9=83=
=D8=A7=D9=85=D9=84=D8=A9 =D9=84=D9=84=D9=85=D8=AE=D9=84=D9=81=D8=A7=D8=AA =
=D8=A7=D9=84=D8=B5=D9=84=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D8=AE=D8=B7=D8=B1=
=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A5=D8=B9=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=AA=D8=AF=D9=88=D9=8A=D8=B1 =
=D9=88=D8=A7=D9=84=D8=A7=D9=82=D8=AA=D8=B5=D8=A7=D8=AF =D8=A7=D9=84=D8=AF=
=D8=A7=D8=A6=D8=B1=D9=8A =D9=83=D8=A2=D9=84=D9=8A=D8=A9 =D9=84=D9=84=D8=A7=
=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9.</span><span dir=3D"LTR" style=3D"font=
-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot=
;"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</span><=
/p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=B3=D8=A7=
=D8=AF=D8=B3:
=D8=A7=D9=84=D8=B3=D8=AC=D9=84=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=82=D9=8A=
=D8=A7=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=D8=A9</span><=
/p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AA=D8=B5=D9=85=D9=8A=D9=85 =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=B3=D8=AC=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=
=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=86=D8=B4=D8=A2=D8=AA.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A3=D9=86=D8=B8=D9=85=D8=A9 =D8=A7=D9=84=D8=B1=D8=B5=D8=AF =D9=88=D8=A7=
=D9=84=D9=82=D9=8A=D8=A7=D8=B3 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A (</span=
><span dir=3D"LTR" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle B=
lack&quot;,&quot;sans-serif&quot;">Monitoring Systems</span><span dir=3D"RT=
L"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:=
14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"><sp=
an dir=3D"RTL"></span><span dir=3D"RTL"></span>).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D8=A4=D8=B4=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =
=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A (</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quo=
t;">Environmental
KPIs</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"=
AR-SA" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&=
quot;sans-serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>).=
</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</=
span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=B3=D8=A7=
=D8=A8=D8=B9:
=D8=AA=D9=83=D8=A7=D9=85=D9=84 =D9=86=D8=B8=D9=85 =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D8=A9 (=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =E2=80=93 =D8=A7=
=D9=84=D8=A8=D9=8A=D8=A6=D8=A9 =E2=80=93 =D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=
=85=D8=A9 =E2=80=93 =D8=A7=D9=84=D8=B7=D8=A7=D9=82=D8=A9)</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D9=81=D9=87=D9=88=D9=85 =D8=A7=D9=84=D9=86=D8=B8=D8=A7=D9=85 =D8=A7=
=D9=84=D9=85=D8=AA=D9=83=D8=A7=D9=85=D9=84 =D9=84=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 (</span><span dir=3D"LTR" style=3D"font-size:14pt;font-family:=
&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">IMS</span><span dir=
=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot=
;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D9=85=D8=B2=D8=A7=D9=8A=D8=A7 =D9=88=D8=A7=D9=84=D8=AA=D8=AD=
=D8=AF=D9=8A=D8=A7=D8=AA =D9=81=D9=8A =D8=AA=D9=88=D8=AD=D9=8A=D8=AF =D8=A7=
=D9=84=D9=86=D8=B8=D9=85.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D8=B1=D8=A7=D8=B3=D8=A7=D8=AA =D8=AD=D8=A7=D9=84=D8=A9 =D9=86=D8=A7=
=D8=AC=D8=AD=D8=A9 =D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82 =D8=A7=D9=84=D8=A3=
=D9=86=D8=B8=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=AA=D9=83=D8=A7=D9=85=D9=84=
=D8=A9.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</=
span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=
=D9=85=D9=86:
=D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=
=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D9=88=
=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=AF=D8=A7=D9=85</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=85=D8=AC =D8=A7=D9=84=D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A8=D9=8A=
=D8=A6=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=
=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A =D9=84=D9=84=
=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=
=D8=AF=D8=A7=D9=85=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A4=D9=88=D9=84=
=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A=D8=A9.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=88=D9=83=
=D9=85=D8=A9 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=
=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=D8=A9 (</span><span dir=3D"LTR" =
style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sa=
ns-serif&quot;">ESG</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span=
><span lang=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;AlSharkTitl=
e Black&quot;,&quot;sans-serif&quot;"><span dir=3D"RTL"></span><span dir=3D=
"RTL"></span>).</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</=
span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 7.1pt 8pt 0in;line-h=
eight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;=
font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;backgroun=
d:lightgrey">=D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AA=D8=A7=
=D8=B3=D8=B9:
=D8=A7=D9=84=D8=AA=D8=AF=D9=82=D9=8A=D9=82 =D9=88=D8=A7=D9=84=D9=85=D8=B1=
=D8=A7=D8=AC=D8=B9=D8=A9 =D8=A7=D9=84=D9=86=D9=87=D8=A7=D8=A6=D9=8A=D8=A9 =
=D9=84=D9=84=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=
=D9=85=D8=B1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&qu=
ot;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AE=D8=B7=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =
=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=
=D8=B9=D8=A9 =D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=D9=8A=D8=A9 =D9=88=D8=A7=
=D9=84=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=D8=AF.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 43.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A3=D8=B3=D8=A7=D9=84=D9=8A=D8=A8 =D8=A7=D9=84=D8=AA=D8=AD=D8=B3=D9=8A=
=D9=86 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=85=D8=B1 (</span><span dir=3D"LTR"=
 style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;s=
ans-serif&quot;">Continuous Improvement</span><span dir=3D"RTL"></span><spa=
n dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;font-fami=
ly:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"><span dir=3D"RTL"=
></span><span dir=3D"RTL"></span>).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 43.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3=
.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;=
font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Time=
s New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=A7=
=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =
=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D9=8A=D8=A9 =D9=84=D9=84=D9=85=D8=B1=D8=A7=
=D8=AC=D8=B9=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D8=AC=D9=87=D8=A7=D8=AA
=D8=A7=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D9=8A=D8=A9.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>=E2=9C=A6</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:AMoshref-Thulth;color:=
rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;colo=
r:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&quot;serif&qu=
ot;;color:rgb(83,129,53);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D9=85=D8=AE=D8=B1=D8=AC=D8=A7=D8=AA
=D8=A7=D9=84=D8=AA=D8=B9=D9=84=D9=85 =D8=A7=D9=84=D9=85=D8=AA=D9=88=D9=82=
=D8=B9=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height=
:107%;font-family:AMoshref-Thulth;color:rgb(83,129,53);background-image:ini=
tial;background-position:initial;background-size:initial;background-repeat:=
initial;background-origin:initial;background-clip:initial"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=A8=D9=86=D9=87=D8=A7=D9=8A=D8=A9 =D8=A7=D9=84=
=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D9=8A=D9=83=D9=88=D9=86 =D8=A7=D9=84=
=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=88=D9=86 =D9=82=D8=A7=D8=AF=D8=B1=D9=8A=
=D9=86 =D8=B9=D9=84=D9=89:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-=
size:14pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=
=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Ti=
mes New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64=
,64,64);background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
=D8=B3=D9=8A=D8=A7=D8=B3=D8=A9 =D9=88=D9=86=D8=B8=D8=A7=D9=85 =D9=85=D8=AA=
=D9=83=D8=A7=D9=85=D9=84 =D9=84=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=
=D9=84=D8=A8=D9=8A=D8=A6=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=
=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Ti=
mes New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64=
,64,64);background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial">=D8=AA=D9=86=D9=81=D9=8A=D8=B0
=D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D9=81=D8=AC=D9=88=D8=A7=D8=AA =D9=85=D9=81=
=D8=B5=D9=91=D9=84 =D9=88=D8=AE=D8=B7=D8=A9 =D8=AA=D8=B5=D8=AD=D9=8A=D8=AD=
=D9=8A=D8=A9 =D9=82=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D8=B7=D8=A8=
=D9=8A=D9=82.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=
=BC<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Ti=
mes New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64=
,64,64);background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial">=D8=A5=D8=AC=D8=B1=D8=A7=D8=A1
=D8=AA=D8=AF=D9=82=D9=8A=D9=82 =D8=AF=D8=A7=D8=AE=D9=84=D9=8A =D9=88=D9=83=
=D8=AA=D8=A7=D8=A8=D8=A9 =D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=AA=D9=88=
=D8=B5=D9=8A=D8=A7=D8=AA =D9=82=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=84=D9=85=
=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 0.5in 8pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:=
11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:1=
4pt;line-height:107%;font-family:Wingdings;color:rgb(64,64,64)">=C3=BC<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-s=
tretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New =
Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D9=
=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=
=82=D9=88=D9=8A=D8=A9 =D9=88=D8=B1=D8=A8=D8=B7=D9=87=D8=A7 =D8=A8=D8=AE=D8=
=B7=D8=A9 =D8=AA=D8=AD=D8=B3=D9=8A=D9=86
=D9=85=D8=B3=D8=AA=D9=85=D8=B1=D8=A9.</span><span dir=3D"LTR" style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-=
position:initial;background-size:initial;background-repeat:initial;backgrou=
nd-origin:initial;background-clip:initial"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>=E2=9C=A6</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:AMoshref-Thulth;color:=
rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;colo=
r:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&quot;serif&qu=
ot;;color:rgb(83,129,53);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D8=B7=D8=B1=D9=82
=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(8=
3,129,53);background-image:initial;background-position:initial;background-s=
ize:initial;background-repeat:initial;background-origin:initial;background-=
clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-=
size:14pt;line-height:107%;font-family:Symbol;color:rgb(64,64,64)">=C2=B7<s=
pan style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times N=
ew Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D9=85=D8=AD=D8=A7=D8=B6=D8=B1=D8=
=A7=D8=AA =D8=AA=D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=A9=D8=8C =D8=AF=D8=B1=D8=
=A7=D8=B3=D8=A7=D8=AA =D8=AD=D8=A7=D9=84=D8=A9 =D9=85=D8=AD=D9=84=D9=8A=D8=
=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:Symbol;color:rgb(64,64,64)">=C2=B7<=
span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times =
New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D9=88=D8=B1=D8=B4 =D8=B9=D9=85=D9=
=84 =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=8A=D8=A9=D8=8C =D9=85=D8=AD=D8=A7=D9=
=83=D8=A7=D8=A9 =D8=AA=D8=AF=D9=82=D9=8A=D9=82=D8=8C =D8=AA=D9=85=D8=A7=D8=
=B1=D9=8A=D9=86 =D8=AC=D9=85=D8=A7=D8=B9=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 0.5in 8pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:=
11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:1=
4pt;line-height:107%;font-family:Symbol;color:rgb(64,64,64)">=C2=B7<span st=
yle=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D9=82=D9=88=D8=A7=D9=84=D8=A8 =D8=
=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=88=D9=86=D9=85=D8=A7=D8=B0=D8=AC =D9=82=D8=
=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D8=B9=D8=AF=D9=8A=D9=84 (</span><s=
pan dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;=
AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64,64,64);backgro=
und-image:initial;background-position:initial;background-size:initial;backg=
round-repeat:initial;background-origin:initial;background-clip:initial">SOP=
s, Checklists, Forms</span><span dir=3D"RTL"></span><span dir=3D"RTL"></spa=
n><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family=
:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64,64,64);=
background-image:initial;background-position:initial;background-size:initia=
l;background-repeat:initial;background-origin:initial;background-clip:initi=
al"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>).</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>=E2=9C=A6</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:AMoshref-Thulth;color:=
rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;colo=
r:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&quot;serif&qu=
ot;;color:rgb(83,129,53);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D8=A3=D8=AF=D9=88=D8=A7=D8=AA
=D9=88=D9=85=D9=88=D8=A7=D8=AF =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</=
span><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:107%;font-fam=
ily:AMoshref-Thulth;color:rgb(83,129,53);background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-=
size:14pt;line-height:107%;font-family:Symbol;color:rgb(64,64,64)">=C2=B7<s=
pan style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times N=
ew Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D8=B4=D8=B1=D8=A7=D8=A6=D8=AD =D8=
=AA=D9=82=D8=AF=D9=8A=D9=85=D9=8A=D8=A9 (</span><span dir=3D"LTR" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgro=
und-position:initial;background-size:initial;background-repeat:initial;back=
ground-origin:initial;background-clip:initial">PowerPoint</span><span dir=
=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-=
position:initial;background-size:initial;background-repeat:initial;backgrou=
nd-origin:initial;background-clip:initial"><span dir=3D"RTL"></span><span d=
ir=3D"RTL"></span>) =D9=84=D9=83=D9=84 =D8=AC=D9=84=D8=B3=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:Symbol;color:rgb(64,64,64)">=C2=B7<=
span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times =
New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D9=86=D9=85=D8=A7=D8=B0=D8=AC: =
=D8=B3=D9=8A=D8=A7=D8=B3=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=
=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D8=A9=D8=8C =D8=AC=D8=AF=D9=88=D9=84 =D8=AA=
=D8=AD=D9=84=D9=8A=D9=84
=D8=A7=D9=84=D9=81=D8=AC=D9=88=D8=A7=D8=AA=D8=8C =D8=B3=D8=AC=D9=84=D8=A7=
=D8=AA =D8=A7=D9=84=D8=AA=D8=AF=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=AF=D8=A7=
=D8=AE=D9=84=D9=8A=D8=8C =D9=82=D9=88=D8=A7=D8=A6=D9=85 =D9=85=D8=B1=D8=A7=
=D8=AC=D8=B9=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 0.5in 8pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:=
11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:1=
4pt;line-height:107%;font-family:Symbol;color:rgb(64,64,64)">=C2=B7<span st=
yle=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=
=AF=D8=B1=D8=A7=D8=B3=D9=8A=D8=A9 =D9=88=D8=A7=D9=82=D8=B9=D9=8A=D8=A9 =D9=
=88=D8=AA=D9=85=D8=A7=D8=B1=D9=8A=D9=86 =D9=85=D9=8A=D8=AF=D8=A7=D9=86=D9=
=8A=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=A9.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;margin:0in 0=
in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:11pt;fon=
t-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-=
position:initial;background-size:initial;background-repeat:initial;backgrou=
nd-origin:initial;background-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>=E2=9C=A6</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:AMoshref-Thulth;color:=
rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;colo=
r:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;line-height:107%;font-family:&quot;Times New Roman&quot;,&quot;serif&qu=
ot;;color:rgb(83,129,53);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D9=85=D9=84=D8=A7=D8=AD=D8=B8=D8=A7=D8=AA
=D8=B9=D8=A7=D9=85=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:20pt=
;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,53);backgrou=
nd-image:initial;background-position:initial;background-size:initial;backgr=
ound-repeat:initial;background-origin:initial;background-clip:initial">:</s=
pan></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 42.5pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Symbol">=C2=B7<span style=3D"font-variant-numeric:=
normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;lin=
e-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AC=D9=85=D9=8A=D8=B9
=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A7=D8=AA =D8=AA=D8=B4=D9=85=D9=84 =
=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9=D8=8C =
=D8=AD=D9=82=D9=8A=D8=A8=D8=A9 =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9=
=D8=8C =D9=88=D9=88=D8=B1=D8=B4 =D8=B9=D9=85=D9=84 =D8=AA=D9=81=D8=A7=D8=B9=
=D9=84=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 42.5pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:14pt;font-family:Symbol">=C2=B7<span style=3D"font-variant-numeric=
:normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;li=
ne-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=8A=D9=85=D9=83=D9=86
=D8=AA=D9=86=D9=81=D9=8A=D8=B0 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =
=D8=AD=D8=B6=D9=88=D8=B1=D9=8A=D9=8B=D8=A7 =D8=A3=D9=88 =D8=A3=D9=88=D9=86=
=D9=84=D8=A7=D9=8A=D9=86 =D8=B9=D8=A8=D8=B1 </span><span dir=3D"LTR" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-se=
rif&quot;">Zoom</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><sp=
an lang=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Bl=
ack&quot;,&quot;sans-serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL=
"></span>.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 42.5pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:14pt;font-family:Symbol">=C2=B7<span style=3D"font-variant-numeric:normal=
;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;line-heig=
ht:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A5=D9=85=D9=83=D8=A7=D9=86=D9=8A=D8=A9
=D8=AA=D8=AE=D8=B5=D9=8A=D8=B5 =D8=A3=D9=8A =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =
=D9=84=D8=AA=D9=83=D9=88=D9=86 =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=D8=B4=
=D8=B1=D9=83=D8=A9 (</span><span dir=3D"LTR" style=3D"font-size:14pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">In-House</span=
><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-=
serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>).</span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black=
&quot;,&quot;sans-serif&quot;"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</span><=
/p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 7.0=
5pt 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lan=
g=3D"AR-SA" style=3D"font-size:16pt;font-family:&quot;Times New Roman&quot;=
,&quot;serif&quot;">=D9=88=D8=A8=D9=87=D8=B0=D9=87 =D8=A7=D9=84=D9=85=D9=86=
=D8=A7=D8=B3=D8=A8=D8=A9 =D9=8A=D8=B3=D8=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=
=D9=88=D8=AA=D9=83=D9=85 =D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =
=D9=88=D8=AA=D8=B9=D9=85=D9=8A=D9=85 =D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =
=D8=B9=D9=84=D9=89
=D8=A7=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=
=D9=88=D8=B6=D9=80=D9=88=D8=B9 =D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9 =D9=88=D8=A5=
=D9=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=D9=86 =D8=AA=D9=82=D8=AA=
=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D8=AF=
=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span><span lang=3D"AR-SA" style=3D"f=
ont-size:16pt;font-family:AMoshref-Thulth"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;;color:rgb(192,0,0)">=D8=AE=D9=8A=D8=A7=
=D8=B1 =D8=B9=D9=85=D9=84=D9=8A =D9=86=D9=85=D9=88=D8=B0=D8=AC=D9=8A: 5 =D8=
=A3=D9=8A=D8=A7=D9=85 (40 =D8=B3=D8=A7=D8=B9=D8=A9). =D9=8A=D9=85=D9=83=D9=
=86 =D8=AA=D9=83=D9=8A=D9=8A=D9=81=D9=87=D8=A7 =D9=83=D8=A8=D8=B1=D9=86=D8=
=A7=D9=85=D8=AC =D9=85=D9=83=D8=AB=D9=81 (3
=D8=A3=D9=8A=D8=A7=D9=85) =D8=A3=D9=88 =D9=85=D9=88=D8=B3=D8=B9 (10 =D8=A3=
=D9=8A=D8=A7=D9=85) =D8=AD=D8=B3=D8=A8 =D8=A7=D8=AD=D8=AA=D9=8A=D8=A7=D8=AC=
=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A9. =D9=8A=D8=AD=D8=B5=
=D9=84 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83 =D8=B9=D9=84=D9=89: =D8=
=B4=D9=87=D8=A7=D8=AF=D8=A9 =D8=A5=D8=AA=D9=85=D8=A7=D9=85
=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9=C2=A0=C2=A0 =D8=AE=D9=84=D8=A7=D9=84 =
=D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =D9=85=D9=86 2 =D8=A7=D9=84=D9=89 6 =
=D9=86=D9=88=D9=81=D9=85=D8=A8=D8=B1
2025 </span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0in 0.0001pt;text-align:center;line-height:normal;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-se=
rif&quot;"><span style=3D"font-size:16pt;font-family:Symbol;color:white">=
=C2=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot=
;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RTL">=
</span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:&quot;AlSha=
rkTitle Black&quot;,&quot;sans-serif&quot;">=D9=84=D9=84=D8=AA=D8=B3=D8=AC=
=D9=8A=D9=84
=D8=A3=D9=88 =D9=84=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D8=B1=D8=B6 =D8=A7=
=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A =D8=A7=D9=84=D9=83=D8=A7=D9=85=
=D9=84=D8=8C =D9=8A=D8=B1=D8=AC=D9=89 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=
=D9=84 =D9=85=D8=B9=D9=86=D8=A7:</span><span dir=3D"LTR" style=3D"font-size=
:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"></=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0in 0.0001pt;text-align:center;line-height:normal;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-s=
erif&quot;"><span dir=3D"RTL"></span><span style=3D"font-size:16pt;font-fam=
ily:Symbol;color:white">=C2=A8<span style=3D"font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-stretch:normal;font-size:7pt;line-height:=
normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:&q=
uot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"><span dir=3D"RTL"></sp=
an><span dir=3D"RTL"></span>=C2=A0=C2=A0</span><span lang=3D"AR-SA" style=
=3D"font-size:20pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-se=
rif&quot;;color:rgb(192,0,0)">=D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=
=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93=D9=85=D8=AF=D9=8A=
=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span><span lang=3D"AR-SA=
" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 25.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:16pt;font-family:Symbol;color:white">=C2=A8<span style=3D"font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font=
-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=C2=A0</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 25.1pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-siz=
e:16pt;font-family:Symbol;color:white">=C2=A8<span style=3D"font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7=
pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=
=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>[=D8=B1=D9=82=D9=85
=D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81 / =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=
=A8]</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"L=
TR" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=A0=C2=A0 </span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span st=
yle=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans=
-serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0</spa=
n><span lang=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;Times New =
Roman&quot;,&quot;serif&quot;">00201069994399
-00201062992510 - 00201096841626</span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 7.1=
pt 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=
=3D"AR-SA" style=3D"font-size:16pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;">=D9=86=D8=AD=D9=86 =D9=81=D9=8A =D8=A7=D9=84=D8=AF=D8=A7=
=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=
=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9=D8=8C =
=D8=B4=D8=B1=D9=83=D8=A7=D8=A4=D9=83=D9=85 =D9=81=D9=8A =D8=A8=D9=86=D8=A7=
=D8=A1 =D8=A7=D9=84=D9=82=D8=AF=D8=B1=D8=A7=D8=AA
=D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=AA=D9=85=D9=8A=D8=B2</=
span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:AMoshref-Thul=
th">.</span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:AMoshr=
ef-Thulth"></span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKmoRrrBkppNCzzTzk5_u0eKo67zMvNa%2B%2BT09Aq0tcrgJQ%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CADj1ZKmoRrrBkppNCzzTzk5_u0eKo67zMvNa%2B%2BT09Aq0tcrgJQ%40=
mail.gmail.com</a>.<br />

--0000000000008f209b0640a3aded--
