Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBK5CUPEAMGQEXYIXB7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 0770EC2CF03
	for <lists+kasan-dev@lfdr.de>; Mon, 03 Nov 2025 16:58:37 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-429ca3e7245sf1238130f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Nov 2025 07:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762185516; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wq2RLh5NGUtnjQrsxNXQP3piZgxjnXCzXa8z9e7KdtusOmluz48MNoeHR87nf3p6sD
         JCooeQnAZuyhI1mPSdg0t0BChFx54GgtoCj8c7ikh6ar+T7R0vVkpZ7eamXajwdXbu6e
         EgVx0HexJfdz8GugkSOpaa5J/63ZOXJSG15DjWMGfD4BqgOluiCwSsFUA7oacVzHFGaB
         jd20CJk9ES0JxXCmJzHzFW1EHSXtf9KwU4owqUGjgOyucSfwMRsDEus9DK1Z/4Ky8ywM
         syCpAZf3a7NLz6nuCoQbCOTub6y2b5+XnhaLju2roEuuJ2ivrtWEeKrCEQGR/PXNsmWl
         YMxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=sh5Q0FR4CYbYA9UKXt5fU0fmb4Q7fAn3wKgSF+c0Rbs=;
        fh=ClY4bETcam53DVl++Z7Ax0m3PGibTNAjY+AA/a3REs4=;
        b=lKS0k/ylU+0dfFstNTAWc1L1TLTfkkN4BCcyalfrVDIw3zk8a82gn9Fa3n0QaMaC4F
         H9lTXdcHJphTzya8Roq/CV68JGcwmxKGMXcMcEJyE3eXSITlB1ftM+THtDxopDNS1/bC
         E1lz3yF1ruFZAzx08NMmqlTAkZiXHnr5OZsNr72ZR1n1bXR11yWtme/k2d57CNqNyoTS
         oXN7klIyL7XUqYgXenjDRuDttQQd650uqUQzzMBr6lDcE2FRh8yWEDY/X/i43OeQ6aMi
         8xyL7f48bHl46AoQThuTMAcc4tL3XYw9ZABKxIOIcGMWRPvxn6CCmn3a5oYUyh7kC3bQ
         QeWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S9J70sRf;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762185516; x=1762790316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sh5Q0FR4CYbYA9UKXt5fU0fmb4Q7fAn3wKgSF+c0Rbs=;
        b=p04BSe5bsyzDxGdiv3WwG7UeJNWWU06y9onkRulXifiIDN0z3Ym9txGqeuhdGoKSdm
         LUJE7bDA79Zgu+H/MRP7T1Yr+adL9x59z2gIZMp1eNIL2+rmDcr+251JoPyWB6vVE4AG
         8xZmTVn3/dJsBv2fvT1DljfEkyW6b1LNQbWPQwbGMvB23YgmM3PcSz2ZVGQyqjUOyGNA
         V2j/jJ54vSHv4yE8VhD/n/cpVhXbp+eGC2sYg5iP9VH3WoXtKqACy/KmfbIl5reYd7EH
         2Kw62iB486m01/lR18AsjmhaFlI/sduzmvGfkJoO6taUlsRJism/tIMW3Ve6DxIZXwy4
         6GqQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762185516; x=1762790316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=sh5Q0FR4CYbYA9UKXt5fU0fmb4Q7fAn3wKgSF+c0Rbs=;
        b=T8+/I7FxVhJB55rZj3ZfwGbNIJ7vaZH2m8r+uPaAP0P/GyvxhwyiRgmqINx9mDPHBx
         0q1nL5j0XS3l2vjz1qeeeNU+UnmswZnyQqA/o++QgwJGOxPjES1nptJNkz3ojBObCWdC
         PWSXk/d9OteCiUKcB1fEyX8pzJz/JanUBFE6Rxq9yFgWPnI5g6ANLk63bVrYq2IEoT/g
         L6PW+Y62chRkf5t4eWjz/DjN5y7TmuXqaBozAN7zMNFRgBxblFzK+4nKcHl+58h1G7Rb
         +q87kxBEwyeUQs+7XFFZiStFZ3w8+6e4lf9hsvRHLggZxPm8Ia8zebO/qhcojdQHYk6k
         pTvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762185516; x=1762790316;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sh5Q0FR4CYbYA9UKXt5fU0fmb4Q7fAn3wKgSF+c0Rbs=;
        b=nLQLS7W6LXC/TYvTuwXOKIWBV0krVZW0H4CiNwobA+Cgf3H3LTKrUwImVsLUTJ8QYj
         BekYOxwXV8abid2lO9zetrM1nE5/kJOFnDt4jgeVU+QiMASVax4l0a1iYhoUxkKwdqqQ
         4D6iQgcFKINeDCAhre4cBlitqgjUfYAn6mHQw0kr8YEt+njwoaOte6S93+5BvlD3bJCB
         dLl+egkooQbSZa+B0JSyJofhtuCVKCcdhl2gD2ebHd92RVNtUoR7PmUR2FEy/ppxFE/0
         ASvwInp5EP6xeOaZM19xuMZsRCb/xcpBQ/SzCJsHp9UqH7chcqkljsvetX+i5IcZ05Ft
         vhVQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHUQTwmuwWiLNsDZpnk8g/xVJ3CFUF9ItAYo3c910O1R9tb97qRnCDpG4R1I0T6yS7MfFPrQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx+m/L8t6Jk5zYEUsmYKSdNwkSMPgHjJcfMazSp495D5yw8dfyN
	0CBF0CPEPqMpV4crQ5x95mQtl/ZmpmC/ed7HwE3VffrEGHPwL5dUfzhN
X-Google-Smtp-Source: AGHT+IE4JLiUDaI73uMTWkDy0Ni62NEBW3qF7Xtf/V2if6H20ffUeHQK7Z3FtWP0yDtE+LazCfztfg==
X-Received: by 2002:a05:6000:4210:b0:429:d215:ca34 with SMTP id ffacd0b85a97d-429d215ce2fmr3745487f8f.18.1762185515998;
        Mon, 03 Nov 2025 07:58:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZYJs4aDtsfw3vxNDLw9qCXWyyg+4lU63wj3yKFiubCyQ=="
Received: by 2002:a05:6000:290c:b0:426:cb20:6c35 with SMTP id
 ffacd0b85a97d-429b4d9375als2905961f8f.0.-pod-prod-06-eu; Mon, 03 Nov 2025
 07:58:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVpJfjAqaLXUnz/Tz/4SAMnzQvqWwsWeJ8wSfzZZro1jPI0owVR5HTqba4A6NuH1lEqV5zo+h7L2WE=@googlegroups.com
X-Received: by 2002:a05:6000:4210:b0:429:d215:ca34 with SMTP id ffacd0b85a97d-429d215ce2fmr3745370f8f.18.1762185513150;
        Mon, 03 Nov 2025 07:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762185513; cv=none;
        d=google.com; s=arc-20240605;
        b=cl9ITKlr7PyhkNeemUkk8aP1/Lbk6v85IaHBii1WuAO4JRZVC2PED5Y3GPlXyJMDnE
         PG8FxTGk2oVgMpEEqy/xZZfEVvsThZLU9G89pbj8NiaOBKyAh/RLgW7qCBrwN0Y0ezWy
         bBTYtTXLRQ9YpN1gPIZbaCt6koYO7HijpP+5U/Fe2iTTBDLfrKtaNoa/cqg2G7yL+DUZ
         7YY1ZoGXI7Ay3qKp91bIJQcAj74GrZ8FRmx1Uig6FoPHpmACK7uLEsxQ5JgY3fqKLuTd
         JXZ0pbWMWm+p6yft08ZCBcQpyMba2fZvzWJWvJnenvf3f1bySPETWJApu7MVwBymyXWw
         Hd1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=JZcv3zYAmrobbpQgmF1FHKMFmajLZRYgnmGws98fPFk=;
        fh=/ZI5jPelNmIoZIOkVV4XK+G1+0sSGnREkMkViVPCO5I=;
        b=Hg4LJ7r6+/HuDHxZAA4X4CctLG3j+GeCLhf3TeNr1NYDhpgraFsqGjUQOf7J+MqU2E
         pwiF0J0ei6mRbTqriO++udY0a1kTuLXObPhPORTBZvXXRwUSn4RvMzu6uVmFj2T9Vl/8
         yKYe4JX+bhq82X9AdHPGo+UYk/EDo32IjclSYI0McGi2XdOwonXXlnmNfJSTg8fsMKRV
         KYxfdROXTD21si+bIg83jGJ2x9gjna/dXfSFXqQdu2bWeEOpK8tP8yk2BjKPC3W5Ufwt
         Zonkl9pH4CIlHCJTpz79+5usZCnfK5CSHK5itAg1azlwXi4HLm1q2yv7hkZvw7RAnlQb
         /vmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S9J70sRf;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429c94184c0si163007f8f.3.2025.11.03.07.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Nov 2025 07:58:33 -0800 (PST)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id a640c23a62f3a-b4f323cf89bso43063266b.2
        for <kasan-dev@googlegroups.com>; Mon, 03 Nov 2025 07:58:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWxr7nBTY+LyBFBsFq8BgDhtTs1WFWEzpJpZgdV/EIy9GtMptRmSW1sgku+deO0vi6QMOtsqfy+2MU=@googlegroups.com
X-Gm-Gg: ASbGncsfvXVYZ3ZTH1MrRWqRhk/wA9le/gq7iMICZGfYs5otNyPhmMvo6ZPtQpC234K
	jgnTOQNLAcEFNKEn3xUtDF9h9sMbtdiHP8U5Rb7Bb/60eQtJZukePsiKVJxwMpXNoGIdinW6eIR
	dmMFflHAUF3xJ3ZpgbzAL69kOcjwXZreWM6Tue8HJ2tUoT4fmf1qXYfSlqPJ2O+2h+KrKWYzhWy
	Cl1LU7q4lqYjFUGuYGfbCqcF9sJ/1lQtfLg4FNWJqc+nHYpa2NzOBdF3ZCbQEdrvYlTtuUklOTM
	p/k=
X-Received: by 2002:a17:907:60c9:b0:b70:b077:b949 with SMTP id
 a640c23a62f3a-b70b077bc32mr497391566b.37.1762185512124; Mon, 03 Nov 2025
 07:58:32 -0800 (PST)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Mon, 3 Nov 2025 19:04:45 +0200
X-Gm-Features: AWmQ_bmgX-gbhZa2gvh0d6GXzZQ_FspwXZjAv5zrOZX9t2sUE6WJX6yPVFhYShw
Message-ID: <CADj1ZKn00wbEWmVhjT0VuEsAMh6FoPZcmMUPrq9d+XAUkw3RZg@mail.gmail.com>
Subject: =?UTF-8?B?2K/ZiNix2KkgItin2YTYpdmB2LXYp9itINmB2Yog2K3ZiNmD2YXYqSDYp9mE2LTYsdmD?=
	=?UTF-8?B?2KfYqiIg2YXZhiA5INil2YTZiSAxMyDZhtmI2YHZhdio2LEgMjAyNdmFINin2YTZgtin2YfYsdipIA==?=
	=?UTF-8?B?4oCTINis2YXZh9mI2LHZitipINmF2LXYsSDYp9mE2LnYsdio2YrYqSDYp9mE2K/Yp9ixINin2YTYudix?=
	=?UTF-8?B?2KjZitipINmE2YTYqtmG2YXZitipINin2YTYpdiv2KfYsdmK2Kkg4oCTIEFIQUQg2LTZh9in2K/YqSA=?=
	=?UTF-8?B?2YXZh9mG2YrYqSDZhdi52KrZhdiv2Kkg4oCTINmF2YjYq9mC2Kkg2YjYqNin2LnYqtmF2KfYryDYr9mI?=
	=?UTF-8?B?2YTZiiDZhdi52KrYsdmBINio2YfYpyDZgdmKINmD2KfZgdipINin2YTYr9mI2YQg2YXYuSDYp9iq2Kc=?=
	=?UTF-8?B?2K3YqSDYp9mE2K/Ysdin2LPYqSDYp9mI2YYg2YTYp9mK2YYg2KrYudiw2LEg2KfZhNit2LbZiNixINin?=
	=?UTF-8?B?2YTZh9iv2YEg2KfZhNi52KfZhSDZhNmE2K/ZiNix2Kk6INiq2LnYsdmK2YEg2KfZhNmF2LTYp9ix2YM=?=
	=?UTF-8?B?2YrZhiDYqNin2YTZhdmB2KfZh9mK2YUg2KfZhNij2LPYp9iz2YrYqSDZhNmE2KXZgdi12KfYrSDZiNin?=
	=?UTF-8?B?2YTYtNmB2KfZgdmK2Kkg2YHZiiDYrdmI2YPZhdipINin2YTYtNix2YPYp9iq2Iwg2YjYqtmF2YPZitmG?=
	=?UTF-8?B?2YfZhSDZhdmGINiq2LfYqNmK2YIg2KPZgdi22YQg2KfZhNmF2YXYp9ix2LPYp9iqINin2YTYr9mI2YQ=?=
	=?UTF-8?B?2YrYqSDZhNi22YXYp9mGINin2YTZhtiy2KfZh9ipINmI2KfZhNmF2LPYp9ih2YTYqSDZiNiq2LnYstmK?=
	=?UTF-8?B?2LIg2KfZhNir2YLYqSDYqNmK2YYg2KPYtdit2KfYqCDYp9mE2YXYtdmE2K3YqS4g2KfZhNmF2K3Yp9mI?=
	=?UTF-8?B?2LEg2KfZhNiq2K/YsdmK2KjZitipOiDCtyDYp9mE2YXZgdin2YfZitmFINin2YTYrdiv2YrYq9ipINmE?=
	=?UTF-8?B?2K3ZiNmD2YXYqSDYp9mE2LTYsdmD2KfYqiDZiNij2YfYr9in2YHZh9inLiDCtyDZhdio2KfYr9imINin?=
	=?UTF-8?B?2YTYpdmB2LXYp9itINmI2KfZhNi02YHYp9mB2YrYqSDZgdmKINin2YTYqtmC2KfYsdmK2LEg2KfZhNmF?=
	=?UTF-8?B?2KfZhNmK2Kk=?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000007a93dc0642b2c913"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=S9J70sRf;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62c
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

--0000000000007a93dc0642b2c913
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

Ktiv2YjYsdipICLYp9mE2KXZgdi12KfYrSDZgdmKINit2YjZg9mF2Kkg2KfZhNi02LHZg9in2Koq
KiIqDQoNCg0KDQoq2YXZhiA5INil2YTZiSAxMyDZhtmI2YHZhdio2LEgMjAyNdmFKg0KDQoq2KfZ
hNmC2KfZh9ix2Kkg4oCTINis2YXZh9mI2LHZitipINmF2LXYsSDYp9mE2LnYsdio2YrYqSoNCg0K
Ktin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNil2K/Yp9ix2YrY
qSDigJMgKipBSEFEKg0KDQoNCg0K2LTZh9in2K/YqSDZhdmH2YbZitipINmF2LnYqtmF2K/YqSDi
gJMg2YXZiNir2YLYqSDZiNio2KfYudiq2YXYp9ivINiv2YjZhNmKINmF2LnYqtix2YEg2KjZh9in
DQoNCiDZgdmKINmD2KfZgdipINin2YTYr9mI2YQNCg0KDQoNCtmF2Lkg2KfYqtin2K3YqSDYp9mE
2K/Ysdin2LPYqSDYp9mI2YYg2YTYp9mK2YYg2KrYudiw2LEg2KfZhNit2LbZiNixDQoNCg0KDQoq
2KfZhNmH2K/ZgSDYp9mE2LnYp9mFINmE2YTYr9mI2LHYqSoqOioNCg0K2KrYudix2YrZgSDYp9mE
2YXYtNin2LHZg9mK2YYg2KjYp9mE2YXZgdin2YfZitmFINin2YTYo9iz2KfYs9mK2Kkg2YTZhNil
2YHYtdin2K0g2YjYp9mE2LTZgdin2YHZitipINmB2Yog2K3ZiNmD2YXYqQ0KDQrYp9mE2LTYsdmD
2KfYqtiMINmI2KrZhdmD2YrZhtmH2YUg2YXZhiDYqti32KjZitmCINij2YHYttmEINin2YTZhdmF
2KfYsdiz2KfYqiDYp9mE2K/ZiNmE2YrYqSDZhNi22YXYp9mGINin2YTZhtiy2KfZh9ipDQoNCtmI
2KfZhNmF2LPYp9ih2YTYqSDZiNiq2LnYstmK2LIg2KfZhNir2YLYqSDYqNmK2YYg2KPYtdit2KfY
qCDYp9mE2YXYtdmE2K3YqS4NCg0KDQoNCirYp9mE2YXYrdin2YjYsSDYp9mE2KrYr9ix2YrYqNmK
2KkqKjoqDQoNCsK3ICAgICAgICAg2KfZhNmF2YHYp9mH2YrZhSDYp9mE2K3Yr9mK2KvYqSDZhNit
2YjZg9mF2Kkg2KfZhNi02LHZg9in2Kog2YjYo9mH2K/Yp9mB2YfYpy4NCg0KwrcgICAgICAgICDZ
hdio2KfYr9imINin2YTYpdmB2LXYp9itINmI2KfZhNi02YHYp9mB2YrYqSDZgdmKINin2YTYqtmC
2KfYsdmK2LEg2KfZhNmF2KfZhNmK2Kkg2YjYutmK2LEg2KfZhNmF2KfZhNmK2KkuDQoNCsK3ICAg
ICAgICAg2YXYs9ik2YjZhNmK2KfYqiDZhdis2YTYsyDYp9mE2KXYr9in2LHYqSDZiNin2YTYpdiv
2KfYsdipINin2YTYqtmG2YHZitiw2YrYqSDZgdmKINin2YTYpdmB2LXYp9itLg0KDQrCtyAgICAg
ICAgINiv2YjYsSDYp9mE2YXYsdin2KzYudipINin2YTYr9in2K7ZhNmK2Kkg2YHZiiDYttmF2KfZ
hiDYp9mE2KXZgdi12KfYrSDYp9mE2LPZhNmK2YUuDQoNCsK3ICAgICAgICAg2KfZhNil2YHYtdin
2K0g2YHZiiDYo9iz2YjYp9mCINin2YTZhdin2YQg2YjYp9mE2LTYsdmD2KfYqiDYp9mE2YXYr9ix
2KzYqS4NCg0KwrcgICAgICAgICDYp9mE2YXYudin2YrZitixINin2YTYr9mI2YTZitipINiw2KfY
qiDYp9mE2LnZhNin2YLYqSAoT0VDRCDigJMgSUZDIOKAkyBDT1NPKS4NCg0KwrcgICAgICAgICDY
r9ix2KfYs9in2Kog2K3Yp9mE2Kkg2KrYt9io2YrZgtmK2Kkg2K3ZiNmEINmF2YXYp9ix2LPYp9iq
INin2YTYpdmB2LXYp9itINin2YTYrNmK2K8uDQoNCg0KDQoq2KfZhNmB2KbYqSDYp9mE2YXYs9iq
2YfYr9mB2KkqKjoqDQoNCsK3ICAgICAgICAg2KPYudi22KfYoSDZhdis2KfZhNizINin2YTYpdiv
2KfYsdipINmI2KPZhdmG2KfYoSDYp9mE2LPYsS4NCg0KwrcgICAgICAgICDZhdiv2LHYp9ihINin
2YTYrdmI2YPZhdipINmI2KfZhNmF2LHYp9is2LnYqSDYp9mE2K/Yp9iu2YTZitipLg0KDQrCtyAg
ICAgICAgINmF2LPYpNmI2YTZiCDYp9mE2KXZgdi12KfYrSDZiNin2YTYudmE2KfZgtin2Kog2YXY
uSDYp9mE2YXYs9in2YfZhdmK2YYuDQoNCsK3ICAgICAgICAg2KfZhNmF2K/Ysdin2KEg2KfZhNmF
2KfZhNmK2YjZhiDZiNin2YTZhdiz2KrYtNin2LHZiNmGINin2YTZgtin2YbZiNmG2YrZiNmGLg0K
DQrCtyAgICAgICAgINin2YTZgtmK2KfYr9in2Kog2KfZhNiq2YbZgdmK2LDZitipINmB2Yog2KfZ
hNi02LHZg9in2Kog2KfZhNmC2KfYqNi22Kkg2YjYp9mE2YXYs9in2YfZhdipLg0KDQoNCg0KDQoN
CirYp9mE2KfYudiq2YXYp9ivINmI2KfZhNi02YfYp9iv2KkqKjoqDQoNCti02YfYp9iv2Kkg2YXZ
h9mG2YrYqSDZhdi52KrZhdiv2Kkg2YXZhiAq2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE
2KrZhtmF2YrYqSDYp9mE2KXYr9in2LHZitipKg0KDQoNCtmI2YHZgiDYo9it2K/YqyDZhdi52KfZ
itmK2LEg2KfZhNiq2K/YsdmK2Kgg2YHZiiDZhdis2KfZhCDYp9mE2K3ZiNmD2YXYqSDZiNin2YTY
pdiv2KfYsdipINin2YTYsdi02YrYr9ipDQoNCi4NCg0KKtmE2YTYqtiz2KzZitmEINmI2KfZhNin
2LPYqtmB2LPYp9ixKio6Kg0KDQrYoy8g2LPYp9ix2Kkg2LnYqNivINin2YTYrNmI2KfYryDigJMg
2YXYr9mK2LEg2KfZhNiq2K/YsdmK2KgNCg0KDQogMDAyMDEwNjk5OTQzOTkg4oCTIDAwMjAxMDYy
OTkyNTEwIOKAkw0KDQogMDAyMDEwOTY4NDE2MjYNCg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1l
c3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImth
c2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCBy
ZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vi
c2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0
dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FEajFaS24wMHdiRVdt
VmhqVDBWdUVzQU1oNkZvUFpjbU1VUHJxOWQlMkJYQVVrdzNSWmclNDBtYWlsLmdtYWlsLmNvbS4K
--0000000000007a93dc0642b2c913
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:center;background-=
image:initial;background-position:initial;background-size:initial;backgroun=
d-repeat:initial;background-origin:initial;background-clip:initial;directio=
n:rtl;unicode-bidi:embed;line-height:16.8667px;font-size:11pt;font-family:C=
alibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;font-family:Arial,&quot;sans-serif&quot;">=D8=AF=D9=88=D8=B1=D8=A9 &quo=
t;=D8=A7=D9=84=D8=A5=D9=81=D8=B5=D8=A7=D8=AD =D9=81=D9=8A =D8=AD=D9=88=D9=
=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=AA</span></b><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"f=
ont-size:20pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>&quot;</sp=
an></b><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" dir=3D"RTL" s=
tyle=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;line-height:11.75pt;backg=
round-image:initial;background-position:initial;background-size:initial;bac=
kground-repeat:initial;background-origin:initial;background-clip:initial;di=
rection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;san=
s-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=A0</span><sp=
an lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center" dir=3D=
"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:center;=
background-image:initial;background-position:initial;background-size:initia=
l;background-repeat:initial;background-origin:initial;background-clip:initi=
al;direction:rtl;unicode-bidi:embed;line-height:16.8667px;font-size:11pt;fo=
nt-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-SA" style=3D"=
font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D9=85=D9=86 9 =D8=
=A5=D9=84=D9=89 13 =D9=86=D9=88=D9=81=D9=85=D8=A8=D8=B1 2025=D9=85</span></=
b><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center" d=
ir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:ce=
nter;background-image:initial;background-position:initial;background-size:i=
nitial;background-repeat:initial;background-origin:initial;background-clip:=
initial;direction:rtl;unicode-bidi:embed;line-height:16.8667px;font-size:11=
pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=82=D8=A7=D9=87=D8=B1=D8=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=
=8A=D8=A9 =D9=85=D8=B5=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</sp=
an></b><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"cent=
er" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-ali=
gn:center;background-image:initial;background-position:initial;background-s=
ize:initial;background-repeat:initial;background-origin:initial;background-=
clip:initial;direction:rtl;unicode-bidi:embed;line-height:16.8667px;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-SA"=
 style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=
=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=
=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=
=D9=8A=D8=A9 =E2=80=93=C2=A0</span></b><b><span dir=3D"LTR" style=3D"font-s=
ize:20pt">AHAD</span></b><span lang=3D"AR-SA"></span></p><p class=3D"MsoNor=
mal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0i=
n 0in 8pt;text-align:center;line-height:11.75pt;background-image:initial;ba=
ckground-position:initial;background-size:initial;background-repeat:initial=
;background-origin:initial;background-clip:initial;direction:rtl;unicode-bi=
di:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span l=
ang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;,&quot;serif&=
quot;">=C2=A0</span><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" =
align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in=
 8pt;text-align:center;background-image:initial;background-position:initial=
;background-size:initial;background-repeat:initial;background-origin:initia=
l;background-clip:initial;direction:rtl;unicode-bidi:embed;line-height:16.8=
667px;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=
=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;=
">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D9=87=D9=86=D9=8A=D8=A9 =D9=85=D8=
=B9=D8=AA=D9=85=D8=AF=D8=A9 =E2=80=93 =D9=85=D9=88=D8=AB=D9=82=D8=A9 =D9=88=
=D8=A8=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=D8=AF =D8=AF=D9=88=D9=84=D9=8A</span><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D=
"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=A0</=
span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;s=
ans-serif&quot;">=D9=85=D8=B9=D8=AA=D8=B1=D9=81 =D8=A8=D9=87=D8=A7</span></=
p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0=
,0,0,0.87);margin:0in 0in 8pt;text-align:center;background-image:initial;ba=
ckground-position:initial;background-size:initial;background-repeat:initial=
;background-origin:initial;background-clip:initial;direction:rtl;unicode-bi=
di:embed;line-height:16.8667px;font-size:11pt;font-family:Calibri,&quot;san=
s-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Ari=
al,&quot;sans-serif&quot;">=C2=A0=D9=81=D9=8A =D9=83=D8=A7=D9=81=D8=A9 =D8=
=A7=D9=84=D8=AF=D9=88=D9=84</span><span lang=3D"AR-SA"></span></p><p class=
=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87)=
;margin:0in 0in 8pt;text-align:center;line-height:11.75pt;background-image:=
initial;background-position:initial;background-size:initial;background-repe=
at:initial;background-origin:initial;background-clip:initial;direction:rtl;=
unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot=
;"><span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span><span lang=3D"AR-SA"></span></p><p class=3D"M=
soNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);marg=
in:0in 0in 8pt;text-align:center;background-image:initial;background-positi=
on:initial;background-size:initial;background-repeat:initial;background-ori=
gin:initial;background-clip:initial;direction:rtl;unicode-bidi:embed;line-h=
eight:16.8667px;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;">=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D9=85=D8=B9 =D8=A7=D8=AA=D8=A7=D8=AD=D8=A9 =D8=A7=D9=84=D8=AF=
=D8=B1=D8=A7=D8=B3=D8=A9 =D8=A7=D9=88=D9=86 =D9=84=D8=A7=D9=8A=D9=86 =D8=AA=
=D8=B9=D8=B0=D8=B1 =D8=A7=D9=84=D8=AD=D8=B6=D9=88=D8=B1</span><span lang=3D=
"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" styl=
e=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:center;line-heigh=
t:13.8pt;background-image:initial;background-position:initial;background-si=
ze:initial;background-repeat:initial;background-origin:initial;background-c=
lip:initial;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Cal=
ibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:12pt;f=
ont-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=C2=A0</span><spa=
n lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center" dir=3D"=
RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:center;b=
ackground-image:initial;background-position:initial;background-size:initial=
;background-repeat:initial;background-origin:initial;background-clip:initia=
l;direction:rtl;unicode-bidi:embed;line-height:16.8667px;font-size:11pt;fon=
t-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-SA" style=3D"f=
ont-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D9=87=
=D8=AF=D9=81 =D8=A7=D9=84=D8=B9=D8=A7=D9=85 =D9=84=D9=84=D8=AF=D9=88=D8=B1=
=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span=
 dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D=
"LTR"></span>:</span></b><span lang=3D"AR-SA"></span></p><p class=3D"MsoNor=
mal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0i=
n 0in 8pt;text-align:center;background-image:initial;background-position:in=
itial;background-size:initial;background-repeat:initial;background-origin:i=
nitial;background-clip:initial;direction:rtl;unicode-bidi:embed;line-height=
:16.8667px;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span=
 lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&=
quot;">=D8=AA=D8=B9=D8=B1=D9=8A=D9=81 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=
=D9=83=D9=8A=D9=86 =D8=A8=D8=A7=D9=84=D9=85=D9=81=D8=A7=D9=87=D9=8A=D9=85 =
=D8=A7=D9=84=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D9=84=D9=84=D8=A5=D9=81=
=D8=B5=D8=A7=D8=AD =D9=88=D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =
=D9=81=D9=8A =D8=AD=D9=88=D9=83=D9=85=D8=A9</span><span lang=3D"AR-SA"></sp=
an></p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:r=
gba(0,0,0,0.87);margin:0in 0in 8pt;text-align:center;background-image:initi=
al;background-position:initial;background-size:initial;background-repeat:in=
itial;background-origin:initial;background-clip:initial;direction:rtl;unico=
de-bidi:embed;line-height:16.8667px;font-size:11pt;font-family:Calibri,&quo=
t;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:20pt;font-famil=
y:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=AA=
=D8=8C =D9=88=D8=AA=D9=85=D9=83=D9=8A=D9=86=D9=87=D9=85 =D9=85=D9=86 =D8=AA=
=D8=B7=D8=A8=D9=8A=D9=82 =D8=A3=D9=81=D8=B6=D9=84 =D8=A7=D9=84=D9=85=D9=85=
=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =
=D9=84=D8=B6=D9=85=D8=A7=D9=86 =D8=A7=D9=84=D9=86=D8=B2=D8=A7=D9=87=D8=A9</=
span><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center=
" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align=
:center;background-image:initial;background-position:initial;background-siz=
e:initial;background-repeat:initial;background-origin:initial;background-cl=
ip:initial;direction:rtl;unicode-bidi:embed;line-height:16.8667px;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D9=88=D8=A7=
=D9=84=D9=85=D8=B3=D8=A7=D8=A1=D9=84=D8=A9 =D9=88=D8=AA=D8=B9=D8=B2=D9=8A=
=D8=B2 =D8=A7=D9=84=D8=AB=D9=82=D8=A9 =D8=A8=D9=8A=D9=86 =D8=A3=D8=B5=D8=AD=
=D8=A7=D8=A8 =D8=A7=D9=84=D9=85=D8=B5=D9=84=D8=AD=D8=A9</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:2=
0pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span><span lang=
=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" s=
tyle=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:center;line-he=
ight:13.8pt;background-image:initial;background-position:initial;background=
-size:initial;background-repeat:initial;background-origin:initial;backgroun=
d-clip:initial;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:12p=
t;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=C2=A0</span><=
span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center" dir=
=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:cent=
er;background-image:initial;background-position:initial;background-size:ini=
tial;background-repeat:initial;background-origin:initial;background-clip:in=
itial;direction:rtl;unicode-bidi:embed;line-height:16.8667px;font-size:11pt=
;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=85=D8=AD=D8=A7=D9=88=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=
=D9=8A=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b=
><span dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"></span><span =
dir=3D"LTR"></span>:</span></b><span lang=3D"AR-SA"></span></p><p class=3D"=
MsoNormal" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 1in 8pt 0=
in;line-height:11.75pt;background-image:initial;background-position:initial=
;background-size:initial;background-repeat:initial;background-origin:initia=
l;background-clip:initial;direction:rtl;unicode-bidi:embed;font-size:11pt;f=
ont-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:10pt;font-family:Sym=
bol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=B7</span><span d=
ir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:7pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><spa=
n dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D9=85=D9=81=D8=
=A7=D9=87=D9=8A=D9=85 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9 =D9=84=D8=
=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=AA =D9=
=88=D8=A3=D9=87=D8=AF=D8=A7=D9=81=D9=87=D8=A7</span><span dir=3D"LTR"></spa=
n><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt"><span=
 dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA"><=
/span></p><p class=3D"MsoNormal" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87=
);margin:0in 1in 8pt 0in;line-height:11.75pt;background-image:initial;backg=
round-position:initial;background-size:initial;background-repeat:initial;ba=
ckground-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:10pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lan=
g=3D"AR-SA" style=3D"font-size:7pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span lang=3D"AR-SA"=
 style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D9=85=
=D8=A8=D8=A7=D8=AF=D8=A6 =D8=A7=D9=84=D8=A5=D9=81=D8=B5=D8=A7=D8=AD =D9=88=
=D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=
=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=
=D8=A9 =D9=88=D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9<=
/span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" s=
tyle=3D"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.=
</span><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" dir=3D"RTL" s=
tyle=3D"color:rgba(0,0,0,0.87);margin:0in 1in 8pt 0in;line-height:11.75pt;b=
ackground-image:initial;background-position:initial;background-size:initial=
;background-repeat:initial;background-origin:initial;background-clip:initia=
l;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot=
;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:10pt;font-family:Symbol"><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span>=C2=B7</span><span dir=3D"RTL"></span><span =
dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:7pt;font-family:=
&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span><sp=
an dir=3D"RTL"></span>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&q=
uot;sans-serif&quot;">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=8A=D8=A7=D8=AA =D9=
=85=D8=AC=D9=84=D8=B3 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D9=88=D8=
=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=
=8A=D8=B0=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D9=81=D8=B5=D8=A7=D8=
=AD</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LT=
R" style=3D"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an>.</span><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" dir=3D"RT=
L" style=3D"color:rgba(0,0,0,0.87);margin:0in 1in 8pt 0in;line-height:11.75=
pt;background-image:initial;background-position:initial;background-size:ini=
tial;background-repeat:initial;background-origin:initial;background-clip:in=
itial;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&=
quot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><s=
pan dir=3D"LTR" style=3D"font-size:10pt;font-family:Symbol"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>=C2=B7</span><span dir=3D"RTL"></span><s=
pan dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:7pt;font-fam=
ily:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span=
><span dir=3D"RTL"></span>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial=
,&quot;sans-serif&quot;">=D8=AF=D9=88=D8=B1 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=
=D8=AC=D8=B9=D8=A9 =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A=D8=A9 =D9=81=
=D9=8A =D8=B6=D9=85=D8=A7=D9=86 =D8=A7=D9=84=D8=A5=D9=81=D8=B5=D8=A7=D8=AD =
=D8=A7=D9=84=D8=B3=D9=84=D9=8A=D9=85</span><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"L=
TR"></span><span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA"></span></p=
><p class=3D"MsoNormal" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:=
0in 1in 8pt 0in;line-height:11.75pt;background-image:initial;background-pos=
ition:initial;background-size:initial;background-repeat:initial;background-=
origin:initial;background-clip:initial;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:10pt;fo=
nt-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=B7<=
/span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA=
" style=3D"font-size:7pt;font-family:&quot;Times New Roman&quot;,&quot;seri=
f&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span lang=3D"AR-SA" style=3D=
"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=
=A5=D9=81=D8=B5=D8=A7=D8=AD =D9=81=D9=8A =D8=A3=D8=B3=D9=88=D8=A7=D9=82 =D8=
=A7=D9=84=D9=85=D8=A7=D9=84 =D9=88=D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=
=AA =D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=AC=D8=A9</span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt"><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA">=
</span></p><p class=3D"MsoNormal" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.8=
7);margin:0in 1in 8pt 0in;line-height:11.75pt;background-image:initial;back=
ground-position:initial;background-size:initial;background-repeat:initial;b=
ackground-origin:initial;background-clip:initial;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:10pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lan=
g=3D"AR-SA" style=3D"font-size:7pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span lang=3D"AR-SA"=
 style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=
=D9=84=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D8=AF=D9=88=D9=84=
=D9=8A=D8=A9 =D8=B0=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=82=D8=A9<=
/span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" s=
tyle=3D"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
=C2=A0(OECD =E2=80=93 IFC =E2=80=93 COSO).</span><span lang=3D"AR-SA"></spa=
n></p><p class=3D"MsoNormal" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);ma=
rgin:0in 1in 8pt 0in;line-height:11.75pt;background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:embe=
d;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"L=
TR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:10=
pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=
=3D"AR-SA" style=3D"font-size:7pt;font-family:&quot;Times New Roman&quot;,&=
quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span lang=3D"AR-SA"=
 style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=AF=
=D8=B1=D8=A7=D8=B3=D8=A7=D8=AA =D8=AD=D8=A7=D9=84=D8=A9 =D8=AA=D8=B7=D8=A8=
=D9=8A=D9=82=D9=8A=D8=A9 =D8=AD=D9=88=D9=84 =D9=85=D9=85=D8=A7=D8=B1=D8=B3=
=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D9=81=D8=B5=D8=A7=D8=AD =D8=A7=D9=84=D8=AC=
=D9=8A=D8=AF</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span>.</span><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" =
align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in=
 8pt;text-align:center;line-height:13.8pt;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D=
"AR-SA" style=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=C2=A0</span><span lang=3D"AR-SA"></span></p><p class=3D"Ms=
oNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margi=
n:0in 0in 8pt;text-align:center;background-image:initial;background-positio=
n:initial;background-size:initial;background-repeat:initial;background-orig=
in:initial;background-clip:initial;direction:rtl;unicode-bidi:embed;line-he=
ight:16.8667px;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><=
b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans=
-serif&quot;">=D8=A7=D9=84=D9=81=D8=A6=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=
=D9=87=D8=AF=D9=81=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span><b><span dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span>:</span></b><span lang=3D"AR-SA"></span></p>=
<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0=
,0,0.87);margin:0in 1in 8pt 0in;text-align:center;line-height:11.75pt;backg=
round-image:initial;background-position:initial;background-size:initial;bac=
kground-repeat:initial;background-origin:initial;background-clip:initial;di=
rection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;san=
s-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:10pt;font-family:Symbol"><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span>=C2=B7</span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:7pt;font-family:&qu=
ot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span><span =
dir=3D"RTL"></span>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</=
span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;s=
ans-serif&quot;">=D8=A3=D8=B9=D8=B6=D8=A7=D8=A1 =D9=85=D8=AC=D8=A7=D9=84=D8=
=B3 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D9=88=D8=A3=D9=85=D9=86=D8=
=A7=D8=A1 =D8=A7=D9=84=D8=B3=D8=B1</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA"></span></p><=
p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,=
0,0.87);margin:0in 1in 8pt 0in;text-align:center;line-height:11.75pt;backgr=
ound-image:initial;background-position:initial;background-size:initial;back=
ground-repeat:initial;background-origin:initial;background-clip:initial;dir=
ection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:10pt;font-family:Symbol"><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span>=C2=B7</span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:7pt;font-family:&qu=
ot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span><span =
dir=3D"RTL"></span>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</=
span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;s=
ans-serif&quot;">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=88=D9=
=83=D9=85=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =D8=
=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></spa=
n><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt"><span=
 dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA"><=
/span></p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"colo=
r:rgba(0,0,0,0.87);margin:0in 1in 8pt 0in;text-align:center;line-height:11.=
75pt;background-image:initial;background-position:initial;background-size:i=
nitial;background-repeat:initial;background-origin:initial;background-clip:=
initial;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri=
,&quot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:10pt;font-family:Symbol"><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span>=C2=B7</span><span dir=3D"RTL"></span>=
<span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:7pt;font-f=
amily:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL"></sp=
an><span dir=3D"RTL"></span>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Ar=
ial,&quot;sans-serif&quot;">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88 =D8=A7=D9=
=84=D8=A5=D9=81=D8=B5=D8=A7=D8=AD =D9=88=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=
=82=D8=A7=D8=AA =D9=85=D8=B9 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D9=87=D9=85=D9=
=8A=D9=86</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span>.</span><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" ali=
gn=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 1in 8p=
t 0in;text-align:center;line-height:11.75pt;background-image:initial;backgr=
ound-position:initial;background-size:initial;background-repeat:initial;bac=
kground-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:10pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lan=
g=3D"AR-SA" style=3D"font-size:7pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span lang=3D"AR-SA"=
 style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=
=D9=84=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=
=D9=88=D9=86 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D9=88=
=D9=86 =D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=D9=8A=D9=88=D9=86</span><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D=
"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span>=
<span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center" dir=
=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 1in 8pt 0in;text-align:=
center;line-height:11.75pt;background-image:initial;background-position:ini=
tial;background-size:initial;background-repeat:initial;background-origin:in=
itial;background-clip:initial;direction:rtl;unicode-bidi:embed;font-size:11=
pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:10pt;font-family=
:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=B7</span><sp=
an dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=
=3D"font-size:7pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;=
"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span lang=3D"AR-SA" style=3D"font-=
size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D9=82=D9=
=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=
=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=AA =D8=A7=D9=
=84=D9=82=D8=A7=D8=A8=D8=B6=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D9=
=87=D9=85=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span>.</span><span lang=3D"AR-SA"></span></p><p class=3D"MsoNorm=
al" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in=
 0in 8pt;text-align:center;line-height:13.8pt;background-image:initial;back=
ground-position:initial;background-size:initial;background-repeat:initial;b=
ackground-origin:initial;background-clip:initial;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lan=
g=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Times New Roman&quot;=
,&quot;serif&quot;">=C2=A0</span><span style=3D"font-family:&quot;Times New=
 Roman&quot;,&quot;serif&quot;;font-size:11pt">=C2=A0</span></p><p class=3D=
"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);ma=
rgin:0in 1in 8pt 0in;text-align:center;line-height:11.75pt;background-image=
:initial;background-position:initial;background-size:initial;background-rep=
eat:initial;background-origin:initial;background-clip:initial;direction:rtl=
;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quo=
t;"><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center"=
 dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:=
center;line-height:13.8pt;background-image:initial;background-position:init=
ial;background-size:initial;background-repeat:initial;background-origin:ini=
tial;background-clip:initial;direction:rtl;unicode-bidi:embed;font-size:11p=
t;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D=
"font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=C2=A0</span><s=
pan lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=3D"center" dir=
=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:cent=
er;background-image:initial;background-position:initial;background-size:ini=
tial;background-repeat:initial;background-origin:initial;background-clip:in=
itial;direction:rtl;unicode-bidi:embed;line-height:16.8667px;font-size:11pt=
;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=D8=AF =D9=88=D8=A7=D9=84=D8=B4=D9=87=D8=A7=
=D8=AF=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b=
><span dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"></span><span =
dir=3D"LTR"></span>:</span></b><span lang=3D"AR-SA"></span></p><p class=3D"=
MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);mar=
gin:0in 0in 8pt;text-align:center;background-image:initial;background-posit=
ion:initial;background-size:initial;background-repeat:initial;background-or=
igin:initial;background-clip:initial;direction:rtl;unicode-bidi:embed;line-=
height:16.8667px;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"=
><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-=
serif&quot;">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D9=87=D9=86=D9=8A=D8=A9 =
=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D9=85=D9=86=C2=A0<b>=D8=A7=D9=84=D8=
=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=
=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=
=A9</b></span><span lang=3D"AR-SA"></span></p><p class=3D"MsoNormal" align=
=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;=
text-align:center;background-image:initial;background-position:initial;back=
ground-size:initial;background-repeat:initial;background-origin:initial;bac=
kground-clip:initial;direction:rtl;unicode-bidi:embed;line-height:16.8667px=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LT=
R" style=3D"font-size:20pt"><br></span><span lang=3D"AR-SA" style=3D"font-s=
ize:20pt;font-family:Arial,&quot;sans-serif&quot;">=D9=88=D9=81=D9=82 =D8=
=A3=D8=AD=D8=AF=D8=AB =D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D8=
=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D9=81=D9=8A =D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=
=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=
=B1=D8=A9 =D8=A7=D9=84=D8=B1=D8=B4=D9=8A=D8=AF=D8=A9</span><span lang=3D"AR=
-SA"></span></p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"color:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:center;background-=
image:initial;background-position:initial;background-size:initial;backgroun=
d-repeat:initial;background-origin:initial;background-clip:initial;directio=
n:rtl;unicode-bidi:embed;line-height:16.8667px;font-size:11pt;font-family:C=
alibri,&quot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span><span dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA"></span></p><p class=3D=
"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0,0,0,0.87);ma=
rgin:0in 0in 8pt;text-align:center;background-image:initial;background-posi=
tion:initial;background-size:initial;background-repeat:initial;background-o=
rigin:initial;background-clip:initial;direction:rtl;unicode-bidi:embed;line=
-height:16.8667px;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;=
"><a name=3D"m_-860455844158246116_m_-8831958232040714215_m_-45380670140517=
" rel=3D"nofollow" style=3D"color:rgb(26,115,232)"></a><b><span lang=3D"AR-=
SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&quot;">=D9=
=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=
=AA=D9=81=D8=B3=D8=A7=D8=B1</span></b><span dir=3D"LTR"></span><span dir=3D=
"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span>:</span></b><span lang=3D"AR-SA"></span><=
/p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(=
0,0,0,0.87);margin:0in 0in 8pt;text-align:center;background-image:initial;b=
ackground-position:initial;background-size:initial;background-repeat:initia=
l;background-origin:initial;background-clip:initial;direction:rtl;unicode-b=
idi:embed;line-height:16.8667px;font-size:11pt;font-family:Calibri,&quot;sa=
ns-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Ar=
ial,&quot;sans-serif&quot;">=D8=A3/ =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=
=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93 =D9=85=D8=AF=D9=8A=D8=
=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span><span lang=3D"AR-SA"><=
/span></p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"colo=
r:rgba(0,0,0,0.87);margin:0in 0in 8pt;text-align:center;background-image:in=
itial;background-position:initial;background-size:initial;background-repeat=
:initial;background-origin:initial;background-clip:initial;direction:rtl;un=
icode-bidi:embed;line-height:16.8667px;font-size:11pt;font-family:Calibri,&=
quot;sans-serif&quot;"><span dir=3D"LTR" style=3D"font-size:20pt;font-famil=
y:Arial,&quot;sans-serif&quot;"><br></span><span dir=3D"LTR" style=3D"font-=
size:20pt">=C2=A000201069994399 =E2=80=93 00201062992510 =E2=80=93</span></=
p><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"color:rgba(0=
,0,0,0.87);margin:0in 0in 8pt;text-align:center;background-image:initial;ba=
ckground-position:initial;background-size:initial;background-repeat:initial=
;background-origin:initial;background-clip:initial;direction:rtl;unicode-bi=
di:embed;line-height:16.8667px;font-size:11pt;font-family:Calibri,&quot;san=
s-serif&quot;"><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A000201096841=
626</span><span lang=3D"AR-SA" style=3D"font-family:Arial,&quot;sans-serif&=
quot;"></span></p><br class=3D"gmail-Apple-interchange-newline"></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKn00wbEWmVhjT0VuEsAMh6FoPZcmMUPrq9d%2BXAUkw3RZg%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CADj1ZKn00wbEWmVhjT0VuEsAMh6FoPZcmMUPrq9d%2BXAUkw3RZg%40mail=
.gmail.com</a>.<br />

--0000000000007a93dc0642b2c913--
