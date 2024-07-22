Return-Path: <kasan-dev+bncBCM7RVHKQ4PRBBOV7C2AMGQEXHFC5OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 42227938C59
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 11:46:47 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-26117e75eb0sf2679839fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 02:46:47 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721641606; x=1722246406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=1kaDgboqML1rOG5c6NSD6HdZcydxSVZ42Pw5HaniUaQ=;
        b=rbfyzBOy7A+Nbtgcpgo4VxfJpJTq890rUpjwrdjVHbLLi3pBa3ZIDlFGux6pHPyD0b
         sI9EODtoD/WejjtIYRvl7KmuhYph3D+g+kc03nSWbP+j3iXx9XxgJSkEMCxQaCSPIJzL
         UMY18GMP7unKHzpA8Fy5e1aeCJ5b41xynst72bPBcMt/Mdz1IF1KDJNQNFfrikd01cGq
         3Hz0YvkVJdb9QIeUfAHuvSpMzyOqs1Df9fY1YZOjUyOhJWc7u1bNOZP+TQG7UfHFHhAw
         6LC1WBGJV3GOm/TdvrGLnqFebZJbCyWi94j1RK9ifWBSIMykgMsT//lsMU5m1IdEz8QI
         GCQQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721641606; x=1722246406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1kaDgboqML1rOG5c6NSD6HdZcydxSVZ42Pw5HaniUaQ=;
        b=nRn3qSeT7JU1bFvd9GAw38KXTHKuWPXffGNCaWLmCnAfwhIvJdvurqe2HzedHrtoQh
         f6OY9aT9nNNe/ocaeATjaxBLpq7emBBZsa2vfmcRIdkdC/ctGXaMKB69ec9m5/pYvLz9
         o1wYIrHNS8dWNI5p2H4i/73h3Rk+TwU4czcSmkpHXq0Am74li7Ielo1dMZQTLuj4sYQe
         Vu9NWe83NohVCyvsl/f80abbxzo2o7qVKZc9W/RVfNltQZXy0LU2NoL61wrL7ncx0csy
         YMPTRLdl1+CIJkEDOK+f6dvfrUgXomNBkQzsbhV+MdcmZeaiCd8pSPONBrrVdOzm0Ifk
         wlKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721641606; x=1722246406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=1kaDgboqML1rOG5c6NSD6HdZcydxSVZ42Pw5HaniUaQ=;
        b=d0pR2a2azOuEkOMdRhiOUVoYu0ThLoJ7AOcrbjMGvQ/fzHptjc5kY6IV7BljSwYvth
         xhHdCfqO9BVJSWBK3FBy4brd75NVRb+m09J1QXbZrPEgsUkrnmRJJoKRAjzVXH3oU/fc
         gCXOMo2BNWAiGye2iQ4RqFEOuEQ+VC0CcPJpe126HQPlKoyDM0Q+xOR2s/zRB4WDTZ2m
         w88nQvX0JCJ7CSbuTy6D334i5hnJHQc2ada4/7ZJFxgiU3Xhj2Y2eRnKlKy2KhJHeYhz
         /TXH0ZekbqVz4nIbw3Be2CEM90vp/LaTBDME6697vjjFB6503owe/Vp5M42BoGkNcOmQ
         dx2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCUcLotyzf8LBhPYg01Tcemx9paHToepe/vH1Tg5VC96PHqpX7oqRQW+ajhzkkL6ITCPWvVoiJLuOcJrBXc3Qk0bedwga8frOw==
X-Gm-Message-State: AOJu0Yx7oVqpI6JZ2GnhYOWmc6MK8u/4XlqwDfFF2ncY5ZM3jVuydlY0
	FFyedtXXltF4yj61wfV6ZquzNdd428OMo/ZGWbSf5xnyGHho9y+e
X-Google-Smtp-Source: AGHT+IHFbkexbJmhgdSlXyIoMPGctLXY5+cooYg/XbBAnc+6Rl2Lbarwdim4kO+WtHLHHjWBc4Bw+w==
X-Received: by 2002:a05:6870:3329:b0:25e:86b:59ec with SMTP id 586e51a60fabf-26121095699mr7093289fac.0.1721641606017;
        Mon, 22 Jul 2024 02:46:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:3a8e:b0:25e:8e6:12bf with SMTP id
 586e51a60fabf-260ec4e66dels2984044fac.2.-pod-prod-07-us; Mon, 22 Jul 2024
 02:46:45 -0700 (PDT)
X-Received: by 2002:a05:6870:f116:b0:25e:b4a:6250 with SMTP id 586e51a60fabf-261212eb04bmr193406fac.1.1721641604742;
        Mon, 22 Jul 2024 02:46:44 -0700 (PDT)
Date: Mon, 22 Jul 2024 02:46:44 -0700 (PDT)
From: Adham Ahmad <adam.ahmad0980@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <a5b117b7-ca0c-4d12-b9df-91031aac2610n@googlegroups.com>
In-Reply-To: <73082b2a-09c0-46e2-a78b-30c98cb1ae6en@googlegroups.com>
References: <73082b2a-09c0-46e2-a78b-30c98cb1ae6en@googlegroups.com>
Subject: =?UTF-8?B?UmU6INit2KjZiNioINiz2KfZitiq2YjYqtmK2YMgKCDYrdio2Yg=?=
 =?UTF-8?B?2Kgg2KfZhNin2KzZh9in2LYgLWN5dG90ZWMpINmB2Yog2Kc=?=
 =?UTF-8?B?2YTYsdmK2KfYtiDYrNiv2Kkg2KfZhNiz2LnZiNiv2YrZhyAwMDk2Ng==?=
 =?UTF-8?B?NTgxNzg0MTA2INit2KjZiNioINiz2KfZitiq2YjYqtmDLdin?=
 =?UTF-8?B?2YTYp9i12YTZitmHICjYrNix2LnZhyDZhdmK2LLZiNio2LHYs9iq2YjZhA==?=
 =?UTF-8?B?INmE2YTYp9is2YfYp9i22J8pINiq2YjYtdmK2YQg2LPYsdmK2Ll82KjYsw==?=
 =?UTF-8?B?2LHZitipINiq2KfZhdipINin2YTYr9mB2Lkg2LnZhtivINin2YTYp9iz2Ko=?=
 =?UTF-8?B?2YTYp9mFINmK2K8g2KjZitivINin2YTYqtiz2YTZitmFINmE2YTYqNmK2Lk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_763888_45403171.1721641604032"
X-Original-Sender: adam.ahmad0980@gmail.com
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

------=_Part_763888_45403171.1721641604032
Content-Type: multipart/alternative; 
	boundary="----=_Part_763889_589821206.1721641604032"

------=_Part_763889_589821206.1721641604032
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

CgogCgogCgoq2KPZiCDYp9iq2LXZhCDYqNmG2Kcg2KfZhNii2YYg2LnZhNmJINin2YTYsdmC2YUg
MDA5NjY1ODE3ODQxMDYgINmI2KfYrdi12YQg2LnZhNmJINin2YTZhdiz2KfYudiv2Kkg2KfZhNiq
2Yog2KrYrdiq2KfYrNmH2KcqCiouKgoKKtit2KfYs9io2Kkg2KfZhNit2YXZhCDZiCDYp9mE2YjZ
hNin2K/YqSDZiNis2YbYsyDYp9mE2KzZhtmK2YYqKjoqCgoq2K3Yp9iz2KjYqSDYp9mE2K3ZhdmE
INmI2KfZhNmI2YTYp9iv2Kkg2YfZiiDYo9iv2KfYqSDZhdmB2YrYr9ipINiq2LPYqtiu2K/ZhSDZ
hNiq2YLYr9mK2LEg2KrYp9ix2YrYriDYp9mE2YjZhNin2K/YqSDYp9mE2YXYqtmI2YLYudipIArZ
iNmF2LnYsdmB2Kkg2KzZhtizINin2YTYrNmG2YrZhi4g2KrYudiq2YXYryDZh9iw2Ycg2KfZhNit
2KfYs9io2Kkg2LnZhNmJINiq2YjYp9ix2YrYriDYp9mE2K/ZiNix2Kkg2KfZhNi02YfYsdmK2Kkg
2KfZhNiz2KfYqNmC2Kkg2YjZhdiv2KkgCtin2YTYrdmF2YQg2KfZhNmF2LnYqtin2K/YqS4g2KrY
s9in2LnYryDZh9iw2Ycg2KfZhNit2KfYs9io2Kkg2KfZhNmG2LPYp9ihINin2YTZhdiu2LfYt9in
2Kog2YTZhNit2YXZhCDYudmE2Ykg2KrYrdiv2YrYryDYp9mE2YHYqtix2KkgCtin2YTYqtmKINmK
2YXZg9mGINiq2YjZgti5INit2K/ZiNirINin2YTZiNmE2KfYr9ipINmB2YrZh9in2Iwg2YjZh9mK
INmF2YHZitiv2Kkg2KPZiti22YvYpyDZhNij2YjZhNim2YMg2KfZhNiw2YrZhiDZitix2LrYqNmI
2YYg2YHZiiAK2YXYudix2YHYqSDYrNmG2LMg2KfZhNis2YbZitmGINmB2Yog2YXYsdit2YTYqSDZ
hdio2YPYsdipINmF2YYg2KfZhNit2YXZhCoqLioKCirYo9iv2YjZitipINil2KzZh9in2LYg2KfZ
hNit2YXZhCoqIGN5dG90ZWMgKirYs9in2YrYqtmI2KrZgyAyMDAg2YHZiiDYudmE2Yog2KfZg9iz
2KjYsdmK2LMg2KfZhdin2LLZiNmGKiogVEwgCjAwOTY2NTgxNzg0MTA2ICAqCgoq2KPYr9mI2YrY
qSDYp9is2YfYp9i2INin2YTYrdmF2YQg2LPYp9mK2KrZiNiq2YrZgyAyMDAg2K3YqNmI2Kgg2LPY
p9mK2KrZiNiq2YMqKiAtKgoKKtiz2KfZitiq2YjYqtmK2YMg2YHZiiDYp9mE2LPYudmI2K/ZitmH
KgoKKtiz2KfZitiq2YjYqtmDINis2K/YqSoqLioKCirYp9is2YfYp9i2INin2YTYrdmF2YQg2YHZ
iiDYp9mE2LPYudmI2K/ZitmHKgoKKtin2KzZh9in2LYg2YHZiiDYp9mE2KXYs9mE2KfZhSoKCirY
t9ix2YrZgtmHINin2KzZh9in2LYg2KfZhNit2YXZhCoKCirYpdis2YfYp9i2INin2YTYt9mB2YQq
Cgoq2LfYsdmK2YLYqSDYp9mE2K3ZhdmEINio2KjZhtiqINmF2KzYsdio2YcqCgoq2LfYsdmK2YLY
qSDYp9mE2K3ZhdmEINio2KjZhtiqKgoKKti32LHZitmC2Kkg2KfZhNit2YXZhCDYqNiq2YjYo9mF
KgoKKtmD2YrZgdmK2Kkg2KfYrNmH2KfYtiDYrNmG2YrZhiDYudmF2LEg2LTZh9ix2YrZhioKCirZ
g9mK2YHZitipINin2YTYrdmF2YQg2KjYs9ix2LnYqSoKCirYp9mE2KXYrNmH2KfYtiDYp9mE2YXY
qNmD2LEqCgoq2KfYudix2KfYtiDYp9is2YfYp9i2INin2YTYrdmF2YQg2YHZiiDYp9mE2LTZh9ix
INin2YTYp9mI2YQqCgoq2LfYsdmK2YLYqSDYp9mE2K3ZhdmEINin2YTYs9ix2YrYuSDYqNi52K8g
2KfZhNiv2YjYsdipKgoKKti32LHZitmC2Kkg2YTZhNit2YXZhCDYp9mE2LPYsdmK2LkqCgoq2LfY
sdmK2YLYqSDYp9iu2KrYqNin2LEg2KfZhNit2YXZhCDYp9mE2YXZhtiy2YTZiioKCirYt9ix2YrZ
gtipINin2YTYrdmF2YQg2KjYqtmI2KPZhSDZhdis2LHYqNipKgoKKtmD2YrZgSDZitit2K/YqyDY
p9mE2KfYrNmH2KfYtiDZgdmKINin2YTYtNmH2LEg2KfZhNir2KfZhtmKKgoKKtin2LPYsdi5INi3
2LHZgiDZhNmE2K3ZhdmEINio2LnYryDYp9mE2KXYrNmH2KfYtioKCirYp9i52LHYp9i2INin2KzZ
h9in2LYg2KfZhNit2YXZhCDZgdmKINin2YTYtNmH2LEg2KfZhNin2YjZhCoKCirYqNiv2KfZitip
INin2YTYtNmH2LEg2KfZhNir2KfZhNirINmF2YYg2KfZhNit2YXZhCoKCirYp9mE2K3ZhdmEINmB
2Yog2KfZhNi02YfYsSDYp9mE2KvYp9mE2KsqCgoq2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZ
iiDYp9mE2LPYudmI2K/ZitmHKgoKKtmI2YrZhiDYp9mE2KfZgtmKINit2KjZiNioINiz2KfZitiq
2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrZhyoKCirYs9i52LEg2K3YqNmI2Kgg2LPYp9mK2KrZ
iNiq2YMg2YHZiiDYp9mE2LPYudmI2K/ZitmHKgoKKtit2KjZiNioINiz2KfZitiq2YjYqtmDINin
2YTYp9i12YTZitmHKgoKKtit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTYqNmK2LkqCgoq2K3Y
qNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/ZitmHKiogLSBDeXRvdGVjIHBp
bGxzIGluIFNhdWRpIEFyYWJpYSAtICoq2KrZitmE2YrYrNix2KfZhSAK2LnZhNmJINin2YTYsdmC
2YUgMDA5NjY1ODE3ODQxMDYqICrYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i5
2YjYr9mK2YcqCgoq2YjZitmGINin2YTYp9mD2Yog2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZ
iiDYp9mE2LPYudmI2K/ZitmHKgoKKtiz2LnYsSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZgdmK
INin2YTYs9i52YjYr9mK2YcqCgoq2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNin2LXZhNmK
2YcqCgoq2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSoKCirYrdio2YjYqCDYs9in
2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2YcgLSDYrdio2YjYqCDYs9in2YrYqtmI2KrZ
gyDZgdmKINin2YTYs9i52YjYr9mK2KkgLSDYqtmK2YTZitis2LHYp9mFINi52YTZiSDYp9mE2LHZ
gtmFIAowMDk2NjU4MTc4NDEwNioKCgoKKtmE2LDZhNmDINiz2KfZitiq2YjYqtmDINmE2YTYp9is
2YfYp9i2KgoKKtit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2KrZhti42YrZgSDYp9mE2LHYrdmF
KgoKKtit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTYr9mB2Lkg2LnZhtivINin2YTYp9iz2KrZ
hNin2YUqCgoq2LPYudixINit2KjZiNioINiz2KfZitiq2YjYqtmDKgoKKtiz2KfZitiq2YjYqtmD
INmE2KrZhtiy2YrZhCDYp9mE2K/ZiNix2KkqCgoq2LPYp9mK2KrZiNiq2YMgMjAwKgoKKtiz2KfZ
itiq2YjYqtmDINmB2Yog2KrYsdmD2YrYpyoKCirYs9i52LEg2K/ZiNin2KEg2LPYp9mK2KrZiNiq
2YMqCgoq2LPYp9mK2KrZiNiq2YMg2LPYp9mK2KrZiNiq2YMqCgoq2LPYp9mK2KrZiNiq2YMg2LPY
p9mK2KrZiNiq2YMg2K3YqNmI2Kgg2KfZhNil2KzZh9in2LYqCgoq2LPYp9mK2KrZiNiq2YMgMjAw
INiz2LnYsSoKCirYs9i52LEg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMgMjAyMioKCirYs9i52LEg
2LPYp9mK2KrZiNiq2YMg2YHZiiDZhdi12LEgMjAyMCoKCio3INit2KjYp9iqINiz2KfZitiq2YjY
qtmDKgoKCgoq2YjZhNmH2Kcg2YXZitiy2YjYqtin2YMgMjAwINil2KzZh9in2LYqCgoq2LPYudix
INmF2YrYstmI2KrYp9mDINin2KzZh9in2LYqCgoq2KjYr9mK2YQg2K3YqNmI2Kgg2LPYp9mK2KrZ
iNiq2YMqCgoq2KjYr9mK2YQg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMqCgoqItit2KjZiNioINin
2KzZh9in2LYg2KfZhNit2YXZhCIqCgoqItin2YTYp9is2YfYp9i2INio2K3YqNmI2Kgg2YXZhti5
INin2YTYrdmF2YQiKgoKKti32LHZitmC2Kkg2LPYp9mK2KrZiNiq2YrZgyDZhNmE2LnZhNin2Kwq
Cgoq2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZitmGINiq2KjYp9i5KgoKKtiz2LnYsSDZhdmK
2LLZiNiq2KfZgyAyMDIwICoKCirZg9mK2YHZitipINin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YMg
2KfZhNin2KzZh9in2LYg2YHZiiDYp9mE2LTZh9ixINin2YTYq9in2YbZiiAqCgoq2KPYrdi22LEg
2LPYp9mK2KrZiNiq2YrZgyDYp9is2YfYp9ivICoKCirZhdmK2LLZiNiq2KfZgyDYr9in2YrZhdmI
2YbYryDZgdmKINin2YTYtNmH2LEg2KfZhNin2YjZhCAqCgoq2LPYudixINi02LHZiti3INmF2YrY
stmI2KrYp9mDINin2YTYo9i12YTZiioKCirZhdiq2Ykg2YrYqNiv2KMg2KfZhNil2KzZh9in2LYg
2KjYudivINij2K7YsCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyAqCgoq2YfZhCDYrdio2YjYqCDY
s9in2YrYqtmDINmE2YfYpyDYo9i22LHYp9ixICoKCirYt9ix2YrZgtipINin2LPYqtiu2K/Yp9mF
INit2KjZiNioINmF2YrYstmI2KrYp9mDINmE2YTYp9is2YfYp9i2INmB2Yog2KfZhNi02YfYsSDY
p9mE2KPZiNmEICoKCirZhdin2YfZiCDYr9mI2KfYoSDYqNmI2KrZitmDICoKCirYrdio2YjYqCDY
s9in2YrYqtmI2KrZitmDINin2YTYp9is2YfYp9ivKgoKKti32LHZitmC2Kkg2KfYrtiwINit2KjZ
iNioINiz2KfZitiq2YjYqtmDKgoKKtin2YTYp9is2YfYp9i2KgoKKti02LHYp9ihINiz2KfZitiq
2YjYqtmDKgoKKti32LHZitmC2Kkg2LPYp9mK2KrZiNiq2YrZgyDZhNmE2LnZhNin2KwqCgoq2K3Y
qNmI2Kgg2KfYrNmH2KfYryDYs9in2YrYqtmI2KrZgyoKCirYudmE2KfYrCDYs9in2YrYqtmI2KrZ
gyAqCgoq2KfZhNii2KvYp9ixINin2YTYrNin2YbYqNmK2KkuKgoKKti02YPZhCDYrdio2YjYqCDY
s9in2YrYqtmI2KrZgyDYp9mE2KfYtdmE2YrZhyAqCgoq2K/ZiNin2KEg2KfYrNmH2KfYtioKCioi
2KfYrNmH2KfYtiDYrdmF2YQg2K7Yp9ix2Kwg2KfZhNix2K3ZhSIqCgoq2K3YqNmI2Kgg2KrYs9mC
2Lcg2KfZhNit2YXZhCDZhNmE2KjZiti5KgoKKtit2KjZiNioINin2YTYp9is2YfYp9i2INmB2Yog
2LXZitiv2YTZitin2KoqCgoq2KjYr9mK2YQg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMqCgoq2LfY
sdmK2YLYqSDYp9iz2KrYrtiv2KfZhSDYrdio2YjYqCDYs9in2YrYqtmDINin2YTYpdis2YfYp9i2
INmB2Yog2KfZhNi02YfYsSDYp9mE2KPZiNmEKgoKKtit2KjZiNioINiz2KfZitiq2YjYqtmK2YMg
2LfYsdmK2YLYqSDYp9iz2KrYrtiv2KfZhSoKCirYqNix2LTYp9mFINiz2KfZitiq2YjYqtmDINmE
2YTYp9is2YfYp9i2ICoKCirZhdiq2Ykg2YrYqNiv2Kcg2YXZgdi52YjZhCDYrdio2YjYqCDYp9mF
2YrYstmI2KrYp9mDICoKCirYqtis2LHYqNiq2Yog2YXYuSDYrdio2YjYqCDYs9in2YrYqtmI2KrZ
gyDZgdiq2YPYp9iqICoKCirYt9ix2YrZgtipINin2K7YsCDYrdio2YjYqCDYs9in2YrYqtmI2KrZ
gyAqCgoq2LPYudixINmF2YrYstmI2KrYp9mDINin2YTYo9i12YTZiiAyMDIxICoKCirYp9mC2LHY
oyDYtdmI2KrZgyoKCirYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INiz2LnYsSDYrdio2YjYqCDY
s9in2YrYqtmI2KrZgyAqCgoq2LPYudixINit2KjZiNioINiz2KfZitiq2YjYqtmDINmB2Yog2KfZ
hNmG2YfYr9mKICoKCirYrdiq2Ykg2YXZitiy2YjYqtin2YMgKgoKKtit2KjZiNioINin2YTZhdi5
2K/ZhyDYs9in2YrYqtmDICoKCirYr9mI2KfYoSDZhdmK2LLZiNiq2KfZgyAqCgoq2YrZhNinINmK
2LfZhNmCINin2YTZhtin2LEqCgoq2YbZhdi02Yog4oCTINmG2YXYtNmKKgoKKtin2YPYs9iq2LHY
pyDigJMg2KfYttin2YHZitipKgoKIAoKIAoKLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2Ug
YmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRl
diIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZp
bmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJl
QGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlz
aXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9hNWIxMTdiNy1j
YTBjLTRkMTItYjlkZi05MTAzMWFhYzI2MTBuJTQwZ29vZ2xlZ3JvdXBzLmNvbS4K
------=_Part_763889_589821206.1721641604032
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=C2=A0</span></b></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=C2=A0</span></b></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A3=D9=88 =D8=A7=D8=AA=D8=B5=D9=84 =D8=A8=D9=86=D8=A7 =
=D8=A7=D9=84=D8=A2=D9=86 =D8=B9=D9=84=D9=89
=D8=A7=D9=84=D8=B1=D9=82=D9=85 00966581784106 =C2=A0=D9=88=D8=A7=D8=AD=D8=
=B5=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B9=D8=AF=D8=
=A9 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=AD=D8=AA=D8=A7=D8=AC=D9=87=D8=A7</sp=
an></b><span dir=3D"LTR"></span><b><span style=3D"font-size: 13.5pt; font-f=
amily: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"><span di=
r=3D"LTR"></span>.</span></b><span style=3D"font-size: 10.5pt; font-family:=
 Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D9=88 =D8=A7=D9=84=D9=88=D9=84=D8=A7=D8=AF=D8=A9
=D9=88=D8=AC=D9=86=D8=B3 =D8=A7=D9=84=D8=AC=D9=86=D9=8A=D9=86</span></b><sp=
an dir=3D"LTR"></span><b><span style=3D"font-size: 13.5pt; font-family: Hel=
vetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"><span dir=3D"LTR">=
</span>:</span></b><span style=3D"font-size: 10.5pt; font-family: Helvetica=
, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D9=88=D8=A7=D9=84=D9=88=D9=84=D8=A7=D8=AF=D8=A9
=D9=87=D9=8A =D8=A3=D8=AF=D8=A7=D8=A9 =D9=85=D9=81=D9=8A=D8=AF=D8=A9 =D8=AA=
=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D9=84=D8=AA=D9=82=D8=AF=D9=8A=D8=B1 =D8=AA=
=D8=A7=D8=B1=D9=8A=D8=AE =D8=A7=D9=84=D9=88=D9=84=D8=A7=D8=AF=D8=A9 =D8=A7=
=D9=84=D9=85=D8=AA=D9=88=D9=82=D8=B9=D8=A9 =D9=88=D9=85=D8=B9=D8=B1=D9=81=
=D8=A9 =D8=AC=D9=86=D8=B3 =D8=A7=D9=84=D8=AC=D9=86=D9=8A=D9=86. =D8=AA=D8=
=B9=D8=AA=D9=85=D8=AF =D9=87=D8=B0=D9=87
=D8=A7=D9=84=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9 =D8=B9=D9=84=D9=89 =D8=AA=D9=88=
=D8=A7=D8=B1=D9=8A=D8=AE =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=
=D8=B4=D9=87=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D8=B3=D8=A7=D8=A8=D9=82=D8=A9 =
=D9=88=D9=85=D8=AF=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=
=D8=B9=D8=AA=D8=A7=D8=AF=D8=A9. =D8=AA=D8=B3=D8=A7=D8=B9=D8=AF =D9=87=D8=B0=
=D9=87
=D8=A7=D9=84=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9 =D8=A7=D9=84=D9=86=D8=B3=D8=A7=
=D8=A1 =D8=A7=D9=84=D9=85=D8=AE=D8=B7=D8=B7=D8=A7=D8=AA =D9=84=D9=84=D8=AD=
=D9=85=D9=84 =D8=B9=D9=84=D9=89 =D8=AA=D8=AD=D8=AF=D9=8A=D8=AF =D8=A7=D9=84=
=D9=81=D8=AA=D8=B1=D8=A9 =D8=A7=D9=84=D8=AA=D9=8A =D9=8A=D9=85=D9=83=D9=86 =
=D8=AA=D9=88=D9=82=D8=B9 =D8=AD=D8=AF=D9=88=D8=AB =D8=A7=D9=84=D9=88=D9=84=
=D8=A7=D8=AF=D8=A9
=D9=81=D9=8A=D9=87=D8=A7=D8=8C =D9=88=D9=87=D9=8A =D9=85=D9=81=D9=8A=D8=AF=
=D8=A9 =D8=A3=D9=8A=D8=B6=D9=8B=D8=A7 =D9=84=D8=A3=D9=88=D9=84=D8=A6=D9=83 =
=D8=A7=D9=84=D8=B0=D9=8A=D9=86 =D9=8A=D8=B1=D8=BA=D8=A8=D9=88=D9=86 =D9=81=
=D9=8A =D9=85=D8=B9=D8=B1=D9=81=D8=A9 =D8=AC=D9=86=D8=B3 =D8=A7=D9=84=D8=AC=
=D9=86=D9=8A=D9=86 =D9=81=D9=8A =D9=85=D8=B1=D8=AD=D9=84=D8=A9 =D9=85=D8=A8=
=D9=83=D8=B1=D8=A9 =D9=85=D9=86
=D8=A7=D9=84=D8=AD=D9=85=D9=84</span></b><span dir=3D"LTR"></span><b><span =
style=3D"font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;;=
 color: rgb(51, 51, 51);"><span dir=3D"LTR"></span>.</span></b><span style=
=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; colo=
r: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A5=D8=AC=D9=87=D8=A7=D8=
=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84</span></b><span dir=3D"LTR"></span><b><s=
pan style=3D"font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&qu=
ot;; color: rgb(51, 51, 51);"><span dir=3D"LTR"></span>
cytotec </span></b><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"font-size: =
13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, =
51);">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200 =D9=81=D9=8A =D8=B9=D9=
=84=D9=8A =D8=A7=D9=83=D8=B3=D8=A8=D8=B1=D9=8A=D8=B3 =D8=A7=D9=85=D8=A7=D8=
=B2=D9=88=D9=86</span></b><span dir=3D"LTR"></span><b><span style=3D"font-s=
ize: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51,=
 51, 51);"><span dir=3D"LTR"></span> TL 00966581784106 =C2=A0</span></b><sp=
an style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quo=
t;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 200 =D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></b><span dir=3D"LTR">=
</span><b><span style=3D"font-size: 13.5pt; font-family: Helvetica, &quot;s=
ans-serif&quot;; color: rgb(51, 51, 51);"><span dir=3D"LTR"></span> -</span=
></b><span style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-s=
erif&quot;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 36pt; font-family: Helvetica, &quot;sans-serif&quot;; color: red=
;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></b><span style=3D"font-size:=
 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;;"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=
=A9</span></b><span dir=3D"LTR"></span><b><span style=3D"font-size: 13.5pt;=
 font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"><=
span dir=3D"LTR"></span>.</span></b><span style=3D"font-size: 10.5pt; font-=
family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></span>=
</p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D9=81=D9=8A
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></b><span style=3D"f=
ont-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rg=
b(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=
=D8=A5=D8=B3=D9=84=D8=A7=D9=85</span></b><span style=3D"font-size: 10.5pt; =
font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></=
span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B7=D8=B1=D9=8A=D9=82=D9=87 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84</span></b><span style=3D"font-size: 10.5=
pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);=
"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=D9=81=D9=
=84</span></b><span style=3D"font-size: 10.5pt; font-family: Helvetica, &qu=
ot;sans-serif&quot;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D8=A8=D8=A8=D9=86=D8=AA =D9=85=D8=AC=D8=B1=D8=A8=D9=87</span></b><span=
 style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;=
; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D8=A8=D8=A8=D9=86=D8=AA</span></b><span style=3D"font-size: 10.5pt; fo=
nt-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></sp=
an></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D8=A8=D8=AA=D9=88=D8=A3=D9=85</span></b><span style=3D"font-size: 10.5=
pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);=
"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D8=AC=D9=86=D9=8A=D9=86 =D8=B9=D9=85=D8=B1
=D8=B4=D9=87=D8=B1=D9=8A=D9=86</span></b><span style=3D"font-size: 10.5pt; =
font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></=
span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D8=A8=D8=B3=D8=B1=D8=B9=D8=A9</span></b><span style=3D"font-size: 10.5=
pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);=
"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D9=
=85=D8=A8=D9=83=D8=B1</span></b><span style=3D"font-size: 10.5pt; font-fami=
ly: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A7=D8=B9=D8=B1=D8=A7=D8=B6 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D9=81=D9=8A
=D8=A7=D9=84=D8=B4=D9=87=D8=B1 =D8=A7=D9=84=D8=A7=D9=88=D9=84</span></b><sp=
an style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quo=
t;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=D8=B9 =D8=A8=D8=B9=D8=AF
=D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9</span></b><span style=3D"font-size: 10=
.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51=
);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D9=84=D9=84=D8=AD=D9=85=D9=
=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=D8=B9</span></b><span style=3D"font-size=
: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51=
, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D8=AE=D8=AA=D8=A8=D8=
=A7=D8=B1 =D8=A7=D9=84=D8=AD=D9=85=D9=84
=D8=A7=D9=84=D9=85=D9=86=D8=B2=D9=84=D9=8A</span></b><span style=3D"font-si=
ze: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, =
51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D8=A8=D8=AA=D9=88=D8=A3=D9=85
=D9=85=D8=AC=D8=B1=D8=A8=D8=A9</span></b><span style=3D"font-size: 10.5pt; =
font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></=
span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D9=83=D9=8A=D9=81 =D9=8A=D8=AD=D8=AF=D8=AB =D8=A7=D9=84=
=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A
=D8=A7=D9=84=D8=B4=D9=87=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A</span><=
/b><span style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-ser=
if&quot;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A7=D8=B3=D8=B1=D8=B9 =D8=B7=D8=B1=D9=82 =D9=84=D9=84=
=D8=AD=D9=85=D9=84 =D8=A8=D8=B9=D8=AF
=D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6</span></b><span style=3D"font-si=
ze: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, =
51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A7=D8=B9=D8=B1=D8=A7=D8=B6 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D9=81=D9=8A
=D8=A7=D9=84=D8=B4=D9=87=D8=B1 =D8=A7=D9=84=D8=A7=D9=88=D9=84</span></b><sp=
an style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quo=
t;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A8=D8=AF=D8=A7=D9=8A=D8=A9 =D8=A7=D9=84=D8=B4=D9=87=D8=
=B1 =D8=A7=D9=84=D8=AB=D8=A7=D9=84=D8=AB =D9=85=D9=86
=D8=A7=D9=84=D8=AD=D9=85=D9=84</span></b><span style=3D"font-size: 10.5pt; =
font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51, 51);"></=
span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=A7=D9=84=D8=AD=D9=85=D9=84 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B4=D9=87=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=D9=84=D8=AB</span></b><span sty=
le=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; co=
lor: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=81=D9=8A
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></b><span style=3D"f=
ont-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rg=
b(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D9=88=D9=8A=D9=86 =D8=A7=D9=84=D8=A7=D9=82=D9=8A =D8=AD=
=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83
=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></b><sp=
an style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quo=
t;; color: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></b><span style=3D"f=
ont-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rg=
b(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D8=A7=D9=84=D8=A7=D8=B5=D9=84=D9=8A=D9=87</span></b><span style=
=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; colo=
r: rgb(51, 51, 51);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 7.5pt; line-height: normal; directio=
n: ltr; unicode-bidi: embed;"><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"=
font-size: 13.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: r=
gb(51, 51, 51);">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=84=D9=84=D8=A8=D9=8A=D8=B9</span></b><span style=3D"font-size=
: 10.5pt; font-family: Helvetica, &quot;sans-serif&quot;; color: rgb(51, 51=
, 51);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 18pt; font-family: Helvetica, &quot;sans-serif&quot;; color: red;">=D8=AD=
=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></b><span dir=3D"LTR=
"></span><b><span dir=3D"LTR" style=3D"font-size: 18pt; font-family: Helvet=
ica, &quot;sans-serif&quot;; color: red;"><span dir=3D"LTR"></span> -
Cytotec pills in Saudi Arabia - </span></b><b><span lang=3D"AR-SA" style=3D=
"font-size: 18pt; font-family: Helvetica, &quot;sans-serif&quot;; color: re=
d;">=D8=AA=D9=8A=D9=84=D9=8A=D8=AC=D8=B1=D8=A7=D9=85 =D8=B9=D9=84=D9=89 =D8=
=A7=D9=84=D8=B1=D9=82=D9=85 00966581784106</span></b><span dir=3D"LTR"></sp=
an><b><span lang=3D"AR-SA" dir=3D"LTR" style=3D"font-size: 18pt; font-famil=
y: Helvetica, &quot;sans-serif&quot;; color: red;"><span dir=3D"LTR"></span=
> </span></b><b><span lang=3D"AR-SA" style=3D"font-size: 15pt; font-family:=
 Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);">=D8=AD=D8=A8=D9=88=
=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></b><span lang=3D"AR-SA" style=
=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb=
(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=88=D9=8A=D9=86 =D8=A7=D9=84=D8=A7=D9=83=D9=8A =D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=
=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></b><span lang=3D"AR-SA" style=3D"f=
ont-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, =
34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=
=87</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: A=
rial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=
=A7=D9=84=D8=A7=D8=B5=D9=84=D9=8A=D9=87</span></b><span lang=3D"AR-SA" styl=
e=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rg=
b(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=
=84=D9=84=D8=A8=D9=8A=D8=B9</span></b><span lang=3D"AR-SA" style=3D"font-si=
ze: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34=
);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 16pt; text-align: c=
enter; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size: 15=
pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(102, 102, 102);"=
>=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=
=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 - =D8=AD=D8=A8=D9=
=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 - =D8=AA=D9=8A=D9=84=D9=8A=D8=AC=D8=
=B1=D8=A7=D9=85
=D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85 00966581784106</span></b>=
<span lang=3D"AR-JO" style=3D"font-size: 12pt; font-family: Arial, &quot;sa=
ns-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 0.0001pt; line-height: normal; direc=
tion: ltr; unicode-bidi: embed;"><span style=3D"font-size: 12pt; font-famil=
y: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"><br />
<br />
</span><span style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans=
-serif&quot;;"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=84=D8=B0=D9=84=D9=83 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=
=84=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6</span></b><span lang=3D"AR-JO" styl=
e=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rg=
b(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=
=84=D8=AA=D9=86=D8=B8=D9=8A=D9=81 =D8=A7=D9=84=D8=B1=D8=AD=D9=85</span></b>=
<span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sa=
ns-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=
=A7=D9=84=D8=AF=D9=81=D8=B9 =D8=B9=D9=86=D8=AF =D8=A7=D9=84=D8=A7=D8=B3=D8=
=AA=D9=84=D8=A7=D9=85</span></b><span lang=3D"AR-SA" style=3D"font-size: 12=
pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></=
span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; fo=
nt-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span><=
/p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D8=AA=D9=86=D8=B2=D9=8A=
=D9=84 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9</span></b><span lang=3D"AR-SA" =
style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color=
: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200</span></b><span lang=3D"AR=
-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; =
color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AA=D8=B1=D9=
=83=D9=8A=D8=A7</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; fo=
nt-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span><=
/p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D8=AF=D9=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; fo=
nt-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span><=
/p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-=
family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=
=D8=B6</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family=
: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200 =D8=B3=D8=B9=D8=B1</span><=
/b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot=
;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 2022</span></b><span lang=3D"AR-SA" style=3D"font-size: 12p=
t; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></s=
pan></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=
=8A =D9=85=D8=B5=D8=B1 2020</span></b><span lang=3D"AR-SA" style=3D"font-si=
ze: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34=
);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">7 =D8=AD=D8=A8=D8=A7=D8=AA =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</sp=
an></b><span lang=3D"AR-JO" style=3D"font-size: 12pt; font-family: Arial, &=
quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p dir=3D"LTR" style=3D"margin-bottom: 0.0001pt; line-height: normal; direc=
tion: ltr; unicode-bidi: embed;"><span style=3D"font-size: 12pt; font-famil=
y: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"><br />
<br />
</span><span style=3D"font-size: 10.5pt; font-family: Helvetica, &quot;sans=
-serif&quot;;"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=88=D9=84=D9=87=D8=A7 =D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=83 200 =
=D8=A5=D8=AC=D9=87=D8=A7=D8=B6</span></b><span lang=3D"AR-JO" style=3D"font=
-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34,=
 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=83 =D8=A7=D8=
=AC=D9=87=D8=A7=D8=B6</span></b><span lang=3D"AR-SA" style=3D"font-size: 12=
pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></=
span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=A8=D8=AF=D9=8A=D9=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83</span></b><span lang=3D"AR-SA" style=3D"font-size: 12=
pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></=
span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=A8=D8=AF=D9=8A=D9=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83</span></b><span lang=3D"AR-SA" style=3D"font-size: 12=
pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></=
span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">"=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=
=AD=D9=85=D9=84"</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; f=
ont-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span>=
</p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">"=D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=A8=D8=AD=D8=A8=D9=88=D8=
=A8 =D9=85=D9=86=D8=B9 =D8=A7=D9=84=D8=AD=D9=85=D9=84"</span></b><span lang=
=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&q=
uot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=
=D9=83 =D9=84=D9=84=D8=B9=D9=84=D8=A7=D8=AC</span></b><span lang=3D"AR-SA" =
style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color=
: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=
=A7=D9=8A=D9=86 =D8=AA=D8=A8=D8=A7=D8=B9</span></b><span lang=3D"AR-SA" sty=
le=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: r=
gb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=83 2020=C2=A0<=
/span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial=
, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=
 =D8=B3=D8=A7=D9=8A=D8=AA=D9=83 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =
=D9=81=D9=8A =D8=A7=D9=84=D8=B4=D9=87=D8=B1
=D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A=C2=A0</span></b><span lang=3D"AR-SA" s=
tyle=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color:=
 rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=A3=D8=AD=D8=B6=D8=B1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83=
 =D8=A7=D8=AC=D9=87=D8=A7=D8=AF=C2=A0</span></b><span lang=3D"AR-SA" style=
=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb=
(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=83 =D8=AF=D8=A7=D9=8A=D9=85=D9=88=
=D9=86=D8=AF =D9=81=D9=8A =D8=A7=D9=84=D8=B4=D9=87=D8=B1 =D8=A7=D9=84=D8=A7=
=D9=88=D9=84=C2=A0</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt;=
 font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></spa=
n></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D8=B4=D8=B1=D9=8A=D8=B7 =D9=85=D9=8A=D8=B2=D9=88=D8=
=AA=D8=A7=D9=83 =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A</span></b><span lang=
=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&q=
uot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=85=D8=AA=D9=89 =D9=8A=D8=A8=D8=AF=D8=A3 =D8=A7=D9=84=D8=A5=D8=AC=D9=
=87=D8=A7=D8=B6 =D8=A8=D8=B9=D8=AF =D8=A3=D8=AE=D8=B0 =D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=C2=A0</span></b><span lang=
=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&q=
uot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=87=D9=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=83 =D9=
=84=D9=87=D8=A7 =D8=A3=D8=B6=D8=B1=D8=A7=D8=B1=C2=A0</span></b><span lang=
=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&q=
uot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=
 =D8=AD=D8=A8=D9=88=D8=A8 =D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=83 =D9=84=
=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B4=D9=87=
=D8=B1
=D8=A7=D9=84=D8=A3=D9=88=D9=84=C2=A0</span></b><span lang=3D"AR-SA" style=
=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb=
(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=85=D8=A7=D9=87=D9=88 =D8=AF=D9=88=D8=A7=D8=A1 =D8=A8=D9=88=D8=AA=D9=
=8A=D9=83=C2=A0</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; fo=
nt-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span><=
/p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83=
 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=AF</span></b><span lang=3D"AR-SA" =
style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color=
: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D8=AE=D8=B0 =D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></b><span lang=3D"AR-S=
A" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; co=
lor: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6</span></b><span lang=3D"AR-SA"=
 style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; colo=
r: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B4=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span=
></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &qu=
ot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=
=D9=83 =D9=84=D9=84=D8=B9=D9=84=D8=A7=D8=AC</span></b><span lang=3D"AR-SA" =
style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color=
: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D8=AC=D9=87=D8=A7=D8=AF =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83</span></b><span lang=3D"AR-SA" style=3D"font-si=
ze: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34=
);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B9=D9=84=D8=A7=D8=AC =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=C2=A0=
</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Aria=
l, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=A7=D9=84=D8=A2=D8=AB=D8=A7=D8=B1 =D8=A7=D9=84=D8=AC=D8=A7=D9=86=D8=A8=
=D9=8A=D8=A9.</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font=
-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p=
>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B4=D9=83=D9=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D8=A7=D9=84=D8=A7=D8=B5=D9=84=D9=8A=D9=87=C2=A0</span></b>=
<span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sa=
ns-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AF=D9=88=D8=A7=D8=A1 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6</span></b><span l=
ang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-seri=
f&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">"=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=AD=D9=85=D9=84 =D8=AE=D8=A7=D8=B1=D8=
=AC =D8=A7=D9=84=D8=B1=D8=AD=D9=85"</span></b><span lang=3D"AR-SA" style=3D=
"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34=
, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=AA=D8=B3=D9=82=D8=B7 =D8=A7=D9=84=D8=AD=D9=
=85=D9=84 =D9=84=D9=84=D8=A8=D9=8A=D8=B9</span></b><span lang=3D"AR-SA" sty=
le=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: r=
gb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=
=81=D9=8A =D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A7=D8=AA</span></b><span lang=
=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&q=
uot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=A8=D8=AF=D9=8A=D9=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83</span></b><span lang=3D"AR-SA" style=3D"font-size: 12=
pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></=
span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=
 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=83 =D8=A7=D9=84=D8=A5=
=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B4=D9=87=D8=B1
=D8=A7=D9=84=D8=A3=D9=88=D9=84</span></b><span lang=3D"AR-SA" style=3D"font=
-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34,=
 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83=
 =D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85<=
/span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial=
, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=A8=D8=B1=D8=B4=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=
 =D9=84=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6=C2=A0</span></b><span lang=3D"A=
R-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;;=
 color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=85=D8=AA=D9=89 =D9=8A=D8=A8=D8=AF=D8=A7 =D9=85=D9=81=D8=B9=D9=88=D9=
=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=
=83=C2=A0</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-fam=
ily: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AA=D8=AC=D8=B1=D8=A8=D8=AA=D9=8A =D9=85=D8=B9 =D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D8=AA=D9=83=D8=A7=D8=
=AA=C2=A0</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-fam=
ily: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D8=AE=D8=B0 =D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=C2=A0</span></b><span lang=
=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&q=
uot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=83 =D8=A7=D9=
=84=D8=A3=D8=B5=D9=84=D9=8A 2021=C2=A0</span></b><span lang=3D"AR-SA" style=
=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb=
(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=A7=D9=82=D8=B1=D8=A3 =D8=B5=D9=88=D8=AA=D9=83</span></b><span lang=3D=
"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-serif&quot=
;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A8=D9=8A=D8=B9=
 =D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83=C2=A0</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt;=
 font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></spa=
n></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D9=86=D9=87=D8=AF=D9=8A=C2=A0</sp=
an></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &=
quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=AA=D9=89 =D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=83=C2=A0</span=
></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &qu=
ot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D9=85=D8=B9=D8=AF=D9=87 =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=83=C2=A0</span></b><span lang=3D"AR-SA" style=3D"font-si=
ze: 12pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34=
);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D9=8A=D8=B2=D9=88=D8=AA=D8=A7=D9=83=C2=A0=
</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Aria=
l, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=8A=D9=84=D8=A7 =D9=8A=D8=B7=D9=84=D9=82 =D8=A7=D9=84=D9=86=D8=A7=D8=
=B1</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: A=
rial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 0.0001pt; text-alig=
n: center; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size=
: 15pt; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);=
">=D9=86=D9=85=D8=B4=D9=8A =E2=80=93 =D9=86=D9=85=D8=B4=D9=8A</span></b><sp=
an lang=3D"AR-SA" style=3D"font-size: 12pt; font-family: Arial, &quot;sans-=
serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p align=3D"center" dir=3D"RTL" style=3D"margin-bottom: 9pt; text-align: ce=
nter; line-height: normal;"><b><span lang=3D"AR-SA" style=3D"font-size: 15p=
t; font-family: Arial, &quot;sans-serif&quot;; color: rgb(71, 71, 73);">=D8=
=A7=D9=83=D8=B3=D8=AA=D8=B1=D8=A7 =E2=80=93 =D8=A7=D8=B6=D8=A7=D9=81=D9=8A=
=D8=A9</span></b><span lang=3D"AR-SA" style=3D"font-size: 12pt; font-family=
: Arial, &quot;sans-serif&quot;; color: rgb(34, 34, 34);"></span></p>

<p dir=3D"RTL"><span dir=3D"LTR">=C2=A0</span></p>

<p dir=3D"RTL"><span dir=3D"LTR">=C2=A0</span></p><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/a5b117b7-ca0c-4d12-b9df-91031aac2610n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/a5b117b7-ca0c-4d12-b9df-91031aac2610n%40googlegroups.com</a>.<b=
r />

------=_Part_763889_589821206.1721641604032--

------=_Part_763888_45403171.1721641604032--
