Return-Path: <kasan-dev+bncBDSKTXUX6YNRBUN7264QMGQEXFNWIBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id E3F919C88FD
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2024 12:32:38 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-296207afc2dsf28573fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2024 03:32:38 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731583954; x=1732188754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Eoy2SfFYNUw9Fv879ABktMWDSgoIhW6iaYQCwdPqa6Y=;
        b=mUcCxQsF9zvX3wS3TUZbSoriBPqDYoZS9dgcEhX3TNsy1+Nhhf/gFlLlhjalRhf10O
         xSn9nCNtdTS94lrnsxqa/N4Cttlfitb3LDsz7CVbLf1qv4ohrdEt6VfjI3AgRT0eLnp1
         gGOIUvxH7po59b7gnkawyuBM4+ZYuTCoIt4bUxUwLWcnwLkAMQXI8dWNyBF8x3Q8gvXH
         RrrrRtdWVbxVtUF8dJv3HY7Pv7SfY1t7ptbxd2PcTyZ1pfTEQx8NFfjqBimRIJEQhXkk
         hRzvEnIoaJLih3JIAHhLgW9TMd3BdKHAGRk528jKVm5jnYDD5eSVVqAWr4/HIxhuRskK
         4c7w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1731583954; x=1732188754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Eoy2SfFYNUw9Fv879ABktMWDSgoIhW6iaYQCwdPqa6Y=;
        b=lI/IPiFyJLrmqDiRpYBPZDRxuGZbqx8yg4CFO2HnQ8qh/ococXHDF+bMF//XbvoD3h
         wXm7qPNVnUTMr/jtXv4PCNaA3kZjLc0OTH9BGxYf+sowMm/25IfJ9txC+FdhOUQO+5O5
         Gqflb155YdRinJjK0DJv70UoThNIfLTmZS7su71yHiCth7f1hhSxjCTPdYyQIEZdsQRF
         svhjkvFum+OQPffQW9PTnhTARoTibVgTCFZ5pQNpb0CbAT25iYWcNigoMjUBprzjDw1R
         1ARfFZjVeIkurk5z7BKjU/3hoMnetHeRN/SC/xd8GjVNRlXahC/Uvf6eb/jEmqw9efaY
         Uk3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731583954; x=1732188754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Eoy2SfFYNUw9Fv879ABktMWDSgoIhW6iaYQCwdPqa6Y=;
        b=UzOoC40QgBGnlfy0TFsjjR41vbGdONcETvrTluUbOc3+WGiZNwzIRWMTKlOzhVi4sZ
         ytGOYSA4vILelvuTQWnvM1O9hJlmGcx3ngB3nQCDJOzgADAdUzeYtZ7sJCn5AyM3x3+Y
         X+Du1nrNMam/xEW1cI1UcEoY8Y4NOUo6th0ZCQukmyPxyiFofLRbTZpTq/1wWa6fOY+r
         A94xrvjIwHPmB6Je38nq4nANZHfsxkUAIxCyqG7nklxwojDRFzGT5dzvhfI1BnXQP5tL
         lOc9ssalvekp5pt5lFG8uvcR3LpvMTKhpfv0Qqd2Ob8jJ+K8+Erv+P91vRML4M9da6wZ
         CovA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCUfO47l2lRr09wlAhbj4bZ6OKmm816815JAKfeMOGH0BlX+zYC6RU3QtstyLNC2/hd1gpeoCw==@lfdr.de
X-Gm-Message-State: AOJu0Yzz40kZLBTWX+X48s1kIYSeV1BDNyD974sDAEn7tcpjurZDllbn
	4FRTMnOWgpxEkUxHMpnHdqJboWtIdp/1c5GeUkAzzErm5tkLAmkQ
X-Google-Smtp-Source: AGHT+IEWdHBLGi+WF+nkmzU//njYCIE4DgeM3nPuGY35A9Bel/22eBDZOpeM4JOMnPJrhg4S9ZJfjw==
X-Received: by 2002:a05:6870:70a2:b0:288:a953:a5c7 with SMTP id 586e51a60fabf-295e8d6a2bamr7249087fac.14.1731583953853;
        Thu, 14 Nov 2024 03:32:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1907:b0:5ec:58bd:88f2 with SMTP id
 006d021491bc7-5ee9cbc33ccls636390eaf.0.-pod-prod-04-us; Thu, 14 Nov 2024
 03:32:33 -0800 (PST)
X-Received: by 2002:a05:6808:1b24:b0:3e7:5af6:4e94 with SMTP id 5614622812f47-3e7b7b63eccmr1928595b6e.12.1731583952758;
        Thu, 14 Nov 2024 03:32:32 -0800 (PST)
Date: Thu, 14 Nov 2024 03:32:32 -0800 (PST)
From: "Edward A. Jenkins" <jenkinsedwarda@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <791a0020-d939-4fb3-bd83-f6bd5151fb24n@googlegroups.com>
In-Reply-To: <ed817b7b-69bc-45b2-a666-2e5a4c6cf340n@googlegroups.com>
References: <0f8bcf08-df8a-4f8e-a5b3-fc156af6e98fn@googlegroups.com>
 <81ac6522-7761-49aa-8f45-7f03ba257d3an@googlegroups.com>
 <7193d113-c2d8-4562-8b18-bd5cb539dad8n@googlegroups.com>
 <2b978e79-a67c-45d5-8fc0-04c8c7c05033n@googlegroups.com>
 <330e091d-e1a7-44d2-8b04-39a3c0673a5an@googlegroups.com>
 <97233167-ad93-4058-91a9-b307ec628355n@googlegroups.com>
 <cf6539bb-acc3-4ada-9916-e49979bf1dfbn@googlegroups.com>
 <2432054c-d758-4005-8cd5-140710f986a0n@googlegroups.com>
 <fda139f3-2470-49b1-b639-0eb0f22c8c9dn@googlegroups.com>
 <8e466b49-cd56-4324-b0e4-781c43be86f9n@googlegroups.com>
 <0fe451b8-18dc-4083-be91-84ddc0132a77n@googlegroups.com>
 <c4f0da86-ffbf-4155-8009-c206a7d29e92n@googlegroups.com>
 <fba97f1d-7404-4a51-98c8-5797750f838an@googlegroups.com>
 <f96289ee-bde7-48b5-a979-40638ced9d85n@googlegroups.com>
 <830720ed-380b-4098-9714-1fb2aacc159cn@googlegroups.com>
 <ed817b7b-69bc-45b2-a666-2e5a4c6cf340n@googlegroups.com>
Subject: =?UTF-8?Q?Re:_UAE_-_=D8=AD=D8=A8=D9=88?=
 =?UTF-8?Q?=D8=A8_=D8=A7=D9=84=D8=A7=D8=AC=D9=87?=
 =?UTF-8?Q?=D8=A7=D8=B6_=D8=B3=D8=A7=D9=8A=D8=AA?=
 =?UTF-8?Q?=D9=88=D8=AA=D9=83_=D8=A7=D9=84?=
 =?UTF-8?Q?=D8=A7=D9=85=D8=A7=D8=B1=D8=A7=D8=AA_?=
 =?UTF-8?Q?00971553031846?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_47878_870487474.1731583952119"
X-Original-Sender: jenkinsedwarda@gmail.com
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

------=_Part_47878_870487474.1731583952119
Content-Type: multipart/alternative; 
	boundary="----=_Part_47879_287086780.1731583952119"

------=_Part_47879_287086780.1731583952119
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

Cj4g2KPYudmE2KfZhiB8INmE2YTYqNmK2Lkg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDY
p9mE2KfZhdin2LHYp9iqINin2KjZiNi42KjZiiDYp9mE2LTYp9ix2YLZhyDYp9mE2LnZitmGINiv
2KjZiiDYqtiz2YTZitmFCj4g2KjYp9mE2YrYryAg2KrZhNis2LHYp9mFINmI2KrYs9in2KggQ3l0
b3RlYyAtIEFtYXpvbi5hZSDZitiq2YXZitiyINiv2YjYp9ihIEN5dG90ZWMgKNiz2KfZitiq2YjY
qtmDKSAK2KjZgdi52KfZhNmK2KrZhyDZgdmKINil2KzZh9in2LYg2KfZhNit2YXZhNiMINmI2KfZ
hNiq2K7ZhNi1INmF2YYg2KfZhNmG2LLZitmBINmF2Kcg2KjYudivINin2YTZiNmE2KfYr9ipLiDZ
iNmH2Ygg2YrYrdiq2YjZiiDYudmE2YkgCtin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqSDZhdmK
2LLZiNio2LHZiNiz2KrZiNmELiDZitiq2YjZgdixINit2KjZiNioINiz2KfZitiq2YjYqtmDINmE
2YTYqNmK2Lkg2YHZiiDYp9mE2K/Zhdin2YXYjCDYp9mE2LHZitin2LbYjCAK2KzYr9ip2Iwg2YjZ
hdmD2Kkg2KfZhNmF2YPYsdmF2KkuINit2YrYqyDZitiz2YfZhCDYp9mE2K3YtdmI2YQg2LnZhNmJ
2YfYpyDYudio2LEg2LHZgtmFINmI2KfYqtiz2KfYqCDYo9mIINiq2YTZitis2LHYp9mFICDYjCDZ
iNmK2YLYr9mFIArYp9mE2YXZiNix2K8g2KrYs9mE2YrZhdmL2Kcg2LTYrti12YrZi9inINio2KfZ
hNmK2K8g2KjYo9iz2LnYp9ixINiq2YbYp9mB2LPZitipLiDYqtio2K3YqyDYp9mE2LnYr9mK2K8g
2YXZhiDYp9mE2YbYs9in2KEg2YHZiiAK2KfZhNmF2YXZhNmD2Kkg2KfZhNi52LHYqNmK2Kkg2KfZ
hNiz2LnZiNiv2YrYqSDYudmGINiz2KfZitiq2YjYqtmDINmD2K7Zitin2LEg2KjYr9mK2YQg2YTZ
hNi52YXZhNmK2KfYqiDYp9mE2KzYsdin2K3ZitipINin2YTYqtmKINiq2YPZhNmBIArYp9mE2YPY
q9mK2LEg2YXZhiDYp9mE2YjZgtiqINmI2KfZhNmF2KfZhNiMINmI2KrYrdmF2YQg2YXYrtin2LfY
sSDYtdit2YrYqSDYudin2YTZitipLiDZitmF2YPZhtmDINin2YTYotmGINin2YTYrdi12YjZhCDY
udmE2YkgCtin2YTYrdio2YjYqCDYp9mE2KLZhdmG2Kkg2YjYp9mE2YHYudin2YTYqSDYqNin2LPY
qtiu2K/Yp9mFINiz2KfZitiq2YjYqtmDLgo+IDEuINit2KjZiNioINiz2KfZitiq2YjYqtmDINmE
2YTYqNmK2Lkg2KjYp9mE2KXZhdin2LHYp9iqOiDYp9mE2YXYudmE2YjZhdin2Kog2KfZhNij2LPY
p9iz2YrYqSDZiNin2YTYqtiz2YTZitmFINio2KfZhNmK2K8KPiAyLiDYrti12YUgMjXZqiDYudmE
2Ykg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTYudmE2KfYrCDYp9mE2KXYrNmH2KfYtiDZgdmK
INiv2KjZigo+IDMuINiq2YHYp9i12YrZhCDYrdmI2YQg2KrYo9ir2YrYsdin2Kog2YjYp9iz2KrY
rtiv2KfZhSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYpdmF2KfYsdin2KoKPiA0
LiDYrtiv2YXYqSDYqtmI2LXZitmEINmB2YjYsdmK2Kkg2YTYrdio2YjYqCDYs9in2YrYqtmI2KrZ
gyDZgdmKINin2YTYpdmF2KfYsdin2Ko6INmD2YQg2YXYpyDYqtit2KrYp9isINmE2YXYudix2YHY
qtmHCj4gNS4g2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTYudmE2KfYrCDYp9mE2KXYrNmH2KfY
tjog2KfZhNiq2LPZhNmK2YUg2KjYp9mE2YrYryDZgdmKINiv2KjZiiDZiNin2YTYpdmF2KfYsdin
2Kog2KfZhNij2K7YsdmJCj4gNi4g2KfZhNit2YjYp9ixINmF2Lkg2KPYrti12KfYptmKINiq2YjZ
hNmK2K8g2K3ZiNmEINin2LPYqtiu2K/Yp9mFINit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2LnZ
hNin2Kwg2KfZhNil2KzZh9in2LYg2YHZiiAK2KfZhNil2YXYp9ix2KfYqgo+IDcuINit2YrYqyDZ
itmF2YPZhiDYp9mE2K3YtdmI2YQg2LnZhNmJINit2KjZiNioINiz2KfZitiq2YjYqtmDINio2KPZ
hdin2YYg2YHZiiDYp9mE2KXZhdin2LHYp9iqCj4gOC4g2YPZitmB2YrYqSDYp9mE2K3YtdmI2YQg
2LnZhNmJINit2KjZiNioINiz2KfZitiq2YjYqtmDINio2LfYsdmK2YLYqSDYotmF2YbYqSDZiNi0
2LHYudmK2Kkg2YHZiiDYp9mE2KXZhdin2LHYp9iqCj4gOS4g2YPZhCDZhdinINiq2K3Yqtin2Kwg
2YTZhdi52LHZgdiq2Ycg2K3ZiNmEINit2KjZiNioINiz2KfZitiq2YjYqtmDINmI2LfYsdmCINin
2LPYqtiu2K/Yp9mF2YfYpyDZhNi52YTYp9isINin2YTYpdis2YfYp9i2INmB2YogCtin2YTYpdmF
2KfYsdin2KoKPiAxMC4g2KPZh9mFINin2YTZhdi52YTZiNmF2KfYqiDYrdmI2YQg2K3YqNmI2Kgg
2LPYp9mK2KrZiNiq2YMg2YjYo9ir2LHZh9inINi52YTZiSDYtdit2Kkg2KfZhNij2YUg2YjYp9mE
2KzZhtmK2YYg2YHZiiAK2KfZhNil2YXYp9ix2KfYqi4KPiAxLiDYrdio2YjYqCDYs9in2YrYqtmI
2KrZgyDZhNmE2KjZiti5INmB2Yog2KfZhNil2YXYp9ix2KfYqjog2KfZhNiq2LPZhNmK2YUg2KfZ
hNmB2YjYsdmKINmI2KfZhNmF2KrYp9io2LnYqSDYp9mE2LfYqNmK2KkKPiAyLiDYrti12YUgMjXZ
qiDYudmE2Ykg2LTYsdin2KEg2LPYp9mK2KrZiNiq2YMg2YHZiiDYr9io2Yo6INi52YTYp9isINmE
2KXZhtmH2KfYoSDYp9mE2K3ZhdmEINio2KPZhdin2YYKPiAzLiDYp9it2LXZhCDYudmE2Ykg2K3Y
qNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2KfZhdin2LHYp9iqINmK2K8g2KjZitivINi5
2YYg2LfYsdmK2YIg2KfZhNmF2YbYr9mI2KjZitmGCj4gNC4g2K3YqNmI2Kgg2LPYp9mK2KrZiNiq
2YMg2YTZhNil2KzZh9in2LYg2YHZiiDYp9mE2KXZhdin2LHYp9iqOiDYqti52LHZgSDYudmE2Ykg
2YXZg9mI2YbYp9iq2YfYpyDZiNii2YTZitipINi52YXZhNmH2KcKPiA1LiDZhdiq2YjZgdix2Kkg
2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2KXZhdin2LHYp9iqOiDYqtiq2YPZiNmG
INmF2YYg2YXZitiy2YjYqNix2LPYqtmI2YQKPiA2LiDYrdi12LHZitin2Ys6INit2KjZiNioINiz
2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZiiDYp9mE2KXZhdin2LHYp9iqINio2KPYs9i52KfY
sSDZhdmG2KfYs9io2KkKPiA3LiDYqti52LHZgSDYudmE2Ykg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq
2YMg2YTZhNil2KzZh9in2LYg2KfZhNmF2YjYrNmI2K/YqSDZgdmKINin2YTYpdmF2KfYsdin2KoK
PiA4LiDZhdiq2YjZgdix2Kkg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDZgdmK
INiv2KjZiiDZiNin2YTYpdmF2KfYsdin2Kog2KjYp9mE2YPYp9mF2YQ6INiq2LPZhNmK2YUg2KjY
s9ix2LnYqSDZiNiz2YfZiNmE2KkKPiA5LiDYrdi12YQg2LnZhNmJINin2YTYudmE2KfYrCDYp9mE
2LDZiiDYqtit2KrYp9is2Ycg2YHZiiDYp9mE2KXZhdin2LHYp9iqINio2LPZh9mI2YTYqTog2K3Y
qNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YXYqtmI2YHYsdipINin2YTYotmGCj4gMTAuINil2YbZh9in
2KEg2KfZhNit2YXZhCDYqNij2YXYp9mGINmB2Yog2KfZhNil2YXYp9ix2KfYqjog2K3YqNmI2Kgg
2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDYqNiv2YjZhiDZiNi12YHYqSDYt9io2YrYqSDZgdmK
IArYr9io2Yog2YjYp9mE2KXZhdin2LHYp9iqINin2YTYo9iu2LHZiS4KPiAxLiDYrdio2YjYqCDY
s9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB2Yog2KfZhNil2YXYp9ix2KfYqiDYqNiu2LXZhSAy
NdmqCj4gMi4g2YPZhCDZhdinINiq2K3Yqtin2Kwg2YXYudix2YHYqtmHINi52YYg2K3YqNmI2Kgg
2LPYp9mK2KrZiNiq2YMg2YjYo9mK2YYg2KrYrNiv2YfYpyDZgdmKINin2YTYpdmF2KfYsdin2KoK
PiAzLiDYs9in2YrYqtmI2KrZgzog2KfZhNit2YQg2KfZhNmB2LnYp9mEINmE2YTYpdis2YfYp9i2
INin2YTYotmF2YYKPiA0LiDYqtiz2YTZitmFINiz2LHZiti5INmI2K/YudmFINi32KjZiiDZhNit
2KjZiNioINiz2KfZitiq2YjYqtmDINmB2Yog2K/YqNmK2Iwg2KfZhNi02KfYsdmC2KnYjCDYp9mE
2LnZitmG2Iwg2KPYqNmI2LjYqNmK2IwgCtmI2LnYrNmF2KfZhgo+IDUuINmF2LnZhNmI2YXYp9iq
INmF2YfZhdipINi52YYg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YjYt9ix2YrZgtipINin2LPY
qtiu2K/Yp9mF2YfYpyDYqNi02YPZhCDYotmF2YYKPiA2LiDYp9mE2KrZiNin2LXZhCDZhdi52YbY
pyDZhNmE2K3YtdmI2YQg2LnZhNmJINit2KjZiNioINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNil
2YXYp9ix2KfYqiDZitivINio2YrYrwo+INi52YbYr9mF2Kcg2YPZhtiqINij2KjYrdirINi52YYg
2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2YjYrNiv2Kog
2KPZhtmH2Kcg2LrZitixINmF2KrYp9it2Kkg2YHZiiAK2KfZhNi12YrYr9mE2YrYp9iqINin2YTY
udin2K/ZitipLiDZiNmE2YPZhiDZhdi5INin2LPYqtmF2LHYp9ixINin2YTYqNit2Ksg2YjYp9mE
2KfYt9mE2KfYuSDYudmE2Ykg2KfZhNmF2LnZhNmI2YXYp9iqINin2YTZhdiq2KfYrdip2IwgCtin
2YPYqti02YHYqiDYo9mG2Ycg2YrZhdmD2YYg2KfZhNit2LXZiNmEINi52YTZiSDZh9iw2Ycg2KfZ
hNit2KjZiNioINmF2YYg2K7ZhNin2YQg2KfZhNi02LHYp9ihINi52KjYsSDYp9mE2KXZhtiq2LHZ
htiqDQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJz
Y3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNj
cmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBz
ZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpU
byB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2Qv
bXNnaWQva2FzYW4tZGV2Lzc5MWEwMDIwLWQ5MzktNGZiMy1iZDgzLWY2YmQ1MTUxZmIyNG4lNDBn
b29nbGVncm91cHMuY29tLgo=
------=_Part_47879_287086780.1731583952119
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGJyIC8+Jmd0OyDYo9i52YTYp9mGIHwg2YTZhNio2YrYuSDYrdio2YjYqCDYs9in2YrYqtmI2KrZ
gyDZgdmKINin2YTYp9mF2KfYsdin2Kog2KfYqNmI2LjYqNmKINin2YTYtNin2LHZgtmHINin2YTY
udmK2YYg2K/YqNmKINiq2LPZhNmK2YU8YnIgLz4mZ3Q7INio2KfZhNmK2K8gwqDYqtmE2KzYsdin
2YUg2YjYqtiz2KfYqCBDeXRvdGVjIC0gQW1hem9uLmFlINmK2KrZhdmK2LIg2K/ZiNin2KEgQ3l0
b3RlYyAo2LPYp9mK2KrZiNiq2YMpINio2YHYudin2YTZitiq2Ycg2YHZiiDYpdis2YfYp9i2INin
2YTYrdmF2YTYjCDZiNin2YTYqtiu2YTYtSDZhdmGINin2YTZhtiy2YrZgSDZhdinINio2LnYryDY
p9mE2YjZhNin2K/YqS4g2YjZh9mIINmK2K3YqtmI2Yog2LnZhNmJINin2YTZhdin2K/YqSDYp9mE
2YHYudin2YTYqSDZhdmK2LLZiNio2LHZiNiz2KrZiNmELiDZitiq2YjZgdixINit2KjZiNioINiz
2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZiiDYp9mE2K/Zhdin2YXYjCDYp9mE2LHZitin2LbY
jCDYrNiv2KnYjCDZiNmF2YPYqSDYp9mE2YXZg9ix2YXYqS4g2K3ZitirINmK2LPZh9mEINin2YTY
rdi12YjZhCDYudmE2YnZh9inINi52KjYsSDYsdmC2YUg2YjYp9iq2LPYp9ioINij2Ygg2KrZhNmK
2KzYsdin2YUgwqDYjCDZiNmK2YLYr9mFINin2YTZhdmI2LHYryDYqtiz2YTZitmF2YvYpyDYtNiu
2LXZitmL2Kcg2KjYp9mE2YrYryDYqNij2LPYudin2LEg2KrZhtin2YHYs9mK2KkuINiq2KjYrdir
INin2YTYudiv2YrYryDZhdmGINin2YTZhtiz2KfYoSDZgdmKINin2YTZhdmF2YTZg9ipINin2YTY
udix2KjZitipINin2YTYs9i52YjYr9mK2Kkg2LnZhiDYs9in2YrYqtmI2KrZgyDZg9iu2YrYp9ix
INio2K/ZitmEINmE2YTYudmF2YTZitin2Kog2KfZhNis2LHYp9it2YrYqSDYp9mE2KrZiiDYqtmD
2YTZgSDYp9mE2YPYq9mK2LEg2YXZhiDYp9mE2YjZgtiqINmI2KfZhNmF2KfZhNiMINmI2KrYrdmF
2YQg2YXYrtin2LfYsSDYtdit2YrYqSDYudin2YTZitipLiDZitmF2YPZhtmDINin2YTYotmGINin
2YTYrdi12YjZhCDYudmE2Ykg2KfZhNit2KjZiNioINin2YTYotmF2YbYqSDZiNin2YTZgdi52KfZ
hNipINio2KfYs9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMuPGJyIC8+Jmd0OyAxLiDYrdio2YjY
qCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INio2KfZhNil2YXYp9ix2KfYqjog2KfZhNmF2LnZ
hNmI2YXYp9iqINin2YTYo9iz2KfYs9mK2Kkg2YjYp9mE2KrYs9mE2YrZhSDYqNin2YTZitivPGJy
IC8+Jmd0OyAyLiDYrti12YUgMjXZqiDYudmE2Ykg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTY
udmE2KfYrCDYp9mE2KXYrNmH2KfYtiDZgdmKINiv2KjZijxiciAvPiZndDsgMy4g2KrZgdin2LXZ
itmEINit2YjZhCDYqtij2KvZitix2KfYqiDZiNin2LPYqtiu2K/Yp9mFINit2KjZiNioINiz2KfZ
itiq2YjYqtmDINmB2Yog2KfZhNil2YXYp9ix2KfYqjxiciAvPiZndDsgNC4g2K7Yr9mF2Kkg2KrZ
iNi12YrZhCDZgdmI2LHZitipINmE2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2KXZ
hdin2LHYp9iqOiDZg9mEINmF2Kcg2KrYrdiq2KfYrCDZhNmF2LnYsdmB2KrZhzxiciAvPiZndDsg
NS4g2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTYudmE2KfYrCDYp9mE2KXYrNmH2KfYtjog2KfZ
hNiq2LPZhNmK2YUg2KjYp9mE2YrYryDZgdmKINiv2KjZiiDZiNin2YTYpdmF2KfYsdin2Kog2KfZ
hNij2K7YsdmJPGJyIC8+Jmd0OyA2LiDYp9mE2K3ZiNin2LEg2YXYuSDYo9iu2LXYp9im2Yog2KrZ
iNmE2YrYryDYrdmI2YQg2KfYs9iq2K7Yr9in2YUg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTY
udmE2KfYrCDYp9mE2KXYrNmH2KfYtiDZgdmKINin2YTYpdmF2KfYsdin2Ko8YnIgLz4mZ3Q7IDcu
INit2YrYqyDZitmF2YPZhiDYp9mE2K3YtdmI2YQg2LnZhNmJINit2KjZiNioINiz2KfZitiq2YjY
qtmDINio2KPZhdin2YYg2YHZiiDYp9mE2KXZhdin2LHYp9iqPGJyIC8+Jmd0OyA4LiDZg9mK2YHZ
itipINin2YTYrdi12YjZhCDYudmE2Ykg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KjYt9ix2YrZ
gtipINii2YXZhtipINmI2LTYsdi52YrYqSDZgdmKINin2YTYpdmF2KfYsdin2Ko8YnIgLz4mZ3Q7
IDkuINmD2YQg2YXYpyDYqtit2KrYp9isINmE2YXYudix2YHYqtmHINit2YjZhCDYrdio2YjYqCDY
s9in2YrYqtmI2KrZgyDZiNi32LHZgiDYp9iz2KrYrtiv2KfZhdmH2Kcg2YTYudmE2KfYrCDYp9mE
2KXYrNmH2KfYtiDZgdmKINin2YTYpdmF2KfYsdin2Ko8YnIgLz4mZ3Q7IDEwLiDYo9mH2YUg2KfZ
hNmF2LnZhNmI2YXYp9iqINit2YjZhCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZiNij2KvYsdmH
2Kcg2LnZhNmJINi12K3YqSDYp9mE2KPZhSDZiNin2YTYrNmG2YrZhiDZgdmKINin2YTYpdmF2KfY
sdin2KouPGJyIC8+Jmd0OyAxLiDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB
2Yog2KfZhNil2YXYp9ix2KfYqjog2KfZhNiq2LPZhNmK2YUg2KfZhNmB2YjYsdmKINmI2KfZhNmF
2KrYp9io2LnYqSDYp9mE2LfYqNmK2Kk8YnIgLz4mZ3Q7IDIuINiu2LXZhSAyNdmqINi52YTZiSDY
tNix2KfYoSDYs9in2YrYqtmI2KrZgyDZgdmKINiv2KjZijog2LnZhNin2Kwg2YTYpdmG2YfYp9ih
INin2YTYrdmF2YQg2KjYo9mF2KfZhjxiciAvPiZndDsgMy4g2KfYrdi12YQg2LnZhNmJINit2KjZ
iNioINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNin2YXYp9ix2KfYqiDZitivINio2YrYryDYudmG
INi32LHZitmCINin2YTZhdmG2K/ZiNio2YrZhjxiciAvPiZndDsgNC4g2K3YqNmI2Kgg2LPYp9mK
2KrZiNiq2YMg2YTZhNil2KzZh9in2LYg2YHZiiDYp9mE2KXZhdin2LHYp9iqOiDYqti52LHZgSDY
udmE2Ykg2YXZg9mI2YbYp9iq2YfYpyDZiNii2YTZitipINi52YXZhNmH2Kc8YnIgLz4mZ3Q7IDUu
INmF2KrZiNmB2LHYqSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYpdmF2KfYsdin
2Ko6INiq2KrZg9mI2YYg2YXZhiDZhdmK2LLZiNio2LHYs9iq2YjZhDxiciAvPiZndDsgNi4g2K3Y
tdix2YrYp9mLOiDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB2Yog2KfZhNil
2YXYp9ix2KfYqiDYqNij2LPYudin2LEg2YXZhtin2LPYqNipPGJyIC8+Jmd0OyA3LiDYqti52LHZ
gSDYudmE2Ykg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNil2KzZh9in2LYg2KfZhNmF2YjY
rNmI2K/YqSDZgdmKINin2YTYpdmF2KfYsdin2Ko8YnIgLz4mZ3Q7IDguINmF2KrZiNmB2LHYqSDY
rdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB2Yog2K/YqNmKINmI2KfZhNil2YXY
p9ix2KfYqiDYqNin2YTZg9in2YXZhDog2KrYs9mE2YrZhSDYqNiz2LHYudipINmI2LPZh9mI2YTY
qTxiciAvPiZndDsgOS4g2K3YtdmEINi52YTZiSDYp9mE2LnZhNin2Kwg2KfZhNiw2Yog2KrYrdiq
2KfYrNmHINmB2Yog2KfZhNil2YXYp9ix2KfYqiDYqNiz2YfZiNmE2Kk6INit2KjZiNioINiz2KfZ
itiq2YjYqtmDINmF2KrZiNmB2LHYqSDYp9mE2KLZhjxiciAvPiZndDsgMTAuINil2YbZh9in2KEg
2KfZhNit2YXZhCDYqNij2YXYp9mGINmB2Yog2KfZhNil2YXYp9ix2KfYqjog2K3YqNmI2Kgg2LPY
p9mK2KrZiNiq2YMg2YTZhNio2YrYuSDYqNiv2YjZhiDZiNi12YHYqSDYt9io2YrYqSDZgdmKINiv
2KjZiiDZiNin2YTYpdmF2KfYsdin2Kog2KfZhNij2K7YsdmJLjxiciAvPiZndDsgMS4g2K3YqNmI
2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDZgdmKINin2YTYpdmF2KfYsdin2Kog2KjYrti1
2YUgMjXZqjxiciAvPiZndDsgMi4g2YPZhCDZhdinINiq2K3Yqtin2Kwg2YXYudix2YHYqtmHINi5
2YYg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YjYo9mK2YYg2KrYrNiv2YfYpyDZgdmKINin2YTY
pdmF2KfYsdin2Ko8YnIgLz4mZ3Q7IDMuINiz2KfZitiq2YjYqtmDOiDYp9mE2K3ZhCDYp9mE2YHY
udin2YQg2YTZhNil2KzZh9in2LYg2KfZhNii2YXZhjxiciAvPiZndDsgNC4g2KrYs9mE2YrZhSDY
s9ix2YrYuSDZiNiv2LnZhSDYt9io2Yog2YTYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZgdmKINiv
2KjZitiMINin2YTYtNin2LHZgtip2Iwg2KfZhNi52YrZhtiMINij2KjZiNi42KjZitiMINmI2LnY
rNmF2KfZhjxiciAvPiZndDsgNS4g2YXYudmE2YjZhdin2Kog2YXZh9mF2Kkg2LnZhiDYrdio2YjY
qCDYs9in2YrYqtmI2KrZgyDZiNi32LHZitmC2Kkg2KfYs9iq2K7Yr9in2YXZh9inINio2LTZg9mE
INii2YXZhjxiciAvPiZndDsgNi4g2KfZhNiq2YjYp9i12YQg2YXYudmG2Kcg2YTZhNit2LXZiNmE
INi52YTZiSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYpdmF2KfYsdin2Kog2YrY
ryDYqNmK2K88YnIgLz4mZ3Q7INi52YbYr9mF2Kcg2YPZhtiqINij2KjYrdirINi52YYg2K3YqNmI
2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2YjYrNiv2Kog2KPZhtmH
2Kcg2LrZitixINmF2KrYp9it2Kkg2YHZiiDYp9mE2LXZitiv2YTZitin2Kog2KfZhNi52KfYr9mK
2KkuINmI2YTZg9mGINmF2Lkg2KfYs9iq2YXYsdin2LEg2KfZhNio2K3YqyDZiNin2YTYp9i32YTY
p9i5INi52YTZiSDYp9mE2YXYudmE2YjZhdin2Kog2KfZhNmF2KrYp9it2KnYjCDYp9mD2KrYtNmB
2Kog2KPZhtmHINmK2YXZg9mGINin2YTYrdi12YjZhCDYudmE2Ykg2YfYsNmHINin2YTYrdio2YjY
qCDZhdmGINiu2YTYp9mEINin2YTYtNix2KfYoSDYudio2LEg2KfZhNil2YbYqtix2YbYqg0KDQo8
cD48L3A+CgotLSA8YnIgLz4KWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBh
cmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAmcXVvdDtrYXNhbi1kZXYmcXVvdDsg
Z3JvdXAuPGJyIC8+ClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNl
aXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8gPGEgaHJlZj0ibWFpbHRvOmth
c2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tIj5rYXNhbi1kZXYrdW5zdWJzY3Jp
YmVAZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZp
c2l0IDxhIGhyZWY9Imh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYv
NzkxYTAwMjAtZDkzOS00ZmIzLWJkODMtZjZiZDUxNTFmYjI0biU0MGdvb2dsZWdyb3Vwcy5jb20/
dXRtX21lZGl1bT1lbWFpbCZ1dG1fc291cmNlPWZvb3RlciI+aHR0cHM6Ly9ncm91cHMuZ29vZ2xl
LmNvbS9kL21zZ2lkL2thc2FuLWRldi83OTFhMDAyMC1kOTM5LTRmYjMtYmQ4My1mNmJkNTE1MWZi
MjRuJTQwZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+Cg==
------=_Part_47879_287086780.1731583952119--

------=_Part_47878_870487474.1731583952119--
