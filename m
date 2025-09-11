Return-Path: <kasan-dev+bncBDA2XNWCVILRBHPQRHDAMGQEMFN3OUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id DA75DB529BC
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 09:19:59 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-31bdc4b5315sf170177fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 00:19:59 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757575198; x=1758179998; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=tkKEkthkt8PaTc/J7FSGxDaowMbDGROF0FtC2UjX8Hg=;
        b=IvP9xpL2WS1tJ91EXZE43bDTAd8uPOvG18VVoSUXvxpONlk5zVHapvkaSDkWEh8sTx
         ft/rRagch33c2y17iQTvUht8LPCgL/z8H5DelxpAjoeRMzMlxl13GK2PhXPbXBlLYUGA
         hrey/FIU01SxGd/QNQkR190on3Or5eP5ZV6hE8yhI0h+Xm7ZQoTcG+QC8tzTmIDtTMak
         IIMBo8Ha/In7z4rsDElF2wQgm6KIe6ACp5ysjavuPdZnDKRo9wgpiu57ITud3QmRIlEa
         y/5AjrjUrpxemSWCYDnM097R1+dKe6Uuc0/2COA/r0YnabozqSf5x+4CccpzwTyx39lO
         xa1A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757575198; x=1758179998; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tkKEkthkt8PaTc/J7FSGxDaowMbDGROF0FtC2UjX8Hg=;
        b=Sv8aCUZYoaVorL5SBR+vI3GN1Vf6kYDq+OjXB4mj0CHwyfLzwFZgQjlmi/8We9sdKY
         R78oKVWF/bcnr/hfUZwZ7lwAmvtXE2aBIa1ZWRSqj8wIH0wXRtn3LQjUTfaHXYbK01Qr
         GuP/9AyDOSztZKjfGeCvvKifH1lAxgygl3rQsP5EtJW4dUVsC9ZOK7tc3+1vHLZdm27s
         errvRVWI9i9cO6YiNbslSY5MEfyoE840+TTlUAs6xoUMVlHd+MIv5oVOfUOumxoCr911
         /Uaj+J9udMSuiVPOoUFBBAQq/T7AN2etwZA0oKKVnTg7QpiW1CPob6Yrlmdgf9XGdNvs
         P7yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757575198; x=1758179998;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=tkKEkthkt8PaTc/J7FSGxDaowMbDGROF0FtC2UjX8Hg=;
        b=F22rRDy26AFRD+F5EgOYMdt8GwOFeL1XDZlb5hDTKLxlvVBt4oO9ZKmvaL3qa/0F+y
         kvNpVtZ8a4FG6QMtSlu6pQ/iHSJrk29tHwmCwgQzhNUQaFDU7//YCHJt1EQod8DWccuR
         O4Og3lxe203Cu67OcXmIHsLBH2S1HVtjB5bWFboGY2hbutEOVrgFaxETf6VHhW8asIDt
         V86Mg4gYpX5/1pU5zH1J5hxuTj9QrOTCsQfKRV7SsaIud9gPWYEuEV99hMRj5igxOFfR
         i/t74pHusJI053JeU7vM86NGItqjMCYmHwTIvdtj+CxEsQbn9TbjAqNGy3Evv761z3hC
         WOBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCVVswFSLAMaJX1igEgCqrpGZdS3bgz+jiqOZPstpSll1bHkjJpuIULCZStpj39VoRSGn2ak0g==@lfdr.de
X-Gm-Message-State: AOJu0YxFh7yYKXoyfgokJWn3fykx8/74RjTRynHXDR2n4jclVQsAqzVU
	OUyEuWnZgI4B4xNiD2bmFHN7SARl+d6BKJqavOvtxwxJio2xvwll9gXX
X-Google-Smtp-Source: AGHT+IEYoK9HKVBcesMys5ZnlrzE9ArTLpkn8HI8T5fB56RqMB22UPLi1j2yiC+4iwxT8Zb9TqENLg==
X-Received: by 2002:a05:6870:1b09:b0:315:6c17:e881 with SMTP id 586e51a60fabf-3226480e8eamr8609659fac.23.1757575198233;
        Thu, 11 Sep 2025 00:19:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd64I1OWW0fsSsU+c257SoWSa0rQlh5BJFpcUw5j151jkw==
Received: by 2002:a05:6871:c:b0:310:fb62:9051 with SMTP id 586e51a60fabf-32d00d3a58fls172369fac.0.-pod-prod-02-us;
 Thu, 11 Sep 2025 00:19:57 -0700 (PDT)
X-Received: by 2002:a05:6808:1201:b0:438:40c3:8765 with SMTP id 5614622812f47-43b29981663mr7642473b6e.0.1757575196950;
        Thu, 11 Sep 2025 00:19:56 -0700 (PDT)
Date: Thu, 11 Sep 2025 00:19:54 -0700 (PDT)
From: =?UTF-8?B?2LPZitiv2Kkg2KzYr9ipINin2YTYs9i52YjYr9mK2Kk=?=
 <memosksaa@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <4f272932-c6b0-4d51-80be-30852a533668n@googlegroups.com>
In-Reply-To: <26b4071e-9689-4466-8ac2-1bcfc583d2e6n@googlegroups.com>
References: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
 <36dacae4-ca3c-47cb-90bc-f74023c8b4dfn@googlegroups.com>
 <26b4071e-9689-4466-8ac2-1bcfc583d2e6n@googlegroups.com>
Subject: =?UTF-8?B?UmU6INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNix2YrYp9i2?=
 =?UTF-8?B?IDA1Mzc0NjY1MzkgI9in2YTYs9i52YjYr9mK2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_4096_1473581852.1757575194694"
X-Original-Sender: memosksaa@gmail.com
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

------=_Part_4096_1473581852.1757575194694
Content-Type: multipart/alternative; 
	boundary="----=_Part_4097_506652436.1757575194694"

------=_Part_4097_506652436.1757575194694
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

CgrZgdmKIDMg2K7Yt9mI2KfYqiDZgdmKINin2YTYsdmK2KfYtiDigYnvuI8wNTMxNjAxOTY3IOKB
ie+4jyDYs9in2YrYqtmI2KrZgyDwn5KxINmF2YrYstmI2KjYsdmI2LPYqtmI2YQg2YXZitmB2YrY
qNix2YrYs9iq2YjZhiDwn5SGIArZhdiq2YjZgdix2Kkg2YHZiiDYp9mE2LHZitin2LYg2I8g8J+M
izAwOTY2NTMxNjAxOTY3INio2LPYsdmK2Kkg2KrYp9mF2KkKCkN5dG90ZWMgINin2YTYsdmK2KfY
tuOAmE1pc29wcm9zdG9sCgrjgJkgIOKclO+4jyDYqtmI2KfYtdmE2Yog2YXYudmG2Kcg2KjYs9ix
2YrYqSDYqtin2YXYqSAgINiz2KfZitiq2YjYqtmDINmB2Yog2KzYr9ipIOKVrCDZhdmD2Kkg4pWs
INin2YTYsdmK2KfYtuKVrCDYp9mE2LTYsdmC2YrYqSDilawgCtis2YrYstin2YYg4pWsINiu2YXZ
itizINmF2LTZiti3IOKVrCDZiNin2YTYsdmB2KfYudiMINmI2YXYr9mK2YbYqSDYudmK2LPZidiM
INmI2YXYr9mK2YbYqSDYrdmF2K/YjCDZiNiz2KrYsdipINmF2KrZiNmB2LEg2KjYrNmF2YrYuSAK
2KfZhNmF2K/ZhiDinJTvuI8g2YXYuSDYp9iz2KrYtNin2LHYqSDZhdis2KfZhtmK2Kkg2LbZhdin
2YYg2KfZhNiu2LXZiNi12YrYqSDYqNin2YTYqtmI2LXZitmEINin2YTYs9ix2YrYuSAKCgrZgdmK
INin2YTYrNmF2LnYqdiMIDUg2LPYqNiq2YXYqNixIDIwMjUg2YHZiiDYqtmF2KfZhSDYp9mE2LPY
p9i52KkgMTA6MDE6MTMg2LUgVVRDLTfYjCDZg9iq2KggCmhheWF0YS4uLkBnbWFpbC5jb20g2LHY
s9in2YTYqSDZhti12YfYpzoKCj4g2LPYp9mK2KrZiNiq2YrZgyjYtdmK2K/ZhNmK2KkpLTA1Mzc0
NjY1MzkvLyDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2LHZitin2LYKPgo+Cj4g2LPYp9mK
2KrZiNiq2YrZgyAo2KfZhNix2YrYp9i2wq4pMDUzNzQ2NjUzOSDYs9i52YjYr9mK2KkKPgo+IE5l
dyAKPiA8aHR0cHM6Ly9mb3J1bS5kamkuY29tL2ZvcnVtLnBocD9tb2Q9cmVkaXJlY3QmdGlkPTMz
NzU2NSZnb3RvPWxhc3Rwb3N0I2xhc3Rwb3N0Pgo+Cj4KPiDYs9in2YrYqtmI2KrZitmDKNiz2YTY
t9mG2Kkg2LnZhdin2YbCriktIDA1Mzc0NjY1MzkgCj4KPiBOZXcgCj4gPGh0dHBzOi8vZm9ydW0u
ZGppLmNvbS9mb3J1bS5waHA/bW9kPXJlZGlyZWN0JnRpZD0zMzc1NjYmZ290bz1sYXN0cG9zdCNs
YXN0cG9zdD4KPgo+Cj4g2LPYp9mK2KrZiNiq2YrZgyjYtdmK2K/ZhNmK2KkpLTA1Mzc0NjY1Mzkg
2KfZhNix2YrYp9i2Cj4KPiBOZXcgCj4gPGh0dHBzOi8vZm9ydW0uZGppLmNvbS9mb3J1bS5waHA/
bW9kPXJlZGlyZWN0JnRpZD0zMzc1NjcmZ290bz1sYXN0cG9zdCNsYXN0cG9zdD4KPgo+INmF2YPY
qSAo2LPYp9mK2KrZiNiq2YrZg8KuKdmF2YrYstmI2KjYsdiz2KrZiNmEIC0gMDUzNzQ2NjUzOSAK
Pgo+IMKu2LPYp9mK2KrZiNiq2YrZgyjYtdmK2K/ZhNmK2KkpLTA1Mzc0NjY1Mzkg2KzYr9ipCj4K
Pgo+INmB2YogRnJpZGF5LCBTZXB0ZW1iZXIgNSwgMjAyNSDZgdmKINiq2YXYp9mFINin2YTYs9in
2LnYqSAxMDowMTowMeKAr0FNIFVUQy032Iwg2YPYqtioINit2KjZiNioIAo+INiz2KfZitiq2YjY
qtmDIOKAkyDZhtiz2KjYqSDZhtis2KfYrSA5NdmqINix2LPYp9mE2Kkg2YbYtdmH2Kc6Cj4KPj4g
2LPYp9mK2KrZiNiq2YrZgyjYtdmK2K/ZhNmK2KkpLTA1Mzc0NjY1MzkvLyDYrdio2YjYqCDYs9in
2YrYqtmI2KrZgyDYp9mE2LHZitin2LYKPj4KPj4KPj4g2LPYp9mK2KrZiNiq2YrZgyAo2KfZhNix
2YrYp9i2wq4pMDUzNzQ2NjUzOSDYs9i52YjYr9mK2KkKPj4KPj4gTmV3IAo+PiA8aHR0cHM6Ly9m
b3J1bS5kamkuY29tL2ZvcnVtLnBocD9tb2Q9cmVkaXJlY3QmdGlkPTMzNzU2NSZnb3RvPWxhc3Rw
b3N0I2xhc3Rwb3N0Pgo+Pgo+Pgo+PiDYs9in2YrYqtmI2KrZitmDKNiz2YTYt9mG2Kkg2LnZhdin
2YbCriktIDA1Mzc0NjY1MzkgCj4+Cj4+IE5ldyAKPj4gPGh0dHBzOi8vZm9ydW0uZGppLmNvbS9m
b3J1bS5waHA/bW9kPXJlZGlyZWN0JnRpZD0zMzc1NjYmZ290bz1sYXN0cG9zdCNsYXN0cG9zdD4K
Pj4KPj4KPj4g2LPYp9mK2KrZiNiq2YrZgyjYtdmK2K/ZhNmK2KkpLTA1Mzc0NjY1Mzkg2KfZhNix
2YrYp9i2Cj4+Cj4+IE5ldyAKPj4gPGh0dHBzOi8vZm9ydW0uZGppLmNvbS9mb3J1bS5waHA/bW9k
PXJlZGlyZWN0JnRpZD0zMzc1NjcmZ290bz1sYXN0cG9zdCNsYXN0cG9zdD4KPj4KPj4g2YXZg9ip
ICjYs9in2YrYqtmI2KrZitmDwq4p2YXZitiy2YjYqNix2LPYqtmI2YQgLSAwNTM3NDY2NTM5IAo+
Pgo+PiDCrtiz2KfZitiq2YjYqtmK2YMo2LXZitiv2YTZitipKS0wNTM3NDY2NTM5INis2K/YqQo+
Pgo+Pgo+PiDZgdmKIFN1bmRheSwgQXVndXN0IDE3LCAyMDI1INmB2Yog2KrZhdin2YUg2KfZhNiz
2KfYudipIDE6MTk6MjnigK9BTSBVVEMtN9iMINmD2KrYqCDYrdio2YjYqCAKPj4g2LPYp9mK2KrZ
iNiq2YMg4oCTINmG2LPYqNipINmG2KzYp9itIDk12aog2LHYs9in2YTYqSDZhti12YfYpzoKPj4K
Pj4+INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNix2YrYp9i2IDA1Mzc0NjY1MzkgI9in2YTYs9i5
2YjYr9mK2Kkg2YTZhNil2KzZh9in2LYg2KfZhNii2YXZhiDZhdi5INivLiDZhtmK2LHZhdmK2YYg
fCB8IAo+Pj4g2KfZhNix2YrYp9i2INis2K/YqSDZhdmD2Kkg2KfZhNiv2YXYp9mFCj4+Pgo+Pj4g
2KfZg9iq2LTZgdmKINmF2Lkg2K8uINmG2YrYsdmF2YrZhtiMINin2YTZiNmD2YrZhCDYp9mE2LHY
s9mF2Yog2YTYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDZ
g9mK2YHZitipIAo+Pj4g2KfZhNil2KzZh9in2LYg2KfZhNi32KjZiiDYp9mE2KLZhdmGINio2KfY
s9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMgMjAwIChNaXNvcHJvc3RvbCkg2KjYpdi02LHYp9mB
INi32KjZiiAKPj4+INmI2LPYsdmR2YrYqSDYqtin2YXYqS4g2KrZiNi12YrZhCDYs9ix2YrYuSDZ
gdmKINin2YTYsdmK2KfYttiMINis2K/YqdiMINmF2YPYqdiMINin2YTYr9mF2KfZhSDZiNio2KfZ
gtmKINin2YTZhdiv2YYuIPCfk54gCj4+PiAwNTM3NDY2NTM5Cj4+Pgo+Pj4g2YHZiiDYp9mE2LPZ
htmI2KfYqiDYp9mE2KPYrtmK2LHYqdiMINij2LXYqNit2Kog2K3YqNmI2Kgg2LPYp9mK2KrZiNiq
2YMgPGh0dHBzOi8va3NhY3l0b3RlYy5jb20vPiAKPj4+IChNaXNvcHJvc3RvbCkg2K7Zitin2LHZ
i9inINi32KjZitmL2Kcg2YXYudix2YjZgdmL2Kcg2YjZgdi52ZHYp9mE2YvYpyDZhNil2YbZh9in
2KEg2KfZhNit2YXZhCDYp9mE2YXYqNmD2LEg2KjYt9ix2YrZgtipIAo+Pj4g2KLZhdmG2Kkg2KrY
rdiqINil2LTYsdin2YEg2YXYrtiq2LXZitmGLiDZiNmF2Lkg2KfZhtiq2LTYp9ixINin2YTZhdmG
2KrYrNin2Kog2KfZhNmF2YLZhNiv2KnYjCDYo9i12KjYrSDZhdmGINin2YTYttix2YjYsdmKINin
2YTYrdi12YjZhCAKPj4+INi52YTZiSDYp9mE2K/ZiNin2KEg2YXZhiDZhdi12K/YsSDZhdmI2KvZ
iNmCINmI2YXYudiq2YXYry4KPj4+INivLiDZhtmK2LHZhdmK2YbYjCDYqNi12YHYqtmH2Kcg2KfZ
hNmI2YPZitmEINin2YTYsdiz2YXZiiDZhNit2KjZiNioINiz2KfZitiq2YjYqtmDINmB2Yog2KfZ
hNiz2LnZiNiv2YrYqdiMINiq2YLYr9mFINmE2YPZkCAKPj4+INmF2YbYqtis2YvYpyDYo9i12YTZ
itmL2Kcg2KjYrNmI2K/YqSDZhdi22YXZiNmG2KnYjCDZhdi5INin2LPYqti02KfYsdipINi32KjZ
itipINmF2KrYrti12LXYqSDZiNiz2LHZkdmK2Kkg2KrYp9mF2Kkg2YHZiiDYp9mE2KrYudin2YXZ
hCAKPj4+INmI2KfZhNiq2YjYtdmK2YQuCj4+Pgo+Pj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tCj4+Pgo+Pj4g2YXYpyDZh9mIINiv2YjYp9ihINiz2KfZitiq2YjYqtmD2J8KPj4+Cj4+
PiDYs9in2YrYqtmI2KrZgyAo2KfZhNmF2KfYr9ipINin2YTZgdi52KfZhNipINmF2YrYstmI2KjY
sdmI2LPYqtmI2YQpINiv2YjYp9ihINmF2Y/Yudiq2YXYryDZgdmKINin2YTZhdis2KfZhCDYp9mE
2LfYqNmK2IwgCj4+PiDZiNmK2Y/Ys9iq2K7Yr9mFINio2KzYsdi52KfYqiDYr9mC2YrZgtipINmE
2KXZhtmH2KfYoSDYp9mE2K3ZhdmEINin2YTZhdio2YPYsdiMINmI2LnZhNin2Kwg2K3Yp9mE2KfY
qiDYt9io2YrYqSDYo9iu2LHZiSDZhdir2YQg2YLYsdit2KkgCj4+PiDYp9mE2YXYudiv2KkuINi5
2YbYryDYp9iz2KrYrtiv2KfZhdmHINmE2YTYpdis2YfYp9i22Iwg2YrYudmF2YQg2LnZhNmJINiq
2K3ZgdmK2LIg2KrZgtmE2LXYp9iqINin2YTYsdit2YUg2YjYpdmB2LHYp9i6INmF2K3YqtmI2YrY
p9iq2YcgCj4+PiDYrtmE2KfZhCDZgdiq2LHYqSDZgti12YrYsdip2Iwg2YXZhdinINmK2KzYudmE
2Ycg2K7Zitin2LHZi9inINmB2LnYp9mE2YvYpyDZiNii2YXZhtmL2Kcg2LnZhtivINil2LTYsdin
2YEg2LfYqNmK2Kgg2YXYrtiq2LUuCj4+Pgo+Pj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tCj4+Pgo+Pj4g2KPZh9mF2YrYqSDYp9mE2K3YtdmI2YQg2LnZhNmJINiz2KfZitiq2YjYqtmD
INmF2YYg2YXYtdiv2LEg2YXZiNir2YjZggo+Pj4KPj4+INmB2Yog2KfZhNiz2LnZiNiv2YrYqdiM
INiq2KrZiNin2KzYryDYp9mE2YPYq9mK2LEg2YXZhiDYp9mE2YLZhtmI2KfYqiDYutmK2LEg2KfZ
hNmF2YjYq9mI2YLYqSDYp9mE2KrZiiDYqtio2YrYuSDZhdmG2KrYrNin2KogCj4+PiDZhdis2YfZ
iNmE2Kkg2KfZhNmF2LXYr9ixINmC2K8g2KrYpNiv2Yog2KXZhNmJINmF2K7Yp9i32LEg2LXYrdmK
2Kkg2KzYs9mK2YXYqS4KPj4+INivLiDZhtmK2LHZhdmK2YYg2KrYttmF2YYg2YTZgzoKPj4+IOKc
lO+4jyDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYo9i12YTZitipIDEwMCUKPj4+IOKclO+4jyDY
qtin2LHZitiuINi12YTYp9it2YrYqSDYrdiv2YrYqwo+Pj4g4pyU77iPINil2LHYtNin2K/Yp9iq
INi32KjZitipINiv2YLZitmC2Kkg2YTZhNin2LPYqtiu2K/Yp9mFCj4+PiDinJTvuI8g2LPYsdmR
2YrYqSDYqtin2YXYqSDZgdmKINin2YTYqtmI2LXZitmECj4+PiDinJTvuI8g2K/YudmFINmI2KfY
s9iq2LTYp9ix2Kkg2LnZhNmJINmF2K/Yp9ixINin2YTYs9in2LnYqQo+Pj4KPj4+IC0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Pj4KPj4+INmE2YXYp9iw2Kcg2KrYrtiq2KfYsdmK2YYg
2K8uINmG2YrYsdmF2YrZhtifCj4+PiAgICAKPj4+ICAgIC0gCj4+PiAgICAKPj4+ICAgINin2YTY
rtio2LHYqSDYp9mE2LfYqNmK2Kk6INivLiDZhtmK2LHZhdmK2YYg2YXYqtiu2LXYtdipINmB2Yog
2KfZhNin2LPYqti02KfYsdin2Kog2KfZhNi32KjZitipINin2YTZhtiz2KfYptmK2KnYjCDZiNiq
2YLYr9mFIAo+Pj4gICAg2YTZg9mQINiv2LnZhdmL2Kcg2YXZh9mG2YrZi9inINmC2KjZhCDZiNij
2KvZhtin2KEg2YjYqNi52K/Yp9iz2KrYrtiv2KfZhSDYs9in2YrYqtmI2KrZgyAKPj4+ICAgIDxo
dHRwczovL3NhdWRpZXJzYWEuY29tLz4uCj4+PiAgICAKPj4+ICAgIC0gCj4+PiAgICAKPj4+ICAg
INin2YTYqtmI2LXZitmEINin2YTYs9ix2YrYuTog2KrYuti32YrYqSDZhNis2YXZiti5INin2YTZ
hdiv2YYg2KfZhNiz2LnZiNiv2YrYqdiMINio2YXYpyDZgdmKINiw2YTZgyDYp9mE2LHZitin2LbY
jCDYrNiv2KnYjCAKPj4+ICAgINmF2YPYqdiMINin2YTYr9mF2KfZhdiMINin2YTYrtio2LHYjCDY
p9mE2LfYp9im2YEg2YjYutmK2LHZh9inLgo+Pj4gICAgCj4+PiAgICAtIAo+Pj4gICAgCj4+PiAg
ICDYrdmF2KfZitipINiu2LXZiNi12YrYqtmDOiDZitiq2YUg2KfZhNiq2LrZhNmK2YEg2KjYt9ix
2YrZgtipINiq2LbZhdmGINin2YTYs9ix2ZHZitipINin2YTZg9in2YXZhNipLgo+Pj4gICAgCj4+
PiAgICAtIAo+Pj4gICAgCj4+PiAgICDYp9mE2KrZiNmD2YrZhCDYp9mE2LHYs9mF2Yo6INi02LHY
p9ih2YMg2YrYqtmFINmF2KjYp9i02LHYqSDZhdmGINin2YTZhdi12K/YsSDYp9mE2YXYudiq2YXY
r9iMINio2LnZitiv2YvYpyDYudmGIAo+Pj4gICAg2KfZhNmF2K7Yp9i32LEuCj4+PiAgICAKPj4+
ICAgIAo+Pj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4+Pgo+Pj4g2YPZitmB2YrY
qSDYt9mE2Kgg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YXZhiDYry4g2YbZitix2YXZitmGCj4+
PiAgICAKPj4+ICAgIDEuIAo+Pj4gICAgCj4+PiAgICDYp9mE2KrZiNin2LXZhCDYudio2LEg2YjY
p9iq2LPYp9ioINi52YTZiSDYp9mE2LHZgtmFOiDwn5OeIDA1Mzc0NjY1MzkKPj4+ICAgIAo+Pj4g
ICAgMi4gCj4+PiAgICAKPj4+ICAgINi02LHYrSDYp9mE2K3Yp9mE2Kkg2KfZhNi12K3ZitipINmI
2YHYqtix2Kkg2KfZhNit2YXZhC4KPj4+ICAgIAo+Pj4gICAgMy4gCj4+PiAgICAKPj4+ICAgINin
2LPYqtmE2KfZhSDYp9mE2KXYsdi02KfYr9in2Kog2KfZhNi32KjZitipINin2YTZhdmG2KfYs9io
2Kkg2YjYp9mE2KzYsdi52Kkg2KfZhNmF2YjYtdmJINio2YfYpy4KPj4+ICAgIAo+Pj4gICAgNC4g
Cj4+PiAgICAKPj4+ICAgINin2LPYqtmE2KfZhSDYp9mE2K3YqNmI2Kgg2K7ZhNin2YQg2YHYqtix
2Kkg2YLYtdmK2LHYqSDYudio2LEg2K7Yr9mF2Kkg2KrZiNi12YrZhCDYotmF2YbYqSDZiNiz2LHZ
itipLgo+Pj4gICAgCj4+PiAgICAKPj4+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+
Pj4KPj4+INiq2YbYqNmK2Ycg2LfYqNmKINmF2YfZhQo+Pj4gICAgCj4+PiAgICAtIAo+Pj4gICAg
Cj4+PiAgICDZitis2Kgg2KfYs9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMg2YHZgti3INiq2K3Y
qiDYpdi02LHYp9mBINi32KjZiiDZhdiu2KrYtS4KPj4+ICAgIAo+Pj4gICAgLSAKPj4+ICAgIAo+
Pj4gICAg2YTYpyDZitmP2YbYtditINio2KfYs9iq2K7Yr9in2YXZhyDZgdmKINit2KfZhNin2Kog
2KfZhNit2YXZhCDYp9mE2YXYqtij2K7YsS4KPj4+ICAgIAo+Pj4gICAgLSAKPj4+ICAgIAo+Pj4g
ICAg2YHZiiDYrdin2YQg2YjYrNmI2K8g2KPZhdix2KfYtiDZhdiy2YXZhtipINij2Ygg2K3Yp9mE
2KfYqiDYrtin2LXYqdiMINmK2KzYqCDYp9iz2KrYtNin2LHYqSDYp9mE2LfYqNmK2Kgg2YLYqNmE
IAo+Pj4gICAg2KfZhNin2LPYqtiu2K/Yp9mFLgo+Pj4gICAgCj4+PiAgICAKPj4+IC0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Pj4KPj4+INiu2K/Zhdin2Kog2KXYttin2YHZitipINmF
2YYg2K8uINmG2YrYsdmF2YrZhgo+Pj4gICAgCj4+PiAgICAtIAo+Pj4gICAgCj4+PiAgICDZhdiq
2KfYqNi52Kkg2KfZhNit2KfZhNipINio2LnYryDYp9mE2KfYs9iq2K7Yr9in2YUuCj4+PiAgICAK
Pj4+ICAgIC0gCj4+PiAgICAKPj4+ICAgINiq2YjZgdmK2LEg2YXYudmE2YjZhdin2Kog2K3ZiNmE
INin2YTYotir2KfYsSDYp9mE2KzYp9mG2KjZitipINin2YTYt9io2YrYudmK2Kkg2YjZg9mK2YHZ
itipINin2YTYqti52KfZhdmEINmF2LnZh9inLgo+Pj4gICAgCj4+PiAgICAtIAo+Pj4gICAgCj4+
PiAgICDYpdix2LTYp9ivINin2YTZhdix2YrYttipINil2YTZiSDYo9mB2LbZhCDZhdmF2KfYsdiz
2KfYqiDYp9mE2LPZhNin2YXYqSDYp9mE2LfYqNmK2KkuCj4+PiAgICAKPj4+ICAgIAo+Pj4gLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4+Pgo+Pj4g2K7ZhNin2LXYqQo+Pj4KPj4+INin
2K7YqtmK2KfYsSDYp9mE2YXYtdiv2LEg2KfZhNmF2YjYq9mI2YIg2LnZhtivINi02LHYp9ihINit
2KjZiNioINiz2KfZitiq2YjYqtmDIAo+Pj4gPGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vYS9j
aHJvbWl1bS5vcmcvZy9zZWN1cml0eS1kZXYvYy9yaHJQcGl2Q1FHTS9tL1hpaFVCaVNMQUFBSj4g
Cj4+PiDZgdmKINin2YTYs9i52YjYr9mK2Kkg2YfZiCDYp9mE2LbZhdin2YYg2KfZhNmI2K3Zitiv
INmE2LPZhNin2YXYqtmD2ZAuCj4+PiDZhdi5INivLiDZhtmK2LHZhdmK2YbYjCDYs9iq2K3YtdmE
2YrZhiDYudmE2Ykg2KfZhNmF2YbYqtisINin2YTYo9i12YTZitiMINin2YTYpdix2LTYp9ivINin
2YTYt9io2Yog2KfZhNmF2KrYrti12LXYjCAKPj4+INmI2KfZhNiq2YjYtdmK2YQg2KfZhNiz2LHZ
iiDYo9mK2YbZhdinINmD2YbYqtmQINmB2Yog2KfZhNmF2YXZhNmD2KkuCj4+Pgo+Pj4g8J+TniDZ
hNmE2KrZiNin2LXZhCDZiNin2YTYt9mE2Kgg2LnYqNixINmI2KfYqtiz2KfYqDogMDUzNzQ2NjUz
OQo+Pj4g2KfZhNmF2K/ZhiDYp9mE2YXYuti32KfYqTog2KfZhNix2YrYp9i2IOKAkyDYrNiv2Kkg
4oCTINmF2YPYqSDigJMg2KfZhNiv2YXYp9mFIOKAkyDYp9mE2K7YqNixIOKAkyDYp9mE2LfYp9im
2YEg4oCTINin2YTZhdiv2YrZhtipIAo+Pj4g2KfZhNmF2YbZiNix2Kkg4oCTINij2KjZh9inIOKA
kyDYrNin2LLYp9mGIOKAkyDYqtio2YjZgy4KPj4+Cj4+PiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0KPj4+Cj4+PiAgCj4+Pgo+Pj4g2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI
2K/Zitip2Iwg2LPYp9mK2KrZiNiq2YMg2KfZhNix2YrYp9i22Iwg2LPYp9mK2KrZiNiq2YMg2KzY
r9ip2Iwg2LPYp9mK2KrZiNiq2YMg2YXZg9ip2Iwg2LPYp9mK2KrZiNiq2YMgCj4+PiDYp9mE2K/Z
hdin2YXYjCDYtNix2KfYoSDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDY
rdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KXYrNmH2KfYttiMINiz2KfZitiq2YjYqtmDINij
2LXZhNmK2IwgCj4+PiDYs9in2YrYqtmI2KrZgyAyMDDYjCBNaXNvcHJvc3RvbCDYp9mE2LPYudmI
2K/Zitip2Iwg2LPYp9mK2KrZiNiq2YMg2KfZhNmG2YfYr9mK2IwgCj4+PiBodHRwczovL2tzYWN5
dG90ZWMuY29tLyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDYr9mD2KrZiNix2Kkg2YbZitix2YXZ
itmGINiz2KfZitiq2YjYqtmDLgo+Pj4KPj4+INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZ
iNiv2YrYqdiMINiz2KfZitiq2YjYqtmDINin2YTYsdmK2KfYttiMINiz2KfZitiq2YjYqtmDINis
2K/YqdiMINiz2KfZitiq2YjYqtmDINmF2YPYqdiMINiz2KfZitiq2YjYqtmDIAo+Pj4g2KfZhNiv
2YXYp9mF2Iwg2LTYsdin2KEg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg
2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNil2KzZh9in2LbYjCDYs9in2YrYqtmI2KrZgyDY
o9i12YTZitiMIAo+Pj4g2LPYp9mK2KrZiNiq2YMgMjAw2IwgTWlzb3Byb3N0b2wg2KfZhNiz2LnZ
iNiv2YrYqdiMINiz2KfZitiq2YjYqtmDINin2YTZhtmH2K/ZitiMINin2YTYpdis2YfYp9i2INin
2YTYt9io2Yog2YHZiiAKPj4+INin2YTYs9i52YjYr9mK2KnYjCDYr9mD2KrZiNix2Kkg2YbZitix
2YXZitmGINiz2KfZitiq2YjYqtmDLgo+Pj4KPj4+DQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBt
ZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJr
YXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3Ag
cmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1
YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNpdCBo
dHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2LzRmMjcyOTMyLWM2YjAt
NGQ1MS04MGJlLTMwODUyYTUzMzY2OG4lNDBnb29nbGVncm91cHMuY29tLgo=
------=_Part_4097_506652436.1757575194694
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: =
0pt;"><span style=3D"font-size: 14pt; font-family: Arial, sans-serif; color=
: rgb(47, 79, 79); background-color: transparent; font-weight: 700; font-va=
riant-numeric: normal; font-variant-east-asian: normal; font-variant-altern=
ates: normal; font-variant-position: normal; font-variant-emoji: normal; ve=
rtical-align: baseline; white-space-collapse: preserve;">=D9=81=D9=8A 3 =D8=
=AE=D8=B7=D9=88=D8=A7=D8=AA =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=
=B6 </span><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; =
color: rgb(0, 0, 0); background-color: transparent; font-variant-numeric: n=
ormal; font-variant-east-asian: normal; font-variant-alternates: normal; fo=
nt-variant-position: normal; font-variant-emoji: normal; vertical-align: ba=
seline; white-space-collapse: preserve;">=E2=81=89=EF=B8=8F</span><span sty=
le=3D"font-size: 19pt; font-family: Arial, sans-serif; color: rgb(34, 54, 6=
9); background-color: transparent; font-weight: 700; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;">0531601967</span><span style=3D"f=
ont-size: 15pt; font-family: Arial, sans-serif; color: rgb(47, 79, 79); fon=
t-variant-numeric: normal; font-variant-east-asian: normal; font-variant-al=
ternates: normal; font-variant-position: normal; font-variant-emoji: normal=
; vertical-align: baseline; white-space-collapse: preserve;"> </span><span =
style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, =
0); background-color: transparent; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; white-spa=
ce-collapse: preserve;">=E2=81=89=EF=B8=8F </span><span style=3D"font-size:=
 14pt; font-family: Arial, sans-serif; color: rgb(47, 79, 79); background-c=
olor: transparent; font-weight: 700; font-variant-numeric: normal; font-var=
iant-east-asian: normal; font-variant-alternates: normal; font-variant-posi=
tion: normal; font-variant-emoji: normal; vertical-align: baseline; white-s=
pace-collapse: preserve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 </span=
><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb=
(0, 0, 0); background-color: transparent; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; wh=
ite-space-collapse: preserve;">=F0=9F=92=B1</span><span style=3D"font-size:=
 14pt; font-family: Arial, sans-serif; color: rgb(17, 85, 204); background-=
color: transparent; font-weight: 700; font-variant-numeric: normal; font-va=
riant-east-asian: normal; font-variant-alternates: normal; font-variant-pos=
ition: normal; font-variant-emoji: normal; vertical-align: baseline; white-=
space-collapse: preserve;"> </span><span style=3D"font-size: 16.5pt; font-f=
amily: Arial, sans-serif; color: rgb(0, 0, 0); font-weight: 700; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;">=D9=85=D9=8A=D8=B2=D9=
=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84 =D9=85=D9=8A=D9=81=D9=8A=D8=
=A8=D8=B1=D9=8A=D8=B3=D8=AA=D9=88=D9=86</span><span style=3D"font-size: 20p=
t; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: t=
ransparent; font-weight: 700; font-style: italic; font-variant-numeric: nor=
mal; font-variant-east-asian: normal; font-variant-alternates: normal; font=
-variant-position: normal; font-variant-emoji: normal; vertical-align: base=
line; white-space-collapse: preserve;"> </span><span style=3D"font-size: 15=
pt; font-family: Arial, sans-serif; color: rgb(47, 79, 79); font-variant-nu=
meric: normal; font-variant-east-asian: normal; font-variant-alternates: no=
rmal; font-variant-position: normal; font-variant-emoji: normal; vertical-a=
lign: baseline; white-space-collapse: preserve;">=F0=9F=94=86</span><span s=
tyle=3D"font-size: 16.5pt; font-family: Arial, sans-serif; color: rgb(0, 0,=
 0); font-weight: 700; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; white-space-collapse:=
 preserve;"> =D9=85=D8=AA=D9=88=D9=81=D8=B1=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B1=D9=8A=D8=A7=D8=B6 </span><span style=3D"font-size: 20pt; font-family=
: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transparent; fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;">=D8=8F</span><span style=3D"font-size: 20pt; font-family: Arial, sans-=
serif; color: rgb(0, 0, 0); background-color: transparent; font-weight: 700=
; font-style: italic; font-variant-numeric: normal; font-variant-east-asian=
: normal; font-variant-alternates: normal; font-variant-position: normal; f=
ont-variant-emoji: normal; vertical-align: baseline; white-space-collapse: =
preserve;"> </span><span style=3D"font-size: 11pt; font-family: Arial, sans=
-serif; color: rgb(0, 0, 0); background-color: transparent; font-variant-nu=
meric: normal; font-variant-east-asian: normal; font-variant-alternates: no=
rmal; font-variant-position: normal; font-variant-emoji: normal; vertical-a=
lign: baseline; white-space-collapse: preserve;">=F0=9F=8C=8B</span><span s=
tyle=3D"font-size: 19pt; font-family: Arial, sans-serif; color: rgb(34, 54,=
 69); background-color: transparent; font-weight: 700; font-variant-numeric=
: normal; font-variant-east-asian: normal; font-variant-alternates: normal;=
 font-variant-position: normal; font-variant-emoji: normal; vertical-align:=
 baseline; white-space-collapse: preserve;">00966531601967 </span><span sty=
le=3D"font-size: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0);=
 background-color: transparent; font-weight: 700; font-style: italic; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; white-space-collapse: preserve;">=D8=A8=D8=B3=D8=
=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9</span></p><p dir=3D"rtl" style=3D"=
line-height: 1.38; text-align: center; margin-top: 0pt; margin-bottom: 0pt;=
"><span style=3D"font-size: 20pt; font-family: Arial, sans-serif; color: rg=
b(0, 0, 0); background-color: transparent; font-weight: 700; font-style: it=
alic; font-variant-numeric: normal; font-variant-east-asian: normal; font-v=
ariant-alternates: normal; font-variant-position: normal; font-variant-emoj=
i: normal; vertical-align: baseline; white-space-collapse: preserve;">Cytot=
ec=C2=A0 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6</span><span style=3D"font-siz=
e: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-co=
lor: transparent; font-weight: 700; font-variant-numeric: normal; font-vari=
ant-east-asian: normal; font-variant-alternates: normal; font-variant-posit=
ion: normal; font-variant-emoji: normal; vertical-align: baseline; white-sp=
ace-collapse: preserve;">=E3=80=98</span><span style=3D"font-size: 20pt; fo=
nt-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transp=
arent; font-weight: 700; font-style: italic; font-variant-numeric: normal; =
font-variant-east-asian: normal; font-variant-alternates: normal; font-vari=
ant-position: normal; font-variant-emoji: normal; vertical-align: baseline;=
 white-space-collapse: preserve;">Misoprostol</span></p><p dir=3D"rtl" styl=
e=3D"line-height: 1.38; text-align: center; margin-top: 0pt; margin-bottom:=
 0pt;"><span style=3D"font-size: 20pt; font-family: Arial, sans-serif; colo=
r: rgb(0, 0, 0); background-color: transparent; font-weight: 700; font-vari=
ant-numeric: normal; font-variant-east-asian: normal; font-variant-alternat=
es: normal; font-variant-position: normal; font-variant-emoji: normal; vert=
ical-align: baseline; white-space-collapse: preserve;">=E3=80=99=C2=A0 </sp=
an><span style=3D"font-size: 20pt; font-family: Arial, sans-serif; color: r=
gb(51, 51, 51); background-color: transparent; font-weight: 700; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;">=E2=9C=94=EF=B8=8F</s=
pan><span style=3D"font-size: 20pt; font-family: Arial, sans-serif; color: =
rgb(0, 0, 0); background-color: transparent; font-weight: 700; font-style: =
italic; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; white-space-collapse: preserve;"> =
=D8=AA=D9=88=D8=A7=D8=B5=D9=84=D9=8A =D9=85=D8=B9=D9=86=D8=A7 =D8=A8=D8=B3=
=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =C2=A0 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AC=D8=AF=D8=A9 </span><span style=3D"fo=
nt-size: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); backgro=
und-color: transparent; font-weight: 700; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; wh=
ite-space-collapse: preserve;">=E2=95=AC =D9=85=D9=83=D8=A9 =E2=95=AC =D8=
=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=E2=95=AC =D8=A7=D9=84=D8=B4=D8=B1=D9=82=
=D9=8A=D8=A9 =E2=95=AC =D8=AC=D9=8A=D8=B2=D8=A7=D9=86 =E2=95=AC =D8=AE=D9=
=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7 =E2=95=AC</span><span style=3D"fon=
t-size: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); backgrou=
nd-color: transparent; font-weight: 700; font-style: italic; font-variant-n=
umeric: normal; font-variant-east-asian: normal; font-variant-alternates: n=
ormal; font-variant-position: normal; font-variant-emoji: normal; vertical-=
align: baseline; white-space-collapse: preserve;"> </span><span style=3D"fo=
nt-size: 13.5pt; font-family: Arial, sans-serif; color: rgb(0, 29, 53); fon=
t-weight: 700; font-style: italic; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; white-spa=
ce-collapse: preserve;">=D9=88=D8=A7=D9=84=D8=B1=D9=81=D8=A7=D8=B9=D8=8C =
=D9=88=D9=85=D8=AF=D9=8A=D9=86=D8=A9 =D8=B9=D9=8A=D8=B3=D9=89=D8=8C =D9=88=
=D9=85=D8=AF=D9=8A=D9=86=D8=A9 =D8=AD=D9=85=D8=AF=D8=8C =D9=88=D8=B3=D8=AA=
=D8=B1=D8=A9</span><span style=3D"font-size: 20pt; font-family: Arial, sans=
-serif; color: rgb(0, 0, 0); background-color: transparent; font-weight: 70=
0; font-style: italic; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; white-space-collapse:=
 preserve;"> =D9=85=D8=AA=D9=88=D9=81=D8=B1 =D8=A8=D8=AC=D9=85=D9=8A=D8=B9 =
=D8=A7=D9=84=D9=85=D8=AF=D9=86 </span><span style=3D"font-size: 20pt; font-=
family: Arial, sans-serif; color: rgb(51, 51, 51); background-color: transp=
arent; font-weight: 700; font-variant-numeric: normal; font-variant-east-as=
ian: normal; font-variant-alternates: normal; font-variant-position: normal=
; font-variant-emoji: normal; vertical-align: baseline; white-space-collaps=
e: preserve;">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size: 20pt; fon=
t-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transpa=
rent; font-weight: 700; font-style: italic; font-variant-numeric: normal; f=
ont-variant-east-asian: normal; font-variant-alternates: normal; font-varia=
nt-position: normal; font-variant-emoji: normal; vertical-align: baseline; =
white-space-collapse: preserve;">=D9=85=D8=B9 =D8=A7=D8=B3=D8=AA=D8=B4=D8=
=A7=D8=B1=D8=A9 =D9=85=D8=AC=D8=A7=D9=86=D9=8A=D8=A9 =D8=B6=D9=85=D8=A7=D9=
=86 =D8=A7=D9=84=D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=A9 =D8=A8=D8=A7=D9=84=D8=
=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=D8=B9</span><spa=
n style=3D"font-size: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0=
, 0); background-color: transparent; font-weight: 700; font-variant-numeric=
: normal; font-variant-east-asian: normal; font-variant-alternates: normal;=
 font-variant-position: normal; font-variant-emoji: normal; vertical-align:=
 baseline; white-space-collapse: preserve;">=C2=A0</span></p><br /><br /><d=
iv class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=
=8A =D8=A7=D9=84=D8=AC=D9=85=D8=B9=D8=A9=D8=8C 5 =D8=B3=D8=A8=D8=AA=D9=85=
=D8=A8=D8=B1 2025 =D9=81=D9=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=
=D8=A7=D8=B9=D8=A9 10:01:13 =D8=B5 UTC-7=D8=8C =D9=83=D8=AA=D8=A8 hayata...=
@gmail.com =D8=B1=D8=B3=D8=A7=D9=84=D8=A9 =D9=86=D8=B5=D9=87=D8=A7:<br/></d=
iv><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-r=
ight: 1px solid rgb(204, 204, 204); padding-right: 1ex;"><p dir=3D"rtl" sty=
le=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"fon=
t-size:15pt;font-family:Arial,sans-serif;color:rgb(0,0,0);font-weight:700;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-0537466539// =D8=AD=D8=
=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=
=B1=D9=8A=D8=A7=D8=B6</span></p><br><br><p dir=3D"rtl" style=3D"line-height=
:1.2;margin-top:4pt;margin-bottom:0pt"><span style=3D"font-size:13.5pt;font=
-family:&quot;Microsoft Yahei&quot;;color:rgb(0,0,0);background-color:rgb(2=
45,245,245);font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 (=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=
=D8=B6=C2=AE)</span><span style=3D"font-size:16pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">0537466539 =D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9</span></p><p dir=3D"rtl" =
style=3D"line-height:1.2;margin-top:2pt;margin-bottom:0pt"><a href=3D"https=
://forum.dji.com/forum.php?mod=3Dredirect&amp;tid=3D337565&amp;goto=3Dlastp=
ost#lastpost" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"ht=
tps://www.google.com/url?hl=3Dar&amp;q=3Dhttps://forum.dji.com/forum.php?mo=
d%3Dredirect%26tid%3D337565%26goto%3Dlastpost%23lastpost&amp;source=3Dgmail=
&amp;ust=3D1757661572547000&amp;usg=3DAOvVaw129I2SIF_yiu9YQRf8jCPg"><span s=
tyle=3D"font-size:9pt;font-family:&quot;Microsoft Yahei&quot;;color:rgb(242=
,108,79);background-color:rgb(245,245,245);font-weight:700;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline">New</span></a></p><br><br><p dir=3D"rtl" style=3D"l=
ine-height:1.2;margin-top:4pt;margin-bottom:0pt"><span style=3D"font-size:1=
3.5pt;font-family:&quot;Microsoft Yahei&quot;;color:rgb(242,108,79);backgro=
und-color:rgb(245,245,245);font-weight:700;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83(=D8=B3=D9=84=D8=B7=
=D9=86=D8=A9 =D8=B9=D9=85=D8=A7=D9=86=C2=AE)- </span><span style=3D"font-si=
ze:16pt;font-family:Arial,sans-serif;color:rgb(0,0,0);font-weight:700;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">0537466539=C2=A0</span></p><p dir=3D"rtl=
" style=3D"line-height:1.2;margin-top:2pt;margin-bottom:0pt"><a href=3D"htt=
ps://forum.dji.com/forum.php?mod=3Dredirect&amp;tid=3D337566&amp;goto=3Dlas=
tpost#lastpost" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"=
https://www.google.com/url?hl=3Dar&amp;q=3Dhttps://forum.dji.com/forum.php?=
mod%3Dredirect%26tid%3D337566%26goto%3Dlastpost%23lastpost&amp;source=3Dgma=
il&amp;ust=3D1757661572547000&amp;usg=3DAOvVaw2YyGprjApLKw-HvJ8HNyHd"><span=
 style=3D"font-size:9pt;font-family:&quot;Microsoft Yahei&quot;;color:rgb(2=
42,108,79);background-color:rgb(245,245,245);font-weight:700;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">New</span></a></p><br><br><p dir=3D"rtl" style=3D=
"line-height:1.2;margin-top:4pt;margin-bottom:0pt"><span style=3D"font-size=
:13.5pt;font-family:&quot;Microsoft Yahei&quot;;color:rgb(0,0,0);background=
-color:rgb(245,245,245);font-weight:700;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=
=84=D9=8A=D8=A9)-</span><span style=3D"font-size:16pt;font-family:Arial,san=
s-serif;color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line">0537466539 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6</span></p><p dir=3D"r=
tl" style=3D"line-height:1.2;margin-top:2pt;margin-bottom:0pt"><a href=3D"h=
ttps://forum.dji.com/forum.php?mod=3Dredirect&amp;tid=3D337567&amp;goto=3Dl=
astpost#lastpost" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=
=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps://forum.dji.com/forum.=
php?mod%3Dredirect%26tid%3D337567%26goto%3Dlastpost%23lastpost&amp;source=
=3Dgmail&amp;ust=3D1757661572547000&amp;usg=3DAOvVaw0lEmIZNbank6vWzExgPOcz"=
><span style=3D"font-size:9pt;font-family:&quot;Microsoft Yahei&quot;;color=
:rgb(242,108,79);background-color:rgb(245,245,245);font-weight:700;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline">New</span></a></p><p dir=3D"rtl" style=3D"l=
ine-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:=
31.5pt;font-family:&quot;Microsoft Yahei&quot;;color:rgb(68,68,68);font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=D9=85=D9=83=D8=A9 (=D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83=C2=AE)=D9=85=D9=8A=D8=B2=D9=88=
=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=84 - </span><span style=3D"font-size:16pt=
;font-family:Arial,sans-serif;color:rgb(0,0,0);font-weight:700;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">0537466539=C2=A0</span></p><br><p dir=3D"rtl" s=
tyle=3D"line-height:1.2;margin-top:4pt;margin-bottom:0pt"><span style=3D"fo=
nt-size:13.5pt;font-family:&quot;Microsoft Yahei&quot;;color:rgb(0,0,0);bac=
kground-color:rgb(245,245,245);font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline">=C2=AE=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83(=D8=B5=
=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-</span><span style=3D"font-size:16pt;font-f=
amily:Arial,sans-serif;color:rgb(0,0,0);font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">0537466539 =D8=AC=D8=AF=D8=A9</span></p><br><br><div c=
lass=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=8A Fr=
iday, September 5, 2025 =D9=81=D9=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=
=D8=B3=D8=A7=D8=B9=D8=A9 10:01:01=E2=80=AFAM UTC-7=D8=8C =D9=83=D8=AA=D8=A8=
 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =E2=80=
=93 =D9=86=D8=B3=D8=A8=D8=A9 =D9=86=D8=AC=D8=A7=D8=AD 95=D9=AA =D8=B1=D8=B3=
=D8=A7=D9=84=D8=A9 =D9=86=D8=B5=D9=87=D8=A7:<br></div><blockquote class=3D"=
gmail_quote" style=3D"margin:0 0 0 0.8ex;border-right:1px solid rgb(204,204=
,204);padding-right:1ex"><p dir=3D"rtl" style=3D"line-height:1.38;margin-to=
p:0pt;margin-bottom:0pt"><span style=3D"font-size:15pt;font-family:Arial,sa=
ns-serif;color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=
=D9=84=D9=8A=D8=A9)-0537466539// =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6</span></p>=
<br><br><p dir=3D"rtl" style=3D"line-height:1.2;margin-top:4pt;margin-botto=
m:0pt"><span style=3D"font-size:13.5pt;font-family:&quot;Microsoft Yahei&qu=
ot;;color:rgb(0,0,0);background-color:rgb(245,245,245);font-weight:700;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=8A=D9=83 (=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=C2=AE)</span><span style=3D=
"font-size:16pt;font-family:Arial,sans-serif;color:rgb(0,0,0);font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">0537466539 =D8=B3=D8=B9=D9=88=D8=
=AF=D9=8A=D8=A9</span></p><p dir=3D"rtl" style=3D"line-height:1.2;margin-to=
p:2pt;margin-bottom:0pt"><a href=3D"https://forum.dji.com/forum.php?mod=3Dr=
edirect&amp;tid=3D337565&amp;goto=3Dlastpost#lastpost" rel=3D"nofollow" tar=
get=3D"_blank" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&a=
mp;q=3Dhttps://forum.dji.com/forum.php?mod%3Dredirect%26tid%3D337565%26goto=
%3Dlastpost%23lastpost&amp;source=3Dgmail&amp;ust=3D1757661572548000&amp;us=
g=3DAOvVaw3evYbgVTHo-sbHHuCX2llV"><span style=3D"font-size:9pt;font-family:=
&quot;Microsoft Yahei&quot;;color:rgb(242,108,79);background-color:rgb(245,=
245,245);font-weight:700;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline">New</span>=
</a></p><br><br><p dir=3D"rtl" style=3D"line-height:1.2;margin-top:4pt;marg=
in-bottom:0pt"><span style=3D"font-size:13.5pt;font-family:&quot;Microsoft =
Yahei&quot;;color:rgb(242,108,79);background-color:rgb(245,245,245);font-we=
ight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=8A=D9=83(=D8=B3=D9=84=D8=B7=D9=86=D8=A9 =D8=B9=D9=85=D8=A7=
=D9=86=C2=AE)- </span><span style=3D"font-size:16pt;font-family:Arial,sans-=
serif;color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">0537466539=C2=A0</span></p><p dir=3D"rtl" style=3D"line-height:1.2;marg=
in-top:2pt;margin-bottom:0pt"><a href=3D"https://forum.dji.com/forum.php?mo=
d=3Dredirect&amp;tid=3D337566&amp;goto=3Dlastpost#lastpost" rel=3D"nofollow=
" target=3D"_blank" data-saferedirecturl=3D"https://www.google.com/url?hl=
=3Dar&amp;q=3Dhttps://forum.dji.com/forum.php?mod%3Dredirect%26tid%3D337566=
%26goto%3Dlastpost%23lastpost&amp;source=3Dgmail&amp;ust=3D1757661572548000=
&amp;usg=3DAOvVaw0_EPZUm6WZ6g8JfMxuo0Lh"><span style=3D"font-size:9pt;font-=
family:&quot;Microsoft Yahei&quot;;color:rgb(242,108,79);background-color:r=
gb(245,245,245);font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">New=
</span></a></p><br><br><p dir=3D"rtl" style=3D"line-height:1.2;margin-top:4=
pt;margin-bottom:0pt"><span style=3D"font-size:13.5pt;font-family:&quot;Mic=
rosoft Yahei&quot;;color:rgb(0,0,0);background-color:rgb(245,245,245);font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-</span><span=
 style=3D"font-size:16pt;font-family:Arial,sans-serif;color:rgb(0,0,0);font=
-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">0537466539 =D8=A7=D9=84=
=D8=B1=D9=8A=D8=A7=D8=B6</span></p><p dir=3D"rtl" style=3D"line-height:1.2;=
margin-top:2pt;margin-bottom:0pt"><a href=3D"https://forum.dji.com/forum.ph=
p?mod=3Dredirect&amp;tid=3D337567&amp;goto=3Dlastpost#lastpost" rel=3D"nofo=
llow" target=3D"_blank" data-saferedirecturl=3D"https://www.google.com/url?=
hl=3Dar&amp;q=3Dhttps://forum.dji.com/forum.php?mod%3Dredirect%26tid%3D3375=
67%26goto%3Dlastpost%23lastpost&amp;source=3Dgmail&amp;ust=3D17576615725480=
00&amp;usg=3DAOvVaw1ANQ_gHU6IFs18Ka1k9C9w"><span style=3D"font-size:9pt;fon=
t-family:&quot;Microsoft Yahei&quot;;color:rgb(242,108,79);background-color=
:rgb(245,245,245);font-weight:700;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">N=
ew</span></a></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;ma=
rgin-bottom:0pt"><span style=3D"font-size:31.5pt;font-family:&quot;Microsof=
t Yahei&quot;;color:rgb(68,68,68);font-weight:700;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=D9=85=D9=83=D8=A9 (=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=8A=D9=83=C2=AE)=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=
=84 - </span><span style=3D"font-size:16pt;font-family:Arial,sans-serif;col=
or:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline">05374=
66539=C2=A0</span></p><br><p dir=3D"rtl" style=3D"line-height:1.2;margin-to=
p:4pt;margin-bottom:0pt"><span style=3D"font-size:13.5pt;font-family:&quot;=
Microsoft Yahei&quot;;color:rgb(0,0,0);background-color:rgb(245,245,245);fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=C2=AE=D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-</s=
pan><span style=3D"font-size:16pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">0537466539 =D8=
=AC=D8=AF=D8=A9</span></p><br><br><div class=3D"gmail_quote"><div dir=3D"au=
to" class=3D"gmail_attr">=D9=81=D9=8A Sunday, August 17, 2025 =D9=81=D9=8A =
=D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9 1:19:29=E2=80=
=AFAM UTC-7=D8=8C =D9=83=D8=AA=D8=A8 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =E2=80=93 =D9=86=D8=B3=D8=A8=D8=A9 =D9=86=D8=
=AC=D8=A7=D8=AD 95=D9=AA =D8=B1=D8=B3=D8=A7=D9=84=D8=A9 =D9=86=D8=B5=D9=87=
=D8=A7:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 0.=
8ex;border-right:1px solid rgb(204,204,204);padding-right:1ex"><p dir=3D"rt=
l" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><span styl=
e=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=
=B6 0537466539 #=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=84=D9=
=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=A2=D9=85=D9=86 =D9=85=D8=
=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 | | =D8=A7=D9=84=D8=B1=D9=
=8A=D8=A7=D8=B6 =D8=AC=D8=AF=D8=A9 =D9=85=D9=83=D8=A9 =D8=A7=D9=84=D8=AF=D9=
=85=D8=A7=D9=85</span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-t=
op:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial=
,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">=D8=A7=D9=83=D8=AA=D8=B4=D9=81=D9=8A =D9=85=D8=B9 =
=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=8C =D8=A7=D9=84=D9=88=D9=83=
=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A =D9=84=D8=AD=D8=A8=D9=88=
=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D9=83=D9=8A=D9=81=D9=8A=D8=A9 =
=D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =
=D8=A7=D9=84=D8=A2=D9=85=D9=86 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=
=D9=85 </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;co=
lor:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200 (Mi=
soprostol)</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif=
;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline"> =D8=A8=D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A =D9=88=
=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9. =D8=AA=D9=88=D8=B5=
=D9=8A=D9=84 =D8=B3=D8=B1=D9=8A=D8=B9 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=
=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=A7=
=D9=84=D8=AF=D9=85=D8=A7=D9=85 =D9=88=D8=A8=D8=A7=D9=82=D9=8A =D8=A7=D9=84=
=D9=85=D8=AF=D9=86. =F0=9F=93=9E 0537466539</span></p><p dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"fon=
t-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">=D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D9=86=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=AE=D9=8A=D8=B1=D8=
=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD=D8=AA</span><a href=3D"https://ksacytote=
c.com/" rel=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"https://=
www.google.com/url?hl=3Dar&amp;q=3Dhttps://ksacytotec.com/&amp;source=3Dgma=
il&amp;ust=3D1757661572548000&amp;usg=3DAOvVaw2QQHmr3qFGeaI9FXoaBs2M"><span=
 style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);back=
ground-color:transparent;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline"> </span><s=
pan style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85,20=
4);background-color:transparent;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;text-decoration-line:underli=
ne;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 </span><span style=3D"=
font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85,204);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;text-decoration-line:unde=
rline;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</=
span></a><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:r=
gb(0,0,0);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline"> (Misoprostol)</span><span style=3D"font-size:11pt;font=
-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline"> =D8=AE=D9=8A=D8=A7=D8=B1=D9=8B=D8=A7 =
=D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=85=D8=B9=D8=B1=D9=88=D9=81=D9=8B=D8=A7 =
=D9=88=D9=81=D8=B9=D9=91=D8=A7=D9=84=D9=8B=D8=A7 =D9=84=D8=A5=D9=86=D9=87=
=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=
=D8=B1 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A2=D9=85=D9=86=D8=A9 =D8=AA=
=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D9=85=D8=AE=D8=AA=D8=B5=D9=8A=
=D9=86. =D9=88=D9=85=D8=B9 =D8=A7=D9=86=D8=AA=D8=B4=D8=A7=D8=B1 =D8=A7=D9=
=84=D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=82=D9=84=D8=
=AF=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD =D9=85=D9=86 =D8=A7=D9=84=D8=B6=D8=
=B1=D9=88=D8=B1=D9=8A =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=
=89 =D8=A7=D9=84=D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=
=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82 =D9=88=D9=85=D8=B9=D8=AA=D9=85=D8=AF.</s=
pan><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"><=
br></span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:=
rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><sp=
an style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=8C =
=D8=A8=D8=B5=D9=81=D8=AA=D9=87=D8=A7 =D8=A7=D9=84=D9=88=D9=83=D9=8A=D9=84 =
=D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A =D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=
=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AA=D9=82=D8=AF=D9=85 =D9=84=D9=83=D9=90 =
=D9=85=D9=86=D8=AA=D8=AC=D9=8B=D8=A7 =D8=A3=D8=B5=D9=84=D9=8A=D9=8B=D8=A7 =
=D8=A8=D8=AC=D9=88=D8=AF=D8=A9 =D9=85=D8=B6=D9=85=D9=88=D9=86=D8=A9=D8=8C =
=D9=85=D8=B9 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=
=D8=A9 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=88=D8=B3=D8=B1=D9=91=D9=8A=
=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=
=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84.</span></p><p=
 dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></=
p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;ma=
rgin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans-serif=
;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">=D9=85=D8=A7 =D9=87=D9=88 =D8=AF=D9=88=D8=A7=D8=
=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=D8=9F</span></span><p dir=3D=
"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><span s=
tyle=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgr=
ound-color:transparent;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 (=D8=A7=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=A7=
=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9 </span><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D9=85=D9=8A=D8=B2=
=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84</span><span style=3D"font-=
size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline">) =D8=AF=D9=88=D8=A7=D8=
=A1 =D9=85=D9=8F=D8=B9=D8=AA=D9=85=D8=AF =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=
=AC=D8=A7=D9=84 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=8C =D9=88=D9=8A=D9=8F=D8=
=B3=D8=AA=D8=AE=D8=AF=D9=85 =D8=A8=D8=AC=D8=B1=D8=B9=D8=A7=D8=AA =D8=AF=D9=
=82=D9=8A=D9=82=D8=A9 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=
=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1=D8=8C =D9=88=D8=B9=D9=
=84=D8=A7=D8=AC =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=
=A3=D8=AE=D8=B1=D9=89 =D9=85=D8=AB=D9=84 =D9=82=D8=B1=D8=AD=D8=A9 =D8=A7=D9=
=84=D9=85=D8=B9=D8=AF=D8=A9. =D8=B9=D9=86=D8=AF =D8=A7=D8=B3=D8=AA=D8=AE=D8=
=AF=D8=A7=D9=85=D9=87 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D9=
=8A=D8=B9=D9=85=D9=84 =D8=B9=D9=84=D9=89 =D8=AA=D8=AD=D9=81=D9=8A=D8=B2 =D8=
=AA=D9=82=D9=84=D8=B5=D8=A7=D8=AA =D8=A7=D9=84=D8=B1=D8=AD=D9=85 =D9=88=D8=
=A5=D9=81=D8=B1=D8=A7=D8=BA =D9=85=D8=AD=D8=AA=D9=88=D9=8A=D8=A7=D8=AA=D9=
=87 =D8=AE=D9=84=D8=A7=D9=84 =D9=81=D8=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=D8=
=B1=D8=A9=D8=8C =D9=85=D9=85=D8=A7 =D9=8A=D8=AC=D8=B9=D9=84=D9=87 =D8=AE=D9=
=8A=D8=A7=D8=B1=D9=8B=D8=A7 =D9=81=D8=B9=D8=A7=D9=84=D9=8B=D8=A7 =D9=88=D8=
=A2=D9=85=D9=86=D9=8B=D8=A7 =D8=B9=D9=86=D8=AF =D8=A5=D8=B4=D8=B1=D8=A7=D9=
=81 =D8=B7=D8=A8=D9=8A=D8=A8 =D9=85=D8=AE=D8=AA=D8=B5.</span></p><p dir=3D"=
rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p=
></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margin-bot=
tom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans-serif;color:r=
gb(0,0,0);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D8=A3=D9=87=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=D8=B5=
=D9=88=D9=84 =D8=B9=D9=84=D9=89 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =
=D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82</span>=
</span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bott=
om:12pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:r=
gb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=
=AA=D8=AA=D9=88=D8=A7=D8=AC=D8=AF =D8=A7=D9=84=D9=83=D8=AB=D9=8A=D8=B1 =D9=
=85=D9=86 =D8=A7=D9=84=D9=82=D9=86=D9=88=D8=A7=D8=AA =D8=BA=D9=8A=D8=B1 =D8=
=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=82=D8=A9 =D8=A7=D9=84=D8=AA=D9=8A =D8=
=AA=D8=A8=D9=8A=D8=B9 =D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =D9=85=D8=AC=D9=
=87=D9=88=D9=84=D8=A9 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D9=82=D8=AF =D8=
=AA=D8=A4=D8=AF=D9=8A =D8=A5=D9=84=D9=89 =D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D8=
=B5=D8=AD=D9=8A=D8=A9 =D8=AC=D8=B3=D9=8A=D9=85=D8=A9.</span><span style=3D"=
font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline"><br></span><span sty=
le=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgrou=
nd-color:transparent;font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><span style=3D"font-si=
ze:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tran=
sparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline"> =D8=AA=D8=B6=D9=85=D9=86 =
=D9=84=D9=83:</span><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline"><br></span><span style=3D"font-size:11pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11p=
t;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparen=
t;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline">=D8=AD=D8=A8=D9=
=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=
=8A=D8=A9 100%</span><span style=3D"font-size:11pt;font-family:Arial,sans-s=
erif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline"><br></span><span style=3D"font-size:11pt;fo=
nt-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F </span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE =D8=B5=D9=84=D8=A7=D8=AD=D9=8A=D8=A9 =D8=AD=
=D8=AF=D9=8A=D8=AB</span><span style=3D"font-size:11pt;font-family:Arial,sa=
ns-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline"><br></span><span style=3D"font-size:11p=
t;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparen=
t;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F </span><span s=
tyle=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgr=
ound-color:transparent;font-weight:700;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=
=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=
=A7=D9=85</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;=
color:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline"><br></span><span style=3D"font-size:11pt;font-fa=
mily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F </span><span style=3D"f=
ont-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-colo=
r:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=
=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84</span><span style=3D"font-size:11pt;font-=
family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline"><br></span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=
=8F </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">=D8=AF=D8=B9=D9=85 =D9=88=D8=A7=D8=B3=D8=AA=D8=B4=D8=
=A7=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D9=85=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=
=B3=D8=A7=D8=B9=D8=A9</span></p><p dir=3D"rtl" style=3D"line-height:1.38;ma=
rgin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"l=
ine-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"font-size=
:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transp=
arent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline">=D9=84=D9=85=
=D8=A7=D8=B0=D8=A7 =D8=AA=D8=AE=D8=AA=D8=A7=D8=B1=D9=8A=D9=86 =D8=AF. =D9=
=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=9F</span></span><ul style=3D"margin-to=
p:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font=
-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:t=
ransparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=
=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:12pt;margin-=
bottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;background-=
color:transparent;font-weight:700;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9</=
span><span style=3D"font-size:11pt;background-color:transparent;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline">: =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=
 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=A7=D8=B3=
=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =
=D8=A7=D9=84=D9=86=D8=B3=D8=A7=D8=A6=D9=8A=D8=A9=D8=8C =D9=88=D8=AA=D9=82=
=D8=AF=D9=85 =D9=84=D9=83=D9=90 =D8=AF=D8=B9=D9=85=D9=8B=D8=A7 =D9=85=D9=87=
=D9=86=D9=8A=D9=8B=D8=A7 =D9=82=D8=A8=D9=84 =D9=88=D8=A3=D8=AB=D9=86=D8=A7=
=D8=A1 =D9=88=D8=A8=D8=B9=D8=AF</span><a href=3D"https://saudiersaa.com/" r=
el=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"https://www.googl=
e.com/url?hl=3Dar&amp;q=3Dhttps://saudiersaa.com/&amp;source=3Dgmail&amp;us=
t=3D1757661572548000&amp;usg=3DAOvVaw1GRcQNJEiTzeSMyDxWC1Gi"><span style=3D=
"font-size:11pt;color:rgb(17,85,204);background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;text-decoration-line:underline;vertical-align:baseline">=D8=A7=D8=B3=
=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</=
span></a><span style=3D"font-size:11pt;background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">.</span><span style=3D"font-size:11pt;back=
ground-color:transparent;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br></=
span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;=
font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" styl=
e=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt" ro=
le=3D"presentation"><span style=3D"font-size:11pt;background-color:transpar=
ent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=
=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=D8=B9</span><spa=
n style=3D"font-size:11pt;background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">: =D8=AA=D8=BA=D8=B7=D9=8A=D8=A9 =D9=84=D8=AC=D9=85=D9=
=8A=D8=B9 =D8=A7=D9=84=D9=85=D8=AF=D9=86 =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=
=AF=D9=8A=D8=A9=D8=8C =D8=A8=D9=85=D8=A7 =D9=81=D9=8A =D8=B0=D9=84=D9=83 </=
span><span style=3D"font-size:11pt;background-color:transparent;font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=
=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=A7=D9=84=
=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=8C =D8=A7=
=D9=84=D8=B7=D8=A7=D8=A6=D9=81</span><span style=3D"font-size:11pt;backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline"> =D9=88=D8=BA=
=D9=8A=D8=B1=D9=87=D8=A7.</span><span style=3D"font-size:11pt;background-co=
lor:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;=
font-variant-alternates:normal;vertical-align:baseline"><br><br></span></p>=
</li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-fami=
ly:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line=
-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt" role=3D"pre=
sentation"><span style=3D"font-size:11pt;background-color:transparent;font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline">=D8=AD=D9=85=D8=A7=D9=8A=
=D8=A9 =D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=AA=D9=83</span><span style=3D"font=
-size:11pt;background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine">: =D9=8A=D8=AA=D9=85 =D8=A7=D9=84=D8=AA=D8=BA=D9=84=D9=8A=D9=81 =D8=A8=
=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=AA=D8=B6=D9=85=D9=86 =D8=A7=D9=84=D8=B3=
=D8=B1=D9=91=D9=8A=D8=A9 =D8=A7=D9=84=D9=83=D8=A7=D9=85=D9=84=D8=A9.</span>=
<span style=3D"font-size:11pt;background-color:transparent;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"li=
st-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;wh=
ite-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;ma=
rgin-top:0pt;margin-bottom:12pt" role=3D"presentation"><span style=3D"font-=
size:11pt;background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D8=A7=D9=84=D8=AA=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=
=D8=B1=D8=B3=D9=85=D9=8A</span><span style=3D"font-size:11pt;background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">: =D8=B4=D8=B1=D8=A7=
=D8=A1=D9=83 =D9=8A=D8=AA=D9=85 =D9=85=D8=A8=D8=A7=D8=B4=D8=B1=D8=A9 =D9=85=
=D9=86 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D8=A7=D9=84=D9=85=D8=B9=D8=AA=
=D9=85=D8=AF=D8=8C =D8=A8=D8=B9=D9=8A=D8=AF=D9=8B=D8=A7 =D8=B9=D9=86 =D8=A7=
=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1.</span><span style=3D"font-size:11pt;b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br=
></span></p></li></ul><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0=
pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height=
:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font=
-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font=
-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">=D9=83=D9=8A=D9=81=D9=
=8A=D8=A9 =D8=B7=D9=84=D8=A8 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D9=85=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86</span></span><ol style=3D"margin-top:0px;margin-bottom:0px"><li dir=
=3D"rtl" style=3D"list-style-type:decimal;font-size:11pt;font-family:Arial,=
sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1=
.38;text-align:right;margin-top:12pt;margin-bottom:0pt" role=3D"presentatio=
n"><span style=3D"font-size:11pt;background-color:transparent;font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=AA=D9=88=D8=A7=
=D8=B5=D9=84 =D8=B9=D8=A8=D8=B1 =D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8</span>=
<span style=3D"font-size:11pt;background-color:transparent;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline"> =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85:=
 </span><span style=3D"font-size:11pt;background-color:transparent;font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=F0=9F=93=9E 0537466539</sp=
an><span style=3D"font-size:11pt;background-color:transparent;font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=
=3D"rtl" style=3D"list-style-type:decimal;font-size:11pt;font-family:Arial,=
sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1=
.38;text-align:right;margin-top:0pt;margin-bottom:0pt" role=3D"presentation=
"><span style=3D"font-size:11pt;background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">=D8=B4=D8=B1=D8=AD =D8=A7=D9=84=D8=AD=D8=A7=D9=84=
=D8=A9 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=A9 =D9=88=D9=81=D8=AA=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AD=D9=85=D9=84.</span><span style=3D"font-size:11pt;backgro=
und-color:transparent;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline"><br><br></spa=
n></p></li><li dir=3D"rtl" style=3D"list-style-type:decimal;font-size:11pt;=
font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" styl=
e=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt" ro=
le=3D"presentation"><span style=3D"font-size:11pt;background-color:transpar=
ent;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline">=D8=A7=D8=B3=D8=AA=D9=84=D8=A7=
=D9=85 =D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D9=84=
=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =
=D9=88=D8=A7=D9=84=D8=AC=D8=B1=D8=B9=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=B5=
=D9=89 =D8=A8=D9=87=D8=A7.</span><span style=3D"font-size:11pt;background-c=
olor:transparent;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline"><br><br></span></p=
></li><li dir=3D"rtl" style=3D"list-style-type:decimal;font-size:11pt;font-=
family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"=
line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt" role=
=3D"presentation"><span style=3D"font-size:11pt;background-color:transparen=
t;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline">=D8=A7=D8=B3=D8=AA=D9=84=D8=A7=D9=
=85 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AE=D9=84=D8=A7=D9=84 =D9=81=D8=
=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=A9 =D8=B9=D8=A8=D8=B1 =D8=AE=D8=
=AF=D9=85=D8=A9 =D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A2=D9=85=D9=86=D8=A9 =D9=
=88=D8=B3=D8=B1=D9=8A=D8=A9.</span><span style=3D"font-size:11pt;background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline"><br><br></span><=
/p></li></ol><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin=
-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;mar=
gin-top:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:A=
rial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">=D8=AA=D9=86=D8=A8=D9=8A=D9=87 =
=D8=B7=D8=A8=D9=8A =D9=85=D9=87=D9=85</span></span><ul style=3D"margin-top:=
0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-s=
ize:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"=
rtl" style=3D"line-height:1.38;text-align:right;margin-top:12pt;margin-bott=
om:0pt" role=3D"presentation"><span style=3D"font-size:11pt;background-colo=
r:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=D9=8A=D8=AC=D8=A8 =
=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=81=D9=82=D8=B7 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=
=D9=81 =D8=B7=D8=A8=D9=8A =D9=85=D8=AE=D8=AA=D8=B5.</span><span style=3D"fo=
nt-size:11pt;background-color:transparent;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:dis=
c;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-c=
olor:transparent;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p=
 dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;marg=
in-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">=D9=84=D8=A7 =
=D9=8A=D9=8F=D9=86=D8=B5=D8=AD =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=
=D9=85=D9=87 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=
=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D8=A3=D8=AE=D8=B1.</span><span style=
=3D"font-size:11pt;background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-ty=
pe:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgr=
ound-color:transparent;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline;white-space:p=
re"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0p=
t;margin-bottom:12pt" role=3D"presentation"><span style=3D"font-size:11pt;b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=81=
=D9=8A =D8=AD=D8=A7=D9=84 =D9=88=D8=AC=D9=88=D8=AF =D8=A3=D9=85=D8=B1=D8=A7=
=D8=B6 =D9=85=D8=B2=D9=85=D9=86=D8=A9 =D8=A3=D9=88 =D8=AD=D8=A7=D9=84=D8=A7=
=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9=D8=8C =D9=8A=D8=AC=D8=A8 =D8=A7=D8=B3=D8=AA=
=D8=B4=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D9=82=D8=A8=
=D9=84 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85.</span><span =
style=3D"font-size:11pt;background-color:transparent;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline"><br><br></span></p></li></ul><p dir=3D"rtl" style=3D"line=
-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"=
rtl" style=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span sty=
le=3D"font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgrou=
nd-color:transparent;font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=A5=D8=B6=D8=A7=D9=81=D9=8A=D8=A9 =D9=
=85=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span></span><ul sty=
le=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style=
-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);bac=
kground-color:transparent;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline;white-spac=
e:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top=
:12pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11p=
t;background-color:transparent;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=
=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=A7=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D8=
=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85.</sp=
an><span style=3D"font-size:11pt;background-color:transparent;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D=
"list-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb=
(0,0,0);background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right=
;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"fon=
t-size:11pt;background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line">=D8=AA=D9=88=D9=81=D9=8A=D8=B1 =D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=
=D8=AA =D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=A2=D8=AB=D8=A7=D8=B1 =D8=A7=D9=84=
=D8=AC=D8=A7=D9=86=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=B9=
=D9=8A=D8=A9 =D9=88=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D8=B9=
=D8=A7=D9=85=D9=84 =D9=85=D8=B9=D9=87=D8=A7.</span><span style=3D"font-size=
:11pt;background-color:transparent;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
<br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-=
size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D=
"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bott=
om:12pt" role=3D"presentation"><span style=3D"font-size:11pt;background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=A5=D8=B1=D8=B4=
=D8=A7=D8=AF =D8=A7=D9=84=D9=85=D8=B1=D9=8A=D8=B6=D8=A9 =D8=A5=D9=84=D9=89 =
=D8=A3=D9=81=D8=B6=D9=84 =D9=85=D9=85=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA =D8=A7=
=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9.<=
/span><span style=3D"font-size:11pt;background-color:transparent;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;vertical-align:baseline"><br><br></span></p></li></ul><p dir=3D"rtl" s=
tyle=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><=
span dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margin-bottom:4p=
t"><span style=3D"font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0=
,0);background-color:transparent;font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline">=D8=AE=D9=84=D8=A7=D8=B5=D8=A9</span></span><p dir=3D"rtl" st=
yle=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"=
font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=A7=D8=AE=D8=AA=
=D9=8A=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D8=A7=D9=84=D9=85=
=D9=88=D8=AB=D9=88=D9=82 =D8=B9=D9=86=D8=AF</span><a href=3D"https://groups=
.google.com/a/chromium.org/g/security-dev/c/rhrPpivCQGM/m/XihUBiSLAAAJ" rel=
=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"https://www.google.=
com/url?hl=3Dar&amp;q=3Dhttps://groups.google.com/a/chromium.org/g/security=
-dev/c/rhrPpivCQGM/m/XihUBiSLAAAJ&amp;source=3Dgmail&amp;ust=3D175766157254=
8000&amp;usg=3DAOvVaw0563gowSvnzw_KiD9HwW0C"><span style=3D"font-size:11pt;=
font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline"> </span><span style=3D"font-size:11=
pt;font-family:Arial,sans-serif;color:rgb(17,85,204);background-color:trans=
parent;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;text-decoration-line:underline;vertical-align:baselin=
e">=D8=B4=D8=B1=D8=A7=D8=A1 </span><span style=3D"font-size:11pt;font-famil=
y:Arial,sans-serif;color:rgb(17,85,204);background-color:transparent;font-w=
eight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;text-decoration-line:underline;vertical-align:base=
line">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</=
span></a><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:r=
gb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=87=
=D9=88 =D8=A7=D9=84=D8=B6=D9=85=D8=A7=D9=86 =D8=A7=D9=84=D9=88=D8=AD=D9=8A=
=D8=AF =D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=AA=D9=83=D9=90.</span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline"><br></span><span=
 style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);back=
ground-color:transparent;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=85=D8=
=B9 </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><s=
pan style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=8C =
=D8=B3=D8=AA=D8=AD=D8=B5=D9=84=D9=8A=D9=86 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D9=85=D9=86=D8=AA=D8=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A=D8=8C =D8=A7=
=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D8=A7=
=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=8C =D9=88=D8=A7=D9=84=D8=AA=D9=88=
=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A =D8=A3=D9=8A=D9=86=D9=85=
=D8=A7 =D9=83=D9=86=D8=AA=D9=90 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=85=D9=84=
=D9=83=D8=A9.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top=
:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">=F0=9F=93=9E =D9=84=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=
=84 =D9=88=D8=A7=D9=84=D8=B7=D9=84=D8=A8 =D8=B9=D8=A8=D8=B1 =D9=88=D8=A7=D8=
=AA=D8=B3=D8=A7=D8=A8: </span><span style=3D"font-size:11pt;font-family:Ari=
al,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline">0537466539</span><span style=3D"fo=
nt-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline"><br></=
span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0=
,0,0);background-color:transparent;font-weight:700;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-=
align:baseline">=D8=A7=D9=84=D9=85=D8=AF=D9=86 =D8=A7=D9=84=D9=85=D8=BA=D8=
=B7=D8=A7=D8=A9</span><span style=3D"font-size:11pt;font-family:Arial,sans-=
serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">: =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =E2=80=93 =D8=AC=D8=
=AF=D8=A9 =E2=80=93 =D9=85=D9=83=D8=A9 =E2=80=93 =D8=A7=D9=84=D8=AF=D9=85=
=D8=A7=D9=85 =E2=80=93 =D8=A7=D9=84=D8=AE=D8=A8=D8=B1 =E2=80=93 =D8=A7=D9=
=84=D8=B7=D8=A7=D8=A6=D9=81 =E2=80=93 =D8=A7=D9=84=D9=85=D8=AF=D9=8A=D9=86=
=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D9=88=D8=B1=D8=A9 =E2=80=93 =D8=A3=D8=A8=D9=
=87=D8=A7 =E2=80=93 =D8=AC=D8=A7=D8=B2=D8=A7=D9=86 =E2=80=93 =D8=AA=D8=A8=
=D9=88=D9=83.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top=
:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-heig=
ht:1.38;margin-top:18pt;margin-bottom:4pt"><span style=3D"font-size:17pt;fo=
nt-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=C2=A0</span></span><=
p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"=
><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0=
);background-color:transparent;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=
=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=85=D9=83=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=B4=D8=B1=D8=A7=D8=A1 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=
=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=
=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=D8=
=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200=D8=8C Misoprostol =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D9=86=D9=87=D8=AF=D9=8A=D8=8C</span><a href=
=3D"https://ksacytotec.com/" rel=3D"nofollow" target=3D"_blank" data-safere=
directurl=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps://ksacytotec.=
com/&amp;source=3Dgmail&amp;ust=3D1757661572548000&amp;usg=3DAOvVaw2QQHmr3q=
FGeaI9FXoaBs2M"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;=
color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline"> </span><span style=3D"font-size:11pt;font-family:Arial,sans-ser=
if;color:rgb(17,85,204);background-color:transparent;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;text-de=
coration-line:underline;vertical-align:baseline">https://ksacytotec.com/</s=
pan></a><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rg=
b(0,0,0);background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=
=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83.</span></p><p dir=3D"rtl" style=3D"=
line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size=
:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=
=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=
=8A=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AC=D8=
=AF=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=83=D8=
=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=
=85=D8=A7=D9=85=D8=8C =D8=B4=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=
=A9=D8=8C =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=D8=8C =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 200=D8=8C Misoprostol =D8=A7=D9=84=D8=B3=D8=B9=D9=88=
=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=
=D9=84=D9=86=D9=87=D8=AF=D9=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=
=D8=B6 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=
=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=
=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83.<=
/span></p><br></blockquote></div></blockquote></div></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/4f272932-c6b0-4d51-80be-30852a533668n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/4f272932-c6b0-4d51-80be-30852a533668n%40googlegroups.com</a>.<br />

------=_Part_4097_506652436.1757575194694--

------=_Part_4096_1473581852.1757575194694--
