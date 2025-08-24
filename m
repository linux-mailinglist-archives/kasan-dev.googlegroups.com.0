Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBJNZVLCQMGQE3UWNGLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AF5CB32D92
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Aug 2025 07:01:39 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-45a1ad21752sf15170575e9.1
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Aug 2025 22:01:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756011686; cv=pass;
        d=google.com; s=arc-20240605;
        b=LhGvfYxv45thCmEZJrIU8pAThXRQJOrPZBkltBXZy5eOrlBXPQ/BoyVuusHwp7rla4
         FCvccDu6Os5zSL58yWa6b5nh1aRgBGuijV98E+++as0+2FpPCXa8nNO5vYk+ax+y/0Ks
         sRfiZEyUr7c2xNzs97kdnXydlqG/f1DvkM9b5vD1Srti7IKyMHDSUgwmEtq3ywUSw9rE
         IAm4Udhmcy73uA5ZsVJnNqQhI3shniwxt6fY4RIpzovsKXZsXGBH9KjaXthM4MsLkI2c
         GUrV5OMaPCocZhX0M8cxlokBo9Di2CSQRWB3d1f6dmD81bGDjgmK9RbCPj4SeOiX/GuD
         307Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=+teMcQn3FnhfO/pOnVSX/VkecX8nDGoO/LLgMOR5Qs4=;
        fh=8OsosmhR6JPoDwtXtY9u8NW5MtZImJoE+2XRe+mWJZ4=;
        b=GdDLusjGKM+7/2fzteBEDRNCetSWr+OWjuPOxL2CH9UIFr/7iTo02KyA1GZJGY8/wQ
         FbfoDYFos85TO967lMIH6Kz290q8the4IDI73rfMVDR7XxgQ82RhUtaz57aPt5kdrbwo
         SB62IKHEgQRQQ5RZHFeCQDr5Qfz/IFulp1vXGHDH8cxfjNKJGxKFexwEIax0DxMCUrwG
         lauo7ts8d8HjeNgv055ysRsg4EQBCn/lxN2prHDzyvdU/9nfFSF1rkVjJx3Js7DY9/kH
         phsTFnJdf/JXm71ersGNhIJT7vvEz4esmTk4ftCc+HhpmL4dqCBCyEgCDFcCt5uVqboK
         4z4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hyljR7Mi;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756011686; x=1756616486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+teMcQn3FnhfO/pOnVSX/VkecX8nDGoO/LLgMOR5Qs4=;
        b=c5vVW9xATizDviX8WcE5EXfAADz6fcf10kyFrLZolQuneZr2ZHIWB0q1pH6uwi9zkI
         16+K4G8hYT8z9+YnJWAZqlhgdlcn07Rv/YULwDdlGl6mXdwF8M7R7WdG1uNPW1VQXEoe
         YQ8EwTqW1Z0JNfTouZ28MCZvpx7VWAGflaAnh0weujYNHoHL871ciXO5l0U/S3Oc2P+T
         vwMVastvlAZX+yLwRxWrhggU2FFo4Jye8tdUCoqZXEGFWGSucglxvm2svaESRsoTXB+z
         ev7PCmF0FcJSn7763AXJItynSDyAoWOuadBdHm8LHQSFMoIG8ftEuQjW1KqWWKJdN8zD
         cAUg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756011686; x=1756616486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=+teMcQn3FnhfO/pOnVSX/VkecX8nDGoO/LLgMOR5Qs4=;
        b=DKe5LtD8A9thrxuxzDbqe33GgqOQ5vXxr1820fcLv51HEFol1RlMYLgRTsk1fAKNXs
         vkt9b8p9Yd0viaK2oZsbCTsPoFXhDfAxfik7hJkqUwfmFIChxGWSVVGoJQC5PnA8zS2w
         joY5oUqseBEfB3qaE5Weq+bXypgzmesX+dKFm/7xmSgvaErRKsXIyvY7aPemLRCO9DpB
         ibyTn7s+tYIRPB/XyYPVR2UJ75q9SaR0ze06U7n3yPVaU1bAhKysqZe2fD5d9l0WZtVO
         BevYOcwUumrRGPER0WbWnmoaSfBQCF1hdNpYhAarkkqSPQchK6+oaMDAOjYvLo3LaCuG
         ArxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756011686; x=1756616486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+teMcQn3FnhfO/pOnVSX/VkecX8nDGoO/LLgMOR5Qs4=;
        b=EO//W8d4itX2XbW50uBvaDL0ySyge8XMhzJYyk1sExfn9lBS9/e9dPlEoAMtv0TGOX
         mcNOfck9YrtXysJMEpshSDwaaFntQITHz9z80X5nVgIxCIzuH7VZb8RishjD8lVTSEcL
         GTCbS4MaY2SmNSxXAcvG7mESDUAfdjQLNisVxrypon+7W7++LstXj7BHIeGiw0oVIgYu
         hoF46zqykDSMuO+HrK7ZVhuYZaIAvvVjIwoVj7cb1QUL0gG50hLuWRn46MTRBERbjhRD
         YPTanw/IJOrNUUB6BW2dvggxXwd+/DZqvULeqekwW3jdur9HBP0kPABmDSG+Dd9Zu6Ot
         cqvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0uqPyaCrnxpHw4rd/SpScrzko9LXgetW+/1EcJhry45uJ8gWpeXd3mTKPuwFQPxlILmHZfw==@lfdr.de
X-Gm-Message-State: AOJu0YxSlR+iOIbC87JL2NDxJ25kyMx4TpaeG99KqEVHPchBkmG6z2zz
	LV3u8Us0+EdU+IIbF+bvJAJMixnLqDFCFhngAnSRIrwvC9WMn6yi4BGL
X-Google-Smtp-Source: AGHT+IE/kPUZzIYhr9A/ZtRYwUK70eoIIAaiIfsvHx19kF38LSnAk7Ixd9migyG/k8p3MPO8OC8RjQ==
X-Received: by 2002:a05:600c:630c:b0:458:bd08:72a8 with SMTP id 5b1f17b1804b1-45b51798cddmr69763695e9.13.1756011685602;
        Sat, 23 Aug 2025 22:01:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdZoUjspnc7N2qsUlUJ3zm8EohqPMMj45vg1JagK1csIQ==
Received: by 2002:a05:600c:4254:b0:456:12a9:e81 with SMTP id
 5b1f17b1804b1-45b4721905fls7643995e9.0.-pod-prod-00-eu-canary; Sat, 23 Aug
 2025 22:01:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUkp2mv9KzanKqnm8c4Az+DDEudfHfMNboUcAWiojU25DuEprY8Jh4qHRCutUnJ1XCdXT+zAp0Cz5M=@googlegroups.com
X-Received: by 2002:a05:6000:2089:b0:3c2:502:d944 with SMTP id ffacd0b85a97d-3c5cf554a43mr6923807f8f.0.1756011683053;
        Sat, 23 Aug 2025 22:01:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756011683; cv=none;
        d=google.com; s=arc-20240605;
        b=JqTWW5w+yZkGE8ciQljzvRhUPspQ1PWHtJLbuRMm6LTFkv55NapsRWiTQ78h/1fjYy
         uv0tqrHBLgONbqLwVPsbEvUWmb8bQStFK5YbIQ4zZD5ZRGcr5Gkn1ELJG0G6fyMGVtGZ
         8p94zb0p/wkaefSiAevztUicQZg/gtyVDnaqulxTq+JvOUr+PejqlAgTx71zrYo72tLn
         nZy08IGPH9iwCKued45nF+2l6ef/dfqpw+V3rP3ogazWdeDUG3FKzE6mnIG5p/91yRu5
         eec9mFvwKwzru6tZKCpkdcB4OejB9b+hFHdrE8Hu1Rk9ygNWq3bkW4ZdpIKQpeoeAhBc
         9Fbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=zNZc30dWHUT38MypNcfo7zyEPEtNbntC0RAANi2aRTo=;
        fh=iPc0BTyj5SkVipcDiCp8ABYyBLhTe3tr/N8j5+ULF2Y=;
        b=dlMgVC9qtpju8vN4xXPwAWzATe3UjqpD1vMPzNYlUI76X1c2knOyod+MGoR74+OZUm
         S0hNeRWZhedXbnqpDKHUPFs8o/ShU7I8z1v0slJDzRMzCZE6rSe93Z9AF0+yuXeTcIT/
         hJJ7HuXTY59qmM+RIfwCi3S4j5IhuW/85SaWTHpE50F+oBhbxrJSvreflTZt4HRec0oH
         tec/cftP8z1qbJhcMsQBcDpV5AS+O99IfuHvsjKj6gpLU6ZH4VSpdsKWPE/dMDSiyXxJ
         SrkustjKFSZ3lvDcY8JAEha6Sf5J3XUBXgfJJXIU6rttG6gJTAHy0AxFpvL7PCcxYVWo
         awmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hyljR7Mi;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3c70e4bba5csi70765f8f.1.2025.08.23.22.01.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 Aug 2025 22:01:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-61c212c3986so2442322a12.0
        for <kasan-dev@googlegroups.com>; Sat, 23 Aug 2025 22:01:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXzBun+IfFIJcpk6E0TbjbxA+gyrl4hpkLJyVLqtkAIyRlLcofA6R5E1RNa7xjpO6J0QVuQfFcMxAI=@googlegroups.com
X-Gm-Gg: ASbGncu0EcJbBSl/nvUmwfZ8bEfQAfGjfhHx0gmyGbH71xvtAEh3lrBehFZOSNHqSr2
	lb7tz+g2fu91ioOX5GfzQkyTMwuXQg+M3WMokIjNDt6VuMpGOCX63mAzjIjsB+g8ucrOGxNRx0F
	rnN7FXRGanjX1CMkNuDWO9gaM4sqpIkrB0F2bRRil11edTcKW7tEdWMfREIZYMw7fx1utQP8i94
	HidTv9RdyYy
X-Received: by 2002:a05:6402:1650:b0:615:9247:e2fa with SMTP id
 4fb4d7f45d1cf-61c21345964mr4061792a12.8.1756011681986; Sat, 23 Aug 2025
 22:01:21 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Sun, 24 Aug 2025 08:00:00 +0300
X-Gm-Features: Ac12FXyoAHZpVl6CjRLUJdd_Yuwq-E4pteNCMF1FcfQdnKo9MUY430hwyNilSoI
Message-ID: <CADj1ZKmy1Ewh5Q=+h1Xm-Ht3c-_FX6R-Q7wXbhcWEGH996FH_A@mail.gmail.com>
Subject: =?UTF-8?B?2KPYrdiv2Ksg2KrZgtmG2YrYp9iqINin2YTYr9mB2Lkg2KfZhNil2YTZg9iq2LHZiNmG?=
	=?UTF-8?B?2Yog2YjYp9mE2YXYrdin2YHYuCDYp9mE2LHZgtmF2YrYqSDinJQg2KfZhNiw2YPYp9ihINin2YTYp9i1?=
	=?UTF-8?B?2LfZhtin2LnZiiDZiNiq2K3ZhNmK2YQg2KfZhNio2YrYp9mG2KfYqiDZgdmKINin2YTZgti32KfYuSA=?=
	=?UTF-8?B?2KfZhNmF2KfZhNmKIOKclCDYp9mE2KfZhdiq2KvYp9mEINmI2KfZhNmE2YjYp9im2K0g2YHZiiDYp9mE?=
	=?UTF-8?B?2KrZg9mG2YjZhNmI2KzZitinINin2YTZhdin2YTZitipIOKclCDYqNmG2KfYoSDYp9iz2KrYsdin2Ko=?=
	=?UTF-8?B?2YrYrNmK2Kkg2LTYp9mF2YTYqSDZhNmE2KrYrdmI2YQg2KfZhNix2YLZhdmKIOKchSDYo9i32YTZgiA=?=
	=?UTF-8?B?2YXZh9in2LHYp9iq2YMg2YTYqti12KjYrSDZgtin2KbYr9mL2Kcg2YHZiiDYp9mE2KvZiNix2Kkg2Kc=?=
	=?UTF-8?B?2YTZhdin2YTZitipINin2YTYsdmC2YXZitipISDwn5OeINmE2YTYrdis2LIg2YjYp9mE2KfYs9iq2YE=?=
	=?UTF-8?B?2LPYp9ixOiAwMDIwMTA2Mjk5MjUxMCAtIDAxMDk2ODQxNjI2INin2YTYs9mE2KfZhSDYudmE2YrZg9mF?=
	=?UTF-8?B?INmI2LHYrdmF2Kkg2KfZhNmE2Ycg2YjYqNix2YPYp9iq2Kkg2KfZhNiv2KfYsSDYp9mE2LnYsdio2Yo=?=
	=?UTF-8?B?2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Yp9ix2YrYqSDYqtmH2K/ZitmD2YUg2KfYt9mK2Kgg2Kc=?=
	=?UTF-8?B?2YTYqtit2YrYp9iqINmI2KrZgtiv2YUg2YTZg9mFINi02YfYp9iv2Kkg2YHZiiDYp9mE2KrYrdmI2ZE=?=
	=?UTF-8?B?2YQg2YbYrdmIINin2YTYqtmD2YbZiNmE2YjYrNmK2Kcg2KfZhNmF2KfZhNmK2KkgKENGVFQpIENlcnRp?=
	=?UTF-8?B?ZmllZCBGaW5hbmNpYWwgVGVjaG5vbG9neSBUcmFuc2Zvcm1hdGlvbiDYqNi02YfYp9iv2Kkg2YXYudiq?=
	=?UTF-8?B?2YXYr9ipINmI2YrZiNis2K8g2K7YtdmFINiu2KfYtSDZhNmE2YXYrNmF2YjYudin2Kog8J+ThSDZhdmI?=
	=?UTF-8?B?2LnYryDYp9mE2K/ZiNix2Kk6INmF2YYgMzEg2KfYutiz2LfYsyDYp9mE2YkgNCDYs9io2KrZhdio2LEg?=
	=?UTF-8?B?MjAyNSDwn5ONINin2YTZhdmD2KfZhjog2KfZiNmGINmE2KfZitmGIChaT09NKSDZgdmJINit77+9?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000086c058063d155423"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hyljR7Mi;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::530
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

--00000000000086c058063d155423
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

Ktij2K3Yr9irINiq2YLZhtmK2KfYqiDYp9mE2K/Zgdi5INin2YTYpdmE2YPYqtix2YjZhtmKINmI
2KfZhNmF2K3Yp9mB2Lgg2KfZhNix2YLZhdmK2KkqDQoq4pyUKiAq2KfZhNiw2YPYp9ihINin2YTY
p9i12LfZhtin2LnZiiDZiNiq2K3ZhNmK2YQg2KfZhNio2YrYp9mG2KfYqiDZgdmKINin2YTZgti3
2KfYuSDYp9mE2YXYp9mE2YoqDQoq4pyUKiAq2KfZhNin2YXYqtir2KfZhCDZiNin2YTZhNmI2KfY
ptitINmB2Yog2KfZhNiq2YPZhtmI2YTZiNis2YrYpyDYp9mE2YXYp9mE2YrYqSoNCirinJQqICrY
qNmG2KfYoSDYp9iz2KrYsdin2KrZitis2YrYqSDYtNin2YXZhNipINmE2YTYqtit2YjZhCDYp9mE
2LHZgtmF2YoqDQoNCirinIUqICrYo9i32YTZgiDZhdmH2KfYsdin2KrZgyDZhNiq2LXYqNitINmC
2KfYptiv2YvYpyDZgdmKINin2YTYq9mI2LHYqSDYp9mE2YXYp9mE2YrYqSDYp9mE2LHZgtmF2YrY
qSoqISoNCg0KKvCfk54qICrZhNmE2K3YrNiyINmI2KfZhNin2LPYqtmB2LPYp9ixKio6Kg0KDQoq
MDAyMDEwNjI5OTI1MTAgLSAwMTA5Njg0MTYyNioNCg0KKtin2YTYs9mE2KfZhSDYudmE2YrZg9mF
INmI2LHYrdmF2Kkg2KfZhNmE2Ycg2YjYqNix2YPYp9iq2KkqDQoNCirYp9mE2K/Yp9ixINin2YTY
udix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYp9iv2KfYsdmK2Kkg2KrZh9iv2YrZg9mFINin
2LfZitioINin2YTYqtit2YrYp9iqINmI2KrZgtiv2YUg2YTZg9mFKg0KDQoq2LTZh9in2K/YqSDZ
gdmKINin2YTYqtit2YjZkdmEINmG2K3ZiCDYp9mE2KrZg9mG2YjZhNmI2KzZitinINin2YTZhdin
2YTZitipICgqKkNGVFQqKikqDQoNCipDZXJ0aWZpZWQgRmluYW5jaWFsIFRlY2hub2xvZ3kgVHJh
bnNmb3JtYXRpb24qDQoNCirYqNi02YfYp9iv2Kkg2YXYudiq2YXYr9ipKg0KDQoq2YjZitmI2KzY
ryDYrti12YUg2K7Yp9i1INmE2YTZhdis2YXZiNi52KfYqioNCg0K8J+ThSAq2YXZiNi52K8g2KfZ
hNiv2YjYsdipKjog2YXZhiAzMSDYp9i62LPYt9izINin2YTZiSA0INiz2KjYqtmF2KjYsSAyMDI1
DQrwn5ONICrYp9mE2YXZg9in2YYqKjoqINin2YjZhiDZhNin2YrZhiAoWk9PTSkg2YHZiSDYrdmK
2YYg2KrYudiw2LEg2KfZhNit2LbZiNixDQoNCirYp9mE2YXZgtiv2YXYqSoNCg0KKtio2LHZhtin
2YXYrCDYqtiv2LHZitio2Yog2KfYrdiq2LHYp9mB2Yog2YrYsdmD2LIg2LnZhNmJINin2YTYqtmC
2YbZitin2Kog2KfZhNmF2KfZhNmK2Kkg2KfZhNmF2KjYqtmD2LHYqSAoKipGaW5UZWNoKiopINmF
2KvZhA0K2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZitiMINin2YTYqNmE2YjZg9iq2LTZ
itmG2Iwg2KfZhNmF2K3Yp9mB2Lgg2KfZhNix2YLZhdmK2KnYjCDYp9mE2KrZhdmI2YrZhCDYp9mE
2LHZgtmF2YrYjCDZhdmG2LXYp9iqINin2YTYr9mB2LkNCtin2YTYpdmE2YPYqtix2YjZhtmKLiog
Ktin2YTYqtmD2YbZiNmE2YjYrNmK2Kcg2YjYp9mE2KfYqNiq2YPYp9ixKg0KDQoq2KfZhNiw2Yog
2YrZh9iv2YEg2KXZhNmJINin2YTYqtmG2KfZgdizINmF2Lkg2KfZhNij2LPYp9mE2YrYqCDYp9mE
2YXYp9mE2YrYqSDYp9mE2KrZgtmE2YrYr9mK2Kkg2YHZiiDYqtmC2K/ZitmFINin2YTYrtiv2YXY
p9iqDQrYp9mE2YXYp9mE2YrYqSDYpdmG2YfYpyDYtdmG2KfYudipINmG2KfYtNim2Kkg2KrYs9iq
2K7Yr9mFINin2YTYqtmD2YbZiNmE2YjYrNmK2Kcg2YTYqtit2LPZitmGINin2YTYo9mG2LTYt9ip
INmB2Yog2KfZhNiq2YXZiNmK2YQg2YXZhg0K2K7ZhNin2YQg2YfYsNinINin2YTYqNix2YbYp9mF
2Kwg2LPZitiq2LnYsdmBINin2YTZhdiq2K/YsdioINi52YTZiSDYo9iz2KfYs9mK2KfYqiDYp9mE
2KrZg9mG2YjZhNmI2KzZitinINin2YTZhdin2YTZitipINmIDQrYp9mE2KXYrNix2KfYodin2Kog
2KfZhNij2YXZhtmK2Kkg2Ygg2LfYsdmCINil2K/Yp9ix2Kkg2KfZhNmF2K7Yp9i32LEg2KfZhNmF
2LHYqtio2LfYqSDYqNmHKg0KDQoq2YrYsdio2Lcg2KjZitmGINin2YTYrNin2YbYqCDYp9mE2KrZ
gtmG2Yog2YjYp9mE2KzYp9mG2Kgg2KfZhNin2LPYqtix2KfYqtmK2KzZiiDZgdmKINin2YTYqtit
2YjZhCDYp9mE2YXYp9mE2Yog2KfZhNix2YLZhdmKLioNCg0KKtin2YTYp9mH2K/Yp9mBKg0KDQrC
tyAgICAgICAgIMK3ICAq2KrYudix2YrZgSDYp9mE2YXYtNin2LHZg9mK2YYg2KjZhdmB2KfZh9mK
2YUg2YjYo9iz2KfYs9mK2KfYqiDYp9mE2KrZg9mG2YjZhNmI2KzZitinINin2YTZhdin2YTZitip
INmI2KrYt9mI2LHZh9inDQrYudin2YTZhdmK2YvYpyoqLioNCg0KwrcgICAgICAgICDCtyAgKtiq
2YXZg9mK2YYg2KfZhNmC2KfYr9ipINmI2KfZhNmF2K/Zitix2YrZhiDZhdmGINi12YrYp9i62Kkg
2KfYs9iq2LHYp9iq2YrYrNmK2KfYqiDYp9mE2KrYrdmI2YQg2KfZhNix2YLZhdmKDQrYp9mE2YXY
p9mE2Yog2K/Yp9iu2YQg2YXYpNiz2LPYp9iq2YfZhSoqLioNCg0KwrcgICAgICAgICDCtyAgKtiq
2LfZiNmK2LEg2KfZhNmC2K/YsdipINi52YTZiSDYqti12YXZitmFINmI2KrZhtmB2YrYsCDYrtin
2LHYt9ipINi32LHZitmCINmE2KfYudiq2YXYp9ivINit2YTZiNmEDQrYp9mE2KrZg9mG2YjZhNmI
2KzZitinINin2YTZhdin2YTZitipKiouKg0KDQrCtyAgICAgICAgIMK3ICAq2KfZhNiq2LnYsdmB
INi52YTZiSDYo9it2K/YqyDYp9mE2KrYt9io2YrZgtin2Kog2YXYq9mEINin2YTZhdit2KfZgdi4
INin2YTYsdmC2YXZitip2Iwg2KfZhNio2YbZiNmDDQrYp9mE2KfZgdiq2LHYp9i22YrYqdiMINmI
2KfZhNin2LPYqti02KfYsdin2Kog2KfZhNix2YjYqNmI2KrZitipKiouKg0KDQrCtyAgICAgICAg
IMK3ICAq2KrYudiy2YrYsiDZhdmH2KfYsdin2Kog2KrYrdmE2YrZhCDYp9mE2YXYrtin2LfYsSDZ
iNin2YTZgdix2LUg2KfZhNmF2LHYqtio2LfYqSDYqNin2YTYqtmD2YbZiNmE2YjYrNmK2KcNCtin
2YTZhdin2YTZitipKiouKg0KDQrCtyAgICAgICAgIMK3ICAq2YHZh9mFINin2YTYqti02LHZiti5
2KfYqiDZiNin2YTZgtmI2KfZhtmK2YYg2KfZhNmF2YbYuNmF2Kkg2YTZhNiq2YPZhtmI2YTZiNis
2YrYpyDYp9mE2YXYp9mE2YrYqSDZhdit2YTZitmL2KcNCtmI2LnYp9mE2YXZitmL2KcqKi4qDQoN
CsK3ICAgICAgICAgwrcgICrYpdmD2LPYp9ioINin2YTZhdiq2K/Ysdio2YrZhiDYo9iv2YjYp9iq
INmC2YrYp9izINin2YTYudin2KbYryDYudmE2Ykg2KfZhNin2LPYqtir2YXYp9ixINmB2Yog2YXY
tNin2LHZiti5DQrYp9mE2KrZg9mG2YjZhNmI2KzZitinINin2YTZhdin2YTZitipKiouKg0KDQrC
tyAgICAgICAgIMK3ICAq2KrYo9mH2YrZhCDYp9mE2YXYtNin2LHZg9mK2YYg2YTZhNiq2LnYp9mF
2YQg2YXYuSDYp9mE2KrYrdiv2YrYp9iqINin2YTYqtmG2LjZitmF2YrYqSDZiNin2YTYo9mF2YYN
Ctin2YTYs9mK2KjYsdin2YbZiiDZgdmKINit2YTZiNmEKiogRmluVGVjaC4qDQoNCsK3ICAgICAg
ICAgwrcgICrYpdi52K/Yp9ivINmD2YjYp9iv2LEg2YLYp9iv2LHYqSDYudmE2Ykg2YLZitin2K/Y
qSDZhdio2KfYr9ix2KfYqiDYp9mE2KfYqNiq2YPYp9ixINin2YTZhdin2YTZiiDZgdmKDQrYp9mE
2YXYpNiz2LPYp9iqKiouKg0KDQrCtyAgICAgICAgIMK3ICAq2LHYqNi3INin2YTYqtmD2YbZiNmE
2YjYrNmK2Kcg2KfZhNmF2KfZhNmK2Kkg2KjYo9mH2K/Yp9mBINin2YTYp9iz2KrYr9in2YXYqSDZ
iNin2YTYtNmF2YjZhCDYp9mE2YXYp9mE2YoqDQoNCirYp9mE2YHYptipINin2YTZhdiz2KrZh9iv
2YHYqSoNCg0KICAgLSAq2KfZhNi52KfZhdmE2YjZhiDZgdmKINin2YTZhdik2LPYs9in2Kog2KfZ
hNmF2KfZhNmK2Kkg2YjYp9mE2YXYtdix2YHZitipLioNCiAgIC0gKtmF2K/Ysdin2KEg2KfZhNiq
2K3ZiNmEINin2YTYsdmC2YXZiiDZiNin2YTYqtmD2YbZiNmE2YjYrNmK2Kcg2YHZiiDYp9mE2LTY
sdmD2KfYqiDYp9mE2YXYp9mE2YrYqS4qDQogICAtICrYp9mE2YXYrdmE2YTZiNmGINin2YTZhdin
2YTZitmI2YYg2YjZhdi32YjYsdmIINin2YTYqNix2YXYrNmK2KfYqi4qDQogICAtICrYp9mE2YXZ
h9iq2YXZiNmGINio2KfZhNiq2K3ZiNmEINin2YTYsdmC2YXZiiDZiNiq2KjZhtmKINin2YTYqtmD
2YbZiNmE2YjYrNmK2Kcg2KfZhNmF2KfZhNmK2KkuKi4NCg0KDQoNCg0KDQoq2KfZhNmK2YjZhSDY
p9mE2KPZiNmEOiDZhdmC2K/ZhdipINmB2Yog2KfZhNiq2YPZhtmI2YTZiNis2YrYpyDYp9mE2YXY
p9mE2YrYqSDZiNmB2YfZhSDYp9mE2KrYrdmI2YQg2KfZhNix2YLZhdmKKg0KDQogICAtINmF2YHZ
h9mI2YUg2KfZhNiq2YPZhtmI2YTZiNis2YrYpyDYp9mE2YXYp9mE2YrYqSAoRmluVGVjaCkg2YjY
o9mH2YXZitiq2YfYpyDZgdmKINin2YTYudi12LEg2KfZhNit2K/ZitirLg0KICAgLSDYp9mE2KfY
qtis2KfZh9in2Kog2KfZhNi52KfZhNmF2YrYqSDZhNmE2KrYrdmI2YQg2KfZhNix2YLZhdmKINmB
2Yog2KfZhNmC2LfYp9i5INin2YTZhdin2YTZii4NCiAgIC0g2KfZhNmB2LHZgiDYqNmK2YYg2KfZ
hNij2YbYuNmF2Kkg2KfZhNmF2KfZhNmK2Kkg2KfZhNiq2YLZhNmK2K/ZitipINmI2KfZhNij2YbY
uNmF2Kkg2KfZhNix2YLZhdmK2KkuDQogICAtINiv2LHYp9iz2Kkg2K3Yp9mE2KfYqiDZhtin2KzY
rdipINmB2Yog2KfZhNiq2K3ZiNmEINin2YTYsdmC2YXZii4NCg0KLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tDQoNCirYp9mE2YrZiNmFINin2YTYq9in2YbZijog2KfZhNio2YbZitipINin
2YTYqtit2KrZitipINin2YTYsdmC2YXZitipINmI2KfZhNiu2K/Zhdin2Kog2KfZhNmF2LXYsdmB
2YrYqSDYp9mE2YXZgdiq2YjYrdipKg0KDQogICAtINin2YTYqNmG2YrYqSDYp9mE2KrYrdiq2YrY
qSDYp9mE2KrZg9mG2YjZhNmI2KzZitipINin2YTYr9in2LnZhdipINmE2YTYqtit2YjZhCDYp9mE
2YXYp9mE2YouDQogICAtINmI2KfYrNmH2KfYqiDYqNix2YXYrNipINin2YTYqti32KjZitmC2KfY
qiAoQVBJcykg2YjYr9mI2LHZh9inINmB2Yog2KfZhNiu2K/Zhdin2Kog2KfZhNmF2KfZhNmK2Kku
DQogICAtINmF2YHZh9mI2YUgKk9wZW4gQmFua2luZyog2YjYqtij2KvZitix2Ycg2LnZhNmJINin
2YTZhdi12KfYsdmBLg0KICAgLSDYp9mE2KrYrdiv2YrYp9iqINin2YTYqtmC2YbZitipINmB2Yog
2KrYt9io2YrZgiDYp9mE2KPZhti42YXYqSDYp9mE2YXZgdiq2YjYrdipLg0KDQotLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KKtin2YTZitmI2YUg2KfZhNir2KfZhNirOiDYrdmE2YjZ
hCDYp9mE2K/Zgdi5INin2YTYpdmE2YPYqtix2YjZhtmKINmI2KfZhNmF2K3Yp9mB2Lgg2KfZhNix
2YLZhdmK2KkqDQoNCiAgIC0g2KrZgtmG2YrYp9iqINin2YTYr9mB2Lkg2KfZhNit2K/Zitir2Kkg
KE1vYmlsZSBQYXltZW50cyDigJMgTkZDIOKAkyBRUiBDb2RlKS4NCiAgIC0g2KfZhNmF2K3Yp9mB
2Lgg2KfZhNil2YTZg9iq2LHZiNmG2YrYqSDZiNij2YbYuNmF2Kkg2KfZhNiv2YHYuSDYudio2LEg
2KfZhNmH2KfYqtmBINin2YTZhdit2YXZiNmELg0KICAgLSDYp9mE2LnZhdmE2KfYqiDYp9mE2LHZ
gtmF2YrYqSDZiNin2YTZhdi02YHYsdipIChDcnlwdG9jdXJyZW5jeSkg2YjYqtij2KvZitix2YfY
py4NCiAgIC0g2KPZhdmGINin2YTZhdiv2YHZiNi52KfYqiDZiNmF2YPYp9mB2K3YqSDYp9mE2KfY
rdiq2YrYp9mEINin2YTZhdin2YTZii4NCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
DQoNCirYp9mE2YrZiNmFINin2YTYsdin2KjYuTog2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin
2LnZiiDZiNiq2K3ZhNmK2YQg2KfZhNio2YrYp9mG2KfYqiDZgdmKINin2YTYqtmD2YbZiNmE2YjY
rNmK2Kcg2KfZhNmF2KfZhNmK2KkqDQoNCiAgIC0g2K/ZiNixINin2YTYsNmD2KfYoSDYp9mE2KfY
tdi32YbYp9i52Yog2YHZiiDYqtit2LPZitmGINin2YTYrtiv2YXYp9iqINin2YTZhdin2YTZitip
Lg0KICAgLSDYp9mE2KrYrdmE2YrZhNin2Kog2KfZhNiq2YbYqNik2YrYqSDZiNin2YTYqNmK2KfZ
htin2Kog2KfZhNi22K7ZhdipINmB2Yog2KfZhNmC2LfYp9i5INin2YTZhdin2YTZii4NCiAgIC0g
2KrYt9io2YrZgtin2KogKk1hY2hpbmUgTGVhcm5pbmcqINmB2Yog2KfZhNin2KbYqtmF2KfZhiDZ
iNil2K/Yp9ix2Kkg2KfZhNmF2K7Yp9i32LEuDQogICAtINit2KfZhNin2Kog2LnZhdmE2YrYqSDZ
hdmGINi02LHZg9in2KogRmluVGVjaCDYp9mE2LnYp9mE2YXZitipLg0KDQotLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0NCg0KKtin2YTZitmI2YUg2KfZhNiu2KfZhdizOiDYp9mE2KfZhdiq
2KvYp9mEINmI2KfZhNmE2YjYp9im2K0g4oCTINio2YbYp9ihINin2LPYqtix2KfYqtmK2KzZitip
INin2YTYqtit2YjZhCoNCg0KICAgLSDYp9mE2KPYt9ixINin2YTZgtin2YbZiNmG2YrYqSDZiNin
2YTYqtmG2LjZitmF2YrYqSDZhNmE2KrYrdmI2YQg2YbYrdmIINin2YTYqtmD2YbZiNmE2YjYrNmK
2Kcg2KfZhNmF2KfZhNmK2KkuDQogICAtINin2YTYp9mF2KrYq9in2YQg2YTZhdi52KfZitmK2LEg
2YXZg9in2YHYrdipINi62LPZhCDYp9mE2KPZhdmI2KfZhCDZiNiq2YXZiNmK2YQg2KfZhNil2LHZ
h9in2KggKEFNTC9DRlQpLg0KICAgLSDYqNmG2KfYoSDYrtin2LHYt9ipINi32LHZitmCINmE2YTY
qtit2YjZhCDYp9mE2LHZgtmF2Yog2YHZiiDYp9mE2YXYpNiz2LPYp9iqINin2YTZhdin2YTZitip
Lg0KICAgLSDZhdi02LHZiNi5INiq2LfYqNmK2YLZiiDZhNmI2LbYuSDYrti32Kkg2KrYrdmI2YQg
2LTYp9mF2YTYqS4NCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCvCfk4wgKtmF
2K7Ysdis2KfYqiDYp9mE2KjYsdmG2KfZhdisKio6Kg0KDQogICAtINi02YfYp9iv2Kkg2YXYudiq
2YXYr9ipINmB2YogKtin2YTYqtit2YjZkdmEINmG2K3ZiCDYp9mE2KrZg9mG2YjZhNmI2KzZitin
INin2YTZhdin2YTZitipKiogKENGVFQpKi4NCiAgIC0g2YXYudix2YHYqSDYp9mE2KPYr9mI2KfY
qiDZiNin2YTYqtmC2YbZitin2Kog2KfZhNmF2LPYqtiu2K/ZhdipINmB2YogRmluVGVjaC4NCiAg
IC0g2KfZhNmC2K/YsdipINi52YTZiSDZgtmK2KfYr9ipINmF2LTYsdmI2LnYp9iqINin2YTYqtit
2YjZhCDYp9mE2LHZgtmF2Yog2KfZhNmF2KfZhNmKLg0KDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0NCg0KKtmI2KjZh9iw2Ycg2KfZhNmF2YbYp9iz2KjYqSDZitiz2LnYr9mG2Kcg2K/Y
udmI2KrZg9mFINmE2YTZhdi02KfYsdmD2Kkg2YjYqti52YXZitmFINiu2LfYp9io2YbYpyDYudmE
2Ykg2KfZhNmF2YfYqtmF2YrZhg0K2KjZhdmA2YDZiNi22YDZiNi5ICoq2KfZhNi02YfYp9iv2Kkg
2KfZhNin2K3Yqtix2KfZgdmK2KkgKirZiNil2YHYp9iv2KrZhtinINio2YXZhiDYqtmC2KrYsdit
2YjZhiDYqtmI2KzZitmHINin2YTYr9i52YjYqSDZhNmH2YUqDQoNCirZhNmF2LLZitivINmF2YYg
2KfZhNmF2LnZhNmI2YXYp9iqINmK2YXZg9mG2YMg2KfZhNiq2YjYp9i12YQg2YXYuSDYoyAvINiz
2KfYsdipINi52KjYryDYp9mE2KzZiNin2K8g4oCTINmG2KfYptioINmF2K/ZitixDQrYp9mE2KrY
r9ix2YrYqCDigJMg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE
2KfYr9in2LHZitipKg0KDQoq2KzZiNin2YQg4oCTINmI2KfYqtizINin2KggOioNCg0KKjAwMjAx
MDY5OTk0Mzk5IC0wMDIwMTA2Mjk5MjUxMCAtIDAwMjAxMDk2ODQxNjI2Kg0KDQotLSAKWW91IHJl
Y2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29v
Z2xlIEdyb3VwcyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdy
b3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBr
YXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1
c3Npb24gdmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9D
QURqMVpLbXkxRXdoNVElM0QlMkJoMVhtLUh0M2MtX0ZYNlItUTd3WGJoY1dFR0g5OTZGSF9BJTQw
bWFpbC5nbWFpbC5jb20uCg==
--00000000000086c058063d155423
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"margin:0in 0in 0.0001pt;text-align:center;direction:rtl;unicode-bidi:em=
bed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&qu=
ot;"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Time=
s New Roman&quot;,&quot;serif&quot;">=D8=A3=D8=AD=D8=AF=D8=AB =D8=AA=D9=82=
=D9=86=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AF=D9=81=D8=B9 =D8=A7=D9=84=D8=A5=
=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A
=D9=88=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=81=D8=B8 =D8=A7=D9=84=D8=B1=D9=82=
=D9=85=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;f=
ont-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;">=E2=9C=94</span></b><b><span d=
ir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=
=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=88=D8=AA=D8=AD=
=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=81=
=D9=8A =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A</span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&=
quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;">=E2=9C=94</span></b><b><span d=
ir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=
=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84
=D9=88=D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=A6=D8=AD =D9=81=D9=8A =D8=A7=D9=84=
=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=D9=84=D9=85=
=D8=A7=D9=84=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:=
20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;">=E2=9C=94</span></b><b><span d=
ir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:2=
0pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A8=D9=86=
=D8=A7=D8=A1
=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9 =D8=B4=D8=A7=
=D9=85=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=
=D9=82=D9=85=D9=8A</span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;f=
ont-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;direction:rtl;unicode-bidi:embed;line-height:10=
7%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Segoe UI Symbol&quot;,&q=
uot;sans-serif&quot;">=E2=9C=85</span></b><b><span dir=3D"LTR" style=3D"fon=
t-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"> </s=
pan></b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;T=
imes New Roman&quot;,&quot;serif&quot;">=D8=A3=D8=B7=D9=84=D9=82
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA=D9=83 =D9=84=D8=AA=D8=B5=D8=A8=D8=AD =
=D9=82=D8=A7=D8=A6=D8=AF=D9=8B=D8=A7 =D9=81=D9=8A =D8=A7=D9=84=D8=AB=D9=88=
=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=B1=
=D9=82=D9=85=D9=8A=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span><b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span>!</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;direction:rtl;unicode-bidi:embed;line-height:10=
7%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Segoe UI Symbol&quot;,&q=
uot;sans-serif&quot;">=F0=9F=93=9E</span></b><b><span dir=3D"LTR" style=3D"=
font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"> =
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quo=
t;Times New Roman&quot;,&quot;serif&quot;">=D9=84=D9=84=D8=AD=D8=AC=D8=B2
=D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1</span></b><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D=
"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;direction:rtl;unicode-bidi:embed;line-height:10=
7%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">00201062992510
- 01096841626</span></b><b><span lang=3D"AR-EG" style=3D"font-size:20pt;fon=
t-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;direction:rtl;unicode-bidi:embed;line-height:10=
7%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-EG" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;">=D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=85 =D8=B9=D9=84=D9=8A=
=D9=83=D9=85
=D9=88=D8=B1=D8=AD=D9=85=D8=A9 =D8=A7=D9=84=D9=84=D9=87 =D9=88=D8=A8=D8=B1=
=D9=83=D8=A7=D8=AA=D8=A9</span></b><span dir=3D"LTR" style=3D"font-size:20p=
t;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"A=
R-EG" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot=
;serif&quot;;color:black">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=
=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=
=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D8=AA=D9=87=D8=AF=D9=8A=D9=83=
=D9=85 =D8=A7=D8=B7=D9=8A=D8=A8
=D8=A7=D9=84=D8=AA=D8=AD=D9=8A=D8=A7=D8=AA =D9=88=D8=AA=D9=82=D8=AF=D9=85 =
=D9=84=D9=83=D9=85</span></b><span lang=3D"AR-SA" style=3D"font-size:20pt;f=
ont-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot=
;,&quot;serif&quot;;color:rgb(227,108,10)">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =
=D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=91=D9=84 =D9=86=D8=AD=D9=88
=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=
=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 (</span></b><b><span dir=3D"LTR" style=
=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot=
;;color:rgb(227,108,10)">CFTT</span></b><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family=
:&quot;Times New Roman&quot;,&quot;serif&quot;;color:rgb(227,108,10)"><span=
 dir=3D"RTL"></span><span dir=3D"RTL"></span>)</span></b><span dir=3D"LTR" =
style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif=
&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span di=
r=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&=
quot;serif&quot;;color:rgb(31,73,125)">Certified Financial
Technology Transformation</span></b><span lang=3D"AR-SA" style=3D"font-size=
:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></p=
>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot=
;,&quot;serif&quot;;color:rgb(0,112,192);background:lightgrey">=D8=A8=D8=B4=
=D9=87=D8=A7=D8=AF=D8=A9
=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span></b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot=
;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><u><span=
 lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&q=
uot;,&quot;serif&quot;;color:black;background:lightgrey">=D9=88=D9=8A=D9=88=
=D8=AC=D8=AF
=D8=AE=D8=B5=D9=85 =D8=AE=D8=A7=D8=B5 =D9=84=D9=84=D9=85=D8=AC=D9=85=D9=88=
=D8=B9=D8=A7=D8=AA</span></u></b><span lang=3D"AR-SA" style=3D"font-size:20=
pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Segoe UI Emoji&quot;,&qu=
ot;sans-serif&quot;">=F0=9F=93=85</span><span dir=3D"LTR" style=3D"font-siz=
e:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=C2=A0</s=
pan><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D9=85=D9=88=D8=B9=D8=AF =D8=A7=D9=84=
=D8=AF=D9=88=D8=B1=D8=A9</span></b><span lang=3D"AR-SA" style=3D"font-size:=
20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">:=C2=A0=D9=
=85=D9=86
31 =D8=A7=D8=BA=D8=B3=D8=B7=D8=B3 =D8=A7=D9=84=D9=89 4 =D8=B3=D8=A8=D8=AA=
=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"LTR" style=3D"font-size:20pt;fon=
t-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Segoe UI=
 Emoji&quot;,&quot;sans-serif&quot;">=F0=9F=93=8D</span><span dir=3D"LTR" s=
tyle=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&=
quot;">=C2=A0</span><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-fa=
mily:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=85=D9=
=83=D8=A7=D9=86</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
><b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New R=
oman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>:</span></b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quo=
t;Times New Roman&quot;,&quot;serif&quot;">=C2=A0</span><span lang=3D"AR-SA=
" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;ser=
if&quot;">=D8=A7=D9=88=D9=86 =D9=84=D8=A7=D9=8A=D9=86 (</span><span dir=3D"=
LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">ZOOM</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><=
span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Rom=
an&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></sp=
an>) =D9=81=D9=89 =D8=AD=D9=8A=D9=86 =D8=AA=D8=B9=D8=B0=D8=B1 =D8=A7=D9=84=
=D8=AD=D8=B6=D9=88=D8=B1</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><u><span=
 lang=3D"AR-EG" style=3D"font-size:20pt;font-family:&quot;Simplified Arabic=
&quot;,&quot;serif&quot;;color:rgb(227,108,10)">=D8=A7=D9=84=D9=85=D9=82=D8=
=AF=D9=85=D8=A9</span></u></b><span lang=3D"AR-SA" style=3D"font-size:20pt;=
font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot=
;,&quot;serif&quot;">=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=AA=D8=AF=D8=
=B1=D9=8A=D8=A8=D9=8A =D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A =D9=8A=D8=
=B1=D9=83=D8=B2 =D8=B9=D9=84=D9=89
=D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=A8=D8=AA=D9=83=D8=B1=D8=A9 (</span=
></b><b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:Cambria,&quot=
;serif&quot;">FinTech</span></b><span dir=3D"RTL"></span><span dir=3D"RTL">=
</span><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span>)
=D9=85=D8=AB=D9=84 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=
=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A=D8=8C =D8=A7=D9=84=D8=A8=D9=84=D9=88=
=D9=83=D8=AA=D8=B4=D9=8A=D9=86=D8=8C =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=81=
=D8=B8 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9=D8=8C =D8=A7=D9=84=D8=AA=
=D9=85=D9=88=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=8C =D9=85=
=D9=86=D8=B5=D8=A7=D8=AA =D8=A7=D9=84=D8=AF=D9=81=D8=B9
=D8=A7=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A.</span></b><sp=
an lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman=
&quot;,&quot;serif&quot;">=C2=A0<b>=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=
=84=D9=88=D8=AC=D9=8A=D8=A7
=D9=88=D8=A7=D9=84=D8=A7=D8=A8=D8=AA=D9=83=D8=A7=D8=B1</b></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot=
;,&quot;serif&quot;">=D8=A7=D9=84=D8=B0=D9=8A =D9=8A=D9=87=D8=AF=D9=81 =D8=
=A5=D9=84=D9=89 =D8=A7=D9=84=D8=AA=D9=86=D8=A7=D9=81=D8=B3 =D9=85=D8=B9 =D8=
=A7=D9=84=D8=A3=D8=B3=D8=A7=D9=84=D9=8A=D8=A8
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=82=D9=84=
=D9=8A=D8=AF=D9=8A=D8=A9 =D9=81=D9=8A =D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=A7=
=D9=84=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=
=D8=A9 =D8=A5=D9=86=D9=87=D8=A7 =D8=B5=D9=86=D8=A7=D8=B9=D8=A9 =D9=86=D8=A7=
=D8=B4=D8=A6=D8=A9 =D8=AA=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D8=A7=D9=84=D8=AA=
=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7
=D9=84=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=A7=D9=84=D8=A3=D9=86=D8=B4=D8=B7=
=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=85=D9=88=D9=8A=D9=84 =D9=85=D9=86=
 =D8=AE=D9=84=D8=A7=D9=84 =D9=87=D8=B0=D8=A7 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=
=D8=A7=D9=85=D8=AC =D8=B3=D9=8A=D8=AA=D8=B9=D8=B1=D9=81 =D8=A7=D9=84=D9=85=
=D8=AA=D8=AF=D8=B1=D8=A8 =D8=B9=D9=84=D9=89 =D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=
=D8=A7=D8=AA
=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=
=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88 =D8=A7=D9=84=D8=A5=D8=AC=D8=B1=
=D8=A7=D8=A1=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D9=85=D9=86=D9=8A=D8=A9 =D9=88 =
=D8=B7=D8=B1=D9=82 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=
=D8=A7=D8=B7=D8=B1 =D8=A7=D9=84=D9=85=D8=B1=D8=AA=D8=A8=D8=B7=D8=A9 =D8=A8=
=D9=87</span></b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&=
quot;Times New Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot=
;,&quot;serif&quot;">=D9=8A=D8=B1=D8=A8=D8=B7 =D8=A8=D9=8A=D9=86 =D8=A7=D9=
=84=D8=AC=D8=A7=D9=86=D8=A8 =D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A =D9=88=D8=
=A7=D9=84=D8=AC=D8=A7=D9=86=D8=A8
=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A =D9=81=
=D9=8A =D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A.</span></b><span lang=3D"AR-SA"=
 style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;seri=
f&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><u><span=
 lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&q=
uot;,&quot;serif&quot;;color:rgb(227,108,10)">=D8=A7=D9=84=D8=A7=D9=87=D8=
=AF=D8=A7=D9=81</span></u></b><span lang=3D"AR-SA" style=3D"font-size:20pt;=
font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=AA=D8=B9=D8=B1=D9=8A=D9=81 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=
=D8=B1=D9=83=D9=8A=D9=86 =D8=A8=D9=85=D9=81=D8=A7=D9=87=D9=8A=D9=85 =D9=88=
=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=83=D9=86=
=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=
=D8=A9 =D9=88=D8=AA=D8=B7=D9=88=D8=B1=D9=87=D8=A7
=D8=B9=D8=A7=D9=84=D9=85=D9=8A=D9=8B=D8=A7</span></b><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt"><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></b><span lang=3D"=
AR-SA" style=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=AA=D9=85=D9=83=D9=8A=D9=86 =D8=A7=D9=84=D9=82=D8=A7=D8=AF=
=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=AF=D9=8A=D8=B1=D9=8A=D9=86 =D9=85=D9=86 =
=D8=B5=D9=8A=D8=A7=D8=BA=D8=A9 =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=
=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=
=D8=B1=D9=82=D9=85=D9=8A
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D8=AF=D8=A7=D8=AE=D9=84 =D9=85=D8=A4=
=D8=B3=D8=B3=D8=A7=D8=AA=D9=87=D9=85</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></b><span lang=3D"AR-SA"=
 style=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=82=D8=AF=D8=B1=
=D8=A9 =D8=B9=D9=84=D9=89 =D8=AA=D8=B5=D9=85=D9=8A=D9=85 =D9=88=D8=AA=D9=86=
=D9=81=D9=8A=D8=B0 =D8=AE=D8=A7=D8=B1=D8=B7=D8=A9 =D8=B7=D8=B1=D9=8A=D9=82 =
=D9=84=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=D8=AF =D8=AD=D9=84=D9=88=D9=84
=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=
=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></b><span lang=3D"AR-SA"=
 style=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=A7=D9=84=D8=AA=D8=B9=D8=B1=D9=81 =D8=B9=D9=84=D9=89 =D8=A3=
=D8=AD=D8=AF=D8=AB =D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA =
=D9=85=D8=AB=D9=84 =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=81=D8=B8 =D8=A7=D9=84=
=D8=B1=D9=82=D9=85=D9=8A=D8=A9=D8=8C =D8=A7=D9=84=D8=A8=D9=86=D9=88=D9=83
=D8=A7=D9=84=D8=A7=D9=81=D8=AA=D8=B1=D8=A7=D8=B6=D9=8A=D8=A9=D8=8C =D9=88=
=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=
=D8=B1=D9=88=D8=A8=D9=88=D8=AA=D9=8A=D8=A9</span></b><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt"><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></b><span lang=3D"=
AR-SA" style=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2 =D9=85=D9=87=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=
=D8=B1 =D9=88=D8=A7=D9=84=D9=81=D8=B1=D8=B5 =D8=A7=D9=84=D9=85=D8=B1=D8=AA=
=D8=A8=D8=B7=D8=A9 =D8=A8=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=
=D8=AC=D9=8A=D8=A7 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span></b><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=
=3D"font-size:20pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></b><span lang=3D"AR-SA" style=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D9=81=D9=87=D9=85 =D8=A7=D9=84=D8=AA=D8=B4=D8=B1=D9=8A=D8=B9=
=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=82=D9=88=D8=A7=D9=86=D9=8A=D9=86 =D8=A7=
=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A9 =D9=84=D9=84=D8=AA=D9=83=D9=86=D9=88=
=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =
=D9=85=D8=AD=D9=84=D9=8A=D9=8B=D8=A7
=D9=88=D8=B9=D8=A7=D9=84=D9=85=D9=8A=D9=8B=D8=A7</span></b><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:2=
0pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></b><span la=
ng=3D"AR-SA" style=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=A5=D9=83=D8=B3=D8=A7=D8=A8 =D8=A7=D9=84=D9=85=D8=AA=D8=AF=
=D8=B1=D8=A8=D9=8A=D9=86 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D9=82=D9=8A=D8=A7=
=D8=B3 =D8=A7=D9=84=D8=B9=D8=A7=D8=A6=D8=AF =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D8=A7=D8=B3=D8=AA=D8=AB=D9=85=D8=A7=D8=B1 =D9=81=D9=8A =D9=85=D8=B4=D8=A7=
=D8=B1=D9=8A=D8=B9
=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=
=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></b><span lang=3D"AR-SA"=
 style=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=AA=D8=A3=D9=87=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=
=D8=B1=D9=83=D9=8A=D9=86 =D9=84=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=
=D8=B9 =D8=A7=D9=84=D8=AA=D8=AD=D8=AF=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=
=D9=86=D8=B8=D9=8A=D9=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A3=D9=85=D9=86
=D8=A7=D9=84=D8=B3=D9=8A=D8=A8=D8=B1=D8=A7=D9=86=D9=8A =D9=81=D9=8A =D8=AD=
=D9=84=D9=88=D9=84</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan><b><span dir=3D"LTR" style=3D"font-size:20pt"><span dir=3D"LTR"></span>=
<span dir=3D"LTR"></span>=C2=A0FinTech.</span></b><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-hei=
ght:107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=B7</span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b>=
<span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D9=83=D9=88=D8=A7=D8=AF=D8=B1 =
=D9=82=D8=A7=D8=AF=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D9=82=D9=8A=D8=A7=D8=AF=
=D8=A9 =D9=85=D8=A8=D8=A7=D8=AF=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=D8=A8=
=D8=AA=D9=83=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D9=81=D9=8A
=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA</span></b><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:2=
0pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></b><span la=
ng=3D"AR-SA" style=3D"font-size:20pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:1=
07%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:=
20pt;font-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
=C2=B7</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=
=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,=
&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;fon=
t-family:Symbol"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=B7</=
span><span dir=3D"LTR" style=3D"font-size:20pt">=C2=A0=C2=A0</span><b><span=
 lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,&quot;sans-serif&=
quot;">=D8=B1=D8=A8=D8=B7 =D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=
=D8=AC=D9=8A=D8=A7 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A8=D8=A3=
=D9=87=D8=AF=D8=A7=D9=81 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=
=D8=A9 =D9=88=D8=A7=D9=84=D8=B4=D9=85=D9=88=D9=84 =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A</span></b><span lang=3D"AR-SA" style=3D"font-size:20pt"></span=
></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><u><span=
 lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&q=
uot;,&quot;serif&quot;;color:rgb(227,108,10)">=D8=A7=D9=84=D9=81=D8=A6=D8=
=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span></u></b><s=
pan lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roma=
n&quot;,&quot;serif&quot;"></span></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0.0001pt 0in=
;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-=
SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;s=
erif&quot;">=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=D9=88=D9=86 =D9=81=D9=8A =
=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A=D8=A9
     =D9=88=D8=A7=D9=84=D9=85=D8=B5=D8=B1=D9=81=D9=8A=D8=A9.</span></b><spa=
n lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&=
quot;,&quot;serif&quot;"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0.0001pt 0in=
;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-=
SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;s=
erif&quot;">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D8=AA=D8=AD=D9=88=
=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A
     =D9=88=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=
=A7 =D9=81=D9=8A =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=AA =D8=A7=D9=84=D9=
=85=D8=A7=D9=84=D9=8A=D8=A9.</span></b><span lang=3D"AR-SA" style=3D"font-s=
ize:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span>=
</li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0.0001pt 0in=
;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-=
SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;s=
erif&quot;">=D8=A7=D9=84=D9=85=D8=AD=D9=84=D9=84=D9=88=D9=86 =D8=A7=D9=84=
=D9=85=D8=A7=D9=84=D9=8A=D9=88=D9=86 =D9=88=D9=85=D8=B7=D9=88=D8=B1=D9=88
     =D8=A7=D9=84=D8=A8=D8=B1=D9=85=D8=AC=D9=8A=D8=A7=D8=AA.</span></b><spa=
n lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&=
quot;,&quot;serif&quot;"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0.0001pt 0in=
;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"AR-=
SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;s=
erif&quot;">=D8=A7=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=88=D9=86 =D8=A8=D8=A7=
=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=88=
=D8=AA=D8=A8=D9=86=D9=8A
     =D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=
=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9.</span></b><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-fa=
mily:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></spa=
n><span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA" style=3D"font-size:=
20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></li=
>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0.0001pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-=
bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span=
 lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&q=
uot;,&quot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-se=
rif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"A=
R-SA" style=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans=
-serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=A3=D9=88=D9=84=
: =D9=85=D9=82=D8=AF=D9=85=D8=A9
=D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=
=D8=A7 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D9=81=D9=87=D9=85 =
=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</=
span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"></s=
pan></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D9=85=D9=81=D9=87=D9=88=D9=85 =D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=
=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</spa=
n><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=
=3D"font-size:20pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span> (FinTech) </span><span lang=3D"AR-SA" style=3D"font-size:20pt;=
line-height:107%;font-family:Arial,&quot;sans-serif&quot;">=D9=88=D8=A3=D9=
=87=D9=85=D9=8A=D8=AA=D9=87=D8=A7 =D9=81=D9=8A =D8=A7=D9=84=D8=B9=D8=B5=D8=
=B1 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB</span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-height=
:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D8=A7=D8=AA=D8=AC=D8=A7=D9=87=D8=A7=D8=AA =D8=A7=D9=84=D8=
=B9=D8=A7=D9=84=D9=85=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=
=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=82=D8=B7=D8=
=A7=D8=B9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A</span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-=
height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li=
>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D9=81=D8=B1=D9=82 =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D8=A3=D9=
=86=D8=B8=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A7=D9=
=84=D8=AA=D9=82=D9=84=D9=8A=D8=AF=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A3=D9=
=86=D8=B8=D9=85=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:20pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=AF=D8=B1=D8=A7=D8=B3=D8=A9 =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D9=86=D8=
=A7=D8=AC=D8=AD=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=
=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:20pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"A=
R-SA" style=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans=
-serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=
=D9=8A: =D8=A7=D9=84=D8=A8=D9=86=D9=8A=D8=A9
=D8=A7=D9=84=D8=AA=D8=AD=D8=AA=D9=8A=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=D9=85=
=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=A7=D9=84=
=D9=85=D8=B5=D8=B1=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=81=D8=AA=D9=88=
=D8=AD=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;line-he=
ight:107%"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D8=A8=D9=86=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D8=AD=D8=AA=D9=
=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=
=A9 =D8=A7=D9=84=D8=AF=D8=A7=D8=B9=D9=85=D8=A9 =D9=84=D9=84=D8=AA=D8=AD=D9=
=88=D9=84 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A</span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-=
height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li=
>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D9=88=D8=A7=D8=AC=D9=87=D8=A7=D8=AA =D8=A8=D8=B1=D9=85=D8=AC=D8=A9 =D8=
=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;=
line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (APIs)=
 </span><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:107%;font-=
family:Arial,&quot;sans-serif&quot;">=D9=88=D8=AF=D9=88=D8=B1=D9=87=D8=A7 =
=D9=81=D9=8A =D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D9=85=
=D8=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D9=85=D9=81=D9=87=D9=88=D9=85 </span><b><span dir=3D"LTR" style=3D"font=
-size:20pt;line-height:107%">Open Banking</span></b><span dir=3D"LTR" style=
=3D"font-size:20pt;line-height:107%"> </span><span lang=3D"AR-SA" style=3D"=
font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot;">=
=D9=88=D8=AA=D8=A3=D8=AB=D9=8A=D8=B1=D9=87 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D9=85=D8=B5=D8=A7=D8=B1=D9=81</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D8=AA=D8=AD=D8=AF=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=
=82=D9=86=D9=8A=D8=A9 =D9=81=D9=8A =D8=AA=D8=B7=D8=A8=D9=8A=D9=82 =D8=A7=D9=
=84=D8=A3=D9=86=D8=B8=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D9=81=D8=AA=D9=88=D8=
=AD=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:20pt;line-height:107%"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:20pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"A=
R-SA" style=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans=
-serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=84=
=D8=AB: =D8=AD=D9=84=D9=88=D9=84
=D8=A7=D9=84=D8=AF=D9=81=D8=B9 =D8=A7=D9=84=D8=A5=D9=84=D9=83=D8=AA=D8=B1=
=D9=88=D9=86=D9=8A =D9=88=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=81=D8=B8 =D8=A7=
=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=
=3D"font-size:20pt;line-height:107%"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=AA=D9=82=D9=86=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AF=D9=81=D8=B9 =D8=
=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9</span><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:=
107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (Mobile Payments =
=E2=80=93 NFC =E2=80=93 QR Code).</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=81=D8=B8 =D8=A7=D9=84=D8=A5=D9=84=D9=
=83=D8=AA=D8=B1=D9=88=D9=86=D9=8A=D8=A9 =D9=88=D8=A3=D9=86=D8=B8=D9=85=D8=
=A9 =D8=A7=D9=84=D8=AF=D9=81=D8=B9 =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D9=87=D8=
=A7=D8=AA=D9=81 =D8=A7=D9=84=D9=85=D8=AD=D9=85=D9=88=D9=84</span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:20pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D8=B9=D9=85=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=B1=D9=82=D9=
=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B4=D9=81=D8=B1=D8=A9</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:20pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span> (Cryptocurrency) </span><span lang=3D"AR-SA" style=3D"font-size:20pt=
;line-height:107%;font-family:Arial,&quot;sans-serif&quot;">=D9=88=D8=AA=D8=
=A3=D8=AB=D9=8A=D8=B1=D9=87=D8=A7</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A3=D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=AF=D9=81=D9=88=D8=B9=D8=A7=D8=
=AA =D9=88=D9=85=D9=83=D8=A7=D9=81=D8=AD=D8=A9 =D8=A7=D9=84=D8=A7=D8=AD=D8=
=AA=D9=8A=D8=A7=D9=84 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A</span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:20pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
>.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:20pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"A=
R-SA" style=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans=
-serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=B1=D8=A7=D8=A8=
=D8=B9: =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=88=D8=AA=D8=AD=
=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=81=
=D9=8A =D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" s=
tyle=3D"font-size:20pt;line-height:107%"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=AF=D9=88=D8=B1 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=
=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=AA=D8=AD=D8=B3=D9=
=8A=D9=86 =D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=
=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=
=AA=D9=86=D8=A8=D8=A4=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=
=86=D8=A7=D8=AA =D8=A7=D9=84=D8=B6=D8=AE=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=
=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:20pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA </span><b><span dir=3D"LTR" s=
tyle=3D"font-size:20pt;line-height:107%">Machine Learning</span></b><span d=
ir=3D"LTR" style=3D"font-size:20pt;line-height:107%"> </span><span lang=3D"=
AR-SA" style=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;san=
s-serif&quot;">=D9=81=D9=8A =D8=A7=D9=84=D8=A7=D8=A6=D8=AA=D9=85=D8=A7=D9=
=86 =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=
=B7=D8=B1</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:20pt;line-height:107%"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=85=D9=
=86 =D8=B4=D8=B1=D9=83=D8=A7=D8=AA</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span> FinTech </span><span la=
ng=3D"AR-SA" style=3D"font-size:20pt;line-height:107%;font-family:Arial,&qu=
ot;sans-serif&quot;">=D8=A7=D9=84=D8=B9=D8=A7=D9=84=D9=85=D9=8A=D8=A9</span=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=
=3D"font-size:20pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span>.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:20pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"A=
R-SA" style=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans=
-serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AE=D8=A7=D9=85=
=D8=B3:
=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84 =D9=88=D8=A7=D9=84=D9=84=
=D9=88=D8=A7=D8=A6=D8=AD =E2=80=93 =D8=A8=D9=86=D8=A7=D8=A1 =D8=A7=D8=B3=D8=
=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D8=AD=D9=
=88=D9=84</span></b><b><span dir=3D"LTR" style=3D"font-size:20pt;line-heigh=
t:107%"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D8=A3=D8=B7=D8=B1 =D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=
=86=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=D9=85=D9=8A=D8=
=A9 =D9=84=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D9=86=D8=AD=D9=88 =D8=A7=D9=84=D8=
=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=D9=84=D9=85=D8=
=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84 =D9=84=D9=85=D8=B9=D8=
=A7=D9=8A=D9=8A=D8=B1 =D9=85=D9=83=D8=A7=D9=81=D8=AD=D8=A9 =D8=BA=D8=B3=D9=
=84 =D8=A7=D9=84=D8=A3=D9=85=D9=88=D8=A7=D9=84 =D9=88=D8=AA=D9=85=D9=88=D9=
=8A=D9=84 =D8=A7=D9=84=D8=A5=D8=B1=D9=87=D8=A7=D8=A8</span><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt=
;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (AML/=
CFT).</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A8=D9=86=D8=A7=D8=A1 =D8=AE=D8=A7=D8=B1=D8=B7=D8=A9 =D8=B7=D8=B1=D9=
=8A=D9=82 =D9=84=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=
=85=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=
=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:=
107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D9=85=D8=B4=D8=B1=D9=88=D8=B9 =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=8A =D9=
=84=D9=88=D8=B6=D8=B9 =D8=AE=D8=B7=D8=A9 =D8=AA=D8=AD=D9=88=D9=84 =D8=B4=D8=
=A7=D9=85=D9=84=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:20pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:20pt;line-height:107%;font-family:&quot;Segoe UI Symbol&=
quot;,&quot;sans-serif&quot;">=F0=9F=93=8C</span><span dir=3D"LTR" style=3D=
"font-size:20pt;line-height:107%"> </span><b><span lang=3D"AR-SA" style=3D"=
font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot;">=
=D9=85=D8=AE=D8=B1=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=
=D9=85=D8=AC</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b=
><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"><span dir=3D"L=
TR"></span><span dir=3D"LTR"></span>:</span></b><span dir=3D"LTR" style=3D"=
font-size:20pt;line-height:107%"></span></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D9=
=81=D9=8A <b>=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=91=D9=84 =D9=86=D8=AD=D9=88 =
=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D8=A7=
=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</b></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt;line-hei=
ght:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (CFTT)</span><=
/b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%">.</span></li=
>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D9=85=D8=B9=D8=B1=D9=81=D8=A9 =D8=A7=D9=84=D8=A3=D8=AF=D9=88=D8=A7=D8=
=AA =D9=88=D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=
=85=D8=B3=D8=AA=D8=AE=D8=AF=D9=85=D8=A9 =D9=81=D9=8A</span><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt=
;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> FinTe=
ch.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D9=82=D8=AF=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D9=82=D9=8A=D8=
=A7=D8=AF=D8=A9 =D9=85=D8=B4=D8=B1=D9=88=D8=B9=D8=A7=D8=AA =D8=A7=D9=84=D8=
=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D8=A7=D9=84=D9=
=85=D8=A7=D9=84=D9=8A</span><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:20pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quo=
t;">=D9=88=D8=A8=D9=87=D8=B0=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=
=A8=D8=A9 =D9=8A=D8=B3=D8=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=
=83=D9=85 =D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=
=B9=D9=85=D9=8A=D9=85 =D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=
=89
=D8=A7=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=
=D9=88=D8=B6=D9=80=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" styl=
e=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=
=D9=81=D9=8A=D8=A9=C2=A0</span></b><b><span lang=3D"AR-SA" style=3D"font-si=
ze:16pt;font-family:Arial,&quot;sans-serif&quot;">=D9=88=D8=A5=D9=81=D8=A7=
=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=D9=86 =D8=AA=D9=82=D8=AA=D8=B1=D8=AD=
=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D8=AF=D8=B9=D9=88=
=D8=A9 =D9=84=D9=87=D9=85</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quo=
t;">=D9=84=D9=85=D8=B2=D9=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=
=84=D9=88=D9=85=D8=A7=D8=AA =D9=8A=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=
=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9 =D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9 =
=D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93
=D9=86=D8=A7=D8=A6=D8=A8 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=
=D8=B1=D9=8A=D8=A8 =E2=80=93 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=
=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=
=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b><span lang=3D"AR-SA=
"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span la=
ng=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;sans-serif&quo=
t;">=D8=AC=D9=88=D8=A7=D9=84 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=
=A8 :</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
107%;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:16pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>0020106999439=
9 -00201062992510 - 00201096841626</span></b><span lang=3D"AR-SA"></span></=
p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:20pt;line-height:107%">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKmy1Ewh5Q%3D%2Bh1Xm-Ht3c-_FX6R-Q7wXbhcWEGH996FH_A%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CADj1ZKmy1Ewh5Q%3D%2Bh1Xm-Ht3c-_FX6R-Q7wXbhcWEGH996FH_A%40=
mail.gmail.com</a>.<br />

--00000000000086c058063d155423--
