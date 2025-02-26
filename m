Return-Path: <kasan-dev+bncBD47LZVWXQIBBZF47S6QMGQEVVXOUNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 96F2EA46188
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 15:00:06 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5fe86c28863sf2557925eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 06:00:06 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740578405; x=1741183205; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5VPxkowohGoiFASLPLbyBkR0izJQaD/0ISC51KPqoyo=;
        b=RN2vw9xTPau3ovUeL6kVGqNLjiyyGvZf3H1vjtYjrqWUJ5PLbOQZbETI3wmDiV6t1E
         t33F3BE+DoWRCPBZl7tDK7sdHVJBG10jd9y52nvJji337DuDwjbC9GVwhr79jwpOiCyS
         wMjwnXBRIpKdMR8lZubwAvHHy0+jjUpCINfmlu7pnUBhXnkwSSs58fKzNMKDBJNYN2rz
         Gci7MjAl6WWfGK2NWG6/oZTjYMaET9Z+vETRCYtoDjPwEZU+Z3i/5E98mMxwal4HCplr
         DAoSSG0RgL4xEoT4re6ji8yycxjTrgMfJz0qICYOHPBxRNw5/pkTLdHtIPvM276bhBFj
         FeDA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740578405; x=1741183205; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5VPxkowohGoiFASLPLbyBkR0izJQaD/0ISC51KPqoyo=;
        b=T4qDA5ZA1bj4NmnpFMtf8VUbIQnYGZsCN92S9rEi7+Q/qeohLS614QqLs1ZrwcUF7l
         tR2o8rtPn2vzl3O0hbnOuYM4Gsb8Hc90izcPH3pnOChBwIULm11BweekRu6BadTChfbU
         X8073l085QJNwOx2r9oNwg4m+ea53Bs0urOWqfyBdw4hl/dl5HeRmOvFkA4sknBx/zI2
         xhjrakGLIzhEMSoEfuyewliNakugHAW/wuT8Qag7jqaYLeuroLIZtCgVy1MRamewauA6
         QA7T8ni4Isj0SKqyexxb73m/E/eo5xwV8gL6wC8zo9ShJk8WjF/RAyTMgAUkWiQAGp/m
         gX/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740578405; x=1741183205;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5VPxkowohGoiFASLPLbyBkR0izJQaD/0ISC51KPqoyo=;
        b=At8wyYh4YwZS0Lknfb9LRMgT1ASv9fg13cfw0OZfQ0/vORXJKKBLFdrFPpPJjNS9Hu
         tDGZj4yuG0ScnY8HId3kBng6j8b+P4PyuDz7u4BJRHeyGaZ4Hh6LuK2XRPz54eTpo18y
         BYwV7jG/aFNVAEVa+UTeYTJB/qJV8AkGPhlIUgTMo1xysH4JddHurGGxuwliqeRXixRO
         N8aniNAcRta9lNJQqo6Ou/vh2tWIMNNYhsmlX7D39UujAV7vA5aUK94kU1QmRnAfbFgL
         P5Szr/vqA0PBeXMaYlVtc7oUNcfzK7KIJZJCCFFfwPt9bOxgJjm/9JUPvACjG+Y0fYGv
         oi4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCVxvFM7yCy8I3DHz/817EhdFAIi5YC2bdtp7vVaEkXWxg8/a0Zx4r1LWkzArOlZbXZnTOXzXA==@lfdr.de
X-Gm-Message-State: AOJu0YwA2LvdFmEF+baKfQdcNy5sRlp8DAM44djCbDtvc8Bi+nAXoNlZ
	rOacXguTZAtuQkvm+8RM9WP5imx8GW0D0S85wALAsbsjzx4+jIXK
X-Google-Smtp-Source: AGHT+IENRkDEInj28S5OcKHci/JCoSv1HwQeMqdM5P8W4ldtIajHFRbHsg6PXrdtumI5sedLs8m39Q==
X-Received: by 2002:a05:6871:6c14:b0:295:eb96:9fd4 with SMTP id 586e51a60fabf-2bd50d0b6b6mr15336884fac.11.1740578404783;
        Wed, 26 Feb 2025 06:00:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGPIlzb/DtPqbvE0HJuLRntbuAwJ9rG10/p0lky0ep1Jw==
Received: by 2002:a05:6871:440d:b0:2c1:415a:8e26 with SMTP id
 586e51a60fabf-2c1415a98acls176350fac.2.-pod-prod-06-us; Wed, 26 Feb 2025
 06:00:04 -0800 (PST)
X-Received: by 2002:a05:6808:198d:b0:3f4:1a7d:959f with SMTP id 5614622812f47-3f540eb932cmr4731765b6e.1.1740578403595;
        Wed, 26 Feb 2025 06:00:03 -0800 (PST)
Date: Wed, 26 Feb 2025 06:00:02 -0800 (PST)
From: Jeremy Shurtleff <jeremyshurtleff54@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <d9043028-8862-460b-9043-4478c086dec0n@googlegroups.com>
Subject: =?UTF-8?B?2K3YqNmI2Kgg2KfZhNil2KzZh9in2LYg2YHZiiDYr9io2Yo=?=
 =?UTF-8?B?6qeFKCgrOTcxNTA3MDk3NzM4KSnqp4Up?=
 =?UTF-8?B?2LTYsdin2KEg2LPYp9mK2KrZiNiq2YMgLyDYp9mE2KfZhQ==?=
 =?UTF-8?B?2KfYsdin2Kog2KfZhNi52LHYqNmK2Kkg2KfZhNmF2KrYrdiv2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_56906_2037775445.1740578402931"
X-Original-Sender: jeremyshurtleff54@gmail.com
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

------=_Part_56906_2037775445.1740578402931
Content-Type: multipart/alternative; 
	boundary="----=_Part_56907_482327485.1740578402931"

------=_Part_56907_482327485.1740578402931
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YTZhNiq2YjYp9i12YQg2YXYudmG2Kcg2LnZhNmJINix2YLZhdmG2Kcg2KfZhNin2YXYp9ix2KfY
qtmKIDAwOTcxNTA3MDk3NzM4INmE2LfZhNioINit2KjZiNioINiz2KfZitiq2YjYqtmDINmB2Yog
Ctin2YTYp9mF2KfYsdin2KoK2KfZhNiv2YHYuSDYudmG2K8g2KfZhNin2LPYqtmE2KfZhSDZiNin
2YTYqtmI2LXZitmEINin2YTZiSDYqNin2Kgg2KfZhNmF2YbYstmECtin2YTYqtmI2LXZitmEINmI
2KfZhNmF2LnYp9mK2YbYqSDZiNin2YTZhdiq2KfYqNi52Kkg2YXYrNin2YbZitipDQoNCi0tIApZ
b3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRo
ZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRo
aXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWls
IHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMg
ZGlzY3Vzc2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4t
ZGV2L2Q5MDQzMDI4LTg4NjItNDYwYi05MDQzLTQ0NzhjMDg2ZGVjMG4lNDBnb29nbGVncm91cHMu
Y29tLgo=
------=_Part_56907_482327485.1740578402931
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2YTZhNiq2YjYp9i12YQg2YXYudmG2Kcg2LnZhNmJINix2YLZhdmG2Kcg2KfZhNin2YXYp9ix2KfY
qtmKIDAwOTcxNTA3MDk3NzM4INmE2LfZhNioINit2KjZiNioINiz2KfZitiq2YjYqtmDINmB2Yog
2KfZhNin2YXYp9ix2KfYqjxiciAvPtin2YTYr9mB2Lkg2LnZhtivINin2YTYp9iz2KrZhNin2YUg
2YjYp9mE2KrZiNi12YrZhCDYp9mE2Ykg2KjYp9ioINin2YTZhdmG2LLZhDxiciAvPtin2YTYqtmI
2LXZitmEINmI2KfZhNmF2LnYp9mK2YbYqSDZiNin2YTZhdiq2KfYqNi52Kkg2YXYrNin2YbZitip
DQoNCjxwPjwvcD4KCi0tIDxiciAvPgpZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2Ug
eW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICZxdW90O2thc2FuLWRldiZx
dW90OyBncm91cC48YnIgLz4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9w
IHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byA8YSBocmVmPSJtYWls
dG86a2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20iPmthc2FuLWRldit1bnN1
YnNjcmliZUBnb29nbGVncm91cHMuY29tPC9hPi48YnIgLz4KVG8gdmlldyB0aGlzIGRpc2N1c3Np
b24gdmlzaXQgPGEgaHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2Fu
LWRldi9kOTA0MzAyOC04ODYyLTQ2MGItOTA0My00NDc4YzA4NmRlYzBuJTQwZ29vZ2xlZ3JvdXBz
LmNvbT91dG1fbWVkaXVtPWVtYWlsJnV0bV9zb3VyY2U9Zm9vdGVyIj5odHRwczovL2dyb3Vwcy5n
b29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L2Q5MDQzMDI4LTg4NjItNDYwYi05MDQzLTQ0Nzhj
MDg2ZGVjMG4lNDBnb29nbGVncm91cHMuY29tPC9hPi48YnIgLz4K
------=_Part_56907_482327485.1740578402931--

------=_Part_56906_2037775445.1740578402931--
