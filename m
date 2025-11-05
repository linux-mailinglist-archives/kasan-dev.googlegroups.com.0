Return-Path: <kasan-dev+bncBDM2ZIVFZQPBB2WPVPEAMGQEUAZVVCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id AA28EC3406B
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 07:00:12 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-63bda1898c7sf7289192a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 22:00:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762322411; cv=pass;
        d=google.com; s=arc-20240605;
        b=DZvGT8C/I5y0anSZBqkmQch5jVXWJqtlaXeUJNKQMg9ORat+ZcNyYRjtkN813zy15h
         uIYDCt/fgpdcUg7Kz6WjFTgAwGoCwGHiZ8ujDoEuWsKSIDM8BxZxgX23Cx1j9yvYXPrE
         /N07ZKboYrCR/QxtXEq8QTpz2xcq3ZH42S5W2mPXHgg1+pkqho8ITtF4MC6ZiKWho9WP
         0bBkbTJd37Nu6YSmr5/5tAfPFCqEEOV/jqVWd2SMXxnfBu2pVG+wXSR79Fty2bWB4jVB
         uSGP6U/f8mcQLnpXn/l0e8iJWN2cuQ1kKm0PNR1rBSJwPKmHRKwR3Jpga2h4vQ4x3Vob
         V1qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=TEXGVKzQ+p4cAFDrGTSkX9jucanQRT6Ur3np5T2rHWM=;
        fh=IxMWYy5fdGKIYu03d/srNh+dWIVIPl4JMOpErRkGjcw=;
        b=cgFQREmB13vCZCvNfEC6NYHxIPzyCFxH5qeVVdul8cLbKVMlcnRd0kvGSff3JwN7zh
         KWqeyJ5ZlzDeFgIqZIGe4bIEefek9iam3+d/Fc/VFXpdvdcs4h6cgnQX/UB4R3Y7vSGT
         EcYXfCHVJ634BpX9k/Cpla4O5TSZL5VKbqo33GMuzrhQJTen3WdYXp2AnUwBcEL+qU14
         S9/E0F5ltDeLtcBL7FA6R7n1IL/SW4QIk21gWRXgk14VxqQPI8uW5OFOli96q6/eCTEm
         FRoRo1HSddvsUU2lKKuQsXP6fG8cyPWJ5ZILKtMGd/MaoQTkJbXmfVpqL63JI6Me/rT9
         ZKqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d4SA5O8N;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762322411; x=1762927211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TEXGVKzQ+p4cAFDrGTSkX9jucanQRT6Ur3np5T2rHWM=;
        b=H3W412ifGdh+UlQN/7RQ2LYkRalvwVIlrj396KerVT7J7WuQP5xmJTFbCrViNRwAI0
         z3xnlstCxWFr5FlU1d/ARr7ETxvt+bDPzBa0xAALEEAGI7ejOeBD+qV2GCvMgqpxqTWz
         9635bvli44tO899V8wN2TenYYClj4mOMH8XJY8OnoCVOm4Cj8aAnLDof4jh7oZdHUqBq
         avVEqnVlErmzgSaUYBSuyj0GkRmrjh2mMcRRM2/LWMFOvcl2rYAOlYwZdNHDX8Cyc5Y1
         A7ofZjoTpuxO2EWgSuHsG1EcSk6ogIGpY4tZRUPbVkZDz4/pWyQmr7ZbDXD8Xx3+ZXS/
         DCMw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762322411; x=1762927211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=TEXGVKzQ+p4cAFDrGTSkX9jucanQRT6Ur3np5T2rHWM=;
        b=hg54LzSyqIn9lKm7P+qdNn1KFSM/iZbnpovd2THjHCy6J/KpYvaWqpWFMT0bbEiKLo
         NWRUgfyWPYZEvJDUDCLghGf18XUcmwiB3/AkeTHXoBFZqe4Iop/ILOvt51pNjXwONAi3
         dxTlTKryU4oaCcwUaoTerzkCBEhc8TkzjIVuZ5fnbGborvNTrbwUKb1SVVU96wg0SWVy
         TaRtpcgbU6P5pBc1TEhwaMgb5ec+k32v65B7jDkQo2mLFDbH7QgQ+0DpPc1PXwFWYeb6
         ZQDbS6oQvNqOrZ9ox+TUsFXHr105OE1yUFJZe8LObEKCYHqOG8HHJNa2ljoB2bEeq4hJ
         ciEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762322411; x=1762927211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TEXGVKzQ+p4cAFDrGTSkX9jucanQRT6Ur3np5T2rHWM=;
        b=pCORvPvHEHMhDShbHkqQkqy7iwj5IGTa754chxA/Meh/Gd0ec88Tdq7pdpFDXAnmz8
         33L06OmxN3ww28+zePEVLRyg59n6uWM/mqN2nXSUIcz6Atsgid12nvdjU7hDpLhHINgF
         biF7/7pKBMihTtBGITebIHYlaLUAlxpqeNdadEKO0nQDUsDpZ2dYQRZqy/gdqeITjSX6
         NfBqLUMpZR1DpOp5vWR39KkO3JmATSjRrVMqr9a+c/Cm1RuBHC9f+dueu/I0bjtfHpR9
         /c21Be2FfXK3WP5L6o4rjoWyCNNLXShJ/5Y11wS+lvl0FORaK3CcDRYvTcWHUNAQdABO
         4A3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGxTZqnBoLhx9+xPSKOBh2USrMd4MAsfwSn7zAyAWSTLo3zz0MxoGK9JzMT+u3UAKfFdwBKw==@lfdr.de
X-Gm-Message-State: AOJu0YwbSi0zSc9+BnxLE/Pl3nxws99Bo7AhmxAobyeqGjPE6i/tNuID
	kZejOrliObZb3i8yClYbhYCKlmHUysuyezC8a+nXeqpzOelueEuxB1F1
X-Google-Smtp-Source: AGHT+IEj+tXPb0+OVnbkxCP6BmruaZ5jzbq7zQaw50JeMUacvrs7UhOkZxwrUgESTtyiiK097IRSPA==
X-Received: by 2002:a05:6402:50c8:b0:640:b9c5:24a1 with SMTP id 4fb4d7f45d1cf-64105b96359mr1459250a12.38.1762322410720;
        Tue, 04 Nov 2025 22:00:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YPN50Qr2FvCBLzANus9WwLddYOceorkArD3BtVs6tpIA=="
Received: by 2002:a05:6402:5344:20b0:640:efac:2bab with SMTP id
 4fb4d7f45d1cf-640efac2e56ls951610a12.0.-pod-prod-09-eu; Tue, 04 Nov 2025
 22:00:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUp/8D3mj+CwVWcb+J6M8b7lSPvePH35BZmQ5l/MLah9Xaxez5tkneF6m6qfZgeMWjeD8ybTP38uUQ=@googlegroups.com
X-Received: by 2002:a05:6402:24d7:b0:640:a7bc:30c5 with SMTP id 4fb4d7f45d1cf-64105a6868fmr1232604a12.28.1762322407766;
        Tue, 04 Nov 2025 22:00:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762322407; cv=none;
        d=google.com; s=arc-20240605;
        b=Ajdka/Y/cFIgHq7qyfp+BIBJE7807QpLTXFRGN7ChJB5LS8YtB8uVsyHNDEg1XQcOO
         2f1SAJ8BLVyuQlloM06DBKxbaWvACvsslq9kuZIokdxohj3zF2rXlnfI4Tj899Yxf3Rl
         2GUP272fdAM0kjZ89Q6A0lj1gXZZFYWE9jy9KZ6AcgeG4bJ08Q66OWP0Zcw1/Ev0nLTK
         VTSMRp7ljKeByMKIzXt0uxWTMpsHIGXg8sjcF664GeF1oVHGgOm0GT0wWlCSZQBUptB1
         poNFhMfMJCZKyxkgx+ThF0eDrRiXtTSoCYtCy8N6N8q8qQ5EGsUfW3kaMqAiPdJImY2p
         wRGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=HayD5toYYGoAbJgM0l2UUk/frFdquL971hIdo0fESTs=;
        fh=8f/FfhzR8FGQKV0Vas4exr2fDP+YHxTSp2+3F/tUdE8=;
        b=QqUIIgkD7FTYKE5baND7jHj0gQL+ygv2Jc6m3M/Qtch+zXS2c1DTEf/ekKQUGv4QGx
         ctUeFaIp2jHeRMZyqwNf/mOny6mNTYvryZkRcIFSg0dZCMr54LCZ9vjyju9cfAyMd01Z
         F+IOZpwH2sWVIH3il66tajbTnGxnC44u95zku7yHMsQQsTxmRP+BLT36XMsiPP9btIpf
         2YLxtZ5JSQ/EhhJdoHQFmtSrOZpGXhNoh70jO8tv8fYjIz3KW040x1FqLL5DA/P0WHyi
         8NAKslSlvy6SB4haXJKB96V3Bw3Lk0kVM53YIA66R8SL5pnPayZQ3xCfH4cou89j5u/Y
         9keA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d4SA5O8N;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-640e6a79106si129228a12.5.2025.11.04.22.00.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Nov 2025 22:00:07 -0800 (PST)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-64034284521so10862279a12.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Nov 2025 22:00:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVEflVMPCS/9UEb7t96i5bAcDB7YU8O4AwBchuC655o9nq5z/sqSdfO3cCwUxyQeviIEjSCIcFdfBA=@googlegroups.com
X-Gm-Gg: ASbGnct6QZ0FVI0IIGefRFJHKWfRt6YTzpefgUw6+EORmrU5nFMaZUDwprf67mGin2K
	w0C6It+w7xVW31B0NkmZfdtFiYyIyPiDJxkrAR91etfgl4kN3fitk0PDPXFAfj7UYyqyaft9r0+
	5JZp2FTp7LOJOvGm+MsHvTtYrfHihEgEbZeMVnLkCoLP5oRylqJQE1fUpkvHim0cQ07zeNJt2gt
	PE2yo8T5QYmbJQVb7C5wyPLlJFUkXHIV0/iva1+906uwTv2Xp9uA5nfgeS1otycuhje
X-Received: by 2002:a05:6402:254a:b0:637:f07d:e80f with SMTP id
 4fb4d7f45d1cf-6410568aac0mr1437282a12.0.1762322406523; Tue, 04 Nov 2025
 22:00:06 -0800 (PST)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Wed, 5 Nov 2025 08:00:00 +0200
X-Gm-Features: AWmQ_bnzZuelSlwxAyxEPRq1HJgSPc1loQtGLHBvOPcielSUhoQhGVQG975mIOQ
Message-ID: <CADj1ZK=YYPOUHPWkB9qhUwcMcJ-aiKEN0bcCqaO-LdQv4Rf5dg@mail.gmail.com>
Subject: =?UTF-8?B?2KfZhNiq2YXZitiyINmB2Yog2KXYr9in2LHYqSDYp9mE2YXYsdin2YHZgiDYp9mE2KfYrQ==?=
	=?UTF-8?B?2KrYsdin2YHZitipIC0g2KfYs9iq2LHYp9iq2YrYrNmK2KfYqiDZgdi52ZHYp9mE2Kkg2YTYpdiv2Kc=?=
	=?UTF-8?B?2LHYqSDYp9mE2YXYsdin2YHZgiDZiNi12YrYp9mG2Kkg2KfZhNio2YbZitipINin2YTYqtit2KrZitip?=
	=?UTF-8?B?INmI2YHZgiDYp9mE2YXYudin2YrZitixINin2YTYudin2YTZhdmK2Kkg2YXZhiA3IOKAkyAxMSDYr9mK?=
	=?UTF-8?B?2LPZhdio2LEg2KfYqti12YQg2KjZhtinIDAwMjAxMDYyOTkyNTEw?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000054b6c0642d2a904"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=d4SA5O8N;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::532
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

--000000000000054b6c0642d2a904
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

Ktiq2YfYr9mK2YPZhSDYp9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin
2YTYpdiv2KfYsdmK2Kkg2KPYt9mK2Kgg2KrYrdmK2KfYqtmH2Kcg2YjYo9i12K/ZgiDYqtmF2YbZ
itin2KrZh9inINio2K/ZiNin2YUNCtin2YTYqtmI2YHZitmCLioNCg0KKtiq2K/YudmI2YPZhSDZ
hNmE2YXYtNin2LHZg9ipINmB2Yo6Kg0KDQrwn4yfICrYpdiv2KfYsdipINin2YTZhdix2KfZgdmC
INin2YTYp9it2KrYsdin2YHZitipKiAq8J+MnyoNCg0KKiAoUHJvZmVzc2lvbmFsIEZhY2lsaXR5
IE1hbmFnZW1lbnQpKg0KDQoNCirYrtmE2KfZhCDYp9mE2YHYqtix2Kkg2YXZhiA3IC0gMTEgLyDY
r9mK2LPZhdio2LEgLyAyMDI1Kg0KDQoq8J+TsioqINin2YTYqtiv2LHZitioINmK2Y/Zgtiv2YUg
2KjZhti42KfZhSDYp9mE2KPZiNmG2YTYp9mK2YYgKNio2Ksg2YXYqNin2LTYsSkqDQoNCirZgdmK
INit2KfZhNipINiq2LnYsNixINin2YTYrdi22YjYsSDZhNmE2YLYp9mH2LHYqSDigJMg2KzZhdmH
2YjYsdmK2Kkg2YXYtdixINin2YTYudix2KjZitipKg0KDQoNCg0KKtin2YTYrdi22YjYsSDZhNmE
2YLYp9mH2LHYqSDigJMg2KzZhdmH2YjYsdmK2Kkg2YXYtdixINin2YTYudix2KjZitipKg0KDQoq
2YXZgtiv2YXYqSA6ICoNCg0K2YHZiiDYuNmEINin2YTYqti32YjYsSDYp9mE2LPYsdmK2Lkg2YHZ
iiDYp9mE2KjZhtmK2Kkg2KfZhNiq2K3YqtmK2Kkg2YjYp9mE2YXYtNix2YjYudin2Kog2KfZhNit
2K/Zitir2KnYjCDYo9i12KjYrdiqICrYpdiv2KfYsdipDQrYp9mE2YXYsdin2YHZgiog2KPYrdiv
INij2YfZhSDYudmG2KfYtdixINin2YTZhtis2KfYrSDYp9mE2KrYtNi62YrZhNmKINmE2YTZhdik
2LPYs9in2Kog2KfZhNit2YPZiNmF2YrYqSDZiNin2YTYrtin2LXYqS4NCtmB2YfZiiDZhNinINiq
2YLYqti12LEg2LnZhNmJINi12YrYp9mG2Kkg2KfZhNmF2KjYp9mG2Yog2YjYp9mE2K7Yr9mF2KfY
qtiMINio2YQg2KrZhdiq2K8g2YTYqti02YXZhCAq2KXYr9in2LHYqSDYp9mE2KPYtdmI2YTYjA0K
2YjYp9mE2KrYrti32YrYtyDYp9mE2KfYs9iq2LHYp9iq2YrYrNmK2Iwg2YjYp9iz2KrYr9in2YXY
qSDYp9mE2KrYtNi62YrZhNiMINmI2LHZgdi5INmD2YHYp9ih2Kkg2KfZhNij2K/Yp9ihINmI2KzZ
iNiv2Kkg2KfZhNiu2K/Zhdin2KoqLg0KDQoq2KfZhNin2YfYr9in2YEgOiAqDQoNCjEuICAgINmB
2YfZhSDYp9mE2YXZgdmH2YjZhSDYp9mE2LTYp9mF2YQg2YTYpdiv2KfYsdipINin2YTZhdix2KfZ
gdmCINmI2K/ZiNix2YfYpyDZgdmKINiq2K3ZgtmK2YIg2YPZgdin2KHYqSDYp9mE2KrYtNi62YrZ
hA0K2KfZhNmF2KTYs9iz2YouDQoNCjIuICAgINin2YTYqti52LHZkdmBINi52YTZiSDYp9mE2YXZ
g9mI2YbYp9iqINin2YTYo9iz2KfYs9mK2Kkg2YTZhti42YUg2KXYr9in2LHYqSDYp9mE2YXYsdin
2YHZgiDYp9mE2K3Yr9mK2KvYqS4NCg0KMy4gICAg2KfZg9iq2LPYp9ioINmF2YfYp9ix2KfYqiDY
qtiu2LfZiti3INmI2KrYtNi62YrZhCDZiNi12YrYp9mG2Kkg2KfZhNmF2LHYp9mB2YIg2KjZgdi5
2KfZhNmK2KkuDQoNCjQuICAgINiq2LfYqNmK2YIg2YXYudin2YrZitixINin2YTYrNmI2K/YqSDZ
iNin2YTYs9mE2KfZhdipINmI2KfZhNin2LPYqtiv2KfZhdipINmB2Yog2KjZitim2Kkg2KfZhNmF
2LHYp9mB2YIuDQoNCjUuICAgINil2K/Yp9ix2Kkg2KfZhNi52YLZiNivINmI2KfZhNmF2YjYsdiv
2YrZhiDZiNmB2YIg2YbZh9isINmC2KfYptmFINi52YTZiSDYp9mE2KPYr9in2KEgKFBlcmZvcm1h
bmNlLUJhc2VkKS4NCg0KNi4gICAg2KjZhtin2KEg2K7Yt9i3INin2LPYqtix2KfYqtmK2KzZitip
INmE2KXYr9in2LHYqSDYp9mE2YXYsdin2YHZgiDYqti22YXZhiDYp9mE2KfYs9iq2K/Yp9mF2Kkg
2YjYqtmC2YTZitmEINin2YTYqtmD2KfZhNmK2YENCtin2YTYqti02LrZitmE2YrYqS4NCg0KICrY
p9mE2YXYrdin2YjYsSDYp9mE2KrZiiDYs9mK2KrZhSDYr9ix2KfYs9iq2YfYpyDZgdmKINin2YQ1
INin2YrYp9mFINiq2K/YsdmK2KggOiAqDQoNCirYp9mE2YrZiNmFINin2YTYo9mI2YQ6INmF2K/Y
rtmEINil2YTZiSDYpdiv2KfYsdipINin2YTZhdix2KfZgdmCINin2YTYrdiv2YrYq9ipKg0KDQog
ICAtINin2YTZhdmB2YfZiNmFINin2YTYudin2YUg2YTYpdiv2KfYsdipINin2YTZhdix2KfZgdmC
INmI2KPZh9mF2YrYqtmH2Kcg2YHZiiDYp9mE2YXYpNiz2LPYp9iqLg0KICAgLSDYp9mE2YHYsdmC
INio2YrZhiDYp9mE2LXZitin2YbYqSDYp9mE2KrYtNi62YrZhNmK2Kkg2YjYpdiv2KfYsdipINin
2YTZhdix2KfZgdmCINin2YTYtNin2YXZhNipLg0KICAgLSDYo9mG2YjYp9i5INin2YTZhdix2KfZ
gdmCICjYpdiv2KfYsdmK2Kkg4oCTINi12YbYp9i52YrYqSDigJMg2KrYrNin2LHZitipIOKAkyDY
qti52YTZitmF2YrYqSDigJMg2LfYqNmK2KkpLg0KICAgLSDYr9mI2LEg2YXYr9mK2LEg2KfZhNmF
2LHYp9mB2YIg2YjZhdiz2KTZiNmE2YrYp9iq2Ycg2KfZhNin2LPYqtix2KfYqtmK2KzZitipLg0K
DQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KICrYp9mE2YrZiNmFINin2YTYq9in
2YbZijog2KXYr9in2LHYqSDYudmF2YTZitin2Kog2KfZhNiq2LTYutmK2YQg2YjYp9mE2LXZitin
2YbYqSoNCg0KICAgLSDYr9mI2LHYqSDYrdmK2KfYqSDYp9mE2YXYsdin2YHZgiDZiNij2LPYp9iz
2YrYp9iqINin2YTYqti02LrZitmEINin2YTZgdi52ZHYp9mELg0KICAgLSDYp9iz2KrYsdin2KrZ
itis2YrYp9iqINin2YTYtdmK2KfZhtipICjYp9mE2YjZgtin2KbZitipIOKAkyDYp9mE2KrZhtio
2KTZitipIOKAkyDYp9mE2KrYtdit2YrYrdmK2KkpLg0KICAgLSDZhti42YUg2KXYr9in2LHYqSDY
p9mE2LXZitin2YbYqSDYp9mE2YXYrdmI2LPYqNipIChDTU1TKS4NCiAgIC0g2YPZgdin2KHYqSDY
p9mE2LfYp9mC2Kkg2YjYpdiv2KfYsdipINin2YTZhdmI2KfYsdivINiv2KfYrtmEINin2YTZhdix
2KfZgdmCLg0KDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KKtin2YTZitmI2YUg
2KfZhNir2KfZhNirOiDYpdiv2KfYsdipINin2YTYudmC2YjYryDZiNin2YTZhdmI2LHYr9mK2YYq
DQoNCiAgIC0g2YXZgdmH2YjZhSDYudmC2YjYryDYp9mE2KPYr9in2KEg2YHZiiDYpdiv2KfYsdip
INin2YTZhdix2KfZgdmCLg0KICAgLSDYtdmK2KfYutipINmI2KrZgtmK2YrZhSDYp9iq2YHYp9mC
2YrYp9iqINmF2LPYqtmI2Ykg2KfZhNiu2K/ZhdipIChTTEEpLg0KICAgLSDZhdik2LTYsdin2Kog
2KfZhNij2K/Yp9ihINin2YTYsdim2YrYs9mK2KkgKEtQSXMpINmB2Yog2KXYr9in2LHYqSDYp9mE
2YXYsdin2YHZgi4NCiAgIC0g2KXYr9in2LHYqSDYp9mE2LnZhNin2YLYqSDZhdi5INin2YTZhdmI
2LHYr9mK2YYg2YjYp9mE2YXYqti52KfZgtiv2YrZhi4NCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tDQoNCirYp9mE2YrZiNmFINin2YTYsdin2KjYuTog2KfZhNis2YjYr9ipINmI2KfZ
hNin2LPYqtiv2KfZhdipINmB2Yog2KXYr9in2LHYqSDYp9mE2YXYsdin2YHZgioNCg0KICAgLSDZ
hdi52KfZitmK2LEg2KfZhNis2YjYr9ipINmB2Yog2KjZitim2Kkg2KfZhNi52YXZhCDZiNin2YTY
rtiv2YXYp9iqINin2YTZhdiz2KfZhtiv2KkuDQogICAtINil2K/Yp9ix2Kkg2KfZhNi12K3YqSDZ
iNin2YTYs9mE2KfZhdipINin2YTZhdmH2YbZitipIChIU0UpLg0KICAgLSDZhdio2KfYr9imINin
2YTYp9iz2KrYr9in2YXYqSDYp9mE2KjZitim2YrYqSDZgdmKINin2YTZhdix2KfZgdmCLg0KICAg
LSDYpdiv2KfYsdipINin2YTZhdiu2KfYt9ixINmI2KfZhNi32YjYp9ix2KYuDQoNCi0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQoq2KfZhNmK2YjZhSDYp9mE2K7Yp9mF2LM6INin2YTY
qtiu2LfZiti3INin2YTYp9iz2KrYsdin2KrZitis2Yog2YjYqti32YjZitixINin2YTYo9iv2KfY
oSoNCg0KICAgLSDYqNmG2KfYoSDYrti32Kkg2KfYs9iq2LHYp9iq2YrYrNmK2Kkg2YTYpdiv2KfY
sdipINin2YTZhdix2KfZgdmCLg0KICAgLSDYp9mE2KrYrdmE2YrZhCDYp9mE2YXYp9mE2Yog2YTY
qtmD2KfZhNmK2YEg2KfZhNiq2LTYutmK2YQg2YjYp9mE2LXZitin2YbYqS4NCiAgIC0g2KfZhNiq
2K3ZiNmEINin2YTYsdmC2YXZiiDZgdmKINil2K/Yp9ix2Kkg2KfZhNmF2LHYp9mB2YIgKFNtYXJ0
IEZNIOKAkyBJb1Qg4oCTIEJJTSkuDQogICAtINmI2LHYtNipINi52YXZhCDYrtiq2KfZhdmK2Kk6
INil2LnYr9in2K8g2YbZhdmI2LDYrCDYrti32Kkg2KXYr9in2LHYqSDZhdix2KfZgdmCINin2K3Y
qtix2KfZgdmK2KkuDQoNCsK3ICAgICAq2KfZhNmB2KbYqSDYp9mE2YXYs9iq2YfYr9mB2KkqKjoq
DQoNCiAgIC0g2YXYr9ix2KfYoSDYp9mE2YXYsdin2YHZgiDZiNin2YTYtdmK2KfZhtipINmI2KfZ
hNiu2K/Zhdin2Kog2KfZhNi52KfZhdipLg0KICAgLSDYp9mE2YXZh9mG2K/Ys9mI2YYg2YjYp9mE
2YHZhtmK2YjZhiDYp9mE2LnYp9mF2YTZiNmGINmB2Yog2KrYtNi62YrZhCDYp9mE2YXYqNin2YbZ
iiDZiNin2YTZhdmG2LTYotiqLg0KICAgLSDZhdiz2KTZiNmE2Ygg2KfZhNis2YjYr9ipINmI2KfZ
hNiz2YTYp9mF2Kkg2KfZhNmF2YfZhtmK2KkuDQogICAtINmF2K/Ysdin2KEg2KfZhNi52YLZiNiv
INmI2KfZhNiq2YjYsdmK2K8g2YjYp9mE2YXYtNiq2LHZitin2KouDQogICAtINin2YTYudin2YXZ
hNmI2YYg2YHZiiDYpdiv2KfYsdin2Kog2KfZhNiq2LTYutmK2YTYjCDYp9mE2KXYr9in2LHYqSDY
p9mE2YfZhtiv2LPZitip2Iwg2KfZhNiu2K/Zhdin2Kog2KfZhNmE2YjYrNiz2KrZitipLg0KICAg
LSDYo9mKINi02K7YtSDZitiz2LnZiSDZhNiq2LfZiNmK2LEg2YXZh9in2LHYp9iq2Ycg2KfZhNmF
2YfZhtmK2Kkg2YHZiiDZhdis2KfZhCAq2KXYr9in2LHYqSDYp9mE2YXYsdin2YHZgiDYp9mE2KfY
rdiq2LHYp9mB2YrYqSouDQoNCirZhdiu2LHYrNin2Kog2KfZhNiq2LnZhNmFICjZhtiq2KfYptis
INin2YTYr9mI2LHYqSkqDQoNCtio2YbZh9in2YrYqSDYp9mE2K/ZiNix2Kkg2LPZitmD2YjZhiDY
p9mE2YXYtNin2LHZgyDZgtin2K/Ysdin2Ysg2LnZhNmJOg0KDQogICAtINmB2YfZhSDYtNin2YXZ
hCDZhNmF2KzYp9mE2KfYqiDYpdiv2KfYsdipINin2YTZhdix2KfZgdmCINin2YTYrdiv2YrYq9ip
INmI2KPYr9mI2KfYsdmH2Kcg2KfZhNiq2LTYutmK2YTZitipINmI2KfZhNin2LPYqtix2KfYqtmK
2KzZitipDQogICAuDQogICAtINil2LnYr9in2K8g2YjYqtmG2YHZitiwINiu2LfYtyDYqti02LrZ
itmEINmI2LXZitin2YbYqSDZgdi52ZHYp9mE2KkuDQogICAtINiq2LXZhdmK2YUg2LnZgtmI2K8g
2K7Yr9mF2KfYqiDZiNmB2YIg2YXYudin2YrZitixINij2K/Yp9ihINmF2K3Yr9iv2KkuDQogICAt
INiq2LfYqNmK2YIg2YXZgdin2YfZitmFINin2YTYrNmI2K/YqSDZiNin2YTYp9iz2KrYr9in2YXY
qSDZgdmKINio2YrYptipINin2YTYudmF2YQuDQogICAtINin2LPYqtiu2K/Yp9mFINij2K/ZiNin
2Kog2KfZhNil2K/Yp9ix2Kkg2KfZhNiw2YPZitipINmI2KrYrdmE2YrZhCDYp9mE2KPYr9in2KEg
2YTYqtit2LPZitmGINin2YTZg9mB2KfYodipINin2YTYqti02LrZitmE2YrYqS4NCg0KKtin2YTY
rtin2KrZhdipIDoqDQoNCtiq2YXYq9mEINmH2LDZhyDYp9mE2K/ZiNix2Kkg2K7Yt9mI2Kkg2KPY
s9in2LPZitipINmG2K3ZiCDYp9mE2KfYrdiq2LHYp9mBINmB2Yog2KXYr9in2LHYqSDYp9mE2YXY
sdin2YHZgtiMINit2YrYqyDYqtis2YXYuSDYqNmK2YYNCtin2YTZhdi52LHZgdipINin2YTZhti4
2LHZitipINmI2KfZhNiq2LfYqNmK2YIg2KfZhNi52YXZhNmK2Iwg2YjYqtiz2KfYudivINin2YTZ
hdi02KfYsdmD2YrZhiDYudmE2Ykg2KjZhtin2KEg2KjZitim2Kkg2KrYtNi62YrZhNmK2KkNCtmF
2KrZg9in2YXZhNipINmI2YXYs9iq2K/Yp9mF2Kkg2K/Yp9iu2YQg2YXYpNiz2LPYp9iq2YfZhS4N
Cg0K2YjYqNi52K8g2KfYrNiq2YrYp9iyINin2YTYr9mI2LHYqSDYqNmG2KzYp9it2Iwg2LPZitmP
2YXZhtitINin2YTZhdi02KfYsdmD2YjZhiDYtNmH2KfYr9ipICLYpdiv2KfYsdipINin2YTZhdix
2KfZgdmCINin2YTYp9it2KrYsdin2YHZitipIg0K2KfZhNiq2Yog2KrYpNmH2YTZh9mFINmE2YLZ
itin2K/YqSDYp9mE2KrYt9mI2YrYsSDZiNin2YTYqtit2LPZitmGINmB2Yog2YfYsNinINin2YTZ
hdis2KfZhCDYp9mE2K3ZitmI2YouDQoNCirZhNmF2LLZitivINmF2YYg2KfZhNmF2LnZhNmI2YXY
p9iqINmG2LHYrNmI2Kcg2KfZhNiq2YjYp9i12YQqDQoNCirwn5OeKiAq2YTZhNiq2LPYrNmK2YQg
2YjYp9mE2KfYs9iq2YHYs9in2LEqDQoqOiAqKtijLyDYs9in2LHYqSDYudio2K8g2KfZhNis2YjY
p9ivIOKAkyDZhdiv2YrYsSDYp9mE2KrYr9ix2YrYqCoNCirwn5OyKiogMDAyMDEwNjk5OTQzOTkg
4oCTIDAwMjAxMDYyOTkyNTEwIOKAkyAwMDIwMTA5Njg0MTYyNioNCg0KDQoNCg0KDQoq2YfYp9iq
2YEgOiAqKjAwMjAyMzc0MzAxMzQgLTAwMjAyMzc4NDMwMTM1ICAtICAwMDIwMjM3NDMwMTMxKg0K
DQoq2KfZhCoNCg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJl
IHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVu
c3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20g
aXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5j
b20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5j
b20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FEajFaSyUzRFlZUE9VSFBXa0I5cWhVd2NNY0otYWlLRU4w
YmNDcWFPLUxkUXY0UmY1ZGclNDBtYWlsLmdtYWlsLmNvbS4K
--000000000000054b6c0642d2a904
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><table class=3D"gmail-MsoTableGrid" border=3D"1" cellspaci=
ng=3D"0" cellpadding=3D"0" width=3D"766" style=3D"width:574.15pt;border-col=
lapse:collapse;border:none">
 <tbody><tr>
  <td width=3D"766" valign=3D"top" style=3D"width:574.15pt;border:4.5pt dou=
ble rgb(196,89,17);padding:0in 5.4pt">
  <p class=3D"MsoNormal" align=3D"center" style=3D"margin:0in;text-align:ce=
nter;line-height:normal;font-size:11pt;font-family:Calibri,sans-serif"><a n=
ame=3D"_Hlk213021139"></a><a name=3D"_Hlk212992177"></a><a name=3D"_Hlk1930=
13417"><b><span lang=3D"AR-EG" dir=3D"RTL" style=3D"font-size:22pt;font-fam=
ily:Arial,sans-serif">=D8=AA=D9=87=D8=AF=D9=8A=D9=83=D9=85
  =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9=
 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D9=8A=D8=A9 =D8=A3=D8=B7=D9=8A=D8=A8 =D8=AA=D8=AD=D9=8A=D8=A7=D8=AA=
=D9=87=D8=A7 =D9=88=D8=A3=D8=B5=D8=AF=D9=82 =D8=AA=D9=85=D9=86=D9=8A=D8=A7=
=D8=AA=D9=87=D8=A7 =D8=A8=D8=AF=D9=88=D8=A7=D9=85 =D8=A7=D9=84=D8=AA=D9=88=
=D9=81=D9=8A=D9=82.</span></b></a><span style=3D"font-size:22pt;font-family=
:Arial,sans-serif"></span></p>
  <p class=3D"MsoNormal" align=3D"center" style=3D"margin:0in;text-align:ce=
nter;line-height:normal;font-size:11pt;font-family:Calibri,sans-serif"><b><=
span lang=3D"AR-EG" dir=3D"RTL" style=3D"font-size:22pt;font-family:Arial,s=
ans-serif">=D8=AA=D8=AF=D8=B9=D9=88=D9=83=D9=85 =D9=84=D9=84=D9=85=D8=B4=D8=
=A7=D8=B1=D9=83=D8=A9 =D9=81=D9=8A:</span></b><span lang=3D"AR-SA" dir=3D"R=
TL" style=3D"font-size:22pt;font-family:Arial,sans-serif"></span></p>
  <p class=3D"MsoNormal" align=3D"center" style=3D"margin:0in;text-align:ce=
nter;line-height:normal;font-size:11pt;font-family:Calibri,sans-serif"><spa=
n style=3D"font-size:20pt;font-family:&quot;Segoe UI Emoji&quot;,sans-serif=
">=F0=9F=8C=9F</span><span style=3D"font-size:20pt;font-family:Arial,sans-s=
erif">
  </span><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"font-size:20pt;font-f=
amily:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=
=D8=B1=D8=A7=D9=81=D9=82 =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=
=D9=8A=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b=
><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:Arial,sans-serif"=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span> </span></b><b><span sty=
le=3D"font-size:20pt;font-family:&quot;Segoe UI Emoji&quot;,sans-serif">=F0=
=9F=8C=9F</span></b><b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"font-size:=
20pt;font-family:Arial,sans-serif"></span></b></p>
  <p class=3D"MsoNormal" align=3D"center" style=3D"margin:0in;text-align:ce=
nter;line-height:normal;font-size:11pt;font-family:Calibri,sans-serif"><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span style=3D"font-size:2=
0pt;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span>=C2=A0(Professional Facility
  Management)<span lang=3D"AR-SA" dir=3D"RTL"></span></span></b></p>
  <p class=3D"MsoNormal" align=3D"center" style=3D"margin:0in;text-align:ce=
nter;line-height:normal;font-size:11pt;font-family:Calibri,sans-serif"><spa=
n style=3D"font-size:22pt;font-family:Arial,sans-serif"><br>
  <b><span lang=3D"AR-SA" dir=3D"RTL" style=3D"color:rgb(192,0,0)">=D8=AE=
=D9=84=D8=A7=D9=84 =D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =D9=85=D9=86 7 - 11=
 / =D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1
  / 2025</span></b></span></p>
  <p class=3D"MsoNormal" align=3D"center" style=3D"margin:0in;text-align:ce=
nter;line-height:normal;font-size:11pt;font-family:Calibri,sans-serif"><b><=
span lang=3D"AR-SA" dir=3D"RTL" style=3D"font-size:20pt;font-family:&quot;S=
egoe UI Emoji&quot;,sans-serif">=F0=9F=93=B2</span></b><b><span lang=3D"AR-=
SA" dir=3D"RTL" style=3D"font-size:20pt;font-family:Arial,sans-serif">=C2=
=A0=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8
  =D9=8A=D9=8F=D9=82=D8=AF=D9=85 =D8=A8=D9=86=D8=B8=D8=A7=D9=85 =D8=A7=D9=
=84=D8=A3=D9=88=D9=86=D9=84=D8=A7=D9=8A=D9=86 (=D8=A8=D8=AB =D9=85=D8=A8=D8=
=A7=D8=B4=D8=B1)</span></b><b><span style=3D"font-size:20pt;font-family:Ari=
al,sans-serif"></span></b></p>
  <p class=3D"MsoNormal" align=3D"center" style=3D"margin:0in;text-align:ce=
nter;line-height:normal;font-size:11pt;font-family:Calibri,sans-serif"><b><=
span lang=3D"AR-EG" dir=3D"RTL" style=3D"font-size:20pt;font-family:Arial,s=
ans-serif">=D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A9 =D8=AA=D8=B9=D8=B0=D8=B1 =
=D8=A7=D9=84=D8=AD=D8=B6=D9=88=D8=B1 =D9=84=D9=84=D9=82=D8=A7=D9=87=D8=B1=
=D8=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =D9=85=D8=B5=D8=
=B1
  =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span></b><b><span lang=3D"AR-=
SA" dir=3D"RTL" style=3D"font-size:20pt;font-family:Arial,sans-serif"></spa=
n></b></p>
  <p class=3D"MsoNormal" align=3D"center" style=3D"margin:0in;text-align:ce=
nter;line-height:normal;font-size:11pt;font-family:Calibri,sans-serif"><b><=
span lang=3D"AR-SA" dir=3D"RTL" style=3D"font-size:20pt;font-family:Arial,s=
ans-serif">=C2=A0</span></b></p>
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8p=
t;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-EG" st=
yle=3D"font-size:22pt;font-family:Arial,sans-serif;color:rgb(192,0,0)">=D8=
=A7=D9=84=D8=AD=D8=B6=D9=88=D8=B1 =D9=84=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=
=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =D9=85=D8=B5=D8=B1=
 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span></b></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;direction:=
rtl;unicode-bidi:embed;margin:0in 0in 8pt;font-size:11pt;font-family:Calibr=
i,sans-serif"><a name=3D"_Hlk212992353"><b><u><span lang=3D"AR-EG" style=3D=
"font-size:20pt;font-family:Arial,sans-serif;color:rgb(192,0,0)">=D9=85=D9=
=82=D8=AF=D9=85=D8=A9 : </span></u></b></a></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-heigh=
t:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D9=81=D9=8A =D8=B8=D9=84 =D8=A7=D9=84=D8=AA=
=D8=B7=D9=88=D8=B1 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=D8=B9 =D9=81=D9=8A =D8=A7=
=D9=84=D8=A8=D9=86=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D8=AD=D8=AA=D9=8A=D8=A9 =
=D9=88=D8=A7=D9=84=D9=85=D8=B4=D8=B1=D9=88=D8=B9=D8=A7=D8=AA =D8=A7=D9=84=
=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD=D8=AA <b>=D8=
=A5=D8=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82</b> =D8=A3=D8=AD=D8=AF =D8=A3=
=D9=87=D9=85 =D8=B9=D9=86=D8=A7=D8=B5=D8=B1 =D8=A7=D9=84=D9=86=D8=AC=D8=A7=
=D8=AD =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84=D9=8A =D9=84=D9=84=D9=85=
=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=
=D8=A9 =D9=88=D8=A7=D9=84=D8=AE=D8=A7=D8=B5=D8=A9</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span=
 dir=3D"LTR"></span>.<br>
  </span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%;font=
-family:Arial,sans-serif">=D9=81=D9=87=D9=8A =D9=84=D8=A7 =D8=AA=D9=82=D8=
=AA=D8=B5=D8=B1
  =D8=B9=D9=84=D9=89 =D8=B5=D9=8A=D8=A7=D9=86=D8=A9 =D8=A7=D9=84=D9=85=D8=
=A8=D8=A7=D9=86=D9=8A =D9=88=D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A7=D8=AA=D8=
=8C =D8=A8=D9=84 =D8=AA=D9=85=D8=AA=D8=AF =D9=84=D8=AA=D8=B4=D9=85=D9=84 <b=
>=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A3=D8=B5=D9=88=D9=84=D8=8C =
=D9=88=D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7
  =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=8C =
=D9=88=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D8=AA=D8=B4=
=D8=BA=D9=8A=D9=84=D8=8C =D9=88=D8=B1=D9=81=D8=B9 =D9=83=D9=81=D8=A7=D8=A1=
=D8=A9 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=AC=D9=88=D8=AF=D8=A9 =
=D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A7=D8=AA</b></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-=
height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span di=
r=3D"LTR"></span>.</span></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;direction:=
rtl;unicode-bidi:embed;margin:0in 0in 8pt;font-size:11pt;font-family:Calibr=
i,sans-serif"><b><u><span lang=3D"AR-EG" style=3D"font-size:20pt;font-famil=
y:Arial,sans-serif;color:rgb(192,0,0)">=D8=A7=D9=84=D8=A7=D9=87=D8=AF=D8=A7=
=D9=81 : </span></u></b></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;line=
-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,sans-serif"><span style=3D"font-size:14pt;line-height:115%;font-famil=
y:Arial,sans-serif">1.<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0
  </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif">=D9=81=D9=87=D9=
=85 =D8=A7=D9=84=D9=85=D9=81=D9=87=D9=88=D9=85 =D8=A7=D9=84=D8=B4=D8=A7=D9=
=85=D9=84 =D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=
=A7=D9=81=D9=82 =D9=88=D8=AF=D9=88=D8=B1=D9=87=D8=A7 =D9=81=D9=8A =D8=AA=D8=
=AD=D9=82=D9=8A=D9=82 =D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D8=AA=D8=
=B4=D8=BA=D9=8A=D9=84
  =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</span><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-he=
ight:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span>.</span></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;line=
-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,sans-serif"><span style=3D"font-size:14pt;line-height:115%;font-famil=
y:Arial,sans-serif">2.<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0
  </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=
=AA=D8=B9=D8=B1=D9=91=D9=81 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D9=83=D9=
=88=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D9=
=84=D9=86=D8=B8=D9=85 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=
=B1=D8=A7=D9=81=D9=82 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:14pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>.</span></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;line=
-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,sans-serif"><span style=3D"font-size:14pt;line-height:115%;font-famil=
y:Arial,sans-serif">3.<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0
  </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=83=D8=
=AA=D8=B3=D8=A7=D8=A8 =D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=AA=D8=AE=D8=
=B7=D9=8A=D8=B7 =D9=88=D8=AA=D8=B4=D8=BA=D9=8A=D9=84 =D9=88=D8=B5=D9=8A=D8=
=A7=D9=86=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 =D8=A8=D9=81=D8=
=B9=D8=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-fa=
mily:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.<=
/span></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;line=
-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,sans-serif"><span style=3D"font-size:14pt;line-height:115%;font-famil=
y:Arial,sans-serif">4.<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0
  </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif">=D8=AA=D8=B7=D8=
=A8=D9=8A=D9=82 =D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D8=AC=D9=
=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=A9 =D9=88=D8=
=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A8=D9=
=8A=D8=A6=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82</span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:14pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span>.</span></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;line=
-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,sans-serif"><span style=3D"font-size:14pt;line-height:115%;font-famil=
y:Arial,sans-serif">5.<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0
  </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=
=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=D9=82=D9=88=D8=AF =D9=88=D8=A7=D9=84=D9=
=85=D9=88=D8=B1=D8=AF=D9=8A=D9=86 =D9=88=D9=81=D9=82 =D9=86=D9=87=D8=AC =D9=
=82=D8=A7=D8=A6=D9=85 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=
=A1</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif"><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span> (Performance-Based).</spa=
n></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;line=
-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Ca=
libri,sans-serif"><span style=3D"font-size:14pt;line-height:115%;font-famil=
y:Arial,sans-serif">6.<span style=3D"font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;font-size-adjust:none;f=
ont-kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0
  </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif">=D8=A8=D9=86=D8=
=A7=D8=A1 =D8=AE=D8=B7=D8=B7 =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=
=AC=D9=8A=D8=A9 =D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=
=B1=D8=A7=D9=81=D9=82 =D8=AA=D8=B6=D9=85=D9=86 =D8=A7=D9=84=D8=A7=D8=B3=D8=
=AA=D8=AF=D8=A7=D9=85=D8=A9 =D9=88=D8=AA=D9=82=D9=84=D9=8A=D9=84 =D8=A7=D9=
=84=D8=AA=D9=83=D8=A7=D9=84=D9=8A=D9=81
  =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84=D9=8A=D8=A9</span><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:=
14pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></spa=
n><span dir=3D"LTR"></span>.</span></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;direction:=
rtl;unicode-bidi:embed;margin:0in 0in 8pt;font-size:11pt;font-family:Calibr=
i,sans-serif"><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><u><span=
 style=3D"font-size:12pt;font-family:Arial,sans-serif"><span dir=3D"RTL"></=
span><span dir=3D"RTL"></span>=C2=A0</span></u></b><b><u><span lang=3D"AR-E=
G" style=3D"font-size:22pt;font-family:Arial,sans-serif;color:rgb(192,0,0)"=
>=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=D8=B1
  =D8=A7=D9=84=D8=AA=D9=8A =D8=B3=D9=8A=D8=AA=D9=85 =D8=AF=D8=B1=D8=A7=D8=
=B3=D8=AA=D9=87=D8=A7 =D9=81=D9=8A =D8=A7=D9=845 =D8=A7=D9=8A=D8=A7=D9=85 =
=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 : </span></u></b><b><u><span lang=3D"AR-EG" =
style=3D"font-size:12pt;font-family:Arial,sans-serif;color:rgb(192,0,0)"></=
span></u></b></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in;line-height:115%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-ser=
if"><b><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%;font-f=
amily:Arial,sans-serif">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=A3=
=D9=88=D9=84: =D9=85=D8=AF=D8=AE=D9=84
  =D8=A5=D9=84=D9=89 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=
=B1=D8=A7=D9=81=D9=82 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9</span></b>=
<b><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-family:A=
rial,sans-serif"></span></b></p>
  <ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=85=D9=81=D9=87=D9=88=
=D9=85 =D8=A7=D9=84=D8=B9=D8=A7=D9=85 =D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 =D9=88=D8=A3=D9=87=D9=85=D9=8A=
=D8=AA=D9=87=D8=A7 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=
=D8=AA</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif=
"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=81=D8=B1=D9=82 =D8=A8=
=D9=8A=D9=86 =D8=A7=D9=84=D8=B5=D9=8A=D8=A7=D9=86=D8=A9 =D8=A7=D9=84=D8=AA=
=D8=B4=D8=BA=D9=8A=D9=84=D9=8A=D8=A9 =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 =D8=A7=D9=84=D8=B4=D8=A7=D9=85=
=D9=84=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans=
-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A3=D9=86=D9=88=D8=A7=D8=B9 =D8=A7=
=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 (=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =
=E2=80=93 =D8=B5=D9=86=D8=A7=D8=B9=D9=8A=D8=A9 =E2=80=93 =D8=AA=D8=AC=D8=A7=
=D8=B1=D9=8A=D8=A9 =E2=80=93 =D8=AA=D8=B9=D9=84=D9=8A=D9=85=D9=8A=D8=A9 =E2=
=80=93
       =D8=B7=D8=A8=D9=8A=D8=A9)</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;=
font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=AF=D9=88=D8=B1 =D9=85=D8=AF=D9=8A=
=D8=B1 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 =D9=88=D9=85=D8=B3=D8=A4=
=D9=88=D9=84=D9=8A=D8=A7=D8=AA=D9=87 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=
=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115=
%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR">=
</span>.</span></li>
  </ul>
 =20
  <div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in=
;text-align:center;line-height:115%;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"font-si=
ze:14pt;line-height:115%;font-family:Arial,sans-serif">
  <hr size=3D"2" width=3D"100%" align=3D"center">
  </span></div>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in;line-height:115%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-ser=
if"><b><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-fami=
ly:Arial,sans-serif">=C2=A0</span></b><b><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=
=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A: =D8=A5=D8=AF=D8=A7=D8=
=B1=D8=A9
  =D8=B9=D9=85=D9=84=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=
=D9=84 =D9=88=D8=A7=D9=84=D8=B5=D9=8A=D8=A7=D9=86=D8=A9</span></b><span dir=
=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-se=
rif"></span></p>
  <ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=AF=D9=88=D8=B1=D8=A9 =D8=AD=D9=8A=
=D8=A7=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 =D9=88=D8=A3=D8=B3=
=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84 =
=D8=A7=D9=84=D9=81=D8=B9=D9=91=D8=A7=D9=84</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D=
"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=
=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=B5=D9=8A=D8=A7=D9=86=D8=A9 (=
=D8=A7=D9=84=D9=88=D9=82=D8=A7=D8=A6=D9=8A=D8=A9 =E2=80=93 =D8=A7=D9=84=D8=
=AA=D9=86=D8=A8=D8=A4=D9=8A=D8=A9 =E2=80=93
       =D8=A7=D9=84=D8=AA=D8=B5=D8=AD=D9=8A=D8=AD=D9=8A=D8=A9)</span><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=86=D8=B8=D9=85 =D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 =D8=A7=D9=84=D8=B5=D9=8A=D8=A7=D9=86=D8=A9 =D8=A7=D9=84=D9=85=
=D8=AD=D9=88=D8=B3=D8=A8=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font=
-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
> (CMMS).</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=A7=
=D9=84=D8=B7=D8=A7=D9=82=D8=A9 =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=
=D9=85=D8=B1=D8=A7=D9=81=D9=82</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font=
-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
>.</span></li>
  </ul>
 =20
  <div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in=
;text-align:center;line-height:115%;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"font-si=
ze:12pt;line-height:115%;font-family:Arial,sans-serif">
  <hr size=3D"2" width=3D"100%" align=3D"center">
  </span></div>
 =20
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in;line-height:115%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-ser=
if"><b><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%;font-f=
amily:Arial,sans-serif">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=
=D8=A7=D9=84=D8=AB: =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D8=B9=D9=82=D9=88=D8=AF =D9=88=D8=A7=D9=84=D9=85=D9=88=D8=B1=
=D8=AF=D9=8A=D9=86</span></b><b><span dir=3D"LTR" style=3D"font-size:14pt;l=
ine-height:115%;font-family:Arial,sans-serif"></span></b></p>
  <ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=85=D9=81=D9=87=D9=88=D9=85 =D8=B9=
=D9=82=D9=88=D8=AF =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=81=D9=8A =D8=A5=
=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82</span><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D=
"font-size:14pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=B5=D9=8A=D8=A7=D8=BA=D8=A9 =D9=88=
=D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=A7=D8=AA=D9=81=D8=A7=D9=82=D9=8A=D8=A7=
=D8=AA =D9=85=D8=B3=D8=AA=D9=88=D9=89 =D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A9<=
/span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" s=
tyle=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif"><span=
 dir=3D"LTR"></span><span dir=3D"LTR"></span> (SLA).</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=85=D8=A4=D8=B4=D8=B1=D8=A7=D8=AA =
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D8=B1=D8=A6=D9=8A=D8=B3=
=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans=
-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (KPIs) </span><s=
pan lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%;font-family:Ari=
al,sans-serif">=D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
       =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span=
 dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=B9=D9=84=D8=A7=D9=82=D8=A9 =D9=85=D8=B9 =D8=A7=D9=84=D9=85=D9=88=
=D8=B1=D8=AF=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=85=D8=AA=D8=B9=D8=A7=D9=82=
=D8=AF=D9=8A=D9=86</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Aria=
l,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></l=
i>
  </ul>
 =20
  <div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in=
;text-align:center;line-height:115%;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"font-si=
ze:12pt;line-height:115%;font-family:Arial,sans-serif">
  <hr size=3D"2" width=3D"100%" align=3D"center">
  </span></div>
 =20
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in;line-height:115%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-ser=
if"><b><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%;font-f=
amily:Arial,sans-serif">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=B1=
=D8=A7=D8=A8=D8=B9: =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9
  =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D9=81=D9=8A=
 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82<=
/span></b><b><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;fon=
t-family:Arial,sans-serif"></span></b></p>
  <ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=81=D9=8A =D8=A8=D9=8A=D8=A6=D8=A9 =
=D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A7=
=D8=AA =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D9=86=D8=AF=D8=A9</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=B5=D8=AD=D8=A9 =D9=88=D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=A9 =
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D=
"LTR"></span> (HSE).</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=85=D8=A8=D8=A7=D8=AF=D8=A6 =D8=A7=
=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D8=A8=D9=8A=
=D8=A6=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82<=
/span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" s=
tyle=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif"><span=
 dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D9=88=D8=A7=D9=84=D8=B7=D9=88=D8=A7=
=D8=B1=D8=A6</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans=
-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
  </ul>
 =20
  <div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in=
;text-align:center;line-height:115%;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"font-si=
ze:12pt;line-height:115%;font-family:Arial,sans-serif">
  <hr size=3D"2" width=3D"100%" align=3D"center">
  </span></div>
 =20
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in;line-height:115%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-ser=
if"><b><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:115%;font-f=
amily:Arial,sans-serif">=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AE=
=D8=A7=D9=85=D8=B3:
  =D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=
=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A =D9=88=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1</span></b><b><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif"></span></=
b></p>
  <ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A8=D9=86=D8=A7=D8=A1 =D8=AE=D8=B7=
=D8=A9 =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9 =D9=84=
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82</=
span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" st=
yle=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif"><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=
=D9=84 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D9=84=D8=AA=D9=83=D8=A7=D9=84=
=D9=8A=D9=81 =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84 =D9=88=D8=A7=D9=84=
=D8=B5=D9=8A=D8=A7=D9=86=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font=
-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=
=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span=
 dir=3D"LTR"></span> (Smart FM =E2=80=93 IoT =E2=80=93 BIM).</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=88=D8=B1=D8=B4=D8=A9 =D8=B9=D9=85=
=D9=84 =D8=AE=D8=AA=D8=A7=D9=85=D9=8A=D8=A9: =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF=
 =D9=86=D9=85=D9=88=D8=B0=D8=AC =D8=AE=D8=B7=D8=A9 =D8=A5=D8=AF=D8=A7=D8=B1=
=D8=A9 =D9=85=D8=B1=D8=A7=D9=81=D9=82
       =D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>.</span></li>
  </ul>
  <p class=3D"gmail-MsoListParagraph" dir=3D"RTL" style=3D"margin:0in 0.5in=
 0in 0in;line-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;f=
ont-family:Calibri,sans-serif"><span style=3D"font-size:24pt;line-height:11=
5%;font-family:Symbol;color:rgb(192,0,0)">=C2=B7<span style=3D"font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;font-size-adjust:none;font-kerning:auto;font-feature-settings:normal;fon=
t-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times N=
ew Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RTL"></=
span><strong><u><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:11=
5%;font-family:Arial,sans-serif;color:rgb(192,0,0)">=D8=A7=D9=84=D9=81=D8=
=A6=D8=A9
  =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span></u></strong=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span><strong><u><span dir=3D"=
LTR" style=3D"font-size:22pt;line-height:115%;font-family:Arial,sans-serif;=
color:rgb(192,0,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</sp=
an></u></strong><u><span lang=3D"AR-SA" style=3D"font-size:24pt;line-height=
:115%;font-family:Arial,sans-serif;color:rgb(192,0,0)"></span></u></p>
  <ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1
       =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 =D9=88=D8=A7=D9=84=D8=B5=
=D9=8A=D8=A7=D9=86=D8=A9 =D9=88=D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =
=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D8=A9</span><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115=
%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR">=
</span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=85=D9=87=D9=86=D8=AF=
=D8=B3=D9=88=D9=86
       =D9=88=D8=A7=D9=84=D9=81=D9=86=D9=8A=D9=88=D9=86 =D8=A7=D9=84=D8=B9=
=D8=A7=D9=85=D9=84=D9=88=D9=86 =D9=81=D9=8A =D8=AA=D8=B4=D8=BA=D9=8A=D9=84 =
=D8=A7=D9=84=D9=85=D8=A8=D8=A7=D9=86=D9=8A =D9=88=D8=A7=D9=84=D9=85=D9=86=
=D8=B4=D8=A2=D8=AA</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Aria=
l,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></l=
i>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
       =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=B3=D9=84=
=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9</span><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:14pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR">=
</span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1
       =D8=A7=D9=84=D8=B9=D9=82=D9=88=D8=AF =D9=88=D8=A7=D9=84=D8=AA=D9=88=
=D8=B1=D9=8A=D8=AF =D9=88=D8=A7=D9=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=A7=
=D8=AA</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif=
"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=
=D9=88=D9=86
       =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=
=D8=B4=D8=BA=D9=8A=D9=84=D8=8C =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D9=87=D9=86=D8=AF=D8=B3=D9=8A=D8=A9=D8=8C =D8=A7=D9=84=D8=AE=
=D8=AF=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D9=84=D9=88=D8=AC=D8=B3=D8=AA=D9=8A=
=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif=
"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A3=D9=8A
       =D8=B4=D8=AE=D8=B5 =D9=8A=D8=B3=D8=B9=D9=89 =D9=84=D8=AA=D8=B7=D9=88=
=D9=8A=D8=B1 =D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA=D9=87 =D8=A7=D9=84=D9=85=
=D9=87=D9=86=D9=8A=D8=A9 =D9=81=D9=8A =D9=85=D8=AC=D8=A7=D9=84 <b>=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 =D8=A7=D9=
=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9</b></span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span>.</span><span lang=3D"AR-SA" style=3D"font-size:1=
4pt;line-height:115%;font-family:Arial,sans-serif"></span></li>
  </ul>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in;line-height:normal=
;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-s=
erif"><b><u><span lang=3D"AR-SA" style=3D"font-size:14pt;font-family:Arial,=
sans-serif;color:rgb(192,0,0)">=D9=85=D8=AE=D8=B1=D8=AC=D8=A7=D8=AA =D8=A7=
=D9=84=D8=AA=D8=B9=D9=84=D9=85 (=D9=86=D8=AA=D8=A7=D8=A6=D8=AC =D8=A7=D9=84=
=D8=AF=D9=88=D8=B1=D8=A9)</span></u></b></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in;line-height:normal=
;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-s=
erif"><span lang=3D"AR-SA" style=3D"font-size:14pt;font-family:Arial,sans-s=
erif">=D8=A8=D9=86=D9=87=D8=A7=D9=8A=D8=A9 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=
=D8=A9
  =D8=B3=D9=8A=D9=83=D9=88=D9=86 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=
 =D9=82=D8=A7=D8=AF=D8=B1=D8=A7=D9=8B =D8=B9=D9=84=D9=89</span><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:=
14pt;font-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span>:</span><span lang=3D"AR-SA" style=3D"font-size:14pt;font-family:=
Arial,sans-serif"></span></p>
  <ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D9=81=D9=87=D9=85
       =D8=B4=D8=A7=D9=85=D9=84 =D9=84=D9=85=D8=AC=D8=A7=D9=84=D8=A7=D8=AA =
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82 =
=D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9 =D9=88=D8=A3=D8=AF=D9=88=D8=A7=
=D8=B1=D9=87=D8=A7 =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84=D9=8A=D8=A9 =
=D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=
=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:115%;font-family:Arial,sans-serif"><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
       =D9=88=D8=AA=D9=86=D9=81=D9=8A=D8=B0 =D8=AE=D8=B7=D8=B7 =D8=AA=D8=B4=
=D8=BA=D9=8A=D9=84 =D9=88=D8=B5=D9=8A=D8=A7=D9=86=D8=A9 =D9=81=D8=B9=D9=91=
=D8=A7=D9=84=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-family:Aria=
l,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></l=
i>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=AA=D8=B5=D9=85=D9=8A=D9=85
       =D8=B9=D9=82=D9=88=D8=AF =D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D9=88=D9=81=
=D9=82 =D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A3=D8=AF=D8=A7=D8=A1 =D9=85=
=D8=AD=D8=AF=D8=AF=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font-famil=
y:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82
       =D9=85=D9=81=D8=A7=D9=87=D9=8A=D9=85 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=
=D8=A9 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D9=81=
=D9=8A =D8=A8=D9=8A=D8=A6=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84</span><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font=
-size:14pt;line-height:115%;font-family:Arial,sans-serif"><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span>.</span></li>
   <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;li=
ne-height:115%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-heigh=
t:115%;font-family:Arial,sans-serif">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=
=D9=85
       =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=
=D8=A9 =D8=A7=D9=84=D8=B0=D9=83=D9=8A=D8=A9 =D9=88=D8=AA=D8=AD=D9=84=D9=8A=
=D9=84 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=84=D8=AA=D8=AD=D8=B3=D9=8A=
=D9=86 =D8=A7=D9=84=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D8=AA=D8=B4=
=D8=BA=D9=8A=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:115%;font=
-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
>.</span></li>
  </ul>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;direction:=
rtl;unicode-bidi:embed;margin:0in 0in 8pt;font-size:11pt;font-family:Calibr=
i,sans-serif"><b><u><span lang=3D"AR-EG" style=3D"font-size:24pt;font-famil=
y:Arial,sans-serif;color:rgb(192,0,0)">=D8=A7=D9=84=D8=AE=D8=A7=D8=AA=D9=85=
=D8=A9
  :</span></u></b><b><u><span lang=3D"AR-EG" style=3D"font-size:24pt;font-f=
amily:Arial,sans-serif;color:red"></span></u></b></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.25in 8pt 0in;lin=
e-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family=
:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-fami=
ly:Arial,sans-serif">=D8=AA=D9=85=D8=AB=D9=84
  =D9=87=D8=B0=D9=87 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=AE=D8=B7=D9=
=88=D8=A9 =D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D9=86=D8=AD=D9=88 =D8=A7=D9=
=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81 =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=
=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A7=D9=81=D9=82=D8=8C =D8=AD=D9=8A=D8=
=AB =D8=AA=D8=AC=D9=85=D8=B9 =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D8=
=B1=D9=81=D8=A9
  =D8=A7=D9=84=D9=86=D8=B8=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=
=D8=A8=D9=8A=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=8C =D9=88=D8=AA=
=D8=B3=D8=A7=D8=B9=D8=AF =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=
=D9=86 =D8=B9=D9=84=D9=89 =D8=A8=D9=86=D8=A7=D8=A1 =D8=A8=D9=8A=D8=A6=D8=A9=
 =D8=AA=D8=B4=D8=BA=D9=8A=D9=84=D9=8A=D8=A9 =D9=85=D8=AA=D9=83=D8=A7=D9=85=
=D9=84=D8=A9
  =D9=88=D9=85=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D8=AF=D8=A7=D8=AE=D9=84=
 =D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA=D9=87=D9=85</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt;fo=
nt-family:Arial,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an>.</span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,s=
ans-serif"></span></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.25in 8pt 0in;lin=
e-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family=
:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-fami=
ly:Arial,sans-serif">=D9=88=D8=A8=D8=B9=D8=AF
  =D8=A7=D8=AC=D8=AA=D9=8A=D8=A7=D8=B2 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9=
 =D8=A8=D9=86=D8=AC=D8=A7=D8=AD=D8=8C =D8=B3=D9=8A=D9=8F=D9=85=D9=86=D8=AD =
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=88=D9=86 =D8=B4=D9=87=D8=A7=
=D8=AF=D8=A9 &quot;=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=
=D8=A7=D9=81=D9=82
  =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9&quot; =D8=A7=
=D9=84=D8=AA=D9=8A =D8=AA=D8=A4=D9=87=D9=84=D9=87=D9=85 =D9=84=D9=82=D9=8A=
=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=88=D8=A7=
=D9=84=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D9=81=D9=8A =D9=87=D8=B0=D8=A7 =D8=A7=
=D9=84=D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=D8=AD=D9=8A=D9=88=D9=8A.</span>=
<b><span lang=3D"AR-EG" style=3D"font-size:16pt;font-family:Arial,sans-seri=
f"></span></b></p>
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
.25in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bi=
di:embed;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR=
-EG" style=3D"font-size:22pt;font-family:Arial,sans-serif;color:red">=D9=84=
=D9=85=D8=B2=D9=8A=D8=AF
  =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D9=
=86=D8=B1=D8=AC=D9=88=D8=A7 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84</spa=
n></b></p>
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
.25in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bi=
di:embed;font-size:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR=
" style=3D"font-size:22pt;font-family:&quot;Segoe UI Emoji&quot;,sans-serif=
;color:black">=F0=9F=93=9E</span></b><b><span dir=3D"LTR" style=3D"font-siz=
e:22pt;font-family:Arial,sans-serif;color:black">=C2=A0</span></b><b><span =
lang=3D"AR-SA" style=3D"font-size:22pt;font-family:Arial,sans-serif;color:b=
lack">=D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=
=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:22pt;font-fam=
ily:Arial,sans-serif;color:black"><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span>:<br>
  </span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:Ar=
ial,sans-serif;color:black">=D8=A3/
  =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=
=A7=D8=AF =E2=80=93 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=
=D9=8A=D8=A8</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-fa=
mily:Arial,sans-serif;color:black"><br>
  </span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot=
;Segoe UI Emoji&quot;,sans-serif;color:black">=F0=9F=93=B2</span></b><b><sp=
an dir=3D"LTR" style=3D"font-size:22pt;font-family:Arial,sans-serif;color:b=
lack">=C2=A000201069994399
  =E2=80=93 00201062992510 =E2=80=93 00201096841626</span></b></p>
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
.25in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bi=
di:embed;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR=
-EG" style=3D"font-size:22pt;font-family:Arial,sans-serif;color:red">=C2=A0=
</span></b></p>
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"f=
ont-size:16pt;font-family:Arial,sans-serif">=C2=A0</span></b></p>
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;t=
ext-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-s=
ize:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"f=
ont-size:16pt;font-family:Arial,sans-serif">=D9=87=D8=A7=D8=AA=D9=81 : </sp=
an></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LT=
R" style=3D"font-size:16pt;font-family:Arial,sans-serif"><span dir=3D"LTR">=
</span><span dir=3D"LTR"></span>0020237430134 -00202378430135=C2=A0 -=C2=A0
  0020237430131</span></b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;f=
ont-family:Arial,sans-serif"></span></b></p>
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;direction:=
rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><b><s=
pan lang=3D"AR-EG" style=3D"font-size:12pt;font-family:Arial,sans-serif">=
=D8=A7=D9=84</span></b><b><span dir=3D"LTR" style=3D"font-size:12pt;font-fa=
mily:Arial,sans-serif"><br>
  <br>
  </span></b><b><span dir=3D"LTR" style=3D"font-size:12pt;font-family:Arial=
,sans-serif"></span></b></p>
 =20
  <p class=3D"MsoNormal" style=3D"margin:0in 0in 0in 8.8pt;line-height:norm=
al;font-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-famil=
y:Arial,sans-serif">=C2=A0</span></p>
  </td>
 =20
 </tr>
</tbody></table>

<p dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embed;margin-right:0in;m=
argin-left:0in;font-size:12pt;font-family:&quot;Times New Roman&quot;,serif=
"><span style=3D"font-size:12pt">=C2=A0</span></p>



<p class=3D"MsoNormal" style=3D"margin:0in 0in 8pt;line-height:107%;font-si=
ze:11pt;font-family:Calibri,sans-serif"><span style=3D"font-family:Arial,sa=
ns-serif">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZK%3DYYPOUHPWkB9qhUwcMcJ-aiKEN0bcCqaO-LdQv4Rf5dg%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CADj1ZK%3DYYPOUHPWkB9qhUwcMcJ-aiKEN0bcCqaO-LdQv4Rf5dg%40mail=
.gmail.com</a>.<br />

--000000000000054b6c0642d2a904--
