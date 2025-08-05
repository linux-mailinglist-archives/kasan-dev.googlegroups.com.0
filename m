Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBUGGZHCAMGQEWZV5TTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 75458B1BB3F
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 22:02:26 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-ae6f9b15604sf505400466b.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 13:02:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754424146; cv=pass;
        d=google.com; s=arc-20240605;
        b=fuE+T0uF5wF0r0CeR8PAy8IHfp4M9287Q2BNuuIl7mlfEkVWzDoodIvgt1c7J3tLKs
         iLbEyuNXVvVjF6z6VG1B+ffK5FGtVOsd443U5v3fFum0JYVfuYrhkzi2y0sqGCiPlCjv
         JMvw3tO7sk0el3CcI+ErWcSrzM2Yv+DhbqKaD1NVdbfrv/rzLRa2xaX/9cK0IZQdmOG4
         utTr8hBlChsJevSo1sJNco/X7YAOU22xobPxUjhvO2y25RJvlFcVwEocqKpAK8VAHL1B
         HT9MyED4akiRLk9cL4UCniAO5tmCH2tQjWEa7vniRIn0xqrINSwZeOiZriDzmsVlCaEV
         E3aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=Zfwb901DM6uwPHGjkMq8V4w04kEiO9HXDyLa1i7QIrI=;
        fh=cCkuCfkanhzV6S6ZBcMlGo/gDFqBZwmyauyDAxUmSfU=;
        b=lhWit4MlpRDadpU7lFdAQRyQ/5senAswyQgTbeOc2oY0enDe5aNPc5b0dLbYUkOTIv
         Id4VrDSqvCR/rMQur+HF546BUpxCRMiq35SnJzknokzctjdJ8mLEccsG5aILlK4z0MI2
         kHUMbZ3TugGoQ9YMy5IWiZvQW/FBVKrjlnLDzD8+rd/XmQKwjzgyeOObHQ5gjnEBPbdt
         cOtgg6+mCV3Zx4Y5YNV8weOi2sGYrINeLStOfZnVLg4acTK9SXSG9PgBanVncSicCihO
         H/ST54umpRvdnZeFFsCTPh4BS6FMzhKL3VEhqaFHwvR9faJ2nP9sEMhXvIvsTKB6KDxq
         szDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cOkkiDEp;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754424146; x=1755028946; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Zfwb901DM6uwPHGjkMq8V4w04kEiO9HXDyLa1i7QIrI=;
        b=s9T3ztuAgI1JA+B4Y/rGgTOrIFEIkkZ8fnHu0u3565s1xEJplyWXOpW7pw79twYYJw
         7V24S/VCRE8QEMlqqw2kH5UIsYx/vIrQVL3uibGemXSXYYEjoayi38WpLsFZhJ4T/vXB
         kBJHZtIlKRDgtI04MeZnqNVy84I/uyIqEtfvLj+QbGqW2TxTcRcw8KgzijxuJXRTHSjh
         I/RZvk0O/UuXdSYCnaVPFbYRp1hnYmT+bWGQodGFzlRzMGepAN7GjqPmaHcsw+InfCBa
         /PU85QezeEBfENbw9GAefOJegMr5JWe3tbL/pAmcNSVuXo7XmQgV0rNr5wyWMi60PTaO
         /ocQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754424146; x=1755028946; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Zfwb901DM6uwPHGjkMq8V4w04kEiO9HXDyLa1i7QIrI=;
        b=FnevyYogBRUUB0tt99heeyNQ+dYgZZyReeFVtWr5bRWMW82B+MOfKa6sgikO9J61/t
         i4KqyQKZdFs8/UzVYE4/UkaxvRTefr6r2Lyz+hIGipQbMnelxj/yVLHnQSVwaIUiDAqF
         Ue7nh9MOuUzwmqLRvu9mluapkvDK6XzPqAUhmkH1ll/9MSCwzJjFirI1tW4zS2T8ck6J
         enZacVt0FwyoW3lUAF/RAnnKcVRFH7gAcjhHQ1tJr05VQZ67Nl+rIYE7YVXBaM6M6crW
         ibwLX5K54tmSA3a0pLxumLBnfjwGkL1wa+KpspTbDMBNhxJ/4keQNRya3eWXs7on8L7/
         Ig4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754424146; x=1755028946;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Zfwb901DM6uwPHGjkMq8V4w04kEiO9HXDyLa1i7QIrI=;
        b=fganVCHl7N6t6b0xiClJNChfFj7YobMM+lo4AjClEL+POsRZCKv19eAt8nbnlHKYxQ
         J49tnp+TcavAQZeXPEpYM8P80DlCCr9OeXUt7MqDIfQXDtwHKSDMQr8XW5N7PNnvk/ek
         jKo1S+u7fbHpglFZMElcnXWzhd4PAYuBz0HNAGvWKPbpMX/RvjH/Ov2CAe8DzRXLl7Eh
         JzHgwZ/Qvg4Ul0IEiCSEG9sqaeLdaXnNTH8JOMWOuoWBcoIuhp3+Ec4snTliGUSf5uBm
         UTYedFofblJol3wlwRVI65zTH+5iAUWJJvUNJTwa5xFncuoSoPPa9xKOU1q+ALahf3IR
         KCtw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjMoVTl0V3P18Q5hEITq1pzmHPanizf6y65JNtipzVodzczxC29+fR4SX/CE0a8Sb/XJRjBQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy12Xd4W3503zjvr+BQkYgyWOgv4Jtp8/UnFKL6pVFOpo6sZCIq
	Hx+UdfHFtpEy6sZ82JpdS1MQr5TYGY3LDNhR07U2odCAN4EM/FeYA80S
X-Google-Smtp-Source: AGHT+IEJAYyQbCKSZDNKvyjkJ6F4oyNXgVu0MTf1KLR8Ej4Qhry4EChULgkapXrRYip++zQjCiIySQ==
X-Received: by 2002:a17:906:478a:b0:af9:3116:e0ff with SMTP id a640c23a62f3a-af99033608fmr28645766b.52.1754424145562;
        Tue, 05 Aug 2025 13:02:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfDK5LH3CF/W8CALuOZFMeh2PDrIfU3nOQDHPqohrHJ0Q==
Received: by 2002:a05:6402:524c:b0:615:7125:5fa8 with SMTP id
 4fb4d7f45d1cf-615a79fdc8fls6964619a12.1.-pod-prod-09-eu; Tue, 05 Aug 2025
 13:02:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWz4/Yp/J4OSElHs9pVrd2d+DuDT+pOZ31Yp71x/iOj4uxw8b3S+WvjW0OE4+1A80Zuh1iPaONkBAk=@googlegroups.com
X-Received: by 2002:a05:6402:350e:b0:604:e33f:e5c0 with SMTP id 4fb4d7f45d1cf-6179619bcb3mr200924a12.30.1754424142888;
        Tue, 05 Aug 2025 13:02:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754424142; cv=none;
        d=google.com; s=arc-20240605;
        b=ikU9Qyh+KhWV55tyUY7w+6WaijpfC7SnzgdvpEy+0fT4W/2SY9djU1CkB7uC382ciU
         ApSwV/bb/vImXoGB3vc/quRH29KkSRHcOoEf0q37cEQL3VqXI5Kla2/dwpODwYDJxrUD
         bqb2nkZDlyehH4Pj7wsXQ7bnKtzQ1x69ghwgB3Nj1xeruM2V6OPC0wPgr5L5GzcU9JJi
         DZJiyy6C0HwzMj7G8HC3FSEc0PnK0HX1fKwQdpgR3NRFXF++Bhph2N/8k1CV28iicgAO
         6pkR+P2wd68vRNqV+YgJdCrzUaZJOcuBOCrI+FpdoU4HfLPNbvyLoUbU8ASW6ffsfDdx
         Ig/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=O2cFsdms4RuCNcP4Iorpa0o1Areo2LvBxNFgdDdoNAo=;
        fh=blhB8IkGiu5ln8XCPRbNDfchnJ0z/XyJWGZBsGyn1T4=;
        b=kD3VR2q3AV2TMgrd6BtH8yw0bJDu7QEI4A37eCrgf4HTsFBMEg0i2Do7nseQKooaM3
         TRW84MLNWL3d/YkIe904Yvgu3DTu70fWU1nRWEToNYqm/okNm/sKpeGqT3ecj/TN/rgc
         WcaPdM7ZpvVLOTt9SpvYBvE5i7LxpuIXXBn/8JSvEcwf17VPhBCcED9X7aH/M0781L1j
         SwApoUhRsyr6BKXwKB9siUuvkwvf4LQmgzOpHSuFSRrSz95SyX33d4u4dOajO2WaKIeD
         R4XXujVn3CkL5PrGHrDCV7TKhUXp9CkH4h+6LUTikiuwW/9XSmKzAodwkEcEMBoqRAxt
         AmkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cOkkiDEp;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8ff4e94si247875a12.3.2025.08.05.13.02.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 13:02:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id a640c23a62f3a-af93c3bac8fso670652966b.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 13:02:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWWVXKkLVWOVK5sSDCaDuslPYeJgdJ4o8zayaSOOhPLZLVTGqwogU55LjUteF2sDtvHIM50hc/DH1Q=@googlegroups.com
X-Gm-Gg: ASbGncsRCKGlj7gLzz0z8woWmIiCsy4hMxPZ5ZFN/sJUO/Zc8vyvGJsp0URiGrwb/h+
	VaHJph6qUUYrZJnsQHlMNOft3k86My1V9VH4UEKFZHgq143SfK0s2MBIHMGUceterIenD2Rn1wV
	Lgmcdi5b1/UC/X3WKkUZvo049/KGAnUYgBFqcKkE2ZfHci+hx8pGtmKrZZIle3k7lQDT+BX23TO
	d36jiWD
X-Received: by 2002:a17:907:3f9e:b0:af8:ed6a:a9c6 with SMTP id
 a640c23a62f3a-af990036e11mr33033566b.20.1754424141917; Tue, 05 Aug 2025
 13:02:21 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Wed, 6 Aug 2025 00:08:15 +0300
X-Gm-Features: Ac12FXwYIyCZzgZImDXAWSSJ4f3JZV9MP2WV4l6ILAaJTX7p4dVuzqHopnqfkaE
Message-ID: <CADj1ZKm9nrk86=0MnWxTzX3gbKNZXDr9xFQD90wQ1G+XuAcxPQ@mail.gmail.com>
Subject: =?UTF-8?B?2LTZh9in2K/YqSDZhdmH2YbZitipINmF2LnYqtmF2K/YqSDZhdiz2KTZiNmEINiq2LfZiA==?=
	=?UTF-8?B?2YrYsSDYp9mE2KPYudmF2KfZhCDYp9mE2YXYrdiq2LHZgSBCdXNpbmVzcyBEZXZlbG9wbWVudCBTcGVj?=
	=?UTF-8?B?aWFsaXN0INij2K3Yr9irINiq2LfYqNmK2YLYp9iqINin2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbYp9i5?=
	=?UTF-8?B?2Yog2YHZiiDYqti32YjZitixINin2YTYo9i52YXYp9mEINin2YTZhdmI2KfYudmK2K8g2KfZhNmF2Ko=?=
	=?UTF-8?B?2KfYrdipOiDYudmGINio2Y/YudivINi52KjYsSBab29tOiDZhdmGIDEwINil2YTZiSAxNCDYo9i62LM=?=
	=?UTF-8?B?2LfYsyAyMDI1INit2LbZiNix2Yog2YHZiiDYp9mE2YLYp9mH2LHYqSDigJMg2YXZgtixINin2YTYr9in?=
	=?UTF-8?B?2LE6INmK2YjZhSDYp9mE2KPYrdivIDcg2LPYqNiq2YXYqNixIDIwMjUg2LTZh9in2K/YqSDZhdmH2YY=?=
	=?UTF-8?B?2YrYqSDZhdi52KrZhdiv2Kkg4oCTINmF2YjYq9mC2Kkg2YjYqNin2LnYqtmF2KfYryDYr9mI2YTZiiA=?=
	=?UTF-8?B?2YXYudiq2LHZgSDYqNmH2Kcg2YHZiiDZg9in2YHYqSDYp9mE2K/ZiNmEINin2YTYr9in2LEg2KfZhNi5?=
	=?UTF-8?B?2LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Yp9ix2YrYqSDigJMgQUhBRCDYqtit2YrYqSA=?=
	=?UTF-8?B?2LfZitio2Kkg2Ygg2KjYudivINiM2IzYjCDYo9i32YrYqCDYp9mE2KPZhdmG2YrYp9iqINmI2KfZhNiq?=
	=?UTF-8?B?2K3Zitin2Kog2KrZh9iv2YrZh9inINmE2YPZhSDYp9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YQ=?=
	=?UTF-8?B?2KrZhtmF2YrYqSDYp9mE2KfYr9in2LHZitipINio2LTZh9in2K/YqSDZhdi52KrZhdivIC0gQUhBRCA=?=
	=?UTF-8?B?2LTZh9in2K/YqSDZhdin2LDYpyDYs9iq2KrYudmE2YU6INij2K/ZiNin2Kog2KfZhNiw2YPYp9ihINin?=
	=?UTF-8?B?2YTYp9i12LfZhtin2LnZiiDYp9mE2K3Yr9mK2KvYqSDZgdmKINiq2LfZiNmK2LEg2KfZhNij2LnZhdin?=
	=?UTF-8?B?2YQg2KrYrdmE2YrZhCDYp9mE2KPYs9mI2KfZgiDZiNiq2K3Yr9mK2K8g2KfZhNmB2LHYtSDYqNin2LM=?=
	=?UTF-8?B?2KrYrtiv2KfZhSDYp9mE2KjZitin2YbYp9iqINiq2LPYsdmK2Lkg2KfZhNin2KjYqtmD2Kfvv70=?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000c3b5da063ba3b312"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cOkkiDEp;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::636
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

--000000000000c3b5da063ba3b312
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

Kti02YfYp9iv2Kkg2YXZh9mG2YrYqSDZhdi52KrZhdiv2KkqDQoNCirZhdiz2KTZiNmEINiq2LfZ
iNmK2LEg2KfZhNij2LnZhdin2YQg2KfZhNmF2K3Yqtix2YEqDQoNCipCdXNpbmVzcyBEZXZlbG9w
bWVudCBTcGVjaWFsaXN0Kg0KDQoq2KPYrdiv2Ksg2KrYt9io2YrZgtin2Kog2KfZhNiw2YPYp9ih
INin2YTYp9i12LfZhtin2LnZiiDZgdmKINiq2LfZiNmK2LEg2KfZhNij2LnZhdin2YQqDQoNCirY
p9mE2YXZiNin2LnZitivINin2YTZhdiq2KfYrdipKio6Kg0KDQoq2LnZhiDYqNmP2LnYryDYudio
2LEqKiBab29tOiog2YXZhiAqMTAgKirYpdmE2YkgMTQg2KPYutiz2LfYsyAyMDI1Kg0KDQoq2K3Y
ttmI2LHZiiDZgdmKINin2YTZgtin2YfYsdipIOKAkyDZhdmC2LEg2KfZhNiv2KfYsSoqOiog2YrZ
iNmFICrYp9mE2KPYrdivIDcg2LPYqNiq2YXYqNixIDIwMjUqDQoNCirYtNmH2KfYr9ipINmF2YfZ
htmK2Kkg2YXYudiq2YXYr9ipIOKAkyDZhdmI2KvZgtipINmI2KjYp9i52KrZhdin2K8g2K/ZiNmE
2YoqICrZhdi52KrYsdmBINio2YfYpyDZgdmKINmD2KfZgdipINin2YTYr9mI2YQqDQoNCirYp9mE
2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYp9iv2KfYsdmK2Kkg4oCT
ICoqQUhBRCoNCg0K2KrYrdmK2Kkg2LfZitio2Kkg2Ygg2KjYudivINiM2IzYjA0KDQrYo9i32YrY
qCDYp9mE2KPZhdmG2YrYp9iqINmI2KfZhNiq2K3Zitin2Kog2KrZh9iv2YrZh9inINmE2YPZhSDY
p9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYp9iv2KfYsdmK2Kkg
2KjYtNmH2KfYr9ipDQrZhdi52KrZhdivIC0gQUhBRA0KDQrYtNmH2KfYr9ipDQoNCtmF2KfYsNin
INiz2KrYqti52YTZhToNCg0K2KPYr9mI2KfYqiDYp9mE2LDZg9in2KEg2KfZhNin2LXYt9mG2KfY
udmKINin2YTYrdiv2YrYq9ipINmB2Yog2KrYt9mI2YrYsSDYp9mE2KPYudmF2KfZhA0KDQrYqtit
2YTZitmEINin2YTYo9iz2YjYp9mCINmI2KrYrdiv2YrYryDYp9mE2YHYsdi1INio2KfYs9iq2K7Y
r9in2YUg2KfZhNio2YrYp9mG2KfYqg0KDQrYqtiz2LHZiti5INin2YTYp9io2KrZg9in2LEg2YjY
qtit2LPZitmGINin2YTYudmF2YTZitin2Kog2KfZhNiq2KzYp9ix2YrYqQ0KDQrZhtmF2KfYsNis
INin2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbYp9i52Yog2YTYr9i52YUg2KfYqtiu2KfYsCDYp9mE
2YLYsdin2LENCg0K2KrZgtmG2YrYp9iqINin2YTYo9iq2YXYqtip2Iwg2KfZhNiq2K7YtdmK2LXY
jCDZiNin2YTYqtit2YTZitmEINin2YTYqtmG2KjYpNmKDQoNCtij2K/ZiNin2Kog2YXYq9mEOiBD
aGF0R1BUIOKAkyBNaWRqb3VybmV5IOKAkyBQb3dlciBCSSDigJMgTm90aW9uIEFJDQoNCg0KDQrY
o9mH2K/Yp9mBINin2YTYqNix2YbYp9mF2Kw6DQoNCjEuICAg2KrZhdmD2YrZhiDYp9mE2YXYtNin
2LHZg9mK2YYg2YXZhiDYp9iz2KrYrtiv2KfZhSDYo9iv2YjYp9iqINin2YTYsNmD2KfYoSDYp9mE
2KfYtdi32YbYp9i52Yog2YTYqti32YjZitixINin2YTYo9i52YXYp9mEDQrZiNiq2K3ZhNmK2YQg
2KfZhNij2LPZiNin2YIuDQoNCjIuICAg2KrYudiy2YrYsiDYp9mE2KrZgdmD2YrYsSDYp9mE2KfY
qNiq2YPYp9ix2Yog2YHZiiDYqti12YXZitmFINmI2KrZiNiz2YrYuSDZhtmF2KfYsNisINin2YTY
o9i52YXYp9mEINio2KfYs9iq2K7Yr9in2YUNCtin2YTYqtmC2YbZitin2Kog2KfZhNiw2YPZitip
Lg0KDQozLiAgINin2YTYqti52LHZgSDYudmE2Ykg2KrYt9io2YrZgtin2Kog2KfZhNiw2YPYp9ih
INin2YTYp9i12LfZhtin2LnZiiDZgdmKINin2YTYqtmG2KjYpCDYqNin2YTYt9mE2KjYjCDZiNiq
2K3Ys9mK2YYg2KrYrNix2KjYqQ0K2KfZhNi52YXZhNin2KEuDQoNCjQuICAg2KjZhtin2KEg2KfY
s9iq2LHYp9iq2YrYrNmK2KfYqiDYqti32YjZitixINij2LnZhdin2YQg2YXYr9i52YjZhdipINio
2KfZhNio2YrYp9mG2KfYqiDZiNin2YTYqtit2YTZitmEINin2YTYsNmD2YouDQoNCjUuICAg2KrY
o9mH2YrZhCDYp9mE2YXYtNin2LHZg9mK2YYg2YTZhNiq2LnYp9mF2YQg2YXYuSDYo9iv2YjYp9iq
INmF2KvZhCBDaGF0R1BU2IwgUG93ZXIgQknYjCBOb3Rpb24gQUnYjA0K2YjYutmK2LHZh9inLg0K
DQo2LiAgINil2LnYr9in2K8g2YPZiNin2K/YsSDZgtin2K/YsdipINi52YTZiSDZgtmK2KfYr9ip
INin2YTYqtit2YjZhCDYp9mE2LHZgtmF2Yog2YjYp9mE2YbZhdmIINin2YTYsNmD2Yog2YHZiiDZ
hdik2LPYs9in2KrZh9mFLg0KDQoNCg0K2KfZhNmF2K3Yp9mI2LEg2KfZhNiq2K/YsdmK2KjZitip
Og0KDQoqMS4gKirZhdiv2K7ZhCDYpdmE2Ykg2KrYt9mI2YrYsSDYp9mE2KPYudmF2KfZhCDYp9mE
2LDZg9mKKg0KDQogICAtINin2YTZhdmB2YfZiNmFINin2YTYrdiv2YrYqyDZhNiq2LfZiNmK2LEg
2KfZhNij2LnZhdin2YQNCiAgIC0g2KfZhNmB2LHZgiDYqNmK2YYg2KfZhNmF2KjZiti52KfYqtiM
INin2YTYqtiz2YjZitmC2Iwg2YjYqti32YjZitixINin2YTYo9i52YXYp9mEDQogICAtINin2YTY
o9iv2YjYp9ixINmI2KfZhNmF2LPYpNmI2YTZitin2Kog2KfZhNix2KbZitiz2YrYqSDZhNmE2YXY
s9ik2YjZhCDYp9mE2YXYrdiq2LHZgQ0KDQoqMi4gKirYo9iv2YjYp9iqINin2YTYsNmD2KfYoSDY
p9mE2KfYtdi32YbYp9i52Yog2YHZiiDYqti32YjZitixINin2YTYo9i52YXYp9mEKg0KDQogICAt
INin2LPYqtiu2K/Yp9mFINin2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbYp9i52Yog2YHZiiDYqtit
2YTZitmEINin2YTYs9mI2YIg2YjYp9mE2YXZhtin2YHYs9mK2YYNCiAgIC0g2KPYr9mI2KfYqiDY
qtmI2YTZitivINin2YTZhdit2KrZiNmJINin2YTYqtiz2YjZitmC2YogKENoYXRHUFQg4oCTIENv
cGlsb3Qg4oCTIE5vdGlvbiBBSSkNCiAgIC0g2KPYqtmF2KrYqSDYrNmF2Lkg2YjYqtit2YTZitmE
INin2YTYqNmK2KfZhtin2Kog2YjYqtmI2KzZitmHINin2YTZgtix2KfYsdin2KoNCg0KKjMuICoq
2KrYrdmE2YrZhCDYp9mE2KjZitin2YbYp9iqINmI2K/YudmFINin2KrYrtin2LAg2KfZhNmC2LHY
p9ixKg0KDQogICAtINiq2K3ZhNmK2YQg2LPZhNmI2YMg2KfZhNi52YXZhNin2KEg2YjYo9mG2YXY
p9i3INin2YTYtNix2KfYoQ0KICAgLSDYp9iz2KrYtNix2KfZgSDYp9mE2KfYqtis2KfZh9in2Kog
2YjYqtmI2YLYuSDYp9mE2YHYsdi1DQogICAtINiq2LfYqNmK2YIgUG93ZXIgQkkg2YHZiiDYudix
2LYg2KfZhNiq2YLYp9ix2YrYsSDYp9mE2LDZg9mK2KkNCg0KKjQuICoq2KrYrdiz2YrZhiDYqtis
2LHYqNipINin2YTYudmF2YrZhCDYqNin2LPYqtiu2K/Yp9mFKiogQUkqDQoNCiAgIC0g2KrYrti1
2YrYtSDYp9mE2LnYsdmI2LYg2YjYp9mE2K7Yr9mF2KfYqiDYotmE2YrZi9inDQogICAtINix2YjY
qNmI2KrYp9iqINin2YTZhdit2KfYr9ir2KkgKENoYXRib3RzKSDZiNiu2K/ZhdipINin2YTYudmF
2YTYp9ihINin2YTYsNmD2YrYqQ0KICAgLSDYqti12YXZitmFINiu2LHYp9im2Lcg2LHYrdmE2Kkg
2KfZhNi52YXZitmEINio2YbYp9ih2Ysg2LnZhNmJINin2YTYqNmK2KfZhtin2KoNCg0KKjUuICoq
2KfYs9iq2LHYp9iq2YrYrNmK2KfYqiDYp9mE2KrZiNiz2Lkg2YjYp9mE2YbZhdmIINio2KfYs9iq
2K7Yr9in2YUg2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiioNCg0KICAgLSDYqti32YjZ
itixINmG2YXYp9iw2Kwg2KPYudmF2KfZhCDZgtin2KjZhNipINmE2YTYqtmI2LPYuQ0KICAgLSDY
r9mF2Kwg2KPYr9mI2KfYqiBBSSDZgdmKINin2LPYqtix2KfYqtmK2KzZitin2Kog2KfZhNiq2LPZ
iNmK2YIg2KfZhNix2YLZhdmKDQogICAtINin2LPYqtiu2K/Yp9mFIE1pZGpvdXJuZXkg2YhEQUxM
wrdFINmB2Yog2KrYt9mI2YrYsSDYp9mE2YfZiNmK2KfYqiDYp9mE2KjYtdix2YrYqQ0KDQoqNi4g
KirZhdi02LHZiNi5INiq2LfYqNmK2YLZijog2K7Yt9ipINiq2LfZiNmK2LEg2KPYudmF2KfZhCDZ
hdiv2LnZiNmF2Kkg2KjZgCoqIEFJKg0KDQogICAtINiq2LfYqNmK2YIg2LnZhdmE2Yo6INiq2K3Z
hNmK2YQg2LTYsdmD2Kkg2YjYp9mC2LnZitipINij2Ygg2YHZg9ix2Kkg2YbYp9i02KbYqQ0KICAg
LSDYqti12YXZitmFINin2LPYqtix2KfYqtmK2KzZitipINiq2LfZiNmK2LEg2KfZhNij2LnZhdin
2YQg2KjYp9iz2KrYrtiv2KfZhSDYo9iv2YjYp9iqINin2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbY
p9i52YoNCiAgIC0g2KrZgtiv2YrZhSDYp9mE2LnYsdi2INin2YTZhtmH2KfYptmKINmI2KrZgtmK
2YrZhdmHINmF2YYg2YLYqNmEINin2YTZhdiv2LHYqA0KDQoNCg0K2KfZhNmB2KbYqSDYp9mE2YXY
s9iq2YfYr9mB2Kk6DQoNCtmD2KfZgdipINin2YTZhdiv2LHYp9ihINmB2Yog2KfZhNmC2LfYp9i5
2YrZhiDYp9mE2LnYp9mFINmI2KfZhNiu2KfYtQ0KDQrZhdiv2LHYp9ihINiq2LfZiNmK2LEg2KfZ
hNij2LnZhdin2YQNCg0K2LHZiNin2K8g2KfZhNij2LnZhdin2YQg2YjYp9mE2KfYs9iq2LTYp9ix
2YrZiNmGDQoNCtmB2LHZgiDYp9mE2KrYs9mI2YrZgiDZiNin2YTZhdio2YrYudin2KoNCg0K2YXY
r9ix2KfYoSDYp9mE2KfYqNiq2YPYp9ixINmI2KfZhNiq2K3ZiNmEINin2YTYsdmC2YXZig0KDQoN
Cg0KKtis2K/ZiNmEINin2YTYr9mI2LHYp9iqINin2YTYqtiv2LHZitio2YrYqSDigJMg2KPYutiz
2LfYsyAyMDI1Kg0KDQoq2YXZgtiv2YXYqSDZhdmGOiDYp9mE2K/Yp9ixINin2YTYudix2KjZitip
INmE2YTYqtmG2YXZitipINin2YTYpdiv2KfYsdmK2KkqKiDigJMgQUhBRCoNCg0KKtin2YTYqtin
2LHZitiuKg0KDQoq2KfYs9mFINin2YTYr9mI2LHYqSoNCg0KKtin2YTZhdiv2KkqDQoNCirYp9mE
2YXZg9in2YYqDQoNCirYp9mE2YXZhNin2K3YuNin2KoqDQoNCjEwIOKAkyAxNCDYo9i62LPYt9iz
DQoNCtin2YTZgtin2KbYryDYp9mE2KXYs9iq2LHYp9iq2YrYrNmKINin2YTZhdi52KrZhdivDQoN
CjUg2KPZitin2YUNCg0K2LnYqNixIFpvb20NCg0K2LTZh9in2K/YqSDZhdmI2KvZgtipINmI2YLY
p9io2YTYqSDZhNmE2KrYtdiv2YrZgg0KDQoxMCDigJMgMTQg2KPYutiz2LfYsw0KDQrYp9mE2KfY
qtmK2YPZitiqINmI2KfZhNio2LHZiNiq2YjZg9mI2YQg2YjYp9mE2YXYsdin2LPZhQ0KDQo1INij
2YrYp9mFDQoNCtin2YTZgtin2YfYsdipINij2YggWm9vbQ0KDQrYtNmH2KfYr9ipINmF2YjYq9mC
2Kkg2YXZhiDYp9mE2K7Yp9ix2KzZitipDQoNCjEwIOKAkyAxOSDYo9i62LPYt9izDQoNCtij2K7Y
tdin2KbZiiDYp9mE2YXZiNin2LHYryDYp9mE2KjYtNix2YrYqSDYp9mE2YXYrdiq2LHZgSAoUEhS
TSkNCg0KMTAg2KPZitin2YUNCg0K2KfZhNmC2KfZh9ix2KkNCg0K2KrYuti32YrYqSDYtNin2YXZ
hNipINmE2YTZhdmI2KfYsdivINin2YTYqNi02LHZitipDQoNCjE3IOKAkyAyMSDYo9i62LPYt9iz
DQoNCtin2YTYsdmC2KfYqNipINmI2KfZhNiq2K/ZgtmK2YIg2KfZhNiv2KfYrtmE2Yog2YjZhdix
2KfYrNi52Kkg2KfZhNit2LPYp9io2KfYqg0KDQo1INij2YrYp9mFDQoNCtin2YTZgtin2YfYsdip
INij2YggWm9vbQ0KDQrYqti32KjZitmC2KfYqiDYudmF2YTZitipINmI2YXZh9mG2YrYqQ0KDQox
NyDigJMgMjEg2KPYutiz2LfYsw0KDQrwn5K7INin2YTZhdmH2KfYsdin2Kog2KfZhNix2YLZhdmK
2Kkg2KfZhNmF2LnYqtmF2K/YqQ0KDQo1INij2YrYp9mFDQoNCtin2YTZgtin2YfYsdipDQoNCti0
2YfYp9iv2KfYqiDYr9mI2YTZitipINmF2LnYqtmF2K/YqQ0KDQoxNyDigJMgMjEg2KPYutiz2LfY
sw0KDQrwn4+tINit2YjZg9mF2Kkg2YjYpdiv2KfYsdipINin2YTZhdi12KfZhti5DQoNCjUg2KPZ
itin2YUNCg0K2KfZhNmC2KfZh9ix2KkNCg0K2K3ZiNmD2YXYqSDYp9mE2KrYtNi62YrZhCDZiNin
2YTYpdmG2KrYp9isINin2YTYtdmG2KfYudmKDQoNCjI0IOKAkyAyOCDYo9i62LPYt9izDQoNCvCf
krwg2YXYrdin2LPYqCDYp9mE2LbYsdin2KbYqCDYp9mE2YXYrdiq2LHZgQ0KDQo1INij2YrYp9mF
DQoNCtin2YTZgtin2YfYsdipDQoNCtiq2K/YsdmK2Kgg2KrYo9mH2YrZhNmKINmB2Yog2KfZhNis
2YjYp9mG2Kgg2KfZhNi22LHZitio2YrYqQ0KDQoyNCDigJMgMjgg2KPYutiz2LfYsw0KDQrwn6e+
INil2K/Yp9ix2Kkg2KfZhNmF2YPYp9iq2Kgg2YjYp9mE2LPZg9ix2KrYp9ix2YrYqSDYp9mE2KrZ
htmB2YrYsNmK2KkNCg0KNSDYo9mK2KfZhQ0KDQrYp9mE2YLYp9mH2LHYqQ0KDQrYr9mI2LHYqSDY
udmF2YTZitipINmF2YPYq9mB2KkNCg0KMjQg4oCTIDI4INij2LrYs9i32LMNCg0K4pyFIE9TSEEg
2YHZiiDYp9mE2LXYrdipINmI2KfZhNiz2YTYp9mF2Kkg2KfZhNmF2YfZhtmK2KkNCg0KNSDYo9mK
2KfZhQ0KDQrYp9mE2YLYp9mH2LHYqQ0KDQrYtNmH2KfYr9ipINiv2YjZhNmK2Kkg2YXYudiq2YXY
r9ipDQoNCjI0IOKAkyAyOCDYo9i62LPYt9izDQoNCvCfkrAg2KfZhNil2K/Yp9ix2Kkg2KfZhNmF
2KfZhNmK2Kkg2YjYp9mE2KrYrdmE2YrZhCDYp9mE2YXYp9mE2Yog2KfZhNmF2KrZgtiv2YUNCg0K
NSDYo9mK2KfZhQ0KDQrYp9mE2YLYp9mH2LHYqQ0KDQrYo9iv2YjYp9iqINmC2YrYp9izINmI2KrY
rdmE2YrZhCDZhdin2YTZiiDZhdiq2YPYp9mF2YQNCg0KMjQg4oCTIDI4INij2LrYs9i32LMNCg0K
8J+TiiDYp9mE2YXZiNin2LLZhtin2Kog2KfZhNiq2K7Yt9mK2LfZitipINmI2KfZhNix2YLYp9io
2Kkg2KfZhNmF2KfZhNmK2KkNCg0KNSDYo9mK2KfZhQ0KDQrYp9mE2YLYp9mH2LHYqQ0KDQrZhdit
2KfZiNixINiq2LfYqNmK2YLZitipINmF2Lkg2KrZhdin2LHZitmGINiq2K3ZhNmK2YQNCg0KMzEg
2KPYutiz2LfYsw0KDQrwn46TINio2K/YoSDYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmK
INin2YTZhdi12LrYsSDZgdmKINin2YTYqtmG2YXZitipINin2YTYqNi02LHZitipDQoNCtio2LHZ
htin2YXYrCDYt9mI2YrZhA0KDQrYp9mE2YLYp9mH2LHYqQ0KDQrYp9mG2LfZhNin2YIg2KPZiNmE
INmK2YjZhSDZhNmE2KjYsdmG2KfZhdisDQoNCg0KDQoNCg0KKvCfk4UqICrYp9mE2LTZh9in2K/Y
p9iqINin2YTZhdmH2YbZitipIOKAkyDYs9io2KrZhdio2LEgMjAyNSoNCg0KKtmFKg0KDQoq2KfY
s9mFINin2YTYtNmH2KfYr9ipINin2YTZhdmH2YbZitipKg0KDQoq2KfZhNiq2K7Ytdi1Kg0KDQoq
2KrYp9ix2YrYriDYp9mE2KfZhti52YLYp9ivKg0KDQoq2KfZhNmF2YLYsSDYp9mE2YXZgtiq2LHY
rSoNCg0KMQ0KDQoq2LTZh9in2K/YqSDYp9mE2YXYr9mK2LEg2KfZhNiq2YbZgdmK2LDZiiDYp9mE
2YXYrdiq2LHZgSoqIChDRU8pKg0KDQrYp9mE2YLZitin2K/YqSDZiNin2YTYpdiv2KfYsdipINin
2YTYudmE2YrYpw0KDQoxIOKAkyA1INiz2KjYqtmF2KjYsQ0KDQrYr9io2YoNCg0KMg0KDQoq2KfZ
hNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDZgdmKINin2KrYrtin2LAg2KfZhNmC2LHYp9ix
INin2YTZhdik2LPYs9mKKg0KDQrYp9mE2KrYrdmI2YQg2KfZhNix2YLZhdmKIC8gQUkNCg0KOCDi
gJMgMTIg2LPYqNiq2YXYqNixDQoNCtil2LPYt9mG2KjZiNmEDQoNCjMNCg0KKti02YfYp9iv2Kkg
2K7YqNmK2LEg2KfZhNit2YjZg9mF2Kkg2KfZhNmF2KTYs9iz2YrYqSDYp9mE2YXYudiq2YXYryoN
Cg0K2KfZhNit2YjZg9mF2KkNCg0KOCDigJMgMTIg2LPYqNiq2YXYqNixDQoNCtin2YTZgtin2YfY
sdipDQoNCjQNCg0KKtmF2K3ZhNmEINin2YTZhdiu2KfYt9ixINin2YTYqti02LrZitmE2YrYqSDY
p9mE2YXYudiq2YXYryoqIChDT1JBKSoNCg0K2KXYr9in2LHYqSDYp9mE2YXYrtin2LfYsQ0KDQox
NSDigJMgMTkg2LPYqNiq2YXYqNixDQoNCtin2YTZgtin2YfYsdipDQoNCjUNCg0KKtmF2K/ZgtmC
INin2YTYrNmI2K/YqSDYp9mE2K/Yp9iu2YTZitipINin2YTZhdi52KrZhdivKiogKENRSUEpKg0K
DQrYp9mE2KzZiNiv2KkgLyBJU08NCg0KMTUg4oCTIDE5INiz2KjYqtmF2KjYsQ0KDQrYp9mE2YLY
p9mH2LHYqQ0KDQo2DQoNCirYrtio2YrYsSDYp9mE2KrYrdmE2YrZhCDYp9mE2YXYp9mE2Yog2YjY
p9mE2KrZgtmK2YrZhSDYp9mE2YXYp9mE2Yog2KfZhNmF2KrZgtiv2YUqDQoNCtmF2KfZhNmK2Kkg
2YjYp9iz2KrYq9mF2KfYsQ0KDQoyMiDigJMgMjYg2LPYqNiq2YXYqNixDQoNCtin2YTZgtin2YfY
sdipDQoNCjcNCg0KKtil2K/Yp9ix2Kkg2KfZhNmF2YjYp9ix2K8g2KfZhNio2LTYsdmK2Kkg2KjY
p9iz2KrYrtiv2KfZhSDYp9mE2KrYrdmE2YrZhNin2Kog2KfZhNiw2YPZitipKg0KDQpIUiBBbmFs
eXRpY3MNCg0KMjIg4oCTIDI2INiz2KjYqtmF2KjYsQ0KDQrYp9mE2YLYp9mH2LHYqQ0KDQo4DQoN
CirYp9mE2KrYrdmC2YrZgiDYp9mE2KXYr9in2LHZiiDZgdmKINin2YTZhdiu2KfZhNmB2KfYqiDZ
iNin2YTYp9mG2K3Ysdin2YHYp9iqINin2YTZhdin2YTZitipKg0KDQrYp9mE2LTYpNmI2YYg2KfZ
hNmC2KfZhtmI2YbZitipIC8g2KfZhNin2YbYttio2KfYtw0KDQoyOSDYs9io2KrZhdio2LEg4oCT
IDMg2KPZg9iq2YjYqNixDQoNCtin2YTZgtin2YfYsdipDQoNCjkNCg0KKtin2YTYqtiu2LfZiti3
INin2YTYqti02LrZitmE2Yog2YjYsdio2LfZhyDYqNin2YTYo9mH2K/Yp9mBINin2YTYp9iz2KrY
sdin2KrZitis2YrYqSoNCg0K2KXYr9in2LHYqSDYp9mE2LnZhdmE2YrYp9iqDQoNCjE1IOKAkyAx
OSDYs9io2KrZhdio2LENCg0K2KfZhNmC2KfZh9ix2KkNCg0KMTANCg0KKti02YfYp9iv2Kkg2YXY
s9iq2LTYp9ixINin2YTYqtiv2LHZitioINmI2KfZhNiq2LfZiNmK2LEg2KfZhNmF2KTYs9iz2Yog
2KfZhNmF2LnYqtmF2K8qDQoNCtiq2LfZiNmK2LEg2KfZhNmF2YjYp9ix2K8g2KfZhNio2LTYsdmK
2KkNCg0KMjkg2LPYqNiq2YXYqNixIOKAkyAzINij2YPYqtmI2KjYsQ0KDQrYp9mE2YLYp9mH2LHY
qQ0KDQoNCg0KKuKchSogKtmF2YTYp9it2LjYp9iqINi52KfZhdipKio6Kg0KDQoq2KzZhdmK2Lkg
2KfZhNi02YfYp9iv2KfYqiDYqti02YXZhCDYtNmH2KfYr9ipINmF2LnYqtmF2K/YqdiMINit2YLZ
itio2Kkg2KrYr9ix2YrYqNmK2KnYjCDZiNmI2LHYtCDYudmF2YQg2KrZgdin2LnZhNmK2KkqKi4q
DQoNCtmK2YXZg9mGINiq2YbZgdmK2LAg2KfZhNio2LHYp9mF2KwgKtit2LbZiNix2YrZi9inINij
2Ygg2KPZiNmG2YTYp9mK2YYg2LnYqNixKiogWm9vbSouDQoNCtil2YXZg9in2YbZitipINiq2K7Y
tdmK2LUg2KPZiiDYtNmH2KfYr9ipINmE2KrZg9mI2YYgKtiv2KfYrtmEINin2YTYtNix2YPYqSoq
IChJbi1Ib3VzZSkqLg0KDQoq2YTZhNiq2LPYrNmK2YQg2YjYp9mE2KfYs9iq2YHYs9in2LEqDQoN
CirZiNio2YfYsNmHINin2YTZhdmG2KfYs9io2Kkg2YrYs9i52K/ZhtinINiv2LnZiNiq2YPZhSDZ
hNmE2YXYtNin2LHZg9ipINmI2KrYudmF2YrZhSDYrti32KfYqNmG2Kcg2LnZhNmJINin2YTZhdmH
2KrZhdmK2YYNCtio2YXZgNmA2YjYttmA2YjYuSAqKtin2YTYtNmH2KfYr9ipINin2YTYp9it2KrY
sdin2YHZitipICoq2YjYpdmB2KfYr9iq2YbYpyDYqNmF2YYg2KrZgtiq2LHYrdmI2YYg2KrZiNis
2YrZhyDYp9mE2K/YudmI2Kkg2YTZh9mFKg0KDQoq2YTZhdiy2YrYryDZhdmGINin2YTZhdi52YTZ
iNmF2KfYqiDZitmF2YPZhtmDINin2YTYqtmI2KfYtdmEINmF2Lkg2KMgLyDYs9in2LHYqSDYudio
2K8g2KfZhNis2YjYp9ivIOKAkyDZhtin2KbYqCDZhdiv2YrYsQ0K2KfZhNiq2K/YsdmK2Kgg4oCT
INin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Yp9ix2YrY
qSoNCg0KKtis2YjYp9mEIOKAkyDZiNin2KrYsyDYp9ioIDoqDQoNCiowMDIwMTA2OTk5NDM5OSAt
MDAyMDEwNjI5OTI1MTAgLSAwMDIwMTA5Njg0MTYyNioNCg0KLS0gCllvdSByZWNlaXZlZCB0aGlz
IG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMg
Imthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3Rv
cCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vu
c3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0
IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FEajFaS205bnJr
ODYlM0QwTW5XeFR6WDNnYktOWlhEcjl4RlFEOTB3UTFHJTJCWHVBY3hQUSU0MG1haWwuZ21haWwu
Y29tLgo=
--000000000000c3b5da063ba3b312
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;l=
ine-height:106%;font-size:11pt;font-family:Calibri,sans-serif"><a name=3D"_=
Hlk205143436"><b><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:1=
06%;font-family:Arial,sans-serif;color:red">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =
=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><=
/b></a><b><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%;color:=
red"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:22pt;line-height:106%;font-family:Arial,sans-serif;color:blac=
k">=D9=85=D8=B3=D8=A4=D9=88=D9=84 =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=
=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84 =D8=A7=D9=84=D9=85=D8=AD=D8=AA=D8=B1=D9=
=81</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"=
font-size:22pt;line-height:106%;color:black">Business Development Specialis=
t</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><i><span lang=3D"AR-SA" sty=
le=3D"font-size:22pt;line-height:106%;font-family:Arial,sans-serif;color:re=
d">=D8=A3=D8=AD=D8=AF=D8=AB =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA =D8=
=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=
=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=
=A3=D8=B9=D9=85=D8=A7=D9=84</span></i></b><b><span dir=3D"LTR" style=3D"fon=
t-size:22pt;line-height:106%;color:red"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:16pt;line-height:106%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D9=88=D8=A7=D8=B9=D9=8A=D8=AF
=D8=A7=D9=84=D9=85=D8=AA=D8=A7=D8=AD=D8=A9</span></b><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt;li=
ne-height:106%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span><=
/b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
106%;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA"=
 style=3D"font-size:16pt;line-height:106%;font-family:Arial,sans-serif">=D8=
=B9=D9=86
=D8=A8=D9=8F=D8=B9=D8=AF =D8=B9=D8=A8=D8=B1</span></b><span dir=3D"LTR"></s=
pan><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt;l=
ine-height:106%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> Zoom:</=
span></b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"> </spa=
n><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;font-family=
:Arial,sans-serif">=D9=85=D9=86 </span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:10=
6%;color:rgb(238,0,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>10=
 </span></b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif;color:rgb(238,0,0)">=D8=A5=D9=84=D9=89 14 =
=D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025</span></b><span dir=3D"LTR" style=3D"fo=
nt-size:16pt;line-height:106%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 8pt 0in;text-align:center;direction:rtl;unicode-bidi:embed;line-height:=
106%;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA"=
 style=3D"font-size:16pt;line-height:106%;font-family:Arial,sans-serif">=D8=
=AD=D8=B6=D9=88=D8=B1=D9=8A
=D9=81=D9=8A =D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9 =E2=80=93 =D9=85=D9=
=82=D8=B1 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1</span></b><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt;line=
-height:106%;color:black"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
>:</span></b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%;col=
or:rgb(238,0,0)"> </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-=
height:106%;font-family:Arial,sans-serif;color:rgb(238,0,0)">=D9=8A=D9=88=
=D9=85 <b>=D8=A7=D9=84=D8=A3=D8=AD=D8=AF 7 =D8=B3=D8=A8=D8=AA=D9=85=D8=A8=
=D8=B1
2025</b></span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">=
</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:106%;font-family:Arial,sans-serif">=D8=B4=D9=
=87=D8=A7=D8=AF=D8=A9
=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =E2=80=
=93 =D9=85=D9=88=D8=AB=D9=82=D8=A9 =D9=88=D8=A8=D8=A7=D8=B9=D8=AA=D9=85=D8=
=A7=D8=AF =D8=AF=D9=88=D9=84=D9=8A</span></b><span dir=3D"LTR"></span><span=
 dir=3D"LTR"></span><b><span lang=3D"AR-SA" dir=3D"LTR" style=3D"font-size:=
20pt;line-height:106%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> <=
/span></b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:106%;=
font-family:Arial,sans-serif">=D9=85=D8=B9=D8=AA=D8=B1=D9=81
=D8=A8=D9=87=D8=A7 =D9=81=D9=8A =D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=AF=
=D9=88=D9=84</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:106%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D8=AF=D8=A7=D8=B1
=D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =E2=80=93 </s=
pan></b><b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:106%">AHAD=
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:106%=
;font-family:Arial,sans-serif"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=3D"=
text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28p=
t;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><=
span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Rom=
an&quot;,serif">=D8=AA=D8=AD=D9=8A=D8=A9 =D8=B7=D9=8A=D8=A8=D8=A9 =D9=88 =
=D8=A8=D8=B9=D8=AF =D8=8C=D8=8C=D8=8C</span></p>

<p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-s=
ize:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt"><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times =
New Roman&quot;,serif">=D8=A3=D8=B7=D9=8A=D8=A8 =D8=A7=D9=84=D8=A3=D9=85=D9=
=86=D9=8A=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=8A=D8=A7=D8=AA=C2=
=A0=D8=AA=D9=87=D8=AF=D9=8A=D9=87=D8=A7
=D9=84=D9=83=D9=85=C2=A0=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=
=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=
=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span><span lang=3D"AR-JO" style=
=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,serif">=C2=A0=D8=
=A8=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF
-=C2=A0</span><span dir=3D"LTR" style=3D"font-size:18pt">AHAD</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:16pt;line-height:106%;font-family:Arial,sans-serif">=D8=B4=D9=87=
=D8=A7=D8=AF=D8=A9</span><b><span lang=3D"AR-SA" style=3D"font-family:Arial=
,sans-serif"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=3D"=
text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28p=
t;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><=
span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Rom=
an&quot;,serif;color:rgb(192,0,0)">=D9=85=D8=A7=D8=B0=D8=A7 =D8=B3=D8=AA=D8=
=AA=D8=B9=D9=84=D9=85</span><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR" style=3D"font-size:22pt;color:rgb(192,0,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>:</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.25in 0in 0in;text-align:center;direction:rtl;unicode-bidi:emb=
ed;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-s=
pacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&qu=
ot;Times New Roman&quot;,serif">=D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=
=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D8=A7=D9=84=D8=AD=
=D8=AF=D9=8A=D8=AB=D8=A9 =D9=81=D9=8A =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=
=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84</span><span dir=3D"LTR" style=3D"font-=
size:22pt"></span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.25in 0in 0in;text-align:center;direction:rtl;unicode-bidi:emb=
ed;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-s=
pacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&qu=
ot;Times New Roman&quot;,serif">=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=
=D8=A3=D8=B3=D9=88=D8=A7=D9=82
=D9=88=D8=AA=D8=AD=D8=AF=D9=8A=D8=AF =D8=A7=D9=84=D9=81=D8=B1=D8=B5 =D8=A8=
=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=
=D9=86=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-size:22pt"></span>=
</p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.25in 0in 0in;text-align:center;direction:rtl;unicode-bidi:emb=
ed;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-s=
pacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&qu=
ot;Times New Roman&quot;,serif">=D8=AA=D8=B3=D8=B1=D9=8A=D8=B9 =D8=A7=D9=84=
=D8=A7=D8=A8=D8=AA=D9=83=D8=A7=D8=B1
=D9=88=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=
=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AC=D8=A7=D8=B1=D9=8A=D8=A9</span><span d=
ir=3D"LTR" style=3D"font-size:22pt"></span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.25in 0in 0in;text-align:center;direction:rtl;unicode-bidi:emb=
ed;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-s=
pacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&qu=
ot;Times New Roman&quot;,serif">=D9=86=D9=85=D8=A7=D8=B0=D8=AC =D8=A7=D9=84=
=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=84=D8=AF=D8=B9=
=D9=85 =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1<=
/span><span dir=3D"LTR" style=3D"font-size:22pt"></span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.25in 0in 0in;text-align:center;direction:rtl;unicode-bidi:emb=
ed;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-s=
pacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&qu=
ot;Times New Roman&quot;,serif">=D8=AA=D9=82=D9=86=D9=8A=D8=A7=D8=AA
=D8=A7=D9=84=D8=A3=D8=AA=D9=85=D8=AA=D8=A9=D8=8C =D8=A7=D9=84=D8=AA=D8=AE=
=D8=B5=D9=8A=D8=B5=D8=8C =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =
=D8=A7=D9=84=D8=AA=D9=86=D8=A8=D8=A4=D9=8A</span><span dir=3D"LTR" style=3D=
"font-size:22pt"></span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"margin:0in 0.25in 0in 0in;text-align:center;direction:rtl;unicode-bidi:emb=
ed;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-s=
pacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&qu=
ot;Times New Roman&quot;,serif">=D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D9=85=D8=AB=
=D9=84</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span>:
ChatGPT =E2=80=93 Midjourney =E2=80=93 Power BI =E2=80=93 Notion AI</span><=
/p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<span dir=3D"LTR" style=3D"font-size:22pt">=C2=A0</span></p>

<p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-s=
ize:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times =
New Roman&quot;,serif;color:rgb(192,0,0)">=D8=A3=D9=87=D8=AF=D8=A7=D9=81 =
=D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;col=
or:rgb(192,0,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span>=
</p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-si=
ze:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.=
5pt">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:aut=
o;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heigh=
t:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=AA=D9=
=85=D9=83=D9=8A=D9=86
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=85=D9=86 =D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=
=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=
=D8=B9=D9=8A =D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=A3=D8=B9=
=D9=85=D8=A7=D9=84 =D9=88=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A3=
=D8=B3=D9=88=D8=A7=D9=82</span><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri L=
ight&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span=
 dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-si=
ze:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.=
5pt">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:aut=
o;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heigh=
t:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=AA=D8=
=B9=D8=B2=D9=8A=D8=B2
=D8=A7=D9=84=D8=AA=D9=81=D9=83=D9=8A=D8=B1 =D8=A7=D9=84=D8=A7=D8=A8=D8=AA=
=D9=83=D8=A7=D8=B1=D9=8A =D9=81=D9=8A =D8=AA=D8=B5=D9=85=D9=8A=D9=85 =D9=88=
=D8=AA=D9=88=D8=B3=D9=8A=D8=B9 =D9=86=D9=85=D8=A7=D8=B0=D8=AC =D8=A7=D9=84=
=D8=A3=D8=B9=D9=85=D8=A7=D9=84 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=
=D9=85 =D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=B0=
=D9=83=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&q=
uot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-si=
ze:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.=
5pt">3.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:aut=
o;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heigh=
t:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=A7=D9=
=84=D8=AA=D8=B9=D8=B1=D9=81
=D8=B9=D9=84=D9=89 =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA =D8=A7=D9=84=
=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=
=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=86=D8=A8=D8=A4 =D8=A8=D8=A7=D9=84=
=D8=B7=D9=84=D8=A8=D8=8C =D9=88=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=AA=D8=AC=
=D8=B1=D8=A8=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D8=A7=D8=A1</span><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-=
0.5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-si=
ze:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.=
5pt">4.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:aut=
o;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heigh=
t:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=A8=D9=
=86=D8=A7=D8=A1
=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=AA=
=D8=B7=D9=88=D9=8A=D8=B1 =D8=A3=D8=B9=D9=85=D8=A7=D9=84 =D9=85=D8=AF=D8=B9=
=D9=88=D9=85=D8=A9 =D8=A8=D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =
=D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=B0=D9=83=
=D9=8A</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-se=
rif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></spa=
n>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-si=
ze:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.=
5pt">5.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:aut=
o;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heigh=
t:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=AA=D8=
=A3=D9=87=D9=8A=D9=84
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=84=D9=84=D8=AA=
=D8=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D9=85=
=D8=AB=D9=84</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,s=
ans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"=
></span> ChatGPT</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><s=
pan lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roma=
n&quot;,serif;letter-spacing:-0.5pt"><span dir=3D"RTL"></span><span dir=3D"=
RTL"></span>=D8=8C </span><span dir=3D"LTR" style=3D"font-size:22pt;font-fa=
mily:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">Power BI</=
span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA"=
 style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;lett=
er-spacing:-0.5pt"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=D8=8C=
 </span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri=
 Light&quot;,sans-serif;letter-spacing:-0.5pt">Notion AI</span><span dir=3D=
"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=D8=8C =D9=88=D8=BA=D9=
=8A=D8=B1=D9=87=D8=A7</span><span dir=3D"LTR"></span><span dir=3D"LTR"></sp=
an><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Ligh=
t&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span di=
r=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span style=3D"font-si=
ze:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.=
5pt">6.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:aut=
o;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heigh=
t:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:22pt;fon=
t-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=A5=D8=
=B9=D8=AF=D8=A7=D8=AF
=D9=83=D9=88=D8=A7=D8=AF=D8=B1 =D9=82=D8=A7=D8=AF=D8=B1=D8=A9 =D8=B9=D9=84=
=D9=89 =D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=88=D8=A7=D9=84=D9=86=D9=85=D9=88 =
=D8=A7=D9=84=D8=B0=D9=83=D9=8A =D9=81=D9=8A =D9=85=D8=A4=D8=B3=D8=B3=D8=A7=
=D8=AA=D9=87=D9=85</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&q=
uot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 8pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt">=C2=A0</span></p>

<p class=3D"gmail-MsoTitle" align=3D"center" dir=3D"RTL" style=3D"text-alig=
n:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-size:28pt=
;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><s=
pan lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roma=
n&quot;,serif;color:rgb(192,0,0)">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=D8=
=B1
=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9</span><span dir=3D"L=
TR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22=
pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt">1.
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D9=85=D8=AF=D8=AE=D9=
=84 =D8=A5=D9=84=D9=89 =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=A3=D8=
=B9=D9=85=D8=A7=D9=84 =D8=A7=D9=84=D8=B0=D9=83=D9=8A</span></b><b><span dir=
=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans=
-serif;letter-spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A7=D9=84=D9=85=D9=81=D9=87=D9=88=D9=85 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=
=D8=AB =D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1
     =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84</span><span dir=3D"LTR" sty=
le=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;lette=
r-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A7=D9=84=D9=81=D8=B1=D9=82 =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=
=A8=D9=8A=D8=B9=D8=A7=D8=AA=D8=8C =D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=
=82=D8=8C
     =D9=88=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=
=A7=D9=84</span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot=
;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A7=D9=84=D8=A3=D8=AF=D9=88=D8=A7=D8=B1 =D9=88=D8=A7=D9=84=D9=85=D8=B3=
=D8=A4=D9=88=D9=84=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=B1=D8=A6=D9=8A=D8=B3=
=D9=8A=D8=A9
     =D9=84=D9=84=D9=85=D8=B3=D8=A4=D9=88=D9=84 =D8=A7=D9=84=D9=85=D8=AD=D8=
=AA=D8=B1=D9=81</span><span dir=3D"LTR" style=3D"font-size:22pt;font-family=
:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt">2.
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=A3=D8=AF=D9=88=D8=
=A7=D8=AA =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=
=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=
=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84</span></b><b><span dir=3D"LTR" styl=
e=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter=
-spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=
=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A
     =D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D9=88=D9=82 =D9=88=
=D8=A7=D9=84=D9=85=D9=86=D8=A7=D9=81=D8=B3=D9=8A=D9=86</span><span dir=3D"L=
TR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=AA=D9=88=D9=84=D9=8A=D8=AF =D8=A7=D9=
=84=D9=85=D8=AD=D8=AA=D9=88=D9=89 =D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=
=82=D9=8A</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans=
-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></=
span> (ChatGPT =E2=80=93 Copilot =E2=80=93 Notion AI)</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A3=D8=AA=D9=85=D8=AA=D8=A9 =D8=AC=D9=85=D8=B9 =D9=88=D8=AA=D8=AD=D9=
=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA
     =D9=88=D8=AA=D9=88=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=
=B1=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-size:22pt;font-family=
:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt">3.
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=AA=D8=AD=D9=84=D9=
=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=88=D8=AF=D8=
=B9=D9=85 =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=
=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quo=
t;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=B3=D9=84=D9=88=D9=83 =D8=A7=D9=84=D8=
=B9=D9=85=D9=84=D8=A7=D8=A1 =D9=88=D8=A3=D9=86=D9=85=D8=A7=D8=B7
     =D8=A7=D9=84=D8=B4=D8=B1=D8=A7=D8=A1</span><span dir=3D"LTR" style=3D"=
font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spac=
ing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A7=D8=B3=D8=AA=D8=B4=D8=B1=D8=A7=D9=81 =D8=A7=D9=84=D8=A7=D8=AA=D8=AC=
=D8=A7=D9=87=D8=A7=D8=AA =D9=88=D8=AA=D9=88=D9=82=D8=B9
     =D8=A7=D9=84=D9=81=D8=B1=D8=B5</span><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot=
;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span> Power BI </span><span lang=3D"AR-SA" style=
=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spa=
cing:-0.5pt">=D9=81=D9=8A
     =D8=B9=D8=B1=D8=B6 =D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=B0=D9=83=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-=
size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-=
0.5pt"></span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt">4.
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=AA=D8=AD=D8=B3=D9=
=8A=D9=86 =D8=AA=D8=AC=D8=B1=D8=A8=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=8A=D9=
=84 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85</span></b><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-si=
ze:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.=
5pt"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> AI</span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=AE=D8=B5=D9=8A=D8=B5 =D8=A7=D9=84=D8=B9=D8=B1=D9=88=D8=B6 =D9=
=88=D8=A7=D9=84=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=A2=D9=84=D9=8A=D9=8B=D8=
=A7</span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calib=
ri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=B1=D9=88=D8=A8=D9=88=D8=AA=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=AD=D8=A7=
=D8=AF=D8=AB=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&q=
uot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span> (Chatbots) </span><span lang=3D"AR-SA" style=3D"font-size:=
22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=
=D9=88=D8=AE=D8=AF=D9=85=D8=A9
     =D8=A7=D9=84=D8=B9=D9=85=D9=84=D8=A7=D8=A1 =D8=A7=D9=84=D8=B0=D9=83=D9=
=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot=
;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=B5=D9=85=D9=8A=D9=85 =D8=AE=D8=B1=D8=A7=D8=A6=D8=B7 =D8=B1=D8=
=AD=D9=84=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=8A=D9=84
     =D8=A8=D9=86=D8=A7=D8=A1=D9=8B =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=A8=
=D9=8A=D8=A7=D9=86=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-size:2=
2pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"=
></span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt">5.
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D8=A7=D8=B3=D8=AA=D8=
=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=88=D8=
=B3=D8=B9 =D9=88=D8=A7=D9=84=D9=86=D9=85=D9=88 =D8=A8=D8=A7=D8=B3=D8=AA=D8=
=AE=D8=AF=D8=A7=D9=85 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A</span></b><b><span d=
ir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sa=
ns-serif;letter-spacing:-0.5pt"></span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=86=D9=85=D8=A7=D8=B0=D8=AC =D8=A3=D8=
=B9=D9=85=D8=A7=D9=84 =D9=82=D8=A7=D8=A8=D9=84=D8=A9
     =D9=84=D9=84=D8=AA=D9=88=D8=B3=D8=B9</span><span dir=3D"LTR" style=3D"=
font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spac=
ing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AF=D9=85=D8=AC =D8=A3=D8=AF=D9=88=D8=A7=D8=AA</span><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;=
font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span> AI </span><span lang=3D"AR-=
SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;l=
etter-spacing:-0.5pt">=D9=81=D9=8A
     =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=
=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=
=8A</span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calib=
ri Light&quot;,sans-serif;letter-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85</span><span dir=3D"LTR"></span=
><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;font-fa=
mily:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span> Midjourney </span><span lang=3D"A=
R-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif=
;letter-spacing:-0.5pt">=D9=88</span><span dir=3D"LTR" style=3D"font-size:2=
2pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"=
>DALL=C2=B7E
     </span><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;=
Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D9=81=D9=8A =D8=AA=D8=
=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=87=D9=88=D9=8A=D8=A7=D8=AA =D8=A7=D9=
=84=D8=A8=D8=B5=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-siz=
e:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5=
pt"></span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in;tex=
t-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"font-s=
ize:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt">6.
</span></b><b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quo=
t;Times New Roman&quot;,serif;letter-spacing:-0.5pt">=D9=85=D8=B4=D8=B1=D9=
=88=D8=B9 =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=8A: =D8=AE=D8=B7=D8=A9 =D8=AA=
=D8=B7=D9=88=D9=8A=D8=B1 =D8=A3=D8=B9=D9=85=D8=A7=D9=84 =D9=85=D8=AF=D8=B9=
=D9=88=D9=85=D8=A9 =D8=A8=D9=80</span></b><span dir=3D"LTR"></span><span di=
r=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&=
quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span> AI</span></b></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82 =D8=B9=D9=85=D9=84=D9=8A: =D8=AA=D8=AD=D9=
=84=D9=8A=D9=84 =D8=B4=D8=B1=D9=83=D8=A9
     =D9=88=D8=A7=D9=82=D8=B9=D9=8A=D8=A9 =D8=A3=D9=88 =D9=81=D9=83=D8=B1=
=D8=A9 =D9=86=D8=A7=D8=B4=D8=A6=D8=A9</span><span dir=3D"LTR" style=3D"font=
-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:=
-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D8=B5=D9=85=D9=8A=D9=85 =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=
=D8=AC=D9=8A=D8=A9 =D8=AA=D8=B7=D9=88=D9=8A=D8=B1
     =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84 =D8=A8=D8=A7=D8=B3=D8=AA=D8=
=AE=D8=AF=D8=A7=D9=85 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=B0=D9=
=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A</spa=
n><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light=
&quot;,sans-serif;letter-spacing:-0.5pt"></span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 0in 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-si=
ze:22pt;font-family:&quot;Times New Roman&quot;,serif;letter-spacing:-0.5pt=
">=D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=A7=D9=84=D8=B9=D8=B1=D8=B6 =D8=A7=D9=
=84=D9=86=D9=87=D8=A7=D8=A6=D9=8A =D9=88=D8=AA=D9=82=D9=8A=D9=8A=D9=85=D9=
=87
     =D9=85=D9=86 =D9=82=D8=A8=D9=84 =D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=A8</=
span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Li=
ght&quot;,sans-serif;letter-spacing:-0.5pt"></span></li>
</ul>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 8pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt">=C2=A0</span></p>

<p class=3D"gmail-MsoTitle" align=3D"center" dir=3D"RTL" style=3D"text-alig=
n:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-size:28pt=
;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><s=
pan lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New Roma=
n&quot;,serif;color:rgb(192,0,0)">=D8=A7=D9=84=D9=81=D8=A6=D8=A9
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span><span dir=3D"L=
TR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22=
pt;color:rgb(192,0,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:<=
/span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" =
style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;lette=
r-spacing:-0.5pt">=D9=83=D8=A7=D9=81=D8=A9
=D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D9=81=D9=8A =D8=A7=D9=84=D9=82=
=D8=B7=D8=A7=D8=B9=D9=8A=D9=86 =D8=A7=D9=84=D8=B9=D8=A7=D9=85 =D9=88=D8=A7=
=D9=84=D8=AE=D8=A7=D8=B5</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" =
style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;lette=
r-spacing:-0.5pt">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1
=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84</=
span><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Li=
ght&quot;,sans-serif;letter-spacing:-0.5pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" =
style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;lette=
r-spacing:-0.5pt">=D8=B1=D9=88=D8=A7=D8=AF
=D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=
=D8=AA=D8=B4=D8=A7=D8=B1=D9=8A=D9=88=D9=86</span><span dir=3D"LTR" style=3D=
"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spa=
cing:-0.5pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" =
style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;lette=
r-spacing:-0.5pt">=D9=81=D8=B1=D9=82
=D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D9=88=D8=A7=D9=84=D9=85=D8=A8=
=D9=8A=D8=B9=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-size:22pt;fo=
nt-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"></spa=
n></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.2=
5in 0in 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" =
style=3D"font-size:22pt;font-family:&quot;Times New Roman&quot;,serif;lette=
r-spacing:-0.5pt">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=A8=D8=AA=D9=83=D8=A7=D8=B1 =D9=88=D8=A7=D9=84=D8=AA=
=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</span><span dir=3D"=
LTR" style=3D"font-size:22pt;font-family:&quot;Calibri Light&quot;,sans-ser=
if;letter-spacing:-0.5pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 8pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:22pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spaci=
ng:-0.5pt">=C2=A0</span></p>

<p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=3D"=
text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28p=
t;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><=
b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New =
Roman&quot;,serif">=D8=AC=D8=AF=D9=88=D9=84 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=
=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9 =E2=80=
=93 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025</span></b><b><span dir=3D"LTR" styl=
e=3D"font-size:22pt"></span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Times New=
 Roman&quot;,serif">=D9=85=D9=82=D8=AF=D9=85=D8=A9 =D9=85=D9=86: =D8=A7=D9=
=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=
=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=
=8A=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><s=
pan dir=3D"LTR" style=3D"font-size:22pt"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span> =E2=80=93
AHAD</span></b><span dir=3D"LTR" style=3D"font-size:22pt"></span></p>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0">
 <thead>
  <tr>
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" dir=3D"RTL" style=3D"line-height:1=
06%;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28pt;font-family:=
&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><b><span lang=
=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Times=
 New Roman&quot;,serif">=D8=A7=D9=84=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE</span></=
b><b><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></b=
></p>
   </td>
  =20
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" dir=3D"RTL" style=3D"line-height:1=
06%;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28pt;font-family:=
&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><b><span lang=
=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Times=
 New Roman&quot;,serif">=D8=A7=D8=B3=D9=85 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=
=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%"></span></b></p>
   </td>
  =20
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" dir=3D"RTL" style=3D"line-height:1=
06%;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28pt;font-family:=
&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><b><span lang=
=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Times=
 New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D8=AF=D8=A9</span></b><b><span d=
ir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></b></p>
   </td>
  =20
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpMiddle" dir=3D"RTL" style=3D"line-height:1=
06%;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28pt;font-family:=
&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><b><span lang=
=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Times=
 New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D9=83=D8=A7=D9=86</span></b><b><=
span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></b></p>
   </td>
  =20
   <td style=3D"border:1pt solid windowtext;padding:0.75pt">
   <p class=3D"gmail-MsoTitleCxSpLast" dir=3D"RTL" style=3D"line-height:106=
%;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-size:28pt;font-f=
amily:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><b><span =
lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;T=
imes New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D9=84=D8=A7=D8=AD=D8=B8=D8=
=A7=D8=AA</span></b><b><span dir=3D"LTR" style=3D"font-size:22pt;line-heigh=
t:106%"></span></b></p>
   </td>
  =20
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">10 =E2=80=93
  14 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D8=A6=D8=AF
  =D8=A7=D9=84=D8=A5=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A =D8=A7=
=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF</span><span dir=3D"LTR" style=3D"font-=
size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=B9=D8=A8=D8=B1</s=
pan><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" sty=
le=3D"font-size:22pt;line-height:106%"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span> Zoom</span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=B4=D9=87=D8=
=A7=D8=AF=D8=A9 =D9=85=D9=88=D8=AB=D9=82=D8=A9
  =D9=88=D9=82=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D8=B5=D8=AF=D9=8A=
=D9=82</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></=
span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">10 =E2=80=93
  14 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D8=A7=D8=
=AA=D9=8A=D9=83=D9=8A=D8=AA
  =D9=88=D8=A7=D9=84=D8=A8=D8=B1=D9=88=D8=AA=D9=88=D9=83=D9=88=D9=84 =D9=88=
=D8=A7=D9=84=D9=85=D8=B1=D8=A7=D8=B3=D9=85</span><span dir=3D"LTR" style=3D=
"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9 =D8=A3=D9=88</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span> Zoom</span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=B4=D9=87=D8=
=A7=D8=AF=D8=A9 =D9=85=D9=88=D8=AB=D9=82=D8=A9
  =D9=85=D9=86 =D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=D9=8A=D8=A9</span><span=
 dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">10 =E2=80=93
  19 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=AE=D8=B5=D8=
=A7=D8=A6=D9=8A
  =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=
=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=AD=D8=AA=D8=B1=D9=81</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:2=
2pt;line-height:106%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (P=
HRM)</span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">10 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106=
%;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</=
span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D8=BA=D8=
=B7=D9=8A=D8=A9 =D8=B4=D8=A7=D9=85=D9=84=D8=A9
  =D9=84=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=
=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:10=
6%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">17 =E2=80=93
  21 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D8=B1=D9=
=82=D8=A7=D8=A8=D8=A9
  =D9=88=D8=A7=D9=84=D8=AA=D8=AF=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=AF=D8=A7=
=D8=AE=D9=84=D9=8A =D9=88=D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =D8=A7=D9=84=
=D8=AD=D8=B3=D8=A7=D8=A8=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-=
size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9 =D8=A3=D9=88</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span> Zoom</span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D8=B7=D8=
=A8=D9=8A=D9=82=D8=A7=D8=AA
  =D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=88=D9=85=D9=87=D9=86=D9=8A=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">17 =E2=80=93
  21 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=F0=9F=92=BB</span>=
<span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"> </span><span l=
ang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Ti=
mes New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA=
 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AA=
=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-hei=
ght:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=B4=D9=87=D8=
=A7=D8=AF=D8=A7=D8=AA =D8=AF=D9=88=D9=84=D9=8A=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">17 =E2=80=93
  21 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=F0=9F=8F=AD</span>=
<span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"> </span><span l=
ang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Ti=
mes New Roman&quot;,serif">=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B5=D8=A7=D9=86=D8=B9</span><spa=
n dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=AD=D9=88=D9=
=83=D9=85=D8=A9
  =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A5=D9=86=
=D8=AA=D8=A7=D8=AC =D8=A7=D9=84=D8=B5=D9=86=D8=A7=D8=B9=D9=8A</span><span d=
ir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">24 =E2=80=93
  28 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=F0=9F=92=BC</span>=
<span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"> </span><span l=
ang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Ti=
mes New Roman&quot;,serif">=D9=85=D8=AD=D8=A7=D8=B3=D8=A8 =D8=A7=D9=84=D8=
=B6=D8=B1=D8=A7=D8=A6=D8=A8 =D8=A7=D9=84=D9=85=D8=AD=D8=AA=D8=B1=D9=81</spa=
n><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=AA=D8=AF=D8=
=B1=D9=8A=D8=A8 =D8=AA=D8=A3=D9=87=D9=8A=D9=84=D9=8A
  =D9=81=D9=8A =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D9=86=D8=A8 =D8=A7=D9=84=D8=
=B6=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-siz=
e:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">24 =E2=80=93
  28 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%;font-family:&quot;Segoe UI Emoji&quot;,sans-serif">=F0=9F=A7=BE</span><=
span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"> </span><span la=
ng=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Tim=
es New Roman&quot;,serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=
=D9=83=D8=A7=D8=AA=D8=A8 =D9=88=D8=A7=D9=84=D8=B3=D9=83=D8=B1=D8=AA=D8=A7=
=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D8=A9</=
span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=AF=D9=88=D8=
=B1=D8=A9 =D8=B9=D9=85=D9=84=D9=8A=D8=A9
  =D9=85=D9=83=D8=AB=D9=81=D8=A9</span><span dir=3D"LTR" style=3D"font-size=
:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">24 =E2=80=93
  28 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=E2=9C=85</span><sp=
an dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"> OSHA </span><span=
 lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;=
Times New Roman&quot;,serif">=D9=81=D9=8A =D8=A7=D9=84=D8=B5=D8=AD=D8=A9 =
=D9=88=D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D9=87=
=D9=86=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-hei=
ght:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=B4=D9=87=D8=
=A7=D8=AF=D8=A9 =D8=AF=D9=88=D9=84=D9=8A=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">24 =E2=80=93
  28 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=F0=9F=92=B0</span>=
<span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"> </span><span l=
ang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Ti=
mes New Roman&quot;,serif">=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=
=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=
=84=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D8=A7=D9=84=D9=85=D8=
=AA=D9=82=D8=AF=D9=85</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=AF=D9=
=88=D8=A7=D8=AA =D9=82=D9=8A=D8=A7=D8=B3
  =D9=88=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D9=85=D8=A7=D9=84=D9=8A =D9=85=D8=
=AA=D9=83=D8=A7=D9=85=D9=84</span><span dir=3D"LTR" style=3D"font-size:22pt=
;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">24 =E2=80=93
  28 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;f=
ont-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></spa=
n></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=F0=9F=93=8A</span>=
<span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"> </span><span l=
ang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Ti=
mes New Roman&quot;,serif">=D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B2=D9=86=D8=A7=
=D8=AA =D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7=D9=8A=D8=A9 =D9=88=D8=A7=
=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D8=A9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=
=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></=
span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">5 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%=
;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D9=8A=D8=A7=D9=85</s=
pan><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D9=85=D8=AD=D8=
=A7=D9=88=D8=B1
  =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=8A=D8=A9 =D9=85=D8=B9 =D8=AA=D9=85=D8=
=A7=D8=B1=D9=8A=D9=86 =D8=AA=D8=AD=D9=84=D9=8A=D9=84</span><span dir=3D"LTR=
" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%">31 </span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:106=
%;font-family:&quot;Times New Roman&quot;,serif">=D8=A3=D8=BA=D8=B3=D8=B7=
=D8=B3</span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></=
span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span dir=3D"LTR" style=3D"font-size:22pt;line-height:1=
06%;font-family:&quot;Segoe UI Symbol&quot;,sans-serif">=F0=9F=8E=93</span>=
<span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"> </span><span l=
ang=3D"AR-SA" style=3D"font-size:22pt;line-height:106%;font-family:&quot;Ti=
mes New Roman&quot;,serif">=D8=A8=D8=AF=D8=A1 =D8=A7=D9=84=D9=85=D8=A7=D8=
=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A7=D9=
=84=D9=85=D8=B5=D8=BA=D8=B1 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=
=8A=D8=A9
  =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=
=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A8=D8=B1=D9=86=D8=
=A7=D9=85=D8=AC =D8=B7=D9=88=D9=8A=D9=84</span><span dir=3D"LTR" style=3D"f=
ont-size:22pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;mar=
gin:0in;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;let=
ter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-heigh=
t:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9</span><span dir=3D"LTR" style=3D"font-size:22pt;line-=
height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:1pt solid windowtext;padding:0.75pt">
  <p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;line-height:106%;direction:rtl;unicode-bidi:embed;margin=
:0in 0in 4pt;font-size:28pt;font-family:&quot;Calibri Light&quot;,sans-seri=
f;letter-spacing:-0.5pt"><span lang=3D"AR-SA" style=3D"font-size:22pt;line-=
height:106%;font-family:&quot;Times New Roman&quot;,serif">=D8=A7=D9=86=D8=
=B7=D9=84=D8=A7=D9=82 =D8=A3=D9=88=D9=84
  =D9=8A=D9=88=D9=85 =D9=84=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC</span=
><span dir=3D"LTR" style=3D"font-size:22pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
</tbody></table>

<p class=3D"gmail-MsoTitle" align=3D"center" dir=3D"RTL" style=3D"text-alig=
n:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-size:28pt=
;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><s=
pan dir=3D"LTR" style=3D"font-size:22pt">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,sa=
ns-serif"><span lang=3D"AR-SA" style=3D"font-family:Arial,sans-serif">=C2=
=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,sa=
ns-serif"><b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%;fon=
t-family:&quot;Segoe UI Symbol&quot;,sans-serif">=F0=9F=93=85</span></b><b>=
<span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"> </span></b><b>=
<span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;font-family:A=
rial,sans-serif">=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A7=D8=AA
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9 =E2=80=93 =D8=B3=D8=A8=D8=AA=D9=
=85=D8=A8=D8=B1 2025</span></b></p>

<table class=3D"gmail-MsoNormalTable" border=3D"1" cellpadding=3D"0" style=
=3D"border:6pt double windowtext">
 <thead>
  <tr>
   <td style=3D"border:6pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:e=
mbed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri=
,sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:10=
6%;font-family:Arial,sans-serif">=D9=85</span></b><b><span dir=3D"LTR" styl=
e=3D"font-size:16pt;line-height:106%"></span></b></p>
   </td>
  =20
   <td style=3D"border:6pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:e=
mbed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri=
,sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:10=
6%;font-family:Arial,sans-serif">=D8=A7=D8=B3=D9=85
   =D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D9=85=D9=87=D9=
=86=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:16pt;line=
-height:106%"></span></b></p>
   </td>
  =20
   <td style=3D"border:6pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:e=
mbed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri=
,sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:10=
6%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D8=AE=D8=B5=D8=B5</span=
></b><b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span>=
</b></p>
   </td>
  =20
   <td style=3D"border:6pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:e=
mbed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri=
,sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:10=
6%;font-family:Arial,sans-serif">=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE
   =D8=A7=D9=84=D8=A7=D9=86=D8=B9=D9=82=D8=A7=D8=AF</span></b><b><span dir=
=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></b></p>
   </td>
  =20
   <td style=3D"border:6pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:e=
mbed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri=
,sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:10=
6%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=85=D9=82=D8=B1
   =D8=A7=D9=84=D9=85=D9=82=D8=AA=D8=B1=D8=AD</span></b><b><span dir=3D"LTR=
" style=3D"font-size:16pt;line-height:106%"></span></b></p>
   </td>
  =20
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">1</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
  =D8=A7=D9=84=D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=
=D8=B0=D9=8A =D8=A7=D9=84=D9=85=D8=AD=D8=AA=D8=B1=D9=81</span></b><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:16pt;line-height:106%"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> (CEO)</span></b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:=
106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9
  =D9=88=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=D9=84=
=D9=8A=D8=A7</span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:10=
6%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">1 =
=E2=80=93 5 </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height=
:106%;font-family:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1</s=
pan><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=AF=D8=A8=D9=8A</span><span dir=3D"LTR" sty=
le=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">2</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1
  =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=
=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1 =D8=A7=D9=
=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</span></b><span dir=3D"LTR" style=3D"font=
-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84
  =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</span><span dir=3D"LTR"></span><span=
 dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:1=
06%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> / AI</span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">8 =
=E2=80=93 12 </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:106%;font-family:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1</=
span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A5=D8=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">3</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
  =D8=AE=D8=A8=D9=8A=D8=B1 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=
=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=
=AA=D9=85=D8=AF</span></b><span dir=3D"LTR" style=3D"font-size:16pt;line-he=
ight:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">8 =
=E2=80=93 12 </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:106%;font-family:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1</=
span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">4</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D9=85=D8=AD=D9=84=D9=84
  =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=
=D9=8A=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF</span><=
/b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" s=
tyle=3D"font-size:16pt;line-height:106%"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span> (CORA)</span></b><span dir=3D"LTR" style=3D"font-size:16pt=
;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1</span><span dir=3D"LTR" style=
=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">15 =
=E2=80=93 19 </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:106%;font-family:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1</=
span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">5</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D9=85=D8=AF=D9=82=D9=82
  =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D8=AF=D8=A7=D8=AE=D9=84=
=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF</span></b><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:16pt;line-height:106%"><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan> (CQIA)</span></b><span dir=3D"LTR" style=3D"font-size:16pt;line-height=
:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9</span><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"f=
ont-size:16pt;line-height:106%"><span dir=3D"LTR"></span><span dir=3D"LTR">=
</span> / ISO</span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">15 =
=E2=80=93 19 </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:106%;font-family:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1</=
span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">6</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D8=AE=D8=A8=D9=8A=D8=B1
  =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A =D9=88=D8=A7=D9=84=D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=A7=D9=84=D9=85=
=D8=A7=D9=84=D9=8A =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=85</span></b><sp=
an dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D9=85=D8=A7=D9=84=D9=8A=D8=A9
  =D9=88=D8=A7=D8=B3=D8=AA=D8=AB=D9=85=D8=A7=D8=B1</span><span dir=3D"LTR" =
style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">22 =
=E2=80=93 26 </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:106%;font-family:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1</=
span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">7</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=
=D9=8A=D8=A9 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A7=D9=84=
=D8=AA=D8=AD=D9=84=D9=8A=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=B0=D9=83=D9=8A=
=D8=A9</span></b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%=
"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">HR =
Analytics</span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">22 =
=E2=80=93 26 </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:106%;font-family:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1</=
span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">8</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D8=AD=D9=82=D9=8A=D9=82
  =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=
=85=D8=AE=D8=A7=D9=84=D9=81=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=A7=D9=86=D8=
=AD=D8=B1=D8=A7=D9=81=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=
=A9</span></b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"><=
/span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=B4=D8=A4=D9=88=D9=86
  =D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=D9=8A=D8=A9 / =D8=A7=D9=84=D8=
=A7=D9=86=D8=B6=D8=A8=D8=A7=D8=B7</span><span dir=3D"LTR" style=3D"font-siz=
e:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">29 =
</span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;font-f=
amily:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 =E2=80=93 3 =
=D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1</span><span dir=3D"LTR" style=3D"font-=
size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">9</=
span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7
  =D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84=D9=8A =D9=88=D8=B1=D8=A8=D8=B7=
=D9=87 =D8=A8=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81 =D8=A7=D9=84=D8=A7=
=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9</span></b><span dir=
=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A7=D8=AA</span><span dir=3D"LTR" =
style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">15 =
=E2=80=93 19 </span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:106%;font-family:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1</=
span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p=
>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
 <tr>
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">10<=
/span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106=
%;font-family:Arial,sans-serif">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
  =D9=85=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=
=D8=A8 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=
=D8=A4=D8=B3=D8=B3=D9=8A =D8=A7=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF</span><=
/b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=AA=D8=B7=D9=88=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=
=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:16pt;line-height:10=
6%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%">29 =
</span><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;font-f=
amily:Arial,sans-serif">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 =E2=80=93 3 =
=D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1</span><span dir=3D"LTR" style=3D"font-=
size:16pt;line-height:106%"></span></p>
  </td>
 =20
  <td style=3D"border:6pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:em=
bed;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,=
sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:106%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</sp=
an><span dir=3D"LTR" style=3D"font-size:16pt;line-height:106%"></span></p>
  </td>
 =20
 </tr>
</tbody></table>

<p class=3D"gmail-MsoTitleCxSpFirst" align=3D"center" dir=3D"RTL" style=3D"=
text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28p=
t;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt"><=
span dir=3D"LTR">=C2=A0</span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span dir=3D"LTR" style=3D"font-family:&quot;Segoe UI Symbol&quot;,sans-=
serif">=E2=9C=85</span></b><b><span dir=3D"LTR"> </span></b><b><span lang=
=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;,serif">=D9=85=
=D9=84=D8=A7=D8=AD=D8=B8=D8=A7=D8=AA =D8=B9=D8=A7=D9=85=D8=A9</span></b><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<b><span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;,se=
rif">=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A7=D8=
=AA
=D8=AA=D8=B4=D9=85=D9=84 =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9=D8=AA=
=D9=85=D8=AF=D8=A9=D8=8C =D8=AD=D9=82=D9=8A=D8=A8=D8=A9 =D8=AA=D8=AF=D8=B1=
=D9=8A=D8=A8=D9=8A=D8=A9=D8=8C =D9=88=D9=88=D8=B1=D8=B4 =D8=B9=D9=85=D9=84 =
=D8=AA=D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=A9</span></b><span dir=3D"LTR"></sp=
an><span dir=3D"LTR"></span><b><span dir=3D"LTR"><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span>.</span></b><span dir=3D"LTR"></span></p>

<p class=3D"gmail-MsoTitleCxSpMiddle" align=3D"center" dir=3D"RTL" style=3D=
"text-align:center;direction:rtl;unicode-bidi:embed;margin:0in;font-size:28=
pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0.5pt">=
<span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;,serif=
">=D9=8A=D9=85=D9=83=D9=86 =D8=AA=D9=86=D9=81=D9=8A=D8=B0
=D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC <b>=D8=AD=D8=B6=D9=88=D8=B1=D9=
=8A=D9=8B=D8=A7 =D8=A3=D9=88 =D8=A3=D9=88=D9=86=D9=84=D8=A7=D9=8A=D9=86 =D8=
=B9=D8=A8=D8=B1</b></span><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
><b><span dir=3D"LTR"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> Zo=
om</span></b><span dir=3D"LTR">.</span></p>

<p class=3D"gmail-MsoTitleCxSpLast" align=3D"center" dir=3D"RTL" style=3D"t=
ext-align:center;direction:rtl;unicode-bidi:embed;margin:0in 0in 4pt;font-s=
ize:28pt;font-family:&quot;Calibri Light&quot;,sans-serif;letter-spacing:-0=
.5pt"><span lang=3D"AR-SA" style=3D"font-family:&quot;Times New Roman&quot;=
,serif">=D8=A5=D9=85=D9=83=D8=A7=D9=86=D9=8A=D8=A9 =D8=AA=D8=AE=D8=B5=D9=8A=
=D8=B5
=D8=A3=D9=8A =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=84=D8=AA=D9=83=D9=88=D9=86 =
<b>=D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A9</b></span>=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR"><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span> (In-House)</span></b><span d=
ir=3D"LTR">.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;font-family:Arial,sans-serif;color:red">=D9=84=D9=84=
=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=81=
=D8=B3=D8=A7=D8=B1</span></b><span dir=3D"LTR" style=3D"font-size:16pt;colo=
r:red"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;font-family:Arial,sans-serif">=D9=88=D8=A8=D9=87=D8=B0=
=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=8A=D8=B3=D8=B9=
=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=85 =D9=84=D9=84=D9=85=
=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=D9=8A=D9=85 =D8=AE=
=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D9=87=
=D8=AA=D9=85=D9=8A=D9=86
=D8=A8=D9=85=D9=80=D9=80=D9=88=D8=B6=D9=80=D9=88=D8=B9=C2=A0</span></b><b><=
span lang=3D"AR-EG" style=3D"font-size:16pt;font-family:Arial,sans-serif">=
=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=C2=A0</span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,sans-se=
rif">=D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=D9=86 =
=D8=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=D9=87 =
=D8=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span></b><span dir=
=3D"LTR" style=3D"font-size:16pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;font-family:Arial,sans-serif">=D9=84=D9=85=D8=B2=D9=8A=
=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =
=D9=8A=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =
=D9=85=D8=B9 =D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=
=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93 =D9=86=D8=A7=D8=A6=D8=A8
=D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =E2=80=
=93 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=
=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=
=A7=D8=B1=D9=8A=D8=A9</span></b><span lang=3D"AR-SA" style=3D"font-size:16p=
t"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;font-family:Arial,sans-serif">=D8=AC=D9=88=D8=A7=D9=84=
 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8 :</span></b><span lang=3D"=
AR-SA" style=3D"font-size:16pt"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:106%=
;font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR"></span><s=
pan dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt"><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span>00201069994399
-00201062992510 - 00201096841626</span></b><span lang=3D"AR-SA" style=3D"fo=
nt-size:16pt"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0in 0in 8pt;line-height:106%;font-size:11pt;font-family:Calibri,sa=
ns-serif"><span lang=3D"AR-SA" style=3D"font-family:Arial,sans-serif">=C2=
=A0</span></p>



<p class=3D"MsoNormal" style=3D"margin:0in 0in 8pt;line-height:106%;font-si=
ze:11pt;font-family:Calibri,sans-serif">=C2=A0</p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKm9nrk86%3D0MnWxTzX3gbKNZXDr9xFQD90wQ1G%2BXuAcxPQ%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CADj1ZKm9nrk86%3D0MnWxTzX3gbKNZXDr9xFQD90wQ1G%2BXuAcxPQ%40=
mail.gmail.com</a>.<br />

--000000000000c3b5da063ba3b312--
