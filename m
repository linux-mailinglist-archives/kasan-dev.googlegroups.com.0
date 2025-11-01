Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBZMGTHEAMGQE6I5RCOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A9C1C283D7
	for <lists+kasan-dev@lfdr.de>; Sat, 01 Nov 2025 18:29:12 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-3779279d9e3sf4636901fa.2
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Nov 2025 10:29:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1762018151; cv=pass;
        d=google.com; s=arc-20240605;
        b=EqvK21J4Q+MQtnw5P5QWGONCpGnrXCP8V42JW1Q+Tqlzd75obJ1wMYA2Bo1YpoTbqq
         Gos2iIF4oCGNOpR+ZoRVBKwixbRrzBNXUlikzRglueuaUFZ6R7QcXV35NvPoiQRKYFXk
         5kpVCog6tIKIjEz67KEcsnQMyHKiNvecevrV6B0E6cnwXGWqUfBRK4pse9TRjNVWIi2Y
         RXzY36sGu/nSuxKjITq1IkPX0LSHPMW9Z34F6OU80MeR5WKYpL1AJTaQU8Y/TjS4e9Rd
         DwLhQjvPrILpimvGrMs0Rl3qiLC5uDuKh4vCmhb4JsBE/Tf8DOTNLoEI4LG7JUtbMOgi
         naKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=8BrowHYSyc11cbwj8PWSiduBSYd/GtknPQuLvDjbIww=;
        fh=13lIy+afPPM2cdbVJEroF7MX0XQJidrciFZIb03VIX4=;
        b=IRztQgVGrChpGJmXI9HjJMuFCONtwkjC3wuy2y9p9vLMJpRyCogVi7E8gfnsfjjB23
         7ekgOKvwtujsv2SEHJoMQ5XuECcM1qrHIFJma9U8FtNxVV+tMHHgDlQIo0QWCZsnJAiz
         P+gsnKeuLFgY3Rs/JR1PxLE+YdB7r2CWsFlyxWra9oQrYa3T7Q6fqKa/9/ptuXCLpHYU
         uHPxTmdLbrfU446N+XCthE0BfR2JzJZqZLVuBcwvTKq6qtF9V/tVhPqBkXFFnWa08iil
         GCnDKId+5DmDtdyQ5byhsq5P4ChSmuJbo6XtFlX22Uq9JQJ91cA/mvwLk5RrrokPODC9
         d87g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QNVLnYTg;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762018151; x=1762622951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8BrowHYSyc11cbwj8PWSiduBSYd/GtknPQuLvDjbIww=;
        b=UGyUZI6IvflHfL8NFz4sYOEdnIqdMnpttn61HIn1dk6LalSrMsVlSNKYjaTZNWvG4p
         530pQV47wBtyfuXzL2tA7zJ+pRAQrHi5+6Qq76zbjf1XAt5PNEcN3bsAVY6CCSdcaYr/
         RcuxzLwe9cmZQRchEWGv0y1ixjuRi5t063O0SM3GfByz/MbCzYviufvCroRFKM7G4Auy
         q7Y08Ui1GBrn1ljL9HIC1O38WwQe8gaq4X8qBoTuicdB3ABKYbY3v0ZBHDn7J65cpZO4
         RgP3yHhU35/VzEL1hONE+AaXOIi2jD4TFeIXL90z1ZBLa6JG6B+TmRhOs01cQYBwW50R
         IiVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762018151; x=1762622951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=8BrowHYSyc11cbwj8PWSiduBSYd/GtknPQuLvDjbIww=;
        b=Wz01Rbr07i8bBbTCf9ddfDHivSDkEG5MXZ3ux1DinE2XMIw5x+hkg97cyi2JLInWUU
         vEqDa7B86atfQ7HwyyfqqhXdz34hxDpMSfQ9CyUu1jMsQfHPpB5/iKyzaotbUfV3NXkK
         MhkXGaw1iJCGmIas2aCT6meTUYEdTFk6/fk1v/Wbhc2JBkUh0KNn7XrWrtpW6gCNWxNP
         5SnzWT0p3pcggVg2LU/+1TH2FGQob9E1oy69JVIuhXhLKkmtUfOapRh+WuVaHOz2JLzc
         X0tRzM+Ob2RzuatvetccvJAiIvDiUglanj3SWeY3tNWycYlOvymQVBSwS1Jy/KH8va75
         twVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762018151; x=1762622951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8BrowHYSyc11cbwj8PWSiduBSYd/GtknPQuLvDjbIww=;
        b=NVWtl8wrEoM7gjIH+US4DQaJIZJMZxThOyJrVkqPzGgaiDsSAn5XmzOakQwGsghg/S
         OQuoAe41Abs3Q5hErL2W7bXcegkWaZhH8J4GmTrfwv7ZfdrK8JL9iBTIl4ejSQyjNq7M
         Qeymqu9mfTr9XavRRTbRS9ea4j7WJSDN4PU9ZEEjo8u2CE9rMPQrJfRXcnIPdMSqOkhZ
         /AQ1wzAgoirAJnEbi98qOXPEul3M2MLPpwJ9XHUFBTLG6jqG6iUvUOQLFzqcF5LaR2rz
         bLxs960opprpcSaa/a41Ymk70Pn5rGFBXxcP3O0ab5XO5KveeJbeqiqYQojn8UZ8pYbX
         XbRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzMLKIDcgj7NR03oQgvqqA0gway9vlGZeQSKp+4gP+7kxi0MIXnpvDtCXIsL5tC3RgRwTKlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy+e+5ZGwryor6VM0w0xitTo7MJLKagQruRH5ECJ0skbdSqqZsV
	79C2aKvaBrwh975BRYP1hwPpZ442k298U94A1pEGTflfV01pzXfhz9ZU
X-Google-Smtp-Source: AGHT+IHkKBf2pD+IllJ7RUHVhxHAm9v1s2nCPmRKXXsNU7sBbWi4k3pjo6t58fNDAHTt5JTG9QAT7A==
X-Received: by 2002:ac2:4c4b:0:b0:594:1992:3bd with SMTP id 2adb3069b0e04-5941d511c09mr2557149e87.9.1762018150591;
        Sat, 01 Nov 2025 10:29:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZEfaFSd/smfDNZ7nXHf63IM0UR6qMMuyq8mbXDfSC6dg=="
Received: by 2002:a2e:9652:0:b0:338:bde:ef39 with SMTP id 38308e7fff4ca-37a10aac4b3ls5476101fa.2.-pod-prod-01-eu;
 Sat, 01 Nov 2025 10:29:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxsxf7Y+30MyTV96RrKwXRzD2d5LuHrjTDQEVTyN0VKGaqBGr26+Jnfo7zUlZd7oPOfBXBvPD94+4=@googlegroups.com
X-Received: by 2002:ac2:4c51:0:b0:592:f115:292d with SMTP id 2adb3069b0e04-5941d511e6amr2608000e87.6.1762018146809;
        Sat, 01 Nov 2025 10:29:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1762018146; cv=none;
        d=google.com; s=arc-20240605;
        b=IRy5znE0kK7LuguDc/qmPFz+E4IrPDW8OuAhQXWnWTeQEwzEdPUyjvQvWtaEK2HXLm
         dv43hI8tCcckv/5VmAmQcnGeqAOVVG6EQ9gnc8s8IHWzmv1MrvX5dnq6wGi9BC4BPE5G
         idXBlBiJAxvkBkeawg8g8kqFZW3Lmmi3lH1T0C4hFnx/mBUHmllfWgDyGAUwt872JlB3
         PrbM6oUxkJcJv1wQzIRKA+dsr/4K4HNL3MpF5n8ZSKwYtYw95PnRwZLDfZlKNaoLB1J5
         AIReBXRNNOpLmTZCNGdYRUgiZWHJWSv7H0tUd00t/FdSZXCAaBbcMZu1Vc002qqChwR6
         TgKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Wv8UprSWvBOKcvMXgH4O57hhE6c6Sw1PifJEJ1P3IPY=;
        fh=od676AGedhT/YP6Lgs0QSxFZ7SvKvatQTjLl4gZWxco=;
        b=eHCZF/Ox4v2fFi4tUUjUf57At9QUog/k2NfLwwhmZNEtbP7pgZKoviSo3kPll7pXX8
         jCiwJAp/wa3rm6+HqHYN9D955P5M4v794sCtgI2qQ71xbjSEPpc/AojEO09+ZAGRG4il
         y/NI/dOPbfHtC6VPJRnmIp/mIDxXjuchfhwQvqySChiXE1YY81uG7yZpFz+55lfmFhOq
         hPbR0D18Y6epgJhsAsNK/DMyKgWxAzHvZNxBwGMmQEIHUeJJRebzgenDhXkxECPk1aME
         LcvHlKehtWByBBXh/kO2THoqL5HsO1+qxwr9aibLc28btc3mDdIX4loox9TukXP+U7zI
         ep5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QNVLnYTg;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5941f5b9a94si163874e87.7.2025.11.01.10.29.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Nov 2025 10:29:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id 4fb4d7f45d1cf-64091c2e520so1433541a12.1
        for <kasan-dev@googlegroups.com>; Sat, 01 Nov 2025 10:29:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU0lZ1VbcgQF6bHuk0cs2JTCd39rK/NjwxhL/jNwNdsWddFSbIVRGAasEyR/M86YVATzIX3/fJjYIA=@googlegroups.com
X-Gm-Gg: ASbGncupC7iycUp4BOgHAP+HsxifmfHc76yYZ81HY0hH+vSr7s0EfJmKW4hGIYE78Lw
	jiAVvTFd2KTt/PNcqINZiCaEMzNUmyqLI5RCuAmCpgdgBvQKZuI6T1yskWctGaOsx7cX+EQkQYJ
	NWfqgzK8EtXfhKZCfqg4Hn1F77XCHSsW4zVlTjocdXgXxIGsquTAsX0NQz8Cu37qe0uGJB2yx0U
	71ZXUIPRWhATUnCnu+RzQZW6plmDPQVmTttbXJpAO6yuj3JoEr6glDlFNbnlGShnV1i
X-Received: by 2002:a17:907:d8e:b0:b47:c1d9:519e with SMTP id
 a640c23a62f3a-b707089e3a9mr695545266b.64.1762018145545; Sat, 01 Nov 2025
 10:29:05 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Sat, 1 Nov 2025 19:28:53 +0200
X-Gm-Features: AWmQ_bm4n64wI8pB1GmEOADsamb0iOGO5AWU7LXK-PT_fz4zoLMVzYTWrQhiLdw
Message-ID: <CADj1ZKm=VKhkrQLq1O707w3vehMo-y9u=9RxtQWSuiQeOOR7hQ@mail.gmail.com>
Subject: =?UTF-8?B?2KXYr9in2LHYqSDZhdio2KrZg9ix2Kkg2YTZhNmF2YbYuNmF2KfYqiDYutmK2LEg2KfZhA==?=
	=?UTF-8?B?2LHYqNit2YrYqSDigKIg2KXYr9in2LHYqSDYp9mE2YXZhti42YXYp9iqINin2YTYrtmK2LHZitipINio?=
	=?UTF-8?B?2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDZiNin2YTYqtit2YTZitmE2KfYqiDYp9mE2YU=?=
	=?UTF-8?B?2KrZgtiv2YXYqSDigKIg2KfZhNmC2YrYp9iv2Kkg2KfZhNix2YLZhdmK2Kkg2YHZiiDYp9mE2LnZhdmE?=
	=?UTF-8?B?INin2YTYrtmK2LHZijog2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDZhNi12YbYuSDYp9mE?=
	=?UTF-8?B?2KPYq9ixINin2YTZhdis2KrZhdi52Yog4oCiINin2YTYp9io2KrZg9in2LEg2YjYp9mE2KrYrdmI2YQg?=
	=?UTF-8?B?2KfZhNix2YLZhdmKINmB2Yog2KfZhNmC2LfYp9i5INi62YrYsSDYp9mE2LHYqNit2Yog2KjYp9iz2Ko=?=
	=?UTF-8?B?2K7Yr9in2YUg2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDigKIg2K3ZiNmD2YXYqSDYp9mE?=
	=?UTF-8?B?2YXZhti42YXYp9iqINin2YTYrtmK2LHZitipINmB2Yog2LnYtdixINin2YTYsNmD2KfYoSDYp9mE2Kc=?=
	=?UTF-8?B?2LXYt9mG2KfYudmKINmI2KfZhNiq2K3ZiNmEINin2YTYsdmC2YXZiiDigKIg2KfZhNiw2YPYp9ihINin?=
	=?UTF-8?B?2YTYp9i12LfZhtin2LnZiiDZiNin2YTYqtmG2YXZitipINin2YTZhdiz2KrYr9in2YXYqSDZgdmKINin?=
	=?UTF-8?B?2YTZgti32KfYuSDYutmK2LEg2KfZhNix2KjYrdmKIOKAoiDZhtit2Ygg2YXZhti42YXYqSDYrtmK2LE=?=
	=?UTF-8?B?2YrYqSDYsNmD2YrYqTog2KXYr9in2LHYqSDYsdmC2YXZitipINmI2LDZg9in2KEg2KfYtdi32YbYp9i5?=
	=?UTF-8?B?2Yog2YTYqtit2YLZitmCINin2YTYo9ir2LEg4oCiINin2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbYp9i5?=
	=?UTF-8?B?2Yog2YjYpdiv2KfYsdipINin2YTZhdmI2KfYsdivINmB2Yog2KfZhNis2YXYudmK2KfYqiDYp9mE2K4=?=
	=?UTF-8?B?2YrYsdmK2Kkg2KfZhNit2K/Zitir2Kkg4oCiINin2YTZgtmK2KfYr9ipINio2KfZhNiw2YPYp9ihINin?=
	=?UTF-8?B?2YTYp9i12LfZhtin2LnZiiDZgdmKINin2YTZgti32KfYuSDYp9mE2KU=?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000a735b906428bd139"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QNVLnYTg;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::531
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

--000000000000a735b906428bd139
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

ICAq2KXYr9in2LHYqSDZhdio2KrZg9ix2Kkg2YTZhNmF2YbYuNmF2KfYqiDYutmK2LEg2KfZhNix
2KjYrdmK2KkqDQoNCirvgrcgICoq2KXYr9in2LHYqSDYp9mE2YXZhti42YXYp9iqINin2YTYrtmK
2LHZitipINio2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDZiNin2YTYqtit2YTZitmE
2KfYqiDYp9mE2YXYqtmC2K/ZhdipKg0KDQoq74K3ICAqKtin2YTZgtmK2KfYr9ipINin2YTYsdmC
2YXZitipINmB2Yog2KfZhNi52YXZhCDYp9mE2K7Zitix2Yo6INin2YTYsNmD2KfYoSDYp9mE2KfY
tdi32YbYp9i52Yog2YTYtdmG2Lkg2KfZhNij2KvYsSDYp9mE2YXYrNiq2YXYudmKKg0KDQoq74K3
ICAqKtin2YTYp9io2KrZg9in2LEg2YjYp9mE2KrYrdmI2YQg2KfZhNix2YLZhdmKINmB2Yog2KfZ
hNmC2LfYp9i5INi62YrYsSDYp9mE2LHYqNit2Yog2KjYp9iz2KrYrtiv2KfZhSDYp9mE2LDZg9in
2KENCtin2YTYp9i12LfZhtin2LnZiioNCg0KKu+CtyAgKirYrdmI2YPZhdipINin2YTZhdmG2LjZ
hdin2Kog2KfZhNiu2YrYsdmK2Kkg2YHZiiDYudi12LEg2KfZhNiw2YPYp9ihINin2YTYp9i12LfZ
htin2LnZiiDZiNin2YTYqtit2YjZhCDYp9mE2LHZgtmF2YoqDQoNCirvgrcgICoq2KfZhNiw2YPY
p9ihINin2YTYp9i12LfZhtin2LnZiiDZiNin2YTYqtmG2YXZitipINin2YTZhdiz2KrYr9in2YXY
qSDZgdmKINin2YTZgti32KfYuSDYutmK2LEg2KfZhNix2KjYrdmKKg0KDQoq74K3ICAqKtmG2K3Z
iCDZhdmG2LjZhdipINiu2YrYsdmK2Kkg2LDZg9mK2Kk6INil2K/Yp9ix2Kkg2LHZgtmF2YrYqSDZ
iNiw2YPYp9ihINin2LXYt9mG2KfYudmKINmE2KrYrdmC2YrZgiDYp9mE2KPYq9ixKg0KDQoq74K3
ICAqKtin2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbYp9i52Yog2YjYpdiv2KfYsdipINin2YTZhdmI
2KfYsdivINmB2Yog2KfZhNis2YXYudmK2KfYqiDYp9mE2K7Zitix2YrYqSDYp9mE2K3Yr9mK2KvY
qSoNCg0KKu+CtyAgKirYp9mE2YLZitin2K/YqSDYqNin2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbY
p9i52Yog2YHZiiDYp9mE2YLYt9in2Lkg2KfZhNil2YbYs9in2YbZiiDZiNin2YTYp9is2KrZhdin
2LnZiioNCg0KDQoNCirYp9mE2LDZg9in2KEg2KfZhNin2LXYt9mG2KfYudmKINmB2Yog2KXYr9in
2LHYqSDYp9mE2YXZhti42YXYp9iqINmI2KfZhNis2YXYudmK2KfYqiDYp9mE2K7Zitix2YrYqSoN
Cg0KKNmC2YrYp9iv2Kkg4oCTINiw2YPYp9ihINin2LXYt9mG2KfYudmKIOKAkyDYqti32YjZitix
INmF2KTYs9iz2Yog4oCTINij2KvYsSDZhdis2KrZhdi52YopOg0KDQoqQXJ0aWZpY2lhbCBJbnRl
bGxpZ2VuY2UgaW4gTWFuYWdpbmcgTm9ucHJvZml0KiogJiAqKkNoYXJpdHkgT3JnYW5pemF0aW9u
cyoNCg0KW2ltYWdlOiDwn5eT77iPXSrYp9mE2YHYqtix2Kk6KiDZhdmGIDkg2KXZhNmJIDEzINmG
2YjZgdmF2KjYsSAyMDI1DQpbaW1hZ2U6IPCfk41dKtin2YTZhdmD2KfZhjoqINin2YTZgtin2YfY
sdipIOKAkyDYrNmF2YfZiNix2YrYqSDZhdi12LEg2KfZhNi52LHYqNmK2KkNCltpbWFnZTog8J+S
u10q2KPZiCDYudmGINio2Y/YudivINi52KjYsSDZhdmG2LXYqSAqKlpPT00qKiAo2YHZiiDYrdin
2YQg2KrYudiw2LEg2KfZhNit2LbZiNixKSoNCltpbWFnZTog8J+Ok10q2KfZhNis2YfYqSDYp9mE
2YXZhti42YXYqToqINin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZ
hNil2K/Yp9ix2YrYqQ0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCipbaW1hZ2U6
IPCfjq9dKirYp9mE2YXZgtiv2YXYqToqDQoNCtmK2LTZh9ivINin2YTZgti32KfYuSDYutmK2LEg
2KfZhNix2KjYrdmKINiq2K3ZiNmE2YvYpyDYsdmC2YXZitmL2Kcg2YXYqtiz2KfYsdi52YvYp9iM
INis2LnZhCDZhdmGINin2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbYp9i52YoNCtij2K/Yp9ip2Ysg
2KfYs9iq2LHYp9iq2YrYrNmK2Kkg2YTYqti52LLZitiyINin2YTZg9mB2KfYodipINmI2KfZhNi0
2YHYp9mB2YrYqSDZiNiq2K3ZgtmK2YIg2KfZhNij2KvYsSDYp9mE2YXYrNiq2YXYudmKINin2YTZ
hdiz2KrYr9in2YUuDQrZitmH2K/ZgSDZh9iw2Kcg2KfZhNio2LHZhtin2YXYrCDYpdmE2Ykg2KrZ
hdmD2YrZhiDZgtmK2KfYr9in2Kog2YjZhdmG2LPZiNio2Yog2KfZhNmF2YbYuNmF2KfYqiDYp9mE
2K7Zitix2YrYqSDZhdmGINiq2YjYuNmK2YEg2KrZgtmG2YrYp9iqDQrYp9mE2LDZg9in2KEg2KfZ
hNin2LXYt9mG2KfYudmKINmB2Yog2KfZhNil2K/Yp9ix2KnYjCDYp9mE2KrZhdmI2YrZhNiMINin
2YTYqtiu2LfZiti32Iwg2YjYp9mE2KrZiNin2LXZhCDYp9mE2YXYrNiq2YXYudmKINmE2KrYrdmC
2YrZgg0K2YbYqtin2KbYrCDYo9mD2KvYsSDZgdin2LnZhNmK2Kkg2YjYp9iz2KrYr9in2YXYqS4N
Ci0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQoqW2ltYWdlOiDwn46vXSoq2KfZhNij
2YfYr9in2YEg2KfZhNiq2K/YsdmK2KjZitipOioNCg0K2KjZhtmH2KfZitipINin2YTYqNix2YbY
p9mF2Kwg2LPZitmD2YjZhiDYp9mE2YXYtNin2LHZgyDZgtin2K/YsdmL2Kcg2LnZhNmJOg0KDQox
LiAgINmB2YfZhSDYqti32KjZitmC2KfYqiDYp9mE2LDZg9in2KEg2KfZhNin2LXYt9mG2KfYudmK
INmB2Yog2KfZhNi52YXZhCDYp9mE2K7Zitix2Yog2YjYp9mE2YLYt9in2Lkg2LrZitixINin2YTY
sdio2K3Zii4NCg0KMi4gICDYqti12YXZitmFINin2LPYqtix2KfYqtmK2KzZitin2Kog2LHZgtmF
2YrYqSDZhNiq2K3Ys9mK2YYg2KfZhNij2K/Yp9ihINmI2KfZhNit2YjZg9mF2Kkg2YHZiiDYp9mE
2KzZhdi52YrYp9iqLg0KDQozLiAgINin2LPYqtiu2K/Yp9mFINij2K/ZiNin2Kog2KfZhNiw2YPY
p9ihINin2YTYp9i12LfZhtin2LnZiiDZgdmKINil2K/Yp9ix2Kkg2KfZhNiq2KjYsdi52KfYqiDZ
iNin2YTZhdi02KfYsdmK2LkuDQoNCjQuICAg2KrYrdmE2YrZhCDYp9mE2KjZitin2YbYp9iqINmE
2K/YudmFINin2KrYrtin2LAg2KfZhNmC2LHYp9ixINmI2KrYrdmC2YrZgiDYp9mE2KPYq9ixINin
2YTYp9is2KrZhdin2LnZii4NCg0KNS4gICDYqti52LLZitiyINin2YTYtNmB2KfZgdmK2Kkg2YjY
p9mE2YXYs9in2KHZhNipINin2YTYsdmC2YXZitipINmB2Yog2KXYr9in2LHYqSDYp9mE2YXZiNin
2LHYry4NCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQoqW2ltYWdlOiDwn5GlXSoq
2KfZhNmB2KbYqSDYp9mE2YXYs9iq2YfYr9mB2Kk6Kg0KDQogICAtINin2YTZgtmK2KfYr9in2Kog
2KfZhNiq2YbZgdmK2LDZitipINmB2Yog2KfZhNis2YXYudmK2KfYqiDZiNin2YTZhdmG2LjZhdin
2Kog2KfZhNiu2YrYsdmK2KkuDQogICAtINmF2LPYpNmI2YTZiCDYp9mE2KrYrti32YrYtyDZiNin
2YTYpdiv2KfYsdipINin2YTZhdin2YTZitipINmB2Yog2KfZhNmC2LfYp9i5INi62YrYsSDYp9mE
2LHYqNit2YouDQogICAtINmF2LPYpNmI2YTZiCDYp9mE2KrYrdmI2YQg2KfZhNix2YLZhdmKINmI
2KfZhNiq2YLZhtmK2Kkg2YHZiiDYp9mE2YXYpNiz2LPYp9iqINin2YTYrtmK2LHZitipLg0KICAg
LSDYp9mE2YXYs9iq2LTYp9ix2YjZhiDZiNin2YTYudin2YXZhNmI2YYg2YHZiiDZhdis2KfZhNin
2Kog2KfZhNiq2YbZhdmK2Kkg2KfZhNmF2KzYqtmF2LnZitipINmI2KfZhNmF2LPYpNmI2YTZitip
INin2YTYp9is2KrZhdin2LnZitipLg0KDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0N
Cg0KKltpbWFnZTog8J+nrV0qKtin2YTZhdit2KfZiNixINin2YTYqtiv2LHZitio2YrYqSAoNSDY
o9mK2KfZhSk6Kg0KDQoq2KfZhNmK2YjZhSDYp9mE2KPZiNmEOiog2YXYr9iu2YQg2KXZhNmJINin
2YTYsNmD2KfYoSDYp9mE2KfYtdi32YbYp9i52Yog2YjYqti32KjZitmC2KfYqtmHINmB2Yog2KfZ
hNi52YXZhCDYp9mE2K7Zitix2YouDQoq2KfZhNmK2YjZhSDYp9mE2KvYp9mG2Yo6KiDYp9mE2KXY
r9in2LHYqSDYp9mE2LDZg9mK2Kkg2YTZhNmF2LTYp9ix2YrYuSDYutmK2LEg2KfZhNix2KjYrdmK
2Kkg2KjYp9iz2KrYrtiv2KfZhSDYo9iv2YjYp9iqINin2YTYsNmD2KfYoQ0K2KfZhNin2LXYt9mG
2KfYudmKLg0KKtin2YTZitmI2YUg2KfZhNir2KfZhNirOiog2KrYrdmE2YrZhCDYp9mE2KjZitin
2YbYp9iqINmI2KfZhNiq2YbYqNikINio2KfYrdiq2YrYp9is2KfYqiDYp9mE2YXYrNiq2YXYuSDZ
iNio2LHYp9mF2Kwg2KfZhNiv2LnZhS4NCirYp9mE2YrZiNmFINin2YTYsdin2KjYuToqINmG2LjZ
hSDYp9mE2LTZgdin2YHZitipINmI2KfZhNit2YjZg9mF2Kkg2KfZhNix2YLZhdmK2Kkg2YHZiiDY
pdiv2KfYsdipINin2YTYrNmF2LnZitin2KouDQoq2KfZhNmK2YjZhSDYp9mE2K7Yp9mF2LM6KiDY
pdi52K/Yp9ivINiu2LfYqSDYp9iz2KrYsdin2KrZitis2YrYqSDYsdmC2YXZitipINmE2YTZhdmG
2LjZhdipINin2YTYrtmK2LHZitipIOKAkyDYr9ix2KfYs9ipINit2KfZhNipLg0KLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCltpbWFnZTog8J+Tnl0q2YTZhNiq2LPYrNmK2YQg2YjY
p9mE2KfYs9iq2YHYs9in2LE6Kg0K2KMvINiz2KfYsdipINi52KjYryDYp9mE2KzZiNin2K8g4oCT
INmF2K/ZitixINin2YTYqtiv2LHZitioDQpbaW1hZ2U6IPCfk7JdMDAyMDEwNjk5OTQzOTkg4oCT
IDAwMjAxMDYyOTkyNTEwIOKAkyAwMDIwMTA5Njg0MTYyNg0KDQotLSAKWW91IHJlY2VpdmVkIHRo
aXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3Vw
cyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBz
dG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYr
dW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gdmlz
aXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQURqMVpLbSUz
RFZLaGtyUUxxMU83MDd3M3ZlaE1vLXk5dSUzRDlSeHRRV1N1aVFlT09SN2hRJTQwbWFpbC5nbWFp
bC5jb20uCg==
--000000000000a735b906428bd139
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;m=
argin:0in 0in 8pt;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;=
"><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New =
Roman&quot;,&quot;serif&quot;">=C2=A0=C2=A0</span></b><b><span lang=3D"AR-S=
A" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;se=
rif&quot;">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D9=85=D8=A8=D8=AA=D9=83=D8=B1=D8=
=A9
=D9=84=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=AA =D8=BA=D9=8A=D8=B1 =D8=A7=
=D9=84=D8=B1=D8=A8=D8=AD=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=
=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot=
;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=EF=82=B7=C2=A0 </span></b><b><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=
=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=
=AA
=D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=8A=D8=A9 =D8=A8=D8=A7=D9=84=D8=B0=D9=83=
=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=88=
=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D9=85=
=D8=AA=D9=82=D8=AF=D9=85=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font=
-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></spa=
n></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=EF=82=B7=C2=A0 </span></b><b><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=
=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=
=8A=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=8A: =D8=A7=
=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=
=D8=B9=D9=8A =D9=84=D8=B5=D9=86=D8=B9 =D8=A7=D9=84=D8=A3=D8=AB=D8=B1 =D8=A7=
=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A</span></b><b><span dir=3D"LTR" s=
tyle=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&=
quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=EF=82=B7=C2=A0 </span></b><b><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=
=A7=D9=84=D8=A7=D8=A8=D8=AA=D9=83=D8=A7=D8=B1 =D9=88=D8=A7=D9=84=D8=AA=D8=
=AD=D9=88=D9=84
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=82=D8=B7=
=D8=A7=D8=B9 =D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D8=B1=D8=A8=D8=AD=D9=8A =D8=A8=
=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=
=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A</span></b><b>=
<span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman=
&quot;,&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=EF=82=B7=C2=A0 </span></b><b><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=
=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=
=AA
=D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=8A=D8=A9 =D9=81=D9=8A =D8=B9=D8=B5=D8=B1 =
=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=
=D8=A7=D8=B9=D9=8A =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=
=D8=B1=D9=82=D9=85=D9=8A</span></b><b><span dir=3D"LTR" style=3D"font-size:=
18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></b>=
</p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=EF=82=B7=C2=A0 </span></b><b><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=
=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=
=A7=D8=B9=D9=8A
=D9=88=D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=
=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D9=82=D8=B7=D8=A7=
=D8=B9 =D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D8=B1=D8=A8=D8=AD=D9=8A</span></b><b=
><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roma=
n&quot;,&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=EF=82=B7=C2=A0 </span></b><b><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D9=
=86=D8=AD=D9=88 =D9=85=D9=86=D8=B8=D9=85=D8=A9 =D8=AE=D9=8A=D8=B1=D9=8A=D8=
=A9
=D8=B0=D9=83=D9=8A=D8=A9: =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=B1=D9=82=D9=85=
=D9=8A=D8=A9 =D9=88=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D8=B5=D8=B7=D9=86=D8=A7=
=D8=B9=D9=8A =D9=84=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=A3=D8=AB=
=D8=B1</span></b><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&=
quot;Times New Roman&quot;,&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=EF=82=B7=C2=A0 </span></b><b><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=
=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=
=A7=D8=B9=D9=8A
=D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=
=D8=AF =D9=81=D9=8A =D8=A7=D9=84=D8=AC=D9=85=D8=B9=D9=8A=D8=A7=D8=AA =D8=A7=
=D9=84=D8=AE=D9=8A=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=
=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&=
quot;Times New Roman&quot;,&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=EF=82=B7=C2=A0 </span></b><b><span lang=3D"AR-SA" style=3D"fo=
nt-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=
=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A8=D8=A7=D9=84=D8=B0=D9=83=D8=
=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=A7=
=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=A7=D9=84=D8=A5=D9=86=D8=B3=D8=A7=D9=86=
=D9=8A =D9=88=D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A</span><=
/b><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New=
 Roman&quot;,&quot;serif&quot;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=C2=A0</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=A5=
=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=AA =
=D9=88=D8=A7=D9=84=D8=AC=D9=85=D8=B9=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=
=D9=8A=D8=B1=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:=
18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></b>=
</p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span=
 dir=3D"RTL"></span><span dir=3D"RTL"></span>(=D9=82=D9=8A=D8=A7=D8=AF=D8=
=A9 =E2=80=93 =D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=
=D9=8A =E2=80=93 =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=85=D8=A4=D8=B3=D8=B3=D9=
=8A =E2=80=93 =D8=A3=D8=AB=D8=B1
=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A):</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">Artificial Intelligence in Managing
Nonprofit</span></b><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><s=
pan lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roma=
n&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></spa=
n>
&amp; </span></b><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&=
quot;Times New Roman&quot;,&quot;serif&quot;">Charity Organizations</span><=
/b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New=
 Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;ser=
if&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=97=93=EF=B8=8F"></s=
pan><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9:</=
span></b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Tim=
es New Roman&quot;,&quot;serif&quot;"> =D9=85=D9=86 9 =D8=A5=D9=84=D9=89 13=
 =D9=86=D9=88=D9=81=D9=85=D8=A8=D8=B1 2025<br>
</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times Ne=
w Roman&quot;,&quot;serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=
=9F=93=8D"></span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=85=D9=83=
=D8=A7=D9=86:</span></b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-f=
amily:&quot;Times New Roman&quot;,&quot;serif&quot;"> =D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =
=D9=85=D8=B5=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9<br>
</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times Ne=
w Roman&quot;,&quot;serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=
=9F=92=BB"></span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A3=D9=88 =D8=B9=D9=86=
 =D8=A8=D9=8F=D8=B9=D8=AF =D8=B9=D8=A8=D8=B1 =D9=85=D9=86=D8=B5=D8=A9 </spa=
n></b><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times =
New Roman&quot;,&quot;serif&quot;">ZOOM</span></b><span dir=3D"RTL"></span>=
<span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;fo=
nt-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL">=
</span><span dir=3D"RTL"></span>
(=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =D8=AA=D8=B9=D8=B0=D8=B1 =D8=A7=D9=84=D8=
=AD=D8=B6=D9=88=D8=B1)</span></b><span lang=3D"AR-SA" style=3D"font-size:18=
pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times Ne=
w Roman&quot;,&quot;serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=
=9F=8E=93"></span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D8=AC=D9=87=
=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A9:</span></b><span lang=3D"=
AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"> =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=
=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=
=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=8E=AF"></span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=85=D9=82=D8=AF=D9=85=D8=
=A9:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=D9=8A=D8=B4=D9=87=D8=AF =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =
=D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D8=B1=D8=A8=D8=AD=D9=8A =D8=AA=D8=AD=D9=88=
=D9=84=D9=8B=D8=A7 =D8=B1=D9=82=D9=85=D9=8A=D9=8B=D8=A7
=D9=85=D8=AA=D8=B3=D8=A7=D8=B1=D8=B9=D9=8B=D8=A7=D8=8C =D8=AC=D8=B9=D9=84 =
=D9=85=D9=86 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=
=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D8=A3=D8=AF=D8=A7=D8=A9=D9=8B =D8=A7=D8=B3=
=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9 =D9=84=D8=AA=D8=B9=D8=B2=
=D9=8A=D8=B2 =D8=A7=D9=84=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D9=88=D8=A7=D9=84=
=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9
=D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=A3=D8=AB=D8=B1 =D8=A7=
=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A =D8=A7=D9=84=D9=85=D8=B3=D8=AA=
=D8=AF=D8=A7=D9=85.<br>
=D9=8A=D9=87=D8=AF=D9=81 =D9=87=D8=B0=D8=A7 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=
=D8=A7=D9=85=D8=AC =D8=A5=D9=84=D9=89 =D8=AA=D9=85=D9=83=D9=8A=D9=86 =D9=82=
=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D9=88=D9=85=D9=86=D8=B3=D9=88=D8=A8=D9=8A =
=D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D9=8A=
=D8=B1=D9=8A=D8=A9 =D9=85=D9=86 =D8=AA=D9=88=D8=B8=D9=8A=D9=81 =D8=AA=D9=82=
=D9=86=D9=8A=D8=A7=D8=AA
=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=
=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9=
=D8=8C =D8=A7=D9=84=D8=AA=D9=85=D9=88=D9=8A=D9=84=D8=8C =D8=A7=D9=84=D8=AA=
=D8=AE=D8=B7=D9=8A=D8=B7=D8=8C =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=
=D9=84 =D8=A7=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A =D9=84=D8=AA=D8=AD=
=D9=82=D9=8A=D9=82 =D9=86=D8=AA=D8=A7=D8=A6=D8=AC
=D8=A3=D9=83=D8=AB=D8=B1 =D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=
=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9.</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=8E=AF"></span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=
=81 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=D8=A8=D9=86=D9=87=D8=A7=D9=8A=D8=A9 =D8=A7=D9=84=D8=A8=D8=B1=
=D9=86=D8=A7=D9=85=D8=AC =D8=B3=D9=8A=D9=83=D9=88=D9=86 =D8=A7=D9=84=D9=85=
=D8=B4=D8=A7=D8=B1=D9=83 =D9=82=D8=A7=D8=AF=D8=B1=D9=8B=D8=A7
=D8=B9=D9=84=D9=89:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D9=81=
=D9=87=D9=85 =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA =D8=A7=D9=84=D8=B0=
=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =
=D9=81=D9=8A =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=
=D9=8A =D9=88=D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=BA=D9=8A=D8=B1
=D8=A7=D9=84=D8=B1=D8=A8=D8=AD=D9=8A.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=AA=
=D8=B5=D9=85=D9=8A=D9=85 =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=
=D9=8A=D8=A7=D8=AA =D8=B1=D9=82=D9=85=D9=8A=D8=A9 =D9=84=D8=AA=D8=AD=D8=B3=
=D9=8A=D9=86 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=A7=D9=84=D8=AD=
=D9=88=D9=83=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AC=D9=85=D8=B9=D9=8A=
=D8=A7=D8=AA.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">3.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=
=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=
=D8=B9=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AA=
=D8=A8=D8=B1=D8=B9=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=
=D9=8A=D8=B9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">4.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=AA=
=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =
=D9=84=D8=AF=D8=B9=D9=85 =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=
=D8=B1=D8=A7=D8=B1 =D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=A3=
=D8=AB=D8=B1 =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A.</span>=
</p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">5.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=AA=
=D8=B9=D8=B2=D9=8A=D8=B2 =D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =
=D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=A1=D9=84=D8=A9 =D8=A7=D9=84=D8=B1=
=D9=82=D9=85=D9=8A=D8=A9 =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF.</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=91=A5"></span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=81=D8=A6=D8=A9 =D8=A7=D9=
=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA
     =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D8=A9 =D9=81=D9=8A =
=D8=A7=D9=84=D8=AC=D9=85=D8=B9=D9=8A=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=85=
=D9=86=D8=B8=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=8A=D8=A9.<=
/span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
     =D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D9=88=D8=A7=D9=84=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=81=D9=
=8A =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D8=
=B1=D8=A8=D8=AD=D9=8A.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
     =D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=
=8A =D9=88=D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=
=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=
=8A=D8=A9.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D9=88=D9=86
     =D9=88=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=D9=88=D9=86 =D9=81=D9=8A =
=D9=85=D8=AC=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=
=D8=A9 =D8=A7=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A=D8=A9 =D9=88=D8=A7=
=D9=84=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AC=
=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=D8=A9.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=A7=AD"></span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=D8=
=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9 (5 =D8=A3=D9=8A=
=D8=A7=D9=85):</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85
=D8=A7=D9=84=D8=A3=D9=88=D9=84:</span></b><span lang=3D"AR-SA" style=3D"fon=
t-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"> =D9=
=85=D8=AF=D8=AE=D9=84 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=
=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=88=D8=AA=D8=
=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA=D9=87
=D9=81=D9=8A =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=
=D9=8A.<br>
<b>=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A:</b>=
 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B0=D9=83=D9=8A=
=D8=A9 =D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9 =D8=BA=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=B1=D8=A8=D8=AD=D9=8A=D8=A9 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=
=D8=AF=D8=A7=D9=85 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=B0=D9=83=
=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A.<br>
<b>=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=84=D8=AB:</b>=
 =D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=
=D8=AA =D9=88=D8=A7=D9=84=D8=AA=D9=86=D8=A8=D8=A4 =D8=A8=D8=A7=D8=AD=D8=AA=
=D9=8A=D8=A7=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9 =
=D9=88=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=AF=D8=B9=D9=85.<br>
<b>=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=B1=D8=A7=D8=A8=D8=B9:</b>=
 =D9=86=D8=B8=D9=85 =D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =D9=88=
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=D9=85=
=D9=8A=D8=A9 =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=
=D9=85=D8=B9=D9=8A=D8=A7=D8=AA.<br>
<b>=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AE=D8=A7=D9=85=D8=B3:</b>=
 =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=AE=D8=B7=D8=A9 =D8=A7=D8=B3=D8=AA=D8=B1=
=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9 =D8=B1=D9=82=D9=85=D9=8A=D8=A9 =D9=84=
=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A9 =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=8A=
=D8=A9 =E2=80=93 =D8=AF=D8=B1=D8=A7=D8=B3=D8=A9 =D8=AD=D8=A7=D9=84=D8=A9.</=
span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;ser=
if&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=93=9E"></span><b><s=
pan lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roma=
n&quot;,&quot;serif&quot;">=D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=
=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1:</span></b><span =
lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&qu=
ot;,&quot;serif&quot;"><br>
=D8=A3/ =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=
=88=D8=A7=D8=AF =E2=80=93 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=
=D8=B1=D9=8A=D8=A8<br>
</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times Ne=
w Roman&quot;,&quot;serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=
=9F=93=B2"></span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>002=
01069994399
=E2=80=93 00201062992510 =E2=80=93 00201096841626</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:16pt;line-height:107%">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKm%3DVKhkrQLq1O707w3vehMo-y9u%3D9RxtQWSuiQeOOR7hQ%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CADj1ZKm%3DVKhkrQLq1O707w3vehMo-y9u%3D9RxtQWSuiQeOOR7hQ%40=
mail.gmail.com</a>.<br />

--000000000000a735b906428bd139--
