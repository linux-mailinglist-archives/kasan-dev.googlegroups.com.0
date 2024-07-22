Return-Path: <kasan-dev+bncBCM7RVHKQ4PRBPGC7C2AMGQEIJWGLLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 20916938BB4
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 11:07:11 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1fc478ff284sf7197785ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 02:07:11 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721639229; x=1722244029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7KOJ1wyBQ2z152hHb/3ZO/fB8h7OoeUuHdu17ezKta0=;
        b=a5pqMU2IoskrdA4E+k5Zw+1KfQDNvSI6TDJT3XcjJ6t7zYNf8TBckThXOQ20wUep2/
         0TD8tM9T80OA7KnhcSko7XkNm3cuel/n0NaC6CGQSv7AzAEgxaM1F/tCc0242gy3UgOi
         0GySCzLOmXYTJX0p2YwV+Qz3rDwNNl8sIv9YTatIyw8zgMRiiajDy0jdZdG9DsdYuEoV
         DAISl2bcVKyHlsM13lBsal3zlienjSTL62wQUrx8LUmi+8ux91pYG1Kq8s4CRl9nwric
         XIBrVAofl6GT8S/snFqYDNkUHIPgzcu92QsQXzw6M5GosZzRMIata6lnLqm1qH7d+Z66
         5/6w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721639229; x=1722244029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7KOJ1wyBQ2z152hHb/3ZO/fB8h7OoeUuHdu17ezKta0=;
        b=RFG8NXOjwXm/sGUm4JqFj5/+04YGOLK6yOdirBRFFO7PXW4MmAWpowRfv2xqtkTBAo
         RlsNS6H7AbpOVE64tg5n3sFsDTnBY5E0Dl5iCQ7gfP0ICXl+2LuppQEA2Y9Rhexn+7pA
         SbuNSxBR63W8IpXcPv0XlmhaswF1JajNEf5Z9g5C05+krW44tXdtz5H2RTnU5JgdEkt4
         dR5GzaaPFvNAAdYb5AGdSWSBUlN/rKJAuyvqrJt8Hqjh/QvyNsXC9ruNBj0fez9XSWZI
         BAE91WFyEiCOgE1fNV5yDHv5dwhxVsBG/y6wCuu/kKHcVDE6vl3l96c4TvpIi4lBda40
         8OSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721639229; x=1722244029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7KOJ1wyBQ2z152hHb/3ZO/fB8h7OoeUuHdu17ezKta0=;
        b=USzaKN69SK8w0t08p1VlVk7LkjWP3iUf+nuk+35nlrK9n15DLcjTP90vHvFE+xvV/7
         VM0t5rCsPYTE301qbb/W+EHCABZeKKA2f1VejsHw0w9Zo2PwFAG/WnVnTAXytUZxEGUy
         gGX5IrutlzJziokSCY9NS/QRPBPbw8g1fVYaMsDsl/hpOMjw1VUGO3qlysiZxncxKzge
         Il/PhXTcKlWQ7EbDmFeB2LFIy/mL9oqZMoZeZfk8MBojCtZlIKyRtZDO8l6E9QKaSFeb
         DnSjse5TLFYM32CvhLNtENnDro0w2oj+5JYjCg87D/7No3eodkrT8A3ag8xXCrK6niEI
         8dYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCUjd3APQdvi9n+/7old/vF1dZF3WX+B0RyPnvBRvnCiiJInLhFBqZNOCcJsk78enDubjDgN8Kh8mVE0p/DATokYzxELzT5y2g==
X-Gm-Message-State: AOJu0YyDoktuo0Gkbb9JkbQBZ8rt7OMd0JXJyz6U07slDN2QdW2ulRZn
	3/6KHxi9pc/f7NRhN417QROK+4szRNWHgqXUUwL5SSBvMpPQ+3Ob
X-Google-Smtp-Source: AGHT+IEGX+YVlqt0YIBPzlMmAKVnSVf7U16t0LYBgDsUEkBxWxbZG2O+LfEFkcCd/0Hymy4tJh9y5Q==
X-Received: by 2002:a17:902:d50c:b0:1f9:d111:8a1e with SMTP id d9443c01a7336-1fd7a2081f5mr3540625ad.26.1721639229084;
        Mon, 22 Jul 2024 02:07:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9e4e:b0:25c:b2bf:2226 with SMTP id
 586e51a60fabf-260ec477bb5ls3687144fac.1.-pod-prod-07-us; Mon, 22 Jul 2024
 02:07:08 -0700 (PDT)
X-Received: by 2002:a05:6871:9c15:b0:258:3996:9b41 with SMTP id 586e51a60fabf-261212e8d78mr130628fac.2.1721639227552;
        Mon, 22 Jul 2024 02:07:07 -0700 (PDT)
Date: Mon, 22 Jul 2024 02:07:06 -0700 (PDT)
From: Adham Ahmad <adam.ahmad0980@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <38e1370a-7cfe-41fb-87f5-ac5698e2aae9n@googlegroups.com>
Subject: =?UTF-8?B?2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYt2YU=?=
 =?UTF-8?B?2YrZgdio2LHYs9iq2YjZhC3Ys9in2YrYqtmI?=
 =?UTF-8?B?2KrZgzIwMCjYp9is2YfYp9i2INin2YTYrdmF2YQpIDAwOTY2NTgxNzg=?=
 =?UTF-8?B?NDEwNiDZg9mE2YXZhtinICjYqtmK?=
 =?UTF-8?B?2YTZitis2LHYp9mFINin2Ygg2YjYp9iq2LM=?=
 =?UTF-8?B?2KfYqCkg2KfZhNiv2YHYuSDYudmG2K8g?=
 =?UTF-8?B?2KfZhNin2LPYqtmE2KfZhSDZhNmE2KjZiti5IA==?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_796624_579531596.1721639226780"
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

------=_Part_796624_579531596.1721639226780
Content-Type: multipart/alternative; 
	boundary="----=_Part_796625_752552060.1721639226780"

------=_Part_796625_752552060.1721639226780
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
pyDigJMg2KfYttin2YHZitipKgoKIAoKIAoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdl
IGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJrYXNhbi1k
ZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2
aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1YnNjcmli
ZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiBvbiB0aGUgd2ViIHZp
c2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvMzhlMTM3MGEt
N2NmZS00MWZiLTg3ZjUtYWM1Njk4ZTJhYWU5biU0MGdvb2dsZWdyb3Vwcy5jb20uCg==
------=_Part_796625_752552060.1721639226780
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

<p dir=3D"RTL"><span dir=3D"LTR">=C2=A0</span></p>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/38e1370a-7cfe-41fb-87f5-ac5698e2aae9n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/38e1370a-7cfe-41fb-87f5-ac5698e2aae9n%40googlegroups.com</a>.<b=
r />

------=_Part_796625_752552060.1721639226780--

------=_Part_796624_579531596.1721639226780--
