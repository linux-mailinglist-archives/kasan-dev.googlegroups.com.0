Return-Path: <kasan-dev+bncBDG4LI57R4KBB4647GKAMGQENYR47WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id DE39653F178
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jun 2022 23:15:32 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id b16-20020ab06650000000b003735ae2cec9sf7629649uaq.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jun 2022 14:15:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654550131; cv=pass;
        d=google.com; s=arc-20160816;
        b=gh1pRz0+n5ifIPpx7QeDsE5W+vG9pWTI+tiMPFAksEa4kl7zM9ZQW0gFyI5bfovUZ1
         dBT5rhtAUl3712TYdh/rMcExnpTWjQF1f+06jcd41eTPegyL5bx1azdQSAqggEFJSEgs
         dkyWuaKqC/zWgKk1YZtMNDh3LzioMxgUD++YIVjiRBq4R5pWLGlaHSG1VoOPtKzksMiY
         FrOGfAosmHo9GAQJnqnDpPinYwzPwCSfKJa0wyrLK4cl5tieGqGOdjcJT6/eGw1bg+5B
         wpqQCxVEAAAPR5MlEPgc6wu3kSBizJ+lKHyiHhrXEzshzvj3KvS0B2RiGFkljr0huucr
         pGVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=4LiViJWiKuI6n5Odne5shXsE2a8TGguazSxYO12YAiA=;
        b=vz24oPeBf16Nhz++dWxrMPr4GyqCmv/3/hX5dKWEPx3jcAmmLqldc8BXQ5LlO8oqGU
         qFO36t4ThbqVJCYQPGf1HWm2gGamKAQ6RKTqYoRsddrlogtGWdgoXTsoDaqfpo0zJwI7
         dAGP3X7EmwA6Er/GcpOtVsZUt4KdDz36Ew5BKMkT7ewShuPalJzzDzMdH9RNA6giXCc+
         hnra7kNnNoCNZRewKpNefq6twJX+Gm6UdaxGJAdaD9FFe0YZcimuWM7Hv96TQA8iRR4M
         EptmrQ80fpLh0ptFfqwSbUO6C4t5VvytrXRsIXV/4ArTQyLc9v1wJDD0pdSLxVSuj4Wc
         v7Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lwYyyfZz;
       spf=pass (google.com: domain of elizabethm356876@gmail.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elizabethm356876@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4LiViJWiKuI6n5Odne5shXsE2a8TGguazSxYO12YAiA=;
        b=XBYPw1SK4z0PpmKR+WNWq+Fhlh/6edYPDdHi5DUgyDK66lSWofAXIoJ5gy9o5vR1hQ
         Rg2mW7fnlEfV6Ge7ZPHz0thLu8iv1V97pXuBWSu1B0PhJxRbvgg6U2cwzkhMVjx/U1Pl
         FnlebqDgQ+zdpQwzWkrI93WRgo6AOfQC/vFVT7FhLu17PPBdBicbwNBPXcu1ScflxJhV
         YqujM+oiXyRaOH4DvhtDZULwblrfN8Hr884iFWltw+4vro6T3Epv5kHrtZvW/b5HAiB5
         jWQzQkM0dacYnBuKrdEbRS+A7onaiYwv3vzy6ieO1YTSO4nf1KLtnY4pvvrx/R0erwvK
         gxaw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4LiViJWiKuI6n5Odne5shXsE2a8TGguazSxYO12YAiA=;
        b=VWHCdSIv1g5n3aZDyNRS5CetTLjq63qRJ2aNe5eG/Bbd0OuZdjYyieqt9TiVA7ei/P
         EmBdDwBUSqbiA76i26hfcyP2zBy5KWQ4pvBLfA3QNlrSU4Rk4Wqg013d6TZHxbujGBPH
         83O1QuwPMCZbXbMD0ptP9ZKDq+Cx6wTSuA9A1aiRBNl1qE10M0up6UVtmzYVXm0klyLR
         5t3VHhwEjcovfF7XL4t2VYsz1HkKi2vMEmELvlLyvPSq/jR3RwDITKWaS04PPP3FkqRt
         l7IlDP8SwVJII/mFHvezSJli7gnXobcEj9kiIFg++S3E2EvMQ4dpn6Z5lahuJcXIotWw
         o45Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4LiViJWiKuI6n5Odne5shXsE2a8TGguazSxYO12YAiA=;
        b=FodZUxigTFAYvD+OqcMrK8M40ploLrz76EIwYiWK9eTUfEoUNdiLvWR8+ujCsDNM/4
         IQTOg8paoiEtYgdO0YN+g8l3dEktMsSmOytblGvT93ZEC4nQQAd3pUTuw4kPF0owO5Rb
         ObAyZe5OpBbSXcWXF8LSRxwOYiq87TutYOj2OAHyheBv+8KjruyqOAenCQj+Mb28YBsB
         HsRruJ++7hF6s1fhIULtiUg9Hg5ySBMckSGKocpMAeglFvveopNPDYW6XQ4b6GKxY0Li
         ID8dpJ9QjScluOCbBXBdZ3D0en1x41Syu1hansusSPp5Hr0yHnWvtYjgXgwuowDDXNCm
         elsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Z5u8TsNB46CpIZtxlH8iDmnCLsDEukdoiF1/lIPZ6LLk9pGMI
	23m1+f3IxreAncACbi8nEbA=
X-Google-Smtp-Source: ABdhPJweHaSQzXuoYUDQ3JS5ViiZkCjeCz+74a1rfNgcLobl+8P2au6HdxtcBCN1mSO/zYsVD87y3Q==
X-Received: by 2002:a67:ca8d:0:b0:34b:caa4:9c5d with SMTP id a13-20020a67ca8d000000b0034bcaa49c5dmr2492035vsl.23.1654550131588;
        Mon, 06 Jun 2022 14:15:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:df9a:0:b0:32c:27bd:37dd with SMTP id x26-20020a67df9a000000b0032c27bd37ddls12061vsk.10.gmail;
 Mon, 06 Jun 2022 14:15:31 -0700 (PDT)
X-Received: by 2002:a05:6102:f06:b0:337:9881:5031 with SMTP id v6-20020a0561020f0600b0033798815031mr11679264vss.67.1654550130993;
        Mon, 06 Jun 2022 14:15:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654550130; cv=none;
        d=google.com; s=arc-20160816;
        b=eR4c9KSABmdMz50J3+DwDupGXP6iN4yz+uMLXm8qUHoyqH4emafKKUcTmf1h7YaPLh
         UYfZqyBNj6t+3Q5CWZQ1W/3kiaVHF6c+ST8KsfrJL/QB6F6aKSw9pcMB0WjYYW66LfYY
         ARSx7SBwKzc5rjS52eFOj2e2aXykhCE0ZT+t5sZC19I/YabJJTEtwm7esXK+w2+m0tgH
         Tsxp7A24wBQCdWpu9YStrxhCBOwX0ntJ9DgWkkB3j3Y/KUCIDYZAhKwmddLcYMD8ZP3c
         z/HhNnNdB2CU166TgaJwm9fRJusmNBawDNSFOQgjo3ZL8NE7TRHZjiVHJzefMuvCC+OS
         DY0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=TGPEYdVyxvHO48X13ACeaEHa9NBOZ4gRnWJp4e86qrQ=;
        b=v1iBn+lyXLi82/a8uw9tyuGK1nopB6mqBDQowKCoIBcZRAyxbm0xMJdOT3xEWUjarO
         gWtDyiToKxsmr8cwWxylVicShZpVe1JPAyLmvN3qo7C+POAu74iUUQw3JAKDWNh/eClc
         kjlxhj4pqw1ncy16Vjxvg5uwj+zSqkXRtBFP8C2GDTMlrwnJ91WCDvj8tz62OXz53Awi
         2+n1tN9bNVW56uU8ojFoMhitUkEoZNwDJDOsluVy/O2hqoxgieDW0zBKP8PMWJWSevUi
         WCnMihYAsoWCfxQLqrAlVAjgXZ1MFWkIldF5AXtLJxB02siv0TBejuhpaGnO0uXdyG1w
         1p5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lwYyyfZz;
       spf=pass (google.com: domain of elizabethm356876@gmail.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elizabethm356876@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id 17-20020a056122081100b0035d09187a08si578833vkj.4.2022.06.06.14.15.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Jun 2022 14:15:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elizabethm356876@gmail.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-2ff7b90e635so156222707b3.5
        for <kasan-dev@googlegroups.com>; Mon, 06 Jun 2022 14:15:30 -0700 (PDT)
X-Received: by 2002:a81:57d6:0:b0:30c:a234:140d with SMTP id
 l205-20020a8157d6000000b0030ca234140dmr28586481ywb.269.1654550130779; Mon, 06
 Jun 2022 14:15:30 -0700 (PDT)
MIME-Version: 1.0
Reply-To: elizabethmark12022@gmail.com
From: Elizabeth Mark <elizabethmark12022@gmail.com>
Date: Tue, 7 Jun 2022 05:15:20 +0800
Message-ID: <CADtbehRT0Q5AdG7=juxqcxtWTuNOUs4BLHTd-8_bm=YO=otOSQ@mail.gmail.com>
Subject: =?UTF-8?B?0JfQtNGA0LDQstC10LnRgtC1?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000cee8f605e0cdf8cb"
X-Original-Sender: elizabethmark12022@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=lwYyyfZz;       spf=pass
 (google.com: domain of elizabethm356876@gmail.com designates
 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elizabethm356876@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000cee8f605e0cdf8cb
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

INCX0LTRgNCw0LLQtdC50YLQtQ0KICDQnNC+0LvRjywg0YHQutGK0L/QuCwg0LzQvtC20LXRgtC1
INC70Lgg0LTQsCDQvNC4INC60LDQttC10YLQtSDQv9GA0LjRh9C40L3QsNGC0LAsINC/0L7RgNCw
0LTQuCDQutC+0Y/RgtC+INC90LUg0YHRgtC1DQrQvtGC0LPQvtCy0L7RgNC40LvQuCDQvdCwINGB
0YrQvtCx0YnQtdC90LjQtdGC0L4g0LzQuA0KICDQktCw0YjQuNGP0YIg0YHQtdGA0LbQsNC90YIg
0JXQu9C40LfQsNCx0LXRgtCwINCc0LDRgNC6DQpIZWxsbw0KIFBsZWFzZSBkZWFyIGNhbiB5b3Ug
bGV0IG1lIGtub3cgdGhlIHJlYXNvbiB3aHkgeW91IGhhdmUgbm90IHJlcGx5IG15DQptZXNzYWdl
DQogWW91ciBzZXJnZWFudCBFbGlzYWJldHRhIE1hcmsNCg0KLS0gCllvdSByZWNlaXZlZCB0aGlz
IG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMg
Imthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3Rv
cCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vu
c3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRo
ZSB3ZWIgdmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9D
QUR0YmVoUlQwUTVBZEc3JTNEanV4cWN4dFdUdU5PVXM0QkxIVGQtOF9ibSUzRFlPJTNEb3RPU1El
NDBtYWlsLmdtYWlsLmNvbS4K
--000000000000cee8f605e0cdf8cb
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGRpdiBkaXI9Imx0ciI+wqDQl9C00YDQsNCy0LXQudGC0LU8YnI+wqAg0JzQvtC70Y8sINGB0LrR
itC/0LgsINC80L7QttC10YLQtSDQu9C4INC00LAg0LzQuCDQutCw0LbQtdGC0LUg0L/RgNC40YfQ
uNC90LDRgtCwLCDQv9C+0YDQsNC00Lgg0LrQvtGP0YLQviDQvdC1INGB0YLQtSDQvtGC0LPQvtCy
0L7RgNC40LvQuCDQvdCwINGB0YrQvtCx0YnQtdC90LjQtdGC0L4g0LzQuDxicj7CoCDQktCw0YjQ
uNGP0YIg0YHQtdGA0LbQsNC90YIg0JXQu9C40LfQsNCx0LXRgtCwINCc0LDRgNC6PGJyPkhlbGxv
PGJyPsKgUGxlYXNlIGRlYXIgY2FuIHlvdSBsZXQgbWUga25vdyB0aGUgcmVhc29uIHdoeSB5b3Ug
aGF2ZSBub3QgcmVwbHkgbXkgbWVzc2FnZTxicj7CoFlvdXIgc2VyZ2VhbnQgRWxpc2FiZXR0YSBN
YXJrwqDCoDxicj48L2Rpdj4NCg0KPHA+PC9wPgoKLS0gPGJyIC8+CllvdSByZWNlaXZlZCB0aGlz
IG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMg
JnF1b3Q7a2FzYW4tZGV2JnF1b3Q7IGdyb3VwLjxiciAvPgpUbyB1bnN1YnNjcmliZSBmcm9tIHRo
aXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWls
IHRvIDxhIGhyZWY9Im1haWx0bzprYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNv
bSI+a2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb208L2E+LjxiciAvPgpUbyB2
aWV3IHRoaXMgZGlzY3Vzc2lvbiBvbiB0aGUgd2ViIHZpc2l0IDxhIGhyZWY9Imh0dHBzOi8vZ3Jv
dXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FEdGJlaFJUMFE1QWRHNyUzRGp1eHFj
eHRXVHVOT1VzNEJMSFRkLThfYm0lM0RZTyUzRG90T1NRJTQwbWFpbC5nbWFpbC5jb20/dXRtX21l
ZGl1bT1lbWFpbCZ1dG1fc291cmNlPWZvb3RlciI+aHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9k
L21zZ2lkL2thc2FuLWRldi9DQUR0YmVoUlQwUTVBZEc3JTNEanV4cWN4dFdUdU5PVXM0QkxIVGQt
OF9ibSUzRFlPJTNEb3RPU1ElNDBtYWlsLmdtYWlsLmNvbTwvYT4uPGJyIC8+Cg==
--000000000000cee8f605e0cdf8cb--
