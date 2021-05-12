Return-Path: <kasan-dev+bncBCGJZ5PL74JRBXPG6CCAMGQEMZ5CFWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3197B37D40C
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 21:58:22 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id v15-20020a2e7a0f0000b02900da3de76cfdsf13103425ljc.22
        for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 12:58:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620849501; cv=pass;
        d=google.com; s=arc-20160816;
        b=SZdSFOYzSulPfkOwezbgbzAivztfYNjTXQcoc6Xu5OJECeX2M3Js/PaD5d4gELInSl
         K9flbp+ba1+KdwobGmnRGocIrQDn/f7Vts8281VYy9Nk+MM22j7syd83+MOMoUgLYywr
         meemss+l+asv6GlOq9Q9Hdvs4cHFAhN+K/H8dfWlt78e872xFAAFB17FEyH39q3exX9g
         KcWz2djenLFWyh/xn/8AQvXQzq0JNcwOUotygkAGU9da9uZixyZ1kgH1evGUj2b/1izC
         rSnNePlyL3ee69CLwyxRVJxS90W8tOmxWBh8ZtCGpqaWkcild+ZyjyEeeFluaYZoS2kI
         h27Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:mime-version:user-agent:date:message-id
         :cc:to:subject:from:sender:dkim-signature;
        bh=9Yr3wFFVCiiJ1+csOSVhkQb+lus7udf4M0cJiOCBXY4=;
        b=CcnJ+CJE+2eIVNHRPPEJKrgmPSMRVXcbWpEbLJm5PxnvFU4RyFMqI6vNu7c9AJtHHI
         SrMZGhlGR+a+L0IO/3g+lgdAutNRIxlC0kGKYvE3vLcS5pUG8z4OYjYNa8NentTehY+B
         vU7BYIdTHWxhdwq+E6R1h5wQNvHYZCqQ58nmAdjKaroKzAJNYjjD93OpkIOt2Gydhhbm
         cBQrYYMuQEOten8wUox6w4cTHQbAgeU4nLpGizXdwU5wpWBgb1x7DoeeQwmbvjC8m3Rq
         gBLsj/qvrKVx5mOP+mMIIzxkFLqNCL1NFZIWA92B91hpNNAlQuHayRoC2ORvw1ygVMx2
         qyWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623 header.b=IWDJpmN7;
       spf=pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=manfred@colorfullife.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:to:cc:message-id:date:user-agent:mime-version
         :content-transfer-encoding:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9Yr3wFFVCiiJ1+csOSVhkQb+lus7udf4M0cJiOCBXY4=;
        b=Bm1O71DBazryVCOSzbdFXfRqYnbLb+x/WgRfW3PHXzbYFOPQXFn2+s43cvZl+9w//L
         IWtNJD9MnoPcu6uNlxNm3w1CZ56xj5K1bdIodtMXY0YkhiZ9e8H3FCcozcpulRQBEwfr
         YgrO8aXqAwb6q9grXawG4d9Jl9VjphCCg3mGqpTAoPs7HHh/OY56YXNARgqRU5eQZHO0
         6aMVHaOIU7evWEtq7mRKj0bEMbzyV/5BZNJM3V62UtljvIw3g1WBFdUHavLlQR5OL0RO
         rFRh0AeININe9IcxK9hRIPJ37YKW4r3joztelmU03+gb18/LYALB0oFCGATHcjq3cUhd
         APzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:to:cc:message-id:date
         :user-agent:mime-version:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9Yr3wFFVCiiJ1+csOSVhkQb+lus7udf4M0cJiOCBXY4=;
        b=e4L+ni1E1uj4LrgOkKjU7NYzs3BaEtJM0M+vzSHYy7sqUW/nXcenR3PIAGQWr7zlW5
         4FBzpXhn8NS4PFUO/AW2gbfdV1cKC2MTH2NPqaUu6dZDq01h8eIj9132M7i1I0vIJSl5
         fpR/jS0naRmiayqI+0mRXjFc07DqvIJztXnMidmsWIwpON+8HML1bNpaEkUOMPg9tv2J
         UQk4NvsKoLwiTSiAGGz5FZuJ6ivK9HW+4G+y3JQm6q/kxbuDKEtSnwUB2ivV3bpURzFL
         d+w/cqgAjrjCRV2XNa3czPEd97mbjT8SkTrY4sS1NJyNSyM1h2S6LivyOnNRxK5vWwli
         Qapg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Lw8DkDMkE2+UuPhK2hKNMKKbbq5p9vI5AAlaz/qzNeT950ByU
	nITLx3BNTfzycJ5W4/8fd1g=
X-Google-Smtp-Source: ABdhPJxgn+Ipj1E0Ue5+q/ozqBYWXXCs5Hjr3HUDPEeuKAM5rJivoS3QdR/XlLqAc8z8AddWihaMmQ==
X-Received: by 2002:ac2:58e7:: with SMTP id v7mr26671105lfo.505.1620849501756;
        Wed, 12 May 2021 12:58:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5592:: with SMTP id v18ls2292803lfg.0.gmail; Wed, 12 May
 2021 12:58:20 -0700 (PDT)
X-Received: by 2002:a05:6512:3f08:: with SMTP id y8mr26366170lfa.657.1620849500493;
        Wed, 12 May 2021 12:58:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620849500; cv=none;
        d=google.com; s=arc-20160816;
        b=iJKVln2KtN+1w4dBAnV517WbgdIuB3UqUrPpr6ImePz+ZRdtKpAg2nbtP9UgDQsgeA
         uayCpKseIpa2zVC2btrH+rDyIDlZb4uOVVRw4P8QF/YmnPOtUOSTQ/ToOIgLBgNWoftm
         +AHF17ENqEQ3uh30ELI1XcObd0B5xSoPllJ2vYT7lhjFMdfvG2hjvGRLjzBQtyn9OxYQ
         yzEf8jRN85wfDCbRHor6yB5QOB64iqmh2OpuDuw2uwkMAR2afzl7muGwy426bnt0+AAa
         RREcJa6G5xmdYslAhieMnzMzawcKMq07U8S2oUDciZUm5IGmjqwdbocbnQUamaNZFh+z
         CGdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:mime-version:user-agent
         :date:message-id:cc:to:subject:from:dkim-signature;
        bh=8raSgKhFeTJ6tUvtJ5IG4FsvccJ6867i6cPal0zUCUk=;
        b=AqL+DHyiKUmMG78wBfscoTGN+v6AXKvCH42K6A+Q/Fsg31endNqTNrVEB1//GzSkU8
         mnQ/UbwWfMlxtrq0x+9ccSUbZCxCy7f/PY/79KvRgUsYcptqWURVTfBbjK9XjackBpDu
         bDte0+VGVj0eDyKWXapmDYLID6cha9aHw/6QarVNOmaL2mqFMMpPUKni6P1xgByJGKto
         ifHiPMhSAnnAlOmKA9IGuroG+GrPkRCamhWpQovoDviAvjhx/kHqCnz0uiUVODomiMp6
         NtDu9FQSItMJ+kqfkU85q4tki+k9YzmuwnP0mAW3eIPYVUCSbUai25HmqVuwv5/WuD6u
         LwYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623 header.b=IWDJpmN7;
       spf=pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=manfred@colorfullife.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id c6si23444ljf.3.2021.05.12.12.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 May 2021 12:58:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id w3so36779827ejc.4
        for <kasan-dev@googlegroups.com>; Wed, 12 May 2021 12:58:20 -0700 (PDT)
X-Received: by 2002:a17:906:e105:: with SMTP id gj5mr40783554ejb.388.1620849499924;
        Wed, 12 May 2021 12:58:19 -0700 (PDT)
Received: from localhost.localdomain (p200300d997048700813060682b44a2a4.dip0.t-ipconnect.de. [2003:d9:9704:8700:8130:6068:2b44:a2a4])
        by smtp.googlemail.com with ESMTPSA id r17sm623181edo.48.2021.05.12.12.58.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 May 2021 12:58:19 -0700 (PDT)
From: Manfred Spraul <manfred@colorfullife.com>
Subject: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
To: kasan-dev <kasan-dev@googlegroups.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 "Paul E. McKenney" <paulmck@kernel.org>
Cc: Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
Message-ID: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
Date: Wed, 12 May 2021 21:58:18 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: base64
Content-Language: en-US
X-Original-Sender: manfred@colorfullife.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623
 header.b=IWDJpmN7;       spf=pass (google.com: domain of manfred@colorfullife.com
 designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=manfred@colorfullife.com
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

SGksDQoNCkkgZ290IGEgcmVwb3J0IGZyb20ga2NzYW4gZm9yIHNlbV9sb2NrKCkvc2VtX3VubG9j
aygpLCBidXQgSSdtIGZhaXJseSANCmNlcnRhaW4gdGhhdCB0aGlzIGlzIGEgZmFsc2UgcG9zaXRp
dmU6DQoNCj4gW8KgIDE4NC4zNDQ5NjBdIEJVRzogS0NTQU46IGRhdGEtcmFjZSBpbiBzZW1fbG9j
ayAvIHNlbV91bmxvY2sucGFydC4wDQo+IFvCoCAxODQuMzYwNDM3XQ0KPiBbwqAgMTg0LjM3NTQ0
M10gd3JpdGUgdG8gMHhmZmZmODg4MTAyMmZkNmMwIG9mIDQgYnl0ZXMgYnkgdGFzayAxMTI4IG9u
IA0KPiBjcHUgMDoNCj4gW8KgIDE4NC4zOTExOTJdwqAgc2VtX3VubG9jay5wYXJ0LjArMHhmYS8w
eDExOA0KMDAwMDAwMDAwMDAwMTM3MSA8c2VtX3VubG9jay5wYXJ0LjA+Og0Kc3RhdGljIGlubGlu
ZSB2b2lkIHNlbV91bmxvY2soc3RydWN0IHNlbV9hcnJheSAqc21hLCBpbnQgbG9ja251bSkNCiDC
oMKgwqAgMTQ2NDrCoMKgwqDCoMKgwqAgZWIgMGbCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKg
wqDCoMKgwqAgam1wwqDCoMKgIDE0NzUgDQo8c2VtX3VubG9jay5wYXJ0LjArMHgxMDQ+DQogwqDC
oMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgIHNtYS0+dXNlX2dsb2JhbF9sb2NrLS07DQogwqDC
oMKgIDE0NjY6wqDCoMKgwqDCoMKgIGU4IDAwIDAwIDAwIDAwwqDCoMKgwqDCoMKgwqDCoMKgIGNh
bGxxwqAgMTQ2YiANCjxzZW1fdW5sb2NrLnBhcnQuMCsweGZhPg0KIMKgwqDCoMKgwqDCoMKgwqDC
oMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgMTQ2NzogUl9YODZfNjRfUExUMzLCoMKgwqAg
X190c2FuX3dyaXRlNC0weDQNCiDCoMKgwqAgMTQ2YjrCoMKgwqDCoMKgwqAgNDEgZmYgY2PCoMKg
wqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgZGVjwqDCoMKgICVyMTJkDQoNCj4gW8KgIDE4NC40
MDY2OTNdwqAgZG9fc2VtdGltZWRvcCsweDY5MC8weGFiMw0KPiBbwqAgMTg0LjQyMjAzMl3CoCBf
X3g2NF9zeXNfc2Vtb3ArMHgzZS8weDQzDQo+IFvCoCAxODQuNDM3MTgwXcKgIGRvX3N5c2NhbGxf
NjQrMHg5ZS8weGI1DQo+IFvCoCAxODQuNDUyMTI1XcKgIGVudHJ5X1NZU0NBTExfNjRfYWZ0ZXJf
aHdmcmFtZSsweDQ0LzB4YWUNCj4gW8KgIDE4NC40NjcyNjldDQo+IFvCoCAxODQuNDgyMjE1XSBy
ZWFkIHRvIDB4ZmZmZjg4ODEwMjJmZDZjMCBvZiA0IGJ5dGVzIGJ5IHRhc2sgMTEyOSBvbiANCj4g
Y3B1IDI6DQo+IFvCoCAxODQuNDk3NzUwXcKgIHNlbV9sb2NrKzB4NTkvMHhlMA0KMDAwMDAwMDAw
MDAwMWJiYyA8c2VtX2xvY2s+Og0KIMKgwqDCoMKgwqDCoMKgIGlmICghc21hLT51c2VfZ2xvYmFs
X2xvY2spIHsNCiDCoMKgwqAgMWMwYTrCoMKgwqDCoMKgwqAgNGMgODkgZWbCoMKgwqDCoMKgwqDC
oMKgwqDCoMKgwqDCoMKgwqAgbW92wqDCoMKgICVyMTMsJXJkaQ0KIMKgwqDCoMKgwqDCoMKgIGlk
eCA9IGFycmF5X2luZGV4X25vc3BlYyhzb3BzLT5zZW1fbnVtLCBzbWEtPnNlbV9uc2Vtcyk7DQog
wqDCoMKgIDFjMGQ6wqDCoMKgwqDCoMKgIDBmIGI3IGRiwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKg
wqDCoMKgIG1vdnp3bCAlYngsJWVieA0KIMKgwqDCoMKgwqDCoMKgIGlmICghc21hLT51c2VfZ2xv
YmFsX2xvY2spIHsNCiDCoMKgwqAgMWMxMDrCoMKgwqDCoMKgwqAgZTggMDAgMDAgMDAgMDDCoMKg
wqDCoMKgwqDCoMKgwqAgY2FsbHHCoCAxYzE1IDxzZW1fbG9jaysweDU5Pg0KIMKgwqDCoMKgwqDC
oMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgMWMxMTogUl9YODZfNjRfUExUMzLC
oMKgwqAgX190c2FuX3JlYWQ0LTB4NA0KDQo+IFvCoCAxODQuNTEzMTIxXcKgIGRvX3NlbXRpbWVk
b3ArMHg0ZjYvMHhhYjMNCj4gW8KgIDE4NC41Mjg0MjddwqAgX194NjRfc3lzX3NlbW9wKzB4M2Uv
MHg0Mw0KPiBbwqAgMTg0LjU0MzU0MF3CoCBkb19zeXNjYWxsXzY0KzB4OWUvMHhiNQ0KPiBbwqAg
MTg0LjU1ODQ3M13CoCBlbnRyeV9TWVNDQUxMXzY0X2FmdGVyX2h3ZnJhbWUrMHg0NC8weGFlDQoN
Cg0Kc21hLT51c2VfZ2xvYmFsX2xvY2sgaXMgZXZhbHVhdGVkIGluIHNlbV9sb2NrKCkgdHdpY2U6
DQoNCj4gwqDCoMKgwqDCoMKgIC8qDQo+IMKgwqDCoMKgwqDCoMKgwqAgKiBJbml0aWFsIGNoZWNr
IGZvciB1c2VfZ2xvYmFsX2xvY2suIEp1c3QgYW4gb3B0aW1pemF0aW9uLA0KPiDCoMKgwqDCoMKg
wqDCoMKgICogbm8gbG9ja2luZywgbm8gbWVtb3J5IGJhcnJpZXIuDQo+IMKgwqDCoMKgwqDCoMKg
wqAgKi8NCj4gwqDCoMKgwqDCoMKgwqAgaWYgKCFzbWEtPnVzZV9nbG9iYWxfbG9jaykgew0KQm90
aCBzaWRlcyBvZiB0aGUgaWYtY2xhdXNlIGhhbmRsZSBwb3NzaWJsZSBkYXRhIHJhY2VzLg0KDQpJ
cw0KDQogwqDCoMKgIGlmICghZGF0YV9yYWNlKHNtYS0+dXNlX2dsb2JhbF9sb2NrKSkgew0KDQp0
aGUgY29ycmVjdCB0aGluZyB0byBzdXBwcmVzcyB0aGUgd2FybmluZz8NCg0KPiDCoMKgwqDCoMKg
wqDCoMKgwqDCoMKgwqDCoMKgwqAgLyoNCj4gwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKg
wqAgKiBJdCBhcHBlYXJzIHRoYXQgbm8gY29tcGxleCBvcGVyYXRpb24gaXMgYXJvdW5kLg0KPiDC
oMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoCAqIEFjcXVpcmUgdGhlIHBlci1zZW1hcGhv
cmUgbG9jay4NCj4gwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgKi8NCj4gwqDCoMKg
wqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgIHNwaW5fbG9jaygmc2VtLT5sb2NrKTsNCj4NCj4gwqDC
oMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgIC8qIHNlZSBTRU1fQkFSUklFUl8xIGZvciBwdXJw
b3NlL3BhaXJpbmcgKi8NCj4gwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgIGlmICghc21w
X2xvYWRfYWNxdWlyZSgmc21hLT51c2VfZ2xvYmFsX2xvY2spKSB7DQpIZXJlIEkgd291bGQgbmVl
ZCBhZHZpc2U6IFRoZSBjb2RlIG9ubHkgY2hlY2tzIGZvciB6ZXJvIC8gbm9uLXplcm8uDQoNClRo
aXMgcGFpcnMgd2l0aCBjb21wbGV4bW9kZV90cnlsZWF2ZSgpOg0KDQo+IMKgwqDCoMKgwqDCoMKg
IGlmIChzbWEtPnVzZV9nbG9iYWxfbG9jayA9PSAxKSB7DQo+DQo+IMKgwqDCoMKgwqDCoMKgwqDC
oMKgwqDCoMKgwqDCoCAvKiBTZWUgU0VNX0JBUlJJRVJfMSBmb3IgcHVycG9zZS9wYWlyaW5nICov
DQo+IMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoCBzbXBfc3RvcmVfcmVsZWFzZSgmc21h
LT51c2VfZ2xvYmFsX2xvY2ssIDApOw0KPiDCoMKgwqDCoMKgwqDCoCB9IGVsc2Ugew0KPiDCoMKg
wqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgc21hLT51c2VfZ2xvYmFsX2xvY2stLTsNCj4gwqDC
oMKgwqDCoMKgwqAgfQ0KDQpJZiB1c2VfZ2xvYmFsX2xvY2sgaXMgcmVkdWNlZCBmcm9tIGUuZy4g
NiB0byA1LCBpdCBpcyB1bmRlZmluZWQgaWYgYSANCmNvbmN1cnJlbnQgcmVhZGVyIHNlZXMgNiBv
ciA1LiBCdXQgaXQgZG9lc24ndCBtYXR0ZXIsIGFzIGJvdGggdmFsdWVzIGFyZSANCm5vbi16ZXJv
Lg0KDQpUaGUgY2hhbmdlIHRvIDAgaXMgcHJvdGVjdGVkLg0KDQpXaGF0IGlzIHRoZSByaWdodCB3
YXkgdG8gcHJldmVudCBmYWxzZSBwb3NpdGl2ZXMgZnJvbSBrY3Nhbj8NCg0KQXMgMm5kIHF1ZXN0
aW9uOg0KDQpuZXQvbmV0ZmlsdGVyL25mX2Nvbm50cmFja19jb3JlLmMsIG5mX2Nvbm50cmFja19h
bGxfbG9jaygpOg0KDQpJcyBhIGRhdGFfcmFjZSgpIG5lZWRlZCBhcm91bmQgIm5mX2Nvbm50cmFj
a19sb2Nrc19hbGwgPSB0cnVlOyI/DQoNCi0tDQoNCiDCoMKgwqAgTWFuZnJlZA0KDQotLSAKWW91
IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUg
R29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlz
IGdyb3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0
byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRp
c2N1c3Npb24gb24gdGhlIHdlYiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNn
aWQva2FzYW4tZGV2L2E5YjM2Yzc3LWRjNDItNGFiMi05NzQwLWYyN2IxOTFkZDQwMyU0MGNvbG9y
ZnVsbGlmZS5jb20uCg==
