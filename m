Return-Path: <kasan-dev+bncBDN6TT4BRQPRBD5IV6CAMGQETDXBWFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-f189.google.com (mail-pf1-f189.google.com [209.85.210.189])
	by mail.lfdr.de (Postfix) with ESMTPS id BDC4F36F833
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 11:55:28 +0200 (CEST)
Received: by mail-pf1-f189.google.com with SMTP id s23-20020a056a001c57b029026369efe398sf19607285pfw.2
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 02:55:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619776527; cv=pass;
        d=google.com; s=arc-20160816;
        b=QuBKMyK5ItNFuAJtLl8GAV3U+G9qbcO+e0apWrBIVrsi2gMJQ/53YbssdwyJVfTdGL
         RrlmllIYkqdDGlfuSpIk/xevs3pfUlWBTDngfC4CkN0wP6U7pYM6cBDlXZbjvFjtvmtD
         jAWe5ZS1hLJL2IjXR4TSQW9ZfUEoo2plDJhU5wQhJEB7luDKRye/BB2bicIS0IyeSpLt
         wNHUjEZeEHhCwEKbWcDQbD5sbbB9xuFhNlUyqxfu5wBj1EnyrXuiGHahHfjKbZT9mrRk
         eMZGz3dbu9L8icGQB4Imj+CUGdnhilBv/9Ks6Oj7gFUY9W9Kybdt07fi+U50XQOx86y7
         Pkog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type
         :content-transfer-encoding:date:message-id:cc:to:from:sender
         :reply-to:subject:mime-version:dkim-filter;
        bh=5+C0/fxpaActyvrMcCjhU7iU/5TgQ6eV5Jg0p+JuwiU=;
        b=YvGFVCnhXfpJ+ZLWJHOxhuEQefoAROzh8i5CrFF0M9/mgu/N4BmpkvKGj1JnEwjgnv
         GpNOoQu/Zd6PnBK+WyXKmMzV58vT9A2K/EI2gZ3jbntHC6KMhazJyej4YOcF/GvEeADE
         OMpp5PZ02vLFJVtc+7kaeF0HZ/6IKXqyaEcT35gRgx307ZMfTOFH6HUGsGouQqpQpB21
         2nFU1+BEkExdZ7F/aBA5nBRzkY7pyFmB+3CQ8FYwmXY/3zLeZ6EgEZGr8G/lumS35eBe
         NXQl20kWwPbJZG+rEAp3GaP0EvHOBOV5Ev/LKW31f7p3fQHRUdnhs6Fy3rSYQACChqBM
         u9sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=hQYTF5vH;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:dkim-filter:mime-version:subject:reply-to:sender
         :from:to:cc:message-id:date:content-transfer-encoding:cms-type
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5+C0/fxpaActyvrMcCjhU7iU/5TgQ6eV5Jg0p+JuwiU=;
        b=ix1culTM+PLSDXjS1h3yqFYApZnvPD3JGjNDnaw2dAMpsM/miH5xOrClspPAjulZWE
         TfKizZtiGTMR0uThsZ9De9r+WTAIPn8Ze8/tmEdW49Utt8PaPy3Sv+3J/S7UO2ZtKbvm
         bYSdhwlBf3Jb3ZFLm/+wA37A51Fzwz3vY8QQ2TWjL3bcUOB4j4X8p16Rb1Ds/z3irOnY
         pBAIXGlXoCRpVUcYOZPoyKvVmJ1sa/5kobonJc+zeCGSOw+NWtZXKoHJoKKGur5zD5FR
         JOJNx/nf0Y4IkSqNt4p7iDiirfQWV0nApT5xuX9ztvZjDuXOwxtm/HsKJpj6MLdQLhKZ
         9daA==
X-Gm-Message-State: AOAM530TI7x/C1ahdKiBGzDKy3Z5AZJGFOPn3zeLkpwQcZwTKqfTPrFF
	NdZBk6+vaqA0xjqnQxvaemA=
X-Google-Smtp-Source: ABdhPJwQWwnKio6YxZGGJWTQcfhsFgfVbLBt640bC7GVvtNmGHUV51BReJt+7uPhlsOGnAYp9gmFcw==
X-Received: by 2002:a62:ea05:0:b029:27a:6fc6:af83 with SMTP id t5-20020a62ea050000b029027a6fc6af83mr4134504pfh.24.1619776527268;
        Fri, 30 Apr 2021 02:55:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ea10:: with SMTP id t16ls472725pfh.9.gmail; Fri, 30 Apr
 2021 02:55:26 -0700 (PDT)
X-Received: by 2002:a62:8c45:0:b029:272:e091:cda5 with SMTP id m66-20020a628c450000b0290272e091cda5mr4163777pfd.59.1619776526786;
        Fri, 30 Apr 2021 02:55:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619776526; cv=none;
        d=google.com; s=arc-20160816;
        b=b2D0aOPywnFXzqzXe4HL1T+rtO5p0HAigY5Zw2roaRI4zWHgKKNHMso7PddA+ea95x
         o7unEEZz/Re7JqjUF9Dv5o1m7D97ZxOI/V2l7v7SUwxgxekU9RSWpOy0VIQSu9EdgNx7
         0M6ar/+Ex5dVdH3Gz39rWLPQNFCSq0+UAPWEp7IM9HAyFh75TM1JYdwUzyrDLO9Gd1mM
         AUtofL2KEf8pEsv6mmqyspHFKJ4cXKQxTIIgm1gFq3DgV7cIugrG2GgRjdEoyt9ERrxL
         V1MdWSmnvWIbmdRpL/SYsmoC4qwc0MeQq6rapkgcC1VEp3u9yq0WKH6hUe0vPheaRMOS
         dtyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:content-transfer-encoding:date:message-id:cc:to
         :from:sender:reply-to:subject:mime-version:dkim-signature
         :dkim-filter;
        bh=gmKvS5TifIGVW/3+aVfJX/p//lGXqtywtz6SAyT62nk=;
        b=da7hAbXAH8QLtRx++FIfZQLK7vCkKL0g/9I/+gaA8oxAoMPCOOy18pzVK+tovf1bZb
         xIG52woz41HaM1mmA5e8P93yGhGtGDCVOQD0coaZ8sprJrbeJbqU9IF6N+nEhlxjh0qa
         nuQmvvL5sO+2aEDT4qld3O+x8ydOP5PZF0HMBWr/me0jzFt78LFS4VsR9v6J35ATmgMB
         mhGTSkZ680edRUOnYqPsoyA/QYEembSOnoBMG86iepIsaYQjp/SPHCHNg1syxI2VozA/
         SHLrgG79ApPy0CR1WBrkPLdyfrQSLmjGPHsgqLF7lOXAY4w+0w9xCsiMHaGigmXBRJ2p
         LKNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=hQYTF5vH;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.samsung.com (mailout2.samsung.com. [203.254.224.25])
        by gmr-mx.google.com with ESMTPS id b17si627074pgs.1.2021.04.30.02.55.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 30 Apr 2021 02:55:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) client-ip=203.254.224.25;
Received: from epcas5p2.samsung.com (unknown [182.195.41.40])
	by mailout2.samsung.com (KnoxPortal) with ESMTP id 20210430095524epoutp021a695a05effa757fafbedba616e3ee56~6mirNwFro3176331763epoutp02q
	for <kasan-dev@googlegroups.com>; Fri, 30 Apr 2021 09:55:24 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.samsung.com 20210430095524epoutp021a695a05effa757fafbedba616e3ee56~6mirNwFro3176331763epoutp02q
Received: from epsmges5p3new.samsung.com (unknown [182.195.42.75]) by
	epcas5p4.samsung.com (KnoxPortal) with ESMTP id
	20210430095524epcas5p44f3cc997f2fefd401f1fbc8673f3f889~6miq28yBo2787027870epcas5p4v;
	Fri, 30 Apr 2021 09:55:24 +0000 (GMT)
X-AuditID: b6c32a4b-7c9ff7000000266b-65-608bd40c1e80
Received: from epcas5p4.samsung.com ( [182.195.41.42]) by
	epsmges5p3new.samsung.com (Symantec Messaging Gateway) with SMTP id
	4B.F1.09835.C04DB806; Fri, 30 Apr 2021 18:55:24 +0900 (KST)
Mime-Version: 1.0
Subject: RE:[PATCH 1/2] mm/kasan: avoid duplicate KASAN issues from
 reporting
Reply-To: maninder1.s@samsung.com
Sender: Maninder Singh <maninder1.s@samsung.com>
From: Maninder Singh <maninder1.s@samsung.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, Dmitry
	Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux
	Memory Management List <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, AMIT SAHRAWAT <a.sahrawat@samsung.com>,
	Vaneet Narang <v.narang@samsung.com>
X-Priority: 3
X-Content-Kind-Code: NORMAL
X-Drm-Type: N,general
X-Msg-Generator: Mail
X-Msg-Type: PERSONAL
X-Reply-Demand: N
Message-ID: <20210430095350epcms5p12b7d36494bbdfc17d795796697f0a649@epcms5p1>
Date: Fri, 30 Apr 2021 15:23:50 +0530
X-CMS-MailID: 20210430095350epcms5p12b7d36494bbdfc17d795796697f0a649
Content-Transfer-Encoding: base64
Content-Type: text/plain; charset="UTF-8"
X-Sendblock-Type: REQ_APPROVE
CMS-TYPE: 105P
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFprNKsWRmVeSWpSXmKPExsWy7bCmli7Ple4Eg1ln2S0u7k61mLN+DZvF
	94nT2S0mPGxjt2g7s53Vov3jXmaLFc/uM1lc3jWHzeLemv+sFse3bmG2OHRyLqMDt8fOWXfZ
	PRZsKvXYM/Ekm8emT5PYPU7M+M3i0bdlFaPH501yAexRXDYpqTmZZalF+nYJXBnbv/1lKuiV
	rmjcwd7AuFGqi5GTQ0LARKLp6FxmEFtIYDejxPrPtl2MHBy8AoISf3cIg4SFBfwlni7bwg5R
	oihxYcYaRpASYQEDiV9bNUDCbAJ6Eqt27WEBsUUEvCVWHjsIVMLFwSzwh0mibUonG8QqXokZ
	7U9ZIGxpie3LtzJC2KISN1e/ZYex3x+bDxUXkWi9d5YZwhaUePBzN1RcRmL15l4WkAUSAt2M
	Eo9/NEM1z2GU+LHEB8I2l9i9YR4LxC++EtcvWYGEWQRUJbatmgl1j4vEoobpYDazgLbEsoWv
	mUHKmQU0Jdbv0ocokZWYemodE0QJn0Tv7ydMMK/smAdjq0q03NzACvPW548foV70kFjx+zDY
	SCGBQIlla2smMMrPQoTtLCR7ZyHsXcDIvIpRMrWgODc9tdi0wDgvtVyvODG3uDQvXS85P3cT
	Izj9aHnvYHz04IPeIUYmDsZDjBIczEoivL/XdSYI8aYkVlalFuXHF5XmpBYfYpTmYFES5xV0
	rk4QEkhPLEnNTk0tSC2CyTJxcEo1MJ2PCr0n5+ReJ9Lx4ZvofrPt02epZWu5lJ61Pt/OUnWp
	YG9ulP6BGes2KFo0fK2Zm+69Z8bDdA/Z+KnKiiVvdqevNFnWMOGvwMMypXcKCsx9qm9nFaQ9
	8tf+c9RmooiK1rYNuSJMkwo0i/aJ9jyb9nf6gzM/jMIZLuvdPfnzxec/xfvty3x43mp31uoo
	3JjYqtMcoFGy4MztSh9+i92fOtT+L9/lsOfv9+51wUuu3du2yebTthMN5osPtiQk9elWRAXo
	3ZkieXHapgSOplAeobS6dNEUm2yzlvprE/NPNIa78Z+85DGheM3d/qWast46axzv/dZQXP9x
	jrjKNSfBxdaqJ1f5JRULFCRo2HC9V2Ipzkg01GIuKk4EAH+jHQ6uAwAA
X-CMS-RootMailID: 20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa
References: <CGME20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa@epcms5p1>
X-Original-Sender: maninder1.s@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=hQYTF5vH;       spf=pass
 (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as
 permitted sender) smtp.mailfrom=maninder1.s@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

SGksDQrCoA0KPg0KPsKgPsKgT27CoFRodSzCoDIywqBBcHLCoDIwMjHCoGF0wqAxMToxNyzCoE1h
bmluZGVywqBTaW5naMKgPG1hbmluZGVyMS5zQHNhbXN1bmcuY29tPsKgd3JvdGU6DQo+wqA+wqA+
DQo+wqA+wqA+wqB3aGVuwqBLQVNBTsKgbXVsdGlzaG90wqBpc8KgT07CoGFuZMKgc29tZcKgYnVn
Z3nCoGNvZGXCoGhpdHPCoHNhbWXCoGNvZGXCoHBhdGgNCj7CoD7CoD7CoG9mwqBLQVNBTsKgaXNz
dWXCoHJlcGV0ZXRpdmVseSzCoGl0wqBjYW7CoGZsb29kwqBsb2dzwqBvbsKgY29uc29sZS4NCj7C
oD7CoD4NCj7CoD7CoD7CoENoZWNrwqBmb3LCoGFsbG9jYXRvbizCoGZyZWXCoGFuZMKgYmFja3Ry
YWNlwqBwYXRowqBhdMKgdGltZcKgb2bCoEtBU0FOwqBlcnJvciwNCj7CoD7CoD7CoGlmwqB0aGVz
ZcKgYXJlwqBzYW1lwqB0aGVuwqBpdMKgaXPCoGR1cGxpY2F0ZcKgZXJyb3LCoGFuZMKgYXZvaWTC
oHRoZXNlwqBwcmludHMNCj7CoD7CoD7CoGZyb23CoEtBU0FOLg0KPsKgPg0KPsKgPsKgT27CoGHC
oG1vcmXCoGZ1bmRhbWVudGFswqBsZXZlbCzCoEnCoHRoaW5rwqB0aGlzwqBzb3J0wqBvZsKgZmls
dGVyaW5nwqBpc8KgdGhlDQo+wqA+wqB3cm9uZ8Kgc29sdXRpb27CoHRvwqB5b3VywqBwcm9ibGVt
LsKgT25lwqByZWFzb27CoHdoecKgaXQnc8KgZ29vZMKgdGhhdA0KPsKgPsKgbXVsdGlzaG90wqBp
c8Kgb2ZmwqBiecKgZGVmYXVsdMKgaXMswqBiZWNhdXNlwqBfZXZlcnlfwqBLQVNBTsKgcmVwb3J0
wqBpcw0KPsKgPsKgY3JpdGljYWzCoGFuZMKgY2FuwqBkZXN0YWJpbGl6ZcKgdGhlwqBzeXN0ZW0u
wqBUaGVyZWZvcmUswqBhbnnCoHJlcG9ydMKgYWZ0ZXINCj7CoD7CoHRoZcKgZmlyc3TCoG9uZcKg
bWlnaHTCoGJlwqBjb21wbGV0ZWx5wqBib2d1cyzCoGJlY2F1c2XCoHRoZcKgc3lzdGVtwqBpc8Kg
aW7CoGENCj7CoD7CoHBvdGVudGlhbGx5wqBiYWTCoHN0YXRlwqBhbmTCoGl0c8KgYmVoYXZpb3Vy
wqBtaWdodMKgYmXCoGNvbXBsZXRlbHnCoHJhbmRvbS4NCsKgDQpZZXPCoGl0J3PCoHZhbGlkwqBw
b2ludMKgLMKgQnV0wqBpbsKgU29tZcKgc2NlbmFyaW9zwqB0ZXN0aW5nwqBpbsKgcHJvZHVjdGlv
bsKgdGFrZcKgdGltZcKgYW5kDQp3YWl0aW5nwqBmb3LCoG9uZcKgaXNzdWXCoGZpeMKgdGFrZXPC
oHRpbWXCoGFzwqB0aGVyZcKgYXJlwqBtdWx0aXBsZcKgc3Rha2Vob2xkZXJzDQppbsKgbW9kdWxl
cy7CoFNvwqB3ZcKgdGhvdWdodMKgaXTCoHdhc8KgYmV0dGVywqB0b8KgY2F0Y2jCoG11bHRpcGxl
wqBpc3N1ZXPCoGluwqBvbmXCoGxvbmfCoHJ1bi4NCsKgDQrCoA0KPsKgPsKgVGhlwqBjb3JyZWN0
wqBzb2x1dGlvbsKgaXPCoHRvwqBub3TCoGxlYXZlwqB0aGXCoHN5c3RlbcKgcnVubmluZyzCoGZp
eMKgdGhlwqBmaXJzdA0KPsKgPsKgYnVnwqBmb3VuZCzCoGNvbnRpbnVlO8Kgcmluc2XCoGFuZMKg
cmVwZWF0LsKgVGhlcmVmb3JlLMKgdGhpc8KgcGF0Y2jCoGFkZHPCoGENCj7CoD7CoGxvdMKgb2bC
oGNvZGXCoGZvcsKgbGl0dGxlwqBiZW5lZml0Lg0KPsKgwqANCj7CoEnCoGFncmVlwqB3aXRowqBN
YXJjb8KgaGVyZS4NCj7CoMKgDQo+wqBJdMKgZG9lc24ndMKgbWFrZcKgc2Vuc2XCoHRvwqBoYXZl
wqB0aGlzwqBkZWR1cGxpY2F0aW9uwqBjb2RlwqBpbsKgdGhlwqBrZXJuZWwNCj7CoGFueXdheS7C
oElmwqB5b3XCoHdhbnTCoHVuaXF1ZcKgcmVwb3J0cyzCoHdyaXRlwqBhwqB1c2Vyc3BhY2XCoHNj
cmlwdMKgdGhhdA0KPsKgcGFyc2VzwqBkbWVzZ8KgYW5kwqBncm91cHPCoHRoZcKgcmVwb3J0cy4N
Cj7CoMKgDQrCoA0KWWVzwqBhZ3JlZSzCoGJ1dMKgaXNzdWXCoGlzwqB3aGVuwqBtdWx0aXNob3TC
oGlzwqBPTizCoHNhbWXCoEtBU0FOwqBlcnJvcg0KcmVwb3J0c8KgbXVsdGlwbGXCoHRpbWXCoGFu
ZMKgY2FuwqBmbG9vZMKgdGhlwqBzZXJpYWzCoGxvZ3MuDQp3aGljaMKgY2FuwqBiZcKgYXZvaWRl
ZMKgd2l0aMKgcGF0Y2jCoFsxLzJdDQrCoA0KVGhhbmtzLA0KTWFuaW5kZXLCoFNpbmdoDQoNCi0t
IApZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRv
IHRoZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9t
IHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVt
YWlsIHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRo
aXMgZGlzY3Vzc2lvbiBvbiB0aGUgd2ViIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20v
ZC9tc2dpZC9rYXNhbi1kZXYvMjAyMTA0MzAwOTUzNTBlcGNtczVwMTJiN2QzNjQ5NGJiZGZjMTdk
Nzk1Nzk2Njk3ZjBhNjQ5JTQwZXBjbXM1cDEuCg==
