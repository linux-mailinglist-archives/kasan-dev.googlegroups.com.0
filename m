Return-Path: <kasan-dev+bncBDOJT7EVXMDBBTHD7KYAMGQEFEVHK6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 646338A71FF
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Apr 2024 19:13:50 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1e3c14a60e3sf36772255ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Apr 2024 10:13:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713287629; cv=pass;
        d=google.com; s=arc-20160816;
        b=IZPHCHH36eIEU2yFF0rbBA5QtQ4SqeycP0PnDY0xYtyjAPbnjCpnbHEIKk7J5mA2KP
         SW6MOcI8VckGvNvXcHuC0TcYV+b8QlidqpLG2wujuXytTEtce9Ze1li8DnZSiYCv4R71
         ows9RsXV1+eUBd4XHa1tQ8j0ATagxOhXR2UswBT0wi5aKrt15vcrnRhSuf2UzIX1CXle
         AtFKmM+SMcLmP6H5xfJJhyRTuuskcZqM/B3Tmjij/jh9Ix2g2VTVOor0s2J1IZwH5Dys
         3Owl3cDLXHKlnhR9YBX9le0FcMKdwmhcbtX/G+mqu9n0celwPNdxIBGHpaO20RaZObtQ
         AcvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:from:date:cc:to:references
         :in-reply-to:message-id:mime-version:sender:dkim-signature;
        bh=/exrxZS1EHFW9R0AEGI72V+G20m5pNrn0oAW5vFiVKI=;
        fh=isRUnn29ACvv7+sYMa4FtrjeNXrt2hj5DJyOUBAw8ng=;
        b=m+LF5iuy3sAySNdHKLMtvfY236iiIUDa83ssbg8UBKVrhkYmIunKLFAT8Q0RWGzPZL
         y7Dmz3Pb3nDXG8yNr2TbApEbdJyLBFkQNdPbi7tkAAYctqYAN/MxkG37HWoPjO3sGYRA
         +O90VcX7cX5g9rOKcLPf7rm6JONVkpgVahQhZTFpryBhYiANILLdcWHu9FRVCdS9/U/Z
         UvYj0JAVoYPIdpDm/VUjpnbMKLLOe0PKzjCF1KUH3UhroMxBRpquMtkqypdpSN1fkrhk
         DPXAO0Vc7PsrmCw4vHoeGuWzeCR0BMBLSmy/xBaHQvf8QEgWCzXfAg3dg4NfgTS1vI0n
         ydjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=fail header.i=@motorola.com header.s=DKIM202306 header.b=5bQZz5gG;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713287629; x=1713892429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:from:date:cc:to:references:in-reply-to:message-id
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/exrxZS1EHFW9R0AEGI72V+G20m5pNrn0oAW5vFiVKI=;
        b=IUSVuaEcL+uNmOr3TMVHZVJ3NYTxGcC43o36IpIdfgW0d2D3M6qpYzDNFirr8UD26g
         h+JsvzBb1Oy56zB0q4PHKE00BGiDaOiTZAJHXOgJ9CWZcDmJPOdwfRi2VkxLzTKHKK+U
         UeXCkI3yOCS01Y/2DqZm4XKmWO7rTvbVCHjJLOCyXrDE+1TBYtArRGNWkAtnqIjRgc1F
         0bmbhIz8+A0MLII+eVsXGOIGrVF1L6j4eINQV1HPRI2eKQ03Diy8zEx5ill3ZCb+Mxsn
         W6vqgP7YQ8aosIZC//nDeTQ4OKQvbdPyIJ7Ah7EGZObONgGzzjzsLn8pqQUQsfG3clPq
         rLCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713287629; x=1713892429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:from:date:cc:to
         :references:in-reply-to:message-id:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/exrxZS1EHFW9R0AEGI72V+G20m5pNrn0oAW5vFiVKI=;
        b=bwhvbs3qR1dUZdJRRfCrgWjMj6+VHDA/rw8ug5Kf3MVepSXMImdwP1kq3oG11gw90c
         tG2i47+1NuLfcdt0Md6zrppr1iCJVJh0Z8qn/8/AowCXWMjLHjZcMrSx/wQT0aItv/od
         89IV0VQyRdnbL536tQ3VKzlubEXCNj0BNUXpaVDP0C+CbHaG0DrELNZqAengmIBU/NlB
         MfQPrdOgfXJNyUgk3fqeZq3MQhL3XzX4NBKH/7XYlkYDBFX0WOGNjaoU12KPdn/SS0/t
         12oY87mxtydf0JJsKH9fsSyAt++7FFUo+MunIjiU9v6RZsCeQyMGp8rpSreK5cGUA1sK
         81Tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3hnmfr7hB+n00EohRrnYK0RKif7nnTXeHL0h2NphCevPLraJPLV3WoWJJ83bSEvLH5Psbal2pOa/4FVF/L9ulwaXsLhkqmw==
X-Gm-Message-State: AOJu0YyY4REAmVhWV1p6AoNYUdrmGQy3AJgHrWVKuTLat794BILkISZ+
	4tHoabs3JYgpMfQ88zt51Kl2eiiRQETjgjdlAuRU4P41QO6iyj6s
X-Google-Smtp-Source: AGHT+IHjwkOSghI8Ac3Xek4AvCKJZ3q835nhsRcQ7kVEG2K6FhCWxzHQ5Kv9My4oooU+TkHfJd4Pbg==
X-Received: by 2002:a17:902:a587:b0:1e7:b7ea:2d61 with SMTP id az7-20020a170902a58700b001e7b7ea2d61mr3393283plb.37.1713287628469;
        Tue, 16 Apr 2024 10:13:48 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22c2:b0:1e4:31fb:1349 with SMTP id
 y2-20020a17090322c200b001e431fb1349ls2625244plg.0.-pod-prod-07-us; Tue, 16
 Apr 2024 10:13:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX51J51a5ia2xoC6jHj9qXKOwfhmi+ufK+ku+WWJhaoE7URCQ8YF97bLxMp3zAbKMR0EQbnLg2TnmIGbDBeEz7W0gGesdgESbVdjA==
X-Received: by 2002:a17:902:bf48:b0:1e2:a2d7:9f5a with SMTP id u8-20020a170902bf4800b001e2a2d79f5amr12466824pls.65.1713287627065;
        Tue, 16 Apr 2024 10:13:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713287627; cv=none;
        d=google.com; s=arc-20160816;
        b=fUbKyrKAQbpv+x1ESh++y1grLQYPwvll9QgGV+aGIHZVRAR9b2n+9GV3es5jGbNmzH
         ExLbpUnQ9ycZ55pv+YPS/mh8QGlKnTCxsFb/T0MJStdJB+R7WhojihBOvbHNfl+nLp1a
         YAAfqgL1zvUTY7jFkjXe+YA8odUO2JaBkbyN+4dz0pJqAb7fkuenC+bEoE1MhvazyKqA
         778yKRewanU6pjkHxnM5B5RC1B52q5FPudgUPRZktP2Smq7yRrCqyUZmiUMEcbdjDNQF
         vOaOegJKOwqMFAGHyTnuo7ALTx65tSnP/5qNzIa36dYMW4l0UiBujGhOD7tIQzv5fpTb
         /TlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=from:date:cc:to:references:in-reply-to:message-id:dkim-signature;
        bh=0DmzzJZbYc/xYD7mMOXY/jAogi5GP4/ooHS3OM87fAA=;
        fh=xPVSiNYn/kx7VYaypoDzj0jx3qF0irgkhVJdGcAmT7k=;
        b=Cmvd4zcyJaYN5G0mHach8cSgJK/m1UNOMq4VgGf6jECGGihicekfEvWLB5C3oRzP9l
         uRcCjR+BFcY5SixMwLVAphBksfW58hhS+0Jm9xf1x6xCIYCRfmlfSfnbjlMPLIQhHKWw
         HSAqyHyZ/grb3md14G6jeL5Fc5g3F4PiawH/H5eoUY6Qj/egyCsdxKpCWYJcXXwNK7xG
         ChD5nfpzfNtkOaDMNxEBgTYQaChTs+jQfWqmjnSS1QgCDuQLhySJnzoy3XW4G189NSIp
         TuVXNwK24M5rjzzCV22/OSZuSGdI2NQiWpsLzdTZEWw/4FtZ2HDXkPhZQz4x/Z9H2M5X
         HYoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=fail header.i=@motorola.com header.s=DKIM202306 header.b=5bQZz5gG;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0b-00823401.pphosted.com (mx0b-00823401.pphosted.com. [148.163.152.46])
        by gmr-mx.google.com with ESMTPS id w3-20020a170902904300b001dd61b4ef8esi670187plz.12.2024.04.16.10.13.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Apr 2024 10:13:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) client-ip=148.163.152.46;
Received: from pps.filterd (m0355090.ppops.net [127.0.0.1])
	by m0355090.ppops.net (8.17.1.24/8.17.1.24) with ESMTP id 43GGBi1b031812;
	Tue, 16 Apr 2024 17:12:43 GMT
Received: from va32lpfpp02.lenovo.com ([104.232.228.22])
	by m0355090.ppops.net (PPS) with ESMTPS id 3xhrya9d1t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 16 Apr 2024 17:12:42 +0000 (GMT)
Received: from va32lmmrp01.lenovo.com (va32lmmrp01.mot.com [10.62.177.113])
	(using TLSv1.2 with cipher ADH-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by va32lpfpp02.lenovo.com (Postfix) with ESMTPS id 4VJrFj1C34z53xyY;
	Tue, 16 Apr 2024 17:12:41 +0000 (UTC)
Received: from ilclbld243.mot.com (ilclbld243.mot.com [100.64.22.29])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: mbland)
	by va32lmmrp01.lenovo.com (Postfix) with ESMTPSA id 4VJrFj0cKvz2VZRf;
	Tue, 16 Apr 2024 17:12:41 +0000 (UTC)
Message-Id: <20240416120827.062020959-4-mbland@motorola.com>
In-Reply-To: <20240416120827.062020959-1-mbland@motorola.com>
References: <20240416120827.062020959-1-mbland@motorola.com>
To: linux-mm@kvack.org
Cc: Maxwell Bland <mbland@motorola.com>
Date: Tue, 16 Apr 2024 17:12:41 +0000 (UTC)
From: mbland@motorola.com
X-Proofpoint-ORIG-GUID: QZeeFHpBA4s9h3l_lYKV7d_Kko3JWPI3
X-Proofpoint-GUID: QZeeFHpBA4s9h3l_lYKV7d_Kko3JWPI3
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-04-16_14,2024-04-16_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 suspectscore=0 bulkscore=0 mlxlogscore=999 mlxscore=0 impostorscore=0
 malwarescore=0 spamscore=0 phishscore=0 adultscore=0 clxscore=1011
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2404010003 definitions=main-2404160107
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=fail
 header.i=@motorola.com header.s=DKIM202306 header.b=5bQZz5gG;       spf=pass
 (google.com: domain of mbland@motorola.com designates 148.163.152.46 as
 permitted sender) smtp.mailfrom=mbland@motorola.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=motorola.com
Content-Type: text/plain; charset="UTF-8"
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

Richard Henderson <richard.henderson@linaro.org>,
Ivan Kokshaysky <ink@jurassic.park.msu.ru>,
Matt Turner <mattst88@gmail.com>,
Vineet Gupta <vgupta@kernel.org>,
Alexander Potapenko <glider@google.com>,
Marco Elver <elver@google.com>,
Dmitry Vyukov <dvyukov@google.com>,
Russell King <linux@armlinux.org.uk>,
Andrey Ryabinin <ryabinin.a.a@gmail.com>,
Andrey Konovalov <andreyknvl@gmail.com>,
Vincenzo Frascino <vincenzo.frascino@arm.com>,
Catalin Marinas <catalin.marinas@arm.com>,
Will Deacon <will@kernel.org>,
Guo Ren <guoren@kernel.org>,
Brian Cain <bcain@quicinc.com>,
Huacai Chen <chenhuacai@kernel.org>,
WANG Xuerui <kernel@xen0n.name>,
Geert Uytterhoeven <geert@linux-m68k.org>,
Sam Creasey <sammy@sammy.net>,
Michal Simek <monstr@monstr.eu>,
Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
Dinh Nguyen <dinguyen@kernel.org>,
Jonas Bonn <jonas@southpole.se>,
Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>,
Stafford Horne <shorne@gmail.com>,
"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
Helge Deller <deller@gmx.de>,
Michael Ellerman <mpe@ellerman.id.au>,
Nicholas Piggin <npiggin@gmail.com>,
Christophe Leroy <christophe.leroy@csgroup.eu>,
"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
Paul Walmsley <paul.walmsley@sifive.com>,
Palmer Dabbelt <palmer@dabbelt.com>,
Albert Ou <aou@eecs.berkeley.edu>,
Heiko Carstens <hca@linux.ibm.com>,
Vasily Gorbik <gor@linux.ibm.com>,
Alexander Gordeev <agordeev@linux.ibm.com>,
Christian Borntraeger <borntraeger@linux.ibm.com>,
Sven Schnelle <svens@linux.ibm.com>,
Yoshinori Sato <ysato@users.sourceforge.jp>,
Rich Felker <dalias@libc.org>,
John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>,
"David S. Miller" <davem@davemloft.net>,
Andreas Larsson <andreas@gaisler.com>,
Richard Weinberger <richard@nod.at>,
Anton Ivanov <anton.ivanov@cambridgegreys.com>,
Johannes Berg <johannes@sipsolutions.net>,
Thomas Gleixner <tglx@linutronix.de>,
Ingo Molnar <mingo@redhat.com>,
Borislav Petkov <bp@alien8.de>,
Dave Hansen <dave.hansen@linux.intel.com>,
x86@kernel.org,
"H. Peter Anvin" <hpa@zytor.com>,
Andy Lutomirski <luto@kernel.org>,
Peter Zijlstra <peterz@infradead.org>,
Chris Zankel <chris@zankel.net>,
Max Filippov <jcmvbkbc@gmail.com>,
Andrew Morton <akpm@linux-foundation.org>,
Muchun Song <muchun.song@linux.dev>,
Dennis Zhou <dennis@kernel.org>,
Tejun Heo <tj@kernel.org>,
Christoph Lameter <cl@linux.com>,
Maxwell Bland <mbland@motorola.com>,
Linus Walleij <linus.walleij@linaro.org>,
David Hildenbrand <david@redhat.com>,
Arnd Bergmann <arnd@arndb.de>,
Ard Biesheuvel <ardb@kernel.org>,
Ryan Roberts <ryan.roberts@arm.com>,
Mark Rutland <mark.rutland@arm.com>,
Nikhil V <quic_nprakash@quicinc.com>,
Rick Edgecombe <rick.p.edgecombe@intel.com>,
Baolin Wang <baolin.wang@linux.alibaba.com>,
Bibo Mao <maobibo@loongson.cn>,
Tianrui Zhao <zhaotianrui@loongson.cn>,
Randy Dunlap <rdunlap@infradead.org>,
Vlastimil Babka <vbabka@suse.cz>,
Kent Overstreet <kent.overstreet@linux.dev>,
Peter Xu <peterx@redhat.com>,
Jiangfeng Xiao <xiaojiangfeng@huawei.com>,
Alexandre Ghiti <alexghiti@rivosinc.com>,
Jisheng Zhang <jszhang@kernel.org>,
Conor Dooley <conor.dooley@microchip.com>,
Mason Huo <mason.huo@starfivetech.com>,
Sia Jee Heng <jeeheng.sia@starfivetech.com>,
Song Shuai <songshuaishuai@tinylab.org>,
Gerald Schaefer <gerald.schaefer@linux.ibm.com>,
Qi Zheng <zhengqi.arch@bytedance.com>,
Hugh Dickins <hughd@google.com>,
Jason Gunthorpe <jgg@ziepe.ca>,
Breno Leitao <leitao@debian.org>,
Josh Poimboeuf <jpoimboe@kernel.org>,
linux-alpha@vger.kernel.org,
linux-kernel@vger.kernel.org,
linux-snps-arc@lists.infradead.org,
kasan-dev@googlegroups.com,
linux-arm-kernel@lists.infradead.org,
linux-csky@vger.kernel.org,
linux-hexagon@vger.kernel.org,
loongarch@lists.linux.dev,
linux-m68k@lists.linux-m68k.org,
linux-mips@vger.kernel.org,
kvm@vger.kernel.org,
linux-openrisc@vger.kernel.org,
linux-parisc@vger.kernel.org,
linuxppc-dev@lists.ozlabs.org,
linux-riscv@lists.infradead.org,
linux-s390@vger.kernel.org,
linux-sh@vger.kernel.org,
sparclinux@vger.kernel.org,
linux-um@lists.infradead.org
From: Maxwell Bland <mbland@motorola.com>
Date: Fri, 5 Apr 2024 13:37:00 -0500
Subject: [PATCH 3/5] mm: add vaddr param to pmd_populate_kernel

This patch affords each architecture the ability to condition the
population of page middle directory entries on the virtual address being
allocated, matching existing PTE infrastructure, easing the necessity of
performing a reverse page table walk in cases where the population
context is not readily accessible, i.e. dynamic vmalloc calls on arm64.

To achieve this goal, it modifies every call and implementation of the
pmd_populate_kernel function across architectures, ensuring uniform
adoption across all kernel deployments.

Signed-off-by: Maxwell Bland <mbland@motorola.com>

---

Hi all,

Thank you for taking the time to review this change. This effects many
subarchitectures so the maintainers list is large. Apologies in advance
if there is a specific maintainer I should have spoken with directly for
deployment across subprojects.

The reason for such a sweeping change is from 
lore.kernel.org/all/cf5409c3-254a-459b-8969-429db2ec6439@redhat.com

It is my understanding as well that some subarchitectures may have
separate "next" or development branches ahead of the main upstream
linux. Please let me know if a cherry-pick to that branch is desired and
I will do my best to check out and deploy it as possible.

 arch/alpha/include/asm/pgalloc.h             |  5 +++--
 arch/arc/include/asm/pgalloc.h               |  3 ++-
 arch/arc/mm/highmem.c                        |  2 +-
 arch/arm/include/asm/kfence.h                |  2 +-
 arch/arm/include/asm/pgalloc.h               |  3 ++-
 arch/arm/mm/kasan_init.c                     |  2 +-
 arch/arm/mm/mmu.c                            |  2 +-
 arch/arm64/include/asm/pgalloc.h             |  3 ++-
 arch/arm64/mm/trans_pgd.c                    |  2 +-
 arch/csky/include/asm/pgalloc.h              |  2 +-
 arch/hexagon/include/asm/pgalloc.h           |  2 +-
 arch/loongarch/include/asm/pgalloc.h         |  3 ++-
 arch/loongarch/mm/init.c                     |  2 +-
 arch/loongarch/mm/kasan_init.c               |  2 +-
 arch/m68k/include/asm/mcf_pgalloc.h          |  2 +-
 arch/m68k/include/asm/motorola_pgalloc.h     |  3 ++-
 arch/m68k/include/asm/sun3_pgalloc.h         |  3 ++-
 arch/microblaze/include/asm/pgalloc.h        |  2 +-
 arch/mips/include/asm/pgalloc.h              |  2 +-
 arch/mips/kvm/mmu.c                          |  2 +-
 arch/nios2/include/asm/pgalloc.h             |  2 +-
 arch/openrisc/include/asm/pgalloc.h          |  2 +-
 arch/parisc/include/asm/pgalloc.h            |  5 +++--
 arch/parisc/mm/init.c                        |  6 +++---
 arch/powerpc/include/asm/book3s/32/pgalloc.h |  2 +-
 arch/powerpc/include/asm/book3s/64/pgalloc.h |  2 +-
 arch/powerpc/include/asm/nohash/32/pgalloc.h |  2 +-
 arch/powerpc/include/asm/nohash/64/pgalloc.h |  2 +-
 arch/powerpc/mm/book3s64/radix_pgtable.c     |  2 +-
 arch/powerpc/mm/kasan/init_32.c              |  4 ++--
 arch/powerpc/mm/kasan/init_book3e_64.c       |  9 ++++++---
 arch/powerpc/mm/kasan/init_book3s_64.c       |  7 +++++--
 arch/powerpc/mm/nohash/book3e_pgtable.c      |  2 +-
 arch/powerpc/mm/pgtable_32.c                 |  4 ++--
 arch/riscv/include/asm/pgalloc.h             |  2 +-
 arch/riscv/kernel/hibernate.c                |  2 +-
 arch/s390/include/asm/pgalloc.h              |  2 +-
 arch/sh/include/asm/pgalloc.h                |  2 +-
 arch/sh/mm/init.c                            |  2 +-
 arch/sparc/include/asm/pgalloc_32.h          |  3 ++-
 arch/sparc/include/asm/pgalloc_64.h          |  4 ++--
 arch/sparc/mm/init_64.c                      |  8 ++++----
 arch/um/include/asm/pgalloc.h                |  4 ++--
 arch/x86/include/asm/pgalloc.h               |  3 ++-
 arch/x86/mm/init_64.c                        | 14 +++++++++++---
 arch/x86/mm/ioremap.c                        |  2 +-
 arch/x86/mm/kasan_init_64.c                  |  2 +-
 arch/xtensa/include/asm/pgalloc.h            |  2 +-
 include/linux/mm.h                           |  4 ++--
 mm/hugetlb_vmemmap.c                         |  4 ++--
 mm/kasan/init.c                              | 14 +++++++++-----
 mm/memory.c                                  |  4 ++--
 mm/percpu.c                                  |  2 +-
 mm/pgalloc-track.h                           |  3 ++-
 mm/sparse-vmemmap.c                          |  2 +-
 55 files changed, 107 insertions(+), 78 deletions(-)

diff --git a/arch/alpha/include/asm/pgalloc.h b/arch/alpha/include/asm/pgalloc.h
index 68be7adbfe58..1d3d86cad3cc 100644
--- a/arch/alpha/include/asm/pgalloc.h
+++ b/arch/alpha/include/asm/pgalloc.h
@@ -7,7 +7,7 @@
 
 #include <asm-generic/pgalloc.h>
 
-/*      
+/*
  * Allocate and free page tables. The xxx_kernel() versions are
  * used to allocate a kernel page table - this turns on ASN bits
  * if any.
@@ -20,7 +20,8 @@ pmd_populate(struct mm_struct *mm, pmd_t *pmd, pgtable_t pte)
 }
 
 static inline void
-pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
+pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte,
+		    unsigned long vaddr)
 {
 	pmd_set(pmd, pte);
 }
diff --git a/arch/arc/include/asm/pgalloc.h b/arch/arc/include/asm/pgalloc.h
index 096b8ef58edb..c0ebfa44b204 100644
--- a/arch/arc/include/asm/pgalloc.h
+++ b/arch/arc/include/asm/pgalloc.h
@@ -34,7 +34,8 @@
 #include <asm-generic/pgalloc.h>
 
 static inline void
-pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
+pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte,
+		    unsigned long vaddr)
 {
 	/*
 	 * The cast to long below is OK in 32-bit PAE40 regime with long long pte
diff --git a/arch/arc/mm/highmem.c b/arch/arc/mm/highmem.c
index c79912a6b196..2d327cf35722 100644
--- a/arch/arc/mm/highmem.c
+++ b/arch/arc/mm/highmem.c
@@ -57,7 +57,7 @@ static noinline pte_t * __init alloc_kmap_pgtable(unsigned long kvaddr)
 		panic("%s: Failed to allocate %lu bytes align=0x%lx\n",
 		      __func__, PAGE_SIZE, PAGE_SIZE);
 
-	pmd_populate_kernel(&init_mm, pmd_k, pte_k);
+	pmd_populate_kernel(&init_mm, pmd_k, pte_k, kvaddr);
 	return pte_k;
 }
 
diff --git a/arch/arm/include/asm/kfence.h b/arch/arm/include/asm/kfence.h
index 7980d0f2271f..dd4e4325d354 100644
--- a/arch/arm/include/asm/kfence.h
+++ b/arch/arm/include/asm/kfence.h
@@ -19,7 +19,7 @@ static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
 		set_pte_ext(pte + i, pfn_pte(pfn + i, PAGE_KERNEL), 0);
-	pmd_populate_kernel(&init_mm, pmd, pte);
+	pmd_populate_kernel(&init_mm, pmd, pte, addr);
 
 	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
 	return 0;
diff --git a/arch/arm/include/asm/pgalloc.h b/arch/arm/include/asm/pgalloc.h
index a17f01235c29..0a88346db17e 100644
--- a/arch/arm/include/asm/pgalloc.h
+++ b/arch/arm/include/asm/pgalloc.h
@@ -122,7 +122,8 @@ static inline void __pmd_populate(pmd_t *pmdp, phys_addr_t pte,
  * Ensure that we always set both PMD entries.
  */
 static inline void
-pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep)
+pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep,
+		    unsigned long vaddr)
 {
 	/*
 	 * The pmd must be loaded with the physical address of the PTE table
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f703136..9b3af2dce71e 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -111,7 +111,7 @@ static void __init kasan_pmd_populate(pud_t *pudp, unsigned long addr,
 				      __func__, addr);
 				return;
 			}
-			pmd_populate_kernel(&init_mm, pmdp, p);
+			pmd_populate_kernel(&init_mm, pmdp, p, addr);
 			flush_pmd_entry(pmdp);
 		}
 
diff --git a/arch/arm/mm/mmu.c b/arch/arm/mm/mmu.c
index c24e29c0b9a4..3cfed8dc4a19 100644
--- a/arch/arm/mm/mmu.c
+++ b/arch/arm/mm/mmu.c
@@ -384,7 +384,7 @@ void __init early_fixmap_init(void)
 		     != FIXADDR_TOP >> PMD_SHIFT);
 
 	pmd = fixmap_pmd(FIXADDR_TOP);
-	pmd_populate_kernel(&init_mm, pmd, bm_pte);
+	pmd_populate_kernel(&init_mm, pmd, bm_pte, __fix_to_virt(FIXADDR_TOP));
 
 	pte_offset_fixmap = pte_offset_early_fixmap;
 }
diff --git a/arch/arm64/include/asm/pgalloc.h b/arch/arm64/include/asm/pgalloc.h
index 8ff5f2a2579e..5785272144e8 100644
--- a/arch/arm64/include/asm/pgalloc.h
+++ b/arch/arm64/include/asm/pgalloc.h
@@ -124,7 +124,8 @@ static inline void __pmd_populate(pmd_t *pmdp, phys_addr_t ptep,
  * of the mm address space.
  */
 static inline void
-pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep)
+pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep,
+		    unsigned long vaddr)
 {
 	VM_BUG_ON(mm && mm != &init_mm);
 	__pmd_populate(pmdp, __pa(ptep), PMD_TYPE_TABLE | PMD_TABLE_UXN);
diff --git a/arch/arm64/mm/trans_pgd.c b/arch/arm64/mm/trans_pgd.c
index 5139a28130c0..f84244d13099 100644
--- a/arch/arm64/mm/trans_pgd.c
+++ b/arch/arm64/mm/trans_pgd.c
@@ -69,7 +69,7 @@ static int copy_pte(struct trans_pgd_info *info, pmd_t *dst_pmdp,
 	dst_ptep = trans_alloc(info);
 	if (!dst_ptep)
 		return -ENOMEM;
-	pmd_populate_kernel(NULL, dst_pmdp, dst_ptep);
+	pmd_populate_kernel(NULL, dst_pmdp, dst_ptep, addr);
 	dst_ptep = pte_offset_kernel(dst_pmdp, start);
 
 	src_ptep = pte_offset_kernel(src_pmdp, start);
diff --git a/arch/csky/include/asm/pgalloc.h b/arch/csky/include/asm/pgalloc.h
index 9c84c9012e53..f2c244c58acf 100644
--- a/arch/csky/include/asm/pgalloc.h
+++ b/arch/csky/include/asm/pgalloc.h
@@ -11,7 +11,7 @@
 #include <asm-generic/pgalloc.h>
 
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
-					pte_t *pte)
+					pte_t *pte, unsigned long vaddr)
 {
 	set_pmd(pmd, __pmd(__pa(pte)));
 }
diff --git a/arch/hexagon/include/asm/pgalloc.h b/arch/hexagon/include/asm/pgalloc.h
index 55988625e6fb..2be773a5ffeb 100644
--- a/arch/hexagon/include/asm/pgalloc.h
+++ b/arch/hexagon/include/asm/pgalloc.h
@@ -62,7 +62,7 @@ static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd,
  * kernel map of the active thread who's calling pmd_populate_kernel...
  */
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
-				       pte_t *pte)
+				       pte_t *pte, unsigned long vaddr)
 {
 	extern spinlock_t kmap_gen_lock;
 	pmd_t *ppmd;
diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/include/asm/pgalloc.h
index 4e2d6b7ca2ee..6384391e69bd 100644
--- a/arch/loongarch/include/asm/pgalloc.h
+++ b/arch/loongarch/include/asm/pgalloc.h
@@ -13,7 +13,8 @@
 #include <asm-generic/pgalloc.h>
 
 static inline void pmd_populate_kernel(struct mm_struct *mm,
-				       pmd_t *pmd, pte_t *pte)
+				       pmd_t *pmd, pte_t *pte,
+				       unsigned long vaddr)
 {
 	set_pmd(pmd, __pmd((unsigned long)pte));
 }
diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
index 4dd53427f657..b8952899b120 100644
--- a/arch/loongarch/mm/init.c
+++ b/arch/loongarch/mm/init.c
@@ -200,7 +200,7 @@ pte_t * __init populate_kernel_pte(unsigned long addr)
 		pte = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 		if (!pte)
 			panic("%s: Failed to allocate memory\n", __func__);
-		pmd_populate_kernel(&init_mm, pmd, pte);
+		pmd_populate_kernel(&init_mm, pmd, pte, addr);
 	}
 
 	return pte_offset_kernel(pmd, addr);
diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index c608adc99845..51d40ff43aa9 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -110,7 +110,7 @@ static pte_t *__init kasan_pte_offset(pmd_t *pmdp, unsigned long addr, int node,
 				__pa_symbol(kasan_early_shadow_pte) : kasan_alloc_zeroed_page(node);
 		if (!early)
 			memcpy(__va(pte_phys), kasan_early_shadow_pte, sizeof(kasan_early_shadow_pte));
-		pmd_populate_kernel(NULL, pmdp, (pte_t *)__va(pte_phys));
+		pmd_populate_kernel(NULL, pmdp, (pte_t *)__va(pte_phys), addr);
 	}
 
 	return pte_offset_kernel(pmdp, addr);
diff --git a/arch/m68k/include/asm/mcf_pgalloc.h b/arch/m68k/include/asm/mcf_pgalloc.h
index 302c5bf67179..989a1aaa8aa1 100644
--- a/arch/m68k/include/asm/mcf_pgalloc.h
+++ b/arch/m68k/include/asm/mcf_pgalloc.h
@@ -30,7 +30,7 @@ extern inline pmd_t *pmd_alloc_kernel(pgd_t *pgd, unsigned long address)
 
 #define pmd_populate(mm, pmd, pte) (pmd_val(*pmd) = (unsigned long)(pte))
 
-#define pmd_populate_kernel pmd_populate
+#define pmd_populate_kernel(mm, pmd, pte, vaddr) pmd_populate(mm, pmd, pte)
 
 static inline void __pte_free_tlb(struct mmu_gather *tlb, pgtable_t pgtable,
 				  unsigned long address)
diff --git a/arch/m68k/include/asm/motorola_pgalloc.h b/arch/m68k/include/asm/motorola_pgalloc.h
index 74a817d9387f..74aec6965981 100644
--- a/arch/m68k/include/asm/motorola_pgalloc.h
+++ b/arch/m68k/include/asm/motorola_pgalloc.h
@@ -79,7 +79,8 @@ static inline pgd_t *pgd_alloc(struct mm_struct *mm)
 }
 
 
-static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
+static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
+				       pte_t *pte, unsigned long vaddr)
 {
 	pmd_set(pmd, pte);
 }
diff --git a/arch/m68k/include/asm/sun3_pgalloc.h b/arch/m68k/include/asm/sun3_pgalloc.h
index 4a137eecb6fe..550283e8bf4d 100644
--- a/arch/m68k/include/asm/sun3_pgalloc.h
+++ b/arch/m68k/include/asm/sun3_pgalloc.h
@@ -23,7 +23,8 @@ do {								\
 	tlb_remove_page_ptdesc((tlb), page_ptdesc(pte));	\
 } while (0)
 
-static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
+static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
+				       pte_t *pte, unsigned long vaddr)
 {
 	pmd_val(*pmd) = __pa((unsigned long)pte);
 }
diff --git a/arch/microblaze/include/asm/pgalloc.h b/arch/microblaze/include/asm/pgalloc.h
index 6c33b05f730f..b3cc2cd8fc50 100644
--- a/arch/microblaze/include/asm/pgalloc.h
+++ b/arch/microblaze/include/asm/pgalloc.h
@@ -35,7 +35,7 @@ extern pte_t *pte_alloc_one_kernel(struct mm_struct *mm);
 #define pmd_populate(mm, pmd, pte) \
 			(pmd_val(*(pmd)) = (unsigned long)page_address(pte))
 
-#define pmd_populate_kernel(mm, pmd, pte) \
+#define pmd_populate_kernel(mm, pmd, pte, vaddr) \
 		(pmd_val(*(pmd)) = (unsigned long) (pte))
 
 #endif /* _ASM_MICROBLAZE_PGALLOC_H */
diff --git a/arch/mips/include/asm/pgalloc.h b/arch/mips/include/asm/pgalloc.h
index f4440edcd8fe..fb71c8776a04 100644
--- a/arch/mips/include/asm/pgalloc.h
+++ b/arch/mips/include/asm/pgalloc.h
@@ -19,7 +19,7 @@
 #include <asm-generic/pgalloc.h>
 
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
-	pte_t *pte)
+	pte_t *pte, unsigned long vaddr)
 {
 	set_pmd(pmd, __pmd((unsigned long)pte));
 }
diff --git a/arch/mips/kvm/mmu.c b/arch/mips/kvm/mmu.c
index 467ee6b95ae1..47f48929a124 100644
--- a/arch/mips/kvm/mmu.c
+++ b/arch/mips/kvm/mmu.c
@@ -133,7 +133,7 @@ static pte_t *kvm_mips_walk_pgd(pgd_t *pgd, struct kvm_mmu_memory_cache *cache,
 			return NULL;
 		new_pte = kvm_mmu_memory_cache_alloc(cache);
 		clear_page(new_pte);
-		pmd_populate_kernel(NULL, pmd, new_pte);
+		pmd_populate_kernel(NULL, pmd, new_pte, addr);
 	}
 	return pte_offset_kernel(pmd, addr);
 }
diff --git a/arch/nios2/include/asm/pgalloc.h b/arch/nios2/include/asm/pgalloc.h
index ce6bb8e74271..ea99d36a6fdd 100644
--- a/arch/nios2/include/asm/pgalloc.h
+++ b/arch/nios2/include/asm/pgalloc.h
@@ -15,7 +15,7 @@
 #include <asm-generic/pgalloc.h>
 
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
-	pte_t *pte)
+	pte_t *pte, unsigned long vaddr)
 {
 	set_pmd(pmd, __pmd((unsigned long)pte));
 }
diff --git a/arch/openrisc/include/asm/pgalloc.h b/arch/openrisc/include/asm/pgalloc.h
index c6a73772a546..304cf8955bec 100644
--- a/arch/openrisc/include/asm/pgalloc.h
+++ b/arch/openrisc/include/asm/pgalloc.h
@@ -25,7 +25,7 @@
 
 extern int mem_init_done;
 
-#define pmd_populate_kernel(mm, pmd, pte) \
+#define pmd_populate_kernel(mm, pmd, pte, vaddr) \
 	set_pmd(pmd, __pmd(_KERNPG_TABLE + __pa(pte)))
 
 static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd,
diff --git a/arch/parisc/include/asm/pgalloc.h b/arch/parisc/include/asm/pgalloc.h
index e3e142b1c5c5..cba92c90a62a 100644
--- a/arch/parisc/include/asm/pgalloc.h
+++ b/arch/parisc/include/asm/pgalloc.h
@@ -61,13 +61,14 @@ static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
 #endif
 
 static inline void
-pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
+pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte, unsigned long vaddr)
 {
 	set_pmd(pmd, __pmd((PxD_FLAG_PRESENT | PxD_FLAG_VALID)
 		+ (__u32)(__pa((unsigned long)pte) >> PxD_VALUE_SHIFT)));
 }
 
 #define pmd_populate(mm, pmd, pte_page) \
-	pmd_populate_kernel(mm, pmd, page_address(pte_page))
+	pmd_populate_kernel(mm, pmd, page_address(pte_page), \
+			    (unsigned long)page_to_virt(pte_page))
 
 #endif
diff --git a/arch/parisc/mm/init.c b/arch/parisc/mm/init.c
index f876af56e13f..1cf3aae67023 100644
--- a/arch/parisc/mm/init.c
+++ b/arch/parisc/mm/init.c
@@ -390,7 +390,7 @@ static void __ref map_pages(unsigned long start_vaddr,
 				pg_table = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 				if (!pg_table)
 					panic("page table allocation failed\n");
-				pmd_populate_kernel(NULL, pmd, pg_table);
+				pmd_populate_kernel(NULL, pmd, pg_table, vaddr);
 			}
 
 			pg_table = pte_offset_kernel(pmd, vaddr);
@@ -481,7 +481,7 @@ void free_initmem(void)
 	/* finally dump all the instructions which were cached, since the
 	 * pages are no-longer executable */
 	flush_icache_range(init_begin, init_end);
-	
+
 	free_initmem_default(POISON_FREE_INITMEM);
 
 	/* set up a new led state on systems shipped LED State panel */
@@ -694,7 +694,7 @@ static void __init fixmap_init(void)
 		if (!pte)
 			panic("fixmap: pte allocation failed.\n");
 
-		pmd_populate_kernel(&init_mm, pmd, pte);
+		pmd_populate_kernel(&init_mm, pmd, pte, addr);
 
 		addr += PAGE_SIZE;
 	} while (addr < end);
diff --git a/arch/powerpc/include/asm/book3s/32/pgalloc.h b/arch/powerpc/include/asm/book3s/32/pgalloc.h
index dc5c039eb28e..b85105158686 100644
--- a/arch/powerpc/include/asm/book3s/32/pgalloc.h
+++ b/arch/powerpc/include/asm/book3s/32/pgalloc.h
@@ -26,7 +26,7 @@ static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
 /* #define pgd_populate(mm, pmd, pte)      BUG() */
 
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp,
-				       pte_t *pte)
+				       pte_t *pte, unsigned long vaddr)
 {
 	*pmdp = __pmd(__pa(pte) | _PMD_PRESENT);
 }
diff --git a/arch/powerpc/include/asm/book3s/64/pgalloc.h b/arch/powerpc/include/asm/book3s/64/pgalloc.h
index dd2cff53a111..061c4be60166 100644
--- a/arch/powerpc/include/asm/book3s/64/pgalloc.h
+++ b/arch/powerpc/include/asm/book3s/64/pgalloc.h
@@ -156,7 +156,7 @@ static inline void __pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd,
 }
 
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
-				       pte_t *pte)
+				       pte_t *pte, unsigned long vaddr)
 {
 	*pmd = __pmd(__pgtable_ptr_val(pte) | PMD_VAL_BITS);
 }
diff --git a/arch/powerpc/include/asm/nohash/32/pgalloc.h b/arch/powerpc/include/asm/nohash/32/pgalloc.h
index 11eac371e7e0..2788ce005b95 100644
--- a/arch/powerpc/include/asm/nohash/32/pgalloc.h
+++ b/arch/powerpc/include/asm/nohash/32/pgalloc.h
@@ -15,7 +15,7 @@
 /* #define pgd_populate(mm, pmd, pte)      BUG() */
 
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp,
-				       pte_t *pte)
+				       pte_t *pte, unsigned long vaddr)
 {
 	if (IS_ENABLED(CONFIG_BOOKE))
 		*pmdp = __pmd((unsigned long)pte | _PMD_PRESENT);
diff --git a/arch/powerpc/include/asm/nohash/64/pgalloc.h b/arch/powerpc/include/asm/nohash/64/pgalloc.h
index e50b211becb3..d069443b4014 100644
--- a/arch/powerpc/include/asm/nohash/64/pgalloc.h
+++ b/arch/powerpc/include/asm/nohash/64/pgalloc.h
@@ -37,7 +37,7 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
 }
 
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
-				       pte_t *pte)
+				       pte_t *pte, unsigned long vaddr)
 {
 	pmd_set(pmd, (unsigned long)pte);
 }
diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/book3s64/radix_pgtable.c
index 15e88f1439ec..a70063cd6f64 100644
--- a/arch/powerpc/mm/book3s64/radix_pgtable.c
+++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
@@ -104,7 +104,7 @@ static int early_map_kernel_page(unsigned long ea, unsigned long pa,
 	if (!pmd_present(*pmdp)) {
 		ptep = early_alloc_pgtable(PAGE_SIZE, nid,
 						region_start, region_end);
-		pmd_populate_kernel(&init_mm, pmdp, ptep);
+		pmd_populate_kernel(&init_mm, pmdp, ptep, ea);
 	}
 	ptep = pte_offset_kernel(pmdp, ea);
 
diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
index aa9aa11927b2..22df07fd1af5 100644
--- a/arch/powerpc/mm/kasan/init_32.c
+++ b/arch/powerpc/mm/kasan/init_32.c
@@ -47,7 +47,7 @@ int __init kasan_init_shadow_page_tables(unsigned long k_start, unsigned long k_
 		if (!new)
 			return -ENOMEM;
 		kasan_populate_pte(new, PAGE_KERNEL);
-		pmd_populate_kernel(&init_mm, pmd, new);
+		pmd_populate_kernel(&init_mm, pmd, new, k_cur);
 	}
 	return 0;
 }
@@ -187,6 +187,6 @@ void __init kasan_early_init(void)
 
 	do {
 		next = pgd_addr_end(addr, end);
-		pmd_populate_kernel(&init_mm, pmd, kasan_early_shadow_pte);
+		pmd_populate_kernel(&init_mm, pmd, kasan_early_shadow_pte, addr);
 	} while (pmd++, addr = next, addr != end);
 }
diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
index 11519e88dc6b..05ccdb88ff51 100644
--- a/arch/powerpc/mm/kasan/init_book3e_64.c
+++ b/arch/powerpc/mm/kasan/init_book3e_64.c
@@ -54,7 +54,7 @@ static int __init kasan_map_kernel_page(unsigned long ea, unsigned long pa, pgpr
 	if (kasan_pte_table(*pmdp)) {
 		ptep = memblock_alloc(PTE_TABLE_SIZE, PTE_TABLE_SIZE);
 		memcpy(ptep, kasan_early_shadow_pte, PTE_TABLE_SIZE);
-		pmd_populate_kernel(&init_mm, pmdp, ptep);
+		pmd_populate_kernel(&init_mm, pmdp, ptep, ea);
 	}
 	ptep = pte_offset_kernel(pmdp, ea);
 
@@ -93,9 +93,12 @@ void __init kasan_early_init(void)
 		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
 			     &kasan_early_shadow_pte[i], zero_pte, 0);
 
-	for (i = 0; i < PTRS_PER_PMD; i++)
+	addr = KASAN_SHADOW_START
+	for (i = 0; i < PTRS_PER_PMD; i++) {
 		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
-				    kasan_early_shadow_pte);
+				    kasan_early_shadow_pte, addr);
+		addr += PMD_SIZE;
+	}
 
 	for (i = 0; i < PTRS_PER_PUD; i++)
 		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index 9300d641cf9a..79569734dc29 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -55,6 +55,7 @@ void __init kasan_init(void)
 	phys_addr_t start, end;
 	u64 i;
 	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL);
+	void *vaddr_start = __va(start);
 
 	if (!early_radix_enabled()) {
 		pr_warn("KASAN not enabled as it requires radix!");
@@ -68,9 +69,11 @@ void __init kasan_init(void)
 		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
 			     &kasan_early_shadow_pte[i], zero_pte, 0);
 
-	for (i = 0; i < PTRS_PER_PMD; i++)
+	for (i = 0; i < PTRS_PER_PMD; i++) {
 		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
-				    kasan_early_shadow_pte);
+				    kasan_early_shadow_pte,
+				    vaddr_start + i * PMD_SIZE);
+	}
 
 	for (i = 0; i < PTRS_PER_PUD; i++)
 		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
diff --git a/arch/powerpc/mm/nohash/book3e_pgtable.c b/arch/powerpc/mm/nohash/book3e_pgtable.c
index 1c5e4ecbebeb..930bdd7a3774 100644
--- a/arch/powerpc/mm/nohash/book3e_pgtable.c
+++ b/arch/powerpc/mm/nohash/book3e_pgtable.c
@@ -107,7 +107,7 @@ int __ref map_kernel_page(unsigned long ea, phys_addr_t pa, pgprot_t prot)
 		pmdp = pmd_offset(pudp, ea);
 		if (!pmd_present(*pmdp)) {
 			ptep = early_alloc_pgtable(PTE_TABLE_SIZE);
-			pmd_populate_kernel(&init_mm, pmdp, ptep);
+			pmd_populate_kernel(&init_mm, pmdp, ptep, ea);
 		}
 		ptep = pte_offset_kernel(pmdp, ea);
 	}
diff --git a/arch/powerpc/mm/pgtable_32.c b/arch/powerpc/mm/pgtable_32.c
index cfd622ebf774..e6fbaf3e9072 100644
--- a/arch/powerpc/mm/pgtable_32.c
+++ b/arch/powerpc/mm/pgtable_32.c
@@ -43,7 +43,7 @@ notrace void __init early_ioremap_init(void)
 
 	for (; (s32)(FIXADDR_TOP - addr) > 0;
 	     addr += PGDIR_SIZE, ptep += PTRS_PER_PTE, pmdp++)
-		pmd_populate_kernel(&init_mm, pmdp, ptep);
+		pmd_populate_kernel(&init_mm, pmdp, ptep, addr);
 
 	early_ioremap_setup();
 }
@@ -64,7 +64,7 @@ pte_t __init *early_pte_alloc_kernel(pmd_t *pmdp, unsigned long va)
 	if (pmd_none(*pmdp)) {
 		pte_t *ptep = early_alloc_pgtable(PTE_FRAG_SIZE);
 
-		pmd_populate_kernel(&init_mm, pmdp, ptep);
+		pmd_populate_kernel(&init_mm, pmdp, ptep, va);
 	}
 	return pte_offset_kernel(pmdp, va);
 }
diff --git a/arch/riscv/include/asm/pgalloc.h b/arch/riscv/include/asm/pgalloc.h
index deaf971253a2..d619daeded7f 100644
--- a/arch/riscv/include/asm/pgalloc.h
+++ b/arch/riscv/include/asm/pgalloc.h
@@ -16,7 +16,7 @@
 #include <asm-generic/pgalloc.h>
 
 static inline void pmd_populate_kernel(struct mm_struct *mm,
-	pmd_t *pmd, pte_t *pte)
+	pmd_t *pmd, pte_t *pte, unsigned long vaddr)
 {
 	unsigned long pfn = virt_to_pfn(pte);
 
diff --git a/arch/riscv/kernel/hibernate.c b/arch/riscv/kernel/hibernate.c
index 671b686c0158..085123ad4fa8 100644
--- a/arch/riscv/kernel/hibernate.c
+++ b/arch/riscv/kernel/hibernate.c
@@ -176,7 +176,7 @@ static int temp_pgtable_map_pte(pmd_t *dst_pmdp, pmd_t *src_pmdp, unsigned long
 		if (!dst_ptep)
 			return -ENOMEM;
 
-		pmd_populate_kernel(NULL, dst_pmdp, dst_ptep);
+		pmd_populate_kernel(NULL, dst_pmdp, dst_ptep, 0);
 	}
 
 	dst_ptep = pte_offset_kernel(dst_pmdp, start);
diff --git a/arch/s390/include/asm/pgalloc.h b/arch/s390/include/asm/pgalloc.h
index 7b84ef6dc4b6..4143b3f9d610 100644
--- a/arch/s390/include/asm/pgalloc.h
+++ b/arch/s390/include/asm/pgalloc.h
@@ -131,7 +131,7 @@ static inline void pmd_populate(struct mm_struct *mm,
 	set_pmd(pmd, __pmd(_SEGMENT_ENTRY | __pa(pte)));
 }
 
-#define pmd_populate_kernel(mm, pmd, pte) pmd_populate(mm, pmd, pte)
+#define pmd_populate_kernel(mm, pmd, pte, vaddr) pmd_populate(mm, pmd, pte)
 
 /*
  * page table entry allocation/free routines.
diff --git a/arch/sh/include/asm/pgalloc.h b/arch/sh/include/asm/pgalloc.h
index 5d8577ab1591..04b29eb9712b 100644
--- a/arch/sh/include/asm/pgalloc.h
+++ b/arch/sh/include/asm/pgalloc.h
@@ -21,7 +21,7 @@ extern void pmd_free(struct mm_struct *mm, pmd_t *pmd);
 #endif
 
 static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
-				       pte_t *pte)
+				       pte_t *pte, unsigned long vaddr)
 {
 	set_pmd(pmd, __pmd((unsigned long)pte));
 }
diff --git a/arch/sh/mm/init.c b/arch/sh/mm/init.c
index bf1b54055316..c862572dbec8 100644
--- a/arch/sh/mm/init.c
+++ b/arch/sh/mm/init.c
@@ -157,7 +157,7 @@ static pte_t * __init one_page_table_init(pmd_t *pmd)
 		if (!pte)
 			panic("%s: Failed to allocate %lu bytes align=0x%lx\n",
 			      __func__, PAGE_SIZE, PAGE_SIZE);
-		pmd_populate_kernel(&init_mm, pmd, pte);
+		pmd_populate_kernel(&init_mm, pmd, pte, 0);
 		BUG_ON(pte != pte_offset_kernel(pmd, 0));
 	}
 
diff --git a/arch/sparc/include/asm/pgalloc_32.h b/arch/sparc/include/asm/pgalloc_32.h
index 4f73e87b22a3..558afcbd9016 100644
--- a/arch/sparc/include/asm/pgalloc_32.h
+++ b/arch/sparc/include/asm/pgalloc_32.h
@@ -53,7 +53,8 @@ static inline void free_pmd_fast(pmd_t * pmd)
 #define pmd_populate(mm, pmd, pte)	pmd_set(pmd, pte)
 
 void pmd_set(pmd_t *pmdp, pte_t *ptep);
-#define pmd_populate_kernel		pmd_populate
+#define pmd_populate_kernel(mm, pmd, pte, vaddr)	\
+	pmd_populate(mm, pmd, pte)
 
 pgtable_t pte_alloc_one(struct mm_struct *mm);
 
diff --git a/arch/sparc/include/asm/pgalloc_64.h b/arch/sparc/include/asm/pgalloc_64.h
index caa7632be4c2..185ad9637442 100644
--- a/arch/sparc/include/asm/pgalloc_64.h
+++ b/arch/sparc/include/asm/pgalloc_64.h
@@ -69,8 +69,8 @@ void pte_free(struct mm_struct *mm, pgtable_t ptepage);
 #define pte_free_defer pte_free_defer
 void pte_free_defer(struct mm_struct *mm, pgtable_t pgtable);
 
-#define pmd_populate_kernel(MM, PMD, PTE)	pmd_set(MM, PMD, PTE)
-#define pmd_populate(MM, PMD, PTE)		pmd_set(MM, PMD, PTE)
+#define pmd_populate_kernel(MM, PMD, PTE, VADDR)	pmd_set(MM, PMD, PTE)
+#define pmd_populate(MM, PMD, PTE)			pmd_set(MM, PMD, PTE)
 
 void pgtable_free(void *table, bool is_page);
 
diff --git a/arch/sparc/mm/init_64.c b/arch/sparc/mm/init_64.c
index 1ca9054d9b97..32b3c89f869d 100644
--- a/arch/sparc/mm/init_64.c
+++ b/arch/sparc/mm/init_64.c
@@ -5,7 +5,7 @@
  *  Copyright (C) 1996-1999 David S. Miller (davem@caip.rutgers.edu)
  *  Copyright (C) 1997-1999 Jakub Jelinek (jj@sunsite.mff.cuni.cz)
  */
- 
+
 #include <linux/extable.h>
 #include <linux/kernel.h>
 #include <linux/sched.h>
@@ -1843,7 +1843,7 @@ static unsigned long __ref kernel_map_range(unsigned long pstart,
 			if (!new)
 				goto err_alloc;
 			alloc_bytes += PAGE_SIZE;
-			pmd_populate_kernel(&init_mm, pmd, new);
+			pmd_populate_kernel(&init_mm, pmd, new, vstart);
 		}
 
 		pte = pte_offset_kernel(pmd, vstart);
@@ -2404,11 +2404,11 @@ void __init paging_init(void)
 	 * work.
 	 */
 	init_mm.pgd += ((shift) / (sizeof(pgd_t)));
-	
+
 	memset(swapper_pg_dir, 0, sizeof(swapper_pg_dir));
 
 	inherit_prom_mappings();
-	
+
 	/* Ok, we can use our TLB miss and window trap handlers safely.  */
 	setup_tba();
 
diff --git a/arch/um/include/asm/pgalloc.h b/arch/um/include/asm/pgalloc.h
index de5e31c64793..300431ff61bb 100644
--- a/arch/um/include/asm/pgalloc.h
+++ b/arch/um/include/asm/pgalloc.h
@@ -1,5 +1,5 @@
 /* SPDX-License-Identifier: GPL-2.0 */
-/* 
+/*
  * Copyright (C) 2000, 2001, 2002 Jeff Dike (jdike@karaya.com)
  * Copyright 2003 PathScale, Inc.
  * Derived from include/asm-i386/pgalloc.h and include/asm-i386/pgtable.h
@@ -12,7 +12,7 @@
 
 #include <asm-generic/pgalloc.h>
 
-#define pmd_populate_kernel(mm, pmd, pte) \
+#define pmd_populate_kernel(mm, pmd, pte, vaddr) \
 	set_pmd(pmd, __pmd(_PAGE_TABLE + (unsigned long) __pa(pte)))
 
 #define pmd_populate(mm, pmd, pte) 				\
diff --git a/arch/x86/include/asm/pgalloc.h b/arch/x86/include/asm/pgalloc.h
index dcd836b59beb..3bc5e0cc7b38 100644
--- a/arch/x86/include/asm/pgalloc.h
+++ b/arch/x86/include/asm/pgalloc.h
@@ -62,7 +62,8 @@ static inline void __pte_free_tlb(struct mmu_gather *tlb, struct page *pte,
 }
 
 static inline void pmd_populate_kernel(struct mm_struct *mm,
-				       pmd_t *pmd, pte_t *pte)
+				       pmd_t *pmd, pte_t *pte,
+				       unsigned long vaddr)
 {
 	paravirt_alloc_pte(mm, __pa(pte) >> PAGE_SHIFT);
 	set_pmd(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
index 7e177856ee4f..ee4a73842466 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -73,7 +73,15 @@ static inline void fname##_init(struct mm_struct *mm,		\
 DEFINE_POPULATE(p4d_populate, p4d, pud, init)
 DEFINE_POPULATE(pgd_populate, pgd, p4d, init)
 DEFINE_POPULATE(pud_populate, pud, pmd, init)
-DEFINE_POPULATE(pmd_populate_kernel, pmd, pte, init)
+
+static inline void pmd_populate_kernel_init(struct mm_struct *mm,
+		pmd_t *arg1, pte_t *arg2, unsigned long arg3, bool init)
+{
+	if (init)
+		pmd_populate_kernel_safe(mm, arg1, arg2);
+	else
+		pmd_populate_kernel(mm, arg1, arg2, arg3);
+}
 
 #define DEFINE_ENTRY(type1, type2, init)			\
 static inline void set_##type1##_init(type1##_t *arg1,		\
@@ -286,7 +294,7 @@ static pte_t *fill_pte(pmd_t *pmd, unsigned long vaddr)
 {
 	if (pmd_none(*pmd)) {
 		pte_t *pte = (pte_t *) spp_getpage();
-		pmd_populate_kernel(&init_mm, pmd, pte);
+		pmd_populate_kernel(&init_mm, pmd, pte, vaddr);
 		if (pte != pte_offset_kernel(pmd, 0))
 			printk(KERN_ERR "PAGETABLE BUG #03!\n");
 	}
@@ -575,7 +583,7 @@ phys_pmd_init(pmd_t *pmd_page, unsigned long paddr, unsigned long paddr_end,
 		paddr_last = phys_pte_init(pte, paddr, paddr_end, new_prot, init);
 
 		spin_lock(&init_mm.page_table_lock);
-		pmd_populate_kernel_init(&init_mm, pmd, pte, init);
+		pmd_populate_kernel_init(&init_mm, pmd, pte, init, __va(paddr));
 		spin_unlock(&init_mm.page_table_lock);
 	}
 	update_page_count(PG_LEVEL_2M, pages);
diff --git a/arch/x86/mm/ioremap.c b/arch/x86/mm/ioremap.c
index aa7d279321ea..8844047fdaad 100644
--- a/arch/x86/mm/ioremap.c
+++ b/arch/x86/mm/ioremap.c
@@ -888,7 +888,7 @@ void __init early_ioremap_init(void)
 
 	pmd = early_ioremap_pmd(fix_to_virt(FIX_BTMAP_BEGIN));
 	memset(bm_pte, 0, sizeof(bm_pte));
-	pmd_populate_kernel(&init_mm, pmd, bm_pte);
+	pmd_populate_kernel(&init_mm, pmd, bm_pte, fix_to_virt(FIX_BTMAP_BEGIN));
 
 	/*
 	 * The boot-ioremap range spans multiple pmds, for which
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 9dddf19a5571..95ae9e12fe41 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -53,7 +53,7 @@ static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
 		}
 
 		p = early_alloc(PAGE_SIZE, nid, true);
-		pmd_populate_kernel(&init_mm, pmd, p);
+		pmd_populate_kernel(&init_mm, pmd, p, addr);
 	}
 
 	pte = pte_offset_kernel(pmd, addr);
diff --git a/arch/xtensa/include/asm/pgalloc.h b/arch/xtensa/include/asm/pgalloc.h
index 7fc0f9126dd3..5359e4091b9a 100644
--- a/arch/xtensa/include/asm/pgalloc.h
+++ b/arch/xtensa/include/asm/pgalloc.h
@@ -21,7 +21,7 @@
  * inside the pgd, so has no extra memory associated with it.
  */
 
-#define pmd_populate_kernel(mm, pmdp, ptep)				     \
+#define pmd_populate_kernel(mm, pmdp, ptep, vaddr)			     \
 	(pmd_val(*(pmdp)) = ((unsigned long)ptep))
 #define pmd_populate(mm, pmdp, page)					     \
 	(pmd_val(*(pmdp)) = ((unsigned long)page_to_virt(page)))
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 7b0ee64225de..7162667c0e37 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2802,7 +2802,7 @@ static inline void mm_dec_nr_ptes(struct mm_struct *mm) {}
 #endif
 
 int __pte_alloc(struct mm_struct *mm, pmd_t *pmd);
-int __pte_alloc_kernel(pmd_t *pmd);
+int __pte_alloc_kernel(pmd_t *pmd, unsigned long vaddr);
 
 #if defined(CONFIG_MMU)
 
@@ -2997,7 +2997,7 @@ pte_t *pte_offset_map_nolock(struct mm_struct *mm, pmd_t *pmd,
 		 NULL : pte_offset_map_lock(mm, pmd, address, ptlp))
 
 #define pte_alloc_kernel(pmd, address)			\
-	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd))? \
+	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd, address))? \
 		NULL: pte_offset_kernel(pmd, address))
 
 #if USE_SPLIT_PMD_PTLOCKS
diff --git a/mm/hugetlb_vmemmap.c b/mm/hugetlb_vmemmap.c
index da177e49d956..cfbe3695fffb 100644
--- a/mm/hugetlb_vmemmap.c
+++ b/mm/hugetlb_vmemmap.c
@@ -58,7 +58,7 @@ static int vmemmap_split_pmd(pmd_t *pmd, struct page *head, unsigned long start,
 	if (!pgtable)
 		return -ENOMEM;
 
-	pmd_populate_kernel(&init_mm, &__pmd, pgtable);
+	pmd_populate_kernel(&init_mm, &__pmd, pgtable, start);
 
 	for (i = 0; i < PTRS_PER_PTE; i++, addr += PAGE_SIZE) {
 		pte_t entry, *pte;
@@ -81,7 +81,7 @@ static int vmemmap_split_pmd(pmd_t *pmd, struct page *head, unsigned long start,
 
 		/* Make pte visible before pmd. See comment in pmd_install(). */
 		smp_wmb();
-		pmd_populate_kernel(&init_mm, pmd, pgtable);
+		pmd_populate_kernel(&init_mm, pmd, pgtable, start);
 		if (!(walk->flags & VMEMMAP_SPLIT_NO_TLB_FLUSH))
 			flush_tlb_kernel_range(start, start + PMD_SIZE);
 	} else {
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 89895f38f722..813f8e8a801c 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -117,7 +117,8 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 
 		if (IS_ALIGNED(addr, PMD_SIZE) && end - addr >= PMD_SIZE) {
 			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+					lm_alias(kasan_early_shadow_pte),
+					addr);
 			continue;
 		}
 
@@ -131,7 +132,7 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 			if (!p)
 				return -ENOMEM;
 
-			pmd_populate_kernel(&init_mm, pmd, p);
+			pmd_populate_kernel(&init_mm, pmd, p, addr);
 		}
 		zero_pte_populate(pmd, addr, next);
 	} while (pmd++, addr = next, addr != end);
@@ -158,7 +159,8 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
 			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+					lm_alias(kasan_early_shadow_pte),
+					addr);
 			continue;
 		}
 
@@ -204,7 +206,8 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
 			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+					lm_alias(kasan_early_shadow_pte),
+					addr);
 			continue;
 		}
 
@@ -267,7 +270,8 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
 			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+					lm_alias(kasan_early_shadow_pte),
+					addr);
 			continue;
 		}
 
diff --git a/mm/memory.c b/mm/memory.c
index d2155ced45f8..67807ade9a0e 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -447,7 +447,7 @@ int __pte_alloc(struct mm_struct *mm, pmd_t *pmd)
 	return 0;
 }
 
-int __pte_alloc_kernel(pmd_t *pmd)
+int __pte_alloc_kernel(pmd_t *pmd, unsigned long vaddr)
 {
 	pte_t *new = pte_alloc_one_kernel(&init_mm);
 	if (!new)
@@ -456,7 +456,7 @@ int __pte_alloc_kernel(pmd_t *pmd)
 	spin_lock(&init_mm.page_table_lock);
 	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
 		smp_wmb(); /* See comment in pmd_install() */
-		pmd_populate_kernel(&init_mm, pmd, new);
+		pmd_populate_kernel(&init_mm, pmd, new, vaddr);
 		new = NULL;
 	}
 	spin_unlock(&init_mm.page_table_lock);
diff --git a/mm/percpu.c b/mm/percpu.c
index 4e11fc1e6def..fc83cf64baf6 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3238,7 +3238,7 @@ void __init __weak pcpu_populate_pte(unsigned long addr)
 		new = memblock_alloc(PTE_TABLE_SIZE, PTE_TABLE_SIZE);
 		if (!new)
 			goto err_alloc;
-		pmd_populate_kernel(&init_mm, pmd, new);
+		pmd_populate_kernel(&init_mm, pmd, new, addr);
 	}
 
 	return;
diff --git a/mm/pgalloc-track.h b/mm/pgalloc-track.h
index e9e879de8649..ac983705a054 100644
--- a/mm/pgalloc-track.h
+++ b/mm/pgalloc-track.h
@@ -45,7 +45,8 @@ static inline pmd_t *pmd_alloc_track(struct mm_struct *mm, pud_t *pud,
 
 #define pte_alloc_kernel_track(pmd, address, mask)			\
 	((unlikely(pmd_none(*(pmd))) &&					\
-	  (__pte_alloc_kernel(pmd) || ({*(mask)|=PGTBL_PMD_MODIFIED;0;})))?\
+	  (__pte_alloc_kernel(pmd, address) ||				\
+	   ({*(mask)|=PGTBL_PMD_MODIFIED;0;})))?\
 		NULL: pte_offset_kernel(pmd, address))
 
 #endif /* _LINUX_PGALLOC_TRACK_H */
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index a2cbe44c48e1..6085c8339b65 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -191,7 +191,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
 		if (!p)
 			return NULL;
-		pmd_populate_kernel(&init_mm, pmd, p);
+		pmd_populate_kernel(&init_mm, pmd, p, addr);
 	}
 	return pmd;
 }
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240416120827.062020959-4-mbland%40motorola.com.
