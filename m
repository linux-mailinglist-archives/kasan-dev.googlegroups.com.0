Return-Path: <kasan-dev+bncBAABBPUO53VAKGQE4ELZN6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 21B89956B9
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 07:38:07 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id x130sf2586332vkc.19
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 22:38:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566279486; cv=pass;
        d=google.com; s=arc-20160816;
        b=ldUsgEEl95a+BZT1U6PCjTpHB8CoxceQuNk4I7PtIK5awDtM5QoMaW486iFiyCAKtE
         pO6g+lbMvtx6K7MHbnxqM2yu9HxqkRQkCRo0GPktrJrHTY7381cjGdK7JFd6uEX43fuU
         vxAuwrtpCUbI+pm66KhNYuPaRXR9degGDVNhv4Hz48n0/4ooiyt1dY9LB8ls7Fg7fHmx
         GcvDk95bny9Oi2s7fJCYBHT8jefLo8iTdz2IKuDyqlEiEkST1YjDSJkpg3Sj8b8j3TL1
         MDTOR1CgwLujPdz1HqDUz3zkhuuui+H0UoOjaQVR712pQJtrMRXbiatoWa00bwjEtNgB
         aWGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=hK9acWsQaLakZV/hkOiKIqKHJevB8uOV5ZiqQnXbfNY=;
        b=MN/nFfwGg/G6uF3tvUwKI+6l4LgEb34gjpFhEY36Xc4g1WuxFx9Hl9uJ66DmsDBGej
         aysqNRfOtjEMqiR1DgRnLj7uuLva5uQLf8lBwjX7mkeEaD5c17kaipOsir9klplHupPa
         KK8ewKUxCjjKzGHu/rzJgQN/UKUp15WW3cwgNjzJ1FriwA2LGF7kr/ZH4omd9x6bEAOM
         FefaXteUplmJqcdpOiaaxOJ5oFOoZ3ZAaJURWh2fEt5vwQuphJHZi7D08ClJoZF03z4Y
         H/ivc9Gu2fM1a6BP6VzO96fQCx7mLU1N85DaIAQC5TuykPZL6kzl+oowlYy++1Q+B/2I
         cf6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hK9acWsQaLakZV/hkOiKIqKHJevB8uOV5ZiqQnXbfNY=;
        b=ZpJLXBPCAyjZ3hQRNYFMCNesL9s/uOv9mREhh84t+/wib5Ems37B8DlLvF6JcWve7A
         aTPtiP+4qyb4i0jKtexGk1H6tIEP6k7hUtJLRfNRwaipuaJ1gxWAfVWe+2k8pxyoF5DL
         RUdPMZD6nGkDuE+AazV8fwYG4Livhhpu09pneYgkTU93XGBgNroV2h/uFT8lIvNA/oij
         RK1q5tpzHEzsOYaDQsLOiSqHObTsgFVi0n5CkSzEA45GJEAonmLY7le6rOMFKKfSqKMJ
         PFoPqSfG57xDsuPI31BrzQAXOrmVy9fntNW6uXiiuQaektZETbY1SFpcIB+lBFT/OT9u
         ik/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hK9acWsQaLakZV/hkOiKIqKHJevB8uOV5ZiqQnXbfNY=;
        b=cR5r4ypT0iKO1zZStJ/7CVcOriTN9odXBb/nUZ2A2ueDQkOAjtSYORnLnjgH7Ha14j
         DOBNPt0l1LDsH5oK6jTWgV8xaov00mWpYC1bHqd3pQpKsoC5B8QQ0f+crSAgA81rEuhF
         0hNRdinCFt8YG8C3q3/Nv7uPrf7Rp9cqlrgzdylsT6QnSrAjtah5IIDVAv5WC5KQIFYa
         aZCWqDV6c4ymkHG8dBJWkVvfNeVUssp5qrZFp++SiIPk5zrpWrY8DJeTt921IdMc7PHY
         W9N30DP5UmwJ/9QGLynlxQJ7s45efnn0E+eSyBDCs+tLenGMG93BntIx/mBT1O1uhYzU
         yrSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXckQcg6Ro5QUi89r33egu7DUGfemVWr/HRI17tYph00Eyw6Oo3
	oAdO5mWxsz2DQgih4f5WP4g=
X-Google-Smtp-Source: APXvYqwCYA284A0eSbpwbBE5hMuSzMKWfN5zNkFj2/ztPWTCffKNSIWNwgAj9KvAuycaKlHb5dKPTw==
X-Received: by 2002:a67:ee98:: with SMTP id n24mr1304742vsp.92.1566279486203;
        Mon, 19 Aug 2019 22:38:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6043:: with SMTP id o3ls1111479ual.1.gmail; Mon, 19 Aug
 2019 22:38:05 -0700 (PDT)
X-Received: by 2002:ab0:1c0c:: with SMTP id a12mr9387891uaj.75.1566279485980;
        Mon, 19 Aug 2019 22:38:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566279485; cv=none;
        d=google.com; s=arc-20160816;
        b=Y5WQw/TbLtwVlVEumcsuId9FZaIEEHWIGW8AM2FhXQZmwjmq0sGQttc6faIu63fb2n
         tHTivelVPNUym/du9mVVWvlyFOHIaHayHevo2vMh+bf8Bpg1e8zecSyHr/41uL63zP+m
         VIZKHtq7McnbkLAa19kH5TMewnMNBtxsQWaEQDPZY981fPvdMxLfLODTujZNP0KyKYqL
         G8TECv91tx1ZFMMEMYo35F0v5zhrWLJD70npLGWxD2HJ5JcSJ4apgR4RgApH9ryBYNwP
         rXIDrJ/wYZLvtbK0zlDsVESU7zP6Wthd6bmKgfrNJp//2M2wuucZWI7X1uivc06mWkPM
         BFwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=aiutwDXcYz8gtA0jVSRs05N+s/bv8JEDTTBbKXPE3wg=;
        b=LweWD/LsO+wHk2o2/OOxNAUGStE+9nbUAN8JcYVKnn13TT5R3FDGV6U9XukDVwxBtK
         C7IH9mpo2J/5mdynqea35/H1cGDN+lbHWC7GpGW4ic2v0cuGr2Jh4sLzypCXnVLvb3We
         d86fZsx9Eu6Yc693/7D2NxGrnK0fbf8r0n/H3oqPeGsPXUQMTGdTNJFvpHqHFqh4WnLd
         YOc3DYKH9vGbS0/Yw/jdgpL9W8OPicqxsAOyBjGeDvIr84RoHEt4BMP9dUdVSon5Zz3M
         LQ7pL7zPi9vEsfvwawL+YJOG1OrBEFIR3nQbxToPsxgsNxEcUlqOt1l7ddHXQ3uL7dCi
         sfOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id a128si879884vkh.1.2019.08.19.22.38.04
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 22:38:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0758c9be4181404e9004a4f966717179-20190820
X-UUID: 0758c9be4181404e9004a4f966717179-20190820
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0707 with TLS)
	with ESMTP id 757742129; Tue, 20 Aug 2019 13:37:58 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 20 Aug 2019 13:37:57 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 20 Aug 2019 13:37:57 +0800
Message-ID: <1566279478.9993.21.camel@mtksdccf07>
Subject: Re: [PATCH v4] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Martin Schwidefsky
	<schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner
	<tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov
	<andreyknvl@google.com>, Miles Chen <miles.chen@mediatek.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Tue, 20 Aug 2019 13:37:58 +0800
In-Reply-To: <20190806054340.16305-1-walter-zh.wu@mediatek.com>
References: <20190806054340.16305-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2019-08-06 at 13:43 +0800, Walter Wu wrote:
> This patch adds memory corruption identification at bug report for
> software tag-based mode, the report show whether it is "use-after-free"
> or "out-of-bound" error instead of "invalid-access" error. This will make
> it easier for programmers to see the memory corruption problem.
> 
> We extend the slab to store five old free pointer tag and free backtrace,
> we can check if the tagged address is in the slab record and make a
> good guess if the object is more like "use-after-free" or "out-of-bound".
> therefore every slab memory corruption can be identified whether it's
> "use-after-free" or "out-of-bound".
> 
> ====== Changes
> Change since v1:
> - add feature option CONFIG_KASAN_SW_TAGS_IDENTIFY.
> - change QUARANTINE_FRACTION to reduce quarantine size.
> - change the qlist order in order to find the newest object in quarantine
> - reduce the number of calling kmalloc() from 2 to 1 time.
> - remove global variable to use argument to pass it.
> - correct the amount of qobject cache->size into the byes of qlist_head.
> - only use kasan_cache_shrink() to shink memory.
> 
> Change since v2:
> - remove the shinking memory function kasan_cache_shrink()
> - modify the description of the CONFIG_KASAN_SW_TAGS_IDENTIFY
> - optimize the quarantine_find_object() and qobject_free()
> - fix the duplicating function name 3 times in the header.
> - modify the function name set_track() to kasan_set_track()
> 
> Change since v3:
> - change tag-based quarantine to extend slab to identify memory corruption

Hi,Andrey,

Would you review the patch,please?
This patch is to pre-allocate slub record(tag and free backtrace) during
create slub object. When kernel has memory corruption, it will print
correct corruption type and free backtrace.

Thanks.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1566279478.9993.21.camel%40mtksdccf07.
