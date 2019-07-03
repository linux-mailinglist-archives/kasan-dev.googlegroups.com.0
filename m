Return-Path: <kasan-dev+bncBCAKHU6U2ENBBDPN6DUAKGQEPUGJA3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 04BDA5DDA3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 07:01:02 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id a19sf219112ljk.18
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 22:01:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562130061; cv=pass;
        d=google.com; s=arc-20160816;
        b=iLkS28MyHkDwsW1S/xa+lRp9y/xwDHhXQXcBG8VolFtiXE7cFog/xf3jL86HN6agTA
         aO1NCPPHLEZNDNYYU5j6bAYFX/DKt5xuKzoCrSVZLZjWb0G6AK4R2/XNF8wCWZzzFWw3
         d/Ez+Hb7TP+hrz0odUgshKCK/C9dBrP9ODjLFUgtxXaXx6WJbpGEtbKHlk4kNPiWhHV7
         BFyM1DlKPWFsqHq7bzut69K6jPSrPP4RSSYUF6kcZXDxB1BC9Q1cos+PjfcAlYXoZOmy
         K7cTMJAFYw/Mb0QzFhKMKRtVv3sBZ2JCHs3tSuIpnDLBD3jIp1/ICprC5jsxlgXlAEd0
         2VTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=TbBbpGvbtC+bYG8eVrvqxg9fcmhqb4VeqKOlNyGbKvk=;
        b=dAGmTv2HYlbIOqW+kmJj9ooVn6RsbfCVtU4xkkdQQ4BocSJAqpQ+tXy8TGuoy1rAgj
         te+bXywlwrOCawlqh0uOO/LpS+U/fffImuzfmdn0Iesa1pZgtFyO+yT8mVO8glqC7kQA
         Mx0crDD7Z4YmZXA+2wgsLAPQRfbKczclyubFeYtWmW/VaTVrbus3v0mow2UYWHfI4JcY
         lGxuQofI85VOotqXDjokRALcdMFclfzoGjdjsBiOdpai9cHcwjAduq8yhMhCGEblEg/0
         peN7q3lU3TZ+6EMQ4zyinWt0f5n1BrjCyYwcD1w6VuJ756D6uJoIBW4UhQiX+BBPKW+a
         jpvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tx6eDsBz;
       spf=pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TbBbpGvbtC+bYG8eVrvqxg9fcmhqb4VeqKOlNyGbKvk=;
        b=HsXkMIMQUz9Iz+kXBUGXZkh9QgeMOcPJYFZy8RZPjyijt6wJOqPqhEynz97lVDVgmH
         zINMZIpfzFIvG/2yH1pZJAuxVB5tpAQYd1Og591W96YajlQ/eVxwpjFa0P6kQbHhd55Y
         hlFvP8pSVjfEB75R2JaW4j49A3F4QLPyirKxaU7v+dQmbeDI9ZDVL2wwONzpZCDvoqvT
         BFxEk8S5+BB5PnUbXao9t0NKNEsLp/pDfz+NJyJEvrsV/aH1D4i3FIunhhQWoq8bcqq/
         wBBO3WDpxAGF3+ni2I1TMm9X/uqqP+qvWK+P5+aRUvmcF03kzWStUwjR418c4d6PxIH0
         YZ+g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TbBbpGvbtC+bYG8eVrvqxg9fcmhqb4VeqKOlNyGbKvk=;
        b=rx45gJa9aWCkgGeLK+AwL9SpjOg3ctYXKp1gMUCkV255wz6K1zCbkBkdPEfrukz6ty
         xruTw2HmqA6m/7926yFpfEQW6XiOiS+mLxQATwoOH3NoL9meDQjvU4lnYn8rIFf+EmZj
         duTfaH6pi/q662539bMixCRjgL3Gz1BeR7CKon+uENk/CWyNyKrdJIhnQpcyAf2i+Hhh
         JE6W6Z4ZBHlWPA0XEo7icgcZftWh+LEVDUbvQe3x+lD0RUxnaz9u+DReVrJmh3ZeUWz0
         jDALmOgcFELL5Eq7KMdvj2UxUEtETAAbhqo4dKV0Un7a/BvvDbXj0dW0KMBuuiB9Bakq
         vRxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TbBbpGvbtC+bYG8eVrvqxg9fcmhqb4VeqKOlNyGbKvk=;
        b=qAhgALX/cBedjm3/JgXQQI7U7ndvuDu6L6T5lQtcWuO+LNusyCTh22o6SOF47EoC97
         KD0uNhNWwfxftjlFkMkIpdu0yiTtwaOYciJhN1q2o9N0s54xqbnf03UQXpdd+Ixw8CD1
         F81KOAniU3utMSptIOo9MgHDoDE2F0A59XMgawygpCpHLe1RH0nN0oA8nyPgs8j6ZuO5
         gwkfsP4cu50gg4fb4nZjvDCK8us343qeK2MUklzjuHT+WsRjYHhUBCbTyqdNnGUkJxmb
         jk95nA2oeFDgmQqVs0SAqf0kJOFbzcacalWeS93UXEHFAZxWDnWPkrieTwN92XQnvvP7
         BwDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVVyY3ro8g7fHDtVlJmfI7KxLrk//7PiUQ+1fFNKDb23tOdLltH
	oubaIUY9rjHsRLTk0WTMIu8=
X-Google-Smtp-Source: APXvYqy0piUcKv8pqam5JGRI0lgUi/RpebzdxYOKTelIc1UxG7cFS4xTciqYinVofDHkjoBiNtUfUg==
X-Received: by 2002:a2e:a171:: with SMTP id u17mr12892069ljl.209.1562130061607;
        Tue, 02 Jul 2019 22:01:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:9744:: with SMTP id z65ls61912lfd.16.gmail; Tue, 02 Jul
 2019 22:01:01 -0700 (PDT)
X-Received: by 2002:a19:c6d4:: with SMTP id w203mr3838069lff.135.1562130061047;
        Tue, 02 Jul 2019 22:01:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562130061; cv=none;
        d=google.com; s=arc-20160816;
        b=t3sHOogFKRdPcNitnMMb78234wpz8zpUdhhrIGVN/ZqIun0COt45/q2KzcK5+DeQjz
         HGhns1arkZyN6r4lqS6M8xfqb38cRLfOI8S8Rpd7aYTPsFlzarxmxTkwsjOC0LRnWHnN
         7am+nj3UHB1yVTspx2jggrRw6FM9YmXfT4J8hn5Ejel5Jlj8eFkzL7YBSNahTkw7AJPk
         YCBjCb5UL2i2qbxslm3tp8vQum4yLl9X6HZv2ySMZji7tRYTgNEHLQ5BqJcF38NetdLc
         GXtew8preByoAcVnIxou7/V59pg6wO/f9vBsKYuXKsuVP051NP6vuPpo8yJBDxBkpQ7d
         xm9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=uXILuLcFiq1ddPvV4XfK2jZrnNnzvY9H4Zq4sAIcaKM=;
        b=UT/7qE071wXiU4HRkUDAhOb1XUvtKYSJ3pYmtUXSmT8eNP4PzRu/lgDkgXSc4xy7Kd
         jnsJkyOHmnDRAWpzuf9ZTGItlDKEEiFuusXQzW0W1sdpstY6wgfMh1lUb7hGytAH2DqR
         x7lZKhHpcW73sQr16QfMwqjXGundu7ViTK6K2p4H/bMeZ9L6fezVrL5l60+o0fHo0poa
         XhyyUiYOTnZX/NPRW7J7PrVsQWDGD0tWDF60VfSfJJQ35vx46E/5CFxLnP4MW2rsn8pT
         g08N67Yf4ypJGB040n3gc2Sw0fwT/Cuj4Kn3M1e9uPr+Xboi3A6O7eu9TQbnnDiZWDye
         TrAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tx6eDsBz;
       spf=pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id m84si40336lje.1.2019.07.02.22.01.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 22:01:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id r15so723326lfm.11
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 22:01:01 -0700 (PDT)
X-Received: by 2002:a19:c7ca:: with SMTP id x193mr2633693lff.151.1562130060687;
 Tue, 02 Jul 2019 22:01:00 -0700 (PDT)
MIME-Version: 1.0
From: Anatol Pomozov <anatol.pomozov@gmail.com>
Date: Tue, 2 Jul 2019 22:00:49 -0700
Message-ID: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
Subject: KTSAN and Linux semaphores
To: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anatol.pomozov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=tx6eDsBz;       spf=pass
 (google.com: domain of anatol.pomozov@gmail.com designates
 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
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

Hi

I am working on getting KernelThreadSanitizer into better shape.
Trying to make it more stable and to report racy accesses a bit more
accurately.

The issue with Linux kernel is that it has a plenty of synchronization
primitives. And KTSAN needs to take care of them.

One such interesting primitive is semaphore
(kernel/locking/semaphore.c). I am not sure what is the use-case for
semaphores and why other primitives do not work instead. I checked
some examples (e.g. console case -
console_trylock/down_console_sem/up_console_sem) and it looks like a
typical mutex to me.

So I tried to add KTSAN interceptors to semaphore implementation and
found that down() and up() for semaphores can be called by different
threads. It confuses KTSAN that expects mutex ownership.

So now I wonder what would be the best way for KTSAN to handle semaphores.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
