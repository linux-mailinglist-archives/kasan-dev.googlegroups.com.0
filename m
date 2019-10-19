Return-Path: <kasan-dev+bncBDV4NDE25QGBB35GVLWQKGQE77ZRKBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B27BCDD6A1
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Oct 2019 06:39:12 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id r144sf4365880oie.4
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2019 21:39:12 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8dVDMwNI1NaOCnXbgk1CfqnGu69jZrIkIuAza6EPX2k=;
        b=cWc2ZbMqzmuGlDZSCQ7DrZyat7U8BMFjeEudnOGz+wfDoM7DtsgJJNFaSlZbQuoS1t
         2DUlFFEJhvJNWTqJgqjuVMars1Nx0yQFCdUdrSJbvqgkNgBjxjalvmGHCtON7bOQtefg
         62uoSjVXqzsU6XBZF+6Hmp2qeLoFaG0IGo0pkfwF14zy1KD9z0ZkzO52XaYvnUtP2/gl
         xhCuyID44tGj7S/OkScDyjoWnVXIc5ndhtu/viPl8IBKKmZYx42xh7ogfMFeQHLYxeNX
         zNidK3FfRPfWouHBG5kcxd+PnzTm6qUovoNiS0TvBEefqn2HU+HTzpQ8o9SvdaxFfVnl
         Yg1w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8dVDMwNI1NaOCnXbgk1CfqnGu69jZrIkIuAza6EPX2k=;
        b=reBnrhVMd8bVcC9xNA7nXHOX2Y0vkHeXitsMTptlAs8SOLaFlnu2+Lzn6gyzuHFLV/
         dJSL3z0ItUkDE/eH7aVCQNvQBRrGe4SRE+VlbGPdGkK8mizrQqXTiAZmXlZjqVZFMR3j
         8wBn/p0zAOQs1Y+s6v6i9LULn6nA4TSsDHXE3dewRQl2S/MDlNNRCKn1oN6V779k70LF
         T1ziT61DopQy35fw98CCNbSd93QCNqRUU3rifbO8nUCQ3fU/ptapd8e2M6FdjGPUnbI5
         2FCtywvSjjsCbcOm0KdAblBAqzWEQ4wzubCm6OH1xXRMFKdz4g3ypMEIJ5XkWVIqiNXz
         hNNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8dVDMwNI1NaOCnXbgk1CfqnGu69jZrIkIuAza6EPX2k=;
        b=DJKQxqE89BkL4hTg1DosPbIFW0sa9mPpTDRZ3oMqUQW6A49hhQP6y2PIII3QgyqtnR
         5ZSYYatDzcJ5FeSxJ34qu0JIts4dcrtkuPkTjWezPXcL12mpw8UAiNxJJVPyVMO99Fkx
         vIq42yIWb07wXneIfTIklnmc6LcvtImeMX8WVrXo//uIfWkIIl+7TeIC8XWBjcsTSYEl
         e+quEFK2GHUXGm+NRwrpQbrojjCDPJP1sToAogDOEiM7+Yw4ZJLwVuIhvckbFUg6RLEq
         MpoRivf1P1aaXMZdqQqrMqfM18rRW9YNeWRghqy8vRlTJ7urIsRUJOfmfoLFWN3wXYA9
         0WIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXFMaPbNoEhxK4XnUqyz6JD/1m3hxd4R61xr7WNlv9hisL/+jiY
	GmmSk0KQZL7Fy3/8H3d+Mgk=
X-Google-Smtp-Source: APXvYqw8rO+OIk/WjzG1aJJcaxwbxN2xZ2uz2h33mCF95YyJiky40RRfdQ+S/5gbJxQWS8Be+RW0jQ==
X-Received: by 2002:a9d:459b:: with SMTP id x27mr9800854ote.167.1571459951567;
        Fri, 18 Oct 2019 21:39:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5585:: with SMTP id j127ls1370926oib.11.gmail; Fri, 18
 Oct 2019 21:39:11 -0700 (PDT)
X-Received: by 2002:a05:6808:213:: with SMTP id l19mr10192437oie.146.1571459951048;
        Fri, 18 Oct 2019 21:39:11 -0700 (PDT)
Date: Fri, 18 Oct 2019 21:39:10 -0700 (PDT)
From: martingilbride2@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <1514652d-2f94-4e44-a5bc-467240aaa7ab@googlegroups.com>
In-Reply-To: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
References: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
Subject: I have already sent you Money Gram payment of $5000.00 today, MTCN
 10288059
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_1338_1329950729.1571459950333"
X-Original-Sender: martingilbride2@gmail.com
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

------=_Part_1338_1329950729.1571459950333
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi I'm writing in regards to the posts. I have not gotten back to you soone=
r because I don't know how to and I have been having personal complications=
. You can reach me at this email or call me at 5702308136. And let me know =
how to proceed. I'll be reaching out to people tomorrow.
Thanks for your time and consideration

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1514652d-2f94-4e44-a5bc-467240aaa7ab%40googlegroups.com.

------=_Part_1338_1329950729.1571459950333--
