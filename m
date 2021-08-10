Return-Path: <kasan-dev+bncBCY5NL7ISQIRBDP2ZGEAMGQET2TEPIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 92B0E3E5AF5
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 15:20:14 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id w21-20020a4ad0350000b0290289b9284ee2sf2217165oor.14
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 06:20:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628601613; cv=pass;
        d=google.com; s=arc-20160816;
        b=gCuCxulVAgg5ZiTsc13lEIxJQMS6S00zvfawviCQ+k2roOCPAz+b3tpEzOMPEqa/d0
         nARjPCODRou9IxSZtdsScJbtcXSRQOZsbTRDuTMiDvPAui9TqeF0R6FlujG4tX5NUDHg
         UMzWetnVh3NHbqN448X0EsfrdYtYXfq5/UJSrwbV/GJO12zQ2uPfj+HjUC1BYHCSymPy
         iYw2QsXmyw+1cA9wOAUUdwb+sIfmnO+6AqJ4Ha/CoNkqsrzGddbKZbe9GxDKcc55YQEn
         jkoejydGiY3yu7Lhc7IhyClC1skh3ubsKaT9NmoqjDvkpF+HTE+3lUIu97rv3ccpI7VU
         wbMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :sender:mime-version:dkim-signature;
        bh=gzR44r2nWeWlxUy01Owc5Mj6YRLpguHeUQ6FC1F0C40=;
        b=okg73q9eLW44/ojPu2r4qA/K+nmR8s6YgkrXZ8k/kSOixLkgbD3mprxInLdhaKoqbp
         lVIGE7bdLphg8TIxlfe9hu4eGAmgRvvdH2vzQLcpQUZQfSV0sq7KJ+vV9t1OfhoERI/S
         tEPS6s/nUBu51MyVwomKHI7w+g7I15388+ENA7E120L3fCj7Ln2Hlev06zY6rI4nwfYr
         dKJejlqUPWIEFBHpvyZgSpz1ydlw4PLWXTyuY43nEiUm5CZNcBQ7mOZtFqlPI+72NCI6
         hE0yMYvdStSFoecF0yTWX88auzu7Rl9szHj99uRhUqlr/iUrvajAPVaYzH8nT+ECaRUE
         t6BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=r56fIwbJ;
       spf=pass (google.com: domain of immeublesourou@gmail.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=immeublesourou@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:sender:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gzR44r2nWeWlxUy01Owc5Mj6YRLpguHeUQ6FC1F0C40=;
        b=lyywXed5SwB3ivRVwVpo8qPEpnr963LQFexNIQvRrzXS2gzRTtnrlyGPuzQWDwosRs
         Az6v0Fkblo5hawoKdPcjAwvi7p50R+qeeqmI6vocCoStubHu+vwRDa63dgnYy/7lqtte
         LH2dRcR6lKdzZ/BKqu5O8UDx7RHDiT9frffxprzr4qqweq/4wx4EOhYfv6L0f2AG10al
         PkNhnG0+9jgG5F+E7ZWPM6YAwoTyNm9TmGt1TK5NsSXJ7qyDHYtY4aecbQGKIKrypLb2
         HuuFfKQGRowiaTSJ9spjWXG13MnYj4qDkntl7qEldGMja5t2Nt0iKNRzkGJt1bxHlwTG
         dXlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:sender:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gzR44r2nWeWlxUy01Owc5Mj6YRLpguHeUQ6FC1F0C40=;
        b=SCmrygMD16c2Y4zlblU0kRMVXRHWnj1iKAPpO9EY2qZ21lQgiSDGLFm+qgd3yOyjMY
         Vz6ecVjmYMWpGr9ulV0uK997jcm8WSG2AYH31ADqSKxHfzYIBpQMGncRxabjGgrDQ9xx
         +glCmqVYu4wK4FlSd0rYDeXBewgTDdv9QBENz6KXLE3gFT1BQBLnmVwYlXtU5TDvl2jL
         ZW+5vHkTDYA/K51XaHVfD5XXn/aEovLwLqnCzeyD8dHTAsnVhrJEfK1tVybNU3CTBVN6
         DNy0Nec18DzjvGOWlsmCX5oSqjTwN1Pbymk6jU9mM8C+CYFnDVuDVCCzhcFI3X77C19d
         qrbg==
X-Gm-Message-State: AOAM533pmqKHdqFsXuX9BtQaUYuYYcFSPhNHbL4BO0TxIxMMpeWKvvJx
	jj9rmANX874UIR8B3WhBhnI=
X-Google-Smtp-Source: ABdhPJylc2Vf4M4hL5pmDvHyG97PLu0P7gWRDHCBwmgPrJSV6tfRp5nwvMIBm4STigSzBzpL6grMBw==
X-Received: by 2002:a4a:41d2:: with SMTP id x201mr6894006ooa.71.1628601613593;
        Tue, 10 Aug 2021 06:20:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:188:: with SMTP id q8ls971851ota.7.gmail; Tue, 10
 Aug 2021 06:20:13 -0700 (PDT)
X-Received: by 2002:a05:6830:199:: with SMTP id q25mr21809210ota.101.1628601613179;
        Tue, 10 Aug 2021 06:20:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628601613; cv=none;
        d=google.com; s=arc-20160816;
        b=ttHLrkDIqgUyU6pWpXTFST55/7/bj9WhcJvfNB5V4s+44pWlEK0ZkjFBY4DZs6Lyv7
         O8uiEnWwW2WNnmbWFM86+yA4Jrnh61rA6dOamQgEvpBLbmkJbGcN5dIdn2/6y7BjXyeB
         dAArlaGSSV6/koighrQthoJiXPlS6ULVamLdQi2+9pKkKQ56a0useg8rgNcMrxD4EnGL
         t+RUrcfNJRCirqLB3Mt1gmfIl8GolmqqEhY5LGx2WnwVFadSm1TubQkl0gWzwq1ctPB6
         Rar0GnT+EGrRVEhdeZmVb0xWrD39QyyLr+sWdDSkPhghZjDq7aMitNQuQcmYQNzG6AKt
         gnjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:sender:mime-version:dkim-signature;
        bh=2tvLhkad0w+Mh63WhnFJkmRFgYsLXsJmUqGVjzUAFIo=;
        b=OTOnVFC3BMk245YUqo67iH+vJkPF43yJugSYuOVyw2bLfiVDl6UwcdFX/+YLCCUhUK
         JDADi0tRluj/bcOGTlomlBLg/QyhHW9WO0aNcRlxBy+j4UMx75h71EASkNr4uvjZqCjC
         y6cfjK5P+hvjIBxDQhpPeYWu/kFCsNswFA35P5OwhSmW8Lz+298POms4QfrI7Ubxf/+c
         y5Uf2c509A9Qyz70ZJtCHuxmuowRqCA8TuoVFDWw2WqtY1EQT36/Q0DwhxkwYWZlpCb+
         xrKpBijg8u1ab76weVrTWIJZdVmCNWtd3HwPrnCD3jb67r21ZVl/OOxxER49rfy63aPF
         jf2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=r56fIwbJ;
       spf=pass (google.com: domain of immeublesourou@gmail.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=immeublesourou@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x92d.google.com (mail-ua1-x92d.google.com. [2607:f8b0:4864:20::92d])
        by gmr-mx.google.com with ESMTPS id p11si534736otp.5.2021.08.10.06.20.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Aug 2021 06:20:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of immeublesourou@gmail.com designates 2607:f8b0:4864:20::92d as permitted sender) client-ip=2607:f8b0:4864:20::92d;
Received: by mail-ua1-x92d.google.com with SMTP id m39so3275553uad.9
        for <kasan-dev@googlegroups.com>; Tue, 10 Aug 2021 06:20:13 -0700 (PDT)
X-Received: by 2002:a9f:2c93:: with SMTP id w19mr9591949uaj.26.1628601612739;
 Tue, 10 Aug 2021 06:20:12 -0700 (PDT)
MIME-Version: 1.0
Sender: immeublesourou@gmail.com
Received: by 2002:ab0:3903:0:0:0:0:0 with HTTP; Tue, 10 Aug 2021 06:20:12
 -0700 (PDT)
From: John Kumor <owo219901@gmail.com>
Date: Wed, 11 Aug 2021 01:20:12 +1200
Message-ID: <CAHdg_cRt+TWqdUjK3Xf84mj5+AwgMtamTmu9J8c3d6u2KdArLQ@mail.gmail.com>
Subject: Urgent
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: owo219901@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=r56fIwbJ;       spf=pass
 (google.com: domain of immeublesourou@gmail.com designates
 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=immeublesourou@gmail.com;
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

My dear,
Greetings! I trust that all is well with you and your family. Did you
receive my previous email?
Regards
John Kumor.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHdg_cRt%2BTWqdUjK3Xf84mj5%2BAwgMtamTmu9J8c3d6u2KdArLQ%40mail.gmail.com.
