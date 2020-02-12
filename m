Return-Path: <kasan-dev+bncBDU2HZXCSQOBB5VNSDZAKGQEA2V6IIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BD2BB15ABD2
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 16:17:11 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id z62sf1359875otb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 07:17:11 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3/tiKxN2/460wcqOR8tpXov53EVnDe6f1VGafIkmDzU=;
        b=C+4Co8QninzdjT6CwTSMa1GcdR3ri7EJhusJs5mLe1SDonujiqNl18BsP6zd/N39Ur
         okMJumRaDrHHgb2k8Rb4JyOwOixVUi4dyMuKpu58nQ/jXU6ZTcqz9lMvMBwpaju+XGUT
         A+ZAe+9iBHXMGcTlwMOlFnMrrrNDr2EBNUJfNFY55auqQ+kM9LVliLZfVnFl8G/Pa0wp
         Lbrybage07OXkkoUh62LT81510/VSlV/SnJ9oOkko4UUar2FkPGprl/M/67or1qbroyO
         EW1KLBLIRBXja7HsIRaqUJ0RQsgi2H6iMSmvYU9iMj9ydR9uU8Zim20bW8QJPyKQKpFA
         FGCw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3/tiKxN2/460wcqOR8tpXov53EVnDe6f1VGafIkmDzU=;
        b=GeIK56oMWFchYdWL5BQO1kN+wNjg47wAXGxq1ReKnQFS8zAO1+6N3ZCQtQclOyHlTQ
         IjFtDfBmbkLg2TI+hlUUXLRUV1Ckua+rDYfVOXaZe8a1opffcVRnj2lCX1EA7FE797hV
         swWrw7CEQhW6+btLUR5BllO8YnkiOTaOZf8JL6x2uW02gy+C0tIY/uHpAs1TOgqgimiT
         xYpQuixXA/LOAdIGtbzsqwgUOnxMcnSBK3PlW1/sIhiP9DAx5cNO+TM8InXoJWPxwmCv
         UoZ/S4xlkRsmy43vzBJWnTXAJGxJZY5v/8qmLLvlgvST9CxhZbGeL9X0Ku/aToFITkoE
         PFJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3/tiKxN2/460wcqOR8tpXov53EVnDe6f1VGafIkmDzU=;
        b=Y7fKzI8gV20j9lASCUam7SMpy6w28fUk2xt1x4fxX1x7/egNyCgZlUZL0UyWeyrlRF
         zq09GiB3/oT8Qzh2GV7Vq4JVvob8qHBrM1RRFNCeV3YufI4LmFr5EOn4GqYhVnnhuJIC
         OMLaJFCjZPqWyMQoEVuEDxHWsGxYPaGn4jDiv46ZQrqYvPpaxyCbi4M7F+MqB52gym1o
         f7qH26Kj9yh3GXJvg4jamaThDfICI5YFtwK4VVprzd3mYOC5T7zcj41PZATwZaqE4HlF
         jM9xoXhNqZdPO5q9z6ftKEIOkzohGwGFjW6TVvFabL6blIP66U5h6VRxvJcJm9rUr+FB
         rrkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWbs19y9eNHooXcfu6uqfSE8iceuy6r18vZWbMiFe14DAfP0oKj
	CxyUTBpkNG60akHd3w8Q1Wo=
X-Google-Smtp-Source: APXvYqzYqYgiMzvJ+JtXXtMk0v2Y1/7A+LL6V6Om3yz/hbe4lrI+e/UiZQxH+TV9tNHWCuaeDpwcbA==
X-Received: by 2002:a9d:64b:: with SMTP id 69mr9318925otn.237.1581520630552;
        Wed, 12 Feb 2020 07:17:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf95:: with SMTP id f143ls6636740oig.7.gmail; Wed, 12
 Feb 2020 07:17:10 -0800 (PST)
X-Received: by 2002:aca:cf12:: with SMTP id f18mr6668104oig.81.1581520629857;
        Wed, 12 Feb 2020 07:17:09 -0800 (PST)
Date: Wed, 12 Feb 2020 07:17:09 -0800 (PST)
From: aguilarbaby44@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <fde35f26-9b3d-480f-8b0c-f28572a57eb4@googlegroups.com>
In-Reply-To: <20200212054724.7708-1-dja@axtens.net>
References: <20200212054724.7708-1-dja@axtens.net>
Subject: [PATCH v6 0/4] KASAN for powerpc64 radix
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_2327_1954377325.1581520629293"
X-Original-Sender: aguilarbaby44@gmail.com
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

------=_Part_2327_1954377325.1581520629293
Content-Type: text/plain; charset="UTF-8"

Fuck u yourfull of shit bitch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fde35f26-9b3d-480f-8b0c-f28572a57eb4%40googlegroups.com.

------=_Part_2327_1954377325.1581520629293--
