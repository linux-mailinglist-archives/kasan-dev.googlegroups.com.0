Return-Path: <kasan-dev+bncBCP2DOOU5EMBBSWPTLWQKGQE75LP2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C1B61D87F2
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 07:16:59 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id m23sf13077455oih.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2019 22:16:59 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=om4dZW5DkX3hAn23J8zp5I6HaG7kroNAEKjwIfWN3/M=;
        b=LK6A9WlL2e+v7Bq1iiY9vcWX4hF08GnG83C5dAqZyh8Ep7/B4baky1pounsfnAx82V
         rDwejCB+TG30XGApfequTHvG4YKGxPi32lbQ8zUZt2ZeEID1OrpptUw0qhBF13DWj5JK
         UUGnft1wAhCPhyEYweRThkwYNtR/6PszxO6YyXK5R4Y6l6Xpx6hznVI1elJC4D14hn/z
         TUp5N9fjbWF/4QT5y/L6ZX4g99Z8rqreO6ZyXqF6ASYq8s0Wak6RL8ku/tNawX7mI63Z
         SMAlwXpkiZE3FGFNCUDp5oD1j+wyep8WOqULtcbh+c9kE9WnuAYgy0aujs56/X5TK/pz
         0VRw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=om4dZW5DkX3hAn23J8zp5I6HaG7kroNAEKjwIfWN3/M=;
        b=OPpQP7Mp70Y7f5Yjzgz/Ix739twGDJ3XGWsp/MrXdCkQ1FAFvbpFlBvLkH/SkCnnWO
         0nlPjCvl+RGWftrnPpHqm1Cg4wq+XyWn6qrOls6hpihKoIfXP8rXXXXXXcQ9dGwdLcYU
         dJD+D/hrNEhM1rK7iGWakQF1Xd4tTrme/Mr41KbBOcrrMLeSXCK4V++iNioQVXzcNvW6
         4V5nSKIej+46hGvEsRjRmKnZ9iLtGqT1a7FRZmuz+FbIPASPospYZsDbSAfDS5W13ahA
         t85GgRZjPLyXrpK+y4OSFGU3Z1t2nWVW60Xg+HVWIUiApBP3sRd6w/jZH5MY1o9U0u5B
         +Xdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=om4dZW5DkX3hAn23J8zp5I6HaG7kroNAEKjwIfWN3/M=;
        b=ew6xSoONN0ru8cqnhwS9rAjysNwdxGP/UTPg5G9wUYZjxvLzD8tSm/5bYGt9RBm6v0
         djSUQe3K3eNjyFH62W/DTbhj4kdvZ36WHtuSCGE04iLk2GXkbIxRzG9xp2pIQo+DSR8G
         02FR2XUG8W9sU6nasVxjfHwLNw+mItYVlXEegaJiCImhOU0nWtSYwmC7y78KcbSk0MRC
         74y0A0h9E1LyGRMV4WIllrSPrrdwXVbPm6iTEMJxIEg0DJGCqTV4M9JST5jXMTdlFQsF
         AoqQd3hxFTlUhsdZXKNO+pWhHCdFp+sPEAza7XYhBMYiOzxFeeKBZUlWZhcQpaKfnso9
         oEtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXARKqrUC/0HdatfQrqJV+rKRWkqvoWIL5z20V7noaANhaz4zBC
	0TqFP0Yjq2cYqN21cf6KMR4=
X-Google-Smtp-Source: APXvYqwyKFVAxyqYlloUL/rWFWXsjnDga1jgMCQzKMngT+7OZLNUyG/QwLFyuYX8K7PjPc46ypo7tg==
X-Received: by 2002:a05:6830:22e6:: with SMTP id t6mr17750445otc.65.1571203018587;
        Tue, 15 Oct 2019 22:16:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:3cc:: with SMTP id o12ls185394oie.0.gmail; Tue, 15
 Oct 2019 22:16:58 -0700 (PDT)
X-Received: by 2002:a05:6808:8d9:: with SMTP id k25mr935435oij.153.1571203017998;
        Tue, 15 Oct 2019 22:16:57 -0700 (PDT)
Date: Tue, 15 Oct 2019 22:16:57 -0700 (PDT)
From: djk4ad@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <b4cf7a84-d833-4a74-a539-54a8f4a2a5fa@googlegroups.com>
In-Reply-To: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
References: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
Subject: I have already sent you Money Gram payment of $5000.00 today, MTCN
 10288059
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_5153_1113313940.1571203017209"
X-Original-Sender: DjK4AD@gmail.com
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

------=_Part_5153_1113313940.1571203017209
Content-Type: text/plain; charset="UTF-8"

Treveon bennett
15906 Wilmore Lane,Missouri city tx
832-739-2841

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b4cf7a84-d833-4a74-a539-54a8f4a2a5fa%40googlegroups.com.

------=_Part_5153_1113313940.1571203017209--
