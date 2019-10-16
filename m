Return-Path: <kasan-dev+bncBCP2DOOU5EMBBXWPTLWQKGQEKZBRTJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A949ED87F5
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 07:17:19 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id d206sf13094241oig.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2019 22:17:19 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jdXBP5mF8Qq/iQA2WG7D6qB+it4rwsEIE+3PhBmCRBY=;
        b=Wi5ixNfZmohshmfpA15Cgej0hKnfnJyDOPQNe7DDiHJoUENc77BTEiXM6gaMCkvinW
         0QW3fw41VtVKy7mvqk5pYOgIjyL1DfrG/e5Sryxo4SMwtM2dker4ei8CNEXQcztY/2t6
         21sEO1X597qjU4+xsUl99zicm1PawUVEXDmDI7wRXXb+k4h5Ff/HUYrr1HfY2RZqDnwI
         Bw0cJFAwxKP25qyOyzUBqFNey31R4zOw1uAJy6oex5kuDOTWii5JGEKuMcM7af2BCqTR
         lsAaIv4bPEUSaCVvAIfobBJaNkMdaCIQWdCxFHxGDdYcuqtV8TBqTTGHO5/zTVXIuI0/
         pX5Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jdXBP5mF8Qq/iQA2WG7D6qB+it4rwsEIE+3PhBmCRBY=;
        b=TMHvdV/hDuQ1GMiP/SaeyY5Y5NOV3hXEKF+e8bBq9D+tNDjj5LOzNuJvxXLAClj3jZ
         aliA+t+Wwz0M23gLdlLzc7+/Usts8q4tDdDtbz+hAFpi5kaAA/NIyGCiLdrnPTTCAYS8
         OxY8shZYfSSP1sqVKrLjPrkpO+B+tQWeBztko+AV4yXbPg/a4fm8uZLR2NMs4UPhso38
         LzrEBBOaI85Jtf11kpu588iTaEL+Pea5l4auePZSPl9eKzXasW05mC/APDHqoTXBZdj5
         yQQlDMOjrxeHw+SZXa7HFtiKJLPMWVbvyLNH9luoP3AL0MhH3HlrDL2WNRv5hWiuwM/I
         GOBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jdXBP5mF8Qq/iQA2WG7D6qB+it4rwsEIE+3PhBmCRBY=;
        b=bE63C/IhM/n8sZdL2+XSHI6U6lZ834zztp8hZga5Agl0ZHivYGoV+8Mj/OY6xeDU82
         WVvPaA20e/mRCNHm26CDpbMH4fQyMk0zDHtQh5o0Bnp7DUVDV/CgzqdI/V7zk5wPKIvs
         u43AiDRSslJyPfNXcLmz0NRTTlmIvn+5dDLrMkmwLgGHX77Qe5EMhb29FM/q4s7cN8F+
         TiAN4bTPck7bYevaDPxEqSYfIrDkmBjhKBLdFofBh0y3HlM4PARRMtn1r3XsDv+Xqw2q
         JRNFETnqT7bkhk/xST6ykklNWiatSvhD7jFv2VnRl9eV4kYtBIKt8bJ/zZIQHb/IW6CZ
         kr5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXA0E5MEDWFRq0iHDhWeMMDcneifGD8EUDhi3A5ry/fk+4Wp0EJ
	FmY9PVVvzQfE2f8NHHjc2yk=
X-Google-Smtp-Source: APXvYqxARHSojHzwGVpkCw1L5LxlhZhleJwh86AmPPUGiRbfTmysUbWAK0n4URNuTnxTlZ+koePE0g==
X-Received: by 2002:a9d:5f16:: with SMTP id f22mr32953781oti.78.1571203038605;
        Tue, 15 Oct 2019 22:17:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1383:: with SMTP id d3ls3799110otq.0.gmail; Tue, 15
 Oct 2019 22:17:18 -0700 (PDT)
X-Received: by 2002:a05:6830:12d6:: with SMTP id a22mr29820000otq.146.1571203038102;
        Tue, 15 Oct 2019 22:17:18 -0700 (PDT)
Date: Tue, 15 Oct 2019 22:17:17 -0700 (PDT)
From: djk4ad@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <f2baa2e7-49c2-4772-afdb-0539e8a9fd8e@googlegroups.com>
In-Reply-To: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
References: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
Subject: I have already sent you Money Gram payment of $5000.00 today, MTCN
 10288059
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_9678_1561522125.1571203037606"
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

------=_Part_9678_1561522125.1571203037606
Content-Type: text/plain; charset="UTF-8"

United states

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f2baa2e7-49c2-4772-afdb-0539e8a9fd8e%40googlegroups.com.

------=_Part_9678_1561522125.1571203037606--
