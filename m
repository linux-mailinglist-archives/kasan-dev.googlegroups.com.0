Return-Path: <kasan-dev+bncBCMIZB7QWENRBAEDUPZQKGQEXD2ALTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id AD46018160A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 11:46:25 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id mp23sf898225pjb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 03:46:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583923584; cv=pass;
        d=google.com; s=arc-20160816;
        b=y5DOiYinnvvzAKNGCZYMYt9rX+CC61XrS9gYbrsUkp6Ue7etbxfMj1oEfoAiwYUb1+
         uG4bM+RwoO6XmcyoqsNe/lp+eRm/Rd3Zk+NZITcVVn71kWEx0qaTZFJ9Al8ml92ln/Wh
         +F1vWsS6RWEkWAf3wikrOL5IO34Z7tRgVYNsBdQNZf80hWf8KfaD1f9mxri0VLDiQSlJ
         B0Zhx9Xq9wTPYvROtaQmWk1Zqo8+pnL6a8CkPFtYm+w1Lzmapds/9YdJqZp8TOhDaTLu
         xj7zfuot+5b/alH+dHItaw7yyDtrGs8zEaXrALPoinVZwZg7Q9cJuEAj+aiezg22oKdr
         v6PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5xb4RX8+oVKrJ76H3h+Qy2RBgbDopdeJ9Gzyvrmq0YY=;
        b=o1SQKRFi2g0U9mUlnDXz3Bet/IlM5jrOfTDjMs9kxH2yD96crltfYQtKs5t2qd7/6h
         49d6irtHrVCZRm282/6YRd43rsafMSLGrXhznmIZIivkEAqhuGYh0jAiGsQkD5Un76KY
         OHd/K8Inj+FdYvAocDE6Hb+wNVfwJY1vKpLQcb9xLcSowV1R6lERdsPvQBh+2WJsOknN
         IYVv/yAnZXOaNflPhtQYT4B/XkRAtijUsSpFwysuYEXcLZ80PacFBzmvdlDVi4hcBwOm
         u5P5xAa5xz6MydeJ9Y5Mkn4kJprp2u8QXZ4nFQokTXZfZLJx/nXkyfD3DD9gkUFo2N6d
         uE1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=byWNOnaB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5xb4RX8+oVKrJ76H3h+Qy2RBgbDopdeJ9Gzyvrmq0YY=;
        b=EwUTnoQeJZalNCDHokzmimdNXmEzaTUu3nrp/Y6+WfZh0sTxlE3SpGOe/p+YfTM97G
         NyqMMRYMRg534fh3LGc9ZA27INdJ+mu8mbhqj53HuSo52NPxp2dUNaoS05tj1EmeF5Qn
         ZvmEkL9ts/3pzJxqziC0v/3g6UXXDS2Z0Ne4cIz47t3Pm2x4+3K3CxAy5lcOYOLSZ/Hy
         c0RoP0K/6aCnj+d0tgqZYCWqveWGs2suJCoC1Uicxe4niTpVoQFmII4VkX++bJ2fANaZ
         rrq2j8hlTd4J6B+5wie+9cpy7j4lmXWXrzPaJE2wzBnLUUz8iby7acDqG/7JJ/EEoP7K
         G4Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5xb4RX8+oVKrJ76H3h+Qy2RBgbDopdeJ9Gzyvrmq0YY=;
        b=cbeYj1GUq1oohOZ7NkAOJH025UB7JNP9jEvEKvbXZ7hg3ZrsCgSa3QBTur573rpcbx
         VNd7gq4mxJiJ05SulLnYtzm4SDyla+9DKAWvpSUSQCYaJ5/3kKNN13nosHKVPQlObMJ9
         SdCAJeVsCSJYNTVRG1PHk5uQad/L0tn/ds9ktX1xSQxY+2j3OSSZREXdVInj8le9LuWt
         lCph2sQkvWViBPR9+5T9CoU9VZ0gc1kSRRRIctNyoENBtRciUQXzB9g1AM0tzv2GWY0R
         IwaQAZpf8+I3Wd9nkIEhOVBAJT20lc9ScbCMwrcwe4SxNob4FT+y43iHbnYs8qyzEcrO
         DGsA==
X-Gm-Message-State: ANhLgQ2NIBhwpSle5XjwxkTBlpnWy/HkEK2OcVcWnm0rBqhb7DReb9T+
	YOWZLOZtNUkt4Ugc3jBqf6U=
X-Google-Smtp-Source: ADFU+vu9Ge6ntZvzPx1b4pk7O9zoYSbmfYc01tFceHq5XuNXaj4eqEjRKklK25uHm2b2ARJt3eQl6A==
X-Received: by 2002:a17:902:8d85:: with SMTP id v5mr2601971plo.146.1583923584194;
        Wed, 11 Mar 2020 03:46:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1853:: with SMTP id 80ls678589pfy.11.gmail; Wed, 11 Mar
 2020 03:46:23 -0700 (PDT)
X-Received: by 2002:aa7:9ab1:: with SMTP id x17mr2292631pfi.36.1583923583753;
        Wed, 11 Mar 2020 03:46:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583923583; cv=none;
        d=google.com; s=arc-20160816;
        b=CNuBUZiytnimDHN/ReqwbSuq+Ug2Hoht+7+4tqsYUQb03YS5kwQd4qnbu1AVQLh5U7
         K74JL0QoeI1Ooted8xwymlSZiPnJy/gR5bZu7Jgk9v8XV/9e9K/8UYQcoFOAemIZR9k4
         NY05VgdfL3se6dJaKWxHcYAdHTYm9ZfO7eBCgKsXwBqHiTHXAl/BvEMYtXtO0q/oJceJ
         Y51vW6JklrnhjJQfMI4P3V7HnW84Rc4Ozj5t1MzHII9GmP9LPh8qshaPKlWFlnJytcjT
         ICz1PO3dqckoBv65V0SbF/yKqNjphAS+2UShQg9iK2EC/95zomSL6efVgVotk38kulFx
         Iw6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q8RSBQ1awf7J0+pbXujt6gnSJdQq7hBnAow/IoAFi0c=;
        b=S6tQ4C6U7UcaKqpOe4tjBHX/66f9oSaceQ3mKy6Hlmrz8uB1IHh8zxrWfWiNd8tp5x
         McudM7sHwheVPS13WJc54gzfxtntKTID/JXf+cEDaWJK3ao8y3ngYuF3jGcd6ejKS4Zp
         d3TOIk3cs/iUe+qpTkdPlFFFlj3cvp7IR/D9pIdyTr0Lto/b2G8PtKR4vxu9xu48lBCT
         zsCRMEZO68wImMAdHbDgkwPeAaJ+pOKh+OOCswanm0MBcZtrWa3e8BEudYEKRzEDl/1W
         AYmplWP3N737SNJTBtMg8KRuMjYWIVS+34fxUWTLMrf4Y48DYvmES9BwkSyULMTRj3N0
         ic/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=byWNOnaB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id l6si52696pgb.3.2020.03.11.03.46.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Mar 2020 03:46:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id l13so1134338qtv.10
        for <kasan-dev@googlegroups.com>; Wed, 11 Mar 2020 03:46:23 -0700 (PDT)
X-Received: by 2002:ac8:6697:: with SMTP id d23mr1966498qtp.257.1583923582471;
 Wed, 11 Mar 2020 03:46:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com> <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
In-Reply-To: <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Mar 2020 11:46:10 +0100
Message-ID: <CACT4Y+ZypjEidZQ6E8ajY1yBU6XA2t6eVz56sJ1JaBjCniRMUQ@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=byWNOnaB;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Mar 11, 2020 at 11:32 AM Johannes Berg
<johannes@sipsolutions.net> wrote:
>
> Hi,
>
> > Hi all, I just want to bump this so we can get all the comments while
> > this is still fresh in everyone's minds. I would love if some UML
> > maintainers could give their thoughts!
>
> I'm not the maintainer, and I don't know where Richard is, but I just
> tried with the test_kasan.ko module, and that seems to work. Did you
> test that too? I was surprised to see this because you said you didn't
> test modules, but surely this would've been the easiest way?
>
> Anyway, as expected, stack (and of course alloca) OOB access is not
> detected right now, but otherwise it seems great.
>
> Here's the log:
> https://p.sipsolutions.net/ca9b4157776110fe.txt
>
> I'll repost my module init thing as a proper patch then, I guess.
>
>
> I do see issues with modules though, e.g.
> https://p.sipsolutions.net/1a2df5f65d885937.txt
>
> where we seem to get some real confusion when lockdep is storing the
> stack trace??
>
> And https://p.sipsolutions.net/9a97e8f68d8d24b7.txt, where something
> convinces ASAN that an address is a user address (it might even be
> right?) and it disallows kernel access to it?

Please pass these reports via scripts/decode_stacktrace.sh to add line
numbers (or any other symbolization script). What is the base
revision?
Hard to analyze without line numbers.

> Also, do you have any intention to work on the stack later? For me,
> enabling that doesn't even report any issues, it just hangs at 'boot'.
>
> johannes
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZypjEidZQ6E8ajY1yBU6XA2t6eVz56sJ1JaBjCniRMUQ%40mail.gmail.com.
