Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVNW42AAMGQEBVAXI7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 484FF30C9EB
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 19:35:03 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id z10sf4336598pfa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 10:35:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612290902; cv=pass;
        d=google.com; s=arc-20160816;
        b=kk7rjsYUpnWVKmZiJfKOpyngdBm1pczh5SSCWFVqFSXVt2KwxNoWKq7e9xAOkJ1jN0
         Rrb8zsYfxwiHWL5iUICVmf/4fkdet/8jKFaXUk8qnxMHXw8ClwsSncYfBgZghNmhGTee
         21aPpb0EnSaSXnsb7ZABOT9KtNwwVaXR0vHBQNLQXYf1aJPH7w7nWbWLNWbP7ZKqeztl
         R5yWOLt0PenHMJoF4AOd05lkXcixyQYp2pb1HOxMLxtjFZ8XnMq5x8sWwXnA4rL1bFO8
         sTPQawLkI3R5nwk7oI+JoyTG2Bi1dpvsX6vhhu3ftQetIM9QybmFoc6Dft7JmJQKA1R1
         G4kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=M0BBH8srY6l3uQaOgpw22f73qkEXFtHopiN4B5cuia0=;
        b=BkbVgQgF5vAoQmya8taF3Yt263UJW1Tufz+RyVy7pLZCV1JH66e+nY1THHnz7zNxon
         AIIPdkRZKKgs0ZNh459Sawgine4RQDNWeYNzY4iu+/7zBHdS8TuEhzF0bA4szdrmgUeR
         Lip+rtvjqO7x4lNpRas1PYV5n5ytMwgsuaWYJv+iWwCkjPwFww8Vh1R6VnKzOcrsjifa
         eTZOPO8iRUjqEU4qS9RnPmCr7+hdj7ARKKxxv22bnV1MFFysnvN3mMpAOm0yB4j79IK9
         o9Yadn5IDYbQeu7WfzFkn5KAyQQj1euxh4Jy764MrrsygyqsRojZTcLz1J4Y8eWw9pVm
         J20Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oU66NOBW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M0BBH8srY6l3uQaOgpw22f73qkEXFtHopiN4B5cuia0=;
        b=J7Pu1csRyc6WfdI6tK8TJ5qAji9Gs2i+M/zwRv66+DdkrBKE013Cau1Os5gojCBwxv
         yyF2EKNjxsk3HMZU1JpKbu7p6KVNZeO8f1LiVdI+gpFkPh1Z5wbwM4jNHnMmagFnbu2W
         oxRygw3eDa3JlMLxCm9TxHRKyrJu7REwvZGKkrc2mw8l4dhxhKn9djlCcBsnkbtSvrqc
         XK192tbTkuRcEImXSPyfC58Rs5S5Azn/UTkbTvIM7o/GJd/DwTRy6orpdrk1aWH3oYXS
         a+tpDF/YsBM7UtpHdZTDvqpVWO+6dmb7PgQCNLqkgDUPPogGh18nRPMEGyykpomIUSGQ
         zrsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M0BBH8srY6l3uQaOgpw22f73qkEXFtHopiN4B5cuia0=;
        b=gKyEq8Mx56DHdsOx0QtAYXq49dLK6Yj0Gtmv5OWVfLedqmcf5J6QzOUqHehJz+aALF
         QoUeAoaiE8kb6BXE1xPGWTa6TD1F7gY44ipnElMqX0E3LXI6rMc8uW4a+I7macOX+EHJ
         6OzMJEpSH7X9BoQGqwl+uMd2pJee7gIbnXTmlxWieKGwZ0/HBTcexIODEuqmSaQ+Moc3
         u/6jaCnEwlGN2vdjU2LRfC3MNlP77l+9pZWQgUc2CQsCca9viCh0wKRWqiumks+V5g8i
         S2U/MgxGXLS38puk4JpUEcqtPSJQ17f38L/mgTOaQndQ0XFn78KdrIaD2F+Vx21O97yH
         CPIg==
X-Gm-Message-State: AOAM530xSw+4zyuv0s/2cvv/D9Tb20HPN8qwa/jh5LdCGYC7veT9rrwc
	Jbe4ae87TtcWCohINkK3Fes=
X-Google-Smtp-Source: ABdhPJzswsVa0SF+Bj14n0mGdxtxiA2Wc+tZGJ70edn47Yzm7uB67oJTOY42VtvD9QnAwUPOW0w1ZQ==
X-Received: by 2002:a63:7f09:: with SMTP id a9mr22943154pgd.63.1612290901967;
        Tue, 02 Feb 2021 10:35:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b8f:: with SMTP id lr15ls1878857pjb.3.gmail; Tue,
 02 Feb 2021 10:35:01 -0800 (PST)
X-Received: by 2002:a17:90b:17cb:: with SMTP id me11mr5635648pjb.64.1612290901230;
        Tue, 02 Feb 2021 10:35:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612290901; cv=none;
        d=google.com; s=arc-20160816;
        b=HMOV9rxgCk+8F49b9R1eOIYE3qdeW50cNw8C12Bw7jVPbz5TSdMHpFMIdNTHktspvq
         Tj84LERMSRZ/CE3OK1gzXoMKOHlZG+PyDFBescrtPVqnmHl+sZcmytBU/Y6O52C9xkem
         6Z9t/Vx5+Oj/6cxgh7+yGJ3X8ytIjfhMijlCXY4f+b4WpP5tq3G22PGYcGS0qq/d9u/E
         r1a2Tf2zRZH/550eocgMaoJ9Z8R+pBpIvtIfCVvI4S2XUl08LbWroUInQqx9Vt334bNo
         WdqjaCzE/vb7feY5Uc6ilOUv6zzmMhHEkGJuH2LNQ4SYrI7cQN6Ret/KJ6PzvvJuDLQa
         H0sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RaNsjOwqUcbpXCG99ecSA5gio3yAqiFYFr3g6/024ao=;
        b=holIQaaqvzNwjvLCtPjBOHOyy2baUadCSys/c+jYZ3ZaA8LrcRj5ciQ87j/3wX1X3d
         rVpLGQSlYK5vn3Ew4TeI/FTlYMzpENOUSFJlFRXJxtaTJZPWyHUhIt/VfD45dglSbJAS
         W72lqw98gX7iZVlw9jKuqG3RWthOwct3NvzanCJKyhJraAWc131+5zFfqkdVnt4mgWTx
         +xPAcyAWKbP6ofTS7Fe5baTQAgpV6pvI8Othln76fSdSYv9mp9W5zeW6G9sFAd9PA+gP
         16NnePyQkhYFi45nF7MrD8Qje2V0CApu8cgV/ft31YqfG4Alw1gHvXK9lsEVj0AltnmD
         SfyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oU66NOBW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id u3si22311pjf.2.2021.02.02.10.35.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 10:35:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id h192so23854354oib.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 10:35:01 -0800 (PST)
X-Received: by 2002:aca:cf50:: with SMTP id f77mr3686942oig.172.1612290900367;
 Tue, 02 Feb 2021 10:35:00 -0800 (PST)
MIME-Version: 1.0
References: <20210201160420.2826895-1-elver@google.com> <CANn89iJFvmLctLT99rYn=mCwD8QaJfEaWvawTiVNV4=5dD=Tnw@mail.gmail.com>
In-Reply-To: <CANn89iJFvmLctLT99rYn=mCwD8QaJfEaWvawTiVNV4=5dD=Tnw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 19:34:48 +0100
Message-ID: <CANpmjNMRFzXY5FgHXgjm+QVf9BqJ0=RQZZQB1k_kZ=umjZ2qUA@mail.gmail.com>
Subject: Re: [PATCH net-next] net: fix up truesize of cloned skb in skb_prepare_for_shift()
To: Eric Dumazet <edumazet@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	David Miller <davem@davemloft.net>, Jakub Kicinski <kuba@kernel.org>, 
	Jonathan Lemon <jonathan.lemon@gmail.com>, Willem de Bruijn <willemb@google.com>, 
	linmiaohe <linmiaohe@huawei.com>, Guillaume Nault <gnault@redhat.com>, 
	Dongseok Yi <dseok.yi@samsung.com>, Yadu Kishore <kyk.segfault@gmail.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, netdev <netdev@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, 
	syzbot <syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oU66NOBW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 2 Feb 2021 at 18:59, Eric Dumazet <edumazet@google.com> wrote:
>
> On Mon, Feb 1, 2021 at 5:04 PM Marco Elver <elver@google.com> wrote:
> >
> > Avoid the assumption that ksize(kmalloc(S)) == ksize(kmalloc(S)): when
> > cloning an skb, save and restore truesize after pskb_expand_head(). This
> > can occur if the allocator decides to service an allocation of the same
> > size differently (e.g. use a different size class, or pass the
> > allocation on to KFENCE).
> >
> > Because truesize is used for bookkeeping (such as sk_wmem_queued), a
> > modified truesize of a cloned skb may result in corrupt bookkeeping and
> > relevant warnings (such as in sk_stream_kill_queues()).
> >
> > Link: https://lkml.kernel.org/r/X9JR/J6dMMOy1obu@elver.google.com
> > Reported-by: syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com
> > Suggested-by: Eric Dumazet <edumazet@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Signed-off-by: Eric Dumazet <edumazet@google.com>

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMRFzXY5FgHXgjm%2BQVf9BqJ0%3DRQZZQB1k_kZ%3DumjZ2qUA%40mail.gmail.com.
