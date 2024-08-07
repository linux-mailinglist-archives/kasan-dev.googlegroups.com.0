Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBYO5ZW2QMGQE4L5XI3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C212894A81E
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 14:56:02 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-52efc9f2080sf1879128e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 05:56:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723035362; cv=pass;
        d=google.com; s=arc-20160816;
        b=sAYSzhq2IBjMYhsw7wzMlBaqx8DHCQEYMzv1ppv7zJS4ZzNXqDC6b148xKBOFHE7C2
         AsuEMK5ow+5YmdMrZI3StoUpZCiZMgqQDYZ2UeQl6BpUcksWqygN4950eqlfhkv5y/T8
         jKqTn/OuPqrXmKfhRd4Vlf05MvheATgvO6zwQRR2yr9wV/57yUw3+oEJRzFZwsxLfa7G
         OYYvBcB+ylLu9aHApsIaFHIPsZwurXjNKrs3b8OWaF5KWKiPrVUiZDFgvNv0ushM/aia
         CWnNOvjsHP9xrIAWErihPewI6Z/mAN5nKIpiqQzIOLJKkoSHqXmjIDF2o7Mk6mkSRaEh
         yotg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=795kylCY1fzhsfspAVzB8ij+HWMw9CRVq3lqyVBRC4c=;
        fh=cKvjGbT4xSgxQ1pNdiF/WlAZ6zuGpm5RahXvKZ6jeso=;
        b=TXqhbrVAzTIHXtS9DlQkPNVyDF0OYlDD0g5h5ee9EKkevfSnUmi8XfZylyhb8l34RQ
         ftRyHvoIGp6BjMGkwydQ94NaMsZqggMNfRPwWEcxtUKmHjSJarQkchDv0JxJOnSgfTPK
         fNikd4e00DQb33/RM/8/NkTTE4Yf472FaTIwGoPhf/2KDnqoS2pf9UQ0X8utb7M5nmaT
         qqlLQ8MhFBtYsx+/9BkiBJqrB4fvo9foGfZ/mmvkIMa+d5yYxy67aX6FJeI8jlTIZu7L
         kuOzFFpo9S0ERVaQavLJ0nY3qkbx/exj8ST2avVFtROgSQeqx1fYsbaxrGAbJbrGCdFK
         ywlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dcoY2Jju;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723035362; x=1723640162; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=795kylCY1fzhsfspAVzB8ij+HWMw9CRVq3lqyVBRC4c=;
        b=ZfWUMCuYGWtYDw/nH7eN0diictAr6gRTfv152yrqkxW8gAKIN4IyNYqEspLFW+4cep
         iq49x0iTplQGG7hg0cYhDzy7377jtUJ1n8F2r8ySs9K1Nnc975As9t86aThwosIxu/+g
         eNbKUFODkhltROp3NcfX+vSZIRpqFF7v9poBxEHPMJq3QyKH6jXaFf9qCyhaigmUN71a
         9SFZvE/SkKP6wWD3NcA2ILMdBUUmFkckCHURX95dyn7bVEE7/3EAbY+ZtG0eFHJPI4/M
         B9dDG21KtGxBNypEz0iySAr5QKccxfrYWpoj+IeKDshy1hOz7fjOSPGUqdZUK3tJCOS+
         MjIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723035362; x=1723640162;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=795kylCY1fzhsfspAVzB8ij+HWMw9CRVq3lqyVBRC4c=;
        b=QmyNCWjf5vrVzqjgv1iXVNc6g2k8jSukJg8KKlel87qKKjM0oKxe3iac4vzvlpGnGs
         AwUUtcDModuwu0wUwXEzdZaclGhzEjrGJ6KWkAKl6qWoGTJ8PYXdwVvgMiIO2XqVWPfd
         ZEpneJQL4vvHp7pyvCV8icZaJwhNu0BcMSsUmcYF3P0lAxZH9bNFWL0FXfl9Ll1hR9aY
         eirOofWA9zgCWJSN3MYzkeZS3X4dvAkU6ecTSgObqbuN+EgoQNVmEuQtnAlLpRfU1Rjw
         gMXrWU9PvNT65RSBu3iUgkWKREYUiKXzPgz4i7mnfb+YYhhEIdlYNIx+XUUaBBBDH30m
         WrFQ==
X-Forwarded-Encrypted: i=2; AJvYcCXU4HA8nlU4q21HJDxz7scYv6YRRiw9b9tPD3uTMDwkV19rSb1d+R7girQG9IdzVqxhbw0ZtImNklBzD5JPgLRIE0RYjQ+DZA==
X-Gm-Message-State: AOJu0YwB4/pMpZLyFBsowO0mlPGtQvpU/P9dyzzKAcW2Hb/uSexEFigf
	SvB6YrClOeAvwlu444qlS2kDySqxq99FfjkV+wjB/abduXuIi9GG
X-Google-Smtp-Source: AGHT+IGj+eh7YTPgahhiSeCLyIhCZRD7TnUhSEmRFkhE/w8LXZFNE5mh83CRyYNscZuOp9GCjlZ23Q==
X-Received: by 2002:a05:6512:4016:b0:52c:e17c:3741 with SMTP id 2adb3069b0e04-530bb39d2e6mr11258504e87.5.1723035361666;
        Wed, 07 Aug 2024 05:56:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:270e:b0:57d:6579:d341 with SMTP id
 4fb4d7f45d1cf-5b97c00a577ls1706014a12.0.-pod-prod-07-eu; Wed, 07 Aug 2024
 05:55:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWsWSbWsn0ebwTaZahkhCDGFS5OzPT5/N15a6A1WIxW/u0ZBDES5S/pYwlJ5DRgpDMPvUfFe/CGCgi2sVxSu0mWDTXoxUV3mKXCQ==
X-Received: by 2002:aa7:cc81:0:b0:57d:10db:488e with SMTP id 4fb4d7f45d1cf-5b7f51297f0mr11233312a12.30.1723035330341;
        Wed, 07 Aug 2024 05:55:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723035330; cv=none;
        d=google.com; s=arc-20160816;
        b=gNuQklOA1zq/reNILVVZKavpkiNc9LO1VN+pgH8nAFW7tLVTpX6ZK7GEZ0lhNNOdLj
         C/XyhpivQ+A/WeuZtpsM4IkUK0JnOSWuqVlqJLqDLTw5SJwF14V0UJ22Kz0QOn4VWw7o
         VXJgiWLQ4VZ20NaRArTI2nu+0eXI63iT/TigBHPp/SBQ2mLz5b+bBWUGlfXviNeVYCH/
         Y5o9lFRHNv56whFYod8diU0uOSUqv0rB2WYyhqlNClEAVXG2ML8vll3O1uy6GDu29Mph
         lqQiNyQGEdNr0LetWjipNMLOaYOBrTLmsn8SQZmO9pJ/dBS8wklz9LRBxy5d22pW/WgN
         uEOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=T0FMpysHiCok2rPZDxNM3hR5ykKAgKtyNJKDi4Mfg6Q=;
        fh=MGFPNFbWa3bnmW7Jt/PPWopBtQQEdU2oi6lgCzzHUaw=;
        b=h1Jz6OZ/eONtUO3B87L2c72CI6u/9a4rWCV1h0VYg6NjIFj9GkxTzxlM+ojz6WP/AN
         063vuAtBLngpsM5ewuTuQuz4gX9QshyEfYora8DKM1QmVbrBg1pH36qsxfqfs1jS+JuX
         LmSM+EXrGdGbrcl+r1HeP0MvnJTg8lnDS362DlNxhgkObLMsC57HCZHE0MBSQ+4nhvE0
         6OpztKmm/ABNPDXJFOe+y7uZPjDxNA9lhENhRKC9mPdYZL8pxa0QZlDF/GvS3K4dVJxx
         tSD6QLRvE++wlvpTYmPOMo6eXYbWuOG/jJFw0kD3sT/xcDyi0kBZ9nJRPBF2JEpLMZhQ
         w4Jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dcoY2Jju;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5b83d6e1b9fsi278314a12.4.2024.08.07.05.55.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Aug 2024 05:55:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso33822a12.0
        for <kasan-dev@googlegroups.com>; Wed, 07 Aug 2024 05:55:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV8viEqJg0rSGiPldIyA8wYiv2i5p7SmGxsbJK1Z9UmguhviiqtaTajiqGpDtYOFp9ikj3CWESNj3iyqZEcvVOyiJbq6VWYL8AGEw==
X-Received: by 2002:a05:6402:84c:b0:59f:9f59:9b07 with SMTP id
 4fb4d7f45d1cf-5bba28bb22amr186027a12.4.1723035328829; Wed, 07 Aug 2024
 05:55:28 -0700 (PDT)
MIME-Version: 1.0
References: <202408071606.258f19a0-oliver.sang@intel.com>
In-Reply-To: <202408071606.258f19a0-oliver.sang@intel.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Aug 2024 14:54:52 +0200
Message-ID: <CAG48ez1if0dEpL9kdby=5=PcFfnwSP+xn_kKO2aibGpqNNqm6Q@mail.gmail.com>
Subject: Re: [linux-next:master] [slub] b82c7add4c: WARNING:at_mm/slub.c:#slab_free_after_rcu_debug
To: kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, 
	Linux Memory Management List <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Pekka Enberg <penberg@kernel.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=dcoY2Jju;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Hi!

On Wed, Aug 7, 2024 at 10:42=E2=80=AFAM kernel test robot <oliver.sang@inte=
l.com> wrote:
> hi, Jann Horn,
>
> as you educated me last time, I know this b82c7add4c is v5:)
> the CONFIG_SLUB_RCU_DEBUG is really enabled, and we saw lots of WARNING i=
n dmesg
> https://download.01.org/0day-ci/archive/20240807/202408071606.258f19a0-ol=
iver.sang@intel.com/dmesg.xz
>
> not sure if it's expected? below report (parsed one of WARNING) just FYI.

Thanks a lot, and sorry that my series is creating so much work for you...

Okay, all these warnings at mm/slub.c:4550 are for the "if
(WARN_ON(is_kfence_address(rcu_head)))" check, which was wrong up to
v5 and fixed in v6. syzbot had also encountered that bug...

Thanks for letting me know, and have a nice day!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez1if0dEpL9kdby%3D5%3DPcFfnwSP%2Bxn_kKO2aibGpqNNqm6Q%40mail.=
gmail.com.
