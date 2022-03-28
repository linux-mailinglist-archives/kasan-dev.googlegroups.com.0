Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQUKRCJAMGQEDZ6MYEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id A0D814E9F47
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 20:58:11 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id d11-20020a17090a2a4b00b001c9c1dd3ac1sf1068313pjg.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 11:58:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648493890; cv=pass;
        d=google.com; s=arc-20160816;
        b=olUsgHIEZm62sqaga+Hf6n/HvJkwwiGOspGV4Y+JMQgBO0mKGjGrUuH7eA2SWE5MCa
         WksGNaf4qqJjcc9+ppjUWT8qy3G1ryC7JvT/KLV2HFQWCP1tVv8FVsrux0Rbv0q0PPgh
         5FfBlJv9mM+a5TbEwabqGeDBNt5Ub6D8VEZ2rq4kPx8eP6Qb4poCpL57fCmfczpLUrZh
         +52953lQ5ERw9qhBVamKBCbTUa8dBrslC5jjnL5eW2aeU/eZ2LGwA/QfI1A5uQU+BKqY
         e6Df8KjaU24WTuQnLdeYUGbhvmtDCvHSopvI6ENBeexaNezgpKA3/FZMI+VpooCskP+y
         Jurg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6vEokmx70TRfOyUTSNYL/dtQHb4j4HsWmevCmTbItb8=;
        b=sRYtilwaKVV4BPsGi2vYQJHJHYZAjLQA9S7aG3AOIRK6sNG0L8R1AUNmKBHG1h24ZY
         lhWVPOsraDQWLLkDI5U8PUBgR2wh58we+EECmlr43eWsGDfS4c9Tqdq+k2KHC1E/1Yok
         Hyw+gQRQJ82Ja2vh68iau186Q/Jvwx/37OBJjQTTjz2zLm6Y2ZkIWPwPtIAAjxdKtUzS
         wQ+3FetXGXhbNiazbWVfvHYO1fishmqcgeeiAoALPY1yDPMk+dVZ2WzaTGB9n8eOx2mQ
         P8GJ1rfgivOd6qkKZuvnW140a+pR7tfx7B2JMurCV6z06yGAOA+t9FW83XmU+uKMHd+H
         nFLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="R0RSG/eD";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6vEokmx70TRfOyUTSNYL/dtQHb4j4HsWmevCmTbItb8=;
        b=sD3ZTVJvoHMseRUy8ZNsO9ZFBDNTxzJdsghLWfPUCOaWlAb7EQUy0ItnyDdUWNAUIz
         k+2XM4JYys6wvtFwykUtlVR+mJcSVFQqND0SZDkbfTF/dK1uW8hUvnhNbDhUd3o72jNu
         bk0k6S55XuzPQ4o/ks9bmymkIrz2gt4inMUfLpGmN2PsWOhdKtOS47M9aRHJoRKfALmJ
         uVjfpzn0Gqapg8UzFVm4fr/GkZOYhQae59/cdEAWyQCtyZRm7CNGsIqBimme5S+2lYqO
         mKORKOQiuvkYFHZJnaVjWnLe4D6l4UBP9k2509mPYT7ZSFJSam1o6wBxg3ant9/GBvHQ
         A35Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6vEokmx70TRfOyUTSNYL/dtQHb4j4HsWmevCmTbItb8=;
        b=H87Q8c4QIBdxPinhjLDIlr2n9jFaopa6j7dVMj4W9XdHgePHLL7dwcYZjn/GjV5Kru
         T9Zi+qbs9Wei7icWmfX0VQiL5uF18DYwmTj3Q2DqMrhqVbgmKJgYFponSb7mNyJtjzAT
         9Uj6JpgDIIrsGuvfdOzAQJRvk6vsv2qP0kEq5t6+4kwmaNWVkDiB86RU0AhfdM2Ec5Cs
         HqAj7G/h+LDiIGBMM/hlHduODfxgexGT/7/kJ8t8SmKUnYkHPRZse5eb2/uvOEdg0NEK
         fJaS75mywODi66lkY2wCxlvxVcrMud/jO7m5k7kNvL9kewbiQneCvM2sPioWpUcQiQyP
         7Llg==
X-Gm-Message-State: AOAM532Rd1RbP6862935m2gAY8LsJCeBe26wx2RRQjET9YhGxko1RkYD
	HYuwrpgKvHULJYu38IN3Q9k=
X-Google-Smtp-Source: ABdhPJzUN8G+SpwAli7k9LBDfbe2fT1HUiA550j3OFVNpJAmewds6sE+/m/60rGAictFj6sZUz3LGw==
X-Received: by 2002:a17:90a:9510:b0:1c7:b89f:4a59 with SMTP id t16-20020a17090a951000b001c7b89f4a59mr582249pjo.37.1648493890330;
        Mon, 28 Mar 2022 11:58:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8c:b0:14d:d65a:dbdb with SMTP id
 m12-20020a170902bb8c00b0014dd65adbdbls10473517pls.6.gmail; Mon, 28 Mar 2022
 11:58:09 -0700 (PDT)
X-Received: by 2002:a17:903:32c9:b0:154:3a2d:fa89 with SMTP id i9-20020a17090332c900b001543a2dfa89mr26879550plr.3.1648493889686;
        Mon, 28 Mar 2022 11:58:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648493889; cv=none;
        d=google.com; s=arc-20160816;
        b=0DtS9+YaZ+6E9Bq/eP8itNpoO1w196Xo8xomtFsXECP5lYsN088yBp74jFkspnLdfh
         aAglPCshaNErfo789FMWl/fN1jbz85yXvNXRS6amBasCX5KeF9hf3VJ7i4FZBEPB4sBH
         LZWf8cX3MH0J+z62nQAidv6HFVcsT8+4GZQ0vCKhHl2ZxoM3WFCcLTS3EXEZSDD3P25t
         gPD7xdwBV0c1U4cJEeVjgGmHYZfSgzp+I9ThGEb/Z0FGdW44QCw0UlbsbrJQoUwmavxL
         +vtmrqpkv6EL2gJk0EKfaDWOLQmFk5WWCE9CRECfHMT4EjEjKMkU7Qmv+rSCeRbEglq4
         wnYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8612p/69znHIDRySiH+8dA+VUWRJM0II/moWC9PgDh0=;
        b=oCngCAuDeOvpl5tpUMXdRmm4sZXZkkYnrByP0ZDWBm3skHbJukgFYMbDXZiw63HVu1
         M7Ii1+cXTuZgusTGyrSZomAPGIGzPdsvsNbORxQI5bd3P1DGjFvn4cAnQTVWTSoxGJwM
         dwz2zG//MHHoSIQPuvYpgSHKCvsq2/UsKf71/c9byFZ+DDkHT6N639Vmq384OiIDTD35
         cQwad6ZY40DsIWd1MFUEJw7hPd++uB9nq2HYS/Z5XNjrROSHneY+bAd/OVe/BTVqnz9i
         q4UivjuR2QpiINn0Zm60noVXDOAS2YWPal4+N+IRhjyEUnmfLiJSIoFlODfPMfxmVtGJ
         xS5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="R0RSG/eD";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id gq24-20020a17090b105800b001c75ad33c27si33433pjb.3.2022.03.28.11.58.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 11:58:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id y142so27649243ybe.11
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 11:58:09 -0700 (PDT)
X-Received: by 2002:a05:6902:241:b0:633:d3e1:ff5e with SMTP id
 k1-20020a056902024100b00633d3e1ff5emr24158708ybs.625.1648493888782; Mon, 28
 Mar 2022 11:58:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220328132843.16624-1-songmuchun@bytedance.com>
 <CANpmjNO=vMYhL_Uf3ewXvfWoan3q+cYjWV0jEze7toKSh2HRjg@mail.gmail.com>
 <CAMZfGtWfudKnm71uNQtS-=+3_m25nsfPDo8-vZYzrktQbxHUMA@mail.gmail.com> <CAMZfGtVkp+xCM3kgLHRNRFUs_fus0f3Ry_jFv8QaSWLfnkXREg@mail.gmail.com>
In-Reply-To: <CAMZfGtVkp+xCM3kgLHRNRFUs_fus0f3Ry_jFv8QaSWLfnkXREg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Mar 2022 20:57:32 +0200
Message-ID: <CANpmjNMszqqOF6TA1RmE93=xRU9pA5oc4RBoAtS+sBWwvS5y4w@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: fix objcgs vector allocation
To: Muchun Song <songmuchun@bytedance.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Xiongchun duan <duanxiongchun@bytedance.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="R0RSG/eD";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as
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

On Mon, 28 Mar 2022 at 17:54, Muchun Song <songmuchun@bytedance.com> wrote:
[...]
> > >
> > > Btw, how did you test this?
> > >
>
> I have tested it with syzkaller with the following configs.
> And I didn't find any issues.
>
> CONFIG_KFENCE=y
> CONFIG_KFENCE_SAMPLE_INTERVAL=10
> CONFIG_KFENCE_NUM_OBJECTS=2550
> CONFIG_KFENCE_DEFERRABLE=n
> CONFIG_KFENCE_STATIC_KEYS=y
> CONFIG_KFENCE_STRESS_TEST_FAULTS=0

Hmm, I would have expected that you have some definitive test case
that shows the issue, and with the patch the issue is gone. Were there
issues triggered by syzkaller w/o this patch?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMszqqOF6TA1RmE93%3DxRU9pA5oc4RBoAtS%2BsBWwvS5y4w%40mail.gmail.com.
