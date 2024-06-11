Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGUUUCZQMGQEEGGC6EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EFC7903640
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 10:26:04 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4406ccfc46dsf7221421cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 01:26:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718094363; cv=pass;
        d=google.com; s=arc-20160816;
        b=gNEASjmSiWGRJR4afr/PKXl6Ae2RtUEVmUW++Uc4vjYbVNTZj+QbQ4C/ZMzX+WmT1R
         nlW6qTRurPqGRSKjUvX0pHQvA4gRdRijnzXFbY7TmhE4aQyswXR2bRgDcG5P4gT9e9p4
         7IZ6AhnO7gOkJQjKjrA1LSTAjxtFCnJPzT60hOUElhzuMYNQgmcPC5EUe+NdPFALS7dh
         e+2dTrYgV3FYpJ12WCfcz6budKduYdgmHeFYFbbJm5RzZ9dHZRMg+mjQCa+RxTw/J23C
         GzwdHV6T0pP7GS/agP1sAL9q9oyyiuDSEdOZQAzKHalit+Oem99q0w9be2ImvHSShJgm
         a0dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:mime-version:dkim-signature;
        bh=bueYqaCk/T91nBI3Fl5/CxHU8uVC5rciHOFBUuelAxM=;
        fh=Gi6unkmxmQJ8jPhLwzZ3OunzUn4yfvQZmy4fpWYLIh8=;
        b=0hVCb+oUqHepSoD8dsrfqIPbYruPF/e/yhWB1d7oJpGYUmh5ZllQJw9cnBrhdF4F//
         rLItd5czt/tbw4JHUZYYpZt6w6kbLD33wRhwLwckhIphLxcpxIDkFcsn33emE5EL/IoA
         7tG12FnAOvoYsRQjHFMnv8Hy3iJCQOY958SU016qflB0LgQHQOj+rRE7nSMbyX5vTVFm
         g2Le9rkiPkjAVaStCKXeHEPfkmwYkuoS1hFWboAs2uo0F/H7WLpww093y22etAg4XpBf
         8oy38bwOvhajjQh6XKZQqcDtvr7foXwGnpyLfN6yRyWBc1Z1I6tgyz5XjwhIRJ6lDq5a
         w8ig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ml9OQ12g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718094363; x=1718699163; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bueYqaCk/T91nBI3Fl5/CxHU8uVC5rciHOFBUuelAxM=;
        b=W+wDLRa+Fz6bwl4rYyT2JnhLnwaNpjfgXrWoPzOcA2DkGzBNJVIu91VbNn29sj9Qs1
         WcbOL+TcVOGp8ztT4Xz7gkDrZmbI0dORybfibBk+htPA3RmZnGZ0SUPlmplReYBrDcG7
         Q3Vx19McaQ/jMxK5NYQ2wEy6NZPiVvmDuCdXkgKfleHqTFxs8XJsG+OjA5+B6be1FP9M
         QRVO6fBHv86UGmrazmgcS7BIpUutK3WJFhpoV2oH8ul+vJGCZ7LVzADw2HlQ413FcftZ
         DwNCrTpzMT6dhrYQFwofSNO5N24a6uBzVdikCjyZvDFCc/2MaqDxucXkJ+xJXnmEN0Ja
         qM3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718094363; x=1718699163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bueYqaCk/T91nBI3Fl5/CxHU8uVC5rciHOFBUuelAxM=;
        b=tW0uV5NG0wl4mBLvLhEDUAEnrSSjsxfvwuFAshHZHLQlOsV2QXp9T1I4P4+9+rdmoT
         bfCnUal2ptunhOgA0CYwa6SkNQ1mLKzyiiYqGrqhMut4PyL0qjIh/OxSRw/wME3MlNMd
         gbXgbX+fW3oxW4I9iXm8KCGLm1M5z5zxoiwuZ+46Usk+mXFMMLGmfhag/Knd1/xY7N0k
         JDKtFzE5miWtHBGgfmr8pUyQsWXSeYnCy3D7ZpHOu8x/owHNvPgVln2BHart1SwXcOQ3
         o57fjyaz7CEVKWqWmuQ26SBf1x8t1kDnG3QS7GDkfMjagsFMnf77bHKhrg9I1KShCjKk
         CsxQ==
X-Forwarded-Encrypted: i=2; AJvYcCUm0EN3L3Vcy8fTzRZXcgGZqLGP2prvjOx76jKuw8ZvbQjMyahq3vRtXObBf0GfhBz/MFP6uaVp0wT0Lxkk2tH/IWuQTC5hWw==
X-Gm-Message-State: AOJu0YyptY2TiX+lUtwsq54BtQcFflLUqUift4LsWgAgrtOoKyxlnM0K
	BRlut4P1pfeSYrfX6+1n9tR/J969XBFClrZOOk9vxX1Ea8K82jTq
X-Google-Smtp-Source: AGHT+IFL/QjgD++Bq/2PKq/po37ol4AcxhbdUUvzfkeqaSswN6p/mGygXHOPFDaACYBwY03Lr3rBEQ==
X-Received: by 2002:a05:622a:24f:b0:441:788:908 with SMTP id d75a77b69052e-441078818a9mr43483721cf.66.1718094363112;
        Tue, 11 Jun 2024 01:26:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a11:b0:440:ff43:c1cf with SMTP id
 d75a77b69052e-441360234a3ls9425311cf.1.-pod-prod-08-us; Tue, 11 Jun 2024
 01:26:02 -0700 (PDT)
X-Received: by 2002:a05:6102:759:b0:48c:3174:a8e0 with SMTP id ada2fe7eead31-48c3174a958mr9394835137.16.1718094362197;
        Tue, 11 Jun 2024 01:26:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718094362; cv=none;
        d=google.com; s=arc-20160816;
        b=BLqUJaK0Cxisth4JbAF6xL0MD2Aw3KM3L4vzCDmbdeQ5zv+i4nh1roec3747MLFz2m
         jwwE4MQwE10NEFL7S25kdOL44NgXtwJx1cOLqvQGzoUNSe5oXkSPuypl45awtZ15opuP
         9FD9vhxNSO+lrcfjVGiu+4a70k1NYxhRrtUM1crlrSoVWk5BcKEB8iJoZB54w+mAg94u
         VJUsTth7WpbVsjemGtFqTeqnaQbKmUVf7NNdl6C9LnMory2aubQJxGLMXKEyhLa96RSy
         +afyYkF2gscmUVOmfsr2H831sPF3yWA5lWf0vgH4A3vHMGd7N5bC0zBw4gKWwqgi6hQ8
         GzYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=ONsoN85X2a2/YNDxMAqYftD0pxqs2anE2AkVugSt+pM=;
        fh=7DXMdIN8+wqT7KPx/9s0a8CjAHRCBl+kRzfQzjH6sbA=;
        b=OYQnBDXE77+cmaXDSbZY5TdRrGCdThzZVE0rlq1EvJVKxUBYkQO/vTvE16DasqrQuM
         TFluFa6oZjs4FJhvNLMItumXq1NyEptQlrzk4qQvDZ0ZaDClO/NOYvvo5BEXes5Pe2gf
         Fi/Ntlsb3Bvc5RM0UeVCdeCwz2tqFyhKybIIZ+rN+kiEgiTb08GhkQo0Qxh1qkNAh24s
         nVkbu65BHudj07nJ7mWFV4krXsrXhsKONDFJh2YqYSIIObPuIPUxH+eT+RTbML08/vx1
         fNtgZSR3Dh+MD422cZT99RI6WBOv7CkdWMhUz0bt9h/X9a/mVTXlu6RPgMIiOXh8tVgn
         gWsg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ml9OQ12g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe30.google.com (mail-vs1-xe30.google.com. [2607:f8b0:4864:20::e30])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-80b8b26c5b3si304116241.0.2024.06.11.01.26.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 01:26:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) client-ip=2607:f8b0:4864:20::e30;
Received: by mail-vs1-xe30.google.com with SMTP id ada2fe7eead31-48c458b9aa7so228839137.2
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 01:26:02 -0700 (PDT)
X-Received: by 2002:a05:6102:2426:b0:48c:4c01:34ff with SMTP id
 ada2fe7eead31-48c4c0135b4mr5242736137.21.1718094361670; Tue, 11 Jun 2024
 01:26:01 -0700 (PDT)
MIME-Version: 1.0
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Jun 2024 10:25:22 +0200
Message-ID: <CANpmjNM-0ALzHqVaEO2u-OGncYQa-KWKtsTCfioSjG4c+YnRbA@mail.gmail.com>
Subject: BoF at LPC 2024 on Sanitizers and Syzkaller
To: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Kees Cook <keescook@chromium.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Ml9OQ12g;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e30 as
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

Hi all,

[Cc'ing K*SAN and syzkaller mailing lists, in case any collaborators
have particular topics they'd like to discuss.]

Paul has reminded me that it might be helpful to do a BoF (or also
talk) on the topic of kernel sanitizers at Linux Plumbers Conference
2024.

Last year Aleksandr did a BoF on syzkaller and syzbot and said it was
helpful with plenty of topics discussed.

My question to fellow K*SAN and syzkaller maintainers and collaborators:

  1. Would you be interested in joining a BoF on Kernel Sanitizers?
Since 2019 (the last in-person LPC I have attended), the kernel has
grown several new sanitizers: KCSAN, KFENCE, KMSAN. I suspect that if
we include the whole range of sanitizers (KASAN, KCSAN, KMSAN, UBSAN,
KFENCE) there will be plenty to talk about, but may also be not enough
time to do any particular topic justice. One way to solve this is by
driving the discussion and allocating an equal amount of time to each
sanitizer (and if there is nothing to talk, move on to the next).

  2. Are we interested in another BoF on syzkaller?

  3. What kind of talk, if any, could be helpful? I have one idea that
might be helpful:

      a. Kernel-focused variant of the GWP-ASan talk:
https://github.com/google/sanitizers/blob/master/gwp-asan/icse2024/slides.pdf
- I would change the talk to not describe the user space version, but
instead talk about how KFENCE works. But the rest, such as results and
intro, would be similar. Title would be "Sampling-Based Detection of
Memory-Safety Bugs in Production". Such a talk might give further
awareness to KFENCE (and GWP-ASan in user space) and perhaps help get
it enabled in more places.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM-0ALzHqVaEO2u-OGncYQa-KWKtsTCfioSjG4c%2BYnRbA%40mail.gmail.com.
