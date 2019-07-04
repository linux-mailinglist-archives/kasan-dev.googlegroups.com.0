Return-Path: <kasan-dev+bncBCMIZB7QWENRBS4D7HUAKGQE6CJJXLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B8345FCBF
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jul 2019 20:13:33 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id d3sf4096700pgc.9
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jul 2019 11:13:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562264012; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pi8SAf+1OIB+xkq35iQvI2plaLRbDfMKultuCMEWrky1Itnp1sBezVWGkSvyj4RV2J
         /984LwIB4pIVd6TU4DtlMBEGU/gSkqyIMh2i44ot3VGqfd23JNDn1blv4Fwb9dkzJmSI
         CKnhzLDDEzQXD1LVpPVBf0A4j1imEhwRti1Q3ueOsE92jFqizMs2Xt7n2xwrCcHPM6tG
         GkQg0icMe3zL/2mpbiNhEyw0W0eEQt4WGGUSgHYR9L3K9inxoYKTwzfX08I4oRPY2WFT
         o5PDlURSsd3+QS9YZpH72rBvScmHUVCYaODTbtm430rVeJ2PnVaRgiCpxb5PtwrK8dOI
         /jqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eBh2jyR/o9qKeBaTuOs8Gakybj7v7lCUF2h8ufsq4U0=;
        b=D0kSXIMYz1/2fvrNCco5Ao1tjPbKHw3C/rp2PtbU8MKff8JezaanOi1aAGv025kleo
         2AvozcSYodhBGqubcTKFgBv1CU8yCuKH5/pKY6llkQJ9IW2oUIiWhnwxvmfzJdOM2ebo
         gojtwUs1d70b/q9vEnchD1606Tbmn0EM+LzQa5DgOVMPQ0KlFqw2TPK2yW8j/3Ev0P3X
         1K8lxU4C+nsWcvTH3sZhGOLX40YDSoNVxIGePjQbUxT6YeFkexoPNMNsfAnt9PYHylny
         VjtNlETjl3F8Ih9nUDXoEN2e1/OMFdqkT5Ifg6WsqNelWsFB36oSnDaeRgy8KybIA3kW
         NevA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M9uMEfmq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eBh2jyR/o9qKeBaTuOs8Gakybj7v7lCUF2h8ufsq4U0=;
        b=REbXJEmdh55Avkkp0tW5Chyrsaa0i+WVovzNpHFxFFsOqPqk1p6fVnkaRQJAC6UqiB
         GoC1WQ6L8qAxj9/C49FXnD+n9qR/XLbHyPIIf1TMWkjgkbbCEOQ+DMtgk7O2pHtATW8j
         ohAZN63m7mgkRTiOZCuSnZTeUP19zGy98Y6CXT+wbfhqPwhyYm5S69yClZApj3nfqwaF
         udwwyGpMrBDgzkPAos3YjwmdYV/Rfv96Dcr3C1CyvMx/fmNqwuG1Nt5Kde9jOa47r7dI
         GIp+NN7kHKViZ00jPyet/zJGStjg455t2/F9T3fXJGamurvioOgW4jC1HsLJaSZvEzp/
         NozQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eBh2jyR/o9qKeBaTuOs8Gakybj7v7lCUF2h8ufsq4U0=;
        b=Um8CsubPyUM+Vi5jH0a7ZF7Igup4Y9AvYQsHAdHNlDz53NJk/gS2pqwlwKMB7Sy2qF
         vMlorR3TnIm209uGlRXt2GyeXtcXhOLCoQkh0kFPzsklfAsmwNjSJyae/Bee9QgCkAsu
         X0QyKmhyfbv+E8Qi86TkpZsV662iWJO6LvTPZwToL2sMFT1Hdcv/h6EwU0KNzBXFWbz9
         /HmihZXrwI/jXc/llPJqB8SWgj2HltBSE+3wRrChKqlWTF/J4nRFqIyiXLn5a09z97H4
         QvU5JhhZH7RDhawZuaaMEp2Z0LglMScyyVgzTAe/acg5HXL4NJIMDsTCJZDMCQbxUHfs
         eJbA==
X-Gm-Message-State: APjAAAUwGhE1PLS8cKf3WtL+cubUTj+iQctaKaT7mW07vTSSvftEQuIb
	QeroxqeQCIQS+9Lv1KFW8Uk=
X-Google-Smtp-Source: APXvYqwBfqkB6A7afc0klt8ng+BXvER5PjKXx6jYPnZokD5cVwvxHxYFmSL2TujLWyPHosSrNzPk0Q==
X-Received: by 2002:a63:5045:: with SMTP id q5mr43237953pgl.380.1562264011564;
        Thu, 04 Jul 2019 11:13:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:372f:: with SMTP id u44ls2297499pjb.5.canary-gmail;
 Thu, 04 Jul 2019 11:13:31 -0700 (PDT)
X-Received: by 2002:a17:902:7d86:: with SMTP id a6mr50685121plm.199.1562264011149;
        Thu, 04 Jul 2019 11:13:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562264011; cv=none;
        d=google.com; s=arc-20160816;
        b=E93+4/NFmWId3IyVqxUz8eY1MakwA/b6UtPWjnfI76ItCOG2WM8Nff0YxaxDmTdcu6
         NFrT+sHA56Xw/TAzq5JHvSxIBbvzvCl6uuIqm6nHdwVlxHZAAe6en6A+4IA05FARqcYc
         eri5dqnMtSBWKGBggw+Mv/5WKpBQ8VPNABqq2YpsUcHh8UygnnCEYcw9UHcJcichztaL
         gBHeKr5kYGuZQaLQRZzoq7WjNsfMVqUe91KDUQ43Ultoz2guujIrgePVuYmQV5dncfj4
         mGS71iFHpdW25PqofzG+inuVf00HQMsH+ksVrjNeHOXqhI7+vXHpmkxAsT3CRS1ru2BH
         mcDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v58Fd/eFKWlEcjs2ag+lFz4xC1jGgKhb9EaMB1xXxy4=;
        b=X+LohOmNAuKBa5awCfxIcwNOFO3RqJZ3lVWWgGt1VxvRJftWqVr9WN8gyBXKIImwV+
         slgKEjyS6RivL5q7G3Xl4rAC1tJb3Ak3tfNlMQpksFJuQ3KhL84d4dnHsjt0H1v3BV1x
         H7yzHoDpVMh3V1XfrXbbaDx3BCGS0S6OrjYgViJUJKLN2565ivULZeSTYObYd3CboySO
         wKoOmWkSiNDsgWSZer7zp/V0j7avLd91UfQsZeQv1wdDqmtoYGI8Iy6Slpro1/vrS9kz
         7/ouQloHB9M3MoEJI3EpKlxmU5rN7g1XsTcVHx2oo+ZICNi1erwPRbEv1JVUah7U5AtD
         naEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M9uMEfmq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id j18si314605pfh.4.2019.07.04.11.13.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Jul 2019 11:13:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id e5so9978749iok.4
        for <kasan-dev@googlegroups.com>; Thu, 04 Jul 2019 11:13:31 -0700 (PDT)
X-Received: by 2002:a02:22c6:: with SMTP id o189mr5152895jao.35.1562264010267;
 Thu, 04 Jul 2019 11:13:30 -0700 (PDT)
MIME-Version: 1.0
References: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
 <CACT4Y+bNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga=BnkscQ@mail.gmail.com>
 <CAOMFOmWrBT8z8ngZOFDR2d4ssPB5=t-hTwump6tF+=7A4YhvBA@mail.gmail.com>
 <CACT4Y+ZJcp9fTsnvc+S3mG5qUJwvdPfgyi3O5=u_+=LGrbTzdg@mail.gmail.com> <CAOMFOmW3td2MYdDEAY1ivjW7fLdtgdk_E_J1VTqNj5ZWNYenaA@mail.gmail.com>
In-Reply-To: <CAOMFOmW3td2MYdDEAY1ivjW7fLdtgdk_E_J1VTqNj5ZWNYenaA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jul 2019 20:13:17 +0200
Message-ID: <CACT4Y+bWYwQYRH=6-zm3_XjSsM3B9M3QWUe4bsdPnbH+r1-aAQ@mail.gmail.com>
Subject: Re: KTSAN and Linux semaphores
To: Anatol Pomozov <anatol.pomozov@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=M9uMEfmq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42
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

On Wed, Jul 3, 2019 at 5:45 PM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
>
> Hello folks
>
> Alright, I pushed the rebased code to
> https://github.com/google/ktsan/commits/ktsan-master
>
> Besides rebasing to Torvald's tree it also fixes a number of issues
> and crashes in KTSAN code itself. It boots fine with Debian stable
> guest at a beefy workstation. At my home coputer with 32GB and Arch
> guest OS it works mostly fine but sometimes (like ~5% of all cases) I
> see it hangs without any WARN messages. It might be related to a
> memory pressure or something else, had no time to debug it.

This is very nice! You are finishing our OKRs :)
Marco is finishing some KASAN-related tasks and then will switch to
KTSAN. We want to setup a minimal syzbot instance with KTSAN, mostly
to provide continuous testing for KTSAN itself at this point. But
depending on how well it works we may start slowly reporting real
races upstream too.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbWYwQYRH%3D6-zm3_XjSsM3B9M3QWUe4bsdPnbH%2Br1-aAQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
