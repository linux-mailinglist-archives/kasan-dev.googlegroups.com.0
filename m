Return-Path: <kasan-dev+bncBCFON2UTZYBBBY5CVWFAMGQEL4KUYZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id F1604414D78
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Sep 2021 17:53:08 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id r4-20020ab03a84000000b002b5e4fae298sf974339uaw.10
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Sep 2021 08:53:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632325988; cv=pass;
        d=google.com; s=arc-20160816;
        b=JUJwFpSsd6qEbb9oz+nLtEinpewFWIRcX2Hr4BrsdpcIhqt3TN4hOpDs4buS3xOhDs
         jdFbkxY4da/eNJzEtNUaVMpNeO+yYZYGwUAMOgmEu59c2AtAYZ0KWT+JTbhMwQJGYNbF
         m70V/WCOFwV6GssBvU65/JQXxnNYdaAhKkdqR7HjTi6T5FYji46W7l7xb3P9Vfrusell
         jU8HAgYOpKFg26jV2u2mx7kW95C92TxbGEEi8TudND/QLKRdoiGuy2xGISQg1z0SxZ5X
         QynKdh5luvrB2enwJ4Uu5S5y0UioUtEqSpdqn2irLLG09E/wL56DbpOqEZPlfDhLOq0t
         W4Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=gTw/9gyJgad5jOtVNgF55V5Uf+5RZoxMFFJ75/p6PVw=;
        b=jrv49IP7v6dzNglS6/UihC134ZJ6QiBwmVgJi42uV4rrU7/kt/A3SvSyMyjBlU2MD2
         fGe7vnsy2hIGFTpq51mBzBuhLoZyKVo5TXb5cVBH3sUIM1XFZtcCE3E0UP9+UTs8oh/7
         Vo5GjugqOCQASYYAfLm3X/nnvb8GlDKVm/lVpfyruHMrc0Xa7KJqWYEFXD3k5cqUNslm
         hLW5jIkVWIFWoLDPolWNciXrgrQB81gSdAZaJfMzFs663sZrrR9AqxuzaC4PVbumvbKo
         6SW5NBUs1xzWTjQoVd2aiq+eFekkmF7veTYEnnq+CZb1saKJlO0NuZhqab8nuo5PlAhV
         fOPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jJP2q82V;
       spf=pass (google.com: domain of erickoumedjro@gmail.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=erickoumedjro@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gTw/9gyJgad5jOtVNgF55V5Uf+5RZoxMFFJ75/p6PVw=;
        b=HxNKyj3JLI/tUZovTBPsRNdIXjoap39gsGFz8B22WnWlW8L4qIEaRRWdlREuAPU0xp
         hIRWLuRRaEw1/BqVFZ2Rj/aMvGgOXoexRf35HgeLcE75LQHUZ3EZq9y+cn/+tLGHkxxu
         MiHQzu54ofeGLFK+rkpooOmF3G3lygfznEJh/1izEE+jJuziPwWCVYX16S+CZ0FK3ada
         Qb98sHvLN7qmHXhIIIhCLIhhM2zIFx9pD0LdmJd/o7DdX2Qbqpgay6hb57RZPqNCkhKb
         iJyhFtM/endj1lKQhrUW6fTu97LGxuRkrKknf5LzwUbWpFPN9JT55s3j+4y5GWJ5/djE
         6ahw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gTw/9gyJgad5jOtVNgF55V5Uf+5RZoxMFFJ75/p6PVw=;
        b=Hcx+WuqYG9NQlEHZYlSdvsDPE49RCA2eq1P6kZtVuwaDhAnKNfOd2CaATPOJPDVhFx
         /dy7nQ9c3Ah+S/YHSiznFYt8nj6WVOo3+kte2Y0AB7OcD+FQWY4tlrkr+PEkNdKFdLMh
         AFL7mjcWZSIqEHYQ3cfnGRDevAmpd+8wkTKhud92ArPtROQEVLRU0nCrFO9xtE22Fzok
         Z91WYw/OkvZyE4xjz0o40CWWCBki7bX6zAh9+08FbOI653NQI1yCZJy09SGpon6Vyzkm
         OJc8Yt2EZZqicQAStaS92Z1wLYV7S1RREcfeOtleLhHYTD0/MXHFAu/0KrnnOw1wlmsr
         oysQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gTw/9gyJgad5jOtVNgF55V5Uf+5RZoxMFFJ75/p6PVw=;
        b=0CAI+3sv4GTlChTE4rZ6uXvzSDwdlCITY0qVzdnz8VQnZO0PU9+rbtFwhYrJXb6VW5
         6dbTayDXWl0bsY/AN2AMTZOprJMZAZ88yc70rH/NKOjvwQnAzbUbsMA/RarJ/AsdO/ul
         LtPETiFkFGkpDy+ZVH9cgX9c0Nfn9qAyJNQocnvKvWAbRQMQCXC5/MgGghEbSxkptpG6
         6vNRPYoQ1iLfwlUZuc4nSWSaANzn6SK9rarWrsFyYAkL2SgeHw55hGf8DpvA6JWSf67A
         JoVqoyJl4UVTob8rVVk/GI6+tKMnQP531GJw0R8lWRoMZ6tomNJ3KpHM7kzIRtGRwChd
         OGMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jAxALabrqk1Symd6nwfm2v8Bz6ZJcjvFPXNhvgk/ZNwzJ/DfP
	H6TC5zvCgmLaGsowNOSHNy8=
X-Google-Smtp-Source: ABdhPJwZGTXA9NTS+cUQ+eqeoS2JwD0+vkfG4b8IYuBe3kLbk042cm3qH0PZ22fnKSseCyCiPZ4Yrg==
X-Received: by 2002:ab0:3447:: with SMTP id a7mr489801uaq.56.1632325987904;
        Wed, 22 Sep 2021 08:53:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:b009:: with SMTP id z9ls667438vse.10.gmail; Wed, 22 Sep
 2021 08:53:07 -0700 (PDT)
X-Received: by 2002:a67:fad5:: with SMTP id g21mr472352vsq.40.1632325987337;
        Wed, 22 Sep 2021 08:53:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632325987; cv=none;
        d=google.com; s=arc-20160816;
        b=JCG08QzXu1iIjaLQyjGzztH+2k7v4O6Z24jheDDJwJMv+3hddTCgtY0l1U+lm5aF12
         w/3qMftlwNPkD0nBV3JvvxkiSmCy/d+ImXhRsmf132MCVBCmFa/7MYbkxcTO5kz7ghVV
         vqb+ryv1QXdD6rgCRa97IZ+JRKlhymNBwoGAvyOHlnoafLhHJoqz8Fo3jZkudVurY2gc
         B/93GB5MZvvqiQQzpumnfFyJLeZ1Cp5AETNaEkW8lF1nKhYDb+nLCAMH1IWQrrRr5KpS
         AU5UWU88l44wwOowwPPmIG5cXdPe5/uE/O9pXywix31eo+nWJ4Tz387iNciTocIGPuAZ
         BTKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=gRruMmVMYJ+84wazlw/4k3bgmd+nxRPQzyNXftYJHhU=;
        b=LLYfL0wMi33/O4TVIPRe+fWbpnIywYf+LDAe4LMuFwC8xQ3dG+6oTbPz+kLYnrUgV0
         mBoJQeFtdrLMn3hgM9dLo1mtvMYSVuLvZkDrIx2GqyQyAToxSm9g9vKDZe0vv1pFq9DC
         zh02PwRaVzEZ8A3DqvEMY5URwPz2u7jMc+ItgpQk4oLr4j3VciirD9H/yW0Xrmmrjajt
         CljEN3wp3V5DgnvWcR3/EyqllJ/x5TTCMTUxJk0KCa7inHuzBzKbWYaTIHtHSPACUVJC
         qaeHt+l4M3Nte4EaccUe8wucfhmxJ1xsA6c1TFh3vLxg8kJRiw0CguZYikvNxVbdPUal
         DE8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jJP2q82V;
       spf=pass (google.com: domain of erickoumedjro@gmail.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=erickoumedjro@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x932.google.com (mail-ua1-x932.google.com. [2607:f8b0:4864:20::932])
        by gmr-mx.google.com with ESMTPS id 4si194429vke.2.2021.09.22.08.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Sep 2021 08:53:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of erickoumedjro@gmail.com designates 2607:f8b0:4864:20::932 as permitted sender) client-ip=2607:f8b0:4864:20::932;
Received: by mail-ua1-x932.google.com with SMTP id r8so2197007uap.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Sep 2021 08:53:07 -0700 (PDT)
X-Received: by 2002:ab0:7e85:: with SMTP id j5mr499569uax.2.1632325987103;
 Wed, 22 Sep 2021 08:53:07 -0700 (PDT)
MIME-Version: 1.0
Reply-To: vlastuinmatthew66@gmail.com
From: Vlastuin Matthew <vlastuinmatthew66@gmail.com>
Date: Wed, 22 Sep 2021 15:52:57 +0000
Message-ID: <CAMqmNDgiWqqF5ConyogQ_Fzcxxb_VemweYKE16UOdB2MhzOx4A@mail.gmail.com>
Subject: Help
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000009e78ae05cc9782c2"
X-Original-Sender: vlastuinmatthew66@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=jJP2q82V;       spf=pass
 (google.com: domain of erickoumedjro@gmail.com designates 2607:f8b0:4864:20::932
 as permitted sender) smtp.mailfrom=erickoumedjro@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000009e78ae05cc9782c2
Content-Type: text/plain; charset="UTF-8"

Please dear friend, I need your attention, reply. Best regards.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMqmNDgiWqqF5ConyogQ_Fzcxxb_VemweYKE16UOdB2MhzOx4A%40mail.gmail.com.

--0000000000009e78ae05cc9782c2
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Please dear friend, I need your attention, reply. Best reg=
ards.<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAMqmNDgiWqqF5ConyogQ_Fzcxxb_VemweYKE16UOdB2MhzOx4A%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAMqmNDgiWqqF5ConyogQ_Fzcxxb_VemweYKE16UOdB2MhzOx4A=
%40mail.gmail.com</a>.<br />

--0000000000009e78ae05cc9782c2--
