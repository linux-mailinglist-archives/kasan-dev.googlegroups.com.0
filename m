Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWOD7SFAMGQE7LNKGAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id B1E9F42580B
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 18:35:38 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id 7-20020aca2807000000b00276b595573dsf3778504oix.6
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 09:35:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633624537; cv=pass;
        d=google.com; s=arc-20160816;
        b=OA74D+8JlDVniQvxIDTrnnK3mSWobHUX3+Cj2h+aAKZ9I4zg6NCsTUBeu9gI1HXWSM
         1/HyYsBJz37PyZkjZCok/q/h7w/rMLks4gILkYMfVeIo0shshno8BoMahI//ZPE4y5vd
         6jr/Rb9Gq5+UZPTBt8fvGeOStHHz1HIBOW63b+v23azIc/vTjnW3mRHmgbJ4OvRQes80
         kjcqLS010FSHGcGOEhDNZvvrmbzOEZabTGgOOJfndhGYLag6r/wWtAWmmLVqpYb2v3aJ
         NEAOX2yUUu6GbvIACQOO+WIKrnSgxPn4VLKEX81Uoo95USaIEIZescOerdp+5LG3eqk6
         n0bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Pw/hNPKQbJAQGild/AXBLkUXGV5F0Vl05TPW0NyNeV4=;
        b=L76zDxZo5pTBhIsWFUOyvslKa7oDNlI8qQf1rOgLjChRnASwO4bjp3y5RrgQHXLv5i
         IXBDwc9WWw86Of2sknJWll65m2pe5MFeq/ynBA0O8xSpfej2VmCOVeh5sAYmec+OWR+V
         j/rtezmEbvmNgbn9GGZC6ks6Vn3e2kUv6XRr/WDrHNgqqRCqs8inCxpVPZ8LeyiOesH/
         IupRaTsu2BTsp3s9B8zdtx2sQD/DPM1Yi3EHLn4NF/3l3McUr7teBlGxeTFp5feaVyiz
         5OldFKMwReeYYhQdh514EQv/sgBgpNxCAnBujQhNnkivdcKxxqKqYvNehn78U374kqzp
         qm0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PZu+JBrK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pw/hNPKQbJAQGild/AXBLkUXGV5F0Vl05TPW0NyNeV4=;
        b=B2Xd3wLMX5v7FKsTi0m9UFmS8cap1ug1QuFs+9g+Ddqav3i9aKHSVYume/cHQVe0vu
         ann+HWVSnukC9nXkQMqufl1gkgylZBSCTQTWhJvJS6Hy5cfEaIa4uMuW32XGzLyeouqI
         ctN/wUqGut0+KsBB0bLUfurKWJB4q5R96ul5C6cpz57xBAvLFqbmXFj3GYNpZ+yNKHai
         G+lIdGpzbQ6ii/n8CVk9P4zr5wsOX0c3tm6fOad+/6hwiLbUuv4elyee035W2xQSx9oM
         jjJPY1lwqIrH8kgIOH5KbuAaneAbI8PcVPH3hvRzCHFWvuTqwSnKPjelX+WtSG55BUNl
         oKug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pw/hNPKQbJAQGild/AXBLkUXGV5F0Vl05TPW0NyNeV4=;
        b=fiPMz22b+Wgbw9ij11jiIrFy+/WNgVHuUyb8ARmZ1gDyewj10jeftcK9vROoGgymDP
         95oT2cXk328E2qBjYAhlaFaUmWDkwj2XZyH24GI2vVt7btlxcrx1psRSX5nh9oWBshJ2
         sEgeVgdGpuOJmy/eDF2S7eXUrPvJxl65JufIRobAnnv44G2zXrBjej0ulLtY+l28wdl1
         QXxTvZw7dwLwZYpLV0qRBfOT5MZ0AFAkpF9o6hTn4SCk+ByDTl7nm7v75IRi5fUUse6O
         R9yzx1t/h7r1Eji6Ru4dZl5Kd8XPwzpAfHrPTNM34luQd+6AkBvYtHSRUjZ/c1tAyahD
         rGHA==
X-Gm-Message-State: AOAM531Y+ItvuyhuP6IytCDELL91u0idhRGyFE8eq3pII/UWIQ3HXIpQ
	LeBvjyeJG/yRWR01z7yXbMg=
X-Google-Smtp-Source: ABdhPJxdH68ntPYGAK16DDjzL0eHBkCd9I1rusJe2dLHzW/9qVcqZ4T+1+FFPiXiBfouBCFGhJr13Q==
X-Received: by 2002:a4a:d251:: with SMTP id e17mr4108720oos.57.1633624537350;
        Thu, 07 Oct 2021 09:35:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:df56:: with SMTP id w83ls163513oig.3.gmail; Thu, 07 Oct
 2021 09:35:37 -0700 (PDT)
X-Received: by 2002:a05:6808:1641:: with SMTP id az1mr12441711oib.67.1633624536952;
        Thu, 07 Oct 2021 09:35:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633624536; cv=none;
        d=google.com; s=arc-20160816;
        b=xJTLf6Dip1cZpWJqU00XhF4uUzji7K5BJSwPT5SMFpZMAG43olzXEZgMpLpWb8U7Nz
         ZhFCwjlthnORr2EMB9/uHZbODKiI/P/KvVtQQm08iCkpkb25002OXK86h64IV4sNjpF2
         5/YzhjlVYU5CFBOrbTmnoNQgxjCKQs91cmBCZlQV2pAbz5n3sBT2zfZxyIHTg9rwQVK8
         AAstouvROsupfHVkgrHkvTiFe9/mInPMzFzTYmJ/c+jdbIG9JIowfcUuN1/WNVSDctgC
         PyUc30Dp25TXVVckXgoigjeW8lIyVkTE54NZq9t6jO+wrYzXP/Ktx9bEpME1uB8vPN2n
         ynaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nCRCBp29mQT9iVJuQWMc24xLxe6qTuiv5JwUggLsF0U=;
        b=V7J0kvwh7Fr0sMA8xPUWFGZGmKF5n2/KuJ12eidXrsQe//N/m1bbppcgSqiqn/MgT5
         vxvQGWrrR/5Cww5DiErRqVSII6SOLDoxl/xQdFmTFKVb9SmkRhvKlPfQhV8b7LwOUqpf
         ZswHiPMQFag2cRVqMlh5VwiVAqszfyrgPCdIQ31RB+sJ02F88OddLxSrqEvfFVSmvuNq
         HSfLbNRmGnMkyn8LOCLjp0FzCvG+0JBmUJuDthtbhRtVVqhJHPju/HkIzxa9uqtJoykY
         dtbNpdEqIUbQ0LxbkNVJdoOp3mx+S7FFi0AfxuT1DOacXhjfrVt68Dh/mnaob1U/6ohj
         5brg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PZu+JBrK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id bd5si8195oib.2.2021.10.07.09.35.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 09:35:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id n64so9814798oih.2
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 09:35:36 -0700 (PDT)
X-Received: by 2002:a54:4618:: with SMTP id p24mr3871519oip.134.1633624536556;
 Thu, 07 Oct 2021 09:35:36 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <20211007163019.GI880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211007163019.GI880162@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Oct 2021 18:35:24 +0200
Message-ID: <CANpmjNMqfVN=CfbxpMb9o=045thHLewB_eTOPFwT67gkO-vOuw@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: paulmck@kernel.org
Cc: kasan-dev <kasan-dev@googlegroups.com>, Boqun Feng <boqun.feng@gmail.com>, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PZu+JBrK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
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

On Thu, 7 Oct 2021 at 18:30, Paul E. McKenney <paulmck@kernel.org> wrote:
[...]
> May I add this information to the article with attribution?

Of course, please go ahead.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMqfVN%3DCfbxpMb9o%3D045thHLewB_eTOPFwT67gkO-vOuw%40mail.gmail.com.
