Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJHNRCIAMGQEPWUIMQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id CF93F4AD4B5
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 10:23:49 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id u9-20020ae9c009000000b0049ae89c924asf10526829qkk.9
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 01:23:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644312228; cv=pass;
        d=google.com; s=arc-20160816;
        b=oOw38HpXfhLugEUgIeH+7MTkBIFCqk3vFQdBx0G6QdPUymVG5NyPJTpiYO9lK75J5e
         xO56VZG4gYPJKHg8ZbHlejb9l/EuiLVV+qPgEIqYlp6XsZApnCeHd4CyDKpuaPp/753B
         hWFAA1Q6ymoY8YzXH2Hka7zU5bEcQzap/S6sAtnyMBi/VCkJOtKvfa5OUPDK2W6HfS1n
         YKWlkGeaV0XMSQ+ghwGJNSzamU4Gr5IgzyRxyL9DD4wfbzQFtic0eV4ig0SFQQwzQNLH
         MyhMYOqdn3SSd12z28guONdzqrgYTe+7J8TM9P+D64SEvMG9VzPqUBWm2fWag/0GgvVJ
         MYMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f+RnaZ5+3cYh8Pp3pTOjjzKEM2f9fVhjW56KnpvzQ1A=;
        b=byzMagEgmcFX+/hPFTRzQ8uqOzW5rVZxdRxrFBZNBX5XFJGLg0WIAzOBysizNh8pQw
         lwB/wYA75CczDApselMh0GTl5Hb5zKnM7qYSBGGlz0Im5jkcRk2Khz80bZXHFHqosH29
         fTDR2qZZaU43LLHVoBvU+q0haxyup8mpIyLNMfTKABf67m7U3999ZIo2qJBO8n18gEKq
         WNz52geRkPt1TQLLw5898P6hZRTMSOEB5pBgBzhbeNNMIIR68vnm5xbCWdTX7Dpqjqy9
         VkL0HujPFPQcrwbI3hmxsYnWbW9CS6kA1CMQA9iKV1ZqgIGr8jx8q7LNdPXAWtTvUMAI
         vUHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DX6memat;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f+RnaZ5+3cYh8Pp3pTOjjzKEM2f9fVhjW56KnpvzQ1A=;
        b=IiyKzEnq8T36V3gqi6XbAsz59COrkQWmO+GYxRwd0ft1fqFvDMAgG+AFgCF2TWKXm8
         vHXs5mKfIUp+AYgIPh/lyLRq0TU/LMUWhPgyy2UE2H46ezQYNPeeaz6U4d3DYjjYpqPl
         e0Z4QM012RewGz6AlYjPvbLtoYbvo/sePBjO+5HdM4r4kmia4KqFmY3ctCgqf5tV3BsL
         +eefntwH7v1aqh0kFdGgdRTgW3SxOuBx/hQnkFg/+MArJx4Ge+IyDRf1uxahvc2RQgMp
         Z0a3uDvYBJQaMg5qLcYs91l28+hZsta8sO+kk2XLAlu6XTfUpnaASN28FXv3X9KMZ81N
         vLUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f+RnaZ5+3cYh8Pp3pTOjjzKEM2f9fVhjW56KnpvzQ1A=;
        b=n7p1cJgCKhxsDCGjrkYeeqQL0lvt0rNLLPWoDROjuK37u6N/JdqaoF+VR3uSI5tg94
         FgRuBfuJB4uCkdJ3cUWKpaqBciMY2Y0alTdNdK4tNln0Nw9MD2ZETiXlQnridqfpYo2y
         1Uok09qKwxzBvlQi7pqm3+H42K38DhAhDEgXO/ytjGDTCRxoiM5n2iMNsjnKzcuvf/yL
         57KGEJLgwq4QimHd0m+LLmJFuSpg/YsxSoI/+CTPx0I1H+8fdVGhtzMpF/E+nHxNeykU
         QZoNetPf1p9DK7uDMVhhDmM76NLF4UFZT2SqYVar9irQ0PFT9vJyFoZ8X+RLimK8HAG3
         nOJg==
X-Gm-Message-State: AOAM533Saw7DX0ISRIjH4wxeKgeaGiHDHYaxFlgzgDmd6iRnGO+YXKpw
	BNM8NkOhXb0fqAhMiIN/muw=
X-Google-Smtp-Source: ABdhPJzOaKz2iuXgzIXXJcr82HzF7qtCecDedgFhUuNglHJJW1ho/TzT5ChVNrPt22AHjLgu7RB00g==
X-Received: by 2002:a05:622a:1011:: with SMTP id d17mr2369243qte.377.1644312228585;
        Tue, 08 Feb 2022 01:23:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1194:: with SMTP id d20ls5534990qtj.2.gmail; Tue, 08 Feb
 2022 01:23:48 -0800 (PST)
X-Received: by 2002:a05:622a:1787:: with SMTP id s7mr2210734qtk.631.1644312228169;
        Tue, 08 Feb 2022 01:23:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644312228; cv=none;
        d=google.com; s=arc-20160816;
        b=f9il/MTbB2pullpJDkZvSBurqKdRZVdeqOmTFJFGHvCcpffqLBD8BgoSOHEvir5d2U
         ivlq9OR/UmUMqqb4Ps36Z7KQLO125pOK5ysKMFcKFRSi7HToOqm06PoqalvZ5xrtd+tz
         5woKCwO3jW/p/r5Pb9kqEaMbLk8Ed+dmjxC6XTOAXHnENsHLVoYzKYIXVTh/LNHZgMn8
         m5HK2lU27yjWm1P+ihBSMRkeO7XDZqg+WImxMODdlGJV5/Byqj4xHy1xl+cNqka1pPo1
         88aHA/HYkZZhauZ8AE2bz+p9f87j6SSaBuYsSAYY2mO8zRmosPMJA4vkcmpeG0M/0Gk1
         oqgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SZ03WaXjCB1/PPBbkHxtR46rnb83dwuwKCXnSai0rXM=;
        b=Z5RkNoucS1NrqbnMJOFdoJvqZbzEkHqHA2kgrugLeeOXajn0IHEQ0eZaxBtUarSXDk
         /VkZAO46IkJylQgsa3HHJUGCrETw8P6AUu99U6feA0EQhO35b3Yg4AvzZLC9MMR8uizc
         rvIom2F+F9/5CLnT9JymG5iPWKvV2+C9SOMkC51WsQRFCbWO1w4JoGLNZTptMf3uCNG0
         yTC1eqMqNrpz95lLAumBqmHvWBlhepYhFlnj7ZeYb1JoqjtR3qRiBB5JYpEQC5ryz+zg
         /tuWKDPJj7y1rg92q2k9uBIiNtOTCSSn76jQm5FLPdRvI2dD76uIgiY5OSN1XTkU1Pzw
         K+AQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DX6memat;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id g5si604766qkf.4.2022.02.08.01.23.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 01:23:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id p19so1520083ybc.6
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 01:23:48 -0800 (PST)
X-Received: by 2002:a0d:ec04:: with SMTP id q4mr3914719ywn.412.1644312227704;
 Tue, 08 Feb 2022 01:23:47 -0800 (PST)
MIME-Version: 1.0
References: <e10b79cf-d6d5-ffcc-bce4-edd92b7cb6b9@molgen.mpg.de>
 <CAHmME9pktmNpcBS_DJhJ5Z+6xO9P1wroQ9_gwx8KZMBxk1FBeQ@mail.gmail.com>
 <CAG48ez17i5ObZ62BtDFF5UguO-n_0qvcvrsqVp4auvq2R4NPTA@mail.gmail.com>
 <CANpmjNPVJP_Y6TjsHAR9dm=RpjY5V-=O5u7iP61dBjH2ePGrRw@mail.gmail.com> <CAHmME9oPGnAQ23ZGGJg+ZZRDjG8M+hkqvTko1Zkrc5+zQYUvVg@mail.gmail.com>
In-Reply-To: <CAHmME9oPGnAQ23ZGGJg+ZZRDjG8M+hkqvTko1Zkrc5+zQYUvVg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Feb 2022 10:23:36 +0100
Message-ID: <CANpmjNNoAEqab7Zi2bB7=3FVpajXe_4jmVV-orCO=DzT1Ber9w@mail.gmail.com>
Subject: Re: BUG: KCSAN: data-race in add_device_randomness+0x20d/0x290
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Jann Horn <jannh@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, pmenzel@molgen.mpg.de, 
	"Theodore Y. Ts'o" <tytso@mit.edu>, LKML <linux-kernel@vger.kernel.org>, 
	Dominik Brodowski <linux@dominikbrodowski.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DX6memat;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
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

On Tue, 8 Feb 2022 at 01:36, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> Hi Marco,
>
> On 2/8/22, Marco Elver <elver@google.com> wrote:
> > Jason - if you're interested in KCSAN data race reports in some
> > subsystems you maintain (I see a few in Wireguard), let me know, and
> > I'll release them from syzbot's moderation queue. The way we're trying
> > to do it with KCSAN is that we pre-moderate and ask maintainers if
> > they're happy to be forwarded all reports that syzbot finds (currently
> > some Networking and RCU, though the latter finds almost all data races
> > via KCSAN-enabled rcutorture).
>
> Oh that'd be great. Please feel free to forward whatever for WireGuard
> or random.c to jason@zx2c4.com and I'll gladly try to fix what needs
> fixing.

Great! I've released everything I could see right now.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNoAEqab7Zi2bB7%3D3FVpajXe_4jmVV-orCO%3DDzT1Ber9w%40mail.gmail.com.
