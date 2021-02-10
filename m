Return-Path: <kasan-dev+bncBCMIZB7QWENRB6FNR2AQMGQER7HU6WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id B61FF3160C4
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 09:19:05 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id y22sf924729pjp.5
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 00:19:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612945144; cv=pass;
        d=google.com; s=arc-20160816;
        b=vDP89E9RjtCKu3YdrLgS6zewcZ6MS5FKosUTi9QX389hBzXx2CAVb1q8d9tJAqI/Jp
         2hRQ29gNTjSqJfpsWfJFLM5VAFnly4EqVA8bhi7DgfjMb4Q+nF1VHs818kXDYATgAiyE
         P8Kmr/SnogytRCN8bwelrJNPedSgsat4pvVSstno95ERWDs7P1plq2mxM+dkTtJasRgM
         muHx8HQEnI9OPnz3lGKyI3FTBKpKJBj0o6kIrBISCzifMWTJLgBFGs1sn86G+Nx7XNEa
         xlw2NHBha67w366e0+qli5z5i06iS6AMRiJCWtu7S0EpuDOwmzww8cFCwMQvLdJZtuQG
         M0GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=T1K/utbL8mnPNQ2KOnI6Aam5+I9alzQiYfiKDfXRsk8=;
        b=aZjyh8lnXLuX4GNCXB8lnHG+g11pLv1CKnBeM8l79f4U1/x8wemV552NJR7/+AvVLi
         RwQEo1HQGq3hkNF8h3ft2c0gzOD4BnpB4WCK1L3jv6KCPNFphOBtZXx41oVWJNNg9L7Z
         63JwbmYvCmFMgyIFik33NRaJvudr5qwH5888N22vHnwrxGVWWNXeUwtdvaBSH3cigpqp
         44Li16HjaTjwgA5mDLJ3UXtqB0m/f4NYBPoKiysCadYU7zdqXWHB9Cio7vPHbinzrEEj
         GFuyzzLxe8BM1sk9qIXs09rMWyZsbB6FxXH7ooF3URVzMtnBjptA1ciBqdA3jk97BJhC
         +c/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rX+ZEL8G;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T1K/utbL8mnPNQ2KOnI6Aam5+I9alzQiYfiKDfXRsk8=;
        b=HcFajSyYtrTm75XgHCOoi9LHftz8njxFP/YNdJ6VZ8pcgDJXoJpmOUeoKYxiVycwxz
         lSLsvHouryDhu3vuvyb5i2e6verNzfQlSadYGorFxPTB+HIZ+P8KvSMf2Hsp9H7pzBW0
         CJumTv/3lsc7oO8vACCcWVnhxeXJq6sRTtwUxPeqdUE7BZBSerlhBVthP+kq0m4yyPRm
         kMBmH+EN7IfEi+a1mf2AxvKseT32RF6VzgHcPYq1GST6JJwAaR0YDFU8/+GAL1stazqo
         akCLvkRBxgkqNWI+z13KBbjUCddYjfk4J/0/Uyb42djJQkVso4bt//JSQYulGn6MSTZs
         YSdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T1K/utbL8mnPNQ2KOnI6Aam5+I9alzQiYfiKDfXRsk8=;
        b=T62ZNMU6MwN3VqgJOQRynB2urO0m5NOTgsHxyqiKaE7lqfQrSaMeJCfQFnGGuDFOdE
         Yox/N8rsDb02rP6DCDwngfk+tYN51cxmUto3SkvxjWXPfOlwwkBoFLnYA5vi52bTqLSS
         zeWaHgIm+Gs87caoHV9P4xFTHqssgOI8q3v2XAWNtGB+uNfE6avye0mGIPFzXaqLKyrN
         76zAdJ3GHbfMiuYVp+8HZcgVrLjbmpyEDhj0al/OUMmW6MzTA3QwzOs9Lu2mN0yMcLeE
         qhdAxfKVx0Kh/LcLbZyc5rFQcsS0p7d8UWatMmTYZDTyOJa2WijEXUtP43E1fz031H0e
         6q+g==
X-Gm-Message-State: AOAM530DXGEwMvrDB846NgKa/4QEnRYY2Uk3hJg59O56N8/B8mDtamgC
	zNr/qD2F7SSOmNY5KqwvwqU=
X-Google-Smtp-Source: ABdhPJxqU5s2mN4Nvb5YXO6r3LfeZMd45jn5bQG45ZtzwZhMIM63Mde1Uc/0QIIzlnvBgr3p7+VoXQ==
X-Received: by 2002:a63:510:: with SMTP id 16mr2081053pgf.42.1612945144514;
        Wed, 10 Feb 2021 00:19:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:27c1:: with SMTP id n184ls612052pgn.3.gmail; Wed, 10 Feb
 2021 00:19:04 -0800 (PST)
X-Received: by 2002:a63:4207:: with SMTP id p7mr2096372pga.406.1612945143905;
        Wed, 10 Feb 2021 00:19:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612945143; cv=none;
        d=google.com; s=arc-20160816;
        b=1AHGPn9k7EdUcfQFZ31KRuj0nvzy7o3P8IBojcNpN94D4/+AVG/5oHSAX/p4wYDz7g
         Lh63XUGsLqtAXreecsawZgEJYiAc0orERdLhHa5EDfUtLSV92sa+9y3c5U56TSHrc+Tc
         qLa7lQGtIPNWdjxN3A7kVBDVv8Ge9KagoEogRSaK1m4qoPsnk2rTEL42HQWieZI8ZHXy
         g/20/lHHBYjQmhhijwdxpnDLtq6VfZXJaKXxLra3P0lbjKksPRmusqXW/02yl40fOxSb
         qT/cUpCslG5I0eCLUUoDyTwpN7vnuLdn+zoxvsfVEAPG/NdKSyhhvHbtrz8Jovzcg8WY
         yfyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HX8s69TcCJ64M8HKG+p5Kjt5BHD13D4sUeZv8Wdp7eA=;
        b=Y3A1Zt/c4B1j5ThMV59C0taSSnRoJUALLVIUOfeccEZDLoR1hzH8DLuqN83+iOWC3v
         lG3n3gUzm7EI4XLLMn7/ZL9woDRomySyTa3bHRnMxwVVhyzabTS+PEEvEESpx/l+eKkp
         +FNTK4FytEXf0MEbLW11N+/a2Tshcw2Sa/ogtVkL2vKi+UrGF1eeFYxN/wHwm9g+FUrc
         hxNMOFlYZgxaT2gk0yyBkkEIsXNTXLpTwKn7mJHM+5bOmCSoKeY34pnD7EFOUVP/5wKv
         8NtZvlDmLEo711wh7hoHK1MqbpufgIoP5lE7KSjFJB8mCAX0CymUFFoWWmvPN8CHdHS+
         YoGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rX+ZEL8G;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id d13si47771pgm.5.2021.02.10.00.19.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Feb 2021 00:19:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id e11so942913qtg.6
        for <kasan-dev@googlegroups.com>; Wed, 10 Feb 2021 00:19:03 -0800 (PST)
X-Received: by 2002:ac8:e0e:: with SMTP id a14mr1743253qti.66.1612945142899;
 Wed, 10 Feb 2021 00:19:02 -0800 (PST)
MIME-Version: 1.0
References: <90cc29f7-8306-4ff7-a5a9-70d9c609c7f1n@googlegroups.com>
In-Reply-To: <90cc29f7-8306-4ff7-a5a9-70d9c609c7f1n@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 Feb 2021 09:18:51 +0100
Message-ID: <CACT4Y+Z6M3TZJFDGYckqwNjqfQ2GA3gxJtzQPo1Rr8GSOCDGPQ@mail.gmail.com>
Subject: Re: [syz usage] how to connect the vms
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rX+ZEL8G;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835
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

On Tue, Feb 9, 2021 at 9:48 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>
> Hi, my name is Jin Huang, a graduate student at TAMU.
>
> I want to ask a question about the usage of syzkaller, when syzkaller is running, how could I connect to the vm/vms through ssh myself to see what happens in it, is it allowed?

+syzkaller mailing list
-kasan-dev to BCC

Hi Jin,

I assume you are using qemu VMs.
You can find the ssh port of each VM using ps command, look for the
"hostfwd" part of command line. Once you have the port, you can ssh
into it using ssh -p PORT.
It is "allowed", but don't disturb what happens there. If you disturb,
don't complain about the results :)
Also keep in mind that these VMs periodically crash and destroyed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ6M3TZJFDGYckqwNjqfQ2GA3gxJtzQPo1Rr8GSOCDGPQ%40mail.gmail.com.
