Return-Path: <kasan-dev+bncBCXKTJ63SAARBRNH42XQMGQEMCQATOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id DE80E87FEDA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:31:50 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dcc05887ee9sf6877861276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 06:31:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710855110; cv=pass;
        d=google.com; s=arc-20160816;
        b=P2wHdWe/FMFmXFfas0sGPTnP4xJjNncqBvQMzxykYTBRnjBJNxlyG6jtKKvVoFdmld
         tA+jc7/RAqkg4olBzG5rYppWc5iAF976+1DwBvNyAIif0xK0e3pu5AThHor3t5NdLbf+
         hmgXY9IHz7Z3F4X8wVSfP58AfrskfI/eBqv4Oj+f4iLM5zfRb7IZkZXzyOp+dFicvBw7
         WC5oz4DLtARCSx5LvZsbMkU8LhccRXXx2LShFZUKQA/CZuhBs1+RdoTSywgTUBb/iLAG
         PkBj1iVeqsRf7/KEZ8Q0/6QiKHvx2XO4qZcol3JMvuu06ytUABGDQwYQ1cw4nU/Us0ja
         Bu1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=euWcUWllW8JgNnnVCb+k8GfOaFmsoG0Rv4ZzctfBEPw=;
        fh=8jhCk8gFnUsD2326RCGsUOr/vN997ffa9MgJTFnHVAY=;
        b=sjtQCDQTfuuBUycL73WQKe9xjG3SX5qrAS5VPeTs2eicFGKxdIWQnpagEXnVFYYlTO
         zfKa9QnLVlNRkMI8rtBhJCB7JMxDj5uwcFZnKAc8TgX6rJt+AB1R7ETsPQOHMoqa7i8X
         wO8QOTBaurhhQHQyCLQH1KEGPX97YcrPYhK1g0zlqkO2rNhzg62aiM8vvLI8gStIeZxH
         OWiNQ4I4nrMzDQgm8DeUN+I3qg7eI/G3lIUWHNWQYkuhcuQOgW79pE5QQpnMP9qm640X
         D69b0uh4ycDd/AN0IFjJ6FE54sTMgOsedEnPsu4pyPzBHxSfep0s+UgkV0oIR/Jh6tsJ
         VZvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KId12DPA;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710855109; x=1711459909; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=euWcUWllW8JgNnnVCb+k8GfOaFmsoG0Rv4ZzctfBEPw=;
        b=ODmbQ/c6FumHxf67AQimZG02iRP7RY73CQ04soIRX6K8vUHB3Wn3SjqW5SEMoR469Z
         iUSV3SkXJi5cAw0mc73t9NkIszHgq4whT4QHGb+cjunjDsLrCiOUqZHAqy/eHLoA5jI5
         21pmTO0wU/1ZlNPO+KfNQ6v7zlGNAy52Cub2WUB+UUTC24a30n/C/ZAYcD+CbtfJvShA
         u9kUBDV3LJgsZTwEuj6+rwSQWIKauH7OJ1oUmLUpTcBGhkWV3BREWmK7oYuC8TjyNVux
         IPOulE5QmOiXz4D+izUGpA9odkXMm1xXO0Rxaxf8Te39BMDYpUc/Bc/ukr52jvovYtfA
         fLLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710855109; x=1711459909;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=euWcUWllW8JgNnnVCb+k8GfOaFmsoG0Rv4ZzctfBEPw=;
        b=QT/+8lt199xg7UGJ/2Gkzje7GbaV4ZsqkMJrWc+YUM2Yo9kNx0aJuPz67rxz0HTFvp
         w1EW/QCZDTPk/6UxKAFOBjib8NqPEiGUUGzSO95XprGYlATlULzafY7TmAOzrOaEtXhr
         yjvrXYdlsVcIjZAQ6myeTV+xBIRg3tTzfXdL9FfhOpKx6pe9L51675adx2w6Z7fe7JYL
         noAqBAJmvnoVYvnGKN44r5WXEuKTilOAc+N2MJvdY62jP/rYimg3Kvg3ofc0Us/JIWOg
         29fl0iE5dKv/rjsY1oEN2Jj3D31gEyZHwe7IXTnf49mT7sNFKJ4s18KecXvBK/1uh94v
         nUfQ==
X-Forwarded-Encrypted: i=2; AJvYcCWkO76uwUch8vjODTceVEQOWyMcfnoS9VB3dhcDz45kfSRxyQ7fd6LNV73wYF6cwPIK3s//TrN4wJ9WgC/2P+/5+piFodiUyw==
X-Gm-Message-State: AOJu0Yy2AcQ/paG+MqcxhJDm5ao7YYdRpD824N/h8AMIxlmH2ZsmX9nI
	nBzrkmzK7+9ak4pWeuzVLPObJ10XsMz/Gb8m3M8Odt+w/qtnElWX
X-Google-Smtp-Source: AGHT+IEM+/u/dnDpiXTp2t04cmGofmLOS2ebZKvBcZwOYUOnfSV8KzgqmwrFXidq9vfyRn9AAiHcSg==
X-Received: by 2002:a5b:bce:0:b0:dcc:52dc:deb5 with SMTP id c14-20020a5b0bce000000b00dcc52dcdeb5mr12485229ybr.20.1710855109650;
        Tue, 19 Mar 2024 06:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:acc6:0:b0:dcc:4b24:c0df with SMTP id x6-20020a25acc6000000b00dcc4b24c0dfls929925ybd.0.-pod-prod-03-us;
 Tue, 19 Mar 2024 06:31:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxlsX+qjE5Gp1JQpxIXC/aSElObK9VkXcHF70WREqOqwjF+7AC+64Wa7hGz0vM3YK+d+XX9nhs/Hm6E/4yMpsQ96uWvKwN3XNwdg==
X-Received: by 2002:a81:6942:0:b0:60a:4a3e:a0c2 with SMTP id e63-20020a816942000000b0060a4a3ea0c2mr14900085ywc.22.1710855108829;
        Tue, 19 Mar 2024 06:31:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710855108; cv=none;
        d=google.com; s=arc-20160816;
        b=JDFuzsi4ct+ZSBNWJ0LFAQOwJGuQdod5iZTWDIcHstvSEnB6b9EDpwnK3x19xbeLSd
         URh1Bc7HdWIF2y7O9ZmwTrIIoNViX6aqCqbxwQVIZN7E3EQu1hw5k7rv6OBA/9SQAdlY
         J0fTmWZsa6vAcX5N4R14pejp4xKW3zBS9hvLZBCC9e8x7z0Lo8uzv3vHGyvxRzCoXLNz
         bMGwCizps9PwBecxpZ2Fcx3PI6pfEooEM2+uSGimMCUIYnjHxINn8yRM/p+IajqFTfwN
         Evt7SYgqGH06EKxMGQJiBIJhSf308uuwJoagijQJVQ5ONtVPjM20rs10NQCe1gcKG8yx
         b2/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YRVBERukyS2wWGyjoD0/ZHq0bNlTnq8NUQZ+B3xdj80=;
        fh=gml/UyllpmyBB8XqQeTrIs0b9y6SeO3FuseV1i5fxHs=;
        b=mZ1iG/lRZOUADCyJdvdNDWoi0HVROO6C63PuTcNtf+H8G3g5aitXww1JSr1UP/BnFJ
         rdmBdZqxKYlTnWo/LxkrvAmnsyxeT1UegltNIl6s9sls711eJaC6aRFeYBWeSFthm6G7
         OMrGuKavCycrrpW9jbRQbMxhSYRDpRHEa59CVrMHkm9DPD69Xc3Gamue3LAQCAx2WQzn
         2eNiPRsaSu3eYW21sQ5Fu9X9uErQOz6giDH+kF9H8xjBPsPG+gSFZjdYov3cgmM/BDdu
         kSqLNIO3rZREWPdJEwB6LYebFQ0X+8LZezumKuVI83GGV0aAZoE/+dPf9ucOo16kzSsg
         DibA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KId12DPA;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id r126-20020a819a84000000b0060a6050a1c1si1286932ywg.4.2024.03.19.06.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 06:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1dee917abd5so152175ad.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 06:31:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWi+NRCAW22yIEPfSZ2bqY6+DKlPpvyxtJ+GNb8X3TusuHEoaCF2vbb/jM2ye5u1zzzvh84e7sfoZO6tvvJ5mz73yBpzGu4s9iHdQ==
X-Received: by 2002:a17:903:2303:b0:1dd:65bd:69ec with SMTP id
 d3-20020a170903230300b001dd65bd69ecmr240302plh.20.1710855107477; Tue, 19 Mar
 2024 06:31:47 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000901b1c0614010091@google.com> <2615678.iZASKD2KPV@ripper>
In-Reply-To: <2615678.iZASKD2KPV@ripper>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Mar 2024 14:31:35 +0100
Message-ID: <CANp29Y7SuK8P8xHa6JzAzs_NxPUN9AvFTiKfMhgLy1POGBodwA@mail.gmail.com>
Subject: Re: [syzbot] [batman?] [bpf?] possible deadlock in lock_timer_base
To: Sven Eckelmann <sven@narfation.org>
Cc: akpm@linux-foundation.org, andrii@kernel.org, ast@kernel.org, 
	b.a.t.m.a.n@lists.open-mesh.org, bpf@vger.kernel.org, christian@brauner.io, 
	daniel@iogearbox.net, dvyukov@google.com, edumazet@google.com, 
	elver@google.com, glider@google.com, hdanton@sina.com, jakub@cloudflare.com, 
	jannh@google.com, john.fastabend@gmail.com, kasan-dev@googlegroups.com, 
	kuba@kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	mareklindner@neomailbox.ch, mark.rutland@arm.com, netdev@vger.kernel.org, 
	pabeni@redhat.com, shakeelb@google.com, syzkaller-bugs@googlegroups.com, 
	syzbot <syzbot+8983d6d4f7df556be565@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KId12DPA;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::630 as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Hi Sven,

On Tue, Mar 19, 2024 at 2:19=E2=80=AFPM Sven Eckelmann <sven@narfation.org>=
 wrote:
>
> On Tuesday, 19 March 2024 11:33:17 CET syzbot wrote:
> > syzbot has found a reproducer for the following issue on:
> >
< ... >
>
> Sorry, this is a little bit off-topic. But how does sysbot figure out the
> subsystems (like "[batman?]"). Because neither the reproducer nor the
> backtrace nor the console output mention anything batman-adv related.

Syzbot looks at several crash reports to determine the bug subsystems
and in this case one of those crashes was pointing to
net/batman-adv/multicast.c:

https://syzkaller.appspot.com/text?tag=3DCrashReport&x=3D15afccb3280000

--=20
Aleksandr

>
> Kind regards,
>         Sven
>
> --

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANp29Y7SuK8P8xHa6JzAzs_NxPUN9AvFTiKfMhgLy1POGBodwA%40mail.gmail.=
com.
