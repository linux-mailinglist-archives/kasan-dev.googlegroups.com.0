Return-Path: <kasan-dev+bncBDP53XW3ZQCBBR6OUDCQMGQEMFUJSFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 58DE4B31161
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 10:16:09 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-76e2eb787f2sf2173933b3a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 01:16:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755850567; cv=pass;
        d=google.com; s=arc-20240605;
        b=JXiz73utyzVKXfpv/7rCsAU1UWna7+GM8V5MZ3jybLfpy1oSFkgClEk1bLaMxSaq2T
         kSHCFSvBkSpkayaJAdJVcwDMmSkuAlDT7BZGvKESKHZcz4Ok54picTK+fsmueb2AcY3M
         /L+zAiecTvzqFhcbVzEreAxnPwytCQjHk5zMLp1CAheEdSuo3GJXNYKeEqrgaZTDCHI7
         wsltpE7plrT1a5E3KUSNqj1tkMoyaynWgxqVXTMYzWfRoAutF63IiUsBI7vTG/xIxQPJ
         vmDxMQGZw99WKAX6NiHprPzIkwjfNkyPyRnHGrwV/6fyhfs9tIfXXq4tKZNk7aKJ5sgK
         2Tlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=IR9n96sCY2qZpHt/bYGh4g5RIiM4mIXNYbY4Q+P4+fM=;
        fh=6FfANy1Rm/tuVqBezl8yUu7TEKyVZXMwpyd1apKgwRg=;
        b=eNWolQTbKzv7piKPZeCkAPuCjqO4npGbhtBhuHPnHMgKKtRw5h/pj4LoiEf2TLj0d+
         S9TvliaHuYOYN5ONf/eiYgrz2DLipOleJRuKT9/az604SJvt9dldxcoacnO2QvVH4LUW
         n0Wlp20no6CfP6WAq5w4kRidWFYI6AVnk0PWCQg7BkyMAdd5toPAZ8okzNUa7Qp+IGLM
         JImwyGHyKstPX7ItorLHa2EKtXkgq7dMI44h6DWMOOO28oOBB4lHSSM8mENEnDyhXDoX
         rl2xYM475f7nBsLz9pnoQQUA2RtkuTH6XhEPpc8mCcRtTdxL43O/QueAQor9PJvMDUUj
         KdGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OEjyyMKp;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755850567; x=1756455367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IR9n96sCY2qZpHt/bYGh4g5RIiM4mIXNYbY4Q+P4+fM=;
        b=gXyapZy+dNVeWRXe49xvcyhSrr6KljS14vMGRvs9e5S2GOrOsbM3e6uSbjYf52t0FT
         Ro1rgI4JLnl+XHxA/R47RC86teTLAaR5QDIod+M8IrntdYW9E4lR/czvOw9Oi5nqzhpB
         kizhW5FU24I88dO/ZMBljyQ4jpgxATo+PtzjUgI8Bd/7tWENcYbtJbccDf6kjVzAUh2t
         z+xiGZQNfI22DrRnpjRT5aJVl68iMVCfIlQw3pSmXAHpXWlUExTTypKbkc39IBGjUpz6
         io6zdZJNn8DXStrKFeX3FD+SvvqfKcAm6PFPDGMpsLHru8AZ+pEys/pJggfAqLZSVTxO
         VXBQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755850567; x=1756455367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IR9n96sCY2qZpHt/bYGh4g5RIiM4mIXNYbY4Q+P4+fM=;
        b=dqqZTMmhNi39Tw7du8xbMzn62o8loYB3cdQCC7j3+ERBwIVRyZf7BGdSweCZTkFcfX
         OQZxuGLVlVmDQ2bOU92S5mVHrAwGBrVRc3xYQrnZIAdOjqTtWBX9+xt/xfIaXUCUqvoN
         g4sZHjtWWLqnZjhbEyVa1FYsz3UPqjorZy2li67f6DGWWlJlEPdTP9cDIia+Trxx/Fa/
         NL/iZOSRhFQVpyKlBqpLMIgIYzm05/0hVqxvljhhNT6ZoGYaIWL0UcX21HWlOFtDJIk9
         kD5WQXcz0Ltzqf6G2BPDw4OzdBsLdjJT4HtOFjPoJndposExEuQeLZpZ2HMPDz6K4xtM
         hEnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755850567; x=1756455367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IR9n96sCY2qZpHt/bYGh4g5RIiM4mIXNYbY4Q+P4+fM=;
        b=jUh00N/gj5JO+gPVsHxQGbU4u7rTDaYFv1WYWAvtD/o3ayinw1v0z6iYUlj/Zg57UF
         /ag2j6P3V7y1bmHhP6ZqUBkmVxHRbQGGkFXpX/dp9ZzpgcZQ20rzhOd1S8i1aBtdTU+q
         EJeo0nVR0ClFk/1lpqIqlUwqWoqb0XJCl+sA0Mkv6sIjPtc6hExwwSk5VCcvS7RsjPsP
         ywzYbtqC7pQXF9hG82GPhWqOPMucmmQYbEhHXfOQZhYtZwjqGeg5634cGYLMq7NElUyw
         SH3a+kXwqRYn0NvG5j7/rnXZl+MeYTMvTGrslTT4ZUCnDgXKQt7RtxQ3rKIkkoKQMjye
         H6Gg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9zdGLzgM1nYka788i35aUTFbwHFZ2R5X03WanIy53vr8YKuzPsL7lGDJ01jF9hi0LZzXlGA==@lfdr.de
X-Gm-Message-State: AOJu0Yzo4V7c9FEz/c2In/elv/goF3tCpm+GuVIOLKtBU/IfIw0wQt49
	ystBoZbVU8kM292lBTiyXGzLBkldZK0UIjTGPucdny1hvyK4WIgQ1woR
X-Google-Smtp-Source: AGHT+IFITE5Ig24VuH/Y8xs28O5MmTRlFUlMJp6CPy3p40ckLaUXpLaK5Ricab9w2kO0NZ5j+5NbHQ==
X-Received: by 2002:a05:6a20:734e:b0:243:78a:8275 with SMTP id adf61e73a8af0-24340e1a096mr3542147637.59.1755850567459;
        Fri, 22 Aug 2025 01:16:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZedF0pZYsQKIkMIhGmu0c1I/C+rLqR5+egFDizE37T5VA==
Received: by 2002:a17:90a:1589:b0:31f:7cc:aa74 with SMTP id
 98e67ed59e1d1-324eb8538fdls1436821a91.2.-pod-prod-02-us; Fri, 22 Aug 2025
 01:16:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2JRX5bO1IG8t0dxQhY2SNZKckHqxZ30BMAm7JB3pk6p5ypU/L0+f5IA6S8TjYvXYaFPFIKpr92JY=@googlegroups.com
X-Received: by 2002:a17:90b:1dd1:b0:324:eaa3:3dcf with SMTP id 98e67ed59e1d1-32517b2debemr3168724a91.35.1755850564903;
        Fri, 22 Aug 2025 01:16:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755850564; cv=none;
        d=google.com; s=arc-20240605;
        b=ebGr3j2WeY3fR8Sye00CsmCMwwxa9rFsMd3TjPpfeQQBtRqqwX+9oPF5htcCj0edkA
         gbV+GQzZNRsTbtNT1lKOlA4iixrkDr7OOBuSiL2cE4c5p7FuwmP9r0pIL4DBxmowUvG2
         7SCTD4WL8/QQgFVtBkDttHj2xeFjktChuasZeCMkWPv35OuxmzE5yfqmuWhxaL6OjaW8
         tK8rhz8hU+UTyQTx9KYAqvN8j+i2ZMItR1ZCUUtDicU+L7J0XOPMwbz7VVXoixG9t/R3
         aWoNFb1qYdeHWFt8wEDMAl84soP9yiVfKMwTfJ8kOHh6qnxAdcadDKEQYI0E7ZaYci7E
         HlEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YVeh8OFS3+/IlZrjuSBDy6MWR0SMYXgiYrxYee0SPuc=;
        fh=5IjYXxeVPAc5IxFl2eawK+jefzUIcm1HZn83TflBZYk=;
        b=hIyzzMeB6fl9Zz9irKWxUhnpkyO2vFPneM/shP15aEiUFDPhzykEbcZO//UaNWU5W7
         APIMwCEhBoXXzaXNsa9XWaXKhOV2VfYHvcMzHM3BXbydKcZqqc/zfh47j6+z++39ABcy
         Wli4xMkeFJXUA3a6YtYjOXzW2/VqDHPZf5AQwEd/y8JqpDzMqdaMwontm8YM3p8FGjhe
         BZ3kWE7IRhu0quHXsIf8fdW10gNdh2Qkz3e83FxN3ouaQSPJH6pPmeiA2LIQB7AneRrg
         tIq8DmxXR7mshABhmUnwvILV6f1ayV3DhHqN22081pjsnOiEzhzuQiB+0+zh+z5qIkRt
         OSqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OEjyyMKp;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-325123dfd27si83731a91.1.2025.08.22.01.16.04
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Aug 2025 01:16:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-24458263458so17673445ad.3;
        Fri, 22 Aug 2025 01:16:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUAVTTw3iuc1y5QqIEQOL150pcjB75PFfrwVu+/cltTmCkP7hBad2exZWklVNQ1t2B/aO81ppxfoJw=@googlegroups.com, AJvYcCXFrHFOcBn8IhEnXA6SnH6rdWdMslX8Zr4/77L71B2Iuw2FNwJjYEUEZOq+l/4BrMuJo3P40nB6roGp@googlegroups.com
X-Gm-Gg: ASbGncsLY6LMLzF73erSxBJ0bQUGhuL15XUDgyves/doY+0hu4T6bjJXeGSBKjsbS2V
	uQDHp3snnkoU8KhfvtFMQSGRmFFlrfll6+BdaBhty8u2hmmPig9WsAOrTgLFDkxKsSPh6oXvAeJ
	nGgPyd44CCo25d5H0Dbbs1Gv1RK1cpf8WmIsTOpurW0j8g9+jdBioOYrh1CafTL1dh2R1vXPosy
	qUu7QMsrBbtHytVQ8/h+Nzf/CWQOCPmw+ju
X-Received: by 2002:a17:902:ea01:b0:245:f5b8:87ab with SMTP id
 d9443c01a7336-2462edd7d9dmr29942155ad.3.1755850564406; Fri, 22 Aug 2025
 01:16:04 -0700 (PDT)
MIME-Version: 1.0
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
 <20250813133812.926145-7-ethan.w.s.graham@gmail.com> <CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A@mail.gmail.com>
 <CALrw=nFKv9ORN=w26UZB1qEi904DP1V5oqDsQv7mt8QGVhPW1A@mail.gmail.com>
 <20250815011744.GB1302@sol> <CALrw=nHcpDNwOV6ROGsXq8TtaPNGC4kGf_5YDTfVs2U1+wjRhg@mail.gmail.com>
 <CANpmjNOdq9iwuS9u6NhCrZ+AsM+_pAfZXZsTmpXMPacjRjV80g@mail.gmail.com>
In-Reply-To: <CANpmjNOdq9iwuS9u6NhCrZ+AsM+_pAfZXZsTmpXMPacjRjV80g@mail.gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Fri, 22 Aug 2025 10:15:51 +0200
X-Gm-Features: Ac12FXwnoEYMnSaKSxMxoYPh7b4TsxXD4qJ__w-NoWUUMjPmRTgOxfHSPEf4r3U
Message-ID: <CANgxf6xCYE4dQQ9=UDotB351wxs46=ZUhWz4zfrROH5nNsSBRg@mail.gmail.com>
Subject: Re: [PATCH v1 RFC 6/6] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Marco Elver <elver@google.com>
Cc: Ignat Korchagin <ignat@cloudflare.com>, Eric Biggers <ebiggers@kernel.org>, ethangraham@google.com, 
	glider@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, rmoar@google.com, 
	shuah@kernel.org, tarasmadan@google.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	David Howells <dhowells@redhat.com>, Lukas Wunner <lukas@wunner.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OEjyyMKp;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 19, 2025 at 12:08=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> For example something like:
> For subsystem foo.c, define a KFuzzTest in foo_kfuzz.c, and then in
> the Makfile add "obj-$(CONFIG_KFUZZTEST) +=3D foo_kfuzz.o".

I agree that fuzz targets should only be built if CONFIG_KFUZZTEST is
enabled. Building a separate foo_kfuzz.o is probably ideal, but will
need to think about how to cleanly handle static functions.

> Alternatively, to test internal static functions, place the KFuzzTest
> harness in a file foo_kfuzz.h, and include at the bottom of foo.c.
>
> Alex, Ethan, and KUnit folks: What's your preference?

I think placing fuzz targets in separate files is a step in the right
direction. Including a foo_kfuzz.h file inside of the source does still
pollute the file to some extent but certainly less than having one or
more KFuzzTest targets defined alongside the code.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6xCYE4dQQ9%3DUDotB351wxs46%3DZUhWz4zfrROH5nNsSBRg%40mail.gmail.com.
