Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBDPJTXZAKGQECZMAY3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id EA82015FC95
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Feb 2020 05:33:18 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 4sf6442750otd.17
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 20:33:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581741197; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fl9MkaM2AdDYR2B4HUwt9YPNnPIwYeS2C5Cfw3c0MUSNJY0eA/b+M1BoNulxiOa9zq
         dvbBO9T0r2n1DIKNraLT/IbuQrxWJYgpjQ5KsKv/kxHzDymRjPkQi6mpOCD/VjkbkNKv
         GyQEkRgWGR5nJcrk69Oz8uQsMrg/Roz1qkqyq7cRJu2b2HM1L58Kjk4vTI6tJAg+d29f
         FTa+Ld7vm8UPO50vcE6HWGDmdw/pdAHSTGnXZCoY5fQC7PdFNQKWx6W73ZLpfONGHDo2
         qHU1ejZ/SnlPgSyr2iWifAP4+wPJDoX4gKDfZEUTgVeNNVBio0V23hWy3DqBoxF8Htx5
         PXWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=YtXcxMKXzb7oatF9MlHqGwI4ocN/mfxKYhNQhErdKgY=;
        b=j+Ys+fU0R6NcWr+QFfroK1mTAniykGhkYo0fIwANSIAxjfDnp3ZR+ZM+rMsYlTjhHj
         se/o05SC7vL0JHO1/3wdYmzyM1xNjKfAZz5rJsdNwD/ZUF3ml5CQlbGMqWURiTsUmuPT
         4NS09pHR6BMiAIIj9a262z75v/x79loPa1VqVaqB/BDAYG5zVB1Zo4H6UHrWoOETIP+u
         LyJWZHEweKbfLMoI9ns2VuIr5nu7goTYno5rWWvglW3k8pdkmX14qgkVxnjxwhRRQNjN
         ToQqHmW0VsClo5+qk/Nt2YP24PNl37h5LB6DpePVONRi69RjUghkEBnnLd9EGa2ywLDK
         m1xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Cdt4oWnk;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YtXcxMKXzb7oatF9MlHqGwI4ocN/mfxKYhNQhErdKgY=;
        b=hglGAX0F5O2FigAAsSzbPbF/7jVn/uzbgQTtwZQP9l+RFKZslVaQRjkxlb5oZirIyZ
         aQTK6DUEHAhPzzqzZTqxM4xc6F34wGpU0WXvd5pX0bPdXyYRNK2x+p22ENkjGQrCni9q
         E0ZbJ+K2JuKCMwOKrjZM34ZZZO4XF1BRWyzqhsE2MsTWH31LNGyKoNIqteElqIqRWX7c
         8A1PuzhyXbcUz0TSxzzrv1KOV1bj9qz3YHFqXR2wgTU6JeMjrHmEORAgH/Wl/9El5EL3
         85Rrs99xyQA+P0jBUDukCuFUyUK4x66f4Jn4sWQwtMrqLrgvHVQr0M+Qol2jx6u5iuk+
         u7GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YtXcxMKXzb7oatF9MlHqGwI4ocN/mfxKYhNQhErdKgY=;
        b=dWkZdFFvq96jRpPU/VZiBLHTgZI1nb9zCPGvncMB2zWF4fCyzWe+29i0Wxc3F3ARas
         khFwUWu5MBAmD874AYEFITWT2aRE8zFy/Qk144OFYPBJW2SjxnPbKmNynwZvL5VeQ//G
         rJ0/XtjPaKbWcsMu4hBDRtRUDhIB4J+2VL8pmdssuOQj7maBmQFMIhexh+y0a4VKi5Qf
         7bJd27qXPYFsyZ/O/EBuJ+E/RcCPcvJrevXP04nS0Pv1/mxfjkCyfMKjwdx3wM3nyPPW
         MPvjtBADwvxEKYjMYxUxx9fBQ5wYfaIP4Qj9MElkRoqBN/zXIZKjGOL8IPFZRC1P4RDn
         7eYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWDr91vLNia9rioY4Q3UzfHNpAZS5v3YMqRND/wh3At5qDTN5zi
	ef7ptpzGbQppM+Ss+bVFigU=
X-Google-Smtp-Source: APXvYqzXWsqwvh6yb31tKPEoF7iOGlgQLVCApiqj/35pckqkXLB40hIqQAk99jJctBDN1xpNyqXJtA==
X-Received: by 2002:a9d:600e:: with SMTP id h14mr4680244otj.113.1581741197745;
        Fri, 14 Feb 2020 20:33:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7109:: with SMTP id n9ls338631otj.10.gmail; Fri, 14 Feb
 2020 20:33:17 -0800 (PST)
X-Received: by 2002:a9d:64ca:: with SMTP id n10mr4848071otl.325.1581741197334;
        Fri, 14 Feb 2020 20:33:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581741197; cv=none;
        d=google.com; s=arc-20160816;
        b=VRW1cnIuGdeWoQqhSiDKc9ajHbugh04KYNJrzryXdwj83jPPcnFllY8ryG4YSYMEfv
         pAzzF2+Z30xNHJTgP298M/Bpt87joU8P+UaTTA00su4UMscAIW+L3tYK549gDlGbluqV
         G9K+lkmKO38qFkFCqKnpxe8OL2wg5dAFd65yc5QLXszhVPtx1+zFhCGpVEpIW8w/TTot
         UH6r+pyPAokypRwPm0PX5c3HaYx2iSQxHgWQYmhJJi0HYc6xQBIjLy3ZBV9oQ6pmSSyC
         U6/PpdxF/Gc9eTFEBlJzGtsyN6xFpuUHzdzC+JXb6iJvZTx3ZyTyJn6oqo53uttAkPFc
         MvlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=mYdwRjSTnaHgy7MaHT1AXLsh61zUZmRedi/1FmHrj2g=;
        b=Q9kttHKzyAm4Txll+A1DGNlC0wQcYExz0Z6RQVbvPldlj/8V1d3Tc5UG529aTzBvPS
         70DEtUsm5Gh6phpC/Rt8MnHA8uWN513f/Yt6M4BK8rxJ7KgRB0oTCRArO4psJ3qUYImG
         Vj29L8HQ4LzVR0w/7ybuB2XmL9IftMHoZ0F6L2z1RAsHIxx3eNgBUWn+5mv9qN9QyZ/M
         mhtvE6ZOl7t/3JWpSQRdC2N0+6kpiK4Cqj/ta7qRot9l8xyHM1N+mX6LvnD2LLiRE8eE
         m0EOB+SCT6aW/2zDH7f7MVCakU7xrbiPV/w6FFOmUvB3kPPwLoC1n2vTKMZry4AYRrtP
         OUOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Cdt4oWnk;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id s10si364785oth.2.2020.02.14.20.33.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 20:33:17 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id t13so8450998qto.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2020 20:33:17 -0800 (PST)
X-Received: by 2002:ac8:461a:: with SMTP id p26mr4942253qtn.317.1581741196631;
        Fri, 14 Feb 2020 20:33:16 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id k50sm4645984qtc.90.2020.02.14.20.33.15
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 20:33:15 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: KCSAN pull request content
Date: Fri, 14 Feb 2020 23:33:14 -0500
Message-Id: <E25FEB93-DAE8-4ADA-B477-920B230CEFF4@lca.pw>
References: <CANpmjNMi3jQaqEB54ypWh2xEKCVRzBesMMfV0zZBcANWbXrcAw@mail.gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>
In-Reply-To: <CANpmjNMi3jQaqEB54ypWh2xEKCVRzBesMMfV0zZBcANWbXrcAw@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=Cdt4oWnk;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::82e as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Feb 14, 2020, at 5:40 PM, Marco Elver <elver@google.com> wrote:
>=20
> False positive appears to be quite subjective when it comes to data
> races, and everybody has a different set of preferences. We know this,
> and KCSAN is already pretty configurable
>=20
> What is your definition of false positive?

I feel like all the annotations are false positives because of the existing=
 code is correct, but only the KCSAN complains. I knew we had this conversa=
tion before and I agreed they are still data races from a compiler=E2=80=99=
s POV, but kernel developers are not all that into compilers.

BTW, I have seen a lot of annotations kernel patches for sparse recently. M=
y gut feeling is I don=E2=80=99t want be that guy, and I don=E2=80=99t want=
 to use sparse at all because I have only seen most of them are annotations=
 and rarely any real *fixes*. Maybe I am alone in that thinking=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/E25FEB93-DAE8-4ADA-B477-920B230CEFF4%40lca.pw.
