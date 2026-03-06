Return-Path: <kasan-dev+bncBDP53XW3ZQCBBGOZVLGQMGQEKX3FXVY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eER+LpysqmnjVAEAu9opvQ
	(envelope-from <kasan-dev+bncBDP53XW3ZQCBBGOZVLGQMGQEKX3FXVY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 11:29:48 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AB9621EB92
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 11:29:47 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-8297d2c1e64sf907194b3a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 02:29:47 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772792986; cv=pass;
        d=google.com; s=arc-20240605;
        b=DsUeVIpqarzgWOf5wG5JSked4UiWXte/icVAc1XHKL+IlAnZbLdMTnDGdn2D6dTLxl
         CE27pV4IJsNBOHlomtVDNnKKBt7o64vldHErkp/z/RgXfw9b71y+G5/EHRIOU60J7Irk
         WBHBO7xStlzWDdkxfvVvJm0hsAVHtan5adLAPBhSaU+vhwsrfTV89fi2wrR1AxoKunfa
         xuoQPcksGIruWdk8ugPrZcwglKwSyo+rPI9sGifdZTdiPZ56xcsUBng8SjWfR2ijo6bl
         4e6QlERQQoM4miZB9VkLoacF/r4HulMcoxFiLrz4e9dkTnpI9fIJJ3jb1PCFr9o7FmrP
         fdfg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=QKiztpzR5QW5TigpFoCnvaWSfP75h1n2rKIAAVeflRQ=;
        fh=U47lET8kO5RsI31NF5llmO7zNo1o4MRnbzkDZoPCcoo=;
        b=RLwEUdSFvDhJ9pmvli6m2tzd7IvbLdPzTLKAmLeVD7sNYMgqSB/3XFE6hbldcrVlGs
         ZglcPBOAe6IGT7WGwFx2OZQBLCvl7wDyRI+GoGd3k5xHzAYJiZgqvF8BuPSWrP2fby72
         1Oh0QEhfdGzMEVfzAUlnpb+37V3D1i3XBrPtoXKmjnovS19ipEXqErAl+MM3Z2ARdpTO
         YEW40bTN3tfuG8otBwZKhK8nDe3KvnW8e05afgumgM8l2Ps4hz8oV9TDW5JBzrA8puAj
         PDI7t8kST9cIkLiwWq7rEoM1P4ICp3dRehxP/Wipg5C8TCG8DarxNN2sQvws5B4BaJU3
         ilPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dUUSJe/6";
       arc=pass (i=1);
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1231 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772792986; x=1773397786; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QKiztpzR5QW5TigpFoCnvaWSfP75h1n2rKIAAVeflRQ=;
        b=rZd0EXQkyVidB/axWaJJ7ntr7irybXMKRhkt75S1glDOhewcIUw2a1Ek34TtiSFyAW
         97xkQsQi1POiDCjCksSxfc49voGQ6C1WU69AQO+V5x8t0O94dCVnRnC9szWPkPNHiw8h
         0n7UuVEeeIBT1uyrIW+JYTmcS9N6ljxojO5ZQ2lh14ORdg+Joc3HWcvtcDsr2OdOkRnm
         8dXNRFuUON14BCg1AKU7eoknYVCfJh+pxNnC95SkB3ijgnmXFp2DRsTjC80UAOn0sx7c
         8FI4FbfRkHB2mhHJ0G+sWWEKXTybJGXYVgaNn/lHKDyCMq4R5837e4KKcKId6QBMYvqV
         GByQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772792986; x=1773397786; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QKiztpzR5QW5TigpFoCnvaWSfP75h1n2rKIAAVeflRQ=;
        b=CnNoHyzQb9O0YYKZMgEiKNNU3KzBeLgbQ1bmNwYOI8IdtqLbOQnyZyMRqgr5frJg68
         Mrkk+NIQTlicsVFhnw66QyK/BU24VMWPZ83Yf1R0c8DoIzz5mgAQ4urGLzCRcDD2UQ8k
         t8jp0DPXOQ4Ba0pVwPBz2BNvwfpRpp+vk//1KPhmJMLC03obLDLPC35HI2Pp0SDy0Pei
         LqeCJvYowTTYJhLXCVtvunbNEUalnpay7MUmaR3xO+Tk5EG58Sb78pUZwAcpRKzNl0iO
         YhXVG0tAirS7cM8H+OZ5lfRf3Icnl5BorEjWmCpOAsxuuojhR4+DdmnCi3XoB+3TvZEe
         ypcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772792986; x=1773397786;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QKiztpzR5QW5TigpFoCnvaWSfP75h1n2rKIAAVeflRQ=;
        b=ZZOm2VTI8J8EJ0hxX9efgx8fJnIQlsE3bsWfoHgkwvRzxLPp9aRMVR7y34Zod/Yvo3
         aoekhCbMD4BaFk05fNSEUNGaUrfN2wnmWNysHLgOEqoZ3dvh6o3+YZ4qkTrDHdiIKG02
         IAWwYshogUNE98PqbQWTIPcjYq6VCCY97dcZlw14z9CYPgXEbiDW2YGCg4YQQ36DADri
         xImsyNxqkvyVLoRZhYITKWckSGqn1Z7IK2McOjW6nIFai/1RGm5EJuuSs0wrPWksVaEm
         U4Rw9RcYxrVqAp4NCvUAsD5Iq4toBgrISslEKY7ZpwQnzYmhYKGsvP6OYsYdhOqSaw8A
         TcxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVZjzH1Ax0HXb8W0qgph8jp4BXT+R9UiSiURiOmsMB0Esoptttq+yUdpovUNvCdS+qzcOSW8A==@lfdr.de
X-Gm-Message-State: AOJu0YwuqI3dxoY5H0zPzIckxWomHweZrZj3rP1fPHOd0Ilucq+7NeNF
	JSO04/hUiXFHmaCSs9vFnnll2bjTpfjVyCnRzZ62TWXPna5DqUiwaSdk
X-Received: by 2002:a05:6a00:3021:b0:824:ab8d:6f9e with SMTP id d2e1a72fcca58-829a2e13ba0mr1556675b3a.29.1772792986072;
        Fri, 06 Mar 2026 02:29:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hb2vUCR2Uw5ylDF7YovtJ0lenWaG7faOjjdsUNvyh5Iw=="
Received: by 2002:a05:6a00:26dc:b0:81e:9ac7:26a0 with SMTP id
 d2e1a72fcca58-82980d69e22ls1505380b3a.2.-pod-prod-07-us; Fri, 06 Mar 2026
 02:29:44 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXPsfF2cG6gDcG96QrBOorFQuPujP5GdoZRey/XjsD8WYiJKy76sT+7jMwE9CyxMOGZIXFkwLYyhlY=@googlegroups.com
X-Received: by 2002:a05:6a00:99b:b0:821:7307:44cf with SMTP id d2e1a72fcca58-829a2d9838amr1660346b3a.15.1772792984615;
        Fri, 06 Mar 2026 02:29:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772792984; cv=pass;
        d=google.com; s=arc-20240605;
        b=YVYqLRbzOco52ompVtT2DpBmY1BgNC1zF9jBoO7m9Q6iQegaoEgBFAi2htMc9dliEB
         gebbWZW3bUtFDEAEfS4Wq5texx2GGe62R2W43Tjupijtkl8+7ImMtB0sozkxznPLpLO8
         Nc24XzZrpgPW2ukb1CMb26V/nxAGii2KwFQ+sdDuratOPr/pDFXXLQ8VhBlo4DK3nJ61
         spb1eZoyy9fXzWYc+9t6TjUelnh5GWCNtaqgaGChYYb5j24Sc/bKzQ0zlM/RD+kgaj6s
         M37GMcKuSsZ3shCdWNpKcT/kqCqyQknQbW9x1LMWp6QczQMfxThpBEhqqodSX++TNQGe
         /K5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z+Brq/6epKBsg4Pkewf6wjnSj/Rj8BpANFOXV5LwXOU=;
        fh=+RI4tJCp63FUKYY3dg2dF4J0UgL+hoQ+i4XY2j8VXBU=;
        b=CN1PIDQ6ifluQj+gZ3E2aw1Ekp7ss12eLtHDTHNn6GjGn1M2EOVzir2t0PU3MnFQfl
         9a+NNdEd0oPw9u5c252dxjneoG5xqy2Yomz+oNWLLh6MnXSq9ziTA/xfLFAC7PKdT3/x
         KGEgQL6SLzpu/TOK2Slo536hRWESzsl2/RFkHyAz+euBYUMpM1kK29VK33Z1fcG2SPNn
         g3O7AyyzWoK43YHGgcRzoQWmmxVvP7UvhH3+m1sUvB2IA3dUfxgfWpIZLYdZnxNpGyKY
         t3dE4trDFMGLF3erA+lWZiJH+bPIZBTscS08l0XPiSM3xCZWCcIeWMxv5BGueTZEvhFc
         cs9g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dUUSJe/6";
       arc=pass (i=1);
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1231 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1231.google.com (mail-dl1-x1231.google.com. [2607:f8b0:4864:20::1231])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-829a48b2c35si31172b3a.4.2026.03.06.02.29.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2026 02:29:44 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::1231 as permitted sender) client-ip=2607:f8b0:4864:20::1231;
Received: by mail-dl1-x1231.google.com with SMTP id a92af1059eb24-12732165d1eso9983952c88.1
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2026 02:29:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772792984; cv=none;
        d=google.com; s=arc-20240605;
        b=MetYyxcZcn0Dc1mt1xsHytcdGAM+IO6ZY9+i7ybD3oP+S2q9TYo/QPbUEsd4JT1OVp
         6c20fKQYYJoERDCeQ/T1qwWuX0anuSQYsBQKIRsDzPK1bTbVeCmpnuCl//iMsV2t6G5s
         /oVKXm8WTWar1fcpba1Pj/8XKQMP4Rl06/VNOyACAxtgPZxLkeTsMYgiN67PtoUnBP0Q
         3xVHJb8YESuCf3dp7xwrbZNP+22ZwDAG7Epi3rivKdC5fKYPdS20cRud84EcZYDPG6gq
         JoXXpQFJIdJYzqDGHisvCflbHUVaKv9QTLxz6yRR8FnX0D5PvCFM8k0pqDFh3jUFiLh+
         nAIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z+Brq/6epKBsg4Pkewf6wjnSj/Rj8BpANFOXV5LwXOU=;
        fh=+RI4tJCp63FUKYY3dg2dF4J0UgL+hoQ+i4XY2j8VXBU=;
        b=DDJbqqZJ1IpWbFGAGkY2+9ZeFjvzYu+BhzE5DeGTeUXNcRZDH0N/mtw6NRfu+aNWGA
         OUwjlihEn7+PXCqE2uznFGfIYYdozaXwlNpmzmJTC6BRvLziqkMYNI4b5O4TxnrGsaBB
         fLaeMm1qzqRVl9glSPYprI50Ml9pBTYW9Cpm8sfwjBzezHmF5R4CG1Vc8/6inIjmhl2H
         jLMMcGnGBe4xDQo+gSzqPJ32ep1RAGy3Dl4B66R8kfRzJR4NLwVoldBdQzeWaNwrFgw+
         jHnLos9AM/Sz7kciVgEEKSxDO7Eu8VorKD6qtSVfbiNZHV3dFgHK7ErowG7YQmDu8DgZ
         Vibw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCU3T28v2rIE0ZOSfKXBcNEm3llkakRcwIrDed+dxl/ygPAwIDIe0l/5JScs/ztfqgUuH5ZAAMJWaxs=@googlegroups.com
X-Gm-Gg: ATEYQzzpot3REgADtgXNBNB/RYDW6BrGLoLja8aPzET4pADDKgT1dNHfLdWk2BX6HWp
	tWeXKNrBYw5cBng2+1H/OP5qUca6vCIT/SEYITB6DKtmkqQz2vVYHFi17ZPW5UKOUWZWFCYN8UP
	VjfLPvwQ/ly22v+hqQLxZaUTsV5OXlnRYXp++ygi5tVO6aE8bJOCw62wBVl8k1ZFxfBIjfSKSWc
	2XELI7jI/U8oz6uNcUGORQfEUV9m6W2JIkom8fXQZP5hFMxklj8Vt7k98Tj3eOVZnTu+jRBVzoZ
	2Q61sIBaGJZ7R5/PtQ0RelZeNvzqrbgF2Yzczw==
X-Received: by 2002:a05:7022:671f:b0:127:9cad:1a65 with SMTP id
 a92af1059eb24-128c2e1136amr744524c88.14.1772792983223; Fri, 06 Mar 2026
 02:29:43 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-4-ethan.w.s.graham@gmail.com> <20260306094459.973-1-jiakaiPeanut@gmail.com>
In-Reply-To: <20260306094459.973-1-jiakaiPeanut@gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Fri, 6 Mar 2026 11:29:32 +0100
X-Gm-Features: AaiRm53Jfg5bSHF6icJs_KFXZYY4iK_phz9SHYzN-JwsHFLACvMKwbEaczno5iQ
Message-ID: <CANgxf6yMNZ3=xm9xVhPZDuxMc__7pQk=mti-CyD1QjUOgTJLEA@mail.gmail.com>
Subject: Re: Question about "stateless or low-state functions" in KFuzzTest doc
To: Jiakai Xu <jiakaipeanut@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy.shevchenko@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, glider@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="dUUSJe/6";       arc=pass
 (i=1);       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com
 designates 2607:f8b0:4864:20::1231 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
X-Rspamd-Queue-Id: 5AB9621EB92
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDP53XW3ZQCBBGOZVLGQMGQEKX3FXVY];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[34];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	FREEMAIL_FROM(0.00)[gmail.com];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	NEURAL_HAM(-0.00)[-0.998];
	FROM_NEQ_ENVFROM(0.00)[ethanwsgraham@gmail.com,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[]
X-Rspamd-Action: no action

On Fri, Mar 6, 2026 at 10:45=E2=80=AFAM Jiakai Xu <jiakaipeanut@gmail.com> =
wrote:
>
> Hi Ethan and all,

Hi Jiakai

> I've been reading the KFuzzTest documentation patch (v4 3/6) with great
> interest. I have some questions about the scope and applicability of this
> framework that I'd like to discuss with the community.
>
> The documentation states:
> > It is intended for testing stateless or low-state functions that are
> > difficult to reach from the system call interface, such as routines
> > involved in file format parsing or complex data transformations.
>
> I'm trying to better understand what qualifies as a "stateless or
> low-state function" in the kernel context. How do we define or identify
> whether a kernel function is stateless or low-state?
>
> Also, I'm curious - what proportion of kernel functions would we
> estimate falls into this category?

I would define it based on "practical heuristics". A function is probably a
good candidate for KFuzzTest if it fits these loose criteria:

- Minimal setup: KFuzzTest currently supports blob-based fuzzing, so the
  function should consume raw data (or a thin wrapper struct) and not
  require a complex web of pre-initialized objects or deep call-chain
  prerequisites.
- Manageable teardown: if the function allocates memory or creates
  objects, the fuzzing harness must be able to cleanly free or revert
  that state before the next iteration. An example of this can be found
  in the pkcs7 example in patch 5/6 [1].
- Non-destructive global impact: it's okay if the function touches global
  state in minor ways (e.g., writing to the OID registry logs as is done
  by the crypto/ functions that are fuzzed by the harnesses in patch 5/6),
  but what matters is that the kernel isn't left in a broken state before t=
he
  next fuzzing iteration, meaning no leaked global locks, no corrupted
  shared data structures, and no deadlocks.

These loose criteria are just suggestions, as you can technically fuzz
anything that you want to - KFuzzTest won't stop you. The danger is
that the kernel isn't designed to have raw userspace inputs shoved
into deep stateful functions out of nowhere. If a harness or function
relies on complex ad-hoc state management or strict preconditions,
fuzzing it out of context will likely just result in false positives, panic=
s,
and ultimately bogus harnesses.

The goal of the framework is to fuzz real functions with realistic inputs
without accidentally breaking other parts of the kernel that the function
wasn't meant to touch. Therefore ideal targets (like the PKCS7 example)
are ones with minimal setup (just passing a blob), have manageable
teardown (like freeing a returned object on success) and don't
destructively impact global state (even if they do minor things like
printing to logs).

That said, I'm curious to see what you come up with! I'm sure there are
other use cases that I haven't thought of.

[1] PKCS7 message parser fuzzing harness:
https://lore.kernel.org/all/20260112192827.25989-6-ethan.w.s.graham@gmail.c=
om/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6yMNZ3%3Dxm9xVhPZDuxMc__7pQk%3Dmti-CyD1QjUOgTJLEA%40mail.gmail.com.
