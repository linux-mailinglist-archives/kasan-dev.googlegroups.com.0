Return-Path: <kasan-dev+bncBDEKVJM7XAHRBHMV3O7QMGQEKZZZAHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 046BEA8308A
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 21:29:35 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e8ffb630ffsf105786926d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 12:29:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744226973; cv=pass;
        d=google.com; s=arc-20240605;
        b=J7jERBLosfSu8H6MaEsJpCzp6usGZU1YDMplKS4EZO5BORwOgjFbiTjWQWEv467HhJ
         Nqp6CtMLRzzyVfgsVEh9/daQ6V2GuLCXkHb4hW/Je6dmdk9j9+2DcIaVjUNtTl0U2DYp
         EoE5Y8lfPriNvBgH58lnPdRgA/Qxk0S6TG9oi1DAGdTucqRAOq8KCON9pVmuzJd6KTSd
         PBHSXKoZOFMZHGuTZ70llAmEh1SO86CmyRhKqaS8KE6hiKE+4UPfEO8OFLO7KkMtVgzE
         o1txatZogi3TUDW/O9I6iew5SN9WfyXTMcs/i3LDajdV8k3IsvcLK6K8F8HhzHtuHqy7
         B4Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:references:in-reply-to
         :message-id:cc:to:from:date:mime-version:feedback-id:sender
         :dkim-signature;
        bh=Zq1zQqPstu9cBw9K/hYPMYSth6QnJ6a2XARoZDX+NeQ=;
        fh=c360kDEOgH3lDhLJxKfIbRjXEx9Uu/BYP2kuLvdxRuo=;
        b=W9FV6F2sM9u9jyMWIe8ez5sNl41WGJlc2Wr4Gqw1YNW4y0pbVDYaeTyhzoqjnh/3DM
         5Eid03SuJhNMp3vo5T7XbXggVKpv1fu83s2is7Qy3pSN5cIV71i/JhUVJ1m8hr0TroRR
         UD4nuKVjytfjv3dwYgQZIVDQtaFcPGfwXWdPh1MoGFPCzRqPjzQ0RKLOSH/G3qQ3ei30
         wTBhGNv6RLdfxh362beaV7OU3CAMtK/jOYk5+bTwmYP6/dPtR5iew6Y+IXL4OKOVRngz
         W+52GlCPDFECwFjvxVVhvXj27sUDmb3RsHvPQiP21vUY6dIBS02TJ06+R8JFwMKSNidr
         Vj/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=SZVS2X+S;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b="MGt2wZC/";
       spf=pass (google.com: domain of arnd@arndb.de designates 103.168.172.156 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744226973; x=1744831773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:references:in-reply-to:message-id:cc:to
         :from:date:mime-version:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Zq1zQqPstu9cBw9K/hYPMYSth6QnJ6a2XARoZDX+NeQ=;
        b=u7dVeNst4eDJnjUOLiqaTnaUQbZbreiXDyfnmOPp0i26fit1gGY0syCHyEzfKWM8iV
         3oPaVcGCGieX83GLdKNBwqU2tQrF0Oc4ti4/5ycJMjpsgMPy236d5E+DpBdBqtMOYl5R
         TtS2ywD5KTnQIm1t//GeCt8Zf+Pw6SS9h6PVjSrflQ4y+2BXfaNoErtZu6K15M+sHBtM
         fkqf5GOIBQ2RuOND097EFqfMrmTwyxbORMKtT6wSElss01JI+hFznwAMn2ngXG0t4JPW
         4yMcWbXQhHewiXn8b7kMn6KEkrsWAlg4I1nglyBgc9xFg/iITEZmvJ5oqx0bRQmTwPuQ
         jcZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744226973; x=1744831773;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zq1zQqPstu9cBw9K/hYPMYSth6QnJ6a2XARoZDX+NeQ=;
        b=hyi1vxGy7Kz7o8sDS3IUcGbbO13ib1f4fygwQe+rd/OXHiIxduaRHeyl9RRjEi2T6h
         BTEbP0BXJLstxv4HvI5VFDPrWGZKUSlL0sieIYStdBoqTd7PpeI7z4PGE/C3K1ZOETNF
         YrV6eSz22NACHQV0t/YEAQ2+VvvxyTeCJ0Z0F4NhqqV0B+wIPu80OCyJsNskg5kUHf0F
         kfEYHu1fFOiiv04eMgqNAdiJSSSEzEb7hiszaZvf1RkEQ1JEekma2dMAE2ZxJ0NY1HPM
         +hNLgK0IDXqJ74v5nt9Kqc+PbiaEl96Z4e9oap1OlD6cUHz0mjKndHJJQl0H3ew72qJV
         HeMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBsnWZBjAGsDwxQF2jq6JZV609rprCBWpIRTjT48v7SHhUpMkN3OjmBgXoC1YnBV78dnP75g==@lfdr.de
X-Gm-Message-State: AOJu0Yys2+9rPfvUrvUC+bbvVd2tvBe76wTyMKD7+09NPklMgktOmcow
	QnfGqX6x2vcvUhRtplkFm58170ViFQc0EkWelMNaE95Tm9e8tPw2
X-Google-Smtp-Source: AGHT+IHGnYn2FiotmKaGDJHHMWvStnKPkauy/jtaGYvuuziXLkE9lQT5JxxIZf7r1f7RyNAa0U/tPw==
X-Received: by 2002:a05:6214:2266:b0:6f0:e2d3:66bb with SMTP id 6a1803df08f44-6f0e5c85466mr1637976d6.43.1744226973632;
        Wed, 09 Apr 2025 12:29:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALq19oOQdVXTOTTwswlZhLasgPZYZdh7ZZTYnZOLTCyuA==
Received: by 2002:a05:6214:451a:b0:6e8:fa98:8af6 with SMTP id
 6a1803df08f44-6f0e4a8bd39ls2813846d6.1.-pod-prod-03-us; Wed, 09 Apr 2025
 12:29:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeLsA1L7Xvzu4PJvxSsrw6pmhLLfyYNIJoESpSqcBzmiyRUyifRv0MZCsSEx88tTkGJv8+4ZuCiIc=@googlegroups.com
X-Received: by 2002:a05:6102:5347:b0:4c1:86a7:74e9 with SMTP id ada2fe7eead31-4c9d34bb79fmr254852137.10.1744226972764;
        Wed, 09 Apr 2025 12:29:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744226972; cv=none;
        d=google.com; s=arc-20240605;
        b=D7D0Smhh8daGM617RHcL1Q08yBJ6QdlEL8ag3mv/U6drZcCjYmJ9Hwv70OZiUEMVao
         GfQlIHL9OuSJKEAqNA0JRePSMdgA8+5+pXyS+uE3G3njwPYWJKT7xRF3B1l4p++8dG+/
         /mSzNjU8A4fWLdXjk5fbrD2mtrVA/PrAowun4/CHxm3Vjenbh9H/ozaMdXH4DdpbpAv8
         LtWf1NsKYV52gQsEkpldGL715a7NamWNzbUZ9Mw20cks99UeFMtYFqaaNVDSGVFuT+Rg
         rddiiG1AIvf4v45pzf+SR46hkcogt8PuM9SNrZPbcxkOfwA4FZbjEOXPTS2zJSMk8Ce+
         GTdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature
         :dkim-signature;
        bh=7LeM8fTejAmZLunIFrf51zCFnY/PxkuNIPidaV8t9E8=;
        fh=pI+fpYMj07lcPs65yxG7sLKXLwEUQ/pT0xQ1ubNTKIo=;
        b=YPemqbrOtARcNY6jn24N8zNX4ZdduFfd8h79EbsZU39cvg7LJQhlrh6tuzzNVIooD9
         Cv6XktKjrxKeBcgXONIvgAcO3NZ8Udn9h8Avwmv7RSe7QEm6DLjay8/oUhLYqYpJVS2W
         A4pp3PGn/jjKcYbXGNfyK9vM0nHtu08UvZHyEJo0pLt4Dr37eiOoeekl3xe597isS5pT
         9yqbjTEAIKVUmNztjkf7nuapZwdeTTdxHqdAGDoq5DDBYsu5B1fI5BJw/DvR97j5hYn5
         y9vZUvRAC564QNP1F/YRB/SAhwW3OlK/Fu5mxBGoVwjIE0H0WXYIkVpyM6h6VsbKGIp1
         yp9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=SZVS2X+S;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b="MGt2wZC/";
       spf=pass (google.com: domain of arnd@arndb.de designates 103.168.172.156 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from fhigh-a5-smtp.messagingengine.com (fhigh-a5-smtp.messagingengine.com. [103.168.172.156])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4c9c95a402esi103905137.0.2025.04.09.12.29.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Apr 2025 12:29:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 103.168.172.156 as permitted sender) client-ip=103.168.172.156;
Received: from phl-compute-12.internal (phl-compute-12.phl.internal [10.202.2.52])
	by mailfhigh.phl.internal (Postfix) with ESMTP id 54F9D11401DF;
	Wed,  9 Apr 2025 15:29:32 -0400 (EDT)
Received: from phl-imap-11 ([10.202.2.101])
  by phl-compute-12.internal (MEProxy); Wed, 09 Apr 2025 15:29:32 -0400
X-ME-Sender: <xms:m8r2Z4IDKxBcEDfYGDYslx0jUkXueEdDQvXueMqzKLgGxpukJDjZLA>
    <xme:m8r2Z4JmRcd0bWpheClZBW7M-qrnMDGY_tTENCYN2lm3Ttlyo4W2PVq_dGT2jclFj
    M34ezDpy7nx5I609no>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefvddrtddtgddvtdeikeegucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggv
    pdfurfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpih
    gvnhhtshculddquddttddmnecujfgurhepofggfffhvfevkfgjfhfutgfgsehtjeertder
    tddtnecuhfhrohhmpedftehrnhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnug
    gsrdguvgeqnecuggftrfgrthhtvghrnhephfdthfdvtdefhedukeetgefggffhjeeggeet
    fefggfevudegudevledvkefhvdeinecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrg
    hmpehmrghilhhfrhhomheprghrnhgusegrrhhnuggsrdguvgdpnhgspghrtghpthhtohep
    udegpdhmohguvgepshhmthhpohhuthdprhgtphhtthhopehnihgtohhlrghssehfjhgrsh
    hlvgdrvghupdhrtghpthhtoheprghnughrvgihkhhnvhhlsehgmhgrihhlrdgtohhmpdhr
    tghpthhtohepughvhihukhhovhesghhoohhglhgvrdgtohhmpdhrtghpthhtohepjhhush
    htihhnshhtihhtthesghhoohhglhgvrdgtohhmpdhrtghpthhtohepmhhorhgsohesghho
    ohhglhgvrdgtohhmpdhrtghpthhtohepkhgrshgrnhdquggvvhesghhoohhglhgvghhroh
    huphhsrdgtohhmpdhrtghpthhtohepkhgvvghssehkvghrnhgvlhdrohhrghdprhgtphht
    thhopehmrghsrghhihhrohihsehkvghrnhgvlhdrohhrghdprhgtphhtthhopehnrghthh
    grnheskhgvrhhnvghlrdhorhhg
X-ME-Proxy: <xmx:m8r2Z4vJ3WXAHXrvKXd5B3xKv4UAtE2V-BrbJEZAyq1B4dzTfpijvA>
    <xmx:m8r2Z1YeiT1XCtilSnIsx6V2-MzbggW-b6mGOWfQy9AEZpRDFmlT5A>
    <xmx:m8r2Z_byLixda4QM1ei16kxOQ2Y7JUi5RRFxBC3Vzf0ThsHM5YccDg>
    <xmx:m8r2ZxAT9c3e6CGKtCSEv5jY1K8fvNyLiQKw-tehgk1U77NzNctBFg>
    <xmx:nMr2Z5lFihtWtcgwl8O9IIHMPAftIujBP4HeUpKPp9ywwLH-kGjpPnka>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id 7B78D2220073; Wed,  9 Apr 2025 15:29:31 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: T654dc7563e4388c4
Date: Wed, 09 Apr 2025 21:28:22 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Kees Cook" <kees@kernel.org>
Cc: "Andrew Morton" <akpm@linux-foundation.org>,
 "Masahiro Yamada" <masahiroy@kernel.org>,
 "Nathan Chancellor" <nathan@kernel.org>,
 "Nicolas Schier" <nicolas@fjasle.eu>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>, linux-kbuild@vger.kernel.org,
 linux-hardening@vger.kernel.org, kasan-dev@googlegroups.com,
 "Bill Wendling" <morbo@google.com>, "Justin Stitt" <justinstitt@google.com>,
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Message-Id: <6f7e3436-8ae8-473d-be64-c962366ca5c8@app.fastmail.com>
In-Reply-To: <202504090919.6DE21CFA7A@keescook>
References: <20250409160251.work.914-kees@kernel.org>
 <32bb421a-1a9e-40eb-9318-d8ca1a0f407f@app.fastmail.com>
 <202504090919.6DE21CFA7A@keescook>
Subject: Re: [PATCH] gcc-plugins: Remove SANCOV plugin
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm1 header.b=SZVS2X+S;       dkim=pass
 header.i=@messagingengine.com header.s=fm2 header.b="MGt2wZC/";
       spf=pass (google.com: domain of arnd@arndb.de designates
 103.168.172.156 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
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

On Wed, Apr 9, 2025, at 18:19, Kees Cook wrote:
> On Wed, Apr 09, 2025 at 06:16:58PM +0200, Arnd Bergmann wrote:
>> On Wed, Apr 9, 2025, at 18:02, Kees Cook wrote:
>> 
>> >  config KCOV
>> >  	bool "Code coverage for fuzzing"
>> >  	depends on ARCH_HAS_KCOV
>> > -	depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
>> > +	depends on CC_HAS_SANCOV_TRACE_PC
>> 
>> So this dependency would also disappear. I think either way is fine.
>> 
>> The rest of the patch is again identical to my version.
>
> Ah! How about you keep the patch as part of your gcc-8.1 clean up, then?
> That seems more clear, etc.

Sure, I can probably keep that all in a branch of the asm-generic
tree, or alternatively send it through the kbuild tree.

Shall I include the patch to remove the structleak plugin as well?

       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6f7e3436-8ae8-473d-be64-c962366ca5c8%40app.fastmail.com.
