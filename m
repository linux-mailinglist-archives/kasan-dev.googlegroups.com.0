Return-Path: <kasan-dev+bncBDQ27FVWWUFRBE5R4PVQKGQEHKEYK5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 615E5AFB45
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 13:20:52 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id x20sf4304271lfe.14
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 04:20:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568200852; cv=pass;
        d=google.com; s=arc-20160816;
        b=xIkaf3aoHyGxXgtwecn8sRQfARA0S1sDpUxip8npRuajjtNjSirsmSuCy7saabsAgs
         h9ACB2icd4LIO+zLXSKUBcEuF971MYjCefNMms5aSDT4GYDNoDdsQB0fdH5c6UWxbHHb
         h1u2uK5HMHveOl5+eZLdLhgmyVv1x0PtKRGL0a9W8vLyglHRr/kxLfEmbTMWC/9LtoXz
         HJ17BEMTbRDOydH1SgXgnFIFa0ajV3Eo2icQ82OPWgksw5yND/86z5oUrfedvi31AlXQ
         C8drrvjb4k5ZC9zpFmxZjiDCgqR8E9W2zYoaFJgwvPHtb+z/pbxKLCScXb84pBh4cv8t
         Yvwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=zR5tpL0ycaE0Avw5s6gI6A50M1JFhFviriXKMvicp30=;
        b=Hk7nvVD9mgZLb2ZOEl/a7af6cyeknGSz9iGpWMAUvB3bKqoahrCyzHttgh6tOIcDpD
         I9qgp2NCahyDozwJy8NNTBvQYJ10VsRDFCFFlojnBnky5tNXmVh+mSKJJDHg4ZSS/w9y
         wp6QhxMxhQbLSMWLfbp1KcAA2xXT5sNJx75mK1WpPBjiOtQ6kyYjBcVaHjJ9SSWn14go
         XJ2gnR9oZHVGpY7U2ihT9Pv0YwfhZo1dDGsX3YzdX52nR4o2r+9+gUnJXT+FdbZHT5gC
         y3cyB282K/UASPLeSwoRGwCZEAY5TGDzL0SVd9df0wzEdz+8h2rbVKWnYTv+ueCnR7JM
         /1gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gVILecSB;
       spf=pass (google.com: domain of dja@axtens.net designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zR5tpL0ycaE0Avw5s6gI6A50M1JFhFviriXKMvicp30=;
        b=tdzaLLIKv93fycz9MeASx95Ul9sHXz++725iJKOAa3aLa1ksyJ/aEZcLls5FRBEilW
         dzbSPFzdQ7E1vcpO2FRz0/n2uHCqa0NnNiTiA6EY4w8Z3EsCpMZZUhhCZdGgbjpiPTv2
         9tZ0ACqVsd6mG9rybTtYVhXPp4zan6dwTPaGfE7qFqVp3WbfNaNtd3nHbeaHj5vE7Xq7
         gQR0rv265uae0ZW7BuCW+dDg9pvGDnF7RVETq5cWOCKt0vqyRjm3mObK5iCLEf3CdR6g
         DWQaBOLdEFhlpVkeLXvvhSIpu6g3OEBmkSrkoZtPNsb+XO7vx8z2IhEVSqcWHuBNRplf
         xMNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zR5tpL0ycaE0Avw5s6gI6A50M1JFhFviriXKMvicp30=;
        b=ACeQO9aReiKjMnJffQ4Z7v8cxDZvQUJFiaSLTbkELdflrCPMRXBwNN2jw9fP2HEd91
         +mBMkSkcOasmlsoKa+QXkCBpMsxp8QV7zUZg/ude6jvD3ZvGscaSUN9jf6kRo9VryP2c
         xFQ5s3rnkA2gn5FPmD7V2EZlFD3KlmEHdrqzqZi9RogpRUM9EzPd5Ba05isbjgPVPK3x
         Gfv0epUzrgijx+i6asCYO1wiWTQqji5LlUo3TsSoKXI0B+XFNEsYUR7evyq4GjBxt3ca
         2NIthnT4UHt+7DkPmAtFrCWH5ke+m7Zf/1IeFlLbJnpiZC5VKF5AyslTWuegA2EQmHDR
         YN7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUKjw0iZMNcJ6+E5aLmb+4FlT/8L0wUHEIEsOXp2QaPatIkub5w
	C+R4rcl/pWDsgWmg2J5evc8=
X-Google-Smtp-Source: APXvYqyiEFr2MLJdeyKeH8S11Ykrq6M/VET5WAr8o1KhK2EysEfSSy2fTOoKu6d6NzHmL15Hw0IH6g==
X-Received: by 2002:a2e:90cc:: with SMTP id o12mr23032151ljg.74.1568200851927;
        Wed, 11 Sep 2019 04:20:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:651a:: with SMTP id z26ls2517455ljb.2.gmail; Wed, 11 Sep
 2019 04:20:51 -0700 (PDT)
X-Received: by 2002:a2e:9a18:: with SMTP id o24mr22966583lji.123.1568200851495;
        Wed, 11 Sep 2019 04:20:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568200851; cv=none;
        d=google.com; s=arc-20160816;
        b=MBqs+keXjP3iWCP7AnkCwHhe543WQaOEp4EYv8MEpJ+NAplne5e4hoRv7RudpTproc
         b0v4b+6v05P0merpDfb7U2IdDPxmwhxxJdpLofnyl1wDXSl8TOgXafDIIu6ldp+fGz0z
         8XcCwBX3y/j9wnFfAYIU4p008ewk+oMSLLS/lCKA+vnamWK0hFXHvyOEU7nCeayemex0
         Hvh0cvE/hKPG0ab5sFXbc0OMAcKJ9UrXC+gCe4MzoXeRJZI8HIXriPWQrdOc9XvrY/M+
         Kz25Dj8CzjdzLa1LYOynpub012R3eDG87H7SFnViROFhGmXMZ1F+Y9f70sVv6eyTT92l
         mHig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=yEm/6Jz34sEd/TPS+tNQ49kUmKwP86ymVLNzLiSgWtk=;
        b=WEu66SmpkfnFf+hkrTpv9p6ZWH81d8hCzzZQcMGJ61qG45W7tC3uEPevl/F3Sf+6z9
         ANtmsBQiqb2Ke0LVNfFkW4aIWSMFHRdgRvjQIsQWWCLFBi77ztr/dbleJCXqSwFkPbRn
         COOioIkVjAVtFpN9lNQb7isSJkpZt5xKqbIs37QePM1nAGviJpO14k8KTtnKuOtaGvOv
         662QDrbROCwo2eD3Bo9KUuoKpnV4wIRb6dd5jUjn892mhNAtbMIqYjCQBgaN2aEs6pDG
         59PePM/l8drE3bKmXoYwt3ekkJui5db8dLyNhXcOTds0LdfSFHkEhCohlSvjWeXDBqWV
         xZnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gVILecSB;
       spf=pass (google.com: domain of dja@axtens.net designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id x17si1559733ljh.0.2019.09.11.04.20.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Sep 2019 04:20:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id h7so23063665wrw.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Sep 2019 04:20:51 -0700 (PDT)
X-Received: by 2002:a05:6000:1632:: with SMTP id v18mr12353420wrb.233.1568200850794;
        Wed, 11 Sep 2019 04:20:50 -0700 (PDT)
Received: from localhost ([148.69.85.38])
        by smtp.gmail.com with ESMTPSA id r9sm35678905wra.19.2019.09.11.04.20.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Sep 2019 04:20:50 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v7 0/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <d43cba17-ef1f-b715-e826-5325432042dd@c-s.fr>
References: <20190903145536.3390-1-dja@axtens.net> <d43cba17-ef1f-b715-e826-5325432042dd@c-s.fr>
Date: Wed, 11 Sep 2019 21:20:49 +1000
Message-ID: <87ftl39izy.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=gVILecSB;       spf=pass
 (google.com: domain of dja@axtens.net designates 2a00:1450:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Christophe,

> Are any other patches required prior to this series ? I have tried to 
> apply it on later powerpc/merge branch without success:

It applies on the latest linux-next. I didn't base it on powerpc/*
because it's generic.

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ftl39izy.fsf%40dja-thinkpad.axtens.net.
