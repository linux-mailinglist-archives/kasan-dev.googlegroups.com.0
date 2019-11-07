Return-Path: <kasan-dev+bncBCR5PSMFZYORB3NSR3XAKGQEINJMFSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E2E65F264A
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2019 05:11:26 +0100 (CET)
Received: by mail-yw1-xc3d.google.com with SMTP id 202sf775575ywf.8
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2019 20:11:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573099885; cv=pass;
        d=google.com; s=arc-20160816;
        b=jli3DnZnD3fCGwn4I8s9ptnjsFuvmX97d2tEfNFwy5/oa3vHrpymJDtxEdioDeGuUF
         /QvETFU1c7xNCku3AmAF7D4xcFOaWUzIXGxhKM2hYH6rjvMyEQVCCj8KwaSxhX2KVA6O
         Snqj3ObrBrg/9nuw/ZSzzMVImoeCfnQXi4zHh6HrIyWkOTs6Ikb9i5old58nUgBmkfD8
         4PEuiKVYOUdEudTfQeFmZla4shBfoTYr/xFmF8W1s07GKo3AA9ctLYgtRyU428+4byQU
         Kwi0ezNbMNrDFSYDxEnhZJ5K336WOixVIqbchh2aQqkSkfEz3epVUOQ+vgqpBvErggyL
         Li/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OseWOzGhLNetmnd2YilbmNSPH5TxvCWVEKFPIaNK/Dw=;
        b=RHCD+CtJf6VsGbT0x3OvnuhNrVjurNgOCihHDje/m/C7rTuGDZ5cRPZUIW7wOSQnYB
         boPUzDGpSdYZUN8drfvmuCfQNtXG2wO516OS1gxeSciCRKq4kagGd7O2LrNM62YimN+O
         I+5Z2Tqovb33Bn/iphp/DuY/OAYRcbRkDTRuOnWoxmDb5uczziiMJBYrTujpjx4nR0IV
         mdjge1DWA5HxTq3pT6OiQlgdydW1wc2kRDj8G3IwzxjWYcxkd5/o2dFgLCE50G3Lwk/P
         5M6sTZQdkvJHr/XsqGG4dd58GgYVrq6g9xQHFxHJNd+rDKPkLniLFK9nSzAwck/RyZJ3
         +ERA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=nGEZ4HST;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OseWOzGhLNetmnd2YilbmNSPH5TxvCWVEKFPIaNK/Dw=;
        b=U4T63yiG2ARSPI9imUdKvzpnN3/kF4hFW0kDkvBlNCa6DdV2XsG86TSPQW/cUZxvNR
         al0W2O9+xMGT1cfwYKHZ08HGZj3j1hTWjL3kTcrPvCpQXkkkcuguL8hZfswoLUA98N5Y
         K2/75DKW/ni/QWqVA7Pkbiu4UpxpSfEkeWPyj6b6wHC9fPHxsEONTg+J2O6FX9d9vdRC
         nd1IpX5FmECqblLlA11OdeSFw1vS9yAMP+24PynC9/TrGK3PaoXI3trvGq6kMe688qhf
         hrFf0EsSEucoDG++DNr0U3LMu75mlToIvx02W6zvoB5wVER0QbDe/y/ysCQPUsypv/5a
         4RGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OseWOzGhLNetmnd2YilbmNSPH5TxvCWVEKFPIaNK/Dw=;
        b=RMNIDmL0C+E92dG24Wujp5SN22Aj5tdwCZQ1/LcH2IuoufpB/8VUqU6yc7NCu+SmZt
         6ovZ/Hp1/9kNU6uWDGbnBQNUYdE0KZ6QK97pnZjwtAH3ve3szeJqDZSEH9IEwWqxAyJM
         OiDuLD17aPfcB3D5dKmBlqdhlHx8LI2KlRaPzmZqeFNsjQeWNKqrKngLDIW8f7bG0AOU
         7sKhbfcFAmFt/7FrBWuk7HAUWbf3z25T0e5i6y4FrWxp5Hqlhx882pZtv2mRTub6Y/EK
         KRr3OcvC7g79adQFl9Frh4Q2p6P1oEDW1VndXVgyqapEqqx5kTvb/E3NV64PCJWaIs1a
         H11A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXjSZomcKfFRL2vXelVOr/ZHKEwPSSGX5szP0eNEkDL3z/KBE9g
	UkzBaxrQKKWeQE+I+rS0QZs=
X-Google-Smtp-Source: APXvYqzh5DHm1dXzvhRfnDccc/QtoFNqlMxPalVTULnKu3nem2uj+KJZWGf52VLWQHqOopHzmnJz2g==
X-Received: by 2002:a25:50c9:: with SMTP id e192mr1428526ybb.208.1573099885634;
        Wed, 06 Nov 2019 20:11:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e403:: with SMTP id n3ls666407ywe.16.gmail; Wed, 06 Nov
 2019 20:11:25 -0800 (PST)
X-Received: by 2002:a81:7403:: with SMTP id p3mr849706ywc.106.1573099885057;
        Wed, 06 Nov 2019 20:11:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573099885; cv=none;
        d=google.com; s=arc-20160816;
        b=vllaav67LI0QOaDCdYpxUX6JRpZpNFolNIcc2CgiDnoLqC3/Xo53OzIXu/Qh+Q+d1V
         NSQHrL13RYzOzlrtoShluCPnhtlYqCmhY/+PfXTWjk89XPsOoRLdCvpXRvnVd4D5jZXe
         PvnS59N9gMV98LA17kPietW6OjrM/HTtsXp17g6Ha/Rsk3l5C7rzIqkLMzdRJ95FQMZh
         MgNg4JDCb8RAHjKsEvIDH6/t5ACv1rWR7sxOgkgRQ7DDc3uyKq8Vjpz14+N9g2lvj6wL
         M2NquBK+tFkqE41fO2Yq3Q6X4sZh3s+ovQnIVhKuYKENMI+Nu8jhn7vA9M9xdkzZGSVf
         33Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=JioWWRWRxfUDi71zZkY8xsA6Z9J7s07L+tQxPkX/JPk=;
        b=JDQV4ixsbMiTOWEFjaFUwrJMk9d61Bb16nmmKoQlPsyQopF5bpc4jg1Clr6Wfhufnb
         QxPwiqsG3cMLnsH40dKpLlOXXLiJzV8bEoIu+OcplmZszmp+5fanRDGsD8hLu11fJ+Bg
         JEAIxyJboLdmIRCguf6aUE3A9qEvTaPzQfL55U7QCHGIx464MgWSu5gkBendPKxok2kp
         tTpNour6rNNVKs/e8RXjjsdfDNELw4zBoNggl302cBKs2L37jZq4PDlfgVMySEg10N3a
         JwnLgD6yPY4sZaMt+JSqlRWAm4daEIEXsYKMvhOdvd29det+H9MhfqdQfHvMgdEdZGtA
         31Ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=nGEZ4HST;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [2401:3900:2:1::2])
        by gmr-mx.google.com with ESMTPS id r185si72311ywe.2.2019.11.06.20.11.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Nov 2019 20:11:24 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) client-ip=2401:3900:2:1::2;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 477qhh1Mjhz9sSZ;
	Thu,  7 Nov 2019 15:11:16 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Stephen Rothwell <sfr@canb.auug.org.au>
Cc: linux-next@vger.kernel.org, christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, linux-arch@vger.kernel.org, x86@kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, Daniel Axtens <dja@axtens.net>
Subject: Please add powerpc topic/kasan-bitops branch to linux-next
Date: Thu, 07 Nov 2019 15:11:12 +1100
Message-ID: <87r22k5nrz.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=nGEZ4HST;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Hi Stephen,

Can you please add the topic/kasan-bitops tree of the powerpc repository
to linux-next.

powerpc         git     git://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git#topic/kasan-bitops

See:
  https://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git/log/?h=topic/kasan-bitops

This will be a (hopefully) short lived branch to carry some cross
architecture KASAN related patches for v5.5.

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87r22k5nrz.fsf%40mpe.ellerman.id.au.
