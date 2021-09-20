Return-Path: <kasan-dev+bncBDDL3KWR4EBRB2OSUKFAMGQELWSD6GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id ED2ED411845
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 17:31:54 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id j18-20020a17090aeb1200b0019cd0887ea3sf2118204pjz.6
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 08:31:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632151913; cv=pass;
        d=google.com; s=arc-20160816;
        b=MRDLWS0CaRoATWCC4TeNkzPVt86IJnbnQcjaH6+iYnmxiYNHmGR1p2dUaoHhLwdw3c
         beXPdgq5ZKMAtiqTguagTP8WKKBWBYmqBEriT15JLSRiH97kvohstMIzSIXJqvN95S3o
         u6gNGtBkOMBqXNL1JAvRVfQFGL8u0HEjC5wTn3FEkmDIxmIFpZFzQM2OFLDQeRuUFkn5
         n+WcVaQmDbeLJzX2YjtJT3YNXUmnVu5FVeQlgDDqJzqXEwtz7Z1B0hAQqPn980VT30pt
         mZEqSl6Fo9JQd+AqdGxzBkMAApmVvv+6fk8clXZ3kz4cxxyzPfbTIXkm0XH4KB71AADe
         oypA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HgMUEDMHbIsH8n2abg2erBzcK+M4VsyzxCD3d99dQ3U=;
        b=JRdtS7gutw2gV1sHA3Q0U9dSzGR3csN6ZC006ObGZ76gkICOu02e9cV3Q1tN0GRtYK
         Ta30rQVrZvicZZnX/SHzKDMV4FeQlWi65gmIsnZlf0vJdggLldkalk5YV7cXwbEHRGbk
         NpCktU5E3XU15cvnDI6hBlIRzlwNZn11E2HA7orrpmQFxvyJtq/fEAOOSDoxEtOS2zuR
         LbwI3OE+yC53+CgvoL1+MoZ/M5/bTvtDRCB/69XW1lB33inWv79BXMnxViv/GD5TPl+Y
         9QmSYEP5jon7L0WSaX4uK2cUi7BIA35hHkqbpXrNgvlj+gY0d+V3u8RwSEpjg+FlnnsY
         Bepw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HgMUEDMHbIsH8n2abg2erBzcK+M4VsyzxCD3d99dQ3U=;
        b=FzBWiQGpdeDWF4teXwWJleKRfVUlT0PpdbBFH6u98Z/Ypa1ggDwCE88TSA5zLrDt2m
         etOh8l7rZCfZPC16CAf+jpVSLubz4c4ZGAozmdeahn83XGepHkHy0lgPMr/QJebwfHVI
         spMXNzItxIWTysQrvQMvP8ZEnFomkYPYOUbhgFvsOMetg8JbXfSJwlrkt70UjfwWgRne
         zRP0REJ2cPALM7Cvf1tpg0LvXaaRfItvxdGHojqOdjA/1BTySoi4W+LWPbsQP+Abqu4C
         zmiH3ZxuKgXzxjFb8nnzusMPoZWNfygxbJrHmqrPEGzITWKqrGmaTZ9HEg/n2t1+Ikzd
         Oqhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HgMUEDMHbIsH8n2abg2erBzcK+M4VsyzxCD3d99dQ3U=;
        b=fD0hpII9UTNPsWKgjHLxzHPVhU0ivcr7utjOJrmRO6LkFArZ0vo0VL0GKLcogGHGub
         Y9Ruy9UtNO527Rq3WVXj6FSyZnI3fOmLoA15+jbAWAocNIexT+ghv7NSja3yE3tylWZ9
         z574yq2NZ+pU/RZFIFttshqES7EGiy22KgujeqGZO2pe4XYRSjthWrb9qomvtajNRaUn
         b4XQDUduWGGiNEOlE4oqNv9Ja7QnIB1FVNkoyEf0DSlnUae3Ko62kZOVlt9F2fqVm3FE
         vpattAvF1YeHhDOtgDt0W18KvuJpmU0BRjqrOLZORVLuzgwqwKPGtOJk7DJRxdatfJop
         A4sQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Rosv18pf7OPfjAaN+UrULJY3lzzmu/cp9GNC+v9Lc7Y1tX1lZ
	RdfBcgGXIDs7zPhemekQ7kc=
X-Google-Smtp-Source: ABdhPJzEaAy7NpQ5XGEi+K490aCrw6OFuACVFbjb3K59vqMkt9VQA2LD19QOJw/B/5g1sR/owJm1dA==
X-Received: by 2002:a17:902:8d85:b0:13c:92f9:ac3c with SMTP id v5-20020a1709028d8500b0013c92f9ac3cmr23542129plo.42.1632151913685;
        Mon, 20 Sep 2021 08:31:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2cd8:: with SMTP id s207ls6456585pfs.11.gmail; Mon, 20
 Sep 2021 08:31:53 -0700 (PDT)
X-Received: by 2002:a63:f963:: with SMTP id q35mr23847218pgk.132.1632151912988;
        Mon, 20 Sep 2021 08:31:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632151912; cv=none;
        d=google.com; s=arc-20160816;
        b=Z6olhczmv5q5t7ZT2Zu6xaQW7ax24fydRaHFX3XPan+UES+spU/sKYF3vCsErAFnL2
         awbir9zmc2jnDpy/UhcJA31KnQdTrPhWyx23dhauzFmPfrTxVvc/bblz/E+uRGWiYE9b
         9pPikrpNxqvnir6yyVFDskI47a7+Vj7S2fIxhdV409n0MFfpuMRUtEY9N3an3GEhEspB
         C17/VB74IyPX2+LNu8NdPIYrjD7Vh+8boVsYjhODd/w1608kTZP15xHMOzUsmOODjzqE
         O+1jCyOa5yn6LrRDcu3bf08LfM7Gif72RcsKEe2CUDCAcjkaKrhnWqUgY5SRLrGy1Mk+
         CYSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=9GtAHbC1HFD8KirtsecZYf62NPobAhlgnc4Akhdyyus=;
        b=XpfWLW+YXOU/waQ+sqnRnb3jSDZUNtwG1ZrPrwS43+gVJK2SuZG00asu5Lr5VsshAq
         bBWdGk+0255raNhGztPFzhRCkXzADhqms00NJL5HxjE0FNVvVXCO53N+EvgzD+QKuloV
         4e0MbUWXKYYetWWXDKuUSTNkUe2rXKL9jgiNEPOh4pH33Ckl6QZ0uDzLkNjxdqHQCPsW
         u2wG3vbRYFLtvJ6OKchZM+lDp5Ge7j47fQ08KXg3ImW1Iew0aUA0mZJ9j2K3DgLg7HEQ
         SC8F3GSxz9qUmmLLApcLBW9lMBoFAWZvX4PVHX7PL3JPFd1lxPC0kBDGb6B2DJCOiE6l
         sd9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v7si11848pjk.2.2021.09.20.08.31.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Sep 2021 08:31:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 86DD66115C;
	Mon, 20 Sep 2021 15:31:50 +0000 (UTC)
Date: Mon, 20 Sep 2021 16:31:47 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH 4/5] arm64: mte: Add asymmetric mode support
Message-ID: <YUipY3x1v2XWeF3n@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-5-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913081424.48613-5-vincenzo.frascino@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Sep 13, 2021 at 09:14:23AM +0100, Vincenzo Frascino wrote:
> MTE provides an asymmetric mode for detecting tag exceptions. In
> particular, when such a mode is present, the CPU triggers a fault
> on a tag mismatch during a load operation and asynchronously updates
> a register when a tag mismatch is detected during a store operation.
> 
> Add support for MTE asymmetric mode.
> 
> Note: If the CPU does not support MTE asymmetric mode the kernel falls
> back on synchronous mode which is the default for kasan=on.
> 
> Cc: Will Deacon <will@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUipY3x1v2XWeF3n%40arm.com.
