Return-Path: <kasan-dev+bncBDUNBGN3R4KRBQ7O5G5AMGQE7A7P4XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E70859EDEFD
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2024 06:40:33 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5d0b5036394sf306363a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2024 21:40:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733982021; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vp5sJ2eQk40ZI48SkRvt5utGEPoH5TaiO0BP2Lg+iy2NDnqUQQxVt/5g1YvlE8Gdax
         3btSDChfxb0MKRSpTmLxg2qHC7wEFC2rwaJc+2+TqTGxKT6gL4OXK1HDpoyUV+5TKxkv
         OF0/F1HYz9evXoc7fmUn5ZzmcVao/IUQmzkKxguVORMG06ufs3ClAdTcmNtsd3bJyVMF
         /zqC4EqiQpOOZyWsRKcu1W8yDV2MlXmdgvlv2fcQkSQvNojnxGlemWSdHPfEo+iZsUSg
         KU0wrDK11Q7BlWyGsjbNG+umahO5tHGAji9Sm69jzxse7KAw1d20sOx+CZrYn0oDK+7Y
         QYbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=9Hq8bPBbI2kJNTVq3li92mRaRdtFDSDn7y/bJ+R/soY=;
        fh=brJKSywizi1mT87PtPHJ077M5lPPASktCKA6s+hdBV0=;
        b=bl5GK22U2gdKNAPffEOh+kS8uE9ZmK6Y2+BMV5LMnETOqTfIjPEjQtUIFGukitM/Jx
         30g8ME4OJbeAbnksJuldmjqiqAECeW7x36EVNMxtVEePInhUAg5NWjOoaddcTh/QoJYs
         Orzy3wcOG7Zfq+4qrPA0gKi68C8oksoHSjE15+sERnH1omR1Zhe1og6/DcbHKuryWNig
         Nunit6TeOeogEeXTL/dUXNnSU1bQxj9WDOg6x6XH+RW4Nf3j7devDcoNvCcWv8zvREIv
         cS0y8JBeCyjgeziPyhUqNaQTlwd5Ez70deZmM2hYi5Uqbl2w5U0nsr72G6kPpNYwwGhY
         9NyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733982021; x=1734586821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9Hq8bPBbI2kJNTVq3li92mRaRdtFDSDn7y/bJ+R/soY=;
        b=Ilp7QBzV4oegoQTtoqqMrSYgBEOagDLLotbDyKcjwGQDmBIzhvfDex4Teu+/uv5NTO
         ABYm2Zv3Icov6TuKAv8/Kj/nLdYF8iFAM6YobYLgCkrfZSdsfbzbyF3cXYct7GPi/tjn
         yQfOOchYL7GMF5WjfE5WNOfR5rzrdtVNwqaO4QJtlUsjNCEyRaZP052XMFrJ2u8IwQWa
         bqB4Iqf7xsF7OjzCKvPdFXUwdlyEwM1aqhFmg0LnYTUIxf9x32ckamjE9tMPIpxRV4H4
         S6wsf7xPhchyi4UfNpqH/N+4ND1ZWKXaaBNdGxBP42U+D1awRdNTe0uMpy9jB8CIyl5A
         hbVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733982021; x=1734586821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=9Hq8bPBbI2kJNTVq3li92mRaRdtFDSDn7y/bJ+R/soY=;
        b=oi2fTtuiCeOaT5kmEs1SjzDbLUXSdb0xI4uun10J/7OCvhX323/7afx2jz4zteDW1K
         wlN8v4HlNkgNtyT1z/mGEdhuF3xORRYl2937eASllkJ8P3Hn/wbHgJHt9ybI4Zz9xDaY
         CQ9KMhSKxltIxq2vTTBrsoRcIAimPBZYRKPlXlx1nj9O/b/+YL0+OAkvj/9AaoXeTT+H
         UhI35bQt9VZ7MQjFKDSedSxmcqGMosIxvuerB0RFupSG+6vuDUdCmul0NgrWia/9YXGJ
         I9ujd1itE+4AVYHX3fDxmddZPlvoBLQwnAfwFpuviKiu82mF4Drvtwoi3zl4Jwf77u+M
         +aQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVwYnCnhXVeWpqBorvguLXXTbTUZYJ17Y3FNJsnH5+ygqfzSi+OkIxg+5sDxES7zGEQkuPqOg==@lfdr.de
X-Gm-Message-State: AOJu0YwVTyuK2SyRjgA0c3pX/wZCkWW0NF50xMh+GCf2MIalJcnZoFHM
	EGPpAh8C24wAnO9SmuHIMcA1N8TtomFzQYDweDeZrq4qL/L+J/DM
X-Google-Smtp-Source: AGHT+IHE0hZGz4arCtdAsDlt/e9K3gBjndhseGs0hDg6DserC7BEU+VMsumZC08llyfDMNNevUwTgg==
X-Received: by 2002:a05:6402:3908:b0:5d4:4143:c07a with SMTP id 4fb4d7f45d1cf-5d445b21ec5mr2041929a12.1.1733982020319;
        Wed, 11 Dec 2024 21:40:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fa88:0:b0:5d3:ecaf:6210 with SMTP id 4fb4d7f45d1cf-5d45426bd7dls38345a12.0.-pod-prod-08-eu;
 Wed, 11 Dec 2024 21:40:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW+J9Hrc2Lk8biKB30C3vcppKkzZGRlJjPXF8xFO/pxWa/ntuXuN11dMM8/hgbznbtcTg2rLjofM7k=@googlegroups.com
X-Received: by 2002:a17:906:18a9:b0:aa6:a7ef:7f1f with SMTP id a640c23a62f3a-aa6c1ae58f3mr234161866b.11.1733982017919;
        Wed, 11 Dec 2024 21:40:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733982017; cv=none;
        d=google.com; s=arc-20240605;
        b=E/VqS9S/KlSQGQvOKMMiE5pzwTGzTC1NcGm70WUWaGwPtqgkMGzqZn9sFC0+9ZvRSa
         /RLQo+r9dC+QkF2PXzT3dmsJ4aspnF3g8hn6B/0CdSmPrqi4S1O3xd0tZC3+7kwvBAS3
         3HCEnfVP7h5rvFQcypfrgP9vyyVQLIlxG6tjTt9pjf2NinfKAD9m4E/XryZLptTiMysq
         rTwKCVQmWQver8HFIs4onWrbgKHVmMyzwYh7z898Bf+Gj1nErljFSJprhDNn71Eelfv4
         qmiuThtfbzfNWTMgXMzZEUrpfOMTaP1EQoGMJC7r1+OtD18pIhq+AKaDXysQ+Rxf3Qjk
         ms0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=u6bBbZf98WDlASPU6owmDPpcO9WcWFqJzpNoOL20AYA=;
        fh=0DP065ItdnCaHxOzDmSgr3FuGuByWFUwGuZaM8mAXMM=;
        b=jJlxGvaLBvUH8KxUXMCwp6fr6ahyBQybNSYISl+lzvUrlM5s95Ns/O9SQ5KMsetIGU
         UoUdrOHCRGHEo8BDHelBijMJ63LGMOYT6Jg93dsWWEo6ff2Uhr1IOfxQ8YEReDhKf/DM
         HhkhalL2ulSNKm/qUOQ0dr5Kf1VCc+9VoKYnfGMR3LN/nj7MqihKNVW4ihWmLlH2xS7d
         Gr9pXCYrBqYr6GRX7NgFobq8sAqP7d94bdwJAIhlgXZjgzrVuET7C76ILAViY0cgRRXj
         UVOSI+7w+Hoq5i4dW1xvJEYvkn5bNIJQWrz4zBDSARRFH1PkpJCZoC2QSRpY6VenzRVR
         2kwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-aa67d6fcd60si19760066b.1.2024.12.11.21.40.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Dec 2024 21:40:17 -0800 (PST)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 0C5B068D07; Thu, 12 Dec 2024 06:40:15 +0100 (CET)
Date: Thu, 12 Dec 2024 06:40:14 +0100
From: Christoph Hellwig <hch@lst.de>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Ahmad Fatoum <a.fatoum@pengutronix.de>, kasan-dev@googlegroups.com,
	iommu@lists.linux.dev, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Christoph Hellwig <hch@lst.de>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Robin Murphy <robin.murphy@arm.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>, Kees Cook <keescook@chromium.org>,
	Pengutronix Kernel Team <kernel@pengutronix.de>
Subject: Re: Using KASAN to catch streaming DMA API violations
Message-ID: <20241212054014.GA4695@lst.de>
References: <72ad8ca7-5280-457e-9769-b8a645966105@pengutronix.de> <360e2ec9-556e-4507-a539-f86f7619fe29@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <360e2ec9-556e-4507-a539-f86f7619fe29@app.fastmail.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de
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

On Fri, Dec 06, 2024 at 09:14:27AM +0100, Arnd Bergmann wrote:
> Right. I would go even further and say that transferring ownership
> to the device poisons an area that is aligned to ARCH_DMA_MINALIGN,
> making it possibly bigger on both ends of the area. Transferring
> ownership back to the CPU only unpoisons the exact area that was
> specified, leaving the unaligned bytes around it as uninitialized.

Yes.

> That may need to be controlled by an additional Kconfig option on
> top of poisoning the data initially.

Note that we'll definitively need a config option for the basic
checks as well.  There is plenty o drivers that don't do any DMA
ownership management right now.  And while I'd like to see everything
fixed it's going to take a while to get there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241212054014.GA4695%40lst.de.
