Return-Path: <kasan-dev+bncBD56ZXUYQUBRBL6TYLCQMGQEYPPOH5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 09193B3AAA1
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 21:10:41 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-327b5e7f2f6sf1237732a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 12:10:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756408239; cv=pass;
        d=google.com; s=arc-20240605;
        b=UlDSHZ/Vj/BHzH8K3r3qRbbSzPUFClCdEKMLmS7wiL6JAZm0clN9rBkZxJctRIoGeh
         CaaGlgkdsh4R/6YJeFyy9FWtU0dZkB44P4nQG7tcr9OCG5LkLEP/W6nChbmvjasxi2c6
         A10ki0C6NQZOkU9wrm8CWjIf/kCsbSKnUFEPwXOdRR3BOmFA3BWH8PuqbQkdDd7qgrOG
         pwRTVWuHKqyJF5QWei7/8Alq9rlasl+liaJjUt6U9R/DXAcO3+/HoAO0HBOZlrUQYTfU
         2wdTwcLsfJ822y7DIIf5D+NCfR7uP0tk6u15KIlSbaQSeViyZi1lWG1GXpXNyQ55j/Pc
         KHcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=O9wIV7a7HCiqyFPGO5uEBL+WJolYOHTOH69PO+JnqEQ=;
        fh=l0blmwDpFdFfj2dmtOEOd2RHT3XSwegAGi7sb/cxbvo=;
        b=GjU3Xjao/8b5rm/qfKkK/wvjc5Lo71UNIAhIha+WWmCr5QKZRsEMxRgx3rZKp6hDe/
         BIvzK7O7uMgTzFBZNqeRFgDwGd6EI7XbjGid+pi2+ZAgbrNHZ7HIgQTdqQZdPKZzHya5
         M67ZiMPBzTI6RpoeBZGrlngkiBDKXs9KjOAhJEGgJVCFpiX2zOx73a3YUBU+xfaYaK/9
         5rIwHEe2CLIeHgcCi6C6lDZ8iGR8B0FTashqxrXJW8P9wKCQ6EqaUcpmki6CvfP4dzRr
         jUxElTRJsFZGvEU3dEEh6PhQ+ge5k0vD6l5ZTcL4ycHkHRTyW0XHKkMAhbQ2FVuaQ3dU
         jXuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kiAyKBDP;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756408239; x=1757013039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=O9wIV7a7HCiqyFPGO5uEBL+WJolYOHTOH69PO+JnqEQ=;
        b=RLWzX/lCmig41Z2BO2fYF58wZDpi1lGj6Luo+HAnpJWIQPapIh+iLyBrVpkfa9TWlZ
         vW7ybfcIeY8P7WbTOV1PyqFCgMP0SuIOZcxolWX0Sk2zLPPqa8xT2NKMSvrrLb8PtCgW
         h86dnwYiGsL+4R7sJLu/KEd/myjlStQSyMaZ/+46CGOa9joOkMFPKYkMiro/SHLnjvTm
         s9SV5g8G0LhN4MACATpiyrFq0QPtAuz/HfAVo0CYkx1HCl1i/awANZ/padJyW0dcSXZL
         2XEqZ17/69y/Gqxpz+v+W/f4I0QzLH575zJeF6aS0xMQfqy2jxrz8MsLpGQ+RLLW1wEV
         ERfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756408239; x=1757013039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O9wIV7a7HCiqyFPGO5uEBL+WJolYOHTOH69PO+JnqEQ=;
        b=m+ZAV/QVvG+5gyv9RVJrk6EJcIkMgMCx7DA0zFpJrWo+7ljXcc0Z3BW4Z1w16XQaze
         QHpoLTE72rBa54Htq5lJFyBe5sKX9mg5QgvUgdTESry3gE1yf98/qreWVCUSDE6HkMbN
         qEf63c264TwN3IhoB5sOAFrTFLLq5Jn8FC/xyVwc9wmFXuHoFMwiHs4uq19tenTkrb5R
         fUfqTWJUjsaXp/smD0ZXqClrbNPSVXnVleg+NHyfEVehS1p58zy0o08rERRE0MAEpoM5
         XWcaTBoTjTtUP7rsqau+7yX95l3TBXImLJOJmqQxm+fZWzzaiCe3EjPH0w2Z5LoTrVXz
         db0A==
X-Forwarded-Encrypted: i=2; AJvYcCWpprtPpWaTDG33IGsU0OicL4rsc1ypqMRk3vFYFMmkb9L0kuYot0iw8ZrHQ5KDaHVwYxUptw==@lfdr.de
X-Gm-Message-State: AOJu0YwWrz9cdhwL0XRK60QqjHWyNdofL+JazDHWrSM3Vk4SfBq8//9l
	QAgx2/VJe3PDkDKN2jV+PNwF1WL7buFd4OOfvM4TKgR/afamcQZ0d+II
X-Google-Smtp-Source: AGHT+IE9ByqtryvftABgDSasdgTzAFQJTwUYqyRVBbYNfF163EmIUmCBnk8gL6ygchdQMe31yA9OSg==
X-Received: by 2002:a17:90b:4f44:b0:327:9e81:ebb1 with SMTP id 98e67ed59e1d1-3279e81f451mr5386102a91.31.1756408239357;
        Thu, 28 Aug 2025 12:10:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc+wPC2Nd/97ygUTSE4CHFwUrJSdhN0Sa+7LdEfAXuE2w==
Received: by 2002:a17:90b:278d:b0:324:e4c7:f1a2 with SMTP id
 98e67ed59e1d1-327aacedf42ls1432331a91.2.-pod-prod-06-us; Thu, 28 Aug 2025
 12:10:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUTgJpi3hKbfM+MKui2/vt5+3eBkEdCPRrzsYOgXmkbcoMp2499NJC0eqEGWvEoEB00uroMg2RfgKY=@googlegroups.com
X-Received: by 2002:a17:90b:5445:b0:327:6a43:c73f with SMTP id 98e67ed59e1d1-3276a43ccb8mr10134269a91.20.1756408237777;
        Thu, 28 Aug 2025 12:10:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756408237; cv=none;
        d=google.com; s=arc-20240605;
        b=aTinBRMM+yUN7nvxLng+bBABKIFeu6gKlDB8gMhed76sQOWio5sS1Tmw34Pj/n1BCJ
         pKPALxM/c2i5gTwAGT7p6obLMBI4DURi95cGaNRlXeMN2yt+cZMUZZCtVRLOS7OcPt2G
         HsFxGUscU4Ey28T8zPEkUl1Gn5BsuRCl8rzfyhikCvjsudJkls2kzus8S9mPd9ve/B3f
         HZOsV5BjMiRfgXnyfPym5tyT3BmBFml+aVl8q82E+uh6OHgrokP4By82bbkLxcmazsjp
         HKD7DNJ9CsefskCzjUEpexfvHr6QHG73zmYY9ucGgpjhNEUpUvCU6u4D1DLUy0wuVIJz
         au5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vCM7BtjhSSdjPD2pC7Een8DTkoaQQR4fjFPHIwA5Djs=;
        fh=kGmHQt+14enYEes1OrQ0DO+++3SaqzFzOlO8vwACg9o=;
        b=ZCoqKBhU3VWgbNyyRJ6Oby9Aisu1txFHWHofVZPmVZrRq0OxUAmPDjf3gEl5XoDzus
         MXWGRt5qs4fUfHMd5sbgMpPdXqQYnmdghorX5nXd25psNbxYOcKQzdg4BAt97scyNGsr
         eROJyNL0ro7KE32NEuICmx58nrpjfcMA+LzeUlxEFZniUetVgYYgA1yLHUP48uhQv/Hl
         yYS540o20Di97/1D0V6FGo8mqxFe0+MT3+Y6Rp+hJTUhgEJPUstXD9ItvQ6fSIrWE1OH
         13a5+Es+5wICIKLgel0EchY6j32UVb81RT3XqcaFfknOV/gPoNh/nHgyYOSJKna/DrGi
         NA2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kiAyKBDP;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f6ad8b5si264338a91.3.2025.08.28.12.10.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 12:10:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id AE2F160139;
	Thu, 28 Aug 2025 19:10:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CFBADC4CEEB;
	Thu, 28 Aug 2025 19:10:34 +0000 (UTC)
Date: Thu, 28 Aug 2025 13:10:32 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <aLCpqI-VQ7KeB6DL@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
 <aLBzeMNT3WOrjprC@kbusch-mbp>
 <20250828165427.GB10073@unreal>
 <aLCOqIaoaKUEOdeh@kbusch-mbp>
 <20250828184115.GE7333@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250828184115.GE7333@nvidia.com>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kiAyKBDP;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Thu, Aug 28, 2025 at 03:41:15PM -0300, Jason Gunthorpe wrote:
> On Thu, Aug 28, 2025 at 11:15:20AM -0600, Keith Busch wrote:
> > 
> > I don't think that was ever the case. Metadata is allocated
> > independently of the data payload, usually by the kernel in
> > bio_integrity_prep() just before dispatching the request. The bio may
> > have a p2p data payload, but the integrity metadata is just a kmalloc
> > buf in that path.
> 
> Then you should do two dma mapping operations today, that is how the
> API was built. You shouldn't mix P2P and non P2P within a single
> operation right now..

Data and metadata are mapped as separate operations. They're just
different parts of one blk-mq request.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLCpqI-VQ7KeB6DL%40kbusch-mbp.
