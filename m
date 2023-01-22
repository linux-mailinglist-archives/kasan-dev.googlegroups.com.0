Return-Path: <kasan-dev+bncBCT4XGV33UIBB7M6WKPAMGQECZPXSPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6560F676A8D
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jan 2023 02:21:03 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id r10-20020a2eb60a000000b00281ccc0c718sf2022740ljn.0
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 17:21:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674350462; cv=pass;
        d=google.com; s=arc-20160816;
        b=qwrn96uaBgOFuIGRMsKIwuvTCAmQVNFeqCJlQ4sLBLqWCd68/cAK4ugqSJ1c6kVFFb
         PXBxp1O/ROxSIJ1kaucZ/VIxcBe0dAogLXcuN6vvFgmJcEwWfXE7e+xWJSZZx3ySH39T
         eb5849E0NSTn+vopJf54hkHjMhAZIjD0EegddX70RHAK37uA/lk7NW2advQeWawY7heU
         r/bs27Ro0x2S1sCuwm+KL8yp578oyc132VH03NKhrySoA4cCynxQb0KHqdzBOz29slAl
         w8BTd+UHR9Zmz9EHF27GfNvhsa4dPRN7a/0c2yHJj3fA1xAbGS5ECDsBnh7nOLScn3hF
         2v5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=X8bApQkrIYR9vmzuPcKd7WGFacf+/+xDPX1SyQMLNFY=;
        b=V1eqmobk5mbJ7g/rg7Oi0oLUWeveCsFhPVX/Ik/H65NNTX9Vn+HmPMpzudemnwnrwV
         WeCms4rRYJHu1NRiAYEtWx6KeooMNxNX85ZqeUXOxIvQ15q7oLtDiMIx8bDRJ5jCCQBO
         UQsGJ2rSTQ79zqyN6NaM+4nM7Da8SkZQ/gQD7u08tGVsjW1tZRAWL+Z/XZ4+gNdT31QJ
         tQNgKCo9x7rfV6yRzl+ANPyEnOATf4sV83iDgdF7BFjBDmdXkUDHLnwwDTCEvb4a71Or
         oCGx1ZVYekBdW5iqvGNb7GrS/W729CGhG3piI/YQSM+aOv0lCcScVrdCfB3qhyQMtw8Z
         HF4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=kQpLLvWG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X8bApQkrIYR9vmzuPcKd7WGFacf+/+xDPX1SyQMLNFY=;
        b=B/PqsXOyytCagW/q7b7VdV3tchCPEmJK1Njrzkr56g2rYi/TQ6Jkfq/koqIoJwIvJR
         SYJoughl2w3tlfawUFzZlTftAz9GtTtwz25SdKxB5U0w/Ef3zW5g/y6yRdUgGrKHtgQ1
         +ZhpaJILEPNOxpmkYu0lPLsmR+P0YW6jbsa8r4g+6UhatXrFYw+/vAMSAJTAuMyDCQzL
         BHaPiEAasq3nqu8j6t90sP2VL4BiQP/S7cAhvC/+UhtsUTaCOWk9FUVQYj+bXKLpWNdQ
         8I9e/Lx4X9LmSV7qtbnObH3BxejHLvUqBrZZWwbTcBlgQJPlr6JiMFI6Rbs3MY/RqjGR
         aQig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X8bApQkrIYR9vmzuPcKd7WGFacf+/+xDPX1SyQMLNFY=;
        b=k6fNmxrRnxQNmtrXxAoDJ0F7Wsv4Gzx4GQlVjlcFTZ280X6wEJ9nwiT7ZCpPa/b9uK
         uxCzg8mlKxcCkIUOnSvz4ptM1uIzXqpgn/pUUEpaLJb43FkRr5xiZiO7ej1vg9Tv1R5g
         euVhGSbjq+dVuAcgzc/agmmJx2jhFgYDzlIaiXN7uPWsFgqPREH21Hg5/wn3E+ZC+CjL
         u+yoMq8LOM5SvbnIFgBYaGU5DOwiHYoybZfB4faAV8syweSgN8fXUBPPFw60T6eDjUZT
         VgxJYW8o9/hNLZlMdtZpxxPqCep1qKmUfXjG3+/MIsz7f+VVvqi1mB7EQJFB9UNi92xB
         ojAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krjc/Uq6Y6RWPWRlkZJeYBwcVplfamUYN+mTqx8XG8AWa36MnQ2
	xaunLKg3trOsIXVqIRT8Hnc=
X-Google-Smtp-Source: AMrXdXslNd4dZyI/x7dh2uTSROAUS99EHITtOSrwfm4oWc1ihwGE6HzXZ5oNPTbWDjAVLxtJy47ufw==
X-Received: by 2002:a2e:88cd:0:b0:288:9e77:4bd6 with SMTP id a13-20020a2e88cd000000b002889e774bd6mr1049163ljk.183.1674350462502;
        Sat, 21 Jan 2023 17:21:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2082:b0:4d1:8575:2d31 with SMTP id
 t2-20020a056512208200b004d185752d31ls2653475lfr.0.-pod-prod-gmail; Sat, 21
 Jan 2023 17:21:00 -0800 (PST)
X-Received: by 2002:ac2:53b3:0:b0:4cb:2c19:ec21 with SMTP id j19-20020ac253b3000000b004cb2c19ec21mr4998358lfh.0.1674350460669;
        Sat, 21 Jan 2023 17:21:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674350460; cv=none;
        d=google.com; s=arc-20160816;
        b=EvBKgq3GMvIi+577Vy8ftw+rmqnB/+aYiWr0Dd4Lk44VA0UP0ee/bvwXiQG2BcvvIz
         oNoXfNdSR8ZUg5OA5k9XcdcepX8e6CTMWKMqUOPUAbZMLo+mf8wnPeKfvsLIezS46ZuD
         FOkj3SVEbkVtZiDuR38piIWiMM+psedqAp2s21WQDxDbOH/zk/5Okp9+yIsS3Kf2FSnT
         6jYbpL40plE9NCx+e/MOhWEQCJtyvKVqiFfyRcqeT+Mil4Si1MnwO89vxI0M2nGHdllX
         JerZ9W4F2Um5udpgpKlMvfhqb/CKikqzcfaL+gGnHl2A079u2bzXRMK1iT+73XxnZN6w
         ti0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=83Hig+gABAkfRDcS8qIlhEYpj8PzIWu7GJi5KYYaB+Y=;
        b=kgLpj94/tvXeml3JjFP0wS6saGNzwrMwCth9WQCIzCGs5nt0aKoeg4Kr7QIetVfSWn
         N1/YaX3PaCXpWfM6Zdqr3HAz92n33l+cyy6PSAECCXiZxpUXtcI1B1/UgUSuY5+rwr4M
         vE+kS6AdXmmqRHT1RqCr3cJb8zvjLnswpo2K258VKF7VrDkq22ESaYbPTavtsCuNtoYx
         oHq40FJrm01fux2fSBqYw0+5K6W5T21f+PNwk4YmuyVvb+UxjXuRjJEjyQFOXCzPzYkD
         GO8vBHtKTk79L2+Mo/SnS0moc0iVY2oI8j8YaUWEBKc+IifN89chEnFOtariVS2KtrPi
         720A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=kQpLLvWG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id e9-20020a05651236c900b004cb0f0982f3si2004541lfs.4.2023.01.21.17.21.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 21 Jan 2023 17:21:00 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id F21E1B80880;
	Sun, 22 Jan 2023 01:20:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 424BEC433EF;
	Sun, 22 Jan 2023 01:20:58 +0000 (UTC)
Date: Sat, 21 Jan 2023 17:20:57 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Christoph Hellwig <hch@lst.de>
Cc: Uladzislau Rezki <urezki@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, Sibi Sankar <quic_sibis@quicinc.com>, Bjorn Andersson
 <andersson@kernel.org>
Subject: Re: cleanup vfree and vunmap
Message-Id: <20230121172057.44095a9626e7fdd05f221b1f@linux-foundation.org>
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=kQpLLvWG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 21 Jan 2023 08:10:41 +0100 Christoph Hellwig <hch@lst.de> wrote:

> Hi all,
> 
> this little series untangles the vfree and vunmap code path a bit.
> 
> For the KASAN maintainers:  the interesting patch re KASAN is patch 8.
> 
> Note that it depends on 'Revert "remoteproc: qcom_q6v5_mss: map/unmap metadata
> region before/after use"' in linux-next.
> 

In what way does it depend?  Not textually.

I could merge the series as-is into mm-unstable, but presumably that
tree will now blow up if someone uses qcom_q6v5_mss.c.  Which I suspect
is unlikely, but taking a copy of a899d542b687c9b ("Revert "remoteproc:
qcom_q6v5_mss: map/unmap metadata region before/after use"") is easy
enough, so I'll do that.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121172057.44095a9626e7fdd05f221b1f%40linux-foundation.org.
