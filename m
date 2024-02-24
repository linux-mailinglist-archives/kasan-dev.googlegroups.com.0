Return-Path: <kasan-dev+bncBCT4XGV33UIBB4HH4SXAMGQEOWNXI7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 002AA862106
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 01:10:25 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-42e5bee9439sf194641cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 16:10:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708733425; cv=pass;
        d=google.com; s=arc-20160816;
        b=kZdn6Mx9J1MWozxxVWU2XApdUs5/C8UFmmfVGPQ/Ayg0ei6gjoXBmYRbvITw+2zmmb
         aJ4FH6LNU5YQnj6H0AtIqd/sBG6hbrrtwWJm7Q/1eSpkqPQljroXtCmDhs56cF4j/CZW
         nba26JOcymfcyA5WE37QqW/Sw42RhosOPJILdXnz/0Q8SxjAokm3TBj+X2tG3B4AM/M2
         Vu5tfktFbs+7nC3k8+oA2a86YAx25uOz1sGMpbV1vWZ/x76kW8a9GWuWR/kRkov9nEBc
         oIz1OJV0pmsJmuHNfZ8adfQB64VarWcnPgmhqZGZQ9yDU3I2UXLBj8RPtaysHgTVxcmO
         nKSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=3urcUfkVpO35nZlOLVaoVuqEogXQpgew0vZAgN2myiM=;
        fh=5EBFzAmApjKWNbPEWl1qTCBok81aZgtFTA/Pxxebpy4=;
        b=UZZ8MuHUN0SGdeUND6JV1bA/jJLRDUwh/xSomFsoILsZT353gvIIC+w3puuDCiJbxZ
         uDiSsGWTk1mgev+rYOwtZsf7KEdNvGfbmN0GEBPZmh8hI5dvDT96Xs+ji+UElPcMA1LF
         Acy+3OXVxY2zc8JIlrWF3oiVDrxMHDrEI3isNBnXwDM5i66dLAiNJA/Xe4FedYfzvWe6
         Furt+Q9YADcFKiaRhUGmPrkFERtBxpC+T//oiK1jaSkcsIsgN0OtP62LfE8BnQn9qxzR
         HzRzTExTYYCvHg861OzgOg7fip0yZ6CyBV9LSW/WZMrd01EVoTJdNm0VdRGNvwNX1++J
         BT6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Kla+jAG5;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708733425; x=1709338225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3urcUfkVpO35nZlOLVaoVuqEogXQpgew0vZAgN2myiM=;
        b=lJcAoRUAh97Q3NHVxhzgdZAZqdZNJmWM5lE4Q4HSX+wdgMKHzohifK8vxkEOVcVpHw
         s+pMR1mipGjBFeqYWMdXVfuL6Mz2S5oTyqaPUJMfJPQG3AsleZm9Pet+eJ8v/9RRba5U
         7zrtlCZe4qGRa+PgtHx84i6hhRf8K7AeGOH+vJiQCRUrs6fY1v+JnqGs5W2XxuovcbpV
         YbrveA9EPZSEZ4T1FvuDFyCwqDds//FPxJi2RpgqgVFsM0z5FYsD0+KhRR7LosbHQ7M3
         tjEDEC8VKwK0Anw6j86HGxNmip9K/BMs8JF+uDbbkYYk75DlW/6NAxNh8eYoSPV01kou
         1sXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708733425; x=1709338225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3urcUfkVpO35nZlOLVaoVuqEogXQpgew0vZAgN2myiM=;
        b=PAI2GmaWunJXRELrrL6k/icaeFdXAFA1QE8FpCSY6gs9NaEXfjEtNGMMnboeUPfACS
         hQyfZezPEVNTyPoRkeyU+BbfGqA3DdbpW6bf+YL4ZTT9WlT9/uBAgM2N8wE1ohXM545m
         hnKPp2HTlr/4XTQots86L7fSdgjvG42X+PsZ3UixRk6jlWFafXHuEboQAYpGqPMqRl+G
         nEVpyq6BGnA6GKeCwWuxx0RjEOQ2XeekH5vMHL9VFSotRLdYkXdnyxjftQY+gNOm4dNZ
         2jqDRfo1zXUrncTIv0VggoMebESKZoKIy4PNGy95Hm4GwlgmLeX8D0fh8qt7Rf+c7HLP
         K4Lw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZnJAVwSS7GkZy+nFsussLwffKCECsqJIJovYokLcMWSsPMKcskD4WR5R+VOvnr4pw228YBYl1k3L4VwIL40mtfKRjdPwuJg==
X-Gm-Message-State: AOJu0YyFiSfo8SCmzpXLQlR0601F0VIAdEZxbxiUharZ5T1OC8x9o02q
	j8STlo+FZIPUNExwTs+4UgSPvZwFmdFWuk+gpTk+Nx2aaGhILHS9
X-Google-Smtp-Source: AGHT+IHhQygNB8NfAbaSSbFk9zYTHB8ra0QGZPDLd1DSrO8ZIZCZvAVLoZ7yBaTJu15a7zSwc3DAFQ==
X-Received: by 2002:ac8:74d9:0:b0:42e:4888:7986 with SMTP id j25-20020ac874d9000000b0042e48887986mr104916qtr.29.1708733424740;
        Fri, 23 Feb 2024 16:10:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d60c:0:b0:dcd:a08f:c83a with SMTP id n12-20020a25d60c000000b00dcda08fc83als1747870ybg.2.-pod-prod-05-us;
 Fri, 23 Feb 2024 16:10:23 -0800 (PST)
X-Received: by 2002:a81:a00c:0:b0:608:5245:46e with SMTP id x12-20020a81a00c000000b006085245046emr1465098ywg.12.1708733423371;
        Fri, 23 Feb 2024 16:10:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708733423; cv=none;
        d=google.com; s=arc-20160816;
        b=YhNVASPYUmpf1skndTr7fnEGIhEyk008GCMJFBoldEELJw33S0pBlZpIv/QsQHqMOp
         stges/Qj8Q4Tkc69A0W3siSWiupzwr8zoRZdNPgQYuwMxnHwF9fnKgPr2ZVFulxtsjwv
         aLdm+IneeDpDJcNgz0B+W7DnWOAtXzY5RS5IRWRXmZa9p4kKI10dW6vLHPLRpADXIhXq
         FOhjidCaCPs2ZKdO85VSCEg7q9UX8SxlaDyuD+cCSV2p7dHnYl0SRJyum4zHjKitWO3T
         hl3jgKLMZ/iKuizrt8e3vTyi/JuVMYXgXTsUlTsAL4V5iPz2y8TxVuMmZtpp5Y615k3r
         8akg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=u8QaGjwUNQzrXAdbEuMiKjIXuuZrH80J3g7kclepQS0=;
        fh=YYfwvWTMyk+Yxjuip3bLTV+bOWUWN1wV/4UaX3SJs5I=;
        b=nLE1/QmK9B87yQX6UuGEFWjtXsAdeRNMNahI5vvv+NWkSkdpUF1AewyxKhyuVxTQbZ
         2IZfEASUgkYu+Y05VVxeFFIHqIbNd41IDbwbeglUP3WQABib1FPR3piQL1QDUkcHJoB4
         7warpXAPBreM8mZqftGPn9kCmZX3Gh7Ts3Z7lZaWJMNZQwHB8tVwopV7WsHvOKWYxGe2
         kCZLCFNjI7Fnr2yoBMWJcC5wY7sXFfQOE7a6A78+dOknv9BkHmA+qf/eHkHW+g3x6AyD
         1wVgdaqWRDx5FeupddpFNzIFikX3Ous8+0/Nr1nR9W84wUxUiNE7t6iz3MusJl+5lX6R
         eSCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Kla+jAG5;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id i141-20020a816d93000000b00608995d44f4si14527ywc.0.2024.02.23.16.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 16:10:22 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D70EA61387;
	Sat, 24 Feb 2024 00:10:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 28601C433F1;
	Sat, 24 Feb 2024 00:10:21 +0000 (UTC)
Date: Fri, 23 Feb 2024 16:10:20 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Paul =?ISO-8859-1?Q?Heidekr=FCger?= <paul.heidekrueger@tum.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, vincenzo.frascino@arm.com, ryabinin.a.a@gmail.com,
 mark.rutland@arm.com, glider@google.com, elver@google.com,
 dvyukov@google.com, andreyknvl@gmail.com
Subject: Re: [merged mm-stable] kasan-add-atomic-tests.patch removed from
 -mm tree
Message-Id: <20240223161020.9b4184e1e74b35f906e0ec78@linux-foundation.org>
In-Reply-To: <xk3hvszpeg3ttyexcm5s7ztj64nx5gxfwp6ivmobvfzogqjwn4@wicwiqm4bw7z>
References: <20240222000304.8FA56C43390@smtp.kernel.org>
	<xk3hvszpeg3ttyexcm5s7ztj64nx5gxfwp6ivmobvfzogqjwn4@wicwiqm4bw7z>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Kla+jAG5;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 23 Feb 2024 21:25:04 +0100 Paul Heidekr=C3=BCger <paul.heidekrueger=
@tum.de> wrote:

> I'm unsure what the protocol is now; do I send you a new patch for the di=
ff=20
> between the above patch and the v3 patch, or can you just use v3 instead =
of the=20
> above patch?

Yes please.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240223161020.9b4184e1e74b35f906e0ec78%40linux-foundation.org.
