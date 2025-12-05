Return-Path: <kasan-dev+bncBAABBCNBZLEQMGQETLMUEVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 60989CA6910
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 08:58:03 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-657a6c9d45esf1205098eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 23:58:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764921482; cv=pass;
        d=google.com; s=arc-20240605;
        b=foJOnSAn45q39FTvChW9K1JEZNBtdgEnAELmgQgTIJEfM6d8gDdVAH/a9VrBgPzgxE
         rmd3bNOuJuGztBaI++OD/fqHGlQ6sEUkhoMIaJgmB6Lq5JIHVEHP9lrciQZMsn6Uc4S3
         WPpBW/gp/lp2AIPdyn71Cs9nqljpCSNAlpUCpeJo2Y2nuzcZy1X71dNsYxOE0mFUo6tq
         68G1YWHg/r/TI0VAe/9PuzT5D1achx9s/JXE6lDuzz3YFqSYJMF+0Sj5ODlFR2fTjOu9
         UUeq2yC62iCV3zxhcE+09mADRezYj34xuzTIOrW835u6T9UkhLrl6f1EIM9+cs9vwo1L
         MvFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=Tia8moYRGl+oq7uqdg2CxVVxxHRbdWSTMI5iD+JhfYg=;
        fh=bT+q3OsvC9/Ya57lElrB5ZvrZ1js+GfeDKrK1wavggU=;
        b=Px1x90k5ohyT1/UUGCBQNIAXuK8YwabTr2UIEVees0uZr/0iyx4tudPjik/fWNU3eJ
         XdCQQ8voj4inPIyp/49x7bKik/WSBVhXFLrOGytZk+PDSncQpDKGPVEOnvgbOtJ043VM
         aWloTBX4ajnpXOSpnzvPvFATXT3MI/EzS9gKR864UrYEKUj1LbywMyGn11JuWal4Mt0c
         9R+Wpczv7akkRBXojvqS6FgSFVi74X3zWVDiFw7EEkFIkY1A9J/C0UAjOFpyGMAJGNxM
         xpdTC8mwuHhsTidRLg+68rPhLL3SpJqe3/jlKKE/OHyQ9z9u6nvTMXy8ybTULIFlXcGA
         Irng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=aEo6vSWz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764921482; x=1765526282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Tia8moYRGl+oq7uqdg2CxVVxxHRbdWSTMI5iD+JhfYg=;
        b=mp2UUtvFGF2rYZj/WK+YTMPe45uZJdMF/nEjPGK6nIWyDH50dT9oLYT6aNslA+NcJR
         h2M253f3DuTP4QO8u13p920ZyTa+ULFNktMBSKLKeqVhBzNEluvQq+IGH9d+VNabHTM+
         AOEcRyFTuiiUrHkV+MefzxgcKoYNydrYPmwXfLGwTE6XqwhATM7ZuvGfT4nnN58C3yWy
         WuxeXCQkiYtx1Pqz9fKfd7DnfAvPdQy/qzLkN8wUEwzS3mydQ+Co3WLwh46UScQzTj3P
         231pll4h3VeQ/5Ays67ff9hZOkFni2leTuoTSoM3OxC4h8ORSC9hYqMWU9W8HcTBVct7
         2QRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764921482; x=1765526282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Tia8moYRGl+oq7uqdg2CxVVxxHRbdWSTMI5iD+JhfYg=;
        b=SGIHoP3bsUJeFAz0wnkZkebVWRzGg8J2SbEbQ9Igw5c57hs63NbTo3511AOJhW44cz
         7xIdAEdrqbCMXackr/MG0yEAkOIZfGrseBgxQIuPZed6x0mOs27BtaNgfkVqkRGZzyIg
         01WIYQ/pP8JDUu8cpyZWjDkNt5SGpSrqDTpPacUh16nip16/xYR7QvfnwMq1iJwiSroG
         aEU2cbG+VIgQUfZ9EUVFWiVUm0pTGvEryuVuueckmo5llF/ginZZCyTBU6e8XW8IgUeJ
         LSpQJgFBnC04ANp4cdHGhBQ2So8BsbRC4cOTPD5RKq/FUoWjJgZFaJibxjDVV6ZoTMR6
         Y0hQ==
X-Forwarded-Encrypted: i=2; AJvYcCWvjDZwBE9AMql+9zP5r42OpkJeR7tG4QgQhq+aDs60aXalF1q6Lyieyi25jfo44OdYN756Jw==@lfdr.de
X-Gm-Message-State: AOJu0Yyo4NZeylQsKohN+03PHWnZqbG0hMXAsHXsAANfBSuKJTASgnmX
	/4DkzGDPucmDmSNI/4jTG7fewDbo3gOB/JTZd9+8W5eqt4i5XY1ZN3ev
X-Google-Smtp-Source: AGHT+IF3//0rEjn5gmf5IVGFZZ1HZXxMvjxubvJ1GfA/PawtLQws2TFYA5+aRtgLr1T4k7RfVTY6CQ==
X-Received: by 2002:a05:6820:f04:b0:657:71fa:5f6d with SMTP id 006d021491bc7-65972784330mr4649619eaf.6.1764921481661;
        Thu, 04 Dec 2025 23:58:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZG8pAX58kkd9ZD/UnAMVYoqvtGuzW1s+42qhkxUM1nww=="
Received: by 2002:a05:6820:2e90:b0:656:cea8:d380 with SMTP id
 006d021491bc7-6597cfea24bls374340eaf.0.-pod-prod-02-us; Thu, 04 Dec 2025
 23:58:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV7Vx6XjtRCDFOQluwNCryroZK05TS6VzDovHfkX8O3DIhZe7kZ1P4f/cbcIkhCVM8xCGCQs7MZWq0=@googlegroups.com
X-Received: by 2002:a05:6830:439f:b0:7c7:6bb4:1197 with SMTP id 46e09a7af769-7c94db2ea1amr4817197a34.24.1764921480806;
        Thu, 04 Dec 2025 23:58:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764921480; cv=none;
        d=google.com; s=arc-20240605;
        b=XGgDS2ZQEW3bkqO/mh5SmVfarytuG3GOp5vhy3MD/dsVMLmA8QmZkSaOf99JjSDft5
         zqCXKEELdUrNoV4NjZD7OX7oRQk9Wih0gHJleYoCgdbOFuODlDNWy8pJWlQX/p2bzCsu
         INxoc6KJYlwaUfcIeaDmmFDaN/wS/5/q3y7snsYKw7dTcnUsKW6dsF/trIHfTarz/uPY
         iwbAj1apBT1CgCt1HA6FAJolKyWRenCLcnwFJB/XPSVHhljiVMmvqQLQRneXq1sIf9lz
         KG+YeQCgUoiVaSnpvngls9zb2S4pjIEOor2sKk54GfZ5a6OQhZRNWYRkhzzzLdeSdqKU
         2+pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=1h9/RRI9HDS7ow72CX1vsz7ZQ6MiMrPzsBwSmu9lD7E=;
        fh=3SQhQYA6mQaSnmMVr5W3CfuW6wwXdAZn99tmz8JwRgQ=;
        b=MER2P/wIWelTrCwSrY7rzokesPiNjSxPusuxcwZedjw894fG/haYn/9O650uI9wsl3
         7jHHT1Prk2jdAhMx22xKWJ9WKB6KtYZV3qfjjtmyRJRDXhSQSt8gvsbSDIWSlxO1ndcc
         jGLjVAVWew5IA2bDQqES8VJBIIrKBexy2d8iCc+yI2Zd5oaXBfhSsWu6Nlf87+Hn1uZY
         Wy0raW0RUnmtkPgNnpxUDJmcwOF4Y9utFx5PprWhJ9uTwfrGT6hrVftharXC72A/7fji
         xXi6YpxzupADXLJkhLf/kZcjrDbcW13YRhVXh7eoXqONikPCFiwM7lQWM/nMl0HG5gI1
         xg9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=aEo6vSWz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244122.protonmail.ch (mail-244122.protonmail.ch. [109.224.244.122])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7c95ac597absi237532a34.4.2025.12.04.23.58.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 23:58:00 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) client-ip=109.224.244.122;
Date: Fri, 05 Dec 2025 07:57:55 +0000
To: Andrew Morton <akpm@linux-foundation.org>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: urezki@gmail.com, dakr@kernel.org, vincenzo.frascino@arm.com, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, kees@kernel.org, elver@google.com, glider@google.com, dvyukov@google.com, jiayuan.chen@linux.dev, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 0/3] kasan: vmalloc: Fixes for the percpu allocator and vrealloc
Message-ID: <t7bhzp4gidfqb7bnlvxio2tifyvifhqirumuugbb7opodxwwra@5iytacnkfwm3>
In-Reply-To: <20251204142112.fc11c55e46bd0017c41b49e1@linux-foundation.org>
References: <cover.1764874575.git.m.wieczorretman@pm.me> <20251204142112.fc11c55e46bd0017c41b49e1@linux-foundation.org>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 5aaf1a947d9e648b1e999cdd04f2d6f929387ec1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=aEo6vSWz;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-12-04 at 14:21:12 -0800, Andrew Morton wrote:
>On Thu, 04 Dec 2025 18:57:44 +0000 Maciej Wieczor-Retman <m.wieczorretman@=
pm.me> wrote:
>
>> Patches fix two issues related to KASAN and vmalloc.
>>
>> The first one, a KASAN tag mismatch, possibly resulting in a kernel
>> panic, can be observed on systems with a tag-based KASAN enabled and
>> with multiple NUMA nodes. Initially it was only noticed on x86 [1] but
>> later a similar issue was also reported on arm64 [2].
>>
>> ...
>>
>
>I added cc:stable to [1/3], unless its omission was intentional?

Thank you for adding it, I forgot it was missing

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/t=
7bhzp4gidfqb7bnlvxio2tifyvifhqirumuugbb7opodxwwra%405iytacnkfwm3.
