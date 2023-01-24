Return-Path: <kasan-dev+bncBCT4XGV33UIBBVEGYGPAMGQEBEML4RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E690767A426
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 21:45:08 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id sa32-20020a1709076d2000b0084d4593797esf10620703ejc.16
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 12:45:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674593108; cv=pass;
        d=google.com; s=arc-20160816;
        b=cmWxy9Hy0qXCvGrUSft4EEi6ippJc/YpsuNodOcW7F8RHVuWoTRRvNIZGq2qZxgQNk
         P0S+ktNnT8mA8DvpbXJjXTs8VMQV6UxGBxdF+Zmawa3J6HgrGX2xjElW9oyEGPeXcybM
         EOnRV9o6f+iATQazA3SQzvMJ8jSDI7w4Pli2AF9vq8YAsD1aDxK3Ye6Vj2vnN5NswCdo
         3gyeUcsh4Ftj4SalT/lamx8JHcL6E4xHWF4ojjIMmXoSJI3Zgj0Y9MxkrlNkAoonn5Ms
         mx53y3LsdFGu484H/cT4uy5mJqscYKcX31Ol0r8SqMuM4BsWOI2Q9psH6wESKTdHhEQO
         zloA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=J1SfUyarSseqvmBoTSHnOO3m95Wt9osNqCoyHu/ZwpM=;
        b=ntUVYtbNuJbqfxQOGLUxG9nVqMN7tqC435nX1rsA0Nwx5PGfb/1kcOo5dpDAJm8xih
         gBkA182ra4OP3x8BFmrlxUyRDwKtrleEWqbBGQ3V35E0ztOmDx3HpIz/VlVc6f9JGlFf
         TUptIBCTxb/h4KQBJWKvKIqgjRgvsjm/8nLLaEVEGcb2F2BE4ritqGVYb+l7Ey6ecqF7
         uhjl+XTpKLqy7vO6At9hh44+StO2x5mYyF5tVKTS28kHvnrYhGM9s/E5r8YcL9fAUtuf
         8oTAnZm9/Fo4WehXjtsqZPLxtpTjNAP5UNGvYr1I5sHaKIWwt1N70aO1z9KpmbxzdPet
         xgQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ktoPCjIa;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J1SfUyarSseqvmBoTSHnOO3m95Wt9osNqCoyHu/ZwpM=;
        b=k6foOmKMCf4EFTeZyTUPhKkkOdJ83fyg9JpgKa3wqqm4aaE0eiwc+kDnnVQz6ULnzX
         XzkpDh628vy0skDrWiiyBRW6rt7mYUtjlRripkmdaU/UAkQV+w9n5vvPWh+NXK02uOVT
         a38bs2zlMlb5eOPepLgNBSWATKvxaA7YjTA6O/fGHIeoOk0Mr3pgch+YvcXjU689nH2e
         JJS5/vqma94wPVs+9iT6jdg2uAcM9zy2WGXvoQz3BvqNM6zUoQKxLyPuMRYTZI94dmn4
         ObUIxP7TSUI8fyP5a+ReEuA5e4BsdppbhdLKOAGwuppkowfbaJ5W6h2WHSisr2i/jH4e
         NbuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J1SfUyarSseqvmBoTSHnOO3m95Wt9osNqCoyHu/ZwpM=;
        b=0NivwJYmTAjWaIf+SbBTDVIfS+XEo52xB/AG0Msp4NHW9vo40Ue2VlgKyIELBziaCi
         HUdgoKgERg/PLO6ijYCD4Gc4cA6TbYP5et1v05Oeg6H8Eac+W5k+a1DmrgbfWC7NiRXN
         aNYlhvYDm8c6vkqrwp4IGz9/N1YYeBcWnTL4bSKkBFpRfjvz0mNLOmJWmcg+Uh2ldTpu
         xDgCyWfAv2izGbAJlaF0l5tMtwJu1Tnid1Jf7LMOkzJlgdUA56D7FGgXFW/QD42vgCxf
         6Gc6g05OWNZmbYTaUEfCfwjbL8UMUCDrU8TeYUll1Nrqv0bL7cwOBQzQYC81kXfX9Lyp
         xShw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koNtItmZZdpYIdfpIMDXauYJ2MSFTuuWFQm/iiBY6GvRBIQEEXU
	32/ZTcIQ2tBkClfh3GXzy7s=
X-Google-Smtp-Source: AMrXdXtl7kvvp0Ty5kHZhtMX4cpH8h0Fe/KxI7QFjh61VSfD0ULj0pXPXdFOxbn5yBaBcLHXbPHr4A==
X-Received: by 2002:a17:907:1b0a:b0:872:84a0:69c8 with SMTP id mp10-20020a1709071b0a00b0087284a069c8mr4330940ejc.220.1674593108368;
        Tue, 24 Jan 2023 12:45:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:b9d9:b0:7ad:9efd:4692 with SMTP id
 xa25-20020a170907b9d900b007ad9efd4692ls10232538ejc.4.-pod-prod-gmail; Tue, 24
 Jan 2023 12:45:07 -0800 (PST)
X-Received: by 2002:a17:906:e247:b0:84d:3928:66b6 with SMTP id gq7-20020a170906e24700b0084d392866b6mr30652419ejb.40.1674593107069;
        Tue, 24 Jan 2023 12:45:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674593107; cv=none;
        d=google.com; s=arc-20160816;
        b=uvGm/VsmgmxAsuQM5uc4WmdB1BM6dNDYh/BzWWvcZUAUnb+XXcF8eD99Z33FS/ybi2
         U5fvBzrsSfj72uPkF3//OtQLtlUB11RWRTtN30u0RRJdTJmRVeS5Z3mQlfENKEPlwYQ5
         6jMldhMU/HnXPtdtJJRsfyVj0+sIsBCtkbhNq8YT80jgut7HuTDsT2JNsQxvluAD0/HJ
         d+y5IBsYZTeXkSDaoJeMNo7Rtr17k2+BuJhizo2sUvhy2Zb9Bj1bC8CyHu9Gf3exqu5U
         CM9/Vy+zbvMmaQbnZyaj2R3ZACbs+fWXsCNt2jPIuuhANBESrvsbGd5uZ9BVMxUCyfV9
         djMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=e4hgHO9o347mzPT5ARss67RUkShwyJudmXP7IuuIrvI=;
        b=pWpWP9L18OW6yBEKLwDQDSUccnVbT4pqigQektfsEtxXBepNPC54qOdQLzVSyncEtP
         d0OWF6MC0Ajc6NHeNsKM9xj5hV/ewGT03Jo99aj+O9JEasU0tnQ2zFKm4dJWKmUAi6oP
         lfHmSf5d/fbsh9x3gi0KSsMVvvd5lSPBJSSzpJ1ie23pNmMFQffSrTbMUxjlbtByfN6s
         Y18JKTGzDLZOAYAMM9oyRO9PswkQ7kWFEDSrqot9SKxJwrfzEQppFAgt0EJt7c5w9AGq
         tPeyA+nqsWJJ4o6tWo0xDAZYjfWUw+6tj5n+m3r9qvdXfgALwhsgTy8rnottoVUiD+Os
         R1jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ktoPCjIa;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id a6-20020a1709063a4600b0086e09d5ce59si169593ejf.2.2023.01.24.12.45.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Jan 2023 12:45:07 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C3E71B816A3;
	Tue, 24 Jan 2023 20:45:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2931EC4339B;
	Tue, 24 Jan 2023 20:45:05 +0000 (UTC)
Date: Tue, 24 Jan 2023 12:45:04 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>,
 Peter Collingbourne <pcc@google.com>
Subject: Re: [PATCH mm] kasan: reset page tags properly with sampling
Message-Id: <20230124124504.2b21f0fde58af208a4f4e290@linux-foundation.org>
In-Reply-To: <24ea20c1b19c2b4b56cf9f5b354915f8dbccfc77.1674592496.git.andreyknvl@google.com>
References: <24ea20c1b19c2b4b56cf9f5b354915f8dbccfc77.1674592496.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=ktoPCjIa;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 24 Jan 2023 21:35:26 +0100 andrey.konovalov@linux.dev wrote:

> The implementation of page_alloc poisoning sampling assumed that
> tag_clear_highpage resets page tags for __GFP_ZEROTAGS allocations.
> However, this is no longer the case since commit 70c248aca9e7
> ("mm: kasan: Skip unpoisoning of user pages").
> 
> This leads to kernel crashes when MTE-enabled userspace mappings are
> used with Hardware Tag-Based KASAN enabled.
> 
> Reset page tags for __GFP_ZEROTAGS allocations in post_alloc_hook().
> 
> Also clarify and fix related comments.

I assume this is a fix against 44383cef54c0 ("kasan: allow sampling
page_alloc allocations for HW_TAGS") which is presently in mm-stable,
yes?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230124124504.2b21f0fde58af208a4f4e290%40linux-foundation.org.
